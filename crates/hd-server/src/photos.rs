//! Photo backup from a phone's browser (`/photos`), for an iPhone or any
//! phone without the sync client.
//!
//! A browser cannot read a phone's photo library on its own or run in the
//! background, so the user opens the page and picks photos; the page's
//! script (`static/photos.js`, the one page with JavaScript) then works
//! out which are new and uploads those into `Photos/<device>/`.
//!
//! The script cuts each file into pieces of [`PIECE`] bytes (the largest
//! chunk the store takes) and names each by its SHA-256, which the browser
//! can compute one piece at a time. That gives:
//! - **End-to-end verification for any size.** The store refuses a piece
//!   that does not hash to its name, and a commit re-reads every piece and
//!   computes the whole file's hash itself.
//! - **Requests the proxy lets through.** Each request carries at most one
//!   piece, so none outlasts Traefik's limit on a whole request.
//! - **Resuming.** A check reports which pieces the store already has, so
//!   an upload cut off by a locked screen goes on where it stopped.
//! - **Skipping what is backed up.** A file is "already in the drive" only
//!   when a current version under `Photos/` holds exactly its bytes: the
//!   same SHA-256 for a one-piece file, the same list of pieces for a
//!   longer one (which only a file uploaded from this page has). Anything
//!   else is uploaded, so a skip can never leave a photo out.
//!
//! Every commit is made with base "absent", so a photo never becomes a
//! version of another photo that had its name (phones reuse names): the
//! store keeps it as a sibling copy instead. Identical content at the same
//! path adds nothing. Nothing here replaces or deletes.
//!
//! The endpoints take the session cookie, the page's CSRF token in an
//! `X-CSRF-Token` header, and a same-origin request, like every web form.

use std::collections::{BTreeMap, BTreeSet};

use hd_api::{J, s};
use hd_chunk::{MAX_CHUNK, ObjectId};
use hd_common::json::Value;
use hd_common::{pathname, timefmt};
use hd_http::{Request, Response};
use hd_store::manifest::Manifest;
use hd_store::model::{Node, Origin};
use hd_store::{Base, ChunkList, Kind, Provenance};

use crate::App;
use crate::api::{error, json};
use crate::html::esc;
use crate::web::Session;

/// The size of every piece but a file's last: the store's largest chunk.
pub const PIECE: u64 = MAX_CHUNK as u64;
/// The folder photos go under, one subfolder per device.
pub const ROOT: &str = "Photos";
/// The longest device name.
const MAX_DEVICE: usize = 64;
/// The most files one check may ask about.
pub const MAX_CHECK_FILES: usize = 500;
/// The most pieces one check may name, across its files.
pub const MAX_CHECK_PIECES: usize = hd_api::MAX_MISSING_QUERY;
/// A check's body: its pieces at 67 bytes each, plus names.
const MAX_CHECK_JSON: usize = 2 * 1024 * 1024;
/// A commit's body: room for the pieces of a 256 GiB file.
const MAX_COMMIT_JSON: usize = 8 * 1024 * 1024;
/// The page's script. Its policy allows scripts from this origin only.
pub const SCRIPT: &str = include_str!("../static/photos.js");
/// The policy for the photos page: the default one, plus this origin's
/// scripts and requests.
const PAGE_POLICY: &str = "default-src 'none'; script-src 'self'; connect-src 'self'; \
                           style-src 'self'; img-src 'self'; form-action 'self'; \
                           frame-ancestors 'none'; base-uri 'none'";

/// The folder for `device`, or why the name cannot be used. It must be one
/// folder name that every client can make.
pub fn device_folder(device: &str) -> Result<String, String> {
    let device = device.trim();
    if device.is_empty() {
        return Err("name this device".into());
    }
    if device.len() > MAX_DEVICE {
        return Err(format!("a device name is at most {MAX_DEVICE} bytes"));
    }
    if device.contains('/') || device.chars().any(char::is_control) {
        return Err("a device name cannot hold '/' or control characters".into());
    }
    pathname::validate(device).map_err(|e| e.message().to_owned())?;
    if let Some(why) = pathname::windows_problem(device) {
        return Err(format!("a device name {why}"));
    }
    Ok(format!("{ROOT}/{device}"))
}

/// A photo's file name, checked to be one valid name.
fn file_name(name: &str) -> Result<&str, String> {
    if name.is_empty() || name.contains('/') || name.chars().any(char::is_control) {
        return Err("invalid file name".into());
    }
    pathname::validate(name).map_err(|e| e.message().to_owned())?;
    Ok(name)
}

/// The length of piece `i` of `n` in a file of `size` bytes.
fn piece_len(size: u64, i: usize, n: usize) -> u32 {
    let len = if i + 1 == n { size - PIECE * (n as u64 - 1) } else { PIECE };
    // At most PIECE, which fits.
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// The pieces a request names for a file of `size` bytes: exactly as many
/// as the size needs, each a SHA-256 in lowercase hex.
fn pieces_of(v: Option<&Value>, size: u64) -> Result<Vec<(ObjectId, u32)>, String> {
    let list = v.and_then(Value::as_array).ok_or("pieces must be a list")?;
    let n = usize::try_from(size.div_ceil(PIECE)).map_err(|_| "the file is too large")?;
    if list.len() != n {
        return Err(format!("a file of {size} bytes has {n} pieces of {PIECE} bytes"));
    }
    list.iter()
        .enumerate()
        .map(|(i, v)| {
            let id = v
                .as_str()
                .and_then(ObjectId::parse)
                .ok_or("each piece must be 64 lowercase hex digits")?;
            Ok((id, piece_len(size, i, n)))
        })
        .collect()
}

/// One file a check asks about.
struct Asked {
    size: u64,
    pieces: Vec<(ObjectId, u32)>,
}

impl App {
    /// `GET /photos`.
    pub(crate) fn photos_page(&self, s: &Session) -> Response<'static> {
        let token = self.sessions.csrf_token(&s.id);
        let body = format!(
            "<h1>Photos</h1>\n\
             <p class=\"page-intro\">Back up photos and videos from this phone into \
             <strong>{ROOT}/</strong> and a folder named for the device. Pick them each time; \
             anything already in the drive is skipped, and an upload stopped by a locked \
             screen or a lost connection carries on where it left off the next time.</p>\n\
             <noscript><p class=\"notice notice-warning\">This page needs JavaScript. Without \
             it, photos can be uploaded from <a href=\"/files\">Files</a>.</p></noscript>\n\
             <section class=\"card\"><h2>Back up</h2>\
             <form id=\"photo-form\" data-csrf=\"{}\" data-piece=\"{PIECE}\" \
             data-check-files=\"{}\" data-check-pieces=\"{}\">\n\
             <div class=\"field\"><label for=\"device\">This device</label>\
             <input type=\"text\" id=\"device\" name=\"device\" value=\"iPhone\" \
             maxlength=\"{MAX_DEVICE}\" autocomplete=\"off\" required>\
             <p class=\"field-help\">Photos go into {ROOT}/<span id=\"device-echo\">iPhone</span>.</p></div>\n\
             <div class=\"field\"><label for=\"photos\">Photos and videos</label>\
             <input type=\"file\" id=\"photos\" name=\"photos\" multiple \
             accept=\"image/*,video/*\" required></div>\n\
             <div class=\"button-row\"><button type=\"submit\" class=\"button\" id=\"start\">\
             Back up</button> <button type=\"button\" class=\"button button-secondary\" \
             id=\"stop\" hidden>Stop</button></div></form>\n\
             <p id=\"photo-status\" class=\"photo-status\" role=\"status\" aria-live=\"polite\"></p>\
             <progress id=\"photo-progress\" class=\"photo-progress\" max=\"1\" value=\"0\" hidden>\
             </progress>\n<ul id=\"photo-log\" class=\"photo-log\"></ul></section>\n\
             <section class=\"card\"><h2>Keep the page open</h2><p>A browser uploads only \
             while this page is on screen. The page asks the phone to stay awake while it \
             works; if the screen locks anyway, come back and pick the same photos again.</p>\
             </section>\n\
             <section class=\"card\"><h2>Freeing space on the phone</h2><p>This page never \
             deletes or changes anything in the drive, and deleting photos from the phone \
             afterwards changes nothing here either. Delete from the phone only photos the \
             summary counted as uploaded or already in the drive; a photo listed as not \
             backed up is not in the drive.</p><p>The phone may hand the browser a \
             converted copy: a HEIC photo as JPEG, a Live Photo as its still image only, or \
             a smaller video. Before deleting originals, open a few in \
             <a href=\"/files?path={ROOT}\">Files</a> to check they are what you expect.</p>\
             </section>\n\
             <script src=\"/static/photos.js?v={}\"></script>\n",
            esc(&token),
            MAX_CHECK_FILES,
            MAX_CHECK_PIECES,
            hd_common::VERSION,
        );
        self.page(s, "Photos", "photos", body)
            .with_header("Content-Security-Policy", PAGE_POLICY.into())
    }

    /// A POST under `/photos/`, already same-origin and signed in.
    pub(crate) fn photos_post(
        &self,
        path: &str,
        req: &mut Request<'_, '_>,
        s: &Session,
    ) -> Response<'static> {
        let token = req.header("x-csrf-token").unwrap_or("");
        if !self.sessions.verify_csrf(&s.id, token) {
            let mut r = error(403, "the page expired; reload it and try again");
            r.close = true;
            return r;
        }
        match path {
            "/photos/check" => self.photos_check(req, &s.user),
            "/photos/piece" => {
                let Some(id) = req.query_value("id").and_then(ObjectId::parse) else {
                    return error(400, "id must be 64 lowercase hex digits");
                };
                self.put_chunk(req, &s.user, &id)
            }
            "/photos/commit" => self.photos_commit(req, &s.user),
            _ => error(404, "Not Found"),
        }
    }

    /// `POST /photos/check`: `{device, files: [{size, pieces}]}`. Each
    /// answer is `{have: true}` (exactly this content is under `Photos/`)
    /// or `{have: false, missing: [piece index]}`.
    fn photos_check(&self, req: &mut Request<'_, '_>, user: &str) -> Response<'static> {
        let body = match Self::read_json(req, MAX_CHECK_JSON) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let folder = match device_folder(body.get("device").and_then(Value::as_str).unwrap_or("")) {
            Ok(f) => f,
            Err(why) => return error(400, &why),
        };
        let Some(files) = body.get("files").and_then(Value::as_array) else {
            return error(400, "files must be a list");
        };
        if files.len() > MAX_CHECK_FILES {
            return error(413, "too many files in one check");
        }
        let mut asked = Vec::with_capacity(files.len());
        let mut total = 0usize;
        for f in files {
            let Some(size) = f.get("size").and_then(Value::as_u64) else {
                return error(400, "each file needs a size");
            };
            let pieces = match pieces_of(f.get("pieces"), size) {
                Ok(p) => p,
                Err(why) => return error(400, &why),
            };
            total = total.saturating_add(pieces.len());
            if total > MAX_CHECK_PIECES {
                return error(413, "too many pieces in one check");
            }
            asked.push(Asked { size, pieces });
        }
        let sizes: BTreeSet<u64> = asked.iter().map(|a| a.size).collect();
        // What is under Photos/ at the asked sizes, read under the lock and
        // compared after it.
        let held: BTreeMap<u64, Vec<([u8; 32], ObjectId)>> = self.store.read(|st| {
            let mut held: BTreeMap<u64, Vec<_>> = BTreeMap::new();
            if let Some(ns) = st.user(user) {
                for (_, e) in ns.subtree(ROOT) {
                    if let Node::File { versions, .. } = &e.node
                        && let Some(v) = versions.last()
                        && sizes.contains(&v.size)
                    {
                        held.entry(v.size).or_default().push((v.sha256, v.manifest));
                    }
                }
            }
            held
        });
        let objects = self.store.objects();
        let mut manifests: BTreeMap<ObjectId, Option<Vec<(ObjectId, u32)>>> = BTreeMap::new();
        let mut answers = Vec::with_capacity(asked.len());
        for a in &asked {
            let candidates = held.get(&a.size).map_or(&[][..], Vec::as_slice);
            let have = match a.pieces.as_slice() {
                // Every empty file is the same file.
                [] => !candidates.is_empty(),
                // One piece is the whole file, so its name is the file's hash.
                [(only, _)] => candidates.iter().any(|(sha, _)| *sha == only.0),
                pieces => candidates.iter().any(|(_, m)| {
                    manifests
                        .entry(*m)
                        .or_insert_with(|| Manifest::load(objects, m).ok().map(|m| m.chunks))
                        .as_deref()
                        == Some(pieces)
                }),
            };
            answers.push(if have {
                J::O(vec![("have", J::Bool(true))])
            } else {
                let missing = a
                    .pieces
                    .iter()
                    .enumerate()
                    .filter(|(_, (id, _))| !objects.contains(Kind::Chunk, id))
                    .map(|(i, _)| J::U(i as u64))
                    .collect();
                J::O(vec![("have", J::Bool(false)), ("missing", J::A(missing))])
            });
        }
        json(200, &J::O(vec![("folder", s(folder)), ("files", J::A(answers))]))
    }

    /// `POST /photos/commit`: `{device, name, size, mtime, pieces}`, once
    /// every piece is stored. The whole file's hash is computed here from
    /// the stored pieces, each verified as it is read, and the store checks
    /// it again as it commits.
    fn photos_commit(&self, req: &mut Request<'_, '_>, user: &str) -> Response<'static> {
        let body = match Self::read_json(req, MAX_COMMIT_JSON) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let folder = match device_folder(body.get("device").and_then(Value::as_str).unwrap_or("")) {
            Ok(f) => f,
            Err(why) => return error(400, &why),
        };
        let name = match file_name(body.get("name").and_then(Value::as_str).unwrap_or("")) {
            Ok(n) => n.to_owned(),
            Err(why) => return error(400, &why),
        };
        let Some(size) = body.get("size").and_then(Value::as_u64) else {
            return error(400, "size must be a number of bytes");
        };
        if size > self.config.max_file {
            return error(413, "the file is larger than the server accepts");
        }
        let pieces = match pieces_of(body.get("pieces"), size) {
            Ok(p) => p,
            Err(why) => return error(400, &why),
        };
        let objects = self.store.objects();
        let missing: Vec<J> = pieces
            .iter()
            .enumerate()
            .filter(|(_, (id, _))| !objects.contains(Kind::Chunk, id))
            .map(|(i, _)| J::U(i as u64))
            .collect();
        if !missing.is_empty() {
            return json(
                409,
                &J::O(vec![
                    ("error", s("some pieces are missing; upload them and commit again")),
                    ("missing", J::A(missing)),
                ]),
            );
        }
        let quota = self.accounts.get(user).map_or(0, |a| a.quota);
        if self.usage(user).saturating_add(size) > quota {
            return error(507, &self.quota_message(user));
        }
        let Ok(mut whole) = hd_crypto::Sha256::new() else {
            return error(500, "SHA-256 failed");
        };
        for (i, (id, len)) in pieces.iter().enumerate() {
            match objects.get(Kind::Chunk, id) {
                Ok(data) if data.len() == *len as usize => whole.update(&data),
                Ok(_) => return error(422, &format!("piece {i} is not {len} bytes")),
                Err(e) => {
                    return json(
                        409,
                        &J::O(vec![
                            (
                                "error",
                                s(format!("piece {i} cannot be used ({e}); upload it again")),
                            ),
                            ("missing", J::A(vec![J::U(i as u64)])),
                        ]),
                    );
                }
            }
        }
        let Ok(sha256) = whole.finish() else {
            return error(500, "SHA-256 failed");
        };
        let now = timefmt::unix_ms();
        // The browser's idea of when the file changed; a time it cannot
        // have is replaced by now.
        let mtime_ms = body
            .get("mtime")
            .and_then(Value::as_i64)
            .filter(|t| *t > 0 && *t <= now + 86_400_000)
            .unwrap_or(now);
        let provenance = Provenance {
            device: "web".into(),
            mtime_ms,
            origin: Origin::Upload,
            created_ms: None,
            executable: Some(false),
        };
        let path = pathname::join(&folder, &name);
        let list = ChunkList { chunks: &pieces, size, sha256 };
        match self.store.commit_chunks(user, &path, Base::Absent, &list, &provenance) {
            Ok(c) => {
                self.note_commit(user, size);
                let status = if c.unchanged {
                    "unchanged"
                } else if c.conflict {
                    "copy"
                } else {
                    "uploaded"
                };
                json(200, &J::O(vec![("path", s(c.path)), ("status", s(status))]))
            }
            Err(e) => self.op_error(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names() {
        assert_eq!(device_folder(" iPhone ").unwrap(), "Photos/iPhone");
        assert_eq!(device_folder("Matt's iPhone 15").unwrap(), "Photos/Matt's iPhone 15");
        for bad in ["", "  ", "a/b", "..", ".", "con", "x\u{0}", "a\nb", &"x".repeat(65)] {
            assert!(device_folder(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn pieces_must_cover_the_size_exactly() {
        let id = "ab".repeat(32);
        let one = hd_common::json::parse(format!("[\"{id}\"]").as_bytes()).unwrap();
        let two = hd_common::json::parse(format!("[\"{id}\",\"{id}\"]").as_bytes()).unwrap();
        let none = hd_common::json::parse(b"[]").unwrap();
        assert!(pieces_of(Some(&none), 0).unwrap().is_empty());
        assert!(pieces_of(Some(&one), 0).is_err());
        assert_eq!(pieces_of(Some(&one), 5).unwrap()[0].1, 5);
        assert_eq!(pieces_of(Some(&one), PIECE).unwrap()[0].1, 4 * 1024 * 1024);
        assert!(pieces_of(Some(&one), PIECE + 1).is_err());
        let p = pieces_of(Some(&two), PIECE + 1).unwrap();
        assert_eq!((p[0].1, p[1].1), (4 * 1024 * 1024, 1));
        let upper = hd_common::json::parse(format!("[\"{}\"]", "AB".repeat(32)).as_bytes());
        assert!(pieces_of(Some(&upper.unwrap()), 1).is_err());
    }
}
