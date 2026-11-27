//! Photo backup from an iPhone, through a Shortcut in Apple's Shortcuts
//! app. `/photos` makes the Shortcut's token and explains how to build it.
//!
//! A browser cannot read a phone's photo library or run unattended, but a
//! Shortcut can: it finds the photos added since its last run, asks the
//! server about each by its SHA-256, and uploads the ones the drive lacks,
//! one request per file, into `Photos/<device>/`.
//!
//! The Shortcut holds a **photo backup token**, a device token with
//! [`Access::Photos`](hd_store::model::Access). It works only on the two
//! endpoints here, and only for its own folder, named by the device; the
//! sync API, WebDAV and the web pages refuse it. A lost phone or a shared
//! Shortcut can add photos, and nothing else.
//!
//! - `GET /api/v1/photos/have?sha256=<hex>` answers `{"have": true}` when a
//!   current version under `Photos/` holds exactly that content.
//! - `POST /api/v1/photos/upload`, the file as the body, with `X-File-Name`
//!   and optionally `X-Taken` (RFC 3339, or seconds since 1970) and
//!   `X-SHA256` (the hash the phone computed), answers
//!   `{"path", "status"}`: `uploaded`, `copy` (kept beside a different photo
//!   with the same name; phones reuse names) or `unchanged`.
//!
//! The body streams into the store, which hashes it as it arrives. Every
//! upload commits with base "absent", so a photo never becomes a version of
//! another photo, and nothing here replaces, moves or deletes. A hash that
//! differs from the phone's is reported as a failure, so the Shortcut never
//! counts a photo as backed up unless the drive holds the bytes the phone
//! hashed.

use std::fmt::Write as _;

use hd_api::{J, s};
use hd_common::{pathname, timefmt};
use hd_http::{Method, Request, Response};
use hd_store::model::{Node, Origin};
use hd_store::{Base, Provenance};

use crate::App;
use crate::api::{error, json};
use crate::auth::Who;
use crate::html::{self, Tone, esc};
use crate::web::Session;

/// The folder photos go under, one subfolder per device.
pub const ROOT: &str = "Photos";
/// The longest device name.
pub const MAX_DEVICE: usize = 64;

/// The folder for `device`, or why the name cannot be used. It must be one
/// folder name that every client can make.
pub fn device_folder(device: &str) -> Result<String, String> {
    if device.trim() != device {
        return Err("a device name cannot start or end with a space".into());
    }
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
    let name = name.trim();
    if name.is_empty() || name.contains('/') || name.chars().any(char::is_control) {
        return Err("X-File-Name must be one file name".into());
    }
    pathname::validate(name).map_err(|e| e.message().to_owned())?;
    Ok(name)
}

/// A SHA-256 in hex, either case (the Shortcuts app writes lowercase, but
/// nothing promises it).
fn sha256_hex(text: &str) -> Option<[u8; 32]> {
    let text = text.trim().as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (i, pair) in text.chunks(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// When the photo was taken, in milliseconds: RFC 3339 (what the
/// Shortcuts app's ISO 8601 date format gives) or seconds since 1970. A
/// time the photo cannot have is `None`.
fn taken_ms(text: &str, now_ms: i64) -> Option<i64> {
    let text = text.trim();
    let ms = if let Ok(secs) = text.parse::<i64>() {
        secs.checked_mul(1000)?
    } else {
        let (secs, nanos) = timefmt::parse_rfc3339(text)?;
        secs.checked_mul(1000)?.checked_add(i64::from(nanos / 1_000_000))?
    };
    (ms > 0 && ms <= now_ms.saturating_add(86_400_000)).then_some(ms)
}

impl App {
    /// `GET /photos`, and the answer to making a token, which is shown once.
    pub(crate) fn photos_page(
        &self,
        s: &Session,
        origin: &str,
        made: Option<(&str, &str)>,
        flashes: Vec<(Tone, String)>,
    ) -> Response<'static> {
        let csrf = self.csrf(s);
        let have = format!("{origin}/api/v1/photos/have?sha256=");
        let upload = format!("{origin}/api/v1/photos/upload");
        let mut b = String::from(
            "<h1>Photos</h1>\n<p class=\"page-intro\">Back up an iPhone's photos and videos with \
             a Shortcut in Apple's Shortcuts app. It uploads what was added since it last \
             ran into <strong>Photos/</strong> and a folder named for the phone, and can run \
             by itself, for example every night while the phone charges.</p>\n",
        );
        if let Some((name, token)) = made {
            let _ = writeln!(
                b,
                "<section class=\"card\"><h2>Token for {}</h2><p class=\"field-help\">Copy it \
                 into the Shortcut now; it is not shown again. It can only add photos to \
                 {ROOT}/{}: it cannot read, change or delete anything.</p>\
                 <p class=\"setup-token\"><code>{}</code></p></section>",
                esc(name),
                esc(name),
                esc(token)
            );
        }
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>1. Make a token for the phone</h2>\
             <form method=\"POST\" action=\"/photos\">{csrf}{}\
             <button type=\"submit\" class=\"button\">Create photo backup token</button></form>\
             <p class=\"field-help\">Revoke it on <a href=\"/devices\">Devices</a> if the phone \
             is lost.</p></section>",
            html::field(
                "name",
                "Phone name",
                "text",
                "iPhone",
                "Photos go into Photos/ and this name. Use a different name for each phone.",
                true
            ),
        );
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>2. Build the Shortcut</h2>\
             <p>On the iPhone, open <strong>Shortcuts</strong>, tap <strong>+</strong>, and add \
             these actions in order (search for each by name). Words in <em>italics</em> are \
             variables: tap the field and pick them.</p><ol class=\"steps\">\
             <li><strong>Text</strong>: paste the token. Rename the result <em>Token</em>.</li>\
             <li><strong>Get File</strong> from the Shortcuts folder, path \
             <code>homedrive-last-run.txt</code>, with <em>Error If Not Found</em> off. Then \
             <strong>Get Dates from Input</strong> on it. Rename the result <em>Last run</em>.</li>\
             <li><strong>Date</strong> (Current Date). Rename it <em>Started</em>.</li>\
             <li><strong>Find Photos</strong>: tap <em>Add Filter</em>, choose \
             <em>Date Added</em> <em>is after</em> <em>Last run</em>; sort by \
             <em>Date Added</em>, <em>Oldest First</em>. (On the first run there is no last \
             run, so every photo is found; that first run can take hours.)</li>\
             <li><strong>Repeat with Each</strong> item in <em>Photos</em>, and inside it:\
             <ol>\
             <li><strong>Generate Hash</strong>: SHA256 of <em>Repeat Item</em>.</li>\
             <li><strong>Get Contents of URL</strong>: <code>{}</code> followed by the \
             <em>Hash</em>. Method GET, header <code>Authorization</code> = <code>Bearer </code> \
             followed by <em>Token</em>.</li>\
             <li><strong>Get Dictionary Value</strong> <code>have</code> from it, then \
             <strong>If</strong> it <em>is</em> <code>0</code> (false):\
             <ol><li><strong>Get Contents of URL</strong>: <code>{}</code>, method POST, \
             request body <em>File</em> = <em>Repeat Item</em>, headers \
             <code>Authorization</code> = <code>Bearer </code><em>Token</em>, \
             <code>X-File-Name</code> = <em>Repeat Item</em>'s <em>Name</em>, a dot, and its \
             <em>File Extension</em>, <code>X-Taken</code> = <em>Repeat Item</em>'s \
             <em>Creation Date</em> formatted as ISO 8601 with time, and <code>X-SHA256</code> = \
             <em>Hash</em>.</li>\
             <li><strong>Get Dictionary Value</strong> <code>status</code> from it. \
             <strong>If</strong> it is not <code>uploaded</code>, <code>copy</code> or \
             <code>unchanged</code>: <strong>Show Alert</strong> with the reply, then \
             <strong>Stop This Shortcut</strong>.</li></ol></li></ol></li>\
             <li>After <strong>End Repeat</strong>: <strong>Save File</strong> <em>Started</em> \
             (as text) to the Shortcuts folder as <code>homedrive-last-run.txt</code>, with \
             <em>Overwrite If File Exists</em> on.</li></ol>\
             <p>The last step runs only when every photo was backed up, so after a failure or \
             a lost connection the next run tries the same photos again; the ones already in \
             the drive are skipped by their hash.</p></section>",
            esc(&have),
            esc(&upload),
        );
        b.push_str(
            "<section class=\"card\"><h2>3. Run it by itself</h2><p>In Shortcuts, open \
             <strong>Automation</strong>, tap <strong>+</strong>, and pick \
             <strong>Charger</strong> (<em>Is Connected</em>) or a <strong>Time of Day</strong>, \
             then <em>Run Immediately</em> and this Shortcut. Keep the phone on Wi-Fi: each \
             video goes up in one request, and a long one needs a fast connection.</p>\
             </section>\n\
             <section class=\"card\"><h2>Freeing space on the phone</h2><p>Nothing the \
             Shortcut sends can replace or delete anything in the drive, and deleting photos \
             from the phone afterwards changes nothing here. Delete from the phone only photos \
             added before the last run that finished without an alert.</p><p>The phone may \
             send a converted copy, such as a JPEG for a HEIC photo, or a Live Photo's still \
             image only. Before deleting originals, open a few in \
             <a href=\"/files?path=Photos\">Files</a> to check they are what you expect.</p>\
             </section>\n",
        );
        self.page_with(s, "Photos", "photos", flashes, b)
    }

    /// `/api/v1/photos/...`, for a photo backup token only.
    pub(crate) fn photos_api(
        &self,
        req: &mut Request<'_, '_>,
        who: &Who,
        route: &str,
    ) -> Response<'static> {
        let Some((_, device)) = who.device.as_ref().filter(|_| who.photos_only()) else {
            return error(403, "these endpoints take a photo backup token; make one on /photos");
        };
        let folder = match device_folder(device) {
            Ok(f) => f,
            Err(why) => return error(403, &why),
        };
        match (req.method, route) {
            (Method::Get | Method::Head, "photos/have") => self.photos_have(req, &who.user),
            (Method::Post, "photos/upload") => self.photos_upload(req, who, &folder),
            (_, "photos/have" | "photos/upload") => error(405, "Method Not Allowed"),
            _ => error(404, "Not Found"),
        }
    }

    /// `GET /api/v1/photos/have?sha256=`: whether a current version under
    /// `Photos/` (any phone's folder) holds exactly that content.
    fn photos_have(&self, req: &Request<'_, '_>, user: &str) -> Response<'static> {
        let Some(sha) = req.query_value("sha256").and_then(sha256_hex) else {
            return error(400, "sha256 must be 64 hex digits");
        };
        let have = self.store.read(|st| {
            st.user(user).is_some_and(|ns| {
                ns.subtree(ROOT).any(|(_, e)| match &e.node {
                    Node::File { versions, .. } => versions.last().is_some_and(|v| v.sha256 == sha),
                    Node::Dir => false,
                })
            })
        });
        json(200, &J::O(vec![("have", J::Bool(have))]))
    }

    /// `POST /api/v1/photos/upload`: the body is the photo.
    fn photos_upload(
        &self,
        req: &mut Request<'_, '_>,
        who: &Who,
        folder: &str,
    ) -> Response<'static> {
        let user = who.user.as_str();
        let name = match file_name(req.header("x-file-name").unwrap_or("")) {
            Ok(n) => n.to_owned(),
            Err(why) => return error(400, &why),
        };
        let expected = match req.header("x-sha256") {
            None => None,
            Some(v) => match sha256_hex(v) {
                Some(h) => Some(h),
                None => return error(400, "X-SHA256 must be 64 hex digits"),
            },
        };
        let now = timefmt::unix_ms();
        let mtime_ms = req.header("x-taken").and_then(|t| taken_ms(t, now)).unwrap_or(now);
        let max = self.config.max_file;
        let declared = req.body().declared_len();
        if declared.is_some_and(|n| n > max) {
            return error(413, "the file is larger than the server accepts");
        }
        if let Some(why) = self.over_quota(user, declared.unwrap_or(0)) {
            return error(507, &why);
        }
        let provenance = Provenance {
            device: who.device_name(),
            mtime_ms,
            origin: Origin::Upload,
            created_ms: None,
            executable: Some(false),
        };
        let path = pathname::join(folder, &name);
        // A body of unknown length stops at the quota, never past it.
        let limit = self.write_limit(user);
        let body = req.body();
        let mut limited = std::io::Read::take(body, max.min(limit).saturating_add(1));
        let result = self.store.write_file(
            user,
            &path,
            Base::Absent,
            &mut limited as &mut dyn std::io::Read,
            max.min(limit),
            &provenance,
        );
        let c = match result {
            Ok(c) => c,
            Err(e) if e.message().contains("larger than the size limit") && limit < max => {
                let mut r = error(507, &self.quota_message(user));
                r.close = true;
                return r;
            }
            Err(e) if e.message().contains("larger than the size limit") => {
                let mut r = error(413, "the file is larger than the server accepts");
                r.close = true;
                return r;
            }
            Err(e) => {
                let mut r = self.op_error(&e);
                // The body may be half read: do not reuse the connection.
                r.close = true;
                return r;
            }
        };
        let stored = self.store.read(|st| {
            st.user(user).and_then(|ns| ns.get(&c.path)).and_then(|e| match &e.node {
                Node::File { versions, .. } => {
                    versions.iter().find(|v| v.id == c.version).map(|v| (v.sha256, v.size))
                }
                Node::Dir => None,
            })
        });
        let Some((sha256, size)) = stored else {
            return error(500, "the upload was stored but cannot be found");
        };
        self.note_commit(user, size);
        if expected.is_some_and(|e| e != sha256) {
            // Kept, since nothing here deletes, but not counted as backed up.
            return json(
                422,
                &J::O(vec![
                    ("path", s(c.path)),
                    ("status", s("mismatch")),
                    (
                        "error",
                        s("the drive received different bytes than the phone hashed; run the \
                           Shortcut again"),
                    ),
                ]),
            );
        }
        let status = if c.unchanged {
            "unchanged"
        } else if c.conflict {
            "copy"
        } else {
            "uploaded"
        };
        json(200, &J::O(vec![("path", s(c.path)), ("status", s(status))]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names() {
        assert_eq!(device_folder("iPhone").unwrap(), "Photos/iPhone");
        assert_eq!(device_folder("Matt's iPhone 15").unwrap(), "Photos/Matt's iPhone 15");
        for bad in ["", " iPhone", "iPhone ", "a/b", "..", ".", "con", "x\u{0}", "a\nb"] {
            assert!(device_folder(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(device_folder(&"x".repeat(65)).is_err());
    }

    #[test]
    fn hashes_and_times() {
        let lower = "ab".repeat(32);
        assert_eq!(sha256_hex(&lower), Some([0xab; 32]));
        assert_eq!(sha256_hex(&"AB".repeat(32)), Some([0xab; 32]));
        assert_eq!(sha256_hex(&"ab".repeat(31)), None);
        assert_eq!(sha256_hex(&format!("{}zz", "ab".repeat(31))), None);
        let now = 1_800_000_000_000;
        assert_eq!(taken_ms("2026-11-27T10:15:30-05:00", now), Some(1_795_792_530_000));
        assert_eq!(taken_ms("2026-11-27T15:15:30Z", now), Some(1_795_792_530_000));
        assert_eq!(taken_ms("1795792530", now), Some(1_795_792_530_000));
        assert_eq!(taken_ms("0", now), None);
        assert_eq!(taken_ms("27 Nov 2026", now), None);
        assert_eq!(taken_ms("1900000000", now), None);
    }
}
