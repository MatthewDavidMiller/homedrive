//! The WebDAV subset under `/dav/<user>/`, for rclone, file managers, and
//! phone apps.
//!
//! WebDAV is mapped onto the same journaled operations as the sync API,
//! so it keeps every guarantee:
//! - PUT adds a version (an overwrite keeps the old one);
//! - DELETE moves to the trash;
//! - MOVE and COPY with `Overwrite: T` trash what they replace;
//! - GET is verified as it is sent.
//!
//! | Method | Behaviour |
//! |---|---|
//! | OPTIONS | `DAV: 1, 2` |
//! | PROPFIND | Depth 0 or 1 (infinity is refused); a fixed set of properties |
//! | GET, HEAD | The current version, verified, with Range; a collection lists its names |
//! | PUT | A new version; `If-Match` / `If-None-Match: *` make it conditional (412); `X-OC-Mtime` sets the modification time |
//! | DELETE | To the trash |
//! | MKCOL | A collection; 409 without a parent, 405 if it exists |
//! | MOVE, COPY | Within the user's drive; `Overwrite: F` gives 412 instead of replacing |
//! | PROPPATCH | Accepted and ignored (Windows sets attributes this way) |
//! | LOCK, UNLOCK | Non-enforcing tokens, so Finder and Windows will write |

use std::fmt::Write as _;
use std::io::Read;

use hd_common::{pathname, timefmt};
use hd_http::{Method, Request, Response};
use hd_store::model::{Entry, Node, Op, Origin};
use hd_store::{Base, Provenance};

use crate::App;
use crate::auth::Who;

/// PROPFIND and PROPPATCH bodies are read (to keep the connection in step)
/// and otherwise ignored, up to this size.
const MAX_XML_BODY: usize = 256 * 1024;

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A content type by extension, for clients that show or open files.
fn content_type(path: &str) -> &'static str {
    let ext = pathname::name(path).rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    match ext.as_deref() {
        Some("txt" | "md" | "log" | "csv") => "text/plain; charset=utf-8",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("pdf") => "application/pdf",
        Some("json") => "application/json",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("svg") => "image/svg+xml",
        Some("mp3") => "audio/mpeg",
        Some("flac") => "audio/flac",
        Some("m4a") => "audio/mp4",
        Some("ogg" | "opus") => "audio/ogg",
        Some("mp4" | "m4v") => "video/mp4",
        Some("mov") => "video/quicktime",
        Some("mkv") => "video/x-matroska",
        Some("zip") => "application/zip",
        Some("gz" | "tgz") => "application/gzip",
        _ => "application/octet-stream",
    }
}

/// The drive path a `/dav/<user>/...` URL path names, decoded and
/// validated. `None` for anything that does not decode to a valid path:
/// a request is refused rather than pointed at some other file.
fn drive_path(rest: &str) -> Option<String> {
    let decoded = hd_http::percent_decode_bytes(rest.as_bytes(), false).ok()?;
    let trimmed = decoded.trim_matches('/');
    pathname::validate(trimmed).ok()?;
    Some(trimmed.to_owned())
}

fn href(user: &str, path: &str, dir: bool) -> String {
    let mut h = format!("/dav/{}/", hd_http::percent_encode(user));
    if !path.is_empty() {
        h.push_str(&hd_http::percent_encode_path(path));
        if dir {
            h.push('/');
        }
    }
    h
}

fn response_xml(out: &mut String, href: &str, entry: Option<&Entry>, path: &str) {
    let _ = write!(out, "<d:response><d:href>{}</d:href><d:propstat><d:prop>", xml_escape(href));
    let name = if path.is_empty() { "" } else { pathname::name(path) };
    let _ = write!(out, "<d:displayname>{}</d:displayname>", xml_escape(name));
    match entry.map(|e| (&e.node, e.changed)) {
        Some((Node::File { versions, .. }, _)) => {
            if let Some(v) = versions.last() {
                let modified = timefmt::http_date(v.mtime_ms.div_euclid(1000));
                let _ = write!(
                    out,
                    "<d:resourcetype/><d:getcontentlength>{}</d:getcontentlength>\
                     <d:getlastmodified>{modified}</d:getlastmodified>\
                     <d:getetag>\"v{}\"</d:getetag><d:getcontenttype>{}</d:getcontenttype>",
                    v.size,
                    v.id,
                    xml_escape(content_type(path))
                );
            }
        }
        Some((Node::Dir, changed)) => {
            let _ = write!(
                out,
                "<d:resourcetype><d:collection/></d:resourcetype><d:getetag>\"d{changed}\"</d:getetag>"
            );
        }
        None => out.push_str("<d:resourcetype><d:collection/></d:resourcetype>"),
    }
    out.push_str("</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>");
}

fn multistatus(body: String) -> Response<'static> {
    Response::new(207, "application/xml; charset=utf-8", body)
}

impl App {
    pub(crate) fn dav<'a>(
        &'a self,
        req: &mut Request<'_, '_>,
        who: &Who,
        rest: &str,
    ) -> Response<'a> {
        // /dav/<user>/<path>: the user segment must be the signed-in user.
        let (user_seg, path_part) = rest.split_once('/').unwrap_or((rest, ""));
        if hd_http::percent_decode(user_seg.as_bytes(), false) != who.user {
            return Response::text(403, "a WebDAV URL names the signed-in user's own drive");
        }
        let Some(path) = drive_path(path_part) else {
            return Response::text(400, "invalid path");
        };
        let user = who.user.as_str();
        match req.method {
            Method::Options => Response::empty(200)
                .with_header("DAV", "1, 2".into())
                .with_header("MS-Author-Via", "DAV".into())
                .with_header(
                    "Allow",
                    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"
                        .into(),
                ),
            Method::Propfind => self.propfind(req, user, &path),
            Method::Get | Method::Head => {
                let entry = self.store.read(|st| st.user(user).and_then(|ns| ns.get(&path)).cloned());
                match entry.map(|e| e.node) {
                    Some(Node::File { versions, .. }) => {
                        let last = versions.last().map(|v| (v.mtime_ms, v.id));
                        let mut r = self.serve_version(req, user, &path, None);
                        if r.status < 300 {
                            r.headers.retain(|(k, _)| k != "Content-Type");
                            r.headers.push(("Content-Type".into(), content_type(&path).into()));
                            if let Some((mtime, _)) = last {
                                r.headers.push((
                                    "Last-Modified".into(),
                                    timefmt::http_date(mtime.div_euclid(1000)),
                                ));
                            }
                        }
                        r
                    }
                    Some(Node::Dir) => self.dir_listing(user, &path),
                    None if path.is_empty() => self.dir_listing(user, &path),
                    None => Response::text(404, "Not Found"),
                }
            }
            Method::Put => self.put(req, who, &path),
            Method::Delete => {
                if path.is_empty() {
                    return Response::text(403, "the drive's root cannot be deleted");
                }
                if !self.exists(user, &path) {
                    return Response::text(404, "Not Found");
                }
                let op = Op::Trash { user: user.to_owned(), path, deleted_ms: timefmt::unix_ms() };
                match self.store.commit(&op) {
                    Ok(_) => Response::empty(204),
                    Err(e) => self.op_error(&e),
                }
            }
            Method::Mkcol => {
                if req.read_body(0).is_err() {
                    return Response::text(415, "MKCOL takes no body");
                }
                if path.is_empty() || self.exists(user, &path) {
                    return Response::text(405, "it already exists");
                }
                let parent = pathname::parent(&path);
                if !parent.is_empty() && !self.is_dir(user, parent) {
                    return Response::text(409, "the parent collection does not exist");
                }
                match self.store.commit(&Op::Mkdir { user: user.to_owned(), path }) {
                    Ok(_) => Response::empty(201),
                    Err(e) => self.op_error(&e),
                }
            }
            Method::Move | Method::Copy => self.move_or_copy(req, who, &path),
            Method::Proppatch => {
                let _ = req.read_body(MAX_XML_BODY);
                if !self.exists(user, &path) && !path.is_empty() {
                    return Response::text(404, "Not Found");
                }
                let mut out = String::from(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
                );
                let _ = write!(
                    out,
                    "<d:response><d:href>{}</d:href><d:propstat><d:prop/><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
                    xml_escape(&href(user, &path, self.is_dir(user, &path)))
                );
                multistatus(out)
            }
            Method::Lock => {
                let _ = req.read_body(MAX_XML_BODY);
                let token = format!(
                    "opaquelocktoken:{}",
                    hd_common::rand::random_hex(16).unwrap_or_else(|_| "0".repeat(32))
                );
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:prop xmlns:d=\"DAV:\"><d:lockdiscovery><d:activelock>\
                     <d:locktype><d:write/></d:locktype><d:lockscope><d:exclusive/></d:lockscope>\
                     <d:depth>0</d:depth><d:timeout>Second-3600</d:timeout>\
                     <d:locktoken><d:href>{token}</d:href></d:locktoken>\
                     <d:lockroot><d:href>{}</d:href></d:lockroot></d:activelock></d:lockdiscovery></d:prop>",
                    xml_escape(&href(user, &path, false))
                );
                Response::new(200, "application/xml; charset=utf-8", body)
                    .with_header("Lock-Token", format!("<{token}>"))
            }
            Method::Unlock => Response::empty(204),
            Method::Post => Response::text(405, "Method Not Allowed"),
        }
    }

    fn exists(&self, user: &str, path: &str) -> bool {
        self.store.read(|st| st.user(user).and_then(|ns| ns.get(path)).is_some())
    }

    fn is_dir(&self, user: &str, path: &str) -> bool {
        path.is_empty()
            || self.store.read(|st| {
                st.user(user).and_then(|ns| ns.get(path)).is_some_and(|e| e.node.is_dir())
            })
    }

    fn propfind(&self, req: &mut Request<'_, '_>, user: &str, path: &str) -> Response<'static> {
        if req.read_body(MAX_XML_BODY).is_err() {
            return Response::text(413, "the PROPFIND body is too large");
        }
        let depth = req.header("depth").unwrap_or("infinity").trim().to_ascii_lowercase();
        let children = match depth.as_str() {
            "0" => false,
            "1" => true,
            _ => {
                return Response::text(403, "Depth: infinity is not supported; use 0 or 1");
            }
        };
        let body = self.store.read(|st| {
            let ns = st.user(user);
            let entry = ns.and_then(|ns| ns.get(path));
            if !path.is_empty() && entry.is_none() {
                return None;
            }
            let mut out = String::from(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">",
            );
            let is_dir = path.is_empty() || entry.is_some_and(|e| e.node.is_dir());
            response_xml(&mut out, &href(user, path, is_dir), entry, path);
            if children
                && is_dir
                && let Some(ns) = ns
            {
                for (child, e) in ns.children(path) {
                    response_xml(&mut out, &href(user, child, e.node.is_dir()), Some(e), child);
                }
            }
            out.push_str("</d:multistatus>");
            Some(out)
        });
        match body {
            Some(b) => multistatus(b),
            None => Response::text(404, "Not Found"),
        }
    }

    fn dir_listing(&self, user: &str, path: &str) -> Response<'static> {
        let names = self.store.read(|st| {
            st.user(user).map_or_else(Vec::new, |ns| {
                ns.children(path)
                    .map(|(p, e)| {
                        let mut n = pathname::name(p).to_owned();
                        if e.node.is_dir() {
                            n.push('/');
                        }
                        n
                    })
                    .collect()
            })
        });
        let mut body = names.join("\n");
        body.push('\n');
        Response::text(200, &body)
    }

    fn put(&self, req: &mut Request<'_, '_>, who: &Who, path: &str) -> Response<'static> {
        let user = who.user.as_str();
        if path.is_empty() {
            return Response::text(405, "cannot PUT the root");
        }
        let current = self.store.read(|st| {
            st.user(user)
                .and_then(|ns| ns.get(path))
                .map(|e| (e.node.is_dir(), e.node.current().map(|v| v.id)))
        });
        if matches!(current, Some((true, _))) {
            return Response::text(405, "a collection exists at that path");
        }
        let current_id = current.and_then(|(_, id)| id);
        // Conditional requests: answered before any of the body is read.
        let mut base = Base::Any;
        if let Some(m) = req.header("if-match") {
            let m = m.trim();
            let wanted = m.trim_matches('"').strip_prefix('v').and_then(|v| v.parse::<u64>().ok());
            match (m == "*", wanted) {
                (true, _) if current_id.is_some() => {}
                (false, Some(v)) if current_id == Some(v) => base = Base::Version(v),
                _ => return Response::text(412, "Precondition Failed"),
            }
        }
        if req.header("if-none-match").is_some_and(|v| v.trim() == "*") {
            if current_id.is_some() {
                return Response::text(412, "Precondition Failed");
            }
            base = Base::Absent;
        }
        let mtime_ms = req
            .header("x-oc-mtime")
            .and_then(|v| v.trim().parse::<i64>().ok())
            .map_or_else(timefmt::unix_ms, |secs| secs.saturating_mul(1000));
        let sets_mtime = req.header("x-oc-mtime").is_some();
        let provenance = Provenance { device: who.device_name(), mtime_ms, origin: Origin::Upload };
        let max = self.config.max_file;
        if req.body().declared_len().is_some_and(|n| n > max) {
            return Response::text(413, "the file is larger than the server accepts");
        }
        let body = req.body();
        let mut limited = body.take(max.saturating_add(1));
        let result = self.store.write_file(
            user,
            path,
            base,
            &mut limited as &mut dyn Read,
            max,
            &provenance,
        );
        match result {
            Ok(c) if c.conflict => {
                // Only when the If-Match version was replaced while the body
                // arrived: the content is kept, beside the file.
                Response::text(412, &format!("the file changed; your copy was kept as {}", c.path))
            }
            Ok(c) => {
                let mut r = Response::empty(if current_id.is_some() { 204 } else { 201 })
                    .with_header("ETag", format!("\"v{}\"", c.version));
                if sets_mtime {
                    r = r.with_header("X-OC-MTime", "accepted".into());
                }
                r
            }
            Err(e) if e.message().contains("larger than the size limit") => {
                Response::text(413, "the file is larger than the server accepts")
            }
            Err(e) => {
                let mut r = self.op_error(&e);
                // The body may be half read: do not reuse the connection.
                r.close = true;
                r
            }
        }
    }

    fn move_or_copy(&self, req: &mut Request<'_, '_>, who: &Who, from: &str) -> Response<'static> {
        let user = who.user.as_str();
        let copy = req.method == Method::Copy;
        let Some(dest) = req.header("destination") else {
            return Response::text(400, "Destination is required");
        };
        // An absolute URL or a path; only the path matters, and it must be
        // inside the same user's drive.
        let dest_path = match dest.find("://") {
            Some(i) => dest[i + 3..].find('/').map_or("/", |j| &dest[i + 3 + j..]),
            None => dest,
        };
        let prefix = format!("/dav/{}/", hd_http::percent_encode(user));
        let raw = if let Some(r) = dest_path.strip_prefix(&prefix) {
            r
        } else if let Some(r) = dest_path.strip_prefix(&format!("/dav/{user}/")) {
            r
        } else {
            return Response::text(502, "the destination is not in your drive");
        };
        let Some(to) = drive_path(raw.split('?').next().unwrap_or(raw)) else {
            return Response::text(400, "invalid destination");
        };
        if from.is_empty() || to.is_empty() {
            return Response::text(403, "the root cannot be moved or copied");
        }
        if !self.exists(user, from) {
            return Response::text(404, "Not Found");
        }
        if from == to {
            return Response::text(403, "source and destination are the same");
        }
        let overwrite =
            !req.header("overwrite").is_some_and(|v| v.trim().eq_ignore_ascii_case("F"));
        let replaced = self.exists(user, &to);
        if replaced && !overwrite {
            return Response::text(412, "the destination exists");
        }
        let parent = pathname::parent(&to);
        if !parent.is_empty() && !self.is_dir(user, parent) {
            return Response::text(409, "the destination's parent does not exist");
        }
        let now = timefmt::unix_ms();
        // What is replaced goes to the trash first, so it stays recoverable.
        let mut trashed = None;
        if replaced {
            let op = Op::Trash { user: user.to_owned(), path: to.clone(), deleted_ms: now };
            match self.store.commit(&op) {
                Ok(a) => trashed = a.trash_id,
                Err(e) => return self.op_error(&e),
            }
        }
        let result = if copy {
            self.copy_tree(user, from, &to, now)
        } else {
            self.store
                .commit(&Op::Move { user: user.to_owned(), from: from.to_owned(), to: to.clone() })
                .map(|_| ())
        };
        match result {
            Ok(()) => Response::empty(if replaced { 204 } else { 201 }),
            Err(e) => {
                // Put back what was replaced, if nothing took its place.
                if let Some(id) = trashed
                    && !self.exists(user, &to)
                {
                    let _ =
                        self.store.commit(&Op::Restore { user: user.to_owned(), trash_id: id, to });
                }
                self.op_error(&e)
            }
        }
    }

    /// Copies a file, or a directory tree file by file.
    fn copy_tree(&self, user: &str, from: &str, to: &str, now: i64) -> hd_common::Result<()> {
        let items: Vec<(String, bool)> = self.store.read(|st| {
            st.user(user).map_or_else(Vec::new, |ns| {
                ns.subtree(from).map(|(p, e)| (p.clone(), e.node.is_dir())).collect()
            })
        });
        for (path, dir) in items {
            let Some(target) = pathname::rebase(&path, from, to) else { continue };
            let op = if dir {
                Op::Mkdir { user: user.to_owned(), path: target }
            } else {
                Op::Copy { user: user.to_owned(), from: path, to: target, created_ms: now }
            };
            self.store.commit(&op)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_decode_strictly() {
        assert_eq!(drive_path("a%20b/c.txt").as_deref(), Some("a b/c.txt"));
        assert_eq!(drive_path("dir/").as_deref(), Some("dir"));
        assert_eq!(drive_path("").as_deref(), Some(""));
        assert_eq!(drive_path("%C3%BC").as_deref(), Some("ü"));
        assert_eq!(drive_path("a/../b"), None);
        assert_eq!(drive_path("%2e%2e/x"), None);
        assert_eq!(drive_path("%ff"), None);
        assert_eq!(drive_path("a//b"), None);
        assert_eq!(href("alice", "a b/c", false), "/dav/alice/a%20b/c");
        assert_eq!(href("alice", "d", true), "/dav/alice/d/");
        assert_eq!(xml_escape("<a&'\">"), "&lt;a&amp;&apos;&quot;&gt;");
    }
}
