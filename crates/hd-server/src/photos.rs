//! Photo backup from an iPhone, through a Shortcut in Apple's Shortcuts
//! app. `/photos` makes the Shortcut's token and shows a prompt, with the
//! server's address and the token filled in, that Siri turns into the
//! Shortcut.
//!
//! The Shortcut goes through every photo on the phone, oldest first, and
//! for each asks the server whether it has it, then uploads it if not.
//! There is no date filter: the Shortcuts app can filter only by when a
//! photo was taken, so a photo saved today with an old date would slip
//! past one. Asking about every photo costs one small request each.
//!
//! The Shortcut holds a **photo backup token**, a device token with
//! [`Access::Photos`](hd_store::model::Access). It works only on the two
//! endpoints here, and only for its own folder, named by the device; the
//! sync API, WebDAV and the web pages refuse it. A lost phone or a shared
//! Shortcut can add photos, and nothing else.
//!
//! - `GET /api/v1/photos/have`, with `X-Name` (the photo's name, with or
//!   without its extension) and `X-Created` (when it was taken: RFC 3339,
//!   which is the Shortcuts app's ISO 8601, or seconds since 1970),
//!   answers the text `yes` when this phone's folder holds a photo of that
//!   name taken at that second, and `no` otherwise. The Shortcut uploads on
//!   any answer but `yes`, so a misconfigured Shortcut sends photos rather
//!   than skipping them.
//! - `POST /api/v1/photos/upload`, a form with the photo in a file field
//!   named `file`, and `X-Created`, answers `uploaded`, `copy` (kept beside
//!   a different photo with the same name; phones reuse names) or
//!   `unchanged`.
//!
//! The photo streams into the store, which hashes it as it arrives. Every
//! upload commits with base "absent", so a photo never becomes a version of
//! another photo, and nothing here replaces, moves or deletes. A photo is
//! matched by name and time only, so one edited on the phone after its
//! backup is not sent again; the original stays in the drive.
//!
//! A Shortcut shows nobody the server's answers, so the last problem each
//! photo token met is kept in memory and shown on `/photos`.

use std::fmt::Write as _;

use hd_common::{pathname, timefmt};
use hd_http::{Method, Request, Response};
use hd_store::model::{Access, Node, Origin};
use hd_store::{Base, Provenance};

use crate::App;
use crate::auth::Who;
use crate::html::{self, Tone, esc};
use crate::multipart::{self, Multipart};
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
        return Err(format!("{name:?} is not one file name"));
    }
    pathname::validate(name).map_err(|e| e.message().to_owned())?;
    Ok(name)
}

/// A name without its extension: `IMG_0001.HEIC` and `IMG_0001` are the
/// same photo's name.
fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// Whether `file`, a name in the photo folder, is the photo named `name`:
/// the same stem, or a copy the store kept beside another photo with that
/// name (`IMG_0001 (conflict ...).HEIC`).
fn same_photo(file: &str, name: &str) -> bool {
    let (file, name) = (stem(file), stem(name));
    file == name || file.strip_prefix(name).is_some_and(|rest| rest.starts_with(" (conflict "))
}

/// When the photo was taken, in whole seconds: RFC 3339 (the Shortcuts
/// app's ISO 8601 format) or seconds since 1970. A time the photo cannot
/// have is `None`.
fn created_secs(text: &str, now_ms: i64) -> Option<i64> {
    let text = text.trim();
    let secs = match text.parse::<i64>() {
        Ok(secs) => secs,
        Err(_) => timefmt::parse_rfc3339(text)?.0,
    };
    (secs > 0 && secs.saturating_mul(1000) <= now_ms.saturating_add(86_400_000)).then_some(secs)
}

/// The words standing in for the token in the Siri prompt. The token is
/// pasted into the built Shortcut instead, so it never goes to Siri.
pub const TOKEN_PLACEHOLDER: &str = "PASTE-TOKEN-HERE";

/// The Siri prompt, with this server's addresses filled in and
/// [`TOKEN_PLACEHOLDER`] where the token goes.
pub fn siri_prompt(origin: &str) -> String {
    let token = TOKEN_PLACEHOLDER;
    format!(
        "Create a shortcut named \"Back up photos to homedrive\" that runs when the \
iPhone is connected to power, without asking. It must do exactly this:

1. Find Photos. Add no filters at all. Sort by Date Created, Oldest First. \
Limit off.

2. Repeat with each item in the Photos from step 1. Inside the repeat:

   a. Get Contents of URL
      - URL: {origin}/api/v1/photos/have
      - Method: GET
      - Headers:
        - Authorization: Bearer {token}
        - X-Name: the Repeat Item's Name
        - X-Created: the Repeat Item's Date Created, formatted as ISO 8601 \
with the time included
      The reply is the plain text \"yes\" or \"no\".

   b. If the Contents of URL from step 2a is not \"yes\":

      c. Get Contents of URL
         - URL: {origin}/api/v1/photos/upload
         - Method: POST
         - Headers:
           - Authorization: Bearer {token}
           - X-Name: the Repeat Item's Name
           - X-Created: the Repeat Item's Date Created, formatted as ISO 8601 \
with the time included
         - Request Body: Form, with one field of type File, key \"file\", \
value the Repeat Item

      End If.

   End Repeat.

Do not add any other filters, actions or conditions. Keep the \
Authorization headers exactly as written: the token is filled in later."
    )
}

/// What `/photos` reports for one photo backup token.
struct PhoneStatus {
    name: String,
    photos: usize,
    last_ms: Option<i64>,
    problem: Option<(i64, String)>,
}

impl App {
    /// Notes the problem a photo token's request met, for `/photos`.
    fn photo_problem(&self, device_id: u64, why: &str) {
        let mut p = self.photo_problems.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        p.insert(device_id, (timefmt::unix_ms(), why.to_owned()));
    }

    fn photo_ok(&self, device_id: u64) {
        let mut p = self.photo_problems.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        p.remove(&device_id);
    }

    fn phone_statuses(&self, user: &str) -> Vec<PhoneStatus> {
        let phones = self.store.read(|st| {
            let Some(ns) = st.user(user) else {
                return Vec::new();
            };
            ns.devices
                .values()
                .filter(|d| d.access == Access::Photos)
                .map(|d| {
                    let folder = format!("{ROOT}/{}", d.name);
                    let mut photos = 0;
                    let mut last_ms = None::<i64>;
                    for (_, e) in ns.subtree(&folder) {
                        if let Node::File { versions, .. } = &e.node
                            && let Some(v) = versions.last()
                        {
                            photos += 1;
                            last_ms = Some(last_ms.map_or(v.created_ms, |l| l.max(v.created_ms)));
                        }
                    }
                    (d.id, PhoneStatus { name: d.name.clone(), photos, last_ms, problem: None })
                })
                .collect::<Vec<_>>()
        });
        let problems =
            self.photo_problems.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        phones
            .into_iter()
            .map(|(id, mut status)| {
                status.problem = problems.get(&id).cloned();
                status
            })
            .collect()
    }

    /// `GET /photos`, and the answer to making a token, which shows the
    /// token once.
    pub(crate) fn photos_page(
        &self,
        s: &Session,
        origin: &str,
        made: Option<(&str, &str)>,
        flashes: Vec<(Tone, String)>,
    ) -> Response<'static> {
        let csrf = self.csrf(s);
        let mut b = String::from(
            "<h1>Photos</h1>\n<p class=\"page-intro\">Back up an iPhone's photos and videos \
             with a Shortcut that Siri builds for you. It runs whenever the phone is \
             charging, sends only photos the drive does not have, and puts them in \
             <strong>Photos/</strong> and a folder named for the phone. Do these steps on \
             the iPhone.</p>\n",
        );
        if let Some((name, token)) = made {
            let _ = writeln!(
                b,
                "<section class=\"card\"><h2>Token for {}</h2><p>Keep this page open: \
                 you paste this token into the Shortcut in step 3, and it is not shown again. \
                 Copy it when you get there: tap the box, then <strong>Select All</strong> \
                 and <strong>Copy</strong>.</p>\
                 <input type=\"text\" class=\"setup-token\" readonly value=\"{}\" \
                 aria-label=\"The token\"></section>",
                esc(name),
                esc(token)
            );
        }
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>1. Make a token for the phone</h2>\
             <form method=\"POST\" action=\"/photos\">{csrf}{}\
             <button type=\"submit\" class=\"button\">Create photo backup token</button></form>\
             <p class=\"field-help\">The token can only add photos to this phone's folder: it \
             cannot read, change or delete anything. Revoke it on <a href=\"/devices\">Devices</a> \
             if the phone is lost.</p></section>",
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
            "<section class=\"card\"><h2>2. Ask Siri to build the Shortcut</h2>\
             <ol class=\"steps\">\
             <li>Copy all the text in the box below: tap it, then <strong>Select All</strong> \
             and <strong>Copy</strong>. It does not hold your token.</li>\
             <li>Open the <strong>Shortcuts</strong> app, tap <strong>+</strong>, and paste \
             the text into the box at the bottom that asks what the Shortcut should do.</li>\
             <li>Check what Siri made: <em>Find Photos</em> has no filters (remove any, such \
             as an empty <em>Album</em> one), both <em>X-Created</em> headers say \
             <em>ISO 8601</em>, and there is an <em>If</em> around the second \
             <em>Get Contents of URL</em>.</li>\
             </ol><textarea class=\"siri-prompt\" readonly rows=\"24\" \
             aria-label=\"The Shortcut prompt\">{}</textarea></section>",
            esc(&siri_prompt(origin))
        );
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>3. Put the token in the Shortcut</h2>\
             <p>The Shortcut has two <em>Get Contents of URL</em> actions, and each has an \
             <em>Authorization</em> header that reads <code>Bearer {TOKEN_PLACEHOLDER}</code>. \
             In both:</p><ol class=\"steps\">\
             <li>Tap the arrow on the action to show its details, then open \
             <strong>Headers</strong>.</li>\
             <li>Tap the <em>Authorization</em> value, and delete \
             <code>{TOKEN_PLACEHOLDER}</code> only. Keep <code>Bearer</code> and the space \
             after it.</li>\
             <li>Paste the token from the top of this page after <code>Bearer </code>. The \
             value now reads <code>Bearer hd1_</code> followed by the rest of the token.</li>\
             </ol><p>The first action ends in <code>/photos/have</code>; the second, inside \
             the <em>If</em>, ends in <code>/photos/upload</code>. Miss either and the \
             Phones table below says the token was refused.</p></section>\n\
             <section class=\"card\"><h2>4. Start the first backup</h2><p>Plug the phone in \
             and tap the play button once. The first run goes through every photo and can \
             take hours; after that, the Shortcut runs by itself whenever the phone is \
             charging and sends only new photos. Check the Phones table below to see it \
             working.</p></section>"
        );
        let phones = self.phone_statuses(&s.user);
        if !phones.is_empty() {
            b.push_str(
                "<section class=\"card\"><h2>Phones</h2><div class=\"table-wrap\">\
                 <table class=\"data-table\"><thead><tr><th>Phone</th><th>Photos in the drive\
                 </th><th>Last photo received</th><th>Last problem</th></tr></thead><tbody>\n",
            );
            for p in phones {
                let last = p.last_ms.map_or_else(|| "none yet".to_owned(), when);
                let problem = p
                    .problem
                    .map_or_else(String::new, |(at, why)| format!("{}: {}", when(at), esc(&why)));
                let _ = writeln!(
                    b,
                    "<tr><td>{}</td><td>{}</td><td>{last}</td><td>{problem}</td></tr>",
                    esc(&p.name),
                    p.photos
                );
            }
            b.push_str("</tbody></table></div></section>\n");
        }
        b.push_str(
            "<section class=\"card\"><h2>Freeing space on the phone</h2><p>Nothing the \
             Shortcut sends can replace or delete anything in the drive, and deleting photos \
             from the phone afterwards changes nothing here. Once the table above shows as \
             many photos as the phone has, and no problem, the phone's photos are in the \
             drive.</p><p>The phone may send a converted copy, such as a JPEG for a HEIC \
             photo. Before deleting originals, open a few in \
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
        let Some((device_id, device)) = who.device.as_ref().filter(|_| who.photos_only()) else {
            return Response::text(
                403,
                "these addresses take a photo backup token; make one on /photos",
            );
        };
        let folder = match device_folder(device) {
            Ok(f) => f,
            Err(why) => return Response::text(403, &why),
        };
        let r = match (req.method, route) {
            (Method::Get | Method::Head, "photos/have") => {
                self.photos_have(req, &who.user, &folder)
            }
            (Method::Post, "photos/upload") => self.photos_upload(req, who, &folder),
            (_, "photos/have" | "photos/upload") => {
                return Response::text(405, "Method Not Allowed");
            }
            _ => return Response::text(404, "Not Found"),
        };
        match r {
            Ok(r) => {
                self.photo_ok(*device_id);
                r
            }
            Err((status, why)) => {
                self.photo_problem(*device_id, &why);
                let mut r = Response::text(status, &why);
                if status != 400 {
                    // The body may be half read: do not reuse the connection.
                    r.close = true;
                }
                r
            }
        }
    }

    /// `GET /api/v1/photos/have`: `yes` when this phone's folder holds a
    /// photo with that name, taken at that second.
    fn photos_have(
        &self,
        req: &Request<'_, '_>,
        user: &str,
        folder: &str,
    ) -> Result<Response<'static>, (u16, String)> {
        let name = req.header("x-name").map_or("", str::trim);
        if name.is_empty() {
            return Err((400, "X-Name is missing: set it to the Repeat Item's Name".into()));
        }
        let created = created(req)?;
        let have = self.store.read(|st| {
            st.user(user).is_some_and(|ns| {
                ns.subtree(folder).any(|(path, e)| match &e.node {
                    Node::File { versions, .. } => versions.last().is_some_and(|v| {
                        v.mtime_ms.div_euclid(1000) == created
                            && same_photo(pathname::name(path), name)
                    }),
                    Node::Dir => false,
                })
            })
        });
        Ok(Response::text(200, if have { "yes" } else { "no" }))
    }

    /// `POST /api/v1/photos/upload`: a form whose `file` field is the photo.
    fn photos_upload(
        &self,
        req: &mut Request<'_, '_>,
        who: &Who,
        folder: &str,
    ) -> Result<Response<'static>, (u16, String)> {
        let user = who.user.as_str();
        let created = created(req)?;
        let fallback = req.header("x-name").map_or("", str::trim).to_owned();
        let Some(boundary) = req.header("content-type").and_then(multipart::boundary) else {
            return Err((
                415,
                "the photo must be sent as a form: set Request Body to Form, with a File \
                 field named file"
                    .into(),
            ));
        };
        let max = self.config.max_file;
        if req.body().declared_len().is_some_and(|n| n > max) {
            return Err((413, "the photo is larger than the server accepts".into()));
        }
        if let Some(why) = self.over_quota(user, 0) {
            return Err((507, why));
        }
        let provenance = Provenance {
            device: who.device_name(),
            mtime_ms: created.saturating_mul(1000),
            origin: Origin::Upload,
            created_ms: None,
            executable: Some(false),
        };
        let limit = max.min(self.write_limit(user));
        let body = req.body();
        let mut parts = Multipart::new(body, &boundary);
        loop {
            let part = match parts.next_part() {
                Ok(Some(p)) => p,
                Ok(None) => {
                    return Err((400, "the form has no File field named file".into()));
                }
                Err(e) => return Err((400, format!("the form could not be read: {e}"))),
            };
            if part.name != "file" {
                if let Err(e) = parts.text(64 * 1024) {
                    return Err((400, format!("the form could not be read: {e}")));
                }
                continue;
            }
            let sent = part.filename.filter(|f| !f.trim().is_empty()).unwrap_or(fallback);
            let name = file_name(&sent).map_err(|why| (400, why))?.to_owned();
            let path = pathname::join(folder, &name);
            let result = self.store.write_file(
                user,
                &path,
                Base::Absent,
                &mut parts as &mut dyn std::io::Read,
                limit,
                &provenance,
            );
            let c = match result {
                Ok(c) => c,
                Err(e) if e.message().contains("larger than the size limit") && limit < max => {
                    return Err((507, self.quota_message(user)));
                }
                Err(e) if e.message().contains("larger than the size limit") => {
                    return Err((413, "the photo is larger than the server accepts".into()));
                }
                Err(e) => return Err((500, format!("{name} was not stored: {}", e.message()))),
            };
            let size = self.store.read(|st| {
                st.user(user)
                    .and_then(|ns| ns.get(&c.path))
                    .and_then(|e| e.node.current().map(|v| v.size))
            });
            self.note_commit(user, size.unwrap_or(0));
            let status = if c.unchanged {
                "unchanged"
            } else if c.conflict {
                "copy"
            } else {
                "uploaded"
            };
            return Ok(Response::text(200, &format!("{status} {}", c.path)));
        }
    }
}

/// The `X-Created` header, in seconds.
fn created(req: &Request<'_, '_>) -> Result<i64, (u16, String)> {
    let Some(text) = req.header("x-created") else {
        return Err((400, "X-Created is missing: set it to the Repeat Item's Date Created".into()));
    };
    created_secs(text, timefmt::unix_ms()).ok_or_else(|| {
        (
            400,
            format!(
                "X-Created is not a date homedrive can read ({:?}): format it as ISO 8601 \
                 with the time included",
                text.chars().take(40).collect::<String>()
            ),
        )
    })
}

/// A time for the page, in UTC.
fn when(ms: i64) -> String {
    let t = timefmt::rfc3339_millis(ms.div_euclid(1000), 0);
    format!("{} {} UTC", &t[..10], &t[11..16])
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
    fn names_and_times() {
        assert!(same_photo("IMG_0001.HEIC", "IMG_0001"));
        assert!(same_photo("IMG_0001.HEIC", "IMG_0001.HEIC"));
        assert!(same_photo("IMG_0001.JPG", "IMG_0001.HEIC"));
        assert!(same_photo("IMG_0001 (conflict iPhone 1 2026-11-27 10.15.30).HEIC", "IMG_0001"));
        assert!(!same_photo("IMG_00011.HEIC", "IMG_0001"));
        assert!(!same_photo("IMG_0001 (restored).HEIC", "IMG_0001"));
        let now = 1_800_000_000_000;
        assert_eq!(created_secs("2026-11-27T10:15:30-05:00", now), Some(1_795_792_530));
        assert_eq!(created_secs("2026-11-27T15:15:30Z", now), Some(1_795_792_530));
        assert_eq!(created_secs("1795792530", now), Some(1_795_792_530));
        assert_eq!(created_secs("0", now), None);
        assert_eq!(created_secs("27 Nov 2026 at 10:15", now), None);
        assert_eq!(created_secs("1900000000", now), None);
    }

    #[test]
    fn the_prompt_names_this_server_and_never_a_token() {
        let p = siri_prompt("https://drive.example.lan");
        assert!(p.contains("URL: https://drive.example.lan/api/v1/photos/have"));
        assert!(p.contains("URL: https://drive.example.lan/api/v1/photos/upload"));
        assert_eq!(p.matches("Authorization: Bearer PASTE-TOKEN-HERE").count(), 2);
        assert!(!p.contains("hd1_"));
        assert!(p.contains("is not \"yes\""));
        assert!(p.contains("Add no filters at all"));
    }
}
