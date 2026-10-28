//! The web UI: plain HTML forms, no JavaScript, usable from a phone.
//!
//! | Page | What it does |
//! |---|---|
//! | `/files?path=` | Browse a folder: download, history, move, delete; upload and new folder |
//! | `/versions?path=` | A file's history: download any version, restore one as the newest |
//! | `/trash` | Deleted items: restore |
//! | `/rewind` (POST) | Preview, then put a folder back as it was some hours or days ago |
//! | `/devices` | Register a device (its token is shown once), revoke one |
//! | `/admin` | For admins: store health, space, maintenance, accounts |
//!
//! Every POST needs a session cookie, a CSRF token bound to it, and a
//! same-origin request (`Origin` matching `Host` when sent, and a
//! `Sec-Fetch-Site` that is not cross-site). Nothing here is destructive:
//! "delete" is the trash, "restore a version" adds a version, "rewind"
//! adds versions and restores from the trash, and "move" refuses to
//! replace anything.

use std::fmt::Write as _;
use std::time::Duration;

use hd_common::{pathname, timefmt};
use hd_http::{Method, Request, Response};
use hd_store::model::{Content, Node, Op, Origin};
use hd_store::{Base, Provenance};

use crate::App;
use crate::html::{self, Page, Tone, esc};
use crate::multipart::{self, Multipart};
use crate::session::{LOGIN_COOKIE, SESSION_COOKIE};

const STYLE: &str = include_str!("../static/style.css");
const FAVICON: &str = include_str!("../static/favicon.svg");
pub const SESSION_LIFETIME: Duration = Duration::from_hours(12);
const MAX_FORM: usize = 64 * 1024;

fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    let mut tenths = 0;
    while value >= 1024 && unit + 1 < UNITS.len() {
        tenths = (value % 1024) * 10 / 1024;
        value /= 1024;
        unit += 1;
    }
    if unit == 0 { format!("{value} B") } else { format!("{value}.{tenths} {}", UNITS[unit]) }
}

fn when(ms: i64) -> String {
    timefmt::rfc3339_millis(ms.div_euclid(1000), 0).replace('T', " ").replace(".000Z", " UTC")
}

fn q(s: &str) -> String {
    hd_http::percent_encode(s)
}

/// A signed-in browser session.
struct Session {
    id: String,
    user: String,
    admin: bool,
}

impl App {
    fn cookie(&self, name: &str, value: &str, max_age: u64) -> String {
        let secure = if self.config.secure_cookies { "; Secure" } else { "" };
        format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}")
    }

    fn web_session(&self, req: &Request<'_, '_>) -> Option<Session> {
        let id = req.cookie(SESSION_COOKIE)?;
        let user = self.sessions.user(id)?;
        let account = self.accounts.get(&user)?;
        Some(Session { id: id.to_owned(), user, admin: account.admin })
    }

    fn same_origin(req: &Request<'_, '_>) -> bool {
        if req.header("sec-fetch-site").is_some_and(|v| v == "cross-site" || v == "same-site") {
            return false;
        }
        match (req.header("origin"), req.header("host")) {
            (Some(origin), Some(host)) => {
                let authority = origin
                    .strip_prefix("https://")
                    .or_else(|| origin.strip_prefix("http://"))
                    .unwrap_or("");
                authority.eq_ignore_ascii_case(host)
            }
            (Some(_), None) => false,
            (None, _) => true,
        }
    }

    fn page(&self, s: &Session, title: &str, nav: &'static str, body: String) -> Response<'static> {
        self.page_with(s, title, nav, Vec::new(), body)
    }

    fn page_with(
        &self,
        s: &Session,
        title: &str,
        nav: &'static str,
        flashes: Vec<(Tone, String)>,
        body: String,
    ) -> Response<'static> {
        let page = Page {
            title: title.into(),
            nav,
            csrf: Some(self.sessions.csrf_token(&s.id)),
            admin: s.admin,
            flashes,
            body,
            ..Page::default()
        };
        Response::html(200, html::render(&page))
    }

    fn csrf(&self, s: &Session) -> String {
        html::csrf_field(&self.sessions.csrf_token(&s.id))
    }

    /// The web UI's routes. `None` means "not a web UI path".
    pub(crate) fn web<'a>(&'a self, req: &mut Request<'_, '_>) -> Option<Response<'a>> {
        let path = req.path.clone();
        let get = matches!(req.method, Method::Get | Method::Head);
        let post = req.method == Method::Post;
        Some(match path.as_str() {
            "/static/style.css" if get => Response::new(200, "text/css; charset=utf-8", STYLE)
                .with_header("Cache-Control", "max-age=3600".into()),
            "/static/favicon.svg" if get => Response::new(200, "image/svg+xml", FAVICON)
                .with_header("Cache-Control", "max-age=3600".into()),
            "/login" if get => self.login_form(None),
            "/login" if post => self.login_submit(req),
            "/" if get => match self.web_session(req) {
                Some(_) => Response::redirect("/files"),
                None => Response::redirect("/login"),
            },
            "/logout" | "/files" | "/download" | "/upload" | "/mkdir" | "/move" | "/delete"
            | "/versions" | "/restore-version" | "/trash" | "/restore" | "/devices"
            | "/devices/revoke" | "/rewind" | "/alerts/dismiss" | "/admin" => {
                let Some(s) = self.web_session(req) else {
                    return Some(if get {
                        Response::redirect("/login")
                    } else {
                        Response::text(403, "sign in first")
                    });
                };
                if post {
                    // Upload forms carry their token in the multipart body,
                    // checked there; every other form is checked here.
                    if !Self::same_origin(req) {
                        return Some(Response::text(403, "cross-site request refused"));
                    }
                    if path == "/upload" {
                        return Some(self.upload(req, &s));
                    }
                    let Ok(form) = req.read_form(MAX_FORM) else {
                        return Some(Response::text(413, "form too large"));
                    };
                    if !self.sessions.verify_csrf(&s.id, form.get("csrf_token").unwrap_or("")) {
                        return Some(Response::text(
                            403,
                            "the form expired; go back and try again",
                        ));
                    }
                    self.web_post(&path, &form, &s)
                } else if get {
                    match path.as_str() {
                        "/files" => {
                            self.files_page(&s, req.query_value("path").unwrap_or(""), Vec::new())
                        }
                        "/download" => self.web_download(req, &s),
                        "/versions" => self.versions_page(
                            &s,
                            req.query_value("path").unwrap_or(""),
                            Vec::new(),
                        ),
                        "/trash" => self.trash_page(&s, Vec::new()),
                        "/devices" => self.devices_page(&s, Vec::new()),
                        "/admin" if s.admin => self.admin_page(&s),
                        _ => Response::text(405, "Method Not Allowed"),
                    }
                } else {
                    Response::text(405, "Method Not Allowed")
                }
            }
            _ => return None,
        })
    }

    fn web_post(&self, path: &str, form: &hd_http::Form, s: &Session) -> Response<'static> {
        let user = s.user.as_str();
        let now = timefmt::unix_ms();
        match path {
            "/logout" => {
                self.sessions.end(&s.id);
                Response::redirect("/login")
                    .with_header("Set-Cookie", self.cookie(SESSION_COOKIE, "", 0))
            }
            "/mkdir" => {
                let dir = form.text("dir").to_owned();
                let name = form.text("name");
                let op = Op::Mkdir { user: user.into(), path: pathname::join(&dir, name) };
                let flash =
                    self.flash(self.store.commit(&op).map(|_| format!("Created folder {name}.")));
                self.files_page(s, &dir, vec![flash])
            }
            "/move" => {
                let from = form.text("path").to_owned();
                let to = form.text("to").trim_matches('/').to_owned();
                let dir = pathname::parent(&from).to_owned();
                let op = Op::Move { user: user.into(), from: from.clone(), to: to.clone() };
                let flash =
                    self.flash(self.store.commit(&op).map(|_| format!("Moved {from} to {to}.")));
                self.files_page(s, &dir, vec![flash])
            }
            "/delete" => {
                let target = form.text("path").to_owned();
                let dir = pathname::parent(&target).to_owned();
                let op = Op::Trash { user: user.into(), path: target.clone(), deleted_ms: now };
                let flash = self
                    .flash(self.store.commit(&op).map(|_| format!("Moved {target} to the trash.")));
                self.files_page(s, &dir, vec![flash])
            }
            "/rewind" => self.rewind_post(form, s),
            // Only a signed-in browser can dismiss an alert: a device token
            // (which ransomware on a computer could use) cannot.
            "/alerts/dismiss" => {
                let flash = self.flash(self.dismiss_alert(user).map(|()| {
                    "Dismissed. Retention resumes for your drive; new unusual activity raises a \
                     new alert."
                        .to_owned()
                }));
                self.files_page(s, "", vec![flash])
            }
            "/restore-version" => {
                let file = form.text("path").to_owned();
                let wanted = form.text("version").parse::<u64>().ok();
                let found = self.store.read(|st| {
                    match st.user(user).and_then(|ns| ns.get(&file)).map(|e| &e.node) {
                        Some(Node::File { versions, .. }) => {
                            versions.iter().find(|v| Some(v.id) == wanted).cloned()
                        }
                        _ => None,
                    }
                });
                let flash = match found {
                    None => (Tone::Danger, "That version no longer exists.".to_owned()),
                    Some(v) => {
                        let op = Op::PutVersion {
                            user: user.into(),
                            path: file.clone(),
                            content: Content {
                                manifest: v.manifest,
                                size: v.size,
                                sha256: v.sha256,
                                mtime_ms: v.mtime_ms,
                                created_ms: now,
                                device: "web".into(),
                                origin: Origin::Restore,
                            },
                        };
                        self.flash(self.store.commit(&op).map(|_| {
                            "Restored: that version is now the newest. Nothing was removed."
                                .to_owned()
                        }))
                    }
                };
                self.versions_page(s, &file, vec![flash])
            }
            "/restore" => {
                let id = form.text("trash_id").parse::<u64>().unwrap_or(0);
                let item = self.store.read(|st| {
                    st.user(user).and_then(|ns| ns.trash.get(&id)).map(|t| t.path.clone())
                });
                let flash = match item {
                    None => (Tone::Danger, "That item is no longer in the trash.".to_owned()),
                    Some(original) => {
                        let taken = self
                            .store
                            .read(|st| st.user(user).and_then(|ns| ns.get(&original)).is_some());
                        let to = if taken {
                            let t = timefmt::rfc3339_millis(now / 1000, 0);
                            pathname::suffixed_name(
                                &original,
                                &format!("restored {} {}{}", &t[..10], &t[11..13], &t[14..16]),
                            )
                        } else {
                            original
                        };
                        let op = Op::Restore { user: user.into(), trash_id: id, to: to.clone() };
                        self.flash(self.store.commit(&op).map(|_| format!("Restored to {to}.")))
                    }
                };
                self.trash_page(s, vec![flash])
            }
            "/devices" => {
                let name = form.text("name").to_owned();
                let mut flashes = Vec::new();
                let token = hd_crypto::random_array::<32>().ok().and_then(|secret| {
                    let hash = hd_crypto::sha256(&secret).ok()?;
                    let op = Op::DeviceAdd {
                        user: user.into(),
                        name: name.clone(),
                        token_hash: hash,
                        created_ms: now,
                    };
                    match self.store.commit(&op) {
                        Ok(a) => Some(hd_api::format_token(a.device_id.unwrap_or(0), &secret)),
                        Err(e) => {
                            flashes.push((Tone::Danger, e.message().to_owned()));
                            None
                        }
                    }
                });
                let mut r = self.devices_page(s, flashes);
                if let Some(t) = token
                    && let hd_http::ResponseBody::Bytes(b) = &mut r.body
                {
                    // Shown once, here, and never again.
                    let notice = format!(
                        "<section class=\"card\"><h2>Token for {}</h2><p class=\"field-help\">Copy it now; it is not shown again. Use it as the password for WebDAV and rclone, or in the sync client.</p><p class=\"setup-token\"><code>{}</code></p></section>\n",
                        esc(&name),
                        esc(&t)
                    );
                    let text = String::from_utf8_lossy(b).replacen(
                        "<h1>Devices</h1>",
                        &format!("<h1>Devices</h1>\n{notice}"),
                        1,
                    );
                    *b = text.into_bytes();
                }
                r
            }
            "/devices/revoke" => {
                let id = form.text("id").parse::<u64>().unwrap_or(0);
                let op = Op::DeviceRevoke { user: user.into(), device_id: id };
                let flash = self.flash(
                    self.store
                        .commit(&op)
                        .map(|_| "Revoked; that token no longer works.".to_owned()),
                );
                self.devices_page(s, vec![flash])
            }
            _ => Response::text(405, "Method Not Allowed"),
        }
    }

    fn flash(&self, r: hd_common::Result<String>) -> (Tone, String) {
        match r {
            Ok(m) => (Tone::Success, m),
            Err(e) if self.store.is_poisoned() => (
                Tone::Danger,
                format!("The store stopped accepting writes; the server needs a restart ({e})."),
            ),
            Err(e) => (Tone::Danger, e.message().to_owned()),
        }
    }

    fn login_form(&self, error: Option<&str>) -> Response<'static> {
        let Ok(nonce) = hd_common::rand::random_hex(16) else {
            return Response::text(500, "randomness unavailable");
        };
        let mut body = String::from(
            "<h1>Sign in</h1>\n<section class=\"card login-card\" aria-labelledby=\"login-heading\">\n<h2 id=\"login-heading\">homedrive</h2>\n",
        );
        if let Some(e) = error {
            let _ =
                writeln!(body, "<p class=\"notice notice-danger\" role=\"alert\">{}</p>", esc(e));
        }
        body.push_str("<form method=\"POST\" action=\"/login\">\n");
        body.push_str(&html::csrf_field(&self.sessions.login_token(&nonce)));
        body.push_str(
            "<div class=\"field\">\n<label for=\"username\">Username</label>\n\
             <input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" required autofocus>\n</div>\n\
             <div class=\"field\">\n<label for=\"password\">Password</label>\n\
             <input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" required>\n\
             </div>\n<button type=\"submit\" class=\"button\">Sign in</button>\n</form>\n</section>",
        );
        let page =
            Page { title: "Sign in".into(), page_class: " page-center", body, ..Page::default() };
        Response::html(if error.is_some() { 401 } else { 200 }, html::render(&page))
            .with_header("Set-Cookie", self.cookie(LOGIN_COOKIE, &nonce, 3600))
    }

    fn login_submit(&self, req: &mut Request<'_, '_>) -> Response<'static> {
        let Ok(form) = req.read_form(MAX_FORM) else {
            return Response::text(413, "form too large");
        };
        let nonce = req.cookie(LOGIN_COOKIE).unwrap_or("").to_owned();
        if !Self::same_origin(req)
            || !self.sessions.verify_login_token(&nonce, form.get("csrf_token").unwrap_or(""))
        {
            return self.login_form(Some("The sign-in form expired. Please try again."));
        }
        let ip = crate::auth::client_ip(req, &self.config.trusted_proxies);
        if self.throttle.blocked(ip) {
            let mut r = self.login_form(Some("Too many failed attempts. Try again later."));
            r.status = 429;
            return r;
        }
        let account = self
            .accounts
            .verify_password(form.text("username"), form.get("password").unwrap_or(""));
        let Some(account) = account else {
            self.throttle.fail(ip);
            eprintln!("hd-server: failed web sign-in from {ip}");
            return self.login_form(Some("Wrong username or password."));
        };
        match self.sessions.create(&account.name) {
            Ok(id) => Response::redirect("/files").with_header(
                "Set-Cookie",
                self.cookie(SESSION_COOKIE, &id, SESSION_LIFETIME.as_secs()),
            ),
            Err(_) => Response::text(500, "cannot start a session"),
        }
    }

    fn files_page(
        &self,
        s: &Session,
        dir: &str,
        flashes: Vec<(Tone, String)>,
    ) -> Response<'static> {
        let dir = dir.trim_matches('/');
        if pathname::validate(dir).is_err() {
            return Response::text(400, "invalid path");
        }
        let rows = self.store.read(|st| {
            let ns = st.user(&s.user)?;
            if !dir.is_empty() && !ns.get(dir).is_some_and(|e| e.node.is_dir()) {
                return None;
            }
            let mut dirs = Vec::new();
            let mut files = Vec::new();
            for (p, e) in ns.children(dir) {
                match &e.node {
                    Node::Dir => dirs.push(p.clone()),
                    Node::File { versions, .. } => {
                        if let Some(v) = versions.last() {
                            files.push((p.clone(), v.size, v.mtime_ms, versions.len()));
                        }
                    }
                }
            }
            Some((dirs, files))
        });
        let (dirs, files) = match rows {
            Some(r) => r,
            None if dir.is_empty() => (Vec::new(), Vec::new()),
            None => return Response::text(404, "no such folder"),
        };
        let csrf = self.csrf(s);
        let mut b = String::new();
        if let Some(a) = self.maintenance.snapshot().alerts.iter().find(|a| a.user == s.user) {
            let _ = writeln!(
                b,
                "<section class=\"card\"><h2>Unusual activity</h2><p><span class=\"notice notice-danger\">{}</span></p><form method=\"POST\" action=\"/alerts/dismiss\">{csrf}<button type=\"submit\" class=\"button button-secondary\">I have looked; dismiss</button></form></section>",
                esc(&crate::api::alert_text(a))
            );
        }
        let used = self.usage(&s.user);
        match self.accounts.get(&s.user).map(|a| a.quota) {
            Some(q) => {
                let full = self.over_quota(&s.user, 0).is_some();
                let _ = writeln!(
                    b,
                    "<p class=\"field-help\">{}Using {} of {} (old versions and the trash count).{}</p>",
                    if full { "<span class=\"notice notice-danger\">Full</span> " } else { "" },
                    crate::gib(used),
                    crate::gib(q),
                    if full {
                        " New files are refused; ask the administrator for more room."
                    } else {
                        ""
                    }
                );
            }
            None => {
                let _ = writeln!(
                    b,
                    "<p class=\"field-help\">Using {} (old versions and the trash count).</p>",
                    crate::gib(used)
                );
            }
        }
        // Breadcrumbs.
        b.push_str("<h1>Files</h1>\n<p class=\"page-intro\"><a href=\"/files\">My drive</a>");
        let mut acc = String::new();
        for part in dir.split('/').filter(|p| !p.is_empty()) {
            acc = pathname::join(&acc, part);
            let _ = write!(b, " / <a href=\"/files?path={}\">{}</a>", q(&acc), esc(part));
        }
        b.push_str("</p>\n");
        b.push_str("<section class=\"card\"><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr></thead><tbody>\n");
        if dirs.is_empty() && files.is_empty() {
            b.push_str(
                "<tr><td colspan=\"4\" class=\"empty-state\">This folder is empty.</td></tr>\n",
            );
        }
        for d in &dirs {
            let _ = writeln!(
                b,
                "<tr><td><a href=\"/files?path={}\">{}/</a></td><td></td><td></td><td>{}</td></tr>",
                q(d),
                esc(pathname::name(d)),
                Self::item_actions(&csrf, d)
            );
        }
        for (p, sz, mtime, n) in &files {
            let _ = writeln!(
                b,
                "<tr><td><a href=\"/download?path={qp}\">{name}</a></td><td>{}</td><td>{}</td><td><a href=\"/versions?path={qp}\">History ({n})</a> {}</td></tr>",
                size(*sz),
                when(*mtime),
                Self::item_actions(&csrf, p),
                qp = q(p),
                name = esc(pathname::name(p)),
            );
        }
        b.push_str("</tbody></table></div></section>\n");
        // Upload: the CSRF token and folder come before the files, so they
        // are checked before any file data is stored.
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>Upload</h2><form method=\"POST\" action=\"/upload\" enctype=\"multipart/form-data\">\n{csrf}<input type=\"hidden\" name=\"dir\" value=\"{}\">\n<div class=\"field\"><label for=\"files\">Files</label><input type=\"file\" id=\"files\" name=\"file\" multiple required></div>\n<button type=\"submit\" class=\"button\">Upload</button></form></section>",
            esc(dir)
        );
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>New folder</h2><form method=\"POST\" action=\"/mkdir\">\n{csrf}<input type=\"hidden\" name=\"dir\" value=\"{}\">\n{}<button type=\"submit\" class=\"button button-secondary\">Create</button></form></section>",
            esc(dir),
            html::field("name", "Name", "text", "", "", true)
        );
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>Rewind</h2><p class=\"field-help\">Undo everything that happened to this folder since a time: after ransomware, a sync gone wrong, or a mistake across many files. Changed files get their earlier content as a new version, and deleted items come back from the trash. Nothing is removed. You see a preview first.</p>\n{}</section>",
            Self::rewind_form(&csrf, dir, "", "hours", false)
        );
        self.page_with(s, "Files", "files", flashes, b)
    }

    /// The rewind form for `dir`, with a preview button, or with a button
    /// that carries the rewind out when `apply` is set.
    fn rewind_form(csrf: &str, dir: &str, amount: &str, unit: &str, apply: bool) -> String {
        let option = |value: &str, label: &str| {
            format!(
                "<option value=\"{value}\"{}>{label}</option>",
                if unit == value { " selected" } else { "" }
            )
        };
        let button = if apply {
            "<button type=\"submit\" name=\"apply\" value=\"1\" class=\"button button-danger\">Rewind now</button>"
        } else {
            "<button type=\"submit\" class=\"button button-secondary\">Preview</button>"
        };
        format!(
            "<form method=\"POST\" action=\"/rewind\">\n{csrf}<input type=\"hidden\" name=\"dir\" value=\"{}\">\n<div class=\"field\"><label for=\"amount\">Put this folder back as it was</label><input type=\"number\" id=\"amount\" name=\"amount\" min=\"1\" max=\"3650\" value=\"{}\" required> <select name=\"unit\">{}{}</select> ago</div>\n{button}</form>",
            esc(dir),
            esc(amount),
            option("hours", "hours"),
            option("days", "days"),
        )
    }

    fn rewind_post(&self, form: &hd_http::Form, s: &Session) -> Response<'static> {
        let dir = form.text("dir").trim_matches('/').to_owned();
        let amount = form.text("amount").trim().to_owned();
        let unit = if form.text("unit") == "days" { "days" } else { "hours" };
        let apply = form.text("apply") == "1";
        let Some(n) = amount.parse::<i64>().ok().filter(|n| (1..=3650).contains(n)) else {
            let flash = (Tone::Danger, "Give a number of hours or days, from 1 to 3650.".into());
            return self.files_page(s, &dir, vec![flash]);
        };
        let at = timefmt::unix_ms() - n * if unit == "days" { 86_400_000 } else { 3_600_000 };
        let place = if dir.is_empty() { "My drive".to_owned() } else { dir.clone() };
        let report = match self.store.rewind(&s.user, &dir, at, apply) {
            Ok(r) => r,
            Err(e) => return self.files_page(s, &dir, vec![self.flash(Err(e))]),
        };
        let examples = |v: &[String]| {
            let mut out: Vec<String> = v.iter().take(10).cloned().collect();
            if v.len() > 10 {
                out.push(format!("and {} more", v.len() - 10));
            }
            out.join(", ")
        };
        let undeleted: Vec<String> = report
            .undeleted
            .iter()
            .map(|(from, to)| if from == to { from.clone() } else { format!("{from} (as {to})") })
            .collect();
        let mut text = format!(
            "{} {place} to {}: {} file(s) {} their earlier content, {} deleted item(s) {} back, \
             and {} file(s) made since {} as they are.",
            if apply { "Rewound" } else { "Rewinding" },
            when(at),
            report.reverted.len(),
            if apply { "got" } else { "would get" },
            undeleted.len(),
            if apply { "came" } else { "would come" },
            report.newer.len(),
            if apply { "stay" } else { "would stay" },
        );
        for (label, list) in [
            ("Earlier content", &report.reverted),
            ("Back from the trash", &undeleted),
            ("Made since, kept", &report.newer),
            ("Changed meanwhile, left alone", &report.skipped),
        ] {
            if !list.is_empty() {
                let _ = write!(text, " {label}: {}.", examples(list));
            }
        }
        text.push_str(if apply {
            " Nothing was removed: every version since is still in each file's history."
        } else {
            " Nothing is removed by a rewind."
        });
        let tone = if apply { Tone::Success } else { Tone::Warning };
        let mut r = self.files_page(s, &dir, vec![(tone, text)]);
        if !apply
            && (!report.reverted.is_empty() || !report.undeleted.is_empty())
            && let hd_http::ResponseBody::Bytes(b) = &mut r.body
        {
            let confirm = format!(
                "<section class=\"card\"><h2>Rewind {}?</h2>{}</section>\n",
                esc(&place),
                Self::rewind_form(&self.csrf(s), &dir, &amount, unit, true)
            );
            let page = String::from_utf8_lossy(b).replacen(
                "<h1>Files</h1>",
                &format!("<h1>Files</h1>\n{confirm}"),
                1,
            );
            *b = page.into_bytes();
        }
        r
    }

    fn item_actions(csrf: &str, path: &str) -> String {
        format!(
            "<details><summary>More</summary>\
             <form method=\"POST\" action=\"/move\">{csrf}<input type=\"hidden\" name=\"path\" value=\"{p}\">\
             <label>Move or rename to <input type=\"text\" name=\"to\" value=\"{p}\" required></label>\
             <button type=\"submit\" class=\"button button-secondary\">Move</button></form>\
             <form method=\"POST\" action=\"/delete\">{csrf}<input type=\"hidden\" name=\"path\" value=\"{p}\">\
             <button type=\"submit\" class=\"button button-danger\">Move to trash</button></form></details>",
            p = esc(path)
        )
    }

    fn upload(&self, req: &mut Request<'_, '_>, s: &Session) -> Response<'static> {
        let Some(boundary) = req.header("content-type").and_then(multipart::boundary) else {
            return Response::text(415, "an upload is multipart/form-data");
        };
        let provenance = Provenance {
            device: "web".into(),
            mtime_ms: timefmt::unix_ms(),
            origin: Origin::Upload,
            created_ms: None,
        };
        let max = self.config.max_file;
        let mut flashes = Vec::new();
        let mut dir = String::new();
        let mut checked = false;
        let body = req.body();
        let mut parts = Multipart::new(body, &boundary);
        let result = (|| -> std::io::Result<()> {
            while let Some(part) = parts.next_part()? {
                match (part.name.as_str(), part.filename) {
                    ("csrf_token", None) => {
                        let token = parts.text(256)?;
                        checked = self.sessions.verify_csrf(&s.id, &token);
                    }
                    ("dir", None) => parts.text(4096)?.trim_matches('/').clone_into(&mut dir),
                    ("file", Some(name)) if checked => {
                        if name.is_empty() {
                            continue;
                        }
                        let target = pathname::join(&dir, &name);
                        if let Some(why) = self.over_quota(&s.user, 0) {
                            flashes.push((Tone::Danger, format!("{name}: {why}")));
                            continue;
                        }
                        let limit = max.min(self.write_limit(&s.user));
                        let r = self.store.write_file(
                            &s.user,
                            &target,
                            Base::Any,
                            &mut parts,
                            limit,
                            &provenance,
                        );
                        let r = match r {
                            Err(e) if limit < max && e.message().contains("size limit") => {
                                Err(hd_common::Error::new(self.quota_message(&s.user)))
                            }
                            r => r,
                        };
                        flashes.push(self.flash(r.map(|c| {
                            if c.unchanged {
                                format!("{name} was already up to date.")
                            } else if c.conflict {
                                format!(
                                    "{name} was stored as {} (something else had that name).",
                                    c.path
                                )
                            } else {
                                format!("Uploaded {name}.")
                            }
                        })));
                    }
                    ("file", Some(_)) => {
                        return Err(std::io::Error::other("the form expired"));
                    }
                    _ => {
                        let _ = parts.text(64 * 1024)?;
                    }
                }
            }
            Ok(())
        })();
        if !checked {
            let mut r = Response::text(403, "the form expired; go back and try again");
            r.close = true;
            return r;
        }
        if let Err(e) = result {
            flashes.push((
                Tone::Danger,
                format!("The upload did not complete: {e}. Files listed as uploaded are safe."),
            ));
            let mut r = self.files_page(s, &dir, flashes);
            r.close = true;
            return r;
        }
        self.files_page(s, &dir, flashes)
    }

    fn web_download<'a>(&'a self, req: &Request<'_, '_>, s: &Session) -> Response<'a> {
        let path = req.query_value("path").unwrap_or("").to_owned();
        let version = req.query_value("version").and_then(|v| v.parse().ok());
        let name = pathname::name(&path).to_owned();
        self.serve_version(req, &s.user, &path, version).with_header(
            "Content-Disposition",
            format!("attachment; filename*=UTF-8''{}", q(&name)),
        )
    }

    fn versions_page(
        &self,
        s: &Session,
        file: &str,
        flashes: Vec<(Tone, String)>,
    ) -> Response<'static> {
        let versions = self.store.read(|st| {
            match st.user(&s.user).and_then(|ns| ns.get(file)).map(|e| &e.node) {
                Some(Node::File { versions, .. }) => Some(versions.clone()),
                _ => None,
            }
        });
        let Some(versions) = versions else { return Response::text(404, "no such file") };
        let csrf = self.csrf(s);
        let mut b = format!(
            "<h1>History</h1>\n<p class=\"page-intro\"><a href=\"/files?path={}\">{}</a>: every version is kept for {} days, then thinned to one a day, a week, and a month.</p>\n",
            q(pathname::parent(file)),
            esc(file),
            self.config.retention.keep_all_ms / 86_400_000
        );
        b.push_str("<section class=\"card\"><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>Saved</th><th>Size</th><th>From</th><th></th></tr></thead><tbody>\n");
        let newest = versions.last().map(|v| v.id);
        for v in versions.iter().rev() {
            let restore = if Some(v.id) == newest {
                "<span class=\"badge\">current</span>".to_owned()
            } else {
                format!(
                    "<form method=\"POST\" action=\"/restore-version\">{csrf}<input type=\"hidden\" name=\"path\" value=\"{}\"><input type=\"hidden\" name=\"version\" value=\"{}\"><button type=\"submit\" class=\"button button-secondary\">Restore</button></form>",
                    esc(file),
                    v.id
                )
            };
            let _ = writeln!(
                b,
                "<tr><td><a href=\"/download?path={}&amp;version={}\">{}</a></td><td>{}</td><td>{} ({})</td><td>{restore}</td></tr>",
                q(file),
                v.id,
                when(v.created_ms),
                size(v.size),
                esc(&v.device),
                crate::api::origin_name(v.origin),
            );
        }
        b.push_str("</tbody></table></div></section>\n");
        self.page_with(s, "History", "files", flashes, b)
    }

    fn trash_page(&self, s: &Session, flashes: Vec<(Tone, String)>) -> Response<'static> {
        let items = self.store.read(|st| {
            st.user(&s.user).map_or_else(Vec::new, |ns| {
                ns.trash
                    .values()
                    .rev()
                    .map(|t| {
                        (
                            t.id,
                            t.path.clone(),
                            t.deleted_ms,
                            t.entries.iter().filter(|(_, n)| !n.is_dir()).count(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        });
        let csrf = self.csrf(s);
        let mut b = format!(
            "<h1>Trash</h1>\n<p class=\"page-intro\">Deleted items are kept for {} days.</p>\n<section class=\"card\"><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>Was at</th><th>Deleted</th><th>Files</th><th></th></tr></thead><tbody>\n",
            self.config.retention.trash_ms / 86_400_000
        );
        if items.is_empty() {
            b.push_str(
                "<tr><td colspan=\"4\" class=\"empty-state\">The trash is empty.</td></tr>\n",
            );
        }
        for (id, p, deleted, n) in items {
            let _ = writeln!(
                b,
                "<tr><td>{}</td><td>{}</td><td>{n}</td><td><form method=\"POST\" action=\"/restore\">{csrf}<input type=\"hidden\" name=\"trash_id\" value=\"{id}\"><button type=\"submit\" class=\"button button-secondary\">Restore</button></form></td></tr>",
                esc(&p),
                when(deleted)
            );
        }
        b.push_str("</tbody></table></div></section>\n");
        self.page_with(s, "Trash", "trash", flashes, b)
    }

    fn devices_page(&self, s: &Session, flashes: Vec<(Tone, String)>) -> Response<'static> {
        let devices = self.store.read(|st| {
            st.user(&s.user).map_or_else(Vec::new, |ns| {
                ns.devices
                    .values()
                    .map(|d| (d.id, d.name.clone(), d.created_ms))
                    .collect::<Vec<_>>()
            })
        });
        let csrf = self.csrf(s);
        let mut b = String::from(
            "<h1>Devices</h1>\n<section class=\"card\"><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>Name</th><th>Registered</th><th></th></tr></thead><tbody>\n",
        );
        if devices.is_empty() {
            b.push_str("<tr><td colspan=\"3\" class=\"empty-state\">No devices yet.</td></tr>\n");
        }
        for (id, name, created) in devices {
            let _ = writeln!(
                b,
                "<tr><td>{}</td><td>{}</td><td><form method=\"POST\" action=\"/devices/revoke\">{csrf}<input type=\"hidden\" name=\"id\" value=\"{id}\"><button type=\"submit\" class=\"button button-danger\">Revoke</button></form></td></tr>",
                esc(&name),
                when(created)
            );
        }
        b.push_str("</tbody></table></div></section>\n");
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>Add a device</h2><form method=\"POST\" action=\"/devices\">{csrf}{}<button type=\"submit\" class=\"button\">Create token</button></form></section>",
            html::field("name", "Name", "text", "", "For example: laptop, phone, rclone", true)
        );
        self.page_with(s, "Devices", "devices", flashes, b)
    }

    fn admin_page(&self, s: &Session) -> Response<'static> {
        let root = self.store.root().to_path_buf();
        let space = hd_sys::posix::fs_space(&root).ok();
        let quarantined = std::fs::read_dir(root.join("quarantine")).map_or(0, Iterator::count);
        let (seq, users) = self.store.read(|st| {
            let users: Vec<(String, usize, u64, usize, usize)> = st
                .users
                .iter()
                .map(|(u, ns)| {
                    let (mut files, mut bytes) = (0, 0);
                    for e in ns.entries.values() {
                        if let Some(v) = e.node.current() {
                            files += 1;
                            bytes += v.size;
                        }
                    }
                    (u.clone(), files, bytes, ns.trash.len(), ns.devices.len())
                })
                .collect();
            (st.seq, users)
        });
        let m = self.maintenance.snapshot();
        let r = self.store.recovery();
        let mut b = String::from("<h1>Admin</h1>\n");
        let healthy = !self.store.is_poisoned() && quarantined == 0 && m.damaged_versions == 0;
        let _ = writeln!(
            b,
            "<section class=\"card\"><h2>Store</h2><dl class=\"details-list\">\
             <dt>State</dt><dd>{}</dd><dt>Store ID</dt><dd><code>{}</code></dd><dt>Location</dt><dd><code>{}</code></dd>\
             <dt>Journal</dt><dd>record {seq}</dd><dt>Free space</dt><dd>{}</dd><dt>Quarantined objects</dt><dd>{quarantined}</dd>\
             <dt>Last start</dt><dd>{} records replayed; {} torn and {} repaired bytes and {} bad snapshot(s) set aside</dd></dl></section>",
            if self.store.is_poisoned() {
                "<span class=\"notice notice-danger\">writes stopped: restart the server</span>"
            } else if healthy {
                "healthy"
            } else if m.damaged_versions > 0 {
                "<span class=\"notice notice-danger\">some versions cannot be read: see the reference check below, and restore from a backup</span>"
            } else {
                "<span class=\"notice notice-warning\">damaged objects in quarantine: run fsck</span>"
            },
            esc(self.store.id()),
            esc(&root.display().to_string()),
            space.map_or_else(
                || "unknown".to_owned(),
                |sp| format!("{} of {}", size(sp.available), size(sp.total))
            ),
            r.records_replayed,
            r.torn_bytes,
            r.repaired_bytes,
            r.bad_snapshots.len()
        );
        if let Some(warning) = self.overcommitted() {
            let _ = writeln!(
                b,
                "<section class=\"card\"><h2>Space</h2><p><span class=\"notice notice-warning\">{}</span></p></section>",
                esc(&warning)
            );
        }
        b.push_str("<section class=\"card\"><h2>Maintenance</h2><dl class=\"details-list\">");
        for (label, entry) in [
            ("Checkpoint", &m.checkpoint),
            ("Retention", &m.retention),
            ("Garbage collection", &m.gc),
            ("Scrub", &m.scrub),
            ("Reference check", &m.check),
        ] {
            let text = entry.as_ref().map_or_else(
                || "not run since start".to_owned(),
                |(at, t)| format!("{}: {t}", when(*at)),
            );
            let _ = write!(b, "<dt>{label}</dt><dd>{}</dd>", esc(&text));
        }
        b.push_str("</dl></section>\n");
        if !m.alerts.is_empty() {
            b.push_str("<section class=\"card\"><h2>Unusual activity</h2><p class=\"field-help\">Retention is held for these drives until their owners dismiss the alert in the web UI.</p><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>User</th><th>When</th><th>Changed</th><th>Deleted</th><th>Look encrypted</th></tr></thead><tbody>\n");
            for a in &m.alerts {
                let _ = writeln!(
                    b,
                    "<tr><td>{}</td><td>{} to {}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&a.user),
                    when(a.from_ms),
                    when(a.to_ms),
                    a.changed,
                    a.deleted,
                    a.suspicious
                );
            }
            b.push_str("</tbody></table></div></section>\n");
        }
        b.push_str("<section class=\"card\"><h2>Accounts</h2><div class=\"table-wrap\"><table class=\"data-table\"><thead><tr><th>User</th><th>Files</th><th>Size (current versions)</th><th>Stored (all versions and trash)</th><th>Quota</th><th>In trash</th><th>Devices</th><th>Can sign in</th></tr></thead><tbody>\n");
        for (u, files, bytes, trash, devices) in users {
            let quota = self.accounts.get(&u).map(|a| a.quota);
            let _ = writeln!(
                b,
                "<tr><td>{}</td><td>{files}</td><td>{}</td><td>{}</td><td>{}</td><td>{trash}</td><td>{devices}</td><td>{}</td></tr>",
                esc(&u),
                size(bytes),
                size(self.usage(&u)),
                quota.map_or_else(|| "none".to_owned(), size),
                if self.accounts.get(&u).is_some() { "yes" } else { "no (not in the users file)" }
            );
        }
        b.push_str("</tbody></table></div></section>\n");
        self.page(s, "Admin", "admin", b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1536), "1.5 KiB");
        assert_eq!(size(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
