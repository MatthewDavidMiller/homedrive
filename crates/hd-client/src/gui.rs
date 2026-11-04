//! The client's GUI: a small web application on this computer, served by the
//! daemon, so one process syncs and shows what it is doing. A wizard takes a
//! new install from the server's address to a synced folder; after that the
//! same address shows each folder's state.
//!
//! **It listens on 127.0.0.1, which is not private.** Any program here can
//! connect, and any web page open in a browser here can make that browser
//! send it requests, so each of these is needed:
//!
//! - A random key, in `gui.json` beside the configuration, which only the
//!   user can read. `/open?key=...` swaps it for a cookie and redirects, so
//!   the key leaves the address bar, and nothing else is served without it.
//! - The cookie is `SameSite=Strict` and `HttpOnly`.
//! - The `Host` header must be this address, which defeats DNS rebinding: a
//!   page on evil.example whose name now points here sends that name.
//! - Every POST needs a CSRF token and, when sent, this exact `Origin`.
//! - The Content-Security-Policy allows no scripts and no outside content.
//!
//! The account password passes through once, to register the device, and is
//! neither stored nor logged; the device token it buys is what is kept.

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use hd_common::{Error, Result, fsio, pathname, timefmt};
use hd_http::{Form, Handler, Method, Request, Response};

use crate::autostart;
use crate::config::{self, Config};
use crate::control::{self, Status};
use crate::history::{self, Kind};
use crate::remote::Remote;
use crate::scan::SENTINEL;
use crate::service::Service;
use crate::state::Persisted;

const INFO_FILE: &str = "gui.json";
const COOKIE: &str = "homedrive_gui";
const STYLE: &str = include_str!("gui.css");
const MAX_FORM: usize = 64 * 1024;
const MAX_LISTED_DIRS: usize = 2000;
const MAX_LISTED_PROBLEMS: usize = 20;
/// The most history entries the History page shows for one folder.
const MAX_LISTED_HISTORY: usize = 300;
const REFRESH_SECONDS: u32 = 5;
const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; \
                   frame-ancestors 'none'";

/// What the wizard has been told and not yet saved.
#[derive(Clone, Debug, Default)]
struct Pending {
    server: String,
    ca_file: Option<PathBuf>,
    /// Said on the next page of the wizard.
    message: Option<String>,
}

#[derive(Debug)]
pub struct Gui {
    dir: PathBuf,
    key: String,
    csrf: String,
    host: String,
    service: Arc<Service>,
    pending: Mutex<Pending>,
    /// One change to the configuration at a time.
    saving: Mutex<()>,
}

/// Escapes text for an element body or a double-quoted attribute.
fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// A URL query value.
fn query(text: &str) -> String {
    hd_http::percent_encode(text)
}

/// How long before `now_ms` a moment `at_ms` was, in words.
fn ago(now_ms: i64, at_ms: i64) -> String {
    let s = (now_ms - at_ms).max(0) / 1000;
    match s {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86_400 => format!("{} h ago", s / 3600),
        _ => match s / 86_400 {
            1 => "1 day ago".to_owned(),
            d => format!("{d} days ago"),
        },
    }
}

/// A moment as a date and time, to the minute. It is in UTC, and says so:
/// the page cannot know this computer's time zone.
fn utc(at_ms: i64) -> String {
    let full = timefmt::rfc3339_millis(at_ms.div_euclid(1000), 0);
    format!("{} UTC", full.get(..16).unwrap_or(&full).replacen('T', " ", 1))
}

/// A moment, as how long ago it was, with the date and time on hover.
fn when(now_ms: i64, at_ms: i64) -> String {
    format!("<time title=\"{}\">{}</time>", utc(at_ms), ago(now_ms, at_ms))
}

/// The address to open, if a homedrive GUI is answering on this computer.
pub fn running_url(dir: &Path) -> Option<String> {
    let text = fsio::read_text(dir.join(INFO_FILE), 4096).ok()??;
    let v = hd_api::parse(text.as_bytes()).ok()?;
    let port = u16::try_from(hd_api::get_u64(&v, "port").ok()?).ok()?;
    let key = hd_api::get_str(&v, "key").ok()?;
    let mut s =
        TcpStream::connect_timeout(&(Ipv4Addr::LOCALHOST, port).into(), Duration::from_secs(2))
            .ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(
        format!("GET /ping HTTP/1.0\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .ok()?;
    let mut reply = [0_u8; 4096];
    let mut len = 0;
    while len < reply.len() {
        match s.read(&mut reply[len..]).ok()? {
            0 => break,
            n => len += n,
        }
    }
    reply[..len].ends_with(b"homedrive").then(|| format!("http://127.0.0.1:{port}/open?key={key}"))
}

impl Gui {
    /// Listens on a free port on 127.0.0.1 and returns the address to open.
    pub fn start(dir: PathBuf, service: Arc<Service>) -> Result<String> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let key = hd_common::rand::random_hex(32)?;
        let info =
            hd_api::J::O(vec![("port", hd_api::J::U(u64::from(port))), ("key", hd_api::s(&*key))])
                .render();
        fsio::mkdir_durable(&dir, 0o700)?;
        fsio::atomic_replace(dir.join(INFO_FILE), info.as_bytes(), 4096)?;
        let url = format!("http://127.0.0.1:{port}/open?key={key}");
        let gui = Arc::new(Self {
            dir,
            key,
            csrf: hd_common::rand::random_hex(32)?,
            host: format!("127.0.0.1:{port}"),
            service,
            pending: Mutex::new(Pending::default()),
            saving: Mutex::new(()),
        });
        std::thread::Builder::new()
            .name("gui".into())
            .stack_size(256 * 1024)
            .spawn(move || hd_http::serve(&listener, &gui))
            .map_err(|e| Error::new(format!("cannot start the GUI: {e}")))?;
        Ok(url)
    }

    fn config(&self) -> Option<Config> {
        Config::load(&self.dir).ok()
    }

    fn signed_in(&self) -> bool {
        self.config().is_some() && config::load_token(&self.dir).is_ok()
    }

    fn page(step: Option<usize>, title: &str, lede: &str, body: &str, refresh: bool) -> String {
        let mut out = format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
             <title>{t} - homedrive</title><link rel=\"stylesheet\" href=\"/style.css\">",
            t = esc(title)
        );
        if refresh {
            let _ = write!(out, "<meta http-equiv=\"refresh\" content=\"{REFRESH_SECONDS}\">");
        }
        let _ = write!(out, "</head><body><main><h1>{}</h1>", esc(title));
        if !lede.is_empty() {
            let _ = write!(out, "<p class=\"lede\">{}</p>", esc(lede));
        }
        if let Some(step) = step {
            out.push_str("<ol class=\"steps\">");
            for (i, name) in ["Server", "Sign in", "Folder"].iter().enumerate() {
                let class = match i.cmp(&step) {
                    std::cmp::Ordering::Less => "done",
                    std::cmp::Ordering::Equal => "now",
                    std::cmp::Ordering::Greater => "",
                };
                let _ = write!(out, "<li class=\"{class}\">{}. {name}</li>", i + 1);
            }
            out.push_str("</ol>");
        }
        out.push_str(body);
        out.push_str("</main></body></html>");
        out
    }

    fn csrf_field(&self) -> String {
        format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", self.csrf)
    }

    fn notice(error: Option<&str>) -> String {
        error.map_or_else(String::new, |e| {
            format!("<p class=\"notice\" role=\"alert\">{}</p>", esc(e))
        })
    }

    fn server_page(&self, error: Option<&str>, server: &str, ca: &str) -> Response<'static> {
        let body = format!(
            "{notice}<form class=\"card\" method=\"post\" action=\"/setup\">{csrf}\
             <label for=\"server\">Server address</label>\
             <input type=\"url\" id=\"server\" name=\"server\" value=\"{server}\" \
             placeholder=\"https://drive.example.com\" required autofocus>\
             <p class=\"help\">The address you use for homedrive in a browser.</p>\
             <label for=\"ca\">Certificate file (optional)</label>\
             <input type=\"text\" id=\"ca\" name=\"ca_file\" value=\"{ca}\">\
             <p class=\"help\">Only if your server uses a private certificate authority. \
             Give the full path to its PEM file.</p>\
             <button class=\"button\" type=\"submit\">Continue</button></form>",
            notice = Self::notice(error),
            csrf = self.csrf_field(),
            server = esc(server),
            ca = esc(ca),
        );
        let html = Self::page(
            Some(0),
            "Set up homedrive",
            "Connect this computer to your homedrive server.",
            &body,
            false,
        );
        Response::html(if error.is_some() { 400 } else { 200 }, html)
    }

    fn signin_page(&self, error: Option<&str>, user: &str, device: &str) -> Response<'static> {
        let server = self.pending.lock().unwrap_or_else(PoisonError::into_inner).server.clone();
        let body = format!(
            "{notice}<form class=\"card\" method=\"post\" action=\"/signin\">{csrf}\
             <p class=\"meta\">Server: {server}</p>\
             <label for=\"user\">User name</label>\
             <input type=\"text\" id=\"user\" name=\"user\" value=\"{user}\" required autofocus \
             autocomplete=\"username\">\
             <label for=\"password\">Password</label>\
             <input type=\"password\" id=\"password\" name=\"password\" required \
             autocomplete=\"current-password\">\
             <p class=\"help\">Used once to register this computer, and not saved.</p>\
             <label for=\"device\">Name for this computer</label>\
             <input type=\"text\" id=\"device\" name=\"device\" value=\"{device}\" required>\
             <div class=\"row\"><button class=\"button\" type=\"submit\">Sign in</button>\
             <a class=\"button plain\" href=\"/setup\">Back</a></div></form>",
            notice = Self::notice(error),
            csrf = self.csrf_field(),
            server = esc(&server),
            user = esc(user),
            device = esc(device),
        );
        let html = Self::page(
            Some(1),
            "Sign in",
            "Your homedrive account, the one you use on the web page.",
            &body,
            false,
        );
        Response::html(if error.is_some() { 400 } else { 200 }, html)
    }

    /// The folders inside `path`, by name, with hidden ones left out.
    fn subfolders(path: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(path)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| !n.starts_with('.') && !n.starts_with('$'))
                    .take(MAX_LISTED_DIRS)
                    .collect()
            })
            .unwrap_or_default();
        names.sort_by_key(|n| n.to_lowercase());
        names
    }

    /// The first step's answer for a folder: what stops it being synced.
    fn folder_problem(&self, path: &Path, cfg: &Config, merge: bool) -> Option<String> {
        if !path.is_absolute() {
            return Some("Give the full path of the folder.".into());
        }
        if path.parent().is_none() {
            return Some("A whole disk cannot be synced. Choose a folder on it.".into());
        }
        let private = [Some(self.dir.clone()), config::state_root().ok()];
        if private.iter().flatten().any(|p| p.starts_with(path) || path.starts_with(p)) {
            return Some(
                "That folder holds homedrive's own settings, including the key to your \
                 account. Choose a folder inside it, such as Documents."
                    .into(),
            );
        }
        if path.exists() && !path.is_dir() {
            return Some("That is a file, not a folder.".into());
        }
        let holds_files = fs::read_dir(path).is_ok_and(|entries| {
            entries.flatten().any(|e| e.file_name() != SENTINEL && e.file_name() != ".homedrive")
        });
        (holds_files && !merge && !cfg.folders.iter().any(|f| f.local == path)).then(|| {
            "This folder already has files in it. They will be uploaded and merged with what \
             is on the server; if a file differs, both copies are kept. Tick the box to go \
             ahead, or choose an empty folder."
                .into()
        })
    }

    fn folder_page(
        &self,
        error: Option<&str>,
        path: &Path,
        remote: &str,
        adding: bool,
    ) -> Response<'static> {
        let mut places = String::new();
        if let Some(parent) = path.parent() {
            let _ = write!(
                places,
                "<li><a href=\"/folder?path={}\">Up one level</a></li>",
                query(&parent.to_string_lossy())
            );
        }
        for root in config::drive_roots() {
            let root = root.to_string_lossy();
            let _ = write!(
                places,
                "<li><a href=\"/folder?path={}\">Disk {}</a></li>",
                query(&root),
                esc(&root)
            );
        }
        for name in Self::subfolders(path) {
            let _ = write!(
                places,
                "<li><a href=\"/folder?path={}\">{}</a></li>",
                query(&path.join(&name).to_string_lossy()),
                esc(&name)
            );
        }
        let shown = esc(&path.to_string_lossy());
        let existing = fs::read_dir(path).is_ok_and(|mut d| d.next().is_some());
        let merge = if existing && !path.join(SENTINEL).exists() {
            "<label class=\"check\"><input type=\"checkbox\" name=\"merge\" value=\"1\">\
             <span>This folder has files in it. Upload them and merge with the server, \
             keeping both copies of any file that differs.</span></label>"
        } else {
            ""
        };
        let start = if adding {
            ""
        } else {
            "<label class=\"check\"><input type=\"checkbox\" name=\"autostart\" value=\"1\" \
             checked><span>Start homedrive when I sign in, so this folder keeps syncing \
             after a restart.</span></label>"
        };
        let body = format!(
            "{notice}<section class=\"card\" aria-label=\"Choose a folder\">\
             <h2>{shown}</h2><form method=\"get\" action=\"/folder\">\
             <label for=\"path\">Go to a folder</label>\
             <input type=\"text\" id=\"path\" name=\"path\" value=\"{shown}\">\
             <button class=\"button plain\" type=\"submit\">Go</button></form>\
             <ul class=\"dirs\">{places}</ul>\
             <form method=\"post\" action=\"/folder/new\">{csrf}\
             <input type=\"hidden\" name=\"path\" value=\"{shown}\">\
             <input type=\"hidden\" name=\"remote\" value=\"{remote}\">\
             <label for=\"name\">New folder here</label>\
             <input type=\"text\" id=\"name\" name=\"name\" required>\
             <button class=\"button plain\" type=\"submit\">Create folder</button></form>\
             </section>\
             <form class=\"card\" method=\"post\" action=\"/folder\">{csrf}\
             <input type=\"hidden\" name=\"path\" value=\"{shown}\">\
             <h2>Sync this folder</h2><p class=\"help\">{shown}</p>\
             <label for=\"remote\">Folder on the server</label>\
             <input type=\"text\" id=\"remote\" name=\"remote\" value=\"{remote}\" \
             placeholder=\"Leave blank for your whole drive\">\
             {merge}{start}<button class=\"button\" type=\"submit\">Sync this folder</button></form>",
            notice = Self::notice(error),
            csrf = self.csrf_field(),
            remote = esc(remote),
        );
        let (step, title, lede) = if adding {
            (None, "Add a folder", "Choose another folder to keep in sync.")
        } else {
            (
                Some(2),
                "Choose a folder",
                "Files in this folder stay in step with your homedrive server.",
            )
        };
        Response::html(
            if error.is_some() { 400 } else { 200 },
            Self::page(step, title, lede, &body, false),
        )
    }

    fn folder_card(&self, cfg: &Config, f: &config::FolderConfig) -> Result<String> {
        let folder = cfg.folder(f)?;
        let st = Status::read(&folder.state_dir);
        let running = self.service.is_running(&f.local);
        let waiting = st.as_ref().is_some_and(|s| {
            s.held_deletes.is_some() || s.held_changes.is_some() || s.ransomware_suspected
        });
        let problems = st.as_ref().map_or(0, |s| s.errors.len());
        let progress = self.service.progress(&f.local);
        // This page refreshes every few seconds, and reading a folder's state
        // means reading and checking all of it, so that is only for a folder
        // nothing here is syncing.
        let files = progress.as_ref().filter(|_| running).map_or_else(
            || Persisted::peek(&folder.state_dir).map_or(0, |s| s.synced.len()),
            |p| usize::try_from(p.files.load(Ordering::Relaxed)).unwrap_or(0),
        );
        let syncing = progress.as_ref().is_some_and(|p| p.running.load(Ordering::Acquire));
        // The status file is from the last round to finish, perhaps before
        // this program started, so it says nothing about this moment.
        let finished_ms = progress.as_ref().map_or(0, |p| p.finished_ms.load(Ordering::Acquire));
        let current = finished_ms != 0 && !syncing;
        let live = progress.as_ref().filter(|_| syncing).map_or_else(String::new, |p| {
            format!(
                "Syncing now: checked {} of {}, {} uploaded, {} downloaded",
                p.checked.load(Ordering::Relaxed),
                p.total.load(Ordering::Relaxed),
                p.uploaded.load(Ordering::Relaxed),
                p.downloaded.load(Ordering::Relaxed),
            )
        });
        let (class, state) = if !running {
            ("bad", "Not syncing: another homedrive process has this folder, or it failed to start")
        } else if st.as_ref().is_some_and(|s| s.ransomware_suspected) {
            ("bad", "Stopped: recent changes look like ransomware")
        } else if waiting {
            ("warn", "Waiting for you")
        } else if syncing {
            ("good", live.as_str())
        } else if !current {
            ("warn", "Starting")
        } else if problems > 0 {
            ("warn", "Some files did not sync")
        } else {
            ("good", "Up to date")
        };
        let remote = if f.remote.is_empty() {
            "your whole drive".to_owned()
        } else {
            format!("/{}", f.remote)
        };
        let mut card = format!(
            "<section class=\"card\"><h2>{local}</h2>\
             <p class=\"state {class}\">{state}</p>\
             <p class=\"meta\">Synced with {remote}; {files} item(s)",
            local = esc(&f.local.to_string_lossy()),
            remote = esc(&remote),
        );
        card.push_str("</p>");
        // A folder this program is not syncing has no live record, so its
        // history is read for when it last changed.
        let now = timefmt::unix_ms();
        let last_change = progress.as_ref().map_or_else(
            || {
                history::read(&folder.state_dir)
                    .iter()
                    .rev()
                    .find(|e| e.is_change())
                    .map_or(0, |e| e.at_ms)
            },
            |p| p.last_change_ms.load(Ordering::Relaxed),
        );
        let change = if last_change == 0 {
            "no changes yet".to_owned()
        } else {
            format!("last change {}", when(now, last_change))
        };
        let checked = if finished_ms == 0 {
            "Not checked yet".to_owned()
        } else {
            format!("Checked {}", when(now, finished_ms))
        };
        let _ = write!(
            card,
            "<p class=\"meta\">{checked}; {change}. <a href=\"/history?path={}\">History</a></p>",
            query(&f.local.to_string_lossy()),
        );
        if let Some(s) = &st {
            if s.held_deletes.is_some() || s.held_changes.is_some() {
                let _ = write!(
                    card,
                    "<p>{} deletion(s) and {} change(s) are held back because so many happened \
                     at once. Nothing has been deleted anywhere.</p>\
                     <form method=\"post\" action=\"/confirm\">{csrf}\
                     <input type=\"hidden\" name=\"path\" value=\"{path}\">\
                     <button class=\"button\" type=\"submit\">I meant to do this</button></form>",
                    s.held_deletes.unwrap_or(0),
                    s.held_changes.unwrap_or(0),
                    csrf = self.csrf_field(),
                    path = esc(&f.local.to_string_lossy()),
                );
            }
            if !s.errors.is_empty() || !s.skipped.is_empty() {
                if !current {
                    card.push_str(
                        "<p class=\"meta\">From the last round to finish, which may already \
                         be out of date:</p>",
                    );
                }
                card.push_str("<ul class=\"problems\">");
                for (p, why) in s.errors.iter().chain(&s.skipped).take(MAX_LISTED_PROBLEMS) {
                    let _ = write!(card, "<li>{}: {}</li>", esc(p), esc(why));
                }
                card.push_str("</ul>");
            }
        }
        let _ = write!(
            card,
            "<a class=\"button plain\" href=\"/remove?path={}\">Stop syncing this folder</a>\
             </section>",
            query(&f.local.to_string_lossy())
        );
        Ok(card)
    }

    fn status_page(&self, cfg: &Config) -> Response<'static> {
        let mut body = format!(
            "<p class=\"meta\">Signed in to {server} as {user}.</p>",
            server = esc(&cfg.server),
            user = esc(&cfg.user),
        );
        for f in &cfg.folders {
            match self.folder_card(cfg, f) {
                Ok(card) => body.push_str(&card),
                Err(e) => body.push_str(&Self::notice(Some(e.message()))),
            }
        }
        let _ = write!(
            body,
            "<div class=\"row\"><a class=\"button\" href=\"/folder\">Add a folder</a>\
             <a class=\"button plain\" href=\"/history\">History</a>\
             <a class=\"button plain\" href=\"{}\" target=\"_blank\" rel=\"noreferrer\">\
             Open my files on the web</a></div>",
            esc(&cfg.server)
        );
        let _ = write!(
            body,
            "<section class=\"card\"><h2>This computer</h2>\
             <form method=\"post\" action=\"/autostart\">{csrf}\
             <p class=\"meta\">homedrive {state} when you sign in.</p>\
             <input type=\"hidden\" name=\"on\" value=\"{next}\">\
             <button class=\"button plain\" type=\"submit\">{action}</button></form>\
             <div class=\"row\"><a class=\"button plain\" href=\"/signout\">Sign out</a>\
             <form method=\"post\" action=\"/quit\">{csrf}\
             <button class=\"button plain\" type=\"submit\">Quit homedrive</button></form>\
             </div></section>",
            csrf = self.csrf_field(),
            state = if autostart::enabled() { "starts" } else { "does not start" },
            next = if autostart::enabled() { "0" } else { "1" },
            action =
                if autostart::enabled() { "Do not start at sign-in" } else { "Start at sign-in" },
        );
        Response::html(200, Self::page(None, "homedrive", "", &body, true))
    }

    /// What each folder's sync rounds changed, newest first; with `only`,
    /// that folder alone.
    fn history_page(cfg: &Config, only: Option<&str>) -> Response<'static> {
        let now = timefmt::unix_ms();
        let mut body =
            String::from("<div class=\"row\"><a class=\"button plain\" href=\"/\">Back</a></div>");
        let shown = cfg.folders.iter().filter(|f| only.is_none_or(|p| Path::new(p) == f.local));
        for f in shown {
            let _ = write!(
                body,
                "<section class=\"card\"><h2>{}</h2>",
                esc(&f.local.to_string_lossy())
            );
            let entries = match cfg.folder(f) {
                Ok(folder) => history::read(&folder.state_dir),
                Err(e) => {
                    body.push_str(&Self::notice(Some(e.message())));
                    body.push_str("</section>");
                    continue;
                }
            };
            if entries.is_empty() {
                body.push_str("<p class=\"meta\">Nothing has changed here yet.</p></section>");
                continue;
            }
            body.push_str("<ol class=\"history\">");
            for e in entries.iter().rev().take(MAX_LISTED_HISTORY) {
                let (class, what) = match e.kind {
                    Kind::Uploaded => ("", "Uploaded"),
                    Kind::Downloaded => ("", "Downloaded"),
                    Kind::DeletedHere => {
                        ("", "Deleted here, as it was deleted elsewhere (kept in .homedrive/trash)")
                    }
                    Kind::DeletedOnServer => ("", "Deleted on the server (kept in its trash)"),
                    Kind::Conflict => (" warn", "Changed here and elsewhere; both copies kept"),
                    Kind::Repaired => (" warn", "Damaged here; replaced with the server's copy"),
                    Kind::Healed => (" warn", "Sent again to repair the server's copy"),
                    Kind::More => ("", ""),
                    Kind::Failed => (" bad", "Sync failed"),
                };
                let detail = match e.kind {
                    Kind::More => format!("and {} more change(s) in that round", e.count),
                    _ => format!(
                        "<span class=\"what{class}\">{what}</span> <span class=\"path\">{}</span>",
                        esc(&e.text)
                    ),
                };
                let _ = write!(body, "<li>{} {detail}</li>", when(now, e.at_ms));
            }
            body.push_str("</ol>");
            if entries.len() > MAX_LISTED_HISTORY {
                let _ = write!(
                    body,
                    "<p class=\"meta\">The newest {MAX_LISTED_HISTORY} of {} kept are shown.</p>",
                    entries.len()
                );
            }
            body.push_str("</section>");
        }
        let lede = format!(
            "What homedrive changed in each folder, newest first. The last {} changes are kept; \
             times are in UTC.",
            history::MAX_ENTRIES
        );
        Response::html(200, Self::page(None, "History", &lede, &body, false))
    }

    fn get(&self, request: &Request<'_, '_>) -> Response<'static> {
        match request.path.as_str() {
            "/" => match self.config() {
                Some(cfg) if self.signed_in() && !cfg.folders.is_empty() => self.status_page(&cfg),
                Some(_) if self.signed_in() => Response::redirect("/folder"),
                _ => Response::redirect("/setup"),
            },
            "/setup" => {
                let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner).clone();
                let ca = pending.ca_file.map(|p| p.to_string_lossy().into_owned());
                self.server_page(
                    pending.message.as_deref(),
                    &pending.server,
                    ca.as_deref().unwrap_or(""),
                )
            }
            "/signin" => {
                if self.pending.lock().unwrap_or_else(PoisonError::into_inner).server.is_empty() {
                    return Response::redirect("/setup");
                }
                self.signin_page(None, "", &config::device_name())
            }
            "/folder" => {
                let Some(cfg) = self.config().filter(|_| self.signed_in()) else {
                    return Response::redirect("/setup");
                };
                let path = request
                    .query_value("path")
                    .filter(|p| !p.is_empty())
                    .map_or_else(config::home_dir, PathBuf::from);
                let shown = if path.is_dir() { path } else { config::home_dir() };
                self.folder_page(None, &shown, "", !cfg.folders.is_empty())
            }
            "/history" => match self.config() {
                Some(cfg) if self.signed_in() => {
                    Self::history_page(&cfg, request.query_value("path").filter(|p| !p.is_empty()))
                }
                _ => Response::redirect("/setup"),
            },
            "/remove" => self.remove_page(request.query_value("path").unwrap_or("")),
            "/signout" => self.signout_page(),
            _ => Response::text(404, "Not found"),
        }
    }

    fn remove_page(&self, path: &str) -> Response<'static> {
        let body = format!(
            "<form class=\"card\" method=\"post\" action=\"/remove\">{csrf}\
             <input type=\"hidden\" name=\"path\" value=\"{path}\">\
             <h2>{path}</h2>\
             <p>homedrive will stop keeping this folder in sync. Nothing is deleted: your files \
             stay in the folder, and the copies on the server stay too. Changes on either side \
             stop reaching the other.</p>\
             <div class=\"row\"><button class=\"button\" type=\"submit\">Stop syncing</button>\
             <a class=\"button plain\" href=\"/\">Cancel</a></div></form>",
            csrf = self.csrf_field(),
            path = esc(path),
        );
        Response::html(200, Self::page(None, "Stop syncing this folder?", "", &body, false))
    }

    fn signout_page(&self) -> Response<'static> {
        let body = format!(
            "<form class=\"card\" method=\"post\" action=\"/signout\">{csrf}\
             <p>This stops all syncing, removes this computer from your account, and clears \
             its list of folders, so you can sign in again or connect to another server. \
             Nothing is deleted: your files stay in their folders, and everything on the \
             server stays there.</p>\
             <div class=\"row\"><button class=\"button\" type=\"submit\">Sign out</button>\
             <a class=\"button plain\" href=\"/\">Cancel</a></div></form>",
            csrf = self.csrf_field(),
        );
        Response::html(200, Self::page(None, "Sign out of homedrive?", "", &body, false))
    }

    fn post_remove(&self, form: &Form) -> Response<'static> {
        let path = PathBuf::from(form.text("path"));
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(mut cfg) = self.config() else { return Response::redirect("/setup") };
        cfg.folders.retain(|f| f.local != path);
        if let Err(e) = cfg.save(&self.dir) {
            return Response::text(500, e.message());
        }
        if !self.service.stop_folder(&path) {
            crate::say!("homedrive: {} will stop when its round ends", path.display());
        }
        Response::redirect("/")
    }

    fn post_signout(&self) -> Response<'static> {
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(mut cfg) = self.config() else { return Response::redirect("/setup") };
        for f in &cfg.folders {
            self.service.stop_folder(&f.local);
        }
        self.service.stop_health();
        // Revoked while the token still works; a server out of reach must
        // not stop anyone signing out, but they should know.
        let revoked = config::load_device_id(&self.dir)
            .ok_or_else(|| Error::new("this computer's device number is not known"))
            .and_then(|id| {
                let token = config::load_token(&self.dir)?;
                Remote::new(&cfg.server, cfg.ca_file.as_deref(), &token)?.revoke_device(id)
            });
        let server = cfg.server.clone();
        let ca_file = cfg.ca_file.clone();
        cfg.folders.clear();
        let saved = cfg.save(&self.dir).and_then(|()| config::clear_sign_in(&self.dir));
        if let Err(e) = saved {
            return Response::text(500, e.message());
        }
        let message = revoked.err().map(|e| {
            format!(
                "Signed out, but this computer could not be removed from your account ({}). \
                 You can remove it on the Devices page of the web site.",
                e.message()
            )
        });
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) =
            Pending { server, ca_file, message };
        Response::redirect("/setup")
    }

    fn post_autostart(form: &Form) -> Response<'static> {
        match autostart::set(form.text("on") == "1") {
            Ok(()) => Response::redirect("/"),
            Err(e) => Response::text(500, e.message()),
        }
    }

    fn post_quit() -> Response<'static> {
        let spawned = std::thread::Builder::new().name("quit".into()).spawn(|| {
            // Long enough for this page to reach the browser. Every change is
            // durable before the client moves on, so ending anywhere is safe.
            std::thread::sleep(Duration::from_millis(300));
            crate::tray::remove();
            std::process::exit(0);
        });
        if spawned.is_err() {
            return Response::text(500, "Could not quit.");
        }
        let body = "<p class=\"card\">Syncing has stopped. Start homedrive again to resume.</p>";
        Response::html(200, Self::page(None, "homedrive has quit", "", body, false))
    }

    fn post_setup(&self, form: &Form) -> Response<'static> {
        let server = form.text("server").trim().trim_end_matches('/').to_owned();
        let ca = form.text("ca_file").trim().to_owned();
        let ca_file = (!ca.is_empty()).then(|| PathBuf::from(&ca));
        if let Err(e) = Remote::probe(&server, ca_file.as_deref()) {
            let hint = if e.message().contains("TLS") || e.message().contains("certificate") {
                " If your server uses a private certificate authority, give its certificate \
                 file below."
            } else {
                ""
            };
            let message = format!("Could not reach that server: {}.{hint}", e.message());
            return self.server_page(Some(&message), &server, &ca);
        }
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) =
            Pending { server, ca_file, message: None };
        Response::redirect("/signin")
    }

    fn post_signin(&self, form: &Form) -> Response<'static> {
        let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if pending.server.is_empty() {
            return Response::redirect("/setup");
        }
        let (user, device) = (form.text("user").trim(), form.text("device").trim());
        let token = Remote::register(
            &pending.server,
            pending.ca_file.as_deref(),
            user,
            form.text("password"),
            device,
        );
        let token = match token {
            Ok(t) => t,
            Err(e) => {
                let message = format!("Could not sign in: {}.", e.message());
                return self.signin_page(Some(&message), user, device);
            }
        };
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let mut cfg = self.config().unwrap_or(Config {
            server: String::new(),
            user: String::new(),
            ca_file: None,
            folders: Vec::new(),
        });
        cfg.server = pending.server;
        user.clone_into(&mut cfg.user);
        cfg.ca_file = pending.ca_file;
        let saved = config::save_token(&self.dir, &token.token)
            .and_then(|()| config::save_device_id(&self.dir, token.device_id))
            .and_then(|()| cfg.save(&self.dir));
        match saved {
            Ok(()) => Response::redirect("/folder"),
            Err(e) => self.signin_page(Some(e.message()), user, device),
        }
    }

    fn post_folder(&self, form: &Form) -> Response<'static> {
        let Some(cfg) = self.config().filter(|_| self.signed_in()) else {
            return Response::redirect("/setup");
        };
        let path = PathBuf::from(form.text("path"));
        let remote = form.text("remote").trim().trim_matches('/').to_owned();
        let adding = !cfg.folders.is_empty();
        let shown = if path.is_dir() { path.clone() } else { config::home_dir() };
        if let Some(problem) = self.folder_problem(&path, &cfg, form.checked("merge")) {
            return self.folder_page(Some(&problem), &shown, &remote, adding);
        }
        let _saving = self.saving.lock().unwrap_or_else(PoisonError::into_inner);
        let added = config::add_folder(&self.dir, &path, &remote, Vec::new());
        if let Err(e) = added {
            return self.folder_page(Some(e.message()), &shown, &remote, adding);
        }
        let started = self.config().and_then(|cfg| {
            self.service.start_health(&cfg).ok()?;
            let f = cfg.folders.iter().find(|f| f.local == path)?;
            self.service.start_folder(&cfg, f).ok()
        });
        if started.is_none() {
            crate::say!("homedrive: {} was added but did not start", path.display());
        }
        if form.checked("autostart")
            && let Err(e) = autostart::set(true)
        {
            crate::say!("homedrive: could not set up starting at sign-in: {e}");
        }
        Response::redirect("/")
    }

    fn post_new_folder(&self, form: &Form) -> Response<'static> {
        let parent = PathBuf::from(form.text("path"));
        let name = form.text("name").trim();
        let remote = form.text("remote");
        let adding = self.config().is_some_and(|c| !c.folders.is_empty());
        let shown = if parent.is_dir() { parent.clone() } else { config::home_dir() };
        if pathname::validate(name).is_err() || name.contains(['/', '\\']) || name.starts_with('.')
        {
            return self.folder_page(
                Some("That is not a usable folder name."),
                &shown,
                remote,
                adding,
            );
        }
        if cfg!(windows)
            && let Some(why) = pathname::windows_problem(name)
        {
            return self.folder_page(Some(&format!("That name {why}.")), &shown, remote, adding);
        }
        let made = parent.join(name);
        match fsio::mkdir_durable(&made, 0o755) {
            Ok(()) => {
                Response::redirect(&format!("/folder?path={}", query(&made.to_string_lossy())))
            }
            Err(e) => self.folder_page(Some(e.message()), &shown, remote, adding),
        }
    }

    fn post_confirm(&self, form: &Form) -> Response<'static> {
        let Some(cfg) = self.config() else { return Response::redirect("/setup") };
        let path = Path::new(form.text("path"));
        if let Some(Ok(folder)) =
            cfg.folders.iter().find(|f| f.local == path).map(|f| cfg.folder(f))
            && let Some(st) = Status::read(&folder.state_dir)
        {
            let _ = control::Request {
                at_ms: timefmt::unix_ms(),
                deletes: st.held_deletes.unwrap_or(0),
                changes: st.held_changes.unwrap_or(0),
                verify: false,
            }
            .write(&folder.state_dir);
        }
        Response::redirect("/")
    }

    fn post(&self, request: &mut Request<'_, '_>) -> Response<'static> {
        if request.header("origin").is_some_and(|o| o != format!("http://{}", self.host)) {
            return Response::text(403, "This request came from another site.");
        }
        let Ok(form) = request.read_form(MAX_FORM) else {
            return Response::text(400, "Bad form");
        };
        if !hd_crypto::ct_equal(form.text("csrf").as_bytes(), self.csrf.as_bytes()) {
            return Response::text(403, "This form has expired. Reload the page.");
        }
        match request.path.as_str() {
            "/setup" => self.post_setup(&form),
            "/signin" => self.post_signin(&form),
            "/folder" => self.post_folder(&form),
            "/folder/new" => self.post_new_folder(&form),
            "/confirm" => self.post_confirm(&form),
            "/remove" => self.post_remove(&form),
            "/signout" => self.post_signout(),
            "/autostart" => Self::post_autostart(&form),
            "/quit" => Self::post_quit(),
            _ => Response::text(404, "Not found"),
        }
    }

    fn authorized(&self, request: &Request<'_, '_>) -> bool {
        request
            .cookie(COOKIE)
            .is_some_and(|c| hd_crypto::ct_equal(c.as_bytes(), self.key.as_bytes()))
    }

    fn route(&self, request: &mut Request<'_, '_>) -> Response<'static> {
        if request.header("host") != Some(&self.host) {
            return Response::text(403, "Open homedrive from its own address.");
        }
        match (request.method, request.path.as_str()) {
            (Method::Get, "/ping") => return Response::text(200, "homedrive"),
            (Method::Get, "/style.css") => {
                return Response::new(200, "text/css", STYLE.as_bytes().to_vec());
            }
            (Method::Get, "/open") => {
                return if request
                    .query_value("key")
                    .is_some_and(|k| hd_crypto::ct_equal(k.as_bytes(), self.key.as_bytes()))
                {
                    Response::redirect("/").with_header(
                        "Set-Cookie",
                        format!("{COOKIE}={}; Path=/; HttpOnly; SameSite=Strict", self.key),
                    )
                } else {
                    Response::text(401, "That link is out of date. Start homedrive again.")
                };
            }
            _ => {}
        }
        if !self.authorized(request) {
            return Response::text(401, "Start homedrive again to open this page.");
        }
        match request.method {
            Method::Get => self.get(request),
            Method::Post => self.post(request),
            _ => Response::text(405, "Method not allowed"),
        }
    }
}

impl Handler for Gui {
    fn handle<'a>(&'a self, request: &mut Request<'_, '_>) -> Response<'a> {
        self.route(request)
            .with_header("Content-Security-Policy", CSP.to_owned())
            .with_header("Cache-Control", "no-store".to_owned())
            // Not no-referrer: with that, browsers send `Origin: null` on
            // every form, which `post` rightly refuses.
            .with_header("Referrer-Policy", "same-origin".to_owned())
            .with_header("X-Content-Type-Options", "nosniff".to_owned())
            .with_header("X-Frame-Options", "DENY".to_owned())
    }

    fn hsts(&self) -> bool {
        false
    }
}
