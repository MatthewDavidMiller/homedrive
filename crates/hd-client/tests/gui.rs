//! The GUI, through the real `homedrive` binary and a real server: the
//! wizard from nothing to a synced folder, and everything that keeps other
//! programs and web pages out of it.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

mod common;

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{PW, World, world};

struct App {
    child: Child,
    config: PathBuf,
    port: u16,
    key: String,
    cookie: Option<String>,
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

fn enc(s: &str) -> String {
    s.bytes().fold(String::new(), |mut out, b| {
        let _ = write!(out, "%{b:02X}");
        out
    })
}

/// The binary: built by cargo here, and beside the tests when
/// `scripts/test-windows.sh` has copied them to Windows.
fn binary() -> PathBuf {
    let beside = std::env::current_exe().unwrap().with_file_name("homedrive.exe");
    if beside.exists() { beside } else { PathBuf::from(env!("CARGO_BIN_EXE_homedrive")) }
}

/// Starts the daemon with its settings under `dir`, and waits for the GUI.
fn start(dir: &Path) -> App {
    let _ = fs::remove_file(dir.join("config/homedrive/gui.json"));
    let (config_home, state_home) = (dir.join("config"), dir.join("state"));
    let child = Command::new(binary())
        .arg("daemon")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("APPDATA", &config_home)
        .env("LOCALAPPDATA", &state_home)
        .env("HOMEDRIVE_NO_BROWSER", "1")
        .env("HOMEDRIVE_AUTOSTART_NAME", format!("homedrive-test-{}", std::process::id()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let config = config_home.join("homedrive");
    let info = config.join("gui.json");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !info.exists() {
        assert!(Instant::now() < deadline, "the GUI did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    let v = hd_api::parse(&fs::read(info).unwrap()).unwrap();
    App {
        child,
        config,
        port: u16::try_from(hd_api::get_u64(&v, "port").unwrap()).unwrap(),
        key: hd_api::get_str(&v, "key").unwrap(),
        cookie: None,
    }
}

impl App {
    fn raw(&self, request: &str) -> Reply {
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).unwrap();
        let reply = String::from_utf8_lossy(&reply).into_owned();
        let (head, body) = reply.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    fn cookie_line(&self) -> String {
        self.cookie.as_ref().map_or_else(String::new, |c| format!("Cookie: {c}\r\n"))
    }

    fn get(&self, path: &str) -> Reply {
        self.raw(&format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
            self.host(),
            self.cookie_line()
        ))
    }

    fn post_with(&self, path: &str, extra: &str, form: &str) -> Reply {
        self.raw(&format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\n{}{extra}Content-Type: \
             application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: \
             close\r\n\r\n{form}",
            self.host(),
            self.cookie_line(),
            form.len()
        ))
    }

    /// Sends a form with the CSRF token a page carries.
    fn post(&self, page: &str, path: &str, fields: &[(&str, &str)]) -> Reply {
        let html = self.get(page).body;
        let csrf = html.split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap();
        let mut form = format!("csrf={csrf}");
        for (k, v) in fields {
            let _ = write!(form, "&{k}={}", enc(v));
        }
        self.post_with(path, "", &form)
    }

    fn sign_in(&mut self) {
        let r = self.get(&format!("/open?key={}", self.key));
        assert_eq!(r.status, 303, "{}", r.head);
        let line = r.head.lines().find(|l| l.starts_with("Set-Cookie:")).unwrap();
        assert!(line.contains("HttpOnly") && line.contains("SameSite=Strict"), "{line}");
        self.cookie = Some(line["Set-Cookie: ".len()..].split(';').next().unwrap().to_owned());
    }

    fn wizard_to_folder(&self, w: &World) {
        let r = self.post("/setup", "/setup", &[("server", &w.server), ("ca_file", "")]);
        assert_eq!(r.status, 303, "{}", r.body);
        let r = self.post(
            "/signin",
            "/signin",
            &[("user", "alice"), ("password", PW), ("device", "wizard")],
        );
        assert_eq!(r.status, 303, "{}", r.body);
    }
}

fn wait_for(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn on_server(w: &World, path: &str) -> bool {
    w.app.store.read(|s| s.user("alice").unwrap().entries.contains_key(path))
}

#[test]
fn the_wizard_goes_from_nothing_to_a_synced_folder() {
    let w = world("gui-wizard");
    let mut app = start(&w.dir.join("home"));
    app.sign_in();
    let first = app.get("/");
    assert_eq!(first.status, 303, "with nothing set up, it starts at the wizard");
    assert!(first.head.contains("Location: /setup"), "{}", first.head);

    // A wrong address is explained on the same page.
    let r = app.post("/setup", "/setup", &[("server", "http://127.0.0.1:1"), ("ca_file", "")]);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("Could not reach that server"), "{}", r.body);
    let r = app.post("/setup", "/setup", &[("server", "http://example.com"), ("ca_file", "")]);
    assert_eq!(r.status, 400, "plain HTTP to another machine would expose the password");

    let r = app.post("/setup", "/setup", &[("server", &w.server), ("ca_file", "")]);
    assert_eq!(r.status, 303, "{}", r.body);

    // A wrong password changes nothing.
    let r = app.post(
        "/signin",
        "/signin",
        &[("user", "alice"), ("password", "wrong password"), ("device", "wizard")],
    );
    assert_eq!(r.status, 400);
    assert!(r.body.contains("not accepted"), "{}", r.body);
    assert!(!app.config.join("token").exists());

    let r = app.post(
        "/signin",
        "/signin",
        &[("user", "alice"), ("password", PW), ("device", "wizard")],
    );
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(app.config.join("token").exists());
    for e in fs::read_dir(&app.config).unwrap() {
        let bytes = fs::read(e.unwrap().path()).unwrap();
        assert!(!bytes.windows(PW.len()).any(|b| b == PW.as_bytes()), "the password is not saved");
    }

    // Choosing a folder: browse to it, make one, sync it.
    let parent = w.dir.join("home").join("Pick");
    fs::create_dir_all(parent.join("Existing")).unwrap();
    let page = app.get(&format!("/folder?path={}", enc(parent.to_str().unwrap()))).body;
    assert!(page.contains(">Existing<"), "{page}");
    let browse = format!("/folder?path={}", enc(parent.to_str().unwrap()));
    let r = app.post(
        &browse,
        "/folder/new",
        &[("path", parent.to_str().unwrap()), ("name", "Drive"), ("remote", "")],
    );
    assert_eq!(r.status, 303, "{}", r.body);
    let local = parent.join("Drive");
    assert!(local.is_dir());
    let r = app.post(&browse, "/folder", &[("path", local.to_str().unwrap()), ("remote", "")]);
    assert_eq!(r.status, 303, "{}", r.body);

    // It syncs straight away, without a restart.
    fs::write(local.join("first.txt"), b"from the wizard").unwrap();
    wait_for("the first file to upload", || on_server(&w, "first.txt"));
    wait_for("the status page to show it", || app.get("/").body.contains("Up to date"));
    assert!(app.get("/").body.contains(local.to_str().unwrap().split('\\').next_back().unwrap()));
}

#[test]
fn the_folder_step_refuses_what_should_not_be_synced() {
    let w = world("gui-folders");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let path = |p: &Path| p.to_str().unwrap().to_owned();

    let root = if cfg!(windows) { PathBuf::from("C:\\") } else { PathBuf::from("/") };
    let r = app.post("/folder", "/folder", &[("path", &path(&root)), ("remote", "")]);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("whole disk"), "{}", r.body);

    // The folder holding the token would upload the key to the account.
    let r = app.post("/folder", "/folder", &[("path", &path(&home)), ("remote", "")]);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("settings"), "{}", r.body);

    // Files already there are merged only when the user says so.
    let full = home.join("Full");
    fs::create_dir_all(&full).unwrap();
    fs::write(full.join("old.txt"), b"already here").unwrap();
    let r = app.post("/folder", "/folder", &[("path", &path(&full)), ("remote", "")]);
    assert_eq!(r.status, 400);
    assert!(r.body.contains("already has files"), "{}", r.body);
    let r = app.post(
        "/folder",
        "/folder",
        &[("path", &path(&full)), ("remote", "backup"), ("merge", "1")],
    );
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the existing file to upload", || on_server(&w, "backup/old.txt"));

    // A folder inside a synced one would be synced twice.
    let inner = full.join("inner");
    fs::create_dir_all(&inner).unwrap();
    let r = app.post(
        "/folder",
        "/folder",
        &[("path", &path(&inner)), ("remote", "other"), ("merge", "1")],
    );
    assert_eq!(r.status, 400);
    assert!(r.body.contains("overlap"), "{}", r.body);
}

/// Every thread of a running daemon yields to everything else, not just the
/// one that asked: the work is done on the threads started after it.
#[cfg(target_os = "linux")]
#[test]
fn every_thread_of_the_daemon_runs_behind_everything_else() {
    let w = world("background");
    let app = start(&w.dir);
    let tasks = format!("/proc/{}/task", app.child.id());
    let nice: Vec<i32> = fs::read_dir(tasks)
        .unwrap()
        .map(|task| {
            let stat = fs::read_to_string(task.unwrap().path().join("stat")).unwrap();
            let after_name = stat.rsplit(')').next().unwrap();
            after_name.split_whitespace().nth(16).unwrap().parse().unwrap()
        })
        .collect();
    assert!(nice.len() > 1, "{nice:?}");
    assert!(nice.iter().all(|n| *n >= 10), "{nice:?}");
}

#[test]
fn nothing_gets_in_without_the_key() {
    let w = world("gui-keys");
    let mut app = start(&w.dir.join("home"));

    assert_eq!(app.get("/").status, 401, "no cookie");
    assert_eq!(app.get("/setup").status, 401);
    assert_eq!(app.get("/open?key=wrong").status, 401);
    let r = app.get("/open?key=");
    assert_eq!(r.status, 401);
    assert!(!r.head.contains("Set-Cookie"));
    assert_eq!(app.post_with("/setup", "", "server=x").status, 401, "no cookie on a POST");

    app.sign_in();
    assert_eq!(app.get("/setup").status, 200);

    // DNS rebinding: a page on another name that now points here.
    let r = app.raw(&format!(
        "GET /setup HTTP/1.1\r\nHost: evil.example:{}\r\n{}Connection: close\r\n\r\n",
        app.port,
        app.cookie_line()
    ));
    assert_eq!(r.status, 403);

    // A form on another site, even if the cookie were sent.
    let csrf = app.get("/setup").body;
    let csrf = csrf.split("name=\"csrf\" value=\"").nth(1).unwrap().split('"').next().unwrap();
    let r = app.post_with(
        "/setup",
        "Origin: https://evil.example\r\n",
        &format!("csrf={csrf}&server=x"),
    );
    assert_eq!(r.status, 403);
    let r = app.post_with("/setup", "", "csrf=wrong&server=x");
    assert_eq!(r.status, 403, "no CSRF token");
    let r = app.post_with("/setup", "Origin: null\r\n", &format!("csrf={csrf}&server=x"));
    assert_eq!(r.status, 403, "a sandboxed frame sends this");

    // What a browser sends for the page's own form. It decides that from the
    // page's Referrer-Policy: no-referrer would make it `Origin: null`, and
    // refuse the whole wizard in every real browser.
    let policy = app.get("/setup");
    assert!(policy.head.contains("Referrer-Policy: same-origin"), "{}", policy.head);
    let own = format!("Origin: http://{}\r\n", app.host());
    let r = app.post_with("/setup", &own, &format!("csrf={csrf}&server=http://127.0.0.1:1"));
    assert_eq!(r.status, 400, "reaches the form, whose address is then refused: {}", r.body);
    assert!(r.body.contains("Could not reach that server"), "{}", r.body);

    // Scripts and outside content are refused by the browser.
    let page = app.get("/setup");
    assert!(page.head.contains("Content-Security-Policy: default-src 'none'"), "{}", page.head);
    assert!(page.head.contains("X-Frame-Options: DENY"));
    assert!(!page.body.contains("<script"));
}

#[test]
fn names_on_disk_cannot_write_into_the_page() {
    let w = world("gui-escape");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let name = if cfg!(windows) { "a&b'c" } else { "<img src=x>" };
    let bad = home.join("Pick").join(name);
    fs::create_dir_all(&bad).unwrap();
    let page = app.get(&format!("/folder?path={}", enc(home.join("Pick").to_str().unwrap()))).body;
    assert!(!page.contains(name), "{page}");
    assert!(page.contains(if cfg!(windows) { "a&amp;b&#39;c" } else { "&lt;img src=x&gt;" }));
}

#[test]
fn a_held_deletion_can_be_confirmed_from_the_page() {
    let w = world("gui-confirm");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    for i in 0..70 {
        fs::write(local.join(format!("{i}.txt")), format!("file {i}")).unwrap();
    }
    let r = app.post(
        "/folder",
        "/folder",
        &[("path", local.to_str().unwrap()), ("remote", ""), ("merge", "1")],
    );
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the files to upload", || on_server(&w, "69.txt"));
    for i in 0..70 {
        fs::remove_file(local.join(format!("{i}.txt"))).unwrap();
    }
    wait_for("the page to ask", || app.get("/").body.contains("I meant to do this"));
    assert!(on_server(&w, "5.txt"), "held back: nothing was deleted");
    let r = app.post("/", "/confirm", &[("path", local.to_str().unwrap())]);
    assert_eq!(r.status, 303);
    wait_for("the deletions to go through", || !on_server(&w, "5.txt"));
}

fn devices(w: &World) -> usize {
    w.app.store.read(|s| s.user("alice").unwrap().devices.len())
}

fn state_root(dir: &Path) -> PathBuf {
    if cfg!(windows) { dir.join("state/homedrive/state") } else { dir.join("state/homedrive") }
}

fn state_dirs(dir: &Path) -> usize {
    fs::read_dir(state_root(dir)).map_or(0, |d| d.flatten().filter(|e| e.path().is_dir()).count())
}

#[test]
fn removing_a_folder_deletes_nothing_and_cannot_turn_into_a_deletion() {
    let w = world("gui-remove");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    fs::write(local.join("keep.txt"), b"keep me").unwrap();
    let path = local.to_str().unwrap();
    let r = app.post("/folder", "/folder", &[("path", path), ("remote", ""), ("merge", "1")]);
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the file to upload", || on_server(&w, "keep.txt"));
    assert_eq!(state_dirs(&home), 1);

    let confirm = format!("/remove?path={}", enc(path));
    assert!(app.get(&confirm).body.contains("Nothing is deleted"));
    let asked = std::time::Instant::now();
    let r = app.post(&confirm, "/remove", &[("path", path)]);
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(asked.elapsed() < Duration::from_secs(10), "the folder's thread is woken to stop");
    assert_eq!(fs::read(local.join("keep.txt")).unwrap(), b"keep me", "the local file stays");
    assert!(on_server(&w, "keep.txt"), "the server's copy stays");
    assert!(!app.get("/").body.contains("Up to date"));
    wait_for("the sync state to go", || state_dirs(&home) == 0);

    // It really has stopped: a new file does not go up.
    fs::write(local.join("after.txt"), b"not synced").unwrap();
    std::thread::sleep(Duration::from_secs(4));
    assert!(!on_server(&w, "after.txt"));

    // The dangerous case: the local copy is deleted while the folder is not
    // synced, and it is added back. No record of the old sync means that is
    // not a deletion: the server's copy comes back, and stays on the server.
    fs::remove_file(local.join("keep.txt")).unwrap();
    let r = app.post("/folder", "/folder", &[("path", path), ("remote", ""), ("merge", "1")]);
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the file to return", || local.join("keep.txt").exists());
    assert_eq!(fs::read(local.join("keep.txt")).unwrap(), b"keep me");
    assert!(on_server(&w, "keep.txt"), "never deleted on the server");
    wait_for("the new file to upload", || on_server(&w, "after.txt"));
}

#[test]
fn signing_out_keeps_every_file_and_a_server_can_be_swapped() {
    let w = world("gui-signout");
    let other = world("gui-signout-other");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    fs::write(local.join("mine.txt"), b"my file").unwrap();
    let path = local.to_str().unwrap();
    let r = app.post("/folder", "/folder", &[("path", path), ("remote", ""), ("merge", "1")]);
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the file to upload", || on_server(&w, "mine.txt"));
    let before = devices(&w);

    let r = app.post("/signout", "/signout", &[]);
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(r.head.contains("Location: /setup"), "{}", r.head);
    assert!(!app.config.join("token").exists(), "the device token is gone");
    assert!(!app.config.join("device").exists());
    let saved = hd_api::parse(&fs::read(app.config.join("config.json")).unwrap()).unwrap();
    assert!(
        hd_api::get_array(&saved, "folders").unwrap().is_empty(),
        "no folder carries over: what it knows about one server means nothing on another"
    );
    assert_eq!(devices(&w), before - 1, "the device is revoked on the server");
    assert_eq!(fs::read(local.join("mine.txt")).unwrap(), b"my file");
    assert!(on_server(&w, "mine.txt"));
    wait_for("the sync state to go", || state_dirs(&home) == 0);
    assert_eq!(app.get("/").status, 303, "back at the wizard");

    // Another server, with the same folder: its empty drive must not look
    // like everything was deleted there.
    let r = app.post("/setup", "/setup", &[("server", &other.server), ("ca_file", "")]);
    assert_eq!(r.status, 303, "{}", r.body);
    let r = app.post(
        "/signin",
        "/signin",
        &[("user", "alice"), ("password", PW), ("device", "second")],
    );
    assert_eq!(r.status, 303, "{}", r.body);
    let r = app.post("/folder", "/folder", &[("path", path), ("remote", ""), ("merge", "1")]);
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the file to reach the new server", || on_server(&other, "mine.txt"));
    assert_eq!(fs::read(local.join("mine.txt")).unwrap(), b"my file");
    assert!(on_server(&w, "mine.txt"), "the old server is left as it was");
}

#[test]
fn signing_out_works_when_the_server_cannot_be_reached() {
    let w = world("gui-offline");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    // A device number that does not exist, standing in for a failed revoke.
    fs::write(app.config.join("device"), b"not a number").unwrap();
    let r = app.post("/signout", "/signout", &[]);
    assert_eq!(r.status, 303, "{}", r.body);
    assert!(!app.config.join("token").exists());
    assert!(app.get("/setup").body.contains("could not be removed from your account"));
}

#[test]
fn start_at_sign_in_is_chosen_in_the_wizard_and_on_the_page() {
    let w = world("gui-autostart");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    let path = local.to_str().unwrap();
    let wizard = app.get("/folder").body;
    assert!(wizard.contains("name=\"autostart\" value=\"1\" checked"), "on by default");
    let r = app.post("/folder", "/folder", &[("path", path), ("remote", ""), ("autostart", "1")]);
    assert_eq!(r.status, 303, "{}", r.body);
    wait_for("the page to say so", || {
        app.get("/").body.contains("homedrive starts when you sign in")
    });
    #[cfg(not(windows))]
    {
        let entry = home.join("config/autostart/homedrive.desktop");
        let text = fs::read_to_string(&entry).unwrap();
        assert!(text.contains(&format!("Exec=\"{}\" daemon", binary().display())), "{text}");
    }
    assert_eq!(app.post("/", "/autostart", &[("on", "0")]).status, 303);
    assert!(app.get("/").body.contains("homedrive does not start when you sign in"));
    #[cfg(not(windows))]
    assert!(!home.join("config/autostart/homedrive.desktop").exists());
    assert_eq!(app.post("/", "/autostart", &[("on", "1")]).status, 303);
    assert_eq!(app.post("/", "/autostart", &[("on", "0")]).status, 303);
}

#[test]
fn quit_ends_the_program_and_it_can_start_again_with_what_it_had() {
    let w = world("gui-quit");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    let path = local.to_str().unwrap();
    assert_eq!(app.post("/folder", "/folder", &[("path", path), ("remote", "")]).status, 303);
    let r = app.post("/", "/quit", &[]);
    assert_eq!(r.status, 200);
    assert!(r.body.contains("has quit"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while app.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "the program did not end");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(app.child.try_wait().unwrap().unwrap().success());

    let again = start(&home);
    fs::write(local.join("later.txt"), b"after a restart").unwrap();
    wait_for("the folder to resume", || on_server(&w, "later.txt"));
    drop(again);
}

#[test]
fn a_second_daemon_does_not_start() {
    let w = world("gui-single");
    let home = w.dir.join("home");
    let app = start(&home);
    let (config_home, state_home) = (home.join("config"), home.join("state"));
    let mut second = Command::new(binary())
        .arg("daemon")
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home)
        .env("APPDATA", &config_home)
        .env("LOCALAPPDATA", &state_home)
        .env("HOMEDRIVE_NO_BROWSER", "1")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A second daemon that wrongly starts never exits, so this cannot just wait.
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = second.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = second.kill();
            panic!("a second daemon started");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(!status.success());
    let mut said = String::new();
    second.stderr.take().unwrap().read_to_string(&mut said).unwrap();
    assert!(said.contains("already running"), "{said}");
    assert_eq!(app.get("/ping").body, "homedrive", "the first keeps running");
}

#[test]
fn a_crash_says_why() {
    let w = world("gui-crash");
    let state = w.dir.join("state");
    let out = Command::new(binary())
        .arg("test-crash-log")
        .env("XDG_STATE_HOME", &state)
        .env("LOCALAPPDATA", &state)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let log = if cfg!(windows) {
        state.join("homedrive/state/crash.log")
    } else {
        state.join("homedrive/crash.log")
    };
    let text = fs::read_to_string(&log).unwrap();
    assert!(text.contains("a test of the crash log"), "{text}");
    assert!(
        text.contains("bin/homedrive.rs") || text.contains("bin\\homedrive.rs"),
        "the location: {text}"
    );
    assert!(text.contains(hd_common::VERSION), "{text}");
}

#[test]
fn the_page_tells_a_sync_in_progress_from_an_old_result() {
    let w = world("gui-live");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    let path = local.to_str().unwrap();
    assert_eq!(app.post("/folder", "/folder", &[("path", path), ("remote", "")]).status, 303);
    wait_for("the first round", || app.get("/").body.contains("Up to date"));
    let r = app.post("/", "/quit", &[]);
    assert_eq!(r.status, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    while app.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }

    // A crashed run left errors behind, and there is a long round ahead.
    for e in fs::read_dir(state_root(&home)).unwrap().flatten().filter(|e| e.path().is_dir()) {
        fs::write(
            e.path().join("status.json"),
            r#"{"at_ms":1,"held_deletes":null,"held_changes":null,"suspicious":0,
               "ransomware_suspected":false,"repaired_local":[],"skipped":[],
               "errors":[{"path":"old.txt","why":"HTTP 429"}]}"#,
        )
        .unwrap();
    }
    for i in 0..800 {
        fs::write(local.join(format!("{i}.txt")), format!("file {i}")).unwrap();
    }
    app = start(&home);
    app.sign_in();
    let mut seen = String::new();
    wait_for("the round to show", || {
        seen = app.get("/").body;
        seen.contains("Syncing now")
    });
    assert!(seen.contains("From the last round to finish"), "{seen}");
    assert!(seen.contains("HTTP 429"), "{seen}");
    assert!(!seen.contains("Some files did not sync"), "not news: {seen}");
    assert!(!seen.contains("Up to date"), "{seen}");
    wait_for("the round to end", || app.get("/").body.contains("Up to date"));
    assert!(!app.get("/").body.contains("HTTP 429"), "the new result replaces the old");
}

#[test]
fn the_history_page_shows_what_synced_and_when() {
    let w = world("gui-history");
    let home = w.dir.join("home");
    let mut app = start(&home);
    app.sign_in();
    app.wizard_to_folder(&w);
    let local = home.join("Sync");
    fs::create_dir_all(&local).unwrap();
    let path = local.to_str().unwrap();
    assert_eq!(app.post("/folder", "/folder", &[("path", path), ("remote", "")]).status, 303);
    wait_for("the first round", || app.get("/").body.contains("Up to date"));
    assert!(app.get("/").body.contains("no changes yet"));
    assert!(app.get("/history").body.contains("Nothing has changed here yet"));

    let name = if cfg!(windows) { "a&b'c.txt" } else { "<img src=x>.txt" };
    fs::write(local.join(name), b"shown in the history").unwrap();
    wait_for("the upload", || on_server(&w, name));
    wait_for("the card to show the change", || app.get("/").body.contains("last change"));
    let page = app.get(&format!("/history?path={}", enc(path))).body;
    assert!(page.contains("Uploaded"), "{page}");
    assert!(!page.contains(name), "names are escaped: {page}");
    assert!(page.contains(if cfg!(windows) {
        "a&amp;b&#39;c.txt"
    } else {
        "&lt;img src=x&gt;.txt"
    }));
    assert!(page.contains(" UTC\""), "the time is on hover: {page}");

    fs::remove_file(local.join(name)).unwrap();
    wait_for("the deletion", || !on_server(&w, name));
    wait_for("the history to show it", || {
        app.get("/history").body.contains("Deleted on the server")
    });

    // It is kept across a restart.
    let r = app.post("/", "/quit", &[]);
    assert_eq!(r.status, 200);
    let deadline = Instant::now() + Duration::from_secs(10);
    while app.child.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(50));
    }
    app = start(&home);
    app.sign_in();
    let page = app.get("/history").body;
    assert!(page.contains("Uploaded") && page.contains("Deleted on the server"), "{page}");
}
