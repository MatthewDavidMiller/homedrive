//! What only real Windows and NTFS can show: names the filesystem folds or
//! rewrites, files other programs hold open, alternate data streams, and
//! paths past the old 260-character limit. Run by `scripts/test-windows.sh`.

#![cfg(windows)]
#![allow(
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use common::{World, kept, trashed, world};
use hd_store::model::Origin;
use hd_store::{Base, Provenance};

fn server_put(w: &World, path: &str, data: &[u8]) {
    let by = Provenance {
        device: "elsewhere".into(),
        mtime_ms: 1_700_000_000_000,
        origin: Origin::Upload,
        created_ms: None,
        executable: None,
    };
    w.app.store.write_file("alice", path, Base::Any, data, 1 << 30, &by).unwrap();
}

fn server_sha(w: &World, path: &str) -> Option<Vec<u8>> {
    let sha = w.app.store.read(|s| {
        s.user("alice").unwrap().entries.get(path).and_then(|e| match &e.node {
            hd_store::model::Node::File { versions, .. } => versions.last().map(|v| v.sha256),
            hd_store::model::Node::Dir => None,
        })
    })?;
    Some(sha.to_vec())
}

/// Sends one WebDAV request with extra header lines; returns the status line.
fn dav(w: &World, method: &str, path: &str, headers: &str) -> String {
    let auth = hd_common::base64::encode(format!("alice:{}", common::PW).as_bytes());
    let addr = w.server.trim_start_matches("http://");
    let mut conn = TcpStream::connect(addr).unwrap();
    write!(
        conn,
        "{method} /dav/alice/{path} HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Basic {auth}\r\n\
         {headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    reply.lines().next().unwrap_or_default().to_owned()
}

fn sha(data: &[u8]) -> Vec<u8> {
    hd_crypto::sha256(data).unwrap().to_vec()
}

/// A path over the 260-character limit, as a client-relative name.
fn long_rel() -> String {
    let step = "d".repeat(70);
    format!("{step}/{step}/{step}/{step}/file.txt")
}

/// `path` in the form that reaches any file, whatever its name or length.
fn verbatim(path: &Path) -> PathBuf {
    let text = path.to_str().unwrap().replace('/', "\\");
    PathBuf::from(format!(r"\\?\{text}"))
}

/// A scan reads a file's stamp with one open, where it used two. Every field
/// must come out as it did, or the first scan after an update would see all
/// of a drive as changed and hash it again.
#[test]
fn a_look_finds_what_the_long_way_finds() {
    use hd_client::scan::LocalEntry;
    let w = world("look");
    let dir = w.dir.join("look");
    fs::create_dir_all(dir.join("folder")).unwrap();
    fs::write(dir.join("plain.txt"), b"plain").unwrap();
    fs::write(dir.join("empty"), b"").unwrap();
    fs::write(dir.join("read only.txt"), b"read only").unwrap();
    let mut read_only = fs::metadata(dir.join("read only.txt")).unwrap().permissions();
    read_only.set_readonly(true);
    fs::set_permissions(dir.join("read only.txt"), read_only).unwrap();
    let old = fs::File::options().write(true).open(dir.join("empty")).unwrap();
    let before_1970 = std::time::UNIX_EPOCH - std::time::Duration::from_hours(24);
    old.set_modified(before_1970).unwrap();
    drop(old);
    let long = verbatim(&dir.join(long_rel()));
    fs::create_dir_all(long.parent().unwrap()).unwrap();
    fs::write(&long, b"far down").unwrap();
    let paths = [
        dir.join("folder"),
        dir.join("plain.txt"),
        dir.join("empty"),
        dir.join("read only.txt"),
        long,
        dir.clone(),
    ];
    for path in paths {
        let meta = fs::symlink_metadata(&path).unwrap();
        let look = LocalEntry::look(&path).unwrap();
        assert_eq!(look.entry, LocalEntry::of(&meta, &path), "{}", path.display());
        assert_eq!(look.is_dir, meta.is_dir());
        assert!(!look.is_symlink);
    }
    assert_eq!(
        LocalEntry::look(&dir.join("not there")).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
}

#[test]
fn folders_differing_in_case_are_never_merged() {
    let w = world("win-case-folders");
    let mut a = w.client("a", "");
    server_put(&w, "CaseDir/a.txt", b"A");
    server_put(&w, "casedir/b.txt", b"B");
    let r = a.sync(0).unwrap();
    for p in ["CaseDir", "casedir", "CaseDir/a.txt", "casedir/b.txt"] {
        assert!(r.skipped.iter().any(|(s, _)| s == p), "{p} reported: {r:?}");
    }
    assert!(!w.path("a", "CaseDir").exists(), "neither folder is made");
}

#[test]
fn names_differing_in_case_beyond_ascii_are_reported_and_left_alone() {
    let w = world("win-case-unicode");
    let mut a = w.client("a", "");
    server_put(&w, "RÉSUMÉ.txt", b"upper");
    server_put(&w, "résumé.txt", b"lower");
    let r = a.sync(0).unwrap();
    assert!(r.skipped.iter().any(|(s, _)| s == "RÉSUMÉ.txt"), "{r:?}");
    assert!(r.skipped.iter().any(|(s, _)| s == "résumé.txt"), "{r:?}");
    assert!(!w.path("a", "résumé.txt").exists());
    assert_eq!(server_sha(&w, "RÉSUMÉ.txt"), Some(sha(b"upper")));
    assert_eq!(server_sha(&w, "résumé.txt"), Some(sha(b"lower")));
}

#[test]
fn a_local_rename_of_letter_case_keeps_syncing() {
    let w = world("win-case-rename");
    let mut a = w.client("a", "");
    w.write("a", "docs/report.txt", b"v1");
    a.sync(0).unwrap();
    // Through a temporary name, so the rename really happens.
    fs::rename(w.path("a", "docs"), w.path("a", "tmp")).unwrap();
    fs::rename(w.path("a", "tmp"), w.path("a", "DOCS")).unwrap();
    fs::rename(w.path("a", "DOCS/report.txt"), w.path("a", "DOCS/tmp")).unwrap();
    fs::rename(w.path("a", "DOCS/tmp"), w.path("a", "DOCS/REPORT.txt")).unwrap();
    let r = a.sync(0).unwrap();
    assert!(r.skipped.is_empty() && r.deleted_remote.is_empty(), "{r:?}");
    assert!(w.app.store.read(|s| s.user("alice").unwrap().trash.is_empty()));
    // Edits, and new files in the renamed folder, still go up.
    w.write("a", "DOCS/REPORT.txt", b"v2 is longer");
    w.write("a", "DOCS/new.txt", b"new");
    let r = a.sync(0).unwrap();
    assert!(r.skipped.is_empty(), "{r:?}");
    assert_eq!(server_sha(&w, "docs/report.txt"), Some(sha(b"v2 is longer")));
    assert_eq!(server_sha(&w, "docs/new.txt"), Some(sha(b"new")));
    // And changes come back down onto the renamed file.
    server_put(&w, "docs/report.txt", b"from elsewhere");
    a.sync(0).unwrap();
    assert_eq!(fs::read(w.path("a", "DOCS/REPORT.txt")).unwrap(), b"from elsewhere");
}

#[test]
fn a_rename_of_letter_case_elsewhere_loses_nothing() {
    let w = world("win-case-remote");
    let mut a = w.client("a", "");
    w.write("a", "name.txt", b"content");
    a.sync(0).unwrap();
    let destination = format!("Destination: {}/dav/alice/NAME.txt\r\n", w.server);
    assert!(dav(&w, "MOVE", "name.txt", &destination).contains(" 201"));
    let r = a.sync(0).unwrap();
    assert!(r.skipped.is_empty() && r.deleted_local.is_empty(), "{r:?}");
    assert_eq!(server_sha(&w, "NAME.txt"), Some(sha(b"content")));
    assert_eq!(fs::read(w.path("a", "NAME.txt")).unwrap(), b"content");
    // The new spelling is tracked: an edit lands on it.
    w.write("a", "NAME.txt", b"edited after");
    a.sync(0).unwrap();
    assert_eq!(server_sha(&w, "NAME.txt"), Some(sha(b"edited after")));
    assert!(w.app.store.read(|s| !s.user("alice").unwrap().entries.contains_key("name.txt")));
}

#[test]
fn names_win32_rewrites_are_reported_not_skipped_silently() {
    let w = world("win-dots");
    let mut a = w.client("a", "");
    let root = w.path("a", "");
    fs::write(verbatim(&root.join("trailing.")), b"dot").unwrap();
    fs::write(verbatim(&root.join("space ")), b"space").unwrap();
    fs::write(verbatim(&root.join("NUL")), b"device").unwrap();
    let r = a.sync(0).unwrap();
    for name in ["trailing.", "space ", "NUL"] {
        assert!(r.skipped.iter().any(|(p, _)| p == name), "{name}: {r:?}");
        assert_eq!(server_sha(&w, name), None);
        fs::remove_file(verbatim(&root.join(name))).unwrap();
    }
}

#[test]
fn long_paths_sync_both_ways_and_use_the_trash() {
    let w = world("win-long");
    let rel = long_rel();
    let mut a = w.client("a", "");
    let path = w.path("a", &rel);
    assert!(path.as_os_str().len() > 300);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"local").unwrap();
    a.sync(0).unwrap();
    assert_eq!(server_sha(&w, &rel), Some(sha(b"local")));
    server_put(&w, &rel, b"remote");
    a.sync(0).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"remote");
    assert!(
        !kept(&w.path("a", "")).iter().any(|d| d == b"local"),
        "a file with no streams expires like any other"
    );
    assert!(trashed(&w.path("a", "")).iter().any(|d| d == b"local"));
}

#[test]
fn a_locked_file_waits_and_is_never_lost() {
    let w = world("win-locked");
    let mut a = w.client("a", "");
    w.write("a", "busy.txt", b"v1");
    w.write("a", "gone.txt", b"gone");
    a.sync(0).unwrap();
    server_put(&w, "busy.txt", b"v2 from elsewhere");
    assert!(dav(&w, "DELETE", "gone.txt", "").contains(" 204"));
    let open = |rel: &str| {
        fs::OpenOptions::new().read(true).write(true).share_mode(0).open(w.path("a", rel)).unwrap()
    };
    let (busy, gone) = (open("busy.txt"), open("gone.txt"));
    let r = a.sync(0).unwrap();
    assert_eq!(r.errors.len(), 2, "{r:?}");
    drop((busy, gone));
    assert_eq!(fs::read(w.path("a", "busy.txt")).unwrap(), b"v1");
    a.sync(0).unwrap();
    assert_eq!(fs::read(w.path("a", "busy.txt")).unwrap(), b"v2 from elsewhere");
    assert!(!w.path("a", "gone.txt").exists());
    assert!(trashed(&w.path("a", "")).iter().any(|d| d == b"gone"));
}

#[test]
fn a_new_locked_file_goes_up_once_it_is_free() {
    let w = world("win-locked-new");
    let mut a = w.client("a", "");
    w.write("a", "new.txt", b"new");
    let held =
        fs::OpenOptions::new().read(true).share_mode(0).open(w.path("a", "new.txt")).unwrap();
    let r = a.sync(0).unwrap();
    assert_eq!(r.errors.len(), 1, "{r:?}");
    drop(held);
    a.sync(0).unwrap();
    assert_eq!(server_sha(&w, "new.txt"), Some(sha(b"new")));
}

#[test]
fn a_read_only_file_is_replaced_and_deleted_through_the_trash() {
    let w = world("win-read-only");
    let mut a = w.client("a", "");
    w.write("a", "ro.txt", b"ro");
    a.sync(0).unwrap();
    let path = w.path("a", "ro.txt");
    let mut p = fs::metadata(&path).unwrap().permissions();
    p.set_readonly(true);
    fs::set_permissions(&path, p).unwrap();
    server_put(&w, "ro.txt", b"ro v2");
    a.sync(0).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"ro v2");
    assert!(trashed(&w.path("a", "")).iter().any(|d| d == b"ro"));
}

#[test]
fn alternate_data_streams_survive_a_replacement() {
    let w = world("win-streams");
    let mut a = w.client("a", "");
    w.write("a", "f.txt", b"v1");
    a.sync(0).unwrap();
    let path = w.path("a", "f.txt");
    let stream = PathBuf::from(format!("{}:notes", path.display()));
    fs::write(&stream, b"only here").unwrap();
    server_put(&w, "f.txt", b"v2 from elsewhere");
    a.sync(0).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"v2 from elsewhere");
    assert_eq!(fs::read(&stream).unwrap(), b"only here", "the new file keeps the stream");
    assert!(kept(&w.path("a", "")).iter().any(|d| d == b"v1"), "and the old one is kept");
}

#[test]
fn the_download_mark_alone_does_not_keep_a_file_forever() {
    let w = world("win-zone");
    let mut a = w.client("a", "");
    w.write("a", "f.txt", b"v1");
    a.sync(0).unwrap();
    let path = w.path("a", "f.txt");
    fs::write(format!("{}:Zone.Identifier", path.display()), b"[ZoneTransfer]").unwrap();
    server_put(&w, "f.txt", b"v2 from elsewhere");
    a.sync(0).unwrap();
    assert!(trashed(&w.path("a", "")).iter().any(|d| d == b"v1"));
    assert!(!kept(&w.path("a", "")).iter().any(|d| d == b"v1"));
}

#[test]
fn a_junction_is_not_followed() {
    let w = world("win-junction");
    let mut a = w.client("a", "");
    let outside = w.dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("private.txt"), b"private").unwrap();
    let made = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(w.path("a", "junction"))
        .arg(&outside)
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
    let r = a.sync(0).unwrap();
    assert!(r.skipped.iter().any(|(p, _)| p == "junction"), "{r:?}");
    assert_eq!(server_sha(&w, "junction/private.txt"), None);
    assert!(outside.join("private.txt").exists());
}

#[test]
fn the_stamp_sees_what_the_modification_time_hides() {
    let w = world("win-stamp");
    let path = w.dir.join("f.txt");
    fs::write(&path, b"one").unwrap();
    let before = hd_sys::windows::file_stamp(&path).unwrap();
    assert_ne!(before.change_ns, 0);
    assert_ne!(before.index, 0);
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
    std::io::Write::write_all(&mut &f, b"two").unwrap();
    f.set_modified(modified).unwrap();
    f.sync_all().unwrap();
    drop(f);
    let after = hd_sys::windows::file_stamp(&path).unwrap();
    assert_ne!(before.change_ns, after.change_ns);
    assert_eq!(before.index, after.index);
    // Attributes can be read even when another program holds the file.
    let held = fs::OpenOptions::new().read(true).share_mode(0).open(&path).unwrap();
    assert_eq!(hd_sys::windows::file_stamp(&path).unwrap(), after);
    drop(held);
}

#[test]
fn a_rename_never_replaces_and_reaches_long_paths() {
    let w = world("win-rename");
    let long = w.dir.join("x".repeat(120)).join("y".repeat(120)).join("z".repeat(40));
    fs::create_dir_all(&long).unwrap();
    let (from, to) = (long.join("from"), long.join("to"));
    fs::write(&from, b"from").unwrap();
    fs::write(&to, b"to").unwrap();
    let err = hd_sys::windows::rename_noreplace(&from, &to).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists, "{err}");
    assert_eq!(fs::read(&to).unwrap(), b"to");
    fs::remove_file(&to).unwrap();
    hd_sys::windows::rename_noreplace(&from, &to).unwrap();
    assert_eq!(fs::read(&to).unwrap(), b"from");
    assert!(hd_sys::windows::alternate_streams(&to).unwrap().is_empty());
}

#[test]
fn a_daemon_with_no_console_keeps_working_and_logs() {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x10;
    let w = world("win-detached");
    let (config_home, state_home) = (w.dir.join("config"), w.dir.join("state"));
    let config_dir = config_home.join("homedrive");
    fs::create_dir_all(&config_dir).unwrap();
    let local = w.path("drive", "");
    hd_client::engine::Engine::mark_root(&local).unwrap();
    hd_client::config::save_token(&config_dir, &w.token).unwrap();
    hd_client::config::Config {
        server: w.server.clone(),
        user: "alice".into(),
        ca_file: None,
        folders: vec![hd_client::config::FolderConfig {
            local: local.clone(),
            remote: String::new(),
            ignore: Vec::new(),
        }],
    }
    .save(&config_dir)
    .unwrap();
    fs::write(local.join("first.txt"), b"reported").unwrap();
    // A console of its own, as a program started from Explorer has.
    let mut child = std::process::Command::new(
        std::env::current_exe().unwrap().with_file_name("homedrive.exe"),
    )
    .arg("daemon")
    .env("APPDATA", &config_home)
    .env("LOCALAPPDATA", &state_home)
    .env("HOMEDRIVE_NO_BROWSER", "1")
    .creation_flags(CREATE_NEW_CONSOLE)
    .spawn()
    .unwrap();
    let log = state_home.join("homedrive/state/daemon.log");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut text = String::new();
    while !text.contains("1 up") {
        assert!(child.try_wait().unwrap().is_none(), "the daemon died: {text}");
        assert!(std::time::Instant::now() < deadline, "no report in the log: {text}");
        std::thread::sleep(std::time::Duration::from_millis(100));
        text = fs::read_to_string(&log).unwrap_or_default();
    }
    let _ = child.kill();
    let _ = child.wait();
}
