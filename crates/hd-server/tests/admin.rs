//! The admin socket, bulk import and verification, and exports.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use hd_api::{J, s};
use hd_server::App;
use hd_server::admin;
use hd_server::config::Config;
use hd_server::export::{self, Export};
use hd_store::model::Node;

fn setup(name: &str) -> (PathBuf, Arc<App>) {
    let dir = std::env::temp_dir().join(format!("hd-admin-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("users.json"),
        r#"{"version":1,"users":[{"name":"alice","password":"alice password","admin":true}]}"#,
    )
    .unwrap();
    hd_store::Store::init(&dir.join("store")).unwrap();
    let mut config = Config::for_test(dir.join("store"), dir.join("users.json"));
    config.export_dir = dir.join("exports");
    config.exports =
        vec![Export { user: "alice".into(), path: "Music".into(), name: "music".into() }];
    let app = Arc::new(App::open(config).unwrap());
    admin::start(&app).unwrap();
    (dir, app)
}

fn write(path: &std::path::Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

#[test]
fn import_over_the_socket_and_maintenance_commands() {
    let (dir, app) = setup("socket");
    let data_dir = dir.join("store");
    assert!(admin::server_running(&data_dir));
    let mode = fs::metadata(admin::socket_path(&data_dir)).unwrap();
    assert_eq!(mode.permissions().mode() & 0o777, 0o600);
    let body = vec![9_u8; 3_000_000];
    let req = J::O(vec![
        ("cmd", s("import")),
        ("user", s("alice")),
        ("path", s("backups/vault/db.tar.gz")),
    ]);
    let v = admin::call(&data_dir, &req, Some(&mut &body[..])).unwrap();
    assert!(!hd_api::get_bool(&v, "conflict").unwrap());
    let stored = app
        .store
        .read(|s| {
            s.user("alice").unwrap().get("backups/vault/db.tar.gz").unwrap().node.current().cloned()
        })
        .unwrap();
    assert_eq!(stored.size, 3_000_000);
    assert_eq!(stored.origin, hd_store::model::Origin::Import);
    // Unknown users and commands are refused.
    let bad = J::O(vec![("cmd", s("import")), ("user", s("mallory")), ("path", s("x"))]);
    assert!(
        admin::call(&data_dir, &bad, Some(&mut &b"x"[..]))
            .unwrap_err()
            .message()
            .contains("not in the users file")
    );
    assert!(admin::call(&data_dir, &J::O(vec![("cmd", s("rm-rf"))]), None).is_err());
    // Maintenance while the server runs.
    assert!(
        hd_api::get_u64(
            &admin::call(&data_dir, &J::O(vec![("cmd", s("checkpoint"))]), None).unwrap(),
            "seq"
        )
        .unwrap()
            > 0
    );
    let f = admin::call(&data_dir, &J::O(vec![("cmd", s("fsck")), ("deep", J::Bool(true))]), None)
        .unwrap();
    assert!(hd_api::get_array(&f, "problems").unwrap().is_empty());
    admin::call(&data_dir, &J::O(vec![("cmd", s("gc")), ("dry_run", J::Bool(true))]), None)
        .unwrap();
    admin::call(&data_dir, &J::O(vec![("cmd", s("scrub"))]), None).unwrap();
}

#[test]
fn import_tree_brings_old_versions_and_verify_tree_proves_it() {
    let (dir, app) = setup("tree");
    let data_dir = dir.join("store");
    let src = dir.join("old/files");
    let versions = dir.join("old/files_versions");
    write(&src.join("Documents/report.odt"), b"final");
    write(&versions.join("Documents/report.odt.v1600000000"), b"first draft");
    write(&versions.join("Documents/report.odt.v1650000000"), b"second draft");
    write(&src.join("Photos/a b/ü.jpg"), &vec![1_u8; 1_500_000]);
    write(&src.join("empty.txt"), b"");
    std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
    let mut log = Vec::new();
    let r = admin::import_tree(&data_dir, "alice", &src, "Imported", Some(&versions), &mut log)
        .unwrap();
    assert_eq!((r.imported, r.versions, r.unchanged), (3, 2, 0));
    assert_eq!(r.skipped, ["link"]);
    assert_eq!(String::from_utf8(log).unwrap().lines().count(), 3);
    let history = app.store.read(|s| {
        match &s.user("alice").unwrap().get("Imported/Documents/report.odt").unwrap().node {
            Node::File { versions, .. } => {
                versions.iter().map(|v| (v.size, v.created_ms)).collect::<Vec<_>>()
            }
            Node::Dir => Vec::new(),
        }
    });
    assert_eq!(history.len(), 3);
    assert_eq!(history[0], (11, 1_600_000_000_000), "old versions keep their dates, oldest first");
    assert_eq!(history[2].0, 5);
    // A second run changes nothing.
    let again =
        admin::import_tree(&data_dir, "alice", &src, "Imported", Some(&versions), &mut Vec::new())
            .unwrap();
    assert_eq!((again.imported, again.unchanged), (0, 3));
    // verify-tree: clean, then a changed source and a missing file show up.
    assert!(admin::verify_tree(&data_dir, "alice", &src, "Imported").unwrap().is_clean());
    write(&src.join("empty.txt"), b"changed after import");
    write(&src.join("new.txt"), b"never imported");
    let v = admin::verify_tree(&data_dir, "alice", &src, "Imported").unwrap();
    assert_eq!(v.mismatched, ["Imported/empty.txt"]);
    assert_eq!(v.missing, ["Imported/new.txt"]);
}

#[test]
fn exports_follow_the_drive() {
    let (dir, app) = setup("export");
    let data_dir = dir.join("store");
    let put = |path: &str, data: &[u8]| {
        let req = J::O(vec![("cmd", s("import")), ("user", s("alice")), ("path", s(path))]);
        admin::call(&data_dir, &req, Some(&mut &data[..])).unwrap();
    };
    put("Music/Artist/Album/01.flac", &vec![3_u8; 600_000]);
    put("Music/Artist/Album/cover.jpg", b"jpeg");
    put("Documents/private.txt", b"not exported");
    let e = &app.config.exports[0];
    let out = dir.join("exports");
    let r = export::reconcile(&app, e, &out).unwrap();
    assert_eq!(r.written, 2);
    assert_eq!(fs::read(out.join("music/Artist/Album/cover.jpg")).unwrap(), b"jpeg");
    assert!(!out.join("music/Documents").exists() && !out.join("Documents").exists());
    // Nothing to do the second time, even after a restart.
    assert_eq!(export::reconcile(&app, e, &out).unwrap(), export::ExportReport::default());
    // A change and a removal follow; files the export did not make stay.
    put("Music/Artist/Album/cover.jpg", b"better jpeg");
    write(&out.join("music/notes-by-hand.txt"), b"mine");
    app.store
        .commit(&hd_store::Op::Trash {
            user: "alice".into(),
            path: "Music/Artist/Album/01.flac".into(),
            deleted_ms: 0,
        })
        .unwrap();
    let r = export::reconcile(&app, e, &out).unwrap();
    assert_eq!((r.written, r.removed), (1, 1));
    assert_eq!(fs::read(out.join("music/Artist/Album/cover.jpg")).unwrap(), b"better jpeg");
    assert!(!out.join("music/Artist/Album/01.flac").exists());
    assert_eq!(fs::read(out.join("music/notes-by-hand.txt")).unwrap(), b"mine");
    // Deleting the whole export loses nothing: it is rebuilt.
    fs::remove_dir_all(out.join("music")).unwrap();
    assert_eq!(export::reconcile(&app, e, &out).unwrap().written, 1);
    // A file someone else put where the export wants to write is never
    // overwritten, and one someone changed after the export wrote it is
    // never replaced or removed.
    write(&out.join("music/Artist/Other/track.flac"), b"someone else's");
    put("Music/Artist/Other/track.flac", b"from the drive");
    write(&out.join("music/Artist/Album/cover.jpg"), b"edited in the export");
    put("Music/Artist/Album/cover.jpg", b"best jpeg");
    let r = export::reconcile(&app, e, &out).unwrap();
    assert_eq!((r.written, r.errors.len()), (0, 2), "{r:?}");
    assert_eq!(fs::read(out.join("music/Artist/Other/track.flac")).unwrap(), b"someone else's");
    assert_eq!(
        fs::read(out.join("music/Artist/Album/cover.jpg")).unwrap(),
        b"edited in the export"
    );
    app.store
        .commit(&hd_store::Op::Trash {
            user: "alice".into(),
            path: "Music/Artist/Album/cover.jpg".into(),
            deleted_ms: 0,
        })
        .unwrap();
    export::reconcile(&app, e, &out).unwrap();
    assert_eq!(
        fs::read(out.join("music/Artist/Album/cover.jpg")).unwrap(),
        b"edited in the export"
    );
    // A lost record costs nothing: files already right are adopted, not
    // rewritten, and the next round has nothing to do.
    fs::remove_file(out.join(".homedrive-music")).unwrap();
    fs::remove_file(out.join("music/Artist/Other/track.flac")).unwrap();
    let r = export::reconcile(&app, e, &out).unwrap();
    assert_eq!((r.written, r.adopted), (1, 0), "{r:?}");
    fs::remove_file(out.join(".homedrive-music")).unwrap();
    let r = export::reconcile(&app, e, &out).unwrap();
    assert_eq!((r.written, r.adopted, r.errors.len()), (0, 1, 0), "{r:?}");
    assert_eq!(export::reconcile(&app, e, &out).unwrap(), export::ExportReport::default());
}

/// Scrub only re-reads objects that exist. An object that vanished (a bad
/// disk, a mistaken delete, an incomplete restore) is found by the
/// reference check maintenance runs after every collection.
#[test]
fn the_reference_check_finds_a_vanished_chunk() {
    fn files(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() { files(&p, out) } else { out.push(p) }
        }
    }
    let (dir, app) = setup("check");
    let data_dir = dir.join("store");
    let req = J::O(vec![("cmd", s("import")), ("user", s("alice")), ("path", s("a.bin"))]);
    admin::call(&data_dir, &req, Some(&mut &vec![9_u8; 100_000][..])).unwrap();
    hd_server::maintenance::check_references(&app);
    assert_eq!(app.maintenance.snapshot().damaged_versions, 0);
    let mut chunks = Vec::new();
    files(&data_dir.join("chunks"), &mut chunks);
    let victim = chunks.iter().find(|p| fs::metadata(p).unwrap().len() > 50_000).unwrap();
    fs::set_permissions(victim, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(victim).unwrap();
    hd_server::maintenance::check_references(&app);
    let status = app.maintenance.snapshot();
    assert_eq!(status.damaged_versions, 1);
    assert!(status.check.unwrap().1.contains("cannot be read"));
}

/// `hd-server repair` through the running server's socket: an object set
/// aside after a read the disk once failed comes back from quarantine,
/// and the damage report clears.
#[test]
fn repair_over_the_socket_restores_from_quarantine() {
    let (dir, app) = setup("repair");
    let data_dir = dir.join("store");
    let req = J::O(vec![("cmd", s("import")), ("user", s("alice")), ("path", s("a.bin"))]);
    admin::call(&data_dir, &req, Some(&mut &vec![5_u8; 100_000][..])).unwrap();
    let manifest = app.store.read(|st| {
        st.user("alice").unwrap().get("a.bin").unwrap().node.current().unwrap().manifest
    });
    app.store
        .objects()
        .quarantine(hd_store::objects::Kind::Manifest, &manifest, "test: unreadable")
        .unwrap();
    hd_server::maintenance::check_references(&app);
    assert_eq!(app.maintenance.snapshot().damaged_current.len(), 1);
    let v = admin::call(&data_dir, &J::O(vec![("cmd", s("repair")), ("from", J::A(vec![]))]), None)
        .unwrap();
    assert_eq!(hd_api::get_u64(&v, "restored").unwrap(), 1);
    assert!(hd_api::get_array(&v, "still_damaged").unwrap().is_empty());
    assert_eq!(app.maintenance.snapshot().damaged_versions, 0);
    assert!(app.store.fsck(true).unwrap().is_clean());
}
