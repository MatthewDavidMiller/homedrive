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
        r#"{"version":1,"users":[{"name":"alice","password":"alice password","admin":true,"quota_gb":10}]}"#,
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
    // verify-tree: the link was never stored, so the tree is not clean
    // until it is accepted (the source must not be retired with it).
    let v = admin::verify_tree(&data_dir, "alice", &src, "Imported").unwrap();
    assert_eq!(v.skipped, ["link"]);
    assert!(!v.is_clean() && v.is_clean_accepting_skipped());
    std::fs::remove_file(src.join("link")).unwrap();
    assert!(admin::verify_tree(&data_dir, "alice", &src, "Imported").unwrap().is_clean());
    // A changed source and a missing file show up.
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

/// Copies a store the way a file-level backup does: every regular file,
/// without the history identity (and the socket, which is not a file).
fn copy_store(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let t = e.file_type().unwrap();
        let target = to.join(e.file_name());
        if t.is_dir() {
            copy_store(&e.path(), &target);
        } else if t.is_file() && e.file_name() != "history.id" {
            fs::copy(e.path(), &target).unwrap();
        }
    }
}

/// The whole chain: a backup copy of the store is restored to plain files,
/// every one verified, and compared with the live drive, which has moved
/// on since. Holes in a backup are found.
#[test]
fn a_backup_restores_to_plain_files_and_the_drill_proves_it() {
    let (dir, app) = setup("drill");
    let data_dir = dir.join("store");
    let put = |path: &str, data: &[u8], executable: bool| {
        let p = hd_store::Provenance {
            device: "laptop".into(),
            mtime_ms: 1_600_000_000_000,
            origin: hd_store::model::Origin::Upload,
            created_ms: None,
            executable: Some(executable),
        };
        app.store.write_file("alice", path, hd_store::Base::Any, data, 1 << 30, &p).unwrap();
    };
    put("docs/a.txt", b"first", false);
    put("bin/run.sh", b"#!/bin/sh\n", true);
    put("photos/p.jpg", &vec![7_u8; 2_000_000], false);
    app.store
        .commit(&hd_store::model::Op::Mkdir { user: "alice".into(), path: "empty".into() })
        .unwrap();
    app.store.checkpoint().unwrap();
    copy_store(&data_dir, &dir.join("backup"));
    std::thread::sleep(std::time::Duration::from_millis(5));
    // Life goes on after the backup.
    put("docs/a.txt", b"second", false);
    put("new.txt", b"made after the backup", false);
    app.store
        .commit(&hd_store::model::Op::Move {
            user: "alice".into(),
            from: "photos".into(),
            to: "pictures".into(),
        })
        .unwrap();

    // The drill, on the backup copy.
    let backup =
        hd_store::Store::open(&dir.join("backup"), &hd_store::StoreOptions::default()).unwrap();
    let out = dir.join("drill");
    let r = hd_server::drill::drill(&backup, &out).unwrap();
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.users, vec![("alice".to_owned(), 3, 2_000_000 + 5 + 10)]);
    assert_eq!(fs::read(out.join("alice/docs/a.txt")).unwrap(), b"first");
    assert!(out.join("alice/empty").is_dir());
    let mode = fs::metadata(out.join("alice/bin/run.sh")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700, "a program comes back executable");
    assert_eq!(
        fs::metadata(out.join("alice/docs/a.txt")).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The manifest is what sha256sum -c reads.
    let manifest = fs::read_to_string(out.join("alice.sha256")).unwrap();
    assert_eq!(manifest.lines().count(), 3);
    let a_line = manifest.lines().find(|l| l.ends_with("  docs/a.txt")).unwrap();
    assert_eq!(&a_line[..64], hd_api::hex(&hd_crypto::sha256(b"first").unwrap()));
    // Restoring never overwrites.
    assert!(
        hd_server::drill::restore_tree(&backup, "alice", "", &out.join("alice"), &dir.join("m"))
            .is_err()
    );

    // Compared with the live drive (through the socket, as the drill
    // script does): clean, although a file moved and another changed.
    let compare = |text: &str| {
        let req = J::O(vec![
            ("cmd", s("drill-compare")),
            ("user", s("alice")),
            ("taken_ms", J::I(r.taken_ms)),
        ]);
        admin::call(&data_dir, &req, Some(&mut text.as_bytes())).unwrap()
    };
    let v = compare(&manifest);
    assert!(hd_api::get_array(&v, "missing").unwrap().is_empty(), "{v:?}");
    assert!(hd_api::get_array(&v, "unknown").unwrap().is_empty(), "{v:?}");
    // A backup missing a file, or holding content the drive never had,
    // fails.
    let holed: String =
        manifest.lines().filter(|l| !l.contains("run.sh")).fold(String::new(), |mut out, l| {
            out.push_str(l);
            out.push('\n');
            out
        });
    let v = compare(&holed);
    assert_eq!(hd_api::get_array(&v, "missing").unwrap()[0].as_str(), Some("bin/run.sh"));
    let forged = format!("{manifest}{}  forged.bin\n", "ab".repeat(32));
    let v = compare(&forged);
    assert_eq!(hd_api::get_array(&v, "unknown").unwrap()[0].as_str(), Some("forged.bin"));

    // Results are reported, and a failure reaches the admins.
    let report = |kind: &str, ok: bool| {
        let req = J::O(vec![
            ("cmd", s("report")),
            ("kind", s(kind)),
            ("ok", J::Bool(ok)),
            ("message", s("test run")),
        ]);
        admin::call(&data_dir, &req, None).unwrap();
    };
    report("drill", true);
    assert!(app.admin_problems().is_empty(), "{:?}", app.admin_problems());
    report("local", false);
    assert!(app.admin_problems().iter().any(|p| p.contains("local backup failed")));
    assert!(app.problems_for("alice").iter().any(|p| p.contains("local backup failed")));
    // A failed import (a backup that did not land) does too.
    let bad = J::O(vec![("cmd", s("import")), ("user", s("alice")), ("path", s("../escape"))]);
    assert!(admin::call(&data_dir, &bad, Some(&mut &b"x"[..])).is_err());
    assert!(app.admin_problems().iter().any(|p| p.contains("import(s) failed")));
}
