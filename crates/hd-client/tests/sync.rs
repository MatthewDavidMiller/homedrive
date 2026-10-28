//! Two clients and a server, end to end over loopback HTTP.
//!
//! The randomized test checks the client's whole reason for being careful.
//! After any mix of edits, deletes, renames, and syncs on two machines,
//! every content that was on disk when a sync looked at it still exists
//! somewhere: as a file, a version on the server, a conflict copy, or in a
//! trash. (Content the user overwrote or deleted before any sync saw it was
//! never the sync's to keep.)

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hd_client::engine::{Engine, Folder, Moment, Options};
use hd_client::remote::Remote;
use hd_server::App;
use hd_server::config::Config;

const PW: &str = "alice password";

struct World {
    dir: PathBuf,
    server: String,
    token: String,
    app: Arc<App>,
}

fn world(name: &str) -> World {
    let dir = std::env::temp_dir().join(format!("hd-client-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let users = dir.join("users.json");
    fs::write(
        &users,
        format!(r#"{{"version":1,"users":[{{"name":"alice","password":"{PW}","admin":true}}]}}"#),
    )
    .unwrap();
    let data = dir.join("store");
    hd_store::Store::init(&data).unwrap();
    let (app, server) = serve(&data, &users);
    let token = Remote::register(&server, None, "alice", PW, "test").unwrap().token;
    World { dir, server, token, app }
}

/// Opens the store at `data` and serves it on a new port.
fn serve(data: &Path, users: &Path) -> (Arc<App>, String) {
    let app = Arc::new(App::open(Config::for_test(data.to_owned(), users.to_owned())).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::clone(&app);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &served))
        .unwrap();
    (app, format!("http://{addr}"))
}

impl World {
    fn client(&self, name: &str, remote: &str) -> Engine {
        let local = self.dir.join(name);
        if !local.join(hd_client::scan::SENTINEL).exists() {
            Engine::mark_root(&local).unwrap();
        }
        self.reopen(name, remote, Options::default())
    }

    fn reopen(&self, name: &str, remote: &str, options: Options) -> Engine {
        let folder = Folder {
            local: self.dir.join(name),
            remote: remote.to_owned(),
            ignore: vec!["*.ignored".into()],
            state_dir: self.dir.join(format!("{name}-state")),
        };
        Engine::open(folder, Remote::new(&self.server, None, &self.token).unwrap(), options)
            .unwrap()
    }

    fn path(&self, client: &str, rel: &str) -> PathBuf {
        self.dir.join(client).join(rel)
    }

    fn write(&self, client: &str, rel: &str, data: &[u8]) {
        let p = self.path(client, rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }
}

/// Every synced file under a folder, by relative path.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
        let mut names: Vec<_> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        for n in names {
            let n = n.to_str().unwrap().to_owned();
            if n == ".homedrive" || n == ".homedrive-root" {
                continue;
            }
            let child = if rel.is_empty() { n.clone() } else { format!("{rel}/{n}") };
            let p = dir.join(&n);
            if p.is_dir() {
                out.insert(format!("{child}/"), Vec::new());
                walk(&p, &child, out);
            } else {
                out.insert(child, fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, "", &mut out);
    out
}

/// Every content in a folder's client trash.
fn trashed(root: &Path) -> Vec<Vec<u8>> {
    fn walk(dir: &Path, out: &mut Vec<Vec<u8>>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries {
                let p = e.unwrap().path();
                if p.is_dir() { walk(&p, out) } else { out.push(fs::read(&p).unwrap()) }
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join(".homedrive/trash"), &mut out);
    out
}

#[test]
fn files_travel_both_ways_and_old_content_is_kept() {
    let w = world("basic");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "docs/report.txt", b"draft 1");
    w.write("a", "photos/cat.jpg", &vec![7_u8; 2_000_000]);
    w.write("a", "empty", b"");
    w.write("a", "skip.ignored", b"not synced");
    fs::create_dir_all(w.path("a", "empty-folder")).unwrap();
    let r = a.sync(0).unwrap();
    assert_eq!(r.uploaded.len(), 3, "{r:?}");
    b.sync(0).unwrap();
    let mut expected = tree(&w.dir.join("a"));
    expected.remove("skip.ignored");
    assert_eq!(tree(&w.dir.join("b")), expected);
    // Edit on b; a's old copy goes to a's trash when it updates.
    w.write("b", "docs/report.txt", b"draft 2");
    b.sync(0).unwrap();
    let r = a.sync(0).unwrap();
    assert_eq!(r.downloaded, ["docs/report.txt"]);
    assert_eq!(fs::read(w.path("a", "docs/report.txt")).unwrap(), b"draft 2");
    assert!(trashed(&w.dir.join("a")).contains(&b"draft 1".to_vec()));
    // Delete on a: the server trashes it, and b moves its copy to its trash.
    fs::remove_file(w.path("a", "photos/cat.jpg")).unwrap();
    assert_eq!(a.sync(0).unwrap().deleted_remote, ["photos/cat.jpg"]);
    assert_eq!(b.sync(0).unwrap().deleted_local, ["photos/cat.jpg"]);
    assert!(!w.path("b", "photos/cat.jpg").exists());
    assert!(trashed(&w.dir.join("b")).iter().any(|t| t.len() == 2_000_000));
    // A deleted folder follows.
    fs::remove_dir(w.path("a", "empty-folder")).unwrap();
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    assert!(!w.path("b", "empty-folder").exists());
    // Nothing more to do on either side.
    assert!(!a.sync(0).unwrap().changed_anything());
    assert!(!b.sync(0).unwrap().changed_anything());
}

#[test]
fn concurrent_edits_keep_both_copies() {
    let w = world("conflict");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "notes.md", b"base");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    w.write("a", "notes.md", b"from a");
    w.write("b", "notes.md", b"from b");
    a.sync(0).unwrap();
    let r = b.sync(0).unwrap();
    assert_eq!(r.conflicts.len(), 1, "{r:?}");
    let conflict = r.conflicts[0].clone();
    assert!(conflict.starts_with("notes (conflict test "), "{conflict}");
    // b now has a's edit under the name and its own as the conflict copy.
    b.sync(0).unwrap();
    assert_eq!(fs::read(w.path("b", "notes.md")).unwrap(), b"from a");
    assert_eq!(fs::read(w.path("b", &conflict)).unwrap(), b"from b");
    a.sync(0).unwrap();
    assert_eq!(tree(&w.dir.join("a")), tree(&w.dir.join("b")));
    // The same file created on both sides independently, identically:
    // adopted, no conflict.
    w.write("a", "same.txt", b"identical");
    w.write("b", "same.txt", b"identical");
    a.sync(0).unwrap();
    assert!(b.sync(0).unwrap().conflicts.is_empty());
    // An edit on one side and a delete on the other: the edit wins.
    w.write("a", "keep.txt", b"v1");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    fs::remove_file(w.path("a", "keep.txt")).unwrap();
    w.write("b", "keep.txt", b"v2");
    b.sync(0).unwrap();
    a.sync(0).unwrap();
    assert_eq!(fs::read(w.path("a", "keep.txt")).unwrap(), b"v2");
}

#[test]
fn guards_stop_damage_before_it_happens() {
    let w = world("guards");
    let mut a = w.client("a", "sub");
    for i in 0..60 {
        w.write("a", &format!("f{i}.txt"), format!("file {i}").as_bytes());
    }
    a.sync(0).unwrap();
    let on_server = || {
        w.app.store.read(|s| {
            s.user("alice").unwrap().entries.values().filter(|e| !e.node.is_dir()).count()
        })
    };
    assert_eq!(on_server(), 60);
    // An unmounted disk: the folder is simply not there.
    let moved = w.dir.join("a-away");
    fs::rename(w.dir.join("a"), &moved).unwrap();
    let err = a.sync(0).unwrap_err();
    assert!(err.message().contains("missing"), "{err}");
    // An empty folder at the same place, without the marker.
    fs::create_dir_all(w.dir.join("a")).unwrap();
    assert!(a.sync(0).unwrap_err().message().contains(".homedrive-root"));
    fs::remove_dir(w.dir.join("a")).unwrap();
    fs::rename(&moved, w.dir.join("a")).unwrap();
    assert_eq!(on_server(), 60);
    // Many deletions at once are held until confirmed.
    for i in 0..60 {
        fs::remove_file(w.path("a", &format!("f{i}.txt"))).unwrap();
    }
    let r = a.sync(0).unwrap();
    assert_eq!(r.held_deletes, Some(60));
    assert_eq!(on_server(), 60);
    let mut confirmed =
        w.reopen("a", "sub", Options { confirm_deletes: true, ..Options::default() });
    drop(a);
    assert_eq!(confirmed.sync(0).unwrap().deleted_remote.len(), 60);
    assert_eq!(on_server(), 0);
    // Deleted on the server means in the server's trash, not gone.
    let in_trash = w.app.store.read(|s| s.user("alice").unwrap().trash.len());
    assert_eq!(in_trash, 60);
}

#[test]
fn lost_client_state_costs_nothing() {
    let w = world("lost-state");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "x.txt", b"x");
    w.write("a", "y.txt", b"y");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    // b loses its state, and meanwhile its copy of y changes.
    drop(b);
    fs::remove_dir_all(w.dir.join("b-state")).unwrap();
    w.write("b", "y.txt", b"y changed while state was lost");
    let mut b = w.reopen("b", "", Options::default());
    let r = b.sync(0).unwrap();
    assert!(r.deleted_local.is_empty() && r.deleted_remote.is_empty(), "{r:?}");
    assert_eq!(r.conflicts.len(), 1, "the changed file is kept as a conflict copy");
    b.sync(0).unwrap();
    a.sync(0).unwrap();
    assert_eq!(tree(&w.dir.join("a")), tree(&w.dir.join("b")));
}

/// Every content on the server, current or old, in place or in its trash.
fn server_hashes(app: &App) -> BTreeSet<[u8; 32]> {
    app.store.read(|s| {
        let ns = s.user("alice").unwrap();
        let mut out = BTreeSet::new();
        let mut add = |n: &hd_store::model::Node| {
            if let hd_store::model::Node::File { versions, .. } = n {
                out.extend(versions.iter().map(|v| v.sha256));
            }
        };
        ns.entries.values().for_each(|e| add(&e.node));
        ns.trash.values().for_each(|t| t.entries.iter().for_each(|(_, n)| add(n)));
        out
    })
}

/// Syncs both sides until neither changes; they must then agree.
fn settle(a: &mut Engine, b: &mut Engine, w: &World) -> BTreeMap<String, Vec<u8>> {
    for _ in 0..10 {
        let ra = a.sync(0).unwrap();
        let rb = b.sync(0).unwrap();
        assert!(ra.errors.is_empty() && rb.errors.is_empty(), "{ra:?} {rb:?}");
        if !ra.changed_anything() && !rb.changed_anything() {
            let ta = tree(&w.dir.join("a"));
            assert_eq!(ta, tree(&w.dir.join("b")), "the two machines differ");
            return ta;
        }
    }
    panic!("the two sides never settled");
}

/// Saves the way most editors do: a new file renamed over the old name.
fn atomic_save(path: &Path, data: &[u8]) {
    let tmp = path.with_extension("editor-tmp");
    fs::write(&tmp, data).unwrap();
    fs::rename(&tmp, path).unwrap();
}

/// A hook that runs `act` once, at the first `moment` for a file named
/// `name`.
fn once_at(
    moment: Moment,
    name: &'static str,
    act: impl FnOnce(&Path) + Send + 'static,
) -> hd_client::engine::Hook {
    let mut act = Some(act);
    Box::new(move |m, path| {
        if m == moment
            && path.file_name().is_some_and(|n| n == name)
            && let Some(act) = act.take()
        {
            act(path);
        }
    })
}

/// The worst moments for an editor to save while the other machine's
/// edit is being downloaded over the file: just before the engine checks
/// the file, and while its name is empty. The save must survive both.
#[test]
fn a_save_racing_a_download_is_never_overwritten() {
    for (case, moment) in [("before", Moment::BeforeReplace), ("vacant", Moment::NameVacant)] {
        let w = world(&format!("race-download-{case}"));
        let mut a = w.client("a", "");
        let mut b = w.client("b", "");
        w.write("a", "f.txt", b"base");
        a.sync(0).unwrap();
        b.sync(0).unwrap();
        w.write("b", "f.txt", b"edited on b");
        b.sync(0).unwrap();
        a.set_hook(once_at(moment, "f.txt", |p| atomic_save(p, b"saved on a meanwhile")));
        let r = a.sync(0).unwrap();
        assert!(r.downloaded.is_empty(), "{case}: {r:?}");
        assert_eq!(fs::read(w.path("a", "f.txt")).unwrap(), b"saved on a meanwhile", "{case}");
        // The next rounds keep both edits on both machines.
        let all: BTreeSet<Vec<u8>> = settle(&mut a, &mut b, &w).into_values().collect();
        assert!(all.contains(&b"saved on a meanwhile"[..]), "{case}");
        assert!(all.contains(&b"edited on b"[..]), "{case}");
    }
}

/// The same for a file deleted on the other machine: an edit made while
/// the engine is moving the file to the trash beats the delete.
#[test]
fn a_save_racing_a_local_delete_is_kept() {
    for (case, moment) in [("before", Moment::BeforeLocalDelete), ("vacant", Moment::NameVacant)] {
        let w = world(&format!("race-delete-{case}"));
        let mut a = w.client("a", "");
        let mut b = w.client("b", "");
        w.write("a", "f.txt", b"base");
        a.sync(0).unwrap();
        b.sync(0).unwrap();
        fs::remove_file(w.path("b", "f.txt")).unwrap();
        b.sync(0).unwrap();
        a.set_hook(once_at(moment, "f.txt", |p| atomic_save(p, b"saved on a meanwhile")));
        a.sync(0).unwrap();
        assert_eq!(fs::read(w.path("a", "f.txt")).unwrap(), b"saved on a meanwhile", "{case}");
        let t = settle(&mut a, &mut b, &w);
        assert_eq!(t.get("f.txt").map(Vec::as_slice), Some(&b"saved on a meanwhile"[..]), "{case}");
    }
}

/// Rewrites a file in place with content of the same size and puts its
/// time back: what a second write in the same timestamp tick looks like
/// on a filesystem with a coarse clock.
fn rewrite_within_one_tick(path: &Path, data: &[u8]) {
    let before = fs::metadata(path).unwrap();
    assert_eq!(before.len(), data.len() as u64);
    fs::write(path, data).unwrap();
    let f = fs::File::options().write(true).open(path).unwrap();
    f.set_modified(before.modified().unwrap()).unwrap();
    drop(f);
    let after = fs::metadata(path).unwrap();
    assert_eq!(after.modified().unwrap(), before.modified().unwrap());
}

/// Size, time and inode alone cannot see a second write in the same
/// clock tick, so a file recorded moments after it changed is compared
/// by content next time.
#[test]
fn a_second_write_in_the_same_clock_tick_is_not_missed() {
    let w = world("same-tick");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    // Written and synced at once, then written again in the same tick.
    w.write("a", "f.txt", b"first");
    a.sync(0).unwrap();
    rewrite_within_one_tick(&w.path("a", "f.txt"), b"again");
    assert_eq!(a.sync(0).unwrap().uploaded, ["f.txt"]);
    // Written again in the same tick while being uploaded, after the
    // engine's last look: the old content is committed, and the next round
    // sends the new.
    w.write("a", "g.txt", b"one");
    a.set_hook(once_at(Moment::BeforeCommit, "g.txt", |p| rewrite_within_one_tick(p, b"two")));
    a.sync(0).unwrap();
    assert_eq!(a.sync(0).unwrap().uploaded, ["g.txt"]);
    let t = settle(&mut a, &mut b, &w);
    assert_eq!(t["f.txt"], b"again");
    assert_eq!(t["g.txt"], b"two");
}

/// Two machines edit the same files and sync at the same moment, again
/// and again, so their commits race on the server. Every edit a sync saw
/// survives, and the machines end up the same.
#[test]
fn two_machines_syncing_at_once_keep_every_edit() {
    let w = world("simultaneous");
    let start = std::sync::Barrier::new(2);
    let written: Vec<Vec<u8>> = std::thread::scope(|scope| {
        let handles: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|side| {
                let mut engine = w.client(side, "");
                let (w, start) = (&w, &start);
                scope.spawn(move || {
                    let mut written = Vec::new();
                    start.wait();
                    for i in 0..25 {
                        for rel in ["shared.txt", "dir/also-shared.bin"] {
                            let mut data = format!("{side} {i} {rel}").into_bytes();
                            data.resize(data.len() + (i % 3) * 400_000, b'x');
                            let p = w.path(side, rel);
                            if p.is_file() || !p.exists() {
                                w.write(side, rel, &data);
                                written.push(data);
                            }
                        }
                        let r = engine.sync(0).unwrap();
                        assert!(r.held_deletes.is_none(), "{r:?}");
                    }
                    (engine, written)
                })
            })
            .collect();
        let mut engines = Vec::new();
        let mut written = Vec::new();
        for h in handles {
            let (e, wr) = h.join().unwrap();
            engines.push(e);
            written.extend(wr);
        }
        let [mut a, mut b]: [Engine; 2] = engines.try_into().unwrap();
        settle(&mut a, &mut b, &w);
        written
    });
    let mut everywhere: BTreeSet<Vec<u8>> = tree(&w.dir.join("a")).into_values().collect();
    everywhere.extend(trashed(&w.dir.join("a")));
    everywhere.extend(trashed(&w.dir.join("b")));
    let on_server = server_hashes(&w.app);
    for data in &written {
        assert!(
            everywhere.contains(data) || on_server.contains(&hd_crypto::sha256(data).unwrap()),
            "an edit was lost: {:?}",
            String::from_utf8_lossy(&data[..data.len().min(40)])
        );
    }
    assert!(w.app.store.fsck(true).unwrap().is_clean());
}

/// A file deleted here, while another machine commits a new version of
/// it after this machine last looked: the edit beats the delete.
#[test]
fn a_delete_based_on_a_stale_view_does_not_remove_a_new_edit() {
    let w = world("stale-delete");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "f.txt", b"base");
    w.write("a", "dir/g.txt", b"in a folder");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    fs::remove_file(w.path("a", "f.txt")).unwrap();
    fs::remove_dir_all(w.path("a", "dir")).unwrap();
    // b's edits land between a's look at the server and a's deletes.
    let app = Arc::clone(&w.app);
    a.set_hook(Box::new(move |m, path| {
        if m == Moment::BeforeRemoteDelete && path.ends_with("f.txt") {
            let by = hd_store::Provenance {
                device: "b".into(),
                mtime_ms: 0,
                origin: hd_store::model::Origin::Upload,
                created_ms: None,
            };
            let store = &app.store;
            store
                .write_file(
                    "alice",
                    "f.txt",
                    hd_store::Base::Any,
                    &b"edited on b"[..],
                    1 << 20,
                    &by,
                )
                .unwrap();
            store
                .write_file(
                    "alice",
                    "dir/new.txt",
                    hd_store::Base::Absent,
                    &b"new on b"[..],
                    1 << 20,
                    &by,
                )
                .unwrap();
        }
    }));
    let report = a.sync(0).unwrap();
    assert!(report.deleted_remote.iter().all(|p| p != "f.txt"), "{report:?}");
    let both = settle(&mut a, &mut b, &w);
    assert_eq!(both["f.txt"], b"edited on b");
    assert_eq!(both["dir/new.txt"], b"new on b");
    assert!(!both.contains_key("dir/g.txt"));
}

/// The server is restored from an older backup, and other machines then
/// commit until its sequence numbers pass this client's. Version numbers
/// from the old history now mean something else. The client must notice
/// the new history and keep everything it has that the restored server
/// lacks, deleting nothing.
#[test]
fn a_server_restored_from_a_backup_loses_nothing_a_client_still_has() {
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let target = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_tree(&e.path(), &target);
            } else {
                fs::copy(e.path(), &target).unwrap();
            }
        }
    }
    let w = world("restored");
    let mut a = w.client("a", "");
    w.write("a", "kept.txt", b"before the backup");
    w.write("a", "edited.txt", b"before the backup");
    w.write("a", "deleted-later.txt", b"before the backup");
    a.sync(0).unwrap();
    // The night's backup, the way the backup script takes it.
    let backup = w.dir.join("backup");
    copy_tree(&w.dir.join("store"), &backup);
    fs::remove_file(backup.join("history.id")).unwrap();
    // Work after the backup, which the restore will lose.
    w.write("a", "edited.txt", b"edited after the backup");
    w.write("a", "created.txt", b"created after the backup");
    fs::remove_file(w.path("a", "deleted-later.txt")).unwrap();
    a.sync(0).unwrap();
    let cursor = a.state.state.cursor;
    // The restore, then other machines' work carrying it past a's cursor.
    let (restored, url) = serve(&backup, &w.dir.join("users.json"));
    let by = hd_store::Provenance {
        device: "phone".into(),
        mtime_ms: 0,
        origin: hd_store::model::Origin::Upload,
        created_ms: None,
    };
    let mut n = 0;
    while restored.store.read(|s| s.seq) <= cursor + 5 {
        let data = format!("other {n}");
        restored
            .store
            .write_file(
                "alice",
                &format!("other/{n}"),
                hd_store::Base::Any,
                data.as_bytes(),
                1 << 20,
                &by,
            )
            .unwrap();
        n += 1;
    }
    drop(a);
    let folder = Folder {
        local: w.dir.join("a"),
        remote: String::new(),
        ignore: Vec::new(),
        state_dir: w.dir.join("a-state"),
    };
    let mut a =
        Engine::open(folder, Remote::new(&url, None, &w.token).unwrap(), Options::default())
            .unwrap();
    for _ in 0..3 {
        let r = a.sync(0).unwrap();
        assert!(r.deleted_local.is_empty() && r.errors.is_empty(), "{r:?}");
    }
    // Every content a had is current somewhere on the restored server (the
    // edit made after the backup may be a conflict copy beside the restored
    // version: without a trustworthy history, both are kept), and a still
    // has all of it too.
    let current: BTreeSet<[u8; 32]> = restored.store.read(|s| {
        s.user("alice")
            .unwrap()
            .entries
            .values()
            .filter_map(|e| e.node.current())
            .map(|v| v.sha256)
            .collect()
    });
    let local: BTreeSet<Vec<u8>> = tree(&w.dir.join("a")).into_values().collect();
    for data in [&b"edited after the backup"[..], b"created after the backup", b"before the backup"]
    {
        assert!(
            current.contains(&hd_crypto::sha256(data).unwrap()),
            "{}",
            String::from_utf8_lossy(data)
        );
        assert!(local.contains(data), "{}", String::from_utf8_lossy(data));
    }
    // The other machines' work arrives, and the file deleted after the
    // backup comes back rather than anything being deleted on the strength
    // of a history that no longer exists.
    assert!(w.path("a", "other/0").is_file());
    assert!(w.path("a", "deleted-later.txt").is_file());
}

/// xorshift, for a reproducible random run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn random_work_on_two_machines_never_loses_content() {
    // HD_E2E_SEEDS=n runs seeds 1..=n instead, for a longer hunt.
    let seeds: Vec<u64> =
        match std::env::var("HD_E2E_SEEDS").ok().and_then(|v| v.parse::<u64>().ok()) {
            Some(n) => (1..=n).collect(),
            None => vec![11, 22, 33],
        };
    for seed in seeds {
        let w = world(&format!("random-{seed}"));
        let mut clients = [w.client("a", "drive"), w.client("b", "drive")];
        let names = ["a.txt", "b.txt", "dir/c.txt", "dir/d.bin", "dir/sub/e", "f"];
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut written: BTreeSet<Vec<u8>> = BTreeSet::new();
        for step in 0..120 {
            let who = rng.below(2);
            let side = if who == 0 { "a" } else { "b" };
            match rng.below(8) {
                0..=3 => {
                    let rel = names[rng.below(names.len())];
                    let size = [0, 10, 5_000, 300_000][rng.below(4)];
                    let mut data = format!("{seed}/{step}/{side}/").into_bytes();
                    data.resize(data.len() + size, u8::try_from(step % 251).unwrap());
                    let p = w.path(side, rel);
                    // A folder may be in the way after another rename.
                    if p.parent().is_some_and(Path::is_file) || p.is_dir() {
                        continue;
                    }
                    w.write(side, rel, &data);
                }
                4 => {
                    let rel = names[rng.below(names.len())];
                    let _ = fs::remove_file(w.path(side, rel));
                }
                5 => {
                    let from = names[rng.below(names.len())];
                    let to = format!("moved-{step}");
                    if w.path(side, from).is_file() {
                        fs::rename(w.path(side, from), w.path(side, &to)).unwrap();
                    }
                }
                _ => {
                    written.extend(tree(&w.dir.join(side)).into_values());
                    clients[who].sync(0).unwrap();
                }
            }
        }
        written.extend(tree(&w.dir.join("a")).into_values());
        written.extend(tree(&w.dir.join("b")).into_values());
        // Settle: sync back and forth until neither side changes.
        let mut rounds = 0;
        loop {
            let ra = clients[0].sync(0).unwrap();
            let rb = clients[1].sync(0).unwrap();
            assert!(ra.held_deletes.is_none() && rb.held_deletes.is_none());
            assert!(ra.errors.is_empty() && rb.errors.is_empty(), "{ra:?} {rb:?}");
            if !ra.changed_anything() && !rb.changed_anything() {
                break;
            }
            rounds += 1;
            assert!(rounds < 10, "the two sides never settled");
        }
        let ta = tree(&w.dir.join("a"));
        assert_eq!(ta, tree(&w.dir.join("b")), "seed {seed}: the two machines differ");
        // Every content ever written is somewhere.
        let mut everywhere: BTreeSet<Vec<u8>> = ta.into_values().collect();
        everywhere.extend(trashed(&w.dir.join("a")));
        everywhere.extend(trashed(&w.dir.join("b")));
        let server_hashes = server_hashes(&w.app);
        for data in &written {
            let h = hd_crypto::sha256(data).unwrap();
            assert!(
                everywhere.contains(data) || server_hashes.contains(&h),
                "seed {seed}: a written content was lost ({} bytes)",
                data.len()
            );
        }
        assert!(w.app.store.fsck(true).unwrap().is_clean());
    }
}
