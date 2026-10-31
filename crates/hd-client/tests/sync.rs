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

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use common::{World, as_if_the_disk_did_it, serve, server_hashes, trashed, tree, world};
use hd_client::engine::{Engine, Folder, Moment, Options};
use hd_client::remote::Remote;
use std::sync::Arc;

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
    // One process syncs a folder at a time.
    assert!(
        Engine::try_open(
            w.folder("a", "sub"),
            Remote::new(&w.server, None, &w.token).unwrap(),
            Options::default()
        )
        .unwrap()
        .is_none()
    );
    drop(a);
    let mut confirmed =
        w.reopen("a", "sub", Options { confirm_deletes: true, ..Options::default() });
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

/// Another synced file renamed onto the one the engine is acting on, at
/// each moment it acts: the renamed file's content now sits at a name the
/// engine is about to replace or delete, and its own name looks deleted.
/// Both contents survive on both machines.
#[test]
fn a_synced_file_renamed_onto_one_being_synced_is_kept() {
    let moments = [
        ("replace", Moment::BeforeReplace),
        ("delete", Moment::BeforeLocalDelete),
        ("vacant", Moment::NameVacant),
        ("commit", Moment::BeforeCommit),
        ("remote-delete", Moment::BeforeRemoteDelete),
    ];
    for (case, moment) in moments {
        let w = world(&format!("race-rename-{case}"));
        let mut a = w.client("a", "");
        let mut b = w.client("b", "");
        w.write("a", "f.txt", b"f as synced");
        w.write("a", "g.txt", b"g, renamed onto f");
        a.sync(0).unwrap();
        b.sync(0).unwrap();
        match moment {
            Moment::BeforeReplace => {
                w.write("b", "f.txt", b"f edited on b");
                b.sync(0).unwrap();
            }
            Moment::BeforeLocalDelete | Moment::NameVacant => {
                fs::remove_file(w.path("b", "f.txt")).unwrap();
                b.sync(0).unwrap();
            }
            Moment::BeforeCommit => w.write("a", "f.txt", b"f edited on a"),
            Moment::BeforeRemoteDelete => fs::remove_file(w.path("a", "f.txt")).unwrap(),
        }
        let other = w.path("a", "g.txt");
        a.set_hook(once_at(moment, "f.txt", move |p| fs::rename(&other, p).unwrap()));
        a.sync(0).unwrap();
        let all: BTreeSet<Vec<u8>> = settle(&mut a, &mut b, &w).into_values().collect();
        let mut kept = all.clone();
        kept.extend(trashed(&w.dir.join("a")));
        kept.extend(trashed(&w.dir.join("b")));
        assert!(all.contains(&b"g, renamed onto f"[..]), "{case}: {all:?}");
        if moment == Moment::BeforeReplace {
            assert!(all.contains(&b"f edited on b"[..]), "{case}");
        }
        if moment == Moment::BeforeCommit {
            let h = hd_crypto::sha256(b"f edited on a").unwrap();
            assert!(kept.contains(&b"f edited on a"[..]) || server_hashes(&w.app).contains(&h));
        }
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

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else { return out };
    for e in entries {
        let path = e.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// The worst case of the race above: while the name is empty, the file
/// moved aside is written through a handle opened earlier, and another
/// program creates a new file at the name. The changed copy cannot go back,
/// and it is the only copy of that edit, so it is kept where the trash's
/// expiry never reaches.
#[test]
fn a_changed_copy_that_cannot_go_back_is_never_expired() {
    let w = world("race-kept");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "f.txt", b"base");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    w.write("b", "f.txt", b"edited on b");
    b.sync(0).unwrap();
    let root = w.dir.join("a");
    let trash = root.join(".homedrive/trash");
    a.set_hook(once_at(Moment::NameVacant, "f.txt", move |p| {
        let moved = files_under(&trash).pop().expect("the file was moved aside");
        fs::write(&moved, b"written through an open handle").unwrap();
        fs::write(p, b"a new file at the name").unwrap();
    }));
    let r = a.sync(0).unwrap();
    assert!(r.errors.iter().any(|(p, _)| p == "f.txt"), "{r:?}");
    assert_eq!(fs::read(w.path("a", "f.txt")).unwrap(), b"a new file at the name");
    // Trash rounds expire once strictly older than the cutoff.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    hd_client::trash::expire(&root, 0).unwrap();
    let kept: Vec<Vec<u8>> =
        files_under(&root.join(".homedrive")).iter().map(|f| fs::read(f).unwrap()).collect();
    assert!(
        kept.iter().any(|c| c == b"written through an open handle"),
        "the changed copy outlives the trash's expiry"
    );
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
                executable: None,
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
        executable: None,
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

/// The server's disk loses pieces of files. Clients that still hold those
/// exact versions send them again, and the store is whole once more.
#[test]
fn clients_heal_a_server_that_lost_data_to_its_disk() {
    let w = world("heal");
    let mut a = w.client("a", "docs");
    let big: Vec<u8> =
        (0..3_000_000_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    w.write("a", "big.bin", &big);
    w.write("a", "small.txt", b"small but important");
    a.sync(0).unwrap();
    // The disk fails under every object of both files.
    let manifests: Vec<_> = ["docs/big.bin", "docs/small.txt"]
        .iter()
        .map(|p| {
            w.app
                .store
                .read(|s| s.user("alice").unwrap().get(p).unwrap().node.current().unwrap().manifest)
        })
        .collect();
    for m in &manifests {
        let mut lose =
            hd_store::manifest::Manifest::objects_used(w.app.store.objects(), m).unwrap();
        lose.truncate(1);
        for id in lose {
            w.app
                .store
                .objects()
                .quarantine(hd_store::objects::Kind::Chunk, &id, "test: bad sector")
                .unwrap();
        }
        w.app
            .store
            .objects()
            .quarantine(hd_store::objects::Kind::Manifest, m, "test: bad sector")
            .unwrap();
    }
    hd_server::maintenance::check_references(&w.app);
    assert_eq!(w.app.maintenance.snapshot().damaged_versions, 2);
    // The next round sends them again; nothing new is committed.
    let r = a.sync(0).unwrap();
    let mut healed = r.healed.clone();
    healed.sort();
    assert_eq!(healed, ["big.bin", "small.txt"], "{r:?}");
    assert!(r.uploaded.is_empty(), "{r:?}");
    assert!(w.app.store.fsck(true).unwrap().is_clean());
    hd_server::maintenance::check_references(&w.app);
    assert_eq!(w.app.maintenance.snapshot().damaged_versions, 0);
    assert!(a.sync(0).unwrap().healed.is_empty());
    // A client whose copy has since changed sends nothing as a repair.
    w.app
        .store
        .objects()
        .quarantine(hd_store::objects::Kind::Manifest, &manifests[1], "test")
        .unwrap();
    hd_server::maintenance::check_references(&w.app);
    w.write("a", "small.txt", b"edited, so not the damaged version");
    let r = a.sync(0).unwrap();
    assert!(r.healed.is_empty(), "{r:?}");
    assert_eq!(r.uploaded, ["small.txt"]);
    // Bit rot on this computer: the content changed but size, time and
    // inode did not, so the file looks unchanged. It must not be sent as
    // a repair of the server's copy.
    w.write("a", "rots.txt", b"original content");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    fs::File::options()
        .write(true)
        .open(w.path("a", "rots.txt"))
        .unwrap()
        .set_modified(old)
        .unwrap();
    a.sync(0).unwrap();
    let m = w.app.store.read(|s| {
        s.user("alice").unwrap().get("docs/rots.txt").unwrap().node.current().unwrap().manifest
    });
    w.app.store.objects().quarantine(hd_store::objects::Kind::Manifest, &m, "test").unwrap();
    hd_server::maintenance::check_references(&w.app);
    rewrite_within_one_tick(&w.path("a", "rots.txt"), b"origiNal content");
    as_if_the_disk_did_it(&mut a, "rots.txt", &w.path("a", "rots.txt"));
    let r = a.sync(0).unwrap();
    assert!(r.healed.is_empty() && r.uploaded.is_empty(), "{r:?}");
    assert!(w.app.store.fsck(false).unwrap().problems.iter().any(|p| p.contains("rots.txt")));
}

/// Things a scan cannot see as files must never become deletions: a
/// pattern ignored after the files were synced, a file replaced by a
/// symbolic link, and paths inside the client's own `.homedrive` folder.
#[test]
fn what_a_scan_cannot_see_is_never_deleted_anywhere() {
    let w = world("unseen");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "debug.log", b"a log");
    w.write("a", "keep/linked.txt", b"becomes a link");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    // a starts ignoring *.log and swaps a file for a symbolic link.
    drop(a);
    let mut a = w.reopen_with_ignore("a", &["*.log"]);
    fs::remove_file(w.path("a", "keep/linked.txt")).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", w.path("a", "keep/linked.txt")).unwrap();
    let r = a.sync(0).unwrap();
    assert!(r.deleted_remote.is_empty(), "{r:?}");
    assert!(r.skipped.iter().any(|(p, _)| p == "keep/linked.txt"), "{r:?}");
    let r = b.sync(0).unwrap();
    assert!(r.deleted_local.is_empty(), "{r:?}");
    assert_eq!(fs::read(w.path("b", "debug.log")).unwrap(), b"a log");
    assert_eq!(fs::read(w.path("b", "keep/linked.txt")).unwrap(), b"becomes a link");
    // A server path inside .homedrive/ is never brought into the client's
    // own trash and staging folder.
    let by = hd_store::Provenance {
        device: "web".into(),
        mtime_ms: 0,
        origin: hd_store::model::Origin::Upload,
        created_ms: None,
        executable: None,
    };
    w.app
        .store
        .write_file(
            "alice",
            ".homedrive/trash/x.txt",
            hd_store::Base::Any,
            &b"odd"[..],
            1 << 20,
            &by,
        )
        .unwrap();
    b.sync(0).unwrap();
    assert!(!w.path("b", ".homedrive/trash/x.txt").exists());
    // A synced folder inside this one is its own business.
    w.write("a", "inner/.homedrive-root", b"marker");
    w.write("a", "inner/x.txt", b"belongs to the inner folder");
    let r = a.sync(0).unwrap();
    assert!(r.skipped.iter().any(|(p, _)| p == "inner"), "{r:?}");
    assert!(w.app.store.read(|s| s.user("alice").unwrap().get("inner/x.txt").is_none()));
}

/// A folder pattern ignored after its files were synced: the scan no longer
/// enters the folder, so its files must not read as deleted.
#[test]
fn ignoring_a_synced_folder_deletes_nothing_inside_it() {
    let w = world("ignored-folder");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "proj/build/out.bin", b"built once, kept");
    w.write("a", "proj/build/deep/more.txt", b"deeper");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    drop(a);
    for pattern in ["build/", "build", "proj/build", "bui*"] {
        let mut a = w.reopen_with_ignore("a", &[pattern]);
        let r = a.sync(0).unwrap();
        assert!(r.deleted_remote.is_empty(), "{pattern}: {r:?}");
        assert!(r.held_deletes.is_none(), "{pattern}: {r:?}");
    }
    let r = b.sync(0).unwrap();
    assert!(r.deleted_local.is_empty(), "{r:?}");
    assert_eq!(fs::read(w.path("b", "proj/build/deep/more.txt")).unwrap(), b"deeper");
    // Nor is anything inside it replaced from the server: ignored is
    // ignored, both ways.
    w.write("b", "proj/build/out.bin", b"rebuilt on b");
    b.sync(0).unwrap();
    let mut a = w.reopen_with_ignore("a", &["build/"]);
    let r = a.sync(0).unwrap();
    assert!(r.downloaded.is_empty(), "{r:?}");
    assert_eq!(fs::read(w.path("a", "proj/build/out.bin")).unwrap(), b"built once, kept");
}

/// Extended attributes are not synced, so a local file's `user.*`
/// attributes (tags, comments, application data) exist only on that
/// computer. A file replaced by a download keeps them on its new content,
/// and the old file, and any such file deleted because it was deleted
/// elsewhere, goes where nothing expires.
#[test]
fn extended_attributes_are_never_lost() {
    use hd_sys::posix::{xattr_get, xattr_set};
    let w = world("xattrs");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "f.txt", b"v1");
    w.write("a", "g.txt", b"deleted elsewhere");
    w.write("a", "plain.txt", b"no attributes");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    if xattr_set(&w.path("b", "f.txt"), b"user.note", b"only here").is_err() {
        eprintln!("this filesystem has no user extended attributes; skipped");
        return;
    }
    xattr_set(&w.path("b", "g.txt"), b"user.note", b"g's note").unwrap();
    w.write("a", "f.txt", b"v2");
    fs::remove_file(w.path("a", "g.txt")).unwrap();
    fs::remove_file(w.path("a", "plain.txt")).unwrap();
    a.sync(0).unwrap();
    let r = b.sync(0).unwrap();
    assert_eq!(r.downloaded, vec!["f.txt".to_owned()], "{r:?}");
    assert_eq!(fs::read(w.path("b", "f.txt")).unwrap(), b"v2");
    assert_eq!(
        xattr_get(&w.path("b", "f.txt"), b"user.note").unwrap().as_deref(),
        Some(&b"only here"[..]),
        "the new content keeps the attribute"
    );
    let kept = files_under(&w.dir.join("b/.homedrive/kept"));
    let note = |p: &PathBuf| xattr_get(p, b"user.note").unwrap();
    assert!(
        kept.iter().any(|p| fs::read(p).unwrap() == b"v1" && note(p).is_some()),
        "the replaced file is kept with its attribute: {kept:?}"
    );
    assert!(
        kept.iter().any(|p| note(p).as_deref() == Some(&b"g's note"[..])),
        "the deleted file is kept with its attribute: {kept:?}"
    );
    // Files with no such attributes go to the trash as before.
    assert!(!kept.iter().any(|p| fs::read(p).unwrap() == b"no attributes"));
    let trash = files_under(&w.dir.join("b/.homedrive/trash"));
    assert!(trash.iter().any(|p| fs::read(p).unwrap() == b"no attributes"));
}

/// Makes every file under `dir` look a minute old: a repository at rest.
fn settle_times(dir: &Path) {
    // Folders too: adding a file changes its folder's time.
    fn folders(dir: &Path, past: std::time::SystemTime) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                folders(&p, past);
            }
        }
        fs::File::open(dir).unwrap().set_modified(past).unwrap();
    }
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    for f in files_under(dir) {
        fs::File::options().write(true).open(&f).unwrap().set_modified(past).unwrap();
    }
    folders(dir, past);
}

/// A git repository inside a synced folder: never synced while git is at
/// work in it, lock files never, and a ref changed on two machines keeps
/// both machines' commits reachable (as refs git sees) instead of making
/// a conflict copy git would ignore, and later prune what it named.
#[test]
fn git_repositories_are_synced_whole_and_keep_every_commit() {
    let w = world("git");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    let one = "1111111111111111111111111111111111111111";
    let two = "2222222222222222222222222222222222222222";
    let three = "3333333333333333333333333333333333333333";
    w.write("a", "proj/src.txt", b"working tree");
    w.write("a", "proj/.git/HEAD", b"ref: refs/heads/main\n");
    w.write("a", "proj/.git/refs/heads/main", format!("{one}\n").as_bytes());
    w.write("a", "proj/.git/objects/11/11", b"an object");
    w.write("a", "proj/.git/packed-refs", format!("{one} refs/heads/old\n").as_bytes());
    w.write("a", "proj/.git/index.lock", b"git is at work");
    // Busy: a lock file. The working tree syncs; the metadata waits.
    let r = a.sync(0).unwrap();
    assert!(r.skipped.iter().any(|(p, _)| p == "proj/.git"), "{r:?}");
    let on_server = |p: &str| w.app.store.read(|s| s.user("alice").unwrap().get(p).is_some());
    assert!(on_server("proj/src.txt") && !on_server("proj/.git/HEAD"));
    // Busy: just written, even without a lock.
    fs::remove_file(w.path("a", "proj/.git/index.lock")).unwrap();
    a.sync(0).unwrap();
    assert!(!on_server("proj/.git/HEAD"));
    // At rest: all of it, and never the lock.
    settle_times(&w.path("a", "proj/.git"));
    a.sync(0).unwrap();
    assert!(on_server("proj/.git/HEAD") && on_server("proj/.git/objects/11/11"));
    b.sync(0).unwrap();
    assert_eq!(
        fs::read(w.path("b", "proj/.git/refs/heads/main")).unwrap(),
        format!("{one}\n").as_bytes()
    );
    // Both machines commit on main, and repack differently.
    w.write("a", "proj/.git/refs/heads/main", format!("{two}\n").as_bytes());
    w.write("a", "proj/.git/packed-refs", format!("{two} refs/heads/old\n").as_bytes());
    settle_times(&w.path("a", "proj/.git"));
    a.sync(0).unwrap();
    w.write("b", "proj/.git/refs/heads/main", format!("{three}\n").as_bytes());
    w.write("b", "proj/.git/packed-refs", format!("{three} refs/tags/v1\n").as_bytes());
    settle_times(&w.path("b", "proj/.git"));
    let r = b.sync(0).unwrap();
    assert_eq!(r.conflicts.len(), 2, "{r:?}");
    // b now has a's main, and its own commit as a ref of its own.
    assert_eq!(
        fs::read(w.path("b", "proj/.git/refs/heads/main")).unwrap(),
        format!("{two}\n").as_bytes()
    );
    let kept_refs: Vec<(String, Vec<u8>)> = files_under(&w.path("b", "proj/.git/refs/homedrive"))
        .into_iter()
        .map(|p| (p.to_string_lossy().into_owned(), fs::read(&p).unwrap()))
        .collect();
    let has = |suffix: &str, id: &str| {
        kept_refs.iter().any(|(p, c)| p.ends_with(suffix) && *c == format!("{id}\n").into_bytes())
    };
    assert!(has("/heads/main", three), "{kept_refs:?}");
    assert!(has("/tags/v1", three), "{kept_refs:?}");
    // Nothing git cannot read was made in the repository, and the
    // replaced files are kept where nothing expires.
    let odd: Vec<PathBuf> = files_under(&w.path("b", "proj/.git"))
        .into_iter()
        .filter(|p| p.to_string_lossy().contains("conflict"))
        .collect();
    assert!(odd.is_empty(), "{odd:?}");
    let kept = files_under(&w.dir.join("b/.homedrive/kept"));
    assert!(kept.iter().any(|p| fs::read(p).unwrap() == format!("{three}\n").into_bytes()));
    // The new refs reach the other machine too, once the repository rests.
    settle_times(&w.path("b", "proj/.git"));
    b.sync(0).unwrap();
    a.sync(0).unwrap();
    assert!(!files_under(&w.path("a", "proj/.git/refs/homedrive")).is_empty());
}

/// A download arrives with the permissions of the folder it lands in, and
/// never widens those of a file it replaces.
#[test]
fn downloads_keep_private_folders_private() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let w = world("modes");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    fs::set_permissions(w.dir.join("b"), fs::Permissions::from_mode(0o700)).unwrap();
    w.write("a", "secret/plan.txt", b"v1");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    assert_eq!(mode(&w.path("b", "secret")), 0o700);
    assert_eq!(mode(&w.path("b", "secret/plan.txt")), 0o600);
    fs::set_permissions(w.path("b", "secret/plan.txt"), fs::Permissions::from_mode(0o400)).unwrap();
    w.write("a", "secret/plan.txt", b"v2");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    assert_eq!(fs::read(w.path("b", "secret/plan.txt")).unwrap(), b"v2");
    assert_eq!(mode(&w.path("b", "secret/plan.txt")), 0o400);
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

/// Renames on renames, on two machines at once: a file renamed over
/// another, two swapped through a third name, three rotated in a cycle,
/// folders renamed, into a name just vacated, and into one another's
/// places, between and across syncs. Whatever either machine held when it
/// synced is still somewhere afterwards: a file, a version, a conflict
/// copy, or a trash.
#[test]
fn renames_of_renamed_files_never_lose_content() {
    let seeds: Vec<u64> =
        match std::env::var("HD_E2E_SEEDS").ok().and_then(|v| v.parse::<u64>().ok()) {
            Some(n) => (1..=n).collect(),
            None => vec![5, 6, 7, 8],
        };
    for seed in seeds {
        let w = world(&format!("renames-{seed}"));
        // Renamed folders read as many deletions; this test is about what
        // the engine does once they are confirmed.
        let all = Options { confirm_deletes: true, confirm_changes: true, ..Options::default() };
        drop([w.client("a", "drive"), w.client("b", "drive")]);
        let mut clients = [w.reopen("a", "drive", all), w.reopen("b", "drive", all)];
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let mut written: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (i, rel) in ["x", "y", "z", "d/p", "d/q", "d/e/r", "f/s"].iter().enumerate() {
            w.write("a", rel, format!("{seed} start {i}").as_bytes());
        }
        clients[0].sync(0).unwrap();
        clients[1].sync(0).unwrap();
        let files = |side: &str| -> Vec<String> {
            tree(&w.dir.join(side)).into_keys().filter(|k| !k.ends_with('/')).collect()
        };
        let dirs = |side: &str| -> Vec<String> {
            tree(&w.dir.join(side))
                .into_keys()
                .filter_map(|k| k.strip_suffix('/').map(str::to_owned))
                .collect()
        };
        for step in 0..150 {
            let who = rng.below(2);
            let side = if who == 0 { "a" } else { "b" };
            let at = |rel: &str| w.path(side, rel);
            let fs_now = files(side);
            let pick = |rng: &mut Rng| fs_now.get(rng.below(fs_now.len().max(1))).cloned();
            match rng.below(10) {
                0 | 1 => {
                    if let Some(rel) = pick(&mut rng) {
                        w.write(side, &rel, format!("{seed}/{step}/{side} edit").as_bytes());
                    }
                }
                // Renamed over another file, or onto a name just vacated.
                2 => {
                    if let (Some(from), Some(to)) = (pick(&mut rng), pick(&mut rng)) {
                        let _ = fs::rename(at(&from), at(&to));
                    }
                }
                // Swapped through a third name.
                3 => {
                    if let (Some(one), Some(two)) = (pick(&mut rng), pick(&mut rng))
                        && one != two
                    {
                        let tmp = format!("swap-{step}");
                        if fs::rename(at(&one), at(&tmp)).is_ok() {
                            let _ = fs::rename(at(&two), at(&one));
                            let _ = fs::rename(at(&tmp), at(&two));
                        }
                    }
                }
                // Three rotated: a -> b -> c -> a.
                4 => {
                    let picked = (pick(&mut rng), pick(&mut rng), pick(&mut rng));
                    if let (Some(one), Some(two), Some(three)) = picked
                        && one != two
                        && two != three
                        && one != three
                    {
                        let tmp = format!("cycle-{step}");
                        if fs::rename(at(&three), at(&tmp)).is_ok() {
                            let _ = fs::rename(at(&two), at(&three));
                            let _ = fs::rename(at(&one), at(&two));
                            let _ = fs::rename(at(&tmp), at(&one));
                        }
                    }
                }
                // A folder renamed: to a new name, into another folder, or
                // over an empty one.
                5 => {
                    let ds = dirs(side);
                    if !ds.is_empty() {
                        let from = &ds[rng.below(ds.len())];
                        let to = match rng.below(3) {
                            0 => format!("dir-{step}"),
                            1 => format!("{}/in-{step}", ds[rng.below(ds.len())]),
                            _ => {
                                let empty = format!("empty-{step}");
                                fs::create_dir_all(at(&empty)).unwrap();
                                empty
                            }
                        };
                        let _ = fs::rename(at(from), at(&to));
                    }
                }
                6 => {
                    if let Some(rel) = pick(&mut rng) {
                        let _ = fs::remove_file(at(&rel));
                    }
                }
                _ => {
                    written.extend(tree(&w.dir.join(side)).into_values());
                    let r = clients[who].sync(0).unwrap();
                    assert!(r.errors.is_empty(), "seed {seed} step {step}: {r:?}");
                }
            }
        }
        written.extend(tree(&w.dir.join("a")).into_values());
        written.extend(tree(&w.dir.join("b")).into_values());
        let mut rounds = 0;
        loop {
            let ra = clients[0].sync(0).unwrap();
            let rb = clients[1].sync(0).unwrap();
            assert!(ra.errors.is_empty() && rb.errors.is_empty(), "{ra:?} {rb:?}");
            // Folder changes are not in the report: settle on the trees.
            let quiet = !ra.changed_anything() && !rb.changed_anything();
            if quiet && tree(&w.dir.join("a")) == tree(&w.dir.join("b")) {
                break;
            }
            rounds += 1;
            assert!(rounds < 10, "seed {seed}: the two sides never settled");
        }
        let ta = tree(&w.dir.join("a"));
        assert_eq!(ta, tree(&w.dir.join("b")), "seed {seed}: the two machines differ");
        let mut everywhere: BTreeSet<Vec<u8>> = ta.into_values().collect();
        everywhere.extend(trashed(&w.dir.join("a")));
        everywhere.extend(trashed(&w.dir.join("b")));
        let server_hashes = server_hashes(&w.app);
        for data in &written {
            let h = hd_crypto::sha256(data).unwrap();
            assert!(
                everywhere.contains(data) || server_hashes.contains(&h),
                "seed {seed}: {:?} was lost",
                String::from_utf8_lossy(data)
            );
        }
        assert!(w.app.store.fsck(true).unwrap().is_clean());
    }
}

fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn prose(i: usize) -> Vec<u8> {
    format!("Document {i}. Minutes of the meeting, with notes and plans for next week.\n")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(8192)
        .collect()
}

/// Ransomware encrypting files in place, and deleting others, is held back
/// on the infected machine: the server and the other machine keep good
/// copies. Confirmed by mistake, a rewind on the server undoes it all.
#[test]
fn ransomware_is_held_back_and_a_rewind_undoes_it() {
    let w = world("ransomware");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    for i in 0..40 {
        w.write("a", &format!("docs/{i}.txt"), &prose(i));
    }
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let before = hd_common::timefmt::unix_ms();
    std::thread::sleep(std::time::Duration::from_millis(20));
    for i in 0..12_u64 {
        w.write("a", &format!("docs/{i}.txt"), &noise(8192, i + 1));
    }
    fs::remove_file(w.path("a", "docs/39.txt")).unwrap();
    fs::remove_file(w.path("a", "docs/38.txt")).unwrap();
    let r = a.sync(0).unwrap();
    assert!(r.ransomware_suspected, "{r:?}");
    assert_eq!(r.held_changes, Some(12));
    assert_eq!(r.suspicious, 12);
    assert_eq!(r.held_deletes, Some(2), "a few deletions are held too while it looks like this");
    assert!(r.uploaded.is_empty() && r.deleted_remote.is_empty(), "{r:?}");
    // The other machine still has every good copy.
    b.sync(0).unwrap();
    for i in 0..40 {
        assert_eq!(fs::read(w.path("b", &format!("docs/{i}.txt"))).unwrap(), prose(i));
    }
    // The status says so, for `homedrive status` and `homedrive confirm`.
    let st = hd_client::control::Status::read(&w.dir.join("a-state")).unwrap();
    assert!(st.ransomware_suspected);
    assert_eq!((st.held_changes, st.held_deletes), (Some(12), Some(2)));
    // A confirmation for fewer than are held approves none of them.
    let confirm = |changes: usize, deletes: usize| {
        hd_client::control::Request {
            at_ms: hd_common::timefmt::unix_ms(),
            changes,
            deletes,
            verify: false,
        }
        .write(&w.dir.join("a-state"))
        .unwrap();
    };
    confirm(5, 0);
    let r = a.sync(0).unwrap();
    assert_eq!((r.held_changes, r.held_deletes), (Some(12), Some(2)));
    assert!(r.uploaded.is_empty() && r.deleted_remote.is_empty());
    // Confirmed (as a user tricked into it might): it all goes through...
    confirm(12, 2);
    let r = a.sync(0).unwrap();
    assert_eq!((r.uploaded.len(), r.deleted_remote.len()), (12, 2), "{r:?}");
    assert!(!r.ransomware_suspected);
    b.sync(0).unwrap();
    assert_eq!(fs::read(w.path("b", "docs/0.txt")).unwrap(), noise(8192, 1));
    // ...and a rewind on the server brings everything back, on both.
    let rw = w.app.store.rewind("alice", "docs", before, true).unwrap();
    assert_eq!((rw.reverted.len(), rw.undeleted.len()), (12, 2), "{rw:?}");
    settle(&mut a, &mut b, &w);
    for i in 0..40 {
        assert_eq!(fs::read(w.path("a", &format!("docs/{i}.txt"))).unwrap(), prose(i));
        assert_eq!(fs::read(w.path("b", &format!("docs/{i}.txt"))).unwrap(), prose(i));
    }
    assert!(w.app.store.fsck(true).unwrap().is_clean());
}

/// Many ordinary changes at once wait for a confirmation; one file saved
/// over and over is one file, never "many".
#[test]
fn many_changes_at_once_wait_for_a_confirmation() {
    let w = world("mass-change");
    drop(w.client("a", ""));
    let few = Options { mass_change_count: 5, mass_change_floor: 5, ..Options::default() };
    let mut a = w.reopen("a", "", few);
    for i in 0..8 {
        w.write("a", &format!("f{i}.txt"), format!("v1 {i}").as_bytes());
    }
    a.sync(0).unwrap();
    // One file saved many times in an hour.
    for n in 0..10 {
        w.write("a", "f0.txt", format!("autosave {n}").as_bytes());
        let r = a.sync(0).unwrap();
        assert!(r.held_changes.is_none(), "{r:?}");
        assert_eq!(r.uploaded, vec!["f0.txt"]);
    }
    for i in 1..8 {
        w.write("a", &format!("f{i}.txt"), format!("v2 {i}").as_bytes());
    }
    let r = a.sync(0).unwrap();
    assert_eq!(r.held_changes, Some(7));
    assert!(!r.ransomware_suspected, "plain text edits are not encryption");
    drop(a);
    let mut a = w.reopen("a", "", Options { confirm_changes: true, ..few });
    assert_eq!(a.sync(0).unwrap().uploaded.len(), 7);
}

/// Content that changes on this computer's disk without anything writing
/// it is replaced with the server's copy, and the damaged copy is kept.
#[test]
fn damage_on_this_computers_disk_is_repaired_from_the_server() {
    let w = world("local-rot");
    drop(w.client("a", ""));
    // No background checking, to show what an ordinary round sees.
    let mut a = w.reopen("a", "", Options { verify_days: 0, ..Options::default() });
    let good = prose(3);
    w.write("a", "notes.txt", &good);
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let set_time = |p: &Path| {
        fs::OpenOptions::new().write(true).open(p).unwrap().set_modified(old).unwrap();
    };
    set_time(&w.path("a", "notes.txt"));
    a.sync(0).unwrap();
    // A bit flips on disk: same size, same time, same inode.
    let mut bad = good.clone();
    bad[100] ^= 0x10;
    {
        use std::io::{Seek, Write};
        let mut f = fs::OpenOptions::new().write(true).open(w.path("a", "notes.txt")).unwrap();
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.write_all(&bad).unwrap();
    }
    set_time(&w.path("a", "notes.txt"));
    as_if_the_disk_did_it(&mut a, "notes.txt", &w.path("a", "notes.txt"));
    // An ordinary round cannot see it: nothing about the file changed.
    let r = a.sync(0).unwrap();
    assert!(r.uploaded.is_empty() && r.repaired_local.is_empty(), "{r:?}");
    // A check of everything (`homedrive verify`) finds and repairs it.
    hd_client::control::Request {
        at_ms: hd_common::timefmt::unix_ms(),
        verify: true,
        ..Default::default()
    }
    .write(&w.dir.join("a-state"))
    .unwrap();
    let r = a.sync(0).unwrap();
    assert_eq!(r.repaired_local, vec!["notes.txt"], "{r:?}");
    assert!(r.verified_all);
    assert!(r.uploaded.is_empty(), "the damage never reaches the server");
    assert_eq!(fs::read(w.path("a", "notes.txt")).unwrap(), good);
    let mut kept = Vec::new();
    for round in fs::read_dir(w.path("a", ".homedrive/damaged")).unwrap() {
        kept.push(fs::read(round.unwrap().path().join("notes.txt")).unwrap());
    }
    assert_eq!(kept, vec![bad]);
    // The server only ever had the good content.
    assert_eq!(server_hashes(&w.app), BTreeSet::from([hd_crypto::sha256(&good).unwrap()]));
}

/// `homedrive status` reads a folder the daemon is syncing without
/// disturbing it.
#[test]
fn looking_at_a_folder_being_synced_changes_nothing() {
    let w = world("peek");
    let mut a = w.client("a", "");
    w.write("a", "one.txt", b"one");
    a.sync(0).unwrap();
    let seen = hd_client::state::Persisted::peek(&w.dir.join("a-state")).unwrap();
    assert!(seen.synced.contains_key("one.txt"));
    w.write("a", "two.txt", b"two");
    a.sync(0).unwrap();
    drop(a);
    let a = w.reopen("a", "", Options::default());
    assert!(a.state.state.synced.contains_key("one.txt"));
    assert!(a.state.state.synced.contains_key("two.txt"), "nothing the engine wrote was lost");
}

/// The background check finds the same damage on its own, a little at a
/// time.
#[test]
fn the_background_check_finds_damage_on_its_own() {
    let w = world("local-rot-bg");
    let mut a = w.client("a", "");
    let good = prose(4);
    w.write("a", "notes.txt", &good);
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let p = w.path("a", "notes.txt");
    fs::OpenOptions::new().write(true).open(&p).unwrap().set_modified(old).unwrap();
    a.sync(0).unwrap();
    let mut bad = good.clone();
    bad[7] ^= 1;
    {
        use std::io::Write;
        fs::OpenOptions::new().write(true).open(&p).unwrap().write_all(&bad).unwrap();
    }
    fs::OpenOptions::new().write(true).open(&p).unwrap().set_modified(old).unwrap();
    as_if_the_disk_did_it(&mut a, "notes.txt", &p);
    std::thread::sleep(std::time::Duration::from_millis(50));
    let r = a.sync(0).unwrap();
    assert_eq!(r.repaired_local, vec!["notes.txt"], "{r:?}");
    assert_eq!(fs::read(&p).unwrap(), good);
}

/// A program stays a program on the other machine, and taking the
/// permission away travels too (it is a change, with a version of its own).
#[test]
fn the_execute_permission_travels() {
    use std::os::unix::fs::PermissionsExt;
    let w = world("exec");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");
    w.write("a", "run.sh", b"#!/bin/sh\necho hi\n");
    w.write("a", "notes.txt", b"plain");
    let mode =
        |side: &str, rel: &str| fs::metadata(w.path(side, rel)).unwrap().permissions().mode();
    fs::set_permissions(w.path("a", "run.sh"), fs::Permissions::from_mode(0o750)).unwrap();
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    assert_eq!(mode("b", "run.sh") & 0o100, 0o100, "{:o}", mode("b", "run.sh"));
    assert_eq!(mode("b", "notes.txt") & 0o111, 0);
    // chmod -x alone (no content change, no time change) is noticed.
    fs::set_permissions(w.path("b", "run.sh"), fs::Permissions::from_mode(0o640)).unwrap();
    let r = b.sync(0).unwrap();
    assert_eq!(r.uploaded, vec!["run.sh"], "{r:?}");
    a.sync(0).unwrap();
    assert_eq!(mode("a", "run.sh") & 0o111, 0, "{:o}", mode("a", "run.sh"));
    let versions =
        w.app.store.read(|s| match &s.user("alice").unwrap().get("run.sh").unwrap().node {
            hd_store::model::Node::File { versions, .. } => {
                versions.iter().map(|v| v.executable).collect::<Vec<_>>()
            }
            hd_store::model::Node::Dir => vec![],
        });
    assert_eq!(versions, vec![true, false]);
    settle(&mut a, &mut b, &w);
}

/// A restore to plain files on a client matches, file for file, what the
/// server's own restore (the drill's) writes, and `check-files` proves it,
/// and catches a file that is wrong or gone.
#[test]
fn a_restore_to_plain_files_is_checked_against_the_servers_manifest() {
    use std::os::unix::fs::PermissionsExt;
    let w = world("restore");
    let mut a = w.client("a", "");
    w.write("a", "docs/report.txt", b"the report");
    w.write("a", "docs/deep/data.bin", &noise(300_000, 4));
    w.write("a", "tools/run.sh", b"#!/bin/sh\n");
    fs::set_permissions(w.path("a", "tools/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    a.sync(0).unwrap();
    let mut remote = Remote::new(&w.server, None, &w.token).unwrap();
    let to = w.dir.join("restored");
    let manifest = w.dir.join("restored.sha256");
    let r = hd_client::restore::restore(&mut remote, "", &to, &manifest).unwrap();
    assert_eq!(r.files, 3);
    assert_eq!(fs::read(to.join("docs/report.txt")).unwrap(), b"the report");
    assert_eq!(fs::metadata(to.join("tools/run.sh")).unwrap().permissions().mode() & 0o100, 0o100);
    // The server's restore of the same drive writes the same manifest.
    let server_manifest = w.dir.join("server.sha256");
    hd_server::drill::restore_tree(
        &w.app.store,
        "alice",
        "",
        &w.dir.join("server"),
        &server_manifest,
    )
    .unwrap();
    let theirs = fs::read_to_string(&server_manifest).unwrap();
    assert_eq!(fs::read_to_string(&manifest).unwrap(), theirs);
    let ok = hd_client::restore::check_files(&to, &theirs).unwrap();
    assert!(ok.is_clean() && ok.matched == 3, "{ok:?}");
    // A wrong file and a missing one are caught.
    fs::write(to.join("docs/report.txt"), b"tampered!!").unwrap();
    fs::remove_file(to.join("tools/run.sh")).unwrap();
    let bad = hd_client::restore::check_files(&to, &theirs).unwrap();
    assert_eq!(bad.different, vec!["docs/report.txt"]);
    assert_eq!(bad.missing, vec!["tools/run.sh"]);
    // A restore never writes into a directory that has something in it.
    assert!(hd_client::restore::restore(&mut remote, "", &to, &manifest).is_err());
    // One folder alone.
    let docs = hd_client::restore::restore(
        &mut remote,
        "docs",
        &w.dir.join("docs-only"),
        &w.dir.join("d.sha256"),
    )
    .unwrap();
    assert_eq!(docs.files, 2);
    assert!(w.dir.join("docs-only/deep/data.bin").is_file());
    // Nor over a file where its manifest goes, on either side; nothing is
    // restored then.
    let taken = w.dir.join("notes.sha256");
    fs::write(&taken, b"my own notes").unwrap();
    assert!(hd_client::restore::restore(&mut remote, "", &w.dir.join("n1"), &taken).is_err());
    assert!(
        hd_server::drill::restore_tree(&w.app.store, "alice", "", &w.dir.join("n2"), &taken)
            .is_err()
    );
    assert_eq!(fs::read(&taken).unwrap(), b"my own notes");
    assert!(!w.dir.join("n1").exists() && !w.dir.join("n2").exists());
}

/// An administrator's copy of the whole store: fetched once, then only
/// what changed; it opens as a store, reads back clean, restores to the
/// same plain files as the server, and is never mistaken for another
/// store's copy.
#[test]
fn an_administrator_keeps_a_copy_of_the_store_on_their_machine() {
    let w = world("store-copy");
    let mut a = w.client("a", "");
    w.write("a", "docs/report.txt", b"the report");
    w.write("a", "big.bin", &noise(3_000_000, 9));
    w.write("a", "gone.txt", b"deleted, but kept in the trash");
    a.sync(0).unwrap();
    fs::remove_file(w.path("a", "gone.txt")).unwrap();
    a.sync(0).unwrap();
    let copy = w.dir.join("copy");
    let mut remote = Remote::new(&w.server, None, &w.token).unwrap();
    let first = hd_client::copy::backup_store(&mut remote, &copy, None).unwrap();
    assert!(first.fetched > 0 && first.fetched == first.objects, "{first:?}");
    // Nothing changed: nothing fetched.
    let again = hd_client::copy::backup_store(&mut remote, &copy, None).unwrap();
    assert_eq!(again.fetched, 0, "{again:?}");
    // A change: only it.
    w.write("a", "docs/report.txt", b"the report, revised");
    a.sync(0).unwrap();
    let third = hd_client::copy::backup_store(&mut remote, &copy, None).unwrap();
    assert!((1..=2).contains(&third.fetched), "{third:?}");
    // The copy is a store: clean, with the trash and history, and its
    // restore matches the live server's.
    {
        let store = hd_client::copy::open_copy(&copy, None).unwrap();
        assert!(store.fsck(true).unwrap().is_clean());
        let ns_trash = store.read(|s| s.user("alice").unwrap().trash.len());
        assert_eq!(ns_trash, 1, "the trash is in the copy");
        let theirs = w.dir.join("live.sha256");
        hd_server::drill::restore_tree(&w.app.store, "alice", "", &w.dir.join("live"), &theirs)
            .unwrap();
        let ours = w.dir.join("from-copy.sha256");
        hd_store::restore::restore_tree(&store, "alice", "", &w.dir.join("from-copy"), &ours)
            .unwrap();
        assert_eq!(fs::read_to_string(ours).unwrap(), fs::read_to_string(theirs).unwrap());
        assert_eq!(
            fs::read(w.dir.join("from-copy/docs/report.txt")).unwrap(),
            b"the report, revised"
        );
    }
    // Damage in the copy is found by its check.
    let victim = w.app.store.read(|s| {
        s.user("alice").unwrap().get("big.bin").unwrap().node.current().unwrap().manifest
    });
    let chunk =
        hd_store::manifest::Manifest::objects_used(w.app.store.objects(), &victim).unwrap()[1];
    let hex = chunk.hex();
    let file = copy.join(format!("chunks/{}/{}/{hex}", &hex[..2], &hex[2..4]));
    let mut bytes = fs::read(&file).unwrap();
    bytes[100] ^= 1;
    fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&file, bytes).unwrap();
    {
        let store = hd_client::copy::open_copy(&copy, None).unwrap();
        assert!(!store.fsck(true).unwrap().is_clean(), "a flipped bit in the copy is found");
    }
    // An object the server sends damaged (its disk rotted) is never kept.
    let live = w.dir.join("store").join(format!("chunks/{}/{}/{hex}", &hex[..2], &hex[2..4]));
    let mut rotted = fs::read(&live).unwrap();
    rotted[200] ^= 4;
    fs::set_permissions(&live, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&live, rotted).unwrap();
    let fresh = w.dir.join("fresh-copy");
    let err = hd_client::copy::backup_store(&mut remote, &fresh, None).unwrap_err();
    assert!(err.message().contains("arrived damaged"), "{err}");
    assert!(!fresh.join(format!("chunks/{}/{}/{hex}", &hex[..2], &hex[2..4])).exists());
    // A directory holding another store's copy is refused.
    fs::write(copy.join("store.id"), b"someone else's store").unwrap();
    let err = hd_client::copy::backup_store(&mut remote, &copy, None).unwrap_err();
    assert!(err.message().contains("different store"), "{err}");
    // The run is reported, and counts as a backup on the server.
    remote.backup_report("client-copy", true, "test").unwrap();
    assert!(hd_server::backups::load(&w.app.config.data_dir).contains_key("client-copy"));
}

/// The server keeps only days of metadata, and what leaves it (the trash
/// purged, or worse) would leave the copy on its next run. Each run keeps
/// the metadata it replaces as a generation, so the copy still opens as it
/// was, plain or encrypted, and restores what the server has let go of.
#[test]
fn a_store_copy_keeps_what_the_server_has_since_let_go() {
    let w = world("copy-generations");
    let mut a = w.client("a", "");
    w.write("a", "precious.txt", b"only ever in one place");
    w.write("a", "other.txt", b"stays");
    a.sync(0).unwrap();
    let plain = w.dir.join("copy");
    let sealed = w.dir.join("sealed");
    let mut remote = Remote::new(&w.server, None, &w.token).unwrap();
    let keys = hd_client::copy::start_encrypted(&sealed, "a long and good passphrase").unwrap();
    assert_eq!(hd_client::copy::backup_store(&mut remote, &plain, None).unwrap().generation, None);
    hd_client::copy::backup_store(&mut remote, &sealed, Some(&keys)).unwrap();
    // Deleted, and the trash purged on the server, with a few checkpoints
    // since, so the server's own metadata no longer holds it either.
    fs::remove_file(w.path("a", "precious.txt")).unwrap();
    a.sync(0).unwrap();
    let id = w.app.store.read(|s| *s.user("alice").unwrap().trash.keys().next().unwrap());
    w.app.store.commit(&hd_store::Op::Purge { user: "alice".into(), trash_id: id }).unwrap();
    for i in 0..4 {
        w.app
            .store
            .commit(&hd_store::Op::Mkdir { user: "alice".into(), path: format!("d{i}") })
            .unwrap();
        w.app.store.checkpoint().unwrap();
    }
    let run = hd_client::copy::backup_store(&mut remote, &plain, None).unwrap();
    let generation = run.generation.expect("the replaced metadata is kept");
    let sealed_run = hd_client::copy::backup_store(&mut remote, &sealed, Some(&keys)).unwrap();
    let sealed_generation = sealed_run.generation.expect("in an encrypted copy too");
    // Nothing changed since: no new generation.
    assert_eq!(hd_client::copy::backup_store(&mut remote, &plain, None).unwrap().generation, None);
    assert_eq!(hd_client::copy::generations(&plain).unwrap(), vec![generation.clone()]);
    let has_precious = |store: &hd_store::Store| {
        store.read(|s| {
            let ns = s.user("alice").unwrap();
            ns.get("precious.txt").is_some() || ns.trash.values().any(|t| t.path == "precious.txt")
        })
    };
    {
        let now = hd_client::copy::open_copy(&plain, None).unwrap();
        assert!(!has_precious(&now), "the copy follows the server");
    }
    {
        let then = hd_client::copy::open_copy(&plain, Some(&generation)).unwrap();
        assert!(has_precious(&then));
        assert!(then.fsck(true).unwrap().is_clean());
        let out = w.dir.join("then");
        hd_store::restore::restore_tree(&then, "alice", "", &out, &w.dir.join("then.sha256"))
            .unwrap();
        assert_eq!(fs::read(out.join("precious.txt")).unwrap(), b"only ever in one place");
    }
    assert!(hd_client::copy::open_copy(&plain, Some("19700101T000000Z")).is_err());
    // The encrypted copy: opened as that generation, into a plain one.
    let opened = w.dir.join("opened");
    hd_client::copy::open_sealed(&sealed, &keys, Some(&opened), Some(&sealed_generation)).unwrap();
    let then = hd_client::copy::open_copy(&opened, None).unwrap();
    assert!(has_precious(&then));
}

/// The bytes of every regular file under `dir`.
fn bytes_under(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    entries
        .map(|e| e.unwrap().path())
        .map(|p| if p.is_dir() { bytes_under(&p) } else { fs::metadata(&p).unwrap().len() })
        .sum()
}

/// Generations are kept as chunks shared between them, so a run that
/// changed a little adds a little, not a whole copy of the metadata; and a
/// damaged chunk of the history is found, never read back as good.
#[test]
fn a_store_copys_history_grows_by_what_changed() {
    let w = world("copy-history-size");
    let mut a = w.client("a", "");
    w.write("a", "f.txt", b"x");
    a.sync(0).unwrap();
    // Metadata of some size: a few thousand folders with long names.
    for i in 0..4000 {
        let path = format!("folder {i:05} {}", "with a long name ".repeat(12));
        w.app.store.commit(&hd_store::Op::Mkdir { user: "alice".into(), path }).unwrap();
    }
    let copy = w.dir.join("copy");
    let mut remote = Remote::new(&w.server, None, &w.token).unwrap();
    let mut change = |n: usize| {
        w.app
            .store
            .commit(&hd_store::Op::Mkdir { user: "alice".into(), path: format!("new {n}") })
            .unwrap();
        hd_client::copy::backup_store(&mut remote, &copy, None).unwrap()
    };
    change(0);
    let meta = bytes_under(&copy.join("meta"));
    assert!(meta > 1_000_000, "{meta}");
    let first = change(1).generation.unwrap();
    let after_one = bytes_under(&copy.join("history"));
    let second = change(2).generation.unwrap();
    let added = bytes_under(&copy.join("history")) - after_one;
    assert!(added < meta / 4, "the second generation took {added} bytes of {meta}");
    // Both open as they were.
    for (g, newest) in [(&first, "new 0"), (&second, "new 1")] {
        let then = hd_client::copy::open_copy(&copy, Some(g)).unwrap();
        let has = |p: &str| then.read(|s| s.user("alice").unwrap().get(p).is_some());
        assert!(has(newest) && !has("new 2"), "{g}");
    }
    assert!(!fs::read_dir(copy.join("tmp")).unwrap().any(|e| e.unwrap().path().is_dir()));
    // A flipped bit in the history is found.
    let mut chunks = Vec::new();
    for group in fs::read_dir(copy.join("history/chunks")).unwrap() {
        chunks.extend(fs::read_dir(group.unwrap().path()).unwrap().map(|e| e.unwrap().path()));
    }
    for chunk in chunks {
        let mut bytes = fs::read(&chunk).unwrap();
        bytes[0] ^= 1;
        fs::write(&chunk, bytes).unwrap();
    }
    let err = hd_client::copy::open_copy(&copy, Some(&first)).unwrap_err();
    assert!(err.message().contains("damaged"), "{err}");
}

/// Every file under `dir`, read whole.
fn all_bytes(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(all_bytes(&p));
        } else {
            out.push((p.clone(), fs::read(&p).unwrap()));
        }
    }
    out
}

/// An encrypted copy, when asked for: nothing of the drive readable in it,
/// not even which content it holds; incremental like a plain one; opened
/// back with the passphrase to a copy that checks clean and restores the
/// same files; and tampering is refused.
#[test]
fn an_encrypted_store_copy_reveals_nothing_and_opens_back() {
    let w = world("sealed-copy");
    let mut a = w.client("a", "");
    w.write("a", "secret/plans.txt", b"THE SECRET PLANS, in plain words");
    w.write("a", "big.bin", &noise(2_500_000, 5));
    a.sync(0).unwrap();
    let copy = w.dir.join("sealed-copy");
    let mut remote = Remote::new(&w.server, None, &w.token).unwrap();
    assert!(hd_client::copy::start_encrypted(&copy, "too short").is_err());
    let keys = hd_client::copy::start_encrypted(&copy, "a long and good passphrase").unwrap();
    let first = hd_client::copy::backup_store(&mut remote, &copy, Some(&keys)).unwrap();
    assert!(first.fetched > 0, "{first:?}");
    assert_eq!(hd_client::copy::backup_store(&mut remote, &copy, Some(&keys)).unwrap().fetched, 0);
    // Nothing readable: no plaintext, no path, no content hash.
    let hashes: Vec<String> = w.app.store.read(|s| {
        s.user("alice")
            .unwrap()
            .entries
            .values()
            .filter_map(|e| e.node.current())
            .map(|v| hd_crypto::hex(&v.sha256))
            .collect()
    });
    for (path, bytes) in all_bytes(&copy) {
        let text = String::from_utf8_lossy(&bytes);
        let shown = path.display().to_string();
        assert!(!text.contains("SECRET PLANS") && !text.contains("plans.txt"), "{shown}");
        for h in &hashes {
            assert!(!shown.contains(h.as_str()) && !text.contains(h.as_str()), "{shown}");
        }
    }
    // A plain run on it, or a second --encrypt, is refused.
    assert!(hd_client::copy::backup_store(&mut remote, &copy, None).is_err());
    assert!(hd_client::copy::start_encrypted(&copy, "a long and good passphrase").is_err());
    // The passphrase opens it; another does not.
    let params = hd_client::copy::key_params(&copy).unwrap().unwrap();
    assert!(hd_store::sealed::Keys::open("not the passphrase", &params).is_err());
    let keys = hd_store::sealed::Keys::open("a long and good passphrase", &params).unwrap();
    let checked = hd_client::copy::open_sealed(&copy, &keys, None, None).unwrap();
    assert!(checked.objects > 0);
    let plain = w.dir.join("opened");
    hd_client::copy::open_sealed(&copy, &keys, Some(&plain), None).unwrap();
    {
        let store = hd_client::copy::open_copy(&plain, None).unwrap();
        assert!(store.fsck(true).unwrap().is_clean());
        let out = w.dir.join("restored");
        hd_store::restore::restore_tree(&store, "alice", "", &out, &w.dir.join("restored.sha256"))
            .unwrap();
        assert_eq!(
            fs::read(out.join("secret/plans.txt")).unwrap(),
            b"THE SECRET PLANS, in plain words"
        );
    }
    // One flipped bit anywhere in the copy is refused.
    let (victim, mut bytes) =
        all_bytes(&copy.join("sealed")).into_iter().max_by_key(|(_, b)| b.len()).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 1;
    fs::set_permissions(&victim, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    fs::write(&victim, bytes).unwrap();
    assert!(hd_client::copy::open_sealed(&copy, &keys, None, None).is_err());
}
