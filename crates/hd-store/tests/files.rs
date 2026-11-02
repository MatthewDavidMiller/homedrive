//! Whole files: storage, verified reads, conflicts, corruption and
//! healing, and garbage collection.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use hd_chunk::{Chunker, ObjectId};
use hd_store::gc::GcOptions;
use hd_store::manifest::Manifest;
use hd_store::model::{Node, Op, Origin};
use hd_store::retention::Policy;
use hd_store::{Base, Kind, Provenance, Store, StoreOptions};

const DAY: i64 = 86_400_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hd-files-{}-{name}", std::process::id()));
    remove(&dir);
    dir
}

fn writable(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                writable(&e.path());
            } else {
                fs::set_permissions(e.path(), fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }
}

fn remove(dir: &Path) {
    if dir.exists() {
        writable(dir);
        fs::remove_dir_all(dir).unwrap();
    }
}

fn open(name: &str) -> (PathBuf, Store) {
    let dir = scratch(name);
    Store::init(&dir).unwrap();
    let store = Store::open(&dir, &StoreOptions::default()).unwrap();
    (dir, store)
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

fn by(device: &str) -> Provenance {
    Provenance {
        device: device.into(),
        mtime_ms: 5,
        origin: Origin::Upload,
        created_ms: None,
        executable: None,
    }
}

fn write(store: &Store, path: &str, base: Base, data: &[u8], device: &str) -> hd_store::Committed {
    store.write_file("alice", path, base, data, u64::MAX, &by(device)).unwrap()
}

fn read_current(store: &Store, path: &str) -> Vec<u8> {
    let manifest = store
        .read(|s| s.user("alice").unwrap().get(path).unwrap().node.current().unwrap().manifest);
    let mut out = Vec::new();
    store.open_content(&manifest).unwrap().read_to_end(&mut out).unwrap();
    out
}

fn current_id(store: &Store, path: &str) -> u64 {
    store.read(|s| s.user("alice").unwrap().get(path).unwrap().node.current().unwrap().id)
}

fn chunk_files(dir: &Path) -> usize {
    let mut n = 0;
    for a in fs::read_dir(dir.join("chunks")).unwrap() {
        for b in fs::read_dir(a.unwrap().path()).unwrap() {
            n += fs::read_dir(b.unwrap().path()).unwrap().count();
        }
    }
    n
}

#[test]
fn files_round_trip_with_ranges_and_deduplicate() {
    let (dir, store) = open("roundtrip");
    for (i, len) in [0, 1, 300_000, 9 * 1024 * 1024 + 7].into_iter().enumerate() {
        let data = noise(len, i as u64 + 1);
        let path = format!("f{i}");
        write(&store, &path, Base::Absent, &data, "pc");
        assert_eq!(read_current(&store, &path), data);
        let manifest = store.read(|s| {
            s.user("alice").unwrap().get(&path).unwrap().node.current().unwrap().manifest
        });
        for offset in [0, 1, len / 2, len.saturating_sub(1), len].into_iter().filter(|&o| o <= len)
        {
            let mut r = store.open_content(&manifest).unwrap();
            r.seek_to(offset as u64).unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            assert_eq!(out, data[offset..], "len {len} offset {offset}");
        }
    }
    // The same content again, under another name: nothing new is stored.
    let before = chunk_files(&dir);
    let big = noise(9 * 1024 * 1024 + 7, 4);
    write(&store, "copy-of-f3", Base::Absent, &big, "pc");
    assert_eq!(chunk_files(&dir), before);
    let a = store.read(|s| s.user("alice").unwrap().get("f3").unwrap().node.current().cloned());
    let b =
        store.read(|s| s.user("alice").unwrap().get("copy-of-f3").unwrap().node.current().cloned());
    assert_eq!(a.unwrap().manifest, b.unwrap().manifest);
    drop(store);
    remove(&dir);
}

#[test]
fn chunked_commits_are_verified_before_anything_is_recorded() {
    let (dir, store) = open("chunks");
    let data = noise(3 * 1024 * 1024, 9);
    let mut chunker = Chunker::new(&data[..]).unwrap();
    let mut chunks = Vec::new();
    let mut bodies = Vec::new();
    while let Some(c) = chunker.next_chunk().unwrap() {
        chunks.push((c.id, u32::try_from(c.data.len()).unwrap()));
        bodies.push(c);
    }
    let summary = chunker.finish().unwrap();
    let commit = |sha: [u8; 32]| {
        let list = hd_store::ChunkList { chunks: &chunks, size: summary.len, sha256: sha };
        store.commit_chunks("alice", "big.bin", Base::Absent, &list, &by("pc"))
    };
    // Nothing uploaded yet.
    let err = commit(summary.sha256).unwrap_err();
    assert!(err.message().contains("missing"), "{err}");
    for c in &bodies {
        store.objects().put_claimed(Kind::Chunk, &c.id, &c.data).unwrap();
    }
    // A claimed hash that the chunks do not produce.
    let mut wrong = summary.sha256;
    wrong[0] ^= 1;
    assert!(commit(wrong).unwrap_err().message().contains("SHA-256"));
    assert!(store.read(|s| s.user("alice").is_none()));
    let done = commit(summary.sha256).unwrap();
    assert!(!done.conflict);
    assert_eq!(read_current(&store, "big.bin"), data);
    drop(store);
    remove(&dir);
}

#[test]
fn conflicts_keep_both_copies() {
    let (dir, store) = open("conflicts");
    let v1 = write(&store, "notes.txt", Base::Absent, b"first", "laptop").version;
    // The phone edits from v1.
    let phone = write(&store, "notes.txt", Base::Version(v1), b"phone edit", "phone");
    assert!(!phone.conflict);
    // The laptop, also from v1, does not know: its edit becomes a sibling.
    let laptop = write(&store, "notes.txt", Base::Version(v1), b"laptop edit", "laptop");
    assert!(laptop.conflict);
    assert!(laptop.path.starts_with("notes (conflict laptop "), "{}", laptop.path);
    assert!(laptop.path.ends_with(").txt"));
    assert_eq!(read_current(&store, "notes.txt"), b"phone edit");
    assert_eq!(read_current(&store, &laptop.path), b"laptop edit");
    let origin = store.read(|s| {
        s.user("alice").unwrap().get(&laptop.path).unwrap().node.current().unwrap().origin
    });
    assert_eq!(origin, Origin::Conflict);
    // The same conflict again gets a second, distinct name.
    let again = write(&store, "notes.txt", Base::Version(v1), b"laptop edit 2", "laptop");
    assert!(again.conflict && again.path != laptop.path);
    // Expecting a new file where one exists: conflict, not overwrite.
    let fresh = write(&store, "notes.txt", Base::Absent, b"new", "pc");
    assert!(fresh.conflict);
    // A directory in the way: the file goes beside it.
    store.commit(&Op::Mkdir { user: "alice".into(), path: "photos".into() }).unwrap();
    let beside = write(&store, "photos", Base::Any, b"x", "pc");
    assert!(beside.conflict && beside.path != "photos");
    // Identical content: no new version, conflict or not.
    let same = write(&store, "notes.txt", Base::Version(v1), b"phone edit", "laptop");
    assert!(same.unchanged && !same.conflict);
    assert_eq!(same.version, current_id(&store, "notes.txt"));
    // Overwrites keep history.
    write(&store, "notes.txt", Base::Any, b"third", "pc");
    let n = store.read(|s| match &s.user("alice").unwrap().get("notes.txt").unwrap().node {
        Node::File { versions, .. } => versions.len(),
        Node::Dir => 0,
    });
    assert_eq!(n, 3);
    drop(store);
    remove(&dir);
}

/// Many machines commit to one file at the same moment, all from the same
/// base and with the same device name, so their conflict names collide
/// too. Exactly one wins the name; every other edit lands at a distinct
/// conflict sibling; nothing is overwritten.
#[test]
fn racing_commits_on_one_base_keep_every_copy() {
    const MACHINES: u64 = 16;
    let (dir, store) = open("racing");
    let v1 = write(&store, "shared.txt", Base::Absent, b"base", "laptop").version;
    let start = std::sync::Barrier::new(usize::try_from(MACHINES).unwrap() * 2);
    let results: Vec<(Vec<u8>, hd_store::Committed)> = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for m in 0..MACHINES {
            // Small edits share one chunk path; large ones stream several
            // chunks, so the commits overlap for longer.
            for (base, data) in [
                (Base::Version(v1), format!("edit from machine {m}").into_bytes()),
                (Base::Absent, noise(3 * 1024 * 1024, m + 1)),
            ] {
                let (store, start) = (&store, &start);
                handles.push(scope.spawn(move || {
                    start.wait();
                    let c = store
                        .write_file("alice", "shared.txt", base, &data[..], u64::MAX, &by("phone"))
                        .unwrap();
                    (data, c)
                }));
            }
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    // A creation expecting no file always conflicts, since the file exists;
    // of the edits from v1, exactly one finds v1 still current.
    let winners: Vec<_> = results.iter().filter(|(_, c)| !c.conflict).collect();
    assert_eq!(winners.len(), 1, "{results:?}");
    assert_eq!(winners[0].1.path, "shared.txt");
    let paths: std::collections::BTreeSet<&str> =
        results.iter().map(|(_, c)| c.path.as_str()).collect();
    assert_eq!(paths.len(), results.len(), "two commits were given one name");
    for (data, c) in &results {
        assert!(!c.unchanged);
        assert_eq!(&read_current(&store, &c.path), data, "{}", c.path);
    }
    // The original is still in the winner's history.
    let history = store.read(|s| match &s.user("alice").unwrap().get("shared.txt").unwrap().node {
        Node::File { versions, .. } => versions.iter().map(|v| v.id).collect::<Vec<_>>(),
        Node::Dir => Vec::new(),
    });
    assert_eq!(history.first(), Some(&v1));
    assert!(store.fsck(true).unwrap().is_clean());
    // And all of it survives a restart.
    drop(store);
    let store = Store::open(&dir, &StoreOptions::default()).unwrap();
    for (data, c) in &results {
        assert_eq!(&read_current(&store, &c.path), data);
    }
    drop(store);
    remove(&dir);
}

/// A failing disk loses one chunk and damages a manifest. A backup of the
/// store (any copy, any age, as long as it has the objects) repairs both,
/// verified; what no copy has is named, not guessed at.
#[test]
fn repair_restores_lost_objects_from_a_backup_copy() {
    fn copy_tree(from: &Path, to: &Path) {
        fs::create_dir_all(to).unwrap();
        for e in fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                copy_tree(&e.path(), &to.join(e.file_name()));
            } else {
                fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        }
    }
    let (dir, store) = open("repair");
    let big = noise(5 * 1024 * 1024, 9);
    write(&store, "big.bin", Base::Absent, &big, "pc");
    let backup = scratch("repair-backup");
    copy_tree(&dir, &backup);
    // Written after the backup: no copy of it exists anywhere else.
    write(&store, "late.txt", Base::Absent, b"after the backup", "pc");
    let manifest = |path: &str| {
        store.read(|s| s.user("alice").unwrap().get(path).unwrap().node.current().unwrap().manifest)
    };
    let big_manifest = manifest("big.bin");
    let chunk = Manifest::load(store.objects(), &big_manifest).unwrap().chunks[1].0;
    let lost = store.objects().path(hd_store::objects::Kind::Chunk, &chunk);
    fs::set_permissions(&lost, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&lost).unwrap();
    let rotten = store.objects().path(hd_store::objects::Kind::Manifest, &big_manifest);
    fs::set_permissions(&rotten, fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = fs::read(&rotten).unwrap();
    bytes[40] ^= 0x01;
    fs::write(&rotten, bytes).unwrap();
    let late = store.objects().path(hd_store::objects::Kind::Manifest, &manifest("late.txt"));
    fs::set_permissions(&late, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&late).unwrap();
    assert_eq!(store.fsck(true).unwrap().problems.len(), 2);
    let r = store.repair_from(std::slice::from_ref(&backup)).unwrap();
    assert_eq!(r.restored, 2, "{r:?}");
    assert_eq!(r.still_damaged.len(), 1, "{r:?}");
    assert!(r.still_damaged[0].contains("late.txt"), "{r:?}");
    assert_eq!(read_current(&store, "big.bin"), big);
    let check = store.fsck(true).unwrap();
    assert_eq!(check.problems.len(), 1, "{check:?}");
    // The backup was only read.
    assert!(
        hd_store::objects::Objects::path_in(&backup, hd_store::objects::Kind::Chunk, &chunk)
            .exists()
    );
    drop(store);
    remove(&dir);
    remove(&backup);
}

#[test]
fn damage_is_reported_never_served_and_heals_on_reupload() {
    let (dir, store) = open("damage");
    let data = noise(8 * 1024 * 1024, 77);
    write(&store, "photo.raw", Base::Absent, &data, "pc");
    assert!(store.fsck(true).unwrap().is_clean());
    // Flip a byte in one of its chunk files.
    let manifest = store.read(|s| {
        s.user("alice").unwrap().get("photo.raw").unwrap().node.current().unwrap().manifest
    });
    let chunks = Manifest::load(store.objects(), &manifest).unwrap().chunks;
    assert!(chunks.len() > 2, "the test needs a file of several chunks");
    let victim = store.objects().path(Kind::Chunk, &chunks[chunks.len() / 2].0);
    let mut bytes = fs::read(&victim).unwrap();
    bytes[100] ^= 1;
    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&victim, &bytes).unwrap();
    // A shallow fsck sees the chunk is there; a deep one sees the damage.
    assert!(store.fsck(false).unwrap().is_clean());
    let deep = store.fsck(true).unwrap();
    assert_eq!(deep.problems.len(), 1);
    assert!(deep.problems[0].starts_with("alice:photo.raw"), "{:?}", deep.problems);
    // fsck changed nothing; scrub finds the damage and quarantines it.
    let report = store.scrub(0, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.quarantined.len(), 1);
    assert!(!store.fsck(false).unwrap().is_clean());
    // Reading now fails rather than returning wrong bytes.
    let mut out = Vec::new();
    assert!(store.open_content(&manifest).unwrap().read_to_end(&mut out).is_err());
    // A client still has the file and uploads it again: healed.
    let again = write(&store, "photo.raw", Base::Any, &data, "pc");
    assert!(again.unchanged);
    assert!(store.fsck(true).unwrap().is_clean());
    assert_eq!(read_current(&store, "photo.raw"), data);
    drop(store);
    remove(&dir);
}

#[test]
fn collection_frees_only_what_nothing_references() {
    let (dir, store) = open("gc");
    // Object ages come from file mtimes, so "now" is the real clock, a
    // minute ahead so that the objects written below are already past a
    // zero grace period.
    let now = hd_common::timefmt::unix_ms() + 60_000;
    let keep = noise(1_500_000, 1);
    let gone = noise(1_500_000, 2);
    write(&store, "keep.bin", Base::Absent, &keep, "pc");
    write(&store, "gone.bin", Base::Absent, &gone, "pc");
    let immediate = GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false };
    // Everything is referenced: nothing moves.
    let r = store.collect_garbage(now, &immediate).unwrap();
    assert_eq!(r.moved, 0);
    // Delete and purge one file; young objects are still protected.
    let long_ago = now - 365 * DAY;
    store
        .commit(&Op::Trash { user: "alice".into(), path: "gone.bin".into(), deleted_ms: long_ago })
        .unwrap();
    store.apply_retention(now, &Policy::default()).unwrap();
    assert!(store.read(|s| s.user("alice").unwrap().trash.is_empty()));
    let cautious = GcOptions { grace_ms: i64::MAX, ..immediate };
    assert_eq!(store.collect_garbage(now, &cautious).unwrap().moved, 0);
    let dry = GcOptions { dry_run: true, ..immediate };
    let planned = store.collect_garbage(now, &dry).unwrap();
    assert!(planned.moved >= 2);
    let before = chunk_files(&dir);
    // Stage 1 moves to gc-trash; stage 2 (hold over) deletes.
    let moved = store.collect_garbage(now, &immediate).unwrap();
    assert_eq!(moved.moved, planned.moved);
    assert!(chunk_files(&dir) < before);
    let deleted = store.collect_garbage(now, &immediate).unwrap();
    assert_eq!(deleted.deleted, moved.moved);
    assert_eq!(deleted.restored, 0);
    assert_eq!(read_current(&store, "keep.bin"), keep);
    assert!(store.fsck(true).unwrap().is_clean());
    // The purged content can come back: it is simply stored again.
    write(&store, "gone.bin", Base::Absent, &gone, "pc");
    assert_eq!(read_current(&store, "gone.bin"), gone);
    drop(store);
    remove(&dir);
}

#[test]
fn reusing_unreferenced_content_protects_it_from_collection() {
    let (dir, store) = open("reuse");
    // Object ages come from file mtimes, so "now" is the real clock, a
    // minute ahead so that the objects written below are already past a
    // zero grace period.
    let now = hd_common::timefmt::unix_ms() + 60_000;
    let data = noise(700_000, 3);
    write(&store, "a", Base::Absent, &data, "pc");
    let long_ago = now - 365 * DAY;
    store
        .commit(&Op::Trash { user: "alice".into(), path: "a".into(), deleted_ms: long_ago })
        .unwrap();
    store.apply_retention(now, &Policy::default()).unwrap();
    // The content is now unreferenced but still on disk; a new upload
    // deduplicates against it, and collection must then keep it.
    assert!(store.read(|s| s.user("alice").unwrap().trash.is_empty()));
    write(&store, "b", Base::Absent, &data, "pc");
    let r = store.collect_garbage(now, &GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false });
    assert_eq!(r.unwrap().moved, 0);
    assert_eq!(read_current(&store, "b"), data);
    // Without the second upload the same content would have been taken:
    // trash "b" too and it goes.
    store
        .commit(&Op::Trash { user: "alice".into(), path: "b".into(), deleted_ms: long_ago })
        .unwrap();
    store.apply_retention(now, &Policy::default()).unwrap();
    let r = store.collect_garbage(now, &GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false });
    assert!(r.unwrap().moved >= 2);
    drop(store);
    remove(&dir);
}

#[test]
fn indirect_manifests_round_trip() {
    let (dir, store) = open("indirect");
    let data = noise(5 * 1024 * 1024, 11);
    let mut chunker = Chunker::new(&data[..]).unwrap();
    let mut chunks = Vec::new();
    while let Some(c) = chunker.next_chunk().unwrap() {
        store.objects().put_claimed(Kind::Chunk, &c.id, &c.data).unwrap();
        chunks.push((c.id, u32::try_from(c.data.len()).unwrap()));
    }
    let s = chunker.finish().unwrap();
    let m = Manifest { size: s.len, sha256: s.sha256, chunks };
    // Force the list into 40-byte pieces.
    let id = m.store_split(store.objects(), 40).unwrap();
    assert_eq!(Manifest::load(store.objects(), &id).unwrap(), m);
    let used = Manifest::objects_used(store.objects(), &id).unwrap();
    assert!(used.len() > m.chunks.len(), "the list's own chunks are kept alive too");
    let mut out = Vec::new();
    store.open_content(&id).unwrap().read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
    let _ = ObjectId::of(b"");
    drop(store);
    remove(&dir);
}

#[test]
fn rewinding_brings_a_folder_back_without_taking_anything_away() {
    let (dir, store) = open("rewind");
    let now = hd_common::timefmt::unix_ms();
    let at = now - 5 * DAY;
    let put = |path: &str, data: &[u8], created: i64| {
        let p = Provenance { created_ms: Some(created), executable: None, ..by("laptop") };
        store.write_file("alice", path, Base::Any, data, u64::MAX, &p).unwrap();
    };
    let trash = |path: &str, when: i64| {
        let op = Op::Trash { user: "alice".into(), path: path.into(), deleted_ms: when };
        store.commit(&op).unwrap();
    };
    // How things were.
    for (p, d) in [
        ("docs/a.txt", &b"alpha"[..]),
        ("docs/b.txt", b"bravo"),
        ("docs/c.txt", b"charlie"),
        ("docs/d.txt", b"delta"),
        ("docs/sub/f.txt", b"foxtrot"),
        ("docs/sub/g.txt", b"golf"),
        ("other/x.txt", b"x-ray"),
    ] {
        put(p, d, now - 10 * DAY);
    }
    // What happened since: files encrypted in place, others renamed
    // (deleted, with a new file beside), a folder deleted after a file in
    // it was, a name reused, and a change outside the folder.
    put("docs/a.txt", b"ENCRYPTED a", now - DAY);
    trash("docs/b.txt", now - DAY);
    put("docs/b.txt.locked", b"ENCRYPTED b", now - DAY);
    put("docs/c.txt", b"ENCRYPTED c", now - 2 * DAY);
    trash("docs/c.txt", now - DAY);
    trash("docs/d.txt", now - 2 * DAY);
    put("docs/d.txt", b"a new d", now - DAY);
    trash("docs/sub/g.txt", now - 3 * DAY);
    trash("docs/sub", now - 2 * DAY);
    put("other/x.txt", b"x-ray 2", now - DAY);

    let preview = store.rewind("alice", "docs", at, false).unwrap();
    let applied = store.rewind("alice", "docs", at, true).unwrap();
    let sorted = |mut v: Vec<String>| {
        v.sort();
        v
    };
    assert_eq!(sorted(preview.reverted.clone()), vec!["docs/a.txt", "docs/c.txt"]);
    assert_eq!(sorted(applied.reverted.clone()), sorted(preview.reverted.clone()));
    assert_eq!(sorted(preview.newer.clone()), vec!["docs/b.txt.locked", "docs/d.txt"]);
    assert_eq!(preview.undeleted.len(), 5);
    assert_eq!(applied.undeleted.len(), 5);
    assert!(applied.skipped.is_empty(), "{:?}", applied.skipped);

    assert_eq!(read_current(&store, "docs/a.txt"), b"alpha");
    assert_eq!(read_current(&store, "docs/b.txt"), b"bravo");
    assert_eq!(read_current(&store, "docs/c.txt"), b"charlie");
    assert_eq!(read_current(&store, "docs/sub/f.txt"), b"foxtrot");
    assert_eq!(read_current(&store, "docs/sub/g.txt"), b"golf");
    // A name taken since: both kept, the old one beside the new.
    assert_eq!(read_current(&store, "docs/d.txt"), b"a new d");
    let (from, to) = applied.undeleted.iter().find(|(f, _)| f == "docs/d.txt").unwrap();
    assert_ne!(from, to);
    assert!(to.starts_with("docs/d (restored "), "{to}");
    assert_eq!(read_current(&store, to), b"delta");
    // What was made since stays, and so does every version since.
    assert_eq!(read_current(&store, "docs/b.txt.locked"), b"ENCRYPTED b");
    assert_eq!(read_current(&store, "other/x.txt"), b"x-ray 2");
    let history =
        store.read(|st| match &st.user("alice").unwrap().get("docs/a.txt").unwrap().node {
            Node::File { versions, .. } => versions.len(),
            Node::Dir => 0,
        });
    assert_eq!(history, 3, "alpha, the encrypted copy, and alpha again");

    // Rewinding again finds nothing left to do.
    let again = store.rewind("alice", "docs", at, true).unwrap();
    assert!(again.reverted.is_empty() && again.undeleted.is_empty(), "{again:?}");
    // The whole drive ("") rewinds too, reaching what the folder did not.
    let all = store.rewind("alice", "", at, false).unwrap();
    assert_eq!(all.reverted, vec!["other/x.txt"], "{all:?}");
    // The present cannot be rewound to.
    assert!(store.rewind("alice", "docs", now + DAY, false).is_err());
    remove(&dir);
}

fn prose(i: usize) -> Vec<u8> {
    format!("Document {i}. Minutes of the meeting, with notes and plans.\n")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(8192)
        .collect()
}

#[test]
fn unusual_activity_raises_an_alert_and_holds_retention() {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use hd_store::activity::AlertPolicy;

    let (dir, store) = open("activity");
    let now = hd_common::timefmt::unix_ms();
    let put = |path: &str, data: &[u8], created: i64, origin: Origin| {
        let p = Provenance { created_ms: Some(created), executable: None, origin, ..by("phone") };
        store.write_file("alice", path, Base::Any, data, u64::MAX, &p).unwrap();
    };
    let policy = AlertPolicy::default();
    let mut verdicts = HashMap::new();
    let alerts = |since: &BTreeMap<String, i64>, verdicts: &mut HashMap<u64, bool>| {
        store.activity_alerts(now, &policy, since, verdicts)
    };
    for i in 0..30 {
        put(&format!("docs/{i}.txt"), &prose(i), now - 40 * DAY, Origin::Upload);
    }
    // Ordinary work, and a nightly backup import replacing many files:
    // nothing to see.
    for i in 0..5 {
        put(&format!("docs/{i}.txt"), &prose(i + 100), now - 3 * DAY, Origin::Upload);
    }
    for i in 0..30_u64 {
        put(&format!("backups/{i}.tar"), &noise(8192, i), now - 3 * DAY, Origin::Import);
        put(&format!("backups/{i}.tar"), &noise(8192, i + 90), now - 3 * DAY + 1, Origin::Import);
        put(&format!("backups/{i}.tar"), &noise(8192, i + 50), now - 2 * DAY, Origin::Import);
    }
    assert!(alerts(&BTreeMap::new(), &mut verdicts).is_empty());
    // Even with a limit the 30 replaced backups would cross, imports do
    // not count.
    let strict = AlertPolicy { changed: 20, ..policy };
    assert!(store.activity_alerts(now, &strict, &BTreeMap::new(), &mut verdicts).is_empty());
    // Twelve documents encrypted within half an hour, through WebDAV.
    for i in 10..22_u32 {
        let at = now - DAY + i64::from(i) * 60_000;
        put(&format!("docs/{i}.txt"), &noise(8192, 7 + u64::from(i)), at, Origin::Upload);
    }
    let found = alerts(&BTreeMap::new(), &mut verdicts);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].user.as_str(), found[0].suspicious), ("alice", 12));
    // Retention leaves an alerted drive alone: a policy keeping one
    // version a day would drop the backups' extra one.
    let daily = Policy {
        keep_all_ms: 0,
        daily_until_ms: i64::MAX,
        weekly_until_ms: i64::MAX,
        trash_ms: i64::MAX,
    };
    let held = BTreeSet::from(["alice".to_owned()]);
    let r = store.apply_retention_holding(now, &daily, &held).unwrap();
    assert_eq!(r, hd_store::retention::RetentionReport::default(), "nothing dropped while held");
    let r = store.apply_retention_holding(now, &daily, &BTreeSet::new()).unwrap();
    assert_eq!(r.dropped_versions, 30, "and once released, retention runs: {r:?}");
    // Dismissed: what came before is not counted again.
    let since = BTreeMap::from([("alice".to_owned(), now)]);
    assert!(alerts(&since, &mut verdicts).is_empty());
    // Mass deletion is unusual too.
    for i in 0..30 {
        let op = Op::Trash {
            user: "alice".into(),
            path: format!("backups/{i}.tar"),
            deleted_ms: now - 1000,
        };
        store.commit(&op).unwrap();
    }
    let few = AlertPolicy { deleted: 20, ..policy };
    let found = store.activity_alerts(now, &few, &BTreeMap::new(), &mut verdicts);
    assert_eq!(found[0].deleted, 30, "{found:?}");
    assert!(store.read(|s| s.user("alice").unwrap().stored_bytes()) > 30 * 8192);
    remove(&dir);
}

/// The first upload after the clock jumps ahead records the wrong time as
/// the newest activity, so the store's activity alone no longer shows the
/// clock is wrong. Retention's own clock still moves on only as fast as
/// the caller vouches time has passed: nothing in the trash goes at once.
#[test]
fn a_clock_that_jumps_ahead_cannot_expire_everything_at_once() {
    let (dir, store) = open("clock-jump");
    let now = hd_common::timefmt::unix_ms();
    write(&store, "a", Base::Absent, b"deleted yesterday", "pc");
    store
        .commit(&Op::Trash { user: "alice".into(), path: "a".into(), deleted_ms: now - DAY })
        .unwrap();
    // A day of maintenance at the right time.
    assert_eq!(store.retention_time(now, 2 * DAY).unwrap(), now);
    // The clock leaps a year; an upload stamps that time.
    let leap = now + 365 * DAY;
    let at = store.retention_time(leap, 2 * DAY).unwrap();
    assert_eq!(at, now + 2 * DAY);
    let stamped = Provenance { created_ms: Some(leap), ..by("pc") };
    store.write_file("alice", "b", Base::Absent, &b"new"[..], u64::MAX, &stamped).unwrap();
    // The store's activity now vouches for the wrong clock: as of it,
    // retention would empty the trash.
    let wrong = hd_store::retention::plan(&store.read(Clone::clone), leap, &Policy::default());
    assert!(wrong.iter().any(|op| matches!(op, Op::Purge { .. })));
    let r = store.apply_retention(at, &Policy::default()).unwrap();
    assert_eq!(r.purged_trash, 0);
    assert_eq!(store.read(|s| s.user("alice").unwrap().trash.len()), 1);
    // It is remembered across a restart, and the clock going back is
    // followed.
    drop(store);
    let store = Store::open(&dir, &StoreOptions::default()).unwrap();
    assert_eq!(store.retention_time(leap, 2 * DAY).unwrap(), now + 4 * DAY);
    assert_eq!(store.retention_time(now, 2 * DAY).unwrap(), now);
    // Time that really passes is caught up with.
    assert_eq!(store.retention_time(now + 91 * DAY, 100 * DAY).unwrap(), now + 91 * DAY);
    drop(store);
    remove(&dir);
}
