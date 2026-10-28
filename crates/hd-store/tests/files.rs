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
    Provenance { device: device.into(), mtime_ms: 5, origin: Origin::Upload, created_ms: None }
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
