//! A randomized test against a reference model.
//!
//! Hundreds of random writes, overwrites, conflicting writes, moves,
//! copies, deletes, and restores run against the store and against a
//! plain in-memory model of what each path should hold. Then retention and
//! two garbage collections run (with no grace or hold periods, the most
//! aggressive settings), and the store is reopened. At every checkpoint:
//! - every live path holds exactly what the model says;
//! - every version the metadata still lists, live or in the trash, reads
//!   back byte for byte and matches its recorded hash;
//! - a deep fsck is clean.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::type_complexity
)]

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use hd_store::gc::GcOptions;
use hd_store::model::{Node, Op, Origin};
use hd_store::retention::Policy;
use hd_store::{Base, Provenance, Store, StoreOptions};

const USER: &str = "alice";
const DAY: i64 = 86_400_000;

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

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(len);
        out
    }
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

fn read_all(store: &Store, manifest: &hd_chunk::ObjectId) -> Vec<u8> {
    let mut out = Vec::new();
    store.open_content(manifest).unwrap().read_to_end(&mut out).unwrap();
    out
}

/// Checks the store against the model and that every listed version reads
/// back intact.
fn check(store: &Store, model: &BTreeMap<String, Vec<u8>>, contents: &HashMap<[u8; 32], Vec<u8>>) {
    let (files, versions) = store.read(|s| {
        let mut files = BTreeMap::new();
        let mut versions = Vec::new();
        if let Some(ns) = s.user(USER) {
            for (path, entry) in &ns.entries {
                if let Node::File { versions: vs, .. } = &entry.node {
                    files.insert(path.clone(), vs.last().unwrap().clone());
                    versions.extend(vs.iter().cloned());
                }
            }
            for item in ns.trash.values() {
                for (_, node) in &item.entries {
                    if let Node::File { versions: vs, .. } = node {
                        versions.extend(vs.iter().cloned());
                    }
                }
            }
        }
        (files, versions)
    });
    let live: Vec<&String> = files.keys().collect();
    let expected: Vec<&String> = model.keys().collect();
    assert_eq!(live, expected, "the live files differ from the model");
    for (path, want) in model {
        let got = read_all(store, &files[path].manifest);
        assert!(got == *want, "{path} holds the wrong content");
    }
    for v in versions {
        let got = read_all(store, &v.manifest);
        assert_eq!(hd_crypto::sha256(&got).unwrap(), v.sha256, "version {} hash", v.id);
        assert!(contents.get(&v.sha256) == Some(&got), "version {} content unknown", v.id);
    }
    let fsck = store.fsck(true).unwrap();
    assert!(fsck.is_clean(), "{:?}", fsck.problems);
}

fn run(seed: u64, steps: usize) {
    let dir: PathBuf = std::env::temp_dir().join(format!("hd-model-{}-{seed}", std::process::id()));
    remove(&dir);
    Store::init(&dir).unwrap();
    let opts = StoreOptions {
        min_free: 0,
        meta: hd_store::MetaOptions { snapshot_every: 25, repair_tail: false },
    };
    let mut store = Store::open(&dir, &opts).unwrap();
    let mut rng = Rng(seed);
    let mut model: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut contents: HashMap<[u8; 32], Vec<u8>> = HashMap::new();
    let mut pool: Vec<Vec<u8>> = Vec::new();
    let names = ["a.txt", "b.bin", "dir/c.txt", "dir/d.bin", "dir/sub/e", "f"];
    let prov =
        |device: &str| Provenance { device: device.into(), mtime_ms: 1, origin: Origin::Upload };
    let mut trash: Vec<(u64, String, Vec<(String, Vec<u8>)>)> = Vec::new();

    for step in 0..steps {
        match rng.below(10) {
            // Write: new content or a reused one (deduplication).
            0..=3 => {
                let path = names[rng.below(names.len())].to_owned();
                let data = if !pool.is_empty() && rng.below(3) == 0 {
                    pool[rng.below(pool.len())].clone()
                } else {
                    let len = [0, 1, 5_000, 300_000, 1_500_000][rng.below(5)];
                    let d = rng.bytes(len);
                    pool.push(d.clone());
                    d
                };
                contents.insert(hd_crypto::sha256(&data).unwrap(), data.clone());
                let res =
                    store.write_file(USER, &path, Base::Any, &data[..], u64::MAX, &prov("pc"));
                match res {
                    Ok(c) => {
                        model.insert(c.path, data);
                    }
                    Err(e) => {
                        // Only a path whose parent is a file can fail.
                        assert!(e.message().contains("parent"), "step {step}: {e}");
                    }
                }
            }
            // A stale write: conflicts unless nothing changed.
            4 => {
                let Some(path) = model.keys().nth(rng.below(model.len().max(1))).cloned() else {
                    continue;
                };
                let data = rng.bytes(2_000);
                contents.insert(hd_crypto::sha256(&data).unwrap(), data.clone());
                let c = store
                    .write_file(USER, &path, Base::Version(0), &data[..], u64::MAX, &prov("phone"))
                    .unwrap();
                assert!(c.conflict && c.path != path);
                model.insert(c.path, data);
            }
            // Move a file somewhere free.
            5 => {
                let Some(from) = model.keys().nth(rng.below(model.len().max(1))).cloned() else {
                    continue;
                };
                let to = format!("moved/{step}");
                store
                    .commit(&Op::Move { user: USER.into(), from: from.clone(), to: to.clone() })
                    .unwrap();
                let data = model.remove(&from).unwrap();
                model.insert(to, data);
            }
            // Copy.
            6 => {
                let Some(from) = model.keys().nth(rng.below(model.len().max(1))).cloned() else {
                    continue;
                };
                let to = format!("copies/{step}");
                store
                    .commit(&Op::Copy {
                        user: USER.into(),
                        from: from.clone(),
                        to: to.clone(),
                        created_ms: 0,
                    })
                    .unwrap();
                let data = model[&from].clone();
                model.insert(to, data);
            }
            // Delete a file, or a whole directory.
            7 | 8 => {
                let Some(path) = model.keys().nth(rng.below(model.len().max(1))).cloned() else {
                    continue;
                };
                let target = if rng.below(2) == 0 {
                    path.clone()
                } else {
                    hd_common::pathname::parent(&path).to_owned()
                };
                let target = if target.is_empty() { path } else { target };
                let applied = store
                    .commit(&Op::Trash {
                        user: USER.into(),
                        path: target.clone(),
                        deleted_ms: step as i64,
                    })
                    .unwrap();
                let gone: Vec<String> = model
                    .keys()
                    .filter(|p| hd_common::pathname::is_within(p, &target))
                    .cloned()
                    .collect();
                let mut items = Vec::new();
                for p in gone {
                    let data = model.remove(&p).unwrap();
                    items.push((p, data));
                }
                trash.push((applied.trash_id.unwrap(), target, items));
            }
            // Restore the most recent deletion somewhere free.
            _ => {
                let Some((id, from, items)) = trash.pop() else { continue };
                let to = format!("restored/{step}");
                store
                    .commit(&Op::Restore { user: USER.into(), trash_id: id, to: to.clone() })
                    .unwrap();
                for (p, data) in items {
                    let new = hd_common::pathname::rebase(&p, &from, &to).unwrap();
                    model.insert(new, data);
                }
            }
        }
        if step % 50 == 49 {
            check(&store, &model, &contents);
        }
    }
    check(&store, &model, &contents);

    // Retention far in the future, then the most aggressive collection.
    let future = hd_common::timefmt::unix_ms() + 1_000 * DAY;
    let report = store.apply_retention(future, &Policy::default()).unwrap();
    assert!(report.purged_trash + report.dropped_versions > 0);
    let now = hd_common::timefmt::unix_ms() + 60_000;
    let gc = GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false };
    store.collect_garbage(now, &gc).unwrap();
    let second = store.collect_garbage(now, &gc).unwrap();
    assert_eq!(second.restored, 0);
    assert_eq!(second.moved, 0, "the first pass left unreferenced objects behind");
    check(&store, &model, &contents);

    // And after a reopen.
    drop(store);
    store = Store::open(&dir, &opts).unwrap();
    check(&store, &model, &contents);
    drop(store);
    remove(&dir);
}

#[test]
fn random_operations_never_lose_or_corrupt_content() {
    for seed in [1, 2, 3] {
        run(0x9e37_79b9_7f4a_7c15 ^ seed, 250);
    }
}
