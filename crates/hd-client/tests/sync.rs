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

use hd_client::engine::{Engine, Folder, Options};
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
    let app = Arc::new(App::open(Config::for_test(data, users)).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::clone(&app);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &served))
        .unwrap();
    let server = format!("http://{addr}");
    let token = Remote::register(&server, None, "alice", PW, "test").unwrap().token;
    World { dir, server, token, app }
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
        let server_hashes: BTreeSet<[u8; 32]> = w.app.store.read(|s| {
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
        });
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
