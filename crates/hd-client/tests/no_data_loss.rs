//! The proof that syncing never loses data, case by case.
//!
//! The sync engine decides what to do with a file from three things: what
//! it held when last in sync (S), what is on this computer now (L), and
//! what the server has now (R). This test runs **every** combination of
//! them, and in each one an editor or another program acts on the file at
//! **every** moment the engine touches it, with both machines' state kept
//! and with this machine's state lost. Two machines and a server then sync
//! until they agree, and the test checks:
//!
//! 1. **Nothing is lost.** Every content either machine held, or that was
//!    written while the engine was at work, is afterwards byte for byte in
//!    a synced file, on the server (any version, in place or in its
//!    trash), or where the client keeps things that never expire
//!    (`.homedrive/kept`, `.homedrive/damaged`). The client trash is *not*
//!    counted: the check holds as if every trash item had already expired.
//!    The only exception is content a program overwrote in place or
//!    deleted itself, which no sync program could keep.
//! 2. **The client trash only ever holds copies.** Everything in either
//!    machine's trash is also on the server, so expiring it costs nothing.
//! 3. **The machines agree**, and the server's store passes a deep check.
//!
//! The cases, for one file `f` (and `h`, a second synced file):
//!
//! | S | this machine (L) | the other machine (R) |
//! |---|---|---|
//! | synced | nothing, edit in place, save by rename, an edit that puts the time back, delete, rename away, `h` renamed onto `f` | nothing, edit, delete, rename away |
//! | never synced | nothing, new | nothing, new, new with the same content |
//!
//! times, at each of the engine's moments (before replacing, before
//! deleting, while the name is empty, before committing, before deleting on
//! the server), none or one of: a write in place, a save by rename, a write
//! that puts the time back, a delete. Every row runs with this machine's
//! sync state kept and lost.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use common::{World, kept, server_hashes, trashed, tree, world};
use hd_client::engine::{Engine, Moment, Options};

/// Every content in this test has this length, so an edit that keeps the
/// size is always possible.
const LEN: usize = 64;

fn content(tag: &str) -> Vec<u8> {
    let mut v = format!("{tag}|").into_bytes();
    assert!(v.len() <= LEN, "tag too long: {tag}");
    v.resize(LEN, b'.');
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Here {
    Nothing,
    Edit,
    Save,
    EditKeepingStat,
    Delete,
    RenameAway,
    RenameOnto,
    New,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum There {
    Nothing,
    Edit,
    Delete,
    RenameAway,
    New,
    NewSame,
}

/// What a program does to the file while the engine is at work on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    Write,
    Save,
    KeepStat,
    Remove,
}

const MOMENTS: [Moment; 5] = [
    Moment::BeforeReplace,
    Moment::BeforeLocalDelete,
    Moment::NameVacant,
    Moment::BeforeCommit,
    Moment::BeforeRemoteDelete,
];
const ACTS: [Act; 4] = [Act::Write, Act::Save, Act::KeepStat, Act::Remove];

/// What was written, and what a program destroyed itself.
#[derive(Default)]
struct Ledger {
    written: BTreeSet<Vec<u8>>,
    destroyed: BTreeSet<Vec<u8>>,
}

type Shared = Arc<Mutex<Ledger>>;

/// Writes `data` over the file at `p` in place, and puts its time back:
/// size, time and inode stay as they were.
fn write_keeping_stat(p: &Path, data: &[u8]) {
    use std::io::Write;
    let modified = fs::metadata(p).unwrap().modified().unwrap();
    let mut f = fs::OpenOptions::new().write(true).open(p).unwrap();
    f.write_all(data).unwrap();
    f.set_modified(modified).unwrap();
    f.sync_all().unwrap();
}

fn age(p: &Path) {
    let f = fs::OpenOptions::new().write(true).open(p).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(120)).unwrap();
}

fn act(what: Act, p: &Path, tag: &str, ledger: &Shared) {
    let mut l = ledger.lock().unwrap();
    let old = fs::read(p).ok();
    let new = content(tag);
    match what {
        Act::Write => fs::write(p, &new).unwrap(),
        Act::Save => {
            let tmp = p.with_extension("editor-tmp");
            fs::write(&tmp, &new).unwrap();
            fs::rename(&tmp, p).unwrap();
        }
        Act::KeepStat => {
            if old.is_none() {
                return;
            }
            write_keeping_stat(p, &new);
        }
        Act::Remove => {
            if old.is_none() {
                return;
            }
            fs::remove_file(p).unwrap();
        }
    }
    l.destroyed.extend(old);
    if what != Act::Remove {
        l.written.insert(new);
    }
}

fn options() -> Options {
    // The guards against mass deletes and changes are tested elsewhere;
    // here every case must play out in full.
    Options { confirm_deletes: true, confirm_changes: true, ..Options::default() }
}

/// Syncs both machines until neither has anything left to do, and says
/// whether they then agree (`None`) or how they differ.
fn settle(a: &mut Engine, b: &mut Engine, w: &World) -> Option<String> {
    let show = |side: &str| -> Vec<(String, String)> {
        tree(&w.dir.join(side))
            .into_iter()
            .map(|(p, d)| (p, String::from_utf8_lossy(&d).into_owned()))
            .collect()
    };
    for _ in 0..12 {
        let ra = a.sync(0).unwrap();
        let rb = b.sync(0).unwrap();
        let quiet = !ra.changed_anything() && !rb.changed_anything();
        if quiet && ra.errors.is_empty() && rb.errors.is_empty() {
            let (ta, tb) = (show("a"), show("b"));
            return (ta != tb).then(|| format!("the two machines differ:\n{ta:?}\n{tb:?}"));
        }
    }
    Some("the two machines never settled".into())
}

/// One row of the table: every race on its own pair of files.
fn run_case(synced: bool, here: Here, there: There, lose_state: bool) -> usize {
    let case = format!("{synced}-{here:?}-{there:?}-{lose_state}");
    let w = world(&format!("proof-{case}"));
    for side in ["a", "b"] {
        Engine::mark_root(&w.dir.join(side)).unwrap();
    }
    let mut here_m = w.reopen("a", "", options());
    let mut there_m = w.reopen("b", "", options());
    let ledger: Shared = Arc::default();
    let mut races = vec![None];
    races.extend(MOMENTS.iter().flat_map(|m| ACTS.iter().map(move |x| Some((*m, *x)))));
    let file = |i: usize| format!("f{i}");
    let other = |i: usize| format!("h{i}");
    let record = |data: &[u8]| ledger.lock().unwrap().written.insert(data.to_vec());

    // Both machines hold f and h, synced and at rest.
    if synced {
        for i in 0..races.len() {
            for (name, tag) in [(file(i), "orig"), (other(i), "other")] {
                let data = content(&format!("{case}/{i}/{tag}"));
                w.write("a", &name, &data);
                age(&w.path("a", &name));
                record(&data);
            }
        }
        here_m.sync(0).unwrap();
        there_m.sync(0).unwrap();
        assert_eq!(tree(&w.dir.join("a")), tree(&w.dir.join("b")), "{case}: setup");
    }
    // The other machine acts, and syncs.
    for i in 0..races.len() {
        let p = w.path("b", &file(i));
        match there {
            There::Nothing => {}
            There::Edit | There::New => {
                let data = content(&format!("{case}/{i}/there"));
                fs::write(&p, &data).unwrap();
                record(&data);
            }
            There::NewSame => {
                let data = content(&format!("{case}/{i}/same"));
                fs::write(&p, &data).unwrap();
                record(&data);
            }
            There::Delete => fs::remove_file(&p).unwrap(),
            There::RenameAway => fs::rename(&p, w.path("b", &format!("gb{i}"))).unwrap(),
        }
    }
    there_m.sync(0).unwrap();
    // This machine acts, without syncing.
    for i in 0..races.len() {
        let p = w.path("a", &file(i));
        let data = if there == There::NewSame {
            content(&format!("{case}/{i}/same"))
        } else {
            content(&format!("{case}/{i}/here"))
        };
        match here {
            Here::Nothing => {}
            Here::Edit | Here::New => fs::write(&p, &data).unwrap(),
            Here::Save => {
                fs::write(p.with_extension("tmp"), &data).unwrap();
                fs::rename(p.with_extension("tmp"), &p).unwrap();
            }
            Here::EditKeepingStat => write_keeping_stat(&p, &data),
            Here::Delete => fs::remove_file(&p).unwrap(),
            Here::RenameAway => fs::rename(&p, w.path("a", &format!("ga{i}"))).unwrap(),
            Here::RenameOnto => fs::rename(w.path("a", &other(i)), &p).unwrap(),
        }
        if matches!(here, Here::Edit | Here::Save | Here::EditKeepingStat | Here::New) {
            record(&data);
        }
    }
    if lose_state {
        drop(here_m);
        fs::remove_dir_all(w.dir.join("a-state")).unwrap();
        here_m = w.reopen("a", "", options());
    }
    // Something acts on each file at one of the engine's moments.
    let mut pending: Vec<(String, Moment, Act)> =
        races.iter().enumerate().filter_map(|(i, r)| r.map(|(m, x)| (file(i), m, x))).collect();
    let hooked = Arc::clone(&ledger);
    let tag = case.clone();
    here_m.set_hook(Box::new(move |m, path| {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return };
        if let Some(i) = pending.iter().position(|(n, pm, _)| n == name && *pm == m) {
            let (_, _, x) = pending.remove(i);
            act(x, path, &format!("{tag}/{name}/race"), &hooked);
        }
    }));
    let unsettled = settle(&mut here_m, &mut there_m, &w);

    // 1. Nothing is lost, even with every trash item expired.
    let server = server_hashes(&w.app);
    let mut kept_here: BTreeSet<Vec<u8>> = BTreeSet::new();
    for side in ["a", "b"] {
        kept_here.extend(tree(&w.dir.join(side)).into_values());
        kept_here.extend(kept(&w.dir.join(side)));
    }
    let seen = ledger.lock().unwrap();
    let mut checked = 0;
    for data in seen.written.difference(&seen.destroyed) {
        let sha = hd_crypto::sha256(data).unwrap();
        assert!(
            kept_here.contains(data) || server.contains(&sha),
            "{case}: lost {:?}",
            String::from_utf8_lossy(data)
        );
        checked += 1;
    }
    // 2. The client trash only ever holds what the server has.
    for side in ["a", "b"] {
        for data in trashed(&w.dir.join(side)) {
            assert!(
                server.contains(&hd_crypto::sha256(&data).unwrap()),
                "{case}: {side}'s trash holds the only copy of {:?}",
                String::from_utf8_lossy(&data)
            );
        }
    }
    // 3. The machines agree, and the store is whole.
    assert!(unsettled.is_none(), "{case}: {}", unsettled.unwrap_or_default());
    assert!(w.app.store.fsck(true).unwrap().is_clean(), "{case}: fsck");
    drop((here_m, there_m));
    let _ = fs::remove_dir_all(&w.dir);
    checked
}

fn rows() -> Vec<(bool, Here, There)> {
    let mut rows = Vec::new();
    for here in [
        Here::Nothing,
        Here::Edit,
        Here::Save,
        Here::EditKeepingStat,
        Here::Delete,
        Here::RenameAway,
        Here::RenameOnto,
    ] {
        for there in [There::Nothing, There::Edit, There::Delete, There::RenameAway] {
            rows.push((true, here, there));
        }
    }
    for (here, there) in [
        (Here::New, There::Nothing),
        (Here::Nothing, There::New),
        (Here::New, There::New),
        (Here::New, There::NewSame),
    ] {
        rows.push((false, here, there));
    }
    rows
}

#[test]
fn every_case_of_the_sync_table_loses_nothing_with_state_kept() {
    let mut checked = 0;
    for (synced, here, there) in rows() {
        checked += run_case(synced, here, there, false);
    }
    assert!(checked > 1000, "only {checked} contents were checked");
}

#[test]
fn every_case_of_the_sync_table_loses_nothing_with_state_lost() {
    let mut checked = 0;
    for (synced, here, there) in rows() {
        checked += run_case(synced, here, there, true);
    }
    assert!(checked > 1000, "only {checked} contents were checked");
}
