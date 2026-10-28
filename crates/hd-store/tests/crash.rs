//! Crash and corruption tests for the metadata.
//!
//! The rule under test: **an acknowledged change is never lost, and
//! recovery never invents one.** After any crash the reopened state must
//! be exactly the state after the acknowledged operations, or after those
//! plus the one in flight when the crash came (its record may have reached
//! the disk before the failure was reported). Anything else, including a
//! refusal to open after an ordinary crash, fails the test.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use hd_common::fsio::faults;
use hd_store::journal;
use hd_store::model::{Content, Origin};
use hd_store::{MetaOptions, Op, State, Store, StoreOptions};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hd-crash-{}-{name}", std::process::id()));
    remove(&dir);
    dir
}

fn writable(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries {
            let entry = entry.unwrap();
            let p = entry.path();
            if entry.file_type().unwrap().is_dir() {
                writable(&p);
            } else {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
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

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

fn options(snapshot_every: u64) -> StoreOptions {
    StoreOptions { min_free: 0, meta: MetaOptions { snapshot_every, repair_tail: false } }
}

fn content(tag: &str) -> Content {
    let id = hd_chunk::ObjectId::of(tag.as_bytes()).unwrap();
    Content {
        manifest: id,
        size: tag.len() as u64,
        sha256: id.0,
        mtime_ms: 1,
        created_ms: 2,
        device: "test".into(),
        origin: Origin::Upload,
    }
}

#[derive(Clone, Debug)]
enum Step {
    Op(Op),
    Checkpoint,
}

/// A script that touches every kind of operation, with checkpoints in
/// between. Trash and version IDs are found by running it on a model.
fn script() -> Vec<Step> {
    let u = || "alice".to_owned();
    let put = |p: &str, t: &str| Op::PutVersion { user: u(), path: p.into(), content: content(t) };
    let mut model = State::default();
    let mut steps = Vec::new();
    let run = |model: &mut State, steps: &mut Vec<Step>, op: Op| {
        let applied = model.apply(&op, model.seq + 1).unwrap();
        steps.push(Step::Op(op));
        applied
    };
    run(&mut model, &mut steps, put("docs/a.txt", "a1"));
    let first = run(&mut model, &mut steps, put("docs/a.txt", "a2")).version;
    run(&mut model, &mut steps, Op::Mkdir { user: u(), path: "photos/2026".into() });
    steps.push(Step::Checkpoint);
    run(&mut model, &mut steps, put("photos/2026/p.jpg", "p"));
    run(
        &mut model,
        &mut steps,
        Op::Move { user: u(), from: "docs".into(), to: "archive/docs".into() },
    );
    run(
        &mut model,
        &mut steps,
        Op::Copy {
            user: u(),
            from: "archive/docs/a.txt".into(),
            to: "b.txt".into(),
            created_ms: 3,
        },
    );
    steps.push(Step::Checkpoint);
    let trash =
        run(&mut model, &mut steps, Op::Trash { user: u(), path: "photos".into(), deleted_ms: 4 })
            .trash_id
            .unwrap();
    run(
        &mut model,
        &mut steps,
        Op::PutVersion { user: "bob".into(), path: "x".into(), content: content("bob") },
    );
    run(&mut model, &mut steps, Op::Restore { user: u(), trash_id: trash, to: "photos".into() });
    run(&mut model, &mut steps, put("archive/docs/a.txt", "a3"));
    steps.push(Step::Checkpoint);
    let _ = first;
    let versions = match &model.user("alice").unwrap().get("archive/docs/a.txt").unwrap().node {
        hd_store::model::Node::File { versions, .. } => versions.clone(),
        hd_store::model::Node::Dir => panic!(),
    };
    run(
        &mut model,
        &mut steps,
        Op::DropVersion {
            user: u(),
            path: "archive/docs/a.txt".into(),
            version_id: versions[0].id,
        },
    );
    let t2 =
        run(&mut model, &mut steps, Op::Trash { user: u(), path: "b.txt".into(), deleted_ms: 5 })
            .trash_id
            .unwrap();
    run(&mut model, &mut steps, Op::Purge { user: u(), trash_id: t2 });
    run(&mut model, &mut steps, put("photos/2026/q.jpg", "q"));
    steps
}

fn ops_of(steps: &[Step]) -> Vec<Op> {
    steps
        .iter()
        .filter_map(|s| match s {
            Step::Op(op) => Some(op.clone()),
            Step::Checkpoint => None,
        })
        .collect()
}

fn model_of(ops: &[Op]) -> State {
    let mut s = State::default();
    for op in ops {
        s.apply(op, s.seq + 1).unwrap();
    }
    s
}

fn state(store: &Store) -> State {
    store.read(State::clone)
}

fn journals(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(dir.join("meta"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with("journal."))
        .collect();
    out.sort();
    out
}

fn quarantined(dir: &Path) -> usize {
    fs::read_dir(dir.join("quarantine")).unwrap().count()
}

/// Proves the reopened store still works: one more change, then another
/// reopen that must see it.
fn still_usable(dir: &Path, opts: &StoreOptions, mut expected: State) {
    let extra = Op::Mkdir { user: "alice".into(), path: "after-recovery".into() };
    {
        let store = Store::open(dir, opts).unwrap();
        store.commit(&extra).unwrap();
    }
    expected.apply(&extra, expected.seq + 1).unwrap();
    let store = Store::open(dir, opts).unwrap();
    assert_eq!(state(&store), expected);
}

#[test]
fn cutting_the_journal_at_every_byte_recovers_exactly_the_whole_records() {
    let template = scratch("cut-template");
    Store::init(&template).unwrap();
    let ops = ops_of(&script());
    {
        let store = Store::open(&template, &options(0)).unwrap();
        for op in &ops {
            store.commit(op).unwrap();
        }
    }
    let journal_path = journals(&template).pop().unwrap();
    let bytes = fs::read(&journal_path).unwrap();
    let scan = journal::scan(&bytes, 1).unwrap();
    assert_eq!(scan.records.len(), ops.len());
    let work = scratch("cut-work");
    for cut in 0..=bytes.len() {
        remove(&work);
        copy_tree(&template, &work);
        let journal = work.join("meta").join(journal_path.file_name().unwrap());
        fs::OpenOptions::new().write(true).open(&journal).unwrap().set_len(cut as u64).unwrap();
        let whole = scan.ends.iter().filter(|&&e| e <= cut as u64).count();
        let expected = model_of(&ops[..whole]);
        let store = Store::open(&work, &options(0))
            .unwrap_or_else(|e| panic!("cut at {cut}: refused to open: {e}"));
        assert_eq!(state(&store), expected, "cut at {cut}");
        let at_boundary = cut == journal::HEADER_LEN || scan.ends.contains(&(cut as u64));
        // Torn bytes are set aside exactly when the cut fell inside a
        // record (an empty file has nothing to set aside).
        let inside_a_record = !at_boundary && cut != 0 && cut < bytes.len();
        assert_eq!(store.recovery().torn_bytes > 0, inside_a_record, "cut {cut}");
        drop(store);
        // Nothing was thrown away: a torn tail is in quarantine.
        if !at_boundary && cut < bytes.len() {
            assert!(quarantined(&work) >= 1, "cut at {cut}");
        }
        // Every 50th cut also checks the store accepts and keeps new writes.
        if cut % 50 == 0 {
            still_usable(&work, &options(0), expected);
        }
    }
    remove(&work);
    remove(&template);
}

/// Runs the script with the `k`-th durable-write step failing. Returns
/// the ops acknowledged, the op in flight when the fault fired, and
/// whether a fault fired at all.
fn run_with_fault(dir: &Path, opts: &StoreOptions, k: u64) -> (Vec<Op>, Option<Op>, bool) {
    let store = Store::open(dir, opts).unwrap();
    faults::arm(k);
    let mut acked = Vec::new();
    let mut in_flight = None;
    for step in script() {
        match step {
            Step::Op(op) => {
                if store.commit(&op).is_ok() {
                    acked.push(op);
                } else {
                    // After the first failure the store refuses writes, so
                    // at most one op can be in doubt.
                    if faults::fired().is_some() {
                        in_flight = Some(op);
                    }
                    break;
                }
            }
            Step::Checkpoint => {
                // A failed checkpoint loses nothing; later commits either
                // continue or are refused.
                let _ = store.checkpoint();
            }
        }
    }
    let fired = faults::fired().is_some();
    faults::disarm();
    drop(store);
    (acked, in_flight, fired)
}

fn fault_at_every_step(name: &str, opts: &StoreOptions) {
    let dir = scratch(name);
    let mut k = 1;
    loop {
        remove(&dir);
        Store::init(&dir).unwrap();
        let (acked, in_flight, fired) = run_with_fault(&dir, opts, k);
        if !fired {
            // Past the last fault point: the script ran clean.
            assert_eq!(acked.len(), ops_of(&script()).len());
            break;
        }
        let store = Store::open(&dir, opts)
            .unwrap_or_else(|e| panic!("fault {k}: refused to open after a crash: {e}"));
        let got = state(&store);
        drop(store);
        let without = model_of(&acked);
        let with = in_flight.map(|op| {
            let mut s = without.clone();
            s.apply(&op, s.seq + 1).unwrap();
            s
        });
        assert!(
            got == without || Some(&got) == with.as_ref(),
            "fault {k}: recovered state matches neither the acknowledged ops nor those plus the \
             one in flight"
        );
        still_usable(&dir, opts, got);
        k += 1;
        assert!(k < 2_000, "the script never ran clean");
    }
    // The script must have crossed many fault points for this to mean much.
    assert!(k > 40, "only {k} fault points were exercised");
    remove(&dir);
}

#[test]
fn a_failure_at_any_write_fsync_link_or_rename_loses_nothing_acknowledged() {
    fault_at_every_step("faults-manual", &options(0));
}

#[test]
fn the_same_holds_with_automatic_checkpoints() {
    fault_at_every_step("faults-auto", &options(3));
}

#[test]
fn a_crash_during_recovery_is_itself_recoverable() {
    let template = scratch("recover-template");
    Store::init(&template).unwrap();
    let ops = ops_of(&script());
    {
        let store = Store::open(&template, &options(0)).unwrap();
        for op in &ops {
            store.commit(op).unwrap();
        }
    }
    // A torn record at the end, as a crash mid-append leaves it.
    let journal_path = journals(&template).pop().unwrap();
    let mut bytes = fs::read(&journal_path).unwrap();
    let extra = journal::record(ops.len() as u64 + 1, &ops[0]).unwrap();
    bytes.extend_from_slice(&extra[..extra.len() / 2]);
    fs::write(&journal_path, &bytes).unwrap();
    let expected = model_of(&ops);
    let work = scratch("recover-work");
    let mut k = 1;
    loop {
        remove(&work);
        copy_tree(&template, &work);
        faults::arm(k);
        let first = Store::open(&work, &options(0));
        let fired = faults::fired().is_some();
        faults::disarm();
        drop(first);
        let store = Store::open(&work, &options(0))
            .unwrap_or_else(|e| panic!("fault {k} in recovery: then refused to open: {e}"));
        assert_eq!(state(&store), expected, "fault {k} in recovery");
        drop(store);
        if !fired {
            break;
        }
        k += 1;
        assert!(k < 500);
    }
    assert!(k > 3, "recovery crossed only {k} fault points");
    remove(&work);
    remove(&template);
}

fn store_with_ops(name: &str, n: usize) -> (PathBuf, Vec<Op>) {
    let dir = scratch(name);
    Store::init(&dir).unwrap();
    let ops: Vec<Op> = ops_of(&script()).into_iter().take(n).collect();
    let store = Store::open(&dir, &options(0)).unwrap();
    for op in &ops {
        store.commit(op).unwrap();
    }
    (dir, ops)
}

#[test]
fn corruption_is_refused_and_only_a_damaged_final_record_can_be_repaired() {
    let (dir, ops) = store_with_ops("corrupt", 6);
    let journal_path = journals(&dir).pop().unwrap();
    let clean = fs::read(&journal_path).unwrap();
    let scan = journal::scan(&clean, 1).unwrap();

    // A flipped byte in a middle record: refused, with or without repair.
    let mut bad = clean.clone();
    let middle = usize::try_from(scan.ends[2]).unwrap() + 20;
    bad[middle] ^= 1;
    fs::write(&journal_path, &bad).unwrap();
    let err = Store::open(&dir, &options(0)).unwrap_err();
    assert!(err.message().contains("refusing to open"), "{err}");

    // In the final record: refused by default; repair sets the record
    // aside in quarantine and opens with everything before it.
    let mut bad = clean.clone();
    let last = usize::try_from(scan.ends[4]).unwrap() + 20;
    bad[last] ^= 1;
    fs::write(&journal_path, &bad).unwrap();
    assert!(Store::open(&dir, &options(0)).unwrap_err().message().contains("--repair-tail"));
    let repair =
        StoreOptions { min_free: 0, meta: MetaOptions { snapshot_every: 0, repair_tail: true } };
    let before = quarantined(&dir);
    let store = Store::open(&dir, &repair).unwrap();
    assert_eq!(state(&store), model_of(&ops[..5]));
    assert!(store.recovery().repaired_bytes > 0);
    drop(store);
    assert_eq!(quarantined(&dir), before + 1);
    remove(&dir);
}

#[test]
fn a_damaged_snapshot_falls_back_to_an_older_one_and_pruning_keeps_enough() {
    let dir = scratch("snapshots");
    Store::init(&dir).unwrap();
    let ops = ops_of(&script());
    {
        let store = Store::open(&dir, &options(0)).unwrap();
        for (i, op) in ops.iter().enumerate() {
            store.commit(op).unwrap();
            if i % 2 == 1 {
                store.checkpoint().unwrap();
            }
        }
    }
    let meta = dir.join("meta");
    let mut snapshots: Vec<PathBuf> = fs::read_dir(&meta)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with("snapshot."))
        .collect();
    snapshots.sort();
    assert_eq!(snapshots.len(), 3, "pruning keeps three snapshots");
    let expected = model_of(&ops);
    // Damage the two newest; the third, with the journals kept for it,
    // still rebuilds everything.
    for p in &snapshots[1..] {
        let mut b = fs::read(p).unwrap();
        b[30] ^= 0xff;
        fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(p, &b).unwrap();
    }
    let store = Store::open(&dir, &options(0)).unwrap();
    assert_eq!(state(&store), expected);
    assert_eq!(store.recovery().bad_snapshots.len(), 2);
    drop(store);
    still_usable(&dir, &options(0), expected);
    remove(&dir);
}

#[test]
fn a_missing_journal_is_refused_rather_than_skipped() {
    let dir = scratch("gap");
    Store::init(&dir).unwrap();
    let ops = ops_of(&script());
    {
        let store = Store::open(&dir, &options(0)).unwrap();
        for (i, op) in ops.iter().enumerate() {
            store.commit(op).unwrap();
            if i == 3 || i == 7 {
                store.checkpoint().unwrap();
            }
        }
    }
    let all = journals(&dir);
    assert_eq!(all.len(), 3);
    // Losing the newest snapshot and the journal after the older one
    // leaves a hole in the records: that must stop the store.
    let meta = dir.join("meta");
    let newest_snapshot = meta.join(format!("snapshot.{:020}", 8));
    fs::remove_file(&newest_snapshot).unwrap();
    fs::remove_file(&all[1]).unwrap();
    let err = Store::open(&dir, &options(0)).unwrap_err();
    assert!(err.message().contains("missing"), "{err}");
    remove(&dir);
}
