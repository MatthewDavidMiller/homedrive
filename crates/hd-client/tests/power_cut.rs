//! The power goes while a client syncs: at every write the client makes,
//! everything not yet fsynced is lost, as `faults::shadow` models it. Then
//! the computer comes back and syncs. Every version of every file must
//! still exist somewhere, and the two machines must agree.

#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::many_single_char_names,
    clippy::panic
)]

mod common;

use std::collections::BTreeSet;
use std::fs;

use common::{World, kept, server_hashes, trashed, tree, world};
use hd_client::engine::Options;
use hd_common::fsio::faults;
use hd_common::fsio::faults::shadow;

/// Sets up a round with one of everything a sync does, and returns every
/// content involved.
fn prepare(w: &World, a_name: &str, b_name: &str, remote: &str) -> Vec<Vec<u8>> {
    let mut a = w.client(a_name, remote);
    let mut b = w.client(b_name, remote);
    let tag = |t: &str| format!("{remote}/{t}/").into_bytes().repeat(40);
    let mut seen = Vec::new();
    let mut write = |side: &str, name: &str, t: &str| {
        let data = tag(t);
        w.write(side, name, &data);
        seen.push(data);
    };
    write(a_name, "replaced.txt", "old");
    write(a_name, "deleted.txt", "doomed");
    write(a_name, "both.txt", "base");
    write(a_name, "dir/kept.txt", "kept");
    a.sync(0).unwrap();
    b.sync(0).unwrap();
    // The other machine changes things.
    write(b_name, "replaced.txt", "newer");
    fs::remove_file(w.path(b_name, "deleted.txt")).unwrap();
    write(b_name, "both.txt", "there");
    write(b_name, "arrives/new.txt", "arriving");
    b.sync(0).unwrap();
    // This machine changes things, to be sent in the round that is cut.
    write(a_name, "both.txt", "here");
    write(a_name, "uploaded.txt", "leaving");
    write(a_name, "dir/kept2.txt", "second");
    seen
}

fn reopen(w: &World, name: &str, remote: &str) -> hd_client::engine::Engine {
    w.reopen(name, remote, Options::default())
}

/// Every file on this machine is whole: one of the contents that were really
/// written, never empty or cut short. Without this, a file the power left
/// empty would pass, since its good content is still an old version on the
/// server, though the user would open an empty file.
fn assert_all_whole(root: &std::path::Path, seen: &[Vec<u8>], label: &str) {
    for (path, data) in tree(root) {
        if path.ends_with('/') || path.contains(hd_client::scan::STAGING_PREFIX) {
            continue;
        }
        assert!(seen.contains(&data), "{label}: {path} is not a whole file: {} bytes", data.len());
    }
}

/// Every content still exists: on either machine, in a trash or kept copy,
/// or on the server.
fn assert_nothing_lost(w: &World, a: &str, b: &str, seen: &[Vec<u8>], label: &str) {
    let server = server_hashes(&w.app);
    let mut held: BTreeSet<Vec<u8>> = BTreeSet::new();
    for side in [a, b] {
        let root = w.dir.join(side);
        held.extend(tree(&root).into_values());
        held.extend(trashed(&root));
        held.extend(kept(&root));
    }
    for data in seen {
        assert!(
            held.contains(data) || server.contains(&hd_crypto::sha256(data).unwrap()),
            "{label}: lost {:?}",
            String::from_utf8_lossy(&data[..data.len().min(40)])
        );
    }
}

/// Cuts the power at each step of one round in turn; returns how many there
/// were.
fn cut_every_step(prefix: &str) -> u64 {
    let w = world(prefix);
    let mut k = 1;
    loop {
        let (a_name, b_name, remote) = (format!("a{k}"), format!("b{k}"), format!("r{k}"));
        let seen = prepare(&w, &a_name, &b_name, &remote);
        let mut a = reopen(&w, &a_name, &remote);
        let local = w.dir.join(&a_name);
        let state = w.dir.join(format!("{a_name}-state"));
        shadow::track(&[local, state]);
        faults::arm(k);
        let result = a.sync(0);
        let point = faults::fired();
        let fired = point.is_some();
        faults::disarm();
        drop(a);
        // A fault that fired is a power cut at that step; with none left to
        // fire, the power goes as the round ends.
        shadow::power_cut();
        assert!(fired || result.is_ok(), "cut {k}: {result:?}");
        let label = format!("cut {k}");
        assert_nothing_lost(&w, &a_name, &b_name, &seen, &label);
        assert_all_whole(&w.dir.join(&a_name), &seen, &label);

        // The computer comes back. It must open, and catch up.
        let mut a = reopen(&w, &a_name, &remote);
        let mut b = reopen(&w, &b_name, &remote);
        for _ in 0..3 {
            let r = a.sync(0).unwrap_or_else(|e| panic!("{label}: after the cut: {e}"));
            assert!(r.errors.is_empty(), "{label}: {r:?}");
            b.sync(0).unwrap();
        }
        assert_nothing_lost(&w, &a_name, &b_name, &seen, &label);
        assert_all_whole(&w.dir.join(&a_name), &seen, &label);
        assert_all_whole(&w.dir.join(&b_name), &seen, &label);
        // A download that was cut off leaves its staging file, cleared later.
        let synced = |side: &str| {
            let mut t = tree(&w.dir.join(side));
            t.retain(|p, _| !p.contains(hd_client::scan::STAGING_PREFIX));
            t
        };
        let (ta, tb) = (synced(&a_name), synced(&b_name));
        assert!(ta == tb, "{label} at {point:?}: the machines disagree");
        drop((a, b));
        if !fired {
            break;
        }
        k += 1;
        assert!(k < 400, "the round never ran clean");
    }
    assert!(w.app.store.fsck(true).unwrap().is_clean());
    k
}

#[test]
fn staging_files_a_cut_left_behind_are_cleared_once_old() {
    let w = world("cut-staging");
    let mut a = w.client("a", "");
    let name = format!("{}abandoned.tmp", hd_client::scan::STAGING_PREFIX);
    let young = format!("{}in-use.tmp", hd_client::scan::STAGING_PREFIX);
    w.write("a", &name, b"half a download");
    w.write("a", &young, b"a download going on now");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
    let f = fs::OpenOptions::new().write(true).open(w.path("a", &name)).unwrap();
    f.set_modified(old).unwrap();
    drop(f);
    a.sync(0).unwrap();
    assert!(!w.path("a", &name).exists());
    assert!(w.path("a", &young).exists(), "it may be in use");
    assert!(w.app.store.read(|s| s.user("alice").unwrap().entries.is_empty()), "never uploaded");
}

#[test]
fn a_power_cut_during_a_sync_loses_nothing() {
    let steps = cut_every_step("cut-round");
    assert!(steps > 20, "only {steps} cuts were exercised");
}
