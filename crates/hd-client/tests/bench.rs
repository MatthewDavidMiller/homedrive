//! How fast a real sync is, end to end over loopback, with real fsyncs.
//!
//! Not part of the gate, because timings prove nothing on a busy machine.
//! `make bench` runs it in a release build. HD_BENCH_FILES and HD_BENCH_MB
//! set the size of the work.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss
)]

mod common;

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::time::Instant;

use common::world;

fn size(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// User and system CPU of this process, client and server together.
fn cpu_seconds() -> (f64, f64) {
    let Ok(stat) = fs::read_to_string("/proc/self/stat") else { return (0.0, 0.0) };
    let after_name = stat.rsplit(')').next().unwrap();
    let field = |n: usize| after_name.split_whitespace().nth(n).unwrap().parse::<f64>().unwrap();
    (field(11) / 100.0, field(12) / 100.0)
}

fn peak_rss_mb() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else { return 0 };
    let line = status.lines().find(|l| l.starts_with("VmHWM")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap() / 1024
}

fn timed<T>(name: &str, items: usize, unit: &str, work: impl FnOnce() -> T) -> T {
    let (started, cpu) = (Instant::now(), cpu_seconds());
    let out = work();
    let wall = started.elapsed().as_secs_f64();
    let rate =
        if items > 0 { format!("{:>10.0} {unit}/s", items as f64 / wall) } else { String::new() };
    let spent = cpu_seconds();
    println!(
        "{name:<34} {wall:>8.2} s wall {:>7.2} s user {:>7.2} s sys {rate}  peak {} MB",
        spent.0 - cpu.0,
        spent.1 - cpu.1,
        peak_rss_mb()
    );
    out
}

/// Bytes that do not repeat, deduplicate, or look like anything in particular.
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

#[test]
#[ignore = "a measurement, run with make bench"]
fn a_sync_end_to_end() {
    let files = size("HD_BENCH_FILES", 20_000);
    let mb = size("HD_BENCH_MB", 1024);
    let w = world("bench");
    let mut a = w.client("a", "");
    let mut b = w.client("b", "");

    timed("write the test files (no sync)", files, "files", || {
        for i in 0..files {
            let rel = format!("small/{}/{}/{i}.txt", i % 50, i % 7);
            w.write("a", &rel, &noise(4096, i as u64 + 1));
        }
    });
    timed("upload small files", files, "files", || a.sync(0).unwrap());
    timed("download small files", files, "files", || b.sync(0).unwrap());
    timed("idle round, nothing changed", files, "files", || a.sync(0).unwrap());

    // Written a piece at a time, so the peak shows the sync's own memory.
    let big = w.path("a", "big.bin");
    let mut file = fs::File::create(&big).unwrap();
    for i in 0..mb {
        file.write_all(&noise(1 << 20, i as u64 + 99)).unwrap();
    }
    timed("upload a large file", mb, "MB", || a.sync(0).unwrap());
    timed("download a large file", mb, "MB", || b.sync(0).unwrap());
    file.seek(SeekFrom::Start((mb as u64) << 19)).unwrap();
    file.write_all(&noise(4096, 7)).unwrap();
    drop(file);
    timed("upload a 4 KB edit of it", mb, "MB", || a.sync(0).unwrap());
    timed("download that edit", mb, "MB", || b.sync(0).unwrap());

    timed("edit one small file", 1, "rounds", || {
        w.write("a", "small/0/0/0.txt", b"edited");
        a.sync(0).unwrap()
    });
    timed("server scrub-style fsck", 0, "", || assert!(w.app.store.fsck(true).unwrap().is_clean()));

    let state = w.app.store.read(hd_store::model::State::clone);
    timed("decode a snapshot of the store", files, "files", || {
        hd_store::model::State::decode(&state.encode()).unwrap()
    });
    println!("data: {}", w.dir.display());
}
