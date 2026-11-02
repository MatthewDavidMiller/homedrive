//! Keeps the reason for a crash. A release build ends at the first panic on
//! any thread, and a program started from Explorer or at sign-in has no
//! console to say why on, so the reason goes to `crash.log` in the state
//! folder. The most recent reports are kept.

use std::fmt::Write as _;

use hd_common::{fsio, timefmt};

use crate::config;

const FILE: &str = "crash.log";
const KEEP: usize = 16 * 1024;

/// Writes every panic to `crash.log`, as well as where it would have gone.
pub fn install() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut report = String::new();
        let thread = std::thread::current();
        let _ = writeln!(
            report,
            "{} homedrive {} on thread {}: {info}",
            timefmt::rfc3339_millis(timefmt::unix_seconds(), 0),
            hd_common::VERSION,
            thread.name().unwrap_or("?"),
        );
        // A panic here would abort without the report, so failures are
        // ignored; the standard message still follows.
        if let Ok(dir) = config::state_root() {
            let _ = fsio::mkdir_durable(&dir, 0o700);
            let path = dir.join(FILE);
            let old = fsio::read_bounded(&path, KEEP).ok().flatten().unwrap_or_default();
            let mut all = old[old.len().saturating_sub(KEEP / 2)..].to_vec();
            all.extend_from_slice(report.as_bytes());
            let _ = fsio::atomic_replace(&path, &all, KEEP * 2);
        }
        previous(info);
    }));
}
