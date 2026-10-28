//! Scrubbing: re-reading every object to find silent damage before it is
//! needed.
//!
//! A bad object is quarantined, never deleted, and then reads as missing,
//! so the next time any client has that content it uploads it again and
//! the store heals. `fsck` says which files a missing object affects.
//!
//! An object the disk cannot read (twice) is quarantined the same way, and
//! the scrub goes on: one bad sector must not hide the rest of the disk.
//!
//! The metadata files are checked too: every snapshot and journal on disk
//! must still verify, because recovery may need them after a restart. The
//! state in memory is good (it was verified when it was read), so damage
//! there is repaired by setting a bad snapshot aside and writing a fresh
//! checkpoint, after which recovery no longer depends on the damaged file.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hd_chunk::ObjectId;
use hd_common::Result;

use crate::Store;
use crate::objects::{HEADER_LEN, Health, Kind};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    pub checked: usize,
    pub bytes: u64,
    /// Objects found damaged or unreadable, and quarantined.
    pub quarantined: Vec<(Kind, ObjectId)>,
    /// Objects that could not be checked or set aside (a failing disk);
    /// "kind id: error".
    pub failed: Vec<String>,
    /// Metadata files found damaged; "name: problem".
    pub metadata_damaged: Vec<String>,
    /// Stopped early because asked to.
    pub stopped: bool,
}

impl Store {
    /// Verifies every object, at no more than `max_bytes_per_sec` (0 for
    /// no limit). `stop` ends it early.
    pub fn scrub(&self, max_bytes_per_sec: u64, stop: &AtomicBool) -> Result<ScrubReport> {
        let started = Instant::now();
        let mut report = ScrubReport::default();
        let objects = self.objects();
        for kind in Kind::ALL {
            objects.for_each(kind, |id, _, meta| {
                if stop.load(Ordering::Relaxed) {
                    report.stopped = true;
                    return Ok(());
                }
                // A read error is retried once, then treated as damage.
                let health = objects.check(kind, &id).or_else(|_| objects.check(kind, &id));
                let reason = match health {
                    Ok(Health::Good | Health::Missing) => None,
                    Ok(Health::Corrupt(reason)) => Some(reason),
                    Err(e) => Some(format!("unreadable: {e}")),
                };
                if let Some(reason) = reason {
                    match objects.quarantine(kind, &id, &reason) {
                        Ok(()) => report.quarantined.push((kind, id)),
                        Err(e) => report.failed.push(format!("{} {id}: {e}", kind.name())),
                    }
                }
                report.checked += 1;
                report.bytes += meta.len().saturating_sub(HEADER_LEN as u64);
                if let Some(due_ms) =
                    report.bytes.saturating_mul(1000).checked_div(max_bytes_per_sec)
                    && let Some(wait) = Duration::from_millis(due_ms).checked_sub(started.elapsed())
                {
                    std::thread::sleep(wait);
                }
                Ok(())
            })?;
        }
        if !report.stopped {
            report.metadata_damaged = self.scrub_metadata()?;
        }
        Ok(report)
    }
}
