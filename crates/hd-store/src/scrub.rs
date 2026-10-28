//! Scrubbing: re-reading every object to find silent damage before it is
//! needed.
//!
//! A bad object is quarantined, never deleted, and then reads as missing,
//! so the next time any client has that content it uploads it again and
//! the store heals. `fsck` says which files a missing object affects.

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
    /// Objects found damaged and quarantined.
    pub quarantined: Vec<(Kind, ObjectId)>,
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
                match objects.check(kind, &id)? {
                    Health::Good | Health::Missing => {}
                    Health::Corrupt(reason) => {
                        objects.quarantine(kind, &id, &reason)?;
                        report.quarantined.push((kind, id));
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
        Ok(report)
    }
}
