//! Background upkeep while the server runs:
//! - a checkpoint every ten minutes when anything changed;
//! - retention then garbage collection every `HD_MAINTENANCE_HOURS`, the
//!   first an hour after start;
//! - a full throttled scrub every `HD_SCRUB_DAYS`, the first a day after
//!   start.
//!
//! Each job's outcome is kept for the admin page. A failure is logged and
//! retried at the next interval; none of them can lose data. The worst a
//! failed GC does is leave space unreclaimed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hd_common::timefmt;

use crate::App;

const TICK: Duration = Duration::from_mins(1);
const CHECKPOINT_EVERY: Duration = Duration::from_mins(10);
const FIRST_MAINTENANCE: Duration = Duration::from_hours(1);
const FIRST_SCRUB: Duration = Duration::from_hours(24);

/// The last outcome of each job, as text for the admin page.
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub checkpoint: Option<(i64, String)>,
    pub retention: Option<(i64, String)>,
    pub gc: Option<(i64, String)>,
    pub scrub: Option<(i64, String)>,
}

#[derive(Debug, Default)]
pub struct Maintenance {
    pub status: Mutex<Status>,
    pub stop: AtomicBool,
}

impl Maintenance {
    fn record(&self, f: impl FnOnce(&mut Status)) {
        f(&mut self.status.lock().unwrap_or_else(PoisonError::into_inner));
    }

    pub fn snapshot(&self) -> Status {
        self.status.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

fn outcome<T: std::fmt::Debug>(r: &hd_common::Result<T>) -> String {
    match r {
        Ok(v) => format!("{v:?}"),
        Err(e) => format!("FAILED: {e}"),
    }
}

/// Starts the maintenance thread.
pub fn start(app: &Arc<App>) -> hd_common::Result<()> {
    let app = Arc::clone(app);
    std::thread::Builder::new()
        .name("maintenance".to_owned())
        .stack_size(512 * 1024)
        .spawn(move || run(&app))
        .map(|_| ())
        .map_err(|e| hd_common::Error::new(format!("cannot start maintenance: {e}")))
}

fn run(app: &App) {
    let started = Instant::now();
    let mut last_checkpoint = (Instant::now(), app.store.read(|s| s.seq));
    let mut next_maintenance = app.config.maintenance_every.map(|_| started + FIRST_MAINTENANCE);
    let mut next_scrub = app.config.scrub_every.map(|_| started + FIRST_SCRUB);
    let m = &app.maintenance;
    while !m.stop.load(Ordering::Relaxed) {
        std::thread::sleep(TICK);
        let now = Instant::now();
        let seq = app.store.read(|s| s.seq);
        if seq != last_checkpoint.1 && now.duration_since(last_checkpoint.0) >= CHECKPOINT_EVERY {
            let r = app.store.checkpoint();
            if let Err(e) = &r {
                eprintln!("hd-server: checkpoint failed: {e}");
            }
            m.record(|s| s.checkpoint = Some((timefmt::unix_ms(), outcome(&r))));
            last_checkpoint = (now, seq);
        }
        if let (Some(at), Some(every)) = (next_maintenance, app.config.maintenance_every)
            && now >= at
        {
            let r = app.store.apply_retention(timefmt::unix_ms(), &app.config.retention);
            eprintln!("hd-server: retention: {}", outcome(&r));
            m.record(|s| s.retention = Some((timefmt::unix_ms(), outcome(&r))));
            let r =
                app.store.collect_garbage(timefmt::unix_ms(), &hd_store::gc::GcOptions::default());
            eprintln!("hd-server: gc: {}", outcome(&r));
            m.record(|s| s.gc = Some((timefmt::unix_ms(), outcome(&r))));
            next_maintenance = Some(now + every);
        }
        if let (Some(at), Some(every)) = (next_scrub, app.config.scrub_every)
            && now >= at
        {
            let r = app.store.scrub(app.config.scrub_bytes_per_sec, &m.stop);
            let text = match &r {
                Ok(rep) => format!(
                    "{} objects, {} bytes, {} quarantined{}",
                    rep.checked,
                    rep.bytes,
                    rep.quarantined.len(),
                    if rep.stopped { " (stopped)" } else { "" }
                ),
                Err(e) => format!("FAILED: {e}"),
            };
            eprintln!("hd-server: scrub: {text}");
            m.record(|s| s.scrub = Some((timefmt::unix_ms(), text)));
            next_scrub = Some(Instant::now() + every);
        }
    }
}
