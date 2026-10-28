//! Background upkeep while the server runs:
//! - a checkpoint every ten minutes when anything changed;
//! - retention, then garbage collection, then a reference check (every
//!   version's manifest and chunks are present) every
//!   `HD_MAINTENANCE_HOURS`, the first an hour after start. Scrub only
//!   re-reads the objects that exist, so an object that went missing
//!   would otherwise go unnoticed until someone ran `fsck`;
//! - a full throttled scrub every `HD_SCRUB_DAYS`, the first a day after
//!   start, of every object and metadata file, followed by a reference
//!   check;
//! - a look for unusual activity in each drive (`hd_store::activity`)
//!   every five minutes and before retention. Retention leaves a drive
//!   with an alert alone until its owner dismisses it in the web UI;
//! - a reference check as soon as anything is quarantined (a read that
//!   found damage or an unreadable disk sector), and every ten minutes
//!   while damage remains, so sync clients holding a damaged file's
//!   content are asked for it promptly (`GET /api/v1/damaged`) and a
//!   healed file stops being reported.
//!
//! Each job's outcome is kept for the admin page. A failure is logged and
//! retried at the next interval; none of them can lose data. The worst a
//! failed GC does is leave space unreclaimed.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use hd_common::timefmt;

use crate::App;

const TICK: Duration = Duration::from_mins(1);
const CHECKPOINT_EVERY: Duration = Duration::from_mins(10);
const FIRST_MAINTENANCE: Duration = Duration::from_hours(1);
const FIRST_SCRUB: Duration = Duration::from_hours(24);
const RECHECK_DAMAGE: Duration = Duration::from_mins(10);
const ACTIVITY_EVERY: Duration = Duration::from_mins(5);

/// The last outcome of each job, as text for the admin page.
#[derive(Clone, Debug, Default)]
pub struct Status {
    pub checkpoint: Option<(i64, String)>,
    pub retention: Option<(i64, String)>,
    pub gc: Option<(i64, String)>,
    pub scrub: Option<(i64, String)>,
    pub check: Option<(i64, String)>,
    /// Versions the last reference check found unreadable.
    pub damaged_versions: usize,
    /// Current versions among them, which a sync client can heal.
    pub damaged_current: Vec<hd_store::fsck::DamagedVersion>,
    /// Objects the last scrub could neither read nor set aside.
    pub unreadable: usize,
    /// Drives with unusual activity not yet dismissed.
    pub alerts: Vec<hd_store::activity::Alert>,
}

#[derive(Debug, Default)]
pub struct Maintenance {
    pub status: Mutex<Status>,
    pub stop: AtomicBool,
    /// Whether each recent change looked like encryption, by version.
    verdicts: Mutex<HashMap<u64, bool>>,
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

/// Checks that every version, live or trashed, can still find its manifest
/// and chunks, and records the outcome. Damage is logged per version, so
/// the operator knows what to restore.
pub fn check_references(app: &App) {
    let r = app.store.fsck(false);
    let current = r.as_ref().map(|rep| rep.damaged_current.clone()).unwrap_or_default();
    let (text, damaged) = match &r {
        Ok(rep) if rep.is_clean() => (format!("{} versions, all readable", rep.versions), 0),
        Ok(rep) => {
            for p in &rep.problems {
                eprintln!("hd-server: check: {p}");
            }
            (
                format!(
                    "{} of {} versions cannot be read; run hd-server fsck --deep",
                    rep.problems.len(),
                    rep.versions
                ),
                rep.problems.len(),
            )
        }
        Err(e) => (format!("FAILED: {e}"), 0),
    };
    eprintln!("hd-server: check: {text}");
    app.maintenance.record(|s| {
        s.check = Some((timefmt::unix_ms(), text));
        s.damaged_versions = damaged;
        s.damaged_current = current;
    });
}

/// Looks for unusual activity in every drive, and records the alerts.
pub fn check_activity(app: &App) {
    let mut verdicts = app.maintenance.verdicts.lock().unwrap_or_else(PoisonError::into_inner);
    if verdicts.len() > 1_000_000 {
        verdicts.clear();
    }
    let alerts = app.store.activity_alerts(
        timefmt::unix_ms(),
        &app.config.alerts,
        &app.dismissed(),
        &mut verdicts,
    );
    drop(verdicts);
    let before: BTreeSet<String> =
        app.maintenance.snapshot().alerts.into_iter().map(|a| a.user).collect();
    for a in alerts.iter().filter(|a| !before.contains(&a.user)) {
        eprintln!(
            "hd-server: ALERT: unusual activity in {}'s drive: {} files changed, {} deleted, {} \
             looking encrypted, within an hour; retention is held for the drive until the alert \
             is dismissed",
            a.user, a.changed, a.deleted, a.suspicious
        );
    }
    app.maintenance.record(|s| s.alerts = alerts);
}

/// Users whose drives retention must leave alone.
fn held(app: &App) -> BTreeSet<String> {
    app.maintenance.snapshot().alerts.into_iter().map(|a| a.user).collect()
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

/// Whether the wall clock has kept pace with the monotonic one since
/// start, within a day. A clock that jumped makes retention's ages wrong.
fn clock_steady(started: Instant, wall_at_start: i64) -> bool {
    let wall = timefmt::unix_ms().saturating_sub(wall_at_start);
    let mono = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
    wall.abs_diff(mono) < 86_400_000
}

fn run(app: &App) {
    let started = Instant::now();
    let wall_at_start = timefmt::unix_ms();
    let mut last_checkpoint = (Instant::now(), app.store.read(|s| s.seq));
    let mut next_maintenance = app.config.maintenance_every.map(|_| started + FIRST_MAINTENANCE);
    let mut next_scrub = app.config.scrub_every.map(|_| started + FIRST_SCRUB);
    let mut quarantined_seen = app.store.objects().quarantined_count();
    let mut last_damage_check = Instant::now();
    let m = &app.maintenance;
    check_activity(app);
    let mut last_activity_check = Instant::now();
    while !m.stop.load(Ordering::Relaxed) {
        std::thread::sleep(TICK);
        let now = Instant::now();
        if now.duration_since(last_activity_check) >= ACTIVITY_EVERY {
            check_activity(app);
            last_activity_check = now;
        }
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
            if clock_steady(started, wall_at_start) {
                check_activity(app);
                last_activity_check = Instant::now();
                let r = app.store.apply_retention_holding(
                    timefmt::unix_ms(),
                    &app.config.retention,
                    &held(app),
                );
                eprintln!("hd-server: retention: {}", outcome(&r));
                m.record(|s| s.retention = Some((timefmt::unix_ms(), outcome(&r))));
            } else {
                let text = "skipped: the system clock jumped since the server started; restart \
                            it once the time is right"
                    .to_owned();
                eprintln!("hd-server: retention: {text}");
                m.record(|s| s.retention = Some((timefmt::unix_ms(), text)));
            }
            let r =
                app.store.collect_garbage(timefmt::unix_ms(), &hd_store::gc::GcOptions::default());
            eprintln!("hd-server: gc: {}", outcome(&r));
            m.record(|s| s.gc = Some((timefmt::unix_ms(), outcome(&r))));
            check_references(app);
            next_maintenance = Some(now + every);
        }
        if let (Some(at), Some(every)) = (next_scrub, app.config.scrub_every)
            && now >= at
        {
            let r = app.store.scrub(app.config.scrub_bytes_per_sec, &m.stop);
            let text = match &r {
                Ok(rep) => format!(
                    "{} objects, {} bytes, {} quarantined, {} unreadable, {} metadata file(s) \
                     repaired{}",
                    rep.checked,
                    rep.bytes,
                    rep.quarantined.len(),
                    rep.failed.len(),
                    rep.metadata_damaged.len(),
                    if rep.stopped { " (stopped)" } else { "" }
                ),
                Err(e) => format!("FAILED: {e}"),
            };
            eprintln!("hd-server: scrub: {text}");
            let unreadable = r.as_ref().map_or(0, |rep| rep.failed.len());
            m.record(|s| {
                s.scrub = Some((timefmt::unix_ms(), text));
                s.unreadable = unreadable;
            });
            check_references(app);
            last_damage_check = Instant::now();
            next_scrub = Some(Instant::now() + every);
        }
        // Something was quarantined (a read found damage), or damage
        // remains that clients may have healed since: check again.
        let quarantined = app.store.objects().quarantined_count();
        let damaged = m.snapshot().damaged_versions > 0;
        if quarantined != quarantined_seen
            || (damaged && last_damage_check.elapsed() >= RECHECK_DAMAGE)
        {
            quarantined_seen = quarantined;
            check_references(app);
            last_damage_check = Instant::now();
        }
    }
}
