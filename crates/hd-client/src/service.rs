//! The background work of the daemon: one thread per synced folder and one
//! that asks the server how it is. The daemon starts what is configured, and
//! the GUI starts and stops folders as the user adds and removes them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{JoinHandle, Thread};
use std::time::{Duration, Instant};

use hd_common::{Error, Result};
use hd_sys::watch::{Waker, Watcher};

use crate::config::{self, Config, FolderConfig};
use crate::engine::{Engine, Options, Progress, Report};
use crate::notify::Notifier;
use crate::remote::Remote;
use crate::trash;

const POLL: Duration = Duration::from_secs(15);
/// How long a folder goes unscanned while its watcher reports nothing and
/// the server has no news. Watchers can miss things (a network disk, a full
/// queue), so one is never the only thing relied on.
const FULL_SCAN: Duration = Duration::from_mins(5);
pub const TRASH_DAYS: u64 = 30;
/// The longest a folder's thread waits before looking at its stop flag when
/// nothing can wake it.
const WAIT_MS: u32 = 500;
/// The most waiting signals passed over before a round, so a folder that never
/// stops changing cannot hold one up.
const MAX_SIGNALS: u32 = 64;
/// How often the daemon asks the server whether its store is healthy.
const HEALTH_EVERY: Duration = Duration::from_mins(10);
/// How long stopping waits for a folder; a round in progress is left to end.
const STOP_WAIT: Duration = Duration::from_secs(20);

/// How the running folders report each round.
pub type Reporter = fn(&Path, &Report);

#[derive(Debug)]
struct Running {
    progress: Arc<Progress>,
    stop: Arc<AtomicBool>,
    forget: Arc<AtomicBool>,
    waker: Option<Arc<Waker>>,
    thread: JoinHandle<()>,
}

#[derive(Debug)]
pub struct Service {
    notifier: Arc<Mutex<Notifier>>,
    report: Reporter,
    running: Mutex<BTreeMap<PathBuf, Running>>,
    health: Mutex<Option<(Arc<AtomicBool>, Thread)>>,
    /// Which folders' last round left something for the user.
    attention: Arc<Mutex<BTreeMap<PathBuf, bool>>>,
}

fn remote(cfg: &Config) -> Result<Remote> {
    Remote::new(&cfg.server, cfg.ca_file.as_deref(), &config::load_token(&config::config_dir()?)?)
}

impl Service {
    pub fn new(report: Reporter) -> Self {
        Self {
            notifier: Arc::new(Mutex::new(Notifier::desktop())),
            report,
            running: Mutex::new(BTreeMap::new()),
            health: Mutex::new(None),
            attention: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Whether this process is syncing the folder at `local`.
    pub fn is_running(&self, local: &Path) -> bool {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(local)
            .is_some_and(|r| !r.thread.is_finished())
    }

    /// What a folder's rounds are doing, if this process is syncing it.
    pub fn progress(&self, local: &Path) -> Option<Arc<Progress>> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(local)
            .map(|r| Arc::clone(&r.progress))
    }

    /// Whether any folder needs the user, for the tray icon.
    pub fn needs_attention(&self) -> bool {
        self.attention.lock().unwrap_or_else(PoisonError::into_inner).values().any(|a| *a)
    }

    /// Starts asking the server how it is, replacing any earlier asking.
    pub fn start_health(&self, cfg: &Config) -> Result<()> {
        self.stop_health();
        let mut remote = remote(cfg)?;
        let notifier = Arc::clone(&self.notifier);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("health".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                while !stopping.load(Ordering::Acquire) {
                    // Unreachable is reported by the folders' rounds.
                    if let Ok(problems) = remote.server_problems() {
                        notifier.lock().unwrap_or_else(PoisonError::into_inner).server(&problems);
                    }
                    // A park can end early, and `stop_health` ends it.
                    let until = Instant::now() + HEALTH_EVERY;
                    while !stopping.load(Ordering::Acquire) {
                        let left = until.saturating_duration_since(Instant::now());
                        if left.is_zero() {
                            break;
                        }
                        std::thread::park_timeout(left);
                    }
                }
            })
            .map_err(|e| Error::new(format!("cannot start the health thread: {e}")))?;
        let health = (stop, thread.thread().clone());
        *self.health.lock().unwrap_or_else(PoisonError::into_inner) = Some(health);
        Ok(())
    }

    pub fn stop_health(&self) {
        let health = self.health.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some((stop, thread)) = health {
            stop.store(true, Ordering::Release);
            thread.unpark();
        }
    }

    /// Starts syncing a configured folder, unless this process already is.
    /// Returns false if another process is syncing it.
    pub fn start_folder(&self, cfg: &Config, f: &FolderConfig) -> Result<bool> {
        if self.is_running(&f.local) {
            return Ok(true);
        }
        let folder = cfg.folder(f)?;
        let state_dir = folder.state_dir.clone();
        let Some(mut engine) = Engine::try_open(folder, remote(cfg)?, Options::default())? else {
            return Ok(false);
        };
        let watcher = Watcher::new().ok();
        let waker = watcher.as_ref().map(Watcher::waker);
        if let Some(watcher) = watcher {
            engine.set_watcher(watcher);
        }
        let progress = engine.progress();
        let notifier = Arc::clone(&self.notifier);
        let attention = Arc::clone(&self.attention);
        let report = self.report;
        let (stop, forget) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (stopping, forgetting) = (Arc::clone(&stop), Arc::clone(&forget));
        let thread = std::thread::Builder::new()
            .name("folder".into())
            .stack_size(1024 * 1024)
            .spawn(move || {
                run_folder(engine, &notifier, &attention, report, &stopping);
                if forgetting.load(Ordering::Acquire)
                    && let Err(e) = trash::remove_folder_state(&state_dir)
                {
                    crate::say!("homedrive: could not clear a folder's sync state: {e}");
                }
            })
            .map_err(|e| Error::new(format!("cannot start a folder thread: {e}")))?;
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(f.local.clone(), Running { progress, stop, forget, waker, thread });
        Ok(true)
    }

    /// Stops syncing `local` and forgets what was synced, so nothing about
    /// it can be taken for a change if it is added again: without a record
    /// of the last sync, a file deleted here since is restored, never
    /// deleted on the server. Touches no synced file. Returns whether it
    /// has stopped; a round in progress finishes first, and the thread
    /// clears up after itself.
    pub fn stop_folder(&self, local: &Path) -> bool {
        let running = self.running.lock().unwrap_or_else(PoisonError::into_inner).remove(local);
        self.attention.lock().unwrap_or_else(PoisonError::into_inner).remove(local);
        let Some(running) = running else { return true };
        running.forget.store(true, Ordering::Release);
        running.stop.store(true, Ordering::Release);
        if let Some(waker) = &running.waker {
            waker.wake();
        }
        let deadline = Instant::now() + STOP_WAIT;
        while !running.thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        running.thread.is_finished()
    }
}

/// What a round leaves for the user.
fn needs_user(r: &Report) -> bool {
    r.ransomware_suspected
        || r.held_changes.is_some()
        || r.held_deletes.is_some()
        || !r.errors.is_empty()
}

fn run_folder(
    mut e: Engine,
    notifier: &Mutex<Notifier>,
    attention: &Mutex<BTreeMap<PathBuf, bool>>,
    report: Reporter,
    stop: &AtomicBool,
) {
    let local = e.folder().local.clone();
    let mut last_expiry = Instant::now();
    while !stop.load(Ordering::Acquire) {
        let result = e.sync(0);
        match &result {
            Ok(r) => report(&local, r),
            Err(err) => crate::say!("{}: {err}", local.display()),
        }
        attention
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(local.clone(), result.as_ref().map_or(true, needs_user));
        notifier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .round(&local, result.as_ref().map_err(Error::message));
        if last_expiry.elapsed() > Duration::from_hours(1) {
            let _ = trash::expire(&local, TRASH_DAYS);
            last_expiry = Instant::now();
        }
        hd_sys::background::release_memory();
        wait_for_work(&mut e, stop);
    }
}

/// Waits until a round has something to do. A scan costs time on every
/// file, so with a watcher each poll only asks the server what is new, and
/// the thread sleeps between polls: the watcher or `Service::stop_folder`
/// wakes it.
fn wait_for_work(e: &mut Engine, stop: &AtomicBool) {
    let scanned = Instant::now();
    let mut deadline = scanned + POLL;
    while !stop.load(Ordering::Acquire) {
        let left = deadline.saturating_duration_since(Instant::now());
        let ms = u32::try_from(left.as_millis()).unwrap_or(u32::MAX);
        match e.wait_for_change(ms.max(1)) {
            None => {
                if left.is_zero() {
                    return;
                }
                std::thread::sleep(left.min(Duration::from_millis(u64::from(WAIT_MS))));
                continue;
            }
            Some(Ok(true)) => {
                // Let a burst of writes settle first. One save can signal
                // several times, and the scan comes after these signals, so it
                // sees what they were about and they need no round of their own.
                std::thread::sleep(Duration::from_secs(2));
                for _ in 0..MAX_SIGNALS {
                    if !matches!(e.wait_for_change(0), Some(Ok(true))) {
                        break;
                    }
                }
                return;
            }
            Some(Ok(false)) => {}
            // Rounds and polls go on without it, at their own pace.
            Some(Err(_)) => std::thread::sleep(left.min(Duration::from_millis(u64::from(WAIT_MS)))),
        }
        if Instant::now() >= deadline {
            if scanned.elapsed() >= FULL_SCAN || e.has_news() {
                return;
            }
            deadline = Instant::now() + POLL;
        }
    }
}
