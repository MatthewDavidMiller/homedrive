//! A read-only consistency check of the whole store: that every version
//! the metadata refers to, live or in the trash, can be read back intact.
//!
//! Opening the store has already replayed and verified the journal. This
//! then loads every referenced manifest and checks every chunk it lists.
//! With `deep`, each chunk is read and hashed against its ID, and a file's
//! hash is recomputed from its chunks; without it, chunks are only checked
//! to exist. Nothing is moved or changed, not even a damaged object.
//!
//! A deep check reads a lot, so it is built not to read anything twice
//! that it need not:
//!
//! - A manifest shared by several versions is checked once.
//! - A chunk shared by several manifests (an edited file keeps most of its
//!   chunks from one version to the next) is read once, apart from the
//!   current versions' own pass below.
//! - Recomputing a file's hash needs every byte of it in order, so that
//!   pass reads each chunk again. It covers the current versions, the ones
//!   a sync client or an import vouches for; older and trashed versions
//!   are checked chunk by chunk, each chunk against its own ID, unless
//!   `all_files` asks for the file hash of those too.
//! - The work is spread over `jobs` threads, so reads from the disk
//!   overlap with the hashing.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hd_chunk::ObjectId;
use hd_common::Result;
use hd_crypto::Sha256;

use crate::Store;
use crate::manifest::Manifest;
use crate::model::Node;
use crate::objects::{Health, Kind};

/// The most threads a check may use.
pub const MAX_JOBS: usize = 16;
/// How often a long check says how far it has got, on stderr.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    pub versions: usize,
    pub manifests: usize,
    pub chunks: usize,
    /// "user:path (version N): problem", one per damaged version.
    pub problems: Vec<String>,
    /// The damaged versions that are some file's current version: a sync
    /// client that still has that file can upload it again and heal them.
    pub damaged_current: Vec<DamagedVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DamagedVersion {
    pub user: String,
    pub path: String,
    pub version: u64,
}

impl FsckReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

/// What a check does, and with how many threads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsckOptions {
    /// Read and hash every chunk, instead of checking it exists.
    pub deep: bool,
    /// With `deep`: recompute the file hash of every version, not only of
    /// the current ones.
    pub all_files: bool,
    /// Threads to read with (1 to [`MAX_JOBS`]).
    pub jobs: usize,
}

impl FsckOptions {
    /// What `Store::fsck(deep)` has always meant: a deep check looks at
    /// everything.
    #[must_use]
    pub fn thorough(deep: bool) -> Self {
        Self { deep, all_files: deep, jobs: if deep { default_jobs() } else { 1 } }
    }
}

/// Four threads, or fewer on a machine that has fewer cores.
#[must_use]
pub fn default_jobs() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get).min(4)
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What is known of each chunk checked so far: its length if it is good,
/// `None` if it is missing or damaged.
type Seen = Mutex<HashMap<ObjectId, Option<usize>>>;

/// How far a long phase has got, said on stderr every half minute.
struct Progress<'a> {
    phase: &'static str,
    unit: &'static str,
    total: usize,
    done: AtomicUsize,
    bytes: &'a AtomicU64,
    started: Instant,
    last_ms: AtomicU64,
    quiet: bool,
}

impl<'a> Progress<'a> {
    fn new(
        phase: &'static str,
        unit: &'static str,
        total: usize,
        bytes: &'a AtomicU64,
        started: Instant,
        quiet: bool,
    ) -> Self {
        Self {
            phase,
            unit,
            total,
            done: AtomicUsize::new(0),
            bytes,
            started,
            last_ms: AtomicU64::new(0),
            quiet,
        }
    }

    fn finished_one(&self) {
        let done = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        if self.quiet {
            return;
        }
        let now = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = u64::try_from(PROGRESS_EVERY.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(last) >= due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let bytes = self.bytes.load(Ordering::Relaxed);
            let secs = (now / 1000).max(1);
            eprintln!(
                "fsck: {}: {done} of {} {} done, {} MiB read ({} MiB/s), {}m{:02}s elapsed",
                self.phase,
                self.total,
                self.unit,
                bytes >> 20,
                (bytes / secs) >> 20,
                secs / 60,
                secs % 60
            );
        }
    }
}

/// Runs `work` on every item with up to `jobs` threads, and returns the
/// results in the items' order. The calling thread works too, so a thread
/// that cannot be started only slows the check.
fn parallel_map<T: Sync, R: Send>(
    jobs: usize,
    items: &[T],
    work: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    if jobs <= 1 || items.len() < 2 {
        return items.iter().map(work).collect();
    }
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));
    let worker = || {
        loop {
            let i = next.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(i) else { break };
            let r = work(item);
            lock(&out).push((i, r));
        }
    };
    std::thread::scope(|scope| {
        for n in 1..jobs.min(items.len()) {
            // The result is dropped on purpose: scope joins the thread.
            let _ = std::thread::Builder::new()
                .name(format!("hd-fsck-{n}"))
                .stack_size(1 << 20)
                .spawn_scoped(scope, worker);
        }
        worker();
    });
    let mut results = out.into_inner().unwrap_or_else(PoisonError::into_inner);
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, r)| r).collect()
}

impl Store {
    /// A check of every version. With `deep`, every chunk of every version
    /// is read and verified, and every file's hash recomputed.
    pub fn fsck(&self, deep: bool) -> Result<FsckReport> {
        self.fsck_with(&FsckOptions::thorough(deep))
    }

    pub fn fsck_with(&self, options: &FsckOptions) -> Result<FsckReport> {
        // Every (user, path, version, manifest), live and trashed.
        // The last flag: the version is a live file's current one.
        let versions: Vec<(String, String, u64, ObjectId, bool)> = self.read(|state| {
            let mut out = Vec::new();
            let mut add = |user: &str, path: &str, node: &Node, live: bool| {
                if let Node::File { versions, .. } = node {
                    for (i, v) in versions.iter().enumerate() {
                        let current = live && i + 1 == versions.len();
                        out.push((user.to_owned(), path.to_owned(), v.id, v.manifest, current));
                    }
                }
            };
            for (user, ns) in &state.users {
                for (path, entry) in &ns.entries {
                    add(user, path, &entry.node, true);
                }
                for item in ns.trash.values() {
                    for (rel, node) in &item.entries {
                        let path = format!("[trash {}] {}/{rel}", item.id, item.path);
                        add(user, &path, node, false);
                    }
                }
            }
            out
        });
        let mut report = FsckReport { versions: versions.len(), ..FsckReport::default() };

        // The manifests, each once, with whether some version of it is a
        // live file's current one.
        let mut slot: HashMap<ObjectId, usize> = HashMap::new();
        let mut manifests: Vec<(ObjectId, bool)> = Vec::new();
        for (_, _, _, manifest, current) in &versions {
            if let Some(&i) = slot.get(manifest) {
                if let Some(m) = manifests.get_mut(i) {
                    m.1 |= *current;
                }
            } else {
                slot.insert(*manifest, manifests.len());
                manifests.push((*manifest, *current));
            }
        }
        report.manifests = manifests.len();

        let jobs = options.jobs.clamp(1, MAX_JOBS);
        let started = Instant::now();
        let bytes = AtomicU64::new(0);
        let seen: Seen = Mutex::new(HashMap::new());
        // (verdict, chunk references checked) per manifest, in `manifests` order.
        let mut verdicts: Vec<(Option<String>, usize)> = vec![(None, 0); manifests.len()];

        // The manifests that need their bytes read in order, to recompute
        // the file hash (or, shallow, all of them: that only looks).
        let wants_file_hash = |current: bool| !options.deep || options.all_files || current;
        let (whole, rest): (Vec<usize>, Vec<usize>) = (0..manifests.len())
            .partition(|&i| manifests.get(i).is_some_and(|m| wants_file_hash(m.1)));

        let progress = Progress::new(
            if options.deep { "file hashes" } else { "chunks present" },
            "manifests",
            whole.len(),
            &bytes,
            started,
            !options.deep,
        );
        let checked = parallel_map(jobs, &whole, |&i| {
            let id = manifests.get(i).map(|m| m.0);
            let r =
                id.map_or((None, 0), |id| self.check_manifest(&id, options.deep, &seen, &bytes));
            progress.finished_one();
            r
        });
        for (&i, r) in whole.iter().zip(checked) {
            if let Some(v) = verdicts.get_mut(i) {
                *v = r;
            }
        }

        if !rest.is_empty() {
            // Older and trashed versions: each chunk against its own ID.
            let loaded = parallel_map(jobs, &rest, |&i| {
                manifests.get(i).map_or_else(
                    || Err("manifest is not known".to_owned()),
                    |m| self.load_manifest(&m.0),
                )
            });
            // Every chunk of those manifests that no earlier pass has
            // read, once.
            let mut wanted: Vec<ObjectId> = Vec::new();
            {
                let known = lock(&seen);
                let mut queued = HashSet::new();
                for manifest in loaded.iter().flatten() {
                    for (chunk, _) in &manifest.chunks {
                        if !known.contains_key(chunk) && queued.insert(*chunk) {
                            wanted.push(*chunk);
                        }
                    }
                }
            }
            let progress = Progress::new("chunks", "chunks", wanted.len(), &bytes, started, false);
            let objects = self.objects();
            let health = parallel_map(jobs, &wanted, |chunk| {
                let len = match objects.peek(Kind::Chunk, chunk) {
                    Ok(Ok(data)) => {
                        bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                        Some(data.len())
                    }
                    _ => None,
                };
                progress.finished_one();
                len
            });
            lock(&seen).extend(wanted.iter().copied().zip(health));
            let known = lock(&seen);
            for (&i, manifest) in rest.iter().zip(loaded) {
                let verdict = match manifest {
                    Err(problem) => (Some(problem), 0),
                    Ok(manifest) => {
                        let mut count = 0;
                        let mut problem = None;
                        for (chunk, len) in &manifest.chunks {
                            if known.get(chunk).copied().flatten() == Some(*len as usize) {
                                count += 1;
                            } else {
                                problem = Some(format!("chunk {chunk} is missing or damaged"));
                                break;
                            }
                        }
                        (problem, count)
                    }
                };
                if let Some(v) = verdicts.get_mut(i) {
                    *v = verdict;
                }
            }
        }

        report.chunks = verdicts.iter().map(|v| v.1).sum();
        for (user, path, version, manifest, current) in versions {
            let problem =
                slot.get(&manifest).and_then(|&i| verdicts.get(i)).and_then(|v| v.0.as_ref());
            if let Some(problem) = problem {
                report.problems.push(format!("{user}:{path} (version {version}): {problem}"));
                if current {
                    report.damaged_current.push(DamagedVersion { user, path, version });
                }
            }
        }
        Ok(report)
    }

    /// The manifest `id` lists, read without moving anything, or what is
    /// wrong with it.
    fn load_manifest(&self, id: &ObjectId) -> std::result::Result<Manifest, String> {
        let objects = self.objects();
        match objects.peek(Kind::Manifest, id) {
            Ok(Ok(_)) => {}
            Ok(Err(Health::Missing)) => return Err(format!("manifest {id} is missing")),
            Ok(Err(h)) => return Err(format!("manifest {id} is damaged: {h:?}")),
            Err(e) => return Err(format!("manifest {id} cannot be read: {e}")),
        }
        Manifest::load_readonly(objects, id).map_err(|e| format!("manifest {id}: {e}"))
    }

    /// One manifest's verdict (`None` when it is sound) and how many chunk
    /// references it checked.
    fn check_manifest(
        &self,
        id: &ObjectId,
        deep: bool,
        seen: &Seen,
        bytes: &AtomicU64,
    ) -> (Option<String>, usize) {
        let mut chunks = 0;
        let problem = self.check_manifest_inner(id, deep, seen, bytes, &mut chunks).err();
        (problem, chunks)
    }

    fn check_manifest_inner(
        &self,
        id: &ObjectId,
        deep: bool,
        seen: &Seen,
        bytes: &AtomicU64,
        chunks: &mut usize,
    ) -> std::result::Result<(), String> {
        let objects = self.objects();
        let manifest = self.load_manifest(id)?;
        let mut whole = if deep { Sha256::new().ok() } else { None };
        for (chunk, len) in &manifest.chunks {
            let known = lock(seen).get(chunk).copied();
            if known == Some(None) {
                return Err(format!("chunk {chunk} is missing or damaged"));
            }
            if deep {
                match objects.peek(Kind::Chunk, chunk) {
                    Ok(Ok(data)) if data.len() == *len as usize => {
                        bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                        if let Some(h) = &mut whole {
                            h.update(&data);
                        }
                        lock(seen).insert(*chunk, Some(data.len()));
                    }
                    _ => {
                        lock(seen).insert(*chunk, None);
                        return Err(format!("chunk {chunk} is missing or damaged"));
                    }
                }
            } else if known.is_none() {
                let present = objects.contains(Kind::Chunk, chunk);
                lock(seen).insert(*chunk, present.then_some(*len as usize));
                if !present {
                    return Err(format!("chunk {chunk} is missing"));
                }
            }
            *chunks += 1;
        }
        if let Some(h) = whole {
            match h.finish() {
                Ok(d) if d == manifest.sha256 => {}
                _ => return Err("the chunks do not hash to the file's SHA-256".to_owned()),
            }
        }
        Ok(())
    }
}
