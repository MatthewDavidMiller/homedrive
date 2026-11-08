//! A cache of source files' SHA-256 for `import-tree` and `verify-tree`
//! (`--hash-cache FILE`), so a second run, or one that continues after an
//! interruption, reads only what changed instead of the whole tree again.
//!
//! **A cached hash is used only while the file is provably the one that was
//! hashed:** the same inode, size, modification time and change time, to
//! the nanosecond. Nobody can set a change time back, and every write moves
//! it, so a file written since misses the cache. One case remains: a write
//! within the same tick of the file system's clock as the read before it
//! leaves both times unchanged. So a hash is kept only for a file whose two
//! times were already [`SETTLED_NS`] old when it was read, and that did not
//! change while it was read.
//!
//! The cache names the source tree it belongs to and is ignored for any
//! other. It is saved every [`SAVE_EVERY`] and at the end, so a run cut off
//! loses at most that much work. A cache that cannot be read starts empty:
//! it can only save time, never decide anything a fresh hash would not.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hd_api::{J, s};
use hd_common::{Error, Result, fsio, timefmt};

/// How old both of a file's times must be before its hash is kept.
pub const SETTLED_NS: i64 = 2_000_000_000;
/// How often a run saves what it has hashed.
pub const SAVE_EVERY: Duration = Duration::from_secs(60);
const MAX_FILE: usize = 512 * 1024 * 1024;

/// What identifies a file's content without reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    ino: u64,
    size: u64,
    mtime_ns: i64,
    ctime_ns: i64,
}

impl Stamp {
    fn of(meta: &fs::Metadata) -> Self {
        let ns = |s: i64, n: i64| s.saturating_mul(1_000_000_000).saturating_add(n);
        Self {
            ino: meta.ino(),
            size: meta.len(),
            mtime_ns: ns(meta.mtime(), meta.mtime_nsec()),
            ctime_ns: ns(meta.ctime(), meta.ctime_nsec()),
        }
    }
}

#[derive(Debug)]
pub struct HashCache {
    path: PathBuf,
    src: String,
    entries: HashMap<String, (Stamp, [u8; 32])>,
    dirty: bool,
    saved: Instant,
    settled_ns: i64,
    /// Hashes taken from the cache, and read afresh, this run.
    pub reused: usize,
    pub hashed: usize,
    /// What `open` found: how many entries it loaded, and why if none.
    pub loaded: usize,
    pub opened: &'static str,
    /// Why entries that were found did not match (a file can count in
    /// several): the file's inode, size, mtime or ctime had moved.
    pub moved: [usize; 4],
    /// Files [`HashCache::warm`] has just hashed, counted in `hashed`
    /// already, which the next `hash` of each must not count as reused.
    warmed: HashSet<String>,
    /// Threads [`HashCache::warm`] reads with.
    jobs: usize,
}

/// Reads a file and returns its SHA-256 and size.
pub type Reader<'a> = dyn Fn(&Path) -> Result<([u8; 32], u64)> + Sync + 'a;

/// The most threads a warm-up may use.
pub const MAX_JOBS: usize = 16;
/// How often a long warm-up says how far it has got, on stderr.
const PROGRESS_EVERY: Duration = Duration::from_secs(30);

fn src_name(src: &Path) -> String {
    fs::canonicalize(src).unwrap_or_else(|_| src.to_owned()).to_string_lossy().into_owned()
}

impl HashCache {
    /// Opens the cache at `path` for the tree `src`; empty if there is none
    /// yet, it belongs to another tree, or it cannot be read.
    pub fn open(path: &Path, src: &Path) -> Self {
        let src = src_name(src);
        let mut entries = HashMap::new();
        let opened = match fsio::read_text(path, MAX_FILE) {
            Ok(Some(text)) => {
                let mut lines = text.lines();
                let header = lines.next().and_then(|l| hd_api::parse(l.as_bytes()).ok());
                if header.and_then(|h| hd_api::get_str(&h, "src").ok()).as_deref() == Some(&*src) {
                    for line in lines {
                        if let Some((rel, stamp, sha)) = parse(line) {
                            entries.insert(rel, (stamp, sha));
                        }
                    }
                    "read"
                } else {
                    "it names another tree, or has no readable header"
                }
            }
            Ok(None) => "there is no file yet",
            Err(_) => "the file could not be read",
        };
        let loaded = entries.len();
        Self {
            path: path.to_owned(),
            src,
            entries,
            dirty: false,
            saved: Instant::now(),
            settled_ns: SETTLED_NS,
            reused: 0,
            hashed: 0,
            loaded,
            opened,
            moved: [0; 4],
            warmed: HashSet::new(),
            jobs: 1,
        }
    }

    /// Hash with up to `jobs` threads in [`HashCache::warm`].
    #[must_use]
    pub fn with_jobs(mut self, jobs: usize) -> Self {
        self.jobs = jobs.clamp(1, MAX_JOBS);
        self
    }

    fn note_moved(&mut self, kept: &Stamp, now: &Stamp) {
        for (n, differs) in [
            kept.ino != now.ino,
            kept.size != now.size,
            kept.mtime_ns != now.mtime_ns,
            kept.ctime_ns != now.ctime_ns,
        ]
        .into_iter()
        .enumerate()
        {
            self.moved[n] += usize::from(differs);
        }
    }

    /// Hashes, with several threads, those of `files` (names under `src`)
    /// whose hash the cache does not hold, so that the `hash` calls that
    /// follow, in whatever order, find them kept. A disk and a processor
    /// that wait on each other when one thread does both are kept busy by
    /// several. A file that cannot be read here is left for `hash` to read
    /// again and report. Does nothing with one thread.
    pub fn warm(&mut self, src: &Path, files: &[String], read: &Reader) -> Result<()> {
        let jobs = self.jobs;
        if jobs <= 1 {
            return Ok(());
        }
        let mut misses: Vec<(&String, PathBuf, Stamp)> = Vec::new();
        for rel in files {
            let abs = src.join(rel);
            let Ok(meta) = fs::symlink_metadata(&abs) else { continue };
            let before = Stamp::of(&meta);
            match self.entries.get(rel).map(|(stamp, _)| *stamp) {
                Some(kept) if kept == before => continue,
                Some(kept) => self.note_moved(&kept, &before),
                None => {}
            }
            misses.push((rel, abs, before));
        }
        if misses.len() < 2 {
            return Ok(());
        }
        let settled_ns = self.settled_ns;
        let started = Instant::now();
        let bytes = AtomicU64::new(0);
        let last_ms = AtomicU64::new(0);
        let next = AtomicUsize::new(0);
        let total = misses.len();
        let shared = Mutex::new(&mut *self);
        let worker = || {
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((rel, abs, before)) = misses.get(i) else { break };
                let now = {
                    let (secs, nanos) = timefmt::wall_clock();
                    secs.saturating_mul(1_000_000_000).saturating_add(i64::from(nanos))
                };
                let Ok((sha, size)) = read(abs) else { continue };
                bytes.fetch_add(size, Ordering::Relaxed);
                let after = fs::symlink_metadata(abs).map(|m| Stamp::of(&m)).ok();
                let settled = now - before.mtime_ns.max(before.ctime_ns) >= settled_ns;
                {
                    let mut cache = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    if after == Some(*before) && size == before.size && settled {
                        cache.entries.insert((*rel).clone(), (*before, sha));
                        cache.warmed.insert((*rel).clone());
                        cache.hashed += 1;
                        cache.dirty = true;
                    } else if cache.entries.remove(*rel).is_some() {
                        cache.dirty = true;
                    }
                    if cache.saved.elapsed() >= SAVE_EVERY {
                        // A failure to save is reported by the final save.
                        let _ = cache.save();
                    }
                }
                let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let last = last_ms.load(Ordering::Relaxed);
                let due = u64::try_from(PROGRESS_EVERY.as_millis()).unwrap_or(u64::MAX);
                if ms.saturating_sub(last) >= due
                    && last_ms
                        .compare_exchange(last, ms, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                {
                    let read = bytes.load(Ordering::Relaxed);
                    let secs = (ms / 1000).max(1);
                    eprintln!(
                        "verify-tree: hashing: {} of {total} files started, {} MiB read ({} MiB/s), {}m{:02}s elapsed",
                        (i + 1).min(total),
                        read >> 20,
                        (read / secs) >> 20,
                        secs / 60,
                        secs % 60
                    );
                }
            }
        };
        std::thread::scope(|scope| {
            for n in 1..jobs.min(total) {
                // The result is dropped on purpose: scope joins the thread.
                let _ = std::thread::Builder::new()
                    .name(format!("hd-hash-{n}"))
                    .stack_size(1 << 20)
                    .spawn_scoped(scope, worker);
            }
            worker();
        });
        Ok(())
    }

    /// The SHA-256 and size of `abs`, known in the tree as `rel`: from the
    /// cache while the file is unchanged, otherwise read with `read`.
    pub fn hash(
        &mut self,
        rel: &str,
        abs: &Path,
        read: impl FnOnce(&Path) -> Result<([u8; 32], u64)>,
    ) -> Result<([u8; 32], u64)> {
        let before = Stamp::of(&fs::symlink_metadata(abs)?);
        if let Some((stamp, sha)) = self.entries.get(rel).copied() {
            if stamp == before {
                // A file the warm-up hashed was counted as hashed then.
                if !self.warmed.remove(rel) {
                    self.reused += 1;
                }
                return Ok((sha, before.size));
            }
            self.note_moved(&stamp, &before);
        }
        let now = {
            let (secs, nanos) = timefmt::wall_clock();
            secs.saturating_mul(1_000_000_000).saturating_add(i64::from(nanos))
        };
        let (sha, size) = read(abs)?;
        self.hashed += 1;
        let after = Stamp::of(&fs::symlink_metadata(abs)?);
        let settled = now - before.mtime_ns.max(before.ctime_ns) >= self.settled_ns;
        if after == before && size == before.size && settled {
            self.entries.insert(rel.to_owned(), (before, sha));
            self.dirty = true;
        } else if self.entries.remove(rel).is_some() {
            self.dirty = true;
        }
        if self.saved.elapsed() >= SAVE_EVERY {
            self.save()?;
        }
        Ok((sha, size))
    }

    /// One line saying what the cache held and why it missed, for the
    /// operator to read when a run is not faster than the one before.
    #[must_use]
    pub fn describe(&self) -> String {
        let [ino, size, mtime, ctime] = self.moved;
        format!(
            "cache: {} entries loaded ({}); changed since they were saved: inode {ino}, size {size}, mtime {mtime}, ctime {ctime}",
            self.loaded, self.opened
        )
    }

    /// For tests: how old a file's times must be before its hash is kept,
    /// instead of [`SETTLED_NS`], so a test need not wait on a wall clock
    /// that may step back.
    #[doc(hidden)]
    #[must_use]
    pub fn settled_after(mut self, ns: i64) -> Self {
        self.settled_ns = ns;
        self
    }

    /// Writes the cache, if anything changed since it was last written.
    pub fn save(&mut self) -> Result<()> {
        if !self.dirty {
            self.saved = Instant::now();
            return Ok(());
        }
        let mut text = J::O(vec![("src", s(&*self.src))]).render();
        text.push('\n');
        for (rel, (st, sha)) in &self.entries {
            text.push_str(
                &J::O(vec![
                    ("p", s(&**rel)),
                    ("h", s(hd_api::hex(sha))),
                    ("i", J::U(st.ino)),
                    ("s", J::U(st.size)),
                    ("m", J::I(st.mtime_ns)),
                    ("c", J::I(st.ctime_ns)),
                ])
                .render(),
            );
            text.push('\n');
        }
        if text.len() > MAX_FILE {
            return Err(Error::new("the hash cache has outgrown its size limit"));
        }
        fsio::atomic_replace(&self.path, text.as_bytes(), MAX_FILE)?;
        self.dirty = false;
        self.saved = Instant::now();
        Ok(())
    }
}

fn parse(line: &str) -> Option<(String, Stamp, [u8; 32])> {
    let v = hd_api::parse(line.as_bytes()).ok()?;
    let stamp = Stamp {
        ino: hd_api::get_u64(&v, "i").ok()?,
        size: hd_api::get_u64(&v, "s").ok()?,
        mtime_ns: hd_api::get_i64(&v, "m").ok()?,
        ctime_ns: hd_api::get_i64(&v, "c").ok()?,
    };
    Some((hd_api::get_str(&v, "p").ok()?, stamp, hd_api::get_hash(&v, "h").ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file written a moment ago could be written again within the same
    /// tick of the file system's clock without its times moving, so its
    /// hash is never kept: the next run reads it again.
    #[test]
    fn a_file_written_just_now_is_never_cached() {
        let dir = std::env::temp_dir().join(format!("hd-hashcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/new.txt"), b"just written").unwrap();
        let read = |p: &Path| -> Result<([u8; 32], u64)> {
            let data = std::fs::read(p)?;
            Ok((hd_crypto::sha256(&data).map_err(|_| Error::new("SHA-256"))?, data.len() as u64))
        };
        let mut cache = HashCache::open(&dir.join("cache"), &dir.join("src"));
        cache.hash("new.txt", &dir.join("src/new.txt"), read).unwrap();
        cache.save().unwrap();
        let mut again = HashCache::open(&dir.join("cache"), &dir.join("src"));
        again.hash("new.txt", &dir.join("src/new.txt"), read).unwrap();
        assert_eq!((again.reused, again.hashed), (0, 1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A cache that misses says why: here the file was rewritten, so its
    /// size and times differ from what was saved, while a cache that is
    /// missing says that instead.
    #[test]
    fn a_miss_is_explained() {
        let dir = std::env::temp_dir().join(format!("hd-hashcache-why-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let file = dir.join("src/a.txt");
        std::fs::write(&file, b"one").unwrap();
        let read = |p: &Path| -> Result<([u8; 32], u64)> {
            let data = std::fs::read(p)?;
            Ok((hd_crypto::sha256(&data).map_err(|_| Error::new("SHA-256"))?, data.len() as u64))
        };
        let none = HashCache::open(&dir.join("cache"), &dir.join("src"));
        assert!(none.describe().contains("0 entries loaded (there is no file yet)"));
        let mut first =
            HashCache::open(&dir.join("cache"), &dir.join("src")).settled_after(i64::MIN);
        first.hash("a.txt", &file, read).unwrap();
        first.save().unwrap();
        std::fs::write(&file, b"changed").unwrap();
        let mut again = HashCache::open(&dir.join("cache"), &dir.join("src"));
        again.hash("a.txt", &file, read).unwrap();
        let text = again.describe();
        assert!(text.contains("1 entries loaded (read)"), "{text}");
        assert!(text.contains("size 1"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
