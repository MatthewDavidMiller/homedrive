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

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
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
    /// Hashes taken from the cache, and read afresh, this run.
    pub reused: usize,
    pub hashed: usize,
}

fn src_name(src: &Path) -> String {
    fs::canonicalize(src).unwrap_or_else(|_| src.to_owned()).to_string_lossy().into_owned()
}

impl HashCache {
    /// Opens the cache at `path` for the tree `src`; empty if there is none
    /// yet, it belongs to another tree, or it cannot be read.
    pub fn open(path: &Path, src: &Path) -> Self {
        let src = src_name(src);
        let mut entries = HashMap::new();
        if let Ok(Some(text)) = fsio::read_text(path, MAX_FILE) {
            let mut lines = text.lines();
            let header = lines.next().and_then(|l| hd_api::parse(l.as_bytes()).ok());
            if header.and_then(|h| hd_api::get_str(&h, "src").ok()).as_deref() == Some(&*src) {
                for line in lines {
                    if let Some((rel, stamp, sha)) = parse(line) {
                        entries.insert(rel, (stamp, sha));
                    }
                }
            }
        }
        Self {
            path: path.to_owned(),
            src,
            entries,
            dirty: false,
            saved: Instant::now(),
            reused: 0,
            hashed: 0,
        }
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
        if let Some((stamp, sha)) = self.entries.get(rel)
            && *stamp == before
        {
            self.reused += 1;
            return Ok((*sha, before.size));
        }
        let now = {
            let (secs, nanos) = timefmt::wall_clock();
            secs.saturating_mul(1_000_000_000).saturating_add(i64::from(nanos))
        };
        let (sha, size) = read(abs)?;
        self.hashed += 1;
        let after = Stamp::of(&fs::symlink_metadata(abs)?);
        let settled = now - before.mtime_ns.max(before.ctime_ns) >= SETTLED_NS;
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
