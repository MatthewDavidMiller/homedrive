//! The homedrive storage engine.
//!
//! ```text
//! <root>/store.id     the sentinel: format and identity of this store
//! <root>/history.id   the identity of this store's history (see below)
//! <root>/meta/LOCK    held by the one process that has the store open
//! <root>/chunks/ ...  content-addressed objects (see `objects`)
//! ```
//!
//! **The store fails closed.** [`Store::open`] refuses a directory without
//! a valid `store.id`, which is what an unmounted disk looks like: an empty
//! mount point. A server that started there would accept uploads onto the
//! wrong disk and then lose them when the real one was mounted again.
//! [`Store::init`] writes the sentinel, and only into an empty directory,
//! so it can never adopt or overwrite an existing tree.
//!
//! **A restored store starts a new history.** Clients follow the store
//! through its change feed by sequence number. A store restored from a
//! backup goes back in time, and once new commits carry it past where a
//! client was, numbers alone can no longer show that the client's view
//! belongs to a history that no longer exists. So the store has a
//! history identity in `history.id`. Backups leave that file out, and
//! opening a store without one makes a new one. Clients that see the
//! identity change compare everything afresh, which can upload or keep
//! both but never delete.
//!
//! The store holds content-addressed objects (`objects`) and the metadata
//! that names them (`model`, kept durable by `meta` and `journal`).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

/// The binary encoding, shared with the client (it lives in `hd-chunk`).
pub use hd_chunk::codec;
pub mod activity;
pub mod files;
pub mod fsck;
pub mod gc;
pub mod journal;
pub mod manifest;
pub mod meta;
pub mod model;
pub mod objects;
pub mod repair;
pub mod retention;
pub mod rewind;
pub mod scrub;

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hd_common::fsio::{self, Created};
use hd_common::{Error, Result};

pub use files::{Base, ChunkList, Committed, FileContent, FileReader, Provenance};
pub use meta::{MetaOptions, Recovery};
pub use model::{Applied, Op, State};
pub use objects::{Health, Kind, Objects};
pub use rewind::RewindReport;

const SENTINEL: &str = "store.id";
const SENTINEL_FORMAT: u32 = 1;
const MAX_SENTINEL: usize = 4096;
const HISTORY: &str = "history.id";
const DIR_MODE: u32 = 0o700;

/// Entries that may exist in a directory `init` still treats as empty: the
/// directory ext4 creates at the root of every filesystem.
const IGNORED_IN_EMPTY: &[&str] = &["lost+found"];

#[derive(Clone, Copy, Debug, Default)]
pub struct StoreOptions {
    /// Writes are refused while the filesystem has less than this free.
    pub min_free: u64,
    pub meta: MetaOptions,
}

/// An open store. Only one process can hold it: the lock is released when
/// this is dropped.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    id: String,
    history: String,
    objects: Objects,
    meta: Mutex<meta::Meta>,
    recovery: Recovery,
    pub(crate) gc: files::GcGate,
    /// The last committed sequence number, signalled on every commit, for
    /// long-polling clients.
    seq: (Mutex<u64>, Condvar),
    _lock: File,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Shipped builds abort on panic, so a poisoned lock only happens in
    // tests; the metadata's own poisoning covers failed writes.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn sentinel_text(id: &str) -> String {
    format!("homedrive store\nformat {SENTINEL_FORMAT}\nid {id}\n")
}

fn history_text(id: &str) -> String {
    format!("homedrive history\nid {id}\n")
}

fn parse_history(text: &str) -> Option<String> {
    let id = text.strip_prefix("homedrive history\nid ")?.strip_suffix('\n')?;
    (id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .then(|| id.to_owned())
}

/// Reads `history.id`, or starts a new history if it is missing (a store
/// restored from a backup, or one made before histories existed). A file
/// that cannot be parsed stops the store: it was written whole and fsynced,
/// so damage means something is wrong with the disk.
fn load_history(root: &Path) -> Result<String> {
    let path = root.join(HISTORY);
    if let Some(text) = fsio::read_text(&path, MAX_SENTINEL)? {
        return parse_history(&text).ok_or_else(|| {
            Error::new(format!(
                "{} is damaged; if this store was restored, delete it to start a new history",
                path.display()
            ))
        });
    }
    let id = hd_common::rand::random_hex(16)?;
    match fsio::write_new_durable(&path, root, &[history_text(&id).as_bytes()], 0o400)? {
        Created::New => {
            eprintln!(
                "hd-store: no {HISTORY} (a store restored from a backup?); started a new history, \
                 so every client compares its files afresh"
            );
            Ok(id)
        }
        Created::Existed => Err(Error::new(format!("{HISTORY} appeared while it was created"))),
    }
}

/// Parses `store.id` and returns the store's identity.
fn parse_sentinel(text: &str) -> Result<String> {
    let mut lines = text.split('\n');
    let bad = || Error::new("store.id is malformed; refusing to use this store");
    if lines.next() != Some("homedrive store") {
        return Err(bad());
    }
    let format = lines.next().and_then(|l| l.strip_prefix("format ")).ok_or_else(bad)?;
    if format != SENTINEL_FORMAT.to_string() {
        return Err(Error::new(format!(
            "store.id says format {format}; this build reads format {SENTINEL_FORMAT} only"
        )));
    }
    let id = lines.next().and_then(|l| l.strip_prefix("id ")).ok_or_else(bad)?;
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(bad());
    }
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(bad());
    }
    Ok(id.to_owned())
}

impl Store {
    /// Makes `root` a new, empty store. `root` must not exist, or be an
    /// empty directory (a fresh filesystem's `lost+found` is allowed).
    /// Returns the new store's identity.
    pub fn init(root: &Path) -> Result<String> {
        fsio::mkdir_durable(root, DIR_MODE)?;
        for entry in fs::read_dir(root)? {
            let name = entry?.file_name();
            if !IGNORED_IN_EMPTY.iter().any(|ignored| name == *ignored) {
                return Err(Error::new(format!(
                    "{} is not empty (it has {}); a store is only created in an empty directory",
                    root.display(),
                    name.to_string_lossy()
                )));
            }
        }
        let id = hd_common::rand::random_hex(16)?;
        let text = sentinel_text(&id);
        match fsio::write_new_durable(root.join(SENTINEL), root, &[text.as_bytes()], 0o400)? {
            Created::New => Ok(id),
            Created::Existed => Err(Error::new("store.id appeared while the store was created")),
        }
    }

    /// Opens an existing store, refusing anything that is not one, and
    /// recovers its metadata.
    pub fn open(root: &Path, options: &StoreOptions) -> Result<Self> {
        let sentinel = root.join(SENTINEL);
        let text = match fsio::read_text(&sentinel, MAX_SENTINEL) {
            Ok(Some(text)) => text,
            Ok(None) => {
                return Err(Error::new(format!(
                    "{} has no store.id, so it is not a homedrive store, or its disk is not \
                     mounted; refusing to start (run `hd-server init` only for a new, empty store)",
                    root.display()
                )));
            }
            Err(e) => return Err(Error::new(format!("cannot read {}: {e}", sentinel.display()))),
        };
        let id = parse_sentinel(&text)?;
        let meta = root.join("meta");
        fsio::mkdir_durable(&meta, DIR_MODE)?;
        let lock = fsio::lock_exclusive(meta.join("LOCK"))?.ok_or_else(|| {
            Error::new(format!("{} is already open in another process", root.display()))
        })?;
        for dir in Objects::directories(root) {
            fsio::mkdir_durable(&dir, DIR_MODE)?;
        }
        let objects = Objects::new(root, options.min_free);
        // Holding the lock, nothing else can be writing: whatever is left in
        // staging is from a write that never reached its commit point.
        let abandoned = fsio::clear_staging(objects.staging())?;
        if abandoned > 0 {
            eprintln!("hd-store: removed {abandoned} unfinished write(s) from staging");
        }
        let (meta, recovery) =
            meta::Meta::open(&meta, objects.staging(), &root.join("quarantine"), options.meta)?;
        let history = load_history(root)?;
        let seq = meta.state().seq;
        Ok(Self {
            root: root.to_path_buf(),
            id,
            history,
            objects,
            meta: Mutex::new(meta),
            recovery,
            gc: files::GcGate::default(),
            seq: (Mutex::new(seq), Condvar::new()),
            _lock: lock,
        })
    }

    /// What opening had to repair.
    pub fn recovery(&self) -> &Recovery {
        &self.recovery
    }

    /// Records `op` durably and applies it.
    pub fn commit(&self, op: &Op) -> Result<Applied> {
        let applied = lock(&self.meta).commit(op)?;
        self.signal(applied.seq);
        Ok(applied)
    }

    fn signal(&self, seq: u64) {
        let mut last = lock(&self.seq.0);
        if seq > *last {
            *last = seq;
            self.seq.1.notify_all();
        }
    }

    /// Waits until a record after `after` is committed, or `timeout`
    /// passes. Returns the last sequence number.
    pub fn wait_for_change(&self, after: u64, timeout: Duration) -> u64 {
        let deadline = Instant::now() + timeout;
        let mut last = lock(&self.seq.0);
        while *last <= after {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else { break };
            last = self.seq.1.wait_timeout(last, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        *last
    }

    /// Decides an operation from the current metadata and commits it with
    /// no other commit in between.
    pub fn commit_with<T>(
        &self,
        decide: impl FnOnce(&State) -> Result<(Option<Op>, T)>,
    ) -> Result<(Option<Applied>, T)> {
        let result = lock(&self.meta).commit_with(decide)?;
        if let Some(applied) = &result.0 {
            self.signal(applied.seq);
        }
        Ok(result)
    }

    /// Runs `f` on the current metadata.
    pub fn read<R>(&self, f: impl FnOnce(&State) -> R) -> R {
        f(lock(&self.meta).state())
    }

    /// Checks the metadata files on disk, and repairs damage from the state
    /// in memory (see `scrub`). Returns what was damaged.
    pub fn scrub_metadata(&self) -> Result<Vec<String>> {
        let damaged = meta::Meta::verify_files(&self.root.join("meta"))?;
        if damaged.is_empty() {
            return Ok(Vec::new());
        }
        let bad_snapshots: Vec<u64> = damaged.iter().filter_map(|(_, _, s)| *s).collect();
        for (name, problem, _) in &damaged {
            eprintln!("hd-store: metadata file {name} is damaged: {problem}");
        }
        lock(&self.meta).supersede(&bad_snapshots)?;
        Ok(damaged.into_iter().map(|(n, p, _)| format!("{n}: {p}")).collect())
    }

    /// Writes a snapshot now; returns its sequence number.
    pub fn checkpoint(&self) -> Result<u64> {
        lock(&self.meta).checkpoint()
    }

    /// Whether a failed write has stopped the store accepting more.
    pub fn is_poisoned(&self) -> bool {
        lock(&self.meta).is_poisoned()
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The store's identity from `store.id`.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The identity of this store's history, from `history.id`.
    pub fn history(&self) -> &str {
        &self.history
    }

    pub fn objects(&self) -> &Objects {
        &self.objects
    }
}

/// Whether `root` holds a store: for `init` to explain itself before
/// touching anything.
pub fn is_store(root: &Path) -> bool {
    match fs::symlink_metadata(root.join(SENTINEL)) {
        Ok(_) => true,
        Err(e) => e.kind() != ErrorKind::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hd_chunk::ObjectId;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hd-store-{}-{name}", std::process::id()));
        if dir.exists() {
            make_writable(&dir);
            fs::remove_dir_all(&dir).unwrap();
        }
        dir
    }

    fn make_writable(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let p = entry.path();
            if entry.file_type().unwrap().is_dir() {
                make_writable(&p);
            } else {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }

    fn fresh(name: &str) -> (PathBuf, Store) {
        let dir = scratch(name);
        Store::init(&dir).unwrap();
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        (dir, store)
    }

    fn cleanup(dir: &Path) {
        make_writable(dir);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Rewrites an object file's bytes behind the store's back.
    fn tamper(path: &Path, f: impl FnOnce(&mut Vec<u8>)) {
        let mut bytes = fs::read(path).unwrap();
        f(&mut bytes);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, &bytes).unwrap();
    }

    #[test]
    fn init_needs_an_empty_directory_and_open_fails_closed() {
        let dir = scratch("init");
        // An unmounted disk: an empty mount point with no sentinel.
        fs::create_dir_all(&dir).unwrap();
        let err = Store::open(&dir, &StoreOptions::default()).unwrap_err();
        assert!(err.message().contains("has no store.id"), "{err}");
        assert!(!is_store(&dir));
        // A fresh ext4 filesystem's lost+found does not count.
        fs::create_dir(dir.join("lost+found")).unwrap();
        let id = Store::init(&dir).unwrap();
        assert!(is_store(&dir));
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        assert_eq!(store.id(), id);
        // One process at a time.
        assert!(
            Store::open(&dir, &StoreOptions::default())
                .unwrap_err()
                .message()
                .contains("already open")
        );
        drop(store);
        Store::open(&dir, &StoreOptions::default()).unwrap();
        // init never adopts or replaces an existing tree.
        assert!(Store::init(&dir).unwrap_err().message().contains("not empty"));
        let other = scratch("init-other");
        fs::create_dir_all(&other).unwrap();
        fs::write(other.join("somebody's file"), b"x").unwrap();
        assert!(Store::init(&other).unwrap_err().message().contains("not empty"));
        assert_eq!(fs::read(other.join("somebody's file")).unwrap(), b"x");
        cleanup(&dir);
        cleanup(&other);
    }

    /// A failing disk: an object whose reads fail. A one-off failure is
    /// retried; a lasting one sets the object aside, without losing its
    /// bytes, so that a good copy can be stored in its place.
    #[test]
    fn unreadable_objects_are_set_aside_and_replaced() {
        use crate::objects::{Health, Kind, read_faults};
        let dir = scratch("unreadable");
        Store::init(&dir).unwrap();
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        let o = store.objects();
        let (id, _) = o.put(Kind::Chunk, b"precious").unwrap();
        let path = o.path(Kind::Chunk, &id);
        // A transient error: the retry reads it.
        read_faults::set(&path, 1);
        assert_eq!(o.get(Kind::Chunk, &id).unwrap(), b"precious");
        assert_eq!(o.quarantined_count(), 0);
        // A lasting one: set aside, and then missing.
        read_faults::set(&path, 2);
        assert!(o.get(Kind::Chunk, &id).unwrap_err().message().contains("could not be read"));
        assert_eq!(o.quarantined_count(), 1);
        assert_eq!(o.check(Kind::Chunk, &id).unwrap(), Health::Missing);
        // The next upload of the content heals it.
        o.put(Kind::Chunk, b"precious").unwrap();
        assert_eq!(o.get(Kind::Chunk, &id).unwrap(), b"precious");
        // An unreadable existing copy does not block a good one.
        read_faults::set(&path, 2);
        o.put(Kind::Chunk, b"precious").unwrap();
        assert_eq!(o.quarantined_count(), 2);
        assert_eq!(o.get(Kind::Chunk, &id).unwrap(), b"precious");
        // Scrub records what it cannot read and carries on, and the
        // reference check then names the file it belongs to.
        let by = Provenance {
            device: "pc".into(),
            mtime_ms: 0,
            origin: model::Origin::Upload,
            created_ms: None,
        };
        store
            .write_file("alice", "f.txt", Base::Absent, &b"also precious"[..], 1 << 20, &by)
            .unwrap();
        let other = ObjectId::of(b"also precious").unwrap();
        read_faults::set(&o.path(Kind::Chunk, &other), 2);
        let report = store.scrub(0, &std::sync::atomic::AtomicBool::new(false)).unwrap();
        assert_eq!(report.quarantined, vec![(Kind::Chunk, other)]);
        assert!(report.checked >= 3, "{report:?}");
        let check = store.fsck(false).unwrap();
        assert_eq!(check.damaged_current.len(), 1);
        assert_eq!(check.damaged_current[0].path, "f.txt");
        // The set-aside copy was fine all along (a passing fault): repair
        // takes it back from quarantine, verified.
        let repaired = store.repair_from(&[]).unwrap();
        assert_eq!((repaired.restored, repaired.still_damaged.len()), (1, 0), "{repaired:?}");
        assert!(store.fsck(true).unwrap().is_clean());
        drop(store);
        cleanup(&dir);
    }

    /// Damaged metadata files are found by scrubbing, while the state in
    /// memory is still good, and repaired by a fresh checkpoint.
    #[test]
    fn scrub_repairs_damaged_metadata_from_memory() {
        let dir = scratch("meta-scrub");
        Store::init(&dir).unwrap();
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        let mkdir = |p: &str| {
            store.commit(&Op::Mkdir { user: "alice".into(), path: p.into() }).unwrap();
        };
        mkdir("a");
        let seq = store.checkpoint().unwrap();
        mkdir("b");
        assert!(store.scrub_metadata().unwrap().is_empty());
        // Bit rot in the newest snapshot, which recovery would start from.
        tamper(&dir.join("meta").join(meta::snapshot_name(seq)), |b| b[30] ^= 0x10);
        let damaged = store.scrub_metadata().unwrap();
        assert_eq!(damaged.len(), 1, "{damaged:?}");
        assert!(store.scrub_metadata().unwrap().is_empty(), "the repair holds");
        drop(store);
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        assert!(store.recovery().bad_snapshots.is_empty());
        assert!(store.read(|s| s.user("alice").unwrap().get("b").is_some()));
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn a_store_without_its_history_id_starts_a_new_history() {
        let dir = scratch("history");
        Store::init(&dir).unwrap();
        let first = Store::open(&dir, &StoreOptions::default()).unwrap().history().to_owned();
        // Kept across restarts...
        assert_eq!(Store::open(&dir, &StoreOptions::default()).unwrap().history(), first);
        // ...and replaced when missing, as in a store restored from a backup.
        fs::set_permissions(dir.join(HISTORY), fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(dir.join(HISTORY)).unwrap();
        let second = Store::open(&dir, &StoreOptions::default()).unwrap().history().to_owned();
        assert_ne!(first, second);
        // A damaged file stops the store rather than guessing.
        fs::set_permissions(dir.join(HISTORY), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(dir.join(HISTORY), "homedrive history\nid xyz\n").unwrap();
        let err = Store::open(&dir, &StoreOptions::default()).unwrap_err();
        assert!(err.message().contains("damaged"), "{err}");
        assert_eq!(parse_history(&history_text(&second)), Some(second));
        cleanup(&dir);
    }

    #[test]
    fn sentinels_are_parsed_strictly() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(parse_sentinel(&sentinel_text(id)).unwrap(), id);
        for bad in [
            String::new(),
            sentinel_text(id).replace("format 1", "format 2"),
            sentinel_text(id).replace("homedrive", "otherdrive"),
            sentinel_text(&id.to_uppercase()),
            sentinel_text(&id[1..]),
            sentinel_text(id) + "extra\n",
            sentinel_text(id).trim_end().to_owned(),
        ] {
            assert!(parse_sentinel(&bad).is_err(), "{bad:?}");
        }
        assert!(
            parse_sentinel(&sentinel_text(id).replace("format 1", "format 2"))
                .unwrap_err()
                .message()
                .contains("format 2")
        );
    }

    #[test]
    fn objects_round_trip_and_deduplicate() {
        let (dir, store) = fresh("roundtrip");
        let o = store.objects();
        let data = b"some file content".to_vec();
        let (id, created) = o.put(Kind::Chunk, &data).unwrap();
        assert_eq!(created, Created::New);
        assert_eq!(id, ObjectId::of(&data).unwrap());
        assert!(o.contains(Kind::Chunk, &id));
        assert_eq!(o.get(Kind::Chunk, &id).unwrap(), data);
        assert_eq!(o.put(Kind::Chunk, &data).unwrap(), (id, Created::Existed));
        // The kinds are separate namespaces.
        assert!(!o.contains(Kind::Manifest, &id));
        assert!(o.get(Kind::Manifest, &id).unwrap_err().message().contains("missing"));
        assert_eq!(o.put(Kind::Manifest, &data).unwrap(), (id, Created::New));
        // Objects are read-only on disk, and nothing is left in staging.
        let mode = fs::metadata(o.path(Kind::Chunk, &id)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o400);
        assert_eq!(fs::read_dir(dir.join("tmp")).unwrap().count(), 0);
        // The empty object is valid.
        let (empty, _) = o.put(Kind::Chunk, b"").unwrap();
        assert_eq!(o.get(Kind::Chunk, &empty).unwrap(), b"");
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn claimed_ids_are_checked_before_anything_is_stored() {
        let (dir, store) = fresh("claimed");
        let o = store.objects();
        let wrong = ObjectId::of(b"what the client said").unwrap();
        let err = o.put_claimed(Kind::Chunk, &wrong, b"what it sent").unwrap_err();
        assert!(err.message().contains("does not match"));
        assert!(!o.contains(Kind::Chunk, &wrong));
        let right = ObjectId::of(b"what it sent").unwrap();
        assert_eq!(o.put_claimed(Kind::Chunk, &right, b"what it sent").unwrap(), Created::New);
        assert!(o.put(Kind::Chunk, &vec![0; objects::MAX_OBJECT + 1]).is_err());
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn every_single_byte_corruption_is_detected_quarantined_and_healed() {
        let (dir, store) = fresh("bitflip");
        let o = store.objects();
        let data: Vec<u8> = (0..48_u8).collect();
        let (id, _) = o.put(Kind::Chunk, &data).unwrap();
        let path = o.path(Kind::Chunk, &id);
        let file_len = objects::HEADER_LEN + data.len();
        for at in 0..file_len {
            for bit in [0x01_u8, 0x80] {
                tamper(&path, |b| b[at] ^= bit);
                assert!(matches!(o.check(Kind::Chunk, &id).unwrap(), Health::Corrupt(_)));
                let err = o.get(Kind::Chunk, &id).unwrap_err();
                assert!(err.message().contains("quarantined"), "byte {at}: {err}");
                // Quarantined objects read as missing, so a client re-sends.
                assert!(!o.contains(Kind::Chunk, &id));
                assert_eq!(o.put(Kind::Chunk, &data).unwrap(), (id, Created::New));
                assert_eq!(o.get(Kind::Chunk, &id).unwrap(), data);
            }
        }
        // Every bad copy was kept for inspection, none deleted.
        assert_eq!(fs::read_dir(dir.join("quarantine")).unwrap().count(), file_len * 2);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn truncation_extension_and_header_lies_are_detected() {
        let (dir, store) = fresh("shapes");
        let o = store.objects();
        let data = vec![7_u8; 1000];
        let (id, _) = o.put(Kind::Chunk, &data).unwrap();
        let path = o.path(Kind::Chunk, &id);
        let cases: [fn(&mut Vec<u8>); 5] = [
            |b| b.truncate(b.len() - 1),
            |b| b.truncate(10),
            |b| b.clear(),
            |b| b.push(7),
            // A consistent header and size that still lie about the content.
            |b| {
                b.truncate(b.len() - 1);
                b[8..16].copy_from_slice(&999_u64.to_le_bytes());
            },
        ];
        for (i, case) in cases.iter().enumerate() {
            tamper(&path, case);
            assert!(o.get(Kind::Chunk, &id).is_err(), "case {i}");
            assert_eq!(o.put(Kind::Chunk, &data).unwrap(), (id, Created::New), "case {i}");
        }
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn storing_over_a_corrupt_copy_heals_it() {
        let (dir, store) = fresh("heal");
        let o = store.objects();
        let (id, _) = o.put(Kind::Chunk, b"precious").unwrap();
        tamper(&o.path(Kind::Chunk, &id), |b| b[20] ^= 1);
        // The client asked whether the chunk exists, was told yes, and
        // uploads anyway (or uploads another file with the same chunk).
        assert_eq!(o.put(Kind::Chunk, b"precious").unwrap(), (id, Created::New));
        assert_eq!(o.get(Kind::Chunk, &id).unwrap(), b"precious");
        assert_eq!(fs::read_dir(dir.join("quarantine")).unwrap().count(), 1);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn opening_clears_abandoned_staging_files() {
        let (dir, store) = fresh("staging");
        drop(store);
        fs::write(dir.join("tmp/0123.tmp"), b"half a chunk").unwrap();
        let store = Store::open(&dir, &StoreOptions::default()).unwrap();
        assert_eq!(fs::read_dir(dir.join("tmp")).unwrap().count(), 0);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn writes_stop_at_the_free_space_reserve_but_reads_continue() {
        let (dir, store) = fresh("reserve");
        let (id, _) = store.objects().put(Kind::Chunk, b"before").unwrap();
        drop(store);
        let store =
            Store::open(&dir, &StoreOptions { min_free: u64::MAX, ..StoreOptions::default() })
                .unwrap();
        let err = store.objects().put(Kind::Chunk, b"after").unwrap_err();
        assert!(err.message().contains("reserve"), "{err}");
        assert_eq!(store.objects().get(Kind::Chunk, &id).unwrap(), b"before");
        // Already-stored content needs no space.
        assert_eq!(store.objects().put(Kind::Chunk, b"before").unwrap().1, Created::Existed);
        drop(store);
        cleanup(&dir);
    }
}
