//! The homedrive storage engine.
//!
//! ```text
//! <root>/store.id     the sentinel: format and identity of this store
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
//! At this milestone (M1) the store holds objects. The metadata journal,
//! the namespace, versions, and GC come in M2 and M3 (docs/PLAN.md).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod objects;

use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use hd_common::fsio::{self, Created};
use hd_common::{Error, Result};

pub use objects::{Health, Kind, Objects};

const SENTINEL: &str = "store.id";
const SENTINEL_FORMAT: u32 = 1;
const MAX_SENTINEL: usize = 4096;
const DIR_MODE: u32 = 0o700;

/// Entries that may exist in a directory `init` still treats as empty: the
/// directory ext4 creates at the root of every filesystem.
const IGNORED_IN_EMPTY: &[&str] = &["lost+found"];

/// An open store. Only one process can hold it: the lock is released when
/// this is dropped.
#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    id: String,
    objects: Objects,
    _lock: File,
}

fn sentinel_text(id: &str) -> String {
    format!("homedrive store\nformat {SENTINEL_FORMAT}\nid {id}\n")
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

    /// Opens an existing store, refusing anything that is not one.
    /// `min_free` is the free-space reserve below which writes are refused.
    pub fn open(root: &Path, min_free: u64) -> Result<Self> {
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
        let objects = Objects::new(root, min_free);
        // Holding the lock, nothing else can be writing: whatever is left in
        // staging is from a write that never reached its commit point.
        let abandoned = fsio::clear_staging(objects.staging())?;
        if abandoned > 0 {
            eprintln!("hd-store: removed {abandoned} unfinished write(s) from staging");
        }
        Ok(Self { root: root.to_path_buf(), id, objects, _lock: lock })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The store's identity from `store.id`.
    pub fn id(&self) -> &str {
        &self.id
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
        let store = Store::open(&dir, 0).unwrap();
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
        let err = Store::open(&dir, 0).unwrap_err();
        assert!(err.message().contains("has no store.id"), "{err}");
        assert!(!is_store(&dir));
        // A fresh ext4 filesystem's lost+found does not count.
        fs::create_dir(dir.join("lost+found")).unwrap();
        let id = Store::init(&dir).unwrap();
        assert!(is_store(&dir));
        let store = Store::open(&dir, 0).unwrap();
        assert_eq!(store.id(), id);
        // One process at a time.
        assert!(Store::open(&dir, 0).unwrap_err().message().contains("already open"));
        drop(store);
        Store::open(&dir, 0).unwrap();
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
        let store = Store::open(&dir, 0).unwrap();
        assert_eq!(fs::read_dir(dir.join("tmp")).unwrap().count(), 0);
        drop(store);
        cleanup(&dir);
    }

    #[test]
    fn writes_stop_at_the_free_space_reserve_but_reads_continue() {
        let (dir, store) = fresh("reserve");
        let (id, _) = store.objects().put(Kind::Chunk, b"before").unwrap();
        drop(store);
        let store = Store::open(&dir, u64::MAX).unwrap();
        let err = store.objects().put(Kind::Chunk, b"after").unwrap_err();
        assert!(err.message().contains("reserve"), "{err}");
        assert_eq!(store.objects().get(Kind::Chunk, &id).unwrap(), b"before");
        // Already-stored content needs no space.
        assert_eq!(store.objects().put(Kind::Chunk, b"before").unwrap().1, Created::Existed);
        drop(store);
        cleanup(&dir);
    }
}
