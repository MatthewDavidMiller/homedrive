//! Immutable, content-addressed objects: chunks of file data, and the
//! manifests that list a file's chunks.
//!
//! ```text
//! <root>/chunks/ab/cd/<id>      a chunk whose SHA-256 is <id> (64 hex digits)
//! <root>/manifests/ab/cd/<id>   a manifest, the same way
//! <root>/quarantine/<kind>-<id>-<unix ms>-<random>
//!                               an object that failed verification
//! <root>/tmp/                   staging for writes (same filesystem)
//! ```
//!
//! Every object file is a 16-byte header followed by the object's bytes:
//!
//! ```text
//! offset 0  4 bytes  magic "HDO1"
//!        4  1 byte   format version (1)
//!        5  1 byte   kind (1 chunk, 2 manifest)
//!        6  2 bytes  zero
//!        8  8 bytes  length of the bytes that follow, little-endian
//! ```
//!
//! An object's ID is the SHA-256 of those bytes alone, so a client can
//! compute it without knowing the file format.
//!
//! The rules this module keeps:
//! - **An object file is written once and never modified.** Writes go
//!   through `fsio::write_new_durable`, which never replaces a name.
//! - **Nothing is returned unverified.** Every read checks the header, the
//!   file size, and the SHA-256 against the name before handing bytes out.
//! - **A bad object is moved aside, never deleted.** Verification failure
//!   moves it to `quarantine/` and reports it, so the object reads as
//!   missing. The next upload of the same content (a client asks which
//!   chunks the server lacks before it uploads) writes a good copy, and the
//!   store heals.
//! - **An unreadable object is treated the same way.** A failing disk
//!   answers some reads with I/O errors. A read that fails twice moves the
//!   object to `quarantine/` too. That only renames it, so the bytes are
//!   kept, and `repair` takes it back if it later reads correctly. A fresh
//!   copy, from a client or a backup, is written to new sectors. An
//!   existing copy that cannot be read never blocks storing a good one.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hd_chunk::{MAX_CHUNK, ObjectId};
use hd_common::fsio::{self, Created};
use hd_common::{Error, Result, timefmt};

const MAGIC: &[u8; 4] = b"HDO1";
const FORMAT: u8 = 1;
pub const HEADER_LEN: usize = 16;
/// The largest object of either kind. Chunks are at most `MAX_CHUNK`, and a
/// manifest too large for one object is itself stored in chunks.
pub const MAX_OBJECT: usize = MAX_CHUNK;
const OBJECT_MODE: u32 = 0o400;
const DIR_MODE: u32 = 0o700;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Chunk,
    Manifest,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Chunk => 1,
            Kind::Manifest => 2,
        }
    }

    pub const ALL: [Kind; 2] = [Kind::Chunk, Kind::Manifest];

    pub fn dir(self) -> &'static str {
        match self {
            Kind::Chunk => "chunks",
            Kind::Manifest => "manifests",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Chunk => "chunk",
            Kind::Manifest => "manifest",
        }
    }
}

/// What verifying one object found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    Good,
    Missing,
    /// The file exists but is not the object its name says. The reason is
    /// for the operator.
    Corrupt(String),
}

/// What reading one object found.
pub(crate) enum Outcome {
    Good(Vec<u8>),
    Missing,
    Corrupt(String),
}

/// The objects under one store root.
#[derive(Debug)]
pub struct Objects {
    root: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    /// Writes are refused while the filesystem has less than this free.
    min_free: u64,
    /// Objects quarantined since the store opened: a change tells the
    /// server to check which files are affected.
    quarantined: AtomicU64,
}

fn header(kind: Kind, len: usize) -> [u8; HEADER_LEN] {
    let mut h = [0_u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = FORMAT;
    h[5] = kind.byte();
    h[8..].copy_from_slice(&(len as u64).to_le_bytes());
    h
}

impl Objects {
    pub(crate) fn new(root: &Path, min_free: u64) -> Self {
        Self {
            root: root.to_path_buf(),
            staging: root.join("tmp"),
            quarantine: root.join("quarantine"),
            min_free,
            quarantined: AtomicU64::new(0),
        }
    }

    /// How many objects were quarantined since the store opened.
    pub fn quarantined_count(&self) -> u64 {
        self.quarantined.load(Ordering::Relaxed)
    }

    /// Where an object of `kind` lives under another store's root (a backup
    /// to repair from).
    pub fn path_in(root: &Path, kind: Kind, id: &ObjectId) -> PathBuf {
        let hex = id.hex();
        root.join(kind.dir()).join(&hex[..2]).join(&hex[2..4]).join(&hex)
    }

    /// Reads an object, retrying once: a failing disk's errors are often
    /// intermittent. An object that still cannot be read is quarantined
    /// (renamed, bytes kept) so it reads as missing and can be replaced.
    fn read_or_set_aside(&self, kind: Kind, id: &ObjectId) -> Result<Outcome> {
        match self.read_verified(kind, id) {
            Ok(o) => Ok(o),
            Err(_) => match self.read_verified(kind, id) {
                Ok(o) => Ok(o),
                Err(e) => {
                    self.quarantine(kind, id, &format!("unreadable: {e}"))?;
                    Err(Error::new(format!(
                        "{} {id} could not be read ({e}) and was quarantined",
                        kind.name()
                    )))
                }
            },
        }
    }

    /// The directories objects live in; created durably at open.
    pub(crate) fn directories(root: &Path) -> [PathBuf; 4] {
        [
            root.join(Kind::Chunk.dir()),
            root.join(Kind::Manifest.dir()),
            root.join("quarantine"),
            root.join("tmp"),
        ]
    }

    pub fn path(&self, kind: Kind, id: &ObjectId) -> PathBuf {
        Self::path_in(&self.root, kind, id)
    }

    /// Whether an object file exists under the name. Existence only: use
    /// [`Objects::get`] or [`Objects::check`] to know it is intact.
    pub fn contains(&self, kind: Kind, id: &ObjectId) -> bool {
        fs::symlink_metadata(self.path(kind, id)).is_ok_and(|m| m.file_type().is_file())
    }

    /// Stores `data` and returns its ID. Storing what is already there is
    /// cheap and changes nothing, unless the existing copy fails
    /// verification, in which case it is quarantined and replaced by this
    /// one.
    pub fn put(&self, kind: Kind, data: &[u8]) -> Result<(ObjectId, Created)> {
        let id = ObjectId::of(data)?;
        Ok((id, self.write(kind, &id, data)?))
    }

    /// As [`Objects::put`], for data that arrived with a claimed ID (an
    /// upload). Data that does not hash to the claim is refused and nothing
    /// is stored.
    pub fn put_claimed(&self, kind: Kind, claimed: &ObjectId, data: &[u8]) -> Result<Created> {
        if ObjectId::of(data)? != *claimed {
            return Err(Error::new(format!("{} {claimed} does not match its ID", kind.name())));
        }
        self.write(kind, claimed, data)
    }

    fn write(&self, kind: Kind, id: &ObjectId, data: &[u8]) -> Result<Created> {
        if data.len() > MAX_OBJECT {
            return Err(Error::new(format!("{} is larger than {MAX_OBJECT} bytes", kind.name())));
        }
        let path = self.path(kind, id);
        // An existing copy that cannot be read (a bad sector) is set aside
        // like a corrupt one, so this good copy can take its place.
        match self.read_or_set_aside(kind, id) {
            Ok(Outcome::Good(_)) => return Ok(Created::Existed),
            Ok(Outcome::Missing) | Err(_) => {}
            Ok(Outcome::Corrupt(reason)) => {
                self.quarantine(kind, id, &reason)?;
            }
        }
        self.require_space(data.len())?;
        let dir = path.parent().ok_or_else(|| Error::new("object path has no parent"))?;
        fsio::mkdir_durable(dir, DIR_MODE)?;
        let created = fsio::write_new_durable(
            &path,
            &self.staging,
            &[&header(kind, data.len()), data],
            OBJECT_MODE,
        )?;
        if created == Created::Existed {
            // Another writer stored it between the check and the link. Its
            // copy must be as good as ours would have been.
            match self.check(kind, id)? {
                Health::Good => {}
                Health::Missing => return Err(Error::new("object vanished while it was stored")),
                Health::Corrupt(reason) => {
                    return Err(Error::new(format!(
                        "{} {id} was stored concurrently and is corrupt: {reason}",
                        kind.name()
                    )));
                }
            }
        }
        Ok(created)
    }

    fn require_space(&self, len: usize) -> Result<()> {
        #[cfg(unix)]
        let space = hd_sys::posix::fs_space(&self.root)?;
        #[cfg(windows)]
        let space = hd_sys::windows::fs_space(&self.root)?;
        let needed = self.min_free.saturating_add(len as u64 + HEADER_LEN as u64);
        if space.available < needed {
            return Err(Error::new(format!(
                "the store has {} bytes free, below its reserve of {}; refusing writes",
                space.available, self.min_free
            )));
        }
        Ok(())
    }

    /// Reads the object file and verifies it. `Err` is an I/O failure that
    /// says nothing about the object itself.
    fn read_verified(&self, kind: Kind, id: &ObjectId) -> Result<Outcome> {
        read_verified_at(&self.path(kind, id), kind, id)
    }

    /// Verifies an object without keeping its bytes: for scrubbing, and to
    /// decide whether an existing copy is acceptable.
    pub fn check(&self, kind: Kind, id: &ObjectId) -> Result<Health> {
        Ok(match self.read_verified(kind, id)? {
            Outcome::Good(_) => Health::Good,
            Outcome::Missing => Health::Missing,
            Outcome::Corrupt(reason) => Health::Corrupt(reason),
        })
    }

    /// The object's bytes, verified. A corrupt object is quarantined and
    /// reported as an error; it then reads as missing until it is uploaded
    /// again.
    pub fn get(&self, kind: Kind, id: &ObjectId) -> Result<Vec<u8>> {
        match self.read_or_set_aside(kind, id)? {
            Outcome::Good(data) => Ok(data),
            Outcome::Missing => Err(Error::new(format!("{} {id} is missing", kind.name()))),
            Outcome::Corrupt(reason) => {
                self.quarantine(kind, id, &reason)?;
                Err(Error::new(format!("{} {id} is corrupt and was quarantined", kind.name())))
            }
        }
    }

    /// Moves a failed object aside so it reads as missing, keeping its bytes
    /// for inspection.
    pub fn quarantine(&self, kind: Kind, id: &ObjectId, reason: &str) -> Result<()> {
        let from = self.path(kind, id);
        // The time says when; the random suffix keeps two quarantines of the
        // same object within one millisecond from colliding.
        let to = self.quarantine.join(format!(
            "{}-{id}-{}-{}",
            kind.name(),
            timefmt::now_ms(),
            hd_common::rand::random_hex(4)?
        ));
        fsio::move_new_durable(&from, &to)?;
        self.quarantined.fetch_add(1, Ordering::Relaxed);
        eprintln!("hd-store: quarantined {} {id}: {reason}", kind.name());
        Ok(())
    }

    /// The object's bytes, verified, without quarantining a bad one: for
    /// read-only checks.
    pub fn peek(&self, kind: Kind, id: &ObjectId) -> Result<std::result::Result<Vec<u8>, Health>> {
        Ok(match self.read_verified(kind, id)? {
            Outcome::Good(data) => Ok(data),
            Outcome::Missing => Err(Health::Missing),
            Outcome::Corrupt(reason) => Err(Health::Corrupt(reason)),
        })
    }

    /// Calls `f` for every object file of `kind`, with its ID and metadata.
    /// Files whose names are not IDs are reported on stderr and skipped.
    pub fn for_each(
        &self,
        kind: Kind,
        mut f: impl FnMut(ObjectId, &Path, &fs::Metadata) -> Result<()>,
    ) -> Result<()> {
        let top = self.root.join(kind.dir());
        for a in sorted_dir(&top)? {
            for b in sorted_dir(&a)? {
                for path in sorted_dir(&b)? {
                    let meta = fs::symlink_metadata(&path)?;
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    match ObjectId::parse(name) {
                        Some(id) if meta.file_type().is_file() && self.path(kind, &id) == path => {
                            f(id, &path, &meta)?;
                        }
                        _ => eprintln!("hd-store: ignoring stray {}", path.display()),
                    }
                }
            }
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The staging directory, cleared when the store opens.
    pub(crate) fn staging(&self) -> &Path {
        &self.staging
    }
}

/// Reads the object file at `path` and verifies it as `kind` `id`. `Err`
/// is an I/O failure that says nothing about the object itself.
pub(crate) fn read_verified_at(path: &Path, kind: Kind, id: &ObjectId) -> Result<Outcome> {
    #[cfg(test)]
    if read_faults::fail(path) {
        return Err(Error::new("injected read error"));
    }
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Outcome::Missing),
        Err(e) => return Err(e.into()),
    };
    let corrupt = |why: &str| Ok(Outcome::Corrupt(why.to_owned()));
    if !meta.file_type().is_file() {
        return corrupt("not a regular file");
    }
    if meta.len() < HEADER_LEN as u64 {
        return corrupt("shorter than the header");
    }
    if meta.len() > (HEADER_LEN + MAX_OBJECT) as u64 {
        return corrupt("larger than any object");
    }
    let mut file = fsio::open_nofollow(path)?;
    let mut head = [0_u8; HEADER_LEN];
    file.read_exact(&mut head)?;
    if &head[..4] != MAGIC {
        return corrupt("bad magic");
    }
    if head[4] != FORMAT {
        return corrupt("unknown format version");
    }
    if head[5] != kind.byte() || head[6] != 0 || head[7] != 0 {
        return corrupt("bad header");
    }
    let mut len_bytes = [0_u8; 8];
    len_bytes.copy_from_slice(&head[8..]);
    let len = u64::from_le_bytes(len_bytes);
    if len.checked_add(HEADER_LEN as u64) != Some(meta.len()) {
        return corrupt("length does not match the file size");
    }
    let len = usize::try_from(len).map_err(|_| Error::new("object length out of range"))?;
    let mut data = Vec::new();
    data.try_reserve_exact(len).map_err(|_| Error::new("out of memory"))?;
    data.resize(len, 0);
    match file.read_exact(&mut data) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return corrupt("truncated"),
        Err(e) => return Err(e.into()),
    }
    // One byte more would mean the file grew after it was measured.
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        return corrupt("longer than its header says");
    }
    if ObjectId::of(&data)? != *id {
        return corrupt("content does not match its ID");
    }
    Ok(Outcome::Good(data))
}

/// Whether `bytes` are a whole, correct object file for `kind` `id`: the
/// same checks as a read from disk, for bytes still in memory.
pub(crate) fn verify_bytes(bytes: &[u8], kind: Kind, id: &ObjectId) -> bool {
    if bytes.len() < HEADER_LEN || bytes.len() > HEADER_LEN + MAX_OBJECT {
        return false;
    }
    let (head, data) = bytes.split_at(HEADER_LEN);
    let mut len_bytes = [0_u8; 8];
    len_bytes.copy_from_slice(&head[8..]);
    &head[..4] == MAGIC
        && head[4] == FORMAT
        && head[5] == kind.byte()
        && head[6] == 0
        && head[7] == 0
        && u64::from_le_bytes(len_bytes) == data.len() as u64
        && ObjectId::of(data).is_ok_and(|got| got == *id)
}

/// A directory's entries, sorted (empty for a directory that does not
/// exist).
fn sorted_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    match fs::read_dir(dir) {
        Ok(entries) => {
            for e in entries {
                out.push(e?.path());
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) if e.kind() == ErrorKind::NotADirectory => {
            eprintln!("hd-store: ignoring stray {}", dir.display());
        }
        Err(e) => return Err(e.into()),
    }
    out.sort();
    Ok(out)
}

/// Unit tests make reads of one path fail, the way a bad sector does.
#[cfg(test)]
pub(crate) mod read_faults {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        static FAILING: RefCell<Option<(PathBuf, u32)>> = const { RefCell::new(None) };
    }

    /// The next `times` reads of `path` on this thread fail.
    pub(crate) fn set(path: &Path, times: u32) {
        FAILING.with(|f| *f.borrow_mut() = Some((path.to_path_buf(), times)));
    }

    pub(super) fn fail(path: &Path) -> bool {
        FAILING.with(|f| match &mut *f.borrow_mut() {
            Some((p, n)) if p == path && *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        })
    }
}
