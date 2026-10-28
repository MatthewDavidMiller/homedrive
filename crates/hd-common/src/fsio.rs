//! File access for paths an operator or another process may control.
//!
//! Reads refuse symlinks and non-regular files, open with `O_NOFOLLOW`, and
//! confirm the opened file is the one that was checked (same device and
//! inode) before reading at most a stated number of bytes. Replacements
//! stage into a fresh mode-0600 file beside the target, fsync it, rename it
//! over, and fsync the directory, so a crash leaves either the old document
//! or the new one.
//!
//! The store's immutable objects use [`write_new_durable`] instead, which
//! never replaces anything: it stages in a scratch directory on the same
//! filesystem, fsyncs, hard-links the staged file into place (a link fails
//! rather than replacing an existing name), and fsyncs the directory.
//! Directories are created with [`mkdir_durable`], which fsyncs each parent
//! that gained an entry, so a crash cannot lose the path to a file whose
//! own fsync succeeded.
//!
//! This module is the only shipped code allowed to write, rename, or
//! delete files (`scripts/check-rust.sh` enforces it), and it deletes only
//! its own staging files and the source name of a completed move.

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use hd_sys::posix::{O_DIRECTORY, O_NOFOLLOW};

use crate::{Error, Result};

/// Reads the whole file, at most `maximum` bytes. `Ok(None)` means the path
/// does not exist.
pub fn read_bounded(path: impl AsRef<Path>, maximum: usize) -> Result<Option<Vec<u8>>> {
    let path = path.as_ref();
    let before = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !before.file_type().is_file() {
        return Err(Error::new("path is not a safe regular file"));
    }
    if before.len() > maximum as u64 {
        return Err(Error::new("file exceeds its size limit"));
    }
    let file = OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() || !opened.file_type().is_file()
    {
        return Err(Error::new("file changed while opening"));
    }
    let mut out = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0).min(maximum));
    // One byte past the limit tells a file that grew after the check apart
    // from one that fits exactly.
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = file.take(limit);
    loop {
        let mut chunk = [0_u8; 8192];
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
        if out.len() > maximum {
            return Err(Error::new("file exceeds its size limit"));
        }
    }
    Ok(Some(out))
}

/// As [`read_bounded`], and also requires valid UTF-8.
pub fn read_text(path: impl AsRef<Path>, maximum: usize) -> Result<Option<String>> {
    match read_bounded(path, maximum)? {
        None => Ok(None),
        Some(bytes) => {
            String::from_utf8(bytes).map(Some).map_err(|_| Error::new("file is not valid UTF-8"))
        }
    }
}

/// The directory a path lives in ("." for a bare name) and its final
/// component.
fn split_path(path: &Path) -> Option<(PathBuf, &std::ffi::OsStr)> {
    let name = path.file_name()?;
    let dir = match path.parent() {
        Some(p) if p.as_os_str().is_empty() => PathBuf::from("."),
        Some(p) => p.to_path_buf(),
        None => return None,
    };
    Some((dir, name))
}

/// Fsyncs a directory, making the entries created, renamed, or removed in
/// it durable.
pub fn sync_directory(dir: &Path) -> Result<()> {
    let handle = OpenOptions::new().read(true).custom_flags(O_DIRECTORY).open(dir)?;
    handle.sync_all()?;
    Ok(())
}

/// Atomically replaces `path` with `data`, durably.
pub fn atomic_replace(path: impl AsRef<Path>, data: &[u8], maximum: usize) -> Result<()> {
    let path = path.as_ref();
    if data.len() > maximum {
        return Err(Error::new("replacement exceeds its size limit"));
    }
    if path.as_os_str().as_encoded_bytes().ends_with(b"/") {
        return Err(Error::new("invalid target path"));
    }
    let (dir, name) = split_path(path).ok_or_else(|| Error::new("invalid target path"))?;
    if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
        return Err(Error::new("target directory is unsafe"));
    }
    if let Ok(m) = fs::symlink_metadata(path)
        && !m.file_type().is_file()
    {
        return Err(Error::new("target path is unsafe"));
    }
    let nonce = crate::rand::random_hex(12)?;
    let mut staged_name = std::ffi::OsString::from(".");
    staged_name.push(name);
    staged_name.push(format!(".{nonce}.tmp"));
    let staged = dir.join(&staged_name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&staged)?;
    let result = (|| -> Result<()> {
        faults::hit("replace.write")?;
        file.write_all(data)?;
        faults::hit("replace.sync")?;
        file.sync_all()?;
        drop(file);
        faults::hit("replace.rename")?;
        fs::rename(&staged, path)?;
        faults::hit("replace.sync_dir")?;
        sync_directory(&dir)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

/// How [`write_new_durable`] ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Created {
    /// The file was written and is durable.
    New,
    /// A file already had the name. Nothing was changed; the caller decides
    /// whether the existing file is acceptable (for content-addressed data,
    /// by verifying it).
    Existed,
}

/// Creates `path` with the concatenation of `parts`, durably and without
/// ever replacing an existing file.
///
/// The data is staged in `staging` (which must be on the same filesystem
/// as `path`), fsynced, and hard-linked to `path`; the link is the commit
/// point, and it fails rather than replacing a file that already has the
/// name. `path`'s directory is then fsynced. A crash at any point leaves
/// either no file at `path` or the complete, fsynced file; at worst a
/// staging file is left behind, which [`clear_staging`] removes.
pub fn write_new_durable(
    path: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    parts: &[&[u8]],
    mode: u32,
) -> Result<Created> {
    let path = path.as_ref();
    let (dir, _) = split_path(path).ok_or_else(|| Error::new("invalid target path"))?;
    if fs::symlink_metadata(path).is_ok() {
        return Ok(Created::Existed);
    }
    let nonce = crate::rand::random_hex(12)?;
    let staged = staging.as_ref().join(format!("{nonce}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(O_NOFOLLOW)
        .open(&staged)?;
    let result = (|| -> Result<Created> {
        faults::hit("new.write")?;
        for part in parts {
            file.write_all(part)?;
        }
        faults::hit("new.sync")?;
        file.sync_all()?;
        faults::hit("new.link")?;
        match fs::hard_link(&staged, path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(Created::Existed),
            Err(e) => return Err(e.into()),
        }
        faults::hit("new.sync_dir")?;
        sync_directory(&dir)?;
        Ok(Created::New)
    })();
    // The staged name is only a second link to the committed file (or an
    // abandoned copy); removing it never touches the data at `path`.
    drop(file);
    let _ = fs::remove_file(&staged);
    result
}

/// Moves a regular file to a new name that must not exist yet, durably:
/// link the new name, fsync its directory, unlink the old name, fsync that
/// directory. A crash leaves the file under one name or both, never
/// neither.
pub fn move_new_durable(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let (from, to) = (from.as_ref(), to.as_ref());
    if !fs::symlink_metadata(from)?.file_type().is_file() {
        return Err(Error::new("source path is unsafe"));
    }
    let (to_dir, _) = split_path(to).ok_or_else(|| Error::new("invalid target path"))?;
    let (from_dir, _) = split_path(from).ok_or_else(|| Error::new("invalid source path"))?;
    faults::hit("move.link")?;
    fs::hard_link(from, to)?;
    faults::hit("move.sync_dir")?;
    sync_directory(&to_dir)?;
    faults::hit("move.unlink")?;
    fs::remove_file(from)?;
    sync_directory(&from_dir)
}

/// Removes every regular file in a staging directory. Only for directories
/// that hold nothing but [`write_new_durable`]'s staging files, at startup,
/// before anything writes. Returns how many were removed.
pub fn clear_staging(dir: impl AsRef<Path>) -> Result<usize> {
    let dir = dir.as_ref();
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if entry.file_type()?.is_file() && name.as_encoded_bytes().ends_with(b".tmp") {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    if removed > 0 {
        sync_directory(dir)?;
    }
    Ok(removed)
}

/// `mkdir -p` that makes each new directory durable: after creating a
/// directory it fsyncs the parent that gained the entry.
pub fn mkdir_durable(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    let path = path.as_ref();
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_dir() => return Ok(()),
        Ok(_) => return Err(Error::new("path exists and is not a directory")),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    mkdir_durable(&parent, mode)?;
    faults::hit("mkdir.create")?;
    match fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        // Another thread made it between the check and here; that thread
        // syncs the parent, but syncing again costs little and is certain.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    if !fs::symlink_metadata(path)?.file_type().is_dir() {
        return Err(Error::new("path exists and is not a directory"));
    }
    faults::hit("mkdir.sync_dir")?;
    sync_directory(&parent)
}

/// Opens (creating if needed) `path` and takes an exclusive advisory lock
/// on it, without waiting. The lock lasts as long as the returned file is
/// open. `Ok(None)` means another process holds it.
pub fn lock_exclusive(path: impl AsRef<Path>) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// A file that only grows, for the metadata journal. Each [`Appender::append`]
/// writes at the end and fdatasyncs before returning, so whatever it
/// accepted survives a crash.
///
/// If an append fails part-way, the file may end in a partial record, and
/// writing after it would bury that record in the middle of the file. So
/// the first failure poisons the appender: every later append is refused
/// until the file is reopened, and reopening is where the torn tail is
/// found and set aside ([`truncate_tail`]).
#[derive(Debug)]
pub struct Appender {
    file: File,
    len: u64,
    poisoned: bool,
}

impl Appender {
    /// Creates `path` holding `header`, durably and without replacing
    /// anything, and opens it for appending.
    pub fn create(
        path: impl AsRef<Path>,
        staging: impl AsRef<Path>,
        header: &[u8],
    ) -> Result<Self> {
        let path = path.as_ref();
        if write_new_durable(path, staging, &[header], 0o600)? == Created::Existed {
            return Err(Error::new("the file to append to already exists"));
        }
        Self::open(path, header.len() as u64)
    }

    /// Opens an existing file whose first `len` bytes are known good and
    /// appends after them. The file must be exactly `len` bytes long: a
    /// longer one has a tail that must be dealt with first.
    pub fn open(path: impl AsRef<Path>, len: u64) -> Result<Self> {
        let file = OpenOptions::new().write(true).custom_flags(O_NOFOLLOW).open(path.as_ref())?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(Error::new("append target is not a regular file"));
        }
        if meta.len() != len {
            return Err(Error::new("append target has bytes past its known end"));
        }
        Ok(Self { file, len, poisoned: false })
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Appends `data` and makes it durable.
    pub fn append(&mut self, data: &[u8]) -> Result<()> {
        if self.poisoned {
            return Err(Error::new("an earlier write failed; reopen the store to recover"));
        }
        let result = (|| -> Result<()> {
            if faults::hit("append.torn").is_err() {
                let half = data.len() / 2;
                self.file.write_all_at(&data[..half], self.len)?;
                return Err(Error::new("injected fault: torn append"));
            }
            self.file.write_all_at(data, self.len)?;
            faults::hit("append.sync")?;
            self.file.sync_data()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.len += data.len() as u64;
                Ok(())
            }
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }
}

/// Sets aside everything in `path` past its first `keep` bytes: the bytes
/// are first copied, durably, to the new file `quarantine`, and only then
/// cut from `path`. Nothing is discarded. `maximum` bounds the tail.
pub fn truncate_tail(
    path: impl AsRef<Path>,
    keep: u64,
    quarantine: impl AsRef<Path>,
    staging: impl AsRef<Path>,
    maximum: usize,
) -> Result<u64> {
    let path = path.as_ref();
    let mut file = OpenOptions::new().read(true).write(true).custom_flags(O_NOFOLLOW).open(path)?;
    let len = file.metadata()?.len();
    if len <= keep {
        return Ok(0);
    }
    let tail_len = len - keep;
    let tail_size = usize::try_from(tail_len).map_err(|_| Error::new("tail too large"))?;
    if tail_size > maximum {
        return Err(Error::new("the tail to set aside exceeds its size limit"));
    }
    let tail = read_at_bounded(&mut file, keep, tail_size, maximum)?;
    if write_new_durable(quarantine, staging, &[&tail], 0o400)? == Created::Existed {
        return Err(Error::new("the quarantine file already exists"));
    }
    faults::hit("truncate.set_len")?;
    file.set_len(keep)?;
    file.sync_all()?;
    Ok(tail_len)
}

/// Fault injection for crash tests. With the `faults` feature, a test arms
/// a countdown and the n-th durable-write step on that thread fails; the
/// test then drops the store (a crash) and checks what reopening finds.
/// Without the feature every hook is an empty inline function.
pub mod faults {
    use std::io;

    #[cfg(feature = "faults")]
    mod state {
        use std::cell::Cell;

        thread_local! {
            pub(super) static COUNTDOWN: Cell<u64> = const { Cell::new(0) };
            pub(super) static PASSED: Cell<u64> = const { Cell::new(0) };
            pub(super) static FIRED: Cell<Option<&'static str>> = const { Cell::new(None) };
        }
    }

    /// Makes the `n`-th hook from now (1-based) fail on this thread; `0`
    /// disarms. Resets the counters.
    #[cfg(feature = "faults")]
    pub fn arm(n: u64) {
        state::COUNTDOWN.with(|c| c.set(n));
        state::PASSED.with(|c| c.set(0));
        state::FIRED.with(|c| c.set(None));
    }

    #[cfg(feature = "faults")]
    pub fn disarm() {
        arm(0);
    }

    /// The hook that fired since the last [`arm`], if any.
    #[cfg(feature = "faults")]
    pub fn fired() -> Option<&'static str> {
        state::FIRED.with(std::cell::Cell::get)
    }

    /// How many hooks have been passed since the last [`arm`].
    #[cfg(feature = "faults")]
    pub fn passed() -> u64 {
        state::PASSED.with(std::cell::Cell::get)
    }

    #[cfg(feature = "faults")]
    pub(crate) fn hit(point: &'static str) -> io::Result<()> {
        state::PASSED.with(|c| c.set(c.get() + 1));
        let fire = state::COUNTDOWN.with(|c| match c.get() {
            0 => false,
            1 => {
                c.set(0);
                true
            }
            n => {
                c.set(n - 1);
                false
            }
        });
        if fire {
            state::FIRED.with(|c| c.set(Some(point)));
            return Err(io::Error::other(format!("injected fault at {point}")));
        }
        Ok(())
    }

    #[cfg(not(feature = "faults"))]
    #[inline]
    #[allow(clippy::unnecessary_wraps)]
    pub(crate) fn hit(_point: &'static str) -> io::Result<()> {
        Ok(())
    }
}

/// A file being written in a staging place before it takes its real name:
/// the client's downloads. Dropping it unfinished removes the staging file.
#[derive(Debug)]
pub struct Staged {
    file: Option<File>,
    path: PathBuf,
    done: bool,
}

impl Staged {
    /// Creates a fresh staging file in `dir`, which must be on the same
    /// filesystem as wherever the file will be committed.
    pub fn create_in(dir: impl AsRef<Path>, prefix: &str) -> Result<Self> {
        let nonce = crate::rand::random_hex(12)?;
        let path = dir.as_ref().join(format!("{prefix}{nonce}.tmp"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&path)?;
        Ok(Self { file: Some(file), path, done: false })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn file(&mut self) -> io::Result<&mut File> {
        self.file.as_mut().ok_or_else(|| io::Error::other("staged file already finished"))
    }

    /// Sets the modification time and permission bits, then fsyncs.
    pub fn finish(&mut self, modified: Option<std::time::SystemTime>, mode: u32) -> Result<()> {
        let file = self.file()?;
        if let Some(t) = modified {
            file.set_modified(t)?;
        }
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        faults::hit("staged.sync")?;
        file.sync_all()?;
        Ok(())
    }

    /// Gives the staged file `target`, which must not exist.
    pub fn commit_new(mut self, target: impl AsRef<Path>) -> Result<()> {
        let target = target.as_ref();
        let (dir, _) = split_path(target).ok_or_else(|| Error::new("invalid target path"))?;
        self.file = None;
        faults::hit("staged.link")?;
        fs::hard_link(&self.path, target)?;
        sync_directory(&dir)?;
        self.done = true;
        let _ = fs::remove_file(&self.path);
        Ok(())
    }

    /// Replaces `target` with the staged file. The caller has already
    /// preserved what `target` held (the client links it into its trash).
    pub fn commit_replace(mut self, target: impl AsRef<Path>) -> Result<()> {
        let target = target.as_ref();
        let (dir, _) = split_path(target).ok_or_else(|| Error::new("invalid target path"))?;
        if let Ok(m) = fs::symlink_metadata(target)
            && !m.file_type().is_file()
        {
            return Err(Error::new("target path is not a regular file"));
        }
        self.file = None;
        faults::hit("staged.rename")?;
        fs::rename(&self.path, target)?;
        self.done = true;
        sync_directory(&dir)
    }
}

impl Write for Staged {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file()?.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file()?.flush()
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            self.file = None;
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Gives the existing file `from` a second name `to` (which must not
/// exist), durably. Both names then refer to the same data.
pub fn link_new_durable(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let to = to.as_ref();
    let (dir, _) = split_path(to).ok_or_else(|| Error::new("invalid target path"))?;
    faults::hit("link.link")?;
    fs::hard_link(from.as_ref(), to)?;
    sync_directory(&dir)
}

/// Removes an empty directory, durably. A directory that is not empty is
/// left alone and reported as `Ok(false)`.
pub fn remove_empty_dir(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();
    match fs::remove_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::DirectoryNotEmpty => return Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(true),
        Err(e) => return Err(e.into()),
    }
    let (dir, _) = split_path(path).ok_or_else(|| Error::new("invalid path"))?;
    sync_directory(&dir)?;
    Ok(true)
}

/// Removes a regular file and syncs its directory; a missing file is fine.
pub fn remove_file_durable(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    match fs::symlink_metadata(path) {
        Ok(m) if !m.file_type().is_file() => return Err(Error::new("target path is unsafe")),
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    fs::remove_file(path)?;
    let (dir, _) = split_path(path).ok_or_else(|| Error::new("target has no parent"))?;
    sync_directory(&dir)
}

/// Rewrites an existing regular file in place, keeping its inode -- for
/// request files another process watches by inode.
pub fn write_fixed_inode(path: impl AsRef<Path>, data: &[u8], maximum: usize) -> Result<()> {
    let path = path.as_ref();
    if data.len() > maximum {
        return Err(Error::new("request exceeds its size limit"));
    }
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file() {
        return Err(Error::new("request file is unsafe"));
    }
    let mut file = OpenOptions::new().write(true).custom_flags(O_NOFOLLOW).open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() || !opened.file_type().is_file()
    {
        return Err(Error::new("request file changed while opening"));
    }
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink() || after.dev() != before.dev() || after.ino() != before.ino()
    {
        return Err(Error::new("request file changed during write"));
    }
    Ok(())
}

/// `mkdir -p` with `mode` for each directory created (subject to the umask).
pub fn mkdir_all(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    let path = path.as_ref();
    match fs::DirBuilder::new().recursive(true).mode(mode).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    match fs::metadata(path) {
        Ok(m) if m.is_dir() => Ok(()),
        _ => Err(Error::from(io::Error::from_raw_os_error(hd_sys::posix::EEXIST))),
    }
}

/// Reads exactly `len` bytes at `offset` of an open file, refusing a `len`
/// above `maximum`. For a slice of a large file.
pub fn read_at_bounded(
    file: &mut File,
    offset: u64,
    len: usize,
    maximum: usize,
) -> Result<Vec<u8>> {
    if len > maximum {
        return Err(Error::new("read exceeds its size limit"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| Error::new("out of memory"))?;
    out.resize(len, 0);
    file.read_exact(&mut out)?;
    Ok(out)
}

/// Opens a file for reading without following a final symlink.
pub fn open_nofollow(path: impl AsRef<Path>) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(O_NOFOLLOW).open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ms-fsio-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_are_bounded_and_refuse_links() {
        let dir = scratch("bounded");
        let p = dir.join("a.txt");
        let link = dir.join("link.txt");
        atomic_replace(&p, b"hello", 16).unwrap();
        assert_eq!(read_bounded(&p, 16).unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(read_bounded(&p, 4).unwrap_err().message(), "file exceeds its size limit");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert_eq!(
            read_bounded(&link, 16).unwrap_err().message(),
            "path is not a safe regular file"
        );
        assert_eq!(read_bounded(dir.join("missing"), 16).unwrap(), None);
        assert_eq!(atomic_replace(&link, b"x", 16).unwrap_err().message(), "target path is unsafe");
        assert!(atomic_replace(&p, b"toolong", 4).is_err());
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        remove_file_durable(&p).unwrap();
        remove_file_durable(&p).unwrap();
        assert!(remove_file_durable(&link).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn text_reads_require_utf8() {
        let dir = scratch("utf8");
        let p = dir.join("bad.txt");
        atomic_replace(&p, b"\xff", 16).unwrap();
        assert_eq!(read_text(&p, 16).unwrap_err().message(), "file is not valid UTF-8");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fixed_inode_writes_keep_the_inode() {
        let dir = scratch("inode");
        let p = dir.join("request");
        assert!(write_fixed_inode(&p, b"x", 16).is_err());
        fs::write(&p, b"previous contents").unwrap();
        let before = fs::metadata(&p).unwrap().ino();
        write_fixed_inode(&p, b"new", 16).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().ino(), before);
        assert_eq!(read_bounded(&p, 64).unwrap().as_deref(), Some(&b"new"[..]));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn slices_are_read_exactly_and_bounded() {
        let dir = scratch("slice");
        let p = dir.join("f");
        fs::write(&p, b"0123456789").unwrap();
        let mut f = File::open(&p).unwrap();
        assert_eq!(read_at_bounded(&mut f, 3, 4, 16).unwrap(), b"3456");
        assert!(read_at_bounded(&mut f, 8, 4, 16).is_err());
        assert!(read_at_bounded(&mut f, 0, 32, 16).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn new_files_are_never_replaced() {
        let dir = scratch("new");
        let staging = dir.join("staging");
        mkdir_durable(&staging, 0o700).unwrap();
        let p = dir.join("a/b/object");
        mkdir_durable(p.parent().unwrap(), 0o700).unwrap();
        assert_eq!(write_new_durable(&p, &staging, &[b"he", b"llo"], 0o400).unwrap(), Created::New);
        assert_eq!(write_new_durable(&p, &staging, &[b"other"], 0o400).unwrap(), Created::Existed);
        assert_eq!(read_bounded(&p, 16).unwrap().as_deref(), Some(&b"hello"[..]));
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o400);
        // The staging directory is left empty either way.
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
        fs::write(staging.join("abandoned.tmp"), b"x").unwrap();
        fs::create_dir(staging.join("keep")).unwrap();
        assert_eq!(clear_staging(&staging).unwrap(), 1);
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn moves_refuse_to_replace() {
        let dir = scratch("move");
        fs::write(dir.join("a"), b"1").unwrap();
        fs::write(dir.join("b"), b"2").unwrap();
        assert!(move_new_durable(dir.join("a"), dir.join("b")).is_err());
        assert_eq!(fs::read(dir.join("b")).unwrap(), b"2");
        move_new_durable(dir.join("a"), dir.join("c")).unwrap();
        assert!(!dir.join("a").exists());
        assert_eq!(fs::read(dir.join("c")).unwrap(), b"1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn durable_mkdir_creates_chains_and_refuses_files() {
        let dir = scratch("mkdir-durable");
        mkdir_durable(dir.join("x/y/z"), 0o700).unwrap();
        mkdir_durable(dir.join("x/y/z"), 0o700).unwrap();
        assert!(dir.join("x/y/z").is_dir());
        fs::write(dir.join("f"), b"").unwrap();
        assert!(mkdir_durable(dir.join("f"), 0o700).is_err());
        assert!(mkdir_durable(dir.join("f/g"), 0o700).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn mkdir_all_creates_and_refuses_files() {
        let dir = scratch("mkdir");
        mkdir_all(dir.join("a/b/c"), 0o700).unwrap();
        mkdir_all(dir.join("a/b/c"), 0o700).unwrap();
        fs::write(dir.join("f"), b"").unwrap();
        assert_eq!(
            mkdir_all(dir.join("f"), 0o700).unwrap_err().message(),
            "File exists (os error 17)"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
