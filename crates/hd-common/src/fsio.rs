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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
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
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&staged, path)?;
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
        for part in parts {
            file.write_all(part)?;
        }
        file.sync_all()?;
        match fs::hard_link(&staged, path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => return Ok(Created::Existed),
            Err(e) => return Err(e.into()),
        }
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
    fs::hard_link(from, to)?;
    sync_directory(&to_dir)?;
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
