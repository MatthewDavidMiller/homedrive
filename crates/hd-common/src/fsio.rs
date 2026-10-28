//! File access for paths an operator or another process may control.
//!
//! Reads refuse symlinks and non-regular files, open with `O_NOFOLLOW`, and
//! confirm the opened file is the one that was checked (same device and
//! inode) before reading at most a stated number of bytes. Replacements
//! stage into a fresh mode-0600 file beside the target, fsync it, rename it
//! over, and fsync the directory, so a crash leaves either the old document
//! or the new one.

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

fn sync_directory(dir: &Path) -> Result<()> {
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
