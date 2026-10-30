//! The client's own trash, inside each synced folder at
//! `.homedrive/trash/<unix seconds>-<random>/<path>`.
//!
//! When the sync engine deletes a local file (because it was deleted on
//! the server), or replaces one (with a newer version from the server), it
//! first moves the file here, and puts it back if it turns out to have
//! changed. A write that lands on the old file through a handle opened
//! earlier ends up here too, not lost. Items expire after a number of
//! days.
//!
//! Together with the state compaction helper at the bottom, this file is
//! the only place in the client allowed to delete files
//! (`scripts/check-rust.sh` enforces it).

use std::fs;
use std::path::{Path, PathBuf};

use hd_common::{Result, fsio, timefmt};

pub const TRASH_DIR: &str = ".homedrive/trash";

/// Where copies found damaged on this computer's disk are kept. They are
/// local only, and never expire: if one was in fact a change made in a way
/// the engine could not see, it is still here.
pub const DAMAGED_DIR: &str = ".homedrive/damaged";

/// Where the engine keeps a changed copy it moved aside and could not put
/// back (something new took its name meanwhile), and a replaced or deleted
/// file whose extended attributes may hold data of their own (Linux
/// `user.*` attributes, Windows alternate data streams), which are not
/// synced and so exist nowhere else. Like [`DAMAGED_DIR`] it never expires.
pub const KEPT_DIR: &str = ".homedrive/kept";

#[derive(Debug)]
pub struct Trash {
    /// This sync round's folder in the trash, made on first use.
    dir: PathBuf,
    made: bool,
    /// Whether what is put here expires (only the trash itself does).
    expires: bool,
}

impl Trash {
    pub fn new(root: &Path) -> Result<Self> {
        Self::in_dir(root, TRASH_DIR)
    }

    /// A trash under `sub` of the folder instead (see [`DAMAGED_DIR`]).
    pub fn in_dir(root: &Path, sub: &str) -> Result<Self> {
        let name = format!("{}-{}", timefmt::unix_seconds(), hd_common::rand::random_hex(4)?);
        Ok(Self { dir: root.join(sub).join(name), made: false, expires: sub == TRASH_DIR })
    }

    /// Whether what is put here is deleted after a while.
    pub fn expires(&self) -> bool {
        self.expires
    }

    fn place(&mut self, rel: &str) -> Result<PathBuf> {
        if !self.made {
            fsio::mkdir_durable(&self.dir, 0o700)?;
            self.made = true;
        }
        let to = self.dir.join(rel);
        if let Some(parent) = to.parent() {
            fsio::mkdir_durable(parent, 0o700)?;
        }
        Ok(to)
    }

    /// Moves a local file into the trash.
    pub fn take(&mut self, abs: &Path, rel: &str) -> Result<PathBuf> {
        let to = self.place(rel)?;
        fsio::move_new_durable(abs, &to)?;
        Ok(to)
    }
}

/// Deletes trash rounds older than `days`. Returns how many went.
pub fn expire(root: &Path, days: u64) -> Result<usize> {
    let dir = root.join(TRASH_DIR);
    let cutoff = timefmt::unix_seconds()
        .saturating_sub(i64::try_from(days.saturating_mul(86_400)).unwrap_or(i64::MAX));
    let mut removed = 0;
    let Ok(entries) = fs::read_dir(&dir) else { return Ok(0) };
    for e in entries {
        let e = e?;
        let stamp = e
            .file_name()
            .to_str()
            .and_then(|n| n.split('-').next())
            .and_then(|s| s.parse::<i64>().ok());
        if stamp.is_some_and(|s| s < cutoff) && e.file_type()?.is_dir() {
            fs::remove_dir_all(e.path())?;
            removed += 1;
        }
    }
    if removed > 0 {
        fsio::sync_directory(&dir)?;
    }
    Ok(removed)
}

/// Removes a metadata file from an administrator's store copy that the
/// store itself no longer keeps (an old snapshot or journal). Never used on
/// synced content, and never on a copy's objects.
pub(crate) fn remove_copy_meta_file(path: &Path) -> Result<()> {
    fsio::remove_file_durable(path)
}

/// Removes the scratch directory an earlier generation of a store copy
/// was opened from: a copy of metadata the copy's history still holds.
/// Never used on synced content, and never on a copy's own files.
pub(crate) fn remove_generation_scratch(path: &Path) -> Result<()> {
    fs::remove_dir_all(path)?;
    Ok(())
}

/// Removes one of the client's own state files (an old log generation
/// after compaction). Never used on synced content.
pub(crate) fn remove_state_file(path: &Path) -> Result<()> {
    fsio::remove_file_durable(path)
}
