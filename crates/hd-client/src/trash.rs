//! The client's own trash, inside each synced folder at
//! `.homedrive/trash/<unix seconds>-<random>/<path>`.
//!
//! When the sync engine deletes a local file (because it was deleted on
//! the server) it moves the file here. When it replaces one (with a newer
//! version from the server) it hard-links the old one here first, which
//! costs no space and also keeps any write that lands on the old file a
//! moment after the check. Items expire after a number of days.
//!
//! Together with the state compaction helper at the bottom, this file is
//! the only place in the client allowed to delete files
//! (`scripts/check-rust.sh` enforces it).

use std::fs;
use std::path::{Path, PathBuf};

use hd_common::{Result, fsio, timefmt};

pub const TRASH_DIR: &str = ".homedrive/trash";

#[derive(Debug)]
pub struct Trash {
    /// This sync round's folder in the trash, made on first use.
    dir: PathBuf,
    made: bool,
}

impl Trash {
    pub fn new(root: &Path) -> Result<Self> {
        let name = format!("{}-{}", timefmt::unix_seconds(), hd_common::rand::random_hex(4)?);
        Ok(Self { dir: root.join(TRASH_DIR).join(name), made: false })
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

    /// Keeps the current content of a file that is about to be replaced.
    pub fn keep(&mut self, abs: &Path, rel: &str) -> Result<PathBuf> {
        let to = self.place(rel)?;
        fsio::link_new_durable(abs, &to)?;
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

/// Removes one of the client's own state files (an old log generation
/// after compaction). Never used on synced content.
pub(crate) fn remove_state_file(path: &Path) -> Result<()> {
    fsio::remove_file_durable(path)
}
