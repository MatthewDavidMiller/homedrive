//! Restoring to plain files on this computer, and checking plain files
//! against a manifest.
//!
//! `homedrive restore` downloads a folder of the drive into a new
//! directory, outside any synced folder: ordinary files, nothing of
//! homedrive's around them. Each is verified against the server's SHA-256
//! before it takes its name, and a manifest in `sha256sum` format is
//! written beside the directory.
//!
//! `homedrive check-files` reads such a manifest (from a restore here, or
//! from the server's restore drill, copied over) and checks every file in a
//! directory against it. That is the last link in proving a backup: the
//! files restored from it, wherever they end up, are the files that were
//! stored.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use hd_api::ChangeInfo;
use hd_common::{Error, Result, fsio, pathname};
use hd_crypto::Sha256;

use crate::remote::Remote;

const STAGING_PREFIX: &str = ".homedrive-restore-";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Restored {
    pub files: usize,
    pub bytes: u64,
}

/// A writer that hashes what passes through.
struct Hashing<'w, W: Write> {
    out: &'w mut W,
    hash: Sha256,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Downloads the current files under `path` ("" for the whole drive) into
/// `to`, which must not exist or be empty, and writes their manifest to
/// `manifest`.
pub fn restore(remote: &mut Remote, path: &str, to: &Path, manifest: &Path) -> Result<Restored> {
    pathname::validate(path)?;
    if std::fs::read_dir(to).is_ok_and(|mut d| d.next().is_some()) {
        return Err(Error::new(format!(
            "{} is not empty; a restore never overwrites",
            to.display()
        )));
    }
    // The whole listing, from the change feed's start.
    let mut files: BTreeMap<String, hd_api::VersionInfo> = BTreeMap::new();
    let mut dirs = Vec::new();
    let mut cursor = 0;
    loop {
        let page = remote.changes(cursor, 0)?;
        for c in page.changes {
            match c {
                ChangeInfo::File { path, version, .. } => {
                    files.insert(path, version);
                }
                ChangeInfo::Dir { path, .. } => dirs.push(path),
                ChangeInfo::Deleted { path, .. } => {
                    files.remove(&path);
                }
            }
        }
        cursor = page.cursor;
        if !page.more {
            break;
        }
    }
    let rel = |p: &str| pathname::rebase(p, path, "");
    fsio::mkdir_all(to, 0o700)?;
    for d in dirs.iter().filter_map(|d| rel(d)).filter(|r| !r.is_empty()) {
        fsio::mkdir_all(to.join(d), 0o700)?;
    }
    let mut report = Restored::default();
    let mut lines = Vec::new();
    for (p, v) in &files {
        let Some(r) = rel(p) else { continue };
        let r = if r.is_empty() { pathname::name(p).to_owned() } else { r };
        let target = to.join(&r);
        let parent = target.parent().ok_or_else(|| Error::new("no parent folder"))?;
        fsio::mkdir_all(parent, 0o700)?;
        let mut staged = fsio::Staged::create_in(parent, STAGING_PREFIX)?;
        let mut hashing = Hashing {
            out: &mut staged,
            hash: Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?,
        };
        if !remote.download(p, v.id, &mut hashing)? {
            return Err(Error::new(format!(
                "{p} changed on the server while restoring; try again"
            )));
        }
        let len = hashing.hash.len();
        let got = hashing.hash.finish().map_err(|_| Error::new("SHA-256 failed"))?;
        if got != v.sha256 || len != v.size {
            return Err(Error::new(format!("{p} did not match its SHA-256; not restored")));
        }
        let modified = u64::try_from(v.mtime_ms)
            .ok()
            .map(|ms| std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms));
        staged.finish(modified, if v.executable { 0o700 } else { 0o600 })?;
        staged.commit_new(&target)?;
        report.files += 1;
        report.bytes += v.size;
        lines.push((v.sha256, r));
    }
    let mut text = String::new();
    for (sha, p) in &lines {
        text.push_str(&hd_store::restore::manifest_line(sha, p));
    }
    fsio::atomic_replace(manifest, text.as_bytes(), usize::MAX)?;
    Ok(report)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Checked {
    pub matched: usize,
    pub missing: Vec<String>,
    pub different: Vec<String>,
}

impl Checked {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.different.is_empty()
    }
}

/// Checks every file a manifest lists, under `dir`.
pub fn check_files(dir: &Path, manifest: &str) -> Result<Checked> {
    let mut out = Checked::default();
    for (sha, p) in hd_store::restore::parse_manifest(manifest)? {
        pathname::validate(&p).map_err(|_| Error::new(format!("{p}: not a valid path")))?;
        let file = dir.join(&p);
        match crate::engine::hash_file(&file) {
            Ok((got, _)) if got == sha => out.matched += 1,
            Err(_) if !file.exists() => out.missing.push(p),
            // Different content, or unreadable: either way not the file.
            _ => out.different.push(p),
        }
    }
    Ok(out)
}
