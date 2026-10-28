//! Walking a synced folder.
//!
//! Symbolic links are never followed. Special files (sockets, devices),
//! names that are not valid drive paths, and anything matching an ignore
//! pattern are skipped. Each skipped item except the ignored ones is
//! reported, so nothing is silently left out of sync. The folder's own
//! `.homedrive` directory and the engine's staging files are always
//! skipped.
//!
//! **What the scan cannot see clearly, it protects.** A missing entry means
//! "deleted here", and a deletion travels to the server and every other
//! machine. So anything the scan could not look at properly is listed in
//! [`Scan::protected`], and the engine leaves those paths, and everything
//! beneath them, alone:
//! - a file or folder whose `stat` failed for any reason but "not found"
//!   (permission denied, an I/O error);
//! - a folder that could not be listed;
//! - a folder on another filesystem (a disk mounted inside the synced
//!   folder: unmounted, it would look empty);
//! - a symbolic link or special file where a synced file may have been;
//! - a folder holding its own `.homedrive-root`: another synced folder,
//!   whose files are that folder's business (two folders syncing the same
//!   files from two places would turn each one's housekeeping into the
//!   other's deletions).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use hd_common::{Result, pathname};

use crate::state::Kind;

pub const SENTINEL: &str = ".homedrive-root";
pub const STAGING_PREFIX: &str = ".homedrive-tmp-";

/// A local file or folder as `stat` sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalEntry {
    pub kind: Kind,
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub dev: u64,
    /// The owner may execute it (always false where there is no such
    /// permission: Windows).
    pub exec: bool,
}

impl LocalEntry {
    pub fn of(meta: &fs::Metadata) -> Option<Self> {
        let kind = if meta.file_type().is_file() {
            Kind::File
        } else if meta.file_type().is_dir() {
            Kind::Dir
        } else {
            return None;
        };
        #[cfg(unix)]
        let (mtime_ns, ino, dev) = {
            use std::os::unix::fs::MetadataExt;
            (
                meta.mtime().saturating_mul(1_000_000_000).saturating_add(meta.mtime_nsec()),
                meta.ino(),
                meta.dev(),
            )
        };
        // Windows has no stable inode through std; size and time identify a
        // file, and anything that differs is settled by hashing it.
        #[cfg(not(unix))]
        let (mtime_ns, ino, dev) = {
            let t = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_nanos()).ok())
                .unwrap_or(0);
            (t, 0, 0)
        };
        #[cfg(unix)]
        let exec = {
            use std::os::unix::fs::PermissionsExt;
            kind == Kind::File && meta.permissions().mode() & 0o100 != 0
        };
        #[cfg(not(unix))]
        let exec = false;
        Some(Self {
            kind,
            size: if kind == Kind::File { meta.len() } else { 0 },
            mtime_ns,
            ino,
            dev,
            exec,
        })
    }
}

#[derive(Debug, Default)]
pub struct Scan {
    pub entries: BTreeMap<String, LocalEntry>,
    /// (path, why) for everything skipped that was not ignored on purpose.
    pub skipped: Vec<(String, String)>,
    /// Paths the scan could not see clearly; they and everything beneath
    /// them must be left alone this round.
    pub protected: Vec<String>,
}

impl Scan {
    fn protect(&mut self, rel: String, why: String) {
        self.skipped.push((rel.clone(), why));
        self.protected.push(rel);
    }

    /// Whether `rel` is, or is inside, a protected path.
    pub fn is_protected(&self, rel: &str) -> bool {
        self.protected.iter().any(|p| pathname::is_within(rel, p))
    }
}

/// Simple ignore patterns: `name` matches that name at any depth, `*.ext`
/// and `prefix*` match names, and a trailing `/` matches only folders.
pub fn ignored(rel: &str, is_dir: bool, patterns: &[String]) -> bool {
    let name = pathname::name(rel);
    if pathname::is_within(rel, ".homedrive")
        || name == SENTINEL
        || name.starts_with(STAGING_PREFIX)
    {
        return true;
    }
    patterns.iter().any(|p| {
        let (p, dir_only) = match p.strip_suffix('/') {
            Some(p) => (p, true),
            None => (p.as_str(), false),
        };
        if dir_only && !is_dir {
            return false;
        }
        if let Some(suffix) = p.strip_prefix('*') {
            name.ends_with(suffix)
        } else if let Some(prefix) = p.strip_suffix('*') {
            name.starts_with(prefix)
        } else {
            name == p || rel == p
        }
    })
}

pub fn scan(root: &Path, patterns: &[String]) -> Result<Scan> {
    let mut out = Scan::default();
    // The root itself must be listable: otherwise there is no scan at all.
    let root_dev = LocalEntry::of(&fs::symlink_metadata(root)?).map_or(0, |e| e.dev);
    let names = list(root)?;
    walk(root, "", names, patterns, &mut out, 0, root_dev);
    Ok(out)
}

fn list(dir: &Path) -> Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for e in fs::read_dir(dir)? {
        names.push(e?.file_name());
    }
    Ok(names)
}

fn walk(
    dir: &Path,
    rel: &str,
    mut names: Vec<std::ffi::OsString>,
    patterns: &[String],
    out: &mut Scan,
    depth: usize,
    root_dev: u64,
) {
    names.sort();
    for os_name in names {
        let Some(name) = os_name.to_str() else {
            out.skipped.push((
                format!("{rel}/{}", os_name.to_string_lossy()),
                "the name is not UTF-8".into(),
            ));
            continue;
        };
        let child_rel = pathname::join(rel, name);
        let abs = dir.join(name);
        let meta = match fs::symlink_metadata(&abs) {
            Ok(m) => m,
            // Gone between listing and stat: the next scan sees the truth.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                out.protect(child_rel, format!("cannot be read ({e}); left alone"));
                continue;
            }
        };
        let is_dir = meta.file_type().is_dir();
        if ignored(&child_rel, is_dir, patterns) {
            continue;
        }
        if meta.file_type().is_symlink() {
            out.protect(child_rel, "symbolic links are not synced".into());
            continue;
        }
        if let Err(e) = pathname::validate(&child_rel) {
            out.skipped.push((child_rel, e.message().to_owned()));
            continue;
        }
        let Some(entry) = LocalEntry::of(&meta) else {
            out.protect(child_rel, "not a regular file or folder".into());
            continue;
        };
        if is_dir && root_dev != 0 && entry.dev != root_dev {
            out.protect(
                child_rel,
                "on another filesystem (a mounted disk); sync it as a folder of its own".into(),
            );
            continue;
        }
        if is_dir {
            if fs::symlink_metadata(abs.join(SENTINEL)).is_ok() {
                out.protect(
                    child_rel,
                    "another synced folder is inside this one; it is synced on its own".into(),
                );
                continue;
            }
            if depth + 1 >= pathname::MAX_DEPTH {
                out.protect(child_rel, "too deep".into());
                continue;
            }
            let names = match list(&abs) {
                Ok(n) => n,
                Err(e) => {
                    out.protect(child_rel, format!("cannot be listed ({e}); left alone"));
                    continue;
                }
            };
            out.entries.insert(child_rel.clone(), entry);
            walk(&abs, &child_rel, names, patterns, out, depth + 1, root_dev);
        } else {
            out.entries.insert(child_rel, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_patterns() {
        let pats = vec![
            "*.tmp".to_owned(),
            "node_modules/".to_owned(),
            "~$*".to_owned(),
            "build/out".to_owned(),
        ];
        assert!(ignored("a/x.tmp", false, &pats));
        assert!(ignored("a/node_modules", true, &pats));
        assert!(!ignored("a/node_modules", false, &pats));
        assert!(ignored("~$doc.docx", false, &pats));
        assert!(ignored("build/out", true, &pats));
        assert!(ignored(".homedrive", true, &[]));
        assert!(ignored(".homedrive/trash/1-ab/f.txt", false, &[]));
        assert!(!ignored(".homedrive-other", false, &[]));
        assert!(ignored("x/.homedrive-tmp-abc.tmp", false, &[]));
        assert!(!ignored("x/.homedrive", true, &[]));
        assert!(!ignored("readme.md", false, &pats));
    }
}
