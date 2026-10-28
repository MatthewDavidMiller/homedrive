//! Walking a synced folder.
//!
//! Symbolic links are never followed. Special files (sockets, devices),
//! names that are not valid drive paths, and anything matching an ignore
//! pattern are skipped. Each skipped item except the ignored ones is
//! reported, so nothing is silently left out of sync. The folder's own
//! `.homedrive` directory and the engine's staging files are always
//! skipped.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
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
        Some(Self {
            kind,
            size: if kind == Kind::File { meta.len() } else { 0 },
            mtime_ns: meta.mtime().saturating_mul(1_000_000_000).saturating_add(meta.mtime_nsec()),
            ino: meta.ino(),
            dev: meta.dev(),
        })
    }
}

#[derive(Debug, Default)]
pub struct Scan {
    pub entries: BTreeMap<String, LocalEntry>,
    /// (path, why) for everything skipped that was not ignored on purpose.
    pub skipped: Vec<(String, String)>,
}

/// Simple ignore patterns: `name` matches that name at any depth, `*.ext`
/// and `prefix*` match names, and a trailing `/` matches only folders.
pub fn ignored(rel: &str, is_dir: bool, patterns: &[String]) -> bool {
    let name = pathname::name(rel);
    if rel == ".homedrive" || name == SENTINEL || name.starts_with(STAGING_PREFIX) {
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
    walk(root, "", patterns, &mut out, 0)?;
    Ok(out)
}

fn walk(dir: &Path, rel: &str, patterns: &[String], out: &mut Scan, depth: usize) -> Result<()> {
    let mut names = Vec::new();
    for e in fs::read_dir(dir)? {
        names.push(e?.file_name());
    }
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
        // Gone between listing and stat: the next scan sees the truth.
        let Ok(meta) = fs::symlink_metadata(&abs) else { continue };
        let is_dir = meta.file_type().is_dir();
        if ignored(&child_rel, is_dir, patterns) {
            continue;
        }
        if meta.file_type().is_symlink() {
            out.skipped.push((child_rel, "symbolic links are not synced".into()));
            continue;
        }
        if let Err(e) = pathname::validate(&child_rel) {
            out.skipped.push((child_rel, e.message().to_owned()));
            continue;
        }
        let Some(entry) = LocalEntry::of(&meta) else {
            out.skipped.push((child_rel, "not a regular file or folder".into()));
            continue;
        };
        out.entries.insert(child_rel.clone(), entry);
        if is_dir {
            if depth + 1 >= pathname::MAX_DEPTH {
                out.skipped.push((child_rel, "too deep".into()));
                continue;
            }
            walk(&abs, &child_rel, patterns, out, depth + 1)?;
        }
    }
    Ok(())
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
        assert!(ignored("x/.homedrive-tmp-abc.tmp", false, &[]));
        assert!(!ignored("x/.homedrive", true, &[]));
        assert!(!ignored("readme.md", false, &pats));
    }
}
