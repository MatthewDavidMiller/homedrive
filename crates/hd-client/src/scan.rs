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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

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
    /// When the file last changed (Unix `ctime`, Windows `ChangeTime`). Every
    /// write moves it, and no program can set it back the way it can the
    /// modification time, so an edit that keeps the size and puts the
    /// time back still shows.
    pub ctime_ns: i64,
    pub ino: u64,
    pub dev: u64,
    /// The owner may execute it (always false where there is no such
    /// permission: Windows).
    pub exec: bool,
}

/// What a look at one path found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Look {
    pub is_dir: bool,
    pub is_symlink: bool,
    /// `None` for what cannot be synced: a link, a socket, a device.
    pub entry: Option<LocalEntry>,
}

impl LocalEntry {
    /// Looks at `path` itself, never what a link points to. On Windows this
    /// is one open, where std and the stamp would be two, and a scan does it
    /// for every file. A reparse point takes the long way, because std knows
    /// which of them are links.
    pub fn look(path: &Path) -> std::io::Result<Look> {
        #[cfg(windows)]
        if let Ok(f) = hd_sys::windows::file_facts(path)
            && !f.reparse_point
        {
            let kind = if f.directory { Kind::Dir } else { Kind::File };
            return Ok(Look {
                is_dir: f.directory,
                is_symlink: false,
                entry: Some(Self {
                    kind,
                    size: if kind == Kind::File { f.size } else { 0 },
                    mtime_ns: f.write_ticks.checked_mul(100).unwrap_or(0),
                    ctime_ns: f.stamp.change_ns,
                    ino: f.stamp.index,
                    dev: f.stamp.volume,
                    exec: false,
                }),
            });
        }
        let meta = fs::symlink_metadata(path)?;
        Ok(Look {
            is_dir: meta.file_type().is_dir(),
            is_symlink: meta.file_type().is_symlink(),
            entry: Self::of(&meta, path),
        })
    }

    /// `path` is where `meta` was read from.
    pub fn of(meta: &fs::Metadata, path: &Path) -> Option<Self> {
        let kind = if meta.file_type().is_file() {
            Kind::File
        } else if meta.file_type().is_dir() {
            Kind::Dir
        } else {
            return None;
        };
        #[cfg(unix)]
        let (mtime_ns, ctime_ns, ino, dev) = {
            use std::os::unix::fs::MetadataExt;
            let _ = path;
            (
                meta.mtime().saturating_mul(1_000_000_000).saturating_add(meta.mtime_nsec()),
                meta.ctime().saturating_mul(1_000_000_000).saturating_add(meta.ctime_nsec()),
                meta.ino(),
                meta.dev(),
            )
        };
        // std has no change time or file number on Windows. If they cannot
        // be read, the stamp differs from the one recorded and hashing the
        // file settles it.
        #[cfg(not(unix))]
        let (mtime_ns, ctime_ns, ino, dev) = {
            let t = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| i64::try_from(d.as_nanos()).ok())
                .unwrap_or(0);
            let stamp = hd_sys::windows::file_stamp(path).unwrap_or_default();
            (t, stamp.change_ns, stamp.index, stamp.volume)
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
            ctime_ns,
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
    /// Download staging files found, which a crash or power cut leaves.
    pub staging: Vec<std::path::PathBuf>,
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

    /// Whether everything scanned is already named as the server names it,
    /// which leaves [`Scan::adopt_spellings`] nothing to do: a path the server
    /// has, and so each folder above it, is either the one spelling the
    /// server has or one of several, and it is left as it is either way. Far
    /// cheaper to ask, and true of every round that brought no new name.
    pub fn named_as_on<V>(&self, remote: &BTreeMap<String, V>) -> bool {
        self.entries.keys().chain(&self.protected).all(|rel| remote.contains_key(rel))
    }

    /// For a case-insensitive filesystem: names what was scanned the way
    /// the server does (or, for what the server no longer has, the way it
    /// was last synced), when they differ only in letter case. That is one
    /// file, and a rename that only changes case must not look like a
    /// delete and a new file. The local name is left as it is. Where the
    /// server has several spellings, or a case-sensitive folder here does,
    /// nothing is adopted and the engine reports the collision.
    pub fn adopt_spellings<'a>(
        &mut self,
        remote: impl Iterator<Item = &'a String>,
        synced: impl Iterator<Item = &'a String>,
    ) {
        let (remote, synced) = (spellings(remote), spellings(synced));
        let crowded: BTreeSet<String> = spellings(self.entries.keys())
            .into_iter()
            .filter(|(_, s)| s.len() > 1)
            .map(|(key, _)| key)
            .collect();
        let canonical = |rel: &str| {
            let mut out = String::new();
            for step in rel.split('/') {
                let here = pathname::join(&out, step);
                let key = pathname::fold_key(&here);
                let known = remote.get(&key).or_else(|| synced.get(&key));
                out = match known.filter(|k| k.len() == 1 && !crowded.contains(&key)) {
                    Some(k) => k.first().map_or(here, |s| (*s).to_owned()),
                    None => here,
                };
            }
            out
        };
        let entries = std::mem::take(&mut self.entries);
        self.entries = entries.into_iter().map(|(rel, e)| (canonical(&rel), e)).collect();
        for p in &mut self.protected {
            *p = canonical(p);
        }
    }
}

/// Paths grouped by the key they collide under.
fn spellings<'a>(paths: impl Iterator<Item = &'a String>) -> BTreeMap<String, BTreeSet<&'a str>> {
    let mut out: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    // Paths come in order, so most share their folders with the one before.
    let mut last_folder = None;
    for rel in paths {
        let folder = rel.rsplit_once('/').map(|(folder, _)| folder);
        if folder != last_folder {
            for p in pathname::ancestors(rel) {
                out.entry(pathname::fold_key(p)).or_default().insert(p);
            }
            last_folder = folder;
        }
        out.entry(pathname::fold_key(rel)).or_default().insert(rel);
    }
    out
}

/// Which of `paths` a case-insensitive filesystem cannot keep apart: those
/// where the path itself or a folder above it shares its key with another
/// spelling among `live`, what exists here or on the server. Folders count,
/// or `Docs/a` and `docs/b` would land in one folder.
pub fn case_collisions<'a>(
    paths: impl Iterator<Item = &'a String>,
    live: impl Iterator<Item = &'a String>,
) -> Vec<&'a String> {
    let live = spellings(live);
    paths
        .filter(|rel| {
            pathname::ancestors(rel)
                .into_iter()
                .chain([rel.as_str()])
                .any(|p| live.get(&pathname::fold_key(p)).is_some_and(|s| s.len() > 1))
        })
        .collect()
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

/// Whether `rel`, or any folder above it, is ignored. The scan never enters
/// an ignored folder, so what is inside one must be left alone like the
/// folder itself, even if it was synced before the pattern was added.
pub fn ignored_within(rel: &str, is_dir: bool, patterns: &[String]) -> bool {
    ignored(rel, is_dir, patterns)
        || pathname::ancestors(rel).into_iter().any(|dir| ignored(dir, true, patterns))
}

pub fn scan(root: &Path, patterns: &[String]) -> Result<Scan> {
    let mut out = Scan::default();
    // The root itself must be listable: otherwise there is no scan at all.
    let root_dev = LocalEntry::look(root)?.entry.map_or(0, |e| e.dev);
    let names = list(root)?;
    walk(&mut root.to_path_buf(), "", names, patterns, &mut out, 0, root_dev);
    Ok(out)
}

fn list(dir: &Path) -> Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for e in fs::read_dir(dir)? {
        names.push(e?.file_name());
    }
    Ok(names)
}

/// `dir` is where `rel` is; it is lent to each child in turn, which a scan
/// does for every file, so no path is made for each.
fn walk(
    dir: &mut PathBuf,
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
        if name.starts_with(STAGING_PREFIX) {
            out.staging.push(dir.join(name));
            continue;
        }
        // Such a name can exist (WSL and other tools make them), but Win32
        // rewrites it, so a stat below would find nothing and the file
        // would silently never sync.
        if cfg!(windows)
            && let Some(why) = pathname::windows_problem(name)
        {
            out.protect(child_rel, format!("the name {why}"));
            continue;
        }
        dir.push(name);
        visit(dir, child_rel, patterns, out, depth, root_dev);
        dir.pop();
    }
}

/// Looks at the child of a folder at `abs`, and goes into it if it is a folder.
fn visit(
    abs: &mut PathBuf,
    child_rel: String,
    patterns: &[String],
    out: &mut Scan,
    depth: usize,
    root_dev: u64,
) {
    {
        let look = match LocalEntry::look(abs) {
            Ok(look) => look,
            // Gone between listing and stat: the next scan sees the truth.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                out.protect(child_rel, format!("cannot be read ({e}); left alone"));
                return;
            }
        };
        let is_dir = look.is_dir;
        if ignored(&child_rel, is_dir, patterns) {
            return;
        }
        if look.is_symlink {
            out.protect(child_rel, "symbolic links are not synced".into());
            return;
        }
        if let Err(e) = pathname::validate(&child_rel) {
            out.skipped.push((child_rel, e.message().to_owned()));
            return;
        }
        let Some(entry) = look.entry else {
            out.protect(child_rel, "not a regular file or folder".into());
            return;
        };
        if is_dir && root_dev != 0 && entry.dev != root_dev {
            out.protect(
                child_rel,
                "on another filesystem (a mounted disk); sync it as a folder of its own".into(),
            );
            return;
        }
        if is_dir {
            if fs::symlink_metadata(abs.join(SENTINEL)).is_ok() {
                out.protect(
                    child_rel,
                    "another synced folder is inside this one; it is synced on its own".into(),
                );
                return;
            }
            if depth + 1 >= pathname::MAX_DEPTH {
                out.protect(child_rel, "too deep".into());
                return;
            }
            let names = match list(abs) {
                Ok(n) => n,
                Err(e) => {
                    out.protect(child_rel, format!("cannot be listed ({e}); left alone"));
                    return;
                }
            };
            out.entries.insert(child_rel.clone(), entry);
            walk(abs, &child_rel, names, patterns, out, depth + 1, root_dev);
        } else {
            out.entries.insert(child_rel, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> LocalEntry {
        LocalEntry {
            kind: Kind::File,
            size: 1,
            mtime_ns: 0,
            ctime_ns: 0,
            ino: 0,
            dev: 0,
            exec: false,
        }
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn scanned(list: &[&str]) -> Scan {
        let mut out = Scan::default();
        for rel in list {
            out.entries.insert((*rel).to_owned(), entry());
        }
        out
    }

    fn keys(s: &Scan) -> Vec<&str> {
        s.entries.keys().map(String::as_str).collect()
    }

    #[test]
    fn a_rename_of_letter_case_keeps_the_servers_spelling() {
        let mut s = scanned(&["DOCS", "DOCS/A.TXT", "DOCS/new.txt", "other.txt"]);
        s.protected.push("DOCS/held".into());
        let remote = names(&["docs", "docs/a.txt"]);
        s.adopt_spellings(remote.iter(), std::iter::empty());
        assert_eq!(keys(&s), ["docs", "docs/a.txt", "docs/new.txt", "other.txt"]);
        assert!(s.is_protected("docs/held"), "protection follows the spelling");
    }

    #[test]
    fn a_file_gone_from_the_server_keeps_its_synced_spelling() {
        let mut s = scanned(&["RCASE.txt"]);
        let synced = names(&["rcase.txt"]);
        s.adopt_spellings(std::iter::empty(), synced.iter());
        assert_eq!(keys(&s), ["rcase.txt"]);
    }

    /// [`Scan::named_as_on`] is only a shortcut: wherever it says there is
    /// nothing to adopt, adopting must change nothing.
    #[test]
    fn a_scan_named_as_on_the_server_has_nothing_to_adopt() {
        let cases: [(&[&str], &[&str], &[&str]); 7] = [
            (&["docs", "docs/a.txt"], &["docs", "docs/a.txt", "other"], &[]),
            (&["docs", "docs/a.txt"], &["docs", "docs/a.txt"], &["docs/a.txt"]),
            (&["Name.txt"], &["Name.txt", "name.txt"], &[]),
            (&["Dir/a", "dir/b"], &["Dir/a", "dir/b"], &[]),
            (&["RÉSUMÉ"], &["RÉSUMÉ", "résumé"], &["résumé"]),
            (&["a/b/c"], &["a/b/c", "A/x"], &["A/x"]),
            (&[], &[], &["old.txt"]),
        ];
        for (scanned_paths, remote_paths, synced_paths) in cases {
            let remote: BTreeMap<String, u8> =
                remote_paths.iter().map(|p| ((*p).to_owned(), 0)).collect();
            let mut s = scanned(scanned_paths);
            assert!(s.named_as_on(&remote), "{scanned_paths:?}");
            let before = keys(&s).join("|");
            s.adopt_spellings(remote.keys(), names(synced_paths).iter());
            assert_eq!(keys(&s).join("|"), before);
        }
    }

    #[test]
    fn what_the_server_lacks_is_not_taken_as_named_as_there() {
        let remote: BTreeMap<String, u8> = [("docs".to_owned(), 0)].into();
        assert!(!scanned(&["DOCS"]).named_as_on(&remote));
        assert!(!scanned(&["docs", "docs/new.txt"]).named_as_on(&remote));
        let mut protected = scanned(&["docs"]);
        protected.protected.push("HELD".into());
        assert!(!protected.named_as_on(&remote), "protected paths are renamed too");
    }

    /// Skipping folders already seen must leave the same answer, in any order.
    #[test]
    fn folders_are_counted_however_the_paths_arrive() {
        let live = names(&["Dir/a/one", "Dir/a/two", "dir/a/three", "Dir/b/four", "z"]);
        let hit = case_collisions(live.iter(), live.iter());
        assert_eq!(hit.len(), 4, "{hit:?}");
        let backwards: Vec<String> = live.iter().rev().cloned().collect();
        assert_eq!(case_collisions(backwards.iter(), backwards.iter()).len(), 4);
    }

    #[test]
    fn spellings_are_not_adopted_when_there_are_several() {
        let remote = names(&["Name.txt", "name.txt"]);
        let mut s = scanned(&["NAME.txt"]);
        s.adopt_spellings(remote.iter(), std::iter::empty());
        assert_eq!(keys(&s), ["NAME.txt"], "the server has two");
        let remote = names(&["name.txt"]);
        let mut s = scanned(&["NAME.txt", "Name.txt"]);
        s.adopt_spellings(remote.iter(), std::iter::empty());
        assert_eq!(keys(&s), ["NAME.txt", "Name.txt"], "a case-sensitive folder has two");
    }

    #[test]
    fn collisions_cover_everything_under_a_folder() {
        let live = names(&["CaseDir", "CaseDir/a.txt", "casedir", "casedir/b.txt", "plain.txt"]);
        let hit = case_collisions(live.iter(), live.iter());
        assert_eq!(hit.len(), 4, "{hit:?}");
        assert!(!hit.contains(&&"plain.txt".to_owned()));
    }

    #[test]
    fn collisions_see_letters_beyond_ascii() {
        let live = names(&["RÉSUMÉ.txt", "résumé.txt"]);
        assert_eq!(case_collisions(live.iter(), live.iter()).len(), 2);
    }

    #[test]
    fn a_stale_record_does_not_collide_with_what_exists() {
        let paths = names(&["RCASE.txt", "rcase.txt"]);
        let live = names(&["RCASE.txt"]);
        assert!(case_collisions(paths.iter(), live.iter()).is_empty());
    }

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
        assert!(ignored_within("a/node_modules/x/y.js", false, &pats));
        assert!(ignored_within("build/out/z", false, &pats));
        assert!(!ignored_within("a/node_modules.txt", false, &pats));
    }
}
