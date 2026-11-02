//! Version control metadata (`.git`, `.hg`, `.svn`, `.bzr`, `.jj`) inside a
//! synced folder.
//!
//! A repository's metadata is many files that make sense only together,
//! changed by a program that locks while it works. Synced file by file
//! like anything else, three things could go wrong:
//! - **a torn state**: a round that runs while git is part way through
//!   (writing objects, then moving a ref) could send the ref without the
//!   objects, or send `index.lock`, which then stops git on the other
//!   machine;
//! - **writing under git**: a download could land while git is running
//!   and about to rename its own lock file over the same name;
//! - **commits lost to a conflict**: an ordinary conflict copy,
//!   `main (conflict ...)`, is no valid ref name, so git ignores it; the
//!   commits only it named become unreachable, `git gc` prunes them a few
//!   weeks later, and that deletion syncs everywhere.
//!
//! So:
//! - a repository whose metadata holds a lock file, or changed within the
//!   last few seconds, is **busy**: nothing in its metadata is synced that
//!   round, either way, and lock files themselves are never synced;
//! - within a round, a repository's objects are handled before the files
//!   that name them (refs, `HEAD`, the index), so the server and other
//!   machines are never sent a ref before its objects;
//! - a file in a repository's metadata **changed on both sides** is not
//!   given a conflict copy. Every commit this machine's copy names (a ref,
//!   `packed-refs`, a detached `HEAD`) is first written as a ref of its own
//!   under `refs/homedrive/<time>/`, which git keeps and which syncs like
//!   any ref, so no commit becomes unreachable. The file itself moves to
//!   `.homedrive/kept/`, which never expires, and the other side's version
//!   takes its place.

// Names here are git's and Mercurial's own, matched exactly as they write
// them, not file types.
#![allow(clippy::case_sensitive_file_extension_comparisons)]

use std::path::Path;

/// Directory names that hold a repository's metadata.
const META_DIRS: &[&str] = &[".git", ".hg", ".svn", ".bzr", ".jj"];

/// A repository busy within this long before a round is left for later.
pub const QUIET_NS: i64 = 5_000_000_000;

/// Where a repository's metadata directory is, if `rel` is inside one:
/// the directory (e.g. `proj/.git`), and `rel` relative to it.
pub fn meta_root(rel: &str) -> Option<(&str, &str)> {
    let mut start = 0;
    for part in rel.split('/') {
        let end = start + part.len();
        if META_DIRS.contains(&part) && end < rel.len() {
            return Some((&rel[..end], &rel[end + 1..]));
        }
        start = end + 1;
    }
    None
}

/// Whether `inner` (a path inside a metadata directory) is a lock: git's
/// `*.lock`, Mercurial's `lock` and `wlock`, and the journals SQLite (as in
/// Subversion's `wc.db`) keeps while it writes.
pub fn is_lock(inner: &str) -> bool {
    let name = inner.rsplit('/').next().unwrap_or(inner);
    name.ends_with(".lock")
        || name == "lock"
        || name == "wlock"
        || name.ends_with("-journal")
        || name.ends_with("-wal")
}

/// Whether `inner` holds content-addressed objects, which never change
/// once written and so are handled first.
pub fn is_object(inner: &str) -> bool {
    inner.starts_with("objects/") || inner.starts_with("store/")
}

fn object_id(text: &str) -> Option<&str> {
    let id = text.trim();
    ((id.len() == 40 || id.len() == 64) && id.bytes().all(|b| b.is_ascii_hexdigit())).then_some(id)
}

/// A ref name part that git accepts: what [`refs_named`] writes under.
fn safe_ref_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('.')
        && !part.ends_with(".lock")
        && !part.contains("..")
        && part.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// The commits a git metadata file (`inner`, relative to `.git`) names, as
/// `(new ref path relative to .git, object id)`, to be written under
/// `refs/homedrive/<stamp>/` before the file is replaced. Other
/// repositories' files, and git files that name no commit, give none.
pub fn refs_named(
    meta_dir: &str,
    inner: &str,
    content: &[u8],
    stamp: &str,
) -> Vec<(String, String)> {
    if meta_dir.rsplit('/').next() != Some(".git") {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(content) else { return Vec::new() };
    let base = format!("refs/homedrive/{stamp}");
    let keep = |name: &str, id: &str| -> Option<(String, String)> {
        let name = name.strip_prefix("refs/").unwrap_or(name);
        name.split('/').all(safe_ref_part).then(|| (format!("{base}/{name}"), id.to_owned()))
    };
    let mut out = Vec::new();
    if inner == "packed-refs" {
        for line in text.lines() {
            if line.starts_with('#') || line.starts_with('^') {
                continue;
            }
            if let Some((id, name)) = line.split_once(' ')
                && let Some(id) = object_id(id)
                && let Some(r) = keep(name.trim(), id)
            {
                out.push(r);
            }
        }
    } else if inner.starts_with("refs/") || matches!(inner, "HEAD" | "ORIG_HEAD") {
        // A symbolic ref ("ref: refs/heads/main") names no commit itself.
        if let Some(id) = object_id(text)
            && let Some(r) = keep(inner, id)
        {
            out.push(r);
        }
    }
    out
}

/// The path of a new ref file `inner` in the metadata directory at `meta`.
pub fn ref_path(meta: &Path, inner: &str) -> std::path::PathBuf {
    inner.split('/').fold(meta.to_path_buf(), |p, part| p.join(part))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_is_recognised() {
        assert_eq!(meta_root("p/.git/refs/heads/main"), Some(("p/.git", "refs/heads/main")));
        assert_eq!(meta_root(".hg/store/data/x.i"), Some((".hg", "store/data/x.i")));
        assert_eq!(meta_root("p/.git"), None, "a worktree's .git file is a file");
        assert_eq!(meta_root("p/.github/workflows/ci.yml"), None);
        assert_eq!(meta_root("p/my.git/HEAD"), None);
        assert!(is_lock("index.lock") && is_lock("refs/heads/main.lock") && is_lock("wlock"));
        assert!(is_lock("wc.db-journal") && !is_lock("refs/heads/locksmith"));
        assert!(is_object("objects/ab/cdef") && !is_object("refs/heads/objects"));
    }

    #[test]
    fn every_commit_a_file_names_is_kept_as_a_ref() {
        let id = "0123456789abcdef0123456789abcdef01234567";
        let stamp = "20261029T120000Z";
        assert_eq!(
            refs_named("p/.git", "refs/heads/main", format!("{id}\n").as_bytes(), stamp),
            vec![(format!("refs/homedrive/{stamp}/heads/main"), id.to_owned())]
        );
        assert_eq!(
            refs_named(".git", "HEAD", format!("{id}\n").as_bytes(), stamp),
            vec![(format!("refs/homedrive/{stamp}/HEAD"), id.to_owned())]
        );
        assert!(refs_named(".git", "HEAD", b"ref: refs/heads/main\n", stamp).is_empty());
        let packed = format!(
            "# pack-refs with: peeled fully-peeled sorted\n{id} refs/heads/a\n^{id}\n{id} refs/tags/v1\n"
        );
        assert_eq!(refs_named(".git", "packed-refs", packed.as_bytes(), stamp).len(), 2);
        assert!(refs_named(".hg", "bookmarks", format!("{id} x").as_bytes(), stamp).is_empty());
        assert!(refs_named(".git", "refs/heads/../x", id.as_bytes(), stamp).is_empty());
        assert!(refs_named(".git", "index", b"DIRC....", stamp).is_empty());
    }
}
