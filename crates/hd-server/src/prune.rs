//! `hd-server prune`: moves old dated backups in one folder to the trash,
//! for backup jobs that name each day's file by its date and want only the
//! last few weeks in the folder.
//!
//! Only files directly in the folder whose names match the pattern are
//! considered. A file counts as old only when both the time it was stored
//! and its own modification time are past the age: a clock that was wrong
//! on either side keeps a file rather than losing it. The newest `keep`
//! matching files are never touched, so a backup job that stops cannot let
//! pruning empty its folder. Nothing is deleted: each file goes to the
//! trash, from which it can be restored until retention purges it. Each
//! file is checked again as it is trashed, and one changed in the meantime
//! is left alone.

use hd_common::{Error, Result, pathname};
use hd_store::Store;
use hd_store::model::{Node, Op};

#[derive(Clone, Debug)]
pub struct Prune {
    /// The folder, relative to the drive's root.
    pub dir: String,
    /// A file name, with `*` standing for any run of characters.
    pub pattern: String,
    pub older_than_ms: i64,
    /// The newest matching files that are always kept.
    pub keep: usize,
}

/// Whether `name` matches `pattern`, where `*` matches any run of
/// characters, including none.
pub fn matches(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let [first, middle @ .., last] = parts.as_slice() else {
        return pattern == name;
    };
    let Some(mut rest) = name.strip_prefix(first) else { return false };
    for part in middle {
        let Some(at) = rest.find(part) else { return false };
        rest = &rest[at + part.len()..];
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

impl Prune {
    pub fn validate(&self) -> Result<()> {
        if !self.dir.is_empty() {
            pathname::validate(&self.dir)?;
        }
        if self.pattern.is_empty() || self.pattern.contains('/') {
            return Err(Error::new("the pattern must be a file name, without a slash"));
        }
        if self.pattern.chars().all(|c| c == '*') {
            return Err(Error::new("the pattern must name more than \"*\""));
        }
        if self.older_than_ms < 86_400_000 {
            return Err(Error::new("only files older than a day can be pruned"));
        }
        if self.keep == 0 {
            return Err(Error::new("at least one file must be kept"));
        }
        Ok(())
    }
}

/// Moves the old matching files to the trash and returns their paths.
pub fn prune(store: &Store, user: &str, p: &Prune, now_ms: i64) -> Result<Vec<String>> {
    p.validate()?;
    // (when it was last touched, path, current version)
    let mut found: Vec<(i64, String, u64)> = store.read(|st| {
        let Some(ns) = st.user(user) else { return Vec::new() };
        ns.children(&p.dir)
            .filter_map(|(path, entry)| {
                let v = entry.node.current()?;
                matches(&p.pattern, pathname::name(path))
                    .then(|| (v.created_ms.max(v.mtime_ms), path.clone(), v.id))
            })
            .collect()
    });
    found.sort_unstable_by(|a, b| b.cmp(a));
    let mut trashed = Vec::new();
    for (touched, path, version) in found.into_iter().skip(p.keep) {
        if now_ms - touched < p.older_than_ms {
            continue;
        }
        let (applied, ()) = store.commit_with(|st| {
            let unchanged = st.user(user).and_then(|ns| ns.get(&path)).is_some_and(|e| {
                matches!(&e.node, Node::File { .. })
                    && e.node.current().map(|v| v.id) == Some(version)
            });
            let op = unchanged.then(|| Op::Trash {
                user: user.to_owned(),
                path: path.clone(),
                deleted_ms: now_ms,
            });
            Ok((op, ()))
        })?;
        if applied.is_some() {
            trashed.push(path);
        }
    }
    trashed.sort();
    Ok(trashed)
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn patterns_match_whole_names() {
        for (pattern, name) in [
            ("vaultwarden_db-*.sqlite3", "vaultwarden_db-11_05_2026.sqlite3"),
            ("music_server_*.tar.gz", "music_server_11_05_2026.tar.gz"),
            ("a*b*c", "abc"),
            ("a*b*c", "a-b-b-c"),
            ("*.gz", ".gz"),
            ("exact", "exact"),
        ] {
            assert!(matches(pattern, name), "{pattern} {name}");
        }
        for (pattern, name) in [
            ("music_server_*.tar.gz", "music_server_11_05_2026.tar.gz.part"),
            ("music_server_*.tar.gz", "old_music_server_1.tar.gz"),
            ("a*bc", "abc_"),
            ("ab*ba", "aba"),
            ("exact", "exactly"),
        ] {
            assert!(!matches(pattern, name), "{pattern} {name}");
        }
    }
}
