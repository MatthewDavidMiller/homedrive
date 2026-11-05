//! Restoring to plain files, from the live store or any copy of it (a
//! backup extracted with borg, a copy an administrator downloaded).
//!
//! [`restore_tree`] writes a drive's current files (or a folder of it) out
//! as ordinary files. Every file is verified against its SHA-256 as it is
//! read, executables come back executable, and the run writes a manifest
//! in the format `sha256sum` reads (`<sha256>  <path>`), so the files can
//! be checked again anywhere: `sha256sum -c`, or `homedrive check-files`.
//!
//! [`drill`] is the restore drill's core: a deep check that every version
//! in a copy reads back, then every drive restored to plain files.

use std::io::{self, Read, Write};
use std::path::Path;

use hd_common::{Error, Result, fsio, pathname};

use std::collections::BTreeMap;

use crate::Store;
use crate::manifest::Manifest;
use crate::model::{Node, Version};
use crate::objects::Objects;

const STAGING_PREFIX: &str = ".homedrive-restore-";

/// The manifest of a restore: `<sha256>  <path>` lines, the format
/// `sha256sum -c` checks, so restored files can be verified with or without
/// homedrive.
/// One manifest line, as `sha256sum` writes it: a name with a backslash
/// is escaped, and the line then starts with a backslash.
pub fn manifest_line(sha: &[u8; 32], path: &str) -> String {
    if path.contains('\\') {
        format!("\\{}  {}\n", hd_crypto::hex(sha), path.replace('\\', "\\\\"))
    } else {
        format!("{}  {path}\n", hd_crypto::hex(sha))
    }
}

/// Refuses a manifest path that is already taken: a restore never
/// overwrites, its manifest included. Checked before restoring anything.
pub fn check_manifest_free(manifest: &Path) -> Result<()> {
    if std::fs::symlink_metadata(manifest).is_ok() {
        return Err(Error::new(format!(
            "{} already exists; a restore never overwrites",
            manifest.display()
        )));
    }
    Ok(())
}

/// Writes a manifest to a new file at `manifest`, never over one.
pub fn write_manifest(manifest: &Path, text: &str) -> Result<()> {
    let dir = match manifest.parent().filter(|d| !d.as_os_str().is_empty()) {
        Some(d) => d.to_path_buf(),
        None => std::path::PathBuf::from("."),
    };
    fsio::mkdir_all(&dir, 0o700)?;
    match fsio::write_new_durable(manifest, &dir, &[text.as_bytes()], 0o600)? {
        fsio::Created::New => Ok(()),
        fsio::Created::Existed => check_manifest_free(manifest),
    }
}

/// Parses a manifest written by [`manifest_line`] (or `sha256sum`).
pub fn parse_manifest(text: &str) -> Result<Vec<([u8; 32], String)>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.is_empty()) {
        let (escaped, line) = match line.strip_prefix('\\') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        let bad = || Error::new(format!("manifest line {} is not \"<sha256>  <path>\"", n + 1));
        let (hex, path) = line.split_once("  ").ok_or_else(bad)?;
        let sha = hd_chunk::ObjectId::parse(hex).ok_or_else(bad)?.0;
        let path = if escaped { path.replace("\\\\", "\\") } else { path.to_owned() };
        out.push((sha, path));
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub files: usize,
    pub bytes: u64,
    /// The manifest: (sha256, path relative to the restore), sorted.
    pub manifest: Vec<([u8; 32], String)>,
}

/// Writes `user`'s current files under `path` ("" for the whole drive) to
/// `to` as plain files, verifying each, and the manifest to `manifest`.
/// `to` must not exist yet, or be empty: a restore never overwrites.
pub fn restore_tree(
    store: &Store,
    user: &str,
    path: &str,
    to: &Path,
    manifest: &Path,
) -> Result<RestoreReport> {
    pathname::validate(path)?;
    check_manifest_free(manifest)?;
    if std::fs::read_dir(to).is_ok_and(|mut d| d.next().is_some()) {
        return Err(Error::new(format!(
            "{} is not empty; a restore never overwrites",
            to.display()
        )));
    }
    fsio::mkdir_all(to, 0o700)?;
    let items: Vec<(String, Option<crate::model::Version>)> = store.read(|st| {
        st.user(user).map_or_else(Vec::new, |ns| {
            ns.subtree(path)
                .map(|(p, e)| {
                    let rel = pathname::rebase(p, path, "").unwrap_or_default();
                    (
                        rel,
                        match &e.node {
                            Node::File { versions, .. } => versions.last().cloned(),
                            Node::Dir => None,
                        },
                    )
                })
                .collect()
        })
    });
    if items.is_empty() && !path.is_empty() {
        return Err(Error::new(format!("{user} has nothing at {path}")));
    }
    let mut report = RestoreReport::default();
    for (rel, version) in items {
        let target = if rel.is_empty() { to.to_path_buf() } else { to.join(&rel) };
        let Some(v) = version else {
            fsio::mkdir_all(&target, 0o700)?;
            continue;
        };
        // A single file restored on its own lands inside `to`.
        let (target, rel) = if rel.is_empty() {
            let name = pathname::name(path).to_owned();
            (to.join(&name), name)
        } else {
            (target, rel)
        };
        restore_file(store, &v, &rel, &target)?;
        report.files += 1;
        report.bytes += v.size;
        report.manifest.push((v.sha256, rel));
    }
    report.manifest.sort_by(|a, b| a.1.cmp(&b.1));
    let mut text = String::new();
    for (sha, p) in &report.manifest {
        text.push_str(&manifest_line(sha, p));
    }
    write_manifest(manifest, &text)?;
    Ok(report)
}

/// Writes one version to the new file `target` as a plain file, verified
/// against its SHA-256 before it is given its name. `rel` names it in
/// errors.
fn restore_file(store: &Store, v: &Version, rel: &str, target: &Path) -> Result<()> {
    let parent = target.parent().ok_or_else(|| Error::new("no parent folder"))?;
    fsio::mkdir_all(parent, 0o700)?;
    let mut staged = fsio::Staged::create_in(parent, STAGING_PREFIX)?;
    let mut reader = store.open_content(&v.manifest)?;
    let mut hasher = hd_crypto::Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
    let mut buf = vec![0_u8; 256 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(Error::new(format!("{rel} cannot be read back: {e}")));
            }
        };
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        staged.write_all(&buf[..n])?;
    }
    let got = hasher.finish().map_err(|_| Error::new("SHA-256 failed"))?;
    if got != v.sha256 {
        return Err(Error::new(format!("{rel} does not match its SHA-256; not restored")));
    }
    let modified = u64::try_from(v.mtime_ms)
        .ok()
        .map(|ms| std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms));
    staged.finish(modified, if v.executable { 0o700 } else { 0o600 })?;
    staged.commit_new(target)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DrillReport {
    /// When the backup was taken, as near as the store can tell: its newest
    /// recorded activity.
    pub taken_ms: i64,
    pub versions_checked: usize,
    pub problems: Vec<String>,
    /// Per user: files and bytes restored.
    pub users: Vec<(String, usize, u64)>,
}

/// Checks a restored copy of the store and restores every drive in it to
/// `to/<user>/`, with manifests at `to/<user>.sha256`.
pub fn drill(store: &Store, to: &Path) -> Result<DrillReport> {
    let fsck = store.fsck(true)?;
    let mut report = DrillReport {
        taken_ms: taken_ms(store),
        versions_checked: fsck.versions,
        problems: fsck.problems,
        users: Vec::new(),
    };
    let users: Vec<String> = store.read(|st| st.users.keys().cloned().collect());
    for user in users {
        match restore_tree(store, &user, "", &to.join(&user), &to.join(format!("{user}.sha256"))) {
            Ok(r) => report.users.push((user, r.files, r.bytes)),
            Err(e) => report.problems.push(format!("restoring {user}'s drive: {e}")),
        }
    }
    Ok(report)
}

/// When a backup copy of a store was taken, as near as it can tell: its
/// newest recorded activity.
fn taken_ms(store: &Store) -> i64 {
    store.read(|st| {
        let newest_in = |n: &Node| match n {
            Node::File { versions, .. } => versions.iter().map(|v| v.created_ms).max(),
            Node::Dir => None,
        };
        st.users
            .values()
            .flat_map(|ns| {
                let live = ns.entries.values().filter_map(|e| newest_in(&e.node));
                let trashed = ns.trash.values().flat_map(|t| {
                    t.entries.iter().filter_map(|(_, n)| newest_in(n)).chain([t.deleted_ms])
                });
                live.chain(trashed).collect::<Vec<_>>()
            })
            .max()
            .unwrap_or(0)
    })
}

/// One file the light drill restores.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sampled {
    pub user: String,
    pub path: String,
    pub version: Version,
}

/// `n` of the current files across every drive, chosen by `seed`: the same
/// seed picks the same files from the same metadata, so the drill can plan
/// what to extract and then restore exactly those. Each file's place in
/// line is the SHA-256 of the seed, its user and its path, which is as good
/// as random and needs no state.
pub fn sample(store: &Store, seed: &[u8], n: usize) -> Result<Vec<Sampled>> {
    let mut all: Vec<([u8; 32], Sampled)> = Vec::new();
    let candidates: Vec<Sampled> = store.read(|st| {
        st.users
            .iter()
            .flat_map(|(user, ns)| {
                ns.entries.iter().filter_map(move |(path, e)| match &e.node {
                    Node::File { versions, .. } => versions.last().map(|v| Sampled {
                        user: user.clone(),
                        path: path.clone(),
                        version: v.clone(),
                    }),
                    Node::Dir => None,
                })
            })
            .collect()
    });
    for c in candidates {
        let mut h = hd_crypto::Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
        h.update(seed);
        h.update(&[0]);
        h.update(c.user.as_bytes());
        h.update(&[0]);
        h.update(c.path.as_bytes());
        all.push((h.finish().map_err(|_| Error::new("SHA-256 failed"))?, c));
    }
    all.sort_unstable_by_key(|a| a.0);
    Ok(all.into_iter().take(n).map(|(_, c)| c).collect())
}

/// The objects the sampled files still need, as paths relative to the
/// store's root (what a backup tool extracts), and the sample's size. A
/// manifest has to be there before its chunks can be named, so the light
/// drill asks again after extracting until nothing is missing.
pub fn sample_needs(store: &Store, sample: &[Sampled]) -> Result<(Vec<String>, u64)> {
    let mut needed = Vec::new();
    for s in sample {
        for (kind, id) in Manifest::missing_objects(store.objects(), &s.version.manifest)? {
            needed.push(Objects::path_in(Path::new(""), kind, &id).to_string_lossy().into_owned());
        }
    }
    needed.sort();
    needed.dedup();
    Ok((needed, sample.iter().map(|s| s.version.size).sum()))
}

/// The light drill: restores the sampled files to `to/<user>/<path>`,
/// each verified against its SHA-256, with a manifest per user at
/// `to/<user>.sha256`. Every object it reads is checked against its ID on
/// the way, so a sampled file comes back intact or is reported. It proves
/// that much of the backup, not all of it: only the full drill reads every
/// object.
pub fn drill_sample(store: &Store, to: &Path, seed: &[u8], n: usize) -> Result<DrillReport> {
    let chosen = sample(store, seed, n)?;
    let mut report = DrillReport { taken_ms: taken_ms(store), ..DrillReport::default() };
    let mut per_user: BTreeMap<String, (usize, u64, String)> = BTreeMap::new();
    for s in &chosen {
        report.versions_checked += 1;
        let target = to.join(&s.user).join(&s.path);
        match restore_file(store, &s.version, &s.path, &target) {
            Ok(()) => {
                let e = per_user.entry(s.user.clone()).or_default();
                e.0 += 1;
                e.1 += s.version.size;
                e.2.push_str(&manifest_line(&s.version.sha256, &s.path));
            }
            Err(e) => report.problems.push(format!("{}'s {}: {e}", s.user, s.path)),
        }
    }
    for (user, (files, bytes, text)) in per_user {
        write_manifest(&to.join(format!("{user}.sha256")), &text)?;
        report.users.push((user, files, bytes));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_round_trip_in_sha256sum_format() {
        let a = [0xab; 32];
        let lines =
            format!("{}{}", manifest_line(&a, "x/plain.txt"), manifest_line(&a, "odd\\name"));
        assert!(lines.starts_with(&format!("{}  x/plain.txt\n", hd_crypto::hex(&a))));
        assert!(lines.contains("\\abab"), "{lines}");
        let back = parse_manifest(&lines).unwrap();
        assert_eq!(back, vec![(a, "x/plain.txt".to_owned()), (a, "odd\\name".to_owned())]);
        assert!(parse_manifest("nonsense\n").is_err());
    }
}
