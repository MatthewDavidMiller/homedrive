//! The restore drill that proves the backups work. Restoring to plain
//! files itself is `hd_store::restore`.
//!
//! **The drill** (`restore-drill`, weekly from the ansible role) runs on a
//! backup extracted to scratch space:
//! 1. a deep check reads every stored object of every version back;
//! 2. every user's drive is restored to plain files, each verified;
//! 3. the running server compares each user's manifest with the live drive
//!    (`drill-compare`): every file that existed when the backup was taken
//!    must be in it, by path or by content (it may have moved since), and
//!    the backup must hold no content the drive never had.
//!
//! The outcome is reported like a backup (`backups`), so a drill that
//! fails, or stops running, reaches the admins.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use hd_common::Result;
use hd_store::model::Node;
pub use hd_store::restore::{DrillReport, RestoreReport, drill, restore_tree};

use crate::App;

/// The most paths of each kind a comparison lists.
const LISTED: usize = 100;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompareReport {
    pub files: usize,
    /// Files the drive had when the backup was taken that the backup lacks.
    pub missing: Vec<String>,
    /// Backup paths whose content the drive has never held.
    pub unknown: Vec<String>,
}

impl CompareReport {
    pub fn is_clean(&self) -> bool {
        self.missing.is_empty() && self.unknown.is_empty()
    }
}

/// Compares a restored backup's manifest for `user`, taken at `taken_ms`,
/// with the live drive.
pub fn compare(app: &App, user: &str, taken_ms: i64, manifest: &str) -> Result<CompareReport> {
    let entries = hd_store::restore::parse_manifest(manifest)?;
    let by_path: BTreeMap<&str, [u8; 32]> =
        entries.iter().map(|(sha, p)| (p.as_str(), *sha)).collect();
    let in_backup: BTreeSet<[u8; 32]> = entries.iter().map(|(sha, _)| *sha).collect();
    let mut report = CompareReport { files: entries.len(), ..CompareReport::default() };
    app.store.read(|st| {
        let Some(ns) = st.user(user) else {
            report.unknown.extend(entries.iter().take(LISTED).map(|(_, p)| p.clone()));
            return;
        };
        let mut known: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut note = |n: &Node| {
            if let Node::File { versions, .. } = n {
                known.extend(versions.iter().map(|v| v.sha256));
            }
        };
        ns.entries.values().for_each(|e| note(&e.node));
        ns.trash.values().flat_map(|t| t.entries.iter()).for_each(|(_, n)| note(n));
        for (path, e) in &ns.entries {
            let Node::File { versions, .. } = &e.node else { continue };
            let then: Vec<&[u8; 32]> =
                versions.iter().filter(|v| v.created_ms <= taken_ms).map(|v| &v.sha256).collect();
            if then.is_empty() {
                continue; // made after the backup
            }
            // There by path, or by content (moved or renamed since).
            let present = by_path.contains_key(path.as_str())
                || then.iter().any(|sha| in_backup.contains(*sha));
            if !present && report.missing.len() < LISTED {
                report.missing.push(path.clone());
            }
        }
        for (sha, p) in &entries {
            if !known.contains(sha) && report.unknown.len() < LISTED {
                report.unknown.push(p.clone());
            }
        }
    });
    Ok(report)
}

/// The drill's summary, as text for the report and the log.
pub fn summary(r: &DrillReport) -> String {
    let files: usize = r.users.iter().map(|(_, f, _)| f).sum();
    let bytes: u64 = r.users.iter().map(|(_, _, b)| b).sum();
    let mut out = format!(
        "{} version(s) read back, {files} file(s) ({}) restored for {} user(s)",
        r.versions_checked,
        crate::gib(bytes),
        r.users.len()
    );
    for p in r.problems.iter().take(10) {
        let _ = write!(out, "; {p}");
    }
    out
}
