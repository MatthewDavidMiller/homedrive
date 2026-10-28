//! Repairing the store from other copies of its objects.
//!
//! Objects are named by their SHA-256, so any copy of an object is as good
//! as the original once it verifies: a backup of the store, mounted with
//! `borg mount`, or an older backup, or another disk. [`Store::repair_from`]
//! walks every version the metadata refers to, live or in the trash, reads
//! each manifest and chunk in full, and replaces any that is missing,
//! damaged or unreadable with a verified copy from the first source that
//! has one. The store's own `quarantine/` is always searched too: an
//! object set aside because a failing disk could not read it once may read
//! correctly now.
//!
//! Nothing is taken on trust: a copy is used only if its header and hash
//! check out, and it is stored through the normal write path (staged,
//! fsynced, linked). The sources are only read.

use std::cell::Cell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use hd_chunk::ObjectId;
use hd_common::{Error, Result};

use crate::Store;
use crate::manifest::Manifest;
use crate::model::Node;
use crate::objects::{Kind, Objects, Outcome, read_verified_at};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    pub versions: usize,
    /// Objects read and verified.
    pub checked: usize,
    /// Objects replaced from a source.
    pub restored: usize,
    /// "user:path (version N): problem" for each version still damaged.
    pub still_damaged: Vec<String>,
}

impl Store {
    /// Replaces every missing, damaged or unreadable object any version
    /// needs with a verified copy from `sources` (other store roots) or this
    /// store's quarantine.
    pub fn repair_from(&self, sources: &[PathBuf]) -> Result<RepairReport> {
        let versions: Vec<(String, ObjectId)> = self.read(|state| {
            let mut out = Vec::new();
            let mut add = |label: String, node: &Node| {
                if let Node::File { versions, .. } = node {
                    for v in versions {
                        out.push((format!("{label} (version {})", v.id), v.manifest));
                    }
                }
            };
            for (user, ns) in &state.users {
                for (path, e) in &ns.entries {
                    add(format!("{user}:{path}"), &e.node);
                }
                for item in ns.trash.values() {
                    for (rel, node) in &item.entries {
                        add(format!("{user}:[trash {}] {}/{rel}", item.id, item.path), node);
                    }
                }
            }
            out
        });
        let mut report = RepairReport { versions: versions.len(), ..RepairReport::default() };
        let restored = Cell::new(0);
        let checked = Cell::new(0);
        let fetch = |kind: Kind, id: &ObjectId| -> Result<Vec<u8>> {
            checked.set(checked.get() + 1);
            self.fetch_or_restore(kind, id, sources, &restored)
        };
        let mut verdicts: HashMap<ObjectId, Option<String>> = HashMap::new();
        let mut chunk_ok: HashMap<ObjectId, bool> = HashMap::new();
        for (label, manifest) in versions {
            let verdict = verdicts.entry(manifest).or_insert_with(|| {
                let m = match Manifest::load_with(&manifest, fetch) {
                    Ok(m) => m,
                    Err(e) => return Some(format!("manifest {manifest}: {e}")),
                };
                for (chunk, _) in &m.chunks {
                    let ok = *chunk_ok
                        .entry(*chunk)
                        .or_insert_with(|| fetch(Kind::Chunk, chunk).is_ok());
                    if !ok {
                        return Some(format!("chunk {chunk} has no good copy anywhere"));
                    }
                }
                None
            });
            if let Some(problem) = verdict {
                report.still_damaged.push(format!("{label}: {problem}"));
            }
        }
        report.restored = restored.get();
        report.checked = checked.get();
        Ok(report)
    }

    /// The object's verified bytes: this store's copy if it is good, or
    /// else the first good copy among the sources, which is then stored.
    fn fetch_or_restore(
        &self,
        kind: Kind,
        id: &ObjectId,
        sources: &[PathBuf],
        restored: &Cell<usize>,
    ) -> Result<Vec<u8>> {
        let objects = self.objects();
        if let Ok(Ok(data)) = objects.peek(kind, id) {
            return Ok(data);
        }
        let mut candidates: Vec<PathBuf> =
            sources.iter().map(|root| Objects::path_in(root, kind, id)).collect();
        candidates.extend(quarantined_copies(&self.root().join("quarantine"), kind, id));
        for path in candidates {
            if let Ok(Outcome::Good(data)) = read_verified_at(&path, kind, id) {
                objects.put_claimed(kind, id, &data)?;
                restored.set(restored.get() + 1);
                eprintln!(
                    "hd-store: repair: restored {} {id} from {}",
                    kind.name(),
                    path.display()
                );
                return Ok(data);
            }
        }
        Err(Error::new(format!("{} {id} has no good copy anywhere", kind.name())))
    }
}

/// The copies of an object in a quarantine directory, newest first.
fn quarantined_copies(dir: &Path, kind: Kind, id: &ObjectId) -> Vec<PathBuf> {
    let prefix = format!("{}-{id}-", kind.name());
    let mut out: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with(&prefix)))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.reverse();
    out
}
