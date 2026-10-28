//! A read-only consistency check of the whole store: that every version
//! the metadata refers to, live or in the trash, can be read back intact.
//!
//! Opening the store has already replayed and verified the journal. This
//! then loads every referenced manifest and checks every chunk it lists.
//! With `deep`, each chunk is read and hashed (and each file's hash
//! recomputed); without it, chunks are only checked to exist. Nothing is
//! moved or changed, not even a damaged object.

use std::collections::HashMap;

use hd_chunk::ObjectId;
use hd_common::Result;
use hd_crypto::Sha256;

use crate::Store;
use crate::manifest::Manifest;
use crate::model::Node;
use crate::objects::{Health, Kind};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckReport {
    pub versions: usize,
    pub manifests: usize,
    pub chunks: usize,
    /// "user:path (version N): problem", one per damaged version.
    pub problems: Vec<String>,
}

impl FsckReport {
    pub fn is_clean(&self) -> bool {
        self.problems.is_empty()
    }
}

impl Store {
    pub fn fsck(&self, deep: bool) -> Result<FsckReport> {
        // Every (user, path, version, manifest), live and trashed.
        let versions: Vec<(String, String, u64, ObjectId)> = self.read(|state| {
            let mut out = Vec::new();
            let mut add = |user: &str, path: &str, node: &Node| {
                if let Node::File { versions, .. } = node {
                    for v in versions {
                        out.push((user.to_owned(), path.to_owned(), v.id, v.manifest));
                    }
                }
            };
            for (user, ns) in &state.users {
                for (path, entry) in &ns.entries {
                    add(user, path, &entry.node);
                }
                for item in ns.trash.values() {
                    for (rel, node) in &item.entries {
                        let path = format!("[trash {}] {}/{rel}", item.id, item.path);
                        add(user, &path, node);
                    }
                }
            }
            out
        });
        let mut report = FsckReport { versions: versions.len(), ..FsckReport::default() };
        // A manifest's verdict is the same for every version sharing it.
        let mut verdicts: HashMap<ObjectId, Option<String>> = HashMap::new();
        let mut chunk_ok: HashMap<ObjectId, bool> = HashMap::new();
        for (user, path, version, manifest) in versions {
            let verdict = verdicts.entry(manifest).or_insert_with(|| {
                report.manifests += 1;
                self.check_manifest(&manifest, deep, &mut chunk_ok, &mut report.chunks).err()
            });
            if let Some(problem) = verdict {
                report.problems.push(format!("{user}:{path} (version {version}): {problem}"));
            }
        }
        Ok(report)
    }

    fn check_manifest(
        &self,
        id: &ObjectId,
        deep: bool,
        chunk_ok: &mut HashMap<ObjectId, bool>,
        chunks: &mut usize,
    ) -> std::result::Result<(), String> {
        let objects = self.objects();
        match objects.peek(Kind::Manifest, id) {
            Ok(Ok(_)) => {}
            Ok(Err(Health::Missing)) => return Err(format!("manifest {id} is missing")),
            Ok(Err(h)) => return Err(format!("manifest {id} is damaged: {h:?}")),
            Err(e) => return Err(format!("manifest {id} cannot be read: {e}")),
        }
        let manifest =
            Manifest::load_readonly(objects, id).map_err(|e| format!("manifest {id}: {e}"))?;
        let mut whole = if deep { Sha256::new().ok() } else { None };
        for (chunk, len) in &manifest.chunks {
            let known = chunk_ok.get(chunk).copied();
            if known == Some(false) {
                return Err(format!("chunk {chunk} is missing or damaged"));
            }
            if deep {
                match objects.peek(Kind::Chunk, chunk) {
                    Ok(Ok(data)) if data.len() == *len as usize => {
                        if let Some(h) = &mut whole {
                            h.update(&data);
                        }
                        chunk_ok.insert(*chunk, true);
                    }
                    _ => {
                        chunk_ok.insert(*chunk, false);
                        return Err(format!("chunk {chunk} is missing or damaged"));
                    }
                }
            } else if known.is_none() {
                let present = objects.contains(Kind::Chunk, chunk);
                chunk_ok.insert(*chunk, present);
                if !present {
                    return Err(format!("chunk {chunk} is missing"));
                }
            }
            *chunks += 1;
        }
        if let Some(h) = whole {
            match h.finish() {
                Ok(d) if d == manifest.sha256 => {}
                _ => return Err("the chunks do not hash to the file's SHA-256".to_owned()),
            }
        }
        Ok(())
    }
}
