//! What a copy of the store is made of, for an administrator to keep on
//! another machine (`homedrive backup-store`, or the web UI's download).
//!
//! A copy is the store's own layout: `store.id`, the metadata files
//! (`meta/snapshot.*` and `meta/journal.*`), and the objects
//! (`chunks/ab/cd/<id>`, `manifests/ab/cd/<id>`). It opens as a store, so
//! everything that works on a store works on it: `fsck`, restoring to plain
//! files, repairing the live store from it, or serving it.
//!
//! [`Store::copy_meta`] checkpoints first, then lists the metadata files
//! with their lengths at that moment. Objects are written before the
//! journal record that names them, so every object that metadata names
//! already exists, and [`Store::copy_objects`], listed afterwards, holds
//! them all (collection keeps unreferenced objects for days, so none of
//! them vanish in between). A copier that fetches the metadata first, then
//! the objects, and only then puts the metadata in place, never holds
//! metadata that names an object it lacks.

use std::fs::{self, File};
use std::path::Path;

use hd_chunk::ObjectId;
use hd_common::{Error, Result, fsio};

use crate::Store;
use crate::objects::{Kind, Outcome, read_verified_at};

pub const STORE_ID: &str = "store.id";

/// One file of a copy and its length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyFile {
    pub name: String,
    pub len: u64,
}

/// The object a copy file name holds, if it names one.
pub fn object_of(name: &str) -> Option<(Kind, ObjectId)> {
    let (kind, rest) = if let Some(r) = name.strip_prefix("chunks/") {
        (Kind::Chunk, r)
    } else {
        (Kind::Manifest, name.strip_prefix("manifests/")?)
    };
    let mut parts = rest.split('/');
    let (a, b, hex) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let id = ObjectId::parse(hex)?;
    (a == &hex[..2] && b == &hex[2..4]).then_some((kind, id))
}

/// Whether `name` is a metadata file a copy holds.
fn is_meta(name: &str) -> bool {
    let Some(file) = name.strip_prefix("meta/") else { return false };
    let digits = file.strip_prefix("snapshot.").or_else(|| file.strip_prefix("journal."));
    digits.is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `name` is any file a copy may hold.
pub fn valid_name(name: &str) -> bool {
    name == STORE_ID || is_meta(name) || object_of(name).is_some()
}

/// Checks the object file at `path` against what its copy name says it
/// is. `Ok(false)`: damaged, short, or not that object.
pub fn verify_object_file(path: &Path, name: &str) -> Result<bool> {
    let (kind, id) = object_of(name).ok_or_else(|| Error::new("not an object's name"))?;
    Ok(matches!(read_verified_at(path, kind, &id)?, Outcome::Good(_)))
}

/// Whether `bytes` are the object file a copy name says, whole and
/// correct.
pub fn verify_object_bytes(bytes: &[u8], name: &str) -> bool {
    object_of(name).is_some_and(|(kind, id)| crate::objects::verify_bytes(bytes, kind, &id))
}

fn sorted_names(dir: &Path) -> Result<Vec<String>> {
    let mut names = Vec::new();
    match fs::read_dir(dir) {
        Ok(entries) => {
            for e in entries {
                if let Some(n) = e?.file_name().to_str() {
                    names.push(n.to_owned());
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    names.sort();
    Ok(names)
}

impl Store {
    /// Writes a checkpoint, then lists `store.id` and the metadata files
    /// with their lengths now. The metadata stays locked meanwhile, so no
    /// commit is part way through an append: every length ends on a whole
    /// record, and a copy never holds part of one.
    pub fn copy_meta(&self) -> Result<Vec<CopyFile>> {
        let mut meta = crate::lock(&self.meta);
        meta.checkpoint()?;
        let mut out = vec![CopyFile {
            name: STORE_ID.to_owned(),
            len: fs::metadata(self.root().join(STORE_ID))?.len(),
        }];
        for n in sorted_names(&self.root().join("meta"))? {
            let name = format!("meta/{n}");
            if is_meta(&name) {
                out.push(CopyFile { len: fs::metadata(self.root().join(&name))?.len(), name });
            }
        }
        drop(meta);
        Ok(out)
    }

    /// Up to `limit` object file names after `after` ("" for the start), in
    /// order, and whether more follow.
    pub fn copy_objects(&self, after: &str, limit: usize) -> Result<(Vec<String>, bool)> {
        let mut out = Vec::new();
        for top in ["chunks", "manifests"] {
            for a in sorted_names(&self.root().join(top))? {
                for b in sorted_names(&self.root().join(top).join(&a))? {
                    let prefix = format!("{top}/{a}/{b}/");
                    // Everything in this folder sorts before `after`.
                    if after > prefix.as_str() && !after.starts_with(&prefix) {
                        continue;
                    }
                    for hex in sorted_names(&self.root().join(top).join(&a).join(&b))? {
                        let name = format!("{prefix}{hex}");
                        if name.as_str() <= after || object_of(&name).is_none() {
                            continue;
                        }
                        if out.len() == limit {
                            return Ok((out, true));
                        }
                        out.push(name);
                    }
                }
            }
        }
        Ok((out, false))
    }

    /// Opens one file of a copy, by its name in the copy, and gives its
    /// length now.
    pub fn copy_open(&self, name: &str) -> Result<(File, u64)> {
        if !valid_name(name) {
            return Err(Error::new("not a file of a store copy"));
        }
        let file = fsio::open_nofollow(self.root().join(name))?;
        let len = file.metadata()?.len();
        Ok((file, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_names_are_strict() {
        let hex = "ab".repeat(32);
        assert!(valid_name("store.id"));
        assert!(valid_name("meta/snapshot.00000000000000000012"));
        assert!(valid_name("meta/journal.00000000000000000013"));
        assert!(valid_name(&format!("chunks/ab/ab/{hex}")));
        assert!(valid_name(&format!("manifests/ab/ab/{hex}")));
        for bad in [
            "meta/LOCK".to_owned(),
            "meta/snapshot.".to_owned(),
            "../store.id".to_owned(),
            "admin.sock".to_owned(),
            "history.id".to_owned(),
            format!("chunks/ab/cd/{hex}"),
            format!("chunks/ab/ab/{hex}/x"),
            format!("quarantine/{hex}"),
            "users.json".to_owned(),
        ] {
            assert!(!valid_name(&bad), "{bad}");
        }
    }
}
