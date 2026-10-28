//! An administrator's copy of the whole store, on this machine: the
//! off-machine backup that nothing on the server can reach or delete.
//!
//! `homedrive backup-store DIR` keeps `DIR` a copy of the store in its own
//! layout (see `hd_store::copy`). Objects never change once written, so a
//! run fetches only the objects the copy lacks, and checks each before it
//! takes its name. The order keeps the copy whole at every moment, even if
//! a run is cut off:
//! 1. the server checkpoints and lists its metadata; those files are
//!    downloaded aside, to `DIR/tmp/`;
//! 2. every object the copy lacks is downloaded and verified (its header,
//!    and its SHA-256 against its name);
//! 3. only then do the new metadata files take their places in `DIR/meta/`
//!    (every object they name is now present), and metadata files the
//!    server no longer keeps are removed. Objects are never removed: the
//!    copy holds everything that was ever stored and collected since.
//!
//! The copy opens as a store: `store-copy-check` reads every version back,
//! and `store-copy-restore` writes a drive out as plain files.
//!
//! **Encrypted copies** (`--encrypt`, off by default) hold the same files,
//! each sealed under a passphrase (`hd_store::sealed`) and named by a keyed
//! hash of its path: `sealed-meta/<name>` for `store.id` and the metadata,
//! `sealed/<ab>/<name>` for objects, and `homedrive-copy.json` with how the
//! keys were derived. Each object is fetched into memory, verified, and
//! sealed there, so nothing of it is written in the clear. Such a copy is
//! checked as it is (every file authenticated, every object verified), and
//! opened back into a plain copy with `store-copy-decrypt`.

use std::io::{self, Write};
use std::path::Path;

use hd_common::{Error, Result, fsio};
use hd_store::copy::{STORE_ID, valid_name, verify_object_bytes, verify_object_file};
use hd_store::sealed::{self, KeyParams, Keys, Sealer};
use hd_store::{Store, StoreOptions};

use crate::remote::Remote;

const STAGING_PREFIX: &str = ".homedrive-copy-";
/// Beside an encrypted copy: how its keys are derived.
pub const KEY_FILE: &str = "homedrive-copy.json";
const SEALED_META: &str = "sealed-meta";
const SEALED: &str = "sealed";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Objects fetched this run, and their bytes.
    pub fetched: usize,
    pub bytes: u64,
    /// Objects the copy holds now.
    pub objects: usize,
    pub meta_files: usize,
}

/// Counts what is written through it.
struct Counting<'w, W: Write> {
    out: &'w mut W,
    n: u64,
}

impl<W: Write> Write for Counting<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.n += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// Downloads `name` into a new staged file in `staging`; with `len`,
/// exactly that many bytes.
fn fetch(
    remote: &mut Remote,
    staging: &Path,
    name: &str,
    len: Option<u64>,
) -> Result<(fsio::Staged, u64)> {
    let mut staged = fsio::Staged::create_in(staging, STAGING_PREFIX)?;
    let mut counting = Counting { out: &mut staged, n: 0 };
    remote.copy_file(name, len, &mut counting)?;
    let got = counting.n;
    if len.is_some_and(|l| l != got) {
        return Err(Error::new(format!("{name} arrived short; nothing of it was kept")));
    }
    staged.finish(None, 0o600)?;
    Ok((staged, got))
}

/// How the copy at `dir` is encrypted: `None` for a plain copy or a new
/// directory.
pub fn key_params(dir: &Path) -> Result<Option<KeyParams>> {
    fsio::read_bounded(dir.join(KEY_FILE), 64 * 1024)?.map(|b| KeyParams::from_json(&b)).transpose()
}

/// Makes `dir` a new encrypted copy, with keys from `passphrase`.
pub fn start_encrypted(dir: &Path, passphrase: &str) -> Result<Keys> {
    if dir.join(STORE_ID).exists() || key_params(dir)?.is_some() {
        return Err(Error::new(format!(
            "{} already holds a copy; an encrypted copy starts in a new directory",
            dir.display()
        )));
    }
    let (keys, params) = Keys::create(passphrase)?;
    fsio::mkdir_all(dir, 0o700)?;
    fsio::atomic_replace(dir.join(KEY_FILE), params.to_json().as_bytes(), 64 * 1024)?;
    Ok(keys)
}

/// Brings the copy at `dir` up to date with the server's store: plain, or
/// sealed with `keys` for an encrypted copy.
pub fn backup_store(remote: &mut Remote, dir: &Path, keys: Option<&Keys>) -> Result<CopyReport> {
    match (keys, key_params(dir)?) {
        (None, None) => backup_plain(remote, dir),
        (Some(k), Some(_)) => backup_sealed(remote, dir, k),
        (None, Some(_)) => {
            Err(Error::new(format!("{} is an encrypted copy; give its passphrase", dir.display())))
        }
        (Some(_), None) => Err(Error::new(format!(
            "{} is not an encrypted copy; start one in a new directory with --encrypt",
            dir.display()
        ))),
    }
}

fn backup_plain(remote: &mut Remote, dir: &Path) -> Result<CopyReport> {
    let staging = dir.join("tmp");
    fsio::mkdir_all(&staging, 0o700)?;
    fsio::mkdir_all(dir.join("meta"), 0o700)?;
    // The store's own lock: no second copier, and no check or restore,
    // while this runs.
    let _lock = fsio::lock_exclusive(dir.join("meta").join("LOCK"))?
        .ok_or_else(|| Error::new(format!("{} is in use by another homedrive", dir.display())))?;
    let listing = remote.copy_meta()?;
    let mut report = CopyReport::default();

    // The store's identity: a copy of one store never takes another's.
    let (id_staged, _) = fetch(remote, &staging, STORE_ID, None)?;
    let theirs = fsio::read_bounded(id_staged.path(), 4096)?.unwrap_or_default();
    match fsio::read_bounded(dir.join(STORE_ID), 4096)? {
        Some(ours) if ours != theirs => {
            return Err(Error::new(format!(
                "{} holds a copy of a different store; use a new directory",
                dir.display()
            )));
        }
        Some(_) => {}
        None => id_staged.commit_new(dir.join(STORE_ID))?,
    }

    // 1. The metadata, aside.
    let mut meta = Vec::new();
    for (name, len) in listing.iter().filter(|(n, _)| n.starts_with("meta/")) {
        let (staged, _) = fetch(remote, &staging, name, Some(*len))?;
        meta.push((name.clone(), staged));
    }

    // 2. Every object the copy lacks.
    let mut after = String::new();
    loop {
        let (names, more) = remote.copy_objects(&after)?;
        for name in &names {
            report.objects += 1;
            let target = dir.join(name);
            if target.is_file() {
                continue;
            }
            let parent = target.parent().ok_or_else(|| Error::new("no parent folder"))?;
            fsio::mkdir_all(parent, 0o700)?;
            let (staged, len) = fetch(remote, &staging, name, None)?;
            if !verify_object_file(staged.path(), name)? {
                return Err(Error::new(format!(
                    "{name} arrived damaged and was not kept; run the copy again (the server's \
                     scrub checks its own copy)"
                )));
            }
            // Already there means another run put it there: the same bytes.
            if staged.commit_new(&target).is_err() && !target.is_file() {
                return Err(Error::new(format!("cannot store {name} in the copy")));
            }
            report.fetched += 1;
            report.bytes += len;
        }
        match names.last() {
            Some(last) if more => after.clone_from(last),
            _ => break,
        }
    }

    // 3. The metadata takes its place; what the store no longer keeps goes.
    for (name, staged) in meta {
        let target = dir.join(&name);
        if target.exists() {
            staged.commit_replace(&target)?;
        } else {
            staged.commit_new(&target)?;
        }
        report.meta_files += 1;
    }
    let keep: Vec<&str> = listing.iter().map(|(n, _)| n.as_str()).collect();
    for e in std::fs::read_dir(dir.join("meta"))? {
        let name = format!("meta/{}", e?.file_name().to_string_lossy());
        let ours = name.starts_with("meta/snapshot.") || name.starts_with("meta/journal.");
        if ours && !keep.contains(&name.as_str()) {
            crate::trash::remove_copy_meta_file(&dir.join(&name))?;
        }
    }
    Ok(report)
}

/// Where a sealed file of store path `name` lives in an encrypted copy.
fn sealed_path(dir: &Path, keys: &Keys, name: &str) -> Result<std::path::PathBuf> {
    let label = keys.sealed_name(name)?;
    Ok(if name.starts_with("meta/") || name == STORE_ID {
        dir.join(SEALED_META).join(label)
    } else {
        dir.join(SEALED).join(&label[..2]).join(label)
    })
}

/// Seals `data` (store path `name`) into a new staged file.
fn seal_staged(staging: &Path, keys: &Keys, name: &str, data: &[u8]) -> Result<fsio::Staged> {
    let mut staged = fsio::Staged::create_in(staging, STAGING_PREFIX)?;
    let mut sealer = Sealer::new(&mut staged, keys, name)?;
    sealer.write_all(data)?;
    sealer.finish()?;
    staged.finish(None, 0o600)?;
    Ok(staged)
}

fn backup_sealed(remote: &mut Remote, dir: &Path, keys: &Keys) -> Result<CopyReport> {
    let staging = dir.join("tmp");
    fsio::mkdir_all(&staging, 0o700)?;
    fsio::mkdir_all(dir.join(SEALED_META), 0o700)?;
    let _lock = fsio::lock_exclusive(dir.join("LOCK"))?
        .ok_or_else(|| Error::new(format!("{} is in use by another homedrive", dir.display())))?;
    let listing = remote.copy_meta()?;
    let mut report = CopyReport::default();

    let mut theirs = Vec::new();
    remote.copy_file(STORE_ID, None, &mut theirs)?;
    let id_path = sealed_path(dir, keys, STORE_ID)?;
    if id_path.exists() {
        let mut ours = Vec::new();
        sealed::open(
            &mut fsio::open_nofollow(&id_path)?,
            keys,
            &keys.sealed_name(STORE_ID)?,
            &mut ours,
        )?;
        if ours != theirs {
            return Err(Error::new(format!(
                "{} holds a copy of a different store; use a new directory",
                dir.display()
            )));
        }
    } else {
        seal_staged(&staging, keys, STORE_ID, &theirs)?.commit_new(&id_path)?;
    }

    // 1. The metadata, sealed as it arrives, aside.
    let mut meta = Vec::new();
    for (name, len) in listing.iter().filter(|(n, _)| n.starts_with("meta/")) {
        let mut staged = fsio::Staged::create_in(&staging, STAGING_PREFIX)?;
        let mut sealer = Sealer::new(&mut staged, keys, name)?;
        let mut counting = Counting { out: &mut sealer, n: 0 };
        remote.copy_file(name, Some(*len), &mut counting)?;
        if counting.n != *len {
            return Err(Error::new(format!("{name} arrived short; nothing of it was kept")));
        }
        sealer.finish()?;
        staged.finish(None, 0o600)?;
        meta.push((sealed_path(dir, keys, name)?, staged));
    }

    // 2. Every object the copy lacks: verified in memory, then sealed.
    let mut after = String::new();
    loop {
        let (names, more) = remote.copy_objects(&after)?;
        for name in &names {
            report.objects += 1;
            let target = sealed_path(dir, keys, name)?;
            if target.is_file() {
                continue;
            }
            let mut bytes = Vec::new();
            remote.copy_file(name, None, &mut bytes)?;
            if !verify_object_bytes(&bytes, name) {
                return Err(Error::new(format!(
                    "{name} arrived damaged and was not kept; run the copy again (the server's \
                     scrub checks its own copy)"
                )));
            }
            let parent = target.parent().ok_or_else(|| Error::new("no parent folder"))?;
            fsio::mkdir_all(parent, 0o700)?;
            let staged = seal_staged(&staging, keys, name, &bytes)?;
            report.bytes += bytes.len() as u64;
            hd_crypto::cleanse(&mut bytes);
            if staged.commit_new(&target).is_err() && !target.is_file() {
                return Err(Error::new(format!("cannot store {name} in the copy")));
            }
            report.fetched += 1;
        }
        match names.last() {
            Some(last) if more => after.clone_from(last),
            _ => break,
        }
    }

    // 3. The metadata takes its place; what the store no longer keeps goes.
    let mut keep = Vec::new();
    for (name, _) in &listing {
        keep.push(sealed_path(dir, keys, name)?);
    }
    for (target, staged) in meta {
        if target.exists() {
            staged.commit_replace(&target)?;
        } else {
            staged.commit_new(&target)?;
        }
        report.meta_files += 1;
    }
    for e in std::fs::read_dir(dir.join(SEALED_META))? {
        let path = e?.path();
        if !keep.contains(&path) {
            crate::trash::remove_copy_meta_file(&path)?;
        }
    }
    Ok(report)
}

/// Every sealed file of an encrypted copy, metadata first.
fn sealed_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir.join(SEALED_META))? {
        out.push(e?.path());
    }
    if let Ok(groups) = std::fs::read_dir(dir.join(SEALED)) {
        for g in groups {
            for e in std::fs::read_dir(g?.path())? {
                out.push(e?.path());
            }
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opened {
    pub files: usize,
    pub objects: usize,
}

/// Opens every file of an encrypted copy: each must authenticate under the
/// passphrase and its name, and each object must be whole and correct.
/// With `to`, writes the plain copy there (a new or empty directory).
pub fn open_sealed(dir: &Path, keys: &Keys, to: Option<&Path>) -> Result<Opened> {
    if let Some(to) = to {
        if std::fs::read_dir(to).is_ok_and(|mut d| d.next().is_some()) {
            return Err(Error::new(format!("{} is not empty", to.display())));
        }
        fsio::mkdir_all(to.join("tmp"), 0o700)?;
    }
    let mut report = Opened::default();
    for path in sealed_files(dir)? {
        let label = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
        let is_meta = path.parent().is_some_and(|p| p.ends_with(SEALED_META));
        let mut input = fsio::open_nofollow(&path)?;
        let fail = |e: Error| Error::new(format!("{}: {e}", path.display()));
        let name = if is_meta {
            // Metadata can be large: it streams to its place (or nowhere).
            match to {
                Some(to) => {
                    let mut staged = fsio::Staged::create_in(to.join("tmp"), STAGING_PREFIX)?;
                    let name = sealed::open(&mut input, keys, &label, &mut staged).map_err(fail)?;
                    if !valid_name(&name) || !(name == STORE_ID || name.starts_with("meta/")) {
                        return Err(fail(Error::new("holds an unexpected name")));
                    }
                    staged.finish(None, 0o600)?;
                    fsio::mkdir_all(to.join("meta"), 0o700)?;
                    staged.commit_new(to.join(&name))?;
                    name
                }
                None => sealed::open(&mut input, keys, &label, &mut io::sink()).map_err(fail)?,
            }
        } else {
            let mut plain = Vec::new();
            let name = sealed::open(&mut input, keys, &label, &mut plain).map_err(fail)?;
            if !verify_object_bytes(&plain, &name) {
                return Err(Error::new(format!("{name} in the copy is damaged")));
            }
            if let Some(to) = to {
                let target = to.join(&name);
                let parent = target.parent().ok_or_else(|| Error::new("no parent folder"))?;
                fsio::mkdir_all(parent, 0o700)?;
                fsio::write_new_durable(&target, to.join("tmp"), &[&plain], 0o600)?;
            }
            hd_crypto::cleanse(&mut plain);
            report.objects += 1;
            name
        };
        if !valid_name(&name) {
            return Err(fail(Error::new("holds an unexpected name")));
        }
        report.files += 1;
    }
    Ok(report)
}

/// Opens the copy at `dir` as a store.
pub fn open_copy(dir: &Path) -> Result<Store> {
    if !dir.join(STORE_ID).is_file() {
        return Err(Error::new(format!("{} is not a store copy", dir.display())));
    }
    Store::open(dir, &StoreOptions { min_free: 0, ..StoreOptions::default() })
}
