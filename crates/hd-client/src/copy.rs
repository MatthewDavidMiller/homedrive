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
//!    server no longer keeps leave it. Objects are never removed: the copy
//!    holds everything that was ever stored and collected since.
//!
//! **Generations.** Before step 3 changes anything, the metadata it is
//! about to replace is kept as a generation named by when it was fetched
//! (see `generations`, which keeps them as chunks shared between them, so
//! a run adds about what changed). The server keeps only a few days of
//! metadata, and whatever happens to its files (retention purging the
//! trash, a mistake, or someone with access to the server) reaches the copy
//! on its next run. Each generation is a complete metadata set over the
//! same objects, so the copy can be opened as it was at any earlier run
//! (`--generation` on `store-copy-check`, `store-copy-restore` and
//! `store-copy-decrypt`). Generations are never removed.
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

use hd_common::{Error, Result, fsio, timefmt};
use hd_store::copy::{STORE_ID, valid_name, verify_object_bytes, verify_object_file};
use hd_store::sealed::{self, KeyParams, Keys, Sealer};
use hd_store::{Store, StoreOptions};

use crate::generations::{self, History};
use crate::remote::Remote;

const STAGING_PREFIX: &str = ".homedrive-copy-";
/// Beside an encrypted copy: how its keys are derived.
pub const KEY_FILE: &str = "homedrive-copy.json";
const SEALED_META: &str = "sealed-meta";
const SEALED: &str = "sealed";
/// Earlier generations of the metadata, in a plain and an encrypted copy.
const HISTORY: &str = "history";
const SEALED_HISTORY: &str = "sealed-history";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Objects fetched this run, and their bytes.
    pub fetched: usize,
    pub bytes: u64,
    /// Objects the copy holds now.
    pub objects: usize,
    pub meta_files: usize,
    /// The generation the replaced metadata was kept as, if anything
    /// changed since the last run.
    pub generation: Option<String>,
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

/// The metadata files directly in `dir` (those `wanted` accepts), with
/// their lengths, sorted by name.
fn held_files(dir: &Path, wanted: impl Fn(&str) -> bool) -> Result<Vec<(String, u64)>> {
    let mut out = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for e in entries {
                let e = e?;
                let name = e.file_name().to_string_lossy().into_owned();
                let meta = std::fs::symlink_metadata(e.path())?;
                if meta.file_type().is_file() && wanted(&name) {
                    out.push((name, meta.len()));
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    out.sort();
    Ok(out)
}

/// When the files at `paths` were fetched: their newest modification time,
/// in Unix seconds.
fn fetched_at(paths: impl Iterator<Item = std::path::PathBuf>) -> i64 {
    paths
        .filter_map(|p| std::fs::symlink_metadata(p).ok()?.modified().ok())
        .max()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or_else(timefmt::unix_seconds)
}

/// The generations the copy at `dir` holds, oldest first.
pub fn generations(dir: &Path) -> Result<Vec<String>> {
    generations::list(&dir.join(HISTORY), &dir.join(SEALED_HISTORY))
}

/// An error naming the generations there are, for one asked for that is
/// not there.
fn no_generation(dir: &Path, name: &str) -> Error {
    let known = generations(dir).unwrap_or_default();
    Error::new(format!(
        "{} has no generation {name}; it has {}",
        dir.display(),
        if known.is_empty() { "none yet".to_owned() } else { known.join(", ") }
    ))
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
        meta.push((name.clone(), *len, staged));
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

    // 3. The metadata takes its place, once what it replaces is kept as a
    //    generation. Unchanged since the last run, nothing moves.
    let meta_dir = dir.join("meta");
    let held = held_files(&meta_dir, |n| valid_name(&format!("meta/{n}")))?;
    let mut incoming: Vec<(String, u64)> =
        meta.iter().map(|(n, len, _)| (n.trim_start_matches("meta/").to_owned(), *len)).collect();
    incoming.sort();
    report.meta_files = incoming.len();
    if held == incoming {
        return Ok(report);
    }
    if !held.is_empty() {
        let fetched = fetched_at(held.iter().map(|(n, _)| meta_dir.join(n)));
        let mut files: Vec<(String, Box<dyn io::Read>)> = Vec::new();
        for (name, len) in &held {
            let file = fsio::open_nofollow(meta_dir.join(name))?;
            files.push((name.clone(), Box::new(io::Read::take(file, *len))));
        }
        let (name, _) = History::Plain(dir.join(HISTORY)).keep(fetched, files, &staging)?;
        report.generation = Some(name);
    }
    for (name, _, staged) in meta {
        let target = dir.join(&name);
        if target.exists() {
            staged.commit_replace(&target)?;
        } else {
            staged.commit_new(&target)?;
        }
    }
    for (name, _) in &held {
        if !incoming.iter().any(|(n, _)| n == name) {
            crate::trash::remove_copy_meta_file(&meta_dir.join(name))?;
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
        let sealed_len = std::fs::metadata(staged.path())?.len();
        meta.push((sealed_path(dir, keys, name)?, sealed_len, staged));
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

    // 3. As in a plain copy: what is replaced is kept as a generation
    //    first. Sealing the same file twice gives the same length.
    let meta_dir = dir.join(SEALED_META);
    let id_label = keys.sealed_name(STORE_ID)?;
    let held = held_files(&meta_dir, |n| n != id_label)?;
    let mut incoming = Vec::new();
    for (target, len, _) in &meta {
        let label = target.file_name().map(|n| n.to_string_lossy().into_owned());
        incoming.push((label.unwrap_or_default(), *len));
    }
    incoming.sort();
    report.meta_files = incoming.len();
    if held == incoming {
        return Ok(report);
    }
    if !held.is_empty() {
        // Kept by what the files hold, so that chunks repeat from one
        // generation to the next; each sealed afresh.
        let fetched = fetched_at(held.iter().map(|(n, _)| meta_dir.join(n)));
        let mut files: Vec<(String, Box<dyn io::Read>)> = Vec::new();
        for (label, _) in &held {
            let mut plain = Vec::new();
            let mut input = fsio::open_nofollow(meta_dir.join(label))?;
            let name = sealed::open(&mut input, keys, label, &mut plain)?;
            let name = name
                .strip_prefix("meta/")
                .ok_or_else(|| Error::new(format!("{label} in the copy holds {name}")))?
                .to_owned();
            files.push((name, Box::new(io::Cursor::new(plain))));
        }
        let history = History::Sealed(dir.join(SEALED_HISTORY), keys);
        let (name, _) = history.keep(fetched, files, &staging)?;
        report.generation = Some(name);
    }
    for (target, _, staged) in meta {
        if target.exists() {
            staged.commit_replace(&target)?;
        } else {
            staged.commit_new(&target)?;
        }
    }
    for (name, _) in &held {
        if !incoming.iter().any(|(n, _)| n == name) {
            crate::trash::remove_copy_meta_file(&meta_dir.join(name))?;
        }
    }
    Ok(report)
}

/// Every sealed file of an encrypted copy, metadata first: `store.id`,
/// then (unless `with_meta` is false) the metadata in `sealed-meta`, then
/// the objects.
fn sealed_files(
    dir: &Path,
    keys: &Keys,
    with_meta: bool,
) -> Result<Vec<(std::path::PathBuf, bool)>> {
    let id = dir.join(SEALED_META).join(keys.sealed_name(STORE_ID)?);
    let mut out = vec![(id.clone(), true)];
    if with_meta {
        for e in std::fs::read_dir(dir.join(SEALED_META))? {
            let path = e?.path();
            if path != id {
                out.push((path, true));
            }
        }
    }
    if let Ok(groups) = std::fs::read_dir(dir.join(SEALED)) {
        for g in groups {
            for e in std::fs::read_dir(g?.path())? {
                out.push((e?.path(), false));
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
/// With `to`, writes the plain copy there (a new or empty directory). With
/// `generation`, the metadata is that earlier generation's.
pub fn open_sealed(
    dir: &Path,
    keys: &Keys,
    to: Option<&Path>,
    generation: Option<&str>,
) -> Result<Opened> {
    if generation.is_some_and(|g| !generations(dir).is_ok_and(|all| all.iter().any(|a| a == g))) {
        return Err(no_generation(dir, generation.unwrap_or_default()));
    }
    if let Some(to) = to {
        if std::fs::read_dir(to).is_ok_and(|mut d| d.next().is_some()) {
            return Err(Error::new(format!("{} is not empty", to.display())));
        }
        fsio::mkdir_all(to.join("tmp"), 0o700)?;
    }
    let mut report = Opened::default();
    if let Some(g) = generation {
        // That generation's metadata, in place of the copy's newest.
        let meta = to.map(|t| t.join("meta"));
        if let Some(m) = &meta {
            fsio::mkdir_all(m, 0o700)?;
        }
        let staging = to.map_or_else(|| dir.join("tmp"), |t| t.join("tmp"));
        let history = History::Sealed(dir.join(SEALED_HISTORY), keys);
        report.files += history.restore(g, meta.as_deref(), &staging)?;
    }
    for (path, is_meta) in sealed_files(dir, keys, generation.is_none())? {
        let label = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_owned();
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

/// A copy opened as a store. One opened as an earlier generation reads
/// that generation's metadata from a scratch directory, removed when this
/// is dropped.
#[derive(Debug)]
pub struct CopyStore {
    store: Store,
    scratch: Option<std::path::PathBuf>,
}

impl std::ops::Deref for CopyStore {
    type Target = Store;
    fn deref(&self) -> &Store {
        &self.store
    }
}

impl Drop for CopyStore {
    fn drop(&mut self) {
        if let Some(scratch) = &self.scratch {
            let _ = crate::trash::remove_generation_scratch(scratch);
        }
    }
}

/// Opens the copy at `dir` as a store: as of its last run, or as of an
/// earlier `generation`.
pub fn open_copy(dir: &Path, generation: Option<&str>) -> Result<CopyStore> {
    if !dir.join(STORE_ID).is_file() {
        return Err(Error::new(format!("{} is not a store copy", dir.display())));
    }
    let options = StoreOptions { min_free: 0, ..StoreOptions::default() };
    let Some(g) = generation else {
        return Ok(CopyStore { store: Store::open(dir, &options)?, scratch: None });
    };
    if !generations(dir)?.iter().any(|a| a == g) {
        return Err(no_generation(dir, g));
    }
    let staging = dir.join("tmp");
    let scratch = staging.join(format!("{STAGING_PREFIX}open-{}", hd_common::rand::random_hex(8)?));
    fsio::mkdir_all(&scratch, 0o700)?;
    let opened = History::Plain(dir.join(HISTORY))
        .restore(g, Some(&scratch), &staging)
        .and_then(|_| Store::open_with_meta(dir, &scratch, &options));
    match opened {
        Ok(store) => Ok(CopyStore { store, scratch: Some(scratch) }),
        Err(e) => {
            let _ = crate::trash::remove_generation_scratch(&scratch);
            Err(e)
        }
    }
}
