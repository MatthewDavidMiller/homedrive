//! The sync engine: one round of reconciling a local folder with its
//! place on the server.
//!
//! For each path the engine knows three things:
//! - **S**: what it held when last in sync (the client's state);
//! - **L**: what is on disk now;
//! - **R**: what the server has now (the change feed's mirror).
//!
//! | S | L vs S | R vs S | Action |
//! |---|---|---|---|
//! | yes | same | same | nothing |
//! | yes | same | changed | download, replacing the local file |
//! | yes | same | deleted | move the local file to the client trash |
//! | yes | changed | same | upload, based on S's version |
//! | yes | changed | changed | keep both (unless identical) |
//! | yes | changed | deleted | upload (an edit beats a delete) |
//! | yes | deleted | same | move the server's copy to its trash |
//! | yes | deleted | changed | download (an edit beats a delete) |
//! | no | new | none | upload |
//! | no | new | present | adopt if identical, else keep both |
//! | no | none | present | download |
//!
//! **Keep both** uploads the local file as new. The server stores it beside
//! the other as "<name> (conflict ...)", the engine renames the local file
//! to match, and the other version is downloaded under the original name.
//!
//! **The rules that keep data safe:**
//! - A local file is replaced or deleted only after re-checking, right
//!   before acting, that it still matches S (same size, time and inode, or
//!   the same SHA-256). The old content is kept in the client trash
//!   (`trash`), and on the server in the version history and trash.
//! - A file that changes while it is being uploaded is not committed; the
//!   next round tries again.
//! - Downloads are written beside the target, verified against the
//!   server's SHA-256, fsynced, and only then given the name.
//! - Without S (a new client, lost state, or a server restored from an
//!   older backup) nothing is ever deleted: the engine can only upload,
//!   download into an empty place, adopt, or keep both.
//! - A missing folder or a missing `.homedrive-root` marker stops the
//!   round before anything happens, because an unmounted disk looks like
//!   an empty folder.
//! - A round that would delete many files performs none of those
//!   deletions until they are confirmed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use hd_api::{BaseSpec, ChangeInfo, CommitRequest, CommitResult};
use hd_chunk::{Chunker, ObjectId};
use hd_common::{Error, Result, fsio, pathname};
use hd_crypto::Sha256;

use crate::remote::{CommitOutcome, Remote};
use crate::scan::{self, LocalEntry, SENTINEL, STAGING_PREFIX};
use crate::state::{Kind, Persisted, RemoteEntry, Synced};
use crate::trash::Trash;

/// Files below this are kept in memory between hashing and uploading.
const KEEP_IN_MEMORY: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Folder {
    pub local: PathBuf,
    /// Where it lives in the drive ("" for the whole drive).
    pub remote: String,
    pub ignore: Vec<String>,
    pub state_dir: PathBuf,
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Perform this round's deletions even if there are many.
    pub confirm_deletes: bool,
    /// More file deletions than this in one round need confirming...
    pub mass_delete_count: usize,
    /// ...as do more than this percentage of the synced files, once there
    /// are more than `mass_delete_floor` deletions.
    pub mass_delete_percent: usize,
    pub mass_delete_floor: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            confirm_deletes: false,
            mass_delete_count: 50,
            mass_delete_percent: 20,
            mass_delete_floor: 10,
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub uploaded: Vec<String>,
    pub downloaded: Vec<String>,
    pub deleted_local: Vec<String>,
    pub deleted_remote: Vec<String>,
    /// Local paths renamed to the server's conflict names.
    pub conflicts: Vec<String>,
    pub skipped: Vec<(String, String)>,
    pub errors: Vec<(String, String)>,
    /// Deletions held back for confirmation.
    pub held_deletes: Option<usize>,
}

impl Report {
    pub fn changed_anything(&self) -> bool {
        !(self.uploaded.is_empty()
            && self.downloaded.is_empty()
            && self.deleted_local.is_empty()
            && self.deleted_remote.is_empty()
            && self.conflicts.is_empty())
    }
}

#[derive(Debug)]
pub struct Engine {
    folder: Folder,
    remote: Remote,
    pub state: Persisted,
    pub options: Options,
}

/// Hashes a file without holding it.
fn hash_file(abs: &Path) -> Result<([u8; 32], u64)> {
    let mut f = fsio::open_nofollow(abs)?;
    let mut h = Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
    let mut buf = vec![0_u8; 256 * 1024];
    loop {
        let n = match f.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let len = h.len();
    Ok((h.finish().map_err(|_| Error::new("SHA-256 failed"))?, len))
}

fn stat(abs: &Path) -> Option<LocalEntry> {
    fs::symlink_metadata(abs).ok().and_then(|m| LocalEntry::of(&m))
}

/// Whether the file at `abs` is still what `s` recorded: the same stat
/// identity, or failing that the same content.
fn still_matches(abs: &Path, s: &Synced) -> Result<bool> {
    let Some(now) = stat(abs) else { return Ok(false) };
    if now.kind != Kind::File {
        return Ok(false);
    }
    if now.size == s.size && now.mtime_ns == s.mtime_ns && now.ino == s.ino && now.dev == s.dev {
        return Ok(true);
    }
    Ok(hash_file(abs)?.0 == s.sha256)
}

fn synced_from(entry: &LocalEntry, version: u64, sha256: [u8; 32]) -> Synced {
    Synced {
        kind: entry.kind,
        version,
        sha256,
        size: entry.size,
        mtime_ns: entry.mtime_ns,
        ino: entry.ino,
        dev: entry.dev,
    }
}

fn dir_synced() -> Synced {
    Synced { kind: Kind::Dir, version: 0, sha256: [0; 32], size: 0, mtime_ns: 0, ino: 0, dev: 0 }
}

fn dir_remote() -> RemoteEntry {
    RemoteEntry { kind: Kind::Dir, version: 0, sha256: [0; 32], size: 0, mtime_ms: 0 }
}

/// A writer that hashes and counts what passes through.
struct Hashing<'w, W: Write> {
    out: &'w mut W,
    hash: Sha256,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.out.write(buf)?;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}

/// What the local side of a file is, compared with its synced record.
enum LocalSide {
    Absent,
    Same,
    Changed([u8; 32]),
}

/// A file as chunked for upload.
struct Chunked {
    entry: LocalEntry,
    chunks: Vec<(ObjectId, u32)>,
    data: Option<Vec<Vec<u8>>>,
    size: u64,
    sha256: [u8; 32],
}

/// Deletions gathered for the second phase.
enum Delete {
    LocalFile(String),
    RemoteFile(String),
    LocalDir(String),
    RemoteDir(String),
}

impl Engine {
    pub fn open(folder: Folder, remote: Remote, options: Options) -> Result<Self> {
        let state = Persisted::open(&folder.state_dir)?;
        Ok(Self { folder, remote, state, options })
    }

    /// Marks `local` as a folder to sync by creating its `.homedrive-root`.
    pub fn mark_root(local: &Path) -> Result<()> {
        fsio::mkdir_durable(local, 0o755)?;
        let staging = local.join(".homedrive").join("staging");
        fsio::mkdir_durable(&staging, 0o700)?;
        fsio::write_new_durable(
            local.join(SENTINEL),
            &staging,
            &[b"This folder is synced by homedrive. Do not delete this file.\n"],
            0o644,
        )?;
        Ok(())
    }

    fn remote_path(&self, rel: &str) -> String {
        pathname::join(&self.folder.remote, rel)
    }

    /// The local path of a server path, if it is inside this folder.
    fn local_rel<'p>(&self, path: &'p str) -> Option<&'p str> {
        let prefix = &self.folder.remote;
        if prefix.is_empty() {
            return Some(path);
        }
        path.strip_prefix(prefix.as_str())?.strip_prefix('/')
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.folder.local.join(rel)
    }

    /// Brings the mirror of the server up to date. `wait_s` long-polls for
    /// the first page. Returns whether anything changed.
    pub fn pull(&mut self, wait_s: u64) -> Result<bool> {
        let mut cursor = self.state.state.cursor;
        let mut changed = false;
        let mut wait = wait_s;
        loop {
            let page = self.remote.changes(cursor, wait)?;
            wait = 0;
            if page.reset {
                eprintln!(
                    "homedrive: the server's history is behind this client's (restored from a \
                     backup?); comparing everything afresh, with no deletions"
                );
                self.state.reset()?;
            }
            for c in &page.changes {
                let Some(rel) = self.local_rel(c.path()).map(str::to_owned) else { continue };
                if scan::ignored(&rel, matches!(c, ChangeInfo::Dir { .. }), &self.folder.ignore) {
                    continue;
                }
                changed = true;
                match c {
                    ChangeInfo::File { version, .. } => self.state.set_remote(
                        &rel,
                        RemoteEntry {
                            kind: Kind::File,
                            version: version.id,
                            sha256: version.sha256,
                            size: version.size,
                            mtime_ms: version.mtime_ms,
                        },
                    )?,
                    ChangeInfo::Dir { .. } => self.state.set_remote(&rel, dir_remote())?,
                    ChangeInfo::Deleted { .. } => self.state.del_remote(&rel)?,
                }
            }
            cursor = page.cursor;
            if !page.more {
                break;
            }
        }
        self.state.set_cursor(cursor)?;
        Ok(changed)
    }

    fn check_root(&self) -> Result<()> {
        let root = &self.folder.local;
        if !fs::symlink_metadata(root).is_ok_and(|m| m.file_type().is_dir()) {
            return Err(Error::new(format!(
                "the folder {} is missing; is its disk mounted? Nothing was changed",
                root.display()
            )));
        }
        if !root.join(SENTINEL).is_file() {
            return Err(Error::new(format!(
                "{} has no {SENTINEL} marker, so it may not be the folder that was synced (an \
                 unmounted disk looks like an empty folder). Nothing was changed. If it is the \
                 right folder, run `homedrive add-folder` on it again",
                root.display()
            )));
        }
        Ok(())
    }

    /// One full round: pull the server's changes, scan, reconcile.
    pub fn sync(&mut self, wait_s: u64) -> Result<Report> {
        self.check_root()?;
        self.pull(wait_s)?;
        self.check_root()?;
        let scanned = scan::scan(&self.folder.local, &self.folder.ignore)?;
        let mut report = Report { skipped: scanned.skipped, ..Report::default() };
        let mut trash = Trash::new(&self.folder.local)?;
        let paths: BTreeSet<String> = self
            .state
            .state
            .synced
            .keys()
            .chain(scanned.entries.keys())
            .chain(self.state.state.remote.keys())
            .cloned()
            .collect();
        let mut deletes = Vec::new();
        for rel in &paths {
            let s = self.state.state.synced.get(rel).cloned();
            let l = scanned.entries.get(rel).copied();
            let r = self.state.state.remote.get(rel).cloned();
            // A path skipped because something above it was refused or not
            // synced stays untouched.
            if let Err(e) = self.reconcile(rel, s, l, r, &mut trash, &mut report, &mut deletes) {
                if Self::state_failed(&e) {
                    return Err(e);
                }
                report.errors.push((rel.clone(), e.message().to_owned()));
            }
        }
        self.delete_phase(deletes, &mut trash, &mut report)?;
        Ok(report)
    }

    /// Errors writing the client's own state end the round; anything else
    /// is about one path and the round goes on.
    fn state_failed(e: &Error) -> bool {
        e.message().contains("an earlier write failed")
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile(
        &mut self,
        rel: &str,
        s: Option<Synced>,
        l: Option<LocalEntry>,
        r: Option<RemoteEntry>,
        trash: &mut Trash,
        report: &mut Report,
        deletes: &mut Vec<Delete>,
    ) -> Result<()> {
        let lk = l.map(|e| e.kind);
        let rk = r.as_ref().map(|e| e.kind);
        // Folders.
        if lk == Some(Kind::Dir)
            || rk == Some(Kind::Dir)
            || s.as_ref().is_some_and(|s| s.kind == Kind::Dir)
        {
            if lk.is_some_and(|k| k != Kind::Dir)
                || rk.is_some_and(|k| k != Kind::Dir)
                || s.as_ref().is_some_and(|s| s.kind != Kind::Dir)
            {
                report.skipped.push((
                    rel.to_owned(),
                    "a file on one side and a folder on the other; rename one".into(),
                ));
                return Ok(());
            }
            return self.reconcile_dir(rel, s.is_some(), lk.is_some(), rk.is_some(), deletes);
        }
        // Files.
        let local = match (&s, l) {
            (_, None) => LocalSide::Absent,
            (Some(s), Some(e)) => {
                if e.size == s.size && e.mtime_ns == s.mtime_ns && e.ino == s.ino && e.dev == s.dev
                {
                    LocalSide::Same
                } else {
                    let (sha, _) = hash_file(&self.abs(rel))?;
                    if sha == s.sha256 {
                        // Touched but not changed: remember the new stat.
                        let mut updated = s.clone();
                        updated.mtime_ns = e.mtime_ns;
                        updated.ino = e.ino;
                        updated.dev = e.dev;
                        self.state.set_synced(rel, updated)?;
                        LocalSide::Same
                    } else {
                        LocalSide::Changed(sha)
                    }
                }
            }
            (None, Some(_)) => LocalSide::Changed(hash_file(&self.abs(rel))?.0),
        };
        let remote_same = match (&s, &r) {
            (Some(s), Some(r)) => s.version == r.version,
            _ => false,
        };
        match (s, local, r) {
            (Some(_), LocalSide::Same, Some(_)) if remote_same => {}
            (Some(s), LocalSide::Same, Some(r)) => {
                if self.download(rel, &r, Some(&s), trash)? {
                    report.downloaded.push(rel.to_owned());
                }
            }
            (Some(_), LocalSide::Same, None) => deletes.push(Delete::LocalFile(rel.to_owned())),
            (Some(s), LocalSide::Changed(sha), Some(r)) => {
                if remote_same {
                    self.upload(rel, BaseSpec::Version(s.version), report)?;
                } else if sha == r.sha256 {
                    self.adopt(rel, &r)?;
                } else {
                    self.keep_both(rel, &r, trash, report)?;
                }
            }
            (_, LocalSide::Changed(_), None) => {
                self.upload(rel, BaseSpec::Absent, report)?;
            }
            (Some(_), LocalSide::Absent, Some(_)) if remote_same => {
                deletes.push(Delete::RemoteFile(rel.to_owned()));
            }
            (Some(s), LocalSide::Absent, Some(r)) => {
                // Deleted here, edited there: the edit wins.
                if self.download(rel, &r, Some(&s), trash)? {
                    report.downloaded.push(rel.to_owned());
                }
            }
            (Some(_), LocalSide::Absent, None) => self.state.del_synced(rel)?,
            (None, LocalSide::Changed(sha), Some(r)) => {
                if sha == r.sha256 {
                    self.adopt(rel, &r)?;
                } else {
                    self.keep_both(rel, &r, trash, report)?;
                }
            }
            (None, LocalSide::Absent, Some(r)) => {
                if self.download(rel, &r, None, trash)? {
                    report.downloaded.push(rel.to_owned());
                }
            }
            (None, LocalSide::Same | LocalSide::Absent, None)
            | (None, LocalSide::Same, Some(_)) => {}
        }
        Ok(())
    }

    fn reconcile_dir(
        &mut self,
        rel: &str,
        s: bool,
        l: bool,
        r: bool,
        deletes: &mut Vec<Delete>,
    ) -> Result<()> {
        match (s, l, r) {
            (_, true, true) => {
                if !s {
                    self.state.set_synced(rel, dir_synced())?;
                }
            }
            (false, true, false) => {
                self.remote.mkdir(&self.remote_path(rel))?;
                self.state.set_remote(rel, dir_remote())?;
                self.state.set_synced(rel, dir_synced())?;
            }
            (false, false, true) => {
                fsio::mkdir_durable(self.abs(rel), 0o755)?;
                self.state.set_synced(rel, dir_synced())?;
            }
            (true, true, false) => deletes.push(Delete::LocalDir(rel.to_owned())),
            (true, false, true) => deletes.push(Delete::RemoteDir(rel.to_owned())),
            (true, false, false) => self.state.del_synced(rel)?,
            (false, false, false) => {}
        }
        Ok(())
    }

    /// Records a local file that already holds exactly the server's
    /// version.
    fn adopt(&mut self, rel: &str, r: &RemoteEntry) -> Result<()> {
        if let Some(e) = stat(&self.abs(rel)) {
            self.state.set_synced(rel, synced_from(&e, r.version, r.sha256))?;
        }
        Ok(())
    }

    fn chunk(abs: &Path) -> Result<Chunked> {
        let file = fsio::open_nofollow(abs)?;
        let entry =
            LocalEntry::of(&file.metadata()?).ok_or_else(|| Error::new("not a regular file"))?;
        let mut chunker = Chunker::new(&file)?;
        let mut chunks = Vec::new();
        let mut data = (entry.size <= KEEP_IN_MEMORY).then(Vec::new);
        while let Some(c) = chunker.next_chunk()? {
            chunks.push((
                c.id,
                u32::try_from(c.data.len()).map_err(|_| Error::new("chunk too large"))?,
            ));
            if let Some(d) = &mut data {
                d.push(c.data);
            }
        }
        let summary = chunker.finish()?;
        Ok(Chunked { entry, chunks, data, size: summary.len, sha256: summary.sha256 })
    }

    /// Uploads the chunks in `needed`, re-reading the file if they are not
    /// in memory. Fails if the file no longer chunks the same way.
    fn send(&mut self, abs: &Path, c: &Chunked, needed: &BTreeSet<ObjectId>) -> Result<()> {
        if needed.is_empty() {
            return Ok(());
        }
        if let Some(data) = &c.data {
            for ((id, _), bytes) in c.chunks.iter().zip(data) {
                if needed.contains(id) {
                    self.remote.put_chunk(id, bytes)?;
                }
            }
            return Ok(());
        }
        let file = fsio::open_nofollow(abs)?;
        let mut chunker = Chunker::new(&file)?;
        let mut i = 0;
        while let Some(chunk) = chunker.next_chunk()? {
            if c.chunks.get(i).map(|(id, _)| *id) != Some(chunk.id) {
                return Err(Error::new("the file changed while it was being uploaded"));
            }
            if needed.contains(&chunk.id) {
                self.remote.put_chunk(&chunk.id, &chunk.data)?;
            }
            i += 1;
        }
        Ok(())
    }

    /// Uploads the local file at `rel`. A conflict renames the local file
    /// to the server's conflict name.
    fn upload(
        &mut self,
        rel: &str,
        base: BaseSpec,
        report: &mut Report,
    ) -> Result<Option<CommitResult>> {
        let abs = self.abs(rel);
        let c = Self::chunk(&abs)?;
        let ids: Vec<ObjectId> =
            c.chunks.iter().map(|(id, _)| *id).collect::<BTreeSet<_>>().into_iter().collect();
        let needed: BTreeSet<ObjectId> = self.remote.missing(&ids)?.into_iter().collect();
        self.send(&abs, &c, &needed)?;
        // A file still being written is not committed; next round retries.
        if stat(&abs) != Some(c.entry) {
            report.skipped.push((rel.to_owned(), "changed while uploading; will retry".into()));
            return Ok(None);
        }
        let request = CommitRequest {
            path: self.remote_path(rel),
            base,
            size: c.size,
            sha256: c.sha256,
            mtime_ms: c.entry.mtime_ns.div_euclid(1_000_000),
            chunks: c.chunks.clone(),
        };
        let mut outcome = self.remote.commit(&request)?;
        if let CommitOutcome::Missing(ids) = outcome {
            // Collected between asking and committing: send them and retry.
            self.send(&abs, &c, &ids.into_iter().collect())?;
            outcome = self.remote.commit(&request)?;
        }
        let result = match outcome {
            CommitOutcome::Done(r) => r,
            CommitOutcome::Missing(_) => {
                return Err(Error::new("the server keeps losing uploaded chunks"));
            }
        };
        let remote_entry = RemoteEntry {
            kind: Kind::File,
            version: result.version,
            sha256: c.sha256,
            size: c.size,
            mtime_ms: request.mtime_ms,
        };
        if result.conflict {
            let Some(new_rel) = self.local_rel(&result.path).map(str::to_owned) else {
                return Err(Error::new("the server put a conflict copy outside this folder"));
            };
            let new_abs = self.abs(&new_rel);
            if stat(&new_abs).is_some() {
                report.skipped.push((
                    rel.to_owned(),
                    format!("kept on the server as {new_rel}, which exists locally"),
                ));
                return Ok(Some(result));
            }
            fsio::move_new_durable(&abs, &new_abs)?;
            if let Some(e) = stat(&new_abs) {
                self.state.set_synced(&new_rel, synced_from(&e, result.version, c.sha256))?;
            }
            self.state.set_remote(&new_rel, remote_entry)?;
            // The original name now belongs to the server's version, which
            // the next pass downloads into the empty place.
            self.state.del_synced(rel)?;
            report.conflicts.push(new_rel);
        } else {
            self.state.set_synced(rel, synced_from(&c.entry, result.version, c.sha256))?;
            self.state.set_remote(rel, remote_entry)?;
            if !result.unchanged {
                report.uploaded.push(rel.to_owned());
            }
        }
        Ok(Some(result))
    }

    /// Both sides changed differently: upload the local file as a new file
    /// (the server names it as a conflict copy), rename the local file to
    /// match, then download the server's version under the original name.
    fn keep_both(
        &mut self,
        rel: &str,
        r: &RemoteEntry,
        trash: &mut Trash,
        report: &mut Report,
    ) -> Result<()> {
        let Some(result) = self.upload(rel, BaseSpec::Absent, report)? else { return Ok(()) };
        if result.conflict
            && stat(&self.abs(rel)).is_none()
            && self.download(rel, r, None, trash)?
        {
            report.downloaded.push(rel.to_owned());
        }
        Ok(())
    }

    /// Downloads `r` to `rel`. `expect` is what the local file must still
    /// be for it to be replaced (`None`: there must be no local file).
    /// `Ok(false)` when nothing was done (the version is gone, or the local
    /// file changed meanwhile; the next round sorts it out).
    fn download(
        &mut self,
        rel: &str,
        r: &RemoteEntry,
        expect: Option<&Synced>,
        trash: &mut Trash,
    ) -> Result<bool> {
        let abs = self.abs(rel);
        let parent = abs.parent().ok_or_else(|| Error::new("no parent folder"))?.to_path_buf();
        fsio::mkdir_durable(&parent, 0o755)?;
        let mut staged = fsio::Staged::create_in(&parent, STAGING_PREFIX)?;
        let mut hashing = Hashing {
            out: &mut staged,
            hash: Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?,
        };
        let remote_path = self.remote_path(rel);
        if !self.remote.download(&remote_path, r.version, &mut hashing)? {
            return Ok(false);
        }
        let got_len = hashing.hash.len();
        let got = hashing.hash.finish().map_err(|_| Error::new("SHA-256 failed"))?;
        if got != r.sha256 || got_len != r.size {
            return Err(Error::new(
                "the download did not match the server's SHA-256; nothing was changed",
            ));
        }
        let modified = u64::try_from(r.mtime_ms)
            .ok()
            .map(|ms| std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms));
        staged.finish(modified, 0o644)?;
        match (stat(&abs), expect) {
            (None, _) => {
                if staged.commit_new(&abs).is_err() {
                    // Something appeared at that name meanwhile; leave it.
                    return Ok(false);
                }
            }
            (Some(_), Some(s)) => {
                if !still_matches(&abs, s)? {
                    return Ok(false);
                }
                trash.keep(&abs, rel)?;
                staged.commit_replace(&abs)?;
            }
            (Some(_), None) => return Ok(false),
        }
        let entry = stat(&abs).ok_or_else(|| Error::new("the downloaded file vanished"))?;
        self.state.set_synced(rel, synced_from(&entry, r.version, r.sha256))?;
        Ok(true)
    }

    fn delete_phase(
        &mut self,
        deletes: Vec<Delete>,
        trash: &mut Trash,
        report: &mut Report,
    ) -> Result<()> {
        let files = deletes
            .iter()
            .filter(|d| matches!(d, Delete::LocalFile(_) | Delete::RemoteFile(_)))
            .count();
        let synced_files =
            self.state.state.synced.values().filter(|s| s.kind == Kind::File).count().max(1);
        let o = self.options;
        let too_many = files > o.mass_delete_count
            || (files > o.mass_delete_floor && files * 100 > synced_files * o.mass_delete_percent);
        if too_many && !o.confirm_deletes {
            report.held_deletes = Some(files);
            return Ok(());
        }
        // Deepest first, so a folder is handled after what was in it.
        let mut deletes = deletes;
        deletes.sort_by(|a, b| {
            let key = |d: &Delete| match d {
                Delete::LocalFile(p)
                | Delete::RemoteFile(p)
                | Delete::LocalDir(p)
                | Delete::RemoteDir(p) => p.clone(),
            };
            key(b).cmp(&key(a))
        });
        for d in deletes {
            let result = match &d {
                Delete::LocalFile(rel) => self.delete_local(rel, trash, report),
                Delete::RemoteFile(rel) => self.delete_remote(rel, report),
                Delete::LocalDir(rel) => self.delete_local_dir(rel),
                Delete::RemoteDir(rel) => self.delete_remote_dir(rel),
            };
            if let Err(e) = result {
                if Self::state_failed(&e) {
                    return Err(e);
                }
                let rel = match d {
                    Delete::LocalFile(p)
                    | Delete::RemoteFile(p)
                    | Delete::LocalDir(p)
                    | Delete::RemoteDir(p) => p,
                };
                report.errors.push((rel, e.message().to_owned()));
            }
        }
        Ok(())
    }

    fn delete_local(&mut self, rel: &str, trash: &mut Trash, report: &mut Report) -> Result<()> {
        let abs = self.abs(rel);
        let Some(s) = self.state.state.synced.get(rel).cloned() else { return Ok(()) };
        if stat(&abs).is_none() {
            return self.state.del_synced(rel);
        }
        if !still_matches(&abs, &s)? {
            // Edited since: it will be uploaded next round instead.
            return Ok(());
        }
        trash.take(&abs, rel)?;
        self.state.del_synced(rel)?;
        report.deleted_local.push(rel.to_owned());
        Ok(())
    }

    fn delete_remote(&mut self, rel: &str, report: &mut Report) -> Result<()> {
        // Re-check: the file may have come back since the scan.
        if stat(&self.abs(rel)).is_some() {
            return Ok(());
        }
        self.remote.trash(&self.remote_path(rel))?;
        self.state.del_remote(rel)?;
        self.state.del_synced(rel)?;
        report.deleted_remote.push(rel.to_owned());
        Ok(())
    }

    fn delete_local_dir(&mut self, rel: &str) -> Result<()> {
        if fsio::remove_empty_dir(self.abs(rel))? {
            self.state.del_synced(rel)
        } else {
            // New local files inside: keep the folder on the server too.
            self.remote.mkdir(&self.remote_path(rel))?;
            self.state.set_remote(rel, dir_remote())
        }
    }

    fn delete_remote_dir(&mut self, rel: &str) -> Result<()> {
        let prefix = format!("{rel}/");
        let occupied = self.state.state.remote.keys().any(|k| k.starts_with(&prefix));
        if occupied || stat(&self.abs(rel)).is_some() {
            // Files remain under it on the server: bring the folder back.
            fsio::mkdir_durable(self.abs(rel), 0o755)?;
            return Ok(());
        }
        self.remote.trash(&self.remote_path(rel))?;
        self.state.del_remote(rel)?;
        self.state.del_synced(rel)
    }

    /// Paths known on either side, for status output.
    pub fn summary(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        m.insert("synced", self.state.state.synced.len());
        m.insert("remote", self.state.state.remote.len());
        m
    }

    pub fn folder(&self) -> &Folder {
        &self.folder
    }
}
