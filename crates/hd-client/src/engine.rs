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
//! - A local file is replaced or deleted by first moving whatever is at
//!   its name into the client trash (`trash`), and only then checking that
//!   what was moved still matches S (same size, time and inode, or the
//!   same SHA-256). If it does not, it goes back. Checking first and moving
//!   second would leave a moment in which an editor's save could land and
//!   then be overwritten. The old content is also kept on the server, in
//!   the version history and trash.
//! - A size, time and inode taken within a few seconds of the file's last
//!   change is not trusted to prove it unchanged later: a second write in
//!   the same timestamp tick (coarse clocks, FAT's 2 s) would leave all
//!   three as they were. Such a file is compared by content next time.
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
//! - **Ransomware guard.** Changes to existing files are uploaded after
//!   the round has seen them all. Many at once (counting the last hour),
//!   or several that turned a file's content random (see `suspect`), are
//!   held back until confirmed, so encrypted copies never replace good
//!   ones on the server and the other computers. While encryption is
//!   suspected, every deletion is held too.
//! - **Local damage.** Files are re-read slowly in the background and
//!   compared with what was synced. One whose content changed although
//!   nothing wrote to it (its size, time and inode are as recorded) was
//!   damaged by this computer's disk: the server's copy takes its place,
//!   and the damaged copy is kept in `.homedrive/damaged/`.
//!
//! **Healing the server.** The server may lose part of a file to a failing
//! disk. It lists such current versions (`GET /api/v1/damaged`), and a
//! client whose copy is that exact version uploads it again. The upload
//! commits nothing new, but it replaces the missing pieces. The copy is
//! first re-hashed in full against the version's SHA-256: size and time
//! cannot vouch for content here, and local bit rot must never be sent as a
//! repair.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use hd_api::{BaseSpec, ChangeInfo, CommitRequest, CommitResult};
use hd_chunk::{Chunker, ObjectId};
use hd_common::{Error, Result, fsio, pathname, suspect, timefmt};
use hd_crypto::Sha256;

use crate::control::{LOCK, Request, Status};
use crate::remote::{CommitOutcome, Expect, Remote, Trashed};
use crate::scan::{self, LocalEntry, SENTINEL, STAGING_PREFIX};
use crate::state::{Kind, Persisted, RemoteEntry, Synced};
use crate::trash::{DAMAGED_DIR, Trash};

/// Files below this are kept in memory between hashing and uploading.
const KEEP_IN_MEMORY: u64 = 16 * 1024 * 1024;

/// A file changed less than this long before its size, time and inode
/// were recorded may change again without any of them moving.
const RACY_NS: i64 = 3_000_000_000;

/// The recorded time of a file whose stat cannot be trusted; it matches
/// no real time, so the next comparison reads the content.
const UNTRUSTED_MTIME: i64 = i64::MIN;

/// The window over which changes are counted for the ransomware guard.
const CHANGE_WINDOW_MS: i64 = 3_600_000;

/// The most background verification may save up while idle.
const MAX_VERIFY_CREDIT: f64 = 1024.0 * 1024.0 * 1024.0;

/// The moments at which the engine acts on a local file it has just
/// checked, for tests that race an edit against it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// A downloaded version is about to take the file's name.
    BeforeReplace,
    /// A file deleted on the server is about to go to the client trash.
    BeforeLocalDelete,
    /// The file was just moved into the client trash and its name is
    /// empty, before the moved file is checked.
    NameVacant,
    /// An uploaded file passed its last check and is about to be committed.
    BeforeCommit,
    /// A file deleted here is about to be deleted on the server.
    BeforeRemoteDelete,
}

/// Called at each [`Moment`] with the file's path. Tests only.
pub type Hook = Box<dyn FnMut(Moment, &Path) + Send>;

struct Hooks(Option<Hook>);

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() { "Hooks(set)" } else { "Hooks(none)" })
    }
}

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
    /// Upload this round's changes even if there are many.
    pub confirm_changes: bool,
    /// More changes to existing files than this within an hour need
    /// confirming...
    pub mass_change_count: usize,
    /// ...as do more than this percentage of the synced files, once there
    /// are more than `mass_change_floor`.
    pub mass_change_percent: usize,
    pub mass_change_floor: usize,
    /// This many changes within an hour that look like encryption hold
    /// every change and deletion until confirmed.
    pub suspicious_limit: usize,
    /// Every synced file is re-read and checked against its recorded
    /// content about once in this many days (0: never in the background).
    pub verify_days: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            confirm_deletes: false,
            mass_delete_count: 50,
            mass_delete_percent: 20,
            mass_delete_floor: 10,
            confirm_changes: false,
            mass_change_count: 100,
            mass_change_percent: 25,
            mass_change_floor: 20,
            suspicious_limit: 10,
            verify_days: 14,
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
    /// Changes to existing files held back for confirmation.
    pub held_changes: Option<usize>,
    /// Of this round's changes, how many looked like encryption.
    pub suspicious: usize,
    /// Enough changes looked like encryption to hold everything back.
    pub ransomware_suspected: bool,
    /// Files found damaged on this computer's disk and replaced with the
    /// server's copy (the damaged copy is in `.homedrive/damaged/`).
    pub repaired_local: Vec<String>,
    /// Files re-read and checked against their recorded content.
    pub verified: usize,
    /// A check of every file, asked for, finished this round.
    pub verified_all: bool,
    /// The server's history changed (it was restored from a backup), so
    /// this round compared everything afresh.
    pub server_restored: bool,
    /// Files whose lost pieces this client sent the server again.
    pub healed: Vec<String>,
}

impl Report {
    pub fn changed_anything(&self) -> bool {
        !(self.uploaded.is_empty()
            && self.downloaded.is_empty()
            && self.deleted_local.is_empty()
            && self.deleted_remote.is_empty()
            && self.conflicts.is_empty()
            && self.repaired_local.is_empty())
    }
}

/// Background verification's place and budget.
#[derive(Debug, Default)]
struct Verify {
    /// The last path checked; the next round goes on after it.
    after: Option<String>,
    /// Bytes it may read now, saved up at the rate that covers every file
    /// once in `verify_days`. Negative after checking a file larger than
    /// was saved up.
    credit: f64,
    last: Option<Instant>,
    /// A check of everything was asked for and is under way.
    full: bool,
}

#[derive(Debug)]
pub struct Engine {
    folder: Folder,
    remote: Remote,
    pub state: Persisted,
    pub options: Options,
    hooks: Hooks,
    /// Set by `pull` when the server's history changed; reported once.
    server_restored: bool,
    /// Held while this engine exists: one process syncs a folder.
    _lock: fs::File,
    /// The files whose changes were uploaded in the last hour: when, and
    /// whether the change looked like encryption. Files, not uploads, are
    /// counted: a document saved every minute is one file.
    recent: BTreeMap<String, (i64, bool)>,
    verify: Verify,
    /// What the last status written said.
    last_status: Option<Status>,
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

/// The time to record for a file last changed at `mtime_ns`: the time
/// itself, or [`UNTRUSTED_MTIME`] if a further change could still go
/// unseen (see [`RACY_NS`]). A time in the future is untrusted too.
fn recorded_mtime(mtime_ns: i64) -> i64 {
    let now_ns = timefmt::unix_ms().saturating_mul(1_000_000);
    if mtime_ns > now_ns.saturating_sub(RACY_NS) { UNTRUSTED_MTIME } else { mtime_ns }
}

/// The permissions of a folder, for one made inside it.
fn dir_mode(parent: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(parent).map_or(0o700, |m| m.permissions().mode() & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        0o700
    }
}

/// The permissions for a downloaded file: those of the file it replaces,
/// or else its folder's without the execute bits. A file kept private on
/// one machine must not arrive readable by everyone on another, and a
/// download must never widen the permissions of a file it replaces.
fn file_mode(abs: &Path, parent: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::symlink_metadata(abs) {
            Ok(m) if m.is_file() => m.permissions().mode() & 0o777,
            _ => dir_mode(parent) & 0o666,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (abs, parent);
        0o600
    }
}

fn synced_from(entry: &LocalEntry, version: u64, sha256: [u8; 32]) -> Synced {
    Synced {
        kind: entry.kind,
        version,
        sha256,
        size: entry.size,
        mtime_ns: recorded_mtime(entry.mtime_ns),
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
    /// Opens the folder for syncing; fails if another process is syncing
    /// it.
    pub fn open(folder: Folder, remote: Remote, options: Options) -> Result<Self> {
        let local = folder.local.clone();
        Self::try_open(folder, remote, options)?.ok_or_else(|| {
            Error::new(format!(
                "another homedrive process (the daemon?) is syncing {} now",
                local.display()
            ))
        })
    }

    /// [`Engine::open`], or `None` if another process is syncing the
    /// folder.
    pub fn try_open(folder: Folder, remote: Remote, options: Options) -> Result<Option<Self>> {
        fsio::mkdir_durable(&folder.state_dir, 0o700)?;
        let Some(lock) = fsio::lock_exclusive(folder.state_dir.join(LOCK))? else {
            return Ok(None);
        };
        let state = Persisted::open(&folder.state_dir)?;
        Ok(Some(Self {
            folder,
            remote,
            state,
            options,
            hooks: Hooks(None),
            server_restored: false,
            _lock: lock,
            recent: BTreeMap::new(),
            verify: Verify::default(),
            last_status: None,
        }))
    }

    /// Creates a folder (and any missing parents) with its parent's
    /// permissions, so a private synced folder stays private.
    fn make_dir(&self, abs: &Path) -> Result<()> {
        if abs.is_dir() {
            return Ok(());
        }
        if let Some(parent) = abs.parent().filter(|p| *p != self.folder.local.as_path()) {
            self.make_dir(parent)?;
        }
        let mode = abs.parent().map_or(0o700, dir_mode);
        fsio::mkdir_durable(abs, mode)
    }

    /// Sets a function to call at each [`Moment`]. Tests only.
    pub fn set_hook(&mut self, hook: Hook) {
        self.hooks = Hooks(Some(hook));
    }

    fn moment(&mut self, moment: Moment, abs: &Path) {
        if let Some(hook) = &mut self.hooks.0 {
            hook(moment, abs);
        }
    }

    /// Moves the file at `rel` into the client trash if it still matches
    /// `s`. Moving first and checking the moved file second means a save
    /// that lands at any moment is either moved and then put back, or
    /// lands after the move at the empty name and is left alone; checking
    /// first could see the old file and then move away the new one.
    /// `Ok(false)` if the file changed (it is back in place); an error if it
    /// changed and something new took its name meanwhile, in which case the
    /// changed copy stays in the trash.
    fn take_if_unchanged(
        &mut self,
        abs: &Path,
        rel: &str,
        s: &Synced,
        trash: &mut Trash,
    ) -> Result<bool> {
        let taken = trash.take(abs, rel)?;
        self.moment(Moment::NameVacant, abs);
        if still_matches(&taken, s)? {
            return Ok(true);
        }
        if fsio::move_new_durable(&taken, abs).is_err() {
            return Err(Error::new(format!(
                "changed while being replaced, and a new file took its name; the changed copy is \
                 kept at {}",
                taken.display()
            )));
        }
        Ok(false)
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
            let known = &self.state.state.history;
            if !page.reset && !known.is_empty() && *known != page.history {
                // A different history: this page continues it from a point
                // that means nothing here. Forget this client's view and
                // read the new history from its start.
                eprintln!(
                    "homedrive: the server's history has changed (restored from a backup?); \
                     comparing everything afresh, with no deletions"
                );
                self.state.reset()?;
                self.state.set_history(&page.history)?;
                self.server_restored = true;
                cursor = 0;
                changed = true;
                continue;
            }
            if page.reset {
                eprintln!(
                    "homedrive: the server's history is behind this client's (restored from a \
                     backup?); comparing everything afresh, with no deletions"
                );
                self.state.reset()?;
                self.server_restored = true;
            }
            self.state.set_history(&page.history)?;
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

    /// One full round: pull the server's changes, scan, reconcile; then
    /// say what needs the user in the folder's status.
    pub fn sync(&mut self, wait_s: u64) -> Result<Report> {
        let request = Request::read(&self.folder.state_dir);
        let report = self.round(wait_s, request.as_ref())?;
        if request.is_some() {
            Request::clear(&self.folder.state_dir)?;
        }
        let status = Status::of(&report);
        if !self.last_status.as_ref().is_some_and(|s| s.same_as(&status)) {
            status.write(&self.folder.state_dir)?;
            self.last_status = Some(status);
        }
        Ok(report)
    }

    fn round(&mut self, wait_s: u64, request: Option<&Request>) -> Result<Report> {
        self.check_root()?;
        self.pull(wait_s)?;
        self.check_root()?;
        let scanned = scan::scan(&self.folder.local, &self.folder.ignore)?;
        let mut report = Report {
            skipped: scanned.skipped.clone(),
            server_restored: std::mem::take(&mut self.server_restored),
            ..Report::default()
        };
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
        // On a case-insensitive filesystem (Windows, macOS) two server paths
        // that differ only in case would land on one local file, and on
        // Windows some names cannot exist at all. Such paths are left alone
        // and reported; nothing is renamed behind the user's back.
        let mut unsafe_here = BTreeSet::new();
        if cfg!(any(windows, target_os = "macos")) {
            let mut seen: BTreeMap<String, &String> = BTreeMap::new();
            for rel in &paths {
                if let Some(other) = seen.insert(pathname::fold_key(rel), rel) {
                    for p in [other, rel] {
                        if unsafe_here.insert(p.clone()) {
                            report.skipped.push((
                                p.clone(),
                                "another path differs only in letter case; rename one".into(),
                            ));
                        }
                    }
                }
            }
        }
        if cfg!(windows) {
            for rel in &paths {
                if let Some(why) = rel.split('/').find_map(pathname::windows_problem)
                    && unsafe_here.insert(rel.clone())
                {
                    report.skipped.push((rel.clone(), format!("the name {why}")));
                }
            }
        }
        let mut deletes = Vec::new();
        let mut edits = Vec::new();
        for rel in &paths {
            if unsafe_here.contains(rel) || scanned.is_protected(rel) {
                continue;
            }
            // A path that matches an ignore pattern now is left alone on
            // both sides, even if it was synced before the pattern was
            // added: ignoring a file must never delete it anywhere.
            let is_dir = [
                scanned.entries.get(rel).map(|e| e.kind),
                self.state.state.synced.get(rel).map(|s| s.kind),
                self.state.state.remote.get(rel).map(|r| r.kind),
            ]
            .contains(&Some(Kind::Dir));
            if scan::ignored(rel, is_dir, &self.folder.ignore) {
                continue;
            }
            let s = self.state.state.synced.get(rel).cloned();
            let l = scanned.entries.get(rel).copied();
            let r = self.state.state.remote.get(rel).cloned();
            // A path skipped because something above it was refused or not
            // synced stays untouched.
            let lists = (&mut deletes, &mut edits);
            if let Err(e) = self.reconcile(rel, s, l, r, &mut trash, &mut report, lists) {
                if Self::state_failed(&e) {
                    return Err(e);
                }
                report.errors.push((rel.clone(), e.message().to_owned()));
            }
        }
        let suspected = self.change_phase(edits, request.map(|r| r.changes), &mut report)?;
        self.delete_phase(deletes, &mut trash, &mut report, request.map(|r| r.deletes), suspected)?;
        self.verify_some(&mut report, request.is_some_and(|r| r.verify))?;
        self.heal_server(&mut report)?;
        Ok(report)
    }

    /// Uploads the round's changes to existing files, unless there are so
    /// many, or so many look like encryption, that they need confirming.
    /// `allowed` is how many the user confirmed. Returns whether
    /// encryption is suspected (and not confirmed), which holds deletions
    /// too.
    fn change_phase(
        &mut self,
        edits: Vec<(String, u64)>,
        allowed: Option<usize>,
        report: &mut Report,
    ) -> Result<bool> {
        let now = timefmt::unix_ms();
        self.recent.retain(|_, (t, _)| now - *t <= CHANGE_WINDOW_MS);
        let flags: Vec<bool> =
            edits.iter().map(|(rel, base)| self.looks_encrypted(rel, *base)).collect();
        let n = edits.len();
        let k = flags.iter().filter(|f| **f).count();
        report.suspicious = k;
        // Distinct files changed within the window, this round's included.
        let mut window: BTreeMap<&str, bool> =
            self.recent.iter().map(|(p, (_, s))| (p.as_str(), *s)).collect();
        for ((rel, _), flag) in edits.iter().zip(&flags) {
            let seen = window.entry(rel.as_str()).or_insert(false);
            *seen |= *flag;
        }
        let total = window.len();
        let suspicious = window.values().filter(|s| **s).count();
        let synced_files =
            self.state.state.synced.values().filter(|s| s.kind == Kind::File).count().max(1);
        let o = self.options;
        let too_many = total > o.mass_change_count
            || (total > o.mass_change_floor && total * 100 > synced_files * o.mass_change_percent);
        let suspected = suspicious >= o.suspicious_limit;
        let confirmed = o.confirm_changes || allowed.is_some_and(|a| n <= a);
        if confirmed {
            // What the user approved starts the count afresh.
            self.recent.clear();
        } else if (too_many || suspected) && n > 0 {
            report.held_changes = Some(n);
            report.ransomware_suspected = suspected;
            return Ok(suspected);
        } else if suspected {
            report.ransomware_suspected = true;
            return Ok(true);
        }
        for ((rel, base), flag) in edits.into_iter().zip(flags) {
            match self.upload(&rel, BaseSpec::Version(base), report) {
                Ok(Some(_)) => {
                    let seen = self.recent.entry(rel).or_insert((now, false));
                    *seen = (now, seen.1 | flag);
                }
                Ok(None) => {}
                Err(e) if Self::state_failed(&e) => return Err(e),
                Err(e) => report.errors.push((rel, e.message().to_owned())),
            }
        }
        Ok(false)
    }

    /// Whether the change to `rel` since version `base` looks like
    /// encryption. Anything that cannot be told (a read error, an old
    /// version gone) counts as not.
    fn looks_encrypted(&mut self, rel: &str, base: u64) -> bool {
        let new = fsio::open_nofollow(self.abs(rel)).map_err(Error::from).and_then(|mut f| {
            let len = f.metadata()?.len().min(suspect::SAMPLE as u64);
            fsio::read_at_bounded(&mut f, 0, usize::try_from(len).unwrap_or(0), suspect::SAMPLE)
        });
        let Ok(new) = new else { return false };
        if !suspect::looks_random(&new) {
            return false;
        }
        match self.remote.head(&self.remote_path(rel), base, suspect::SAMPLE) {
            Ok(Some(old)) => suspect::turned_random(&old, &new),
            _ => false,
        }
    }

    /// Re-reads some synced files and checks them against what was
    /// recorded, at a pace that covers every file once in `verify_days`
    /// (or all of them now, if `full`). A file whose content changed
    /// although its size, time and inode did not was damaged by the disk:
    /// the server's copy replaces it, and the damaged copy is kept.
    fn verify_some(&mut self, report: &mut Report, full: bool) -> Result<()> {
        if full && !self.verify.full {
            self.verify.full = true;
            self.verify.after = None;
        }
        if self.options.verify_days == 0 && !self.verify.full {
            return Ok(());
        }
        let now = Instant::now();
        let files: Vec<(String, Synced)> = {
            let synced = &self.state.state.synced;
            let rest: Box<dyn Iterator<Item = (&String, &Synced)>> = match &self.verify.after {
                Some(a) => Box::new(synced.range::<str, _>((
                    std::ops::Bound::Excluded(a.as_str()),
                    std::ops::Bound::Unbounded,
                ))),
                None => Box::new(synced.iter()),
            };
            rest.filter(|(_, s)| s.kind == Kind::File)
                .map(|(p, s)| (p.clone(), s.clone()))
                .collect()
        };
        let budget = if self.verify.full {
            f64::INFINITY
        } else {
            #[allow(clippy::cast_precision_loss)]
            let total = self
                .state
                .state
                .synced
                .values()
                .filter(|s| s.kind == Kind::File)
                .map(|s| s.size as f64)
                .sum::<f64>();
            #[allow(clippy::cast_precision_loss)]
            let rate = total / (self.options.verify_days.max(1) * 86_400) as f64;
            let elapsed = self.verify.last.map_or(0.0, |t| now.duration_since(t).as_secs_f64());
            self.verify.credit = (self.verify.credit + elapsed * rate).min(MAX_VERIFY_CREDIT);
            self.verify.credit
        };
        self.verify.last = Some(now);
        let mut damaged = Trash::in_dir(&self.folder.local, DAMAGED_DIR)?;
        let mut spent = 0.0;
        let mut finished = true;
        for (rel, s) in files {
            #[allow(clippy::cast_precision_loss)]
            let size = s.size as f64;
            // A file larger than what is saved up is still checked when
            // the budget is positive; the debt then delays the next ones.
            if spent + size > budget && (spent > 0.0 || budget <= 0.0) {
                finished = false;
                break;
            }
            self.verify.after = Some(rel.clone());
            let Some(r) = self.state.state.remote.get(&rel).cloned() else { continue };
            if r.version != s.version
                || s.mtime_ns == UNTRUSTED_MTIME
                || scan::ignored(&rel, false, &self.folder.ignore)
            {
                continue;
            }
            let abs = self.abs(&rel);
            let Some(before) = stat(&abs) else { continue };
            let unchanged = |e: &LocalEntry| {
                e.kind == Kind::File
                    && e.size == s.size
                    && e.mtime_ns == s.mtime_ns
                    && e.ino == s.ino
                    && e.dev == s.dev
            };
            if !unchanged(&before) {
                // Changed in the ordinary way: the next round's business.
                continue;
            }
            spent += size;
            report.verified += 1;
            let sha = match hash_file(&abs) {
                Ok((sha, _)) => sha,
                Err(e) => {
                    report.errors.push((
                        rel,
                        format!("cannot be read from this computer's disk ({e}); left alone"),
                    ));
                    continue;
                }
            };
            if sha == s.sha256 || stat(&abs) != Some(before) {
                continue;
            }
            // Read once more: a flaky read (failing memory, a cable) is not
            // the same as damage on the disk, and nothing is replaced on it.
            if hash_file(&abs).map(|(again, _)| again) != Ok(sha) {
                report.errors.push((
                    rel,
                    "reads back differently each time; this computer's memory or disk may be \
                     failing. Left alone"
                        .into(),
                ));
                continue;
            }
            match self.download(&rel, &r, Some(&s), &mut damaged) {
                Ok(true) => report.repaired_local.push(rel),
                Ok(false) => {}
                Err(e) if Self::state_failed(&e) => return Err(e),
                Err(e) => report.errors.push((
                    rel,
                    format!(
                        "damaged on this computer's disk, and the server's copy could not \
                         replace it ({e}); left alone"
                    ),
                )),
            }
        }
        if !self.verify.full {
            self.verify.credit -= spent;
        }
        if finished {
            self.verify.after = None;
            if self.verify.full {
                self.verify.full = false;
                self.verify.credit = 0.0;
                report.verified_all = true;
            }
        }
        Ok(())
    }

    /// Uploads again any file the server lists as damaged that this client
    /// holds at exactly that version.
    fn heal_server(&mut self, report: &mut Report) -> Result<()> {
        // An older server without the call, or a passing error: next round.
        let Ok(damaged) = self.remote.damaged() else { return Ok(()) };
        for (path, version) in damaged {
            let Some(rel) = self.local_rel(&path).map(str::to_owned) else { continue };
            let Some(s) = self.state.state.synced.get(&rel).cloned() else { continue };
            let remote_version = self.state.state.remote.get(&rel).map(|r| r.version);
            if s.version != version || remote_version != Some(version) {
                continue;
            }
            match hash_file(&self.abs(&rel)) {
                Ok((sha, size)) if sha == s.sha256 && size == s.size => {}
                _ => continue,
            }
            match self.upload(&rel, BaseSpec::Version(version), report) {
                Ok(Some(r)) if r.unchanged => report.healed.push(rel),
                Ok(_) => {}
                Err(e) if Self::state_failed(&e) => return Err(e),
                Err(e) => {
                    report.errors.push((rel, format!("re-sending to repair the server: {e}")));
                }
            }
        }
        Ok(())
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
        (deletes, edits): (&mut Vec<Delete>, &mut Vec<(String, u64)>),
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
                        updated.mtime_ns = recorded_mtime(e.mtime_ns);
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
                    // Uploaded once the round has seen every change.
                    edits.push((rel.to_owned(), s.version));
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
                self.make_dir(&self.abs(rel))?;
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
        self.moment(Moment::BeforeCommit, &abs);
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
        self.make_dir(&parent)?;
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
        staged.finish(modified, file_mode(&abs, &parent))?;
        self.moment(Moment::BeforeReplace, &abs);
        match (stat(&abs), expect) {
            (None, _) => {}
            (Some(_), Some(s)) => {
                if !self.take_if_unchanged(&abs, rel, s, trash)? {
                    return Ok(false);
                }
            }
            (Some(_), None) => return Ok(false),
        }
        // Never replaces: a file that appeared at the name since is left
        // alone, and the next round compares it afresh.
        if staged.commit_new(&abs).is_err() {
            return Ok(false);
        }
        let entry = stat(&abs).ok_or_else(|| Error::new("the downloaded file vanished"))?;
        self.state.set_synced(rel, synced_from(&entry, r.version, r.sha256))?;
        Ok(true)
    }

    /// Carries out the round's deletions, unless there are so many that
    /// they need confirming (`allowed` is how many the user confirmed), or
    /// encryption is `suspected`, which holds any.
    fn delete_phase(
        &mut self,
        deletes: Vec<Delete>,
        trash: &mut Trash,
        report: &mut Report,
        allowed: Option<usize>,
        suspected: bool,
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
        let confirmed = o.confirm_deletes || allowed.is_some_and(|a| files <= a);
        if (too_many || (suspected && files > 0)) && !confirmed {
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
        self.moment(Moment::BeforeLocalDelete, &abs);
        if stat(&abs).is_none() {
            return self.state.del_synced(rel);
        }
        if !self.take_if_unchanged(&abs, rel, &s, trash)? {
            // Edited since: it will be uploaded next round instead.
            return Ok(());
        }
        self.state.del_synced(rel)?;
        report.deleted_local.push(rel.to_owned());
        Ok(())
    }

    fn delete_remote(&mut self, rel: &str, report: &mut Report) -> Result<()> {
        // Re-check: the file may have come back since the scan.
        if stat(&self.abs(rel)).is_some() {
            return Ok(());
        }
        let Some(version) = self.state.state.synced.get(rel).map(|s| s.version) else {
            return Ok(());
        };
        self.moment(Moment::BeforeRemoteDelete, &self.abs(rel));
        // Only the version this client last saw: another machine may have
        // committed a newer one since, and an edit beats a delete.
        if self.remote.trash(&self.remote_path(rel), Expect::Version(version))? == Trashed::Changed
        {
            return Ok(());
        }
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
        // The server checks emptiness too, at the moment of deleting: this
        // client's view of the folder may be behind another machine's.
        if occupied
            || stat(&self.abs(rel)).is_some()
            || self.remote.trash(&self.remote_path(rel), Expect::EmptyFolder)? == Trashed::Changed
        {
            // Files remain under it on the server: bring the folder back.
            self.make_dir(&self.abs(rel))?;
            return Ok(());
        }
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
