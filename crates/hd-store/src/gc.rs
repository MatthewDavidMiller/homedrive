//! Releasing what nothing needs any more. This is one of the two places in
//! shipped code allowed to delete files (the client's trash is the other),
//! and everything here deletes only what a rule proves is unneeded.
//!
//! Object collection is mark-and-sweep, never reference counting: a count
//! that drifts by one loses data, while a mark is recomputed from the
//! metadata every time. An unreferenced object is first moved to
//! `gc-trash/<day>/`, and only deleted after the hold period, at which
//! point it is checked against a fresh mark once more.
//!
//! Metadata pruning keeps the newest snapshots and every journal that any
//! of them might need. A journal is deleted only when the next journal
//! starts at or before the record after the oldest kept snapshot, which
//! means every record in it is already inside that snapshot. The newest
//! journal is never deleted.

use std::fs;
use std::path::Path;

use hd_common::Result;
use hd_common::fsio;

use crate::journal;
use crate::meta::{self, snapshot_name};

/// Deletes snapshots older than the newest `keep`, and journals that only
/// hold records the oldest kept snapshot already contains.
pub(crate) fn prune_meta(dir: &Path, keep: usize) -> Result<()> {
    let (snapshots, journals) = meta::listing(dir)?;
    let keep = keep.max(1);
    if snapshots.len() < keep {
        return Ok(());
    }
    let oldest_kept = snapshots[snapshots.len() - keep];
    let mut removed = false;
    for &seq in &snapshots[..snapshots.len() - keep] {
        fs::remove_file(dir.join(snapshot_name(seq)))?;
        removed = true;
    }
    for pair in journals.windows(2) {
        let (first, next_first) = (pair[0], pair[1]);
        if next_first <= oldest_kept + 1 {
            fs::remove_file(dir.join(journal::file_name(first)))?;
            removed = true;
        }
    }
    if removed {
        fsio::sync_directory(dir)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Object garbage collection.
// ---------------------------------------------------------------------------

use std::collections::HashSet;
use std::sync::PoisonError;

use hd_chunk::ObjectId;
use hd_common::Error;

use crate::Store;
use crate::manifest::Manifest;
use crate::objects::Kind;

const DAY_MS: i64 = 86_400_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcOptions {
    /// Objects younger than this are never collected: they may belong to
    /// an upload that has not been committed yet.
    pub grace_ms: i64,
    /// How long a collected object waits in `gc-trash/` before deletion.
    pub hold_ms: i64,
    /// Report what would happen and change nothing.
    pub dry_run: bool,
}

impl Default for GcOptions {
    fn default() -> Self {
        Self { grace_ms: 2 * DAY_MS, hold_ms: 7 * DAY_MS, dry_run: false }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Objects the metadata references.
    pub live: usize,
    /// Unreferenced objects left alone because they are young.
    pub young: usize,
    /// Unreferenced objects moved to `gc-trash/` (stage 1).
    pub moved: usize,
    pub moved_bytes: u64,
    /// Objects deleted from `gc-trash/` after the hold (stage 2).
    pub deleted: usize,
    pub deleted_bytes: u64,
    /// Objects found referenced in `gc-trash/` and put back. Always zero
    /// unless something is wrong; logged loudly when not.
    pub restored: usize,
}

fn mtime_ms(meta: &fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(i64::MAX)
}

fn trash_name(kind: Kind, id: &ObjectId) -> String {
    format!("{}-{id}", kind.name())
}

fn parse_trash_name(name: &str) -> Option<(Kind, ObjectId)> {
    let (kind, id) = name.split_once('-')?;
    let kind = Kind::ALL.into_iter().find(|k| k.name() == kind)?;
    Some((kind, ObjectId::parse(id)?))
}

impl Store {
    /// Every object the metadata needs: each referenced manifest and the
    /// chunks it uses. Any manifest that cannot be read stops the
    /// collection, since its chunks would otherwise look unreferenced.
    fn mark(&self) -> Result<HashSet<(Kind, ObjectId)>> {
        let manifests = self.read(crate::model::State::referenced_manifests);
        let mut live = HashSet::new();
        for m in manifests {
            let used = Manifest::objects_used(self.objects(), &m).map_err(|e| {
                Error::new(format!(
                    "manifest {m} is referenced but unreadable ({e}); not collecting anything"
                ))
            })?;
            live.insert((Kind::Manifest, m));
            live.extend(used.into_iter().map(|c| (Kind::Chunk, c)));
        }
        Ok(live)
    }

    /// Runs one collection as of `now_ms`.
    ///
    /// 1. Commits from now on record the objects they use.
    /// 2. Mark everything the metadata references.
    /// 3. Stage 2: delete objects that have waited in `gc-trash/` past the
    ///    hold, unless they turn out to be referenced, in which case they
    ///    go back.
    /// 4. Stage 1: move each unreferenced object past the grace period into
    ///    `gc-trash/`, unless a commit used it since the mark. Each move
    ///    holds the GC gate's write side, so no commit is half way through.
    pub fn collect_garbage(&self, now_ms: i64, options: &GcOptions) -> Result<GcReport> {
        {
            let _w = self.gc.gate.write().unwrap_or_else(PoisonError::into_inner);
            let mut t = self.gc.touched.lock().unwrap_or_else(PoisonError::into_inner);
            t.active = true;
            t.ids.clear();
        }
        let result = self.collect(now_ms, options);
        let mut t = self.gc.touched.lock().unwrap_or_else(PoisonError::into_inner);
        t.active = false;
        t.ids.clear();
        result
    }

    fn collect(&self, now_ms: i64, options: &GcOptions) -> Result<GcReport> {
        let live = self.mark()?;
        let mut report = GcReport { live: live.len(), ..GcReport::default() };
        let objects = self.objects();
        let trash_root = objects.root().join("gc-trash");
        if !options.dry_run {
            fsio::mkdir_durable(&trash_root, 0o700)?;
        }

        // Stage 2.
        let today = now_ms.div_euclid(DAY_MS);
        let mut days: Vec<(i64, std::path::PathBuf)> = Vec::new();
        if let Ok(entries) = fs::read_dir(&trash_root) {
            for e in entries {
                let e = e?;
                if let Some(day) = e.file_name().to_str().and_then(|n| n.parse::<i64>().ok()) {
                    days.push((day, e.path()));
                }
            }
        }
        days.sort();
        for (day, dir) in days {
            if (today - day) * DAY_MS < options.hold_ms {
                continue;
            }
            for e in fs::read_dir(&dir)? {
                let e = e?;
                let path = e.path();
                let Some((kind, id)) = e.file_name().to_str().and_then(parse_trash_name) else {
                    eprintln!("hd-store: gc: ignoring stray {}", path.display());
                    continue;
                };
                let len = e.metadata()?.len();
                if live.contains(&(kind, id)) && !objects.contains(kind, &id) {
                    eprintln!(
                        "hd-store: gc: {} {id} in gc-trash is referenced; putting it back",
                        kind.name()
                    );
                    if !options.dry_run {
                        let to = objects.path(kind, &id);
                        if let Some(parent) = to.parent() {
                            fsio::mkdir_durable(parent, 0o700)?;
                        }
                        fsio::move_new_durable(&path, &to)?;
                    }
                    report.restored += 1;
                    continue;
                }
                if !options.dry_run {
                    fs::remove_file(&path)?;
                }
                report.deleted += 1;
                report.deleted_bytes += len;
            }
            if !options.dry_run {
                fsio::sync_directory(&dir)?;
                if fs::read_dir(&dir)?.next().is_none() {
                    fs::remove_dir(&dir)?;
                    fsio::sync_directory(&trash_root)?;
                }
            }
        }

        // Stage 1.
        let day_dir = trash_root.join(today.to_string());
        for kind in Kind::ALL {
            objects.for_each(kind, |id, path, meta| {
                if live.contains(&(kind, id)) {
                    return Ok(());
                }
                if now_ms.saturating_sub(mtime_ms(meta)) < options.grace_ms {
                    report.young += 1;
                    return Ok(());
                }
                let _w = self.gc.gate.write().unwrap_or_else(PoisonError::into_inner);
                let touched = self
                    .gc
                    .touched
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .ids
                    .contains(&id);
                if touched {
                    return Ok(());
                }
                if !options.dry_run {
                    fsio::mkdir_durable(&day_dir, 0o700)?;
                    let to = day_dir.join(trash_name(kind, &id));
                    if fs::symlink_metadata(&to).is_ok() {
                        // Collected once today already, re-uploaded, and
                        // unreferenced again: the older copy is identical.
                        return Ok(());
                    }
                    fsio::move_new_durable(path, &to)?;
                }
                report.moved += 1;
                report.moved_bytes += meta.len();
                Ok(())
            })?;
        }
        Ok(report)
    }
}
