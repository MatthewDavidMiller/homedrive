//! Rewinding a folder to how it was at an earlier time.
//!
//! The way back from ransomware, a sync client gone wrong, or a mistake
//! made across many files. Like everything else here, it adds and never
//! takes away:
//! - a file whose content has changed since that time gets the content it
//!   had then as a new version (the versions since stay in its history);
//! - an item deleted since then comes back from the trash, under its old
//!   name if that is free, or else beside it as "<name> (restored ...)";
//! - a file made since then is left as it is, and reported.
//!
//! "The content it had then" is the newest version stored at or before
//! that time. Retention thins old histories, so for a time more than 30
//! days back that may be a little older than the exact moment.
//!
//! Files moved since then stay where they were moved to.
//!
//! [`plan`] decides from the metadata alone, so a preview and the real
//! thing agree. [`Store::rewind`] then carries the plan out one step at a
//! time, checking each against the drive as it is at that moment: a step
//! that something else has overtaken is skipped and reported, never
//! forced.

use std::collections::BTreeMap;

use hd_common::{Error, Result, pathname, timefmt};

use crate::Store;
use crate::model::{Content, Node, Op, Origin, State, Version};

/// The device name recorded on the versions a rewind makes.
pub const DEVICE: &str = "rewind";

/// What a rewind does, or would do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RewindReport {
    /// Files given back the content they had, as a new version.
    pub reverted: Vec<String>,
    /// Deleted items put back: (where they were, where they are now).
    pub undeleted: Vec<(String, String)>,
    /// Files made since that time, left as they are.
    pub newer: Vec<String>,
    /// Steps skipped because the drive changed while the rewind ran.
    pub skipped: Vec<String>,
}

/// A file to give its old content back to: it must still be at `current`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Revert {
    path: String,
    current: u64,
    then: Version,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Plan {
    /// (trash id, where it was), most recently deleted first: a folder is
    /// put back before a file deleted from it earlier, so the file finds
    /// its folder rather than taking the folder's name.
    undelete: Vec<(u64, String)>,
    reverts: Vec<Revert>,
    newer: Vec<String>,
}

/// What file `node` at `path` needs to look as it did at `at_ms`.
fn judge(path: &str, node: &Node, at_ms: i64, plan: &mut Plan) {
    let Node::File { versions, .. } = node else { return };
    let Some(current) = versions.last() else { return };
    if current.created_ms <= at_ms {
        return;
    }
    match versions.iter().rev().find(|v| v.created_ms <= at_ms) {
        None => plan.newer.push(path.to_owned()),
        Some(then) if then.sha256 == current.sha256 => {}
        Some(then) => plan.reverts.push(Revert {
            path: path.to_owned(),
            current: current.id,
            then: then.clone(),
        }),
    }
}

/// What rewinding `user`'s `path` to `at_ms` takes.
fn plan(state: &State, user: &str, path: &str, at_ms: i64) -> Plan {
    let mut plan = Plan::default();
    let Some(ns) = state.user(user) else { return plan };
    // For each place, the first deletion after that time is the one that
    // took what was there then; anything trashed there later was made
    // since.
    let mut first: BTreeMap<&str, (i64, u64)> = BTreeMap::new();
    for item in ns.trash.values() {
        let relevant =
            pathname::is_within(&item.path, path) || pathname::is_within(path, &item.path);
        if item.deleted_ms <= at_ms || !relevant {
            continue;
        }
        let existed_then = item.entries.iter().all(|(_, n)| n.is_dir())
            || item
                .entries
                .iter()
                .any(|(_, n)| matches!(n, Node::File { versions, .. } if versions.iter().any(|v| v.created_ms <= at_ms)));
        if !existed_then {
            continue;
        }
        let slot = first.entry(item.path.as_str()).or_insert((item.deleted_ms, item.id));
        if item.deleted_ms < slot.0 {
            *slot = (item.deleted_ms, item.id);
        }
    }
    let mut undelete: Vec<(i64, u64, String)> =
        first.into_iter().map(|(p, (when, id))| (when, id, p.to_owned())).collect();
    undelete.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, id, original) in &undelete {
        if let Some(item) = ns.trash.get(id) {
            for (rel, node) in &item.entries {
                let p =
                    if rel.is_empty() { original.clone() } else { pathname::join(original, rel) };
                if pathname::is_within(&p, path) {
                    judge(&p, node, at_ms, &mut plan);
                }
            }
        }
    }
    plan.undelete = undelete.into_iter().map(|(_, id, p)| (id, p)).collect();
    for (p, entry) in ns.subtree(path) {
        judge(p, &entry.node, at_ms, &mut plan);
    }
    plan
}

impl Store {
    /// Rewinds `user`'s `path` ("" for the whole drive) to how it was at
    /// `at_ms`. With `apply` false, only reports what it would do.
    pub fn rewind(&self, user: &str, path: &str, at_ms: i64, apply: bool) -> Result<RewindReport> {
        pathname::validate(path)?;
        let now = timefmt::unix_ms();
        if at_ms >= now {
            return Err(Error::new("the time to rewind to must be in the past"));
        }
        let plan = self.read(|st| plan(st, user, path, at_ms));
        let mut report = RewindReport { newer: plan.newer, ..RewindReport::default() };
        if !apply {
            report.undeleted = plan.undelete.iter().map(|(_, p)| (p.clone(), p.clone())).collect();
            report.reverted = plan.reverts.into_iter().map(|r| r.path).collect();
            return Ok(report);
        }
        // Where each put-back item ended up, to find the files inside it.
        let mut moved: Vec<(String, String)> = Vec::new();
        let stamp = {
            let t = timefmt::rfc3339_millis(now / 1000, 0);
            format!("restored {} {}{}", &t[..10], &t[11..13], &t[14..16])
        };
        for (id, original) in plan.undelete {
            let decided = self.commit_with(|st| {
                let Some(ns) = st.user(user) else { return Ok((None, None)) };
                if !ns.trash.contains_key(&id) {
                    return Ok((None, None));
                }
                let mut to = original.clone();
                let mut n = 1;
                loop {
                    let op = Op::Restore { user: user.to_owned(), trash_id: id, to: to.clone() };
                    if st.validate(&op).is_ok() {
                        return Ok((Some(op), Some(to)));
                    }
                    if n > 100 {
                        return Ok((None, None));
                    }
                    let label = if n == 1 { stamp.clone() } else { format!("{stamp} {n}") };
                    to = pathname::suffixed_name(&original, &label);
                    n += 1;
                }
            })?;
            match decided {
                (Some(_), Some(to)) => {
                    if to != original {
                        moved.push((original.clone(), to.clone()));
                    }
                    report.undeleted.push((original, to));
                }
                _ => report.skipped.push(format!("{original}: no longer in the trash")),
            }
        }
        for r in plan.reverts {
            let path_now = moved
                .iter()
                .find_map(|(from, to)| pathname::rebase(&r.path, from, to))
                .unwrap_or_else(|| r.path.clone());
            let content = Content {
                manifest: r.then.manifest,
                size: r.then.size,
                sha256: r.then.sha256,
                mtime_ms: r.then.mtime_ms,
                created_ms: timefmt::unix_ms(),
                device: DEVICE.to_owned(),
                origin: Origin::Restore,
                executable: r.then.executable,
            };
            let (applied, ()) = self.commit_with(|st| {
                let node = st.user(user).and_then(|ns| ns.get(&path_now)).map(|e| &e.node);
                let Some(Node::File { versions, .. }) = node else { return Ok((None, ())) };
                // Changed since the plan was made: that change is newer
                // than anything a rewind knows about, so it stands. The old
                // version must still be in the history it is taken from.
                if versions.last().map(|c| c.id) != Some(r.current)
                    || !versions.iter().any(|v| v.id == r.then.id)
                {
                    return Ok((None, ()));
                }
                let op = Op::PutVersion { user: user.to_owned(), path: path_now.clone(), content };
                Ok((Some(op), ()))
            })?;
            if applied.is_some() {
                report.reverted.push(path_now);
            } else {
                report.skipped.push(format!("{path_now}: changed while rewinding; left as it is"));
            }
        }
        Ok(report)
    }
}
