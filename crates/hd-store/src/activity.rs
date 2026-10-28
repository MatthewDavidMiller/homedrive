//! Unusual activity in a drive: the server's own ransomware alarm.
//!
//! The sync client guards its own uploads, but WebDAV clients (rclone, a
//! phone app, a file manager) and the web UI have no such guard. So the
//! server looks at what happened to each drive, from the metadata alone:
//! - files changed in place (a new version over an older one, uploaded);
//! - files deleted (moved to the trash);
//! - changes that look like encryption: the new content looks random and
//!   the old did not, or the old began with a known format's signature
//!   that the new lacks (`hd_common::suspect`).
//!
//! Distinct files are counted within any one-hour window of the last
//! week. More than [`AlertPolicy::changed`] changed files,
//! [`AlertPolicy::deleted`] deleted ones, or [`AlertPolicy::suspicious`]
//! encrypted-looking ones raise an alert for that drive.
//!
//! Imports (the homelab's backups), restores and rewinds, and copies are
//! not counted: they are the server's own doing, or add without replacing.
//!
//! Because it is worked out from the metadata, an alert survives a restart
//! and needs no state of its own. Only its dismissal does: activity at or
//! before the time a drive's alert was dismissed is not counted again.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use hd_chunk::ObjectId;
use hd_common::suspect;

use crate::Store;
use crate::model::{Node, Origin, Version};

const HOUR_MS: i64 = 3_600_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlertPolicy {
    pub window_ms: i64,
    /// How far back activity is looked at.
    pub lookback_ms: i64,
    /// More changed files than this within the window raise an alert...
    pub changed: usize,
    /// ...as do more deleted files than this...
    pub deleted: usize,
    /// ...or this many changes that look like encryption.
    pub suspicious: usize,
}

impl Default for AlertPolicy {
    fn default() -> Self {
        Self {
            window_ms: HOUR_MS,
            lookback_ms: 7 * 24 * HOUR_MS,
            changed: 200,
            deleted: 200,
            suspicious: 10,
        }
    }
}

/// A drive's unusual activity: the busiest window's counts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub user: String,
    /// From the first to the last event of the windows that crossed a
    /// limit.
    pub from_ms: i64,
    pub to_ms: i64,
    pub changed: usize,
    pub deleted: usize,
    pub suspicious: usize,
}

enum Event {
    Change { path: String, version: u64, old: ObjectId, new: ObjectId },
    Delete { files: usize },
}

/// Up to `suspect::SAMPLE` bytes from the start of a stored file.
fn head(store: &Store, manifest: &ObjectId) -> Option<Vec<u8>> {
    let mut reader = store.open_content(manifest).ok()?;
    let mut out = vec![0_u8; suspect::SAMPLE];
    let mut filled = 0;
    while filled < out.len() {
        match reader.read(&mut out[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    out.truncate(filled);
    Some(out)
}

/// Changes among `versions` (oldest first) after `floor`, as events.
fn changes(path: &str, versions: &[Version], floor: i64, now: i64, out: &mut Vec<(i64, Event)>) {
    for pair in versions.windows(2) {
        let (old, new) = (&pair[0], &pair[1]);
        if new.origin == Origin::Upload && new.created_ms > floor && new.created_ms <= now {
            out.push((
                new.created_ms,
                Event::Change {
                    path: path.to_owned(),
                    version: new.id,
                    old: old.manifest,
                    new: new.manifest,
                },
            ));
        }
    }
}

impl Store {
    /// The drives with unusual activity in the last `policy.lookback_ms`.
    /// `since` is, per user, the time their last alert was dismissed.
    /// `verdicts` caches, by version, whether a change looked like
    /// encryption; the caller keeps it between calls.
    pub fn activity_alerts(
        &self,
        now_ms: i64,
        policy: &AlertPolicy,
        since: &BTreeMap<String, i64>,
        verdicts: &mut HashMap<u64, bool>,
    ) -> Vec<Alert> {
        let per_user: Vec<(String, Vec<(i64, Event)>)> = self.read(|st| {
            st.users
                .iter()
                .map(|(user, ns)| {
                    let floor = (now_ms - policy.lookback_ms)
                        .max(since.get(user).copied().unwrap_or(i64::MIN));
                    let mut events = Vec::new();
                    for (path, e) in &ns.entries {
                        if let Node::File { versions, .. } = &e.node {
                            changes(path, versions, floor, now_ms, &mut events);
                        }
                    }
                    for item in ns.trash.values() {
                        for (rel, node) in &item.entries {
                            if let Node::File { versions, .. } = node {
                                let path = if rel.is_empty() {
                                    item.path.clone()
                                } else {
                                    format!("{}/{rel}", item.path)
                                };
                                changes(&path, versions, floor, now_ms, &mut events);
                            }
                        }
                        if item.deleted_ms > floor && item.deleted_ms <= now_ms {
                            let files = item.entries.iter().filter(|(_, n)| !n.is_dir()).count();
                            events.push((item.deleted_ms, Event::Delete { files }));
                        }
                    }
                    events.sort_by_key(|(at, _)| *at);
                    (user.clone(), events)
                })
                .collect()
        });
        let mut alerts = Vec::new();
        for (user, events) in per_user {
            // Whether each change looked like encryption, read outside the
            // metadata lock and remembered.
            let flags: Vec<bool> = events
                .iter()
                .map(|(_, e)| match e {
                    Event::Change { version, old, new, .. } => {
                        *verdicts.entry(*version).or_insert_with(|| {
                            let Some(n) = head(self, new) else { return false };
                            suspect::looks_random(&n)
                                && head(self, old).is_some_and(|o| suspect::turned_random(&o, &n))
                        })
                    }
                    Event::Delete { .. } => false,
                })
                .collect();
            if let Some(alert) = window(&user, &events, &flags, policy) {
                alerts.push(alert);
            }
        }
        alerts
    }
}

/// Slides a window over `events` (in time order) and reports the busiest
/// counts, if any window crossed a limit.
fn window(
    user: &str,
    events: &[(i64, Event)],
    flags: &[bool],
    policy: &AlertPolicy,
) -> Option<Alert> {
    // Per path: changes in the window, and how many looked encrypted.
    let mut paths: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut suspicious = 0;
    let mut deleted = 0;
    let mut start = 0;
    let mut alert: Option<Alert> = None;
    for (end, (at, event)) in events.iter().enumerate() {
        match event {
            Event::Change { path, .. } => {
                let slot = paths.entry(path.as_str()).or_insert((0, 0));
                slot.0 += 1;
                if flags[end] {
                    if slot.1 == 0 {
                        suspicious += 1;
                    }
                    slot.1 += 1;
                }
            }
            Event::Delete { files } => deleted += files,
        }
        while events[start].0 < at - policy.window_ms {
            match &events[start].1 {
                Event::Change { path, .. } => {
                    if let Some(slot) = paths.get_mut(path.as_str()) {
                        slot.0 -= 1;
                        if flags[start] {
                            slot.1 -= 1;
                            if slot.1 == 0 {
                                suspicious -= 1;
                            }
                        }
                        if slot.0 == 0 {
                            paths.remove(path.as_str());
                        }
                    }
                }
                Event::Delete { files } => deleted -= files,
            }
            start += 1;
        }
        let changed = paths.len();
        if changed > policy.changed || deleted > policy.deleted || suspicious >= policy.suspicious {
            let a = alert.get_or_insert(Alert {
                user: user.to_owned(),
                from_ms: events[start].0,
                to_ms: *at,
                changed: 0,
                deleted: 0,
                suspicious: 0,
            });
            a.to_ms = *at;
            a.changed = a.changed.max(changed);
            a.deleted = a.deleted.max(deleted);
            a.suspicious = a.suspicious.max(suspicious);
        }
    }
    alert
}
