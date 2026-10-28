//! Which old versions and trash items to let go of.
//!
//! For each file, the current version is always kept. Older versions are
//! kept like this:
//! - every one younger than `keep_all`;
//! - then the newest of each day until `daily_until`;
//! - the newest of each week until `weekly_until`;
//! - and the newest of each calendar month after that, for good.
//!
//! Trash items older than `trash` are purged. Retention only *plans*
//! `DropVersion` and `Purge` operations. They go through the journal like
//! any other change, and the bytes are freed later by GC, after its grace
//! periods. The plan is a pure function of the state and the time.

use std::collections::BTreeSet;

use hd_common::{Result, timefmt};

use crate::Store;
use crate::model::{Node, Op, State};

const DAY_MS: i64 = 86_400_000;
const WEEK_MS: i64 = 7 * DAY_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub keep_all_ms: i64,
    pub daily_until_ms: i64,
    pub weekly_until_ms: i64,
    pub trash_ms: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            keep_all_ms: 30 * DAY_MS,
            daily_until_ms: 90 * DAY_MS,
            weekly_until_ms: 365 * DAY_MS,
            trash_ms: 90 * DAY_MS,
        }
    }
}

impl Policy {
    /// Keeps every version and trash item forever.
    pub fn forever() -> Self {
        Self {
            keep_all_ms: i64::MAX,
            daily_until_ms: i64::MAX,
            weekly_until_ms: i64::MAX,
            trash_ms: i64::MAX,
        }
    }
}

/// The bucket an old version falls in; the newest version in each bucket
/// is kept. `None` means "younger than keep_all": always kept.
fn bucket(created_ms: i64, now_ms: i64, p: &Policy) -> Option<(u8, i64)> {
    let age = now_ms.saturating_sub(created_ms);
    if age < p.keep_all_ms {
        None
    } else if age < p.daily_until_ms {
        Some((1, created_ms.div_euclid(DAY_MS)))
    } else if age < p.weekly_until_ms {
        Some((2, created_ms.div_euclid(WEEK_MS)))
    } else {
        let (year, month, _) = timefmt::civil_from_days(created_ms.div_euclid(DAY_MS));
        Some((3, year * 12 + i64::from(month)))
    }
}

/// The operations retention would issue now.
pub fn plan(state: &State, now_ms: i64, policy: &Policy) -> Vec<Op> {
    let mut ops = Vec::new();
    for (user, ns) in &state.users {
        for (path, entry) in &ns.entries {
            let Node::File { versions, .. } = &entry.node else { continue };
            let Some((_, old)) = versions.split_last() else { continue };
            let mut seen = BTreeSet::new();
            // Newest first, so the first version met in a bucket is kept.
            for v in old.iter().rev() {
                match bucket(v.created_ms, now_ms, policy) {
                    None => {}
                    Some(b) if seen.insert(b) => {}
                    Some(_) => ops.push(Op::DropVersion {
                        user: user.clone(),
                        path: path.clone(),
                        version_id: v.id,
                    }),
                }
            }
        }
        for item in ns.trash.values() {
            if now_ms.saturating_sub(item.deleted_ms) >= policy.trash_ms {
                ops.push(Op::Purge { user: user.clone(), trash_id: item.id });
            }
        }
    }
    ops
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RetentionReport {
    pub dropped_versions: usize,
    pub purged_trash: usize,
}

impl Store {
    /// Applies the retention policy as of `now_ms`.
    pub fn apply_retention(&self, now_ms: i64, policy: &Policy) -> Result<RetentionReport> {
        let ops = self.read(|s| plan(s, now_ms, policy));
        let mut report = RetentionReport::default();
        for op in ops {
            // Each op is validated again at commit; one that no longer
            // applies (the file changed meanwhile) is simply skipped.
            if self.read(|s| s.validate(&op)).is_err() {
                continue;
            }
            self.commit(&op)?;
            match op {
                Op::DropVersion { .. } => report.dropped_versions += 1,
                Op::Purge { .. } => report.purged_trash += 1,
                _ => {}
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Content;
    use crate::model::tests::content;

    fn put_at(s: &mut State, path: &str, created_ms: i64) {
        let c = Content { created_ms, ..content(&created_ms.to_string()) };
        let op = Op::PutVersion { user: "u".into(), path: path.into(), content: c };
        s.apply(&op, s.seq + 1).unwrap();
    }

    fn kept(s: &State, path: &str, now: i64, p: &Policy) -> Vec<i64> {
        let mut s = s.clone();
        for op in plan(&s.clone(), now, p) {
            s.apply(&op, s.seq + 1).unwrap();
        }
        match &s.user("u").unwrap().get(path).unwrap().node {
            Node::File { versions, .. } => versions.iter().map(|v| v.created_ms).collect(),
            Node::Dir => panic!(),
        }
    }

    #[test]
    fn thinning_keeps_one_per_bucket_and_always_the_current() {
        let now = 1_000 * DAY_MS;
        let mut s = State::default();
        // Hourly versions over the last 400 days.
        let mut t = now - 400 * DAY_MS;
        while t < now {
            put_at(&mut s, "f", t);
            t += DAY_MS / 24;
        }
        let p = Policy::default();
        let kept = kept(&s, "f", now, &p);
        let newest = *kept.last().unwrap();
        assert_eq!(newest, t - DAY_MS / 24, "the current version is kept");
        let age = |c: i64| now - c;
        // Everything in the last 30 days: hourly from 1 h old to 30 days
        // less an hour.
        assert_eq!(kept.iter().filter(|&&c| age(c) < 30 * DAY_MS).count(), 30 * 24 - 1);
        // About one a day from 30 to 90 days, one a week to a year, then
        // monthly.
        let daily = kept.iter().filter(|&&c| (30 * DAY_MS..90 * DAY_MS).contains(&age(c))).count();
        assert!((59..=61).contains(&daily), "{daily}");
        let weekly =
            kept.iter().filter(|&&c| (90 * DAY_MS..365 * DAY_MS).contains(&age(c))).count();
        assert!((38..=41).contains(&weekly), "{weekly}");
        let monthly = kept.iter().filter(|&&c| age(c) >= 365 * DAY_MS).count();
        assert!((1..=3).contains(&monthly), "{monthly}");
        // Applying it again changes nothing.
        let mut once = s.clone();
        for op in plan(&s, now, &p) {
            once.apply(&op, once.seq + 1).unwrap();
        }
        assert!(plan(&once, now, &p).is_empty());
    }

    #[test]
    fn forever_keeps_everything_and_trash_expires() {
        let now = 500 * DAY_MS;
        let mut s = State::default();
        for d in 0..10 {
            put_at(&mut s, "f", d * DAY_MS);
        }
        assert!(plan(&s, now, &Policy::forever()).is_empty());
        let trash = Op::Trash { user: "u".into(), path: "f".into(), deleted_ms: now - 91 * DAY_MS };
        s.apply(&trash, s.seq + 1).unwrap();
        let ops = plan(&s, now, &Policy::default());
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], Op::Purge { .. }));
        assert!(plan(&s, now - 2 * DAY_MS, &Policy::default()).is_empty());
    }
}
