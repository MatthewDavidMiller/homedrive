//! What passes between the `homedrive` command and the process syncing a
//! folder, through files in the folder's state directory.
//!
//! **One process syncs a folder at a time.** It holds an exclusive lock on
//! `lock` for as long as it runs. Two at once (a daemon and a
//! `homedrive sync` run by hand) would act on the same files from two
//! views, and each would compact the state the other is writing.
//!
//! So the command does not act on a folder the daemon is syncing. It
//! leaves a request in `request.json` (confirm what is held back, or
//! check every file now), which the daemon carries out on its next round.
//! A confirmation names how many deletions and changes it approves, and is
//! good for an hour: one given and forgotten never approves a larger burst
//! later. The syncing process writes what each round held back or could
//! not do to `status.json`, for `homedrive status` and `homedrive confirm`
//! to read.

use std::path::Path;

use hd_api::{J, s};
use hd_common::{Result, fsio, timefmt};

use crate::engine::Report;

pub const LOCK: &str = "lock";
const REQUEST: &str = "request.json";
const STATUS: &str = "status.json";
const MAX_FILE: usize = 4 * 1024 * 1024;
/// The most paths of each kind a status lists.
const MAX_LISTED: usize = 200;
/// How long a request stays good.
pub const REQUEST_TTL_MS: i64 = 3_600_000;

/// What the user asked of the process syncing a folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub at_ms: i64,
    /// Deletions approved in one round, up to this many.
    pub deletes: usize,
    /// Changes approved in one round, up to this many.
    pub changes: usize,
    /// Check every synced file against its recorded content now.
    pub verify: bool,
}

impl Request {
    pub fn write(&self, state_dir: &Path) -> Result<()> {
        fsio::mkdir_durable(state_dir, 0o700)?;
        let text = J::O(vec![
            ("at_ms", J::I(self.at_ms)),
            ("deletes", J::U(self.deletes as u64)),
            ("changes", J::U(self.changes as u64)),
            ("verify", J::Bool(self.verify)),
        ])
        .render();
        fsio::atomic_replace(state_dir.join(REQUEST), text.as_bytes(), MAX_FILE)
    }

    /// The pending request, if there is one still good.
    pub fn read(state_dir: &Path) -> Option<Self> {
        let bytes = fsio::read_bounded(state_dir.join(REQUEST), MAX_FILE).ok()??;
        let v = hd_api::parse(&bytes).ok()?;
        let r = Self {
            at_ms: hd_api::get_i64(&v, "at_ms").ok()?,
            deletes: usize::try_from(hd_api::get_u64(&v, "deletes").ok()?).ok()?,
            changes: usize::try_from(hd_api::get_u64(&v, "changes").ok()?).ok()?,
            verify: hd_api::get_bool(&v, "verify").ok()?,
        };
        let age = timefmt::unix_ms() - r.at_ms;
        (0..REQUEST_TTL_MS).contains(&age).then_some(r)
    }

    /// Marks the request carried out.
    pub fn clear(state_dir: &Path) -> Result<()> {
        if state_dir.join(REQUEST).exists() {
            fsio::atomic_replace(state_dir.join(REQUEST), b"", MAX_FILE)?;
        }
        Ok(())
    }
}

/// What the last round of a folder left for the user.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub at_ms: i64,
    pub held_deletes: Option<usize>,
    pub held_changes: Option<usize>,
    /// Held changes that looked like encryption.
    pub suspicious: usize,
    pub ransomware_suspected: bool,
    pub errors: Vec<(String, String)>,
    pub skipped: Vec<(String, String)>,
    pub repaired_local: Vec<String>,
}

fn pairs(v: &[(String, String)]) -> J {
    J::A(
        v.iter()
            .take(MAX_LISTED)
            .map(|(p, why)| J::O(vec![("path", s(&**p)), ("why", s(&**why))]))
            .collect(),
    )
}

fn read_pairs(v: &hd_common::json::Value, key: &str) -> Vec<(String, String)> {
    hd_api::get_array(v, key)
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    Some((hd_api::get_str(p, "path").ok()?, hd_api::get_str(p, "why").ok()?))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn opt(n: Option<usize>) -> J {
    n.map_or(J::Null, |n| J::U(n as u64))
}

fn read_opt(v: &hd_common::json::Value, key: &str) -> Option<usize> {
    v.get(key).and_then(hd_common::json::Value::as_u64).and_then(|n| usize::try_from(n).ok())
}

impl Status {
    pub fn of(r: &Report) -> Self {
        Self {
            at_ms: timefmt::unix_ms(),
            held_deletes: r.held_deletes,
            held_changes: r.held_changes,
            suspicious: r.suspicious,
            ransomware_suspected: r.ransomware_suspected,
            errors: r.errors.iter().take(MAX_LISTED).cloned().collect(),
            skipped: r.skipped.iter().take(MAX_LISTED).cloned().collect(),
            repaired_local: r.repaired_local.iter().take(MAX_LISTED).cloned().collect(),
        }
    }

    /// Whether `other` says the same, whenever it was written.
    pub fn same_as(&self, other: &Self) -> bool {
        Self { at_ms: 0, ..self.clone() } == Self { at_ms: 0, ..other.clone() }
    }

    pub fn write(&self, state_dir: &Path) -> Result<()> {
        let text = J::O(vec![
            ("at_ms", J::I(self.at_ms)),
            ("held_deletes", opt(self.held_deletes)),
            ("held_changes", opt(self.held_changes)),
            ("suspicious", J::U(self.suspicious as u64)),
            ("ransomware_suspected", J::Bool(self.ransomware_suspected)),
            ("errors", pairs(&self.errors)),
            ("skipped", pairs(&self.skipped)),
            ("repaired_local", J::A(self.repaired_local.iter().map(|p| s(&**p)).collect())),
        ])
        .render();
        fsio::atomic_replace(state_dir.join(STATUS), text.as_bytes(), MAX_FILE)
    }

    pub fn read(state_dir: &Path) -> Option<Self> {
        let bytes = fsio::read_bounded(state_dir.join(STATUS), MAX_FILE).ok()??;
        let v = hd_api::parse(&bytes).ok()?;
        Some(Self {
            at_ms: hd_api::get_i64(&v, "at_ms").ok()?,
            held_deletes: read_opt(&v, "held_deletes"),
            held_changes: read_opt(&v, "held_changes"),
            suspicious: read_opt(&v, "suspicious").unwrap_or(0),
            ransomware_suspected: hd_api::get_bool(&v, "ransomware_suspected").unwrap_or(false),
            errors: read_pairs(&v, "errors"),
            skipped: read_pairs(&v, "skipped"),
            repaired_local: hd_api::get_array(&v, "repaired_local")
                .map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_owned)).collect())
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_status_round_trip_and_requests_expire() {
        let dir = std::env::temp_dir().join(format!("hd-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(Request::read(&dir), None);
        let r = Request { at_ms: timefmt::unix_ms(), deletes: 3, changes: 120, verify: true };
        r.write(&dir).unwrap();
        assert_eq!(Request::read(&dir), Some(r.clone()));
        Request::clear(&dir).unwrap();
        assert_eq!(Request::read(&dir), None);
        // An old confirmation approves nothing.
        Request { at_ms: timefmt::unix_ms() - REQUEST_TTL_MS - 1, ..r }.write(&dir).unwrap();
        assert_eq!(Request::read(&dir), None);

        let st = Status {
            at_ms: 5,
            held_deletes: Some(60),
            held_changes: None,
            suspicious: 2,
            ransomware_suspected: true,
            errors: vec![("a".into(), "why".into())],
            skipped: vec![],
            repaired_local: vec!["b".into()],
        };
        st.write(&dir).unwrap();
        let back = Status::read(&dir).unwrap();
        assert_eq!(back, st);
        assert!(back.same_as(&Status { at_ms: 9, ..st }));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
