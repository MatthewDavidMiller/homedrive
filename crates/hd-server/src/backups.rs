//! Backup results, so a backup that stopped working is noticed.
//!
//! The backup jobs report each run: the local borg backup and the restore
//! drill through the admin socket (`hd-server report-backup`), an
//! administrator's copy (`homedrive backup-store`) through the API
//! (`POST /api/v1/backup-report`, admins only), and a finished download of
//! the store from the web UI by itself. The last success and failure of each kind are kept in
//! `backups.json` in the data directory.
//!
//! An admin is told (admin page, `GET /api/v1/status`, and so their sync
//! clients' notifications) when a kind's last run failed, or when it has
//! not succeeded for too long: two days for backups, eight for the weekly
//! drill. A kind that has never reported is shown on the admin page but
//! raises nothing, since the server cannot know it is meant to exist.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use hd_api::{J, s};
use hd_common::json::Value;
use hd_common::{Error, Result, fsio, timefmt};

const FILE: &str = "backups.json";
const DAY_MS: i64 = 86_400_000;
const MAX_MESSAGE: usize = 1000;

/// Serializes read-modify-write of the file.
static WRITING: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub ok_ms: Option<i64>,
    pub failed_ms: Option<i64>,
    /// What the last run said.
    pub message: String,
}

impl Outcome {
    /// Whether the last run failed.
    pub fn failing(&self) -> bool {
        self.failed_ms.is_some_and(|f| self.ok_ms.is_none_or(|o| f > o))
    }
}

/// A kind is a short lowercase name: `local`, `client-copy`, `drill`.
pub fn valid_kind(kind: &str) -> bool {
    (1..=32).contains(&kind.len())
        && kind.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// How long a kind may go without a success before it is reported.
pub fn stale_after_ms(kind: &str) -> i64 {
    // The drill runs weekly, and an administrator's copy is taken by hand.
    if kind == "drill" || kind == "client-copy" { 8 * DAY_MS } else { 2 * DAY_MS }
}

pub fn load(data_dir: &Path) -> BTreeMap<String, Outcome> {
    let Ok(Some(bytes)) = fsio::read_bounded(data_dir.join(FILE), 1 << 20) else {
        return BTreeMap::new();
    };
    let Ok(v) = hd_api::parse(&bytes) else { return BTreeMap::new() };
    hd_api::get_array(&v, "kinds")
        .map(|list| {
            list.iter()
                .filter_map(|k| {
                    let kind = hd_api::get_str(k, "kind").ok().filter(|k| valid_kind(k))?;
                    Some((
                        kind,
                        Outcome {
                            ok_ms: k.get("ok_ms").and_then(Value::as_i64),
                            failed_ms: k.get("failed_ms").and_then(Value::as_i64),
                            message: hd_api::get_str(k, "message").unwrap_or_default(),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Records one run of `kind`.
pub fn record(data_dir: &Path, kind: &str, ok: bool, message: &str) -> Result<()> {
    if !valid_kind(kind) {
        return Err(Error::new("a backup kind is 1-32 of a-z 0-9 -"));
    }
    let _guard = WRITING.lock().unwrap_or_else(PoisonError::into_inner);
    let mut all = load(data_dir);
    let o = all.entry(kind.to_owned()).or_default();
    let now = timefmt::unix_ms();
    if ok {
        o.ok_ms = Some(now);
    } else {
        o.failed_ms = Some(now);
    }
    o.message = message.chars().filter(|c| !c.is_control()).take(MAX_MESSAGE).collect();
    let opt = |v: Option<i64>| v.map_or(J::Null, J::I);
    let text = J::O(vec![(
        "kinds",
        J::A(
            all.iter()
                .map(|(k, o)| {
                    J::O(vec![
                        ("kind", s(&**k)),
                        ("ok_ms", opt(o.ok_ms)),
                        ("failed_ms", opt(o.failed_ms)),
                        ("message", s(&*o.message)),
                    ])
                })
                .collect(),
        ),
    )])
    .render();
    fsio::atomic_replace(data_dir.join(FILE), text.as_bytes(), 1 << 20)
}

/// What the admins should hear about the backups.
pub fn problems(data_dir: &Path, now_ms: i64) -> Vec<String> {
    let when = |ms: i64| timefmt::rfc3339_millis(ms / 1000, 0);
    let mut out = Vec::new();
    for (kind, o) in load(data_dir) {
        if o.failing() {
            out.push(format!(
                "the {kind} backup failed at {}: {}",
                when(o.failed_ms.unwrap_or(0)),
                o.message
            ));
        } else if let Some(ok) = o.ok_ms
            && now_ms - ok > stale_after_ms(&kind)
        {
            out.push(format!("the {kind} backup has not succeeded since {}", when(ok)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_are_kept_and_failures_and_silence_reported() {
        let dir = std::env::temp_dir().join(format!("hd-backups-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let now = timefmt::unix_ms();
        assert!(problems(&dir, now).is_empty(), "nothing reported yet, nothing to say");
        record(&dir, "local", true, "archive homedrive-2026-10-28").unwrap();
        record(&dir, "drill", true, "12 files restored").unwrap();
        assert!(problems(&dir, now).is_empty());
        record(&dir, "client-copy", false, "cannot reach the server").unwrap();
        let p = problems(&dir, now);
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("client-copy") && p[0].contains("cannot reach"));
        // Days later with no new run: local is stale, the drill not yet.
        let p = problems(&dir, now + 3 * DAY_MS);
        assert!(p.iter().any(|m| m.contains("local backup has not succeeded")), "{p:?}");
        assert!(!p.iter().any(|m| m.contains("drill")));
        assert!(problems(&dir, now + 9 * DAY_MS).iter().any(|m| m.contains("drill")));
        assert!(record(&dir, "Bad Kind", true, "").is_err());
        assert_eq!(load(&dir).len(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
