//! What a folder's sync rounds did, for the GUI's History page: one line
//! per change in `history.jsonl` in the folder's state directory, oldest
//! first.
//!
//! It is a record for the user to read, not state the engine relies on, so
//! it is bounded rather than complete: the newest [`MAX_ENTRIES`] changes
//! are kept, and a round that changes more than [`MAX_PER_ROUND`] files
//! records that many and a count of the rest. A round that changes nothing
//! adds nothing. A failed round is recorded once, not again for each retry
//! that fails the same way. A history that cannot be read starts afresh; it
//! never stops a folder syncing.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use hd_api::{J, s};
use hd_common::{Result, fsio};

use crate::engine::Report;

pub const FILE: &str = "history.jsonl";
/// The most changes kept.
pub const MAX_ENTRIES: usize = 1000;
/// The most changes one round records by name.
pub const MAX_PER_ROUND: usize = 200;
const MAX_FILE: usize = 4 * 1024 * 1024;
/// The longest path or message kept for one entry.
const MAX_TEXT: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Uploaded,
    Downloaded,
    /// Deleted on the server, so moved to this folder's trash here.
    DeletedHere,
    /// Deleted here, so moved to the server's trash.
    DeletedOnServer,
    /// Changed here and elsewhere; both copies kept.
    Conflict,
    /// A damaged copy here replaced with the server's.
    Repaired,
    /// Pieces the server lost, sent again from here.
    Healed,
    /// `count` more changes in the round before, not named.
    More,
    /// The round failed; `text` says why.
    Failed,
}

impl Kind {
    const ALL: [(Self, &'static str); 9] = [
        (Self::Uploaded, "uploaded"),
        (Self::Downloaded, "downloaded"),
        (Self::DeletedHere, "deleted_here"),
        (Self::DeletedOnServer, "deleted_on_server"),
        (Self::Conflict, "conflict"),
        (Self::Repaired, "repaired"),
        (Self::Healed, "healed"),
        (Self::More, "more"),
        (Self::Failed, "failed"),
    ];

    fn name(self) -> &'static str {
        Self::ALL.iter().find(|(k, _)| *k == self).map_or("", |(_, n)| n)
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().find(|(_, n)| *n == name).map(|(k, _)| *k)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub at_ms: i64,
    pub kind: Kind,
    /// The path, relative to the folder; for `Failed`, the reason; for
    /// `More`, empty.
    pub text: String,
    /// How many changes the entry stands for: 1, except for `More`.
    pub count: u64,
}

impl Entry {
    fn render(&self) -> String {
        J::O(vec![
            ("at_ms", J::I(self.at_ms)),
            ("kind", s(self.kind.name())),
            ("text", s(&*self.text)),
            ("count", J::U(self.count)),
        ])
        .render()
    }

    fn parse(line: &str) -> Option<Self> {
        let v = hd_api::parse(line.as_bytes()).ok()?;
        Some(Self {
            at_ms: hd_api::get_i64(&v, "at_ms").ok()?,
            kind: Kind::from_name(&hd_api::get_str(&v, "kind").ok()?)?,
            text: hd_api::get_str(&v, "text").ok()?,
            count: hd_api::get_u64(&v, "count").ok()?,
        })
    }

    /// Whether it says something changed, rather than that a round failed.
    pub fn is_change(&self) -> bool {
        self.kind != Kind::Failed
    }
}

fn clip(text: &str) -> String {
    if text.len() <= MAX_TEXT {
        return text.to_owned();
    }
    let mut end = MAX_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Every entry a folder's history holds, oldest first. Lines that cannot
/// be read are passed over.
pub fn read(state_dir: &Path) -> Vec<Entry> {
    let Ok(Some(text)) = fsio::read_text(state_dir.join(FILE), MAX_FILE) else {
        return Vec::new();
    };
    text.lines().filter_map(Entry::parse).collect()
}

/// The history of the folder an engine syncs, kept in memory so a round
/// adds to it without reading it back.
#[derive(Debug)]
pub struct History {
    path: PathBuf,
    entries: VecDeque<Entry>,
}

impl History {
    pub fn open(state_dir: &Path) -> Self {
        let mut entries: VecDeque<Entry> = read(state_dir).into();
        while entries.len() > MAX_ENTRIES {
            entries.pop_front();
        }
        Self { path: state_dir.join(FILE), entries }
    }

    /// When the newest change was, if any is kept.
    pub fn last_change_ms(&self) -> Option<i64> {
        self.entries.iter().rev().find(|e| e.is_change()).map(|e| e.at_ms)
    }

    /// Adds what a round changed, if anything, and saves.
    pub fn record_round(&mut self, report: &Report, at_ms: i64) -> Result<()> {
        let named = [
            (Kind::Uploaded, &report.uploaded),
            (Kind::Downloaded, &report.downloaded),
            (Kind::DeletedHere, &report.deleted_local),
            (Kind::DeletedOnServer, &report.deleted_remote),
            (Kind::Conflict, &report.conflicts),
            (Kind::Repaired, &report.repaired_local),
            (Kind::Healed, &report.healed),
        ];
        let total: usize = named.iter().map(|(_, paths)| paths.len()).sum();
        if total == 0 {
            return Ok(());
        }
        let mut added = 0;
        for (kind, paths) in named {
            for p in paths.iter().take(MAX_PER_ROUND - added) {
                self.entries.push_back(Entry { at_ms, kind, text: clip(p), count: 1 });
                added += 1;
            }
        }
        if total > added {
            self.entries.push_back(Entry {
                at_ms,
                kind: Kind::More,
                text: String::new(),
                count: (total - added) as u64,
            });
        }
        self.save()
    }

    /// Adds a failed round, unless the newest entry already says the same.
    pub fn record_failure(&mut self, why: &str, at_ms: i64) -> Result<()> {
        let why = clip(why);
        if self.entries.back().is_some_and(|e| e.kind == Kind::Failed && e.text == why) {
            return Ok(());
        }
        self.entries.push_back(Entry { at_ms, kind: Kind::Failed, text: why, count: 1 });
        self.save()
    }

    fn save(&mut self) -> Result<()> {
        while self.entries.len() > MAX_ENTRIES {
            self.entries.pop_front();
        }
        let mut text = String::new();
        for e in &self.entries {
            text.push_str(&e.render());
            text.push('\n');
        }
        fsio::atomic_replace(&self.path, text.as_bytes(), MAX_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hd-history-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_round_is_kept_in_order_and_survives_a_restart() {
        let d = dir("round");
        let mut h = History::open(&d);
        assert_eq!(h.last_change_ms(), None);
        h.record_round(&Report::default(), 1).unwrap();
        assert!(read(&d).is_empty(), "a quiet round adds nothing");
        let report = Report {
            uploaded: vec!["a.txt".into()],
            downloaded: vec!["b \"quoted\"\n.txt".into()],
            deleted_local: vec!["c".into()],
            deleted_remote: vec!["d".into()],
            conflicts: vec!["e (conflict)".into()],
            repaired_local: vec!["f".into()],
            healed: vec!["g".into()],
            ..Report::default()
        };
        h.record_round(&report, 5).unwrap();
        let kinds: Vec<Kind> = read(&d).iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [
                Kind::Uploaded,
                Kind::Downloaded,
                Kind::DeletedHere,
                Kind::DeletedOnServer,
                Kind::Conflict,
                Kind::Repaired,
                Kind::Healed
            ]
        );
        assert_eq!(read(&d)[1].text, "b \"quoted\"\n.txt", "any name comes back as it was");
        let again = History::open(&d);
        assert_eq!(again.last_change_ms(), Some(5));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_big_round_is_named_in_part_and_counted_in_full() {
        let d = dir("big");
        let mut h = History::open(&d);
        let report = Report {
            uploaded: (0..MAX_PER_ROUND + 40).map(|i| format!("{i}")).collect(),
            downloaded: vec!["x".into(); 10],
            ..Report::default()
        };
        h.record_round(&report, 7).unwrap();
        let entries = read(&d);
        assert_eq!(entries.len(), MAX_PER_ROUND + 1);
        let more = entries.last().unwrap();
        assert_eq!((more.kind, more.count), (Kind::More, 50));
        assert_eq!(entries.iter().map(|e| e.count).sum::<u64>(), (MAX_PER_ROUND + 50) as u64);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn only_the_newest_entries_are_kept() {
        let d = dir("cap");
        let mut h = History::open(&d);
        for i in 0..(MAX_ENTRIES / MAX_PER_ROUND + 2) {
            let report = Report {
                uploaded: (0..MAX_PER_ROUND).map(|n| format!("{i}/{n}")).collect(),
                ..Report::default()
            };
            h.record_round(&report, i64::try_from(i).unwrap()).unwrap();
        }
        let entries = read(&d);
        assert_eq!(entries.len(), MAX_ENTRIES);
        let newest = MAX_ENTRIES / MAX_PER_ROUND + 1;
        assert_eq!(entries.last().unwrap().text, format!("{newest}/{}", MAX_PER_ROUND - 1));
        assert!(entries.first().unwrap().at_ms >= 2, "the oldest went first");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_failure_is_recorded_once_until_something_else_happens() {
        let d = dir("fail");
        let mut h = History::open(&d);
        h.record_failure("cannot reach the server", 1).unwrap();
        h.record_failure("cannot reach the server", 2).unwrap();
        assert_eq!(read(&d).len(), 1);
        h.record_round(&Report { uploaded: vec!["a".into()], ..Report::default() }, 3).unwrap();
        h.record_failure("cannot reach the server", 4).unwrap();
        assert_eq!(read(&d).len(), 3);
        assert_eq!(h.last_change_ms(), Some(3), "a failure is not a change");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_damaged_history_is_read_around_and_long_text_is_cut() {
        let d = dir("damaged");
        let good = Entry { at_ms: 1, kind: Kind::Uploaded, text: "a".into(), count: 1 };
        std::fs::write(
            d.join(FILE),
            format!(
                "{}\nnot json\n{{\"at_ms\":2,\"kind\":\"nonsense\"}}\n{{\"at_ms\":3",
                good.render()
            ),
        )
        .unwrap();
        assert_eq!(read(&d), [good]);
        let mut h = History::open(&d);
        h.record_failure(&"é".repeat(MAX_TEXT), 9).unwrap();
        let last = read(&d).pop().unwrap();
        assert!(last.text.len() <= MAX_TEXT + '…'.len_utf8(), "{}", last.text.len());
        assert!(last.text.ends_with('…'));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
