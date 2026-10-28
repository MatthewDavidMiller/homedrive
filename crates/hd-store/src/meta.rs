//! The metadata's durable form: snapshots plus the journal, and recovery.
//!
//! ```text
//! meta/snapshot.<seq, 20 digits>   the whole state after record <seq>
//! meta/journal.<first seq>         records from <first seq> on
//! ```
//!
//! A snapshot is written whole and fsynced before it is linked into place,
//! so it is never partial. It holds magic "HDS1", format 1, four zero
//! bytes, the sequence number, the length of the encoded state, the state,
//! and a SHA-256 of everything before it.
//!
//! **Recovery** takes the newest snapshot that verifies (a bad one is moved
//! to quarantine, loudly, and the next older one is used), then replays
//! every journal record after it. Records must continue without a gap. Only
//! the newest journal may end badly: a torn tail is set aside
//! automatically, while a corrupt one stops the store unless the operator
//! asked for `repair_tail`. Either way the bytes go to quarantine first.
//!
//! **Commit** validates the operation against the state, appends its
//! record (fdatasynced), and only then applies it in memory. The order
//! matters: memory never runs ahead of disk. Any failure after the record
//! may have reached the disk poisons the metadata, refusing further
//! writes, because only a reopen (which replays the journal) can say what
//! the true state is.
//!
//! **Checkpoints** write a snapshot, start a new journal after it, and
//! prune: the newest [`KEEP_SNAPSHOTS`] snapshots are kept, with every
//! journal any of them needs, so a damaged newest snapshot still has a
//! fallback.

use std::fs;
use std::path::{Path, PathBuf};

use hd_common::fsio::{self, Appender, Created};
use hd_common::{Error, Result, timefmt};

use crate::journal::{self, Tail};
use crate::model::{Applied, Op, State};

const SNAPSHOT_MAGIC: &[u8; 4] = b"HDS1";
const SNAPSHOT_FORMAT: u8 = 1;
const SNAPSHOT_HEADER: usize = 24;
/// The largest snapshot read back: far beyond any homelab's metadata.
const MAX_SNAPSHOT: usize = 1 << 31;
/// The largest journal read back during recovery: checkpoints keep
/// journals far shorter.
const MAX_JOURNAL: usize = 1 << 31;
pub const KEEP_SNAPSHOTS: usize = 3;

pub fn snapshot_name(seq: u64) -> String {
    format!("snapshot.{seq:020}")
}

fn parse_snapshot_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("snapshot.")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())?
}

fn encode_snapshot(state: &State) -> Result<Vec<u8>> {
    let body = state.encode();
    let mut out = Vec::with_capacity(body.len() + SNAPSHOT_HEADER + 32);
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.push(SNAPSHOT_FORMAT);
    out.extend_from_slice(&[0; 3]);
    out.extend_from_slice(&state.seq.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
    let check = hd_crypto::sha256(&out).map_err(|_| Error::new("SHA-256 failed"))?;
    out.extend_from_slice(&check);
    Ok(out)
}

fn decode_snapshot(bytes: &[u8], seq: u64) -> Result<State> {
    let bad = |why: &str| Error::new(format!("snapshot {seq} is unusable: {why}"));
    if bytes.len() < SNAPSHOT_HEADER + 32 {
        return Err(bad("too short"));
    }
    let (signed, check) = bytes.split_at(bytes.len() - 32);
    if hd_crypto::sha256(signed).map_err(|_| bad("SHA-256 failed"))? != check {
        return Err(bad("checksum mismatch"));
    }
    if &signed[..4] != SNAPSHOT_MAGIC || signed[4] != SNAPSHOT_FORMAT || signed[5..8] != [0; 3] {
        return Err(bad("bad header"));
    }
    let word = |at: usize| {
        let mut w = [0_u8; 8];
        w.copy_from_slice(&signed[at..at + 8]);
        u64::from_le_bytes(w)
    };
    if word(8) != seq {
        return Err(bad("sequence number does not match its name"));
    }
    if word(16) != (signed.len() - SNAPSHOT_HEADER) as u64 {
        return Err(bad("length does not match"));
    }
    let state = State::decode(&signed[SNAPSHOT_HEADER..]).map_err(|e| bad(e.message()))?;
    if state.seq != seq {
        return Err(bad("state does not match its sequence number"));
    }
    Ok(state)
}

/// A fresh name in quarantine for `base`: the time says when, and the
/// random part keeps a retried recovery (after a crash during the first
/// attempt) from colliding with what the first attempt set aside.
fn quarantine_name(base: &str) -> Result<String> {
    Ok(format!("{base}.{}.{}", timefmt::now_ms(), hd_common::rand::random_hex(4)?))
}

#[derive(Clone, Copy, Debug)]
pub struct MetaOptions {
    /// Records between automatic checkpoints; `0` checkpoints only on
    /// request.
    pub snapshot_every: u64,
    /// Set aside a corrupt journal tail instead of refusing to open.
    pub repair_tail: bool,
}

impl Default for MetaOptions {
    fn default() -> Self {
        Self { snapshot_every: 10_000, repair_tail: false }
    }
}

/// What recovery had to do, for the log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recovery {
    /// Bytes of torn tail set aside.
    pub torn_bytes: u64,
    /// Bytes of corrupt tail set aside under `repair_tail`.
    pub repaired_bytes: u64,
    /// Snapshots that failed verification and were quarantined.
    pub bad_snapshots: Vec<String>,
    pub records_replayed: u64,
}

#[derive(Debug)]
pub struct Meta {
    dir: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    state: State,
    journal: Appender,
    since_snapshot: u64,
    options: MetaOptions,
    poisoned: Option<String>,
}

struct Listing {
    snapshots: Vec<u64>,
    journals: Vec<u64>,
}

fn list(dir: &Path) -> Result<Listing> {
    let mut snapshots = Vec::new();
    let mut journals = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(seq) = parse_snapshot_name(name) {
            snapshots.push(seq);
        } else if let Some(first) = journal::parse_name(name) {
            journals.push(first);
        }
    }
    snapshots.sort_unstable();
    journals.sort_unstable();
    Ok(Listing { snapshots, journals })
}

impl Meta {
    /// Recovers the metadata from `dir`. `staging` and `quarantine` must be
    /// on the same filesystem.
    pub fn open(
        dir: &Path,
        staging: &Path,
        quarantine: &Path,
        options: MetaOptions,
    ) -> Result<(Self, Recovery)> {
        let mut recovery = Recovery::default();
        let listing = list(dir)?;
        let set_aside = |name: &str| -> Result<()> {
            fsio::move_new_durable(dir.join(name), quarantine.join(quarantine_name(name)?))
        };

        // The newest snapshot that verifies.
        let mut base: Option<State> = None;
        for &seq in listing.snapshots.iter().rev() {
            let name = snapshot_name(seq);
            let loaded = fsio::read_bounded(dir.join(&name), MAX_SNAPSHOT)
                .and_then(|b| b.ok_or_else(|| Error::new("vanished")))
                .and_then(|b| decode_snapshot(&b, seq));
            match loaded {
                Ok(state) => {
                    base = Some(state);
                    break;
                }
                Err(e) => {
                    eprintln!("hd-store: {e}; moving it to quarantine and using an older one");
                    set_aside(&name)?;
                    recovery.bad_snapshots.push(name);
                }
            }
        }
        let have_start = listing.journals.first() == Some(&1);
        let mut state = match base {
            Some(state) => state,
            None if listing.snapshots.is_empty() || have_start => State::default(),
            None => {
                return Err(Error::new(
                    "no snapshot verifies and the journal no longer reaches back to the \
                     beginning; refusing to open (restore the metadata from backup)",
                ));
            }
        };
        let snapshot_seq = state.seq;

        // Replay. Each journal must start no later than the record after
        // the last one applied; only the newest may end badly.
        // The newest journal: its first sequence number, good length, and
        // record count.
        let mut newest: Option<(u64, u64, u64)> = None;
        for (i, &first) in listing.journals.iter().enumerate() {
            let last = i + 1 == listing.journals.len();
            let name = journal::file_name(first);
            let path = dir.join(&name);
            if first > state.seq + 1 {
                return Err(Error::new(format!(
                    "{name} starts at record {first} but the metadata ends at {}; records are \
                     missing, refusing to open",
                    state.seq
                )));
            }
            let bytes = fsio::read_bounded(&path, MAX_JOURNAL)?
                .ok_or_else(|| Error::new(format!("{name} vanished during recovery")))?;
            if bytes.len() < journal::HEADER_LEN && last {
                // Created but its header never fully written: it holds no
                // records. Set it aside and start it again.
                eprintln!("hd-store: {name} has no complete header; setting it aside");
                set_aside(&name)?;
                recovery.torn_bytes += bytes.len() as u64;
                continue;
            }
            let scan = journal::scan(&bytes, first).map_err(|e| {
                Error::new(format!("{name}: {e}; refusing to open (restore from backup)"))
            })?;
            let cut = match &scan.tail {
                Tail::Clean => None,
                Tail::Torn { at } if last => {
                    recovery.torn_bytes += bytes.len() as u64 - at;
                    Some(*at)
                }
                Tail::Corrupt { at, reason } if last && options.repair_tail => {
                    eprintln!("hd-store: {name} is corrupt at byte {at} ({reason}); repairing");
                    recovery.repaired_bytes += bytes.len() as u64 - at;
                    Some(*at)
                }
                Tail::Torn { at } | Tail::Corrupt { at, .. } => {
                    let why = match &scan.tail {
                        Tail::Corrupt { reason, .. } => reason.clone(),
                        _ => "an incomplete record".to_owned(),
                    };
                    return Err(Error::new(format!(
                        "{name} is damaged at byte {at} ({why}); refusing to open. If it is the \
                         newest journal, `hd-server fsck --repair-tail` sets the damaged tail \
                         aside in quarantine"
                    )));
                }
            };
            if let Some(at) = cut {
                let to = quarantine.join(quarantine_name(&format!("{name}.tail"))?);
                let moved = fsio::truncate_tail(&path, at, &to, staging, MAX_JOURNAL)?;
                eprintln!("hd-store: set aside {moved} bytes at the end of {name}");
            }
            for (seq, op) in &scan.records {
                if *seq <= state.seq {
                    continue;
                }
                state.apply(op, *seq).map_err(|e| {
                    Error::new(format!(
                        "record {seq} in {name} does not apply ({e}); refusing to open"
                    ))
                })?;
                recovery.records_replayed += 1;
            }
            if last {
                let len = cut.unwrap_or(bytes.len() as u64);
                newest = Some((first, len, scan.records.len() as u64));
            }
        }

        // Appends continue the newest journal only if its own numbering
        // leads straight to the next record. An empty journal that does not
        // (left by a checkpoint that failed part-way) holds nothing and is
        // set aside; a non-empty one cannot happen and is refused.
        let next = state.seq + 1;
        let journal = match newest {
            Some((first, len, count)) if first + count == next => {
                Appender::open(dir.join(journal::file_name(first)), len)?
            }
            Some((first, _, 0)) => {
                let name = journal::file_name(first);
                eprintln!("hd-store: {name} is empty and out of sequence; setting it aside");
                set_aside(&name)?;
                Appender::create(
                    dir.join(journal::file_name(next)),
                    staging,
                    &journal::header(next),
                )?
            }
            Some((first, _, count)) => {
                return Err(Error::new(format!(
                    "{} ends at record {} but the metadata ends at {}; refusing to open",
                    journal::file_name(first),
                    first + count - 1,
                    state.seq
                )));
            }
            None => Appender::create(
                dir.join(journal::file_name(next)),
                staging,
                &journal::header(next),
            )?,
        };
        let since_snapshot = state.seq - snapshot_seq;
        let meta = Self {
            dir: dir.to_path_buf(),
            staging: staging.to_path_buf(),
            quarantine: quarantine.to_path_buf(),
            state,
            journal,
            since_snapshot,
            options,
            poisoned: None,
        };
        Ok((meta, recovery))
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Durably records `op` and applies it.
    pub fn commit(&mut self, op: &Op) -> Result<Applied> {
        if let Some(why) = &self.poisoned {
            return Err(Error::new(format!("the store stopped accepting writes: {why}")));
        }
        self.state.validate(op)?;
        let seq = self.state.seq + 1;
        let record = journal::record(seq, op)?;
        if let Err(e) = self.journal.append(&record) {
            self.poisoned = Some(format!("a journal write failed ({e}); restart to recover"));
            return Err(e);
        }
        let applied = match self.state.apply(op, seq) {
            Ok(applied) => applied,
            Err(e) => {
                // Validated a moment ago, so this is a bug; the record is on
                // disk and the state is not, so nothing more may be written.
                self.poisoned = Some(format!("record {seq} failed to apply ({e})"));
                return Err(Error::new("internal error applying a record"));
            }
        };
        self.since_snapshot += 1;
        if self.options.snapshot_every > 0 && self.since_snapshot >= self.options.snapshot_every {
            // The record is durable already; a failed checkpoint only means
            // a longer replay next time, and is retried at the next commit.
            if let Err(e) = self.checkpoint() {
                eprintln!("hd-store: checkpoint failed (it will be retried): {e}");
            }
        }
        Ok(applied)
    }

    /// Decides an operation from the current state and commits it, with no
    /// other commit in between. `decide` returns the op (or none, when
    /// nothing needs to change) and a value for the caller.
    pub fn commit_with<T>(
        &mut self,
        decide: impl FnOnce(&State) -> Result<(Option<Op>, T)>,
    ) -> Result<(Option<Applied>, T)> {
        let (op, value) = decide(&self.state)?;
        match op {
            Some(op) => Ok((Some(self.commit(&op)?), value)),
            None => Ok((None, value)),
        }
    }

    /// Writes a snapshot of the current state, starts a new journal after
    /// it, and prunes what no kept snapshot needs. Returns the snapshot's
    /// sequence number.
    pub fn checkpoint(&mut self) -> Result<u64> {
        if let Some(why) = &self.poisoned {
            return Err(Error::new(format!("the store stopped accepting writes: {why}")));
        }
        let seq = self.state.seq;
        let bytes = encode_snapshot(&self.state)?;
        let path = self.dir.join(snapshot_name(seq));
        match fsio::write_new_durable(&path, &self.staging, &[&bytes], 0o400)? {
            Created::New => {}
            Created::Existed => {
                // Only possible for the same sequence number, so the same
                // state; check rather than assume.
                let existing = fsio::read_bounded(&path, MAX_SNAPSHOT)?.unwrap_or_default();
                if existing != bytes {
                    return Err(Error::new(format!("snapshot {seq} exists with other contents")));
                }
            }
        }
        let first = seq + 1;
        let next = self.dir.join(journal::file_name(first));
        if fs::symlink_metadata(&next).is_err() {
            match Appender::create(&next, &self.staging, &journal::header(first)) {
                Ok(journal) => self.journal = journal,
                Err(e) => {
                    // The new journal may exist on disk without being open
                    // here. Appending to the old one now would number its
                    // records against the wrong file, so stop until a
                    // reopen sorts it out.
                    self.poisoned = Some(format!("starting a new journal failed ({e})"));
                    return Err(e);
                }
            }
        }
        self.since_snapshot = 0;
        crate::gc::prune_meta(&self.dir, KEEP_SNAPSHOTS)?;
        Ok(seq)
    }

    pub fn quarantine_dir(&self) -> &Path {
        &self.quarantine
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }
}

/// The snapshots and journals in a metadata directory, for pruning.
pub(crate) fn listing(dir: &Path) -> Result<(Vec<u64>, Vec<u64>)> {
    let l = list(dir)?;
    Ok((l.snapshots, l.journals))
}
