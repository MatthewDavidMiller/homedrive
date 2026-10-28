//! The client's memory of one synced folder: what each path held when it
//! was last in sync (`synced`), a mirror of the server's side (`remote`),
//! and the change-feed cursor.
//!
//! **Losing this state is safe by construction.** The engine only deletes
//! or overwrites a local file when it matches the `synced` record for that
//! path, and with no record it can only upload, download into an empty
//! place, or keep both copies. So a damaged or missing state costs a
//! re-scan and some hashing, never a file. That is why the state is kept
//! simply:
//! - `state.snap` is a whole snapshot, atomically replaced and checksummed;
//! - `log.<generation>` is an append-only, checksummed record of changes
//!   since that snapshot;
//! - opening reads both and compacts into a new generation.
//!
//! A damaged snapshot or log record is logged and the rest ignored.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use hd_chunk::codec::{Dec, Enc};
use hd_common::fsio::{self, Appender};
use hd_common::{Error, Result};

const SNAP_MAGIC: &[u8; 4] = b"HDCS";
const LOG_MAGIC: &[u8; 4] = b"HDCL";
/// Format 2 added the server's history identity; format 1 is still read.
const FORMAT: u8 = 2;
const MAX_SNAPSHOT: usize = 1 << 30;
const MAX_LOG: usize = 1 << 30;
const MAX_RECORD: usize = 64 * 1024;
/// Records after which the log is folded into a new snapshot.
const COMPACT_AFTER: u64 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
}

/// A path as it was when last in sync.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synced {
    pub kind: Kind,
    pub version: u64,
    pub sha256: [u8; 32],
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub dev: u64,
}

/// The server's side of a path, from the change feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteEntry {
    pub kind: Kind,
    pub version: u64,
    pub sha256: [u8; 32],
    pub size: u64,
    pub mtime_ms: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    pub cursor: u64,
    /// The identity of the server history `cursor` belongs to ("" before
    /// the first page).
    pub history: String,
    pub synced: BTreeMap<String, Synced>,
    pub remote: BTreeMap<String, RemoteEntry>,
}

enum Record {
    SetSynced(String, Synced),
    DelSynced(String),
    SetRemote(String, RemoteEntry),
    DelRemote(String),
    Cursor(u64),
    History(String),
    /// Forget everything (the server was restored from an older backup).
    Reset,
}

fn kind_byte(k: Kind) -> u8 {
    match k {
        Kind::File => 1,
        Kind::Dir => 2,
    }
}

fn kind_from(b: u8) -> Result<Kind> {
    match b {
        1 => Ok(Kind::File),
        2 => Ok(Kind::Dir),
        _ => Err(Error::new("bad kind")),
    }
}

fn enc_synced(e: &mut Enc, s: &Synced) {
    e.u8(kind_byte(s.kind))
        .u64(s.version)
        .raw(&s.sha256)
        .u64(s.size)
        .i64(s.mtime_ns)
        .u64(s.ino)
        .u64(s.dev);
}

fn dec_synced(d: &mut Dec<'_>) -> Result<Synced> {
    Ok(Synced {
        kind: kind_from(d.u8()?)?,
        version: d.u64()?,
        sha256: d.raw32()?,
        size: d.u64()?,
        mtime_ns: d.i64()?,
        ino: d.u64()?,
        dev: d.u64()?,
    })
}

fn enc_remote(e: &mut Enc, r: &RemoteEntry) {
    e.u8(kind_byte(r.kind)).u64(r.version).raw(&r.sha256).u64(r.size).i64(r.mtime_ms);
}

fn dec_remote(d: &mut Dec<'_>) -> Result<RemoteEntry> {
    Ok(RemoteEntry {
        kind: kind_from(d.u8()?)?,
        version: d.u64()?,
        sha256: d.raw32()?,
        size: d.u64()?,
        mtime_ms: d.i64()?,
    })
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        match self {
            Record::SetSynced(p, s) => {
                e.u8(1).str(p);
                enc_synced(&mut e, s);
            }
            Record::DelSynced(p) => {
                e.u8(2).str(p);
            }
            Record::SetRemote(p, r) => {
                e.u8(3).str(p);
                enc_remote(&mut e, r);
            }
            Record::DelRemote(p) => {
                e.u8(4).str(p);
            }
            Record::Cursor(c) => {
                e.u8(5).u64(*c);
            }
            Record::Reset => {
                e.u8(6);
            }
            Record::History(h) => {
                e.u8(7).str(h);
            }
        }
        e.finish()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Dec::new(bytes);
        let r = match d.u8()? {
            1 => Record::SetSynced(d.str()?, dec_synced(&mut d)?),
            2 => Record::DelSynced(d.str()?),
            3 => Record::SetRemote(d.str()?, dec_remote(&mut d)?),
            4 => Record::DelRemote(d.str()?),
            5 => Record::Cursor(d.u64()?),
            6 => Record::Reset,
            7 => Record::History(d.str()?),
            _ => return Err(Error::new("unknown record")),
        };
        d.end()?;
        Ok(r)
    }

    fn apply(self, s: &mut State) {
        match self {
            Record::SetSynced(p, v) => {
                s.synced.insert(p, v);
            }
            Record::DelSynced(p) => {
                s.synced.remove(&p);
            }
            Record::SetRemote(p, v) => {
                s.remote.insert(p, v);
            }
            Record::DelRemote(p) => {
                s.remote.remove(&p);
            }
            Record::Cursor(c) => s.cursor = c,
            Record::History(h) => s.history = h,
            Record::Reset => *s = State::default(),
        }
    }
}

fn frame(body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).map_err(|_| Error::new("record too large"))?;
    let mut out = Vec::with_capacity(body.len() + 40);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(body);
    let check = hd_crypto::sha256(&out).map_err(|_| Error::new("SHA-256 failed"))?;
    out.extend_from_slice(&check);
    Ok(out)
}

/// The records of a log, up to the first that does not verify.
fn read_log(bytes: &[u8], generation: u64) -> Vec<Record> {
    let mut out = Vec::new();
    if bytes.len() < 12 || &bytes[..4] != LOG_MAGIC || bytes[4..12] != generation.to_le_bytes() {
        return out;
    }
    let mut pos = 12;
    while bytes.len() - pos >= 8 {
        let mut w = [0_u8; 4];
        w.copy_from_slice(&bytes[pos..pos + 4]);
        let len = u32::from_le_bytes(w);
        w.copy_from_slice(&bytes[pos + 4..pos + 8]);
        if u32::from_le_bytes(w) != !len || len as usize > MAX_RECORD {
            break;
        }
        let end = pos + 8 + len as usize + 32;
        if end > bytes.len() {
            break;
        }
        let ok = hd_crypto::sha256(&bytes[pos..end - 32]).is_ok_and(|h| h == bytes[end - 32..end]);
        if !ok {
            break;
        }
        match Record::decode(&bytes[pos + 8..end - 32]) {
            Ok(r) => out.push(r),
            Err(_) => break,
        }
        pos = end;
    }
    if pos != bytes.len() {
        eprintln!("homedrive: the sync state log ends in a damaged record; it was ignored");
    }
    out
}

fn encode_state(s: &State, generation: u64) -> Result<Vec<u8>> {
    let mut e = Enc::new();
    e.raw(SNAP_MAGIC).u8(FORMAT).u64(generation).u64(s.cursor).str(&s.history);
    e.len(s.synced.len());
    for (p, v) in &s.synced {
        e.str(p);
        enc_synced(&mut e, v);
    }
    e.len(s.remote.len());
    for (p, v) in &s.remote {
        e.str(p);
        enc_remote(&mut e, v);
    }
    let mut out = e.finish();
    let check = hd_crypto::sha256(&out).map_err(|_| Error::new("SHA-256 failed"))?;
    out.extend_from_slice(&check);
    Ok(out)
}

fn decode_state(bytes: &[u8]) -> Result<(State, u64)> {
    if bytes.len() < 32 {
        return Err(Error::new("too short"));
    }
    let (body, check) = bytes.split_at(bytes.len() - 32);
    if hd_crypto::sha256(body).map_err(|_| Error::new("SHA-256 failed"))? != check {
        return Err(Error::new("checksum mismatch"));
    }
    let mut d = Dec::new(body);
    if d.u32()? != u32::from_le_bytes(*SNAP_MAGIC) {
        return Err(Error::new("not a state snapshot"));
    }
    let format = d.u8()?;
    if !(1..=FORMAT).contains(&format) {
        return Err(Error::new("not a state snapshot"));
    }
    let generation = d.u64()?;
    let mut s = State { cursor: d.u64()?, ..State::default() };
    if format >= 2 {
        s.history = d.str()?;
    }
    for _ in 0..d.len(8)? {
        let p = d.str()?;
        s.synced.insert(p, dec_synced(&mut d)?);
    }
    for _ in 0..d.len(8)? {
        let p = d.str()?;
        s.remote.insert(p, dec_remote(&mut d)?);
    }
    d.end()?;
    Ok((s, generation))
}

fn log_name(generation: u64) -> String {
    format!("log.{generation:020}")
}

/// The state of one folder, kept durable as it changes.
#[derive(Debug)]
pub struct Persisted {
    dir: PathBuf,
    generation: u64,
    log: Appender,
    records: u64,
    pub state: State,
}

impl Persisted {
    pub fn open(dir: &Path) -> Result<Self> {
        fsio::mkdir_durable(dir, 0o700)?;
        let staging = dir.join("staging");
        fsio::mkdir_durable(&staging, 0o700)?;
        fsio::clear_staging(&staging)?;
        let mut logs = Vec::new();
        for e in fs::read_dir(dir)? {
            let name = e?.file_name();
            if let Some(g) = name
                .to_str()
                .and_then(|n| n.strip_prefix("log."))
                .and_then(|g| g.parse::<u64>().ok())
            {
                logs.push(g);
            }
        }
        let (mut state, generation) = match fsio::read_bounded(
            dir.join("state.snap"),
            MAX_SNAPSHOT,
        )? {
            None => (State::default(), 0),
            Some(bytes) => match decode_state(&bytes) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!(
                        "homedrive: the sync state is damaged ({e}); starting afresh, which is safe"
                    );
                    (State::default(), u64::MAX)
                }
            },
        };
        // The log holds changes since the snapshot. Without the snapshot it
        // must not be applied: a "synced" record without the server's side
        // would look like a file deleted on the server. Afresh means empty.
        if generation != u64::MAX
            && let Some(bytes) = fsio::read_bounded(dir.join(log_name(generation)), MAX_LOG)?
        {
            for r in read_log(&bytes, generation) {
                r.apply(&mut state);
            }
        }
        let generation = if generation == u64::MAX { 0 } else { generation };
        // Fold into a new generation, then drop the old logs.
        let next = logs.iter().copied().max().unwrap_or(0).max(generation) + 1;
        fsio::atomic_replace(dir.join("state.snap"), &encode_state(&state, next)?, MAX_SNAPSHOT)?;
        let mut header = LOG_MAGIC.to_vec();
        header.extend_from_slice(&next.to_le_bytes());
        let log = Appender::create(dir.join(log_name(next)), &staging, &header)?;
        for g in logs {
            if g != next {
                crate::trash::remove_state_file(&dir.join(log_name(g)))?;
            }
        }
        Ok(Self { dir: dir.to_path_buf(), generation: next, log, records: 0, state })
    }

    fn record(&mut self, r: Record) -> Result<()> {
        self.log.append(&frame(&r.encode())?)?;
        r.apply(&mut self.state);
        self.records += 1;
        if self.records >= COMPACT_AFTER {
            self.compact()?;
        }
        Ok(())
    }

    fn compact(&mut self) -> Result<()> {
        let next = self.generation + 1;
        fsio::atomic_replace(
            self.dir.join("state.snap"),
            &encode_state(&self.state, next)?,
            MAX_SNAPSHOT,
        )?;
        let mut header = LOG_MAGIC.to_vec();
        header.extend_from_slice(&next.to_le_bytes());
        let log =
            Appender::create(self.dir.join(log_name(next)), self.dir.join("staging"), &header)?;
        let old = self.dir.join(log_name(self.generation));
        self.log = log;
        self.generation = next;
        self.records = 0;
        crate::trash::remove_state_file(&old)
    }

    pub fn set_synced(&mut self, path: &str, s: Synced) -> Result<()> {
        self.record(Record::SetSynced(path.to_owned(), s))
    }

    pub fn del_synced(&mut self, path: &str) -> Result<()> {
        if self.state.synced.contains_key(path) {
            self.record(Record::DelSynced(path.to_owned()))?;
        }
        Ok(())
    }

    pub fn set_remote(&mut self, path: &str, r: RemoteEntry) -> Result<()> {
        if self.state.remote.get(path) != Some(&r) {
            self.record(Record::SetRemote(path.to_owned(), r))?;
        }
        Ok(())
    }

    pub fn del_remote(&mut self, path: &str) -> Result<()> {
        if self.state.remote.contains_key(path) {
            self.record(Record::DelRemote(path.to_owned()))?;
        }
        Ok(())
    }

    pub fn set_cursor(&mut self, cursor: u64) -> Result<()> {
        if self.state.cursor != cursor {
            self.record(Record::Cursor(cursor))?;
        }
        Ok(())
    }

    pub fn set_history(&mut self, history: &str) -> Result<()> {
        if self.state.history != history {
            self.record(Record::History(history.to_owned()))?;
        }
        Ok(())
    }

    /// Forgets everything known about both sides.
    pub fn reset(&mut self) -> Result<()> {
        self.record(Record::Reset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synced(v: u64) -> Synced {
        Synced {
            kind: Kind::File,
            version: v,
            sha256: [u8::try_from(v).unwrap(); 32],
            size: v,
            mtime_ns: -1,
            ino: 2,
            dev: 3,
        }
    }

    #[test]
    fn state_survives_reopening_and_damage_only_forgets() {
        let dir = std::env::temp_dir().join(format!("hd-client-state-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        {
            let mut p = Persisted::open(&dir).unwrap();
            p.set_synced("a", synced(1)).unwrap();
            p.set_synced("b", synced(2)).unwrap();
            p.del_synced("a").unwrap();
            p.set_remote(
                "b",
                RemoteEntry { kind: Kind::File, version: 2, sha256: [2; 32], size: 2, mtime_ms: 5 },
            )
            .unwrap();
            p.set_cursor(9).unwrap();
            p.set_history("h1").unwrap();
        }
        let p = Persisted::open(&dir).unwrap();
        assert_eq!(p.state.cursor, 9);
        assert_eq!(p.state.history, "h1");
        assert_eq!(p.state.synced.keys().collect::<Vec<_>>(), ["b"]);
        assert_eq!(p.state.remote.len(), 1);
        let expected = p.state.clone();
        drop(p);
        // Reopening compacts: the state is in the snapshot alone now.
        let p = Persisted::open(&dir).unwrap();
        assert_eq!(p.state, expected);
        drop(p);
        // A damaged snapshot starts afresh rather than guessing.
        let snap = dir.join("state.snap");
        let mut bytes = fs::read(&snap).unwrap();
        bytes[20] ^= 1;
        fs::write(&snap, bytes).unwrap();
        let mut p = Persisted::open(&dir).unwrap();
        assert_eq!(p.state, State::default());
        // A damaged snapshot with a log beside it: the log is not applied
        // on its own, since half a state can look like deletions.
        p.set_synced("c", synced(3)).unwrap();
        p.set_cursor(12).unwrap();
        drop(p);
        let mut bytes = fs::read(&snap).unwrap();
        bytes[20] ^= 1;
        fs::write(&snap, bytes).unwrap();
        let p = Persisted::open(&dir).unwrap();
        assert_eq!(p.state, State::default());
        let logs = fs::read_dir(&dir)
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("log."))
            .count();
        assert_eq!(logs, 1);
        fs::remove_dir_all(&dir).unwrap();
    }
}
