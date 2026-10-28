//! The sync protocol: JSON messages under `/api/v1`, shared by the server
//! and the client so both sides encode and decode them one way.
//!
//! | Request | Body | Answer |
//! |---|---|---|
//! | `POST /api/v1/devices` (Basic, account password) | `{"name"}` | [`DeviceToken`] |
//! | `GET /api/v1/devices` | | `{"devices":[{"id","name","created_ms"}]}` |
//! | `DELETE /api/v1/devices/<id>` | | 204 |
//! | `GET /api/v1/changes?since=<seq>&wait=<s>` | | [`ChangesPage`] |
//! | `GET /api/v1/status` | | `{"problems":[text]}`: empty when the store is healthy |
//! | `GET /api/v1/damaged` | | `{"files":[{"path","version"}]}`: this user's current versions the store cannot read; a client holding the same content uploads it again |
//! | `POST /api/v1/chunks/missing` | `{"ids":[hex]}` | `{"missing":[hex]}` |
//! | `PUT /api/v1/chunks/<id>` | the chunk | 201, or 200 if already stored |
//! | `POST /api/v1/commit` | [`CommitRequest`] | [`CommitResult`], or 409 with `missing` |
//! | `GET /api/v1/file?path=&version=` | | the content, verified, with Range |
//! | `POST /api/v1/mkdir` | `{"path"}` | `{"seq"}` |
//! | `POST /api/v1/move` | `{"from","to"}` | `{"seq"}` |
//! | `POST /api/v1/copy` | `{"from","to"}` | `{"seq"}` |
//! | `POST /api/v1/trash` | `{"path"}`, optionally `"version"` or `"if_empty"` | `{"seq","trash_id"}`, or 412 |
//! | `POST /api/v1/restore` | `{"trash_id","to"}` | `{"seq"}` |
//! | `GET /api/v1/versions?path=` | | `{"versions":[VersionInfo]}` |
//! | `GET /api/v1/trash` | | `{"items":[{"id","path","deleted_ms","files"}]}` |
//! | `POST /api/v1/backup-report` (admins) | `{"kind","ok","message"}` | `{}`: records a backup run (an administrator's copy of the store) |
//! | `GET /api/v1/store-copy/...` (admins) | | a copy of the whole store, file by file (see `hd_server::copy`) |
//! | `POST /api/v1/rewind` | `{"path","at_ms","apply"}` | `{"applied","reverted","undeleted":[{"from","to"}],"newer","skipped"}`, each list with a `_count` (lists stop at 1,000) |
//!
//! A rewind puts `path` back as it was at `at_ms`: changed files get their
//! old content as a new version, and items deleted since come back from
//! the trash. Files made since stay. Nothing is removed, so it can be
//! undone by another rewind. Without `"apply": true` it only reports what
//! it would do.
//!
//! A trash request with `"version"` trashes the file only if that is still
//! its current version, and one with `"if_empty": true` trashes a folder
//! only if nothing is in it. Either answers 412 otherwise, with nothing
//! changed: the sync client's view may be stale, and another machine's new
//! edit must not be deleted on the strength of it.
//!
//! Chunks are stored once for all users. There is deliberately no way to
//! read a chunk by its ID: content is only ever read through a file the
//! requesting user owns. `chunks/missing` does say whether the store holds
//! a chunk at all, so a user who already has some content can learn that
//! another user stores it too. That is the price of deduplicating across
//! accounts, and it is acceptable only because every account on one
//! server is trusted not to probe the others.
//!
//! Everything but device registration uses `Authorization: Bearer <token>`.
//! Errors are `{"error": "<message>"}` with a 4xx or 5xx status.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

use std::fmt::Write as _;

use hd_chunk::ObjectId;
use hd_common::json::{self, Value};
use hd_common::{Error, Result};

/// The largest JSON body either side sends: a commit of a very large file
/// lists every chunk.
pub const MAX_JSON: usize = 64 * 1024 * 1024;
/// The most IDs one missing-chunks query may ask about.
pub const MAX_MISSING_QUERY: usize = 10_000;

/// A JSON value to write.
#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    I(i64),
    U(u64),
    S(String),
    A(Vec<J>),
    O(Vec<(&'static str, J)>),
}

impl J {
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::I(n) => {
                let _ = write!(out, "{n}");
            }
            J::U(n) => {
                let _ = write!(out, "{n}");
            }
            J::S(s) => json::write_string(out, s),
            J::A(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            J::O(members) => {
                out.push('{');
                for (i, (k, v)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    json::write_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

pub fn s(v: impl Into<String>) -> J {
    J::S(v.into())
}

/// `{"error": message}`.
pub fn error_body(message: &str) -> String {
    J::O(vec![("error", s(message))]).render()
}

pub fn parse(bytes: &[u8]) -> Result<Value> {
    json::parse(bytes).map_err(|e| Error::new(format!("invalid JSON: {}", e.message())))
}

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value> {
    v.get(key).ok_or_else(|| Error::new(format!("missing field {key}")))
}

pub fn get_str(v: &Value, key: &str) -> Result<String> {
    field(v, key)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::new(format!("{key} must be a string")))
}

pub fn get_u64(v: &Value, key: &str) -> Result<u64> {
    field(v, key)?.as_u64().ok_or_else(|| Error::new(format!("{key} must be a whole number")))
}

pub fn get_i64(v: &Value, key: &str) -> Result<i64> {
    field(v, key)?.as_i64().ok_or_else(|| Error::new(format!("{key} must be a whole number")))
}

pub fn get_bool(v: &Value, key: &str) -> Result<bool> {
    field(v, key)?.as_bool().ok_or_else(|| Error::new(format!("{key} must be true or false")))
}

pub fn get_id(v: &Value, key: &str) -> Result<ObjectId> {
    parse_id(&get_str(v, key)?)
}

pub fn parse_id(text: &str) -> Result<ObjectId> {
    ObjectId::parse(text).ok_or_else(|| Error::new("an ID must be 64 lowercase hex digits"))
}

pub fn get_hash(v: &Value, key: &str) -> Result<[u8; 32]> {
    Ok(get_id(v, key)?.0)
}

pub fn get_array<'a>(v: &'a Value, key: &str) -> Result<&'a [Value]> {
    field(v, key)?.as_array().ok_or_else(|| Error::new(format!("{key} must be a list")))
}

pub fn hex(bytes: &[u8]) -> String {
    hd_common::buf::hex(bytes)
}

/// A file version as the API shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionInfo {
    pub id: u64,
    pub size: u64,
    pub sha256: [u8; 32],
    pub mtime_ms: i64,
    pub created_ms: i64,
    pub device: String,
    /// "upload", "conflict", "restore", "import", or "copy".
    pub origin: String,
    pub executable: bool,
}

impl VersionInfo {
    pub fn to_json(&self) -> J {
        J::O(vec![
            ("id", J::U(self.id)),
            ("size", J::U(self.size)),
            ("sha256", s(hex(&self.sha256))),
            ("mtime_ms", J::I(self.mtime_ms)),
            ("created_ms", J::I(self.created_ms)),
            ("device", s(&*self.device)),
            ("origin", s(&*self.origin)),
            ("executable", J::Bool(self.executable)),
        ])
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        Ok(Self {
            id: get_u64(v, "id")?,
            size: get_u64(v, "size")?,
            sha256: get_hash(v, "sha256")?,
            mtime_ms: get_i64(v, "mtime_ms")?,
            created_ms: get_i64(v, "created_ms")?,
            device: get_str(v, "device")?,
            origin: get_str(v, "origin")?,
            // Absent from servers before 0.1.5.
            executable: v.get("executable").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeInfo {
    File { path: String, seq: u64, version: VersionInfo },
    Dir { path: String, seq: u64 },
    Deleted { path: String, seq: u64 },
}

impl ChangeInfo {
    pub fn path(&self) -> &str {
        match self {
            ChangeInfo::File { path, .. }
            | ChangeInfo::Dir { path, .. }
            | ChangeInfo::Deleted { path, .. } => path,
        }
    }

    pub fn to_json(&self) -> J {
        match self {
            ChangeInfo::File { path, seq, version } => J::O(vec![
                ("path", s(&**path)),
                ("seq", J::U(*seq)),
                ("kind", s("file")),
                ("version", version.to_json()),
            ]),
            ChangeInfo::Dir { path, seq } => {
                J::O(vec![("path", s(&**path)), ("seq", J::U(*seq)), ("kind", s("dir"))])
            }
            ChangeInfo::Deleted { path, seq } => {
                J::O(vec![("path", s(&**path)), ("seq", J::U(*seq)), ("kind", s("deleted"))])
            }
        }
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let path = get_str(v, "path")?;
        let seq = get_u64(v, "seq")?;
        Ok(match get_str(v, "kind")?.as_str() {
            "file" => ChangeInfo::File {
                path,
                seq,
                version: VersionInfo::from_json(field(v, "version")?)?,
            },
            "dir" => ChangeInfo::Dir { path, seq },
            "deleted" => ChangeInfo::Deleted { path, seq },
            _ => return Err(Error::new("unknown change kind")),
        })
    }
}

/// One page of the change feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangesPage {
    /// The cursor to ask from next.
    pub cursor: u64,
    /// The server's last sequence number.
    pub current: u64,
    /// The client's cursor is ahead of the server (the store was restored
    /// from an older backup): this page lists everything from the start,
    /// and the client must reconcile rather than trust what it last saw.
    pub reset: bool,
    /// The identity of the store's history. It changes when the store is
    /// restored from a backup; a client that sees it change must reconcile
    /// everything afresh, as for `reset`.
    pub history: String,
    pub more: bool,
    pub changes: Vec<ChangeInfo>,
}

impl ChangesPage {
    pub fn to_json(&self) -> String {
        J::O(vec![
            ("cursor", J::U(self.cursor)),
            ("current", J::U(self.current)),
            ("reset", J::Bool(self.reset)),
            ("history", s(&self.history)),
            ("more", J::Bool(self.more)),
            ("changes", J::A(self.changes.iter().map(ChangeInfo::to_json).collect())),
        ])
        .render()
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        Ok(Self {
            cursor: get_u64(v, "cursor")?,
            current: get_u64(v, "current")?,
            reset: get_bool(v, "reset")?,
            history: get_str(v, "history")?,
            more: get_bool(v, "more")?,
            changes: get_array(v, "changes")?
                .iter()
                .map(ChangeInfo::from_json)
                .collect::<Result<_>>()?,
        })
    }
}

/// What a commit expects to replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseSpec {
    Any,
    Absent,
    Version(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRequest {
    pub path: String,
    pub base: BaseSpec,
    pub size: u64,
    pub sha256: [u8; 32],
    pub mtime_ms: i64,
    pub chunks: Vec<(ObjectId, u32)>,
    /// Whether the file is executable; `None` (from a client that does not
    /// say) keeps what the current version says.
    pub executable: Option<bool>,
}

impl CommitRequest {
    pub fn to_json(&self) -> String {
        let base = match self.base {
            BaseSpec::Any => s("any"),
            BaseSpec::Absent => s("absent"),
            BaseSpec::Version(v) => J::U(v),
        };
        J::O(vec![
            ("path", s(&*self.path)),
            ("base", base),
            ("size", J::U(self.size)),
            ("sha256", s(hex(&self.sha256))),
            ("mtime_ms", J::I(self.mtime_ms)),
            ("executable", self.executable.map_or(J::Null, J::Bool)),
            (
                "chunks",
                J::A(
                    self.chunks
                        .iter()
                        .map(|(id, len)| J::A(vec![s(id.hex()), J::U(u64::from(*len))]))
                        .collect(),
                ),
            ),
        ])
        .render()
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        let base = match field(v, "base")? {
            Value::String(t) if t == "any" => BaseSpec::Any,
            Value::String(t) if t == "absent" => BaseSpec::Absent,
            other => BaseSpec::Version(
                other
                    .as_u64()
                    .ok_or_else(|| Error::new("base must be any, absent, or a version"))?,
            ),
        };
        let mut chunks = Vec::new();
        for item in get_array(v, "chunks")? {
            let pair = item.as_array().filter(|p| p.len() == 2);
            let Some(pair) = pair else { return Err(Error::new("each chunk is [id, length]")) };
            let id = pair[0].as_str().ok_or_else(|| Error::new("chunk id must be a string"))?;
            let len = pair[1]
                .as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| Error::new("chunk length out of range"))?;
            chunks.push((parse_id(id)?, len));
        }
        Ok(Self {
            path: get_str(v, "path")?,
            base,
            size: get_u64(v, "size")?,
            sha256: get_hash(v, "sha256")?,
            mtime_ms: get_i64(v, "mtime_ms")?,
            chunks,
            executable: match v.get("executable") {
                None | Some(Value::Null) => None,
                Some(b) => Some(
                    b.as_bool().ok_or_else(|| Error::new("executable must be true or false"))?,
                ),
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitResult {
    pub path: String,
    pub version: u64,
    pub conflict: bool,
    pub unchanged: bool,
}

impl CommitResult {
    pub fn to_json(&self) -> String {
        J::O(vec![
            ("path", s(&*self.path)),
            ("version", J::U(self.version)),
            ("conflict", J::Bool(self.conflict)),
            ("unchanged", J::Bool(self.unchanged)),
        ])
        .render()
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        Ok(Self {
            path: get_str(v, "path")?,
            version: get_u64(v, "version")?,
            conflict: get_bool(v, "conflict")?,
            unchanged: get_bool(v, "unchanged")?,
        })
    }
}

/// A newly registered device's credentials. The token is shown once.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceToken {
    pub user: String,
    pub device_id: u64,
    pub token: String,
}

impl std::fmt::Debug for DeviceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeviceToken({}, {})", self.user, self.device_id)
    }
}

impl DeviceToken {
    pub fn to_json(&self) -> String {
        J::O(vec![
            ("user", s(&*self.user)),
            ("device_id", J::U(self.device_id)),
            ("token", s(&*self.token)),
        ])
        .render()
    }

    pub fn from_json(v: &Value) -> Result<Self> {
        Ok(Self {
            user: get_str(v, "user")?,
            device_id: get_u64(v, "device_id")?,
            token: get_str(v, "token")?,
        })
    }
}

/// A device token: `hd1_<device id>_<64 hex digits of secret>`. The server
/// keeps only SHA-256 of the secret.
pub fn format_token(device_id: u64, secret: &[u8; 32]) -> String {
    format!("hd1_{device_id}_{}", hex(secret))
}

/// The device ID and secret of a token.
pub fn parse_token(token: &str) -> Option<(u64, [u8; 32])> {
    let rest = token.strip_prefix("hd1_")?;
    let (id, secret) = rest.split_once('_')?;
    let id = id.parse().ok()?;
    let secret = ObjectId::parse(secret)?;
    Some((id, secret.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T: PartialEq + std::fmt::Debug>(
        value: &T,
        enc: impl Fn(&T) -> String,
        dec: impl Fn(&Value) -> Result<T>,
    ) {
        let text = enc(value);
        assert_eq!(&dec(&parse(text.as_bytes()).unwrap()).unwrap(), value, "{text}");
    }

    #[test]
    fn messages_round_trip() {
        let id = ObjectId::of(b"x").unwrap();
        let v = VersionInfo {
            id: 3,
            size: 9,
            sha256: id.0,
            mtime_ms: -1,
            created_ms: 5,
            device: "laptop \"x\"".into(),
            origin: "upload".into(),
            executable: true,
        };
        let page = ChangesPage {
            cursor: 9,
            current: 10,
            reset: false,
            history: "0123456789abcdef0123456789abcdef".into(),
            more: true,
            changes: vec![
                ChangeInfo::File { path: "a/b.txt".into(), seq: 4, version: v },
                ChangeInfo::Dir { path: "a".into(), seq: 4 },
                ChangeInfo::Deleted { path: "ü".into(), seq: 9 },
            ],
        };
        roundtrip(&page, ChangesPage::to_json, ChangesPage::from_json);
        for (base, executable) in [
            (BaseSpec::Any, None),
            (BaseSpec::Absent, Some(true)),
            (BaseSpec::Version(7), Some(false)),
        ] {
            let c = CommitRequest {
                path: "x".into(),
                base,
                size: 1,
                sha256: id.0,
                mtime_ms: 2,
                chunks: vec![(id, 1)],
                executable,
            };
            roundtrip(&c, CommitRequest::to_json, CommitRequest::from_json);
        }
        let r = CommitResult { path: "p".into(), version: 1, conflict: true, unchanged: false };
        roundtrip(&r, CommitResult::to_json, CommitResult::from_json);
    }

    #[test]
    fn bad_messages_are_refused() {
        for bad in [
            r#"{"path":"x","base":"maybe","size":1,"sha256":"00","mtime_ms":1,"chunks":[]}"#,
            r#"{"path":"x","base":"any","size":1,"sha256":"00","mtime_ms":1,"chunks":[]}"#,
            r#"{"path":"x","base":"any","size":1,"mtime_ms":1,"chunks":[]}"#,
            r#"{"path":"x","base":-1,"size":1,"sha256":"00","mtime_ms":1,"chunks":[]}"#,
        ] {
            assert!(CommitRequest::from_json(&parse(bad.as_bytes()).unwrap()).is_err(), "{bad}");
        }
    }

    #[test]
    fn tokens() {
        let t = format_token(42, &[0xab; 32]);
        assert!(t.starts_with("hd1_42_abab"));
        assert_eq!(parse_token(&t), Some((42, [0xab; 32])));
        assert_eq!(parse_token("hd1_x_00"), None);
        assert_eq!(parse_token(&t.to_uppercase()), None);
        assert_eq!(parse_token(&t[..t.len() - 1]), None);
        let d = DeviceToken { user: "u".into(), device_id: 1, token: t };
        assert!(!format!("{d:?}").contains("abab"));
    }
}
