//! The sync API under `/api/v1` (the message formats are in `hd_api`).
//!
//! Every handler acts as the signed-in user, inside that user's drive
//! only. Writes go through the store's validated, journaled operations;
//! content is verified before it is committed and again when it is read.

use std::time::Duration;

use hd_api::{
    BaseSpec, BatchHead, BatchResult, ChangeInfo, ChangesPage, CommitRequest, CommitResult, J,
    VersionInfo, s,
};
use hd_chunk::{MAX_CHUNK, ObjectId};
use hd_common::Error;
use hd_common::timefmt;
use hd_http::{Method, ReadSource, Request, Response, StreamSource};
use hd_store::model::{ChangeKind, Node, Op, Origin, Version};
use hd_store::{Base, ChunkList, GroupFile, Kind, Provenance};

use crate::App;
use crate::auth::Who;

/// Changes per page of the feed (never splitting one record's changes).
const PAGE: usize = 5_000;
/// The longest a change-feed request waits for something to happen.
const MAX_WAIT: Duration = Duration::from_secs(60);
/// The largest batch of small JSON bodies (everything but commits).
const MAX_SMALL_JSON: usize = 1024 * 1024;

fn base_of(base: BaseSpec) -> Base {
    match base {
        BaseSpec::Any => Base::Any,
        BaseSpec::Absent => Base::Absent,
        BaseSpec::Version(v) => Base::Version(v),
    }
}

fn provenance_of(commit: &CommitRequest, who: &Who) -> Provenance {
    Provenance {
        device: who.device_name(),
        mtime_ms: commit.mtime_ms,
        origin: Origin::Upload,
        created_ms: None,
        executable: commit.executable,
    }
}

pub fn json(status: u16, body: &J) -> Response<'static> {
    Response::json(status, body.render())
}

pub fn error(status: u16, message: &str) -> Response<'static> {
    Response::json(status, hd_api::error_body(message))
}

pub fn origin_name(o: Origin) -> &'static str {
    match o {
        Origin::Upload => "upload",
        Origin::Conflict => "conflict",
        Origin::Restore => "restore",
        Origin::Import => "import",
        Origin::Copy => "copy",
    }
}

pub fn version_info(v: &Version) -> VersionInfo {
    VersionInfo {
        id: v.id,
        size: v.size,
        sha256: v.sha256,
        mtime_ms: v.mtime_ms,
        created_ms: v.created_ms,
        device: v.device.clone(),
        origin: origin_name(v.origin).to_owned(),
        executable: v.executable,
    }
}

/// An unusual-activity alert, in words for the drive's owner.
pub fn alert_text(a: &hd_store::activity::Alert) -> String {
    format!(
        "unusual activity in your drive between {} and {}: {} files changed, {} deleted, {} \
         changed so they look encrypted, within an hour. If that was not you (ransomware, a \
         device or app gone wrong), use Rewind in the web UI. Old versions and deleted files \
         are kept, and nothing is thinned or purged, until you dismiss this in the web UI",
        timefmt::rfc3339_millis(a.from_ms / 1000, 0),
        timefmt::rfc3339_millis(a.to_ms / 1000, 0),
        a.changed,
        a.deleted,
        a.suspicious
    )
}

/// The most paths of each kind a rewind answer lists; the counts are
/// always complete.
const REWIND_LIST: usize = 1_000;

fn rewind_json(r: &hd_store::RewindReport, applied: bool) -> J {
    let list = |v: &[String]| J::A(v.iter().take(REWIND_LIST).map(|p| s(&**p)).collect());
    J::O(vec![
        ("applied", J::Bool(applied)),
        ("reverted_count", J::U(r.reverted.len() as u64)),
        ("reverted", list(&r.reverted)),
        ("undeleted_count", J::U(r.undeleted.len() as u64)),
        (
            "undeleted",
            J::A(
                r.undeleted
                    .iter()
                    .take(REWIND_LIST)
                    .map(|(from, to)| J::O(vec![("from", s(&**from)), ("to", s(&**to))]))
                    .collect(),
            ),
        ),
        ("newer_count", J::U(r.newer.len() as u64)),
        ("newer", list(&r.newer)),
        ("skipped", list(&r.skipped)),
    ])
}

impl App {
    /// A failed store operation: 503 if the store has stopped accepting
    /// writes (it needs a restart), otherwise 409 with the reason.
    pub(crate) fn op_error(&self, e: &Error) -> Response<'static> {
        if self.store.is_poisoned() {
            error(503, "the store stopped accepting writes; the server needs a restart")
        } else if e.message().contains("refusing writes") {
            error(507, e.message())
        } else {
            error(409, e.message())
        }
    }

    fn read_json(
        req: &mut Request<'_, '_>,
        max: usize,
    ) -> Result<hd_common::json::Value, Response<'static>> {
        let body = req.read_body(max).map_err(|e| match e {
            hd_http::BodyError::TooLarge => error(413, "the request body is too large"),
            hd_http::BodyError::Broken => error(400, "the request body could not be read"),
        })?;
        hd_api::parse(&body).map_err(|e| error(400, e.message()))
    }

    fn commit_op(&self, op: &Op) -> Response<'static> {
        match self.store.commit(op) {
            Ok(applied) => {
                let mut fields = vec![("seq", J::U(applied.seq))];
                if let Some(t) = applied.trash_id {
                    fields.push(("trash_id", J::U(t)));
                }
                json(200, &J::O(fields))
            }
            Err(e) => self.op_error(&e),
        }
    }

    /// What `user` should hear about: the store's problems, unusual
    /// activity in their own drive, and a drive over its quota. Nothing
    /// about anyone else's files.
    pub fn problems_for(&self, user: &str) -> Vec<String> {
        let mut out = self.problems();
        if let Some(a) = self.maintenance.snapshot().alerts.iter().find(|a| a.user == user) {
            out.push(alert_text(a));
        }
        if let Some(why) = self.over_quota(user, 0) {
            out.push(why);
        }
        if self.accounts.get(user).is_some_and(|a| a.admin) {
            out.extend(self.admin_problems());
        }
        out
    }

    /// What only the administrators need to hear: backups failing or gone
    /// quiet, imports (the homelab's backups) failing, and the disk
    /// promised to more than it holds.
    pub fn admin_problems(&self) -> Vec<String> {
        let now = timefmt::unix_ms();
        let mut out = crate::backups::problems(&self.config.data_dir, now);
        let failed = self.maintenance.snapshot().failed_imports;
        let recent: Vec<&(i64, String, String)> =
            failed.iter().filter(|(at, _, _)| now - at < 2 * 86_400_000).collect();
        if let Some((at, user, why)) = recent.last() {
            out.push(format!(
                "{} import(s) failed in the last two days; the latest, into {user}'s drive at {}: \
                 {why}",
                recent.len(),
                timefmt::rfc3339_millis(at / 1000, 0)
            ));
        }
        if let Some(warning) = self.overcommitted() {
            out.push(warning);
        }
        let behind = self.maintenance.snapshot().retention_behind_ms;
        if behind > 2 * 86_400_000 {
            out.push(format!(
                "the server's clock is {} days ahead of the time that has passed (or the server \
                 was off that long); retention acts as of its own, slower clock meanwhile. If \
                 the system clock is wrong, set it right",
                behind / 86_400_000
            ));
        }
        out
    }

    /// What is wrong with the store, in words for any signed-in user (sync
    /// clients show it as a notification): nothing about anyone's files,
    /// only that the administrator needs to act.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.store.is_poisoned() {
            out.push("the server stopped accepting changes and needs a restart".to_owned());
        }
        let quarantined =
            std::fs::read_dir(self.store.root().join("quarantine")).map_or(0, Iterator::count);
        if quarantined > 0 {
            out.push(format!("{quarantined} damaged piece(s) of stored data were set aside"));
        }
        let status = self.maintenance.snapshot();
        if status.damaged_versions > 0 {
            out.push(format!("{} stored file version(s) cannot be read", status.damaged_versions));
        }
        if status.unreadable > 0 {
            out.push(format!(
                "the server's disk could not read {} piece(s) of stored data; it may be failing",
                status.unreadable
            ));
        }
        out
    }

    /// Trashes a path, if the request's precondition still holds: the
    /// check and the trash are one decision, with no commit in between.
    fn trash(&self, body: &hd_common::json::Value, user: &str) -> Response<'static> {
        let Ok(path) = hd_api::get_str(body, "path") else {
            return error(400, "path is required");
        };
        let version = match body.get("version") {
            None => None,
            Some(v) => match v.as_u64() {
                Some(v) => Some(v),
                None => return error(400, "version must be a whole number"),
            },
        };
        let if_empty = match body.get("if_empty") {
            None => false,
            Some(v) => match v.as_bool() {
                Some(b) => b,
                None => return error(400, "if_empty must be true or false"),
            },
        };
        let decided = self.store.commit_with(|st| {
            let ns = st.user(user);
            let Some(entry) = ns.and_then(|ns| ns.get(&path)) else {
                return Err(hd_common::Error::new("the path does not exist"));
            };
            if let Some(v) = version
                && entry.node.current().map(|c| c.id) != Some(v)
            {
                return Ok((None, Some("the file has changed since; nothing was deleted")));
            }
            if if_empty && ns.is_some_and(|ns| ns.subtree(&path).nth(1).is_some()) {
                return Ok((None, Some("the folder is not empty; nothing was deleted")));
            }
            let op = Op::Trash { user: user.to_owned(), path, deleted_ms: timefmt::unix_ms() };
            Ok((Some(op), None))
        });
        match decided {
            Ok((Some(applied), None)) => {
                let mut fields = vec![("seq", J::U(applied.seq))];
                if let Some(t) = applied.trash_id {
                    fields.push(("trash_id", J::U(t)));
                }
                json(200, &J::O(fields))
            }
            Ok((_, Some(why))) => error(412, why),
            Ok((None, None)) => error(500, "nothing was decided"),
            Err(e) => self.op_error(&e),
        }
    }

    /// Rewinds a folder to an earlier time (see `hd_store::rewind`):
    /// previewed unless `apply` is true.
    fn rewind(&self, body: &hd_common::json::Value, user: &str) -> Response<'static> {
        let path = body.get("path").and_then(|p| p.as_str()).unwrap_or("").to_owned();
        let Ok(at_ms) = hd_api::get_i64(body, "at_ms") else {
            return error(400, "at_ms is required");
        };
        let apply = body.get("apply").and_then(hd_common::json::Value::as_bool).unwrap_or(false);
        match self.store.rewind(user, &path, at_ms, apply) {
            Ok(r) => json(200, &rewind_json(&r, apply)),
            Err(e) if self.store.is_poisoned() => self.op_error(&e),
            Err(e) => error(400, e.message()),
        }
    }

    pub(crate) fn api<'a>(
        &'a self,
        req: &mut Request<'_, '_>,
        who: &Who,
        route: &str,
    ) -> Response<'a> {
        let user = who.user.as_str();
        let small = |req: &mut Request<'_, '_>| Self::read_json(req, MAX_SMALL_JSON);
        match (req.method, route) {
            (Method::Get, "whoami") => json(
                200,
                &J::O(vec![
                    ("user", s(user)),
                    ("admin", J::Bool(who.admin)),
                    ("device_id", who.device.as_ref().map_or(J::Null, |(id, _)| J::U(*id))),
                    ("used_bytes", J::U(self.usage(user))),
                    ("quota_bytes", J::U(self.accounts.get(user).map_or(0, |a| a.quota))),
                ]),
            ),
            (Method::Post, "devices") => self.register_device(req, who),
            (Method::Get, "damaged") => {
                let files: Vec<J> = self
                    .maintenance
                    .snapshot()
                    .damaged_current
                    .into_iter()
                    .filter(|d| d.user == user)
                    .map(|d| J::O(vec![("path", s(d.path)), ("version", J::U(d.version))]))
                    .collect();
                json(200, &J::O(vec![("files", J::A(files))]))
            }
            (Method::Get, "status") => json(
                200,
                &J::O(vec![(
                    "problems",
                    J::A(self.problems_for(user).into_iter().map(s).collect()),
                )]),
            ),
            (Method::Get, "devices") => {
                let list = self.store.read(|st| {
                    st.user(user).map_or_else(Vec::new, |ns| {
                        ns.devices
                            .values()
                            .map(|d| {
                                J::O(vec![
                                    ("id", J::U(d.id)),
                                    ("name", s(&*d.name)),
                                    ("created_ms", J::I(d.created_ms)),
                                ])
                            })
                            .collect()
                    })
                });
                json(200, &J::O(vec![("devices", J::A(list))]))
            }
            (Method::Delete, r) if r.starts_with("devices/") => {
                let Ok(id) = r["devices/".len()..].parse::<u64>() else {
                    return error(404, "no such device");
                };
                self.commit_op(&Op::DeviceRevoke { user: user.to_owned(), device_id: id })
            }
            (Method::Get, "changes") => self.changes(req, user),
            (Method::Post, "chunks/missing") => {
                let body = match small(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let Ok(ids) = hd_api::get_array(&body, "ids") else {
                    return error(400, "ids must be a list");
                };
                if ids.len() > hd_api::MAX_MISSING_QUERY {
                    return error(413, "too many ids in one query");
                }
                let mut missing = Vec::new();
                for v in ids {
                    let Some(id) = v.as_str().and_then(ObjectId::parse) else {
                        return error(400, "each id must be 64 lowercase hex digits");
                    };
                    if !self.store.objects().contains(Kind::Chunk, &id) {
                        missing.push(s(id.hex()));
                    }
                }
                json(200, &J::O(vec![("missing", J::A(missing))]))
            }
            (Method::Put, r) if r.starts_with("chunks/") => {
                let Some(id) = ObjectId::parse(&r["chunks/".len()..]) else {
                    return error(404, "no such chunk");
                };
                if let Some(why) = self.over_quota(user, 0) {
                    return error(507, &why);
                }
                let data = match req.read_body(MAX_CHUNK) {
                    Ok(d) => d,
                    Err(hd_http::BodyError::TooLarge) => {
                        return error(413, "a chunk is at most 4 MiB");
                    }
                    Err(hd_http::BodyError::Broken) => {
                        return error(400, "the chunk could not be read");
                    }
                };
                if data.len() as u64 > self.room(user) {
                    return error(507, &self.quota_message(user));
                }
                match self.store.objects().put_claimed(Kind::Chunk, &id, &data) {
                    Ok(hd_common::fsio::Created::New) => {
                        self.note_chunk(user, data.len() as u64);
                        Response::empty(201)
                    }
                    Ok(hd_common::fsio::Created::Existed) => Response::empty(200),
                    Err(e) if e.message().contains("does not match") => error(422, e.message()),
                    Err(e) => self.op_error(&e),
                }
            }
            (Method::Post, "commit") => self.commit(req, who),
            (Method::Post, "upload-batch") => self.upload_batch(req, who),
            (Method::Post, "download-batch") => match small(req) {
                Ok(body) => self.download_batch(&body, user),
                Err(r) => r,
            },
            (Method::Get | Method::Head, "file") => self.download(req, user),
            (Method::Post, "mkdir") => match small(req)
                .and_then(|b| hd_api::get_str(&b, "path").map_err(|e| error(400, e.message())))
            {
                Ok(path) => self.commit_op(&Op::Mkdir { user: user.to_owned(), path }),
                Err(r) => r,
            },
            (Method::Post, "move" | "copy") => {
                let body = match small(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Ok(from), Ok(to)) =
                    (hd_api::get_str(&body, "from"), hd_api::get_str(&body, "to"))
                else {
                    return error(400, "from and to are required");
                };
                if route == "copy" {
                    let adding = self.store.read(|st| {
                        st.user(user)
                            .and_then(|ns| ns.get(&from))
                            .and_then(|e| e.node.current())
                            .map_or(0, |v| v.size)
                    });
                    if let Some(why) = self.over_quota(user, adding) {
                        return error(507, &why);
                    }
                }
                let user = user.to_owned();
                self.commit_op(&if route == "move" {
                    Op::Move { user, from, to }
                } else {
                    Op::Copy { user, from, to, created_ms: timefmt::unix_ms() }
                })
            }
            (Method::Post, "trash") => match small(req) {
                Ok(body) => self.trash(&body, user),
                Err(r) => r,
            },
            (Method::Post, "restore") => {
                let body = match small(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Ok(trash_id), Ok(to)) =
                    (hd_api::get_u64(&body, "trash_id"), hd_api::get_str(&body, "to"))
                else {
                    return error(400, "trash_id and to are required");
                };
                self.commit_op(&Op::Restore { user: user.to_owned(), trash_id, to })
            }
            // An administrator's copy (homedrive backup-store) reports here,
            // with an
            // administrator's device token.
            (Method::Post, "backup-report") => {
                if !who.admin {
                    return error(403, "only an administrator can report backups");
                }
                let body = match small(req) {
                    Ok(b) => b,
                    Err(r) => return r,
                };
                let (Ok(kind), Ok(good)) =
                    (hd_api::get_str(&body, "kind"), hd_api::get_bool(&body, "ok"))
                else {
                    return error(400, "kind and ok are required");
                };
                let message = hd_api::get_str(&body, "message").unwrap_or_default();
                match crate::backups::record(&self.config.data_dir, &kind, good, &message) {
                    Ok(()) => {
                        if !good {
                            eprintln!("hd-server: ALERT: the {kind} backup failed: {message}");
                        }
                        json(200, &J::O(vec![]))
                    }
                    Err(e) => error(400, e.message()),
                }
            }
            (Method::Get, r) if r.starts_with("store-copy/") => {
                if !who.admin {
                    return error(403, "only an administrator can copy the store");
                }
                self.store_copy(req, r)
            }
            (Method::Post, "rewind") => match small(req) {
                Ok(body) => self.rewind(&body, user),
                Err(r) => r,
            },
            (Method::Get, "versions") => {
                let path = req.query_value("path").unwrap_or("").to_owned();
                let found =
                    self.store.read(|st| match st.user(user).and_then(|ns| ns.get(&path)) {
                        Some(e) => match &e.node {
                            Node::File { versions, .. } => Some(
                                versions
                                    .iter()
                                    .map(|v| version_info(v).to_json())
                                    .collect::<Vec<_>>(),
                            ),
                            Node::Dir => None,
                        },
                        None => None,
                    });
                match found {
                    Some(list) => json(200, &J::O(vec![("versions", J::A(list))])),
                    None => error(404, "no file at that path"),
                }
            }
            (Method::Get, "trash") => {
                let items = self.store.read(|st| {
                    st.user(user).map_or_else(Vec::new, |ns| {
                        ns.trash
                            .values()
                            .map(|t| {
                                J::O(vec![
                                    ("id", J::U(t.id)),
                                    ("path", s(&*t.path)),
                                    ("deleted_ms", J::I(t.deleted_ms)),
                                    (
                                        "files",
                                        J::U(t.entries.iter().filter(|(_, n)| !n.is_dir()).count()
                                            as u64),
                                    ),
                                ])
                            })
                            .collect()
                    })
                });
                json(200, &J::O(vec![("items", J::A(items))]))
            }
            _ => error(404, "no such API call"),
        }
    }

    fn register_device(&self, req: &mut Request<'_, '_>, who: &Who) -> Response<'static> {
        if who.device.is_some() {
            return error(403, "register devices with the account password, not a device token");
        }
        let body = match Self::read_json(req, MAX_SMALL_JSON) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let Ok(name) = hd_api::get_str(&body, "name") else {
            return error(400, "a device needs a name");
        };
        let Ok(secret) = hd_crypto::random_array::<32>() else {
            return error(500, "randomness failed");
        };
        let Ok(token_hash) = hd_crypto::sha256(&secret) else {
            return error(500, "hashing failed");
        };
        let op = Op::DeviceAdd {
            user: who.user.clone(),
            name: name.clone(),
            token_hash,
            created_ms: timefmt::unix_ms(),
        };
        match self.store.commit(&op) {
            Ok(applied) => {
                let device_id = applied.device_id.unwrap_or(0);
                eprintln!("hd-server: {} registered device {device_id} ({name})", who.user);
                let token = hd_api::DeviceToken {
                    user: who.user.clone(),
                    device_id,
                    token: hd_api::format_token(device_id, &secret),
                };
                Response::json(201, token.to_json())
            }
            Err(e) => self.op_error(&e),
        }
    }

    fn changes(&self, req: &Request<'_, '_>, user: &str) -> Response<'static> {
        let since = req.query_value("since").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let wait = req
            .query_value("wait")
            .and_then(|v| v.parse::<u64>().ok())
            .map_or(Duration::ZERO, |w| Duration::from_secs(w).min(MAX_WAIT));
        let deadline = std::time::Instant::now() + wait;
        loop {
            let page = self.store.read(|st| {
                let reset = since > st.seq;
                let from = if reset { 0 } else { since };
                // Nothing recorded since: a client waiting for news asks
                // this often, and a drive can hold a million entries.
                let (changes, more) = if from == st.seq {
                    (Vec::new(), false)
                } else {
                    st.user(user).map_or((Vec::new(), false), |ns| ns.changes(from, PAGE))
                };
                let cursor = if more { changes.last().map_or(st.seq, |c| c.seq) } else { st.seq };
                let changes = changes
                    .into_iter()
                    .map(|c| match c.kind {
                        ChangeKind::File(v) => {
                            ChangeInfo::File { path: c.path, seq: c.seq, version: version_info(&v) }
                        }
                        ChangeKind::Dir => ChangeInfo::Dir { path: c.path, seq: c.seq },
                        ChangeKind::Deleted => ChangeInfo::Deleted { path: c.path, seq: c.seq },
                    })
                    .collect();
                ChangesPage {
                    cursor,
                    current: st.seq,
                    reset,
                    history: self.store.history().to_owned(),
                    more,
                    changes,
                }
            });
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if !page.changes.is_empty() || page.reset || left.is_zero() {
                return Response::json(200, page.to_json());
            }
            self.store.wait_for_change(page.current, left);
        }
    }

    fn commit(&self, req: &mut Request<'_, '_>, who: &Who) -> Response<'static> {
        let body = match Self::read_json(req, hd_api::MAX_JSON) {
            Ok(b) => b,
            Err(r) => return r,
        };
        let commit = match CommitRequest::from_json(&body) {
            Ok(c) => c,
            Err(e) => return error(400, e.message()),
        };
        if commit.size > self.config.max_file {
            return error(413, "the file is larger than the server accepts");
        }
        let missing: Vec<J> = commit
            .chunks
            .iter()
            .filter(|(id, _)| !self.has_chunk(id))
            .map(|(id, _)| s(id.hex()))
            .collect();
        if !missing.is_empty() {
            return json(
                409,
                &J::O(vec![
                    ("error", s("some chunks are missing; upload them and commit again")),
                    ("missing", J::A(missing)),
                ]),
            );
        }
        let base = base_of(commit.base);
        let provenance = provenance_of(&commit, who);
        // The commit's own chunks were counted as pending when uploaded;
        // what the commit adds to the drive is checked against what it
        // holds, and then replaces them in the count.
        let quota = self.accounts.get(&who.user).map_or(0, |a| a.quota);
        if self.usage(&who.user).saturating_add(commit.size) > quota {
            return error(507, &self.quota_message(&who.user));
        }
        let list = ChunkList { chunks: &commit.chunks, size: commit.size, sha256: commit.sha256 };
        match self.store.commit_chunks(&who.user, &commit.path, base, &list, &provenance) {
            Ok(c) => {
                self.note_commit(&who.user, commit.size);
                Response::json(
                    200,
                    CommitResult {
                        path: c.path,
                        version: c.version,
                        conflict: c.conflict,
                        unchanged: c.unchanged,
                    }
                    .to_json(),
                )
            }
            Err(e) => self.op_error(&e),
        }
    }

    fn has_chunk(&self, id: &ObjectId) -> bool {
        self.store.objects().contains(Kind::Chunk, id)
    }

    /// Several small files in one request (see [`BatchHead`]). The checks
    /// are those of `PUT chunks/` and `commit`, and the reply comes once
    /// everything in it is durable; only the disk's work is shared, by
    /// storing side by side and flushing the journal once.
    fn upload_batch(&self, req: &mut Request<'_, '_>, who: &Who) -> Response<'static> {
        let user = who.user.as_str();
        if let Some(why) = self.over_quota(user, 0) {
            return error(507, &why);
        }
        let limit = 4 + hd_api::MAX_BATCH_JSON + hd_api::MAX_BATCH_BYTES;
        let body = match req.read_body(limit) {
            Ok(b) => b,
            Err(hd_http::BodyError::TooLarge) => return error(413, "the batch is too large"),
            Err(hd_http::BodyError::Broken) => return error(400, "the batch could not be read"),
        };
        let (batch, data) = match BatchHead::from_body(&body) {
            Ok(parsed) => parsed,
            Err(e) => return error(400, e.message()),
        };
        if batch.commits.len() > hd_api::MAX_BATCH_FILES {
            return error(413, "too many files in one batch");
        }
        let size: usize = data.iter().map(|d| d.len()).sum();
        if data.iter().any(|d| d.len() > MAX_CHUNK) || size > hd_api::MAX_BATCH_BYTES {
            return error(413, "the batch is too large");
        }
        if size as u64 > self.room(user) {
            return error(507, &self.quota_message(user));
        }
        let pairs: Vec<_> = batch.chunks.iter().zip(&data).collect();
        let stored = hd_store::in_parallel(&pairs, |((id, _), bytes)| {
            self.store.objects().put_claimed(Kind::Chunk, id, bytes)
        });
        let mut problem = None;
        for (result, bytes) in stored.iter().zip(&data) {
            match result {
                Ok(hd_common::fsio::Created::New) => self.note_chunk(user, bytes.len() as u64),
                Ok(hd_common::fsio::Created::Existed) => {}
                Err(e) if e.message().contains("does not match") => {
                    problem = Some(error(422, e.message()));
                }
                Err(e) => problem = Some(self.op_error(e)),
            }
        }
        if let Some(response) = problem {
            return response;
        }
        // Every file gets an answer: these are the ones that may proceed.
        let mut results: Vec<Option<BatchResult>> = vec![None; batch.commits.len()];
        let quota = self.accounts.get(user).map_or(0, |a| a.quota);
        let mut holds = self.usage(user);
        let mut going = Vec::new();
        for (i, c) in batch.commits.iter().enumerate() {
            if c.size > self.config.max_file {
                results[i] = Some(BatchResult::Refused(
                    "the file is larger than the server accepts".to_owned(),
                ));
            } else if c.chunks.iter().any(|(id, _)| !self.has_chunk(id)) {
                results[i] = Some(BatchResult::Missing);
            } else if holds.saturating_add(c.size) > quota {
                results[i] = Some(BatchResult::Refused(self.quota_message(user)));
            } else {
                holds = holds.saturating_add(c.size);
                going.push(i);
            }
        }
        let provenances: Vec<Provenance> =
            going.iter().map(|&i| provenance_of(&batch.commits[i], who)).collect();
        let files: Vec<GroupFile<'_>> = going
            .iter()
            .zip(&provenances)
            .map(|(&i, provenance)| {
                let c = &batch.commits[i];
                GroupFile {
                    path: &c.path,
                    base: base_of(c.base),
                    list: ChunkList { chunks: &c.chunks, size: c.size, sha256: c.sha256 },
                    provenance,
                }
            })
            .collect();
        let committed = match self.store.commit_chunks_group(user, &files) {
            Ok(committed) => committed,
            Err(e) => return self.op_error(&e),
        };
        for (&i, outcome) in going.iter().zip(committed) {
            results[i] = Some(match outcome {
                Ok(c) => {
                    self.note_commit(user, batch.commits[i].size);
                    BatchResult::Done(CommitResult {
                        path: c.path,
                        version: c.version,
                        conflict: c.conflict,
                        unchanged: c.unchanged,
                    })
                }
                Err(e) => BatchResult::Refused(e.message().to_owned()),
            });
        }
        let rendered: Vec<String> = results.iter().flatten().map(BatchResult::to_json).collect();
        Response::json(200, format!(r#"{{"results":[{}]}}"#, rendered.join(",")))
    }

    /// Several small files in one reply, each read and verified as a single
    /// download is. One that is gone, too large to fit, or damaged comes
    /// back as `null`, and asking for it alone gets the real answer.
    fn download_batch(&self, body: &hd_common::json::Value, user: &str) -> Response<'static> {
        let Ok(files) = hd_api::get_array(body, "files") else {
            return error(400, "files must be a list");
        };
        if files.len() > hd_api::MAX_BATCH_FILES {
            return error(413, "too many files in one batch");
        }
        let mut wanted = Vec::with_capacity(files.len());
        for file in files {
            let (Ok(path), Ok(version)) =
                (hd_api::get_str(file, "path"), hd_api::get_u64(file, "version"))
            else {
                return error(400, "each file needs a path and a version");
            };
            wanted.push((path, version));
        }
        let mut room = hd_api::MAX_BATCH_BYTES as u64;
        let found: Vec<Option<Version>> = self.store.read(|st| {
            let drive = st.user(user);
            wanted
                .iter()
                .map(|(path, id)| {
                    let Some(Node::File { versions, .. }) =
                        drive.and_then(|d| d.get(path)).map(|e| &e.node)
                    else {
                        return None;
                    };
                    let version = versions.iter().find(|v| v.id == *id)?;
                    room = room.checked_sub(version.size)?;
                    Some(version.clone())
                })
                .collect()
        });
        let read = hd_store::in_parallel(&found, |version| {
            let version = version.as_ref()?;
            let mut reader = self.store.open_content(&version.manifest).ok()?;
            // Read to the very end: that is where the whole file is checked.
            let size = usize::try_from(version.size).ok()?;
            let mut bytes = vec![0; size + 1];
            let mut filled = 0;
            loop {
                match std::io::Read::read(&mut reader, &mut bytes[filled..]).ok()? {
                    0 => break,
                    got => filled += got,
                }
                if filled > size {
                    return None;
                }
            }
            bytes.truncate(filled);
            (filled == size).then_some(bytes)
        });
        Response::new(200, "application/octet-stream", hd_api::fetch_reply(&read))
    }

    /// The current version (or `version=`) of a file, verified as it is
    /// sent, with Range.
    pub(crate) fn download<'a>(&'a self, req: &Request<'_, '_>, user: &str) -> Response<'a> {
        let path = req.query_value("path").unwrap_or("").to_owned();
        let wanted = req.query_value("version").and_then(|v| v.parse::<u64>().ok());
        self.serve_version(req, user, &path, wanted)
    }

    pub(crate) fn serve_version<'a>(
        &'a self,
        req: &Request<'_, '_>,
        user: &str,
        path: &str,
        wanted: Option<u64>,
    ) -> Response<'a> {
        let found = self.store.read(|st| {
            match st.user(user).and_then(|ns| ns.get(path)).map(|e| &e.node) {
                Some(Node::File { versions, .. }) => match wanted {
                    Some(id) => versions.iter().find(|v| v.id == id).cloned(),
                    None => versions.last().cloned(),
                },
                _ => None,
            }
        });
        let Some(version) = found else { return error(404, "no such file or version") };
        let store = &self.store;
        let manifest = version.manifest;
        Response::ranged(
            req.header("range"),
            "application/octet-stream",
            version.size,
            move |offset| {
                let mut reader = store
                    .open_content(&manifest)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                reader.seek_to(offset).map_err(|e| std::io::Error::other(e.to_string()))?;
                Ok(Box::new(ReadSource(reader)) as Box<dyn StreamSource + 'a>)
            },
        )
        .with_header("ETag", format!("\"v{}\"", version.id))
    }
}
