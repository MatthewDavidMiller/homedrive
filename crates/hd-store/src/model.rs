//! The metadata: every user's tree of directories and files, each file's
//! versions, and the trash, together with the operations that change them.
//!
//! The state is a pure function of the journal. [`State::apply`] is
//! deterministic: it uses no clock, no randomness, and no I/O, and every
//! identifier it hands out comes from the state's own counter. Replaying
//! the same records always rebuilds the same state, which is what lets the
//! journal be the only thing written for each change.
//!
//! Every operation is validated against the state before it is written
//! ([`State::validate`]), and applying a validated operation cannot fail.
//! A record that fails to apply during replay therefore means the journal
//! or this code is wrong, and the store refuses to open rather than guess.
//!
//! No operation destroys file content. Overwrites add a version, deletes
//! move a subtree to the trash, and moves keep every file's history. Only
//! [`Op::DropVersion`] and [`Op::Purge`] release content, and only
//! retention issues them (M3).

use std::collections::BTreeMap;

use hd_chunk::ObjectId;
use hd_common::pathname;
use hd_common::{Error, Result};

use crate::codec::{Dec, Enc};

pub const MAX_USER_NAME: usize = 64;
pub const MAX_DEVICE_NAME: usize = 64;

/// How a version came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Upload,
    /// Stored beside the file it conflicted with, under a conflict name.
    Conflict,
    Restore,
    Import,
    Copy,
}

impl Origin {
    fn byte(self) -> u8 {
        match self {
            Origin::Upload => 1,
            Origin::Conflict => 2,
            Origin::Restore => 3,
            Origin::Import => 4,
            Origin::Copy => 5,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            1 => Origin::Upload,
            2 => Origin::Conflict,
            3 => Origin::Restore,
            4 => Origin::Import,
            5 => Origin::Copy,
            _ => return Err(Error::new("unknown version origin")),
        })
    }
}

/// One stored version of a file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    /// Unique across the whole store and never reused.
    pub id: u64,
    pub manifest: ObjectId,
    pub size: u64,
    pub sha256: [u8; 32],
    /// The file's modification time on the device that made it.
    pub mtime_ms: i64,
    /// When the server stored it.
    pub created_ms: i64,
    pub device: String,
    pub origin: Origin,
    /// The file is a program (its execute permission is set).
    pub executable: bool,
}

/// The content of a version, as an operation carries it before the
/// version has an ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content {
    pub manifest: ObjectId,
    pub size: u64,
    pub sha256: [u8; 32],
    pub mtime_ms: i64,
    pub created_ms: i64,
    pub device: String,
    pub origin: Origin,
    pub executable: bool,
}

impl Content {
    fn version(&self, id: u64) -> Version {
        Version {
            id,
            manifest: self.manifest,
            size: self.size,
            sha256: self.sha256,
            mtime_ms: self.mtime_ms,
            created_ms: self.created_ms,
            device: self.device.clone(),
            origin: self.origin,
            executable: self.executable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Dir,
    /// `versions` is oldest first and never empty; the last is current.
    File {
        file_id: u64,
        versions: Vec<Version>,
    },
}

impl Node {
    pub fn current(&self) -> Option<&Version> {
        match self {
            Node::Dir => None,
            Node::File { versions, .. } => versions.last(),
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self, Node::Dir)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub node: Node,
    /// The sequence number of the last record that changed this entry.
    pub changed: u64,
}

/// A deleted file or directory tree, restorable until purged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrashItem {
    pub id: u64,
    /// Where it was.
    pub path: String,
    pub deleted_ms: i64,
    /// The item itself (relative path `""`) and, for a directory,
    /// everything beneath it, relative to `path`.
    pub entries: Vec<(String, Node)>,
}

/// A device allowed to sync. Only a hash of its token is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Device {
    pub id: u64,
    pub name: String,
    pub token_hash: [u8; 32],
    pub created_ms: i64,
}

/// One user's drive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Namespace {
    pub entries: BTreeMap<String, Entry>,
    pub trash: BTreeMap<u64, TrashItem>,
    /// Paths that stopped existing, with the record that removed them: the
    /// change feed reports them as deletions.
    pub removed: BTreeMap<String, u64>,
    pub devices: BTreeMap<u64, Device>,
}

/// One entry of the change feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub path: String,
    /// The record that made this change.
    pub seq: u64,
    pub kind: ChangeKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// A file, with its current version.
    File(Version),
    Dir,
    /// The path no longer exists.
    Deleted,
}

/// The whole store's metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    /// The sequence number of the last record applied.
    pub seq: u64,
    /// The next identifier to hand out for a file, version, or trash item.
    pub next_id: u64,
    pub users: BTreeMap<String, Namespace>,
}

impl Default for State {
    fn default() -> Self {
        Self { seq: 0, next_id: 1, users: BTreeMap::new() }
    }
}

/// A change to the metadata: the body of one journal record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Adds a version to the file at `path`, creating the file and any
    /// missing parent directories.
    PutVersion {
        user: String,
        path: String,
        content: Content,
    },
    /// Creates a directory and any missing parents. Creating one that
    /// exists is allowed and changes nothing.
    Mkdir {
        user: String,
        path: String,
    },
    /// Moves a file or directory tree, keeping every file's history.
    Move {
        user: String,
        from: String,
        to: String,
    },
    /// Makes a new file at `to` whose one version is `from`'s current one.
    Copy {
        user: String,
        from: String,
        to: String,
        created_ms: i64,
    },
    /// Moves a file or directory tree into the trash.
    Trash {
        user: String,
        path: String,
        deleted_ms: i64,
    },
    /// Puts a trash item back at `to`.
    Restore {
        user: String,
        trash_id: u64,
        to: String,
    },
    /// Removes a trash item for good (retention only).
    Purge {
        user: String,
        trash_id: u64,
    },
    /// Removes one old version of a live file (retention only). The
    /// current version can never be dropped.
    DropVersion {
        user: String,
        path: String,
        version_id: u64,
    },
    /// Registers a device; `token_hash` is the SHA-256 of its secret.
    DeviceAdd {
        user: String,
        name: String,
        token_hash: [u8; 32],
        created_ms: i64,
    },
    DeviceRevoke {
        user: String,
        device_id: u64,
    },
}

/// What applying an operation produced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub seq: u64,
    /// The new version, for `PutVersion` and `Copy`.
    pub version: Option<u64>,
    /// The new trash item, for `Trash`.
    pub trash_id: Option<u64>,
    /// The new device, for `DeviceAdd`.
    pub device_id: Option<u64>,
}

fn bad(message: &str) -> Error {
    Error::new(message)
}

pub fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user.len() > MAX_USER_NAME
        || !user.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(bad("invalid user name"));
    }
    Ok(())
}

fn validate_device(device: &str) -> Result<()> {
    if device.len() > MAX_DEVICE_NAME || device.chars().any(char::is_control) {
        return Err(bad("invalid device name"));
    }
    Ok(())
}

/// A path an operation acts on: valid and not the root.
fn target(path: &str) -> Result<()> {
    pathname::validate(path)?;
    if path.is_empty() {
        return Err(bad("the drive's root cannot be the target"));
    }
    Ok(())
}

/// The first and last keys of everything strictly beneath `dir`: keys
/// starting with "dir/" sort together, between "dir/" and "dir0" ('0' is
/// the byte after '/').
fn below(dir: &str) -> (String, String) {
    (format!("{dir}/"), format!("{dir}0"))
}

impl Namespace {
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    /// Everything that changed after record `since`, oldest first. At most
    /// about `limit` changes are returned, but never part of one record's
    /// changes (a moved directory changes many paths at once). The `bool`
    /// says more remain; continue from the last change's `seq`.
    pub fn changes(&self, since: u64, limit: usize) -> (Vec<Change>, bool) {
        let mut all: Vec<Change> = Vec::new();
        for (path, entry) in &self.entries {
            if entry.changed > since {
                let kind = match &entry.node {
                    Node::Dir => ChangeKind::Dir,
                    Node::File { versions, .. } => match versions.last() {
                        Some(v) => ChangeKind::File(v.clone()),
                        None => continue,
                    },
                };
                all.push(Change { path: path.clone(), seq: entry.changed, kind });
            }
        }
        for (path, &seq) in &self.removed {
            if seq > since {
                all.push(Change { path: path.clone(), seq, kind: ChangeKind::Deleted });
            }
        }
        all.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.path.cmp(&b.path)));
        if all.len() <= limit {
            return (all, false);
        }
        let cut_seq = all[limit.max(1) - 1].seq;
        let end = all.iter().position(|c| c.seq > cut_seq).unwrap_or(all.len());
        let more = end < all.len();
        all.truncate(end);
        (all, more)
    }

    /// Bytes this drive holds: every version of every file, in the drive
    /// and in its trash, counted at full size (content shared with other
    /// files or drives is counted for each). What a quota limits.
    pub fn stored_bytes(&self) -> u64 {
        let versions = |n: &Node| match n {
            Node::File { versions, .. } => versions.iter().map(|v| v.size).sum(),
            Node::Dir => 0,
        };
        let live: u64 = self.entries.values().map(|e| versions(&e.node)).sum();
        let trashed: u64 =
            self.trash.values().flat_map(|t| t.entries.iter()).map(|(_, n)| versions(n)).sum();
        live.saturating_add(trashed)
    }

    /// The device with `id`.
    pub fn device(&self, id: u64) -> Option<&Device> {
        self.devices.get(&id)
    }

    /// `path` and everything beneath it, in key order; for the root
    /// (`""`), everything.
    pub fn subtree<'a>(
        &'a self,
        path: &'a str,
    ) -> Box<dyn Iterator<Item = (&'a String, &'a Entry)> + 'a> {
        if path.is_empty() {
            return Box::new(self.entries.iter());
        }
        let (lo, hi) = below(path);
        Box::new(self.entries.get_key_value(path).into_iter().chain(self.entries.range(lo..hi)))
    }

    /// The entries directly inside `dir` (the root is `""`).
    pub fn children<'a>(&'a self, dir: &'a str) -> impl Iterator<Item = (&'a String, &'a Entry)> {
        let range: Box<dyn Iterator<Item = (&String, &Entry)>> = if dir.is_empty() {
            Box::new(self.entries.iter())
        } else {
            let (lo, hi) = below(dir);
            Box::new(self.entries.range(lo..hi))
        };
        range.filter(move |(p, _)| pathname::parent(p) == dir)
    }

    /// Every ancestor of `path` must be absent (to be created) or a
    /// directory.
    fn check_parents(&self, path: &str) -> Result<()> {
        for dir in pathname::ancestors(path) {
            if let Some(e) = self.entries.get(dir)
                && !e.node.is_dir()
            {
                return Err(bad("a parent of the path is a file"));
            }
        }
        Ok(())
    }

    fn ensure_parents(&mut self, path: &str, seq: u64) {
        for dir in pathname::ancestors(path) {
            if !self.entries.contains_key(dir) {
                self.insert(dir.to_owned(), Node::Dir, seq);
            }
        }
    }

    fn insert(&mut self, path: String, node: Node, seq: u64) {
        self.removed.remove(&path);
        self.entries.insert(path, Entry { node, changed: seq });
    }

    /// Removes `path` and everything beneath it, returning them relative to
    /// `path` (the item itself as `""`), parents before children.
    fn take_subtree(&mut self, path: &str, seq: u64) -> Vec<(String, Node)> {
        let keys: Vec<String> = self.subtree(path).map(|(k, _)| k.clone()).collect();
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(entry) = self.entries.remove(&key) {
                let rel =
                    if key == path { String::new() } else { key[path.len() + 1..].to_owned() };
                self.removed.insert(key, seq);
                out.push((rel, entry.node));
            }
        }
        out
    }

    fn put_subtree(&mut self, at: &str, nodes: Vec<(String, Node)>, seq: u64) {
        for (rel, node) in nodes {
            let path = if rel.is_empty() { at.to_owned() } else { pathname::join(at, &rel) };
            self.insert(path, node, seq);
        }
    }

    /// The path a new entry may be created at: free, and under directories.
    fn check_free(&self, path: &str) -> Result<()> {
        target(path)?;
        if self.entries.contains_key(path) {
            return Err(bad("the destination already exists"));
        }
        self.check_parents(path)
    }
}

impl State {
    /// The namespace of `user`, if the user has stored anything.
    pub fn user(&self, user: &str) -> Option<&Namespace> {
        self.users.get(user)
    }

    /// Checks that `op` can be applied, without changing anything.
    pub fn validate(&self, op: &Op) -> Result<()> {
        let user = op.user();
        validate_user(user)?;
        let empty = Namespace::default();
        let ns = self.users.get(user).unwrap_or(&empty);
        match op {
            Op::PutVersion { path, content, .. } => {
                target(path)?;
                validate_device(&content.device)?;
                ns.check_parents(path)?;
                if ns.get(path).is_some_and(|e| e.node.is_dir()) {
                    return Err(bad("a directory exists at the path"));
                }
            }
            Op::Mkdir { path, .. } => {
                target(path)?;
                ns.check_parents(path)?;
                if ns.get(path).is_some_and(|e| !e.node.is_dir()) {
                    return Err(bad("a file exists at the path"));
                }
            }
            Op::Move { from, to, .. } => {
                target(from)?;
                if ns.get(from).is_none() {
                    return Err(bad("the source does not exist"));
                }
                if pathname::is_within(to, from) {
                    return Err(bad("cannot move a directory into itself"));
                }
                ns.check_free(to)?;
            }
            Op::Copy { from, to, .. } => {
                target(from)?;
                match ns.get(from) {
                    Some(Entry { node: Node::File { .. }, .. }) => {}
                    Some(_) => return Err(bad("only files can be copied")),
                    None => return Err(bad("the source does not exist")),
                }
                ns.check_free(to)?;
            }
            Op::Trash { path, .. } => {
                target(path)?;
                if ns.get(path).is_none() {
                    return Err(bad("the path does not exist"));
                }
            }
            Op::Restore { trash_id, to, .. } => {
                if !ns.trash.contains_key(trash_id) {
                    return Err(bad("no such trash item"));
                }
                ns.check_free(to)?;
            }
            Op::Purge { trash_id, .. } => {
                if !ns.trash.contains_key(trash_id) {
                    return Err(bad("no such trash item"));
                }
            }
            Op::DeviceAdd { name, .. } => {
                if name.is_empty() {
                    return Err(bad("a device needs a name"));
                }
                validate_device(name)?;
            }
            Op::DeviceRevoke { device_id, .. } => {
                if ns.device(*device_id).is_none() {
                    return Err(bad("no such device"));
                }
            }
            Op::DropVersion { path, version_id, .. } => {
                target(path)?;
                let Some(Entry { node: Node::File { versions, .. }, .. }) = ns.get(path) else {
                    return Err(bad("no file at the path"));
                };
                let Some(i) = versions.iter().position(|v| v.id == *version_id) else {
                    return Err(bad("no such version"));
                };
                if i + 1 == versions.len() {
                    return Err(bad("the current version cannot be dropped"));
                }
            }
        }
        Ok(())
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Validates and applies `op` as record `seq`, which must follow the
    /// last one applied.
    pub fn apply(&mut self, op: &Op, seq: u64) -> Result<Applied> {
        if seq != self.seq + 1 {
            return Err(bad("records out of sequence"));
        }
        self.validate(op)?;
        let mut applied = Applied { seq, ..Applied::default() };
        match op {
            Op::PutVersion { user, path, content } => {
                let existing_file = match self.users.get(user).and_then(|ns| ns.get(path)) {
                    Some(Entry { node: Node::File { file_id, .. }, .. }) => Some(*file_id),
                    _ => None,
                };
                let file_id = existing_file.unwrap_or_else(|| self.take_id());
                let version_id = self.take_id();
                let ns = self.users.entry(user.clone()).or_default();
                ns.ensure_parents(path, seq);
                let version = content.version(version_id);
                match ns.entries.get_mut(path) {
                    Some(Entry { node: Node::File { versions, .. }, changed }) => {
                        versions.push(version);
                        *changed = seq;
                    }
                    _ => ns.insert(
                        path.clone(),
                        Node::File { file_id, versions: vec![version] },
                        seq,
                    ),
                }
                applied.version = Some(version_id);
            }
            Op::Mkdir { user, path } => {
                let ns = self.users.entry(user.clone()).or_default();
                ns.ensure_parents(path, seq);
                if !ns.entries.contains_key(path) {
                    ns.insert(path.clone(), Node::Dir, seq);
                }
            }
            Op::Move { user, from, to } => {
                let ns = self.users.entry(user.clone()).or_default();
                let nodes = ns.take_subtree(from, seq);
                ns.ensure_parents(to, seq);
                ns.put_subtree(to, nodes, seq);
            }
            Op::Copy { user, from, to, created_ms } => {
                let file_id = self.take_id();
                let version_id = self.take_id();
                let ns = self.users.entry(user.clone()).or_default();
                let source = ns.get(from).and_then(|e| e.node.current()).cloned();
                let Some(mut version) = source else {
                    return Err(bad("the source has no current version"));
                };
                version.id = version_id;
                version.created_ms = *created_ms;
                version.origin = Origin::Copy;
                ns.ensure_parents(to, seq);
                ns.insert(to.clone(), Node::File { file_id, versions: vec![version] }, seq);
                applied.version = Some(version_id);
            }
            Op::Trash { user, path, deleted_ms } => {
                let id = self.take_id();
                let ns = self.users.entry(user.clone()).or_default();
                let entries = ns.take_subtree(path, seq);
                ns.trash.insert(
                    id,
                    TrashItem { id, path: path.clone(), deleted_ms: *deleted_ms, entries },
                );
                applied.trash_id = Some(id);
            }
            Op::Restore { user, trash_id, to } => {
                let ns = self.users.entry(user.clone()).or_default();
                let Some(item) = ns.trash.remove(trash_id) else {
                    return Err(bad("no such trash item"));
                };
                ns.ensure_parents(to, seq);
                ns.put_subtree(to, item.entries, seq);
            }
            Op::Purge { user, trash_id } => {
                let ns = self.users.entry(user.clone()).or_default();
                ns.trash.remove(trash_id);
            }
            Op::DeviceAdd { user, name, token_hash, created_ms } => {
                let id = self.take_id();
                let ns = self.users.entry(user.clone()).or_default();
                ns.devices.insert(
                    id,
                    Device {
                        id,
                        name: name.clone(),
                        token_hash: *token_hash,
                        created_ms: *created_ms,
                    },
                );
                applied.device_id = Some(id);
            }
            Op::DeviceRevoke { user, device_id } => {
                let ns = self.users.entry(user.clone()).or_default();
                ns.devices.remove(device_id);
            }
            Op::DropVersion { user, path, version_id } => {
                let ns = self.users.entry(user.clone()).or_default();
                if let Some(Entry { node: Node::File { versions, .. }, changed }) =
                    ns.entries.get_mut(path)
                {
                    versions.retain(|v| v.id != *version_id);
                    *changed = seq;
                }
            }
        }
        self.seq = seq;
        Ok(applied)
    }

    /// Every manifest any live version or trash item refers to: what GC
    /// must keep.
    pub fn referenced_manifests(&self) -> std::collections::BTreeSet<ObjectId> {
        let mut out = std::collections::BTreeSet::new();
        let mut add = |node: &Node| {
            if let Node::File { versions, .. } = node {
                out.extend(versions.iter().map(|v| v.manifest));
            }
        };
        for ns in self.users.values() {
            for entry in ns.entries.values() {
                add(&entry.node);
            }
            for item in ns.trash.values() {
                for (_, node) in &item.entries {
                    add(node);
                }
            }
        }
        out
    }
}

impl Op {
    pub fn user(&self) -> &str {
        match self {
            Op::PutVersion { user, .. }
            | Op::Mkdir { user, .. }
            | Op::Move { user, .. }
            | Op::Copy { user, .. }
            | Op::Trash { user, .. }
            | Op::Restore { user, .. }
            | Op::Purge { user, .. }
            | Op::DropVersion { user, .. }
            | Op::DeviceAdd { user, .. }
            | Op::DeviceRevoke { user, .. } => user,
        }
    }

    pub fn encode(&self, e: &mut Enc) {
        match self {
            Op::PutVersion { user, path, content } => {
                e.u8(1).str(user).str(path);
                encode_content(e, content);
            }
            Op::Mkdir { user, path } => {
                e.u8(2).str(user).str(path);
            }
            Op::Move { user, from, to } => {
                e.u8(3).str(user).str(from).str(to);
            }
            Op::Copy { user, from, to, created_ms } => {
                e.u8(4).str(user).str(from).str(to).i64(*created_ms);
            }
            Op::Trash { user, path, deleted_ms } => {
                e.u8(5).str(user).str(path).i64(*deleted_ms);
            }
            Op::Restore { user, trash_id, to } => {
                e.u8(6).str(user).u64(*trash_id).str(to);
            }
            Op::Purge { user, trash_id } => {
                e.u8(7).str(user).u64(*trash_id);
            }
            Op::DropVersion { user, path, version_id } => {
                e.u8(8).str(user).str(path).u64(*version_id);
            }
            Op::DeviceAdd { user, name, token_hash, created_ms } => {
                e.u8(9).str(user).str(name).raw(token_hash).i64(*created_ms);
            }
            Op::DeviceRevoke { user, device_id } => {
                e.u8(10).str(user).u64(*device_id);
            }
        }
    }

    pub fn decode(d: &mut Dec<'_>) -> Result<Self> {
        Ok(match d.u8()? {
            1 => Op::PutVersion { user: d.str()?, path: d.str()?, content: decode_content(d)? },
            2 => Op::Mkdir { user: d.str()?, path: d.str()? },
            3 => Op::Move { user: d.str()?, from: d.str()?, to: d.str()? },
            4 => Op::Copy { user: d.str()?, from: d.str()?, to: d.str()?, created_ms: d.i64()? },
            5 => Op::Trash { user: d.str()?, path: d.str()?, deleted_ms: d.i64()? },
            6 => Op::Restore { user: d.str()?, trash_id: d.u64()?, to: d.str()? },
            7 => Op::Purge { user: d.str()?, trash_id: d.u64()? },
            8 => Op::DropVersion { user: d.str()?, path: d.str()?, version_id: d.u64()? },
            9 => Op::DeviceAdd {
                user: d.str()?,
                name: d.str()?,
                token_hash: d.raw32()?,
                created_ms: d.i64()?,
            },
            10 => Op::DeviceRevoke { user: d.str()?, device_id: d.u64()? },
            _ => return Err(bad("unknown operation")),
        })
    }
}

/// The top bit of the origin byte says the file is executable. Origins
/// use 1 to 5, so every record written before the flag existed reads as
/// not executable, which is what it was.
const EXECUTABLE: u8 = 0x80;

fn encode_content(e: &mut Enc, c: &Content) {
    e.id(&c.manifest)
        .u64(c.size)
        .raw(&c.sha256)
        .i64(c.mtime_ms)
        .i64(c.created_ms)
        .str(&c.device)
        .u8(c.origin.byte() | if c.executable { EXECUTABLE } else { 0 });
}

fn decode_content(d: &mut Dec<'_>) -> Result<Content> {
    let executable;
    Ok(Content {
        manifest: d.id()?,
        size: d.u64()?,
        sha256: d.raw32()?,
        mtime_ms: d.i64()?,
        created_ms: d.i64()?,
        device: d.str()?,
        origin: {
            let b = d.u8()?;
            executable = b & EXECUTABLE != 0;
            Origin::from_byte(b & !EXECUTABLE)?
        },
        executable,
    })
}

fn encode_version(e: &mut Enc, v: &Version) {
    e.u64(v.id);
    encode_content(
        e,
        &Content {
            manifest: v.manifest,
            size: v.size,
            sha256: v.sha256,
            mtime_ms: v.mtime_ms,
            created_ms: v.created_ms,
            device: v.device.clone(),
            origin: v.origin,
            executable: v.executable,
        },
    );
}

fn decode_version(d: &mut Dec<'_>) -> Result<Version> {
    let id = d.u64()?;
    Ok(decode_content(d)?.version(id))
}

fn encode_node(e: &mut Enc, node: &Node) {
    match node {
        Node::Dir => {
            e.u8(1);
        }
        Node::File { file_id, versions } => {
            e.u8(2).u64(*file_id).len(versions.len());
            for v in versions {
                encode_version(e, v);
            }
        }
    }
}

fn decode_node(d: &mut Dec<'_>) -> Result<Node> {
    Ok(match d.u8()? {
        1 => Node::Dir,
        2 => {
            let file_id = d.u64()?;
            let n = d.len(32)?;
            let mut versions = Vec::with_capacity(n);
            for _ in 0..n {
                versions.push(decode_version(d)?);
            }
            if versions.is_empty() {
                return Err(bad("a file with no versions"));
            }
            Node::File { file_id, versions }
        }
        _ => return Err(bad("unknown node kind")),
    })
}

impl State {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::new();
        e.u64(self.seq).u64(self.next_id).len(self.users.len());
        for (user, ns) in &self.users {
            e.str(user).len(ns.entries.len());
            for (path, entry) in &ns.entries {
                e.str(path).u64(entry.changed);
                encode_node(&mut e, &entry.node);
            }
            e.len(ns.trash.len());
            for item in ns.trash.values() {
                e.u64(item.id).str(&item.path).i64(item.deleted_ms).len(item.entries.len());
                for (rel, node) in &item.entries {
                    e.str(rel);
                    encode_node(&mut e, node);
                }
            }
            e.len(ns.removed.len());
            for (path, seq) in &ns.removed {
                e.str(path).u64(*seq);
            }
            e.len(ns.devices.len());
            for d in ns.devices.values() {
                e.u64(d.id).str(&d.name).raw(&d.token_hash).i64(d.created_ms);
            }
        }
        e.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Dec::new(bytes);
        let mut state = State { seq: d.u64()?, next_id: d.u64()?, users: BTreeMap::new() };
        for _ in 0..d.len(8)? {
            let user = d.str()?;
            let mut ns = Namespace::default();
            for _ in 0..d.len(8)? {
                let path = d.str()?;
                let changed = d.u64()?;
                let node = decode_node(&mut d)?;
                ns.entries.insert(path, Entry { node, changed });
            }
            for _ in 0..d.len(8)? {
                let id = d.u64()?;
                let path = d.str()?;
                let deleted_ms = d.i64()?;
                let mut entries = Vec::new();
                for _ in 0..d.len(5)? {
                    entries.push((d.str()?, decode_node(&mut d)?));
                }
                ns.trash.insert(id, TrashItem { id, path, deleted_ms, entries });
            }
            for _ in 0..d.len(12)? {
                let path = d.str()?;
                ns.removed.insert(path, d.u64()?);
            }
            for _ in 0..d.len(52)? {
                let id = d.u64()?;
                let name = d.str()?;
                let token_hash = d.raw32()?;
                let created_ms = d.i64()?;
                ns.devices.insert(id, Device { id, name, token_hash, created_ms });
            }
            state.users.insert(user, ns);
        }
        d.end()?;
        Ok(state)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn content(tag: &str) -> Content {
        Content {
            manifest: ObjectId::of(tag.as_bytes()).unwrap(),
            size: tag.len() as u64,
            sha256: ObjectId::of(tag.as_bytes()).unwrap().0,
            mtime_ms: 1_000,
            created_ms: 2_000,
            device: "laptop".to_owned(),
            origin: Origin::Upload,
            executable: tag.starts_with("exec"),
        }
    }

    fn put(path: &str, tag: &str) -> Op {
        Op::PutVersion { user: "u".into(), path: path.into(), content: content(tag) }
    }

    fn run(state: &mut State, op: &Op) -> Result<Applied> {
        let seq = state.seq + 1;
        state.apply(op, seq)
    }

    #[test]
    fn versions_accumulate_and_parents_appear() {
        let mut s = State::default();
        let a = run(&mut s, &put("docs/a.txt", "one")).unwrap();
        let b = run(&mut s, &put("docs/a.txt", "two")).unwrap();
        let ns = s.user("u").unwrap();
        assert!(ns.get("docs").unwrap().node.is_dir());
        let Node::File { versions, .. } = &ns.get("docs/a.txt").unwrap().node else { panic!() };
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].id, a.version.unwrap());
        assert_eq!(versions[1].id, b.version.unwrap());
        assert_eq!(ns.get("docs/a.txt").unwrap().changed, 2);
        // A file cannot become a directory's parent, or be replaced by one.
        assert!(run(&mut s, &put("docs/a.txt/x", "x")).is_err());
        assert!(run(&mut s, &Op::Mkdir { user: "u".into(), path: "docs/a.txt".into() }).is_err());
        assert!(run(&mut s, &put("docs", "x")).is_err());
        // A failed operation consumes no sequence number.
        assert_eq!(s.seq, 2);
    }

    #[test]
    fn moves_keep_history_and_trash_keeps_everything() {
        let mut s = State::default();
        run(&mut s, &put("a/x.txt", "1")).unwrap();
        run(&mut s, &put("a/x.txt", "2")).unwrap();
        run(&mut s, &put("a/sub/y.txt", "3")).unwrap();
        let before = s.user("u").unwrap().get("a/x.txt").unwrap().node.clone();
        let mv = Op::Move { user: "u".into(), from: "a".into(), to: "b/c".into() };
        run(&mut s, &mv).unwrap();
        let ns = s.user("u").unwrap();
        assert!(ns.get("a").is_none() && ns.get("a/x.txt").is_none());
        assert_eq!(ns.get("b/c/x.txt").unwrap().node, before);
        assert!(ns.get("b/c/sub/y.txt").is_some());
        assert!(ns.removed.contains_key("a/sub/y.txt"));
        // Into itself, onto something, or from nothing: refused.
        for bad in [
            Op::Move { user: "u".into(), from: "b".into(), to: "b/c/d".into() },
            Op::Move { user: "u".into(), from: "b/c/x.txt".into(), to: "b/c/sub".into() },
            Op::Move { user: "u".into(), from: "nope".into(), to: "z".into() },
        ] {
            assert!(run(&mut s, &bad).is_err(), "{bad:?}");
        }
        let t = run(&mut s, &Op::Trash { user: "u".into(), path: "b".into(), deleted_ms: 9 })
            .unwrap()
            .trash_id
            .unwrap();
        let ns = s.user("u").unwrap();
        assert!(ns.entries.is_empty());
        assert_eq!(ns.trash[&t].entries.len(), 5);
        // Every manifest is still referenced from the trash.
        assert_eq!(s.referenced_manifests().len(), 3);
        run(&mut s, &Op::Restore { user: "u".into(), trash_id: t, to: "restored".into() }).unwrap();
        let ns = s.user("u").unwrap();
        assert_eq!(ns.get("restored/c/x.txt").unwrap().node, before);
        assert!(ns.trash.is_empty());
        assert!(!ns.removed.contains_key("restored/c/x.txt"));
    }

    #[test]
    fn copies_and_drops() {
        let mut s = State::default();
        let v1 = run(&mut s, &put("f", "1")).unwrap().version.unwrap();
        let v2 = run(&mut s, &put("f", "2")).unwrap().version.unwrap();
        let copy = Op::Copy { user: "u".into(), from: "f".into(), to: "g".into(), created_ms: 5 };
        run(&mut s, &copy).unwrap();
        let g = s.user("u").unwrap().get("g").unwrap().node.current().unwrap().clone();
        assert_eq!(g.manifest, content("2").manifest);
        assert_eq!(g.origin, Origin::Copy);
        let drop_current = Op::DropVersion { user: "u".into(), path: "f".into(), version_id: v2 };
        assert!(run(&mut s, &drop_current).is_err());
        let drop_old = Op::DropVersion { user: "u".into(), path: "f".into(), version_id: v1 };
        run(&mut s, &drop_old).unwrap();
        assert!(run(&mut s, &drop_old).is_err());
        let Node::File { versions, .. } = &s.user("u").unwrap().get("f").unwrap().node else {
            panic!()
        };
        assert_eq!(versions.len(), 1);
    }

    #[test]
    fn names_are_validated() {
        let mut s = State::default();
        for op in [
            Op::Mkdir { user: "u".into(), path: String::new() },
            Op::Mkdir { user: "u".into(), path: "../x".into() },
            Op::Mkdir { user: "bad user".into(), path: "x".into() },
            Op::Mkdir { user: String::new(), path: "x".into() },
        ] {
            assert!(run(&mut s, &op).is_err(), "{op:?}");
        }
        let mut c = content("x");
        c.device = "a\nb".into();
        assert!(
            run(&mut s, &Op::PutVersion { user: "u".into(), path: "x".into(), content: c })
                .is_err()
        );
        assert!(s.apply(&Op::Mkdir { user: "u".into(), path: "x".into() }, 5).is_err());
    }

    #[test]
    fn ops_and_states_round_trip_through_their_encodings() {
        let mut s = State::default();
        let ops = vec![
            put("a/b.txt", "1"),
            put("a/run.sh", "exec 1"),
            Op::Mkdir { user: "v".into(), path: "empty".into() },
            Op::Copy { user: "u".into(), from: "a/b.txt".into(), to: "c".into(), created_ms: -1 },
            Op::Move { user: "u".into(), from: "c".into(), to: "d".into() },
            Op::Trash { user: "u".into(), path: "a".into(), deleted_ms: 3 },
        ];
        for op in &ops {
            let mut e = Enc::new();
            op.encode(&mut e);
            let bytes = e.finish();
            let mut d = Dec::new(&bytes);
            assert_eq!(&Op::decode(&mut d).unwrap(), op);
            d.end().unwrap();
            run(&mut s, op).unwrap();
        }
        let bytes = s.encode();
        assert_eq!(State::decode(&bytes).unwrap(), s);
        // The executable flag rides in the origin byte's top bit; a record
        // from before it existed has the bit clear and reads as before.
        let mut e = Enc::new();
        put("x", "exec 2").encode(&mut e);
        let flagged = e.finish();
        let Op::PutVersion { content, .. } = Op::decode(&mut Dec::new(&flagged)).unwrap() else {
            panic!()
        };
        assert!(content.executable && content.origin == Origin::Upload);
        let mut e = Enc::new();
        put("x", "plain").encode(&mut e);
        let plain = e.finish();
        let Op::PutVersion { content, .. } = Op::decode(&mut Dec::new(&plain)).unwrap() else {
            panic!()
        };
        assert!(!content.executable);
        for cut in [0, 1, bytes.len() / 2, bytes.len() - 1] {
            assert!(State::decode(&bytes[..cut]).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(State::decode(&longer).is_err());
    }

    #[test]
    fn the_change_feed_reports_everything_once_and_pages_by_record() {
        let mut s = State::default();
        run(&mut s, &put("a/1", "1")).unwrap();
        run(&mut s, &put("a/2", "2")).unwrap();
        run(&mut s, &put("b", "3")).unwrap();
        let mv = Op::Move { user: "u".into(), from: "a".into(), to: "c".into() };
        run(&mut s, &mv).unwrap();
        let ns = s.user("u").unwrap();
        let (all, more) = ns.changes(0, 100);
        assert!(!more);
        let paths: Vec<(&str, u64)> = all.iter().map(|c| (c.path.as_str(), c.seq)).collect();
        assert_eq!(
            paths,
            [("b", 3), ("a", 4), ("a/1", 4), ("a/2", 4), ("c", 4), ("c/1", 4), ("c/2", 4)]
        );
        assert!(
            all.iter().filter(|c| c.path.starts_with('a')).all(|c| c.kind == ChangeKind::Deleted)
        );
        // A page stops between records...
        let (page, more) = ns.changes(0, 1);
        assert!(more);
        assert_eq!(page.len(), 1);
        // ...but never splits record 4's six changes.
        let (page, more) = ns.changes(0, 2);
        assert!(!more);
        assert_eq!(page.len(), 7);
        let (page, more) = ns.changes(3, 1);
        assert_eq!((page.len(), more), (6, false));
        assert!(ns.changes(4, 10).0.is_empty());
    }

    #[test]
    fn devices_are_added_and_revoked() {
        let mut s = State::default();
        let add = Op::DeviceAdd {
            user: "u".into(),
            name: "laptop".into(),
            token_hash: [7; 32],
            created_ms: 1,
        };
        let id = run(&mut s, &add).unwrap().device_id.unwrap();
        assert_eq!(s.user("u").unwrap().device(id).unwrap().token_hash, [7; 32]);
        assert_eq!(State::decode(&s.encode()).unwrap(), s);
        run(&mut s, &Op::DeviceRevoke { user: "u".into(), device_id: id }).unwrap();
        assert!(s.user("u").unwrap().device(id).is_none());
        assert!(run(&mut s, &Op::DeviceRevoke { user: "u".into(), device_id: id }).is_err());
        let unnamed = Op::DeviceAdd {
            user: "u".into(),
            name: String::new(),
            token_hash: [0; 32],
            created_ms: 1,
        };
        assert!(run(&mut s, &unnamed).is_err());
    }

    #[test]
    fn listing_children_and_subtrees() {
        let mut s = State::default();
        for p in ["a/1", "a/2", "a/b/3", "a0", "a.x"] {
            run(&mut s, &put(p, p)).unwrap();
        }
        let ns = s.user("u").unwrap();
        let kids: Vec<&String> = ns.children("a").map(|(k, _)| k).collect();
        assert_eq!(kids, ["a/1", "a/2", "a/b"]);
        let top: Vec<&String> = ns.children("").map(|(k, _)| k).collect();
        assert_eq!(top, ["a", "a.x", "a0"]);
        assert_eq!(ns.subtree("a").count(), 5);
    }
}
