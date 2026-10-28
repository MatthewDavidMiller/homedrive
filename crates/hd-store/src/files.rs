//! Whole files: storing content, reading it back verified, and committing
//! it as a version.
//!
//! **Writing.** [`Store::write_file`] chunks a stream and stores it.
//! [`Store::commit_chunks`] takes a client's list of already-uploaded chunks
//! and checks them: every chunk must be present and intact, and their
//! concatenation must hash to the whole-file SHA-256 the client claims. A
//! commit whose data does not check out is refused before anything is
//! recorded.
//!
//! **Conflicts.** A commit names the version it was based on. If the file
//! has moved on since, the new content is still stored, as a sibling named
//! "<stem> (conflict <device> <date>).<ext>". Both copies are kept and
//! nothing is overwritten. Content identical to the current version adds
//! no version.
//!
//! **Reading.** [`FileReader`] streams a version's chunks, verifying each
//! against its ID, and on a read from the start also checks the
//! whole-file hash at the end. A failed check is an error the caller must
//! pass on (an HTTP server aborts the response), never a short or wrong
//! body.
//!
//! **GC safety.** A commit can reuse an object that is old and currently
//! unreferenced, because deduplication found it. Garbage collection must
//! not move such an object away between its mark phase and the commit. So
//! commits run under the read side of the GC gate and record the objects
//! they use while a collection is running, and the collector checks those
//! records under the write side before moving each object (see `gc`).

use std::collections::HashSet;
use std::io::{self, ErrorKind, Read};
use std::sync::{Mutex, PoisonError, RwLock};

use hd_chunk::{Chunker, ObjectId};
use hd_common::{Error, Result, pathname, timefmt};
use hd_crypto::Sha256;

use crate::Store;
use crate::manifest::Manifest;
use crate::model::{Content, Entry, Node, Op, Origin};
use crate::objects::{Kind, Objects};

/// Stored content, ready to become a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileContent {
    pub manifest: ObjectId,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// What a commit expects to replace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    /// Whatever is there (a WebDAV PUT, an import): the new content becomes
    /// the current version.
    Any,
    /// Nothing: the path should be new.
    Absent,
    /// This version should still be current.
    Version(u64),
}

/// A file as a client describes it after uploading its chunks.
#[derive(Clone, Copy, Debug)]
pub struct ChunkList<'a> {
    pub chunks: &'a [(ObjectId, u32)],
    pub size: u64,
    pub sha256: [u8; 32],
}

/// Who made a version, and when the device says the file was modified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub device: String,
    pub mtime_ms: i64,
    pub origin: Origin,
    /// When the version was made, if not now: an import of old versions
    /// keeps their dates, so retention treats them by their real age.
    pub created_ms: Option<i64>,
    /// Whether the file is executable; `None` keeps what the current
    /// version says (WebDAV and the browser cannot tell).
    pub executable: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// Where the content was stored: the requested path, or a conflict
    /// sibling.
    pub path: String,
    pub version: u64,
    pub conflict: bool,
    /// The content was already the current version; nothing was added.
    pub unchanged: bool,
}

/// Coordination between commits and garbage collection.
#[derive(Debug, Default)]
pub(crate) struct GcGate {
    pub(crate) gate: RwLock<()>,
    pub(crate) touched: Mutex<Touched>,
}

#[derive(Debug, Default)]
pub(crate) struct Touched {
    pub(crate) active: bool,
    pub(crate) ids: HashSet<ObjectId>,
}

impl GcGate {
    fn touch(&self, ids: impl IntoIterator<Item = ObjectId>) {
        let mut t = self.touched.lock().unwrap_or_else(PoisonError::into_inner);
        if t.active {
            t.ids.extend(ids);
        }
    }
}

/// The current version at `path`, if a file is there.
fn current_version(entry: Option<&Entry>) -> Option<&crate::model::Version> {
    entry.and_then(|e| e.node.current())
}

impl Store {
    /// Stores a stream as chunks and a manifest. `max_size` bounds it.
    fn store_stream(&self, reader: impl Read, max_size: u64) -> Result<FileContent> {
        let objects = self.objects();
        let mut chunker = Chunker::new(reader)?;
        let mut chunks = Vec::new();
        while let Some(chunk) = chunker.next_chunk()? {
            if chunk.offset + chunk.data.len() as u64 > max_size {
                return Err(Error::new("file is larger than the size limit"));
            }
            self.gc.touch([chunk.id]);
            objects.put_claimed(Kind::Chunk, &chunk.id, &chunk.data)?;
            let len = u32::try_from(chunk.data.len()).map_err(|_| Error::new("chunk too large"))?;
            chunks.push((chunk.id, len));
        }
        let summary = chunker.finish()?;
        let manifest = Manifest { size: summary.len, sha256: summary.sha256, chunks };
        let id = manifest.store(objects)?;
        self.gc.touch([id]);
        Ok(FileContent { manifest: id, size: summary.len, sha256: summary.sha256 })
    }

    /// Checks uploaded chunks and stores their manifest: every chunk must
    /// be intact, and together they must be `size` bytes hashing to
    /// `sha256`.
    fn store_chunks(
        &self,
        chunks: &[(ObjectId, u32)],
        size: u64,
        sha256: [u8; 32],
    ) -> Result<FileContent> {
        let objects = self.objects();
        self.gc.touch(chunks.iter().map(|(id, _)| *id));
        let manifest = Manifest { size, sha256, chunks: chunks.to_vec() };
        manifest.validate()?;
        let mut whole = Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?;
        let mut missing = Vec::new();
        for (id, len) in chunks {
            if !objects.contains(Kind::Chunk, id) {
                missing.push(*id);
                continue;
            }
            let data = objects.get(Kind::Chunk, id).map_err(|e| {
                Error::new(format!("chunk {id} cannot be used ({e}); upload it again"))
            })?;
            if data.len() != *len as usize {
                return Err(Error::new(format!("chunk {id} is not {len} bytes")));
            }
            whole.update(&data);
        }
        if !missing.is_empty() {
            return Err(Error::new(format!(
                "{} chunk(s) are missing, first {}; upload them and commit again",
                missing.len(),
                missing[0]
            )));
        }
        if whole.finish().map_err(|_| Error::new("SHA-256 failed"))? != sha256 {
            return Err(Error::new("the chunks do not hash to the file's SHA-256"));
        }
        let id = manifest.store(objects)?;
        self.gc.touch([id]);
        Ok(FileContent { manifest: id, size, sha256 })
    }

    /// Stores a stream and commits it as a version of `path`.
    pub fn write_file(
        &self,
        user: &str,
        path: &str,
        base: Base,
        reader: impl Read,
        max_size: u64,
        provenance: &Provenance,
    ) -> Result<Committed> {
        let _gate = self.gc.gate.read().unwrap_or_else(PoisonError::into_inner);
        let content = self.store_stream(reader, max_size)?;
        self.commit_content(user, path, base, &content, provenance)
    }

    /// Commits a file made of chunks the client uploaded earlier.
    pub fn commit_chunks(
        &self,
        user: &str,
        path: &str,
        base: Base,
        list: &ChunkList<'_>,
        provenance: &Provenance,
    ) -> Result<Committed> {
        let _gate = self.gc.gate.read().unwrap_or_else(PoisonError::into_inner);
        let content = self.store_chunks(list.chunks, list.size, list.sha256)?;
        self.commit_content(user, path, base, &content, provenance)
    }

    /// Records stored content as a version, at `path` or, if `base` no
    /// longer holds, at a conflict sibling.
    fn commit_content(
        &self,
        user: &str,
        path: &str,
        base: Base,
        content: &FileContent,
        provenance: &Provenance,
    ) -> Result<Committed> {
        let now = provenance.created_ms.unwrap_or_else(timefmt::unix_ms);
        self.commit_with(|state| {
            let ns = state.user(user);
            let entry = ns.and_then(|ns| ns.get(path));
            let current = current_version(entry);
            let executable =
                provenance.executable.unwrap_or_else(|| current.is_some_and(|v| v.executable));
            if let Some(v) = current
                && v.sha256 == content.sha256
                && v.size == content.size
                && v.executable == executable
            {
                return Ok((
                    None,
                    Committed {
                        path: path.to_owned(),
                        version: v.id,
                        conflict: false,
                        unchanged: true,
                    },
                ));
            }
            let is_dir = entry.is_some_and(|e| e.node.is_dir());
            let base_holds = !is_dir
                && match base {
                    Base::Any => true,
                    Base::Absent => entry.is_none(),
                    Base::Version(id) => current.map(|v| v.id) == Some(id),
                };
            let (target, origin, conflict) = if base_holds {
                (path.to_owned(), provenance.origin, false)
            } else {
                // "yyyy-mm-dd hhmm" in UTC.
                let t = timefmt::rfc3339_millis(now / 1000, 0);
                let stamp = format!("{} {}{}", &t[..10], &t[11..13], &t[14..16]);
                let mut name = pathname::conflict_name(path, &provenance.device, &stamp);
                let mut n = 2;
                while ns.is_some_and(|ns| ns.get(&name).is_some()) {
                    name = pathname::conflict_name(
                        path,
                        &format!("{} {n}", provenance.device),
                        &stamp,
                    );
                    n += 1;
                }
                (name, Origin::Conflict, true)
            };
            let op = Op::PutVersion {
                user: user.to_owned(),
                path: target.clone(),
                content: Content {
                    manifest: content.manifest,
                    size: content.size,
                    sha256: content.sha256,
                    mtime_ms: provenance.mtime_ms,
                    created_ms: now,
                    device: provenance.device.clone(),
                    origin,
                    executable,
                },
            };
            Ok((Some(op), Committed { path: target, version: 0, conflict, unchanged: false }))
        })
        .map(|(applied, mut committed)| {
            if let Some(applied) = applied {
                committed.version = applied.version.unwrap_or(0);
            }
            committed
        })
    }

    /// A reader over a version's content.
    pub fn open_content(&self, manifest: &ObjectId) -> Result<FileReader<'_>> {
        FileReader::new(self.objects(), manifest)
    }
}

/// Streams a file's content, verifying every chunk.
#[derive(Debug)]
pub struct FileReader<'a> {
    objects: &'a Objects,
    manifest: Manifest,
    next_chunk: usize,
    buf: Vec<u8>,
    at: usize,
    /// The whole-file hash, when reading from the start.
    whole: Option<Sha256>,
    remaining: u64,
}

impl<'a> FileReader<'a> {
    fn new(objects: &'a Objects, id: &ObjectId) -> Result<Self> {
        let manifest = Manifest::load(objects, id)?;
        let remaining = manifest.size;
        Ok(Self {
            objects,
            manifest,
            next_chunk: 0,
            buf: Vec::new(),
            at: 0,
            whole: Some(Sha256::new().map_err(|_| Error::new("SHA-256 failed"))?),
            remaining,
        })
    }

    pub fn size(&self) -> u64 {
        self.manifest.size
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Positions the reader at `offset`, for a range request. Every chunk
    /// is still verified against its ID, which with the manifest's own
    /// verified ID covers the whole file; only the redundant whole-file
    /// hash is skipped.
    pub fn seek_to(&mut self, offset: u64) -> Result<()> {
        if offset > self.manifest.size {
            return Err(Error::new("offset past the end of the file"));
        }
        let mut start = 0_u64;
        self.next_chunk = self.manifest.chunks.len();
        self.buf.clear();
        self.at = 0;
        for (i, (_, len)) in self.manifest.chunks.iter().enumerate() {
            let end = start + u64::from(*len);
            if offset < end {
                self.next_chunk = i;
                self.load_next()?;
                self.at = usize::try_from(offset - start).map_err(|_| Error::new("overflow"))?;
                break;
            }
            start = end;
        }
        if offset != 0 {
            self.whole = None;
        }
        self.remaining = self.manifest.size - offset;
        Ok(())
    }

    fn load_next(&mut self) -> Result<()> {
        let (id, len) = self.manifest.chunks[self.next_chunk];
        let data = self.objects.get(Kind::Chunk, &id)?;
        if data.len() != len as usize {
            return Err(Error::new(format!("chunk {id} has the wrong length")));
        }
        if let Some(h) = &mut self.whole {
            h.update(&data);
        }
        self.buf = data;
        self.at = 0;
        self.next_chunk += 1;
        Ok(())
    }

    fn check_end(&mut self) -> io::Result<()> {
        if let Some(h) = self.whole.take() {
            let digest = h.finish().map_err(|_| io::Error::other("SHA-256 failed"))?;
            if digest != self.manifest.sha256 {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "the file's content does not match its SHA-256",
                ));
            }
        }
        Ok(())
    }
}

impl Read for FileReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.at >= self.buf.len() {
            if self.next_chunk >= self.manifest.chunks.len() {
                self.check_end()?;
                return Ok(0);
            }
            self.load_next().map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))?;
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        self.remaining -= n as u64;
        if self.remaining == 0 && self.next_chunk >= self.manifest.chunks.len() {
            self.check_end()?;
        }
        Ok(n)
    }
}

/// The file at `path` and its current version's content, for callers that
/// need both.
pub fn file_at<'a>(
    state: &'a crate::model::State,
    user: &str,
    path: &str,
) -> Option<(&'a Node, &'a crate::model::Version)> {
    let entry = state.user(user)?.get(path)?;
    Some((&entry.node, entry.node.current()?))
}
