//! Manifests: the ordered list of chunks that makes up one file's content.
//!
//! ```text
//! magic "HDM1" · kind (1 direct, 2 indirect) · 3 zero bytes
//! file size (u64) · file SHA-256 (32 bytes) · count (u64)
//! count × (chunk ID (32 bytes) · chunk length (u32))
//! ```
//!
//! A direct manifest lists the file's chunks. A file with so many chunks
//! that its list would not fit in one object (more than about 116,000
//! chunks, roughly 100 GiB) gets an indirect manifest instead: the direct
//! encoding is stored as plain chunks, and the indirect manifest lists
//! those, with the file's own size and hash repeated for checking.
//!
//! A manifest is an object like any other, named by its SHA-256, so
//! identical files share one manifest as well as their chunks.

use hd_chunk::{MAX_CHUNK, ObjectId};
use hd_common::{Error, Result};

use crate::codec::{Dec, Enc};
use crate::objects::{Kind, MAX_OBJECT, Objects};

const MAGIC: &[u8; 4] = b"HDM1";
const DIRECT: u8 = 1;
const INDIRECT: u8 = 2;
const ENTRY: usize = 32 + 4;

/// One file's content: its chunks in order, its size, and its hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub size: u64,
    pub sha256: [u8; 32],
    pub chunks: Vec<(ObjectId, u32)>,
}

fn encode(kind: u8, size: u64, sha256: &[u8; 32], chunks: &[(ObjectId, u32)]) -> Vec<u8> {
    let mut e = Enc::new();
    e.raw(MAGIC).u8(kind).raw(&[0; 3]).u64(size).raw(sha256).len(chunks.len());
    for (id, len) in chunks {
        e.id(id).u32(*len);
    }
    e.finish()
}

fn decode(bytes: &[u8]) -> Result<(u8, Manifest)> {
    let bad = || Error::new("malformed manifest");
    let mut d = Dec::new(bytes);
    if d.u32()? != u32::from_le_bytes(*MAGIC) {
        return Err(bad());
    }
    let kind = d.u8()?;
    if (d.u8()?, d.u8()?, d.u8()?) != (0, 0, 0) || !(kind == DIRECT || kind == INDIRECT) {
        return Err(bad());
    }
    let size = d.u64()?;
    let sha256 = d.raw32()?;
    let n = d.len(ENTRY)?;
    let mut chunks = Vec::with_capacity(n);
    for _ in 0..n {
        chunks.push((d.id()?, d.u32()?));
    }
    d.end()?;
    Ok((kind, Manifest { size, sha256, chunks }))
}

impl Manifest {
    /// Checks the manifest is self-consistent: the chunk lengths add up to
    /// the size, no chunk is empty or over the limit, and an empty file has
    /// no chunks.
    pub fn validate(&self) -> Result<()> {
        let mut total: u64 = 0;
        for (_, len) in &self.chunks {
            if *len == 0 || *len as usize > MAX_CHUNK {
                return Err(Error::new("manifest has a chunk of impossible length"));
            }
            total = total.checked_add(u64::from(*len)).ok_or_else(|| Error::new("overflow"))?;
        }
        if total != self.size {
            return Err(Error::new("manifest chunk lengths do not add up to the file size"));
        }
        Ok(())
    }

    /// Stores the manifest (and, for a very large file, the chunks of its
    /// list) and returns its ID.
    pub fn store(&self, objects: &Objects) -> Result<ObjectId> {
        self.store_split(objects, MAX_OBJECT)
    }

    /// As [`Manifest::store`], going indirect above `max_direct` bytes.
    /// Tests use a small limit to exercise indirect manifests.
    #[doc(hidden)]
    pub fn store_split(&self, objects: &Objects, max_direct: usize) -> Result<ObjectId> {
        self.validate()?;
        let direct = encode(DIRECT, self.size, &self.sha256, &self.chunks);
        if direct.len() <= max_direct.min(MAX_OBJECT) {
            return Ok(objects.put(Kind::Manifest, &direct)?.0);
        }
        let mut parts = Vec::new();
        for piece in direct.chunks(max_direct.clamp(1, MAX_CHUNK)) {
            let (id, _) = objects.put(Kind::Chunk, piece)?;
            parts.push((id, u32::try_from(piece.len()).map_err(|_| Error::new("overflow"))?));
        }
        let indirect = encode(INDIRECT, self.size, &self.sha256, &parts);
        if indirect.len() > MAX_OBJECT {
            return Err(Error::new("file is too large for a manifest"));
        }
        Ok(objects.put(Kind::Manifest, &indirect)?.0)
    }

    /// Loads and checks a manifest. Every object read on the way is
    /// verified against its ID (and a damaged one quarantined).
    pub fn load(objects: &Objects, id: &ObjectId) -> Result<Self> {
        Self::load_with(id, |kind, id| objects.get(kind, id))
    }

    /// As [`Manifest::load`], but moves nothing: for read-only checks.
    pub fn load_readonly(objects: &Objects, id: &ObjectId) -> Result<Self> {
        Self::load_with(id, |kind, id| match objects.peek(kind, id)? {
            Ok(data) => Ok(data),
            Err(health) => Err(Error::new(format!("{} {id}: {health:?}", kind.name()))),
        })
    }

    fn load_with(
        id: &ObjectId,
        fetch: impl Fn(Kind, &ObjectId) -> Result<Vec<u8>>,
    ) -> Result<Self> {
        let bytes = fetch(Kind::Manifest, id)?;
        let (kind, top) = decode(&bytes)?;
        let manifest = if kind == DIRECT {
            top
        } else {
            let mut list = Vec::new();
            for (part, len) in &top.chunks {
                let piece = fetch(Kind::Chunk, part)?;
                if piece.len() != *len as usize {
                    return Err(Error::new("manifest part has the wrong length"));
                }
                list.extend_from_slice(&piece);
            }
            let (inner_kind, inner) = decode(&list)?;
            if inner_kind != DIRECT || inner.size != top.size || inner.sha256 != top.sha256 {
                return Err(Error::new("indirect manifest does not match its parts"));
            }
            inner
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// The objects a manifest keeps alive besides itself: its chunks and,
    /// if indirect, the chunks holding its list.
    pub fn objects_used(objects: &Objects, id: &ObjectId) -> Result<Vec<ObjectId>> {
        let bytes = objects.get(Kind::Manifest, id)?;
        let (kind, top) = decode(&bytes)?;
        let mut out: Vec<ObjectId> = top.chunks.iter().map(|(c, _)| *c).collect();
        if kind == INDIRECT {
            out.extend(Self::load(objects, id)?.chunks.iter().map(|(c, _)| *c));
        }
        Ok(out)
    }
}
