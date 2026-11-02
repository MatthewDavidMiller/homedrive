//! Earlier generations of an administrator's store copy (see `copy`).
//!
//! Each `backup-store` run keeps the metadata it replaces, so the copy can
//! be opened as it was at any earlier run. Kept whole, every generation
//! would hold a full set of the store's snapshots, and the history would
//! grow by that much with every run. So each file is cut into chunks where
//! its content says (a gear hash over the store chunker's table, but cut
//! near 64 KiB rather than the store's 1 MiB, since metadata changes are
//! small and scattered), each chunk is kept once under its SHA-256, and a
//! generation is a small listing of its files and their chunks.
//! Consecutive snapshots differ only where the drives changed, and journals
//! only grow, so a run adds roughly what changed. The cut points are not a
//! format: a listing names its chunks, so reading never depends on them.
//!
//! Nothing here is ever deleted. A chunk found damaged when a run needs it
//! again is set aside in `damaged/` and written afresh; a listing is
//! written last, so a generation exists whole or not at all, and every
//! chunk and every file is checked against its SHA-256 when read back.
//!
//! - plain copy: `history/chunks/<ab>/<sha256>` and `history/<generation>`;
//! - encrypted copy: each chunk sealed under the name
//!   `history/chunks/<sha256>` at `sealed-history/chunks/<ab>/<label>`,
//!   and each listing sealed under `history/<generation>` at
//!   `sealed-history/<generation>/<label>`, so neither shows what it holds.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use hd_common::{Error, Result, fsio, timefmt};
use hd_store::copy::valid_name;
use hd_store::sealed::{self, Keys, Sealer};

const STAGING_PREFIX: &str = ".homedrive-history-";
const HEADER: &str = "homedrive-copy-generation 1";
/// A listing names a few files of at most a few thousand chunks each.
const MAX_LISTING: usize = 4 << 20;
const CHUNKS: &str = "chunks";
/// History chunks: at least 16 KiB, cut where the hash's top 16 bits are
/// zero (so near 64 KiB apart), and at most 256 KiB.
const MIN_PIECE: usize = 16 * 1024;
const MAX_PIECE: usize = 256 * 1024;
const PIECE_MASK: u64 = !0 << (64 - 16);
const DAMAGED: &str = "damaged";

/// Where a copy keeps its generations, plain or sealed.
pub(crate) enum History<'a> {
    Plain(PathBuf),
    Sealed(PathBuf, &'a Keys),
}

/// Whether `name` can be a generation's name: what [`History::keep`]
/// makes, a UTC time with perhaps a counter.
fn generation_name(name: &str) -> bool {
    name.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Where the first piece of `data` ends: a content-defined cut point.
fn cut_point(gear: &[u64; 256], data: &[u8]) -> usize {
    if data.len() <= MIN_PIECE {
        return data.len();
    }
    let end = data.len().min(MAX_PIECE);
    let mut hash = 0_u64;
    for (i, &b) in data.iter().enumerate().take(end).skip(MIN_PIECE) {
        hash = (hash << 1).wrapping_add(gear[usize::from(b)]);
        if hash & PIECE_MASK == 0 {
            return i + 1;
        }
    }
    end
}

/// Cuts `reader` into pieces, calling `each` with every one, and returns
/// the whole stream's length and SHA-256.
fn pieces(
    mut reader: impl Read,
    mut each: impl FnMut(&[u8]) -> Result<()>,
) -> Result<(u64, String)> {
    let gear = hd_chunk::gear()?;
    let mut whole = hd_crypto::Sha256::new().map_err(sha_failed)?;
    let mut len = 0_u64;
    let mut buf = Vec::with_capacity(2 * MAX_PIECE);
    let mut eof = false;
    loop {
        while !eof && buf.len() < MAX_PIECE {
            let start = buf.len();
            buf.resize(start + MAX_PIECE, 0);
            match reader.read(&mut buf[start..]) {
                Ok(n) => {
                    buf.truncate(start + n);
                    eof = n == 0;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => buf.truncate(start),
                Err(e) => return Err(e.into()),
            }
        }
        if buf.is_empty() {
            return Ok((len, hd_crypto::hex(&whole.finish().map_err(sha_failed)?)));
        }
        let cut = cut_point(gear, &buf);
        whole.update(&buf[..cut]);
        len += cut as u64;
        each(&buf[..cut])?;
        buf.drain(..cut);
    }
}

fn sha_failed<E>(_: E) -> Error {
    Error::new("SHA-256 failed")
}

fn hash_hex(data: &[u8]) -> Result<String> {
    Ok(hd_crypto::hex(&hd_crypto::sha256(data).map_err(sha_failed)?))
}

impl History<'_> {
    fn root(&self) -> &Path {
        match self {
            History::Plain(root) | History::Sealed(root, _) => root,
        }
    }

    fn chunk_path(&self, hex: &str) -> Result<PathBuf> {
        let file = match self {
            History::Plain(_) => hex.to_owned(),
            History::Sealed(_, keys) => keys.sealed_name(&format!("history/{CHUNKS}/{hex}"))?,
        };
        Ok(self.root().join(CHUNKS).join(&file[..2]).join(file))
    }

    fn listing_path(&self, generation: &str) -> Result<PathBuf> {
        Ok(match self {
            History::Plain(root) => root.join(generation),
            History::Sealed(root, keys) => {
                root.join(generation).join(keys.sealed_name(&format!("history/{generation}"))?)
            }
        })
    }

    /// Reads a file of this history whole: `name` is what it was sealed
    /// under, for an encrypted copy. `None`: it is not there.
    fn read(&self, path: &Path, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
        match self {
            History::Plain(_) => fsio::read_bounded(path, max),
            History::Sealed(_, keys) => {
                let mut input = match fsio::open_nofollow(path) {
                    Ok(f) => f,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(e) => return Err(e.into()),
                };
                let label = path.file_name().map(|n| n.to_string_lossy().into_owned());
                let mut out = Vec::new();
                let inner = sealed::open(
                    &mut io::Read::take(&mut input, max as u64 * 2 + 4096),
                    keys,
                    &label.unwrap_or_default(),
                    &mut out,
                )?;
                if inner != name || out.len() > max {
                    return Err(Error::new(format!("{} holds something else", path.display())));
                }
                Ok(Some(out))
            }
        }
    }

    /// Writes a new file of this history, sealed under `name` for an
    /// encrypted copy. It must not exist.
    fn write_new(&self, path: &Path, name: &str, data: &[u8], staging: &Path) -> Result<()> {
        let parent = path.parent().ok_or_else(|| Error::new("no parent folder"))?;
        fsio::mkdir_all(parent, 0o700)?;
        let mut staged = fsio::Staged::create_in(staging, STAGING_PREFIX)?;
        match self {
            History::Plain(_) => staged.write_all(data)?,
            History::Sealed(_, keys) => {
                let mut sealer = Sealer::new(&mut staged, keys, name)?;
                sealer.write_all(data)?;
                sealer.finish()?;
            }
        }
        staged.finish(None, 0o600)?;
        staged.commit_new(path)
    }

    /// A chunk, checked against its SHA-256.
    fn read_chunk(&self, hex: &str) -> Result<Vec<u8>> {
        let path = self.chunk_path(hex)?;
        let data = self
            .read(&path, &format!("history/{CHUNKS}/{hex}"), MAX_PIECE)?
            .ok_or_else(|| Error::new(format!("chunk {hex} of the history is missing")))?;
        if hash_hex(&data)? != hex {
            return Err(Error::new(format!("chunk {hex} of the history is damaged")));
        }
        Ok(data)
    }

    /// Keeps a chunk, unless a good copy is already kept. A damaged copy
    /// is set aside, never deleted. Returns whether it was written.
    fn keep_chunk(&self, hex: &str, data: &[u8], staging: &Path) -> Result<bool> {
        let path = self.chunk_path(hex)?;
        if std::fs::symlink_metadata(&path).is_ok() {
            if self.read_chunk(hex).is_ok() {
                return Ok(false);
            }
            let aside = self.root().join(DAMAGED);
            fsio::mkdir_all(&aside, 0o700)?;
            let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
            let name = format!(
                "{}.{}.{}",
                file.unwrap_or_default(),
                timefmt::unix_seconds(),
                hd_common::rand::random_hex(4)?
            );
            fsio::move_new_durable(&path, aside.join(name))?;
        }
        self.write_new(&path, &format!("history/{CHUNKS}/{hex}"), data, staging)?;
        Ok(true)
    }

    /// Keeps `files` (each a metadata file's name, e.g. `snapshot.12`, and
    /// its contents) as a new generation named by `fetched` (Unix
    /// seconds). Returns its name and how many bytes of new chunks it took.
    pub(crate) fn keep(
        &self,
        fetched: i64,
        files: Vec<(String, Box<dyn Read + '_>)>,
        staging: &Path,
    ) -> Result<(String, u64)> {
        let base = timefmt::compact_utc(fetched);
        let mut generation = base.clone();
        let mut n = 2;
        while std::fs::symlink_metadata(self.root().join(&generation)).is_ok() {
            generation = format!("{base}-{n}");
            n += 1;
        }
        let mut listing = format!("{HEADER}\n");
        let mut added = 0_u64;
        for (name, reader) in files {
            if !valid_name(&format!("meta/{name}")) {
                return Err(Error::new(format!("{name} is not a metadata file")));
            }
            let mut ids = Vec::new();
            let (len, sha) = pieces(reader, |piece| {
                let hex = hash_hex(piece)?;
                if self.keep_chunk(&hex, piece, staging)? {
                    added += piece.len() as u64;
                }
                ids.push(hex);
                Ok(())
            })?;
            let line = [name, len.to_string(), sha, ids.join(",")];
            listing.push_str(&line.join("\t"));
            listing.push('\n');
        }
        // Last: until the listing exists, the generation does not.
        let path = self.listing_path(&generation)?;
        self.write_new(&path, &format!("history/{generation}"), listing.as_bytes(), staging)?;
        Ok((generation, added))
    }

    /// Writes generation `generation`'s metadata files into `out`, each
    /// checked chunk by chunk and whole; with no `out`, only checks them.
    /// `staging` must be on `out`'s filesystem. Returns how many files.
    pub(crate) fn restore(
        &self,
        generation: &str,
        out: Option<&Path>,
        staging: &Path,
    ) -> Result<usize> {
        let bytes = self
            .read(&self.listing_path(generation)?, &format!("history/{generation}"), MAX_LISTING)?
            .ok_or_else(|| Error::new(format!("there is no generation {generation}")))?;
        let text = String::from_utf8(bytes)
            .map_err(|_| Error::new("a generation's listing is damaged"))?;
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err(Error::new(format!("generation {generation} is in an unknown format")));
        }
        let mut count = 0;
        for line in lines {
            let bad = || Error::new(format!("generation {generation} has a damaged line"));
            let mut fields = line.split('\t');
            let (Some(name), Some(len), Some(sha), Some(chunks), None) =
                (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(bad());
            };
            let len: u64 = len.parse().map_err(|_| bad())?;
            if !valid_name(&format!("meta/{name}")) {
                return Err(bad());
            }
            let mut staged = match out {
                Some(_) => Some(fsio::Staged::create_in(staging, STAGING_PREFIX)?),
                None => None,
            };
            let mut whole = hd_crypto::Sha256::new().map_err(sha_failed)?;
            let mut got = 0_u64;
            for hex in chunks.split(',').filter(|h| !h.is_empty()) {
                if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(bad());
                }
                let data = self.read_chunk(hex)?;
                whole.update(&data);
                got += data.len() as u64;
                if let Some(s) = staged.as_mut() {
                    s.write_all(&data)?;
                }
            }
            if got != len || hd_crypto::hex(&whole.finish().map_err(sha_failed)?) != sha {
                return Err(Error::new(format!(
                    "{name} in generation {generation} does not read back whole"
                )));
            }
            if let (Some(mut s), Some(out)) = (staged, out) {
                s.finish(None, 0o600)?;
                s.commit_new(out.join(name))?;
            }
            count += 1;
        }
        Ok(count)
    }
}

/// The generations a copy holds, oldest first: those whose listing was
/// written, plain or sealed.
pub(crate) fn list(plain: &Path, sealed: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (root, is_sealed) in [(plain, false), (sealed, true)] {
        let Ok(entries) = std::fs::read_dir(root) else { continue };
        for e in entries {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let kind = e.file_type()?;
            let whole = if is_sealed {
                kind.is_dir()
                    && std::fs::read_dir(e.path())?.any(|f| f.is_ok_and(|f| f.path().is_file()))
            } else {
                kind.is_file()
            };
            if generation_name(&name) && whole {
                out.push(name);
            }
        }
    }
    out.sort();
    Ok(out)
}
