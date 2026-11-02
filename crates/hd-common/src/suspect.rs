//! Telling an edit from encryption, for the ransomware guard.
//!
//! Ransomware rewrites files in place with ciphertext, and ciphertext looks
//! like random bytes. Compressed formats (photos, archives, office
//! documents) look random too, so randomness alone proves nothing. An edit
//! is suspicious when it turns a file random that was not, or when a file
//! that began with a known format's signature becomes random without it.
//! Both need the old content's first bytes: the sync client fetches them
//! from the server, and the server reads them from its store.

/// How much of a file is looked at.
pub const SAMPLE: usize = 64 * 1024;

/// Below this, a sample says too little to judge.
const MIN_SAMPLE: usize = 4096;

/// Bits of entropy per byte above which a sample looks random. Text is
/// around 4.5 to 5.5; compressed or encrypted data is close to 8.
const RANDOM_BITS: f64 = 7.5;

/// Whether `sample` looks like random bytes (compressed or encrypted).
pub fn looks_random(sample: &[u8]) -> bool {
    if sample.len() < MIN_SAMPLE {
        return false;
    }
    let mut counts = [0_u32; 256];
    for &b in sample {
        counts[usize::from(b)] += 1;
    }
    #[allow(clippy::cast_precision_loss)]
    let n = sample.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum();
    bits >= RANDOM_BITS
}

/// The format a file's first bytes announce, for formats whose content is
/// random-looking after a fixed signature.
pub fn signature(head: &[u8]) -> Option<&'static str> {
    const AT_START: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "zip"),
        (b"%PDF", "pdf"),
        (b"\xFF\xD8\xFF", "jpeg"),
        (b"\x89PNG", "png"),
        (b"GIF8", "gif"),
        (b"ID3", "mp3"),
        (b"fLaC", "flac"),
        (b"OggS", "ogg"),
        (b"RIFF", "riff"),
        (b"\x1F\x8B", "gzip"),
        (b"7z\xBC\xAF", "7z"),
        (b"Rar!", "rar"),
        (b"\xFD7zXZ", "xz"),
        (b"BZh", "bzip2"),
        (b"\x28\xB5\x2F\xFD", "zstd"),
        (b"\xD0\xCF\x11\xE0", "ole"),
        (b"SQLite format 3\0", "sqlite"),
        (b"\x1A\x45\xDF\xA3", "matroska"),
    ];
    if let Some((_, name)) = AT_START.iter().find(|(magic, _)| head.starts_with(magic)) {
        return Some(name);
    }
    // MP4, MOV, HEIC and friends: a box size, then "ftyp".
    (head.get(4..8) == Some(b"ftyp")).then_some("iso-media")
}

/// Whether going from `old` to `new` (each a file's first bytes) looks
/// like encryption rather than an edit.
pub fn turned_random(old: &[u8], new: &[u8]) -> bool {
    if !looks_random(new) {
        return false;
    }
    if !looks_random(old) && old.len() >= MIN_SAMPLE {
        return true;
    }
    signature(old).is_some_and(|s| signature(new) != Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noise(len: usize, mut seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 8);
        while out.len() < len {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            out.extend_from_slice(&seed.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn text(len: usize) -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. Minutes of the meeting follow.\n"
            .iter()
            .copied()
            .cycle()
            .take(len)
            .collect()
    }

    #[test]
    fn encryption_is_told_from_editing() {
        assert!(looks_random(&noise(SAMPLE, 7)));
        assert!(!looks_random(&text(SAMPLE)));
        assert!(!looks_random(&noise(100, 7)), "too little to judge");
        // Text encrypted: suspicious. Text edited: not.
        assert!(turned_random(&text(SAMPLE), &noise(SAMPLE, 1)));
        assert!(!turned_random(&text(SAMPLE), &text(SAMPLE / 2)));
        // A photo edited stays a photo; a photo encrypted loses its
        // signature.
        let mut photo = b"\xFF\xD8\xFF\xE0".to_vec();
        photo.extend(noise(SAMPLE, 2));
        let mut edited = b"\xFF\xD8\xFF\xE1".to_vec();
        edited.extend(noise(SAMPLE, 3));
        assert!(!turned_random(&photo, &edited));
        assert!(turned_random(&photo, &noise(SAMPLE, 4)));
        // Random data of no known format replaced by more: can't tell.
        assert!(!turned_random(&noise(SAMPLE, 5), &noise(SAMPLE, 6)));
        // A tiny old file grown into random data: can't tell either.
        assert!(!turned_random(b"hi", &noise(SAMPLE, 6)));
        let mut mp4 = vec![0, 0, 0, 0x20];
        mp4.extend_from_slice(b"ftypisom");
        assert_eq!(signature(&mp4), Some("iso-media"));
    }
}
