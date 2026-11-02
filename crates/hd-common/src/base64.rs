//! Standard base64 (RFC 4648 §4): padded encoding, and a decoder that
//! ignores ASCII whitespace (PEM bodies wrap at 70 columns) and refuses
//! anything else that is not alphabet or trailing padding.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], chunk.get(1).copied().unwrap_or(0), chunk.get(2).copied().unwrap_or(0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// [`encode`] without the trailing `=` padding (OpenSSH fingerprints).
pub fn encode_unpadded(data: &[u8]) -> String {
    let mut s = encode(data);
    while s.ends_with('=') {
        s.pop();
    }
    s
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).and_then(|p| u32::try_from(p).ok())
}

pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc = 0_u32;
    let mut bits = 0;
    let mut padding = 0;
    for &c in text {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            if padding > 2 {
                return None;
            }
            continue;
        }
        if padding > 0 {
            return None;
        }
        acc = acc << 6 | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    // Leftover bits must be zero padding of a final partial group.
    if bits >= 6 || acc & ((1 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors() {
        for (plain, coded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded.as_bytes()).unwrap(), plain.as_bytes());
        }
        assert_eq!(encode_unpadded(b"f"), "Zg");
        assert_eq!(decode(b"Zm9v\nYmFy\n").unwrap(), b"foobar");
        for bad in [&b"Zm9v!"[..], b"Zg===", b"Zg=a", b"Zh=="] {
            assert!(decode(bad).is_none(), "{bad:?}");
        }
    }
}
