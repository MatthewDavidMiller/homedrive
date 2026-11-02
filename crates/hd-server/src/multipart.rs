//! A streaming `multipart/form-data` reader (RFC 7578), so a browser
//! upload goes straight into the chunker without ever being held whole.
//!
//! Parts are read in order: [`Multipart::next_part`] moves to the next
//! part's headers, and [`Multipart`]'s `Read` yields that part's bytes up to
//! the next delimiter. Upload forms put their small fields (the CSRF token,
//! the target folder) before the file inputs, so those are checked before
//! any file data is stored.

use std::io::{self, ErrorKind, Read};

const MAX_PART_HEADERS: usize = 8 * 1024;
const MAX_BOUNDARY: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    /// The file name the browser sent, reduced to its last component.
    pub filename: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum State {
    /// Before the first delimiter.
    Preamble,
    InPart,
    /// At a delimiter, not yet consumed.
    AtDelimiter,
    Done,
}

pub struct Multipart<'r> {
    src: &'r mut dyn Read,
    /// "\r\n--" + boundary.
    delim: Vec<u8>,
    buf: Vec<u8>,
    src_done: bool,
    state: State,
}

impl std::fmt::Debug for Multipart<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Multipart({:?})", self.state)
    }
}

/// The boundary of a `multipart/form-data` content type.
pub fn boundary(content_type: &str) -> Option<String> {
    let mut parts = content_type.split(';');
    if !parts.next()?.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for p in parts {
        let (k, v) = p.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() && v.len() <= MAX_BOUNDARY {
                return Some(v.to_owned());
            }
        }
    }
    None
}

fn bad(why: &str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, why.to_owned())
}

/// The value of `key="..."` in a Content-Disposition header.
fn disposition_param(header: &str, key: &str) -> Option<String> {
    for p in header.split(';').skip(1) {
        let (k, v) = p.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case(key) {
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(v);
            return Some(v.replace("\\\"", "\"").replace("\\\\", "\\"));
        }
    }
    None
}

impl<'r> Multipart<'r> {
    pub fn new(src: &'r mut dyn Read, boundary: &str) -> Self {
        let mut delim = b"\r\n--".to_vec();
        delim.extend_from_slice(boundary.as_bytes());
        // The body starts with "--boundary"; pretending a CRLF came before
        // it lets one delimiter pattern find every boundary.
        Self { src, delim, buf: b"\r\n".to_vec(), src_done: false, state: State::Preamble }
    }

    /// Reads until at least `n` bytes are buffered or the source ends.
    fn fill(&mut self, n: usize) -> io::Result<()> {
        let mut chunk = [0_u8; 16 * 1024];
        while self.buf.len() < n && !self.src_done {
            match self.src.read(&mut chunk) {
                Ok(0) => self.src_done = true,
                Ok(k) => self.buf.extend_from_slice(&chunk[..k]),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn find_delim(&self) -> Option<usize> {
        self.buf.windows(self.delim.len()).position(|w| w == self.delim.as_slice())
    }

    /// Bytes of the current part, up to the delimiter.
    fn part_bytes(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(i) = self.find_delim() {
                if i == 0 {
                    self.state = State::AtDelimiter;
                    return Ok(0);
                }
                let n = i.min(out.len());
                out[..n].copy_from_slice(&self.buf[..n]);
                self.buf.drain(..n);
                return Ok(n);
            }
            // Everything but a possible partial delimiter at the end is
            // part data.
            let safe = self.buf.len().saturating_sub(self.delim.len() - 1);
            if safe > 0 {
                let n = safe.min(out.len());
                out[..n].copy_from_slice(&self.buf[..n]);
                self.buf.drain(..n);
                return Ok(n);
            }
            if self.src_done {
                return Err(bad("the form data ended in the middle of a part"));
            }
            self.fill(self.buf.len() + 16 * 1024)?;
        }
    }

    /// Moves to the next part; `None` after the last.
    pub fn next_part(&mut self) -> io::Result<Option<Part>> {
        let mut sink = [0_u8; 16 * 1024];
        while matches!(self.state, State::Preamble | State::InPart) {
            if self.part_bytes(&mut sink)? == 0 && self.state != State::AtDelimiter {
                return Err(bad("the form data ended early"));
            }
        }
        if self.state == State::Done {
            return Ok(None);
        }
        // At the delimiter: "--" ends the body, CRLF starts another part.
        self.fill(self.delim.len() + 2)?;
        if self.buf.len() < self.delim.len() + 2 {
            return Err(bad("the form data ended at a boundary"));
        }
        let after = [self.buf[self.delim.len()], self.buf[self.delim.len() + 1]];
        self.buf.drain(..self.delim.len() + 2);
        if &after == b"--" {
            self.state = State::Done;
            return Ok(None);
        }
        if &after != b"\r\n" {
            return Err(bad("malformed boundary"));
        }
        let end = loop {
            if let Some(i) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i;
            }
            if self.buf.len() > MAX_PART_HEADERS {
                return Err(bad("part headers too long"));
            }
            if self.src_done {
                return Err(bad("the form data ended in part headers"));
            }
            self.fill(self.buf.len() + 1024)?;
        };
        let headers =
            String::from_utf8(self.buf[..end].to_vec()).map_err(|_| bad("part headers"))?;
        self.buf.drain(..end + 4);
        let disposition = headers
            .split("\r\n")
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim().eq_ignore_ascii_case("content-disposition").then(|| v.trim().to_owned())
            })
            .ok_or_else(|| bad("a part has no Content-Disposition"))?;
        let name =
            disposition_param(&disposition, "name").ok_or_else(|| bad("a part has no name"))?;
        let filename = disposition_param(&disposition, "filename")
            .map(|f| f.rsplit(['/', '\\']).next().unwrap_or_default().to_owned());
        self.state = State::InPart;
        Ok(Some(Part { name, filename }))
    }

    /// The rest of the current part as text, at most `max` bytes.
    pub fn text(&mut self, max: usize) -> io::Result<String> {
        let mut out = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            let n = self.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if out.len() + n > max {
                return Err(bad("a form field is too long"));
            }
            out.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8(out).map_err(|_| bad("a form field is not UTF-8"))
    }
}

impl Read for Multipart<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.state != State::InPart || out.is_empty() {
            return Ok(0);
        }
        self.part_bytes(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader handing out a few bytes at a time, so delimiters straddle
    /// reads.
    struct Dribble<'a>(&'a [u8], usize);

    impl Read for Dribble<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.1.min(out.len()).min(self.0.len());
            out[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn body(file: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"csrf_token\"\r\n\r\nabc\r\n");
        b.extend_from_slice(b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"C:\\\\dir\\\\a \\\"b\\\".txt\"\r\nContent-Type: text/plain\r\n\r\n");
        b.extend_from_slice(file);
        b.extend_from_slice(b"\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"\"\r\n\r\n\r\n--XyZ--\r\nepilogue");
        b
    }

    #[test]
    fn parts_stream_through_any_read_size() {
        // File content that contains near-delimiters.
        let file = b"line1\r\n--XyY\r\n--Xy\r\nend\r\n".repeat(500);
        let b = body(&file);
        for step in [1, 2, 3, 7, 64, 100_000] {
            let mut src = Dribble(&b, step);
            let mut m = Multipart::new(&mut src, "XyZ");
            let p = m.next_part().unwrap().unwrap();
            assert_eq!(p, Part { name: "csrf_token".into(), filename: None });
            assert_eq!(m.text(100).unwrap(), "abc");
            let p = m.next_part().unwrap().unwrap();
            assert_eq!(p.filename.as_deref(), Some("a \"b\".txt"));
            let mut got = Vec::new();
            let mut chunk = [0_u8; 333];
            loop {
                let n = m.read(&mut chunk).unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..n]);
            }
            assert_eq!(got, file, "step {step}");
            let empty = m.next_part().unwrap().unwrap();
            assert_eq!(empty.filename.as_deref(), Some(""));
            assert_eq!(m.text(10).unwrap(), "");
            assert!(m.next_part().unwrap().is_none());
            assert!(m.next_part().unwrap().is_none());
        }
    }

    #[test]
    fn truncated_bodies_fail() {
        let b = body(b"data");
        for cut in [10, 40, 120, b.len() - 20] {
            let mut src = Dribble(&b[..cut], 5);
            let mut m = Multipart::new(&mut src, "XyZ");
            let result = (|| -> io::Result<()> {
                while m.next_part()?.is_some() {
                    let _ = m.text(1_000_000)?;
                }
                Ok(())
            })();
            assert!(result.is_err(), "cut {cut}");
        }
    }

    #[test]
    fn boundaries_are_parsed() {
        assert_eq!(boundary("multipart/form-data; boundary=abc").as_deref(), Some("abc"));
        assert_eq!(boundary("multipart/form-data; boundary=\"a b\"").as_deref(), Some("a b"));
        assert_eq!(boundary("text/plain; boundary=abc"), None);
        assert_eq!(boundary("multipart/form-data"), None);
    }
}
