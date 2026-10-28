//! A small HTTP/1.1 server: a thread per connection under a fixed ceiling,
//! keep-alive, and every read bounded in size and time.
//!
//! Request bodies are not read ahead. A handler reads its body through
//! [`Request::body`], which decodes `Content-Length` or chunked framing and
//! answers `Expect: 100-continue` on first use, so a multi-gigabyte upload
//! streams through without being held in memory. Small bodies (forms,
//! JSON) are read with [`Request::read_body`] up to a stated limit.
//!
//! Response bodies are bytes, a slice of an open file (sendfile through
//! `std::io::copy`), or a stream. A stream with a known length keeps the
//! connection alive; one without is framed by closing it.
//!
//! A connection is kept for the next request only when the last one was
//! cleanly finished: its body read to the end (or drained, if small), its
//! response framed by length, and neither side asked to close. Idle
//! connections time out quickly, since each one holds a thread.
//!
//! TLS is not here. In production Traefik terminates HTTPS and forwards to
//! this listener on an internal Podman network.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::disallowed_methods))]

pub mod range;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufWriter, ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

pub use range::{RangeOutcome, parse_range};

pub const MAX_CONNECTIONS: usize = 128;
/// Headers and request line together.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_TARGET_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 64;
/// Requests served on one connection before it is closed.
const MAX_REQUESTS_PER_CONNECTION: usize = 1000;
/// Unread body bytes the server will read and discard to keep a
/// connection alive; past this it closes instead.
const MAX_DRAIN: u64 = 64 * 1024;
/// The longest chunk-size line (with extensions) and trailer section.
const MAX_CHUNK_LINE: usize = 1024;
const MAX_TRAILERS: usize = 8 * 1024;
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const BODY_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
const THREAD_STACK: usize = 512 * 1024;
const STREAM_BUFFER: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Options,
    Propfind,
    Proppatch,
    Mkcol,
    Copy,
    Move,
    Lock,
    Unlock,
}

impl Method {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            "PROPFIND" => Method::Propfind,
            "PROPPATCH" => Method::Proppatch,
            "MKCOL" => Method::Mkcol,
            "COPY" => Method::Copy,
            "MOVE" => Method::Move,
            "LOCK" => Method::Lock,
            "UNLOCK" => Method::Unlock,
            _ => return None,
        })
    }
}

/// One connection's read side: the socket and whatever has been read from
/// it but not yet consumed (the rest of a header block, the start of a
/// body, or a pipelined next request).
#[derive(Debug)]
struct Conn<'s> {
    stream: &'s TcpStream,
    buf: Vec<u8>,
    start: usize,
}

impl Conn<'_> {
    fn available(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Reads more from the socket; `Ok(0)` at end of stream.
    fn fill(&mut self) -> io::Result<usize> {
        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        let mut chunk = [0_u8; 8192];
        loop {
            match (&*self.stream).read(&mut chunk) {
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads into `out` from the buffer first, then the socket.
    fn read_into(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.available().is_empty() && self.fill()? == 0 {
            return Ok(0);
        }
        let n = out.len().min(self.available().len());
        out[..n].copy_from_slice(&self.available()[..n]);
        self.consume(n);
        Ok(n)
    }

    /// One CRLF-terminated line, without the terminator, at most `max`
    /// bytes.
    fn line(&mut self, max: usize) -> io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.available().windows(2).position(|w| w == b"\r\n") {
                let line = self.available()[..i].to_vec();
                self.consume(i + 2);
                return Ok(line);
            }
            if self.available().len() > max {
                return Err(io::Error::new(ErrorKind::InvalidData, "line too long"));
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "connection closed"));
            }
        }
    }
}

#[derive(Debug)]
enum Framing {
    Length { remaining: u64 },
    Chunked { in_chunk: u64, done: bool },
}

/// A request body, decoded from its framing as it is read.
#[derive(Debug)]
pub struct Body<'c, 's> {
    conn: &'c mut Conn<'s>,
    framing: Framing,
    /// `Expect: 100-continue` that has not been answered yet.
    continue_pending: bool,
    /// The body could not be decoded; the connection must close.
    broken: bool,
    total: u64,
}

impl Body<'_, '_> {
    /// Whether the whole body has been read.
    pub fn is_done(&self) -> bool {
        match self.framing {
            Framing::Length { remaining } => remaining == 0,
            Framing::Chunked { done, .. } => done,
        }
    }

    /// The length the client declared, if it used `Content-Length`.
    pub fn declared_len(&self) -> Option<u64> {
        match self.framing {
            Framing::Length { remaining } => Some(self.total + remaining),
            Framing::Chunked { .. } => None,
        }
    }

    fn send_continue(&mut self) -> io::Result<()> {
        if self.continue_pending {
            self.continue_pending = false;
            (&*self.conn.stream).write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        }
        Ok(())
    }

    fn read_chunked(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            let Framing::Chunked { in_chunk, done } = &mut self.framing else {
                return Ok(0);
            };
            if *done {
                return Ok(0);
            }
            if *in_chunk > 0 {
                let want = usize::try_from(*in_chunk).unwrap_or(usize::MAX).min(out.len());
                let n = self.conn.read_into(&mut out[..want])?;
                if n == 0 {
                    return Err(io::Error::new(ErrorKind::UnexpectedEof, "body cut short"));
                }
                *in_chunk -= n as u64;
                if *in_chunk == 0 && !self.conn.line(2)?.is_empty() {
                    return Err(io::Error::new(ErrorKind::InvalidData, "bad chunk terminator"));
                }
                return Ok(n);
            }
            let line = self.conn.line(MAX_CHUNK_LINE)?;
            let size_text = line.split(|&b| b == b';').next().unwrap_or(&[]);
            let size_text = std::str::from_utf8(size_text)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "bad chunk size"))?
                .trim();
            let size = u64::from_str_radix(size_text, 16)
                .map_err(|_| io::Error::new(ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                // Trailers, ignored, up to an empty line.
                let mut seen = 0;
                loop {
                    let t = self.conn.line(MAX_TRAILERS)?;
                    seen += t.len() + 2;
                    if t.is_empty() {
                        break;
                    }
                    if seen > MAX_TRAILERS {
                        return Err(io::Error::new(ErrorKind::InvalidData, "trailers too long"));
                    }
                }
                *done = true;
                return Ok(0);
            }
            *in_chunk = size;
        }
    }
}

impl Read for Body<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.is_done() {
            return Ok(0);
        }
        if self.broken {
            return Err(io::Error::new(ErrorKind::InvalidData, "body unreadable"));
        }
        let result = (|| {
            self.send_continue()?;
            match &mut self.framing {
                Framing::Length { remaining } => {
                    let want = usize::try_from(*remaining).unwrap_or(usize::MAX).min(out.len());
                    let n = self.conn.read_into(&mut out[..want])?;
                    if n == 0 {
                        return Err(io::Error::new(ErrorKind::UnexpectedEof, "body cut short"));
                    }
                    *remaining -= n as u64;
                    Ok(n)
                }
                Framing::Chunked { .. } => self.read_chunked(out),
            }
        })();
        match result {
            Ok(n) => {
                self.total += n as u64;
                Ok(n)
            }
            Err(e) => {
                self.broken = true;
                Err(e)
            }
        }
    }
}

/// Why a body could not be read in full.
#[derive(Debug, PartialEq, Eq)]
pub enum BodyError {
    TooLarge,
    Broken,
}

#[derive(Debug)]
pub struct Request<'c, 's> {
    pub method: Method,
    /// The path without its query string, percent-decoding not applied.
    pub path: String,
    pub query: Vec<(String, String)>,
    /// Header names lowercased; a repeated header keeps its first value.
    pub headers: HashMap<String, String>,
    pub peer: IpAddr,
    body: Body<'c, 's>,
}

impl<'c, 's> Request<'c, 's> {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then_some(v)
        })
    }

    /// The body, to stream.
    pub fn body(&mut self) -> &mut Body<'c, 's> {
        &mut self.body
    }

    /// The whole body, at most `max` bytes.
    pub fn read_body(&mut self, max: usize) -> Result<Vec<u8>, BodyError> {
        if self.body.declared_len().is_some_and(|n| n > max as u64) {
            return Err(BodyError::TooLarge);
        }
        let mut out = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            match self.body.read(&mut chunk) {
                Ok(0) => return Ok(out),
                Ok(n) => {
                    if out.len() + n > max {
                        return Err(BodyError::TooLarge);
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Err(_) => return Err(BodyError::Broken),
            }
        }
    }

    fn is_form(&self) -> bool {
        self.header("content-type").is_some_and(|t| {
            t.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/x-www-form-urlencoded"))
        })
    }

    /// The body as an `application/x-www-form-urlencoded` form of at most
    /// `max` bytes. A body of any other type reads as an empty form.
    pub fn read_form(&mut self, max: usize) -> Result<Form, BodyError> {
        if !self.is_form() {
            return Ok(Form(Vec::new()));
        }
        let mut body = self.read_body(max)?;
        let form = Form(parse_urlencoded(&body));
        hd_common::buf::wipe_vec(&mut body);
        Ok(form)
    }
}

/// Decoded form fields, in order. Values may hold secrets, so the Debug
/// output shows only the field names.
pub struct Form(Vec<(String, String)>);

impl Form {
    pub fn new(pairs: Vec<(String, String)>) -> Self {
        Self(pairs)
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.0.iter().filter(move |(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// The trimmed value, or "" when absent.
    pub fn text(&self, name: &str) -> &str {
        self.get(name).unwrap_or("").trim()
    }

    pub fn checked(&self, name: &str) -> bool {
        self.get(name).is_some_and(|v| v == "on" || v == "1" || v == "true")
    }
}

impl std::fmt::Debug for Form {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.iter().map(|(k, _)| k)).finish()
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        for (_, v) in &mut self.0 {
            hd_common::buf::wipe_string(v);
        }
    }
}

fn hex_value(c: u8) -> Option<u8> {
    char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// Percent-decodes `s`, with `+` as a space when `plus` is set. Invalid
/// escapes are kept literally; invalid UTF-8 is replaced.
pub fn percent_decode(s: &[u8], plus: bool) -> String {
    match percent_decode_bytes(s, plus) {
        Ok(s) => s,
        Err(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Percent-decodes `s`; `Err` holds the bytes when they are not UTF-8.
/// Paths use this, refusing what does not decode, rather than silently
/// replacing characters and naming a different file.
pub fn percent_decode_bytes(s: &[u8], plus: bool) -> Result<String, Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' if plus => out.push(b' '),
            b'%' if i + 2 < s.len() => {
                if let (Some(hi), Some(lo)) = (hex_value(s[i + 1]), hex_value(s[i + 2])) {
                    out.push(hi << 4 | lo);
                    i += 2;
                } else {
                    out.push(b'%');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).map_err(std::string::FromUtf8Error::into_bytes)
}

/// Percent-encodes everything but the RFC 3986 unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Percent-encodes a path, keeping its `/` separators.
pub fn percent_encode_path(s: &str) -> String {
    s.split('/').map(percent_encode).collect::<Vec<_>>().join("/")
}

pub fn parse_urlencoded(body: &[u8]) -> Vec<(String, String)> {
    body.split(|&b| b == b'&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &[][..]),
            };
            (percent_decode(k, true), percent_decode(v, true))
        })
        .collect()
}

/// A body produced while it is sent. `pump` writes until the source is
/// exhausted; an error writing to `out` means the client went away. An
/// error from the source itself (a failed verification) aborts the
/// response: the connection is closed without completing it, so the
/// client can never take a partial body for a whole one.
pub trait StreamSource: Send {
    fn pump(&mut self, out: &mut dyn Write) -> io::Result<()>;
}

/// Any reader is a stream source.
pub struct ReadSource<R>(pub R);

impl<R> std::fmt::Debug for ReadSource<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadSource")
    }
}

impl<R: Read + Send> StreamSource for ReadSource<R> {
    fn pump(&mut self, out: &mut dyn Write) -> io::Result<()> {
        io::copy(&mut self.0, out).map(|_| ())
    }
}

pub enum ResponseBody<'a> {
    Bytes(Vec<u8>),
    /// `len` bytes of `file` from `offset`.
    File {
        file: File,
        offset: u64,
        len: u64,
    },
    /// A generated body. With a `length`, exactly that many bytes are
    /// promised and anything else aborts the connection; without, the body
    /// ends when the connection closes.
    Stream {
        source: Box<dyn StreamSource + 'a>,
        length: Option<u64>,
    },
}

impl std::fmt::Debug for ResponseBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseBody::Bytes(b) => write!(f, "Bytes({})", b.len()),
            ResponseBody::File { offset, len, .. } => write!(f, "File({offset}+{len})"),
            ResponseBody::Stream { length, .. } => write!(f, "Stream({length:?})"),
        }
    }
}

#[derive(Debug)]
pub struct Response<'a> {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: ResponseBody<'a>,
    /// Close the connection after this response.
    pub close: bool,
}

impl<'a> Response<'a> {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body: ResponseBody::Bytes(body.into()),
            close: false,
        }
    }

    /// A response with no body at all (no Content-Type either).
    pub fn empty(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: ResponseBody::Bytes(Vec::new()), close: false }
    }

    pub fn html(status: u16, body: String) -> Self {
        Self::new(status, "text/html; charset=utf-8", body)
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", body)
    }

    pub fn json(status: u16, body: String) -> Self {
        Self::new(status, "application/json", body)
    }

    /// A 303 to a same-site path; anything else becomes "/".
    pub fn redirect(location: &str) -> Self {
        let safe = location.starts_with('/')
            && !location.starts_with("//")
            && !location.contains(['\\', '\r', '\n']);
        let mut r = Self::new(303, "text/plain; charset=utf-8", "See Other");
        r.headers.push(("Location".to_owned(), if safe { location } else { "/" }.to_owned()));
        r
    }

    /// A representation of `size` bytes, honouring the request's `Range`:
    /// `open(offset)` produces the bytes from `offset` on.
    pub fn ranged(
        range: Option<&str>,
        content_type: &str,
        size: u64,
        open: impl FnOnce(u64) -> io::Result<Box<dyn StreamSource + 'a>>,
    ) -> Self {
        let (status, start, len, content_range) = match parse_range(range, size) {
            RangeOutcome::Full => (200, 0, size, None),
            RangeOutcome::Partial { start, end } => {
                (206, start, end - start + 1, Some(format!("bytes {start}-{end}/{size}")))
            }
            RangeOutcome::Unsatisfiable => {
                return Self::text(416, "Range Not Satisfiable")
                    .with_header("Content-Range", format!("bytes */{size}"));
            }
        };
        let Ok(source) = open(start) else {
            return Self::text(500, "the file cannot be read");
        };
        let mut r = Self {
            status,
            headers: vec![
                ("Content-Type".to_owned(), content_type.to_owned()),
                ("Accept-Ranges".to_owned(), "bytes".to_owned()),
            ],
            body: ResponseBody::Stream {
                source: Box::new(Limit { inner: source, len }),
                length: Some(len),
            },
            close: false,
        };
        if let Some(cr) = content_range {
            r.headers.push(("Content-Range".to_owned(), cr));
        }
        r
    }

    #[must_use]
    pub fn with_header(mut self, name: &str, value: String) -> Self {
        self.headers.push((name.to_owned(), value));
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A stream cut to `len` bytes, for ranges.
struct Limit<'a> {
    inner: Box<dyn StreamSource + 'a>,
    len: u64,
}

impl StreamSource for Limit<'_> {
    fn pump(&mut self, out: &mut dyn Write) -> io::Result<()> {
        struct Cut<'w> {
            out: &'w mut dyn Write,
            left: u64,
        }
        impl Write for Cut<'_> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                if self.left == 0 {
                    // Enough was sent: stop the source.
                    return Err(io::Error::other("range complete"));
                }
                let n = usize::try_from(self.left).unwrap_or(usize::MAX).min(buf.len());
                self.out.write_all(&buf[..n])?;
                self.left -= n as u64;
                Ok(n)
            }
            fn flush(&mut self) -> io::Result<()> {
                self.out.flush()
            }
        }
        let mut cut = Cut { out, left: self.len };
        match self.inner.pump(&mut cut) {
            Ok(()) => Ok(()),
            Err(_) if cut.left == 0 => Ok(()),
            Err(e) => Err(e),
        }
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        207 => "Multi-Status",
        301 => "Moved Permanently",
        303 => "See Other",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        410 => "Gone",
        411 => "Length Required",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Range Not Satisfiable",
        423 => "Locked",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Internal Server Error",
    }
}

/// Headers every response carries unless it sets its own. The pages use no
/// JavaScript, no inline styles, and no third-party origins, so the policy
/// can refuse all of them.
const SECURITY_HEADERS: &[(&str, &str)] = &[
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"),
    ("Cache-Control", "no-store"),
];

fn head_block(r: &Response<'_>, hsts: bool, close: bool) -> String {
    let mut out = String::with_capacity(1024);
    let _ = write!(out, "HTTP/1.1 {} {}\r\n", r.status, reason(r.status));
    for (k, v) in SECURITY_HEADERS {
        if !r.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(k)) {
            let _ = write!(out, "{k}: {v}\r\n");
        }
    }
    if hsts {
        out.push_str("Strict-Transport-Security: max-age=31536000\r\n");
    }
    for (k, v) in &r.headers {
        // Header values are built by this program, but a stray newline must
        // never split a response.
        if k.contains(['\r', '\n']) || v.contains(['\r', '\n']) {
            continue;
        }
        let _ = write!(out, "{k}: {v}\r\n");
    }
    let length = match &r.body {
        ResponseBody::Bytes(b) => Some(b.len() as u64),
        ResponseBody::File { len, .. } => Some(*len),
        ResponseBody::Stream { length, .. } => *length,
    };
    if let Some(n) = length {
        let _ = write!(out, "Content-Length: {n}\r\n");
    }
    out.push_str(if close {
        "Connection: close\r\n\r\n"
    } else {
        "Connection: keep-alive\r\n\r\n"
    });
    out
}

/// Writes a response. `Err` means the connection is unusable (the client
/// went away, or a streamed body failed part-way and must not be
/// completed).
fn write_response(
    stream: &TcpStream,
    r: Response<'_>,
    head_only: bool,
    hsts: bool,
    close: bool,
) -> io::Result<()> {
    let mut stream = stream;
    let head = head_block(&r, hsts, close);
    stream.write_all(head.as_bytes())?;
    match r.body {
        ResponseBody::Bytes(mut bytes) => {
            if !head_only {
                stream.write_all(&bytes)?;
            }
            hd_common::buf::wipe_vec(&mut bytes);
        }
        ResponseBody::File { file, offset, len } if !head_only => {
            use std::io::{Seek, SeekFrom};
            let mut file = file;
            file.seek(SeekFrom::Start(offset))?;
            // std turns a File-to-TcpStream copy into sendfile(2).
            let copied = io::copy(&mut file.take(len), &mut stream)?;
            if copied != len {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "file shrank"));
            }
        }
        ResponseBody::Stream { mut source, length } if !head_only => {
            struct Counting<'w, W: Write> {
                out: &'w mut W,
                sent: u64,
            }
            impl<W: Write> Write for Counting<'_, W> {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    let n = self.out.write(buf)?;
                    self.sent += n as u64;
                    Ok(n)
                }
                fn flush(&mut self) -> io::Result<()> {
                    self.out.flush()
                }
            }
            let mut buffered = BufWriter::with_capacity(STREAM_BUFFER, &mut stream);
            let mut counting = Counting { out: &mut buffered, sent: 0 };
            source.pump(&mut counting)?;
            let sent = counting.sent;
            buffered.flush()?;
            if length.is_some_and(|n| n != sent) {
                return Err(io::Error::new(ErrorKind::InvalidData, "stream length mismatch"));
            }
        }
        ResponseBody::File { .. } | ResponseBody::Stream { .. } => {}
    }
    stream.flush()
}

#[derive(Debug)]
enum ReadError {
    Status(u16),
    /// The connection closed or timed out between requests: no response.
    Gone,
}

/// Finds the end of the header block: the index just past "\r\n\r\n".
fn header_end(buf: &[u8], from: usize) -> Option<usize> {
    let tail = buf.get(from..)?;
    tail.windows(4).position(|w| w == b"\r\n\r\n").map(|i| from + i + 4)
}

struct Head {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    headers: HashMap<String, String>,
    http10: bool,
}

fn read_head(conn: &mut Conn<'_>) -> Result<Head, ReadError> {
    let mut searched = 0;
    let end = loop {
        if let Some(end) = header_end(conn.available(), searched) {
            break end;
        }
        searched = conn.available().len().saturating_sub(3);
        if conn.available().len() > MAX_HEADER_BYTES {
            return Err(ReadError::Status(431));
        }
        match conn.fill() {
            Ok(0) => return Err(ReadError::Gone),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                // Silence before a request starts is just an idle client.
                return Err(if conn.available().is_empty() {
                    ReadError::Gone
                } else {
                    ReadError::Status(408)
                });
            }
            Err(_) => return Err(ReadError::Gone),
        }
    };
    if end > MAX_HEADER_BYTES {
        return Err(ReadError::Status(431));
    }
    let head = std::str::from_utf8(&conn.available()[..end - 4])
        .map_err(|_| ReadError::Status(400))?
        .to_owned();
    conn.consume(end);
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(ReadError::Status(400))?;
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Status(400));
    };
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(ReadError::Status(400)),
    };
    let method = Method::parse(method).ok_or(ReadError::Status(501))?;
    if !target.starts_with('/') {
        return Err(ReadError::Status(400));
    }
    if target.len() > MAX_TARGET_BYTES {
        return Err(ReadError::Status(414));
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, parse_urlencoded(q.as_bytes())),
        None => (target, Vec::new()),
    };
    let mut headers = HashMap::new();
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(ReadError::Status(431));
        }
        let (name, value) = line.split_once(':').ok_or(ReadError::Status(400))?;
        if name.is_empty() || name.contains(|c: char| !c.is_ascii_graphic()) {
            return Err(ReadError::Status(400));
        }
        let name = name.to_ascii_lowercase();
        if (name == "content-length" || name == "transfer-encoding") && headers.contains_key(&name)
        {
            // Two framings, or two lengths: the classic request-smuggling
            // shapes. Refuse rather than pick one.
            return Err(ReadError::Status(400));
        }
        headers.entry(name).or_insert_with(|| value.trim().to_owned());
    }
    Ok(Head { method, path: path.to_owned(), query, headers, http10 })
}

fn framing(headers: &HashMap<String, String>) -> Result<Framing, ReadError> {
    match (headers.get("transfer-encoding"), headers.get("content-length")) {
        (Some(_), Some(_)) => Err(ReadError::Status(400)),
        (Some(te), None) => {
            if te.eq_ignore_ascii_case("chunked") {
                Ok(Framing::Chunked { in_chunk: 0, done: false })
            } else {
                Err(ReadError::Status(501))
            }
        }
        (None, Some(cl)) => hd_common::buf::parse_u64(cl.as_bytes(), u64::MAX)
            .map(|remaining| Framing::Length { remaining })
            .ok_or(ReadError::Status(400)),
        (None, None) => Ok(Framing::Length { remaining: 0 }),
    }
}

pub trait Handler: Send + Sync + 'static {
    fn handle<'a>(&'a self, request: &mut Request<'_, '_>) -> Response<'a>;
    /// Whether responses advertise HSTS (only when served behind HTTPS).
    fn hsts(&self) -> bool;
}

fn wants_close(headers: &HashMap<String, String>, http10: bool) -> bool {
    let connection = headers.get("connection").map(|v| v.to_ascii_lowercase());
    match connection.as_deref() {
        Some(v) if v.split(',').any(|t| t.trim() == "close") => true,
        Some(v) if v.split(',').any(|t| t.trim() == "keep-alive") => false,
        _ => http10,
    }
}

fn serve_connection<H: Handler>(handler: &H, stream: &TcpStream, peer: SocketAddr) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = stream.set_nodelay(true);
    let hsts = handler.hsts();
    let mut conn = Conn { stream, buf: Vec::new(), start: 0 };
    for served in 0..MAX_REQUESTS_PER_CONNECTION {
        let timeout = if served == 0 { FIRST_REQUEST_TIMEOUT } else { IDLE_TIMEOUT };
        let _ = stream.set_read_timeout(Some(timeout));
        let head = match read_head(&mut conn) {
            Ok(head) => head,
            Err(ReadError::Gone) => return,
            Err(ReadError::Status(code)) => {
                let _ =
                    write_response(stream, Response::text(code, reason(code)), false, hsts, true);
                return;
            }
        };
        let framing = match framing(&head.headers) {
            Ok(f) => f,
            Err(ReadError::Status(code)) => {
                let _ =
                    write_response(stream, Response::text(code, reason(code)), false, hsts, true);
                return;
            }
            Err(ReadError::Gone) => return,
        };
        let _ = stream.set_read_timeout(Some(BODY_TIMEOUT));
        let mut close =
            wants_close(&head.headers, head.http10) || served + 1 == MAX_REQUESTS_PER_CONNECTION;
        let expect_continue =
            head.headers.get("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
        let head_only = head.method == Method::Head;
        let mut request = Request {
            method: head.method,
            path: head.path,
            query: head.query,
            headers: head.headers,
            peer: peer.ip(),
            body: Body {
                conn: &mut conn,
                framing,
                continue_pending: expect_continue,
                broken: false,
                total: 0,
            },
        };
        let response = handler.handle(&mut request);
        // Keep the connection only if the body is finished, or can be
        // finished cheaply. A body the client is still waiting to send
        // (100-continue never sent) means the client decides; close.
        let body = request.body();
        if !body.is_done() {
            if body.continue_pending || body.broken {
                close = true;
            } else {
                let mut sink = io::sink();
                let drained = io::copy(&mut body.take(MAX_DRAIN), &mut sink);
                if drained.is_err() || !body.is_done() {
                    close = true;
                }
            }
        }
        if body.broken {
            close = true;
        }
        let unframed =
            matches!(response.body, ResponseBody::Stream { length: None, .. }) && !head_only;
        close = close || response.close || unframed;
        if write_response(stream, response, head_only, hsts, close).is_err() || close {
            return;
        }
    }
}

/// Accepts connections forever, serving each on its own thread. Past
/// [`MAX_CONNECTIONS`] concurrent connections a client gets a 503.
pub fn serve<H: Handler>(listener: &TcpListener, handler: &Arc<H>) {
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else { continue };
        let Ok(peer) = stream.peer_addr() else { continue };
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::AcqRel);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = write_response(&stream, Response::text(503, "busy"), false, false, true);
            continue;
        }
        let handler = Arc::clone(handler);
        let counter = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("http".to_owned())
            .stack_size(THREAD_STACK)
            .spawn(move || {
                serve_connection(handler.as_ref(), &stream, peer);
                let _ = stream.shutdown(std::net::Shutdown::Both);
                counter.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencoded_forms_decode() {
        let pairs = parse_urlencoded(b"a=1&b=hello+world&c=%2Fx%3D&d&e=%zz&f=%e2%9c%93");
        let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("a"), Some("1"));
        assert_eq!(get("b"), Some("hello world"));
        assert_eq!(get("c"), Some("/x="));
        assert_eq!(get("d"), Some(""));
        assert_eq!(get("e"), Some("%zz"));
        assert_eq!(get("f"), Some("\u{2713}"));
        assert_eq!(percent_decode(b"%4", false), "%4");
        assert_eq!(percent_decode(b"%41", false), "A");
        assert_eq!(percent_decode(b"a+b", false), "a+b");
        assert!(percent_decode_bytes(b"%ff", false).is_err());
    }

    #[test]
    fn percent_encoding_round_trips() {
        let s = "Björk – Jóga (live)/1.mp3";
        let e = percent_encode(s);
        assert!(e.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)));
        assert_eq!(percent_decode(e.as_bytes(), false), s);
        assert_eq!(percent_encode_path("a b/c"), "a%20b/c");
    }

    #[test]
    fn redirects_stay_on_site() {
        let loc = |r: Response<'_>| r.header("Location").unwrap().to_owned();
        assert_eq!(loc(Response::redirect("/status")), "/status");
        assert_eq!(loc(Response::redirect("//evil.example")), "/");
        assert_eq!(loc(Response::redirect("https://evil.example")), "/");
        assert_eq!(loc(Response::redirect("/a\r\nSet-Cookie: x")), "/");
    }

    #[test]
    fn form_debug_hides_values() {
        let f = Form(vec![("p".to_owned(), "hunter2".to_owned())]);
        assert_eq!(format!("{f:?}"), "[\"p\"]");
    }

    #[test]
    fn head_block_frames_each_body_kind() {
        struct Empty;
        impl StreamSource for Empty {
            fn pump(&mut self, _: &mut dyn Write) -> io::Result<()> {
                Ok(())
            }
        }
        let stream = |length| Response {
            status: 200,
            headers: Vec::new(),
            body: ResponseBody::Stream { source: Box::new(Empty), length },
            close: false,
        };
        let bytes = head_block(&Response::text(200, "abc"), false, false);
        assert!(bytes.contains("Content-Length: 3\r\n"));
        assert!(bytes.ends_with("Connection: keep-alive\r\n\r\n"));
        let open = head_block(&stream(None), true, true);
        assert!(!open.contains("Content-Length"));
        assert!(open.ends_with("Connection: close\r\n\r\n"));
        assert!(open.contains("Strict-Transport-Security"));
        assert!(head_block(&stream(Some(9)), false, false).contains("Content-Length: 9\r\n"));
        let cached = head_block(
            &Response::text(200, "").with_header("Cache-Control", "max-age=60".into()),
            false,
            false,
        );
        assert!(cached.contains("Cache-Control: max-age=60") && !cached.contains("no-store"));
    }
}
