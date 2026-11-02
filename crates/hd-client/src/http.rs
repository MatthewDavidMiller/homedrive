//! A small HTTP/1.1 client for the sync API: plain or TLS, keep-alive,
//! bounded responses, one retry on a stale reused connection, and patience
//! with a proxy that says to slow down.

use std::ffi::CString;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use hd_common::{Error, Result};
use hd_sys::ssl::safe::{Client as TlsClient, Stream as TlsStream};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HEADER: usize = 64 * 1024;
/// The largest response read into memory (JSON, a chunk).
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// Where the server is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Parses `https://host[:port]` or `http://host[:port]` (a path, if
    /// any, is not allowed: the API lives at the root).
    pub fn parse(url: &str) -> Result<Self> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(Error::new("the server address must start with https:// (or http://)"));
        };
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
            return Err(Error::new("the server address is just https://host[:port]"));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h.to_owned(), p.parse().map_err(|_| Error::new("bad port in the server address"))?)
            }
            _ => (rest.to_owned(), if tls { 443 } else { 80 }),
        };
        // Plain HTTP would send the password and the device token in the
        // clear; it is only for a server on this same machine.
        if !tls && !is_loopback(&host) {
            return Err(Error::new(
                "http:// is only allowed for a server on this computer (localhost); use https://",
            ));
        }
        Ok(Self { tls, host, port })
    }
}

fn is_loopback(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    bare.eq_ignore_ascii_case("localhost")
        || bare.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// A status, headers, the body length (none: to the end of the
/// connection), and whether the connection closes afterwards.
type Head = (u16, Vec<(String, String)>, Option<u64>, bool);

/// The waits after each HTTP 429, in seconds. A first sync is thousands of
/// small requests, and rate limits in front of the server are normal, so this
/// is a pause and not a failed file.
const THROTTLE_WAITS: [u64; 6] = [1, 2, 4, 8, 15, 30];
/// The longest a `Retry-After` is obeyed for.
const MAX_RETRY_AFTER: u64 = 60;
const TOO_MANY_REQUESTS: u16 = 429;

/// How long to wait after the reply, by its own word if it gives one.
fn throttle_wait(reply: &Reply, scheduled: u64) -> Duration {
    let asked = reply
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok());
    Duration::from_secs(asked.map_or(scheduled, |s| s.min(MAX_RETRY_AFTER)))
}

/// A response with its body in memory.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The `{"error"}` message of a failed call, or the status.
    pub fn error_text(&self) -> String {
        hd_api::parse(&self.body)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str().map(str::to_owned)))
            .unwrap_or_else(|| format!("HTTP {}", self.status))
    }
}

pub struct Http {
    endpoint: Endpoint,
    tls: Option<Arc<TlsClient>>,
    authorization: String,
    conn: Option<BufReader<Conn>>,
    /// Whether a 429 is waited out.
    patient: bool,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Http({:?})", self.endpoint)
    }
}

impl Http {
    /// `authorization` is the whole header value ("Bearer ...").
    pub fn new(
        endpoint: Endpoint,
        ca_file: Option<&std::path::Path>,
        authorization: String,
    ) -> Result<Self> {
        let tls = if endpoint.tls {
            if let Some(f) = ca_file.filter(|f| !f.is_file()) {
                return Err(Error::new(format!("the CA file {} does not exist", f.display())));
            }
            let built_in = if ca_file.is_none() { crate::config::default_ca_file()? } else { None };
            let ca = match ca_file.or(built_in.as_deref()) {
                Some(p) => Some(
                    CString::new(p.as_os_str().as_encoded_bytes())
                        .map_err(|_| Error::new("bad CA file path"))?,
                ),
                None => None,
            };
            Some(Arc::new(TlsClient::new(ca.as_deref())?))
        } else {
            None
        };
        Ok(Self { endpoint, tls, authorization, conn: None, patient: true })
    }

    /// Takes a 429 as the answer. For signing in, where it means too many
    /// wrong passwords and trying again would only make that worse.
    pub fn answer_at_once(&mut self) {
        self.patient = false;
    }

    pub fn set_authorization(&mut self, authorization: String) {
        self.authorization = authorization;
    }

    fn connect(&self) -> io::Result<BufReader<Conn>> {
        let addrs = (self.endpoint.host.as_str(), self.endpoint.port).to_socket_addrs()?;
        let mut last = io::Error::new(ErrorKind::NotFound, "the server's name did not resolve");
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    s.set_read_timeout(Some(READ_TIMEOUT))?;
                    s.set_write_timeout(Some(READ_TIMEOUT))?;
                    s.set_nodelay(true)?;
                    let conn = match &self.tls {
                        Some(client) => {
                            let host = CString::new(self.endpoint.host.as_bytes())
                                .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "bad host"))?;
                            Conn::Tls(Box::new(client.connect(s, &host)?))
                        }
                        None => Conn::Plain(s),
                    };
                    return Ok(BufReader::with_capacity(64 * 1024, conn));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn send(
        &mut self,
        method: &str,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
        extra: Option<(&str, &str)>,
    ) -> io::Result<()> {
        let conn = match &mut self.conn {
            Some(c) => c,
            None => self.conn.insert(self.connect()?),
        };
        let mut head = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: {}\r\nContent-Length: {}\r\nUser-Agent: homedrive/{}\r\n",
            self.endpoint.host,
            self.authorization,
            body.len(),
            hd_common::VERSION
        );
        if let Some(ct) = content_type {
            head.push_str("Content-Type: ");
            head.push_str(ct);
            head.push_str("\r\n");
        }
        if let Some((name, value)) = extra {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let w = conn.get_mut();
        w.write_all(head.as_bytes())?;
        w.write_all(body)?;
        w.flush()
    }

    /// Reads the status line and headers. `None` length means the body
    /// runs to the end of the connection.
    fn read_head(&mut self) -> io::Result<Head> {
        let conn = self.conn.as_mut().ok_or_else(|| io::Error::other("not connected"))?;
        let mut total = 0;
        let mut line = Vec::new();
        let mut lines = Vec::new();
        loop {
            line.clear();
            let n = conn.by_ref().take(MAX_HEADER as u64).read_until(b'\n', &mut line)?;
            if n == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "the server closed the connection",
                ));
            }
            total += n;
            if total > MAX_HEADER {
                return Err(io::Error::new(ErrorKind::InvalidData, "response headers too long"));
            }
            let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_owned();
            if text.is_empty() {
                if lines.is_empty() {
                    continue;
                }
                break;
            }
            lines.push(text);
        }
        let status_line = lines.first().ok_or_else(|| io::Error::other("no status line"))?;
        let status = status_line
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "bad status line"))?;
        let mut headers = Vec::new();
        for l in &lines[1..] {
            if let Some((k, v)) = l.split_once(':') {
                headers.push((k.trim().to_owned(), v.trim().to_owned()));
            }
        }
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _): &&(String, String)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        let length = get("content-length").and_then(|v| v.parse().ok());
        let close =
            get("connection").is_some_and(|v| v.eq_ignore_ascii_case("close")) || length.is_none();
        if status == 100 {
            return self.read_head();
        }
        Ok((status, headers, length, close))
    }

    fn exchange(
        &mut self,
        method: &str,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
        extra: Option<(&str, &str)>,
        sink: Option<&mut dyn Write>,
    ) -> io::Result<Reply> {
        self.send(method, target, content_type, body, extra)?;
        let (status, headers, length, close) = self.read_head()?;
        let conn = self.conn.as_mut().ok_or_else(|| io::Error::other("not connected"))?;
        let mut reply = Reply { status, headers, body: Vec::new() };
        let limit = length.unwrap_or(MAX_BODY as u64 + 1);
        let mut reader = conn.by_ref().take(limit);
        match sink {
            Some(out) if status == 200 || status == 206 => {
                let copied = io::copy(&mut reader, out)?;
                if length.is_some_and(|n| n != copied) {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the download was cut short",
                    ));
                }
            }
            _ => {
                let mut chunk = [0_u8; 16 * 1024];
                loop {
                    let n = match reader.read(&mut chunk) {
                        Ok(n) => n,
                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    };
                    if n == 0 {
                        break;
                    }
                    reply.body.extend_from_slice(&chunk[..n]);
                    if reply.body.len() > MAX_BODY {
                        return Err(io::Error::new(ErrorKind::InvalidData, "response too large"));
                    }
                }
                if length.is_some_and(|n| n != reply.body.len() as u64) {
                    return Err(io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "the response was cut short",
                    ));
                }
            }
        }
        if close {
            self.conn = None;
        }
        Ok(reply)
    }

    /// Sends a request and reads the reply into memory. A request on a
    /// reused connection that fails before any reply is retried once on a
    /// fresh one; the API's calls are all safe to repeat.
    pub fn request(
        &mut self,
        method: &str,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<Reply> {
        self.request_with(method, target, content_type, body, None)
    }

    /// [`Http::request`] with one more header. A reply saying to slow down
    /// is waited out and sent again.
    pub fn request_with(
        &mut self,
        method: &str,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
        extra: Option<(&str, &str)>,
    ) -> Result<Reply> {
        let mut reply = self.request_once(method, target, content_type, body, extra)?;
        if self.patient {
            for wait in THROTTLE_WAITS {
                if reply.status != TOO_MANY_REQUESTS {
                    break;
                }
                std::thread::sleep(throttle_wait(&reply, wait));
                reply = self.request_once(method, target, content_type, body, extra)?;
            }
        }
        Ok(reply)
    }

    fn request_once(
        &mut self,
        method: &str,
        target: &str,
        content_type: Option<&str>,
        body: &[u8],
        extra: Option<(&str, &str)>,
    ) -> Result<Reply> {
        let reused = self.conn.is_some();
        match self.exchange(method, target, content_type, body, extra, None) {
            Ok(r) => Ok(r),
            Err(_) if reused => {
                self.conn = None;
                self.exchange(method, target, content_type, body, extra, None).map_err(|e| {
                    self.conn = None;
                    Error::new(format!("cannot reach the server: {e}"))
                })
            }
            Err(e) => {
                self.conn = None;
                Err(Error::new(format!("cannot reach the server: {e}")))
            }
        }
    }

    /// A GET whose 200 body is streamed into `sink`; other statuses come
    /// back in the reply. Not retried: `sink` may hold part of a body.
    pub fn download(&mut self, target: &str, sink: &mut dyn Write) -> Result<Reply> {
        let mut reply = self.download_once(target, sink)?;
        // Only a 200's body reaches `sink`, so a 429 leaves it empty.
        for wait in THROTTLE_WAITS {
            if reply.status != TOO_MANY_REQUESTS || !self.patient {
                break;
            }
            std::thread::sleep(throttle_wait(&reply, wait));
            reply = self.download_once(target, sink)?;
        }
        Ok(reply)
    }

    fn download_once(&mut self, target: &str, sink: &mut dyn Write) -> Result<Reply> {
        self.exchange("GET", target, None, b"", None, Some(sink)).map_err(|e| {
            self.conn = None;
            Error::new(format!("download failed: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serves `statuses` in turn, one per connection, and counts requests.
    fn server(statuses: &'static [&'static str]) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let thread = std::thread::spawn(move || {
            let mut served = 0;
            for status in statuses {
                let (mut s, _) = listener.accept().unwrap();
                let mut head = [0_u8; 4096];
                let _ = s.read(&mut head).unwrap();
                served += 1;
                write!(s, "HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                    .unwrap();
            }
            served
        });
        (address, thread)
    }

    #[test]
    fn being_told_to_slow_down_is_waited_out() {
        let (address, served) = server(&[
            "429 Too Many Requests\r\nRetry-After: 0",
            "429 Too Many Requests\r\nRetry-After: 0",
            "200 OK",
        ]);
        let mut http =
            Http::new(Endpoint::parse(&address).unwrap(), None, "Bearer x".into()).unwrap();
        let reply = http.request("GET", "/", None, b"").unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(served.join().unwrap(), 3);
    }

    #[test]
    fn a_throttled_sign_in_is_not_repeated() {
        let (address, served) = server(&["429 Too Many Requests\r\nRetry-After: 0"]);
        let mut http =
            Http::new(Endpoint::parse(&address).unwrap(), None, "Bearer x".into()).unwrap();
        http.answer_at_once();
        assert_eq!(http.request("GET", "/", None, b"").unwrap().status, 429);
        assert_eq!(served.join().unwrap(), 1);
    }

    #[test]
    fn endpoints() {
        assert_eq!(
            Endpoint::parse("https://drive.example").unwrap(),
            Endpoint { tls: true, host: "drive.example".into(), port: 443 }
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:8080/").unwrap(),
            Endpoint { tls: false, host: "127.0.0.1".into(), port: 8080 }
        );
        assert!(Endpoint::parse("http://localhost:8080").is_ok());
        assert!(Endpoint::parse("http://[::1]:8080").is_ok());
        // Plain HTTP anywhere else would send credentials in the clear.
        for bad in [
            "drive.example",
            "https://",
            "https://a/b",
            "ftp://x",
            "https://u@x",
            "https://x:port",
            "http://drive.example",
            "http://192.168.1.5:8080",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
}
