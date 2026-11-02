//! The server over loopback TCP: framing, keep-alive, and streamed bodies.

#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hd_crypto::Sha256;
use hd_http::{Handler, Method, ReadSource, Request, Response};

struct Echo;

impl Handler for Echo {
    fn handle<'a>(&'a self, req: &mut Request<'_, '_>) -> Response<'a> {
        match (req.method, req.path.as_str()) {
            // Streams the body through a hash, never holding it.
            (Method::Put, "/hash") => {
                let mut h = Sha256::new().unwrap();
                let mut buf = vec![0_u8; 65536];
                loop {
                    match req.body().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => h.update(&buf[..n]),
                        Err(_) => return Response::text(400, "bad body"),
                    }
                }
                let len = h.len();
                Response::text(200, &format!("{len} {}", hd_crypto::hex(&h.finish().unwrap())))
            }
            (Method::Post, "/small") => match req.read_body(16) {
                Ok(b) => Response::new(200, "application/octet-stream", b),
                Err(_) => Response::text(413, "too large"),
            },
            (Method::Get | Method::Head, "/range") => {
                let data: Vec<u8> = (0..100_u8).collect();
                Response::ranged(req.header("range"), "application/octet-stream", 100, |off| {
                    let off = usize::try_from(off).unwrap();
                    Ok(Box::new(ReadSource(io::Cursor::new(data[off..].to_vec()))))
                })
            }
            // Ignores its body entirely.
            (_, "/ignore") => Response::text(200, "ignored"),
            _ => Response::text(404, "nope"),
        }
    }
    fn hsts(&self) -> bool {
        false
    }
}

fn start() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = Arc::new(Echo);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &h))
        .unwrap();
    addr
}

fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s
}

/// Reads one response: (status, headers, body).
fn response(s: &mut TcpStream) -> (u16, String, Vec<u8>) {
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(s.read(&mut byte).unwrap(), 1, "connection closed mid-head");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    let status: u16 = head[9..12].parse().unwrap();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .map_or(0, |v| v.trim().parse().unwrap());
    let mut body = vec![0_u8; len];
    s.read_exact(&mut body).unwrap();
    (status, head, body)
}

fn closed(s: &mut TcpStream) -> bool {
    let mut b = [0_u8; 1];
    matches!(s.read(&mut b), Ok(0) | Err(_))
}

#[test]
fn keep_alive_and_pipelining() {
    let addr = start();
    let mut s = connect(addr);
    // Two requests in one write: both answered, in order, on one socket.
    s.write_all(b"POST /small HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcPOST /small HTTP/1.1\r\nContent-Length: 2\r\n\r\nxy").unwrap();
    let (st, head, body) = response(&mut s);
    assert_eq!((st, body.as_slice()), (200, &b"abc"[..]));
    assert!(head.contains("Connection: keep-alive"));
    assert_eq!(response(&mut s).2, b"xy");
    // Connection: close is honoured.
    s.write_all(b"GET /x HTTP/1.1\r\nConnection: close\r\n\r\n").unwrap();
    let (st, head, _) = response(&mut s);
    assert_eq!(st, 404);
    assert!(head.contains("Connection: close"));
    assert!(closed(&mut s));
    // HTTP/1.0 closes by default.
    let mut s = connect(addr);
    s.write_all(b"GET /x HTTP/1.0\r\n\r\n").unwrap();
    response(&mut s);
    assert!(closed(&mut s));
}

#[test]
fn large_bodies_stream_with_either_framing() {
    let addr = start();
    let data: Vec<u8> = (0..5_000_000_u32).map(|i| (i * 7 % 251) as u8).collect();
    let expected = format!("{} {}", data.len(), hd_crypto::hex(&hd_crypto::sha256(&data).unwrap()));
    let mut s = connect(addr);
    s.write_all(format!("PUT /hash HTTP/1.1\r\nContent-Length: {}\r\n\r\n", data.len()).as_bytes())
        .unwrap();
    s.write_all(&data).unwrap();
    assert_eq!(String::from_utf8(response(&mut s).2).unwrap(), expected);
    // Chunked, in uneven pieces, with an extension and a trailer.
    s.write_all(b"PUT /hash HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
    for piece in data.chunks(123_457) {
        s.write_all(format!("{:x};ext=1\r\n", piece.len()).as_bytes()).unwrap();
        s.write_all(piece).unwrap();
        s.write_all(b"\r\n").unwrap();
    }
    s.write_all(b"0\r\nX-Trailer: y\r\n\r\n").unwrap();
    assert_eq!(String::from_utf8(response(&mut s).2).unwrap(), expected);
    // Still alive afterwards.
    s.write_all(b"POST /small HTTP/1.1\r\nContent-Length: 1\r\n\r\nz").unwrap();
    assert_eq!(response(&mut s).2, b"z");
}

#[test]
fn expect_continue_is_answered_only_when_the_body_is_wanted() {
    let addr = start();
    let mut s = connect(addr);
    s.write_all(b"PUT /hash HTTP/1.1\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n")
        .unwrap();
    let mut interim = [0_u8; 25];
    s.read_exact(&mut interim).unwrap();
    assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
    s.write_all(b"abc").unwrap();
    assert_eq!(response(&mut s).0, 200);
    // A handler that refuses without reading: no 100, and the connection
    // closes because the client's body is in limbo.
    let mut s = connect(addr);
    s.write_all(b"PUT /ignore HTTP/1.1\r\nContent-Length: 1000000\r\nExpect: 100-continue\r\n\r\n")
        .unwrap();
    let (st, head, _) = response(&mut s);
    assert_eq!(st, 200);
    assert!(head.contains("Connection: close"));
}

#[test]
fn unread_bodies_are_drained_if_small_and_close_the_connection_if_not() {
    let addr = start();
    let mut s = connect(addr);
    s.write_all(b"PUT /ignore HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello").unwrap();
    assert!(response(&mut s).1.contains("keep-alive"));
    s.write_all(b"POST /small HTTP/1.1\r\nContent-Length: 1\r\n\r\nq").unwrap();
    assert_eq!(response(&mut s).2, b"q");
    let mut s = connect(addr);
    let big = vec![b'x'; 200_000];
    s.write_all(
        format!("PUT /ignore HTTP/1.1\r\nContent-Length: {}\r\n\r\n", big.len()).as_bytes(),
    )
    .unwrap();
    let _ = s.write_all(&big);
    assert!(response(&mut s).1.contains("Connection: close"));
    // Bodies over a handler's limit are refused.
    let mut s = connect(addr);
    s.write_all(b"POST /small HTTP/1.1\r\nContent-Length: 17\r\n\r\n01234567890123456").unwrap();
    assert_eq!(response(&mut s).0, 413);
}

#[test]
fn ambiguous_framing_is_refused() {
    let addr = start();
    for req in [
        &b"POST /small HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"[..],
        b"POST /small HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
        b"POST /small HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
        b"POST /small HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
    ] {
        let mut s = connect(addr);
        s.write_all(req).unwrap();
        let (st, _, _) = response(&mut s);
        assert!(st == 400 || st == 501, "{st}");
        assert!(closed(&mut s));
    }
    let mut s = connect(addr);
    s.write_all(b"PUT /hash HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").unwrap();
    assert_eq!(response(&mut s).0, 400);
}

#[test]
fn ranges() {
    let addr = start();
    let mut s = connect(addr);
    s.write_all(b"GET /range HTTP/1.1\r\nRange: bytes=10-19\r\n\r\n").unwrap();
    let (st, head, body) = response(&mut s);
    assert_eq!(st, 206);
    assert!(head.contains("Content-Range: bytes 10-19/100"));
    assert_eq!(body, (10..20_u8).collect::<Vec<_>>());
    s.write_all(b"GET /range HTTP/1.1\r\nRange: bytes=-5\r\n\r\n").unwrap();
    assert_eq!(response(&mut s).2, (95..100_u8).collect::<Vec<_>>());
    s.write_all(b"GET /range HTTP/1.1\r\nRange: bytes=200-\r\n\r\n").unwrap();
    assert_eq!(response(&mut s).0, 416);
    s.write_all(b"GET /range HTTP/1.1\r\n\r\n").unwrap();
    assert_eq!(response(&mut s).2.len(), 100);
    s.write_all(b"HEAD /range HTTP/1.1\r\n\r\n").unwrap();
    let mut head = Vec::new();
    let mut b = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    assert!(String::from_utf8(head).unwrap().contains("Content-Length: 100"));
    // The HEAD sent no body, so the connection is still in step.
    s.write_all(b"POST /small HTTP/1.1\r\nContent-Length: 1\r\n\r\nk").unwrap();
    assert_eq!(response(&mut s).2, b"k");
}
