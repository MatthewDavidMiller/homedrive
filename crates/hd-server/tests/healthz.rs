//! The assembled server over loopback TCP: what `hd-server healthcheck` and
//! the container's HEALTHCHECK rely on.

#![allow(clippy::disallowed_methods, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use hd_server::App;
use hd_server::config::Config;

fn start() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Arc::new(App::new(Config { listen: addr, data_dir: std::env::temp_dir() }));
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &app))
        .unwrap();
    addr
}

fn get(addr: std::net::SocketAddr, request: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    s.take(64 * 1024).read_to_string(&mut out).unwrap();
    out
}

#[test]
fn healthz_answers_and_everything_else_is_not_found() {
    let addr = start();
    let ok = get(addr, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(ok.starts_with("HTTP/1.1 200 OK\r\n"), "{ok}");
    assert!(ok.ends_with("\r\n\r\nok"));
    assert!(ok.contains("X-Content-Type-Options: nosniff"));
    let head = get(addr, "HEAD /healthz HTTP/1.1\r\nHost: x\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 200") && head.ends_with("\r\n\r\n"));
    let post = get(addr, "POST /healthz HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    assert!(post.starts_with("HTTP/1.1 405"));
    assert!(get(addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n").starts_with("HTTP/1.1 404"));
    assert!(get(addr, "BREW / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 501"));
}
