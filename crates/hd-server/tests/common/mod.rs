//! A server on loopback with a fresh store and users file, and a minimal
//! HTTP client for driving it.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hd_server::App;
use hd_server::config::Config;

pub const ALICE_PW: &str = "alice password";
pub const BOB_PW: &str = "bob password!";

pub struct Server {
    pub addr: SocketAddr,
    pub app: Arc<App>,
    pub dir: PathBuf,
}

pub fn start(name: &str) -> Server {
    let dir = std::env::temp_dir().join(format!("hd-server-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let users = dir.join("users.json");
    std::fs::write(
        &users,
        format!(
            r#"{{"version":1,"users":[{{"name":"alice","password":"{ALICE_PW}","admin":true}},{{"name":"bob","password":"{BOB_PW}"}}]}}"#
        ),
    )
    .unwrap();
    let data = dir.join("store");
    hd_store::Store::init(&data).unwrap();
    let app = Arc::new(App::open(Config::for_test(data, users)).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::clone(&app);
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(move || hd_http::serve(&listener, &served))
        .unwrap();
    Server { addr, app, dir }
}

pub struct Reply {
    pub status: u16,
    pub head: String,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> hd_common::json::Value {
        hd_api::parse(&self.body).unwrap_or_else(|e| panic!("{e}: {}", self.text()))
    }

    pub fn header(&self, name: &str) -> Option<String> {
        let prefix = format!("{}: ", name.to_ascii_lowercase());
        self.head
            .split("\r\n")
            .find(|l| l.to_ascii_lowercase().starts_with(&prefix))
            .map(|l| l[prefix.len()..].to_owned())
    }
}

pub fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", hd_common::base64::encode(format!("{user}:{password}").as_bytes()))
}

pub fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// One request on its own connection.
pub fn request(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(70))).unwrap();
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        let _ = write!(head, "{k}: {v}\r\n");
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(body).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("no header block") + 4;
    let head = String::from_utf8(raw[..split].to_vec()).unwrap();
    let status = head[9..12].parse().unwrap();
    Reply { status, head, body: raw[split..].to_vec() }
}
