//! The homedrive server entry point.
//!
//! ```text
//! hd-server [serve]      Run the server (the container's command)
//! hd-server healthcheck  Exit 0 when the local server answers /healthz
//! hd-server version      Print the version
//! ```
//!
//! Configuration comes from the environment; see `hd_server::config`.

#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::Arc;

use hd_common::{Error, Result};
use hd_server::App;
use hd_server::config::Config;

fn serve() -> Result<()> {
    // As PID 1 in a container an unhandled SIGTERM is ignored, so `podman
    // stop` would wait and then SIGKILL. The signals are blocked before any
    // thread starts, and one thread takes them and exits. Every write the
    // server acknowledges is already durable, so stopping needs no flush.
    let signals = hd_sys::posix::TerminationSignals::new()?;
    signals.block()?;
    let config = Config::from_env()?;
    let listen = config.listen;
    let app = Arc::new(App::new(config));
    std::thread::Builder::new()
        .name("signals".to_owned())
        .stack_size(64 * 1024)
        .spawn(move || {
            if let Ok(sig) = signals.wait() {
                eprintln!("hd-server: signal {sig}; stopping");
                std::process::exit(0);
            }
        })
        .map_err(|e| Error::new(format!("cannot start the signal thread: {e}")))?;
    let listener = TcpListener::bind(listen)
        .map_err(|e| Error::new(format!("cannot listen on {listen}: {e}")))?;
    eprintln!("hd-server {} listening on {listen}", hd_common::VERSION);
    hd_http::serve(&listener, &app);
    Ok(())
}

/// GET /healthz on the configured listener (loopback for a wildcard).
fn healthcheck() -> Result<()> {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
    use std::time::Duration;
    let config = Config::from_env()?;
    let mut addr = config.listen;
    if addr.ip().is_unspecified() {
        addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port());
    }
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
    let mut head = [0_u8; 12];
    stream.read_exact(&mut head)?;
    if &head == b"HTTP/1.1 200" { Ok(()) } else { Err(Error::new("unhealthy")) }
}

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "serve".to_owned());
    let result = match command.as_str() {
        "serve" => serve(),
        "healthcheck" => healthcheck(),
        "version" | "--version" => {
            println!("hd-server {}", hd_common::VERSION);
            Ok(())
        }
        _ => Err(Error::new("usage: hd-server [serve|healthcheck|version]")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hd-server: {e}");
            ExitCode::FAILURE
        }
    }
}
