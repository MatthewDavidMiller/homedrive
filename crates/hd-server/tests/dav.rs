//! WebDAV semantics that rclone does not exercise.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

mod common;

use std::io::{Read, Write};

use common::{ALICE_PW, BOB_PW, basic, request, start};

#[test]
fn webdav_semantics() {
    let s = start("dav");
    let a = basic("alice", ALICE_PW);
    let auth = [("Authorization", a.as_str())];
    let with = |extra: &[(&'static str, &'static str)]| {
        let mut h: Vec<(&str, &str)> = vec![("Authorization", a.as_str())];
        h.extend_from_slice(extra);
        h
    };
    // Another user's drive is off limits.
    assert_eq!(
        request(
            s.addr,
            "PROPFIND",
            "/dav/bob/",
            &[("Authorization", &basic("alice", ALICE_PW)), ("Depth", "0")],
            b""
        )
        .status,
        403
    );
    assert_eq!(
        request(
            s.addr,
            "PROPFIND",
            "/dav/bob/",
            &[("Authorization", &basic("bob", BOB_PW)), ("Depth", "0")],
            b""
        )
        .status,
        207
    );
    let r = request(s.addr, "OPTIONS", "/dav/alice/", &auth, b"");
    assert_eq!(r.header("DAV").as_deref(), Some("1, 2"));
    // MKCOL needs a parent, and refuses what exists.
    assert_eq!(request(s.addr, "MKCOL", "/dav/alice/a/b", &auth, b"").status, 409);
    assert_eq!(request(s.addr, "MKCOL", "/dav/alice/a", &auth, b"").status, 201);
    assert_eq!(request(s.addr, "MKCOL", "/dav/alice/a", &auth, b"").status, 405);
    // PUT, with a client modification time.
    let r = request(
        s.addr,
        "PUT",
        "/dav/alice/a/f.txt",
        &with(&[("X-OC-Mtime", "1700000000")]),
        b"one",
    );
    assert_eq!(r.status, 201);
    assert_eq!(r.header("X-OC-MTime").as_deref(), Some("accepted"));
    let etag = r.header("ETag").unwrap();
    let r = request(s.addr, "PROPFIND", "/dav/alice/a/f.txt", &with(&[("Depth", "0")]), b"");
    assert_eq!(r.status, 207);
    let xml = r.text();
    assert!(xml.contains("<d:getcontentlength>3</d:getcontentlength>"), "{xml}");
    assert!(xml.contains("Tue, 14 Nov 2023 22:13:20 GMT"), "{xml}");
    assert!(xml.contains(&format!("<d:getetag>{etag}</d:getetag>")));
    // Conditional PUTs: a stale If-Match is refused, a current one works.
    let r =
        request(s.addr, "PUT", "/dav/alice/a/f.txt", &with(&[("If-Match", "\"v999999\"")]), b"x");
    assert_eq!(r.status, 412);
    let mut h = with(&[]);
    h.push(("If-Match", etag.as_str()));
    assert_eq!(request(s.addr, "PUT", "/dav/alice/a/f.txt", &h, b"two").status, 204);
    assert_eq!(
        request(s.addr, "PUT", "/dav/alice/a/f.txt", &with(&[("If-None-Match", "*")]), b"three")
            .status,
        412
    );
    // A chunked PUT.
    let mut sock = std::net::TcpStream::connect(s.addr).unwrap();
    write!(sock, "PUT /dav/alice/chunked.bin HTTP/1.1\r\nAuthorization: {a}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n").unwrap();
    let mut out = String::new();
    sock.read_to_string(&mut out).unwrap();
    assert!(out.starts_with("HTTP/1.1 201"), "{out}");
    assert_eq!(request(s.addr, "GET", "/dav/alice/chunked.bin", &auth, b"").body, b"hello world");
    // Depth 1 lists children; infinity is refused.
    let r = request(s.addr, "PROPFIND", "/dav/alice/", &with(&[("Depth", "1")]), b"");
    let xml = r.text();
    assert!(
        xml.contains("<d:href>/dav/alice/a/</d:href>") && xml.contains("/dav/alice/chunked.bin<"),
        "{xml}"
    );
    assert_eq!(
        request(s.addr, "PROPFIND", "/dav/alice/", &with(&[("Depth", "infinity")]), b"").status,
        403
    );
    // MOVE with Overwrite: F refuses; T trashes what it replaces.
    assert_eq!(request(s.addr, "PUT", "/dav/alice/other.txt", &auth, b"other").status, 201);
    let dest = format!("http://{}/dav/alice/other.txt", s.addr);
    let r = request(
        s.addr,
        "MOVE",
        "/dav/alice/a/f.txt",
        &with(&[("Overwrite", "F")])
            .into_iter()
            .chain([("Destination", dest.as_str())])
            .collect::<Vec<_>>(),
        b"",
    );
    assert_eq!(r.status, 412);
    let r = request(
        s.addr,
        "MOVE",
        "/dav/alice/a/f.txt",
        &with(&[]).into_iter().chain([("Destination", dest.as_str())]).collect::<Vec<_>>(),
        b"",
    );
    assert_eq!(r.status, 204);
    assert_eq!(request(s.addr, "GET", "/dav/alice/other.txt", &auth, b"").body, b"two");
    let in_trash = s
        .app
        .store
        .read(|st| st.user("alice").unwrap().trash.values().any(|t| t.path == "other.txt"));
    assert!(in_trash, "the replaced file went to the trash");
    // COPY of a directory tree; destinations outside the drive are refused.
    assert_eq!(request(s.addr, "PUT", "/dav/alice/a/x/y.txt", &auth, b"y").status, 201);
    let r =
        request(s.addr, "COPY", "/dav/alice/a", &with(&[("Destination", "/dav/alice/a2")]), b"");
    assert_eq!(r.status, 201);
    assert_eq!(request(s.addr, "GET", "/dav/alice/a2/x/y.txt", &auth, b"").body, b"y");
    assert_eq!(
        request(s.addr, "COPY", "/dav/alice/a", &with(&[("Destination", "/dav/bob/a")]), b"")
            .status,
        502
    );
    assert_eq!(
        request(
            s.addr,
            "MOVE",
            "/dav/alice/a",
            &with(&[("Destination", "/dav/alice/a/inside")]),
            b""
        )
        .status,
        409
    );
    // DELETE goes to the trash; the root cannot be deleted.
    assert_eq!(request(s.addr, "DELETE", "/dav/alice/a2", &auth, b"").status, 204);
    assert_eq!(request(s.addr, "DELETE", "/dav/alice/", &auth, b"").status, 403);
    assert_eq!(request(s.addr, "GET", "/dav/alice/a2/x/y.txt", &auth, b"").status, 404);
    // Locks are granted (and not enforced).
    let r = request(s.addr, "LOCK", "/dav/alice/other.txt", &auth, b"<lockinfo/>");
    assert_eq!(r.status, 200);
    assert!(r.header("Lock-Token").unwrap().starts_with("<opaquelocktoken:"));
    assert_eq!(request(s.addr, "UNLOCK", "/dav/alice/other.txt", &auth, b"").status, 204);
    // Bad paths.
    assert_eq!(request(s.addr, "GET", "/dav/alice/%2e%2e/x", &auth, b"").status, 400);
    assert_eq!(request(s.addr, "GET", "/dav/alice/%ff", &auth, b"").status, 400);
    assert!(s.app.store.fsck(true).unwrap().is_clean());
}

/// An upload cut off part way (a dropped phone connection, a killed
/// client) must leave no version behind, and must not disturb the file
/// already there, whichever way the body was framed.
#[test]
fn an_interrupted_upload_changes_nothing() {
    let s = start("dav-interrupted");
    let a = basic("alice", ALICE_PW);
    let r = request(s.addr, "PUT", "/dav/alice/f.bin", &[("Authorization", &a)], b"original");
    assert_eq!(r.status, 201, "{}", r.text());
    let versions = || {
        s.app.store.read(|st| match &st.user("alice").unwrap().get("f.bin").unwrap().node {
            hd_store::model::Node::File { versions, .. } => versions.len(),
            hd_store::model::Node::Dir => 0,
        })
    };
    let big = vec![b'z'; 3 * 1024 * 1024];
    for (framing, send) in [
        // Declares 3 MiB, sends 2 MiB, then hangs up.
        ("length", format!("Content-Length: {}\r\n\r\n", big.len()).into_bytes()),
        // A chunked body that stops without its final zero-length chunk.
        ("chunked", b"Transfer-Encoding: chunked\r\n\r\n".to_vec()),
    ] {
        for target in ["/dav/alice/f.bin", "/dav/alice/new.bin"] {
            let mut c = std::net::TcpStream::connect(s.addr).unwrap();
            let head = format!(
                "PUT {target} HTTP/1.1\r\nHost: test\r\nAuthorization: {a}\r\nConnection: close\r\n"
            );
            c.write_all(head.as_bytes()).unwrap();
            c.write_all(&send).unwrap();
            let part = &big[..2 * 1024 * 1024];
            if framing == "chunked" {
                c.write_all(format!("{:x}\r\n", part.len()).as_bytes()).unwrap();
                c.write_all(part).unwrap();
                c.write_all(b"\r\n").unwrap();
            } else {
                c.write_all(part).unwrap();
            }
            c.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = Vec::new();
            let _ = c.read_to_end(&mut reply);
            let reply = String::from_utf8_lossy(&reply);
            assert!(!reply.starts_with("HTTP/1.1 2"), "{framing} {target}: {reply}");
        }
        let r = request(s.addr, "GET", "/dav/alice/f.bin", &[("Authorization", &a)], b"");
        assert_eq!(r.body, b"original", "{framing}");
        assert_eq!(versions(), 1, "{framing}");
        let r = request(s.addr, "GET", "/dav/alice/new.bin", &[("Authorization", &a)], b"");
        assert_eq!(r.status, 404, "{framing}");
    }
    assert!(s.app.store.fsck(true).unwrap().is_clean());
}
