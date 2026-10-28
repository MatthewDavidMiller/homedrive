//! The sync API end to end over loopback HTTP.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    // Bodies of megabytes: compare without printing them on failure.
    clippy::manual_assert_eq
)]

mod common;

use std::time::{Duration, Instant};

use common::{ALICE_PW, BOB_PW, basic, bearer, request, start};
use hd_api::{BaseSpec, ChangeInfo, ChangesPage, CommitRequest, CommitResult};
use hd_chunk::Chunker;

fn register(addr: std::net::SocketAddr, user: &str, pw: &str, name: &str) -> String {
    let r = request(
        addr,
        "POST",
        "/api/v1/devices",
        &[("Authorization", &basic(user, pw))],
        format!(r#"{{"name":"{name}"}}"#).as_bytes(),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    hd_api::DeviceToken::from_json(&r.json()).unwrap().token
}

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

/// Uploads `data` to `path` the way the client does: chunk, ask what is
/// missing, upload that, commit.
fn upload(
    addr: std::net::SocketAddr,
    token: &str,
    path: &str,
    base: BaseSpec,
    data: &[u8],
) -> CommitResult {
    let auth = bearer(token);
    let mut c = Chunker::new(data).unwrap();
    let mut chunks = Vec::new();
    let mut bodies = Vec::new();
    while let Some(ch) = c.next_chunk().unwrap() {
        chunks.push((ch.id, u32::try_from(ch.data.len()).unwrap()));
        bodies.push(ch);
    }
    let summary = c.finish().unwrap();
    let ids: Vec<String> = chunks.iter().map(|(id, _)| format!("\"{}\"", id.hex())).collect();
    let r = request(
        addr,
        "POST",
        "/api/v1/chunks/missing",
        &[("Authorization", &auth)],
        format!(r#"{{"ids":[{}]}}"#, ids.join(",")).as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let missing: Vec<String> = hd_api::get_array(&r.json(), "missing")
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    for ch in &bodies {
        if missing.contains(&ch.id.hex()) {
            let r = request(
                addr,
                "PUT",
                &format!("/api/v1/chunks/{}", ch.id.hex()),
                &[("Authorization", &auth)],
                &ch.data,
            );
            assert!(r.status == 201 || r.status == 200, "{}", r.text());
        }
    }
    let commit = CommitRequest {
        path: path.into(),
        base,
        size: summary.len,
        sha256: summary.sha256,
        mtime_ms: 1,
        chunks,
    };
    let r = request(
        addr,
        "POST",
        "/api/v1/commit",
        &[("Authorization", &auth)],
        commit.to_json().as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    CommitResult::from_json(&r.json()).unwrap()
}

fn changes(addr: std::net::SocketAddr, token: &str, since: u64, wait: u64) -> ChangesPage {
    let r = request(
        addr,
        "GET",
        &format!("/api/v1/changes?since={since}&wait={wait}"),
        &[("Authorization", &bearer(token))],
        b"",
    );
    assert_eq!(r.status, 200, "{}", r.text());
    ChangesPage::from_json(&r.json()).unwrap()
}

#[test]
fn health_and_sign_in() {
    let s = start("auth");
    assert_eq!(request(s.addr, "GET", "/healthz", &[], b"").text(), "ok");
    let r = request(s.addr, "GET", "/api/v1/whoami", &[], b"");
    assert_eq!(r.status, 401);
    assert!(r.header("WWW-Authenticate").unwrap().starts_with("Basic"));
    let r = request(
        s.addr,
        "GET",
        "/api/v1/whoami",
        &[("Authorization", &basic("alice", ALICE_PW))],
        b"",
    );
    assert_eq!(r.status, 200);
    assert_eq!(hd_api::get_str(&r.json(), "user").unwrap(), "alice");
    // Tokens work as bearer, and as a Basic password for their own user.
    let token = register(s.addr, "alice", ALICE_PW, "laptop");
    let r = request(s.addr, "GET", "/api/v1/whoami", &[("Authorization", &bearer(&token))], b"");
    assert!(hd_api::get_u64(&r.json(), "device_id").is_ok());
    assert_eq!(
        request(
            s.addr,
            "GET",
            "/api/v1/whoami",
            &[("Authorization", &basic("alice", &token))],
            b""
        )
        .status,
        200
    );
    assert_eq!(
        request(s.addr, "GET", "/api/v1/whoami", &[("Authorization", &basic("bob", &token))], b"")
            .status,
        401
    );
    // A token cannot register more devices.
    assert_eq!(
        request(
            s.addr,
            "POST",
            "/api/v1/devices",
            &[("Authorization", &bearer(&token))],
            br#"{"name":"x"}"#
        )
        .status,
        403
    );
    // Revoked tokens stop working at once.
    let id = hd_api::get_u64(
        &request(s.addr, "GET", "/api/v1/whoami", &[("Authorization", &bearer(&token))], b"")
            .json(),
        "device_id",
    )
    .unwrap();
    assert_eq!(
        request(
            s.addr,
            "DELETE",
            &format!("/api/v1/devices/{id}"),
            &[("Authorization", &basic("alice", ALICE_PW))],
            b""
        )
        .status,
        200
    );
    assert_eq!(
        request(s.addr, "GET", "/api/v1/whoami", &[("Authorization", &bearer(&token))], b"").status,
        401
    );
    // Wrong passwords are throttled per address (the two failures above
    // count too), and then even the right one is refused for a while.
    for _ in 0..hd_server::auth::FAILURE_LIMIT {
        let st = request(
            s.addr,
            "GET",
            "/api/v1/whoami",
            &[("Authorization", &basic("bob", "wrong password"))],
            b"",
        )
        .status;
        assert!(st == 401 || st == 429);
    }
    assert_eq!(
        request(s.addr, "GET", "/api/v1/whoami", &[("Authorization", &basic("bob", BOB_PW))], b"")
            .status,
        429
    );
}

#[test]
fn upload_download_conflict_and_history() {
    let s = start("sync");
    let laptop = register(s.addr, "alice", ALICE_PW, "laptop");
    let phone = register(s.addr, "alice", ALICE_PW, "phone");
    let data = noise(3_500_000, 5);
    let first = upload(s.addr, &laptop, "docs/report.pdf", BaseSpec::Absent, &data);
    assert!(!first.conflict);
    // The same bytes again: nothing to upload, nothing new stored.
    let again = upload(s.addr, &phone, "docs/report.pdf", BaseSpec::Version(first.version), &data);
    assert!(again.unchanged);
    // Download, whole and in part.
    let auth = bearer(&phone);
    let r = request(
        s.addr,
        "GET",
        "/api/v1/file?path=docs/report.pdf",
        &[("Authorization", &auth)],
        b"",
    );
    assert_eq!(r.status, 200);
    assert!(r.body == data);
    assert_eq!(r.header("ETag").unwrap(), format!("\"v{}\"", first.version));
    let r = request(
        s.addr,
        "GET",
        "/api/v1/file?path=docs/report.pdf",
        &[("Authorization", &auth), ("Range", "bytes=1000000-1000099")],
        b"",
    );
    assert_eq!(r.status, 206);
    assert_eq!(r.body, data[1_000_000..1_000_100]);
    // Two devices edit from the same version: the second becomes a
    // conflict copy, and both are kept.
    let edit_a = noise(100_000, 6);
    let edit_b = noise(100_000, 7);
    let a = upload(s.addr, &phone, "docs/report.pdf", BaseSpec::Version(first.version), &edit_a);
    assert!(!a.conflict);
    let b = upload(s.addr, &laptop, "docs/report.pdf", BaseSpec::Version(first.version), &edit_b);
    assert!(b.conflict);
    assert!(b.path.starts_with("docs/report (conflict laptop "), "{}", b.path);
    let r = request(
        s.addr,
        "GET",
        &format!("/api/v1/file?path={}", hd_http::percent_encode_path(&b.path)),
        &[("Authorization", &auth)],
        b"",
    );
    assert!(r.body == edit_b);
    // History keeps the original.
    let r = request(
        s.addr,
        "GET",
        "/api/v1/versions?path=docs/report.pdf",
        &[("Authorization", &auth)],
        b"",
    );
    let versions = hd_api::get_array(&r.json(), "versions").unwrap().len();
    assert_eq!(versions, 2);
    let r = request(
        s.addr,
        "GET",
        &format!("/api/v1/file?path=docs/report.pdf&version={}", first.version),
        &[("Authorization", &auth)],
        b"",
    );
    assert!(r.body == data);
    // Bob sees none of it.
    let bob = register(s.addr, "bob", BOB_PW, "pc");
    let r = request(
        s.addr,
        "GET",
        "/api/v1/file?path=docs/report.pdf",
        &[("Authorization", &bearer(&bob))],
        b"",
    );
    assert_eq!(r.status, 404);
    assert!(changes(s.addr, &bob, 0, 0).changes.is_empty());
}

#[test]
fn bad_uploads_are_refused() {
    let s = start("bad");
    let t = register(s.addr, "alice", ALICE_PW, "laptop");
    let auth = bearer(&t);
    let wrong_id = hd_chunk::ObjectId::of(b"something else").unwrap();
    let r = request(
        s.addr,
        "PUT",
        &format!("/api/v1/chunks/{}", wrong_id.hex()),
        &[("Authorization", &auth)],
        b"these bytes",
    );
    assert_eq!(r.status, 422);
    // A commit naming a chunk the server lacks: 409 listing it.
    let id = hd_chunk::ObjectId::of(b"never uploaded").unwrap();
    let commit = CommitRequest {
        path: "x".into(),
        base: BaseSpec::Absent,
        size: 14,
        sha256: id.0,
        mtime_ms: 0,
        chunks: vec![(id, 14)],
    };
    let r = request(
        s.addr,
        "POST",
        "/api/v1/commit",
        &[("Authorization", &auth)],
        commit.to_json().as_bytes(),
    );
    assert_eq!(r.status, 409);
    assert_eq!(hd_api::get_array(&r.json(), "missing").unwrap()[0].as_str().unwrap(), id.hex());
    // A commit whose whole-file hash is wrong.
    let r = request(
        s.addr,
        "PUT",
        &format!("/api/v1/chunks/{}", id.hex()),
        &[("Authorization", &auth)],
        b"never uploaded",
    );
    assert_eq!(r.status, 201);
    let lie = CommitRequest { sha256: [0; 32], ..commit };
    let r = request(
        s.addr,
        "POST",
        "/api/v1/commit",
        &[("Authorization", &auth)],
        lie.to_json().as_bytes(),
    );
    assert_eq!(r.status, 409, "{}", r.text());
    assert!(changes(s.addr, &t, 0, 0).changes.is_empty());
    // Paths that climb out are refused.
    let r = request(
        s.addr,
        "POST",
        "/api/v1/mkdir",
        &[("Authorization", &auth)],
        br#"{"path":"../etc"}"#,
    );
    assert_eq!(r.status, 409);
    assert_eq!(
        request(s.addr, "POST", "/api/v1/commit", &[("Authorization", &auth)], b"{not json").status,
        400
    );
}

#[test]
fn the_change_feed_long_polls_and_reports_deletes() {
    let s = start("feed");
    let t = register(s.addr, "alice", ALICE_PW, "laptop");
    let start_seq = changes(s.addr, &t, 0, 0).current;
    let addr = s.addr;
    let t2 = t.clone();
    let waiter = std::thread::spawn(move || {
        let began = Instant::now();
        let page = changes(addr, &t2, start_seq, 30);
        (page, began.elapsed())
    });
    std::thread::sleep(Duration::from_millis(300));
    upload(s.addr, &t, "a.txt", BaseSpec::Absent, b"hello");
    let (page, waited) = waiter.join().unwrap();
    assert!(waited < Duration::from_secs(10), "the long poll did not wake: {waited:?}");
    assert!(
        page.changes.iter().any(|c| matches!(c, ChangeInfo::File { path, .. } if path == "a.txt"))
    );
    let cursor = page.cursor;
    let auth = bearer(&t);
    let r = request(
        s.addr,
        "POST",
        "/api/v1/trash",
        &[("Authorization", &auth)],
        br#"{"path":"a.txt"}"#,
    );
    let trash_id = hd_api::get_u64(&r.json(), "trash_id").unwrap();
    let page = changes(s.addr, &t, cursor, 0);
    assert!(matches!(&page.changes[..], [ChangeInfo::Deleted { path, .. }] if path == "a.txt"));
    let r = request(s.addr, "GET", "/api/v1/trash", &[("Authorization", &auth)], b"");
    assert_eq!(hd_api::get_array(&r.json(), "items").unwrap().len(), 1);
    let r = request(
        s.addr,
        "POST",
        "/api/v1/restore",
        &[("Authorization", &auth)],
        format!(r#"{{"trash_id":{trash_id},"to":"back/a.txt"}}"#).as_bytes(),
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let r =
        request(s.addr, "GET", "/api/v1/file?path=back/a.txt", &[("Authorization", &auth)], b"");
    assert_eq!(r.body, b"hello");
    // A cursor from the future (a store restored from an older backup)
    // gets a full listing marked as a reset.
    let page = changes(s.addr, &t, 1_000_000, 0);
    assert!(page.reset);
    assert!(page.changes.iter().any(|c| c.path() == "back/a.txt"));
    // Moves and copies.
    let r = request(
        s.addr,
        "POST",
        "/api/v1/move",
        &[("Authorization", &auth)],
        br#"{"from":"back","to":"moved"}"#,
    );
    assert_eq!(r.status, 200);
    let r = request(
        s.addr,
        "POST",
        "/api/v1/copy",
        &[("Authorization", &auth)],
        br#"{"from":"moved/a.txt","to":"copy.txt"}"#,
    );
    assert_eq!(r.status, 200);
    let r = request(s.addr, "GET", "/api/v1/file?path=copy.txt", &[("Authorization", &auth)], b"");
    assert_eq!(r.body, b"hello");
}

#[test]
fn a_directory_that_is_not_a_store_is_refused() {
    let dir = std::env::temp_dir().join(format!("hd-server-{}-unmounted", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("store")).unwrap();
    std::fs::write(
        dir.join("users.json"),
        format!(
            r#"{{"version":1,"users":[{{"name":"alice","password":"{ALICE_PW}","admin":true}}]}}"#
        ),
    )
    .unwrap();
    let err = hd_server::App::open(hd_server::config::Config::for_test(
        dir.join("store"),
        dir.join("users.json"),
    ))
    .unwrap_err();
    assert!(err.message().contains("refusing to start"), "{err}");
}
