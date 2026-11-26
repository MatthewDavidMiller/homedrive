//! Photo backup from a phone's browser (`/photos`), driven as its script
//! drives it: check, send the missing pieces, commit.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::map_unwrap_or
)]

mod common;

use std::net::SocketAddr;

use common::{ALICE_PW, BOB_PW, Reply, request};
use hd_chunk::ObjectId;
use hd_server::photos::PIECE;

fn cookie(r: &Reply, name: &str) -> String {
    r.head
        .split("\r\n")
        .filter_map(|l| l.strip_prefix("Set-Cookie: "))
        .find_map(|c| c.strip_prefix(&format!("{name}=")))
        .map(|c| c.split(';').next().unwrap().to_owned())
        .unwrap_or_else(|| panic!("no {name} cookie in {}", r.head))
}

fn attr(html: &str, name: &str) -> String {
    let key = format!("{name}=\"");
    let at = html.find(&key).unwrap_or_else(|| panic!("no {name} in {html}")) + key.len();
    html[at..at + html[at..].find('"').unwrap()].to_owned()
}

/// Signs in and opens the photos page: (session, the page's CSRF token).
fn open(addr: SocketAddr, user: &str, pw: &str) -> (String, String) {
    let form = request(addr, "GET", "/login", &[], b"");
    let nonce = cookie(&form, "hd_login");
    let token = attr(&form.text(), "name=\"csrf_token\" value");
    let body =
        format!("csrf_token={token}&username={user}&password={}", hd_http::percent_encode(pw));
    let r = request(
        addr,
        "POST",
        "/login",
        &[
            ("Cookie", &format!("hd_login={nonce}")),
            ("Content-Type", "application/x-www-form-urlencoded"),
        ],
        body.as_bytes(),
    );
    assert_eq!(r.status, 303, "{}", r.text());
    let session = cookie(&r, "hd_session");
    let page =
        request(addr, "GET", "/photos", &[("Cookie", &format!("hd_session={session}"))], b"");
    assert_eq!(page.status, 200, "{}", page.text());
    let csrf = attr(&page.text(), "data-csrf");
    (session, csrf)
}

struct Phone {
    addr: SocketAddr,
    session: String,
    csrf: String,
}

impl Phone {
    fn post(&self, target: &str, body: &[u8]) -> Reply {
        request(
            self.addr,
            "POST",
            target,
            &[
                ("Cookie", &format!("hd_session={}", self.session)),
                ("X-CSRF-Token", &self.csrf),
                ("Content-Type", "application/json"),
                // What a browser sends for the page's own requests.
                ("Origin", "https://test"),
                ("Sec-Fetch-Site", "same-origin"),
            ],
            body,
        )
    }

    fn check(&self, device: &str, files: &[&[u8]]) -> Reply {
        let list: Vec<String> = files
            .iter()
            .map(|f| format!("{{\"size\":{},\"pieces\":{}}}", f.len(), pieces_json(f)))
            .collect();
        let body = format!("{{\"device\":\"{device}\",\"files\":[{}]}}", list.join(","));
        self.post("/photos/check", body.as_bytes())
    }

    fn piece(&self, data: &[u8]) -> Reply {
        self.post(&format!("/photos/piece?id={}", ObjectId::of(data).unwrap().hex()), data)
    }

    fn commit(&self, device: &str, name: &str, file: &[u8]) -> Reply {
        let body = format!(
            "{{\"device\":\"{device}\",\"name\":\"{name}\",\"size\":{},\"mtime\":1700000000000,\"pieces\":{}}}",
            file.len(),
            pieces_json(file)
        );
        self.post("/photos/commit", body.as_bytes())
    }

    /// What the script does for one file: check, send what is missing,
    /// commit. Returns the commit's status, or "have".
    fn back_up(&self, device: &str, name: &str, file: &[u8]) -> String {
        let r = self.check(device, &[file]);
        assert_eq!(r.status, 200, "{}", r.text());
        let answer = &r.json().get("files").unwrap().as_array().unwrap()[0].clone();
        if answer.get("have").unwrap().as_bool().unwrap() {
            return "have".into();
        }
        for i in answer.get("missing").unwrap().as_array().unwrap() {
            let i = usize::try_from(i.as_u64().unwrap()).unwrap();
            let r = self.piece(pieces(file)[i]);
            assert!(r.status == 201 || r.status == 200, "{}", r.text());
        }
        let r = self.commit(device, name, file);
        assert_eq!(r.status, 200, "{}", r.text());
        r.json().get("status").unwrap().as_str().unwrap().to_owned()
    }

    fn download(&self, path: &str) -> Reply {
        request(
            self.addr,
            "GET",
            &format!("/download?path={}", hd_http::percent_encode(path)),
            &[("Cookie", &format!("hd_session={}", self.session))],
            b"",
        )
    }
}

fn pieces(file: &[u8]) -> Vec<&[u8]> {
    file.chunks(usize::try_from(PIECE).unwrap()).collect()
}

fn pieces_json(file: &[u8]) -> String {
    let ids: Vec<String> =
        pieces(file).iter().map(|p| format!("\"{}\"", ObjectId::of(p).unwrap().hex())).collect();
    format!("[{}]", ids.join(","))
}

fn missing(r: &Reply, i: usize) -> Vec<u64> {
    let files = r.json();
    let answer = &files.get("files").unwrap().as_array().unwrap()[i];
    answer
        .get("missing")
        .map(|m| m.as_array().unwrap().iter().map(|v| v.as_u64().unwrap()).collect())
        .unwrap_or_default()
}

fn have(r: &Reply, i: usize) -> bool {
    r.json().get("files").unwrap().as_array().unwrap()[i].get("have").unwrap().as_bool().unwrap()
}

#[test]
fn the_page_allows_only_its_own_script() {
    let s = common::start("photos-page");
    let (session, _) = open(s.addr, "alice", ALICE_PW);
    let page =
        request(s.addr, "GET", "/photos", &[("Cookie", &format!("hd_session={session}"))], b"");
    let policy = page.header("Content-Security-Policy").unwrap();
    assert!(policy.contains("script-src 'self'"), "{policy}");
    assert!(!policy.contains("unsafe"), "{policy}");
    assert_eq!(page.header("Referrer-Policy").as_deref(), Some("same-origin"));
    assert!(page.text().contains("/static/photos.js?v="));
    // Every other page keeps the policy that refuses scripts.
    let files =
        request(s.addr, "GET", "/files", &[("Cookie", &format!("hd_session={session}"))], b"");
    let policy = files.header("Content-Security-Policy").unwrap();
    assert!(!policy.contains("script-src"), "{policy}");
    assert!(files.text().contains("href=\"/photos\""));
    let js = request(s.addr, "GET", "/static/photos.js", &[], b"");
    assert_eq!(js.status, 200);
    assert!(js.header("Content-Type").unwrap().starts_with("text/javascript"));
    // Signed out, the page sends to sign-in and the endpoints refuse.
    assert_eq!(request(s.addr, "GET", "/photos", &[], b"").status, 303);
    assert_eq!(request(s.addr, "POST", "/photos/check", &[], b"{}").status, 403);
}

#[test]
fn photos_are_backed_up_once_and_never_replace_one_another() {
    let s = common::start("photos-backup");
    let (session, csrf) = open(s.addr, "alice", ALICE_PW);
    let phone = Phone { addr: s.addr, session, csrf };
    let a = b"a photo".to_vec();
    let b = b"another photo, same name".to_vec();
    let empty: Vec<u8> = Vec::new();

    // New: every piece is missing, and nothing is stored before a commit.
    let r = phone.check("iPhone", &[&a, &empty]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json().get("folder").unwrap().as_str(), Some("Photos/iPhone"));
    assert!(!have(&r, 0) && !have(&r, 1));
    assert_eq!(missing(&r, 0), vec![0]);
    assert!(missing(&r, 1).is_empty());

    assert_eq!(phone.back_up("iPhone", "IMG_0001.HEIC", &a), "uploaded");
    assert_eq!(phone.back_up("iPhone", "empty.txt", &empty), "uploaded");
    let got = phone.download("Photos/iPhone/IMG_0001.HEIC");
    assert_eq!(got.status, 200);
    assert_eq!(got.body, a);

    // Picked again, under any name: already in the drive.
    assert_eq!(phone.back_up("iPhone", "IMG_0001.HEIC", &a), "have");
    assert_eq!(phone.back_up("iPhone", "image.jpg", &a), "have");
    assert_eq!(phone.back_up("iPhone", "empty.txt", &empty), "have");
    // From another device's folder too: anything under Photos/ counts.
    assert_eq!(phone.back_up("iPad", "IMG_0001.HEIC", &a), "have");
    // The same size is not the same photo.
    let r = phone.check("iPhone", &[b"a phot0"]);
    assert!(!have(&r, 0));

    // A different photo with a name already used is kept beside it, and
    // the first one is not made an old version of it.
    let stored = phone.back_up("iPhone", "IMG_0001.HEIC", &b);
    assert_eq!(stored, "copy");
    assert_eq!(phone.download("Photos/iPhone/IMG_0001.HEIC").body, a);
    let versions = s.app.store.read(|st| {
        let ns = st.user("alice").unwrap();
        let files: Vec<(String, usize)> = ns
            .subtree("Photos/iPhone")
            .filter_map(|(p, e)| match &e.node {
                hd_store::model::Node::File { versions, .. } => Some((p.clone(), versions.len())),
                hd_store::model::Node::Dir => None,
            })
            .collect();
        files
    });
    assert_eq!(versions.len(), 3, "{versions:?}");
    assert!(versions.iter().all(|(_, n)| *n == 1), "{versions:?}");
    let copy = versions.iter().find(|(p, _)| p.contains("conflict")).unwrap();
    assert_eq!(phone.download(&copy.0).body, b);

    // The browser's modification time is kept.
    let mtime = s.app.store.read(|st| {
        st.user("alice")
            .unwrap()
            .get("Photos/iPhone/IMG_0001.HEIC")
            .unwrap()
            .node
            .current()
            .unwrap()
            .mtime_ms
    });
    assert_eq!(mtime, 1_700_000_000_000);

    // Another user's photos are not "already in the drive" for bob.
    let (session, csrf) = open(s.addr, "bob", BOB_PW);
    let bob = Phone { addr: s.addr, session, csrf };
    let r = bob.check("iPhone", &[&a]);
    assert!(!have(&r, 0));
}

#[test]
fn a_long_video_goes_up_in_pieces_and_resumes() {
    let s = common::start("photos-pieces");
    let (session, csrf) = open(s.addr, "alice", ALICE_PW);
    let phone = Phone { addr: s.addr, session, csrf };
    let len = usize::try_from(PIECE * 2 + 12_345).unwrap();
    let video: Vec<u8> =
        (0..len).map(|i| u8::try_from((i * 7 + i / 4093) % 251).unwrap()).collect();
    let parts = pieces(&video);
    assert_eq!(parts.len(), 3);

    let r = phone.check("iPhone", &[&video]);
    assert_eq!(missing(&r, 0), vec![0, 1, 2]);
    // The screen locks after the first piece.
    assert_eq!(phone.piece(parts[0]).status, 201);
    // A commit now names what is still missing, and stores nothing.
    let r = phone.commit("iPhone", "IMG_0002.MOV", &video);
    assert_eq!(r.status, 409, "{}", r.text());
    let still: Vec<u64> = r
        .json()
        .get("missing")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect();
    assert_eq!(still, vec![1, 2]);
    assert!(
        s.app.store.read(|st| st
            .user("alice")
            .and_then(|ns| ns.get("Photos/iPhone/IMG_0002.MOV"))
            .is_none())
    );
    // Picked again: only the rest is sent.
    let r = phone.check("iPhone", &[&video]);
    assert_eq!(missing(&r, 0), vec![1, 2]);
    assert_eq!(phone.back_up("iPhone", "IMG_0002.MOV", &video), "uploaded");
    let got = phone.download("Photos/iPhone/IMG_0002.MOV");
    assert_eq!(got.status, 200);
    assert!(got.body == video, "the video came back different");
    // And again: already in the drive, by its list of pieces.
    assert_eq!(phone.back_up("iPhone", "IMG_0002.MOV", &video), "have");

    // The same bytes but one, at the same size: not the same video.
    let mut edited = video.clone();
    edited[len - 1] ^= 1;
    let r = phone.check("iPhone", &[&edited]);
    assert!(!have(&r, 0));
    assert_eq!(missing(&r, 0), vec![2]);

    // The same video stored another way (a WebDAV PUT, cut by the
    // store's own chunker) is uploaded again rather than assumed: the
    // store keeps one copy of its chunks, and the commit adds nothing
    // when the path already holds it.
    // Pseudo-random, so the chunker finds cut points of its own (on the
    // video above it finds none and cuts at 4 MiB, as the page does).
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let other: Vec<u8> = (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect();
    let put = request(
        s.addr,
        "PUT",
        "/dav/alice/Photos/iPhone/VID.MOV",
        &[("Authorization", &common::basic("alice", ALICE_PW))],
        &other,
    );
    assert!(put.status == 201 || put.status == 204, "{}", put.text());
    assert_eq!(phone.back_up("iPhone", "VID.MOV", &other), "unchanged");
}

#[test]
fn requests_are_checked() {
    let s = common::start("photos-refused");
    let (session, csrf) = open(s.addr, "alice", ALICE_PW);
    let phone = Phone { addr: s.addr, session: session.clone(), csrf: csrf.clone() };
    let a = b"photo".to_vec();

    // No token, a wrong one, or a cross-site request.
    let no_token = request(
        s.addr,
        "POST",
        "/photos/check",
        &[("Cookie", &format!("hd_session={session}")), ("Content-Type", "application/json")],
        b"{\"device\":\"iPhone\",\"files\":[]}",
    );
    assert_eq!(no_token.status, 403);
    let wrong = Phone { addr: s.addr, session: session.clone(), csrf: "x".repeat(csrf.len()) };
    assert_eq!(wrong.check("iPhone", &[&a]).status, 403);
    let cross = request(
        s.addr,
        "POST",
        "/photos/check",
        &[
            ("Cookie", &format!("hd_session={session}")),
            ("X-CSRF-Token", &csrf),
            ("Origin", "https://evil.example"),
        ],
        b"{\"device\":\"iPhone\",\"files\":[]}",
    );
    assert_eq!(cross.status, 403);

    // Device and file names that are not one folder or file name.
    for device in ["", "a/b", "..", "con", "x:y"] {
        let r = phone.check(device, &[&a]);
        assert_eq!(r.status, 400, "{device:?}: {}", r.text());
    }
    assert_eq!(phone.piece(&a).status, 201);
    for name in ["", "a/b.jpg", "..", "."] {
        let r = phone.commit("iPhone", name, &a);
        assert_eq!(r.status, 400, "{name:?}: {}", r.text());
    }

    // Pieces that do not cover the size, or a piece whose bytes are not
    // its name.
    let r =
        phone.post("/photos/check", br#"{"device":"iPhone","files":[{"size":99,"pieces":[]}]}"#);
    assert_eq!(r.status, 400, "{}", r.text());
    let r = phone.post(&format!("/photos/piece?id={}", ObjectId::of(b"other").unwrap().hex()), &a);
    assert_eq!(r.status, 422, "{}", r.text());
    let r = phone.post("/photos/piece?id=nothex", &a);
    assert_eq!(r.status, 400, "{}", r.text());

    // Too many files in one check.
    let many: Vec<&[u8]> = vec![&a; hd_server::photos::MAX_CHECK_FILES + 1];
    assert_eq!(phone.check("iPhone", &many).status, 413);

    // Nothing above stored a file.
    assert!(s.app.store.read(|st| st.user("alice").and_then(|ns| ns.get("Photos")).is_none()));
}

/// Every file under `Photos/`: (path, current content, versions held).
fn photos_in_drive(app: &hd_server::App) -> Vec<(String, [u8; 32], usize)> {
    app.store.read(|st| {
        st.user("alice").map_or_else(Vec::new, |ns| {
            ns.subtree("Photos")
                .filter_map(|(p, e)| match &e.node {
                    hd_store::model::Node::File { versions, .. } => {
                        Some((p.clone(), versions.last().unwrap().sha256, versions.len()))
                    }
                    hd_store::model::Node::Dir => None,
                })
                .collect()
        })
    })
}

/// The usual way to use the page: back up, then delete the photos from the
/// phone to free space, and later back up what the phone has then. The
/// page never compares the phone with the drive, so nothing the phone no
/// longer has is touched: not trashed, replaced, or given a new version,
/// and still there after retention and garbage collection.
#[test]
fn photos_deleted_from_the_phone_stay_in_the_drive() {
    let s = common::start("photos-phone-deletes");
    let (session, csrf) = open(s.addr, "alice", ALICE_PW);
    let phone = Phone { addr: s.addr, session, csrf };
    let len = usize::try_from(PIECE + 99).unwrap();
    let video: Vec<u8> = (0..len).map(|i| u8::try_from(i % 241).unwrap()).collect();
    let first: Vec<(&str, Vec<u8>)> = vec![
        ("IMG_0001.HEIC", b"first photo".to_vec()),
        ("IMG_0002.HEIC", b"second photo".to_vec()),
        ("IMG_0003.HEIC", b"third photo".to_vec()),
        ("IMG_0004.MOV", video),
    ];
    for (name, data) in &first {
        assert_eq!(phone.back_up("iPhone", name, data), "uploaded");
    }
    let before = photos_in_drive(&s.app);
    assert_eq!(before.len(), 4);

    // The phone deleted all but the third, then took new photos, one of
    // them reusing a deleted photo's name (phones count up again).
    let reused = b"a new photo with an old name".to_vec();
    let later: Vec<(&str, Vec<u8>)> = vec![
        ("IMG_0003.HEIC", b"third photo".to_vec()),
        ("IMG_0005.HEIC", b"fifth photo".to_vec()),
        ("IMG_0001.HEIC", reused.clone()),
    ];
    let got: Vec<String> =
        later.iter().map(|(name, data)| phone.back_up("iPhone", name, data)).collect();
    assert_eq!(got, ["have", "uploaded", "copy"]);
    // Picking nothing at all asks about nothing.
    let r = phone.check("iPhone", &[]);
    assert_eq!(r.status, 200, "{}", r.text());

    // What was there before is there as it was, with no new version.
    let after = photos_in_drive(&s.app);
    for b in &before {
        assert!(after.contains(b), "{} changed or went: {after:?}", b.0);
    }
    assert_eq!(after.len(), 6, "{after:?}");
    let trash = s.app.store.read(|st| st.user("alice").map_or(0, |ns| ns.trash.len()));
    assert_eq!(trash, 0);

    // Retention and garbage collection, with no grace at all.
    let now = hd_common::timefmt::unix_ms();
    s.app.store.apply_retention(now, &hd_store::retention::Policy::default()).unwrap();
    let gc = hd_store::gc::GcOptions { grace_ms: 0, hold_ms: 0, dry_run: false };
    s.app.store.collect_garbage(now, &gc).unwrap();
    assert_eq!(photos_in_drive(&s.app), after);
    for (name, data) in &first {
        let r = phone.download(&format!("Photos/iPhone/{name}"));
        assert_eq!(r.status, 200, "{name}");
        assert!(r.body == *data, "{name} came back different");
    }
}
