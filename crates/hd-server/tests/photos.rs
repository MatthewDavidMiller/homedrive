//! Photo backup from an iPhone Shortcut: the token `/photos` makes, the two
//! endpoints it may use, and everything else it may not.

#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::map_unwrap_or,
    clippy::format_collect,
    clippy::cast_possible_truncation
)]

mod common;

use std::net::SocketAddr;

use common::{ALICE_PW, Reply, basic, bearer, request};

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha(data: &[u8]) -> String {
    hex(&hd_crypto::sha256(data).unwrap())
}

/// A signed-in browser.
struct Browser {
    addr: SocketAddr,
    session: String,
}

impl Browser {
    fn sign_in(addr: SocketAddr) -> Self {
        let form = request(addr, "GET", "/login", &[], b"");
        let nonce = cookie(&form, "hd_login");
        let token = attr(&form.text(), "name=\"csrf_token\" value");
        let body = format!(
            "csrf_token={token}&username=alice&password={}",
            hd_http::percent_encode(ALICE_PW)
        );
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
        Self { addr, session: cookie(&r, "hd_session") }
    }

    fn get(&self, path: &str) -> Reply {
        request(self.addr, "GET", path, &[("Cookie", &format!("hd_session={}", self.session))], b"")
    }

    /// Submits the photos page's form: the page's answer.
    fn make_token(&self, name: &str) -> Reply {
        let page = self.get("/photos");
        assert_eq!(page.status, 200, "{}", page.text());
        let csrf = attr(&page.text(), "name=\"csrf_token\" value");
        let body = format!("csrf_token={csrf}&name={}", hd_http::percent_encode(name));
        request(
            self.addr,
            "POST",
            "/photos",
            &[
                ("Cookie", &format!("hd_session={}", self.session)),
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Origin", "http://test"),
            ],
            body.as_bytes(),
        )
    }

    /// A phone's token, made on the photos page.
    fn phone(&self, name: &str) -> Phone {
        let r = self.make_token(name);
        assert_eq!(r.status, 200, "{}", r.text());
        let text = r.text();
        let at = text.find("<code>hd1_").unwrap_or_else(|| panic!("no token in {text}")) + 6;
        let token = text[at..at + text[at..].find('<').unwrap()].to_owned();
        Phone { addr: self.addr, token }
    }
}

/// What the Shortcut does, request by request.
struct Phone {
    addr: SocketAddr,
    token: String,
}

impl Phone {
    fn have(&self, data: &[u8]) -> bool {
        let r = request(
            self.addr,
            "GET",
            &format!("/api/v1/photos/have?sha256={}", sha(data)),
            &[("Authorization", &bearer(&self.token))],
            b"",
        );
        assert_eq!(r.status, 200, "{}", r.text());
        r.json().get("have").and_then(hd_common::json::Value::as_bool).unwrap()
    }

    fn upload(&self, name: &str, data: &[u8], extra: &[(&str, &str)]) -> Reply {
        let auth = bearer(&self.token);
        let hash = sha(data);
        let mut headers = vec![
            ("Authorization", auth.as_str()),
            ("X-File-Name", name),
            ("X-SHA256", hash.as_str()),
            ("Content-Type", "image/heic"),
        ];
        for (k, v) in extra {
            headers.retain(|(h, _)| !h.eq_ignore_ascii_case(k));
            headers.push((k, v));
        }
        request(self.addr, "POST", "/api/v1/photos/upload", &headers, data)
    }

    /// One photo as the Shortcut handles it: "have", or the upload's status.
    fn back_up(&self, name: &str, data: &[u8]) -> String {
        if self.have(data) {
            return "have".into();
        }
        let r = self.upload(name, data, &[]);
        assert_eq!(r.status, 200, "{name}: {}", r.text());
        r.json().get("status").and_then(hd_common::json::Value::as_str).unwrap().to_owned()
    }
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

fn download(addr: SocketAddr, path: &str) -> Reply {
    request(
        addr,
        "GET",
        &format!(
            "/dav/alice/{}",
            path.split('/').map(hd_http::percent_encode).collect::<Vec<_>>().join("/")
        ),
        &[("Authorization", &basic("alice", ALICE_PW))],
        b"",
    )
}

#[test]
fn the_page_makes_a_photo_token_and_explains_the_shortcut() {
    let s = common::start("photos-page");
    let web = Browser::sign_in(s.addr);
    let page = web.get("/photos");
    assert_eq!(page.status, 200);
    let text = page.text();
    // The Shortcut's addresses, as the browser reached the server.
    assert!(text.contains("http://test/api/v1/photos/have?sha256="), "{text}");
    assert!(text.contains("http://test/api/v1/photos/upload"), "{text}");
    // No script, and the default policy, which allows none.
    assert!(!text.contains("<script"));
    let policy = page.header("Content-Security-Policy").unwrap();
    assert!(policy.contains("default-src 'none'") && !policy.contains("script-src"), "{policy}");
    assert_eq!(request(s.addr, "GET", "/static/photos.js", &[], b"").status, 404);

    let made = web.make_token("iPhone");
    assert_eq!(made.status, 200);
    assert!(made.text().contains("<code>hd1_"), "{}", made.text());
    let devices = web.get("/devices").text();
    assert!(devices.contains("iPhone <span class=\"badge\">photo backup only</span>"), "{devices}");

    // A second token with the same name would share the folder: refused,
    // as are names that are not one folder name.
    for bad in ["iPhone", "a/b", "..", " ", "con"] {
        let r = web.make_token(bad);
        assert_eq!(r.status, 200);
        assert!(!r.text().contains("<code>hd1_"), "{bad:?} made a token");
        assert!(r.text().contains("notice-danger") || r.text().contains("danger"), "{bad:?}");
    }
    let count = s.app.store.read(|st| st.user("alice").unwrap().devices.len());
    assert_eq!(count, 1);

    // The form is a form like any other: no session, no token, or another
    // site, and nothing is made.
    let r = request(s.addr, "POST", "/photos", &[], b"name=iPad");
    assert_eq!(r.status, 403);
    let r = request(
        s.addr,
        "POST",
        "/photos",
        &[
            ("Cookie", &format!("hd_session={}", web.session)),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "https://elsewhere.example"),
        ],
        b"csrf_token=x&name=iPad",
    );
    assert_eq!(r.status, 403);
    let count = s.app.store.read(|st| st.user("alice").unwrap().devices.len());
    assert_eq!(count, 1);
}

#[test]
fn photos_are_added_once_and_never_replace_one_another() {
    let s = common::start("photos-add");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");

    let photo = b"a HEIC photo".to_vec();
    assert_eq!(phone.back_up("IMG_0001.HEIC", &photo), "uploaded");
    // Run again: the hash says it is there, and nothing is sent.
    assert_eq!(phone.back_up("IMG_0001.HEIC", &photo), "have");
    // Sent anyway (a run cut off before it saved its date): nothing added.
    let r = phone.upload("IMG_0001.HEIC", &photo, &[]);
    assert_eq!(r.status, 200);
    assert_eq!(r.json().get("status").and_then(hd_common::json::Value::as_str), Some("unchanged"));
    // A different photo with a reused name is kept beside the first.
    let other = b"a different photo, same name".to_vec();
    let r = phone.upload("IMG_0001.HEIC", &other, &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    let j = r.json();
    assert_eq!(j.get("status").and_then(hd_common::json::Value::as_str), Some("copy"));
    let copy = j.get("path").and_then(hd_common::json::Value::as_str).unwrap().to_owned();
    assert!(copy.starts_with("Photos/iPhone/") && copy != "Photos/iPhone/IMG_0001.HEIC");
    assert_eq!(download(s.addr, "Photos/iPhone/IMG_0001.HEIC").body, photo);
    assert_eq!(download(s.addr, &copy).body, other);

    // The time the photo was taken becomes the file's time.
    let r = phone.upload(
        "IMG_0002.HEIC",
        b"taken in the morning",
        &[("X-Taken", "2026-11-27T10:15:30-05:00")],
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let mtime = s.app.store.read(|st| {
        st.user("alice")
            .unwrap()
            .get("Photos/iPhone/IMG_0002.HEIC")
            .unwrap()
            .node
            .current()
            .unwrap()
            .mtime_ms
    });
    assert_eq!(mtime, 1_795_792_530_000);

    // Bytes that are not what the phone hashed are kept (nothing here
    // deletes) but reported, so the Shortcut stops and says so.
    let r = phone.upload("IMG_0003.HEIC", b"what arrived", &[("X-SHA256", &sha(b"what was sent"))]);
    assert_eq!(r.status, 422, "{}", r.text());
    assert_eq!(r.json().get("status").and_then(hd_common::json::Value::as_str), Some("mismatch"));

    // A second phone has its own folder, and what any phone backed up
    // counts as there.
    let ipad = web.phone("iPad");
    assert_eq!(ipad.back_up("IMG_0001.HEIC", &photo), "have");
    assert_eq!(ipad.back_up("IMG_9000.HEIC", b"from the iPad"), "uploaded");
    let paths: Vec<String> = photos_in_drive(&s.app).into_iter().map(|(p, ..)| p).collect();
    assert!(paths.contains(&"Photos/iPad/IMG_9000.HEIC".to_owned()), "{paths:?}");
    // Every file has exactly one version: nothing was ever replaced.
    assert!(photos_in_drive(&s.app).iter().all(|(_, _, n)| *n == 1));
    // A long video in one request.
    let video: Vec<u8> =
        (0..9_000_000_u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    assert_eq!(phone.back_up("IMG_0004.MOV", &video), "uploaded");
    assert_eq!(sha(&download(s.addr, "Photos/iPhone/IMG_0004.MOV").body), sha(&video));
}

/// The token can add photos to its own folder, and do nothing else
/// anywhere: not read, list, move, trash, register devices, or sign in to
/// the web pages.
#[test]
fn a_photo_token_can_only_add_photos() {
    let s = common::start("photos-scope");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    assert_eq!(phone.back_up("IMG_0001.HEIC", b"photo"), "uploaded");
    let auth = bearer(&phone.token);
    let as_basic = basic("alice", &phone.token);
    let refused: &[(&str, &str, &[u8])] = &[
        ("GET", "/api/v1/whoami", b""),
        ("GET", "/api/v1/tree?path=", b""),
        ("GET", "/api/v1/changes?since=0", b""),
        ("GET", "/api/v1/devices", b""),
        ("POST", "/api/v1/devices", br#"{"name":"laptop"}"#),
        ("POST", "/api/v1/trash", br#"{"path":"Photos/iPhone/IMG_0001.HEIC"}"#),
        ("POST", "/api/v1/move", br#"{"from":"Photos","to":"Elsewhere"}"#),
        ("POST", "/api/v1/mkdir", br#"{"path":"x"}"#),
        ("GET", "/api/v1/versions?path=Photos/iPhone/IMG_0001.HEIC", b""),
        ("GET", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b""),
        ("PROPFIND", "/dav/alice/", b""),
        ("PUT", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b"replaced"),
        ("DELETE", "/dav/alice/Photos/iPhone/IMG_0001.HEIC", b""),
        ("MOVE", "/dav/alice/Photos", b""),
    ];
    for (method, target, body) in refused {
        for a in [&auth, &as_basic] {
            let r = request(s.addr, method, target, &[("Authorization", a)], body);
            assert_eq!(r.status, 403, "{method} {target}: {} {}", r.status, r.text());
        }
    }
    // The web pages take a session, which a token never gets.
    let r = request(s.addr, "GET", "/files", &[("Authorization", &auth)], b"");
    assert!(matches!(r.status, 302 | 303), "{}", r.status);
    // Nothing changed.
    assert_eq!(photos_in_drive(&s.app).len(), 1);
    assert_eq!(download(s.addr, "Photos/iPhone/IMG_0001.HEIC").body, b"photo");
    assert_eq!(s.app.store.read(|st| st.user("alice").unwrap().devices.len()), 1);

    // The endpoints take only a photo token: not the password, and not a
    // full device token.
    let have = format!("/api/v1/photos/have?sha256={}", sha(b"photo"));
    let r = request(s.addr, "GET", &have, &[("Authorization", &basic("alice", ALICE_PW))], b"");
    assert_eq!(r.status, 403);
    let full = request(
        s.addr,
        "POST",
        "/api/v1/devices",
        &[("Authorization", &basic("alice", ALICE_PW))],
        br#"{"name":"laptop"}"#,
    );
    assert_eq!(full.status, 201, "{}", full.text());
    let full =
        full.json().get("token").and_then(hd_common::json::Value::as_str).unwrap().to_owned();
    let r = request(s.addr, "GET", &have, &[("Authorization", &bearer(&full))], b"");
    assert_eq!(r.status, 403);
    // A revoked token is refused outright.
    let id = s.app.store.read(|st| {
        st.user("alice").unwrap().devices.values().find(|d| d.name == "iPhone").unwrap().id
    });
    let page = web.get("/devices");
    let csrf = attr(&page.text(), "name=\"csrf_token\" value");
    let r = request(
        s.addr,
        "POST",
        "/devices/revoke",
        &[
            ("Cookie", &format!("hd_session={}", web.session)),
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Origin", "http://test"),
        ],
        format!("csrf_token={csrf}&id={id}").as_bytes(),
    );
    assert_eq!(r.status, 200);
    let r = request(s.addr, "GET", &have, &[("Authorization", &auth)], b"");
    assert_eq!(r.status, 401);
}

#[test]
fn requests_are_checked() {
    let s = common::start("photos-checks");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    let auth = bearer(&phone.token);
    for (name, why) in
        [("", "no name"), ("a/b.HEIC", "a path"), ("..", "a parent"), ("x\u{1}", "control")]
    {
        let r = phone.upload(name, b"photo", &[]);
        assert_eq!(r.status, 400, "{why}: {}", r.text());
    }
    let r = phone.upload("IMG_0001.HEIC", b"photo", &[("X-SHA256", "not a hash")]);
    assert_eq!(r.status, 400);
    for target in ["/api/v1/photos/have", "/api/v1/photos/have?sha256=12"] {
        let r = request(s.addr, "GET", target, &[("Authorization", &auth)], b"");
        assert_eq!(r.status, 400, "{target}");
    }
    let r = request(s.addr, "GET", "/api/v1/photos/upload", &[("Authorization", &auth)], b"");
    assert_eq!(r.status, 405);
    let r = request(s.addr, "POST", "/api/v1/photos/other", &[("Authorization", &auth)], b"");
    assert_eq!(r.status, 404);
    let r = request(s.addr, "GET", "/api/v1/photos/have?sha256=00", &[], b"");
    assert_eq!(r.status, 401);
    // A time the photo cannot have is replaced by the upload's.
    let r = phone.upload("IMG_0002.HEIC", b"later", &[("X-Taken", "2999-01-01T00:00:00Z")]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(photos_in_drive(&s.app).len(), 1);
}

/// The usual way to use it: back up, then delete the photos from the
/// phone to free space, and later back up what the phone has then. The
/// Shortcut never compares the phone with the drive, so nothing the phone
/// no longer has is touched: not trashed, replaced, or given a new version,
/// and still there after retention and garbage collection.
#[test]
fn photos_deleted_from_the_phone_stay_in_the_drive() {
    let s = common::start("photos-phone-deletes");
    let web = Browser::sign_in(s.addr);
    let phone = web.phone("iPhone");
    let video: Vec<u8> = (0..5_000_000_u32).map(|i| (i % 241) as u8).collect();
    let first: Vec<(&str, Vec<u8>)> = vec![
        ("IMG_0001.HEIC", b"first photo".to_vec()),
        ("IMG_0002.HEIC", b"second photo".to_vec()),
        ("IMG_0003.HEIC", b"third photo".to_vec()),
        ("IMG_0004.MOV", video),
    ];
    for (name, data) in &first {
        assert_eq!(phone.back_up(name, data), "uploaded");
    }
    let before = photos_in_drive(&s.app);
    assert_eq!(before.len(), 4);

    // The phone deleted all but the third, then took new photos, one of
    // them reusing a deleted photo's name (phones count up again).
    let later: Vec<(&str, Vec<u8>)> = vec![
        ("IMG_0003.HEIC", b"third photo".to_vec()),
        ("IMG_0005.HEIC", b"fifth photo".to_vec()),
        ("IMG_0001.HEIC", b"a new photo with an old name".to_vec()),
    ];
    let got: Vec<String> = later.iter().map(|(name, data)| phone.back_up(name, data)).collect();
    assert_eq!(got, ["have", "uploaded", "copy"]);

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
        let r = download(s.addr, &format!("Photos/iPhone/{name}"));
        assert_eq!(r.status, 200, "{name}");
        assert!(r.body == *data, "{name} came back different");
    }
}
