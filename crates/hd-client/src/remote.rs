//! The sync API, as the client calls it.

use std::fmt::Write as _;
use std::io::Write;

use hd_api::{ChangesPage, CommitRequest, CommitResult, J, s};
use hd_chunk::ObjectId;
use hd_common::{Error, Result};

use crate::http::{Endpoint, Http, Reply};

/// What a commit came back with.
#[derive(Debug)]
pub enum CommitOutcome {
    Done(CommitResult),
    /// Chunks the server does not have (collected since they were asked
    /// about): upload them and commit again.
    Missing(Vec<ObjectId>),
}

#[derive(Debug)]
pub struct Remote {
    http: Http,
}

fn fail(r: &Reply, what: &str) -> Error {
    Error::new(format!("{what}: {}", r.error_text()))
}

fn json(r: &Reply) -> Result<hd_common::json::Value> {
    hd_api::parse(&r.body)
}

impl Remote {
    pub fn new(server: &str, ca_file: Option<&std::path::Path>, token: &str) -> Result<Self> {
        let endpoint = Endpoint::parse(server)?;
        Ok(Self { http: Http::new(endpoint, ca_file, format!("Bearer {token}"))? })
    }

    /// Registers a device with the account password and returns its token.
    pub fn register(
        server: &str,
        ca_file: Option<&std::path::Path>,
        user: &str,
        password: &str,
        name: &str,
    ) -> Result<hd_api::DeviceToken> {
        let basic =
            format!("Basic {}", hd_common::base64::encode(format!("{user}:{password}").as_bytes()));
        let mut http = Http::new(Endpoint::parse(server)?, ca_file, basic)?;
        let body = J::O(vec![("name", s(name))]).render();
        let r =
            http.request("POST", "/api/v1/devices", Some("application/json"), body.as_bytes())?;
        if r.status != 201 {
            return Err(fail(&r, "registering this device failed"));
        }
        hd_api::DeviceToken::from_json(&json(&r)?)
    }

    pub fn whoami(&mut self) -> Result<String> {
        let r = self.http.request("GET", "/api/v1/whoami", None, b"")?;
        if r.status != 200 {
            return Err(fail(&r, "signing in failed"));
        }
        hd_api::get_str(&json(&r)?, "user")
    }

    /// What the server says is wrong with it; empty when healthy.
    pub fn server_problems(&mut self) -> Result<Vec<String>> {
        let r = self.http.request("GET", "/api/v1/status", None, b"")?;
        if r.status != 200 {
            return Err(fail(&r, "asking the server's status failed"));
        }
        hd_api::get_array(&json(&r)?, "problems")?
            .iter()
            .map(|p| p.as_str().map(str::to_owned).ok_or_else(|| Error::new("bad status")))
            .collect()
    }

    pub fn changes(&mut self, since: u64, wait_s: u64) -> Result<ChangesPage> {
        let r = self.http.request(
            "GET",
            &format!("/api/v1/changes?since={since}&wait={wait_s}"),
            None,
            b"",
        )?;
        if r.status != 200 {
            return Err(fail(&r, "reading changes failed"));
        }
        ChangesPage::from_json(&json(&r)?)
    }

    /// Which of `ids` the server lacks.
    pub fn missing(&mut self, ids: &[ObjectId]) -> Result<Vec<ObjectId>> {
        let mut out = Vec::new();
        for batch in ids.chunks(hd_api::MAX_MISSING_QUERY) {
            let body =
                J::O(vec![("ids", J::A(batch.iter().map(|id| s(id.hex())).collect()))]).render();
            let r = self.http.request(
                "POST",
                "/api/v1/chunks/missing",
                Some("application/json"),
                body.as_bytes(),
            )?;
            if r.status != 200 {
                return Err(fail(&r, "asking for missing chunks failed"));
            }
            for v in hd_api::get_array(&json(&r)?, "missing")? {
                out.push(hd_api::parse_id(v.as_str().unwrap_or(""))?);
            }
        }
        Ok(out)
    }

    pub fn put_chunk(&mut self, id: &ObjectId, data: &[u8]) -> Result<()> {
        let r = self.http.request(
            "PUT",
            &format!("/api/v1/chunks/{}", id.hex()),
            Some("application/octet-stream"),
            data,
        )?;
        if r.status == 200 || r.status == 201 {
            Ok(())
        } else {
            Err(fail(&r, "uploading a chunk failed"))
        }
    }

    pub fn commit(&mut self, req: &CommitRequest) -> Result<CommitOutcome> {
        let r = self.http.request(
            "POST",
            "/api/v1/commit",
            Some("application/json"),
            req.to_json().as_bytes(),
        )?;
        match r.status {
            200 => Ok(CommitOutcome::Done(CommitResult::from_json(&json(&r)?)?)),
            409 => {
                let v = json(&r)?;
                match v.get("missing").and_then(|m| m.as_array()) {
                    Some(list) => Ok(CommitOutcome::Missing(
                        list.iter()
                            .map(|x| hd_api::parse_id(x.as_str().unwrap_or("")))
                            .collect::<Result<_>>()?,
                    )),
                    None => Err(fail(&r, "the commit was refused")),
                }
            }
            _ => Err(fail(&r, "the commit failed")),
        }
    }

    /// Streams a version into `sink`. `Ok(false)` if that version no longer
    /// exists (the next change feed explains why).
    pub fn download(&mut self, path: &str, version: u64, sink: &mut dyn Write) -> Result<bool> {
        let target = format!("/api/v1/file?path={}&version={version}", hd_api_path(path));
        let r = self.http.download(&target, sink)?;
        match r.status {
            200 => Ok(true),
            404 => Ok(false),
            _ => Err(fail(&r, "downloading failed")),
        }
    }

    fn post(&mut self, call: &str, body: &J) -> Result<Reply> {
        self.http.request(
            "POST",
            &format!("/api/v1/{call}"),
            Some("application/json"),
            body.render().as_bytes(),
        )
    }

    pub fn mkdir(&mut self, path: &str) -> Result<()> {
        let r = self.post("mkdir", &J::O(vec![("path", s(path))]))?;
        if r.status == 200 { Ok(()) } else { Err(fail(&r, "creating a folder failed")) }
    }

    /// Moves `path` to the trash, but only if it is still what the client
    /// believes it is: the file at `expect`'s version, or an empty folder.
    pub fn trash(&mut self, path: &str, expect: Expect) -> Result<Trashed> {
        let mut body = vec![("path", s(path))];
        match expect {
            Expect::Version(v) => body.push(("version", J::U(v))),
            Expect::EmptyFolder => body.push(("if_empty", J::Bool(true))),
        }
        let r = self.post("trash", &J::O(body))?;
        match r.status {
            200 => Ok(Trashed::Done),
            409 if r.error_text().contains("does not exist") => Ok(Trashed::Gone),
            412 => Ok(Trashed::Changed),
            _ => Err(fail(&r, "deleting failed")),
        }
    }
}

/// What a trash request requires of the path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// A file whose current version is this one.
    Version(u64),
    /// A folder with nothing in it.
    EmptyFolder,
}

/// What a trash request did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trashed {
    Done,
    /// Nothing was at the path.
    Gone,
    /// The path is no longer what the client expected; nothing changed.
    Changed,
}

/// A path as a query value.
fn hd_api_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}
