//! An administrator's copy of the whole store, kept on another machine:
//! the off-machine backup that nothing on this server can reach or delete.
//!
//! | Request (administrators only) | Answer |
//! |---|---|
//! | `GET /api/v1/store-copy/meta` | `{"files":[{"name","len"}]}`: `store.id` and the metadata, after a checkpoint |
//! | `GET /api/v1/store-copy/objects?after=&limit=` | `{"objects":[name],"more"}`, in order |
//! | `GET /api/v1/store-copy/file?name=&len=` | the first `len` bytes of one file |
//! | `GET /admin/store-copy.tar` (web UI) | everything, as one tar file |
//! | `POST /admin/store-copy.tar` (web UI, with a passphrase) | the same, encrypted (`hd_store::sealed`); `homedrive decrypt-file` opens it |
//!
//! `homedrive backup-store DIR` uses the API and fetches only what the copy
//! lacks; the web UI's download is the same copy as a single file. Either
//! way the copy opens as a store (see `hd_store::copy`), so it can be
//! checked, restored to plain files, or used to repair this one.
//!
//! This hands every user's files to whoever holds an administrator's
//! password or device token. Administrators can read the store on the
//! server anyway; the copy makes that reachable over the network.

use std::io::{self, Write};

use hd_api::{J, s};
use hd_http::{Request, Response, ResponseBody, StreamSource};
use hd_store::copy::CopyFile;
use hd_store::sealed::{self, KeyParams, Keys, Sealer};

use crate::App;
use crate::api::{error, json};

/// The most object names in one page.
const PAGE: usize = 10_000;

impl App {
    pub(crate) fn store_copy<'a>(&'a self, req: &Request<'_, '_>, route: &str) -> Response<'a> {
        match route {
            "store-copy/meta" => match self.store.copy_meta() {
                Ok(files) => json(
                    200,
                    &J::O(vec![(
                        "files",
                        J::A(
                            files
                                .into_iter()
                                .map(|f| J::O(vec![("name", s(f.name)), ("len", J::U(f.len))]))
                                .collect(),
                        ),
                    )]),
                ),
                Err(e) => self.op_error(&e),
            },
            "store-copy/objects" => {
                let after = req.query_value("after").unwrap_or("").to_owned();
                let limit = req
                    .query_value("limit")
                    .and_then(|l| l.parse::<usize>().ok())
                    .map_or(PAGE, |l| l.clamp(1, PAGE));
                match self.store.copy_objects(&after, limit) {
                    Ok((names, more)) => json(
                        200,
                        &J::O(vec![
                            ("objects", J::A(names.into_iter().map(s).collect())),
                            ("more", J::Bool(more)),
                        ]),
                    ),
                    Err(e) => self.op_error(&e),
                }
            }
            "store-copy/file" => {
                let name = req.query_value("name").unwrap_or("").to_owned();
                let Ok((file, len)) = self.store.copy_open(&name) else {
                    return error(404, "no such file in the store");
                };
                let wanted =
                    req.query_value("len").and_then(|l| l.parse::<u64>().ok()).unwrap_or(len);
                if wanted > len {
                    return error(409, "the file is shorter than asked for");
                }
                let mut r = Response::new(200, "application/octet-stream", Vec::new());
                r.body = ResponseBody::File { file, offset: 0, len: wanted };
                r
            }
            _ => error(404, "no such API call"),
        }
    }

    /// The whole store as one tar file, for the web UI: plain, or with
    /// a passphrase, encrypted as it streams.
    pub(crate) fn store_copy_tar(&self, passphrase: Option<&str>) -> Response<'_> {
        let sealing = match passphrase {
            None => None,
            Some(p) => match Keys::create(p) {
                Ok(k) => Some(k),
                Err(e) => return Response::text(400, e.message()),
            },
        };
        let stamp = hd_common::timefmt::compact_utc(hd_common::timefmt::unix_seconds());
        let (kind, name) = if sealing.is_some() {
            ("application/octet-stream", format!("homedrive-store-{stamp}.tar.hdenc"))
        } else {
            ("application/x-tar", format!("homedrive-store-{stamp}.tar"))
        };
        let mut r = Response::new(200, kind, Vec::new());
        r.headers.push(("Content-Disposition".into(), format!("attachment; filename=\"{name}\"")));
        r.body =
            ResponseBody::Stream { source: Box::new(TarCopy { app: self, sealing }), length: None };
        r
    }
}

/// Writes the store as a tar stream: `store.id`, the metadata, then every
/// object, in the order a copier needs them.
struct TarCopy<'a> {
    app: &'a App,
    /// Encrypt the stream, with these keys and parameters.
    sealing: Option<(Keys, KeyParams)>,
}

/// A ustar header for a regular file.
fn tar_header(name: &str, len: u64, mtime: i64) -> io::Result<[u8; 512]> {
    let mut h = [0_u8; 512];
    if name.len() > 100 || len >= 8 << 30 {
        return Err(io::Error::other(format!("{name} cannot be stored in a tar file")));
    }
    let octal = |field: &mut [u8], value: u64| {
        let text = format!("{value:0width$o}", width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
    };
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], 0o600);
    octal(&mut h[108..116], 0);
    octal(&mut h[116..124], 0);
    octal(&mut h[124..136], len);
    octal(&mut h[136..148], u64::try_from(mtime).unwrap_or(0));
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let text = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(text.as_bytes());
    Ok(h)
}

impl TarCopy<'_> {
    fn add(&self, out: &mut dyn Write, f: &CopyFile, now: i64) -> io::Result<()> {
        let (mut file, len) = self.app.store.copy_open(&f.name).map_err(io::Error::other)?;
        let len = len.min(f.len);
        out.write_all(&tar_header(&f.name, len, now)?)?;
        let copied = io::copy(&mut io::Read::take(&mut file, len), out)?;
        if copied != len {
            return Err(io::Error::other(format!("{} shrank while being copied", f.name)));
        }
        let pad = (512 - len % 512) % 512;
        out.write_all(&vec![0_u8; usize::try_from(pad).unwrap_or(0)])
    }
}

impl TarCopy<'_> {
    fn pump_sealed(&self, out: &mut dyn Write, keys: &Keys, params: &KeyParams) -> io::Result<()> {
        sealed::write_standalone_head(out, params).map_err(io::Error::other)?;
        let mut sealer =
            Sealer::new(&mut *out, keys, sealed::STANDALONE_NAME).map_err(io::Error::other)?;
        self.write_tar(&mut sealer)?;
        sealer.finish().map_err(io::Error::other)?;
        Ok(())
    }

    fn write_tar(&self, out: &mut dyn Write) -> io::Result<()> {
        let now = hd_common::timefmt::unix_seconds();
        {
            for f in self.app.store.copy_meta().map_err(io::Error::other)? {
                self.add(out, &f, now)?;
            }
            let mut after = String::new();
            loop {
                let (names, more) =
                    self.app.store.copy_objects(&after, PAGE).map_err(io::Error::other)?;
                for name in &names {
                    // Objects never change, so their length now is theirs.
                    let len = self.app.store.copy_open(name).map_err(io::Error::other)?.1;
                    self.add(out, &CopyFile { name: name.clone(), len }, now)?;
                }
                match names.last() {
                    Some(last) if more => after.clone_from(last),
                    _ => break,
                }
            }
            out.write_all(&[0_u8; 1024])?;
            out.flush()
        }
    }
}

impl StreamSource for TarCopy<'_> {
    fn pump(&mut self, out: &mut dyn Write) -> io::Result<()> {
        let result = match &self.sealing {
            Some((keys, params)) => self.pump_sealed(out, keys, params),
            None => self.write_tar(out),
        };
        let message = match &result {
            Ok(()) => "downloaded through the web UI".to_owned(),
            Err(e) => format!("a download through the web UI broke off: {e}"),
        };
        // A download that broke off is not a failed backup, only one that
        // did not happen; a finished one counts as a copy taken.
        if result.is_ok() {
            let _ =
                crate::backups::record(&self.app.config.data_dir, "client-copy", true, &message);
        }
        result
    }
}
