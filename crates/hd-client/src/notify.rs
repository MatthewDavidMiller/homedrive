//! Notifications for what needs the user's attention, as the daemon syncs:
//! - deletions or changes held back because there were unusually many;
//! - changes that look like encryption (ransomware), held back;
//! - files damaged on this computer's disk, replaced with the server's
//!   copy;
//! - a conflict, and the name the user's copy was kept under;
//! - files that could not sync;
//! - files left out of sync (a name the drive cannot hold, a symbolic
//!   link, a file that changes during every upload) for over an hour:
//!   they are not backed up, and nothing else would say so;
//! - a folder whose sync has stopped (its disk unmounted, its marker
//!   missing, the server unreachable) for more than half an hour;
//! - the server restored from a backup;
//! - damage the server reports in its store, and files this computer sent
//!   again to repair it.
//!
//! Everything is also written to the log. A condition that lasts is shown
//! again at most once a day; once it clears, it is shown as soon as it
//! returns. Events (a conflict, a restore) are shown each time.
//!
//! On Linux they go to the desktop's notification service over the D-Bus
//! session bus, spoken directly in [`dbus`]: the client starts no programs,
//! so `notify-send` is not an option. On Windows they are notification-area
//! balloons, which Windows 10 and 11 show as toasts. Elsewhere, or with no
//! bus to reach, the log is all there is.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::engine::Report;

/// How often a lasting condition is shown again.
const REPEAT: Duration = Duration::from_hours(24);
/// How long a folder's sync may keep failing before it is worth a
/// notification: a laptop off its network for a few minutes is not news.
const STOPPED_AFTER: Duration = Duration::from_mins(30);
/// How long a file may stay out of sync before it is worth a notification:
/// one being saved while it uploads catches up within a round or two.
const UNSYNCED_AFTER: Duration = Duration::from_hours(1);

/// One thing to tell the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// A lasting condition's key, for showing it once a day at most;
    /// `None` for an event, shown every time.
    pub key: Option<String>,
    pub title: String,
    pub body: String,
    pub urgent: bool,
}

impl Notice {
    fn condition(key: String, title: &str, body: String, urgent: bool) -> Self {
        Self { key: Some(key), title: title.to_owned(), body, urgent }
    }

    fn event(title: &str, body: String) -> Self {
        Self { key: None, title: title.to_owned(), body, urgent: false }
    }
}

/// Where notices go.
pub type Sink = Box<dyn FnMut(&Notice) + Send>;

pub struct Notifier {
    shown: HashMap<String, Instant>,
    failing_since: HashMap<String, Instant>,
    /// Per folder, each path left out of sync and since when.
    unsynced_since: HashMap<String, HashMap<String, Instant>>,
    unsynced_after: Duration,
    sink: Sink,
}

impl std::fmt::Debug for Notifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Notifier").field("shown", &self.shown.len()).finish_non_exhaustive()
    }
}

impl Notifier {
    /// Notices to the log, and on Linux to the desktop.
    pub fn desktop() -> Self {
        let mut bus_failed = false;
        Self::with_sink(Box::new(move |n: &Notice| {
            eprintln!("homedrive: {}: {}", n.title, n.body);
            #[cfg(target_os = "linux")]
            match dbus::notify(&n.title, &n.body, n.urgent) {
                Ok(_) => bus_failed = false,
                Err(e) => {
                    // Said once, not on every notice, until it works again.
                    if !bus_failed {
                        eprintln!("homedrive: desktop notifications are unavailable: {e}");
                    }
                    bus_failed = true;
                }
            }
            #[cfg(windows)]
            match hd_sys::windows::notify::show(&n.title, &n.body, n.urgent) {
                Ok(()) => bus_failed = false,
                Err(e) => {
                    if !bus_failed {
                        eprintln!("homedrive: desktop notifications are unavailable: {e}");
                    }
                    bus_failed = true;
                }
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            let _ = &mut bus_failed;
        }))
    }

    pub fn with_sink(sink: Sink) -> Self {
        Self {
            shown: HashMap::new(),
            failing_since: HashMap::new(),
            unsynced_since: HashMap::new(),
            unsynced_after: UNSYNCED_AFTER,
            sink,
        }
    }

    /// How long a file may stay out of sync before it is reported. Tests.
    pub fn set_unsynced_after(&mut self, after: Duration) {
        self.unsynced_after = after;
    }

    /// Shows `n`, unless it is a condition already shown in the last day.
    pub fn raise(&mut self, n: &Notice) {
        if let Some(key) = &n.key {
            if self.shown.get(key).is_some_and(|at| at.elapsed() < REPEAT) {
                return;
            }
            self.shown.insert(key.clone(), Instant::now());
        }
        (self.sink)(n);
    }

    /// A condition has cleared: show it again as soon as it returns.
    fn clear(&mut self, key: &str) {
        self.shown.remove(key);
    }

    /// What one sync round of `folder` should tell the user. `result` is
    /// the round's report, or the error that stopped it.
    pub fn round(&mut self, folder: &Path, result: std::result::Result<&Report, &str>) {
        let name = folder.display().to_string();
        let stopped = format!("stopped:{name}");
        let r = match result {
            Err(why) => {
                let since = *self.failing_since.entry(stopped.clone()).or_insert_with(Instant::now);
                if since.elapsed() >= STOPPED_AFTER {
                    self.raise(&Notice::condition(
                        stopped,
                        "Sync has stopped",
                        format!("{name} has not synced for a while: {why}"),
                        true,
                    ));
                }
                return;
            }
            Ok(r) => r,
        };
        self.failing_since.remove(&stopped);
        self.clear(&stopped);
        let held = format!("held:{name}");
        match r.held_deletes {
            Some(n) => self.raise(&Notice::condition(
                held,
                "Deletions are waiting for you",
                format!(
                    "{n} files were deleted at once in {name}, so none were deleted anywhere \
                     yet. If you meant it, run `homedrive confirm`."
                ),
                true,
            )),
            None => self.clear(&held),
        }
        let ransom = format!("ransomware:{name}");
        if r.ransomware_suspected {
            self.raise(&Notice::condition(
                ransom,
                "Files look encrypted: possible ransomware",
                format!(
                    "Files in {name} were changed so that their content now looks encrypted. \
                     homedrive is holding back every change and deletion there, so the server \
                     and your other computers keep good copies. If you did not do this, \
                     disconnect this computer from the network now, then use Rewind in the \
                     web UI to put things back. If you did (encrypting or compressing files), \
                     run `homedrive confirm`."
                ),
                true,
            ));
        } else {
            self.clear(&ransom);
        }
        let held_changes = format!("held-changes:{name}");
        match r.held_changes {
            Some(n) if !r.ransomware_suspected => self.raise(&Notice::condition(
                held_changes,
                "Changes are waiting for you",
                format!(
                    "{n} files were changed at once in {name}, so the changes have not been \
                     uploaded yet. If you meant it, run `homedrive confirm`. If not, the \
                     server still has the earlier versions."
                ),
                true,
            )),
            _ => self.clear(&held_changes),
        }
        if !r.repaired_local.is_empty() {
            self.raise(&Notice {
                key: None,
                title: "Repaired damaged files on this computer".into(),
                body: format!(
                    "{} file(s) in {name} were damaged on this computer's disk: their content \
                     changed although nothing wrote to them. They were replaced with the \
                     server's copies, and the damaged copies kept in .homedrive/damaged. If \
                     this happens again, check this computer's disk.",
                    r.repaired_local.len()
                ),
                urgent: true,
            });
        }
        for copy in &r.conflicts {
            self.raise(&Notice::event(
                "Kept both copies",
                format!(
                    "A file in {name} was changed on two computers at once. Both are kept: \
                     yours is now {copy}."
                ),
            ));
        }
        let errors = format!("errors:{name}");
        if r.errors.is_empty() {
            self.clear(&errors);
        } else {
            self.raise(&Notice::condition(
                errors,
                "Some files did not sync",
                format!(
                    "{} file(s) in {name} could not sync. Run `homedrive status` to see \
                     which, and why.",
                    r.errors.len()
                ),
                false,
            ));
        }
        if !r.healed.is_empty() {
            self.raise(&Notice::event(
                "Repaired the server's copy",
                format!(
                    "The server had lost part of {} file(s) in {name}, probably to a failing \
                     disk. This computer still had them and sent them again.",
                    r.healed.len()
                ),
            ));
        }
        // Files left out of sync, round after round.
        let since = self.unsynced_since.entry(name.clone()).or_default();
        let now = Instant::now();
        let current: HashMap<&str, &str> =
            r.skipped.iter().map(|(p, why)| (p.as_str(), why.as_str())).collect();
        since.retain(|p, _| current.contains_key(p.as_str()));
        for p in current.keys() {
            since.entry((*p).to_owned()).or_insert(now);
        }
        let mut long: Vec<&String> = since
            .iter()
            .filter(|(_, t)| t.elapsed() >= self.unsynced_after)
            .map(|(p, _)| p)
            .collect();
        long.sort();
        let unsynced = format!("unsynced:{name}");
        if let Some(first) = long.first() {
            let why = current.get(first.as_str()).copied().unwrap_or("");
            let notice = Notice::condition(
                unsynced,
                "Some files are not being synced",
                format!(
                    "{} file(s) in {name} have not synced for over an hour, so they are not \
                     backed up; {first}, for one: {why}. Run `homedrive status` for all of \
                     them. Fix or rename them, or add an ignore pattern to leave them out on \
                     purpose.",
                    long.len()
                ),
                false,
            );
            self.raise(&notice);
        } else {
            self.clear(&unsynced);
        }
        if r.server_restored {
            self.raise(&Notice::event(
                "The server was restored from a backup",
                format!(
                    "{name} was compared with it afresh. Nothing was deleted, and anything the \
                     server no longer had was uploaded again."
                ),
            ));
        }
    }

    /// What the server says is wrong with its store.
    pub fn server(&mut self, problems: &[String]) {
        let stale: Vec<String> =
            self.shown.keys().filter(|k| k.starts_with("server:")).cloned().collect();
        let key = format!("server:{}", problems.join("; "));
        for k in stale {
            if k != key {
                self.clear(&k);
            }
        }
        if !problems.is_empty() {
            self.raise(&Notice::condition(
                key,
                "The server needs attention",
                format!(
                    "{}. Your files here are safe; ask whoever runs the server to look at its \
                     admin page.",
                    capitalize(&problems.join("; "))
                ),
                true,
            ));
        }
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next().map_or_else(String::new, |f| f.to_uppercase().chain(c).collect())
}

/// Just enough of D-Bus to call `org.freedesktop.Notifications.Notify` on
/// the session bus: the SASL EXTERNAL handshake, `Hello`, and one method
/// call, marshalled little-endian by hand.
#[cfg(target_os = "linux")]
pub mod dbus {
    use std::io::{Read, Write};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::{SocketAddr, UnixStream};
    use std::time::Duration;

    use hd_common::{Error, Result};

    const TIMEOUT: Duration = Duration::from_secs(3);
    /// The most a message from the bus may be.
    const MAX_MESSAGE: usize = 64 * 1024;
    /// The most messages read while waiting for the reply.
    const MAX_MESSAGES: usize = 32;

    const METHOD_CALL: u8 = 1;
    const METHOD_RETURN: u8 = 2;
    const ERROR: u8 = 3;

    const PATH: u8 = 1;
    const INTERFACE: u8 = 2;
    const MEMBER: u8 = 3;
    const ERROR_NAME: u8 = 4;
    const REPLY_SERIAL: u8 = 5;
    const DESTINATION: u8 = 6;
    const SIGNATURE: u8 = 8;

    /// A header field's value.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Value {
        Str(String),
        Path(String),
        Sig(String),
        U32(u32),
    }

    /// Writes D-Bus wire format, aligning relative to the buffer's start
    /// (a body starts 8-aligned in its message, so that is the same).
    #[derive(Debug, Default)]
    pub struct W(pub Vec<u8>);

    impl W {
        pub fn pad(&mut self, align: usize) {
            while !self.0.len().is_multiple_of(align) {
                self.0.push(0);
            }
        }
        pub fn byte(&mut self, v: u8) {
            self.0.push(v);
        }
        pub fn u32(&mut self, v: u32) {
            self.pad(4);
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        pub fn i32(&mut self, v: i32) {
            self.pad(4);
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        pub fn str(&mut self, v: &str) -> Result<()> {
            self.u32(u32::try_from(v.len()).map_err(|_| Error::new("string too long"))?);
            self.0.extend_from_slice(v.as_bytes());
            self.0.push(0);
            Ok(())
        }
        pub fn sig(&mut self, v: &str) -> Result<()> {
            self.byte(u8::try_from(v.len()).map_err(|_| Error::new("signature too long"))?);
            self.0.extend_from_slice(v.as_bytes());
            self.0.push(0);
            Ok(())
        }
        fn value(&mut self, v: &Value) -> Result<()> {
            match v {
                Value::Str(s) => {
                    self.sig("s")?;
                    self.str(s)
                }
                Value::Path(s) => {
                    self.sig("o")?;
                    self.str(s)
                }
                Value::Sig(s) => {
                    self.sig("g")?;
                    self.sig(s)
                }
                Value::U32(n) => {
                    self.sig("u")?;
                    self.u32(*n);
                    Ok(())
                }
            }
        }
    }

    /// A whole message: the fixed header, the header fields, the body.
    pub fn message(kind: u8, serial: u32, fields: &[(u8, Value)], body: &[u8]) -> Result<Vec<u8>> {
        let mut w = W::default();
        for b in [b'l', kind, 0, 1] {
            w.byte(b);
        }
        w.u32(u32::try_from(body.len()).map_err(|_| Error::new("body too long"))?);
        w.u32(serial);
        w.u32(0);
        let start = w.0.len();
        for (code, v) in fields {
            w.pad(8);
            w.byte(*code);
            w.value(v)?;
        }
        let len = u32::try_from(w.0.len() - start).map_err(|_| Error::new("header too long"))?;
        w.0[12..16].copy_from_slice(&len.to_le_bytes());
        w.pad(8);
        w.0.extend_from_slice(body);
        Ok(w.0)
    }

    /// Reads D-Bus wire format, little- or big-endian.
    #[derive(Debug)]
    pub struct R<'a> {
        pub buf: &'a [u8],
        pub pos: usize,
        pub big: bool,
    }

    impl R<'_> {
        fn bad() -> Error {
            Error::new("malformed message from the bus")
        }
        pub fn align(&mut self, a: usize) {
            self.pos = self.pos.next_multiple_of(a);
        }
        pub fn byte(&mut self) -> Result<u8> {
            let b = *self.buf.get(self.pos).ok_or_else(Self::bad)?;
            self.pos += 1;
            Ok(b)
        }
        pub fn u32(&mut self) -> Result<u32> {
            self.align(4);
            let b: [u8; 4] = self
                .buf
                .get(self.pos..self.pos + 4)
                .ok_or_else(Self::bad)?
                .try_into()
                .map_err(|_| Self::bad())?;
            self.pos += 4;
            Ok(if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
        }
        fn bytes(&mut self, n: usize) -> Result<String> {
            let s = self.buf.get(self.pos..self.pos + n).ok_or_else(Self::bad)?;
            if self.buf.get(self.pos + n) != Some(&0) {
                return Err(Self::bad());
            }
            self.pos += n + 1;
            String::from_utf8(s.to_vec()).map_err(|_| Self::bad())
        }
        pub fn str(&mut self) -> Result<String> {
            let n = usize::try_from(self.u32()?).map_err(|_| Self::bad())?;
            self.bytes(n)
        }
        pub fn sig(&mut self) -> Result<String> {
            let n = usize::from(self.byte()?);
            self.bytes(n)
        }
    }

    /// A message read from the bus: its type, header fields, and body.
    #[derive(Debug)]
    pub struct Message {
        pub kind: u8,
        pub big: bool,
        pub fields: Vec<(u8, Value)>,
        pub body: Vec<u8>,
    }

    impl Message {
        pub fn field(&self, code: u8) -> Option<&Value> {
            self.fields.iter().find(|(c, _)| *c == code).map(|(_, v)| v)
        }
    }

    /// Reads one message.
    pub fn read_message(s: &mut impl Read) -> Result<Message> {
        let mut fixed = [0_u8; 16];
        s.read_exact(&mut fixed)?;
        let big = match fixed[0] {
            b'l' => false,
            b'B' => true,
            _ => return Err(Error::new("malformed message from the bus")),
        };
        let mut head = R { buf: &fixed, pos: 4, big };
        let body_len = usize::try_from(head.u32()?).map_err(|_| R::bad())?;
        head.u32()?;
        let fields_len = usize::try_from(head.u32()?).map_err(|_| R::bad())?;
        let header_end = (16 + fields_len).next_multiple_of(8);
        if header_end + body_len > MAX_MESSAGE {
            return Err(Error::new("a message from the bus is too large"));
        }
        let mut rest = vec![0_u8; header_end - 16 + body_len];
        s.read_exact(&mut rest)?;
        let mut all = fixed.to_vec();
        all.extend_from_slice(&rest);
        let mut r = R { buf: &all[..16 + fields_len], pos: 16, big };
        let mut fields = Vec::new();
        while r.pos < 16 + fields_len {
            r.align(8);
            let code = r.byte()?;
            let v = match r.sig()?.as_str() {
                "s" => Value::Str(r.str()?),
                "o" => Value::Path(r.str()?),
                "g" => Value::Sig(r.sig()?),
                "u" => Value::U32(r.u32()?),
                _ => return Err(R::bad()),
            };
            fields.push((code, v));
        }
        Ok(Message { kind: fixed[1], big, fields, body: all[header_end..].to_vec() })
    }

    /// The `Notify` call's body: (susssasa{sv}i).
    pub fn notify_body(summary: &str, body: &str, urgent: bool) -> Result<Vec<u8>> {
        let mut w = W::default();
        w.str("homedrive")?;
        w.u32(0);
        w.str("folder-sync")?;
        w.str(summary)?;
        w.str(body)?;
        w.u32(0); // actions: none
        // hints: {"urgency": <byte>}, 1 normal and 2 critical. The array's
        // length counts from its first element, after the 8-byte padding.
        w.u32(0);
        let len_at = w.0.len() - 4;
        w.pad(8);
        let start = w.0.len();
        w.str("urgency")?;
        w.sig("y")?;
        w.byte(if urgent { 2 } else { 1 });
        let len = u32::try_from(w.0.len() - start).map_err(|_| Error::new("hints too long"))?;
        w.0[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
        w.i32(-1);
        Ok(w.0)
    }

    /// The session bus addresses to try, from `DBUS_SESSION_BUS_ADDRESS`
    /// or the standard place under `XDG_RUNTIME_DIR`.
    fn addresses() -> Vec<String> {
        if let Ok(a) = std::env::var("DBUS_SESSION_BUS_ADDRESS")
            && !a.is_empty()
        {
            return a.split(';').map(str::to_owned).collect();
        }
        std::env::var("XDG_RUNTIME_DIR")
            .map_or_else(|_| Vec::new(), |d| vec![format!("unix:path={d}/bus")])
    }

    /// Undoes D-Bus address escaping (`%xx`).
    fn unescape(v: &str) -> Option<Vec<u8>> {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        Some(out)
    }

    /// Connects to one `unix:path=...` or `unix:abstract=...` address.
    pub fn connect(address: &str) -> Result<UnixStream> {
        let params = address
            .strip_prefix("unix:")
            .ok_or_else(|| Error::new(format!("unsupported bus address {address}")))?;
        for p in params.split(',') {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let Some(v) = unescape(v) else { continue };
            let addr = match k {
                "path" => SocketAddr::from_pathname(std::ffi::OsStr::from_bytes(&v))?,
                "abstract" => SocketAddr::from_abstract_name(&v)?,
                _ => continue,
            };
            let s = UnixStream::connect_addr(&addr)?;
            s.set_read_timeout(Some(TIMEOUT))?;
            s.set_write_timeout(Some(TIMEOUT))?;
            return Ok(s);
        }
        Err(Error::new(format!("unsupported bus address {address}")))
    }

    /// Authenticates as this process's user (SASL EXTERNAL).
    fn authenticate(s: &mut UnixStream) -> Result<()> {
        let uid = std::fs::metadata("/proc/self")?.uid().to_string();
        let hex = hd_common::buf::hex(uid.as_bytes());
        s.write_all(format!("\0AUTH EXTERNAL {hex}\r\n").as_bytes())?;
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while !line.ends_with(b"\r\n") {
            if line.len() > 512 {
                return Err(Error::new("the bus sent an overlong reply"));
            }
            s.read_exact(&mut byte)?;
            line.push(byte[0]);
        }
        if !line.starts_with(b"OK ") {
            return Err(Error::new("the session bus refused this user"));
        }
        s.write_all(b"BEGIN\r\n")?;
        Ok(())
    }

    /// Sends one notification at `address`; returns its id.
    pub fn send(address: &str, summary: &str, body: &str, urgent: bool) -> Result<u32> {
        let mut s = connect(address)?;
        authenticate(&mut s)?;
        let bus = "org.freedesktop.DBus";
        let hello = message(
            METHOD_CALL,
            1,
            &[
                (PATH, Value::Path("/org/freedesktop/DBus".into())),
                (INTERFACE, Value::Str(bus.into())),
                (MEMBER, Value::Str("Hello".into())),
                (DESTINATION, Value::Str(bus.into())),
            ],
            &[],
        )?;
        let service = "org.freedesktop.Notifications";
        let notify = message(
            METHOD_CALL,
            2,
            &[
                (PATH, Value::Path("/org/freedesktop/Notifications".into())),
                (INTERFACE, Value::Str(service.into())),
                (MEMBER, Value::Str("Notify".into())),
                (DESTINATION, Value::Str(service.into())),
                (SIGNATURE, Value::Sig("susssasa{sv}i".into())),
            ],
            &notify_body(summary, body, urgent)?,
        )?;
        s.write_all(&hello)?;
        s.write_all(&notify)?;
        for _ in 0..MAX_MESSAGES {
            let m = read_message(&mut s)?;
            if m.field(REPLY_SERIAL) != Some(&Value::U32(2)) {
                continue;
            }
            return match m.kind {
                METHOD_RETURN => R { buf: &m.body, pos: 0, big: m.big }.u32(),
                ERROR => Err(Error::new(match m.field(ERROR_NAME) {
                    Some(Value::Str(name)) => format!("the notification service said {name}"),
                    _ => "the notification service refused".to_owned(),
                })),
                _ => Err(Error::new("unexpected reply from the bus")),
            };
        }
        Err(Error::new("no reply from the notification service"))
    }

    /// Sends one notification on the session bus.
    pub fn notify(summary: &str, body: &str, urgent: bool) -> Result<u32> {
        let mut last = Error::new("no session bus (DBUS_SESSION_BUS_ADDRESS is not set)");
        for a in addresses() {
            match send(&a, summary, body, urgent) {
                Ok(id) => return Ok(id),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn recording() -> (Notifier, Arc<Mutex<Vec<Notice>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let g = Arc::clone(&got);
        (Notifier::with_sink(Box::new(move |n| g.lock().unwrap().push(n.clone()))), got)
    }

    #[test]
    fn conditions_are_shown_once_until_they_clear_and_events_every_time() {
        let (mut n, got) = recording();
        let folder = Path::new("/home/me/Documents");
        let held = Report { held_deletes: Some(60), ..Report::default() };
        n.round(folder, Ok(&held));
        n.round(folder, Ok(&held));
        assert_eq!(got.lock().unwrap().len(), 1);
        assert!(got.lock().unwrap()[0].body.contains("homedrive confirm"));
        // Cleared, then back: shown again.
        n.round(folder, Ok(&Report::default()));
        n.round(folder, Ok(&held));
        assert_eq!(got.lock().unwrap().len(), 2);
        // Each conflict and each restore is its own event.
        let conflict = Report {
            conflicts: vec!["a (conflict laptop 2026-10-28 1200).txt".into()],
            server_restored: true,
            ..Report::default()
        };
        n.round(folder, Ok(&conflict));
        n.round(folder, Ok(&conflict));
        let titles: Vec<String> = got.lock().unwrap().iter().map(|n| n.title.clone()).collect();
        assert_eq!(titles.iter().filter(|t| t.as_str() == "Kept both copies").count(), 2);
        assert_eq!(titles.iter().filter(|t| t.contains("restored")).count(), 2);
    }

    #[test]
    fn files_left_out_of_sync_are_reported_once_they_stay_out() {
        let (mut n, got) = recording();
        let folder = Path::new("/home/me/Documents");
        let skipped = Report {
            skipped: vec![("link".into(), "symbolic links are not synced".into())],
            ..Report::default()
        };
        // Once is not news (a file saved during its upload is retried).
        n.round(folder, Ok(&skipped));
        assert!(got.lock().unwrap().is_empty());
        n.set_unsynced_after(Duration::ZERO);
        n.round(folder, Ok(&skipped));
        assert_eq!(got.lock().unwrap().len(), 1);
        assert!(got.lock().unwrap()[0].body.contains("not backed up"));
        // Shown once a day, and cleared when it syncs.
        n.round(folder, Ok(&skipped));
        assert_eq!(got.lock().unwrap().len(), 1);
        n.round(folder, Ok(&Report::default()));
        n.round(folder, Ok(&skipped));
        assert_eq!(got.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_short_outage_is_not_news() {
        let (mut n, got) = recording();
        let folder = Path::new("/home/me/Documents");
        n.round(folder, Err("connection refused"));
        n.round(folder, Err("connection refused"));
        assert!(got.lock().unwrap().is_empty());
        // Failing for long enough is.
        n.failing_since.insert(
            "stopped:/home/me/Documents".into(),
            Instant::now().checked_sub(STOPPED_AFTER).unwrap(),
        );
        n.round(folder, Err("the folder is missing"));
        assert_eq!(got.lock().unwrap().len(), 1);
        assert!(got.lock().unwrap()[0].urgent);
        // A good round resets the clock.
        n.round(folder, Ok(&Report::default()));
        n.round(folder, Err("connection refused"));
        assert_eq!(got.lock().unwrap().len(), 1);
    }

    #[test]
    fn server_problems_are_shown_once_and_again_when_they_change() {
        let (mut n, got) = recording();
        n.server(&[]);
        n.server(&["1 stored file version(s) cannot be read".into()]);
        n.server(&["1 stored file version(s) cannot be read".into()]);
        assert_eq!(got.lock().unwrap().len(), 1);
        assert!(got.lock().unwrap()[0].body.starts_with("1 stored"));
        n.server(&["2 stored file version(s) cannot be read".into()]);
        assert_eq!(got.lock().unwrap().len(), 2);
        n.server(&[]);
        n.server(&["2 stored file version(s) cannot be read".into()]);
        assert_eq!(got.lock().unwrap().len(), 3);
    }

    /// The client against a stand-in bus: the handshake, then `Hello` and
    /// a `Notify` whose arguments decode back to what was sent.
    #[cfg(target_os = "linux")]
    #[test]
    fn notify_speaks_the_bus_protocol() {
        use dbus::{R, Value, W, message, read_message};
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("hd-notify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("bus");
        let listener = UnixListener::bind(&socket).unwrap();
        let bus = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut byte = [0_u8; 1];
            while !seen.ends_with(b"\r\n") {
                s.read_exact(&mut byte).unwrap();
                seen.push(byte[0]);
            }
            assert!(seen.starts_with(b"\0AUTH EXTERNAL "));
            s.write_all(b"OK 0123456789abcdef0123456789abcdef\r\n").unwrap();
            let mut begin = [0_u8; 7];
            s.read_exact(&mut begin).unwrap();
            assert_eq!(&begin, b"BEGIN\r\n");
            let hello = read_message(&mut s).unwrap();
            assert_eq!(hello.field(3), Some(&Value::Str("Hello".into())));
            let mut w = W::default();
            w.str(":1.42").unwrap();
            s.write_all(
                &message(2, 1, &[(5, Value::U32(1)), (8, Value::Sig("s".into()))], &w.0).unwrap(),
            )
            .unwrap();
            let call = read_message(&mut s).unwrap();
            assert_eq!(call.field(3), Some(&Value::Str("Notify".into())));
            assert_eq!(call.field(8), Some(&Value::Sig("susssasa{sv}i".into())));
            let mut r = R { buf: &call.body, pos: 0, big: false };
            let args = (
                r.str().unwrap(),
                r.u32().unwrap(),
                r.str().unwrap(),
                r.str().unwrap(),
                r.str().unwrap(),
            );
            // An unrelated signal first, as a real bus may send.
            s.write_all(&message(4, 2, &[(3, Value::Str("NameAcquired".into()))], &[]).unwrap())
                .unwrap();
            let mut w = W::default();
            w.u32(7);
            s.write_all(
                &message(2, 3, &[(5, Value::U32(2)), (8, Value::Sig("u".into()))], &w.0).unwrap(),
            )
            .unwrap();
            args
        });
        let id = dbus::send(&format!("unix:path={}", socket.display()), "Title", "Body text", true)
            .unwrap();
        assert_eq!(id, 7);
        let (app, replaces, _, summary, body) = bus.join().unwrap();
        assert_eq!((app.as_str(), replaces), ("homedrive", 0));
        assert_eq!((summary.as_str(), body.as_str()), ("Title", "Body text"));
        // The hints dictionary is a well-formed a{sv}: {"urgency": byte 2}.
        let b = dbus::notify_body("T", "B", true).unwrap();
        let mut r = R { buf: &b, pos: 0, big: false };
        r.str().unwrap();
        r.u32().unwrap();
        for _ in 0..3 {
            r.str().unwrap();
        }
        assert_eq!(r.u32().unwrap(), 0);
        let len = usize::try_from(r.u32().unwrap()).unwrap();
        r.align(8);
        let end = r.pos + len;
        r.align(8);
        assert_eq!(r.str().unwrap(), "urgency");
        assert_eq!(r.sig().unwrap(), "y");
        assert_eq!(r.byte().unwrap(), 2);
        assert_eq!(r.pos, end);
        assert_eq!(r.u32().unwrap(), u32::MAX);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
