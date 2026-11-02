//! The tray icon. Windows has its own, in `hd_sys::windows::tray`. On Linux
//! it is a StatusNotifierItem on the session bus, which KDE, and GNOME with
//! the AppIndicator extension, show. With no panel to show it, nothing
//! happens: the GUI and notifications do not depend on it.

/// Starts the icon. `open` shows the GUI and `quit` ends the program.
#[cfg(windows)]
pub fn start(
    service: std::sync::Arc<crate::service::Service>,
    open: impl Fn() + Send + Sync + 'static,
    quit: impl Fn() + Send + Sync + 'static,
) {
    let spawned =
        std::thread::Builder::new().name("tray".into()).stack_size(256 * 1024).spawn(move || {
            let actions = hd_sys::windows::tray::Actions {
                open: Box::new(open),
                quit: Box::new(quit),
                needs_attention: Box::new(move || service.needs_attention()),
            };
            if let Err(e) = hd_sys::windows::tray::run(actions) {
                crate::say!("homedrive: no tray icon: {e}");
            }
        });
    if let Err(e) = spawned {
        crate::say!("homedrive: no tray icon: {e}");
    }
}

/// Takes the icon away before the program ends.
pub fn remove() {
    #[cfg(windows)]
    hd_sys::windows::tray::remove();
}

#[cfg(not(windows))]
pub use linux::start;

#[cfg(not(windows))]
mod linux {
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use hd_common::{Error, Result};

    use crate::notify::dbus::{
        DESTINATION, ERROR, ERROR_NAME, INTERFACE, MEMBER, METHOD_CALL, METHOD_RETURN, Message,
        PATH, R, REPLY_SERIAL, SENDER, SIGNAL, SIGNATURE, Value, W, addresses, authenticate,
        connect, message, read_message,
    };
    use crate::service::Service;

    const ITEM_PATH: &str = "/StatusNotifierItem";
    const ITEM: &str = "org.kde.StatusNotifierItem";
    const WATCHER: &str = "org.kde.StatusNotifierWatcher";
    const REGISTER_EVERY: Duration = Duration::from_secs(30);
    const TICK: Duration = Duration::from_secs(2);
    const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
    const INTROSPECTION: &str = "<node>\
        <interface name=\"org.kde.StatusNotifierItem\">\
        <method name=\"Activate\"><arg type=\"i\" direction=\"in\"/>\
        <arg type=\"i\" direction=\"in\"/></method>\
        <method name=\"SecondaryActivate\"><arg type=\"i\" direction=\"in\"/>\
        <arg type=\"i\" direction=\"in\"/></method>\
        <method name=\"ContextMenu\"><arg type=\"i\" direction=\"in\"/>\
        <arg type=\"i\" direction=\"in\"/></method>\
        <signal name=\"NewStatus\"><arg type=\"s\"/></signal>\
        <signal name=\"NewIcon\"/>\
        <property name=\"Category\" type=\"s\" access=\"read\"/>\
        <property name=\"Id\" type=\"s\" access=\"read\"/>\
        <property name=\"Title\" type=\"s\" access=\"read\"/>\
        <property name=\"Status\" type=\"s\" access=\"read\"/>\
        <property name=\"IconName\" type=\"s\" access=\"read\"/>\
        <property name=\"ItemIsMenu\" type=\"b\" access=\"read\"/>\
        </interface></node>";

    fn string_property(w: &mut W, key: &str, value: &str) -> Result<()> {
        w.pad(8);
        w.str(key)?;
        w.sig("s")?;
        w.str(value)
    }

    fn status(attention: bool) -> &'static str {
        if attention { "NeedsAttention" } else { "Active" }
    }

    fn icon(attention: bool) -> &'static str {
        if attention { "dialog-warning" } else { "folder-sync" }
    }

    fn string_value(name: &str, attention: bool) -> Option<&'static str> {
        Some(match name {
            "Category" => "ApplicationStatus",
            "Id" | "Title" => "homedrive",
            "Status" => status(attention),
            "IconName" => icon(attention),
            _ => return None,
        })
    }

    /// `a{sv}`: every property.
    fn all_properties(attention: bool) -> Result<Vec<u8>> {
        let mut w = W::default();
        w.u32(0);
        w.pad(8);
        let start = w.0.len();
        for key in ["Category", "Id", "Title", "Status", "IconName"] {
            let value = string_value(key, attention).unwrap_or("");
            string_property(&mut w, key, value)?;
        }
        w.pad(8);
        w.str("ItemIsMenu")?;
        w.sig("b")?;
        w.u32(0);
        let len = u32::try_from(w.0.len() - start).map_err(|_| Error::new("too long"))?;
        w.0[0..4].copy_from_slice(&len.to_le_bytes());
        Ok(w.0)
    }

    /// One bus connection, with the serial of the next message.
    struct Bus {
        s: UnixStream,
        serial: u32,
    }

    impl Bus {
        fn next(&mut self) -> u32 {
            self.serial += 1;
            self.serial
        }

        fn reply(&mut self, to: &Message, signature: Option<&str>, body: &[u8]) -> Result<()> {
            let serial = self.next();
            let mut fields = vec![(REPLY_SERIAL, Value::U32(to.serial))];
            if let Some(Value::Str(sender)) = to.field(SENDER) {
                fields.push((DESTINATION, Value::Str(sender.clone())));
            }
            if let Some(sig) = signature {
                fields.push((SIGNATURE, Value::Sig(sig.to_owned())));
            }
            self.s.write_all(&message(METHOD_RETURN, serial, &fields, body)?)?;
            Ok(())
        }

        fn refuse(&mut self, to: &Message) -> Result<()> {
            let serial = self.next();
            let mut fields = vec![
                (REPLY_SERIAL, Value::U32(to.serial)),
                (ERROR_NAME, Value::Str("org.freedesktop.DBus.Error.UnknownMethod".into())),
            ];
            if let Some(Value::Str(sender)) = to.field(SENDER) {
                fields.push((DESTINATION, Value::Str(sender.clone())));
            }
            self.s.write_all(&message(ERROR, serial, &fields, &[])?)?;
            Ok(())
        }

        fn signal(&mut self, member: &str, signature: Option<&str>, body: &[u8]) -> Result<()> {
            let serial = self.next();
            let mut fields = vec![
                (PATH, Value::Path(ITEM_PATH.into())),
                (INTERFACE, Value::Str(ITEM.into())),
                (MEMBER, Value::Str(member.into())),
            ];
            if let Some(sig) = signature {
                fields.push((SIGNATURE, Value::Sig(sig.to_owned())));
            }
            self.s.write_all(&message(SIGNAL, serial, &fields, body)?)?;
            Ok(())
        }

        fn register(&mut self, unique: &str) -> Result<u32> {
            let serial = self.next();
            let mut w = W::default();
            w.str(unique)?;
            self.s.write_all(&message(
                METHOD_CALL,
                serial,
                &[
                    (PATH, Value::Path("/StatusNotifierWatcher".into())),
                    (INTERFACE, Value::Str(WATCHER.into())),
                    (MEMBER, Value::Str("RegisterStatusNotifierItem".into())),
                    (DESTINATION, Value::Str(WATCHER.into())),
                    (SIGNATURE, Value::Sig("s".into())),
                ],
                &w.0,
            )?)?;
            Ok(serial)
        }

        fn hello(&mut self) -> Result<String> {
            let bus = "org.freedesktop.DBus";
            let serial = self.next();
            self.s.write_all(&message(
                METHOD_CALL,
                serial,
                &[
                    (PATH, Value::Path("/org/freedesktop/DBus".into())),
                    (INTERFACE, Value::Str(bus.into())),
                    (MEMBER, Value::Str("Hello".into())),
                    (DESTINATION, Value::Str(bus.into())),
                ],
                &[],
            )?)?;
            for _ in 0..32 {
                let m = read_message(&mut self.s)?;
                if m.field(REPLY_SERIAL) == Some(&Value::U32(serial)) {
                    return R { buf: &m.body, pos: 0, big: m.big }.str();
                }
            }
            Err(Error::new("no reply from the bus"))
        }

        fn handle(&mut self, m: &Message, attention: bool, open: &dyn Fn()) -> Result<()> {
            let member = match m.field(MEMBER) {
                Some(Value::Str(name)) => name.as_str(),
                _ => "",
            };
            let interface = match m.field(INTERFACE) {
                Some(Value::Str(name)) => name.as_str(),
                _ => "",
            };
            match (interface, member) {
                (ITEM, "Activate" | "SecondaryActivate" | "ContextMenu") => {
                    open();
                    self.reply(m, None, &[])
                }
                ("org.freedesktop.DBus.Properties", "GetAll") => {
                    self.reply(m, Some("a{sv}"), &all_properties(attention)?)
                }
                ("org.freedesktop.DBus.Properties", "Get") => {
                    let mut r = R { buf: &m.body, pos: 0, big: m.big };
                    r.str()?;
                    r.align(4);
                    let name = r.str()?;
                    let mut w = W::default();
                    if name == "ItemIsMenu" {
                        w.sig("b")?;
                        w.u32(0);
                    } else if let Some(value) = string_value(&name, attention) {
                        w.sig("s")?;
                        w.str(value)?;
                    } else {
                        return self.refuse(m);
                    }
                    self.reply(m, Some("v"), &w.0)
                }
                ("org.freedesktop.DBus.Introspectable", "Introspect") => {
                    let mut w = W::default();
                    w.str(INTROSPECTION)?;
                    self.reply(m, Some("s"), &w.0)
                }
                ("org.freedesktop.DBus.Peer", "Ping") => self.reply(m, None, &[]),
                _ => self.refuse(m),
            }
        }

        /// Serves until the connection ends.
        fn serve(&mut self, service: &Service, open: &dyn Fn()) -> Result<()> {
            let unique = self.hello()?;
            let mut registered = false;
            let mut pending = None;
            let mut last_try: Option<Instant> = None;
            let mut attention = false;
            self.s.set_read_timeout(Some(TICK))?;
            loop {
                if !registered && last_try.is_none_or(|t| t.elapsed() >= REGISTER_EVERY) {
                    pending = Some(self.register(&unique)?);
                    last_try = Some(Instant::now());
                }
                let now = service.needs_attention();
                if now != attention {
                    attention = now;
                    let mut w = W::default();
                    w.str(status(attention))?;
                    self.signal("NewStatus", Some("s"), &w.0)?;
                    self.signal("NewIcon", None, &[])?;
                }
                // The short timeout is only for waiting: once a message has
                // begun, the rest of it is read whole.
                let mut first = [0_u8; 1];
                match self.s.read(&mut first) {
                    Ok(0) => return Err(Error::new("the bus went away")),
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
                self.s.set_read_timeout(Some(MESSAGE_TIMEOUT))?;
                let m = read_message(&mut first.as_slice().chain(&mut self.s))?;
                self.s.set_read_timeout(Some(TICK))?;
                match m.kind {
                    METHOD_CALL => self.handle(&m, attention, open)?,
                    METHOD_RETURN | ERROR => {
                        if let (Some(Value::U32(to)), Some(p)) = (m.field(REPLY_SERIAL), pending)
                            && *to == p
                        {
                            registered = m.kind == METHOD_RETURN;
                            pending = None;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Runs the item in the background, for as long as there is a bus.
    pub fn start(
        service: Arc<Service>,
        open: impl Fn() + Send + Sync + 'static,
        _quit: impl Fn() + Send + Sync + 'static,
    ) {
        let spawned = std::thread::Builder::new().name("tray".into()).stack_size(256 * 1024).spawn(
            move || {
                for address in addresses() {
                    let connected = connect(&address).and_then(|mut s| {
                        authenticate(&mut s)?;
                        Ok(s)
                    });
                    let Ok(s) = connected else { continue };
                    let mut bus = Bus { s, serial: 0 };
                    if let Err(e) = bus.serve(&service, &open) {
                        crate::say!("homedrive: the tray icon stopped: {e}");
                    }
                    return;
                }
            },
        );
        if let Err(e) = spawned {
            crate::say!("homedrive: no tray icon: {e}");
        }
    }
}
