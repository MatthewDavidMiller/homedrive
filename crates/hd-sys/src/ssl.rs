//! OpenSSL 3 libssl, client side only: the sync client's HTTPS. Built only
//! with the `tls` feature, so the server never links libssl (Traefik
//! terminates its TLS). Ported from rpi-omt-client's omt-sys.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void};

opaque!(SSL_CTX, SSL, SSL_METHOD, X509, X509_STORE);

const TLS1_2_VERSION: c_long = 0x0303;
const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
const TLSEXT_NAMETYPE_HOST_NAME: c_long = 0;
const SSL_VERIFY_PEER: c_int = 1;
const SSL_ERROR_SSL: c_int = 1;
const SSL_ERROR_SYSCALL: c_int = 5;
const SSL_ERROR_ZERO_RETURN: c_int = 6;
const SSL_R_UNEXPECTED_EOF_WHILE_READING: c_ulong = 294;
const ERR_REASON_MASK: c_ulong = 0x7F_FFFF;
const X509_V_OK: c_long = 0;

unsafe extern "C" {
    fn TLS_client_method() -> *const SSL_METHOD;
    fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    fn SSL_CTX_free(ctx: *mut SSL_CTX);
    fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, cb: *const c_void);
    fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    fn SSL_CTX_load_verify_locations(
        ctx: *mut SSL_CTX,
        file: *const c_char,
        dir: *const c_char,
    ) -> c_int;
    fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    fn SSL_free(ssl: *mut SSL);
    fn SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int;
    fn SSL_ctrl(ssl: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    fn SSL_set1_host(ssl: *mut SSL, host: *const c_char) -> c_int;
    fn SSL_connect(ssl: *mut SSL) -> c_int;
    fn SSL_read(ssl: *mut SSL, buf: *mut c_void, num: c_int) -> c_int;
    fn SSL_write(ssl: *mut SSL, buf: *const c_void, num: c_int) -> c_int;
    fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    fn SSL_get_verify_result(ssl: *const SSL) -> c_long;
    fn SSL_shutdown(ssl: *mut SSL) -> c_int;
    fn X509_verify_cert_error_string(n: c_long) -> *const c_char;
    fn ERR_get_error() -> c_ulong;
    fn ERR_peek_error() -> c_ulong;
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    fn ERR_clear_error();
}

/// Owned client contexts and connections over blocking sockets.
pub mod safe {
    #[allow(clippy::wildcard_imports)]
    use super::*;
    use std::ffi::CStr;
    use std::io;
    use std::net::TcpStream;
    use std::ptr::{self, NonNull};

    /// The oldest queued OpenSSL error as text; the queue is then cleared.
    fn take_error() -> String {
        // SAFETY: reads the calling thread's error queue.
        let code = unsafe { ERR_get_error() };
        let mut text = String::from("unknown TLS error");
        if code != 0 {
            let mut buf = [0_u8; 256];
            // SAFETY: `buf` is writable for its length; OpenSSL writes a NUL
            // terminated string of at most that many bytes.
            unsafe { ERR_error_string_n(code, buf.as_mut_ptr().cast(), buf.len()) };
            if let Ok(s) = CStr::from_bytes_until_nul(&buf) {
                text = s.to_string_lossy().into_owned();
            }
        }
        // SAFETY: clears the calling thread's error queue.
        unsafe { ERR_clear_error() };
        text
    }

    /// The descriptor OpenSSL's socket BIO takes: a file descriptor, or on
    /// Windows the SOCKET handle, which OpenSSL itself narrows to `int`.
    fn raw_socket(s: &TcpStream) -> c_int {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            s.as_raw_fd()
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            // OpenSSL takes the SOCKET as an int; Windows socket handles
            // fit, which is what OpenSSL's own Windows code relies on.
            #[allow(clippy::cast_possible_truncation)]
            {
                s.as_raw_socket() as c_int
            }
        }
    }

    /// A client context: TLS 1.2 or newer, peer verification on.
    #[derive(Debug)]
    pub struct Client(NonNull<SSL_CTX>);

    // SAFETY: an SSL_CTX is safe to share between threads once configured;
    // this type only configures it in its constructor.
    unsafe impl Send for Client {}
    // SAFETY: as above.
    unsafe impl Sync for Client {}

    impl Drop for Client {
        fn drop(&mut self) {
            // SAFETY: owned and freed once; connections hold their own
            // reference.
            unsafe { SSL_CTX_free(self.0.as_ptr()) };
        }
    }

    impl Client {
        /// Trusts `ca_file` if given, else the system's default locations.
        pub fn new(ca_file: Option<&CStr>) -> io::Result<Self> {
            // SAFETY: the getter takes no arguments and returns a static.
            let method = unsafe { TLS_client_method() };
            // SAFETY: returns an owned context or NULL.
            let ctx = NonNull::new(unsafe { SSL_CTX_new(method) })
                .map(Self)
                .ok_or_else(|| io::Error::other(take_error()))?;
            let p = ctx.0.as_ptr();
            // SAFETY: the context is live; the control takes a version.
            if unsafe {
                SSL_CTX_ctrl(p, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, ptr::null_mut())
            } != 1
            {
                return Err(io::Error::other(take_error()));
            }
            // SAFETY: the context is live; NULL keeps OpenSSL's verifier.
            unsafe { SSL_CTX_set_verify(p, SSL_VERIFY_PEER, ptr::null()) };
            let loaded = match ca_file {
                // SAFETY: the context is live and the path NUL-terminated.
                Some(f) => unsafe { SSL_CTX_load_verify_locations(p, f.as_ptr(), ptr::null()) },
                // SAFETY: the context is live.
                None => unsafe { SSL_CTX_set_default_verify_paths(p) },
            };
            if loaded != 1 {
                return Err(io::Error::other(format!("cannot load trusted CAs: {}", take_error())));
            }
            Ok(ctx)
        }

        /// Connects over `socket`, checking the certificate against `host`.
        pub fn connect(&self, socket: TcpStream, host: &CStr) -> io::Result<Stream> {
            // SAFETY: the context is live; SSL_new takes its own reference.
            let ssl = NonNull::new(unsafe { SSL_new(self.0.as_ptr()) })
                .ok_or_else(|| io::Error::other(take_error()))?;
            let stream = Stream { ssl, socket };
            let p = stream.ssl.as_ptr();
            // SAFETY: the connection is live and the descriptor owned by the
            // same Stream, which frees the SSL before closing it.
            if unsafe { SSL_set_fd(p, raw_socket(&stream.socket)) } != 1 {
                return Err(io::Error::other(take_error()));
            }
            // SAFETY: OpenSSL copies the name; the cast is the macro's own.
            let sni = unsafe {
                SSL_ctrl(
                    p,
                    SSL_CTRL_SET_TLSEXT_HOSTNAME,
                    TLSEXT_NAMETYPE_HOST_NAME,
                    host.as_ptr().cast_mut().cast(),
                )
            };
            // SAFETY: OpenSSL copies the name.
            if sni != 1 || unsafe { SSL_set1_host(p, host.as_ptr()) } != 1 {
                return Err(io::Error::other(take_error()));
            }
            // SAFETY: the connection is live; the socket is blocking.
            if unsafe { SSL_connect(p) } != 1 {
                let why = stream.verify_error().unwrap_or_else(take_error);
                return Err(io::Error::other(format!("TLS handshake failed: {why}")));
            }
            Ok(stream)
        }
    }

    #[derive(Debug)]
    pub struct Stream {
        ssl: NonNull<SSL>,
        socket: TcpStream,
    }

    // SAFETY: the SSL object is owned exclusively by this value and used
    // only through `&mut self`.
    unsafe impl Send for Stream {}

    impl Drop for Stream {
        fn drop(&mut self) {
            // SAFETY: a best-effort close_notify, then the SSL is freed once,
            // before the socket field closes the descriptor.
            unsafe {
                SSL_shutdown(self.ssl.as_ptr());
            }
            // SAFETY: as above.
            unsafe { SSL_free(self.ssl.as_ptr()) };
        }
    }

    impl Stream {
        pub fn socket(&self) -> &TcpStream {
            &self.socket
        }

        fn verify_error(&self) -> Option<String> {
            // SAFETY: the connection is live.
            let code = unsafe { SSL_get_verify_result(self.ssl.as_ptr()) };
            if code == X509_V_OK {
                return None;
            }
            // SAFETY: returns a static string for any code.
            let text = unsafe { X509_verify_cert_error_string(code) };
            if text.is_null() {
                return Some(format!("certificate error {code}"));
            }
            // SAFETY: a NUL-terminated static string.
            Some(unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned())
        }
    }

    impl io::Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
            // SAFETY: `buf` is writable for at least `n` bytes.
            let rc = unsafe { SSL_read(self.ssl.as_ptr(), buf.as_mut_ptr().cast(), n) };
            if rc > 0 {
                return Ok(usize::try_from(rc).unwrap_or(0));
            }
            // SAFETY: the connection is live and `rc` came from it.
            let code = unsafe { SSL_get_error(self.ssl.as_ptr(), rc) };
            // SAFETY: reads the calling thread's error queue.
            let reason = unsafe { ERR_peek_error() } & ERR_REASON_MASK;
            match code {
                SSL_ERROR_ZERO_RETURN => Ok(0),
                SSL_ERROR_SYSCALL if rc == 0 => Ok(0),
                // A peer that closes without close_notify: the end of the
                // body is framed by Content-Length, so this is just EOF.
                SSL_ERROR_SSL if reason == SSL_R_UNEXPECTED_EOF_WHILE_READING => {
                    let _ = take_error();
                    Ok(0)
                }
                _ => Err(io::Error::other(take_error())),
            }
        }
    }

    impl io::Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
            // SAFETY: `buf` is readable for at least `n` bytes.
            let rc = unsafe { SSL_write(self.ssl.as_ptr(), buf.as_ptr().cast(), n) };
            if rc > 0 {
                Ok(usize::try_from(rc).unwrap_or(0))
            } else {
                Err(io::Error::other(take_error()))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
