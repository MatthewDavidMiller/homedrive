//! The C library calls std does not wrap: getrandom(2), kill(2), statvfs(3)
//! for the store's free-space reserve, and the signal mask and sigwait(3)
//! that let a dedicated thread take SIGTERM (as PID 1 in a container, an
//! unhandled SIGTERM is ignored).

use std::ffi::{CString, c_char, c_int, c_uint, c_void};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

pub type pid_t = c_int;
pub type ssize_t = isize;

#[cfg(target_arch = "x86_64")]
pub const O_DIRECTORY: c_int = 0o200_000;
#[cfg(target_arch = "x86_64")]
pub const O_NOFOLLOW: c_int = 0o400_000;
#[cfg(target_arch = "aarch64")]
pub const O_DIRECTORY: c_int = 0o40_000;
#[cfg(target_arch = "aarch64")]
pub const O_NOFOLLOW: c_int = 0o100_000;

pub const EINTR: i32 = 4;
pub const ESRCH: i32 = 3;
pub const EEXIST: i32 = 17;

pub const SIGINT: c_int = 2;
pub const SIGKILL: c_int = 9;
pub const SIGTERM: c_int = 15;
const SIG_BLOCK: c_int = 0;

/// The C library's signal set: 1024 bits on Linux in both musl and glibc.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct sigset_t {
    bits: [u64; 16],
}

/// The leading fields of `struct statvfs`, which musl and glibc lay out
/// alike on 64-bit Linux (every count is 64 bits wide), followed by more
/// spare room than either library's trailing fields need.
#[repr(C)]
#[derive(Debug)]
// The C library fills every field; only the ones fs_space reports are read.
#[allow(dead_code)]
struct statvfs_t {
    f_bsize: u64,
    f_frsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_favail: u64,
    _rest: [u64; 24],
}

unsafe extern "C" {
    fn statvfs(path: *const c_char, buf: *mut statvfs_t) -> c_int;
    fn getrandom(buf: *mut c_void, len: usize, flags: c_uint) -> ssize_t;
    fn kill(pid: pid_t, sig: c_int) -> c_int;
    fn sigemptyset(set: *mut sigset_t) -> c_int;
    fn sigaddset(set: *mut sigset_t, sig: c_int) -> c_int;
    fn pthread_sigmask(how: c_int, set: *const sigset_t, old: *mut sigset_t) -> c_int;
    fn sigwait(set: *const sigset_t, sig: *mut c_int) -> c_int;
}

/// Fills `buf` from the kernel's random source, retrying on interruption.
pub fn fill_random(buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let rest = &mut buf[done..];
        // SAFETY: `rest` is a valid, writable region of `rest.len()` bytes.
        let n = unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(EINTR) {
                continue;
            }
            return Err(err);
        }
        done += n.unsigned_abs();
    }
    Ok(())
}

/// Space on the filesystem holding `path`, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsSpace {
    /// Available to an unprivileged process (statvfs `f_bavail`).
    pub available: u64,
    pub total: u64,
}

/// statvfs(3) for `path`.
pub fn fs_space(path: &Path) -> io::Result<FsSpace> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: the struct is plain integers, so all zeroes is a valid value.
    let mut buf: statvfs_t = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path and `buf` is writable and larger
    // than the C library's struct statvfs.
    if unsafe { statvfs(c.as_ptr(), &raw mut buf) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let unit = buf.f_frsize;
    Ok(FsSpace {
        available: buf.f_bavail.saturating_mul(unit),
        total: buf.f_blocks.saturating_mul(unit),
    })
}

/// Sends `sig` to a process (`pid` > 0) or a whole process group (`pid` < 0).
pub fn send_signal(pid: pid_t, sig: c_int) -> io::Result<()> {
    // SAFETY: kill takes plain integers and has no memory effects.
    if unsafe { kill(pid, sig) } == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// SIGTERM and SIGINT, to be blocked in every thread and taken by one.
#[derive(Clone, Copy, Debug)]
pub struct TerminationSignals(sigset_t);

impl TerminationSignals {
    pub fn new() -> io::Result<Self> {
        let mut set = sigset_t { bits: [0; 16] };
        // SAFETY: `set` is a valid, writable sigset_t.
        if unsafe { sigemptyset(&raw mut set) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for sig in [SIGTERM, SIGINT] {
            // SAFETY: `set` is an initialised sigset_t; `sig` is a valid signal.
            if unsafe { sigaddset(&raw mut set, sig) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self(set))
    }

    /// Blocks the signals in the calling thread, and so in every thread it
    /// starts afterwards. Call it first thing in `main`.
    pub fn block(&self) -> io::Result<()> {
        // SAFETY: the set is initialised; the old mask is not wanted.
        let rc = unsafe { pthread_sigmask(SIG_BLOCK, &raw const self.0, ptr::null_mut()) };
        if rc == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(rc)) }
    }

    /// Waits until one of the (blocked) signals is pending and takes it.
    pub fn wait(&self) -> io::Result<c_int> {
        let mut sig: c_int = 0;
        // SAFETY: the set is initialised and `sig` is writable.
        let rc = unsafe { sigwait(&raw const self.0, &raw mut sig) };
        if rc == 0 { Ok(sig) } else { Err(io::Error::from_raw_os_error(rc)) }
    }
}

/// inotify(7), as a wake-up hint for the sync client: something under a
/// watched directory changed. The client always rescans to learn what, so
/// event details (and overflow) do not matter.
#[cfg(target_os = "linux")]
pub mod inotify {
    use std::ffi::{CString, c_char, c_int, c_short, c_uint, c_ulong};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const IN_CLOEXEC: c_int = 0o2_000_000;
    const IN_NONBLOCK: c_int = 0o4_000;
    const IN_MODIFY: u32 = 0x2;
    const IN_ATTRIB: u32 = 0x4;
    const IN_CLOSE_WRITE: u32 = 0x8;
    const IN_MOVED_FROM: u32 = 0x40;
    const IN_MOVED_TO: u32 = 0x80;
    const IN_CREATE: u32 = 0x100;
    const IN_DELETE: u32 = 0x200;
    const IN_DELETE_SELF: u32 = 0x400;
    const IN_MOVE_SELF: u32 = 0x800;
    const IN_ONLYDIR: u32 = 0x0100_0000;
    const IN_DONT_FOLLOW: u32 = 0x0200_0000;
    const POLLIN: c_short = 1;

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }

    unsafe extern "C" {
        fn inotify_init1(flags: c_int) -> c_int;
        fn inotify_add_watch(fd: c_int, path: *const c_char, mask: c_uint) -> c_int;
        fn poll(fds: *mut PollFd, n: c_ulong, timeout: c_int) -> c_int;
    }

    #[derive(Debug)]
    pub struct Inotify {
        file: File,
    }

    impl Inotify {
        pub fn new() -> io::Result<Self> {
            // SAFETY: no pointers; returns a new descriptor or -1.
            let fd = unsafe { inotify_init1(IN_CLOEXEC | IN_NONBLOCK) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` is a fresh descriptor this value now owns.
            Ok(Self { file: unsafe { File::from_raw_fd(fd) } })
        }

        /// Watches one directory (not recursively).
        pub fn watch_dir(&self, dir: &Path) -> io::Result<()> {
            let c = CString::new(dir.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
            let mask = IN_MODIFY
                | IN_ATTRIB
                | IN_CLOSE_WRITE
                | IN_MOVED_FROM
                | IN_MOVED_TO
                | IN_CREATE
                | IN_DELETE
                | IN_DELETE_SELF
                | IN_MOVE_SELF
                | IN_ONLYDIR
                | IN_DONT_FOLLOW;
            // SAFETY: the descriptor is live and `c` NUL-terminated.
            if unsafe { inotify_add_watch(self.file.as_raw_fd(), c.as_ptr(), mask) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// Waits up to `timeout_ms` for an event; true if any arrived. The
        /// events are read and discarded.
        pub fn wait(&mut self, timeout_ms: i32) -> io::Result<bool> {
            let mut p = PollFd { fd: self.file.as_raw_fd(), events: POLLIN, revents: 0 };
            // SAFETY: `p` is one valid pollfd.
            let rc = unsafe { poll(&raw mut p, 1, timeout_ms) };
            if rc < 0 {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted { Ok(false) } else { Err(e) };
            }
            if rc == 0 {
                return Ok(false);
            }
            let mut buf = [0_u8; 4096];
            loop {
                match self.file.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            Ok(true)
        }
    }
}
