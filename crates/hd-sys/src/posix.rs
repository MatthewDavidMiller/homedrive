//! The C library calls std does not wrap: getrandom(2), kill(2) for process
//! groups, and the signal mask and sigwait(3) that let a dedicated thread
//! take SIGTERM (as PID 1 in a container, an unhandled SIGTERM is ignored).

use std::ffi::{c_int, c_uint, c_void};
use std::io;
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

unsafe extern "C" {
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
