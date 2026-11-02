//! Letting everything else on the computer go first. A sync can wait, and
//! whatever the person at the computer is doing cannot. This only changes who
//! gets the processor and the disk when both want them, so on a quiet
//! computer a sync runs as fast as ever.

use std::io;

#[cfg(target_os = "linux")]
mod os {
    use std::ffi::{c_int, c_long, c_uint};
    use std::io;

    const PRIO_PROCESS: c_int = 0;
    /// `nice` for a program that yields to anything ordinary.
    const NICE: c_int = 10;
    const SYS_IOPRIO_SET: c_long = 251;
    const SYS_IOPRIO_GET: c_long = 252;
    const IOPRIO_WHO_PROCESS: c_long = 1;
    const THIS_THREAD: c_long = 0;
    const IOPRIO_CLASS_IDLE: c_long = 3;
    const IOPRIO_CLASS_SHIFT: c_long = 13;

    unsafe extern "C" {
        fn setpriority(which: c_int, who: c_uint, priority: c_int) -> c_int;
        fn getpriority(which: c_int, who: c_uint) -> c_int;
        fn syscall(number: c_long, ...) -> c_long;
    }

    pub(super) fn enter() -> io::Result<()> {
        // SAFETY: plain values; 0 means the calling thread.
        if unsafe { setpriority(PRIO_PROCESS, 0, NICE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let idle = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
        // SAFETY: plain values; 0 means the calling thread.
        if unsafe { syscall(SYS_IOPRIO_SET, IOPRIO_WHO_PROCESS, THIS_THREAD, idle) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn active() -> bool {
        // SAFETY: plain values; 0 means the calling thread.
        let nice = unsafe { getpriority(PRIO_PROCESS, 0) };
        // SAFETY: plain values; 0 means the calling thread.
        let io = unsafe { syscall(SYS_IOPRIO_GET, IOPRIO_WHO_PROCESS, THIS_THREAD) };
        nice >= NICE && io >> IOPRIO_CLASS_SHIFT == IOPRIO_CLASS_IDLE
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use std::io;

    type Handle = *mut c_void;

    const PROCESS_MODE_BACKGROUND_BEGIN: u32 = 0x0010_0000;
    const ERROR_PROCESS_MODE_ALREADY_BACKGROUND: i32 = 402;
    const PROCESS_MEMORY_PRIORITY: u32 = 0;
    /// What background mode lowers memory priority to, or below.
    const MEMORY_PRIORITY_LOW: u32 = 2;

    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn SetPriorityClass(process: Handle, class: u32) -> i32;
        fn GetProcessInformation(process: Handle, class: u32, info: *mut c_void, size: u32) -> i32;
    }

    pub(super) fn enter() -> io::Result<()> {
        // SAFETY: takes nothing, and gives the constant for this process.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is this process, and the flag is a plain value.
        if unsafe { SetPriorityClass(process, PROCESS_MODE_BACKGROUND_BEGIN) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PROCESS_MODE_ALREADY_BACKGROUND) {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(super) fn active() -> bool {
        let mut priority = u32::MAX;
        // SAFETY: takes nothing, and gives the constant for this process.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: `process` is this process, and `priority` is writable and
        // of the size given.
        let read = unsafe {
            GetProcessInformation(
                process,
                PROCESS_MEMORY_PRIORITY,
                (&raw mut priority).cast(),
                size_of::<u32>() as u32,
            )
        };
        read != 0 && priority <= MEMORY_PRIORITY_LOW
    }
}

/// Puts this process behind everything else for the processor and the disk.
/// On Linux it covers the calling thread and the threads it starts from then
/// on, so call it before starting any.
pub fn enter() -> io::Result<()> {
    os::enter()
}

/// Whether [`enter`] has taken effect here.
pub fn active() -> bool {
    os::active()
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    /// On Linux this is per thread, so a thread of its own keeps the rest of
    /// the test run out of it.
    #[test]
    fn it_takes_effect_and_threads_started_after_it_inherit_it() {
        std::thread::spawn(|| {
            assert!(!active());
            enter().unwrap();
            assert!(active());
            enter().unwrap();
            assert!(std::thread::spawn(active).join().unwrap());
        })
        .join()
        .unwrap();
        assert!(std::thread::spawn(active).join().is_ok_and(|a| !a), "it stayed in that thread");
    }
}
