//! The few Windows calls the sync client needs that std does not wrap:
//! free disk space, and change notifications as a wake-up hint. kernel32 is
//! already linked by std on every Windows target.

use std::ffi::c_void;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

type Handle = *mut c_void;
const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
const WAIT_OBJECT_0: u32 = 0;
const WAIT_TIMEOUT: u32 = 0x102;
const FILE_NOTIFY_CHANGE_FILE_NAME: u32 = 0x1;
const FILE_NOTIFY_CHANGE_DIR_NAME: u32 = 0x2;
const FILE_NOTIFY_CHANGE_SIZE: u32 = 0x8;
const FILE_NOTIFY_CHANGE_LAST_WRITE: u32 = 0x10;

unsafe extern "system" {
    fn GetDiskFreeSpaceExW(
        dir: *const u16,
        avail: *mut u64,
        total: *mut u64,
        free: *mut u64,
    ) -> i32;
    fn FindFirstChangeNotificationW(path: *const u16, subtree: i32, filter: u32) -> Handle;
    fn FindNextChangeNotification(handle: Handle) -> i32;
    fn FindCloseChangeNotification(handle: Handle) -> i32;
    fn WaitForSingleObject(handle: Handle, ms: u32) -> u32;
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Space on the volume holding `path`, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsSpace {
    pub available: u64,
    pub total: u64,
}

pub fn fs_space(path: &Path) -> io::Result<FsSpace> {
    let w = wide(path);
    let (mut avail, mut total, mut free) = (0_u64, 0_u64, 0_u64);
    // SAFETY: `w` is NUL-terminated and the three outputs are writable.
    if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &raw mut avail, &raw mut total, &raw mut free) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(FsSpace { available: avail, total })
}

/// A recursive change notification on one directory tree.
#[derive(Debug)]
pub struct ChangeNotification(Handle);

// SAFETY: the handle is owned by this value and only waited on through it.
unsafe impl Send for ChangeNotification {}

impl Drop for ChangeNotification {
    fn drop(&mut self) {
        // SAFETY: the handle came from FindFirstChangeNotificationW and is
        // closed once.
        unsafe { FindCloseChangeNotification(self.0) };
    }
}

impl ChangeNotification {
    pub fn new(dir: &Path) -> io::Result<Self> {
        let w = wide(dir);
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE;
        // SAFETY: `w` is NUL-terminated; the result is checked.
        let h = unsafe { FindFirstChangeNotificationW(w.as_ptr(), 1, filter) };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(h))
    }

    /// Waits up to `ms`; true if something under the tree changed.
    pub fn wait(&mut self, ms: u32) -> io::Result<bool> {
        // SAFETY: the handle is live.
        match unsafe { WaitForSingleObject(self.0, ms) } {
            WAIT_OBJECT_0 => {
                // SAFETY: the handle is live; re-arms it for the next change.
                if unsafe { FindNextChangeNotification(self.0) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(true)
            }
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }
}
