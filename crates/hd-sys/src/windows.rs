//! The few Windows calls the sync client needs that std does not wrap:
//! free disk space, a rename that never replaces (for FAT and exFAT disks,
//! which have no hard links), listing a file's alternate data streams (so a
//! replaced file keeps them), change notifications as a wake-up hint, and
//! desktop notifications. kernel32 is already linked by std on every Windows
//! target; user32 and shell32 are linked by the build script.

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
    fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    fn FindFirstStreamW(
        path: *const u16,
        level: u32,
        data: *mut FindStreamData,
        flags: u32,
    ) -> Handle;
    fn FindNextStreamW(handle: Handle, data: *mut FindStreamData) -> i32;
    fn FindClose(handle: Handle) -> i32;
}

/// `WIN32_FIND_STREAM_DATA`: a stream's size and its name, as
/// ":name:$DATA" (MAX_PATH + 36 characters at most).
#[repr(C)]
struct FindStreamData {
    size: i64,
    name: [u16; 296],
}

const FIND_STREAM_INFO_STANDARD: u32 = 0;
const ERROR_HANDLE_EOF: i32 = 38;

/// The names of `path`'s alternate data streams (not the file's content,
/// the unnamed stream). A volume without streams (FAT, exFAT) has none.
pub fn alternate_streams(path: &Path) -> io::Result<Vec<String>> {
    let w = wide(path);
    let mut data = FindStreamData { size: 0, name: [0; 296] };
    // SAFETY: `w` is a NUL-terminated path; `data` is writable and the size
    // FindStreamInfoStandard writes.
    let handle =
        unsafe { FindFirstStreamW(w.as_ptr(), FIND_STREAM_INFO_STANDARD, &raw mut data, 0) };
    if handle == INVALID_HANDLE_VALUE {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            // No streams at all, or a filesystem without them.
            Some(ERROR_HANDLE_EOF | 1 | 50) => Ok(Vec::new()),
            _ => Err(e),
        };
    }
    let mut out = Vec::new();
    loop {
        let len = data.name.iter().position(|c| *c == 0).unwrap_or(data.name.len());
        let full = String::from_utf16_lossy(&data.name[..len]);
        if let Some(name) = full.strip_prefix(':').and_then(|n| n.strip_suffix(":$DATA"))
            && !name.is_empty()
        {
            out.push(name.to_owned());
        }
        // SAFETY: `handle` is the open search; `data` is writable.
        if unsafe { FindNextStreamW(handle, &raw mut data) } == 0 {
            break;
        }
    }
    // SAFETY: `handle` is the open search, closed once.
    unsafe { FindClose(handle) };
    Ok(out)
}

/// Flushes the rename to disk before returning; without
/// `MOVEFILE_REPLACE_EXISTING`, an existing target makes it fail.
const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Renames `from` to `to`, failing with `AlreadyExists` rather than
/// replacing anything at `to`, and flushed before it returns.
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (wide(from), wide(to));
    // SAFETY: both are NUL-terminated UTF-16 paths that outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
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

/// Desktop notifications: a notification-area icon with a balloon, which
/// Windows 10 and 11 show as a toast. No message loop is needed to show it.
pub mod notify {
    use std::ffi::c_void;
    use std::io;
    use std::time::Duration;

    type Handle = *mut c_void;
    type WndProc = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

    const HWND_MESSAGE: Handle = -3_isize as Handle;
    const NIM_ADD: u32 = 0;
    const NIM_MODIFY: u32 = 1;
    const NIM_DELETE: u32 = 2;
    const NIF_ICON: u32 = 0x2;
    const NIF_TIP: u32 = 0x4;
    const NIF_INFO: u32 = 0x10;
    const NIIF_INFO: u32 = 0x1;
    const NIIF_WARNING: u32 = 0x2;
    const IDI_WARNING: usize = 32515;
    const IDI_INFORMATION: usize = 32516;
    /// How long the icon stays, so the balloon can be read and clicked.
    const SHOWN_FOR: Duration = Duration::from_secs(20);

    #[repr(C)]
    struct WndClassExW {
        cb_size: u32,
        style: u32,
        wnd_proc: Option<WndProc>,
        cls_extra: i32,
        wnd_extra: i32,
        instance: Handle,
        icon: Handle,
        cursor: Handle,
        background: Handle,
        menu_name: *const u16,
        class_name: *const u16,
        icon_small: Handle,
    }

    /// NOTIFYICONDATAW, in full (Vista and later).
    #[repr(C)]
    struct NotifyIconData {
        cb_size: u32,
        window: Handle,
        id: u32,
        flags: u32,
        callback_message: u32,
        icon: Handle,
        tip: [u16; 128],
        state: u32,
        state_mask: u32,
        info: [u16; 256],
        timeout_or_version: u32,
        info_title: [u16; 64],
        info_flags: u32,
        guid: [u32; 4],
        balloon_icon: Handle,
    }

    // The sizes Windows documents for 64-bit, so a layout mistake fails the
    // build rather than the call.
    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(size_of::<NotifyIconData>() == 976 && size_of::<WndClassExW>() == 80);

    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn RegisterClassExW(class: *const WndClassExW) -> u16;
        fn CreateWindowExW(
            ex_style: u32,
            class: *const u16,
            name: *const u16,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: Handle,
            menu: Handle,
            instance: Handle,
            param: *mut c_void,
        ) -> Handle;
        fn DestroyWindow(window: Handle) -> i32;
        fn DefWindowProcW(window: Handle, msg: u32, w: usize, l: isize) -> isize;
        fn LoadIconW(instance: Handle, name: *const u16) -> Handle;
        fn Shell_NotifyIconW(message: u32, data: *mut NotifyIconData) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Copies `s` into a fixed buffer, cut to fit with its NUL.
    fn fill<const N: usize>(s: &str) -> [u16; N] {
        let mut out = [0_u16; N];
        for (slot, c) in out.iter_mut().take(N - 1).zip(s.encode_utf16()) {
            *slot = c;
        }
        out
    }

    unsafe extern "system" fn window_proc(w: Handle, msg: u32, wp: usize, lp: isize) -> isize {
        // SAFETY: the arguments are the system's, passed on unchanged.
        unsafe { DefWindowProcW(w, msg, wp, lp) }
    }

    /// Shows a notification. It is shown from a thread of its own, which
    /// removes the icon after a while; this returns at once.
    pub fn show(title: &str, body: &str, urgent: bool) -> io::Result<()> {
        let title = title.to_owned();
        let body = body.to_owned();
        std::thread::Builder::new()
            .name("notify".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                if let Err(e) = show_now(&title, &body, urgent) {
                    eprintln!("homedrive: a desktop notification failed: {e}");
                }
            })
            .map(|_| ())
    }

    fn show_now(title: &str, body: &str, urgent: bool) -> io::Result<()> {
        let class = wide("homedrive-notify");
        // SAFETY: a null name asks for this program's own module.
        let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
        let wc = WndClassExW {
            cb_size: u32::try_from(size_of::<WndClassExW>()).unwrap_or(0),
            style: 0,
            wnd_proc: Some(window_proc),
            cls_extra: 0,
            wnd_extra: 0,
            instance,
            icon: std::ptr::null_mut(),
            cursor: std::ptr::null_mut(),
            background: std::ptr::null_mut(),
            menu_name: std::ptr::null(),
            class_name: class.as_ptr(),
            icon_small: std::ptr::null_mut(),
        };
        // SAFETY: `wc` and the class name outlive the call. Registering a
        // second time fails harmlessly: the class is already there.
        unsafe { RegisterClassExW(&raw const wc) };
        // SAFETY: the class is registered; a message-only window needs no
        // size, menu or parameters.
        let window = unsafe {
            CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                std::ptr::null_mut(),
                instance,
                std::ptr::null_mut(),
            )
        };
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        let stock = if urgent { IDI_WARNING } else { IDI_INFORMATION };
        // SAFETY: a stock icon, named by its resource number.
        let icon = unsafe { LoadIconW(std::ptr::null_mut(), stock as *const u16) };
        let mut data = NotifyIconData {
            cb_size: u32::try_from(size_of::<NotifyIconData>()).unwrap_or(0),
            window,
            id: 1,
            flags: NIF_ICON | NIF_TIP,
            callback_message: 0,
            icon,
            tip: fill("homedrive"),
            state: 0,
            state_mask: 0,
            info: [0; 256],
            timeout_or_version: 0,
            info_title: [0; 64],
            info_flags: 0,
            guid: [0; 4],
            balloon_icon: std::ptr::null_mut(),
        };
        // SAFETY: `data` is a complete NOTIFYICONDATAW for `window`.
        if unsafe { Shell_NotifyIconW(NIM_ADD, &raw mut data) } == 0 {
            // SAFETY: the window was made above and is destroyed once.
            unsafe { DestroyWindow(window) };
            return Err(io::Error::other("the notification area refused the icon"));
        }
        data.flags = NIF_INFO;
        data.info = fill(body);
        data.info_title = fill(title);
        data.info_flags = if urgent { NIIF_WARNING } else { NIIF_INFO };
        // SAFETY: as above; the icon was added.
        let shown = unsafe { Shell_NotifyIconW(NIM_MODIFY, &raw mut data) } != 0;
        std::thread::sleep(SHOWN_FOR);
        // SAFETY: the icon was added above and is removed once.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &raw mut data) };
        // SAFETY: the window was made above and is destroyed once.
        unsafe { DestroyWindow(window) };
        if shown { Ok(()) } else { Err(io::Error::other("the balloon was refused")) }
    }
}
