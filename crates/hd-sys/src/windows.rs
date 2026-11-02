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
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetConsoleProcessList(list: *mut u32, count: u32) -> u32;
    fn FreeConsole() -> i32;
    fn SetStdHandle(which: u32, handle: Handle) -> i32;
    fn GetFileInformationByHandle(handle: Handle, info: *mut ByHandleFileInformation) -> i32;
    fn GetFileInformationByHandleEx(
        handle: Handle,
        class: u32,
        info: *mut c_void,
        size: u32,
    ) -> i32;
}

/// `BY_HANDLE_FILE_INFORMATION`.
#[repr(C)]
#[derive(Default)]
struct ByHandleFileInformation {
    attributes: u32,
    times: [u32; 6],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}

/// `FILE_BASIC_INFO`: four times, in 100 ns units since 1601, and the
/// attributes, padded to eight bytes.
#[repr(C)]
#[derive(Default)]
struct FileBasicInfo {
    creation: i64,
    access: i64,
    write: i64,
    change: i64,
    attributes: u32,
    pad: u32,
}

const _: () = assert!(size_of::<ByHandleFileInformation>() == 52);
const _: () = assert!(size_of::<FileBasicInfo>() == 40);

const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_ALL: u32 = 0x7;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_BASIC_INFO_CLASS: u32 = 0;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// From 1601 to 1970, in 100 ns units.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// What Unix's `stat` says about a file and std does not say on Windows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileStamp {
    /// When the file's content or metadata last changed, in nanoseconds
    /// since 1970. Unlike the modification time, no program can set it.
    pub change_ns: i64,
    /// The file's number on its volume.
    pub index: u64,
    pub volume: u64,
}

/// Everything a scan needs about a file, from one open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileFacts {
    pub stamp: FileStamp,
    pub size: u64,
    /// The modification time, in 100 ns units since 1970 (before it: 0).
    pub write_ticks: i64,
    pub directory: bool,
    /// A link or other reparse point, which only a closer look can tell.
    pub reparse_point: bool,
}

/// Reads the stamp of the file or folder at `path`, itself if it is a link.
pub fn file_stamp(path: &Path) -> io::Result<FileStamp> {
    file_facts(path).map(|f| f.stamp)
}

/// Reads the facts of the file or folder at `path`, itself if it is a link.
/// Asking only for attributes succeeds on a file another program has open
/// exclusively.
pub fn file_facts(path: &Path) -> io::Result<FileFacts> {
    let w = wide_long(path);
    // SAFETY: `w` is NUL-terminated; the other arguments are plain values
    // and the null pointers the call documents as optional.
    let handle = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_ALL,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let mut ids = ByHandleFileInformation::default();
    let mut basic = FileBasicInfo::default();
    // SAFETY: `handle` is open and `ids` is writable and of the size written.
    let got_ids = unsafe { GetFileInformationByHandle(handle, &raw mut ids) } != 0;
    // SAFETY: `handle` is open and `basic` is writable and of the size given.
    let got_basic = got_ids
        && unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_BASIC_INFO_CLASS,
                (&raw mut basic).cast(),
                size_of::<FileBasicInfo>() as u32,
            )
        } != 0;
    let error = io::Error::last_os_error();
    // SAFETY: `handle` is open and closed once.
    unsafe { CloseHandle(handle) };
    if !got_basic {
        return Err(error);
    }
    let write = i64::from(ids.times[5]) << 32 | i64::from(ids.times[4]);
    Ok(FileFacts {
        stamp: FileStamp {
            change_ns: basic.change.saturating_sub(UNIX_EPOCH_TICKS).saturating_mul(100),
            index: u64::from(ids.index_high) << 32 | u64::from(ids.index_low),
            volume: u64::from(ids.volume),
        },
        size: u64::from(ids.size_high) << 32 | u64::from(ids.size_low),
        write_ticks: write.saturating_sub(UNIX_EPOCH_TICKS).max(0),
        directory: ids.attributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        reparse_point: ids.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
    })
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
    let w = wide_long(path);
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

/// `path` for a call that takes a file's path, which fails past 260
/// characters without the `\\?\` prefix. std adds it to its own calls.
fn wide_long(path: &Path) -> Vec<u16> {
    let absolute = std::path::absolute(path).unwrap_or_else(|_| path.to_owned());
    let text: Vec<u16> = absolute.as_os_str().encode_wide().collect();
    let (back, colon) = (u16::from(b'\\'), u16::from(b':'));
    let (prefix, rest): (&str, &[u16]) = match text.as_slice() {
        [a, b, c, ..] if *a == back && *b == back && (*c == 0x3f || *c == 0x2e) => ("", &text),
        [a, b, rest @ ..] if *a == back && *b == back => ("\\\\?\\UNC\\", rest),
        [_, b, ..] if *b == colon => ("\\\\?\\", &text),
        _ => ("", &text),
    };
    prefix.encode_utf16().chain(rest.iter().copied()).chain(std::iter::once(0)).collect()
}

/// Renames `from` to `to`, failing with `AlreadyExists` rather than
/// replacing anything at `to`, and flushed before it returns.
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let (from, to) = (wide_long(from), wide_long(to));
    // SAFETY: both are NUL-terminated UTF-16 paths that outlive the call.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } != 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe extern "system" {
    fn ShellExecuteW(
        window: Handle,
        operation: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show: i32,
    ) -> Handle;
}

/// Opens `url` in the default browser.
pub fn open_url(url: &str) -> io::Result<()> {
    const SW_SHOWNORMAL: i32 = 1;
    let wide_str = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (operation, file) = (wide_str("open"), wide_str(url));
    // SAFETY: both strings are NUL-terminated and outlive the call; the
    // other pointers are the documented optional nulls.
    let done = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // Anything above 32 is success.
    if done as usize > 32 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Closes the console window if this process is the only one using it,
/// which is how a program started from Explorer or at sign-in runs; a command
/// prompt keeps its window. Output then goes to the file at `log`, or nowhere
/// if it cannot be opened: writing to a console that has gone fails, and Rust
/// ends the program over a failed print.
pub fn leave_own_console(log: &Path) {
    const STD_OUTPUT_HANDLE: u32 = 0xFFFF_FFF5;
    const STD_ERROR_HANDLE: u32 = 0xFFFF_FFF4;
    const FILE_APPEND_DATA: u32 = 0x4;
    const FILE_SHARE_ALL: u32 = 0x7;
    const OPEN_ALWAYS: u32 = 4;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    let mut list = [0_u32; 2];
    // SAFETY: `list` is writable for the two entries given.
    let processes = unsafe { GetConsoleProcessList(list.as_mut_ptr(), 2) };
    if processes > 1 {
        return;
    }
    // SAFETY: takes no arguments; failure only leaves the window open.
    unsafe { FreeConsole() };
    let open = |path: &[u16]| {
        // SAFETY: `path` is NUL-terminated; the rest are plain values and
        // the null pointers the call documents as optional.
        unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_APPEND_DATA,
                FILE_SHARE_ALL,
                std::ptr::null_mut(),
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        }
    };
    let mut output = open(&wide_long(log));
    if output == INVALID_HANDLE_VALUE {
        let nul: Vec<u16> = "NUL".encode_utf16().chain(std::iter::once(0)).collect();
        output = open(&nul);
    }
    // SAFETY: both are standard handle numbers; the handle stays open for
    // the life of the process.
    unsafe { SetStdHandle(STD_OUTPUT_HANDLE, output) };
    // SAFETY: as above.
    unsafe { SetStdHandle(STD_ERROR_HANDLE, output) };
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

/// Programs that start when this user signs in: values under
/// `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`. They need no
/// administrator, and apply to this user alone.
pub mod run_key {
    use super::{Handle, io};

    const HKEY_CURRENT_USER: Handle = 0x8000_0001_usize as Handle;
    const KEY_READ: u32 = 0x2_0019;
    const KEY_SET_VALUE: u32 = 0x2;
    const REG_SZ: u32 = 1;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const MAX_VALUE: usize = 2048;

    unsafe extern "system" {
        fn RegOpenKeyExW(
            key: Handle,
            sub: *const u16,
            options: u32,
            access: u32,
            out: *mut Handle,
        ) -> i32;
        fn RegCloseKey(key: Handle) -> i32;
        fn RegSetValueExW(
            key: Handle,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            size: u32,
        ) -> i32;
        fn RegQueryValueExW(
            key: Handle,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            size: *mut u32,
        ) -> i32;
        fn RegDeleteValueW(key: Handle, name: *const u16) -> i32;
    }

    fn wide_str(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn open(access: u32) -> io::Result<Handle> {
        let sub = wide_str("Software\\Microsoft\\Windows\\CurrentVersion\\Run");
        let mut key = std::ptr::null_mut();
        // SAFETY: `sub` is NUL-terminated and `key` is writable.
        let e = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, sub.as_ptr(), 0, access, &raw mut key) };
        if e == 0 { Ok(key) } else { Err(io::Error::from_raw_os_error(e)) }
    }

    fn close(key: Handle) {
        // SAFETY: `key` came from `open` and is closed once.
        unsafe { RegCloseKey(key) };
    }

    /// The command stored under `name`, if there is one.
    pub fn get(name: &str) -> io::Result<Option<String>> {
        let key = open(KEY_READ)?;
        let n = wide_str(name);
        let mut data = [0_u16; MAX_VALUE];
        let mut size = u32::try_from(size_of_val(&data)).unwrap_or(0);
        // SAFETY: the name is NUL-terminated, and `data` holds `size` bytes.
        let e = unsafe {
            RegQueryValueExW(
                key,
                n.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                data.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        close(key);
        match e {
            0 => {
                let chars = usize::try_from(size).unwrap_or(0) / 2;
                let text = &data[..chars.min(MAX_VALUE)];
                let end = text.iter().position(|c| *c == 0).unwrap_or(text.len());
                Ok(Some(String::from_utf16_lossy(&text[..end])))
            }
            ERROR_FILE_NOT_FOUND => Ok(None),
            e => Err(io::Error::from_raw_os_error(e)),
        }
    }

    /// Stores `command` under `name`.
    pub fn set(name: &str, command: &str) -> io::Result<()> {
        let key = open(KEY_SET_VALUE)?;
        let (n, value) = (wide_str(name), wide_str(command));
        let size = u32::try_from(size_of_val(value.as_slice()))
            .map_err(|_| io::Error::other("the command is too long"))?;
        // SAFETY: the name is NUL-terminated, and `value` holds `size` bytes.
        let e = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_SZ, value.as_ptr().cast(), size) };
        close(key);
        if e == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(e)) }
    }

    /// Removes `name`, which is no error if it is not there.
    pub fn delete(name: &str) -> io::Result<()> {
        let key = open(KEY_SET_VALUE)?;
        let n = wide_str(name);
        // SAFETY: the key is open and the name NUL-terminated.
        let e = unsafe { RegDeleteValueW(key, n.as_ptr()) };
        close(key);
        match e {
            0 | ERROR_FILE_NOT_FOUND => Ok(()),
            e => Err(io::Error::from_raw_os_error(e)),
        }
    }
}

/// The icon in the notification area: left-click opens the GUI, right-click
/// shows a menu, and it turns amber when something needs the user. Explorer
/// forgets icons when it restarts, so it is added again when it says so.
pub mod tray {
    use std::ffi::c_void;
    use std::io;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicUsize, Ordering};

    type Handle = *mut c_void;
    type WndProc = unsafe extern "system" fn(Handle, u32, usize, isize) -> isize;

    const WM_DESTROY: u32 = 0x2;
    const WM_COMMAND: u32 = 0x111;
    const WM_TIMER: u32 = 0x113;
    const WM_NULL: u32 = 0;
    const WM_APP: u32 = 0x8000;
    const WM_LBUTTONUP: u32 = 0x202;
    const WM_RBUTTONUP: u32 = 0x205;
    const WM_CONTEXTMENU: u32 = 0x7B;
    const CALLBACK: u32 = WM_APP + 1;
    const NIM_ADD: u32 = 0;
    const NIM_MODIFY: u32 = 1;
    const NIM_DELETE: u32 = 2;
    const NIF_MESSAGE: u32 = 1;
    const NIF_ICON: u32 = 2;
    const NIF_TIP: u32 = 4;
    const MF_STRING: u32 = 0;
    const TPM_RIGHTBUTTON: u32 = 2;
    const MENU_OPEN: usize = 1;
    const MENU_QUIT: usize = 2;
    const REFRESH_MS: u32 = 5000;
    const SIZE: i32 = 32;

    /// What the icon does; set once, by `run`.
    #[allow(missing_debug_implementations)]
    pub struct Actions {
        pub open: Box<dyn Fn() + Send + Sync>,
        pub quit: Box<dyn Fn() + Send + Sync>,
        pub needs_attention: Box<dyn Fn() -> bool + Send + Sync>,
    }

    static ACTIONS: OnceLock<Actions> = OnceLock::new();
    static WINDOW: AtomicIsize = AtomicIsize::new(0);
    static ICON_CALM: AtomicUsize = AtomicUsize::new(0);
    static ICON_ALERT: AtomicUsize = AtomicUsize::new(0);
    static ALERT: AtomicBool = AtomicBool::new(false);
    static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

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

    #[repr(C)]
    struct Msg {
        window: Handle,
        message: u32,
        w: usize,
        l: isize,
        time: u32,
        pt: [i32; 2],
        private: u32,
    }

    #[cfg(target_pointer_width = "64")]
    const _: () = assert!(
        size_of::<NotifyIconData>() == 976
            && size_of::<WndClassExW>() == 80
            && size_of::<Msg>() == 48
    );

    unsafe extern "system" {
        fn GetModuleHandleW(name: *const u16) -> Handle;
        fn RegisterClassExW(class: *const WndClassExW) -> u16;
        fn RegisterWindowMessageW(name: *const u16) -> u32;
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
        fn DefWindowProcW(window: Handle, msg: u32, w: usize, l: isize) -> isize;
        fn GetMessageW(msg: *mut Msg, window: Handle, min: u32, max: u32) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
        fn PostQuitMessage(code: i32);
        fn PostMessageW(window: Handle, msg: u32, w: usize, l: isize) -> i32;
        fn SetTimer(window: Handle, id: usize, ms: u32, callback: *const c_void) -> usize;
        fn CreateIcon(
            instance: Handle,
            width: i32,
            height: i32,
            planes: u8,
            bits: u8,
            and_mask: *const u8,
            colour: *const u8,
        ) -> Handle;
        fn CreatePopupMenu() -> Handle;
        fn AppendMenuW(menu: Handle, flags: u32, id: usize, text: *const u16) -> i32;
        fn TrackPopupMenu(
            menu: Handle,
            flags: u32,
            x: i32,
            y: i32,
            reserved: i32,
            window: Handle,
            rect: *const c_void,
        ) -> i32;
        fn DestroyMenu(menu: Handle) -> i32;
        fn GetCursorPos(point: *mut [i32; 2]) -> i32;
        fn SetForegroundWindow(window: Handle) -> i32;
        fn Shell_NotifyIconW(message: u32, data: *mut NotifyIconData) -> i32;
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A rounded square in `colour` (BGR) with a white house, 32 by 32.
    fn draw(colour: [u8; 3]) -> Vec<u8> {
        let mut pixels = Vec::with_capacity(4 * 32 * 32);
        for y in 0..32_i32 {
            for x in 0..32_i32 {
                let corner =
                    ((x - 15).abs() - 11).max(0).pow(2) + ((y - 15).abs() - 11).max(0).pow(2);
                let inside = (2..=29).contains(&x) && (2..=29).contains(&y) && corner <= 16;
                let roof = (7..=15).contains(&y) && (x - 15).abs() <= y - 6;
                let walls = (15..=24).contains(&y) && (8..=22).contains(&x);
                let door = (18..=24).contains(&y) && (13..=17).contains(&x);
                let white = (roof || walls) && !door;
                pixels.extend_from_slice(&match (inside, white) {
                    (false, _) => [0, 0, 0, 0],
                    (true, true) => [255, 255, 255, 255],
                    (true, false) => [colour[0], colour[1], colour[2], 255],
                });
            }
        }
        pixels
    }

    fn make_icon(instance: Handle, colour: [u8; 3]) -> Handle {
        let pixels = draw(colour);
        let mask = [0_u8; 4 * 32];
        // SAFETY: `pixels` is 32 by 32 at 32 bits, and `mask` 32 by 32 at
        // one bit, in rows of four bytes. CreateIcon copies them.
        unsafe { CreateIcon(instance, SIZE, SIZE, 1, 32, mask.as_ptr(), pixels.as_ptr()) }
    }

    fn data(flags: u32, alert: bool) -> NotifyIconData {
        let icon = if alert { &ICON_ALERT } else { &ICON_CALM };
        let mut tip = [0_u16; 128];
        let text = if alert { "homedrive: something needs you" } else { "homedrive" };
        for (slot, c) in tip.iter_mut().zip(text.encode_utf16()) {
            *slot = c;
        }
        NotifyIconData {
            cb_size: u32::try_from(size_of::<NotifyIconData>()).unwrap_or(0),
            window: WINDOW.load(Ordering::Acquire) as Handle,
            id: 1,
            flags,
            callback_message: CALLBACK,
            icon: icon.load(Ordering::Acquire) as Handle,
            tip,
            state: 0,
            state_mask: 0,
            info: [0; 256],
            timeout_or_version: 0,
            info_title: [0; 64],
            info_flags: 0,
            guid: [0; 4],
            balloon_icon: std::ptr::null_mut(),
        }
    }

    fn apply(message: u32) -> bool {
        let mut d = data(NIF_MESSAGE | NIF_ICON | NIF_TIP, ALERT.load(Ordering::Acquire));
        // SAFETY: `d` is a complete NOTIFYICONDATAW for the tray's window.
        unsafe { Shell_NotifyIconW(message, &raw mut d) != 0 }
    }

    /// Takes the icon away; it would otherwise linger until the mouse
    /// passes over it.
    pub fn remove() {
        if WINDOW.load(Ordering::Acquire) != 0 {
            apply(NIM_DELETE);
        }
    }

    fn add_item(menu: Handle, id: usize, text: &str) {
        let text = wide(text);
        // SAFETY: `menu` is live and `text` NUL-terminated; it is copied.
        unsafe { AppendMenuW(menu, MF_STRING, id, text.as_ptr()) };
    }

    fn show_menu(window: Handle) {
        // SAFETY: takes no arguments; the menu is destroyed below.
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        add_item(menu, MENU_OPEN, "Open homedrive");
        add_item(menu, MENU_QUIT, "Quit homedrive");
        let mut point = [0_i32; 2];
        // SAFETY: `point` is writable.
        unsafe { GetCursorPos(&raw mut point) };
        // Windows needs the window in the foreground, and the WM_NULL after,
        // for the menu to close when the user clicks elsewhere.
        // SAFETY: `window` is the tray's own.
        unsafe { SetForegroundWindow(window) };
        // SAFETY: `menu` and `window` are live; no rectangle is passed.
        unsafe {
            TrackPopupMenu(menu, TPM_RIGHTBUTTON, point[0], point[1], 0, window, std::ptr::null())
        };
        // SAFETY: `window` is the tray's own.
        unsafe { PostMessageW(window, WM_NULL, 0, 0) };
        // SAFETY: `menu` was made above and is destroyed once.
        unsafe { DestroyMenu(menu) };
    }

    unsafe extern "system" fn window_proc(w: Handle, msg: u32, wp: usize, lp: isize) -> isize {
        let Some(actions) = ACTIONS.get() else {
            // SAFETY: the arguments are the system's, passed on unchanged.
            return unsafe { DefWindowProcW(w, msg, wp, lp) };
        };
        match msg {
            CALLBACK => match u32::try_from(lp & 0xFFFF).unwrap_or(0) {
                WM_LBUTTONUP => (actions.open)(),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(w),
                _ => {}
            },
            WM_COMMAND => match wp & 0xFFFF {
                MENU_OPEN => (actions.open)(),
                MENU_QUIT => {
                    remove();
                    (actions.quit)();
                }
                _ => {}
            },
            WM_TIMER => {
                let alert = (actions.needs_attention)();
                if ALERT.swap(alert, Ordering::AcqRel) != alert {
                    apply(NIM_MODIFY);
                }
            }
            WM_DESTROY => {
                remove();
                // SAFETY: takes a plain exit code.
                unsafe { PostQuitMessage(0) };
            }
            m if m == TASKBAR_CREATED.load(Ordering::Acquire) && m != 0 => {
                apply(NIM_ADD);
            }
            _ => {
                // SAFETY: the arguments are the system's, passed on unchanged.
                return unsafe { DefWindowProcW(w, msg, wp, lp) };
            }
        }
        0
    }

    /// Shows the icon and handles its messages until the process ends. Call
    /// it from a thread of its own, once.
    pub fn run(actions: Actions) -> io::Result<()> {
        if ACTIONS.set(actions).is_err() {
            return Err(io::Error::other("the tray is already running"));
        }
        let class = wide("homedrive-tray");
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
        // SAFETY: `wc` and the class name outlive the call.
        if unsafe { RegisterClassExW(&raw const wc) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the name is NUL-terminated.
        let created = unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) };
        TASKBAR_CREATED.store(created, Ordering::Release);
        ICON_CALM.store(make_icon(instance, [0xEB, 0x6F, 0x1F]) as usize, Ordering::Release);
        ICON_ALERT.store(make_icon(instance, [0x00, 0x8A, 0xD9]) as usize, Ordering::Release);
        // SAFETY: the class is registered. A window that is never shown:
        // a message-only one could not own the menu.
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
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null_mut(),
            )
        };
        if window.is_null() {
            return Err(io::Error::last_os_error());
        }
        WINDOW.store(window as isize, Ordering::Release);
        if !apply(NIM_ADD) {
            return Err(io::Error::other("the notification area refused the icon"));
        }
        // SAFETY: the window is ours; a null callback means WM_TIMER.
        unsafe { SetTimer(window, 1, REFRESH_MS, std::ptr::null()) };
        let mut msg = Msg {
            window: std::ptr::null_mut(),
            message: 0,
            w: 0,
            l: 0,
            time: 0,
            pt: [0; 2],
            private: 0,
        };
        // SAFETY: `msg` is writable and this thread owns the window.
        while unsafe { GetMessageW(&raw mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
            // SAFETY: `msg` came from GetMessageW.
            unsafe { TranslateMessage(&raw const msg) };
            // SAFETY: as above.
            unsafe { DispatchMessageW(&raw const msg) };
        }
        Ok(())
    }
}
