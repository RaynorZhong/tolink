//! Native Windows handles and ACLs. Readonly attributes are never a privacy check.
use std::{
    ffi::c_void,
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE, LocalFree},
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub(crate) struct PrivateDir {
    pub(crate) path: std::path::PathBuf,
    _pins: Vec<File>,
}
fn invalid_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unsafe Windows path refused")
}
fn checked_path(path: &Path) -> io::Result<std::path::PathBuf> {
    use std::path::{Component, Prefix};
    // Reject DOS aliases before absolute() can normalize them. Only local disk
    // namespaces are allowed: no UNC, device, pipe, ADS or traversal components.
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
                _ => return Err(invalid_path()),
            },
            Component::ParentDir => {}
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                if text.ends_with(['.', ' '])
                    || text.chars().any(|c| c < ' ' || "<>:\"|?*".contains(c))
                {
                    return Err(invalid_path());
                }
                let base = text.split('.').next().unwrap_or("").to_ascii_uppercase();
                if matches!(
                    base.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|p| {
                    base.strip_prefix(p).is_some_and(|n| {
                        matches!(
                            n,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                }) {
                    return Err(invalid_path());
                }
            }
            _ => {}
        }
    }
    let absolute = std::path::absolute(path)?;
    let mut path = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                path.pop();
            }
            Component::CurDir => {}
            _ => path.push(component.as_os_str()),
        }
    }
    if !matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
    {
        return Err(invalid_path());
    }
    wide(&path)?;
    Ok(path)
}
fn pin_dirs(path: &Path) -> io::Result<PrivateDir> {
    use std::path::Component;
    let path = checked_path(path)?;
    let mut prefix = std::path::PathBuf::new();
    let mut pins = Vec::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Normal(_)) {
            // Sharing excludes DELETE, so no checked ancestor can be renamed or
            // replaced until the operation (or the Client guard) has completed.
            let file = open(
                &prefix,
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                OPEN_EXISTING,
                None,
            )?;
            if info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                return Err(invalid_path());
            }
            pins.push(file);
        }
    }
    Ok(PrivateDir { path, _pins: pins })
}
pub(crate) fn pin_private_dir(path: &Path) -> io::Result<PrivateDir> {
    let guard = pin_dirs(path)?;
    let file = guard._pins.last().ok_or_else(invalid_path)?;
    if checked_privacy(file, true)? != (true, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory must have a protected current-user-only DACL and be owned by current user",
        ));
    }
    Ok(guard)
}

#[cfg(test)]
#[test]
fn native_acl_refuses_unprotected_private_boundary() {
    let root = super::tests::Fixture::new();
    let path = root.0.join("inheritance-enabled-boundary");
    let descriptor = inherited_fixture_sd().unwrap();
    let native_path = wide(&path).unwrap();
    assert_ne!(
        unsafe { CreateDirectoryW(native_path.as_ptr(), &attributes(&descriptor)) },
        0,
        "{}",
        io::Error::last_os_error()
    );
    let candidate = pin_dirs(&path).unwrap();
    assert_eq!(
        privacy(candidate._pins.last().unwrap()).unwrap(),
        (true, true)
    );
    drop(candidate);
    match pin_private_dir(&path) {
        Ok(_) => panic!("current-user-only DACL did not establish a protected boundary"),
        Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
    }
}

pub(crate) fn read_key(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let path = checked_path(path)?;
    let _parents = pin_private_dir(path.parent().ok_or_else(invalid_path)?)?;
    let mut file = open(
        &path,
        GENERIC_READ | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_EXISTING,
        None,
    )?;
    if regular_info(&file)?.nNumberOfLinks != 1 || privacy(&file)? != (true, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "key must be a private, owned regular file without aliases",
        ));
    }
    // Admission and content read use this same deny-write/delete handle.
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key exceeds local bound",
        ));
    }
    Ok(bytes)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity(pub u64, pub u64);
pub(crate) struct KeyMetadata {
    pub(crate) identity: FileIdentity,
    pub(crate) private: bool,
    pub(crate) owner: bool,
    _file: File,
    _parents: PrivateDir,
}
struct LocalMemory(*mut c_void);
impl Drop for LocalMemory {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut raw: Vec<u16> = path.as_os_str().encode_wide().collect();
    if raw.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"));
    }
    raw.push(0);
    Ok(raw)
}
fn current_sid() -> io::Result<Vec<usize>> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut data = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(data)
}
fn sid(data: &[usize]) -> PSID {
    unsafe { (*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid }
}
fn current_sid_string() -> io::Result<String> {
    let current = current_sid()?;
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid(&current), &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let text_memory = LocalMemory(text.cast());
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let current = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) });
    drop(text_memory);
    current.map_err(io::Error::other)
}
fn descriptor_from_sddl(sddl: &str) -> io::Result<LocalMemory> {
    let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalMemory(descriptor))
}
fn private_sd() -> io::Result<LocalMemory> {
    let current = current_sid_string()?;
    // No SYSTEM or Administrators grants, inherited or explicit.
    descriptor_from_sddl(&format!("O:{current}D:P(A;OICI;FA;;;{current})"))
}
#[cfg(test)]
fn inherited_fixture_sd() -> io::Result<LocalMemory> {
    // TokenOwner can differ from TokenUser on CI. Supply only the owner so
    // Windows still inherits the DACL from the fixture's private parent.
    descriptor_from_sddl(&format!("O:{}", current_sid_string()?))
}
#[cfg(test)]
pub(crate) fn write_inherited_fixture_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let path = checked_path(path)?;
    let _parent = pin_private_dir(path.parent().ok_or_else(invalid_path)?)?;
    let descriptor = inherited_fixture_sd()?;
    open(&path, GENERIC_WRITE, 0, CREATE_NEW, Some(&descriptor))?.write_all(bytes)
}
fn attributes(sd: &LocalMemory) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    }
}
fn open(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    security: Option<&LocalMemory>,
) -> io::Result<File> {
    let path = wide(path)?;
    let sa = security.map(attributes);
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            share,
            sa.as_ref().map_or(null(), |v| v),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}
fn info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { std::mem::zeroed() };
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a disk file",
        ));
    }
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "reparse point refused",
        ));
    }
    Ok(info)
}
fn regular_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let info = info(file)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(info)
}
fn identity(info: &BY_HANDLE_FILE_INFORMATION) -> FileIdentity {
    FileIdentity(
        info.dwVolumeSerialNumber as u64,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    )
}
fn privacy(file: &File) -> io::Result<(bool, bool)> {
    checked_privacy(file, false)
}
fn checked_privacy(file: &File, require_protected: bool) -> io::Result<(bool, bool)> {
    let current = current_sid()?;
    let mut owner = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _descriptor = LocalMemory(descriptor);
    let owner_matches = !owner.is_null() && unsafe { EqualSid(owner, sid(&current)) } != 0;
    if dacl.is_null() {
        return Ok((false, owner_matches));
    }
    if require_protected {
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0 {
            return Ok((false, owner_matches));
        }
    }
    let mut current_allow = false;
    for index in 0..unsafe { (*dacl).AceCount } {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        match u32::from(header.AceType) {
            ACCESS_ALLOWED_ACE_TYPE => {
                let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let allowed_sid = std::ptr::addr_of!(allow.SidStart).cast_mut().cast();
                if unsafe { EqualSid(allowed_sid, sid(&current)) } == 0 {
                    return Ok((false, owner_matches));
                }
                current_allow |=
                    allow.Mask != 0 && u32::from(header.AceFlags) & INHERIT_ONLY_ACE == 0;
            }
            ACCESS_DENIED_ACE_TYPE => {}
            // Unknown, object-specific, callback and conditional ACEs fail closed.
            _ => return Ok((false, owner_matches)),
        }
    }
    Ok((current_allow, owner_matches))
}
#[cfg_attr(not(test), allow(dead_code))] // Shared secure fixture/bootstrap primitive.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    let path = checked_path(path)?;
    let _parents = pin_dirs(path.parent().ok_or_else(invalid_path)?)?;
    let descriptor = private_sd()?;
    let attributes = attributes(&descriptor);
    let path = wide(&path)?;
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn open_private_new(path: &Path) -> io::Result<File> {
    let path = checked_path(path)?;
    let _parents = pin_private_dir(path.parent().ok_or_else(invalid_path)?)?;
    let descriptor = private_sd()?;
    let file = open(
        &path,
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ,
        CREATE_NEW,
        Some(&descriptor),
    )?;
    regular_info(&file)?;
    Ok(file)
}
pub(crate) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    let source = checked_path(source)?;
    let destination = checked_path(destination)?;
    if source.parent() != destination.parent() {
        return Err(invalid_path());
    }
    let _parents = pin_private_dir(source.parent().ok_or_else(invalid_path)?)?;
    // Native handle rename preserves the source's protected private DACL;
    // ReplaceFileW can merge the old destination's permissions and streams.
    let original = open(
        &destination,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    );
    match original {
        Ok(file) => {
            regular_info(&file)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Keep and rename the source handle, not a reopened pathname. POSIX rename
    // semantics permit a share-delete reader to finish its old snapshot without
    // truncating it. MoveFileExW fails with ERROR_ACCESS_DENIED for that case on
    // native Windows; never work around that by deleting the old destination.
    use windows_sys::Win32::System::WindowsProgramming::{
        FILE_RENAME_FLAG_POSIX_SEMANTICS, FILE_RENAME_FLAG_REPLACE_IF_EXISTS,
    };
    let source = open(
        &source,
        DELETE | GENERIC_WRITE | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    )?;
    if regular_info(&source)?.nNumberOfLinks != 1 || privacy(&source)? != (true, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe replacement source",
        ));
    }
    let destination = wide(&destination)?;
    let size =
        std::mem::offset_of!(FILE_RENAME_INFO, FileName) + destination.len() * size_of::<u16>();
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    let rename = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*rename).Anonymous.Flags =
            FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
        (*rename).RootDirectory = null_mut();
        (*rename).FileNameLength = ((destination.len() - 1) * size_of::<u16>()) as u32;
        std::ptr::copy_nonoverlapping(
            destination.as_ptr(),
            std::ptr::addr_of_mut!((*rename).FileName).cast::<u16>(),
            destination.len(),
        );
        if SetFileInformationByHandle(
            source.as_raw_handle(),
            FileRenameInfoEx,
            rename.cast(),
            size as u32,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    source.sync_all()
}
pub(crate) fn sync_parent(_path: &Path) -> io::Result<()> {
    // replace_file already flushes the renamed file handle. Windows directory
    // sync_all is unsupported; this is not a claim of Unix directory-fsync or
    // filesystem-independent power-loss durability.
    Ok(())
}
pub(crate) fn lock_file(home: &Path) -> io::Result<File> {
    use windows_sys::Win32::{Foundation::ERROR_LOCK_VIOLATION, System::IO::OVERLAPPED};
    let guard = pin_private_dir(home)?;
    let descriptor = private_sd()?;
    // OPEN_ALWAYS, never truncate/rename/unlink. This noninheritable handle
    // shares read/write (other contenders reach LockFileEx), but denies DELETE.
    let file = open(
        &guard.path.join("client.lock"),
        GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        OPEN_ALWAYS,
        Some(&descriptor),
    )?;
    if regular_info(&file)?.nNumberOfLinks != 1 || privacy(&file)? != (true, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lane lock",
        ));
    }
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    if unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "request lane already held",
            ));
        }
        return Err(error);
    }
    Ok(file)
}
pub(crate) fn read_regular(
    path: &Path,
    limit: u64,
    key: Option<&KeyMetadata>,
) -> Result<Vec<u8>, &'static str> {
    read_bounded(path, limit, key, false)
}
pub(crate) fn read_private_regular(
    path: &Path,
    limit: u64,
    key: Option<&KeyMetadata>,
) -> Result<Vec<u8>, &'static str> {
    read_bounded(path, limit, key, true)
}
fn read_bounded(
    path: &Path,
    limit: u64,
    key: Option<&KeyMetadata>,
    private: bool,
) -> Result<Vec<u8>, &'static str> {
    use std::io::Read;
    fn status(error: io::Error) -> &'static str {
        match error.kind() {
            io::ErrorKind::NotFound => "missing",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::InvalidInput => "not_regular",
            _ => "unreadable",
        }
    }
    let path = checked_path(path).map_err(status)?;
    let parent = path.parent().ok_or("not_regular")?;
    let _parents = if private {
        pin_private_dir(parent)
    } else {
        pin_dirs(parent)
    }
    .map_err(status)?;
    let before = open(
        &path,
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    )
    .map_err(status)?;
    let before = regular_info(&before).map_err(status)?;
    if key.is_some_and(|k| k.identity == identity(&before)) {
        return Err("signing_key_read_refused");
    }
    // Preserve snapshot sharing: the publisher may still be flushing the renamed
    // file on its writable handle while an offline or mailbox reader opens it.
    let access = GENERIC_READ | if private { READ_CONTROL } else { 0 };
    let file = open(
        &path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    )
    .map_err(status)?;
    let meta = regular_info(&file).map_err(status)?;
    if key.is_some_and(|k| k.identity == identity(&meta)) {
        return Err("signing_key_read_refused");
    }
    if identity(&before) != identity(&meta) {
        return Err("changed_during_read");
    }
    // Inherited current-user-only ACEs are fine on a child of the protected
    // parent. Check the actual content handle, not the earlier identity probe.
    if private && privacy(&file).map_err(status)? != (true, true) {
        return Err("permission_denied");
    }
    if (u64::from(meta.nFileSizeHigh) << 32) | u64::from(meta.nFileSizeLow) > limit {
        return Err("too_large");
    }
    let mut raw = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut raw)
        .map_err(status)?;
    if raw.len() as u64 > limit {
        return Err("too_large");
    }
    Ok(raw)
}
pub(crate) fn append_private(path: &Path) -> io::Result<File> {
    let path = checked_path(path)?;
    let _parents = pin_private_dir(path.parent().ok_or_else(invalid_path)?)?;
    let descriptor = private_sd()?;
    let file = open(
        &path,
        FILE_APPEND_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL,
        FILE_SHARE_READ,
        OPEN_ALWAYS,
        Some(&descriptor),
    )?;
    if regular_info(&file)?.nNumberOfLinks != 1 || privacy(&file)? != (true, true) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe private append target",
        ));
    }
    Ok(file)
}
static STOP_TARGET: std::sync::atomic::AtomicPtr<std::sync::atomic::AtomicBool> =
    std::sync::atomic::AtomicPtr::new(null_mut());
unsafe extern "system" fn console_stop(event: u32) -> i32 {
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if !matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        return 0;
    }
    let target = STOP_TARGET.load(Ordering::Acquire);
    if target.is_null() {
        return 0;
    }
    unsafe {
        (*target).store(true, Ordering::Relaxed);
    }
    1
}

pub(crate) fn install_stop_handler(stop: &'static std::sync::atomic::AtomicBool) -> io::Result<()> {
    install_stop_with(
        stop,
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler,
    )
}
pub(super) fn install_stop_with(
    stop: &'static std::sync::atomic::AtomicBool,
    register: unsafe extern "system" fn(
        windows_sys::Win32::System::Console::PHANDLER_ROUTINE,
        i32,
    ) -> i32,
) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    STOP_TARGET.store(std::ptr::from_ref(stop).cast_mut(), Ordering::Release);
    // CREATE_NEW_PROCESS_GROUP can inherit an ignored Ctrl+C attribute. Enable
    // delivery explicitly; registering a callback alone does not clear it.
    if unsafe { register(None, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { register(Some(console_stop), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn process_exists(pid: u32) -> Option<bool> {
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZATION_SYNCHRONIZE,
            WaitForSingleObject,
        },
    };
    if pid == 0 || pid == u32::MAX {
        return Some(false);
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZATION_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return match io::Error::last_os_error().raw_os_error() {
            Some(n) if n == ERROR_INVALID_PARAMETER as i32 => Some(false),
            Some(n) if n == ERROR_ACCESS_DENIED as i32 => Some(true),
            _ => None,
        };
    }
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => Some(true),
        WAIT_OBJECT_0 => Some(false),
        _ => None,
    }
}
pub(crate) fn key_metadata(path: &Path) -> io::Result<KeyMetadata> {
    let path = checked_path(path)?;
    let parents = pin_dirs(path.parent().ok_or_else(invalid_path)?)?;
    // READ_CONTROL/READ_ATTRIBUTES grant no seed-content access.
    let file = open(
        &path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        OPEN_EXISTING,
        None,
    )?;
    let info = regular_info(&file)?;
    let (private, owner) = privacy(&file)?;
    Ok(KeyMetadata {
        identity: identity(&info),
        private,
        owner,
        _file: file,
        _parents: parents,
    })
}
