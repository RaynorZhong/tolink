//! Unix implementations retain private modes, flock, no-follow reads and fsync.
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, AtomicPtr, Ordering},
};

pub(crate) struct PrivateDir {
    pub(crate) path: PathBuf,
    _file: File,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity(pub u64, pub u64);
pub(crate) struct KeyMetadata {
    pub(crate) identity: FileIdentity,
    pub(crate) private: bool,
    pub(crate) owner: bool,
}
fn identity(meta: &Metadata) -> FileIdentity {
    FileIdentity(meta.dev(), meta.ino())
}
fn private(meta: &Metadata) -> bool {
    meta.permissions().mode() & 0o077 == 0
}
fn owned(meta: &Metadata) -> bool {
    meta.uid() == unsafe { libc::geteuid() }
}
fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "expected a private, current-user-owned regular file or directory",
    )
}
#[cfg_attr(not(test), allow(dead_code))] // Shared secure fixture/bootstrap primitive.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)
}
pub(crate) fn pin_private_dir(path: &Path) -> io::Result<PrivateDir> {
    // macOS normally exposes /var as a link to /private/var. Resolve its existing
    // directory namespace before retaining the admitted leaf directory handle.
    let path = fs::canonicalize(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_dir() || !private(&meta) || !owned(&meta) {
        return Err(denied());
    }
    Ok(PrivateDir { path, _file: file })
}
pub(crate) fn open_private_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
pub(crate) fn append_private(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || !private(&meta) || !owned(&meta) {
        return Err(denied());
    }
    Ok(file)
}
pub(crate) fn read_key(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || !private(&meta) || !owned(&meta) {
        return Err(denied());
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file).take(4097).read_to_end(&mut raw)?;
    if raw.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "key exceeds local bound",
        ));
    }
    Ok(raw)
}
pub(crate) fn key_metadata(path: &Path) -> io::Result<KeyMetadata> {
    // Metadata only, including a link's target identity, so a rejected signing
    // key symlink cannot trick diagnostics into reading its target via an alias.
    let meta = fs::metadata(path)?;
    Ok(KeyMetadata {
        identity: identity(&meta),
        private: private(&meta),
        owner: owned(&meta),
    })
}
pub(crate) fn read_regular(
    path: &Path,
    limit: u64,
    key: Option<&KeyMetadata>,
) -> Result<Vec<u8>, &'static str> {
    fn status(error: io::Error) -> &'static str {
        match error.kind() {
            io::ErrorKind::NotFound => "missing",
            io::ErrorKind::PermissionDenied => "permission_denied",
            _ => "unreadable",
        }
    }
    let before = fs::symlink_metadata(path).map_err(status)?;
    if !before.is_file() {
        return Err("not_regular");
    }
    if key.is_some_and(|k| k.identity == identity(&before)) {
        return Err("signing_key_read_refused");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(status)?;
    let meta = file.metadata().map_err(status)?;
    if !meta.is_file() {
        return Err("not_regular");
    }
    if key.is_some_and(|k| k.identity == identity(&meta)) {
        return Err("signing_key_read_refused");
    }
    if identity(&before) != identity(&meta) {
        return Err("changed_during_read");
    }
    if meta.len() > limit {
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
pub(crate) fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}
pub(crate) fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?,
    )?
    .sync_all()
}
pub(crate) fn lock_file(home: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home.join("client.lock"))?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || !private(&meta) || !owned(&meta) {
        return Err(denied());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}
static STOP_TARGET: AtomicPtr<AtomicBool> = AtomicPtr::new(std::ptr::null_mut());
extern "C" fn stop(_: libc::c_int) {
    let target = STOP_TARGET.load(Ordering::Acquire);
    if !target.is_null() {
        unsafe {
            (*target).store(true, Ordering::Relaxed);
        }
    }
}
pub(crate) fn install_stop_handler(target: &'static AtomicBool) -> io::Result<()> {
    STOP_TARGET.store(std::ptr::from_ref(target).cast_mut(), Ordering::Release);
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = stop as *const () as usize;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for signal in [libc::SIGTERM, libc::SIGINT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
pub(crate) fn process_exists(pid: u32) -> Option<bool> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Some(false);
    }
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return Some(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Some(false),
        Some(libc::EPERM) => Some(true),
        _ => None,
    }
}
