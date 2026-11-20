//! Security-sensitive operating-system primitives. No transport or journal policy.
use std::io;

#[cfg(windows)]
#[path = "platform/windows.rs"]
mod native;
#[cfg(unix)]
#[path = "platform/unix.rs"]
mod native;
#[cfg(unix)]
pub(crate) use native::read_regular as read_private_regular;
pub(crate) use native::*;

pub(crate) fn random_bytes(bytes: &mut [u8]) -> io::Result<()> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
        };
        for chunk in bytes.chunks_mut(u32::MAX as usize) {
            let status = unsafe {
                BCryptGenRandom(
                    std::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status < 0 {
                return Err(io::Error::other("system CSPRNG failed"));
            }
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")?.read_exact(bytes)
    }
}

pub(crate) fn default_hermes_path() -> io::Result<std::path::PathBuf> {
    #[cfg(windows)]
    let (variable, suffix) = ("LOCALAPPDATA", "hermes/bin/hermes.exe");
    #[cfg(unix)]
    let (variable, suffix) = ("HOME", ".local/bin/hermes");
    let root = std::env::var_os(variable)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "launcher home variable missing"))?;
    let path = std::path::PathBuf::from(root).join(suffix);
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher home must be absolute",
        ));
    }
    Ok(path)
}
pub(crate) fn default_curl() -> &'static str {
    #[cfg(windows)]
    {
        "curl.exe"
    }
    #[cfg(unix)]
    {
        "/usr/bin/curl"
    }
}

pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let _directory = pin_private_dir(
        path.parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing parent"))?,
    )?;
    let mut random = [0u8; 16];
    random_bytes(&mut random)?;
    let temporary = path.with_extension(format!(
        "rust-tmp-{}-{:032x}",
        std::process::id(),
        u128::from_ne_bytes(random)
    ));
    let mut file = open_private_new(&temporary)?;
    let committed = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&temporary, path)?;
        sync_parent(path)
    })();
    if committed.is_err() {
        // Only the exclusively created temporary belongs to this invocation.
        let _ = std::fs::remove_file(&temporary);
    }
    committed
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) struct Fixture(pub(super) std::path::PathBuf);
    impl Fixture {
        pub(super) fn new() -> Self {
            let mut suffix = [0u8; 16];
            random_bytes(&mut suffix).unwrap();
            let path = std::path::PathBuf::from(std::env::var_os("TMPDIR").expect("test TMPDIR"))
                .join(format!(
                    "tolink-platform-{}-{:032x}",
                    std::process::id(),
                    u128::from_ne_bytes(suffix)
                ));
            create_private_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn private_creation_and_admission_use_current_user_only_dacl_not_readonly() {
        use std::io::Write;
        let root = Fixture::new();
        let path = root.0.join("synthetic.seed");
        let mut file = open_private_new(&path).unwrap();
        file.write_all(b"synthetic, never a real seed").unwrap();
        drop(file);
        let info = key_metadata(&path).unwrap();
        assert!(info.private && info.owner);
        drop(info);
        assert!(
            open_private_new(&path).is_err(),
            "must never truncate existing files"
        );
        for grant in ["*S-1-5-18:(F)", "*S-1-5-32-544:(F)", "*S-1-1-0:(R)"] {
            assert!(
                std::process::Command::new("icacls.exe")
                    .arg(&path)
                    .args(["/grant", grant])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
            assert!(
                !key_metadata(&path).unwrap().private,
                "explicit foreign allow ACE: {grant}"
            );
        }
        let original_permissions = std::fs::metadata(&path).unwrap().permissions();
        let mut permissions = original_permissions.clone();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(
            !key_metadata(&path).unwrap().private,
            "readonly is not privacy"
        );
        std::fs::set_permissions(&path, original_permissions).unwrap();
        let inherited = root.0.join("inherited");
        std::fs::create_dir(&inherited).unwrap();
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&inherited)
                .args(["/grant", "*S-1-5-18:(OI)(CI)(F)"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let child = inherited.join("seed");
        std::fs::write(&child, b"synthetic").unwrap();
        assert!(
            !key_metadata(&child).unwrap().private,
            "inherited foreign allow ACE"
        );
    }

    #[cfg(windows)]
    #[test]
    fn key_admission_rejects_ads_and_reparse_ancestors() {
        use std::io::Write;
        let root = Fixture::new();
        let key = root.0.join("seed");
        open_private_new(&key)
            .unwrap()
            .write_all(b"synthetic key bytes")
            .unwrap();
        assert_eq!(read_key(&key).unwrap(), b"synthetic key bytes");
        let alternate = root.0.join("seed:stream");
        std::fs::write(&alternate, b"synthetic stream bytes").unwrap();
        assert!(
            read_key(&alternate).is_err(),
            "alternate data stream must not be admitted"
        );
        let junction = root.0.join("junction");
        let target = root.0.join("target");
        create_private_dir(&target).unwrap();
        open_private_new(&target.join("seed"))
            .unwrap()
            .write_all(b"synthetic")
            .unwrap();
        let made = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "{}",
            String::from_utf8_lossy(&made.stderr)
        );
        let rejected = read_key(&junction.join("seed")).is_err();
        std::fs::remove_dir(&junction).unwrap();
        assert!(rejected, "reparse ancestor must not be followed");
        for suffix in ["NUL", "CON", "AUX", "COM1", "LPT9.txt", "seed.", "seed "] {
            assert!(
                read_key(&root.0.join(suffix)).is_err(),
                "ambiguous/device path: {suffix}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn held_lock_is_exclusive_noninheritable_deny_delete_and_released_on_close() {
        use std::os::windows::io::AsRawHandle;
        if let Some(home) = std::env::var_os("TOLINK_PLATFORM_LOCK_PROBE") {
            assert_eq!(
                lock_file(std::path::Path::new(&home)).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            return;
        }
        let root = Fixture::new();
        let lock = lock_file(&root.0).unwrap();
        let mut flags = 0;
        assert_ne!(
            unsafe {
                windows_sys::Win32::Foundation::GetHandleInformation(
                    lock.as_raw_handle(),
                    &mut flags,
                )
            },
            0
        );
        assert_eq!(
            flags & windows_sys::Win32::Foundation::HANDLE_FLAG_INHERIT,
            0
        );
        assert_eq!(
            lock_file(&root.0).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(
            std::fs::remove_file(root.0.join("client.lock")).is_err(),
            "held lock cannot be unlinked"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                &format!(
                    "{}::held_lock_is_exclusive_noninheritable_deny_delete_and_released_on_close",
                    module_path!().split_once("::").unwrap().1
                ),
                "--exact",
                "--nocapture",
            ])
            .env("TOLINK_PLATFORM_LOCK_PROBE", &root.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        drop(lock);
        assert!(
            root.0.join("client.lock").is_file(),
            "lock pathname must remain stable"
        );
        drop(lock_file(&root.0).unwrap());
        let child = root.0.join("pinned");
        create_private_dir(&child).unwrap();
        let guard = pin_private_dir(&child).unwrap();
        assert!(
            std::fs::rename(&child, root.0.join("moved")).is_err(),
            "pinned private directory cannot be swapped"
        );
        drop(guard);
        std::fs::rename(&child, root.0.join("moved")).unwrap();
    }

    #[test]
    fn atomic_save_replaces_existing_inode_privately_without_truncating_readers() {
        use std::io::Read;
        let root = Fixture::new();
        let path = root.0.join("state.json");
        atomic_write(&path, b"old journal").unwrap();
        let mut old = std::fs::File::open(&path).unwrap();
        atomic_write(&path, b"new journal").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new journal");
        let mut bytes = Vec::new();
        old.read_to_end(&mut bytes).unwrap();
        assert_eq!(
            bytes, b"old journal",
            "must replace, never truncate old journal"
        );
        assert!(key_metadata(&path).unwrap().private);
        drop(old);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let blocker = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(3)
                .open(&path)
                .unwrap();
            assert!(atomic_write(&path, b"must not commit").is_err());
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"new journal",
                "replacement failure must not delete old destination"
            );
            drop(blocker);
        }
        let entries: Vec<_> = std::fs::read_dir(&root.0).unwrap().collect();
        assert_eq!(
            entries.len(),
            1,
            "only this invocation's temporary file may be cleaned up"
        );
    }

    #[test]
    fn metadata_guard_refuses_signing_key_hardlink_aliases_and_bounds_reads() {
        use std::io::Write;
        let root = Fixture::new();
        let key = root.0.join("seed");
        open_private_new(&key)
            .unwrap()
            .write_all(b"synthetic seed sentinel")
            .unwrap();
        let metadata = key_metadata(&key).unwrap();
        let alias = root.0.join("ca.pem");
        std::fs::hard_link(&key, &alias).unwrap();
        assert_eq!(metadata.identity, key_metadata(&alias).unwrap().identity);
        assert_eq!(
            read_regular(&alias, 4096, Some(&metadata)).unwrap_err(),
            "signing_key_read_refused"
        );
        let normal = root.0.join("state.json");
        open_private_new(&normal).unwrap().write_all(b"{}").unwrap();
        assert_eq!(read_regular(&normal, 2, Some(&metadata)).unwrap(), b"{}");
        assert_eq!(
            read_regular(&normal, 1, Some(&metadata)).unwrap_err(),
            "too_large"
        );
        #[cfg(windows)]
        {
            assert_eq!(
                read_private_regular(&alias, 4096, Some(&metadata)).unwrap_err(),
                "signing_key_read_refused"
            );
            assert_eq!(
                read_private_regular(&normal, 2, Some(&metadata)).unwrap(),
                b"{}"
            );
            assert_eq!(
                read_private_regular(&normal, 1, Some(&metadata)).unwrap_err(),
                "too_large"
            );
        }
        assert!(read_regular(&root.0, 4096, Some(&metadata)).is_err());
        assert!(
            read_key(&alias).is_err(),
            "key admission rejects hardlink aliases"
        );
    }

    #[cfg(windows)]
    #[test]
    fn append_admission_rejects_foreign_grants_and_seed_aliases() {
        use std::io::Write;
        let root = Fixture::new();
        let path = root.0.join("client.log");
        append_private(&path)
            .unwrap()
            .write_all(b"first\n")
            .unwrap();
        append_private(&path)
            .unwrap()
            .write_all(b"second\n")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first\nsecond\n");
        assert!(key_metadata(&path).unwrap().private);
        assert!(
            std::process::Command::new("icacls.exe")
                .arg(&path)
                .args(["/grant", "*S-1-5-18:(F)"])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(
            append_private(&path).is_err(),
            "unsafe existing log must not be written"
        );
        let seed = root.0.join("seed");
        open_private_new(&seed)
            .unwrap()
            .write_all(b"synthetic seed")
            .unwrap();
        let alias = root.0.join("alias.log");
        std::fs::hard_link(&seed, &alias).unwrap();
        assert!(append_private(&alias).is_err());
        assert_eq!(std::fs::read(seed).unwrap(), b"synthetic seed");
    }

    #[cfg(windows)]
    #[test]
    fn native_console_ctrl_c_and_break_set_stop_without_killing_worker() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use windows_sys::Win32::System::Console::*;
        if std::env::var_os("TOLINK_PLATFORM_CTRL_PROBE").is_some() {
            // Isolate from the parent terminal before delivering real events.
            unsafe {
                FreeConsole();
            }
            assert_ne!(unsafe { AllocConsole() }, 0);
            static STOP: AtomicBool = AtomicBool::new(false);
            install_stop_handler(&STOP).unwrap();
            for event in [CTRL_BREAK_EVENT, CTRL_C_EVENT] {
                STOP.store(false, Ordering::Relaxed);
                assert_ne!(unsafe { GenerateConsoleCtrlEvent(event, 0) }, 0);
                let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !STOP.load(Ordering::Relaxed) && std::time::Instant::now() < until {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                assert!(
                    STOP.load(Ordering::Relaxed),
                    "console event {event} was lost"
                );
            }
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                &format!(
                    "{}::native_console_ctrl_c_and_break_set_stop_without_killing_worker",
                    module_path!().split_once("::").unwrap().1
                ),
                "--exact",
                "--nocapture",
            ])
            .env("TOLINK_PLATFORM_CTRL_PROBE", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child status {:?}: {} {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(windows)]
    #[test]
    fn console_registration_failure_is_propagated_not_silently_ignored() {
        use std::sync::atomic::AtomicBool;
        unsafe extern "system" fn rejected(
            _: windows_sys::Win32::System::Console::PHANDLER_ROUTINE,
            _: i32,
        ) -> i32 {
            unsafe {
                windows_sys::Win32::Foundation::SetLastError(
                    windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE,
                );
            }
            0
        }
        static STOP: AtomicBool = AtomicBool::new(false);
        let error = native::install_stop_with(&STOP, rejected).unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE as i32)
        );
    }

    #[test]
    fn process_presence_is_metadata_only_for_current_and_absent_pids() {
        assert_eq!(process_exists(std::process::id()), Some(true));
        assert_eq!(process_exists(u32::MAX), Some(false));
        assert_eq!(process_exists(0), Some(false));
    }

    #[test]
    fn native_default_tool_paths_match_the_host_launcher_convention() {
        #[cfg(windows)]
        {
            assert_eq!(
                default_hermes_path().unwrap(),
                std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
                    .join("hermes/bin/hermes.exe")
            );
            assert_eq!(default_curl(), "curl.exe");
        }
        #[cfg(unix)]
        {
            assert_eq!(
                default_hermes_path().unwrap(),
                std::path::PathBuf::from(std::env::var_os("HOME").unwrap())
                    .join(".local/bin/hermes")
            );
            assert_eq!(default_curl(), "/usr/bin/curl");
        }
    }

    #[test]
    fn native_random_fills_tokens_and_jitter() {
        let mut first = [0u8; 24];
        let mut second = [0u8; 24];
        random_bytes(&mut first).unwrap();
        random_bytes(&mut second).unwrap();
        assert_ne!(first, [0; 24]);
        assert_ne!(first, second);
        random_bytes(&mut [0u8; 1]).unwrap();
        random_bytes(&mut []).unwrap();
    }
}
