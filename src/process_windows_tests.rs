//! Real native peers only. The fixture duplicates observation-only process
//! handles into this test process before publishing readiness. Cleanup checks
//! therefore observe exact kernel objects, never a reused PID and never taskkill.
use super::capture;
use std::{
    ffi::c_void,
    fs,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::PathBuf,
    process::Command,
    sync::{
        OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WaitForSingleObject(handle: *mut c_void, millis: u32) -> u32;
    fn GetExitCodeProcess(handle: *mut c_void, code: *mut u32) -> i32;
}

const INPUT_BOUND: usize = 100 * 1024;
const PEER_SOURCE: &str = r#"
use std::{env, ffi::c_void, fs, io::{self, Read, Write}, os::windows::{io::AsRawHandle, process::CommandExt}, process::{self, Command, Stdio}, thread, time::Duration};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn OpenProcess(access: u32, inherit: i32, id: u32) -> *mut c_void;
    fn DuplicateHandle(source_process: *mut c_void, source: *mut c_void, target_process: *mut c_void, target: *mut *mut c_void, access: u32, inherit: i32, options: u32) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn SetHandleInformation(handle: *mut c_void, mask: u32, flags: u32) -> i32;
    fn IsProcessInJob(process: *mut c_void, job: *mut c_void, result: *mut i32) -> i32;
}
fn observed_handle(target: *mut c_void, process: *mut c_void) -> usize {
    let mut handle = std::ptr::null_mut();
    assert_ne!(unsafe { DuplicateHandle(GetCurrentProcess(), process, target, &mut handle, 0x0010_1000, 0, 0) }, 0);
    handle as usize
}
fn main() {
    let args: Vec<_> = env::args().collect();
    let mode = &args[1];
    if mode == "warmup" { return; }
    if mode == "hold-pipes" { thread::sleep(Duration::from_secs(8)); return; }
    let record = &args[2];
    let parent: u32 = args[3].parse().unwrap();
    let target = unsafe { OpenProcess(0x40, 0, parent) };
    assert!(!target.is_null());
    let leader_handle = observed_handle(target, unsafe { GetCurrentProcess() });
    let mut descendant = None;
    if ["inherited-pipes", "closed-pipes-descendant", "tree-timeout"].contains(&mode.as_str()) {
        let mut child = Command::new(env::current_exe().unwrap());
        child.arg("hold-pipes").stdin(Stdio::null());
        if mode == "closed-pipes-descendant" || mode == "tree-timeout" {
            // Windows inherited stdio handles can themselves be inheritable.
            // Clear that flag before spawning with null stdio, so this fixture
            // truly holds no hidden inherited copy of the leader's pipes.
            assert_ne!(unsafe { SetHandleInformation(io::stdout().as_raw_handle(), 1, 0) }, 0);
            assert_ne!(unsafe { SetHandleInformation(io::stderr().as_raw_handle(), 1, 0) }, 0);
            child.stdout(Stdio::null()).stderr(Stdio::null());
        }
        descendant = Some(child.spawn().unwrap());
    }
    let descendant_id = descendant.as_ref().map_or(0, |c| c.id());
    let descendant_handle = descendant.as_ref().map_or(0, |c| observed_handle(target, c.as_raw_handle()));
    assert_ne!(unsafe { CloseHandle(target) }, 0);
    fs::write(record, format!("{} {} {} {}\n", process::id(), descendant_id, leader_handle, descendant_handle)).unwrap();
    match mode.as_str() {
        "inherited-pipes" | "closed-pipes-descendant" => (),
        "direct-timeout" | "blocked-stdin" | "tree-timeout" => thread::sleep(Duration::from_secs(8)),
        "closed-output-timeout" => {
            // Close the actual inherited handles, not just Rust wrappers.
            assert_ne!(unsafe { CloseHandle(io::stdout().as_raw_handle()) }, 0);
            assert_ne!(unsafe { CloseHandle(io::stderr().as_raw_handle()) }, 0);
            thread::sleep(Duration::from_secs(8));
        }
        "echo" => {
            assert_eq!(args[4], "参数 空格 \"quote\" 尾\\");
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes).unwrap();
            io::stdout().write_all(&bytes).unwrap();
            io::stderr().write_all(b"native-peer\0\r\n").unwrap();
        }
        "limits-duplex" => {
            // Deliberately fill both outputs before reading a pipe-sized input.
            io::stdout().write_all(&vec![b'o'; 4 * 1024 * 1024]).unwrap();
            io::stderr().write_all(&vec![b'e'; 64 * 1024]).unwrap();
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes).unwrap();
            let expected: Vec<_> = "中🙂\0\r\n".as_bytes().iter().copied().cycle().take(100 * 1024).collect();
            assert_eq!(bytes, expected);
        }
        "stdout-overflow" => { let _ = io::stdout().write_all(&vec![b'o'; 4 * 1024 * 1024 + 1]); }
        "stderr-overflow" => { let _ = io::stderr().write_all(&vec![b'e'; 64 * 1024 + 1]); }
        "nonzero" => {
            io::stdout().write_all(b"out-before-exit").unwrap();
            io::stderr().write_all(b"err-before-exit").unwrap();
            process::exit(7);
        }
        "job-at-entry" => {
            let mut in_job = 0;
            assert_ne!(unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) }, 0);
            assert_ne!(in_job, 0);
            // No breakaway is permitted by the owned job.
            let result = Command::new(env::current_exe().unwrap()).arg("warmup")
                .creation_flags(0x0100_0000).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn();
            assert!(result.is_err(), "descendant escaped owned job");
            io::stdout().write_all(b"owned-before-entry;no-breakaway").unwrap();
        }
        _ => panic!("unknown native fixture mode"),
    }
}
"#;

struct Peer {
    directory: PathBuf,
    executable: PathBuf,
}
fn peer() -> &'static Peer {
    static PEER: OnceLock<Peer> = OnceLock::new();
    PEER.get_or_init(|| {
        // MinGW ld's active-code-page output path cannot represent every Unicode
        // character. Compile in ASCII, then run a copied binary from Unicode.
        let build_directory =
            std::env::temp_dir().join(format!("tolink-process-{}", std::process::id()));
        let directory = build_directory.join("空 格🙂");
        fs::create_dir_all(&directory).unwrap();
        let source = build_directory.join("native-peer.rs");
        let built_executable = build_directory.join("native-peer.exe");
        let executable = directory.join("native-peer.exe");
        fs::write(&source, PEER_SOURCE).unwrap();
        let compiler = std::env::var_os("TOLINK_TEST_RUSTC").unwrap_or_else(|| "rustc".into());
        let built = Command::new(compiler)
            .args(["--edition=2024", "-o"])
            .arg(&built_executable)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "native peer compilation: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        fs::copy(&built_executable, &executable).unwrap();
        assert!(
            Command::new(&executable)
                .arg("warmup")
                .status()
                .unwrap()
                .success()
        );
        Peer {
            directory,
            executable,
        }
    })
}
fn command(mode: &str) -> (Command, PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let peer = peer();
    let record = peer.directory.join(format!(
        "{mode}-{}.ready",
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut command = Command::new(&peer.executable);
    command
        .env_clear()
        .current_dir(&peer.directory)
        .arg(mode)
        .arg(&record)
        .arg(std::process::id().to_string())
        .arg("参数 空格 \"quote\" 尾\\");
    // Native Windows needs its system-directory environment, not any model or
    // network configuration inherited from the developer shell.
    for name in ["SystemRoot", "WINDIR", "PATH", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    (command, record)
}
fn assert_clean(record: &PathBuf) {
    let text = fs::read_to_string(record).expect("native child readiness record");
    assert!(text.ends_with('\n'), "incomplete readiness record");
    let fields: Vec<usize> = text
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(fields.len(), 4);
    assert!(fields[0] > 0);
    assert_ne!(fields[2], 0);
    assert_eq!(fields[1] == 0, fields[3] == 0);
    for raw in [fields[2], fields[3]].into_iter().filter(|h| *h != 0) {
        // SAFETY: peer duplicated precisely this owned handle into our process,
        // and every readiness record is consumed once. No PID lookup/signaling.
        let process = unsafe { OwnedHandle::from_raw_handle(raw as *mut c_void) };
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            0,
            "owned fixture process still alive"
        );
        let mut code = 259;
        assert_ne!(
            unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) },
            0
        );
        assert_ne!(code, 259, "fixture has not exited");
    }
}
fn deadline_case(mode: &str, input: &[u8]) {
    let (command, record) = command(mode);
    let began = Instant::now();
    let error = capture(command, input, 1, false, &AtomicBool::new(false)).unwrap_err();
    let elapsed = began.elapsed();
    eprintln!(
        "case={mode} operation_seconds=1 elapsed_seconds={:.6} error={error}",
        elapsed.as_secs_f64()
    );
    assert_eq!(
        error.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::TimedOut),
        "{error}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "operation plus bounded cleanup took {elapsed:?}"
    );
    assert_clean(&record);
}

#[test]
fn unicode_binary_input_arguments_and_paths_round_trip() {
    let (command, record) = command("echo");
    let input = "中文🙂\0\nsecond line\r\n".as_bytes().repeat(2048);
    assert!(input.len() <= INPUT_BOUND);
    let output = capture(command, &input, 3, false, &AtomicBool::new(false)).unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, input);
    assert_eq!(output.stderr, b"native-peer\0\r\n");
    assert_clean(&record);
}
#[test]
fn exact_output_limits_and_large_duplex_stdin() {
    let (command, record) = command("limits-duplex");
    let input: Vec<_> = "中🙂\0\r\n"
        .as_bytes()
        .iter()
        .copied()
        .cycle()
        .take(INPUT_BOUND)
        .collect();
    let output = capture(command, &input, 5, false, &AtomicBool::new(false)).unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, vec![b'o'; 4 * 1024 * 1024]);
    assert_eq!(output.stderr, vec![b'e'; 64 * 1024]);
    assert_clean(&record);
}
#[test]
fn stdout_one_byte_overflow_is_rejected() {
    let (command, record) = command("stdout-overflow");
    let error = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("stdout limit"), "{error}");
    assert_clean(&record);
}
#[test]
fn stderr_one_byte_overflow_is_rejected() {
    let (command, record) = command("stderr-overflow");
    let error = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap_err();
    assert!(error.to_string().contains("stderr limit"), "{error}");
    assert_clean(&record);
}
#[test]
fn nonzero_status_and_both_streams_are_preserved() {
    let (command, record) = command("nonzero");
    let output = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"out-before-exit");
    assert_eq!(output.stderr, b"err-before-exit");
    assert_clean(&record);
}
#[test]
fn direct_child_deadline() {
    deadline_case("direct-timeout", b"");
}
#[test]
fn blocked_stdin_deadline() {
    deadline_case("blocked-stdin", &vec![b'i'; INPUT_BOUND]);
}
#[test]
fn inherited_descendant_pipes_share_the_original_deadline() {
    deadline_case("inherited-pipes", b"");
}
#[test]
fn closed_output_pipes_do_not_hide_a_live_leader() {
    deadline_case("closed-output-timeout", b"");
}
#[test]
fn deadline_cleans_a_whole_descendant_tree() {
    deadline_case("tree-timeout", b"");
}
#[test]
fn successful_leader_cleans_closed_pipe_descendant() {
    let (command, record) = command("closed-pipes-descendant");
    let began = Instant::now();
    let output = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap();
    assert!(output.status.success());
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_clean(&record);
}
#[test]
fn child_is_owned_before_entry_and_cannot_break_away() {
    let (command, record) = command("job-at-entry");
    let output = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(output.stdout, b"owned-before-entry;no-breakaway");
    assert_clean(&record);
}
#[test]
fn pre_stopped_interruptible_command_never_starts() {
    let (command, record) = command("echo");
    let error = capture(command, b"", 3, true, &AtomicBool::new(true)).unwrap_err();
    assert!(error.to_string().contains("owner_stop"), "{error}");
    assert!(!record.exists());
}
#[test]
fn noninterruptible_command_ignores_stop() {
    let (command, record) = command("echo");
    let output = capture(command, b"finish", 3, false, &AtomicBool::new(true)).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"finish");
    assert_clean(&record);
}
fn cancellation_case(mode: &str, input: &[u8]) {
    let (command, record) = command(mode);
    let stop = AtomicBool::new(false);
    let began = Instant::now();
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            let until = Instant::now() + Duration::from_secs(1);
            while !fs::read_to_string(&record).is_ok_and(|r| r.ends_with('\n'))
                && Instant::now() < until
            {
                std::thread::sleep(Duration::from_millis(2));
            }
            stop.store(true, Ordering::Relaxed);
        });
        capture(command, input, 4, true, &stop)
    });
    let error = result.unwrap_err();
    assert!(error.to_string().contains("owner_stop"), "{error}");
    assert!(began.elapsed() < Duration::from_secs(2));
    assert_clean(&record);
}
#[test]
fn cancellation_retires_a_pending_stdin_write() {
    cancellation_case("blocked-stdin", &vec![b'i'; INPUT_BOUND]);
}
#[test]
fn cancellation_retires_inherited_pipe_reads() {
    cancellation_case("inherited-pipes", b"");
}
#[test]
fn zero_budget_never_starts_a_child() {
    let (command, record) = command("echo");
    let error = capture(command, b"", 0, false, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::TimedOut)
    );
    assert!(!record.exists());
}
#[test]
fn oversized_input_is_rejected_without_spawn_or_truncation() {
    let (command, record) = command("echo");
    let error = capture(
        command,
        &vec![b'i'; INPUT_BOUND + 1],
        3,
        false,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    assert!(error.to_string().contains("stdin limit"), "{error}");
    assert!(!record.exists());
}
#[test]
fn overflowing_deadline_is_rejected_without_spawn() {
    let (command, record) = command("echo");
    let error = capture(command, b"", u64::MAX, false, &AtomicBool::new(false)).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::InvalidInput)
    );
    assert!(!record.exists());
}
#[test]
fn ordinary_error_text_is_not_cleanup_unconfirmed() {
    assert!(!super::cleanup_unconfirmed(&std::io::Error::other(
        "owned child cleanup unconfirmed"
    )));
}

#[test]
fn cleanup_unconfirmed_retains_its_type_operation_and_source() {
    use std::error::Error;
    let error = super::CleanupUnconfirmed {
        operation: Some(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "owner_stop",
        )),
        cleanup: std::io::Error::from_raw_os_error(5),
    };
    let boxed: Box<dyn Error> = Box::new(error);
    assert!(super::cleanup_unconfirmed(boxed.as_ref()));
    assert!(boxed.to_string().contains("owner_stop"));
    assert!(
        boxed
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .is_some()
    );
}

#[test]
fn owned_job_and_parent_pipe_handles_are_not_inheritable() {
    use windows_sys::Win32::{
        Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT},
        System::JobObjects::{
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectExtendedLimitInformation, QueryInformationJobObject,
        },
    };
    let job = super::new_job().unwrap();
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    assert_ne!(
        unsafe {
            QueryInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        },
        0
    );
    assert_eq!(
        info.BasicLimitInformation.LimitFlags,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    );
    let (pipe, _client) = super::Pipe::pair(true).unwrap();
    for handle in [
        job.as_raw_handle(),
        pipe.raw(),
        pipe.operation.as_ref().unwrap().event.as_raw_handle(),
    ] {
        let mut flags = HANDLE_FLAG_INHERIT;
        assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }
}

#[test]
fn canceled_overlapped_read_keeps_its_allocation_until_observed_completion() {
    let (mut pipe, _client) = super::Pipe::pair(true).unwrap();
    let mut output = Vec::new();
    pipe.read(&mut output, super::STDOUT_LIMIT, "stdout")
        .unwrap();
    assert!(
        pipe.pending,
        "a live silent peer must leave this ReadFile pending"
    );
    let allocation = pipe.operation.as_ref().unwrap().overlapped.get();
    pipe.cancel();
    assert!(pipe.pending, "CancelIoEx is not completion");
    assert_eq!(
        pipe.operation.as_ref().unwrap().overlapped.get(),
        allocation
    );
    let until = Instant::now() + super::CLEANUP_BUDGET;
    while !pipe.retire() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!pipe.pending, "cancellation completion not observed");
    assert!(pipe.handle.is_none());
    assert_eq!(
        pipe.operation.as_ref().unwrap().overlapped.get(),
        allocation
    );
}

#[test]
fn unassigned_suspended_child_is_terminated_without_executing() {
    use std::{os::windows::process::CommandExt, process::Stdio};
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
    let (mut command, record) = command("echo");
    command
        .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut owned = super::OwnedChild {
        child: command.spawn().unwrap(),
        job: super::new_job().unwrap(),
        assigned: false,
        disarmed: false,
    };
    let (a, _a_client) = super::Pipe::pair(false).unwrap();
    let (b, _b_client) = super::Pipe::pair(true).unwrap();
    let (c, _c_client) = super::Pipe::pair(true).unwrap();
    let mut pipes = [a, b, c];
    let began = Instant::now();
    owned.cleanup(&mut pipes).unwrap();
    assert!(began.elapsed() < super::CLEANUP_BUDGET);
    assert!(
        !record.exists(),
        "suspended child was executed before ownership"
    );
    assert_eq!(
        unsafe { WaitForSingleObject(owned.child.as_raw_handle(), 0) },
        0
    );
    assert_eq!(owned.active().unwrap(), 0);
}

#[test]
fn spawn_failure_is_not_misclassified_as_unconfirmed_cleanup() {
    let command = Command::new(peer().directory.join("does-not-exist.exe"));
    let error = capture(command, b"", 3, false, &AtomicBool::new(false)).unwrap_err();
    assert!(!super::cleanup_unconfirmed(error.as_ref()));
    assert_eq!(
        error.downcast_ref::<std::io::Error>().map(|e| e.kind()),
        Some(std::io::ErrorKind::NotFound)
    );
}
