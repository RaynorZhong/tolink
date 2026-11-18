//! Bounded macOS subprocess capture. Only the group made by process_group(0)
//! is ours; the caller must not install another reaper for this direct child.
use std::{
    error::Error,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

const STDOUT_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_LIMIT: usize = 64 * 1024;
const CLEANUP_BUDGET: Duration = Duration::from_millis(500);

#[derive(Debug)]
struct CleanupUnconfirmed {
    operation: Option<io::Error>,
    cleanup: io::Error,
}
impl std::fmt::Display for CleanupUnconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(operation) = &self.operation {
            write!(f, "{operation}; ")?;
        }
        write!(f, "owned child cleanup unconfirmed: {}", self.cleanup)
    }
}
impl Error for CleanupUnconfirmed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cleanup)
    }
}
pub(crate) fn cleanup_unconfirmed(error: &(dyn Error + 'static)) -> bool {
    error.is::<CleanupUnconfirmed>()
}

/// The monotonic budget starts before synchronous spawn and covers stdin, exit
/// and both output EOFs. Command::spawn itself cannot be preempted (in particular,
/// callers must not add blocking pre_exec hooks). Cleanup gets at most 500 ms.
/// Success is never returned
/// after the original deadline, including when successful I/O needs cleanup.
/// This is group ownership, not a sandbox for descendants that leave the group.
pub(crate) fn capture(
    mut command: Command,
    input: &[u8],
    seconds: u64,
    interruptible: bool,
    stop: &AtomicBool,
) -> Result<Output, Box<dyn Error>> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(seconds))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "child deadline overflow"))?;
    check_budget(deadline, interruptible, stop)?;
    command
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn()?;
    // No early return after spawn: all ordinary I/O/error paths reach cleanup.
    let transfer = transfer(&mut child, input, deadline, interruptible, stop);
    drop(child.stdin.take());
    drop(child.stdout.take());
    drop(child.stderr.take());
    let completed = cleanup(child);
    match (transfer, completed) {
        (Err(reason), Err(cleanup)) => Err(Box::new(CleanupUnconfirmed {
            operation: Some(reason),
            cleanup,
        })),
        (Err(reason), Ok(_)) => Err(reason.into()),
        (Ok(_), Err(cleanup)) => Err(Box::new(CleanupUnconfirmed {
            operation: None,
            cleanup,
        })),
        (Ok((stdout, stderr)), Ok(status)) => {
            check_budget(deadline, interruptible, stop)?;
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }
    }
}

fn check_budget(deadline: Instant, interruptible: bool, stop: &AtomicBool) -> io::Result<()> {
    if interruptible && stop.load(Ordering::Relaxed) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "owner_stop"));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned child deadline exceeded",
        ));
    }
    Ok(())
}

fn nonblocking(stream: &impl AsRawFd) -> io::Result<()> {
    let fd = stream.as_raw_fd();
    // SAFETY: this is a live, exclusively owned pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn read_pipe<R: Read>(
    pipe: &mut Option<R>,
    bytes: &mut Vec<u8>,
    bound: usize,
    label: &str,
) -> io::Result<()> {
    if let Some(stream) = pipe.as_mut() {
        let mut buffer = [0u8; 8192];
        let room = bound - bytes.len();
        let count = buffer.len().min(room + 1);
        match stream.read(&mut buffer[..count]) {
            Ok(0) => {
                pipe.take();
            }
            Ok(count) if count > room => {
                return Err(io::Error::other(format!("child {label} limit exceeded")));
            }
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                ()
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn transfer(
    child: &mut Child,
    input: &[u8],
    deadline: Instant,
    interruptible: bool,
    stop: &AtomicBool,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut stdin = Some(
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing stdin"))?,
    );
    let mut stdout = Some(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout"))?,
    );
    let mut stderr = Some(
        child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr"))?,
    );
    nonblocking(stdin.as_ref().unwrap())?;
    nonblocking(stdout.as_ref().unwrap())?;
    nonblocking(stderr.as_ref().unwrap())?;
    // macOS per-descriptor suppression, without changing the caller's SIGPIPE policy.
    if unsafe { libc::fcntl(stdin.as_ref().unwrap().as_raw_fd(), libc::F_SETNOSIGPIPE, 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let (mut out, mut err, mut written) = (Vec::new(), Vec::new(), 0);
    let mut exited = false;
    loop {
        check_budget(deadline, interruptible, stop)?;
        if written == input.len() {
            stdin.take();
        }
        read_pipe(&mut stdout, &mut out, STDOUT_LIMIT, "stdout")?;
        check_budget(deadline, interruptible, stop)?;
        read_pipe(&mut stderr, &mut err, STDERR_LIMIT, "stderr")?;
        check_budget(deadline, interruptible, stop)?;
        if let Some(stream) = stdin.as_mut() {
            let count = (input.len() - written).min(8192);
            match stream.write(&input[written..written + count]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "child stdin write zero",
                    ));
                }
                Ok(count) => written += count,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    ()
                }
                Err(e) => return Err(e),
            }
        }
        if written == input.len() {
            stdin.take();
        }
        if !exited {
            match observe_exit(child.id() as libc::pid_t) {
                Ok(done) => exited = done,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        check_budget(deadline, interruptible, stop)?;
        if exited && stdin.is_none() && stdout.is_none() && stderr.is_none() {
            return Ok((out, err));
        }
        let mut fds = [
            libc::pollfd {
                fd: stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(20) as libc::c_int;
        // All reads/writes are nonblocking, one chunk each, so neither stream
        // nor a full stdin pipe can monopolize the deadline/cancellation checks.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

fn observe_exit(pid: libc::pid_t) -> io::Result<bool> {
    // SAFETY: zero is a valid siginfo_t initializer; WNOWAIT reserves the leader
    // PID even after exit. Only this helper observes it until cleanup disarms.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.si_pid() } == pid)
}

fn group_present(pid: libc::pid_t) -> io::Result<bool> {
    // Signal zero is an absence check, including after reaping; never a kill.
    if unsafe { libc::kill(-pid, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn cleanup(mut child: Child) -> io::Result<ExitStatus> {
    let until = Instant::now() + CLEANUP_BUDGET;
    let pid = child.id() as libc::pid_t;
    if pid <= 1 {
        return Err(io::Error::other("refusing unsafe owned process group"));
    }
    // Refuse to signal if ownership has already been lost (e.g. another reaper).
    loop {
        if Instant::now() >= until {
            return Err(io::Error::other("cleanup deadline before ownership check"));
        }
        match observe_exit(pid) {
            Ok(_) => break,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    let signal_error = match group_present(pid) {
        Ok(true) => {
            // The ONLY termination signal. The leader is still unreaped here.
            // No Drop guard or retry may signal this cached PGID after this point.
            if unsafe { libc::kill(-pid, libc::SIGKILL) } < 0 {
                let error = io::Error::last_os_error();
                (error.raw_os_error() != Some(libc::ESRCH)).then_some(error)
            } else {
                None
            }
        }
        Ok(false) => None,
        // A zombie-only macOS group can fail signal-zero with EPERM. This is
        // not accepted as absence: reap below, then REQUIRE ESRCH within budget.
        Err(e) if e.raw_os_error() == Some(libc::EPERM) => None,
        Err(e) => Some(e),
    };
    // TERMINATION SIGNALING IS NOW PERMANENTLY DISARMED. Only WNOHANG reaping
    // and non-signalling absence checks follow, even if this number is reused.
    let mut status = None;
    loop {
        if Instant::now() >= until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "cleanup deadline exceeded (leader_reaped={}, signal_error={signal_error:?})",
                    status.is_some()
                ),
            ));
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let absent = match group_present(pid) {
            Ok(present) => !present,
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => false,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if absent {
            if let Some(status) = status {
                if let Some(error) = signal_error {
                    return Err(error);
                }
                if Instant::now() >= until {
                    continue;
                }
                return Ok(status);
            }
        }
        thread::sleep(
            Duration::from_millis(5).min(until.saturating_duration_since(Instant::now())),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::capture;
    use std::{
        fs,
        os::unix::{fs::DirBuilderExt, process::CommandExt},
        path::PathBuf,
        process::Command,
        sync::{
            OnceLock,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    // The peer is native Rust, not a shell/Python stand-in for a subprocess.
    const PEER: &str = r#"
use std::{env, fs, io::{self, Read, Write}, process::{self, Command, Stdio}, thread, time::Duration};
fn main() {
    let args: Vec<_> = env::args().collect();
    let mode = &args[1];
    if mode == "warmup" { return; }
    if mode == "hold-pipes" { thread::sleep(Duration::from_secs(3)); return; }
    let record = &args[2];
    let mut descendant = 0;
    if mode == "inherited-pipes" || mode == "closed-pipes-descendant" {
        let mut child = Command::new(env::current_exe().unwrap());
        child.arg("hold-pipes").stdin(Stdio::null());
        if mode == "closed-pipes-descendant" {
            child.stdout(Stdio::null()).stderr(Stdio::null());
        }
        descendant = child.spawn().unwrap().id();
    }
    fs::write(record, format!("{} {}\n", process::id(), descendant)).unwrap();
    match mode.as_str() {
        "inherited-pipes" | "closed-pipes-descendant" => (),
        "direct-timeout" => thread::sleep(Duration::from_secs(3)),
        "blocked-stdin" => {
            thread::sleep(Duration::from_secs(3));
            io::stdin().read_to_end(&mut Vec::new()).unwrap();
        }
        "echo" => {
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes).unwrap();
            io::stdout().write_all(&bytes).unwrap();
            io::stderr().write_all(b"native-peer\0\n").unwrap();
        }
        "limits-and-duplex" => {
            io::stdout().write_all(&vec![b'o'; 4 * 1024 * 1024]).unwrap();
            io::stderr().write_all(&vec![b'e'; 64 * 1024]).unwrap();
            let mut bytes = Vec::new();
            io::stdin().read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, vec![b'i'; 512 * 1024]);
        }
        "stdout-overflow" => io::stdout().write_all(&vec![b'o'; 4 * 1024 * 1024 + 1]).unwrap(),
        "stderr-overflow" => io::stderr().write_all(&vec![b'e'; 64 * 1024 + 1]).unwrap(),
        "nonzero" => process::exit(7),
        _ => panic!("unknown peer mode"),
    }
}
"#;

    struct Peer {
        directory: PathBuf,
        executable: PathBuf,
    }
    fn peer() -> &'static Peer {
        static PEER_BINARY: OnceLock<Peer> = OnceLock::new();
        PEER_BINARY.get_or_init(|| {
            let directory =
                std::env::temp_dir().join(format!("tolink-process-peers-{}", std::process::id()));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let source = directory.join("peer.rs");
            let executable = directory.join("peer");
            fs::write(&source, PEER).unwrap();
            let compiler = std::env::var_os("TOLINK_TEST_RUSTC").unwrap_or_else(|| "rustc".into());
            let built = Command::new(compiler)
                .args(["--edition=2024", "-o"])
                .arg(&executable)
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                built.status.success(),
                "peer compilation: {}",
                String::from_utf8_lossy(&built.stderr)
            );
            // Cold macOS executable startup is setup, not the timed operation.
            let warmup = Command::new(&executable)
                .env_clear()
                .arg("warmup")
                .output()
                .unwrap();
            assert!(warmup.status.success());
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
            .arg(&record);
        (command, record)
    }
    fn assert_clean(record: &PathBuf) {
        let ready = fs::read_to_string(record).unwrap();
        assert!(ready.ends_with('\n'), "incomplete peer readiness record");
        let ids: Vec<libc::pid_t> = ready
            .split_whitespace()
            .map(|s| s.parse().unwrap())
            .collect();
        assert_eq!(ids.len(), 2);
        let leader = ids[0];
        assert!(leader > 1);
        let mut status = 0;
        // WNOHANG can only reap this test's own direct child, never an unrelated one.
        assert_eq!(
            unsafe { libc::waitpid(leader, &mut status, libc::WNOHANG) },
            -1,
            "leader was not reaped"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_eq!(
            unsafe { libc::kill(-leader, 0) },
            -1,
            "owned group still exists"
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        if ids[1] != 0 {
            assert_eq!(
                unsafe { libc::kill(ids[1], 0) },
                -1,
                "fixture descendant still exists"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }
    fn deadline_case(mode: &str, input: &[u8]) {
        let (command, record) = command(mode);
        let began = Instant::now();
        let result = capture(command, input, 1, false, &AtomicBool::new(false));
        let elapsed = began.elapsed();
        eprintln!(
            "case={mode} configured_seconds=1 elapsed_seconds={:.6} returned_ok={} result={:?}",
            elapsed.as_secs_f64(),
            result.is_ok(),
            result.as_ref().map(|o| o.status)
        );
        assert!(
            result.is_err(),
            "{mode} incorrectly returned success after its deadline"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "{mode} exceeded operation plus bounded cleanup: {elapsed:?}"
        );
        assert!(result.unwrap_err().to_string().contains("deadline"));
        assert_clean(&record);
    }

    #[test]
    fn normal_success_control() {
        let (command, record) = command("echo");
        let input = b"multiline\n\0UTF-8: \xe4\xb8\xad\xe6\x96\x87\n";
        let began = Instant::now();
        let output = capture(command, input, 2, false, &AtomicBool::new(false)).unwrap();
        eprintln!(
            "case=normal-success elapsed_seconds={:.6}",
            began.elapsed().as_secs_f64()
        );
        assert!(output.status.success());
        assert_eq!(output.stdout, input);
        assert_eq!(output.stderr, b"native-peer\0\n");
        assert_clean(&record);
    }
    #[test]
    fn direct_child_timeout() {
        deadline_case("direct-timeout", b"");
    }
    #[test]
    fn inherited_pipes_deadline() {
        deadline_case("inherited-pipes", b"");
    }
    #[test]
    fn blocked_stdin_deadline() {
        deadline_case("blocked-stdin", &vec![b'i'; 2 * 1024 * 1024]);
    }
    #[test]
    fn exact_output_limits_and_simultaneous_stdin() {
        let (command, record) = command("limits-and-duplex");
        let output = capture(
            command,
            &vec![b'i'; 512 * 1024],
            2,
            false,
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, vec![b'o'; 4 * 1024 * 1024]);
        assert_eq!(output.stderr, vec![b'e'; 64 * 1024]);
        assert_clean(&record);
    }
    #[test]
    fn output_overflow_is_an_error() {
        for mode in ["stdout-overflow", "stderr-overflow"] {
            let (command, record) = command(mode);
            let error = capture(command, b"", 2, false, &AtomicBool::new(false)).unwrap_err();
            assert!(error.to_string().contains("limit"), "{error}");
            assert_clean(&record);
        }
    }
    #[test]
    fn successful_leader_does_not_leave_closed_pipe_descendant() {
        let (command, record) = command("closed-pipes-descendant");
        let began = Instant::now();
        let output = capture(command, b"", 2, false, &AtomicBool::new(false)).unwrap();
        assert!(output.status.success());
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_clean(&record);
    }
    #[test]
    fn interruptible_stop_policy() {
        let stop = AtomicBool::new(true);
        let (stopped, stopped_record) = command("echo");
        let error = capture(stopped, b"", 2, true, &stop).unwrap_err();
        assert!(error.to_string().contains("owner_stop"), "{error}");
        assert!(!stopped_record.exists(), "stopped command was started");
        let (finishing, record) = command("echo");
        let output = capture(finishing, b"finish", 2, false, &stop).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"finish");
        assert_clean(&record);
    }
    #[test]
    fn stop_interrupts_blocked_stdin() {
        let (command, record) = command("blocked-stdin");
        let stop = AtomicBool::new(false);
        let began = Instant::now();
        let result = std::thread::scope(|scope| {
            scope.spawn(|| {
                let until = Instant::now() + Duration::from_secs(1);
                while !fs::read_to_string(&record).is_ok_and(|r| r.ends_with('\n'))
                    && Instant::now() < until
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                stop.store(true, Ordering::Relaxed);
            });
            capture(command, &vec![b'i'; 2 * 1024 * 1024], 2, true, &stop)
        });
        let error = result.unwrap_err();
        assert!(error.to_string().contains("owner_stop"), "{error}");
        assert!(began.elapsed() < Duration::from_secs(2));
        assert_clean(&record);
    }
    #[test]
    fn cleanup_refuses_already_reaped_leader() {
        let (mut command, record) = command("echo");
        command
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().unwrap();
        assert!(child.wait().unwrap().success());
        let error = super::cleanup(child).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        assert_clean(&record);
    }
    #[test]
    fn nonzero_status_is_preserved() {
        let (command, record) = command("nonzero");
        let output = capture(command, b"", 2, false, &AtomicBool::new(false)).unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_clean(&record);
    }
    #[test]
    fn cleanup_classification_is_typed_not_message_matching() {
        let cleanup = super::CleanupUnconfirmed {
            operation: None,
            cleanup: std::io::Error::other("synthetic native cleanup error"),
        };
        assert!(super::cleanup_unconfirmed(&cleanup));
        assert!(!super::cleanup_unconfirmed(&std::io::Error::other(
            "cleanup unconfirmed as ordinary text"
        )));
    }
}
