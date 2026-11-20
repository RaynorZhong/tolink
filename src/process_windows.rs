//! Native Windows capture, with no shell, worker threads, PID-based signaling,
//! or ownership of a shared service contacted by the local command.
//!
//! The child starts suspended. Its non-inheritable, unnamed job (kill-on-close,
//! no breakaway) owns it BEFORE its primary thread is resumed. This is local
//! process-tree ownership, not a security sandbox against hostile same-user code.
//! Parent pipe endpoints use genuine OVERLAPPED I/O; child endpoints are ordinary
//! synchronous stdio. One monotonic deadline covers setup, stdin, exit and EOFs.
//! Like CreateProcessW itself, Command::spawn is synchronous and not preemptible;
//! its elapsed time is charged to that same deadline and checked before resume.
use std::{
    cell::UnsafeCell,
    error::Error,
    fs::File,
    io,
    mem::{self, size_of},
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::{ChildExt, CommandExt},
    },
    process::{Child, Command, ExitStatus, Output, Stdio},
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING, ERROR_NO_DATA,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    },
    Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, ReadFile, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateEventW, ResetEvent, ResumeThread,
            TerminateProcess, WaitForMultipleObjects, WaitForSingleObject,
        },
    },
};

const STDIN_LIMIT: usize = 100 * 1024;
const STDOUT_LIMIT: usize = 4 * 1024 * 1024;
const STDERR_LIMIT: usize = 64 * 1024;
const CHUNK: usize = 8192;
const CLEANUP_BUDGET: Duration = Duration::from_millis(500);
const POLL_MILLIS: u32 = 20;

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

/// Accepts at most 100 KiB of input, without truncation. Both output limits are
/// inclusive; a one-byte probe distinguishes exact-limit EOF from overflow.
/// Every post-spawn ordinary return attempts and verifies cleanup within a
/// separate 500 ms budget, including active-job-count zero AND leader exit.
/// A failed proof is a typed CleanupUnconfirmed, never a successful Output.
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
    if input.len() > STDIN_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "child stdin limit exceeded (100 KiB)",
        )
        .into());
    }
    let job = new_job()?;
    check_budget(deadline, interruptible, stop)?;
    let (stdin, child_stdin) = Pipe::pair(false)?;
    check_budget(deadline, interruptible, stop)?;
    let (stdout, child_stdout) = Pipe::pair(true)?;
    check_budget(deadline, interruptible, stop)?;
    let (stderr, child_stderr) = Pipe::pair(true)?;
    let mut pipes = [stdin, stdout, stderr];
    check_budget(deadline, interruptible, stop)?;
    // Override creation flags deliberately: in particular do not accept caller
    // breakaway flags. Only the client endpoints are supplied as child stdio;
    // our server/event/job handles were all created non-inheritable.
    command
        .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
        .stdin(child_stdin)
        .stdout(child_stdout)
        .stderr(child_stderr);
    let child = command.spawn();
    // Command retains its original Stdio handles after spawn. These MUST close
    // now, otherwise our own copies suppress EOF forever.
    drop(command);
    let mut owned = OwnedChild {
        child: child?,
        job,
        assigned: false,
        disarmed: false,
    };
    // No `?` escapes between creation of OwnedChild and verified cleanup.
    let operation = (|| {
        check_budget(deadline, interruptible, stop)?;
        if unsafe {
            AssignProcessToJobObject(owned.job.as_raw_handle(), owned.child.as_raw_handle())
        } == 0
        {
            return Err(context(
                "AssignProcessToJobObject",
                io::Error::last_os_error(),
            ));
        }
        owned.assigned = true;
        check_budget(deadline, interruptible, stop)?;
        // This stable std ChildExt API preserves Command's Windows quoting,
        // environment and cwd behavior. No undocumented NtResumeProcess call.
        let previous = unsafe { ResumeThread(owned.child.main_thread_handle().as_raw_handle()) };
        if previous == u32::MAX {
            return Err(context("ResumeThread", io::Error::last_os_error()));
        }
        if previous != 1 {
            return Err(io::Error::other(
                "unexpected primary-thread suspension count",
            ));
        }
        transfer(
            &mut owned.child,
            &mut pipes,
            input,
            deadline,
            interruptible,
            stop,
        )
    })();
    let cleaned = owned.cleanup(&mut pipes);
    match (operation, cleaned) {
        (Err(operation), Err(cleanup)) => Err(Box::new(CleanupUnconfirmed {
            operation: Some(operation),
            cleanup,
        })),
        (Err(operation), Ok(_)) => Err(operation.into()),
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

fn context(label: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{label}: {error}"))
}
fn checked_handle(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: all callers pass a fresh, exclusively owned Win32 handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn new_job() -> io::Result<OwnedHandle> {
    // NULL attributes/name: private, unnamed, non-inheritable handle.
    let job = checked_handle(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // In particular neither BREAKAWAY_OK nor SILENT_BREAKAWAY_OK is set.
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

struct OwnedChild {
    child: Child,
    job: OwnedHandle,
    assigned: bool,
    disarmed: bool,
}
impl OwnedChild {
    fn terminate(&self) -> Option<io::Error> {
        // Never touch an enclosing/ambient job. An assignment failure leaves an
        // owned SUSPENDED direct child, safely terminated through its handle.
        let ok = unsafe {
            if self.assigned {
                TerminateJobObject(self.job.as_raw_handle(), 1)
            } else {
                TerminateProcess(self.child.as_raw_handle(), 1)
            }
        };
        (ok == 0).then(io::Error::last_os_error)
    }
    fn active(&self) -> io::Result<u32> {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        if unsafe {
            QueryInformationJobObject(
                self.job.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
    }
    fn cleanup(&mut self, pipes: &mut [Pipe; 3]) -> io::Result<ExitStatus> {
        let until = Instant::now() + CLEANUP_BUDGET;
        let signal_error = self.terminate();
        for pipe in pipes.iter_mut() {
            pipe.cancel();
        }
        let mut status = None;
        let mut last_error = None;
        loop {
            if Instant::now() >= until {
                // Drop still closes the kill-on-close job. This error is NOT
                // silently downgraded merely because termination was requested.
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "cleanup deadline exceeded (leader_exited={}, signal_error={signal_error:?}, observation_error={last_error:?})",
                        status.is_some()
                    ),
                ));
            }
            let mut retired = true;
            for pipe in pipes.iter_mut() {
                retired &= pipe.retire();
            }
            if status.is_none() {
                match self.child.try_wait() {
                    Ok(value) => status = value,
                    Err(error) => last_error = Some(error),
                }
            }
            let empty = match self.active() {
                Ok(count) => count == 0,
                Err(error) => {
                    last_error = Some(error);
                    false
                }
            };
            // ActiveProcesses can reach zero before kernel teardown signals
            // the process/job objects. Require those signals too: count-zero
            // alone experimentally left descendant handles pending for ~1 ms.
            let leader_signaled =
                unsafe { WaitForSingleObject(self.child.as_raw_handle(), 0) } == WAIT_OBJECT_0;
            let job_signaled = !self.assigned
                || unsafe { WaitForSingleObject(self.job.as_raw_handle(), 0) } == WAIT_OBJECT_0;
            if retired
                && empty
                && leader_signaled
                && job_signaled
                && let Some(status) = status
                && Instant::now() < until
            {
                self.disarmed = true;
                return Ok(status);
            }
            thread::sleep(
                Duration::from_millis(5).min(until.saturating_duration_since(Instant::now())),
            );
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Panic/error fallback uses owned handles only, and never waits. Normal
        // paths instead use cleanup's bounded positive proof. Closing the last
        // job handle also terminates assigned descendants if proof failed.
        if !self.disarmed {
            let _ = self.terminate();
        }
    }
}

// Both OVERLAPPED and the bytes it references live in one stable heap allocation
// until completion. UnsafeCell explicitly permits the kernel's asynchronous
// writes. There is never more than one operation outstanding on each pipe.
struct Operation {
    overlapped: UnsafeCell<OVERLAPPED>,
    buffer: UnsafeCell<[u8; CHUNK]>,
    event: OwnedHandle,
}
impl Operation {
    fn new() -> io::Result<Box<Self>> {
        let event = checked_handle(unsafe { CreateEventW(null(), 1, 0, null()) })?;
        let overlapped = OVERLAPPED {
            hEvent: event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        Ok(Box::new(Self {
            overlapped: UnsafeCell::new(overlapped),
            buffer: UnsafeCell::new([0; CHUNK]),
            event,
        }))
    }
    fn reset(&mut self) -> io::Result<()> {
        if unsafe { ResetEvent(self.event.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        *self.overlapped.get_mut() = OVERLAPPED {
            hEvent: self.event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        Ok(())
    }
}
struct Pipe {
    handle: Option<OwnedHandle>,
    operation: Option<Box<Operation>>,
    pending: bool,
}
impl Pipe {
    fn pair(read: bool) -> io::Result<(Self, Stdio)> {
        let mut nonce = [0u8; 16];
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(io::Error::other(format!(
                "pipe name randomness failed: {status:#x}"
            )));
        }
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let name: Vec<u16> = format!(r"\\.\pipe\tolink-{}-{suffix}", std::process::id())
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let access = if read {
            PIPE_ACCESS_INBOUND
        } else {
            PIPE_ACCESS_OUTBOUND
        };
        let handle = checked_handle(unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                access | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                CHUNK as u32,
                CHUNK as u32,
                0,
                null(),
            )
        })?;
        let mut pipe = Self {
            handle: Some(handle),
            operation: Some(Operation::new()?),
            pending: false,
        };
        // Local exclusive client open: no WaitNamedPipe or potentially unbounded
        // synchronous ReadFile/WriteFile. Only the child uses this sync endpoint.
        let client = checked_handle(unsafe {
            CreateFileW(
                name.as_ptr(),
                if read { GENERIC_WRITE } else { GENERIC_READ },
                0,
                null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        })?;
        let op = pipe.operation.as_ref().unwrap();
        if unsafe { ConnectNamedPipe(pipe.raw(), op.overlapped.get()) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                // Normally the already-open local client yields PIPE_CONNECTED.
                // Even an unexpected pending connect retains its allocation.
                pipe.pending = error.raw_os_error() == Some(ERROR_IO_PENDING as i32);
                return Err(context("ConnectNamedPipe", error));
            }
        }
        Ok((pipe, Stdio::from(File::from(client))))
    }
    fn raw(&self) -> HANDLE {
        self.handle.as_ref().unwrap().as_raw_handle()
    }
    fn completion(&mut self) -> io::Result<Option<usize>> {
        debug_assert!(self.pending);
        let op = self.operation.as_ref().unwrap();
        let mut count = 0;
        if unsafe { GetOverlappedResult(self.raw(), op.overlapped.get(), &mut count, 0) } != 0 {
            self.pending = false;
            return Ok(Some(count as usize));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32) {
            return Ok(None);
        }
        // Completion errors (including OPERATION_ABORTED) are terminal, but an
        // unexpected API failure is not itself proof that the kernel is done.
        if unsafe { WaitForSingleObject(op.event.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
            self.pending = false;
        }
        Err(error)
    }
    fn start(&mut self, read: bool, count: usize) -> io::Result<Option<usize>> {
        debug_assert!(!self.pending && count <= CHUNK && count > 0);
        let handle = self.raw();
        let op = self.operation.as_mut().unwrap();
        op.reset()?;
        let ok = unsafe {
            if read {
                ReadFile(
                    handle,
                    (*op.buffer.get()).as_mut_ptr(),
                    count as u32,
                    null_mut(),
                    op.overlapped.get(),
                )
            } else {
                WriteFile(
                    handle,
                    (*op.buffer.get()).as_ptr(),
                    count as u32,
                    null_mut(),
                    op.overlapped.get(),
                )
            }
        };
        if ok != 0 {
            self.pending = true;
            return self.completion();
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_IO_PENDING as i32) {
            self.pending = true;
            Ok(None)
        } else {
            Err(error)
        }
    }
    fn read(&mut self, bytes: &mut Vec<u8>, bound: usize, label: &str) -> io::Result<()> {
        if self.handle.is_none() {
            return Ok(());
        }
        let room = bound - bytes.len();
        let result = if self.pending {
            self.completion()
        } else {
            self.start(true, CHUNK.min(room + 1))
        };
        match result {
            Ok(Some(0)) => {
                self.handle.take();
            }
            Ok(Some(count)) => {
                if count > room {
                    return Err(io::Error::other(format!("child {label} limit exceeded")));
                }
                // Completion was observed, so no concurrent kernel write.
                bytes
                    .extend_from_slice(&self.operation.as_mut().unwrap().buffer.get_mut()[..count]);
            }
            Ok(None) => (),
            Err(error) if !self.pending && pipe_eof(&error) => {
                self.handle.take();
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    fn write(&mut self, input: &[u8], written: &mut usize) -> io::Result<()> {
        if self.handle.is_none() {
            return Ok(());
        }
        if !self.pending && *written == input.len() {
            self.handle.take();
            return Ok(());
        }
        let count = CHUNK.min(input.len() - *written);
        let result = if self.pending {
            self.completion()?
        } else {
            // Only fill an idle buffer; never mutate a pending WriteFile buffer.
            self.operation.as_mut().unwrap().buffer.get_mut()[..count]
                .copy_from_slice(&input[*written..*written + count]);
            self.start(false, count)?
        };
        if let Some(count) = result {
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "child stdin write zero",
                ));
            }
            *written += count;
        }
        if !self.pending && *written == input.len() {
            self.handle.take();
        }
        Ok(())
    }
    fn cancel(&self) {
        if self.pending {
            // A successful CancelIoEx (or ERROR_NOT_FOUND race) is NOT completion.
            unsafe {
                CancelIoEx(
                    self.raw(),
                    self.operation.as_ref().unwrap().overlapped.get(),
                );
            }
        }
    }
    fn retire(&mut self) -> bool {
        if self.pending {
            let _ = self.completion();
        }
        if !self.pending {
            self.handle.take();
        }
        !self.pending
    }
    fn wait_handle(&self) -> Option<HANDLE> {
        self.pending
            .then(|| self.operation.as_ref().unwrap().event.as_raw_handle())
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.cancel();
        let _ = self.retire();
        if self.pending {
            // Never block past cleanup's bound and NEVER free a kernel-referenced
            // OVERLAPPED/buffer/event. Close requests cancellation, but if even
            // completion cannot be proved, quarantine this small allocation for
            // process lifetime. The caller receives CleanupUnconfirmed on the
            // normal post-spawn path. No unbounded detached thread/join is used.
            self.handle.take();
            if let Some(operation) = self.operation.take() {
                mem::forget(operation);
            }
        }
    }
}
fn pipe_eof(error: &io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_NO_DATA as i32 || code == ERROR_PIPE_NOT_CONNECTED as i32)
}

fn transfer(
    child: &mut Child,
    pipes: &mut [Pipe; 3],
    input: &[u8],
    deadline: Instant,
    interruptible: bool,
    stop: &AtomicBool,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let (mut stdout, mut stderr, mut written) = (Vec::new(), Vec::new(), 0);
    let mut exited = false;
    loop {
        check_budget(deadline, interruptible, stop)?;
        // At most one chunk per stream between deadline/cancellation checks;
        // neither output nor blocked stdin can monopolize this pump.
        pipes[1].read(&mut stdout, STDOUT_LIMIT, "stdout")?;
        check_budget(deadline, interruptible, stop)?;
        pipes[2].read(&mut stderr, STDERR_LIMIT, "stderr")?;
        check_budget(deadline, interruptible, stop)?;
        pipes[0].write(input, &mut written)?;
        if !exited {
            exited = child.try_wait()?.is_some();
        }
        check_budget(deadline, interruptible, stop)?;
        if exited && pipes.iter().all(|p| p.handle.is_none()) {
            return Ok((stdout, stderr));
        }
        // If any pipe completed synchronously there is more immediate work; do
        // not add 20 ms per 8 KiB and penalize exact-limit duplex transfers.
        let idle = pipes.iter().any(|p| p.handle.is_some() && !p.pending);
        if idle {
            continue;
        }
        let mut handles: Vec<HANDLE> = pipes.iter().filter_map(Pipe::wait_handle).collect();
        if !exited {
            handles.push(child.as_raw_handle());
        }
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(POLL_MILLIS as u128) as u32;
        debug_assert!(!handles.is_empty());
        if unsafe { WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, millis) }
            == WAIT_FAILED
        {
            return Err(io::Error::last_os_error());
        }
    }
}

#[cfg(test)]
#[path = "process_windows_tests.rs"]
mod tests;
