//! Bounded capture of locally owned subprocesses, not ownership of a shared
//! service/gateway contacted by those subprocesses.

#[cfg(target_os = "macos")]
#[path = "process_macos.rs"]
mod implementation;
#[cfg(windows)]
#[path = "process_windows.rs"]
mod implementation;

#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("bounded subprocess capture supports macOS and native Windows only");

#[cfg(any(target_os = "macos", windows))]
pub(crate) use implementation::{capture, cleanup_unconfirmed};
