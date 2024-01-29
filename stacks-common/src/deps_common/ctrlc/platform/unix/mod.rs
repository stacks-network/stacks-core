// Copyright (c) 2017 CtrlC developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use std::os::unix::io::RawFd;

use nix::unistd;

use crate::deps_common::ctrlc::error::Error as CtrlcError;
use crate::deps_common::ctrlc::SignalId;

static mut PIPE: (RawFd, RawFd) = (-1, -1);

/// Platform specific error type
pub type Error = nix::Error;

/// Platform specific signal type
pub type Signal = nix::sys::signal::Signal;

impl SignalId {
    pub fn from_c_signal(c_sig_id: nix::libc::c_int) -> SignalId {
        match c_sig_id {
            x if x == Signal::SIGTERM as nix::libc::c_int
                || x == Signal::SIGHUP as nix::libc::c_int =>
            {
                SignalId::Termination
            }
            x if x == Signal::SIGINT as nix::libc::c_int => SignalId::CtrlC,
            x if x == Signal::SIGBUS as nix::libc::c_int => SignalId::Bus,
            _ => SignalId::Other,
        }
    }

    pub fn from_u8(sig_id: u8) -> SignalId {
        match sig_id {
            x if x == SignalId::CtrlC as u8 => SignalId::CtrlC,
            x if x == SignalId::Termination as u8 => SignalId::Termination,
            x if x == SignalId::Bus as u8 => SignalId::Bus,
            _ => SignalId::Other,
        }
    }
}

extern "C" fn os_handler(c_sig_id: nix::libc::c_int) {
    let sig_id = SignalId::from_c_signal(c_sig_id) as u8;
    // Assuming this always succeeds. Can't really handle errors in any meaningful way.
    unsafe {
        let _ = unistd::write(PIPE.1, &[sig_id]);
    }
}

// pipe2(2) is not available on macOS or iOS, so we need to use pipe(2) and fcntl(2)
#[inline]
#[cfg(any(target_os = "ios", target_os = "macos"))]
fn pipe2(flags: nix::fcntl::OFlag) -> nix::Result<(RawFd, RawFd)> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag, OFlag};

    let pipe = unistd::pipe()?;

    let mut res = Ok(0);

    if flags.contains(OFlag::O_CLOEXEC) {
        res = res
            .and_then(|_| fcntl(pipe.0, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)))
            .and_then(|_| fcntl(pipe.1, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)));
    }

    if flags.contains(OFlag::O_NONBLOCK) {
        res = res
            .and_then(|_| fcntl(pipe.0, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)))
            .and_then(|_| fcntl(pipe.1, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)));
    }

    match res {
        Ok(_) => Ok(pipe),
        Err(e) => {
            let _ = unistd::close(pipe.0);
            let _ = unistd::close(pipe.1);
            Err(e)
        }
    }
}

#[inline]
#[cfg(not(any(target_os = "ios", target_os = "macos")))]
fn pipe2(flags: nix::fcntl::OFlag) -> nix::Result<(RawFd, RawFd)> {
    unistd::pipe2(flags)
}

/// Register os signal handler.
///
/// Must be called before calling [`block_ctrl_c()`](fn.block_ctrl_c.html)
/// and should only be called once.
///
/// # Errors
/// Will return an error if a system error occurred.
///
#[inline]
pub unsafe fn init_os_handler() -> Result<(), Error> {
    use nix::fcntl;
    use nix::sys::signal;

    PIPE = pipe2(fcntl::OFlag::O_CLOEXEC)?;

    let close_pipe = |e: nix::Error| -> Error {
        // Try to close the pipes. close() should not fail,
        // but if it does, there isn't much we can do
        let _ = unistd::close(PIPE.1);
        let _ = unistd::close(PIPE.0);
        e
    };

    // Make sure we never block on write in the os handler.
    if let Err(e) = fcntl::fcntl(PIPE.1, fcntl::FcntlArg::F_SETFL(fcntl::OFlag::O_NONBLOCK)) {
        return Err(close_pipe(e));
    }

    let handler = signal::SigHandler::Handler(os_handler);
    let new_action = signal::SigAction::new(
        handler,
        signal::SaFlags::SA_RESTART,
        signal::SigSet::empty(),
    );

    let sigint_old = match signal::sigaction(signal::Signal::SIGINT, &new_action) {
        Ok(old) => old,
        Err(e) => return Err(close_pipe(e)),
    };

    let sigterm_old = match signal::sigaction(signal::Signal::SIGTERM, &new_action) {
        Ok(old) => old,
        Err(e) => {
            signal::sigaction(signal::Signal::SIGINT, &sigint_old).unwrap();
            return Err(close_pipe(e));
        }
    };

    // new with stacks-blockchain: build-in "termination" feature, and handle SIGBUS
    let sigbus_old = match signal::sigaction(signal::Signal::SIGBUS, &new_action) {
        Ok(old) => old,
        Err(e) => {
            signal::sigaction(signal::Signal::SIGINT, &sigint_old).unwrap();
            signal::sigaction(signal::Signal::SIGTERM, &sigterm_old).unwrap();
            return Err(close_pipe(e));
        }
    };

    match signal::sigaction(signal::Signal::SIGHUP, &new_action) {
        Ok(_) => {}
        Err(e) => {
            signal::sigaction(signal::Signal::SIGINT, &sigint_old).unwrap();
            signal::sigaction(signal::Signal::SIGTERM, &sigterm_old).unwrap();
            signal::sigaction(signal::Signal::SIGBUS, &sigbus_old).unwrap();
            return Err(close_pipe(e));
        }
    }

    // TODO: Maybe throw an error if old action is not SigDfl.

    Ok(())
}

/// Blocks until a Ctrl-C signal is received.
///
/// Must be called after calling [`init_os_handler()`](fn.init_os_handler.html).
///
/// # Errors
/// Will return an error if a system error occurred.
///
#[inline]
pub unsafe fn block_ctrl_c() -> Result<SignalId, CtrlcError> {
    use std::io;
    let mut buf = [0u8];

    // TODO: Can we safely convert the pipe fd into a std::io::Read
    // with std::os::unix::io::FromRawFd, this would handle EINTR
    // and everything for us.
    loop {
        match unistd::read(PIPE.0, &mut buf[..]) {
            Ok(1) => break,
            Ok(_) => return Err(CtrlcError::System(io::ErrorKind::UnexpectedEof.into())),
            Err(nix::errno::Errno::EINTR) => {}
            Err(e) => return Err(e.into()),
        }
    }

    Ok(SignalId::from_u8(buf[0]))
}
