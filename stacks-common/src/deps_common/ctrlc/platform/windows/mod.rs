// Copyright (c) 2017 CtrlC developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT
// license <LICENSE-MIT or http://opensource.org/licenses/MIT>,
// at your option. All files in the project carrying such
// notice may not be copied, modified, or distributed except
// according to those terms.

use std::{io, ptr};

use winapi::ctypes::c_long;
use winapi::shared::minwindef::{BOOL, DWORD, FALSE, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::consoleapi::SetConsoleCtrlHandler;
use winapi::um::handleapi::CloseHandle;
use winapi::um::synchapi::{ReleaseSemaphore, WaitForSingleObject};
use winapi::um::winbase::{CreateSemaphoreA, INFINITE, WAIT_FAILED, WAIT_OBJECT_0};

use crate::deps_common::ctrlc::SignalId;

/// Platform specific error type
pub type Error = io::Error;

/// Platform specific signal type
pub type Signal = DWORD;

const MAX_SEM_COUNT: c_long = 255;
static mut SEMAPHORE: HANDLE = 0 as HANDLE;

unsafe extern "system" fn os_handler(_: DWORD) -> BOOL {
    // Assuming this always succeeds. Can't really handle errors in any meaningful way.
    ReleaseSemaphore(SEMAPHORE, 1, ptr::null_mut());
    TRUE
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
    SEMAPHORE = CreateSemaphoreA(ptr::null_mut(), 0, MAX_SEM_COUNT, ptr::null());
    if SEMAPHORE.is_null() {
        return Err(io::Error::last_os_error());
    }

    if SetConsoleCtrlHandler(Some(os_handler), TRUE) == FALSE {
        let e = io::Error::last_os_error();
        CloseHandle(SEMAPHORE);
        SEMAPHORE = 0 as HANDLE;
        return Err(e);
    }

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
pub unsafe fn block_ctrl_c() -> Result<SignalId, Error> {
    match WaitForSingleObject(SEMAPHORE, INFINITE) {
        WAIT_OBJECT_0 => Ok(SignalId::CtrlC),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        ret => Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "WaitForSingleObject(), unexpected return value \"{:x}\"",
                ret
            ),
        )),
    }
}
