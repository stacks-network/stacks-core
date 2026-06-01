// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Platform-specific per-thread CPU time (user + kernel), in nanoseconds.
//!
//! | Platform | Source | Typical resolution |
//! |----------|--------|--------------------|
//! | macOS | `clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID)` | sub-microsecond |
//! | Linux | `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` | sub-microsecond |
//! | Windows | `GetThreadTimes` (kernel32) | ~15.6 ms |
//! | Other | — | returns 0 (unsupported) |
//!
//! **Windows caveat:** `GetThreadTimes` only advances once per system clock interrupt (~15.6 ms),
//! so short spans may report 0 ns of CPU time. Aggregated totals converge to accurate values.

trait ThreadCpuTimer {
    /// Cumulative CPU time (user + kernel) of the calling thread, in nanoseconds.
    /// Must be monotonically non-decreasing within a thread.
    fn thread_cpu_nanos() -> u64;
}

#[cfg(target_os = "macos")]
mod darwin {
    unsafe extern "C" {
        /// In libSystem on macOS: `uint64_t clock_gettime_nsec_np(clockid_t clk_id);`
        pub(super) fn clock_gettime_nsec_np(clk_id: libc::clockid_t) -> u64;
    }

    pub(super) struct Timer;

    impl super::ThreadCpuTimer for Timer {
        #[inline(always)]
        fn thread_cpu_nanos() -> u64 {
            // Sub-microsecond resolution; single FFI call.
            unsafe { clock_gettime_nsec_np(libc::CLOCK_THREAD_CPUTIME_ID) }
        }
    }

    #[test]
    fn timer_equivalence_smoke() {
        fn via_timespec() -> u64 {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            let _ = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
            (ts.tv_sec as u64) * 1_000_000_000u64 + (ts.tv_nsec as u64)
        }

        fn via_nsec_np() -> u64 {
            unsafe { clock_gettime_nsec_np(libc::CLOCK_THREAD_CPUTIME_ID) }
        }

        const EPS_NS: u64 = 50_000;

        for _ in 0..10_000 {
            let a1 = via_timespec();
            let b = via_nsec_np();
            let a2 = via_timespec();

            assert!(
                a2 >= a1,
                "timespec clock was not monotonic: a1={a1}, a2={a2}"
            );
            if b + EPS_NS < a1 || b > a2 + EPS_NS {
                panic!("nsec_np not consistent: a1={a1}, b={b}, a2={a2}, eps={EPS_NS}ns");
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    pub(super) struct Timer;

    impl super::ThreadCpuTimer for Timer {
        #[inline(always)]
        fn thread_cpu_nanos() -> u64 {
            // Sub-microsecond resolution via POSIX clock_gettime.
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe {
                libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts);
            }
            (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    /// Win32 FILETIME (100-nanosecond intervals).
    #[repr(C)]
    struct FILETIME {
        low: u32,
        high: u32,
    }

    impl FILETIME {
        /// Convert to a single u64 (units: 100 ns intervals).
        #[inline]
        fn as_100ns(&self) -> u64 {
            (self.high as u64) << 32 | self.low as u64
        }
    }

    #[allow(non_snake_case)]
    unsafe extern "system" {
        fn GetCurrentThread() -> *mut core::ffi::c_void;
        fn GetThreadTimes(
            hThread: *mut core::ffi::c_void,
            lpCreationTime: *mut FILETIME,
            lpExitTime: *mut FILETIME,
            lpKernelTime: *mut FILETIME,
            lpUserTime: *mut FILETIME,
        ) -> i32;
    }

    pub(super) struct Timer;

    impl super::ThreadCpuTimer for Timer {
        #[inline(always)]
        fn thread_cpu_nanos() -> u64 {
            // See module-level docs for resolution caveats (~15.6 ms).
            unsafe {
                let mut creation: FILETIME = core::mem::zeroed();
                let mut exit: FILETIME = core::mem::zeroed();
                let mut kernel: FILETIME = core::mem::zeroed();
                let mut user: FILETIME = core::mem::zeroed();

                let handle = GetCurrentThread();
                if GetThreadTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0 {
                    // kernel + user = total CPU time. FILETIME units are 100 ns intervals; multiply
                    // by 100 for nanos.
                    (kernel.as_100ns() + user.as_100ns()) * 100
                } else {
                    0
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported {
    pub(super) struct Timer;

    impl super::ThreadCpuTimer for Timer {
        #[inline(always)]
        fn thread_cpu_nanos() -> u64 {
            // No per-thread CPU timer available on this platform.
            0
        }
    }
}

#[cfg(target_os = "macos")]
use darwin::Timer as PlatformTimer;
#[cfg(target_os = "linux")]
use linux::Timer as PlatformTimer;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use unsupported::Timer as PlatformTimer;
#[cfg(target_os = "windows")]
use windows::Timer as PlatformTimer;

/// Cumulative CPU time (user + kernel) of the calling thread in nanoseconds.
/// See [module-level docs](self) for per-platform resolution.
#[inline(always)]
pub fn thread_cpu_nanos() -> u64 {
    PlatformTimer::thread_cpu_nanos()
}
