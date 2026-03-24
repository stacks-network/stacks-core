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

//! A simple allocation-counting backend for the `marf` bench harness.
//!
//! This module installs a single global allocator wrapper that records
//! alloc/realloc/dealloc call and byte totals, and exposes `reset_stats()`
//! and `snapshot()` so each subcommand can measure its own phases consistently.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering};

// Pick the backing allocator based on platform, matching the choice used in the `stacks-node`
// binary.
#[rustfmt::skip]
#[cfg(any(target_os = "macos", target_os = "windows", target_arch = "arm"))]
use std::alloc::System;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
use tikv_jemallocator::Jemalloc;

/// A global allocator wrapper that counts allocation calls and bytes.
pub struct CountingAllocator;

/// A snapshot of allocation stats at a point in time.
#[derive(Clone, Copy, Debug)]
pub struct Snapshot {
    pub alloc_calls: u64,
    pub alloc_bytes: u64,
    pub realloc_calls: u64,
    pub dealloc_calls: u64,
    pub dealloc_bytes: u64,
}

/// Accumulated count of allocation calls, across all threads, since the last reset.
static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
/// Accumulated count of allocated bytes, across all threads, since the last reset.
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
/// Accumulated count of realloc calls, across all threads, since the last reset.
static REALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
/// Accumulated count of deallocation calls, across all threads, since the last reset.
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
/// Accumulated count of deallocated bytes, across all threads, since the last reset.
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);

// Set the backing allocator (jemalloc on supported platforms, system allocator otherwise) and
// install the counting wrapper as the global allocator.

#[cfg(not(any(target_os = "macos", target_os = "windows", target_arch = "arm")))]
static ALLOCATOR: Jemalloc = Jemalloc;
#[cfg(any(target_os = "macos", target_os = "windows", target_arch = "arm"))]
static ALLOCATOR: System = System;

/// The global allocator wrapper that counts calls and bytes.
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// `GlobalAlloc` implementation which wraps the backing allocator and updates the global counters
/// on each call.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { ALLOCATOR.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { ALLOCATOR.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        unsafe { ALLOCATOR.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        REALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        DEALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        unsafe { ALLOCATOR.realloc(ptr, layout, new_size) }
    }
}

/// Reset all allocation counters to zero.
pub fn reset_stats() {
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    REALLOC_CALLS.store(0, Ordering::Relaxed);
    DEALLOC_CALLS.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
}

/// Take a snapshot of the current allocation counters.
pub fn snapshot() -> Snapshot {
    Snapshot {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        realloc_calls: REALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
    }
}
