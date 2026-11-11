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
use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout};
use std::sync::OnceLock;

thread_local! {
    static THREAD_ALLOCATIONS: Cell<AllocationCounter> = const { Cell::new(AllocationCounter::ZERO) };
}

/// A static bool for checking if the tracking allocator is installed
///  as the global allocator
static TRACKING_ALLOCATOR_INSTALLED: OnceLock<bool> = OnceLock::new();

/// Counter for net allocated bytes
#[derive(Clone, Copy)]
pub struct AllocationCounter {
    net_allocated: u64,
}

impl AllocationCounter {
    pub const ZERO: Self = Self { net_allocated: 0 };

    /// Net allocation (allocated - deallocated) over a `baseline`
    pub fn net_allocated(&self, baseline: &AllocationCounter) -> u64 {
        self.net_allocated.saturating_sub(baseline.net_allocated)
    }

    /// Return `self` with net allocated incremented by `increment`
    fn increment(mut self, increment: u64) -> Self {
        self.net_allocated = self.net_allocated.saturating_add(increment);
        self
    }

    /// Return `self` with net allocated decremented by `decrement`
    fn decrement(mut self, decrement: u64) -> Self {
        self.net_allocated = self.net_allocated.saturating_sub(decrement);
        self
    }
}

/// Check if the tracking allocator is installed
///
/// If the check has already been performed in this process,
///  it returns the prior value. Otherwise, it forces an allocation
///  and checks if the tracker picked it up.
pub fn tracking_allocator_installed() -> bool {
    *TRACKING_ALLOCATOR_INSTALLED.get_or_init(|| {
        let before = thread_allocated();
        let probe: Vec<u8> = Vec::with_capacity(1024);
        // Prevent the optimizer from eliding the allocation.                                                             
        std::hint::black_box(&probe);
        let installed = thread_allocated().net_allocated(&before) > 0;
        if !installed {
            error!(
                "TrackingAllocator is not installed as the global allocator; any configured memory limits will never trigger"
            );
        }
        drop(probe);
        installed
    })
}

/// Read the allocation counter for the current thread.
///
/// Returns AllocationCounter::ZERO if the tracking allocator is not installed or if TLS is
/// being torn down (thread shutdown).
pub fn thread_allocated() -> AllocationCounter {
    THREAD_ALLOCATIONS
        .try_with(Cell::get)
        .unwrap_or(AllocationCounter::ZERO)
}

/// A `GlobalAlloc` wrapper that counts per-thread allocations and
/// deallocations. Delegates all actual allocation work to the inner
/// allocator `A`.
pub struct TrackingAllocator<A: GlobalAlloc> {
    /// The underlying allocator that performs the real work.
    pub inner: A,
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for TrackingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc(layout) };
        if !ptr.is_null() {
            let _ = THREAD_ALLOCATIONS.try_with(|c| {
                let next = c.get().increment(layout.size() as u64);
                c.set(next);
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        let _ = THREAD_ALLOCATIONS.try_with(|c| {
            let next = c.get().decrement(layout.size() as u64);
            c.set(next);
        });
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let _ = THREAD_ALLOCATIONS.try_with(|c| {
                let next = c.get().increment(layout.size() as u64);
                c.set(next);
            });
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { self.inner.realloc(ptr, layout, new_size) };
        // Note: if `new_ptr` is null, no deallocation or allocation
        // happened, `ptr` remains valid.
        if !new_ptr.is_null() {
            let _ = THREAD_ALLOCATIONS.try_with(|c| {
                let next = c
                    .get()
                    .decrement(layout.size() as u64)
                    .increment(new_size as u64);
                c.set(next);
            });
        }
        new_ptr
    }
}
