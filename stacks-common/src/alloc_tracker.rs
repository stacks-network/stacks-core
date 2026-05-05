// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;

thread_local! {
    static THREAD_ALLOCATIONS: Cell<AllocationCounter> = const { Cell::new(AllocationCounter::ZERO) };
}

/// Counter for allocated and deallocated bytes
#[derive(Clone, Copy)]
pub struct AllocationCounter {
    allocated: u64,
    deallocated: u64,
}

impl AllocationCounter {
    pub const ZERO: Self = Self {
        allocated: 0,
        deallocated: 0,
    };

    /// Net allocation (allocated - deallocated) over a `baseline`
    pub fn net_allocated(&self, baseline: &AllocationCounter) -> u64 {
        let alloc = self.allocated.saturating_sub(baseline.allocated);
        let dealloc = self.deallocated.saturating_sub(baseline.deallocated);
        alloc.saturating_sub(dealloc)
    }

    /// Return `self` with allocated incremented by `increment`
    fn increment_alloc(mut self, increment: u64) -> Self {
        self.allocated += increment;
        self
    }

    /// Return `self` with deallocated incremented by `increment`
    fn increment_dealloc(mut self, increment: u64) -> Self {
        self.deallocated += increment;
        self
    }
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
                let next = c.get().increment_alloc(layout.size() as u64);
                c.set(next);
            });
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        let _ = THREAD_ALLOCATIONS.try_with(|c| {
            let next = c.get().increment_dealloc(layout.size() as u64);
            c.set(next);
        });
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let _ = THREAD_ALLOCATIONS.try_with(|c| {
                let next = c.get().increment_alloc(layout.size() as u64);
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
                    .increment_dealloc(layout.size() as u64)
                    .increment_alloc(new_size as u64);
                c.set(next);
            });
        }
        new_ptr
    }
}
