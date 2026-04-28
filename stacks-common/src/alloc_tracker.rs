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
    static THREAD_ALLOCATED: Cell<u64> = const { Cell::new(0) };
    static THREAD_DEALLOCATED: Cell<u64> = const { Cell::new(0) };
}

/// Read cumulative bytes allocated on the current thread.
///
/// Returns 0 if the tracking allocator is not installed or if TLS is
/// being torn down (thread shutdown).
pub fn thread_allocated() -> u64 {
    THREAD_ALLOCATED.try_with(Cell::get).unwrap_or(0)
}

/// Read cumulative bytes deallocated on the current thread.
///
/// Returns 0 if the tracking allocator is not installed or if TLS is
/// being torn down (thread shutdown).
pub fn thread_deallocated() -> u64 {
    THREAD_DEALLOCATED.try_with(Cell::get).unwrap_or(0)
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
            let _ = THREAD_ALLOCATED.try_with(|c| c.set(c.get() + layout.size() as u64));
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.inner.dealloc(ptr, layout) };
        let _ = THREAD_DEALLOCATED.try_with(|c| c.set(c.get() + layout.size() as u64));
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.inner.alloc_zeroed(layout) };
        if !ptr.is_null() {
            let _ = THREAD_ALLOCATED.try_with(|c| c.set(c.get() + layout.size() as u64));
        }
        ptr
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { self.inner.realloc(ptr, layout, new_size) };
        // Note: if `new_ptr` is null, no deallocation or allocation
        // happened, `ptr` remains valid.
        if !new_ptr.is_null() {
            let _ = THREAD_DEALLOCATED.try_with(|c| c.set(c.get() + layout.size() as u64));
            let _ = THREAD_ALLOCATED.try_with(|c| c.set(c.get() + new_size as u64));
        }
        new_ptr
    }
}
