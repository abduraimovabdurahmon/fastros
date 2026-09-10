//! Kernel Heap — bump allocator + GlobalAlloc
//!
//! Stage 1: Bump allocator — O(1) alloc, no free.
//!          Simple and safe for early kernel data structures.
//! Stage 2: TODO — slab allocator for small fixed-size objects,
//!          buddy allocator for large allocations.
//!
//! Heap region: 4 MB static buffer in BSS.  Upgraded to a VMM-backed
//! virtual region once VMM is operational.

use core::alloc::{GlobalAlloc, Layout};
use crate::kernel::sync::spinlock::SpinLock;

const HEAP_SIZE: usize = 4 * 1024 * 1024; // 4 MB

/// The heap backing store — lives in BSS, zeroed at startup.
#[repr(align(16))]
struct HeapStorage([u8; HEAP_SIZE]);

static mut HEAP: HeapStorage = HeapStorage([0u8; HEAP_SIZE]);
static mut HEAP_NEXT: usize = 0;
static mut HEAP_USED: usize = 0;

static HEAP_LOCK: SpinLock = SpinLock::new();

pub struct BumpAllocator;

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        HEAP_LOCK.lock();

        let start   = HEAP_NEXT;
        let aligned = (start + layout.align() - 1) & !(layout.align() - 1);
        let end     = aligned + layout.size();

        let ptr = if end <= HEAP_SIZE {
            HEAP_NEXT = end;
            HEAP_USED += layout.size();
            HEAP.0.as_mut_ptr().add(aligned)
        } else {
            core::ptr::null_mut() // OOM
        };

        HEAP_LOCK.unlock();
        ptr
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: dealloc is a no-op.
        // Memory is only reclaimed on process exit (whole heap reset) or
        // when the slab allocator replaces this.
        HEAP_LOCK.lock();
        HEAP_USED = HEAP_USED.saturating_sub(_layout.size());
        HEAP_LOCK.unlock();
    }
}

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

pub fn init() {
    // Nothing to do for the static bump allocator.
    // When upgrading to VMM-backed heap, map virtual pages here.
}

pub fn used_bytes()  -> usize { unsafe { HEAP_USED } }
pub fn total_bytes() -> usize { HEAP_SIZE }
