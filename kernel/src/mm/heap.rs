//! The kernel heap (`GlobalAlloc`):
//!
//! | request                    | served by                                  |
//! |----------------------------|--------------------------------------------|
//! | ≤ 2 KiB                    | hardened slab ([`fastros_alloc::slab`])    |
//! | ≤ 4 MiB (buddy max order)  | contiguous frames from the buddy allocator |
//! | larger                     | vmalloc (virtually contiguous, guarded)    |
//!
//! Every allocation is returned zero-filled and every freed byte is wiped, so
//! stale kernel data can never leak into a new object. An invalid free
//! (double free, foreign pointer) panics instead of corrupting the heap.

use super::{frame, phys_to_virt, virt_to_phys, vmalloc, PAGE_SIZE};
use crate::sync::SpinLock;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};
use fastros_alloc::slab::{class_for, PageProvider, Slab, SIZE_CLASSES};

struct BuddyPages;

impl PageProvider for BuddyPages {
    fn alloc_pages(&mut self, order: usize) -> Option<usize> {
        frame::alloc(order).map(phys_to_virt)
    }
    fn free_pages(&mut self, addr: usize, order: usize) {
        let p = virt_to_phys(addr).expect("slab page outside the direct map");
        frame::free(p, order);
    }
}

static SLAB: SpinLock<Option<Slab<BuddyPages>>> = SpinLock::new(None);
static USED: AtomicUsize = AtomicUsize::new(0);

pub fn init() {
    let secret = crate::arch::cpu::hw_random().unwrap_or(0) ^ crate::arch::cpu::rdtsc().rotate_left(29);
    *SLAB.lock() = Some(Slab::new(BuddyPages, secret as usize));
}

pub fn used_bytes() -> usize {
    USED.load(Ordering::Relaxed)
}

pub fn slab_footprint() -> usize {
    SLAB.lock().as_ref().map_or(0, |s| s.footprint())
}

pub fn slab_stats() -> [fastros_alloc::slab::ClassStats; 8] {
    SLAB.lock().as_ref().map(|s| s.stats()).unwrap_or_default()
}

fn large_order(layout: &Layout) -> Option<usize> {
    let order = super::order_for(layout.size());
    (order <= frame::MAX_FRAME_ORDER && layout.align() <= PAGE_SIZE << order).then_some(order)
}

struct KernelHeap;

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let p = if let Some(class) = class_for(layout.size(), layout.align()) {
                USED.fetch_add(SIZE_CLASSES[class], Ordering::Relaxed);
                SLAB.lock().as_mut().and_then(|s| s.alloc(class))
            } else if let Some(order) = large_order(&layout) {
                USED.fetch_add(PAGE_SIZE << order, Ordering::Relaxed);
                frame::alloc_zeroed(order).map(phys_to_virt).map(|v| v as *mut u8)
            } else if layout.align() <= PAGE_SIZE {
                let pages = super::align_up(layout.size(), PAGE_SIZE) / PAGE_SIZE;
                USED.fetch_add(pages * PAGE_SIZE, Ordering::Relaxed);
                vmalloc::alloc(pages).map(|v| v as *mut u8)
            } else {
                None
            };
            p.unwrap_or(core::ptr::null_mut())
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            let addr = ptr as usize;
            if let Some(class) = class_for(layout.size(), layout.align()) {
                USED.fetch_sub(SIZE_CLASSES[class], Ordering::Relaxed);
                let r = SLAB.lock().as_mut().expect("heap::init").free(ptr, class);
                if let Err(e) = r {
                    panic!("heap: invalid free of {addr:#x} ({} bytes): {e:?}", layout.size());
                }
            } else if vmalloc::contains(addr) {
                let pages = super::align_up(layout.size(), PAGE_SIZE) / PAGE_SIZE;
                USED.fetch_sub(pages * PAGE_SIZE, Ordering::Relaxed);
                vmalloc::free(addr);
            } else {
                let order = large_order(&layout).expect("layout changed between alloc and dealloc");
                USED.fetch_sub(PAGE_SIZE << order, Ordering::Relaxed);
                core::ptr::write_bytes(ptr, 0, PAGE_SIZE << order);
                frame::free(virt_to_phys(addr).expect("large block outside the direct map"), order);
            }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            // Every path above already returns zeroed memory.
            self.alloc(layout)
        }
    }
}

#[global_allocator]
static HEAP: KernelHeap = KernelHeap;
