//! Physical Memory Manager (PMM)
//!
//! Manages 4 KB physical frames using a static bitmap.
//! One bit per frame: 0 = free, 1 = used.
//!
//! Memory layout assumed for QEMU -m 256M:
//!   0x000000 – 0x0FFFFF   Low 1 MB (BIOS, VGA, ROM) — marked USED
//!   0x100000 – 0x3FFFFF   Kernel (~3 MB) — marked USED
//!   0x400000 – 0xFFFFFFF  Free (~252 MB)
//!
//! When Multiboot2 is fully parsed, init() will use the real memory map.

pub mod bitmap;

use bitmap::{addr_to_frame, frame_to_addr, find_free, set_bit, clear_bit, is_free, FRAME_SIZE};
use crate::kernel::sync::spinlock::SpinLock;

/// Maximum addressable memory: 4 GB → 1 M frames → 128 KB bitmap.
const MAX_FRAMES:   usize = 4 * 1024 * 1024 * 1024 / 4096; // 1_048_576
const BITMAP_WORDS: usize = MAX_FRAMES / 64;                // 16_384

/// The bitmap — all 1s initially (everything "used" until freed by init).
static mut BITMAP: [u64; BITMAP_WORDS] = [!0u64; BITMAP_WORDS];
static mut TOTAL_FRAMES: usize = 0;
static mut FREE_FRAMES:  usize = 0;

static PMM_LOCK: SpinLock = SpinLock::new();

/// Initialize the PMM from a memory range.
///
/// For QEMU -m 256M this is called with `usable_start=0x40_0000, usable_end=0x1000_0000`.
/// When Multiboot2 parsing is implemented, call this once per usable region.
pub fn init() {
    // Default: free the region 4 MB – 256 MB for QEMU -m 256M.
    // Kernel is linked at 1 MB and assumed to be < 3 MB in size.
    add_region(0x0040_0000, 0x1000_0000);
}

/// Mark a physical range [start, end) as free (usable RAM).
pub fn add_region(start: u64, end: u64) {
    PMM_LOCK.lock();
    unsafe {
        let first = addr_to_frame(start);
        let last  = addr_to_frame(end.saturating_sub(1));
        for f in first..=last {
            if f < MAX_FRAMES && !is_free(&BITMAP, f) {
                clear_bit(&mut BITMAP, f);
                FREE_FRAMES  += 1;
                TOTAL_FRAMES += 1;
            }
        }
    }
    PMM_LOCK.unlock();
}

/// Mark a physical range [start, end) as reserved (do not allocate).
pub fn reserve_region(start: u64, end: u64) {
    PMM_LOCK.lock();
    unsafe {
        let first = addr_to_frame(start);
        let last  = addr_to_frame(end.saturating_sub(1));
        for f in first..=last {
            if f < MAX_FRAMES && is_free(&BITMAP, f) {
                set_bit(&mut BITMAP, f);
                FREE_FRAMES = FREE_FRAMES.saturating_sub(1);
            }
        }
    }
    PMM_LOCK.unlock();
}

/// Allocate one physical frame.  Returns its physical address or None if OOM.
pub fn alloc_frame() -> Option<u64> {
    PMM_LOCK.lock();
    let result = unsafe {
        find_free(&BITMAP).and_then(|f| {
            if f < MAX_FRAMES {
                set_bit(&mut BITMAP, f);
                FREE_FRAMES = FREE_FRAMES.saturating_sub(1);
                Some(frame_to_addr(f))
            } else {
                None
            }
        })
    };
    PMM_LOCK.unlock();
    result
}

/// Allocate a contiguous run of `count` frames.  Returns the first frame's address.
pub fn alloc_frames(count: usize) -> Option<u64> {
    if count == 0 { return Some(0); }
    if count == 1 { return alloc_frame(); }

    PMM_LOCK.lock();
    let result = unsafe {
        // Linear scan for `count` consecutive free frames
        let mut run_start = 0usize;
        let mut run_len   = 0usize;
        for f in 0..MAX_FRAMES {
            if is_free(&BITMAP, f) {
                if run_len == 0 { run_start = f; }
                run_len += 1;
                if run_len == count {
                    for i in run_start..run_start + count {
                        set_bit(&mut BITMAP, i);
                    }
                    FREE_FRAMES = FREE_FRAMES.saturating_sub(count);
                    break;
                }
            } else {
                run_len = 0;
            }
        }
        if run_len == count { Some(frame_to_addr(run_start)) } else { None }
    };
    PMM_LOCK.unlock();
    result
}

/// Free a previously allocated physical frame.
pub fn free_frame(phys: u64) {
    let f = addr_to_frame(phys);
    PMM_LOCK.lock();
    unsafe {
        if f < MAX_FRAMES && !is_free(&BITMAP, f) {
            clear_bit(&mut BITMAP, f);
            FREE_FRAMES += 1;
        }
    }
    PMM_LOCK.unlock();
}

/// Free `count` contiguous frames starting at `phys`.
pub fn free_frames(phys: u64, count: usize) {
    for i in 0..count as u64 {
        free_frame(phys + i * FRAME_SIZE);
    }
}

pub fn free_frame_count()  -> usize { unsafe { FREE_FRAMES  } }
pub fn total_frame_count() -> usize { unsafe { TOTAL_FRAMES } }
