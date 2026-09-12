//! Swap: a backing store for anonymous pages under memory pressure.
//!
//! When a user page fault cannot get a physical frame, the kernel reclaims cold
//! anonymous-private pages of the faulting address space by writing them to a
//! dedicated **swap block device** and replacing their page-table entries with a
//! swap reference. A later access to such a page faults, reads the contents back
//! into a fresh frame, and frees the swap slot.
//!
//! The swap store is a *separate* raw disk (`sdb`), never the root filesystem —
//! so swap I/O touches no filesystem metadata and can never corrupt it, and a
//! reclaim under out-of-memory never has to allocate to do its I/O.
//!
//! Only anonymous-private, singly-owned pages are evicted; shared, file-backed
//! and copy-on-write pages are left in place. Eviction is race-safe: the page's
//! dirty bit is re-checked after the (sleeping) disk write, so a page written
//! concurrently is never replaced by a stale swap copy.

use super::{PhysAddr, PAGE_SIZE};
use crate::drivers::block::BlockDevice;
use crate::sync::{Mutex, SpinLock};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Sectors per page slot (4096 / 512).
const SECTORS_PER_SLOT: u64 = (PAGE_SIZE / 512) as u64;

struct SwapDev {
    dev: Arc<dyn BlockDevice>,
    /// Usage bitmap: bit `i` set = slot `i` in use.
    bitmap: SpinLock<Vec<u64>>,
    slots: usize,
}

static SWAP: SpinLock<Option<SwapDev>> = SpinLock::new(None);
static ENABLED: AtomicBool = AtomicBool::new(false);
static USED: AtomicU64 = AtomicU64::new(0);

/// A single serialized reclaim/eviction context holding the bounce buffer used
/// to stage a page's contents across the (sleeping) disk write. Serializing
/// reclaim keeps eviction simple and bounds the memory it needs to a constant.
static RECLAIM: Mutex<Bounce> = Mutex::new(Bounce { buf: [0u8; PAGE_SIZE] });

/// Page-aligned so its address satisfies the block layer's DMA/PIO alignment
/// requirement (an odd buffer address is rejected outright).
#[repr(C, align(4096))]
struct Bounce {
    buf: [u8; PAGE_SIZE],
}

/// True once a swap device is configured. Cheap to check on the fault path.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// (used_slots, total_slots) for `/proc/meminfo`-style reporting.
pub fn usage() -> (u64, u64) {
    let total = SWAP.lock().as_ref().map(|s| s.slots as u64).unwrap_or(0);
    (USED.load(Ordering::Relaxed), total)
}

/// Pick a swap device — a raw disk that is not the root filesystem. The root fs
/// lives on `sda`; a second disk (`sdb`) is used as swap. No device → no swap.
pub fn init() {
    let dev = match crate::drivers::block::get("sdb") {
        Some(d) => d,
        None => {
            crate::kinfo!("swap", "no swap device (sdb) present; swap disabled");
            return;
        }
    };
    let slots = (dev.sectors() / SECTORS_PER_SLOT) as usize;
    if slots == 0 {
        return;
    }
    let words = slots.div_ceil(64);
    let sw = SwapDev { dev, bitmap: SpinLock::new(vec![0u64; words]), slots };
    crate::kinfo!("swap", "{} slots ({} MiB) on sdb", slots, (slots as u64 * PAGE_SIZE as u64) >> 20);
    *SWAP.lock() = Some(sw);
    ENABLED.store(true, Ordering::Release);
}

/// Reserve a free swap slot, or `None` when the device is full.
fn alloc_slot() -> Option<usize> {
    let guard = SWAP.lock();
    let sw = guard.as_ref()?;
    let mut bm = sw.bitmap.lock();
    for (wi, word) in bm.iter_mut().enumerate() {
        if *word != u64::MAX {
            let bit = (!*word).trailing_zeros() as usize;
            let idx = wi * 64 + bit;
            if idx >= sw.slots {
                break;
            }
            *word |= 1u64 << bit;
            USED.fetch_add(1, Ordering::Relaxed);
            return Some(idx);
        }
    }
    None
}

/// Release a swap slot (on swap-in, unmap, or address-space teardown).
pub fn free_slot(idx: usize) {
    let guard = SWAP.lock();
    let Some(sw) = guard.as_ref() else { return };
    let (wi, bit) = (idx / 64, idx % 64);
    let mut bm = sw.bitmap.lock();
    if let Some(w) = bm.get_mut(wi) {
        if *w & (1u64 << bit) != 0 {
            *w &= !(1u64 << bit);
            USED.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

fn device() -> Option<Arc<dyn BlockDevice>> {
    SWAP.lock().as_ref().map(|s| s.dev.clone())
}

/// Write one page's worth of bytes to a swap slot; returns false on I/O error.
fn write_slot(idx: usize, data: &[u8; PAGE_SIZE]) -> bool {
    let Some(dev) = device() else { return false };
    dev.write(idx as u64 * SECTORS_PER_SLOT, data).is_ok()
}

/// Read a swap slot back into a page buffer; returns false on I/O error.
pub fn read_slot(idx: usize, out: &mut [u8; PAGE_SIZE]) -> bool {
    let Some(dev) = device() else { return false };
    dev.read(idx as u64 * SECTORS_PER_SLOT, out).is_ok()
}

/// Stage `phys`'s current contents to a fresh swap slot and return the slot.
/// The caller must have ensured the page is stable (dirty bit cleared) before
/// calling and must re-check the dirty bit afterwards; this only does the I/O.
/// Returns `None` if the swap device is full or the write failed.
pub fn store_page(phys: PhysAddr) -> Option<usize> {
    let idx = alloc_slot()?;
    let mut ctx = RECLAIM.lock();
    // Copy the page into the bounce buffer, then write it out.
    unsafe {
        core::ptr::copy_nonoverlapping(super::phys_to_virt(phys) as *const u8, ctx.buf.as_mut_ptr(), PAGE_SIZE);
    }
    let ok = write_slot(idx, &ctx.buf);
    drop(ctx);
    if ok {
        Some(idx)
    } else {
        free_slot(idx);
        None
    }
}
