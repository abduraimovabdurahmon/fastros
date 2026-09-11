//! Physical frame allocator: one buddy allocator over all of RAM.

use super::{align_down, align_up, phys_to_virt, PhysAddr, PAGE_SIZE};
use crate::boot::BootInfo;
use crate::sync::SpinLock;
use fastros_alloc::buddy::{Buddy, FrameMemory, MAX_ORDER};

pub use fastros_alloc::buddy::MAX_ORDER as MAX_FRAME_ORDER;

/// Free-list nodes live in the free frames, reached through the direct map.
struct DirectMap;
impl FrameMemory for DirectMap {
    fn frame_ptr(&self, idx: usize) -> *mut u8 {
        phys_to_virt((idx * PAGE_SIZE) as PhysAddr) as *mut u8
    }
}

static FRAMES: SpinLock<Option<Buddy<DirectMap>>> = SpinLock::new(None);

/// The boot page tables only map the first 4 GiB; memory above is added
/// once the final page tables exist.
const LOW_LIMIT: u64 = 4 << 30;

struct Reserved {
    ranges: [(u64, u64); 8],
    n: usize,
}

impl Reserved {
    fn push(&mut self, start: u64, end: u64) {
        self.ranges[self.n] = (start, end);
        self.n += 1;
    }
    /// Call `f` for each piece of `[start, end)` not covered by a reserved range.
    fn subtract(&self, start: u64, end: u64, f: &mut dyn FnMut(u64, u64)) {
        let mut pieces = [(start, end); 17];
        let mut count = 1;
        for &(rs, re) in &self.ranges[..self.n] {
            let mut next = [(0u64, 0u64); 17];
            let mut m = 0;
            for &(s, e) in &pieces[..count] {
                if re <= s || rs >= e {
                    next[m] = (s, e);
                    m += 1;
                    continue;
                }
                if s < rs {
                    next[m] = (s, rs);
                    m += 1;
                }
                if re < e {
                    next[m] = (re, e);
                    m += 1;
                }
            }
            pieces = next;
            count = m;
        }
        for &(s, e) in &pieces[..count] {
            if e > s {
                f(s, e);
            }
        }
    }
}

static RESERVED: SpinLock<Reserved> = SpinLock::new(Reserved { ranges: [(0, 0); 8], n: 0 });

pub fn init(boot: &BootInfo) {
    let max = boot.max_ram();
    let frames = align_up(align_up(max as usize, PAGE_SIZE) / PAGE_SIZE, 1 << MAX_ORDER);
    let state_bytes = align_up(frames, PAGE_SIZE) as u64;
    let (kstart, kend) = super::kspace::image_phys_range();

    // Place the per-frame state array in the first low usable range after the kernel.
    let mut state_at = None;
    for r in boot.usable() {
        let s = align_up(r.start.max(kend).max(0x10_0000) as usize, PAGE_SIZE) as u64;
        let e = align_down(r.end.min(LOW_LIMIT) as usize, PAGE_SIZE) as u64;
        if e > s && e - s >= state_bytes {
            state_at = Some(s);
            break;
        }
    }
    let state_at = state_at.expect("no room for the frame allocator's state array");

    let mut res = RESERVED.lock();
    res.push(0, 0x10_0000); // real-mode IVT, BIOS data, EBDA, VGA, option ROMs
    res.push(kstart, kend);
    res.push(state_at, state_at + state_bytes);

    let mut buddy = unsafe { Buddy::new(DirectMap, phys_to_virt(state_at) as *mut u8, frames) };
    for r in boot.usable() {
        let s = align_up(r.start as usize, PAGE_SIZE) as u64;
        let e = align_down(r.end.min(LOW_LIMIT) as usize, PAGE_SIZE) as u64;
        if e > s {
            res.subtract(s, e, &mut |a, b| buddy.add_range(a as usize / PAGE_SIZE, b as usize / PAGE_SIZE));
        }
    }
    drop(res);
    *FRAMES.lock() = Some(buddy);
}

/// Add usable RAM above 4 GiB (after `kspace::init` mapped it).
pub fn add_high_memory(boot: &BootInfo) {
    let mut g = FRAMES.lock();
    let buddy = g.as_mut().expect("frame::init");
    let res = RESERVED.lock();
    for r in boot.usable() {
        let s = align_up(r.start.max(LOW_LIMIT) as usize, PAGE_SIZE) as u64;
        let e = align_down(r.end as usize, PAGE_SIZE) as u64;
        if e > s {
            res.subtract(s, e, &mut |a, b| buddy.add_range(a as usize / PAGE_SIZE, b as usize / PAGE_SIZE));
        }
    }
}

/// Allocate `2^order` contiguous frames (naturally aligned).
pub fn alloc(order: usize) -> Option<PhysAddr> {
    let idx = FRAMES.lock().as_mut()?.alloc(order)?;
    Some((idx * PAGE_SIZE) as PhysAddr)
}

/// Allocate and zero-fill.
pub fn alloc_zeroed(order: usize) -> Option<PhysAddr> {
    let p = alloc(order)?;
    unsafe { core::ptr::write_bytes(phys_to_virt(p) as *mut u8, 0, PAGE_SIZE << order) };
    Some(p)
}

/// Free frames obtained from [`alloc`]. A mismatched free is a kernel bug.
pub fn free(p: PhysAddr, order: usize) {
    let r = FRAMES.lock().as_mut().expect("frame::init").free(p as usize / PAGE_SIZE, order);
    if let Err(e) = r {
        panic!("frame::free({p:#x}, order {order}): {e:?}");
    }
}

/// (managed frames, free frames)
pub fn counts() -> (usize, usize) {
    match FRAMES.lock().as_ref() {
        Some(b) => (b.managed_frames(), b.free_frames()),
        None => (0, 0),
    }
}

pub fn free_blocks() -> [usize; MAX_ORDER + 1] {
    FRAMES.lock().as_ref().map(|b| b.free_blocks()).unwrap_or([0; MAX_ORDER + 1])
}

// ── page reference counts (user memory) ────────────────────────────────────
//
// Pages mapped into user address spaces can be shared: copy-on-write after
// fork, shared file mappings. Each frame has a 16-bit count in a table in
// vmalloc space (2 bytes per frame: 512 KiB per GiB of RAM). Only user pages
// use it; kernel allocations never touch the table.

use core::sync::atomic::{AtomicU16, AtomicUsize, Ordering};

static REF_TABLE: AtomicUsize = AtomicUsize::new(0);
static REF_FRAMES: AtomicUsize = AtomicUsize::new(0);

/// Allocate the reference-count table (after the heap and vmalloc work).
pub fn init_page_refs() {
    let frames = FRAMES.lock().as_ref().map(|b| b.total_frames()).unwrap_or(0);
    let pages = align_up(frames * 2, PAGE_SIZE) / PAGE_SIZE;
    let base = super::vmalloc::alloc(pages).expect("out of memory for the page reference table");
    unsafe { core::ptr::write_bytes(base as *mut u8, 0, pages * PAGE_SIZE) };
    REF_FRAMES.store(frames, Ordering::Relaxed);
    REF_TABLE.store(base, Ordering::Release);
}

fn ref_slot(p: PhysAddr) -> &'static AtomicU16 {
    let idx = p as usize / PAGE_SIZE;
    assert!(idx < REF_FRAMES.load(Ordering::Relaxed), "page ref for frame {p:#x} outside RAM");
    let base = REF_TABLE.load(Ordering::Acquire);
    assert!(base != 0, "frame::init_page_refs not called");
    unsafe { &*((base as *const AtomicU16).add(idx)) }
}

/// A zeroed page for user memory, with one reference.
pub fn alloc_user_page() -> Option<PhysAddr> {
    let p = alloc_zeroed(0)?;
    ref_slot(p).store(1, Ordering::Release);
    Some(p)
}

/// Take another reference to a user page.
pub fn page_get(p: PhysAddr) {
    let old = ref_slot(p).fetch_add(1, Ordering::AcqRel);
    assert!(old != 0 && old != u16::MAX, "page_get on a page with count {old} ({p:#x})");
}

/// Drop a reference; the page returns to the allocator with the last one.
pub fn page_put(p: PhysAddr) {
    let old = ref_slot(p).fetch_sub(1, Ordering::AcqRel);
    assert!(old != 0, "page_put on a free page ({p:#x})");
    if old == 1 {
        free(p, 0);
    }
}

pub fn page_count(p: PhysAddr) -> u16 {
    ref_slot(p).load(Ordering::Acquire)
}
