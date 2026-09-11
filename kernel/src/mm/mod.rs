//! Memory management.
//!
//! Virtual address space layout (4-level paging, 48-bit):
//!
//! | range                                   | use                               |
//! |-----------------------------------------|-----------------------------------|
//! | `0000_0000_0000_1000..0000_7FFF_FFFF_F000` | user space (per process)        |
//! | `FFFF_8000_0000_0000..`  (PML4 256)     | direct map of all physical memory |
//! | `FFFF_C000_0000_0000..`  (PML4 384)     | vmalloc: stacks, large buffers    |
//! | `FFFF_FFFF_8000_0000..`  (PML4 511)     | kernel image                      |
//!
//! Every kernel mapping is no-execute except the kernel's `.text`, and the
//! kernel's `.text`/`.rodata` are read-only — enforced by the MMU (`CR0.WP`).

pub mod aspace;
pub mod dma;
pub mod fault;
pub mod frame;
pub mod heap;
pub mod kspace;
pub mod vmalloc;

pub type PhysAddr = u64;

pub const PAGE_SIZE: usize = 4096;
pub const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;
pub const KERNEL_VMA: usize = 0xFFFF_FFFF_8000_0000;
pub const VMALLOC_START: usize = 0xFFFF_C000_0000_0000;
pub const VMALLOC_END: usize = VMALLOC_START + (512usize << 30);
/// Direct-map window size (PML4 entry 256: 512 GiB).
pub const DIRECT_MAP_SIZE: usize = 512usize << 30;
/// First address of user space that may be mapped (keeps NULL deref faulting).
pub const USER_START: usize = 0x1_0000;
pub const USER_END: usize = 0x0000_7FFF_FFFF_F000;

#[inline]
pub const fn phys_to_virt(p: PhysAddr) -> usize {
    p as usize + PHYS_OFFSET
}

/// Physical address of a kernel virtual address (direct map, kernel image or vmalloc).
pub fn virt_to_phys(v: usize) -> Option<PhysAddr> {
    if v >= KERNEL_VMA {
        Some((v - KERNEL_VMA) as PhysAddr)
    } else if (PHYS_OFFSET..PHYS_OFFSET + DIRECT_MAP_SIZE).contains(&v) {
        Some((v - PHYS_OFFSET) as PhysAddr)
    } else {
        kspace::translate(v).map(|(p, _)| p)
    }
}

#[inline]
pub const fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}
#[inline]
pub const fn align_down(v: usize, a: usize) -> usize {
    v & !(a - 1)
}

/// Order of the smallest power-of-two page block holding `bytes`.
pub fn order_for(bytes: usize) -> usize {
    let pages = align_up(bytes.max(1), PAGE_SIZE) / PAGE_SIZE;
    pages.next_power_of_two().trailing_zeros() as usize
}

/// A kernel stack in vmalloc space with an unmapped guard page below it:
/// overflowing the stack faults immediately instead of corrupting memory.
pub struct KernelStack {
    base: usize,
    pages: usize,
}

impl KernelStack {
    pub fn new(pages: usize) -> Option<Self> {
        let base = vmalloc::alloc(pages)?;
        Some(Self { base, pages })
    }
    pub fn top(&self) -> usize {
        self.base + self.pages * PAGE_SIZE
    }
    pub fn bottom(&self) -> usize {
        self.base
    }
}

impl Drop for KernelStack {
    fn drop(&mut self) {
        vmalloc::free(self.base);
    }
}

/// Initialise physical frames, the final kernel page tables and the heap.
pub fn init(boot: &crate::boot::BootInfo) {
    frame::init(boot);
    kspace::init(boot);
    frame::add_high_memory(boot);
    heap::init();
    frame::init_page_refs();
}

pub struct MemStats {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub heap_bytes: u64,
    pub slab_bytes: u64,
    pub vmalloc_bytes: u64,
}

pub fn stats() -> MemStats {
    let (managed, free) = frame::counts();
    MemStats {
        total_bytes: managed as u64 * PAGE_SIZE as u64,
        free_bytes: free as u64 * PAGE_SIZE as u64,
        heap_bytes: heap::used_bytes() as u64,
        slab_bytes: heap::slab_footprint() as u64,
        vmalloc_bytes: vmalloc::mapped_bytes() as u64,
    }
}
