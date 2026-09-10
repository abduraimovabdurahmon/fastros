//! Virtual Memory Manager (VMM)
//!
//! Manages virtual address spaces for the kernel and each process.
//! Wraps the arch-level page table operations (arch::x86_64::memory::paging).
//! Sits on top of PMM (allocates physical frames).

pub mod address_space;

use address_space::{AddressSpace, Vma, VmaKind};
use crate::kernel::memory::pmm;
use crate::arch::x86_64::memory::paging::{self, flags, read_cr3};

/// Initialize the kernel's virtual address space.
///
/// The boot page tables (set up in boot.s) identity-map the first 1 GB.
/// The kernel is loaded in this range, so nothing needs to change yet.
/// Once the heap grows beyond 4 MB (or we want a higher-half kernel),
/// we extend the page tables here.
pub fn init() {
    // The current PML4 is from boot.s — it identity-maps 0–1 GB.
    // We'll use it as the kernel address space.
    // TODO: set up proper higher-half kernel mappings.
}

/// Map a single virtual page to a physical frame in the current address space.
pub fn map_page(virt: u64, phys: u64, page_flags: u64) -> bool {
    let pml4 = read_cr3();
    unsafe {
        paging::map_page(pml4, virt, phys, page_flags, &mut || pmm::alloc_frame())
    }
}

/// Map a contiguous virtual range to contiguous physical frames.
/// Allocates physical frames from PMM.
pub fn alloc_map(virt_start: u64, size: u64, page_flags: u64) -> bool {
    let pml4 = read_cr3();
    let pages = (size + 0xFFF) / 4096;
    for i in 0..pages {
        let virt = virt_start + i * 4096;
        let phys = match pmm::alloc_frame() {
            Some(p) => p,
            None    => return false, // OOM
        };
        unsafe {
            if !paging::map_page(pml4, virt, phys, page_flags, &mut || pmm::alloc_frame()) {
                return false;
            }
        }
    }
    true
}

/// Unmap and free a single virtual page.
pub fn unmap_free(virt: u64) {
    let pml4 = read_cr3();
    if let Some(phys) = unsafe { paging::translate(pml4, virt) } {
        unsafe { paging::unmap_page(pml4, virt); }
        pmm::free_frame(phys);
    }
}

/// Translate a virtual address to physical in the current address space.
pub fn translate(virt: u64) -> Option<u64> {
    let pml4 = read_cr3();
    unsafe { paging::translate(pml4, virt) }
}

/// Page-fault handler — called by the IDT page-fault hook.
///
/// Returns true if the fault was handled (demand allocation).
/// Returns false if it's a genuine access violation (kernel should SIGSEGV the process).
pub fn handle_page_fault(
    fault_addr: u64,
    present: bool,
    write: bool,
    _user: bool,
    _rip: u64,
) -> bool {
    if present {
        // Page was present but protection violated (e.g. write to read-only CoW page).
        // TODO: CoW — copy page and remap as writable.
        return false;
    }

    // Page not present — demand paging: look up VMA and allocate a frame.
    // TODO: replace with per-process VMA lookup when process management is live.
    // For now, always fail (let the exception handler panic).
    let _ = (fault_addr, write);
    false
}

/// Create a new empty address space (for fork/exec).
/// Allocates a fresh PML4 and copies kernel mappings.
pub fn create_address_space() -> Option<AddressSpace> {
    let pml4_frame = pmm::alloc_frame()?;
    // Zero the new PML4
    unsafe {
        let pml4 = pml4_frame as *mut [u64; 512];
        (*pml4) = [0u64; 512];
    }
    let mut space = AddressSpace::empty();
    space.pml4_phys = pml4_frame;
    // TODO: copy kernel PML4 entries (upper half) so the process can call into kernel
    Some(space)
}
