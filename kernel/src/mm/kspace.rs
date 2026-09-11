//! The kernel's own address space: direct map, kernel image, vmalloc area.

use super::{align_up, frame, PhysAddr, KERNEL_VMA, PAGE_SIZE, PHYS_OFFSET, VMALLOC_START};
use crate::arch::cpu;
use crate::arch::paging::{self, flags::*, MapError, HUGE_2M};
use crate::boot::BootInfo;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU64, Ordering};

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __kernel_end: u8;
}

/// Physical load address of the image (linker.ld: KERNEL_PHYS).
const KERNEL_PHYS: u64 = 0x10_0000;

static PML4: AtomicU64 = AtomicU64::new(0);
/// Serialises changes to kernel page tables below the pre-created PDPTs.
static LOCK: SpinLock<()> = SpinLock::new(());

fn sym(s: &u8) -> usize {
    s as *const u8 as usize
}

/// Physical `[start, end)` occupied by the kernel image (boot stub included).
pub fn image_phys_range() -> (u64, u64) {
    let end = unsafe { sym(&__kernel_end) } - KERNEL_VMA;
    (KERNEL_PHYS, align_up(end, PAGE_SIZE) as u64)
}

pub fn pml4() -> PhysAddr {
    PML4.load(Ordering::Relaxed)
}

fn alloc_table() -> Option<PhysAddr> {
    frame::alloc_zeroed(0)
}

/// Build the final kernel page tables and switch to them.
pub fn init(boot: &BootInfo) {
    let root = frame::alloc_zeroed(0).expect("out of memory for the kernel PML4");
    // Pre-create the PDPTs of every kernel-half PML4 slot we use, so user
    // address spaces can share them by copying three PML4 entries.
    for slot in [256usize, 384, 511] {
        let pdpt = frame::alloc_zeroed(0).expect("out of memory for kernel PDPTs");
        unsafe { paging::entries(root)[slot] = pdpt | PRESENT | WRITABLE };
    }

    // Direct map: all RAM (and at least the 4 GiB holding MMIO), 2 MiB pages,
    // never executable. Chunks without RAM are MMIO: map them uncached.
    let top = align_up(boot.max_ram().max(4 << 30) as usize, HUGE_2M);
    let mut pa = 0usize;
    while pa < top {
        let ram = boot
            .usable()
            .any(|r| (r.start as usize) < pa + HUGE_2M && (r.end as usize) > pa);
        let cache = if ram { 0 } else { NO_CACHE | WRITE_THROUGH };
        unsafe {
            paging::map_2m(root, PHYS_OFFSET + pa, pa as PhysAddr, WRITABLE | GLOBAL | NO_EXECUTE | cache, &mut alloc_table)
                .expect("direct map");
        }
        pa += HUGE_2M;
    }

    // Kernel image with per-section permissions (W^X).
    let (text, text_end, ro, ro_end, data, end) = unsafe {
        (
            sym(&__text_start),
            sym(&__text_end),
            sym(&__rodata_start),
            sym(&__rodata_end),
            sym(&__data_start),
            align_up(sym(&__kernel_end), PAGE_SIZE),
        )
    };
    let mut va = text;
    while va < end {
        let fl = if va < text_end {
            GLOBAL
        } else if (ro..ro_end).contains(&va) {
            GLOBAL | NO_EXECUTE
        } else if va >= data {
            GLOBAL | WRITABLE | NO_EXECUTE
        } else {
            GLOBAL | NO_EXECUTE
        };
        unsafe {
            paging::map_4k(root, va, (va - KERNEL_VMA) as PhysAddr, fl, &mut alloc_table).expect("kernel image map");
        }
        va += PAGE_SIZE;
    }

    PML4.store(root, Ordering::Relaxed);
    unsafe { cpu::write_cr3(root) };
}

/// Map one 4 KiB kernel page (vmalloc area). Always no-execute.
pub fn map(virt: usize, phys: PhysAddr, writable: bool) -> Result<(), MapError> {
    debug_assert!(virt >= VMALLOC_START);
    let _g = LOCK.lock();
    let fl = GLOBAL | NO_EXECUTE | if writable { WRITABLE } else { 0 };
    unsafe { paging::map_4k(pml4(), virt, phys, fl, &mut alloc_table) }
}

/// Unmap one kernel page; returns the frame it mapped.
pub fn unmap(virt: usize) -> Option<PhysAddr> {
    let _g = LOCK.lock();
    let r = unsafe { paging::unmap_4k(pml4(), virt) }.map(|(p, _)| p);
    cpu::invlpg(virt);
    r
}

pub fn translate(virt: usize) -> Option<(PhysAddr, u64)> {
    unsafe { paging::translate(pml4(), virt) }
}

/// Kernel-half PML4 entries (256..512) to install in a new address space.
pub fn kernel_half() -> [u64; 256] {
    let mut out = [0u64; 256];
    unsafe { out.copy_from_slice(&paging::entries(pml4())[256..]) };
    out
}
