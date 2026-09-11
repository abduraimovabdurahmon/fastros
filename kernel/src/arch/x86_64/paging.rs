//! 4-level x86_64 page tables.
//!
//! Tables are addressed physically and accessed through the kernel's direct
//! map (`mm::phys_to_virt`). All mapping functions take a frame allocator for
//! intermediate tables, so the same code builds the kernel's tables at boot
//! and user address spaces later.

use crate::mm::{phys_to_virt, PhysAddr};

pub const PAGE_SIZE: usize = 4096;
pub const HUGE_2M: usize = 2 * 1024 * 1024;

pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    /// Software bit: page is copy-on-write (write fault → copy).
    pub const COW: u64 = 1 << 9;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    OutOfMemory,
    AlreadyMapped,
    HugePageInTheWay,
}

#[inline]
fn index(virt: usize, level: usize) -> usize {
    (virt >> (12 + 9 * level)) & 0x1FF
}

#[inline]
unsafe fn table(phys: PhysAddr) -> &'static mut [u64; 512] {
    unsafe {
        &mut *(phys_to_virt(phys) as *mut [u64; 512])
    }
}

/// Walk to the level-0 (4 KiB) entry for `virt`, creating tables if asked.
/// Intermediate entries get the most permissive flags; the leaf decides.
unsafe fn walk(
    root: PhysAddr,
    virt: usize,
    create: bool,
    alloc: &mut dyn FnMut() -> Option<PhysAddr>,
) -> Result<Option<*mut u64>, MapError> {
    unsafe {
        let mut t = root;
        for level in (1..4).rev() {
            let e = &mut table(t)[index(virt, level)];
            if *e & flags::PRESENT == 0 {
                if !create {
                    return Ok(None);
                }
                let new = alloc().ok_or(MapError::OutOfMemory)?;
                core::ptr::write_bytes(phys_to_virt(new) as *mut u8, 0, PAGE_SIZE);
                let user = if virt < 0x0000_8000_0000_0000 { flags::USER } else { 0 };
                *e = new | flags::PRESENT | flags::WRITABLE | user;
            } else if *e & flags::HUGE != 0 {
                return Err(MapError::HugePageInTheWay);
            }
            t = *e & ADDR_MASK;
        }
        Ok(Some(&mut table(t)[index(virt, 0)] as *mut u64))
    }
}

/// Map one 4 KiB page.
///
/// # Safety
/// `root` must be a valid PML4 and the mapping must not break memory safety
/// (e.g. aliasing kernel data as user-writable).
pub unsafe fn map_4k(
    root: PhysAddr,
    virt: usize,
    phys: PhysAddr,
    fl: u64,
    alloc: &mut dyn FnMut() -> Option<PhysAddr>,
) -> Result<(), MapError> {
    unsafe {
        let e = walk(root, virt, true, alloc)?.expect("create=true");
        if *e & flags::PRESENT != 0 {
            return Err(MapError::AlreadyMapped);
        }
        *e = (phys & ADDR_MASK) | fl | flags::PRESENT;
        Ok(())
    }
}

/// Map one 2 MiB page (level-1 entry with the HUGE bit).
pub unsafe fn map_2m(
    root: PhysAddr,
    virt: usize,
    phys: PhysAddr,
    fl: u64,
    alloc: &mut dyn FnMut() -> Option<PhysAddr>,
) -> Result<(), MapError> {
    unsafe {
        let mut t = root;
        for level in (2..4).rev() {
            let e = &mut table(t)[index(virt, level)];
            if *e & flags::PRESENT == 0 {
                let new = alloc().ok_or(MapError::OutOfMemory)?;
                core::ptr::write_bytes(phys_to_virt(new) as *mut u8, 0, PAGE_SIZE);
                *e = new | flags::PRESENT | flags::WRITABLE;
            }
            t = *e & ADDR_MASK;
        }
        let e = &mut table(t)[index(virt, 1)];
        if *e & flags::PRESENT != 0 {
            return Err(MapError::AlreadyMapped);
        }
        *e = (phys & ADDR_MASK) | fl | flags::PRESENT | flags::HUGE;
        Ok(())
    }
}

/// Remove the 4 KiB mapping of `virt`; returns the physical page it mapped.
/// The caller flushes the TLB entry.
pub unsafe fn unmap_4k(root: PhysAddr, virt: usize) -> Option<(PhysAddr, u64)> {
    unsafe {
        let e = walk(root, virt, false, &mut || None).ok()??;
        if *e & flags::PRESENT == 0 {
            return None;
        }
        let old = *e;
        *e = 0;
        Some((old & ADDR_MASK, old & !ADDR_MASK))
    }
}

/// Physical address and flags `virt` maps to (4 KiB or 2 MiB pages).
pub unsafe fn translate(root: PhysAddr, virt: usize) -> Option<(PhysAddr, u64)> {
    unsafe {
        let mut t = root;
        for level in (0..4).rev() {
            let e = table(t)[index(virt, level)];
            if e & flags::PRESENT == 0 {
                return None;
            }
            if level == 0 {
                return Some(((e & ADDR_MASK) + (virt as u64 & 0xFFF), e & !ADDR_MASK));
            }
            if level == 1 && e & flags::HUGE != 0 {
                return Some(((e & 0x000F_FFFF_FFE0_0000) + (virt as u64 & 0x1F_FFFF), e & !ADDR_MASK));
            }
            t = e & ADDR_MASK;
        }
        None
    }
}

/// Pointer to the leaf entry for `virt`, if every level exists.
pub unsafe fn leaf_entry(root: PhysAddr, virt: usize) -> Option<*mut u64> {
    unsafe {
        walk(root, virt, false, &mut || None).ok().flatten()
    }
}

pub unsafe fn update_flags(root: PhysAddr, virt: usize, set: u64, clear: u64) -> bool {
    unsafe {
        match leaf_entry(root, virt) {
            Some(e) if *e & flags::PRESENT != 0 => {
                *e = (*e | set) & !clear;
                true
            }
            _ => false,
        }
    }
}

/// Raw access to a table's entries (used to share the kernel half).
pub unsafe fn entries(phys: PhysAddr) -> &'static mut [u64; 512] {
    unsafe {
        table(phys)
    }
}

pub const fn entry_addr(e: u64) -> PhysAddr {
    e & ADDR_MASK
}
