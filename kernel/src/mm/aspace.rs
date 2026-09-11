//! User address spaces.
//!
//! Each user process owns an [`AddressSpace`]: its own PML4 whose upper half
//! (the kernel) is shared with every other space by copying the three
//! pre-created kernel PML4 entries, and a lower half of [`Region`]s (the VMAs
//! of a Linux `mm_struct`). Pages are reference-counted (see
//! [`super::frame`]), so `fork` maps every private page copy-on-write in both
//! parent and child and only copies on the first write fault.

use super::frame;
use super::{align_down, align_up, kspace, PhysAddr, PAGE_SIZE, USER_END, USER_START};
use crate::arch::paging::{self, flags, MapError};
use crate::arch::{cpu, trap::TrapFrame};
use crate::errno::{Errno, KResult};
use crate::fs::file::File;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// What a mapping permits (the `PROT_*` of `mmap`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prot(u8);

impl Prot {
    pub const NONE: Prot = Prot(0);
    pub const READ: Prot = Prot(1);
    pub const WRITE: Prot = Prot(2);
    pub const EXEC: Prot = Prot(4);

    pub const fn bits(self) -> u8 {
        self.0
    }
    pub const fn from_bits_truncate(b: u8) -> Prot {
        Prot(b & 7)
    }
    pub const fn contains(self, o: Prot) -> bool {
        self.0 & o.0 == o.0
    }
}

impl core::ops::BitOr for Prot {
    type Output = Prot;
    fn bitor(self, o: Prot) -> Prot {
        Prot(self.0 | o.0)
    }
}

/// A private, read-on-fault file mapping (MAP_PRIVATE): pages are filled from
/// the file the first time they fault and stay private thereafter. This is
/// what the dynamic linker uses to map shared libraries.
#[derive(Clone)]
struct FileBacking {
    file: Arc<dyn File>,
    /// File offset that maps to `region.start`.
    offset: u64,
    /// Bytes of real file content from `region.start`; the rest is a zero
    /// (bss) tail, as ELF segments and `ld.so` expect.
    length: u64,
}

/// One contiguous mapping — a VMA. Either anonymous (demand-zeroed) or backed
/// by a file (demand-filled, private). Every page is per-process private.
#[derive(Clone)]
struct Region {
    start: usize,
    end: usize,
    prot: Prot,
    /// Grows downward on faults just below `start` (the stack).
    grows_down: bool,
    /// `Some` for a file-backed (MAP_PRIVATE) mapping.
    backing: Option<FileBacking>,
}

pub struct AddressSpace {
    pml4: PhysAddr,
    regions: SpinLock<Vec<Region>>,
    /// Highest brk address handed out; program break starts at `brk_base`.
    brk: SpinLock<usize>,
    brk_base: AtomicUsize,
    /// Where a fresh `mmap` with no hint is placed (grows down from here).
    mmap_top: SpinLock<usize>,
}

/// Base of the mmap region (below the stack), matching a small ASLR-free
/// Linux layout: stack at the top of the lower half, mmap below it.
const MMAP_TOP: usize = 0x0000_7F00_0000_0000;
pub const USER_STACK_TOP: usize = 0x0000_7FFF_FFFF_F000;

fn to_page_flags(prot: Prot) -> u64 {
    let mut f = flags::USER;
    if prot.contains(Prot::WRITE) {
        f |= flags::WRITABLE;
    }
    if !prot.contains(Prot::EXEC) {
        f |= flags::NO_EXECUTE;
    }
    f
}

impl AddressSpace {
    /// A new, empty space sharing the kernel half.
    pub fn new() -> KResult<Arc<AddressSpace>> {
        let pml4 = frame::alloc_zeroed(0).ok_or(Errno::ENOMEM)?;
        let kernel = kspace::kernel_half();
        unsafe {
            let e = paging::entries(pml4);
            e[256..].copy_from_slice(&kernel);
        }
        Ok(Arc::new(AddressSpace {
            pml4,
            regions: SpinLock::new(Vec::new()),
            brk: SpinLock::new(0),
            brk_base: AtomicUsize::new(0),
            mmap_top: SpinLock::new(MMAP_TOP),
        }))
    }

    pub fn pml4(&self) -> PhysAddr {
        self.pml4
    }

    /// Install this space on the current CPU.
    pub fn activate(&self) {
        unsafe { cpu::write_cr3(self.pml4) };
    }

    fn overlaps(regions: &[Region], start: usize, end: usize) -> bool {
        regions.iter().any(|r| start < r.end && r.start < end)
    }

    /// Reserve `[start, end)` with `prot`. Fails if it overlaps or leaves the
    /// user range. Pages are allocated lazily on first touch.
    pub fn map_region(&self, start: usize, end: usize, prot: Prot, grows_down: bool) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(end, PAGE_SIZE));
        if start < USER_START || end > USER_END || start >= end {
            return Err(Errno::EINVAL);
        }
        let mut regions = self.regions.lock();
        if Self::overlaps(&regions, start, end) {
            return Err(Errno::EEXIST);
        }
        regions.push(Region { start, end, prot, grows_down, backing: None });
        Ok(())
    }

    /// Reserve a private, file-backed mapping (used by `mmap` with an fd and
    /// by the ELF loader for file-mapped segments).
    fn map_file_region(&self, start: usize, end: usize, prot: Prot, file: Arc<dyn File>, offset: u64, length: u64) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(end, PAGE_SIZE));
        if start < USER_START || end > USER_END || start >= end {
            return Err(Errno::EINVAL);
        }
        let mut regions = self.regions.lock();
        if Self::overlaps(&regions, start, end) {
            return Err(Errno::EEXIST);
        }
        regions.push(Region { start, end, prot, grows_down: false, backing: Some(FileBacking { file, offset, length }) });
        Ok(())
    }

    /// Place a mapping of `len` bytes, honouring a fixed `hint`. When `file`
    /// is `Some`, the mapping is private and filled from the file at `offset`.
    pub fn mmap(&self, hint: usize, len: usize, prot: Prot, fixed: bool, file: Option<(Arc<dyn File>, u64)>) -> KResult<usize> {
        let len = align_up(len.max(1), PAGE_SIZE);
        let place = |this: &Self, start: usize| -> KResult<()> {
            match &file {
                Some((f, off)) => this.map_file_region(start, start + len, prot, f.clone(), *off, len as u64),
                None => this.map_region(start, start + len, prot, false),
            }
        };
        if fixed {
            let start = align_down(hint, PAGE_SIZE);
            self.unmap(start, len).ok();
            place(self, start)?;
            return Ok(start);
        }
        if hint >= USER_START {
            let start = align_down(hint, PAGE_SIZE);
            if !Self::overlaps(&self.regions.lock(), start, start + len) && start + len <= USER_END {
                place(self, start)?;
                return Ok(start);
            }
        }
        let mut top = self.mmap_top.lock();
        let start = top.checked_sub(len).ok_or(Errno::ENOMEM)?;
        let start = align_down(start, PAGE_SIZE);
        place(self, start)?;
        *top = start;
        Ok(start)
    }

    /// Map `[start, end)` of `file` (from `offset`) with `length` bytes of
    /// real content and a zero tail — the ELF loader's file-backed segments.
    pub fn map_segment(&self, start: usize, end: usize, prot: Prot, file: &Arc<dyn File>, offset: u64, length: u64) -> KResult<()> {
        self.map_file_region(start, end, prot, file.clone(), offset, length)
    }

    /// Remove any mapping in `[start, start+len)`, freeing backing pages.
    pub fn unmap(&self, start: usize, len: usize) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(start + len, PAGE_SIZE));
        let mut regions = self.regions.lock();
        let mut out = Vec::new();
        for r in regions.drain(..) {
            if end <= r.start || start >= r.end {
                out.push(r);
                continue;
            }
            if r.start < start {
                out.push(Region { end: start, ..r.clone() });
            }
            if end < r.end {
                out.push(Region { start: end, ..r.clone() });
            }
        }
        *regions = out;
        drop(regions);
        let mut va = start;
        while va < end {
            if let Some((phys, fl)) = unsafe { paging::unmap_4k(self.pml4, va) } {
                if fl & flags::PRESENT != 0 {
                    frame::page_put(phys);
                }
                cpu::invlpg(va);
            }
            va += PAGE_SIZE;
        }
        Ok(())
    }

    /// Change protection of `[start, start+len)`.
    pub fn protect(&self, start: usize, len: usize, prot: Prot) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(start + len, PAGE_SIZE));
        let mut regions = self.regions.lock();
        if !regions.iter().any(|r| r.start <= start && end <= r.end) {
            return Err(Errno::ENOMEM);
        }
        // Split regions so the changed range is its own region.
        let mut out = Vec::new();
        for r in regions.drain(..) {
            if end <= r.start || start >= r.end {
                out.push(r);
                continue;
            }
            if r.start < start {
                out.push(Region { end: start, ..r.clone() });
            }
            out.push(Region { start: start.max(r.start), end: end.min(r.end), prot, grows_down: r.grows_down, backing: r.backing.clone() });
            if end < r.end {
                out.push(Region { start: end, ..r.clone() });
            }
        }
        *regions = out;
        drop(regions);
        // Re-flag the pages that are present; the rest fault in with the new prot.
        let mut va = start;
        while va < end {
            let want = to_page_flags(prot);
            unsafe {
                if let Some(e) = paging::leaf_entry(self.pml4, va) {
                    if *e & flags::PRESENT != 0 {
                        // Keep COW read-only until the copy happens.
                        let keep_ro = *e & flags::COW != 0;
                        let mut fl = want;
                        if keep_ro {
                            fl &= !flags::WRITABLE;
                        }
                        *e = (*e & (paging::entry_addr(*e) | flags::PRESENT | flags::COW | flags::ACCESSED | flags::DIRTY)) | fl;
                        cpu::invlpg(va);
                    }
                }
            }
            va += PAGE_SIZE;
        }
        Ok(())
    }

    fn region_at(&self, addr: usize) -> Option<Region> {
        self.regions.lock().iter().find(|r| r.start <= addr && addr < r.end).cloned()
    }

    /// Is every page of `[addr, addr+len)` mapped with at least READ (and
    /// WRITE when `write`)? Used to bounds-check user pointers in syscalls.
    pub fn verify(&self, addr: usize, len: usize, write: bool) -> bool {
        let Some(end) = addr.checked_add(len) else { return false };
        if addr < USER_START || end > USER_END {
            return false;
        }
        let regions = self.regions.lock();
        let mut va = align_down(addr, PAGE_SIZE);
        while va < end {
            match regions.iter().find(|r| r.start <= va && va < r.end) {
                Some(r) if r.prot.contains(Prot::READ) && (!write || r.prot.contains(Prot::WRITE)) => {}
                _ => return false,
            }
            va += PAGE_SIZE;
        }
        true
    }

    /// Read a NUL-terminated string from user memory (argv/envp/paths),
    /// capped at `max` bytes.
    pub fn read_cstr(&self, addr: usize, max: usize) -> KResult<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        let mut a = addr;
        loop {
            if out.len() >= max {
                return Err(Errno::ENAMETOOLONG);
            }
            let mut b = [0u8; 1];
            self.read(a, &mut b)?;
            if b[0] == 0 {
                return Ok(out);
            }
            out.push(b[0]);
            a += 1;
        }
    }

    /// Copy bytes into user memory, faulting pages in as needed.
    pub fn write(&self, addr: usize, data: &[u8]) -> KResult<()> {
        let mut off = 0;
        while off < data.len() {
            let va = addr + off;
            let page = align_down(va, PAGE_SIZE);
            self.fault_in(page, true)?;
            let n = (PAGE_SIZE - (va - page)).min(data.len() - off);
            let phys = self.phys_of(va).ok_or(Errno::EFAULT)?;
            unsafe { core::ptr::copy_nonoverlapping(data[off..off + n].as_ptr(), super::phys_to_virt(phys) as *mut u8, n) };
            off += n;
        }
        Ok(())
    }

    /// Read bytes out of user memory.
    pub fn read(&self, addr: usize, out: &mut [u8]) -> KResult<()> {
        let mut off = 0;
        while off < out.len() {
            let va = addr + off;
            let page = align_down(va, PAGE_SIZE);
            self.fault_in(page, false)?;
            let n = (PAGE_SIZE - (va - page)).min(out.len() - off);
            let phys = self.phys_of(va).ok_or(Errno::EFAULT)?;
            unsafe { core::ptr::copy_nonoverlapping(super::phys_to_virt(phys) as *const u8, out[off..off + n].as_mut_ptr(), n) };
            off += n;
        }
        Ok(())
    }

    fn phys_of(&self, va: usize) -> Option<PhysAddr> {
        unsafe { paging::translate(self.pml4, va) }.map(|(p, _)| p)
    }

    /// Physical address backing user virtual address `va`, faulting the page in
    /// (for a read) first. Used to key futexes by their backing frame so a
    /// futex in shared memory is matched across processes.
    pub fn phys_translate(&self, va: usize) -> KResult<u64> {
        let page = align_down(va, PAGE_SIZE);
        self.fault_in(page, false)?;
        let base = self.phys_of(page).ok_or(Errno::EFAULT)?;
        Ok(base as u64 + (va & (PAGE_SIZE - 1)) as u64)
    }

    /// Ensure the page containing `page` is present (allocating it), for a
    /// read or a write. Used by the kernel to touch user memory directly.
    fn fault_in(&self, page: usize, write: bool) -> KResult<()> {
        let r = self.region_at(page).ok_or(Errno::EFAULT)?;
        if write && !r.prot.contains(Prot::WRITE) {
            return Err(Errno::EFAULT);
        }
        self.ensure_page(page, &r, write)
    }

    fn ensure_page(&self, page: usize, r: &Region, write: bool) -> KResult<()> {
        unsafe {
            if let Some(e) = paging::leaf_entry(self.pml4, page) {
                if *e & flags::PRESENT != 0 {
                    if write && *e & flags::COW != 0 {
                        return self.do_cow(page, e);
                    }
                    return Ok(());
                }
            }
        }
        let phys = frame::alloc_user_page().ok_or(Errno::ENOMEM)?;
        // File-backed page: fill from the file (zero tail past `length`).
        if let Some(b) = &r.backing {
            let page_off = (page - r.start) as u64;
            if page_off < b.length {
                let n = (b.length - page_off).min(PAGE_SIZE as u64) as usize;
                let dst = unsafe { core::slice::from_raw_parts_mut(super::phys_to_virt(phys) as *mut u8, n) };
                // A short read leaves the rest zero (already zeroed).
                let _ = b.file.pread(b.offset + page_off, dst);
            }
        }
        let fl = to_page_flags(r.prot);
        unsafe {
            paging::map_4k(self.pml4, page, phys, fl, &mut alloc_table).map_err(map_err)?;
        }
        cpu::invlpg(page);
        Ok(())
    }

    /// Copy a shared (COW) page and make the copy writable.
    fn do_cow(&self, page: usize, e: *mut u64) -> KResult<()> {
        unsafe {
            let old = paging::entry_addr(*e);
            if frame::page_count(old) == 1 {
                // We are the only owner: just drop COW and restore write.
                *e = (*e & !flags::COW) | flags::WRITABLE;
                cpu::invlpg(page);
                return Ok(());
            }
            let new = frame::alloc_user_page().ok_or(Errno::ENOMEM)?;
            core::ptr::copy_nonoverlapping(super::phys_to_virt(old) as *const u8, super::phys_to_virt(new) as *mut u8, PAGE_SIZE);
            let keep = *e & (flags::USER | flags::NO_EXECUTE);
            *e = new | flags::PRESENT | flags::WRITABLE | keep;
            cpu::invlpg(page);
            frame::page_put(old);
        }
        Ok(())
    }

    /// Handle a user page fault. Returns true if it was resolved.
    pub fn handle_fault(&self, addr: usize, write: bool, exec: bool) -> bool {
        if !(USER_START..USER_END).contains(&addr) {
            return false;
        }
        let page = align_down(addr, PAGE_SIZE);
        // Automatic stack growth: a fault just below a grows-down region.
        let region = self.region_at(page).or_else(|| self.try_grow_stack(page));
        let Some(r) = region else { return false };
        if write && !r.prot.contains(Prot::WRITE) {
            return false;
        }
        if exec && !r.prot.contains(Prot::EXEC) {
            return false;
        }
        self.ensure_page(page, &r, write).is_ok()
    }

    fn try_grow_stack(&self, page: usize) -> Option<Region> {
        let mut regions = self.regions.lock();
        let idx = regions.iter().position(|r| r.grows_down && page < r.start && r.start - page <= 64 * PAGE_SIZE)?;
        // Don't grow into another mapping.
        let new_start = page;
        if regions.iter().enumerate().any(|(i, o)| i != idx && new_start < o.end && o.start < regions[idx].end) {
            return None;
        }
        regions[idx].start = new_start;
        Some(regions[idx].clone())
    }

    /// A child address space that shares every page copy-on-write.
    pub fn fork(&self) -> KResult<Arc<AddressSpace>> {
        let child = AddressSpace::new()?;
        let regions = self.regions.lock().clone();
        for r in &regions {
            let mut va = r.start;
            while va < r.end {
                unsafe {
                    if let Some(e) = paging::leaf_entry(self.pml4, va) {
                        if *e & flags::PRESENT != 0 {
                            let phys = paging::entry_addr(*e);
                            // Writable pages become read-only + COW in both copies.
                            if *e & flags::WRITABLE != 0 {
                                *e = (*e & !flags::WRITABLE) | flags::COW;
                                cpu::invlpg(va);
                            }
                            let fl = *e & !paging::entry_addr(*e);
                            frame::page_get(phys);
                            paging::map_4k(child.pml4, va, phys, fl, &mut alloc_table).map_err(map_err)?;
                        }
                    }
                }
                va += PAGE_SIZE;
            }
        }
        *child.regions.lock() = regions;
        *child.brk.lock() = *self.brk.lock();
        child.brk_base.store(self.brk_base.load(Ordering::Relaxed), Ordering::Relaxed);
        *child.mmap_top.lock() = *self.mmap_top.lock();
        Ok(child)
    }

    /// Set the program break base (the end of the loaded image), once.
    pub fn set_brk_base(&self, base: usize) {
        let base = align_up(base, PAGE_SIZE);
        self.brk_base.store(base, Ordering::Relaxed);
        *self.brk.lock() = base;
    }

    /// `brk(addr)`: move the program break. `addr == 0` queries it.
    pub fn brk(&self, addr: usize) -> usize {
        let base = self.brk_base.load(Ordering::Relaxed);
        let mut brk = self.brk.lock();
        if addr < base {
            return *brk;
        }
        let new = align_up(addr, PAGE_SIZE);
        let cur = *brk;
        if new > cur {
            // Extend (or create) the heap region.
            let mut regions = self.regions.lock();
            if let Some(r) = regions.iter_mut().find(|r| r.end == cur && r.start >= base && !r.grows_down) {
                r.end = new;
            } else if !Self::overlaps(&regions, cur, new) {
                regions.push(Region { start: base.max(cur), end: new, prot: Prot::READ | Prot::WRITE, grows_down: false, backing: None });
            } else {
                return cur;
            }
        } else if new < cur {
            drop(brk);
            self.unmap(new, cur - new).ok();
            brk = self.brk.lock();
        }
        *brk = new;
        new
    }
}

fn alloc_table() -> Option<PhysAddr> {
    frame::alloc_zeroed(0)
}

fn map_err(e: MapError) -> Errno {
    match e {
        MapError::OutOfMemory => Errno::ENOMEM,
        _ => Errno::EFAULT,
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        // Free every user page, then the lower-half page tables.
        let regions = core::mem::take(&mut *self.regions.lock());
        for r in regions {
            let mut va = r.start;
            while va < r.end {
                if let Some((phys, fl)) = unsafe { paging::unmap_4k(self.pml4, va) } {
                    if fl & flags::PRESENT != 0 {
                        frame::page_put(phys);
                    }
                }
                va += PAGE_SIZE;
            }
        }
        free_lower_tables(self.pml4);
        frame::free(self.pml4, 0);
    }
}

/// Free the page-table pages of the lower half (user space) only; the upper
/// half is shared and must not be touched.
fn free_lower_tables(pml4: PhysAddr) {
    unsafe {
        let top = paging::entries(pml4);
        for slot in 0..256 {
            let e = top[slot];
            if e & flags::PRESENT != 0 {
                free_table(paging::entry_addr(e), 3);
            }
        }
    }
}

unsafe fn free_table(phys: PhysAddr, level: usize) {
    unsafe {
        if level > 1 {
            let t = paging::entries(phys);
            for &e in t.iter() {
                if e & flags::PRESENT != 0 && e & flags::HUGE == 0 {
                    free_table(paging::entry_addr(e), level - 1);
                }
            }
        }
        frame::free(phys, 0);
    }
}

/// Resolve a fault forwarded from the trap layer against the current process.
pub fn handle_user_fault(tf: &mut TrapFrame, addr: usize) -> bool {
    let write = tf.error & 0x2 != 0;
    let exec = tf.error & 0x10 != 0;
    let Some(space) = crate::proc::current_aspace() else { return false };
    space.handle_fault(addr, write, exec)
}
