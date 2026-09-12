//! User address spaces.
//!
//! Each user process owns an [`AddressSpace`]: its own PML4 whose upper half
//! (the kernel) is shared with every other space by copying the three
//! pre-created kernel PML4 entries, and a lower half of [`Region`]s (the VMAs
//! of a Linux `mm_struct`). Pages are reference-counted (see
//! [`super::frame`]), so `fork` maps every private page copy-on-write in both
//! parent and child and only copies on the first write fault.

use super::frame;
use super::swap;
use super::{align_down, align_up, kspace, PhysAddr, PAGE_SIZE, USER_END, USER_START};
use crate::arch::paging::{self, flags, MapError};
use crate::arch::{cpu, trap::TrapFrame};
use crate::errno::{Errno, KResult};
use crate::fs::file::File;
use crate::sync::SpinLock;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use alloc::collections::BTreeMap;
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

impl FileBacking {
    /// The backing for a sub-region starting `delta` bytes into this one: the
    /// file offset advances and the real-content length shrinks (the rest is
    /// the zero/bss tail). Splitting a file-backed VMA (unmap/mprotect) must use
    /// this, or the tail would demand-fill from the wrong file offset.
    fn shifted(&self, delta: usize) -> FileBacking {
        FileBacking { file: self.file.clone(), offset: self.offset + delta as u64, length: self.length.saturating_sub(delta as u64) }
    }
}

/// Shift an optional file backing by `delta` bytes (no-op for anonymous VMAs).
fn shift_backing(b: &Option<FileBacking>, delta: usize) -> Option<FileBacking> {
    b.as_ref().map(|fb| fb.shifted(delta))
}

/// A shared anonymous object: its pages are shared by every mapping of it,
/// including across `fork`, so `MAP_SHARED | MAP_ANONYMOUS` memory is genuinely
/// shared. This is what a database (postgres) and other IPC uses for its main
/// shared-memory segment; combined with futexes keyed by physical frame, it
/// gives working cross-process locks.
pub struct SharedAnon {
    /// page virtual address → backing frame (one owning reference each).
    pages: SpinLock<BTreeMap<usize, PhysAddr>>,
}

impl SharedAnon {
    pub fn new() -> Arc<SharedAnon> {
        Arc::new(SharedAnon { pages: SpinLock::new(BTreeMap::new()) })
    }
}

impl Drop for SharedAnon {
    fn drop(&mut self) {
        // Release the object's own reference to every frame it holds.
        for phys in self.pages.get_mut().values() {
            frame::page_put(*phys);
        }
    }
}

/// One contiguous mapping — a VMA. Anonymous private (demand-zeroed), file
/// backed (demand-filled, private, copy-on-write), or shared anonymous.
#[derive(Clone)]
struct Region {
    start: usize,
    end: usize,
    prot: Prot,
    /// Grows downward on faults just below `start` (the stack).
    grows_down: bool,
    /// `Some` for a file-backed (MAP_PRIVATE) mapping.
    backing: Option<FileBacking>,
    /// `Some` for a shared mapping (`MAP_SHARED`): anonymous, System V shm, or a
    /// file's shared page set. Pages are keyed within the object by
    /// `shared_base + (page - start)`, so the same object mapped at different
    /// addresses (or file offsets) in different processes shares pages.
    shared: Option<Arc<SharedAnon>>,
    /// Offset added to `page - start` when keying `shared` (the file offset that
    /// `start` maps to; 0 for anonymous shared and System V segments).
    shared_base: usize,
}

pub struct AddressSpace {
    pml4: PhysAddr,
    regions: SpinLock<Vec<Region>>,
    /// Highest brk address handed out; program break starts at `brk_base`.
    brk: SpinLock<usize>,
    brk_base: AtomicUsize,
    /// Where a fresh `mmap` with no hint is placed (grows down from here).
    mmap_top: SpinLock<usize>,
    /// The container this address space is charged to (memory cgroup), if any.
    container: SpinLock<Option<alloc::string::String>>,
    /// Resident pages committed in this space (for RSS reporting).
    committed: AtomicU64,
}

/// A page-table entry marker for a swapped-out page: the PRESENT bit is clear
/// (so the CPU faults on access) and this ignored bit is set to distinguish a
/// swap entry from a never-touched (demand-zero) entry. The swap slot index is
/// stored in bits [12..], leaving this bit and the low bits free.
const PTE_SWAPPED: u64 = 1 << 10;

/// How many pages one reclaim pass tries to free when memory is exhausted.
const RECLAIM_BATCH: u64 = 32;

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
            container: SpinLock::new(None),
            committed: AtomicU64::new(0),
        }))
    }

    pub fn pml4(&self) -> PhysAddr {
        self.pml4
    }

    /// Charge this space's committed pages to `cid`'s memory cgroup.
    pub fn set_container(&self, cid: Option<alloc::string::String>) {
        *self.container.lock() = cid;
    }

    /// Resident memory in bytes (committed pages) — for RSS reporting.
    pub fn rss_bytes(&self) -> u64 {
        self.committed.load(Ordering::Relaxed) * PAGE_SIZE as u64
    }

    /// Total mapped (virtual) size in bytes — the sum of the regions.
    pub fn virt_bytes(&self) -> u64 {
        self.regions.lock().iter().map(|r| (r.end - r.start) as u64).sum()
    }

    /// Charge one page (to the cgroup and the RSS counter); false → over the
    /// memory limit (ENOMEM).
    fn charge_page(&self) -> bool {
        if let Some(cid) = &*self.container.lock() {
            if !crate::cgroup::try_charge_page(cid) {
                return false;
            }
        }
        self.committed.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn uncharge_pages(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.committed.fetch_sub(n.min(self.committed.load(Ordering::Relaxed)), Ordering::Relaxed);
        if let Some(cid) = &*self.container.lock() {
            crate::cgroup::uncharge_pages(cid, n);
        }
    }

    /// Charge one page to the cgroup's swap allowance (on eviction); false → the
    /// memory+swap limit is reached, so the page must not be swapped out.
    fn charge_swap(&self) -> bool {
        match &*self.container.lock() {
            Some(cid) => crate::cgroup::try_charge_swap(cid),
            None => true,
        }
    }

    fn uncharge_swap(&self, n: u64) {
        if let Some(cid) = &*self.container.lock() {
            crate::cgroup::uncharge_swap(cid, n);
        }
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
        regions.push(Region { start, end, prot, grows_down, backing: None, shared: None, shared_base: 0 });
        Ok(())
    }

    /// Reserve a shared anonymous mapping (`MAP_SHARED|MAP_ANONYMOUS`): its
    /// pages are shared across every mapping and across fork.
    fn map_shared_region(&self, start: usize, end: usize, prot: Prot) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(end, PAGE_SIZE));
        if start < USER_START || end > USER_END || start >= end {
            return Err(Errno::EINVAL);
        }
        let mut regions = self.regions.lock();
        if Self::overlaps(&regions, start, end) {
            return Err(Errno::EEXIST);
        }
        regions.push(Region { start, end, prot, grows_down: false, backing: None, shared: Some(SharedAnon::new()), shared_base: 0 });
        Ok(())
    }

    /// Attach an existing shared-anonymous object into this address space (the
    /// System V `shmat` path). `hint` is honoured if free, else a slot is chosen
    /// growing down from the mmap area. Returns the attach address.
    pub fn attach_shared(&self, hint: usize, len: usize, prot: Prot, obj: Arc<SharedAnon>) -> KResult<usize> {
        let len = align_up(len.max(1), PAGE_SIZE);
        let hinted = if hint >= USER_START {
            let s = align_down(hint, PAGE_SIZE);
            let regions = self.regions.lock();
            (!Self::overlaps(&regions, s, s + len) && s + len <= USER_END).then_some(s)
        } else {
            None
        };
        let start = match hinted {
            Some(s) => s,
            None => {
                let mut top = self.mmap_top.lock();
                let s = align_down(top.checked_sub(len).ok_or(Errno::ENOMEM)?, PAGE_SIZE);
                *top = s;
                s
            }
        };
        let mut regions = self.regions.lock();
        if Self::overlaps(&regions, start, start + len) {
            return Err(Errno::EEXIST);
        }
        regions.push(Region { start, end: start + len, prot, grows_down: false, backing: None, shared: Some(obj), shared_base: 0 });
        Ok(start)
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
        regions.push(Region { start, end, prot, grows_down: false, backing: Some(FileBacking { file, offset, length }), shared: None, shared_base: 0 });
        Ok(())
    }

    /// Place a mapping of `len` bytes, honouring a fixed `hint`. When `file`
    /// is `Some`, the mapping is private and filled from the file at `offset`.
    pub fn mmap(&self, hint: usize, len: usize, prot: Prot, fixed: bool, file: Option<(Arc<dyn File>, u64)>, shared: bool) -> KResult<usize> {
        let len = align_up(len.max(1), PAGE_SIZE);
        let place = |this: &Self, start: usize| -> KResult<()> {
            match &file {
                // MAP_SHARED of a file whose fs backs shared memory (tmpfs /
                // shm_open): all mappers share the file's page set (POSIX shm).
                Some((f, off)) if shared => match f.shared_mmap() {
                    Some(obj) => this.map_shared_file_region(start, start + len, prot, obj, *off as usize),
                    // Other filesystems: fall back to a private mapping.
                    None => this.map_file_region(start, start + len, prot, f.clone(), *off, len as u64),
                },
                Some((f, off)) => this.map_file_region(start, start + len, prot, f.clone(), *off, len as u64),
                None if shared => this.map_shared_region(start, start + len, prot),
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

    /// Reserve a `MAP_SHARED` mapping backed by a file's shared page set `obj`,
    /// where `base` is the file offset that `start` maps to. Every process that
    /// maps the same file shares `obj`, so writes are visible to all — POSIX
    /// shared memory (postgres' dynamic shared memory segments).
    fn map_shared_file_region(&self, start: usize, end: usize, prot: Prot, obj: Arc<SharedAnon>, base: usize) -> KResult<()> {
        let (start, end) = (align_down(start, PAGE_SIZE), align_up(end, PAGE_SIZE));
        if start < USER_START || end > USER_END || start >= end {
            return Err(Errno::EINVAL);
        }
        let mut regions = self.regions.lock();
        if Self::overlaps(&regions, start, end) {
            return Err(Errno::EEXIST);
        }
        regions.push(Region { start, end, prot, grows_down: false, backing: None, shared: Some(obj), shared_base: base });
        Ok(())
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
                out.push(Region { start: end, backing: shift_backing(&r.backing, end - r.start), ..r.clone() });
            }
        }
        *regions = out;
        drop(regions);
        let mut va = start;
        let mut freed = 0u64;
        let mut swapped = 0u64;
        while va < end {
            if free_swap_entry(self.pml4, va) {
                // A swapped page: its slot is released; nothing resident to free.
                swapped += 1;
            } else if let Some((phys, fl)) = unsafe { paging::unmap_4k(self.pml4, va) } {
                if fl & flags::PRESENT != 0 {
                    frame::page_put(phys);
                    freed += 1;
                }
                cpu::invlpg(va);
            }
            va += PAGE_SIZE;
        }
        self.uncharge_pages(freed);
        self.uncharge_swap(swapped);
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
            let mid_start = start.max(r.start);
            out.push(Region { start: mid_start, end: end.min(r.end), prot, grows_down: r.grows_down, backing: shift_backing(&r.backing, mid_start - r.start), shared: r.shared.clone(), shared_base: r.shared_base + (mid_start - r.start) });
            if end < r.end {
                out.push(Region { start: end, backing: shift_backing(&r.backing, end - r.start), ..r.clone() });
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

    /// Human-readable description of the region containing `addr` (for fault
    /// diagnostics): `(start, offset_within, prot_bits, file_backed)`.
    pub fn describe(&self, addr: usize) -> Option<(usize, usize, u8, bool)> {
        self.region_at(addr).map(|r| (r.start, addr - r.start, r.prot.bits(), r.backing.is_some()))
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

    /// Make every page of `[addr, addr+len)` present (allocating, or swapping
    /// back in) so a subsequent direct kernel copy cannot fault. This is how
    /// `uaccess` guarantees a user pointer is resolvable: an unresolvable page
    /// (bad pointer, or a swap-in that fails under pressure) returns EFAULT here
    /// instead of taking a kernel-mode fault that no fixup would catch.
    pub fn fault_in_range(&self, addr: usize, len: usize, write: bool) -> KResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = addr.checked_add(len).ok_or(Errno::EFAULT)?;
        let mut page = align_down(addr, PAGE_SIZE);
        while page < end {
            self.fault_in(page, write)?;
            page += PAGE_SIZE;
        }
        Ok(())
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
                // A swapped-out page: read it back from the swap device.
                if *e & PTE_SWAPPED != 0 {
                    return self.swap_in(page, e, r);
                }
            }
        }
        // About to commit a new page into this space — charge the memory cgroup
        // (per-space, so it balances with the uncharge on unmap/teardown). Under
        // a full cgroup, reclaim (which uncharges swapped pages) may free budget.
        if !self.charge_page() {
            self.reclaim(RECLAIM_BATCH);
            if !self.charge_page() {
                return Err(Errno::ENOMEM);
            }
        }
        // Shared anonymous page: resolve it through the shared object so every
        // mapping (and every process after fork) sees the same frame. Keyed by
        // the page's offset within the region, so a System V segment attached at
        // different addresses in different processes still shares its pages.
        if let Some(sh) = &r.shared {
            let off = r.shared_base + (page - r.start);
            let mut pages = sh.pages.lock();
            let phys = match pages.get(&off) {
                Some(&p) => {
                    frame::page_get(p); // this page table's reference
                    p
                }
                None => {
                    let p = match self.alloc_pressure() {
                        Some(p) => p,
                        None => {
                            self.uncharge_pages(1);
                            return Err(Errno::ENOMEM);
                        }
                    }; // the object's reference
                    pages.insert(off, p);
                    frame::page_get(p); // this page table's reference
                    p
                }
            };
            drop(pages);
            let fl = to_page_flags(r.prot);
            unsafe {
                paging::map_4k(self.pml4, page, phys, fl, &mut alloc_table).map_err(map_err)?;
            }
            cpu::invlpg(page);
            return Ok(());
        }
        let phys = match self.alloc_pressure() {
            Some(p) => p,
            None => {
                self.uncharge_pages(1);
                return Err(Errno::ENOMEM);
            }
        };
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

    /// Read a swapped-out page back into a fresh frame and restore its PTE. The
    /// leaf entry `e` currently holds the swap slot; on success it becomes a
    /// present mapping again and the slot is freed. The page has already been
    /// charged? No — swap-in charges here (a swapped page was uncharged on evict).
    fn swap_in(&self, page: usize, e: *mut u64, r: &Region) -> KResult<()> {
        let slot = (unsafe { *e } >> 12) as usize;
        if !self.charge_page() {
            self.reclaim(RECLAIM_BATCH);
            if !self.charge_page() {
                return Err(Errno::ENOMEM);
            }
        }
        let phys = match self.alloc_pressure() {
            Some(p) => p,
            None => {
                self.uncharge_pages(1);
                return Err(Errno::ENOMEM);
            }
        };
        // Read the slot straight into the new frame via the kernel direct map.
        let dst = unsafe { &mut *(super::phys_to_virt(phys) as *mut [u8; PAGE_SIZE]) };
        if !swap::read_slot(slot, dst) {
            frame::page_put(phys);
            self.uncharge_pages(1);
            return Err(Errno::EIO);
        }
        let fl = to_page_flags(r.prot);
        unsafe {
            paging::map_4k(self.pml4, page, phys, fl, &mut alloc_table).map_err(map_err)?;
        }
        cpu::invlpg(page);
        swap::free_slot(slot);
        self.uncharge_swap(1); // the page is resident again, no longer in swap
        Ok(())
    }

    /// Allocate a user frame, reclaiming (swapping out cold pages) once if the
    /// allocator is exhausted, then retrying.
    fn alloc_pressure(&self) -> Option<PhysAddr> {
        if let Some(p) = frame::alloc_user_page() {
            return Some(p);
        }
        self.reclaim(RECLAIM_BATCH);
        frame::alloc_user_page()
    }

    /// Reclaim up to `target` anonymous-private pages of this space by writing
    /// them to swap. Returns the number actually evicted (0 if swap is off).
    ///
    /// Two passes guarantee forward progress: the first honours the ACCESSED bit
    /// (a second chance for recently-used pages), and if that frees too few, a
    /// second pass evicts regardless — so a workload that just touched every page
    /// can still be reclaimed instead of wedging the fault path.
    fn reclaim(&self, target: u64) -> u64 {
        if !swap::enabled() {
            return 0;
        }
        let mut freed = self.reclaim_pass(target, false);
        if freed < target {
            freed += self.reclaim_pass(target - freed, true);
        }
        freed
    }

    fn reclaim_pass(&self, target: u64, force: bool) -> u64 {
        let regions = self.regions.lock().clone();
        let mut freed = 0u64;
        // Only writable anonymous-private memory (heap, stack, data) is swapped.
        // Executable/read-only pages — including a statically-loaded program's
        // own code — are left resident so the running program is never paged out
        // from under its own instruction fetches.
        for r in regions.iter().filter(|r| r.backing.is_none() && r.shared.is_none() && r.prot.contains(Prot::WRITE)) {
            let mut va = r.start;
            while va < r.end {
                if freed >= target {
                    return freed;
                }
                if self.try_evict(va, force) {
                    freed += 1;
                }
                va += PAGE_SIZE;
            }
        }
        freed
    }

    /// Try to evict one anonymous-private page at `va` to swap. Only a present,
    /// singly-owned, non-COW page whose ACCESSED bit is clear is taken; a page
    /// touched since the last pass gets a second chance (its ACCESSED bit is
    /// cleared and it is skipped). The page's contents are written to swap while
    /// the mapping stays live, and the PTE is only replaced if the page was not
    /// written during the (sleeping) I/O — so a concurrent write is never lost.
    fn try_evict(&self, va: usize, force: bool) -> bool {
        let phys;
        {
            let _irq = cpu::IrqGuard::new();
            let e = match unsafe { paging::leaf_entry(self.pml4, va) } {
                Some(e) => e,
                None => return false,
            };
            let pte = unsafe { *e };
            if pte & flags::PRESENT == 0 || pte & flags::COW != 0 {
                return false;
            }
            let p = paging::entry_addr(pte);
            if frame::page_count(p) != 1 {
                return false; // shared with another space (e.g. lingering COW)
            }
            if !force && pte & flags::ACCESSED != 0 {
                // Recently used: clear the bit and give it another chance.
                unsafe { *e = pte & !flags::ACCESSED };
                cpu::invlpg(va);
                return false;
            }
            // Clear DIRTY so a concurrent write during the I/O is detectable.
            unsafe { *e = pte & !flags::DIRTY };
            cpu::invlpg(va);
            phys = p;
        }
        // Write the page out (may sleep); the mapping is still live and readable.
        let slot = match swap::store_page(phys) {
            Some(s) => s,
            None => return false,
        };
        // Commit only if nothing wrote the page while it was being staged.
        {
            let _irq = cpu::IrqGuard::new();
            let e = match unsafe { paging::leaf_entry(self.pml4, va) } {
                Some(e) => e,
                None => {
                    swap::free_slot(slot);
                    return false;
                }
            };
            let pte = unsafe { *e };
            if pte & flags::PRESENT == 0 || paging::entry_addr(pte) != phys || pte & flags::DIRTY != 0 {
                swap::free_slot(slot);
                return false;
            }
            // Charge the swap allowance; if memory+swap is exhausted, keep the
            // page resident (reclaim then frees nothing → the fault OOMs, so a
            // `-m` limit still bounds total memory).
            if !self.charge_swap() {
                swap::free_slot(slot);
                return false;
            }
            unsafe { *e = ((slot as u64) << 12) | PTE_SWAPPED };
            cpu::invlpg(va);
        }
        frame::page_put(phys);
        self.uncharge_pages(1);
        true
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
            let is_shared = r.shared.is_some();
            let mut va = r.start;
            while va < r.end {
                // A swapped page must be brought back into the parent first, so
                // the child inherits its contents (no shared swap slots).
                if let Some(e) = unsafe { paging::leaf_entry(self.pml4, va) } {
                    if unsafe { *e } & flags::PRESENT == 0 && unsafe { *e } & PTE_SWAPPED != 0 {
                        let _ = self.swap_in(va, e, r);
                    }
                }
                unsafe {
                    if let Some(e) = paging::leaf_entry(self.pml4, va) {
                        if *e & flags::PRESENT != 0 {
                            let phys = paging::entry_addr(*e);
                            // Shared pages stay writable in both processes (that
                            // is the point). Private writable pages become
                            // read-only + copy-on-write in both copies.
                            if !is_shared && *e & flags::WRITABLE != 0 {
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
                regions.push(Region { start: base.max(cur), end: new, prot: Prot::READ | Prot::WRITE, grows_down: false, backing: None, shared: None, shared_base: 0 });
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

/// If `va` holds a swapped-out entry, release its swap slot and clear the entry.
/// Returns true if it was a swap entry (so the caller skips the resident-page
/// path). A non-present entry that is left cleared costs nothing.
fn free_swap_entry(pml4: PhysAddr, va: usize) -> bool {
    unsafe {
        if let Some(e) = paging::leaf_entry(pml4, va) {
            let pte = *e;
            if pte & flags::PRESENT == 0 && pte & PTE_SWAPPED != 0 {
                swap::free_slot((pte >> 12) as usize);
                *e = 0;
                return true;
            }
        }
    }
    false
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
        let mut freed = 0u64;
        let mut swapped = 0u64;
        for r in regions {
            let mut va = r.start;
            while va < r.end {
                if free_swap_entry(self.pml4, va) {
                    swapped += 1; // release its swap slot
                } else if let Some((phys, fl)) = unsafe { paging::unmap_4k(self.pml4, va) } {
                    if fl & flags::PRESENT != 0 {
                        frame::page_put(phys);
                        freed += 1;
                    }
                }
                va += PAGE_SIZE;
            }
        }
        self.uncharge_pages(freed);
        self.uncharge_swap(swapped);
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
