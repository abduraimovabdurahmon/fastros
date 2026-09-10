//! x86_64 4-level page table implementation
//!
//! Hierarchy: CR3 → PML4[512] → PDPT[512] → PD[512] → PT[512] → 4 KB page
//!
//! Virtual address bits:
//!   [47:39] = PML4 index
//!   [38:30] = PDPT index
//!   [29:21] = PD   index
//!   [20:12] = PT   index
//!   [11: 0] = page offset

/// Page table entry flags.
pub mod flags {
    pub const PRESENT:    u64 = 1 << 0;
    pub const WRITABLE:   u64 = 1 << 1;
    pub const USER:       u64 = 1 << 2;
    pub const WRITE_THRU: u64 = 1 << 3;
    pub const NO_CACHE:   u64 = 1 << 4;
    pub const ACCESSED:   u64 = 1 << 5;
    pub const DIRTY:      u64 = 1 << 6;
    pub const HUGE_PAGE:  u64 = 1 << 7;
    pub const GLOBAL:     u64 = 1 << 8;
    pub const NO_EXEC:    u64 = 1 << 63;

    /// Kernel read-write page (present + writable + global + NX).
    pub const KERN_RW: u64 = PRESENT | WRITABLE | GLOBAL | NO_EXEC;
    /// Kernel executable page (present + writable + global, no NX).
    pub const KERN_X:  u64 = PRESENT | WRITABLE | GLOBAL;
    /// User read-write page.
    pub const USER_RW: u64 = PRESENT | WRITABLE | USER | NO_EXEC;
    /// User executable page.
    pub const USER_X:  u64 = PRESENT | USER;
}

const ENTRIES: usize = 512;
const PAGE_SIZE: u64 = 4096;
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// A single level of the 4-level page table hierarchy.
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; ENTRIES],
}

impl PageTable {
    pub const fn new() -> Self {
        Self { entries: [0; ENTRIES] }
    }

    /// Index into this table for a virtual address at `level`.
    /// level: 4=PML4, 3=PDPT, 2=PD, 1=PT
    pub fn index(virt: u64, level: u8) -> usize {
        let shift = 12 + (level as u64 - 1) * 9;
        ((virt >> shift) & 0x1FF) as usize
    }

    /// Physical address stored in an entry (strips flags).
    pub fn entry_phys(entry: u64) -> u64 {
        entry & PHYS_ADDR_MASK
    }

    /// Check if an entry has PRESENT flag.
    pub fn is_present(entry: u64) -> bool {
        entry & flags::PRESENT != 0
    }
}

/// Map one 4 KB virtual page to a physical frame.
///
/// # Safety
/// - `pml4_phys` must be the physical address of the active PML4.
/// - `alloc_frame` must return a fresh, zeroed 4 KB physical frame on each call.
/// - All physical addresses must be accessible via identity mapping.
pub unsafe fn map_page(
    pml4_phys: u64,
    virt: u64,
    phys: u64,
    page_flags: u64,
    alloc_frame: &mut dyn FnMut() -> Option<u64>,
) -> bool {
    let pml4 = &mut *(pml4_phys as *mut PageTable);

    let pml4_idx = PageTable::index(virt, 4);
    let pdpt_phys = ensure_table(&mut pml4.entries[pml4_idx], alloc_frame);
    let pdpt_phys = match pdpt_phys { Some(p) => p, None => return false };

    let pdpt = &mut *(pdpt_phys as *mut PageTable);
    let pdpt_idx = PageTable::index(virt, 3);
    let pd_phys = ensure_table(&mut pdpt.entries[pdpt_idx], alloc_frame);
    let pd_phys = match pd_phys { Some(p) => p, None => return false };

    let pd = &mut *(pd_phys as *mut PageTable);
    let pd_idx = PageTable::index(virt, 2);
    let pt_phys = ensure_table(&mut pd.entries[pd_idx], alloc_frame);
    let pt_phys = match pt_phys { Some(p) => p, None => return false };

    let pt = &mut *(pt_phys as *mut PageTable);
    let pt_idx = PageTable::index(virt, 1);
    pt.entries[pt_idx] = (phys & PHYS_ADDR_MASK) | page_flags;

    // Invalidate TLB for this virtual address
    core::arch::asm!("invlpg [{0}]", in(reg) virt, options(nostack));
    true
}

/// Translate a virtual address to physical using the given PML4.
/// Returns None if any level is not present.
pub unsafe fn translate(pml4_phys: u64, virt: u64) -> Option<u64> {
    let pml4 = &*(pml4_phys as *const PageTable);
    let e3 = pml4.entries[PageTable::index(virt, 4)];
    if !PageTable::is_present(e3) { return None; }

    let pdpt = &*(PageTable::entry_phys(e3) as *const PageTable);
    let e2 = pdpt.entries[PageTable::index(virt, 3)];
    if !PageTable::is_present(e2) { return None; }

    let pd = &*(PageTable::entry_phys(e2) as *const PageTable);
    let e1 = pd.entries[PageTable::index(virt, 2)];
    if !PageTable::is_present(e1) { return None; }

    // Check for 2 MB huge page
    if e1 & flags::HUGE_PAGE != 0 {
        return Some(PageTable::entry_phys(e1) + (virt & 0x1F_FFFF));
    }

    let pt = &*(PageTable::entry_phys(e1) as *const PageTable);
    let e0 = pt.entries[PageTable::index(virt, 1)];
    if !PageTable::is_present(e0) { return None; }

    Some(PageTable::entry_phys(e0) + (virt & 0xFFF))
}

/// Unmap a single 4 KB page, leaving the page table structure intact.
pub unsafe fn unmap_page(pml4_phys: u64, virt: u64) {
    let pml4 = &*(pml4_phys as *const PageTable);
    let e3 = pml4.entries[PageTable::index(virt, 4)];
    if !PageTable::is_present(e3) { return; }
    let pdpt = &*(PageTable::entry_phys(e3) as *const PageTable);
    let e2 = pdpt.entries[PageTable::index(virt, 3)];
    if !PageTable::is_present(e2) { return; }
    let pd = &*(PageTable::entry_phys(e2) as *const PageTable);
    let e1 = pd.entries[PageTable::index(virt, 2)];
    if !PageTable::is_present(e1) { return; }
    let pt = &mut *(PageTable::entry_phys(e1) as *mut PageTable);
    pt.entries[PageTable::index(virt, 1)] = 0;
    core::arch::asm!("invlpg [{0}]", in(reg) virt, options(nostack));
}

/// Read CR3 (physical address of active PML4).
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe { core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack)); }
    cr3 & PHYS_ADDR_MASK
}

/// Write CR3 — switches address space (flushes TLB).
pub unsafe fn write_cr3(pml4_phys: u64) {
    core::arch::asm!("mov cr3, {0}", in(reg) pml4_phys, options(nostack));
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// If the entry is not present, allocate a new zeroed page table frame and link it.
/// Returns the physical address of the child table (existing or freshly allocated).
unsafe fn ensure_table(
    entry: &mut u64,
    alloc: &mut dyn FnMut() -> Option<u64>,
) -> Option<u64> {
    if PageTable::is_present(*entry) {
        return Some(PageTable::entry_phys(*entry));
    }
    let frame = alloc()?;
    // Zero the new page table
    let table = &mut *(frame as *mut PageTable);
    table.entries = [0; ENTRIES];
    *entry = frame | flags::PRESENT | flags::WRITABLE;
    Some(frame)
}
