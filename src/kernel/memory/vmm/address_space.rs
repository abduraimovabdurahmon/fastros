//! Per-process virtual address space + Virtual Memory Areas (VMAs)
//!
//! Each process has an AddressSpace which tracks:
//!   - PML4 physical address (for CR3)
//!   - A list of VMAs (virtual memory areas / mappings)
//!
//! VMA types:
//!   Anonymous — zero-filled demand pages (heap, stack)
//!   File      — file-backed mapping (executable, shared lib)
//!   Device    — MMIO region (framebuffer, etc.)

const MAX_VMAS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VmaKind {
    Anonymous,
    FileBacked { inode_idx: u32, file_offset: u64 },
    Device,
}

#[derive(Clone, Copy)]
pub struct Vma {
    pub start: u64,       // first byte (inclusive)
    pub end:   u64,       // first byte NOT in region (exclusive)
    pub flags: u64,       // page table flags (from paging::flags::*)
    pub kind:  VmaKind,
}

impl Vma {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}

#[derive(Clone, Copy)]
pub struct AddressSpace {
    /// Physical address of the PML4 table (goes into CR3).
    pub pml4_phys: u64,
    vmas:      [Option<Vma>; MAX_VMAS],
    vma_count: usize,
}

impl AddressSpace {
    pub const fn empty() -> Self {
        Self { pml4_phys: 0, vmas: [None; MAX_VMAS], vma_count: 0 }
    }

    /// Add a VMA to this address space.  Returns false if the table is full.
    pub fn add_vma(&mut self, vma: Vma) -> bool {
        if self.vma_count >= MAX_VMAS { return false; }
        for slot in &mut self.vmas {
            if slot.is_none() {
                *slot = Some(vma);
                self.vma_count += 1;
                return true;
            }
        }
        false
    }

    /// Remove the VMA that contains `addr`.
    pub fn remove_vma_at(&mut self, addr: u64) {
        for slot in &mut self.vmas {
            if let Some(v) = slot {
                if v.contains(addr) {
                    *slot = None;
                    self.vma_count -= 1;
                    return;
                }
            }
        }
    }

    /// Find the VMA that contains `fault_addr`.
    pub fn find_vma(&self, fault_addr: u64) -> Option<&Vma> {
        for slot in &self.vmas {
            if let Some(v) = slot {
                if v.contains(fault_addr) { return Some(v); }
            }
        }
        None
    }

    /// Iterator over all active VMAs.
    pub fn iter_vmas(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.iter().filter_map(|s| s.as_ref())
    }

    /// Switch to this address space (write CR3).
    pub unsafe fn activate(&self) {
        core::arch::asm!("mov cr3, {0}", in(reg) self.pml4_phys, options(nostack));
    }
}
