//! Per-process virtual address space
//!
//! Each process has its own AddressSpace (its own PML4 root).
//! The kernel's higher-half mappings are shared across all address spaces.

pub struct AddressSpace {
    /// Physical address of the PML4 root table (loaded into CR3).
    pub cr3: u64,
}

impl AddressSpace {
    /// Create a new empty address space with kernel mappings copied in.
    pub fn new() -> Option<Self> {
        // TODO: Allocate a PML4 frame.
        // TODO: Copy kernel PML4 entries (upper half) from kernel address space.
        None
    }

    /// Switch to this address space (load CR3).
    pub unsafe fn activate(&self) {
        // TODO: mov cr3, self.cr3
        let _ = self.cr3;
    }

    /// Map a virtual page to a physical frame within this address space.
    pub fn map(&mut self, _virt: u64, _phys: u64) -> Result<(), &'static str> {
        // TODO: Walk page tables, allocate missing tables, set entry.
        Err("not implemented")
    }
}
