//! HAL: Memory interface trait

pub trait MemoryInterface {
    /// Map a physical frame to a virtual page.
    /// Returns Err if mapping already exists or out of memory.
    fn map(&mut self, phys: u64, virt: u64, flags: PageFlags) -> Result<(), MapError>;

    /// Unmap a virtual page. Returns the physical address it pointed to.
    fn unmap(&mut self, virt: u64) -> Result<u64, MapError>;

    /// Translate a virtual address to physical. Returns None if not mapped.
    fn translate(&self, virt: u64) -> Option<u64>;

    /// Flush the TLB entry for a specific virtual address.
    fn flush_tlb(&self, virt: u64);

    /// Flush the entire TLB.
    fn flush_tlb_all(&self);
}

#[derive(Debug, Clone, Copy)]
pub struct PageFlags {
    pub writable:   bool,
    pub executable: bool,
    pub user:       bool,
    pub no_cache:   bool,
}

impl PageFlags {
    pub const KERNEL_RW: Self = Self {
        writable: true, executable: false, user: false, no_cache: false,
    };
    pub const KERNEL_RX: Self = Self {
        writable: false, executable: true, user: false, no_cache: false,
    };
    pub const USER_RW: Self = Self {
        writable: true, executable: false, user: true, no_cache: false,
    };
}

#[derive(Debug)]
pub enum MapError {
    AlreadyMapped,
    OutOfMemory,
    InvalidAddress,
}
