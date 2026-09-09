//! x86_64 4-level page table implementation
//!
//! Page table hierarchy:
//!   CR3 → PML4 (512 entries)
//!           └── PDPT (512 entries)
//!                 └── PD (512 entries, or 2MB huge page here)
//!                       └── PT (512 entries, each = 4KB page)
//!
//! Virtual address breakdown (48-bit canonical):
//!   [47:39] PML4 index
//!   [38:30] PDPT index
//!   [29:21] PD index
//!   [20:12] PT index
//!   [11:0]  Page offset

/// Page table entry flags (x86_64 format).
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
}

// TODO: Implement PageTable struct (array of 512 u64 entries).
// TODO: Implement map/unmap/translate functions.
// TODO: Implement frame allocator integration.
