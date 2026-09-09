//! Physical Memory Manager (PMM)
//!
//! Tracks which 4 KB physical frames are free or in use.
//! Implementation: bitmap allocator (1 bit per frame).
//!   0 = free, 1 = used
//!
//! Must be initialized first with the memory map from the bootloader.

pub mod bitmap;

/// Initialize the PMM with the bootloader's memory map.
pub fn init() {
    // TODO: Parse Multiboot2 memory map tag.
    // TODO: Mark all frames used, then free usable regions.
    // TODO: Mark kernel frames as used.
}

/// Allocate one physical frame. Returns the physical address or None.
pub fn alloc_frame() -> Option<u64> {
    // TODO: bitmap::find_free_frame()
    None
}

/// Free a physical frame.
pub fn free_frame(phys_addr: u64) {
    // TODO: bitmap::clear_bit(frame_index)
    let _ = phys_addr;
}
