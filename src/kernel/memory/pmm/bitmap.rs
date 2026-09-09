//! Bitmap physical frame allocator
//!
//! Each bit represents one 4 KB physical frame.
//! Total memory 4 GB → 1 million frames → 128 KB bitmap.

const FRAME_SIZE: u64 = 4096;

/// Find the first free frame in the bitmap. Returns frame index.
pub fn find_free(_bitmap: &mut [u64]) -> Option<usize> {
    // TODO: scan bitmap for zero bit using bit tricks
    None
}

/// Mark a frame as used.
pub fn set_bit(_bitmap: &mut [u64], _frame: usize) {
    // TODO: bitmap[frame / 64] |= 1 << (frame % 64)
}

/// Mark a frame as free.
pub fn clear_bit(_bitmap: &mut [u64], _frame: usize) {
    // TODO: bitmap[frame / 64] &= !(1 << (frame % 64))
}

/// Check if a frame is free.
pub fn is_free(_bitmap: &[u64], _frame: usize) -> bool {
    // TODO: (bitmap[frame / 64] >> (frame % 64)) & 1 == 0
    false
}

/// Convert a physical address to a frame index.
pub fn addr_to_frame(phys: u64) -> usize {
    (phys / FRAME_SIZE) as usize
}

/// Convert a frame index to a physical address.
pub fn frame_to_addr(frame: usize) -> u64 {
    (frame as u64) * FRAME_SIZE
}
