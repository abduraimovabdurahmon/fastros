//! Bitmap physical frame allocator — core bit operations.
//!
//! 1 bit per 4 KB frame.  0 = free, 1 = used.
//! 64 frames packed per u64 word → fast scan with trailing-zeros trick.

pub const FRAME_SIZE: u64 = 4096;

/// Find the first free (0) bit.  Returns the frame index or None if full.
pub fn find_free(bitmap: &[u64]) -> Option<usize> {
    for (word_idx, &word) in bitmap.iter().enumerate() {
        if word != !0u64 {
            // At least one free bit in this word
            let bit = word.trailing_ones() as usize; // first 0 bit position
            return Some(word_idx * 64 + bit);
        }
    }
    None
}

/// Mark frame `n` as used (set bit to 1).
#[inline]
pub fn set_bit(bitmap: &mut [u64], n: usize) {
    bitmap[n / 64] |= 1u64 << (n % 64);
}

/// Mark frame `n` as free (clear bit to 0).
#[inline]
pub fn clear_bit(bitmap: &mut [u64], n: usize) {
    bitmap[n / 64] &= !(1u64 << (n % 64));
}

/// Check if frame `n` is free.
#[inline]
pub fn is_free(bitmap: &[u64], n: usize) -> bool {
    (bitmap[n / 64] >> (n % 64)) & 1 == 0
}

/// Physical address → frame index.
#[inline]
pub fn addr_to_frame(phys: u64) -> usize {
    (phys / FRAME_SIZE) as usize
}

/// Frame index → physical address.
#[inline]
pub fn frame_to_addr(frame: usize) -> u64 {
    (frame as u64) * FRAME_SIZE
}
