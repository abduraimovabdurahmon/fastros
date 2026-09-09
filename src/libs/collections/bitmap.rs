//! Fixed-size bitmap
//!
//! Compact bit array. Uses u64 words for fast operations.
//! Used by: PMM frame allocator, IPC signal masks, port maps.

pub struct Bitmap<const BITS: usize>
where
    [(); (BITS + 63) / 64]: Sized,
{
    words: [u64; (BITS + 63) / 64],
}

impl<const BITS: usize> Bitmap<BITS>
where
    [(); (BITS + 63) / 64]: Sized,
{
    pub const fn new() -> Self {
        Self { words: [0; (BITS + 63) / 64] }
    }

    pub fn set(&mut self, bit: usize) {
        self.words[bit / 64] |= 1u64 << (bit % 64);
    }

    pub fn clear(&mut self, bit: usize) {
        self.words[bit / 64] &= !(1u64 << (bit % 64));
    }

    pub fn get(&self, bit: usize) -> bool {
        (self.words[bit / 64] >> (bit % 64)) & 1 == 1
    }

    /// Find the first zero (free) bit. Returns None if all set.
    pub fn find_first_zero(&self) -> Option<usize> {
        for (i, &word) in self.words.iter().enumerate() {
            if word != u64::MAX {
                let bit = word.trailing_ones() as usize;
                let index = i * 64 + bit;
                if index < BITS { return Some(index); }
            }
        }
        None
    }
}
