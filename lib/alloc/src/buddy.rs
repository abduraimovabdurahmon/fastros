//! Binary buddy allocator over a contiguous range of page frames.
//!
//! Frames are addressed by index (`0..frames`) relative to a base that the
//! caller keeps aligned to `2^MAX_ORDER` frames, so a block of order `o`
//! always starts at an index that is a multiple of `2^o` and its buddy is
//! `idx ^ (1 << o)`.
//!
//! Book-keeping:
//! * one state byte per frame (`state[idx]`) says whether the frame heads a
//!   free block, heads an allocated block (and of which order), is reserved
//!   (never allocatable: holes, the kernel image, MMIO), or is the interior
//!   of a larger block;
//! * one intrusive doubly-linked free list per order, whose nodes live in the
//!   first 16 bytes of each free block (so the lists cost no extra memory).
//!
//! Freeing verifies the state byte, so a double free or a free with the wrong
//! order is reported instead of silently corrupting the lists.

pub const MAX_ORDER: usize = 10;
const NIL: usize = usize::MAX;

const ST_NONE: u8 = 0x00;
const ST_RESERVED: u8 = 0x40;
const ST_FREE: u8 = 0x80;
const ST_USED: u8 = 0xC0;
const ST_KIND: u8 = 0xC0;
const ST_ORDER: u8 = 0x0F;

/// Access to the memory of the managed frames (free-list nodes live there).
pub trait FrameMemory {
    /// Address of the first byte of frame `idx`; must be writable, 16-byte aligned.
    fn frame_ptr(&self, idx: usize) -> *mut u8;
}

#[repr(C)]
struct Link {
    next: usize,
    prev: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeError {
    OutOfRange,
    NotAllocated,
    WrongOrder { allocated: usize },
}

pub struct Buddy<M: FrameMemory> {
    mem: M,
    state: *mut u8,
    frames: usize,
    heads: [usize; MAX_ORDER + 1],
    counts: [usize; MAX_ORDER + 1],
    free_frames: usize,
    managed_frames: usize,
}

// The raw pointers refer to memory owned exclusively by this allocator.
unsafe impl<M: FrameMemory + Send> Send for Buddy<M> {}

impl<M: FrameMemory> Buddy<M> {
    /// Create an allocator for `frames` frames, all initially reserved.
    ///
    /// # Safety
    /// `state` must point to `frames` bytes of writable memory owned by the
    /// allocator for its whole lifetime, and `mem.frame_ptr(i)` must be valid
    /// for every frame later released with [`Buddy::add_range`].
    pub unsafe fn new(mem: M, state: *mut u8, frames: usize) -> Self {
        core::ptr::write_bytes(state, ST_RESERVED, frames);
        Self {
            mem,
            state,
            frames,
            heads: [NIL; MAX_ORDER + 1],
            counts: [0; MAX_ORDER + 1],
            free_frames: 0,
            managed_frames: 0,
        }
    }

    pub fn frames(&self) -> usize {
        self.frames
    }
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }
    /// Size of the frame index space (managed or not).
    pub fn total_frames(&self) -> usize {
        self.frames
    }
    /// Frames ever released into the allocator (usable RAM).
    pub fn managed_frames(&self) -> usize {
        self.managed_frames
    }
    /// Number of free blocks of each order.
    pub fn free_blocks(&self) -> [usize; MAX_ORDER + 1] {
        self.counts
    }

    /// Release the reserved frames in `[start, end)`. Frames that are not
    /// currently reserved are skipped, so overlapping calls are harmless.
    pub fn add_range(&mut self, start: usize, end: usize) {
        let end = end.min(self.frames);
        let mut idx = start;
        while idx < end {
            if self.st(idx) != ST_RESERVED {
                idx += 1;
                continue;
            }
            let mut run_end = idx;
            while run_end < end && self.st(run_end) == ST_RESERVED {
                run_end += 1;
            }
            self.add_run(idx, run_end);
            idx = run_end;
        }
    }

    fn add_run(&mut self, mut idx: usize, end: usize) {
        while idx < end {
            let mut order = MAX_ORDER;
            while order > 0 && (idx & ((1 << order) - 1) != 0 || idx + (1 << order) > end) {
                order -= 1;
            }
            for i in idx..idx + (1 << order) {
                self.set(i, ST_NONE);
            }
            self.free_frames += 1 << order;
            self.managed_frames += 1 << order;
            self.release(idx, order);
            idx += 1 << order;
        }
    }

    /// Mark `[start, end)` reserved again. Only frames that are free can be
    /// taken back; returns false (and changes nothing) otherwise.
    pub fn reserve_range(&mut self, start: usize, end: usize) -> bool {
        let end = end.min(self.frames);
        for idx in start..end {
            if !self.is_free(idx) {
                return false;
            }
        }
        // Split every free block that overlaps the range down to single frames
        // inside the range, then drop those frames from the lists.
        let mut idx = start;
        while idx < end {
            let (head, order) = self.free_block_containing(idx).expect("checked free above");
            self.unlink(head, order);
            self.free_frames -= 1 << order;
            // Re-release the parts of the block outside [start, end).
            let mut i = head;
            while i < head + (1 << order) {
                if i >= start && i < end {
                    self.set(i, ST_RESERVED);
                    self.managed_frames -= 1;
                    i += 1;
                } else {
                    self.free_frames += 1;
                    self.release(i, 0);
                    i += 1;
                }
            }
            idx = head + (1 << order);
        }
        true
    }

    /// True when frame `idx` lies inside a free block.
    pub fn is_free(&self, idx: usize) -> bool {
        self.free_block_containing(idx).is_some()
    }

    fn free_block_containing(&self, idx: usize) -> Option<(usize, usize)> {
        if idx >= self.frames {
            return None;
        }
        // A free block of order `o` containing `idx` must start at `idx`
        // rounded down to `2^o` (blocks are naturally aligned).
        (0..=MAX_ORDER).find_map(|order| {
            let head = idx & !((1usize << order) - 1);
            (self.st(head) == ST_FREE | order as u8).then_some((head, order))
        })
    }

    /// Order of the allocated block headed by `idx`, if any.
    pub fn allocated_order(&self, idx: usize) -> Option<usize> {
        if idx >= self.frames {
            return None;
        }
        let st = self.st(idx);
        (st & ST_KIND == ST_USED).then_some((st & ST_ORDER) as usize)
    }

    /// Allocate a block of `2^order` frames; returns the index of its first frame.
    pub fn alloc(&mut self, order: usize) -> Option<usize> {
        if order > MAX_ORDER {
            return None;
        }
        let mut o = order;
        while o <= MAX_ORDER && self.heads[o] == NIL {
            o += 1;
        }
        if o > MAX_ORDER {
            return None;
        }
        let idx = self.heads[o];
        self.unlink(idx, o);
        while o > order {
            o -= 1;
            self.push(idx + (1 << o), o);
        }
        self.set(idx, ST_USED | order as u8);
        self.free_frames -= 1 << order;
        Some(idx)
    }

    /// Return a block obtained from [`Buddy::alloc`] with the same `order`.
    pub fn free(&mut self, idx: usize, order: usize) -> Result<(), FreeError> {
        if idx >= self.frames {
            return Err(FreeError::OutOfRange);
        }
        let st = self.st(idx);
        if st & ST_KIND != ST_USED {
            return Err(FreeError::NotAllocated);
        }
        let allocated = (st & ST_ORDER) as usize;
        if allocated != order {
            return Err(FreeError::WrongOrder { allocated });
        }
        self.free_frames += 1 << order;
        self.release(idx, order);
        Ok(())
    }

    /// Merge the block with free buddies and put it on a free list.
    fn release(&mut self, mut idx: usize, mut order: usize) {
        self.set(idx, ST_NONE);
        while order < MAX_ORDER {
            let buddy = idx ^ (1 << order);
            if buddy >= self.frames || self.st(buddy) != ST_FREE | order as u8 {
                break;
            }
            self.unlink(buddy, order);
            self.set(buddy, ST_NONE);
            idx = idx.min(buddy);
            order += 1;
        }
        self.push(idx, order);
    }

    // ── state + intrusive list helpers ──────────────────────────────────────

    #[inline]
    fn st(&self, idx: usize) -> u8 {
        debug_assert!(idx < self.frames);
        unsafe { *self.state.add(idx) }
    }
    #[inline]
    fn set(&mut self, idx: usize, v: u8) {
        debug_assert!(idx < self.frames);
        unsafe { *self.state.add(idx) = v }
    }
    #[inline]
    fn link(&self, idx: usize) -> *mut Link {
        self.mem.frame_ptr(idx) as *mut Link
    }

    fn push(&mut self, idx: usize, order: usize) {
        let head = self.heads[order];
        unsafe {
            let l = self.link(idx);
            (*l).next = head;
            (*l).prev = NIL;
            if head != NIL {
                (*self.link(head)).prev = idx;
            }
        }
        self.heads[order] = idx;
        self.counts[order] += 1;
        self.set(idx, ST_FREE | order as u8);
    }

    fn unlink(&mut self, idx: usize, order: usize) {
        unsafe {
            let l = self.link(idx);
            let (next, prev) = ((*l).next, (*l).prev);
            if prev != NIL {
                (*self.link(prev)).next = next;
            } else {
                self.heads[order] = next;
            }
            if next != NIL {
                (*self.link(next)).prev = prev;
            }
        }
        self.counts[order] -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) struct Arena {
        base: *mut u8,
        _mem: Vec<u8>,
    }
    impl Arena {
        pub(crate) fn new(frames: usize) -> Self {
            let mut mem = vec![0u8; (frames + 1) * 4096];
            let base = ((mem.as_mut_ptr() as usize + 4095) & !4095) as *mut u8;
            Self { base, _mem: mem }
        }
    }
    impl FrameMemory for &Arena {
        fn frame_ptr(&self, idx: usize) -> *mut u8 {
            unsafe { self.base.add(idx * 4096) }
        }
    }

    fn make(arena: &Arena, frames: usize) -> (Buddy<&Arena>, Vec<u8>) {
        let mut state = vec![0u8; frames];
        let b = unsafe { Buddy::new(arena, state.as_mut_ptr(), frames) };
        (b, state)
    }

    #[test]
    fn full_range_coalesces_to_max_blocks() {
        let arena = Arena::new(4096);
        let (mut b, _s) = make(&arena, 4096);
        b.add_range(0, 4096);
        assert_eq!(b.free_frames(), 4096);
        assert_eq!(b.free_blocks()[MAX_ORDER], 4);
    }

    #[test]
    fn alloc_free_roundtrip_restores_everything() {
        let arena = Arena::new(2048);
        let (mut b, _s) = make(&arena, 2048);
        b.add_range(3, 2000); // unaligned edges
        let before = b.free_frames();
        let mut got = Vec::new();
        for o in [0, 3, 1, 5, 0, 2, 7, 0, 4] {
            let i = b.alloc(o).unwrap();
            assert_eq!(i % (1 << o), 0, "block must be naturally aligned");
            got.push((i, o));
        }
        for &(i, o) in got.iter().rev() {
            b.free(i, o).unwrap();
        }
        assert_eq!(b.free_frames(), before);
        // Everything must have coalesced back: allocating the whole range
        // frame by frame must succeed exactly `before` times.
        let mut n = 0;
        while b.alloc(0).is_some() {
            n += 1;
        }
        assert_eq!(n, before);
    }

    #[test]
    fn blocks_never_overlap() {
        let arena = Arena::new(1024);
        let (mut b, _s) = make(&arena, 1024);
        b.add_range(0, 1024);
        let mut owner = vec![usize::MAX; 1024];
        let mut live = Vec::new();
        let mut seed = 12345u64;
        for step in 0..20000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let r = (seed >> 33) as usize;
            if r % 3 != 0 || live.is_empty() {
                let o = r % 6;
                if let Some(i) = b.alloc(o) {
                    for f in i..i + (1 << o) {
                        assert_eq!(owner[f], usize::MAX, "overlap at step {step}");
                        owner[f] = step;
                    }
                    live.push((i, o));
                }
            } else {
                let (i, o) = live.swap_remove(r % live.len());
                for f in i..i + (1 << o) {
                    owner[f] = usize::MAX;
                }
                b.free(i, o).unwrap();
            }
        }
        let used: usize = live.iter().map(|&(_, o)| 1 << o).sum();
        assert_eq!(b.free_frames() + used, 1024);
    }

    #[test]
    fn double_free_and_wrong_order_are_rejected() {
        let arena = Arena::new(64);
        let (mut b, _s) = make(&arena, 64);
        b.add_range(0, 64);
        let i = b.alloc(2).unwrap();
        assert_eq!(b.free(i, 1), Err(FreeError::WrongOrder { allocated: 2 }));
        assert_eq!(b.free(i, 2), Ok(()));
        assert_eq!(b.free(i, 2), Err(FreeError::NotAllocated));
        assert_eq!(b.free(1000, 0), Err(FreeError::OutOfRange));
    }

    #[test]
    fn reserved_frames_are_never_handed_out() {
        let arena = Arena::new(256);
        let (mut b, _s) = make(&arena, 256);
        b.add_range(0, 256);
        assert!(b.reserve_range(10, 20));
        assert_eq!(b.free_frames(), 246);
        let mut seen = Vec::new();
        while let Some(i) = b.alloc(0) {
            seen.push(i);
        }
        assert_eq!(seen.len(), 246);
        assert!(seen.iter().all(|&i| !(10..20).contains(&i)));
        // Allocated frames cannot be reserved.
        assert!(!b.reserve_range(0, 1));
    }
}
