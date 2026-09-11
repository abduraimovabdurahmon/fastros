//! Size-class slab allocator for small kernel objects (≤ 2 KiB).
//!
//! Each size class carves naturally aligned blocks of `2^order` pages
//! ("slabs") obtained from a [`PageProvider`] into equal objects. A slab
//! starts with a [`SlabHeader`]; the header of any object is found by
//! rounding its address down to the slab size, so `free` needs no lookup.
//!
//! Hardening (the same ideas as Linux SLUB's `FREELIST_HARDENED` +
//! `init_on_free`, but always on):
//! * free-list pointers are stored XOR-ed with a per-allocator secret and the
//!   address of the slot holding them, so a heap overflow cannot forge a
//!   usable pointer;
//! * every object is zeroed when freed, so freed data never leaks and a new
//!   allocation is always zero-filled;
//! * the header magic, the class, the slot alignment and a double-free check
//!   are verified on every free; a violation is reported as an error that the
//!   kernel turns into a panic instead of corrupting memory.

pub const PAGE_SIZE: usize = 4096;
pub const SIZE_CLASSES: [usize; 8] = [16, 32, 64, 128, 256, 512, 1024, 2048];
/// Pages per slab, as a buddy order, for each class.
const SLAB_ORDER: [usize; 8] = [0, 0, 0, 0, 0, 1, 2, 2];
const HEADER_SIZE: usize = 64;
const MAGIC: usize = 0x5AB5_1AB5_F457_2005;
/// Largest request served by the slab layer.
pub const MAX_SLAB_SIZE: usize = 2048;

/// Source of page blocks for new slabs.
pub trait PageProvider {
    /// A naturally aligned block of `2^order` pages, or `None` when out of memory.
    fn alloc_pages(&mut self, order: usize) -> Option<usize>;
    fn free_pages(&mut self, addr: usize, order: usize);
}

#[repr(C)]
struct SlabHeader {
    magic: usize,
    class: usize,
    in_use: usize,
    capacity: usize,
    free: usize, // encoded pointer to first free object (see `encode`)
    next: usize, // partial list links (slab addresses, 0 = none)
    prev: usize,
    on_partial: usize,
}

const _: () = assert!(core::mem::size_of::<SlabHeader>() <= HEADER_SIZE);
/// Offset of `SlabHeader::free`: the slot address used to encode the list head.
const FREE_FIELD: usize = core::mem::offset_of!(SlabHeader, free);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabError {
    /// The pointer is not inside a slab of the class its size maps to.
    NotASlabObject,
    /// The pointer is inside a slab but not at an object boundary.
    Misaligned,
    /// The object is already on the free list.
    DoubleFree,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ClassStats {
    pub size: usize,
    pub slabs: usize,
    pub objects_in_use: usize,
    pub capacity: usize,
}

pub struct Slab<P: PageProvider> {
    pages: P,
    secret: usize,
    partial: [usize; 8],
    empty: [usize; 8],
    slabs: [usize; 8],
    in_use: [usize; 8],
}

/// Index of the smallest class that fits `size` bytes aligned to `align`.
pub fn class_for(size: usize, align: usize) -> Option<usize> {
    let need = size.max(align).max(1);
    SIZE_CLASSES.iter().position(|&c| c >= need)
}

fn slab_bytes(class: usize) -> usize {
    PAGE_SIZE << SLAB_ORDER[class]
}

fn first_offset(class: usize) -> usize {
    SIZE_CLASSES[class].max(HEADER_SIZE)
}

fn capacity(class: usize) -> usize {
    (slab_bytes(class) - first_offset(class)) / SIZE_CLASSES[class]
}

impl<P: PageProvider> Slab<P> {
    pub const fn new(pages: P, secret: usize) -> Self {
        Self {
            pages,
            secret: secret | 1,
            partial: [0; 8],
            empty: [0; 8],
            slabs: [0; 8],
            in_use: [0; 8],
        }
    }

    pub fn pages_mut(&mut self) -> &mut P {
        &mut self.pages
    }

    pub fn stats(&self) -> [ClassStats; 8] {
        let mut out = [ClassStats::default(); 8];
        for c in 0..8 {
            out[c] = ClassStats {
                size: SIZE_CLASSES[c],
                slabs: self.slabs[c],
                objects_in_use: self.in_use[c],
                capacity: self.slabs[c] * capacity(c),
            };
        }
        out
    }

    /// Bytes of page memory currently held by slabs.
    pub fn footprint(&self) -> usize {
        (0..8).map(|c| self.slabs[c] * slab_bytes(c)).sum()
    }

    /// Encode (and, being an XOR, also decode) a free-list pointer stored at `slot`.
    #[inline]
    fn encode(&self, ptr: usize, slot: usize) -> usize {
        ptr ^ self.secret ^ slot.swap_bytes()
    }

    /// Allocate a zero-filled object of class `class`.
    pub fn alloc(&mut self, class: usize) -> Option<*mut u8> {
        if self.partial[class] == 0 {
            self.grow(class)?;
        }
        let slab = self.partial[class];
        let h = slab as *mut SlabHeader;
        let head_slot = slab + FREE_FIELD;
        unsafe {
            let obj = self.encode((*h).free, head_slot);
            debug_assert!(obj != 0, "slab on partial list has no free object");
            let next = self.encode(*(obj as *const usize), obj);
            (*h).free = self.encode(next, head_slot);
            *(obj as *mut usize) = 0;
            if (*h).in_use == 0 {
                self.empty[class] -= 1;
            }
            (*h).in_use += 1;
            self.in_use[class] += 1;
            if next == 0 {
                self.unlink_partial(class, slab);
            }
            Some(obj as *mut u8)
        }
    }

    /// Return an object to its slab. `class` must be the class it was allocated with.
    ///
    /// # Safety
    /// `ptr` must not be used after this call.
    pub unsafe fn free(&mut self, ptr: *mut u8, class: usize) -> Result<(), SlabError> {
        let obj = ptr as usize;
        let size = SIZE_CLASSES[class];
        let slab = obj & !(slab_bytes(class) - 1);
        let h = slab as *mut SlabHeader;
        if slab == 0 || (*h).magic != MAGIC || (*h).class != class {
            return Err(SlabError::NotASlabObject);
        }
        let off = obj - slab;
        if off < first_offset(class) || (off - first_offset(class)) % size != 0 {
            return Err(SlabError::Misaligned);
        }
        if self.looks_free(slab, obj, size) {
            return Err(SlabError::DoubleFree);
        }
        core::ptr::write_bytes(ptr, 0, size);
        let head = self.encode((*h).free, slab + FREE_FIELD);
        *(obj as *mut usize) = self.encode(head, obj);
        (*h).free = self.encode(obj, slab + FREE_FIELD);
        (*h).in_use -= 1;
        self.in_use[class] -= 1;
        if (*h).on_partial == 0 {
            self.link_partial(class, slab);
        }
        if (*h).in_use == 0 {
            if self.empty[class] >= 1 {
                // Keep one empty slab per class to absorb churn; give back the rest.
                self.unlink_partial(class, slab);
                (*h).magic = 0;
                self.slabs[class] -= 1;
                self.pages.free_pages(slab, SLAB_ORDER[class]);
            } else {
                self.empty[class] += 1;
            }
        }
        Ok(())
    }

    /// A freed object is all zero except its first word, which decodes to
    /// another object of the same slab or to the end-of-list marker.
    unsafe fn looks_free(&self, slab: usize, obj: usize, size: usize) -> bool {
        let words = obj as *const usize;
        let next = *words ^ self.secret ^ obj.swap_bytes();
        let plausible = next == 0
            || (next & !(slab_bytes((*(slab as *const SlabHeader)).class) - 1) == slab
                && (next - slab) >= HEADER_SIZE.min(size)
                && (next - slab) % size == 0);
        if !plausible {
            return false;
        }
        (1..size / 8).all(|i| *words.add(i) == 0)
    }

    fn grow(&mut self, class: usize) -> Option<()> {
        let order = SLAB_ORDER[class];
        let slab = self.pages.alloc_pages(order)?;
        let size = SIZE_CLASSES[class];
        let cap = capacity(class);
        unsafe {
            core::ptr::write_bytes(slab as *mut u8, 0, slab_bytes(class));
            let h = slab as *mut SlabHeader;
            (*h).magic = MAGIC;
            (*h).class = class;
            (*h).capacity = cap;
            // Thread the free list from the last object to the first so the
            // first allocation returns the lowest address.
            let mut next = 0usize;
            for i in (0..cap).rev() {
                let obj = slab + first_offset(class) + i * size;
                *(obj as *mut usize) = self.encode(next, obj);
                next = obj;
            }
            (*h).free = self.encode(next, slab + FREE_FIELD);
        }
        self.slabs[class] += 1;
        self.empty[class] += 1;
        self.link_partial(class, slab);
        Some(())
    }

    fn link_partial(&mut self, class: usize, slab: usize) {
        let h = slab as *mut SlabHeader;
        let head = self.partial[class];
        unsafe {
            (*h).next = head;
            (*h).prev = 0;
            (*h).on_partial = 1;
            if head != 0 {
                (*(head as *mut SlabHeader)).prev = slab;
            }
        }
        self.partial[class] = slab;
    }

    fn unlink_partial(&mut self, class: usize, slab: usize) {
        let h = slab as *mut SlabHeader;
        unsafe {
            let (next, prev) = ((*h).next, (*h).prev);
            if prev != 0 {
                (*(prev as *mut SlabHeader)).next = next;
            } else {
                self.partial[class] = next;
            }
            if next != 0 {
                (*(next as *mut SlabHeader)).prev = prev;
            }
            (*h).on_partial = 0;
            (*h).next = 0;
            (*h).prev = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buddy::{Buddy, FrameMemory};

    struct Arena {
        base: usize,
        _mem: Vec<u8>,
    }
    impl FrameMemory for &'static Arena {
        fn frame_ptr(&self, idx: usize) -> *mut u8 {
            (self.base + idx * PAGE_SIZE) as *mut u8
        }
    }
    struct Pages {
        buddy: Buddy<&'static Arena>,
        base: usize,
        live_blocks: usize,
    }
    impl PageProvider for Pages {
        fn alloc_pages(&mut self, order: usize) -> Option<usize> {
            let i = self.buddy.alloc(order)?;
            self.live_blocks += 1;
            Some(self.base + i * PAGE_SIZE)
        }
        fn free_pages(&mut self, addr: usize, order: usize) {
            self.live_blocks -= 1;
            self.buddy.free((addr - self.base) / PAGE_SIZE, order).unwrap();
        }
    }

    fn make(frames: usize) -> Slab<Pages> {
        // 2^MAX_ORDER alignment keeps buddy blocks naturally aligned in memory.
        let align = PAGE_SIZE << crate::buddy::MAX_ORDER;
        let mut mem = vec![0u8; frames * PAGE_SIZE + align];
        let base = (mem.as_mut_ptr() as usize + align - 1) & !(align - 1);
        let arena: &'static Arena = Box::leak(Box::new(Arena { base, _mem: mem }));
        let state: &'static mut [u8] = Box::leak(vec![0u8; frames].into_boxed_slice());
        let mut buddy = unsafe { Buddy::new(arena, state.as_mut_ptr(), frames) };
        buddy.add_range(0, frames);
        Slab::new(Pages { buddy, base, live_blocks: 0 }, 0xDEAD_BEEF_1234_5678)
    }

    #[test]
    fn class_selection() {
        assert_eq!(class_for(1, 1), Some(0));
        assert_eq!(class_for(16, 8), Some(0));
        assert_eq!(class_for(17, 8), Some(1));
        assert_eq!(class_for(8, 64), Some(2));
        assert_eq!(class_for(2048, 8), Some(7));
        assert_eq!(class_for(2049, 8), None);
    }

    #[test]
    fn objects_are_distinct_aligned_and_zeroed() {
        let mut s = make(4096);
        for class in 0..8 {
            let size = SIZE_CLASSES[class];
            let mut ptrs = Vec::new();
            for i in 0..500 {
                let p = s.alloc(class).unwrap();
                assert_eq!(p as usize % size, 0, "class {class} alignment");
                let bytes = unsafe { core::slice::from_raw_parts_mut(p, size) };
                assert!(bytes.iter().all(|&b| b == 0), "class {class} object {i} not zeroed");
                bytes.fill(0xA5);
                ptrs.push(p as usize);
            }
            let mut sorted = ptrs.clone();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), ptrs.len());
            for w in sorted.windows(2) {
                assert!(w[1] - w[0] >= size, "overlap in class {class}");
            }
            for p in ptrs {
                unsafe { s.free(p as *mut u8, class).unwrap() };
            }
        }
        // All but one cached empty slab per class went back to the page allocator.
        assert!(s.pages_mut().live_blocks <= 8);
    }

    #[test]
    fn double_free_is_detected() {
        let mut s = make(256);
        let a = s.alloc(2).unwrap();
        let _b = s.alloc(2).unwrap();
        unsafe {
            s.free(a, 2).unwrap();
            assert_eq!(s.free(a, 2), Err(SlabError::DoubleFree));
        }
    }

    #[test]
    fn wrong_pointer_is_detected() {
        let mut s = make(256);
        let a = s.alloc(3).unwrap();
        unsafe {
            assert_eq!(s.free(a.add(8), 3), Err(SlabError::Misaligned));
            assert_eq!(s.free(a, 5), Err(SlabError::NotASlabObject));
            s.free(a, 3).unwrap();
        }
    }

    #[test]
    fn churn_matches_model() {
        let mut s = make(8192);
        let mut live: Vec<(usize, usize, u8)> = Vec::new();
        let mut seed = 99u64;
        for step in 0..50_000u32 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let r = (seed >> 33) as usize;
            if r % 5 < 3 || live.is_empty() {
                let class = r % 8;
                let p = s.alloc(class).unwrap() as usize;
                let tag = (step % 251) as u8 + 1;
                unsafe { core::ptr::write_bytes(p as *mut u8, tag, SIZE_CLASSES[class]) };
                live.push((p, class, tag));
            } else {
                let (p, class, tag) = live.swap_remove(r % live.len());
                let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, SIZE_CLASSES[class]) };
                assert!(bytes.iter().all(|&b| b == tag), "object corrupted");
                unsafe { s.free(p as *mut u8, class).unwrap() };
            }
        }
        let st = s.stats();
        for c in 0..8 {
            assert_eq!(st[c].objects_in_use, live.iter().filter(|l| l.1 == c).count());
        }
    }
}
