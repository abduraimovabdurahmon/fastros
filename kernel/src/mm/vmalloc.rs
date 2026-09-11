//! Virtually contiguous kernel memory backed by individual frames.
//!
//! Used for kernel stacks (with an unmapped guard page below each one) and
//! for allocations larger than the buddy allocator's biggest block. Every
//! allocation is followed by an unmapped gap page too, so linear overflows
//! off either end fault instead of silently hitting a neighbour.

use super::{frame, kspace, PAGE_SIZE, VMALLOC_END, VMALLOC_START};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicUsize, Ordering};

struct Space {
    /// Never-used address space starts here.
    next: usize,
    /// Returned ranges: start → length in pages (guards included).
    free: BTreeMap<usize, usize>,
    /// Live allocations: usable start → (reservation start, total pages, mapped pages).
    live: BTreeMap<usize, (usize, usize, usize)>,
}

static SPACE: SpinLock<Space> = SpinLock::new(Space { next: VMALLOC_START, free: BTreeMap::new(), live: BTreeMap::new() });
static MAPPED: AtomicUsize = AtomicUsize::new(0);

pub fn mapped_bytes() -> usize {
    MAPPED.load(Ordering::Relaxed) * PAGE_SIZE
}

/// Reserve `pages + 2` pages of address space (guard, data, guard).
fn reserve(total: usize) -> Option<usize> {
    let mut s = SPACE.lock();
    let hit = s.free.iter().find(|(_, &len)| len >= total).map(|(&a, &l)| (a, l));
    if let Some((start, len)) = hit {
        s.free.remove(&start);
        if len > total {
            s.free.insert(start + total * PAGE_SIZE, len - total);
        }
        return Some(start);
    }
    let start = s.next;
    let end = start.checked_add(total * PAGE_SIZE)?;
    if end > VMALLOC_END {
        return None;
    }
    s.next = end;
    Some(start)
}

fn release(start: usize, total: usize) {
    let mut s = SPACE.lock();
    // Coalesce with the following and preceding free ranges.
    let mut start = start;
    let mut total = total;
    if let Some(len) = s.free.remove(&(start + total * PAGE_SIZE)) {
        total += len;
    }
    let prev = s.free.range(..start).next_back().map(|(&a, &l)| (a, l));
    if let Some((a, l)) = prev {
        if a + l * PAGE_SIZE == start {
            s.free.remove(&a);
            start = a;
            total += l;
        }
    }
    if start + total * PAGE_SIZE == s.next {
        s.next = start;
    } else {
        s.free.insert(start, total);
    }
}

/// Map `pages` fresh zeroed frames; returns the first usable address.
pub fn alloc(pages: usize) -> Option<usize> {
    let total = pages.checked_add(2)?;
    let base = reserve(total)?;
    let data = base + PAGE_SIZE;
    for i in 0..pages {
        let ok = frame::alloc_zeroed(0).and_then(|p| kspace::map(data + i * PAGE_SIZE, p, true).ok());
        if ok.is_none() {
            unmap_range(data, i);
            release(base, total);
            return None;
        }
    }
    MAPPED.fetch_add(pages, Ordering::Relaxed);
    SPACE.lock().live.insert(data, (base, total, pages));
    Some(data)
}

fn unmap_range(data: usize, pages: usize) {
    for i in 0..pages {
        if let Some(p) = kspace::unmap(data + i * PAGE_SIZE) {
            frame::free(p, 0);
        }
    }
}

/// Free an allocation made by [`alloc`]. Unknown addresses are a kernel bug.
pub fn free(data: usize) {
    let entry = SPACE.lock().live.remove(&data);
    let (base, total, pages) = entry.unwrap_or_else(|| panic!("vmalloc::free of unknown address {data:#x}"));
    unmap_range(data, pages);
    MAPPED.fetch_sub(pages, Ordering::Relaxed);
    release(base, total);
}

pub fn contains(addr: usize) -> bool {
    (VMALLOC_START..VMALLOC_END).contains(&addr)
}

/// If `addr` is a guard page of a live allocation, the allocation's usable start.
pub fn guard_owner(addr: usize) -> Option<usize> {
    let s = SPACE.lock();
    s.live.iter().find_map(|(&data, &(base, total, _))| {
        let first_guard = base..base + PAGE_SIZE;
        let last_guard = base + (total - 1) * PAGE_SIZE..base + total * PAGE_SIZE;
        (first_guard.contains(&addr) || last_guard.contains(&addr)).then_some(data)
    })
}
