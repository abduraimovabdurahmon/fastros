//! Kernel heap allocator
//!
//! Provides dynamic memory allocation for kernel data structures.
//! Strategy: slab allocator for small fixed-size objects,
//!            buddy allocator for large allocations.
//!
//! Once implemented, this enables use of alloc:: (Box, Vec, etc.)
//! by setting the global allocator via #[global_allocator].

pub fn init() {
    // TODO: Map a region of virtual memory for the heap.
    // TODO: Initialize slab/buddy allocator over that region.
}

// TODO: Implement GlobalAlloc for the heap allocator.
// TODO: Set #[global_allocator] once ready.
