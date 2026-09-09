//! Kernel memory management
//!
//! Three-layer system:
//!   pmm  — physical frames (4 KB units)
//!   vmm  — virtual address spaces, page mappings
//!   heap — dynamic kernel allocations (kmalloc equivalent)

pub mod heap;
pub mod pmm;
pub mod vmm;
