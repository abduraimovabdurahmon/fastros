//! Virtual Memory Manager (VMM)
//!
//! Manages virtual address spaces for the kernel and each process.
//! Sits on top of PMM (allocates frames) and hal::memory (maps pages).

pub mod address_space;

pub fn init() {
    // TODO: Create kernel address space.
    // TODO: Set up higher-half kernel mappings.
}
