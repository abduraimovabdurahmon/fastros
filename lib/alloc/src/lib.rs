//! Memory allocator algorithms for the FastROS kernel.
//!
//! These are pure data-structure implementations with no hardware access, so
//! they are unit-tested on the host (`cargo test -p fastros-alloc`) and used
//! unchanged by the kernel:
//!
//! * [`buddy::Buddy`] — power-of-two physical frame allocator with coalescing,
//!   double-free and wrong-order detection.
//! * [`slab::Slab`]   — size-class object allocator on top of page blocks,
//!   with hardened (address-bound, XOR-encoded) free lists and zero-on-free.

#![cfg_attr(not(test), no_std)]

pub mod buddy;
pub mod slab;
