//! LAYER 1 — Hardware Abstraction Layer (HAL)
//!
//! Defines traits that abstract over hardware differences.
//! All hardware access above this layer goes through these traits.
//!
//! CAN IMPORT:   arch/
//! CANNOT IMPORT: kernel/, drivers/, fs/, userspace/

pub mod cpu;
pub mod interrupt;
pub mod io;
pub mod memory;

pub use cpu::CpuInterface;
pub use interrupt::InterruptController;
pub use io::IoInterface;
pub use memory::MemoryInterface;
