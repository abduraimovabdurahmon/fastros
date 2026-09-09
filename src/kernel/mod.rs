//! LAYER 2 — Core Kernel
//!
//! Architecture-independent kernel subsystems.
//! This layer knows NOTHING about x86_64 or any specific hardware.
//! All hardware access goes through hal/ traits.
//!
//! CAN IMPORT:   hal/, libs/
//! CANNOT IMPORT: arch/, drivers/, fs/, userspace/

pub mod ipc;
pub mod memory;
pub mod process;
pub mod sync;
pub mod syscall;
