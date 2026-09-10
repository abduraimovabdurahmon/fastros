//! LAYER 2 — Core Kernel
//!
//! Architecture-independent kernel subsystems.
//! This layer knows NOTHING about x86_64 or any specific hardware.
//! All hardware access goes through hal/ traits.
//!
//! CAN IMPORT:   hal/, libs/
//! CANNOT IMPORT: arch/, drivers/, fs/, container/, orchestrator/, userspace/

pub mod cgroup;
pub mod log;
pub mod ipc;
pub mod memory;
pub mod namespace;
pub mod net;
pub mod process;
pub mod sync;
pub mod syscall;
pub mod users;
