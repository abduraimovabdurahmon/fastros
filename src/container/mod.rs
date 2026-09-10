//! LAYER 6 — Built-in Container Runtime
//!
//! FastROS container runtime — no Docker, no Podman, no OCI.
//! Containers are first-class kernel objects, not userspace processes
//! wrapped with cgroups. The kernel manages their lifecycle directly.
//!
//! Subsystems:
//!   image/   — FastROS native image format (not OCI)
//!   runtime/ — container lifecycle (create, start, stop, delete)
//!   overlay/ — overlay filesystem for container root FS
//!
//! CAN IMPORT:   kernel/, fs/, drivers/, hal/, libs/
//! CANNOT IMPORT: orchestrator/, userspace/

pub mod image;
pub mod overlay;
pub mod runtime;

pub use runtime::{Container, ContainerState};

/// Initialize the container runtime subsystem.
pub fn init() {
    // TODO: scan image store
    // TODO: restore any containers that were running before reboot
}
