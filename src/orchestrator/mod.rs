//! LAYER 7 — Built-in Orchestration Layer
//!
//! FastROS orchestration — no Kubernetes, no external scheduler.
//! The kernel itself schedules containers across nodes, monitors health,
//! and provides service discovery.
//!
//! Subsystems:
//!   agent/     — this node's agent (heartbeat, state sync)
//!   scheduler/ — place containers on nodes
//!   health/    — liveness/readiness checks, self-healing
//!   discovery/ — service registry (replaces DNS/etcd)
//!   netmesh/   — container-to-container networking (replaces Cilium)
//!
//! CAN IMPORT:   container/, kernel/, drivers/, hal/, libs/
//! CANNOT IMPORT: userspace/

pub mod agent;
pub mod discovery;
pub mod health;
pub mod netmesh;
pub mod scheduler;

/// Initialize the orchestration layer.
pub fn init() {
    agent::init();
    discovery::init();
    netmesh::init();
}
