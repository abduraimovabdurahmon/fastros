//! Container Runtime — Lifecycle Management
//!
//! A Container is a kernel object that wraps:
//!   - a set of namespaces (pid, mnt, net, user)
//!   - a cgroup (cpu + memory limits)
//!   - one or more processes
//!   - an overlay root filesystem
//!
//! Lifecycle:
//!   Created → Running → Stopped → Deleted
//!                 ↑         |
//!                 └─────────┘  (restart)

use crate::kernel::namespace::NsSet;
use crate::kernel::cgroup::Cgroup;

/// Unique container ID (128-bit, random).
pub type ContainerId = [u8; 16];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Stopped,
    Deleted,
}

pub struct Container {
    pub id:       ContainerId,
    pub state:    ContainerState,
    pub ns:       NsSet,
    pub cgroup:   Cgroup,
    /// Index into the image table.
    pub image_idx: usize,
}

impl Container {
    /// Create a new container in Created state.
    pub fn create(id: ContainerId, image_idx: usize, cgroup_id: u64) -> Self {
        Self {
            id,
            state: ContainerState::Created,
            ns: NsSet::root(), // TODO: allocate fresh namespaces
            cgroup: Cgroup::unlimited(cgroup_id),
            image_idx,
        }
    }

    /// Start the container (spawn PID 1 inside the container's namespace).
    pub fn start(&mut self) {
        // TODO: mount overlay root FS
        // TODO: clone process into container namespaces
        // TODO: exec /init inside the container
        self.state = ContainerState::Running;
    }

    /// Stop the container (send SIGTERM to PID 1, then SIGKILL).
    pub fn stop(&mut self) {
        // TODO: send signal to container PID 1
        // TODO: wait for all processes to exit
        self.state = ContainerState::Stopped;
    }
}
