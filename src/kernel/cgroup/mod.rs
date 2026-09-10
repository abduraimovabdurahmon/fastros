//! Control Groups (cgroups) — resource accounting and limiting
//!
//! Cgroups limit what a container can USE:
//!   CPU   — max CPU time per period
//!   Memory — max RAM + swap
//!
//! Every container gets a cgroup. The scheduler enforces limits.
//!
//! CAN IMPORT:   hal/, libs/
//! CANNOT IMPORT: arch/, drivers/, fs/, userspace/

pub mod cpu;
pub mod memory;

/// Unique cgroup identifier.
pub type CgroupId = u64;

/// Combined resource limits for one container / process group.
pub struct Cgroup {
    pub id:     CgroupId,
    pub cpu:    cpu::CpuCgroup,
    pub memory: memory::MemoryCgroup,
}

impl Cgroup {
    /// Unlimited cgroup (used by the kernel itself).
    pub const fn unlimited(id: CgroupId) -> Self {
        Self {
            id,
            cpu:    cpu::CpuCgroup::unlimited(),
            memory: memory::MemoryCgroup::unlimited(),
        }
    }
}
