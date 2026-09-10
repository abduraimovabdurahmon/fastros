//! Node Agent
//!
//! Every FastROS node runs an agent that:
//!   - reports node resources (CPU, memory, disk) to the cluster
//!   - receives container placement decisions from the scheduler
//!   - enforces desired state (start/stop containers as instructed)
//!   - sends heartbeat to detect node failures

/// Node resource snapshot reported to the cluster.
pub struct NodeResources {
    pub cpu_cores:    u32,
    pub mem_total_kb: u64,
    pub mem_free_kb:  u64,
    pub disk_total_kb: u64,
    pub disk_free_kb:  u64,
}

pub fn init() {
    // TODO: enumerate hardware resources
    // TODO: register this node with the cluster leader
    // TODO: start heartbeat timer
}

/// Collect current node resource usage.
pub fn collect_resources() -> NodeResources {
    // TODO: query PMM for memory, query scheduler for CPU
    NodeResources {
        cpu_cores:     1,
        mem_total_kb:  0,
        mem_free_kb:   0,
        disk_total_kb: 0,
        disk_free_kb:  0,
    }
}
