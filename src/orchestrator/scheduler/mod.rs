//! Cluster Scheduler — Container Placement
//!
//! Decides which node should run each container based on:
//!   - resource requirements (CPU, memory)
//!   - affinity / anti-affinity rules
//!   - node health (only schedule on healthy nodes)
//!
//! Algorithm: Bin-packing (best-fit decreasing) for resource efficiency.
//! Pluggable: implement SchedulerPolicy for custom strategies.

use crate::container::runtime::ContainerId;

/// Resource requirements for a container.
pub struct ResourceRequirements {
    pub cpu_millicores: u32,
    pub mem_bytes:      u64,
}

/// A placement decision: run container on node.
pub struct Placement {
    pub container_id: ContainerId,
    pub node_id:      u32,
}

pub trait SchedulerPolicy {
    /// Given container requirements, return the best node ID.
    fn pick_node(&self, req: &ResourceRequirements) -> Option<u32>;
}

/// Default bin-packing scheduler.
pub struct BinPackScheduler;

impl SchedulerPolicy for BinPackScheduler {
    fn pick_node(&self, _req: &ResourceRequirements) -> Option<u32> {
        // TODO: query agent::collect_resources() for all nodes
        // TODO: pick node with most free resources that can fit the container
        None
    }
}
