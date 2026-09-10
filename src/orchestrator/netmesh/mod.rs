//! Network Mesh — Built-in Container Networking
//!
//! FastROS replaces Cilium / Calico with a kernel-native network mesh.
//! Every container gets a virtual network interface.
//! The mesh routes packets between containers across nodes.
//!
//! Architecture:
//!   container veth → bridge → VXLAN tunnel → remote node → container veth
//!
//! Features:
//!   - Container-to-container networking (same node and cross-node)
//!   - Load balancing via virtual IPs (ties into discovery/)
//!   - Network policies (deny/allow rules per namespace)
//!   - Encrypted tunnels (optional, ChaCha20-Poly1305)

pub mod policy;
pub mod veth;
pub mod vxlan;

pub fn init() {
    // TODO: create bridge interface
    // TODO: allocate container IP pool (e.g., 10.244.0.0/16)
    // TODO: set up VXLAN for cross-node traffic
}

/// Allocate a veth pair for a new container.
/// Returns (container_ip, host_veth_idx).
pub fn alloc_veth(_container_id: &[u8; 16]) -> Option<(u32, usize)> {
    // TODO: pick next IP from pool
    // TODO: create veth pair in kernel
    // TODO: move one end into container net namespace
    None
}

/// Free the veth pair when a container is deleted.
pub fn free_veth(_host_veth_idx: usize) {
    // TODO: delete veth pair, return IP to pool
}
