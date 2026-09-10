//! Virtual Ethernet (veth) pairs
//!
//! A veth pair is two virtual network interfaces connected back-to-back.
//! Packets sent to one end come out the other.
//! Used to connect a container's net namespace to the host bridge.

pub struct VethPair {
    pub host_idx:      usize,
    pub container_idx: usize,
    pub container_ip:  u32,
}

impl VethPair {
    pub fn create(_host_name: &[u8; 16], _container_name: &[u8; 16]) -> Option<Self> {
        // TODO: allocate two virtual NICs in drivers/net/veth
        // TODO: wire them together at the driver level
        None
    }

    pub fn destroy(self) {
        // TODO: free both virtual NICs
    }
}
