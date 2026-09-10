//! Service Discovery
//!
//! FastROS has a built-in service registry — no external DNS or etcd needed.
//! Services register themselves with a name and get a virtual IP.
//! Clients look up services by name and get routed to a healthy instance.
//!
//! Design:
//!   - Flat namespace: "web", "db", "cache"
//!   - Virtual IPs in 10.96.0.0/12 range (same as Kubernetes)
//!   - Round-robin load balancing across healthy instances
//!   - Integrated with netmesh for packet routing

/// A registered service endpoint.
pub struct ServiceEndpoint {
    pub name:       [u8; 64],
    pub virtual_ip: u32,      // IPv4 in host byte order
    pub port:       u16,
    pub instances:  [ServiceInstance; 16],
    pub instance_count: usize,
}

pub struct ServiceInstance {
    pub container_ip: u32,
    pub port:         u16,
    pub healthy:      bool,
}

pub fn init() {
    // TODO: allocate virtual IP pool
    // TODO: start discovery heartbeat
}

/// Register a container as an instance of a named service.
pub fn register(_name: &[u8], _container_ip: u32, _port: u16) {
    // TODO: allocate virtual IP if first instance
    // TODO: add to instance list
    // TODO: notify netmesh to set up routing
}

/// Look up the virtual IP for a service name.
pub fn lookup(_name: &[u8]) -> Option<u32> {
    // TODO: search service table
    None
}
