//! Network Namespace
//!
//! Each network namespace has its own:
//!   - network interfaces (lo, veth pairs)
//!   - routing table
//!   - firewall rules
//!   - sockets
//!
//! Container networking is built on top of veth pairs connecting
//! container net-ns to the host net-ns (or bridge).

use super::{Namespace, NsId};

pub struct NetNamespace {
    id: NsId,
    // TODO: list of virtual network interfaces
    // TODO: routing table
}

impl NetNamespace {
    pub const fn root() -> Self {
        Self { id: 0 }
    }

    pub fn new(id: NsId) -> Self {
        Self { id }
    }
}

impl Namespace for NetNamespace {
    fn id(&self) -> NsId { self.id }
}
