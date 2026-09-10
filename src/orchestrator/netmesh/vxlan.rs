//! VXLAN — Virtual Extensible LAN
//!
//! Encapsulates container ethernet frames in UDP packets
//! to tunnel them across nodes over the physical network.
//!
//! VXLAN frame: [Outer Ethernet][Outer IP][UDP][VXLAN Header][Inner Ethernet Frame]
//! Default port: 4789 (IANA assigned)

const VXLAN_PORT: u16 = 4789;

/// VXLAN Network Identifier — separates different overlay networks.
pub type Vni = u32;

pub struct VxlanTunnel {
    pub vni:        Vni,
    pub local_ip:   u32,
    pub remote_ip:  u32,
}

impl VxlanTunnel {
    pub fn new(vni: Vni, local_ip: u32, remote_ip: u32) -> Self {
        Self { vni, local_ip, remote_ip }
    }

    /// Encapsulate an inner ethernet frame for tunnel transmission.
    pub fn encapsulate(&self, _inner_frame: &[u8], _out: &mut [u8]) -> usize {
        // TODO: build outer Ethernet + IP + UDP + VXLAN headers
        0
    }

    /// Decapsulate a received VXLAN packet, returning the inner frame.
    pub fn decapsulate<'a>(&self, _packet: &'a [u8]) -> Option<&'a [u8]> {
        // TODO: validate VXLAN header, strip outer headers
        None
    }
}
