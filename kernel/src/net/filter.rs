//! Packet filter hook points (the rule engine lives in `crate::firewall`).

/// Inbound Ethernet frame from the NIC: may it reach the stack?
#[inline]
pub fn allow_in(frame: &[u8]) -> bool {
    crate::firewall::check(crate::firewall::Dir::In, frame)
}

/// Outbound frame towards the NIC.
#[inline]
pub fn allow_out(frame: &[u8]) -> bool {
    crate::firewall::check(crate::firewall::Dir::Out, frame)
}
