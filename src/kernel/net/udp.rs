//! UDP — User Datagram Protocol (RFC 768).
//!
//! Stateless datagram delivery.  Each socket gets an RX ring buffer.
//! UDP sockets are looked up by (local_ip, local_port) on receive.
//!
//! Linux equivalent: net/ipv4/udp.c  include/linux/udp.h

use super::checksum;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const UDP_HLEN: usize = 8;

// Well-known ports
pub const PORT_DNS:  u16 = 53;
pub const PORT_DHCP_SERVER: u16 = 67;
pub const PORT_DHCP_CLIENT: u16 = 68;

// ── Parsed header ─────────────────────────────────────────────────────────────

pub struct UdpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length:   u16,   // header + payload
    pub checksum: u16,
}

/// Parse a UDP header from raw bytes.
pub fn parse(buf: &[u8]) -> Option<(UdpHdr, &[u8])> {
    if buf.len() < UDP_HLEN { return None; }
    let hdr = UdpHdr {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        length:   u16::from_be_bytes([buf[4], buf[5]]),
        checksum: u16::from_be_bytes([buf[6], buf[7]]),
    };
    let payload_len = (hdr.length as usize).saturating_sub(UDP_HLEN);
    let payload_len = payload_len.min(buf.len() - UDP_HLEN);
    Some((hdr, &buf[UDP_HLEN..UDP_HLEN + payload_len]))
}

// ── Packet building ───────────────────────────────────────────────────────────

/// Build a UDP datagram into `buf`.
/// `pseudo_acc` is the IP pseudo-header accumulator from ip::pseudo_header_acc().
/// Returns bytes written (UDP_HLEN + payload.len()), or 0 on error.
pub fn build(
    buf:        &mut [u8],
    src_port:   u16,
    dst_port:   u16,
    payload:    &[u8],
    pseudo_acc: u32,
) -> usize {
    let total = UDP_HLEN + payload.len();
    if buf.len() < total { return 0; }

    let length = total as u16;
    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..6].copy_from_slice(&length.to_be_bytes());
    buf[6..8].copy_from_slice(&[0, 0]);                // checksum placeholder
    buf[UDP_HLEN..total].copy_from_slice(payload);

    // UDP checksum = pseudo-header + UDP header + payload
    let acc = checksum::accumulate(&buf[..total], pseudo_acc);
    let ck  = checksum::fold(acc);
    // RFC 768: if computed checksum is 0, transmit 0xFFFF
    let ck = if ck == 0 { 0xFFFF } else { ck };
    buf[6..8].copy_from_slice(&ck.to_be_bytes());
    total
}

/// Verify UDP checksum. `pseudo_acc` must include length field.
/// Returns true if valid (or if received checksum is 0 = disabled).
pub fn verify_checksum(buf: &[u8], pseudo_acc: u32) -> bool {
    let recv_ck = u16::from_be_bytes([buf[6], buf[7]]);
    if recv_ck == 0 { return true; }  // sender disabled checksum
    let acc = checksum::accumulate(buf, pseudo_acc);
    checksum::fold(acc) == 0
}
