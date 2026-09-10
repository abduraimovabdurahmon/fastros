//! ICMP — Internet Control Message Protocol (RFC 792).
//!
//! Handles echo request/reply (ping), destination-unreachable,
//! time-exceeded, and parameter-problem messages.
//!
//! Linux equivalent: net/ipv4/icmp.c  include/linux/icmp.h

use super::checksum;

// ── Type codes (icmp_type) ────────────────────────────────────────────────────

pub const ICMP_ECHO_REPLY:         u8 = 0;
pub const ICMP_DEST_UNREACH:       u8 = 3;
pub const ICMP_TIME_EXCEEDED:      u8 = 11;
pub const ICMP_PARAM_PROBLEM:      u8 = 12;
pub const ICMP_ECHO_REQUEST:       u8 = 8;

// Destination unreachable codes
pub const ICMP_NET_UNREACH:        u8 = 0;
pub const ICMP_HOST_UNREACH:       u8 = 1;
pub const ICMP_PORT_UNREACH:       u8 = 3;

// Time exceeded codes
pub const ICMP_TTL_EXCEEDED:       u8 = 0;  // TTL in transit
pub const ICMP_FRAG_TIME_EXCEEDED: u8 = 1;  // fragment reassembly

pub const ICMP_HLEN: usize = 8;

// ── Parsed header ─────────────────────────────────────────────────────────────

pub struct IcmpHdr {
    pub type_:    u8,
    pub code:     u8,
    pub checksum: u16,
    /// For echo req/reply: identifier; for others: depends on type
    pub rest_hi:  u16,
    /// For echo req/reply: sequence number; for others: depends on type
    pub rest_lo:  u16,
}

impl IcmpHdr {
    pub fn id(&self)  -> u16 { self.rest_hi }
    pub fn seq(&self) -> u16 { self.rest_lo }
}

/// Parse an ICMP header.
pub fn parse(buf: &[u8]) -> Option<(IcmpHdr, &[u8])> {
    if buf.len() < ICMP_HLEN { return None; }
    let hdr = IcmpHdr {
        type_:    buf[0],
        code:     buf[1],
        checksum: u16::from_be_bytes([buf[2], buf[3]]),
        rest_hi:  u16::from_be_bytes([buf[4], buf[5]]),
        rest_lo:  u16::from_be_bytes([buf[6], buf[7]]),
    };
    Some((hdr, &buf[ICMP_HLEN..]))
}

// ── Packet building ───────────────────────────────────────────────────────────

/// Build an ICMP echo request into `buf`.
/// Returns bytes written (ICMP_HLEN + payload.len()).
pub fn build_echo_request(buf: &mut [u8], id: u16, seq: u16, payload: &[u8]) -> usize {
    build_msg(buf, ICMP_ECHO_REQUEST, 0, id, seq, payload)
}

/// Build an ICMP echo reply into `buf`.
pub fn build_echo_reply(buf: &mut [u8], id: u16, seq: u16, payload: &[u8]) -> usize {
    build_msg(buf, ICMP_ECHO_REPLY, 0, id, seq, payload)
}

/// Build an ICMP destination-unreachable message.
/// `orig_hdr` is the IP header + first 8 bytes of the offending datagram.
pub fn build_dest_unreach(buf: &mut [u8], code: u8, orig_hdr: &[u8]) -> usize {
    build_msg(buf, ICMP_DEST_UNREACH, code, 0, 0, orig_hdr)
}

/// Build an ICMP time-exceeded message.
pub fn build_time_exceeded(buf: &mut [u8], code: u8, orig_hdr: &[u8]) -> usize {
    build_msg(buf, ICMP_TIME_EXCEEDED, code, 0, 0, orig_hdr)
}

/// Generic ICMP message builder.
fn build_msg(
    buf:     &mut [u8],
    type_:   u8,
    code:    u8,
    rest_hi: u16,
    rest_lo: u16,
    payload: &[u8],
) -> usize {
    let total = ICMP_HLEN + payload.len();
    if buf.len() < total { return 0; }
    buf[0] = type_;
    buf[1] = code;
    buf[2..4].copy_from_slice(&[0, 0]);                    // checksum = 0
    buf[4..6].copy_from_slice(&rest_hi.to_be_bytes());
    buf[6..8].copy_from_slice(&rest_lo.to_be_bytes());
    buf[ICMP_HLEN..total].copy_from_slice(&payload[..payload.len()]);
    // Compute checksum over entire ICMP message
    let ck = checksum::compute(&buf[..total]);
    buf[2..4].copy_from_slice(&ck.to_be_bytes());
    total
}

/// Verify ICMP checksum. Returns true if valid.
pub fn verify_checksum(buf: &[u8]) -> bool {
    checksum::compute(buf) == 0
}
