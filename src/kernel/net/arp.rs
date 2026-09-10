//! ARP — Address Resolution Protocol (RFC 826).
//!
//! Maps IPv4 addresses to MAC addresses.
//! Maintains a fixed-size ARP cache (like Linux's arp_tbl neighbour cache).
//!
//! Linux equivalent: net/ipv4/arp.c  include/net/arp.h

use super::eth;

// ── Constants ────────────────────────────────────────────────────────────────

pub const ARP_HTYPE_ETHER: u16 = 1;
pub const ARP_PTYPE_IPV4:  u16 = 0x0800;
pub const ARP_HDR_LEN:     usize = 28;  // fixed for Ethernet/IPv4
pub const ARP_OP_REQUEST:  u16 = 1;
pub const ARP_OP_REPLY:    u16 = 2;

const CACHE_CAP: usize = 16;

// ── ARP cache ────────────────────────────────────────────────────────────────

struct ArpEntry {
    ip:    [u8; 4],
    mac:   [u8; 6],
    valid: bool,
}

impl ArpEntry {
    const fn empty() -> Self {
        Self { ip: [0;4], mac: [0;6], valid: false }
    }
}

static mut CACHE: [ArpEntry; CACHE_CAP] = [const { ArpEntry::empty() }; CACHE_CAP];

/// Look up a cached MAC for `ip`. Returns None if not in cache.
pub fn lookup(ip: &[u8; 4]) -> Option<[u8; 6]> {
    unsafe {
        for e in CACHE.iter() {
            if e.valid && &e.ip == ip { return Some(e.mac); }
        }
    }
    None
}

/// Insert or refresh an ARP cache entry (like Linux neighbour_update).
pub fn cache_update(ip: &[u8; 4], mac: &[u8; 6]) {
    unsafe {
        // Refresh existing
        for e in CACHE.iter_mut() {
            if e.valid && &e.ip == ip {
                e.mac.copy_from_slice(mac);
                return;
            }
        }
        // Find free slot
        for e in CACHE.iter_mut() {
            if !e.valid {
                e.ip.copy_from_slice(ip);
                e.mac.copy_from_slice(mac);
                e.valid = true;
                return;
            }
        }
        // Evict slot 0 (simple FIFO — Linux uses LRU)
        let e = &mut CACHE[0];
        e.ip.copy_from_slice(ip);
        e.mac.copy_from_slice(mac);
        e.valid = true;
    }
}

/// Iterate the ARP cache, calling `f(ip, mac)` for each valid entry.
pub fn iter<F: FnMut(&[u8;4], &[u8;6])>(mut f: F) {
    unsafe {
        for e in CACHE.iter() {
            if e.valid { f(&e.ip, &e.mac); }
        }
    }
}

// ── Packet parsing ────────────────────────────────────────────────────────────

pub struct ArpPacket {
    pub op:     u16,
    pub sha:    [u8; 6],  // sender MAC
    pub spa:    [u8; 4],  // sender IP
    pub tha:    [u8; 6],  // target MAC
    pub tpa:    [u8; 4],  // target IP
}

/// Parse an ARP payload (after Ethernet header).
/// Also updates the ARP cache with sender info (Linux arp_rcv does this).
pub fn parse(payload: &[u8]) -> Option<ArpPacket> {
    if payload.len() < ARP_HDR_LEN { return None; }
    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    if htype != ARP_HTYPE_ETHER || ptype != ARP_PTYPE_IPV4 { return None; }
    if payload[4] != 6 || payload[5] != 4 { return None; } // hlen, plen

    let op = u16::from_be_bytes([payload[6], payload[7]]);
    let mut pkt = ArpPacket { op, sha: [0;6], spa: [0;4], tha: [0;6], tpa: [0;4] };
    pkt.sha.copy_from_slice(&payload[8..14]);
    pkt.spa.copy_from_slice(&payload[14..18]);
    pkt.tha.copy_from_slice(&payload[18..24]);
    pkt.tpa.copy_from_slice(&payload[24..28]);

    // Gratuitous learning (Linux: arp_update_arp_entry)
    cache_update(&pkt.spa, &pkt.sha);
    Some(pkt)
}

// ── Packet building ───────────────────────────────────────────────────────────

/// Build a complete ARP request frame (Ethernet + ARP header).
/// Returns bytes written into `buf`, or 0 on error.
pub fn build_request(
    buf:        &mut [u8],
    our_mac:    &[u8; 6],
    our_ip:     &[u8; 4],
    target_ip:  &[u8; 4],
) -> usize {
    build_frame(buf, our_mac, our_ip, &eth::MAC_BCAST, &[0u8;6], target_ip, ARP_OP_REQUEST)
}

/// Build a complete ARP reply frame (Ethernet + ARP header).
pub fn build_reply(
    buf:      &mut [u8],
    our_mac:  &[u8; 6],
    our_ip:   &[u8; 4],
    dst_mac:  &[u8; 6],
    dst_ip:   &[u8; 4],
) -> usize {
    build_frame(buf, our_mac, our_ip, dst_mac, dst_mac, dst_ip, ARP_OP_REPLY)
}

fn build_frame(
    buf:    &mut [u8],
    sha:    &[u8; 6],
    spa:    &[u8; 4],
    dst_mac:&[u8; 6],
    tha:    &[u8; 6],
    tpa:    &[u8; 4],
    op:     u16,
) -> usize {
    let total = eth::ETH_HLEN + ARP_HDR_LEN;
    if buf.len() < total { return 0; }

    eth::build(buf, dst_mac, sha, eth::ETH_P_ARP);
    let a = &mut buf[eth::ETH_HLEN..eth::ETH_HLEN + ARP_HDR_LEN];
    a[0..2].copy_from_slice(&ARP_HTYPE_ETHER.to_be_bytes());
    a[2..4].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes());
    a[4] = 6;   // hlen
    a[5] = 4;   // plen
    a[6..8].copy_from_slice(&op.to_be_bytes());
    a[8..14].copy_from_slice(sha);
    a[14..18].copy_from_slice(spa);
    a[18..24].copy_from_slice(tha);
    a[24..28].copy_from_slice(tpa);
    total
}
