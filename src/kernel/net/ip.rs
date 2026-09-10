//! IPv4 — Internet Protocol version 4 (RFC 791).
//!
//! Handles IP header parsing, building, checksum, and fragmentation detection.
//! Routing (next-hop selection) is done in route.rs.
//!
//! Linux equivalent: net/ipv4/ip_input.c  net/ipv4/ip_output.c
//!                   include/linux/ip.h

use super::checksum;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const IP_HLEN:      usize = 20;    // minimum header (no options)
pub const IP_VERSION:   u8    = 4;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP:  u8 = 6;
pub const IPPROTO_UDP:  u8 = 17;

pub const IP_DF:  u16 = 0x4000;   // don't fragment flag
pub const IP_MF:  u16 = 0x2000;   // more fragments flag

pub const TTL_DEFAULT: u8 = 64;

// ── Parsed header ─────────────────────────────────────────────────────────────

pub struct IpHdr {
    pub ihl:      usize,   // header length in bytes (IHL * 4)
    pub tos:      u8,
    pub tot_len:  u16,
    pub id:       u16,
    pub frag_off: u16,     // flags (3 bits) + fragment offset (13 bits)
    pub ttl:      u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src:      [u8; 4],
    pub dst:      [u8; 4],
}

impl IpHdr {
    pub fn is_fragment(&self) -> bool {
        (self.frag_off & IP_MF != 0) || ((self.frag_off & 0x1FFF) != 0)
    }
    pub fn payload_len(&self) -> usize {
        (self.tot_len as usize).saturating_sub(self.ihl)
    }
}

// ── Parse ─────────────────────────────────────────────────────────────────────

/// Parse an IP header from a raw buffer.
/// Returns (IpHdr, payload_slice) or None if invalid.
pub fn parse(buf: &[u8]) -> Option<(IpHdr, &[u8])> {
    if buf.len() < IP_HLEN { return None; }
    let version = buf[0] >> 4;
    if version != IP_VERSION { return None; }
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if ihl < IP_HLEN || buf.len() < ihl { return None; }

    let tot_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < tot_len { return None; }

    let mut hdr = IpHdr {
        ihl,
        tos:      buf[1],
        tot_len:  tot_len as u16,
        id:       u16::from_be_bytes([buf[4], buf[5]]),
        frag_off: u16::from_be_bytes([buf[6], buf[7]]),
        ttl:      buf[8],
        protocol: buf[9],
        checksum: u16::from_be_bytes([buf[10], buf[11]]),
        src:      [0; 4],
        dst:      [0; 4],
    };
    hdr.src.copy_from_slice(&buf[12..16]);
    hdr.dst.copy_from_slice(&buf[16..20]);

    Some((hdr, &buf[ihl..tot_len]))
}

// ── Build ─────────────────────────────────────────────────────────────────────

/// Write a 20-byte IPv4 header into `buf[0..20]` and compute the checksum.
/// `payload_len` is the number of bytes after the IP header.
/// Returns the total length (20 + payload_len).
pub fn build(
    buf:         &mut [u8],
    src:         &[u8; 4],
    dst:         &[u8; 4],
    protocol:    u8,
    payload_len: usize,
    id:          u16,
    ttl:         u8,
) -> usize {
    let tot_len = (IP_HLEN + payload_len) as u16;
    buf[0]  = 0x45;                             // version=4, IHL=5
    buf[1]  = 0;                                // DSCP/ECN
    buf[2..4].copy_from_slice(&tot_len.to_be_bytes());
    buf[4..6].copy_from_slice(&id.to_be_bytes());
    buf[6..8].copy_from_slice(&IP_DF.to_be_bytes()); // DF flag set, no fragmentation
    buf[8]  = ttl;
    buf[9]  = protocol;
    buf[10..12].copy_from_slice(&[0, 0]);       // checksum placeholder
    buf[12..16].copy_from_slice(src);
    buf[16..20].copy_from_slice(dst);
    // Compute header checksum over the 20-byte header
    let ck = checksum::compute(&buf[..IP_HLEN]);
    buf[10..12].copy_from_slice(&ck.to_be_bytes());
    IP_HLEN + payload_len
}

// ── Pseudo-header ─────────────────────────────────────────────────────────────

/// Build the TCP/UDP pseudo-header accumulator (RFC 793 §3.1).
/// Used as the starting accumulator for TCP/UDP checksum computation.
///
///  ┌──────────────────────────────────────────┐
///  │  Source IP (4 bytes)                     │
///  │  Destination IP (4 bytes)                │
///  │  Zero (1 byte) + Protocol (1 byte)       │
///  │  TCP/UDP segment length (2 bytes)        │
///  └──────────────────────────────────────────┘
pub fn pseudo_header_acc(src: &[u8; 4], dst: &[u8; 4], proto: u8, seg_len: u16) -> u32 {
    let mut acc: u32 = 0;
    acc = checksum::accumulate(src, acc);
    acc = checksum::accumulate(dst, acc);
    acc = checksum::accumulate(&[0, proto], acc);
    acc = checksum::accumulate(&seg_len.to_be_bytes(), acc);
    acc
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format an IPv4 address as "A.B.C.D" into a fixed-size buffer.
/// Returns the number of bytes written.
pub fn fmt_ip(ip: &[u8; 4], out: &mut [u8; 16]) -> usize {
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        let s = itoa(octet);
        for &b in s.as_bytes() {
            if pos < 15 { out[pos] = b; pos += 1; }
        }
        if i < 3 && pos < 15 { out[pos] = b'.'; pos += 1; }
    }
    pos
}

fn itoa(n: u8) -> &'static str {
    // Small static table avoids alloc
    match n {
        0   => "0",   1   => "1",   2   => "2",   3   => "3",   4   => "4",
        5   => "5",   6   => "6",   7   => "7",   8   => "8",   9   => "9",
        10  => "10",  11  => "11",  12  => "12",  13  => "13",  14  => "14",
        15  => "15",  16  => "16",  17  => "17",  18  => "18",  19  => "19",
        20  => "20",  21  => "21",  22  => "22",  23  => "23",  24  => "24",
        25  => "25",  26  => "26",  27  => "27",  28  => "28",  29  => "29",
        30  => "30",  50  => "50",  64  => "64",  100 => "100", 127 => "127",
        128 => "128", 192 => "192", 255 => "255",
        n   => {
            // General case via scratch buffer in static storage
            // (safe: single-threaded kernel)
            static mut BUF: [u8; 4] = [0u8; 4];
            unsafe {
                let mut pos = 4usize;
                let mut v = n;
                loop {
                    pos -= 1;
                    BUF[pos] = b'0' + v % 10;
                    v /= 10;
                    if v == 0 { break; }
                }
                core::str::from_utf8(&BUF[pos..]).unwrap_or("?")
            }
        }
    }
}

/// Global IP packet ID counter (like Linux's ip_idents).
static mut IP_ID: u16 = 1;

pub fn next_id() -> u16 {
    unsafe {
        let id = IP_ID;
        IP_ID = IP_ID.wrapping_add(1);
        id
    }
}
