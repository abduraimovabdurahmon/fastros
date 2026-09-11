//! Minimal DNS A-record resolver.
//!
//! Sends a single UDP query to 8.8.8.8:53 and waits for the first A record
//! in the response.  IP-address literals are returned immediately without a
//! network round-trip.
//!
//! Linux equivalent: getaddrinfo() + res_query()

use crate::kernel::net::{self, socket};

const DNS_SERVER:   [u8; 4] = [8, 8, 8, 8];
const DNS_PORT:     u16     = 53;
const DNS_SRC_PORT: u16     = 54_353;

static mut QUERY_BUF: [u8; 512] = [0; 512];
static mut RESP_BUF:  [u8; 512] = [0; 512];

/// Resolve `hostname` to an IPv4 address.
///
/// If `hostname` is already a dotted-quad (e.g. "10.0.2.2") it is parsed
/// directly without sending any DNS query.
pub fn resolve(hostname: &[u8]) -> Option<[u8; 4]> {
    // Fast path: already an IP literal
    if let Some(ip) = parse_dotted_quad(hostname) { return Some(ip); }

    // Allocate UDP socket
    let fd = socket::socket(socket::AF_INET, socket::SOCK_DGRAM, socket::IPPROTO_UDP)?;
    if let Some(s) = socket::get_mut(fd) {
        s.local_ip   = net::primary_ip();
        s.local_port = DNS_SRC_PORT;
    }

    // Build and send query
    let qlen = unsafe { build_query(&mut QUERY_BUF, hostname, 0xABCD) };
    if qlen == 0 { socket::close(fd); return None; }

    if !net::udp_send_to(&DNS_SERVER, DNS_SRC_PORT, DNS_PORT,
                          unsafe { &QUERY_BUF[..qlen] }) {
        // First send may fail if ARP for the gateway is not yet resolved.
        // Wait briefly and retry.
        for _ in 0..800_000u64 { core::hint::spin_loop(); }
        net::poll_drivers();
        net::udp_send_to(&DNS_SERVER, DNS_SRC_PORT, DNS_PORT,
                         unsafe { &QUERY_BUF[..qlen] });
    }

    // Wait for response — up to ~3 s
    let mut rlen = 0usize;
    'wait: for _ in 0..3_000_000u64 {
        net::poll_drivers();
        if let Some(s) = socket::get_mut(fd) {
            if s.rx_available() > 6 {
                rlen = s.rx_pop(unsafe { &mut RESP_BUF });
                break 'wait;
            }
        }
    }

    socket::close(fd);

    if rlen <= 6 { return None; }
    // rcv_udp() prepends 4-byte src_ip + 2-byte src_port before each datagram.
    parse_response(unsafe { &RESP_BUF[6..rlen] })
}

// ── DNS packet builder ────────────────────────────────────────────────────────

/// Build a DNS query for an A record.  Returns bytes written (0 on error).
fn build_query(buf: &mut [u8; 512], hostname: &[u8], id: u16) -> usize {
    // Header (12 bytes)
    buf[0..2].copy_from_slice(&id.to_be_bytes());
    buf[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD = 1
    buf[4..6].copy_from_slice(&1u16.to_be_bytes());      // QDCOUNT = 1
    buf[6..12].fill(0);                                   // AN/NS/AR = 0

    let mut pos = 12usize;

    // QNAME: encode each label
    let mut label_start = 0usize;
    let mut i = 0usize;
    loop {
        let sep = i == hostname.len() || hostname[i] == b'.';
        if sep {
            let label_len = i - label_start;
            if pos + 1 + label_len >= 512 { return 0; }
            buf[pos] = label_len as u8;
            pos += 1;
            buf[pos..pos + label_len].copy_from_slice(&hostname[label_start..i]);
            pos += label_len;
            label_start = i + 1;
            if i == hostname.len() { break; }
        }
        i += 1;
    }
    // Root label
    if pos >= 512 { return 0; }
    buf[pos] = 0; pos += 1;

    // QTYPE = A (1), QCLASS = IN (1)
    if pos + 4 > 512 { return 0; }
    buf[pos..pos + 2].copy_from_slice(&1u16.to_be_bytes());
    buf[pos + 2..pos + 4].copy_from_slice(&1u16.to_be_bytes());
    pos + 4
}

// ── DNS response parser ───────────────────────────────────────────────────────

/// Parse a DNS response and return the first A record.
fn parse_response(buf: &[u8]) -> Option<[u8; 4]> {
    if buf.len() < 12 { return None; }

    let flags   = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 { return None; }  // QR bit must be 1 (response)

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 { return None; }

    let mut pos = 12usize;

    // Skip questions
    for _ in 0..qdcount {
        pos = skip_name(buf, pos)?;
        pos = pos.checked_add(4)?;  // QTYPE + QCLASS
        if pos > buf.len() { return None; }
    }

    // Parse answer records
    for _ in 0..ancount {
        pos = skip_name(buf, pos)?;
        if pos + 10 > buf.len() { return None; }

        let rtype = u16::from_be_bytes([buf[pos],     buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;

        if rtype == 1 && rdlen == 4 && pos + 4 <= buf.len() {
            return Some([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
        }
        pos = pos.checked_add(rdlen)?;
        if pos > buf.len() { return None; }
    }

    None
}

/// Skip a DNS name (sequence of labels, possibly ending with a compressed pointer).
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= buf.len() { return None; }
        let len = buf[pos];
        if len == 0          { return Some(pos + 1); }          // root label
        if len & 0xC0 == 0xC0 { return Some(pos + 2); }        // compression pointer
        pos += 1 + (len as usize);
    }
}

// ── IP literal parser ─────────────────────────────────────────────────────────

/// Parse "A.B.C.D" → [A, B, C, D].  Returns None if the input is not a valid
/// dotted-quad.
pub fn parse_dotted_quad(s: &[u8]) -> Option<[u8; 4]> {
    let mut ip   = [0u8; 4];
    let mut idx  = 0usize;
    let mut acc  = 0u32;
    let mut dots = 0u32;

    for &b in s {
        match b {
            b'0'..=b'9' => {
                acc = acc.saturating_mul(10).saturating_add((b - b'0') as u32);
                if acc > 255 { return None; }
            }
            b'.' => {
                if idx >= 3 || dots >= 3 { return None; }
                ip[idx] = acc as u8;
                idx += 1; acc = 0; dots += 1;
            }
            _ => return None,
        }
    }

    if dots != 3 || idx != 3 { return None; }
    ip[idx] = acc as u8;
    Some(ip)
}
