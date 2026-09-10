//! ping — send ICMP echo requests and report round-trip time.
//!
//! Usage: ping [-c count] [-i interval] [-t ttl] <host>
//!
//! Linux behaviour:
//!   - Sends ICMP echo request, prints reply info (bytes, seq, ttl, time).
//!   - Ctrl-C stops; sends summary (transmitted / received / loss).
//!   - Count defaults to unlimited; we default to 4 (like Windows ping).

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::net::{self, icmp, ip, socket};

pub struct PingCommand;
pub static PING: PingCommand = PingCommand;

impl Command for PingCommand {
    fn name(&self) -> &'static str { "ping" }
    fn description(&self) -> &'static str { "Send ICMP echo requests to a host" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        // ── Parse arguments ───────────────────────────────────────────────────
        let mut count:    usize = 4;
        let mut dest_ip:  Option<[u8;4]> = None;

        let mut i = 0;
        while i < args.len() {
            match args[i] {
                b"-c" => {
                    i += 1;
                    if i < args.len() { count = parse_u32(args[i]) as usize; }
                }
                _ => { dest_ip = parse_ip(args[i]); }
            }
            i += 1;
        }

        let dest = match dest_ip {
            Some(d) => d,
            None => {
                io.write_bytes(b"ping: usage: ping [-c count] <A.B.C.D>\n");
                return 1;
            }
        };

        // ── Open a RAW socket for ICMP ────────────────────────────────────────
        let fd = match socket::socket(socket::AF_INET, socket::SOCK_RAW, socket::IPPROTO_ICMP) {
            Some(f) => f,
            None => {
                io.write_bytes(b"ping: cannot open raw socket\n");
                return 1;
            }
        };

        // ── Print header (Linux: "PING host (ip): 56(84) bytes of data.") ─────
        io.write_bytes(b"PING ");
        print_ip(io, &dest);
        io.write_bytes(b" (");
        print_ip(io, &dest);
        io.write_bytes(b"): 56 data bytes\n");

        let our_ip = net::primary_ip();
        let payload = b"fastros ping payload abcdefghijklmnopqrstuvwxyz0123456789!!"; // 56 bytes
        let ping_id: u16 = 0x1337;

        let mut transmitted = 0usize;
        let mut received    = 0usize;

        for seq in 1u16..=(count as u16) {
            // Poll for any pending frames first so ARP replies arrive
            net::poll_drivers();

            // ── Build ICMP echo request ───────────────────────────────────────
            // We need: Ethernet(14) + IP(20) + ICMP(8+56=64) = 98 bytes
            static mut ICMP_BUF: [u8; 64] = [0; 64];
            let icmp_len = unsafe {
                icmp::build_echo_request(&mut ICMP_BUF, ping_id, seq, payload)
            };
            if icmp_len == 0 { continue; }

            // ── Send via IP layer ─────────────────────────────────────────────
            let sent = unsafe {
                net::send_ipv4(&dest, ip::IPPROTO_ICMP, &ICMP_BUF[..icmp_len])
            };

            if !sent {
                // ARP not resolved yet — wait for ARP reply and retry
                busy_wait(500_000);
                net::poll_drivers();
                let _ = unsafe {
                    net::send_ipv4(&dest, ip::IPPROTO_ICMP, &ICMP_BUF[..icmp_len])
                };
            }
            transmitted += 1;

            // ── Wait for echo reply (poll with timeout) ───────────────────────
            let mut reply_received = false;
            let timeout_loops: u64 = 2_000_000;  // ~2 seconds at ~1M loop/sec
            let mut loops = 0u64;

            while loops < timeout_loops && !reply_received {
                net::poll_drivers();

                // Check raw socket for ICMP reply
                if let Some(s) = socket::get_mut(fd) {
                    if s.rx_available() >= icmp::ICMP_HLEN {
                        let mut buf = [0u8; 128];
                        let n = s.rx_pop(&mut buf);
                        if n >= icmp::ICMP_HLEN {
                            if let Some((reply, _)) = icmp::parse(&buf[..n]) {
                                if reply.type_ == icmp::ICMP_ECHO_REPLY
                                    && reply.id()  == ping_id
                                    && reply.seq() == seq
                                {
                                    // RTT: approximate based on loop count (no timer yet)
                                    let rtt_ms = loops / 1000;
                                    io.write_bytes(b"64 bytes from ");
                                    print_ip(io, &dest);
                                    io.write_bytes(b": icmp_seq=");
                                    print_u16(io, seq);
                                    io.write_bytes(b" ttl=64 time=");
                                    print_u64(io, rtt_ms);
                                    io.write_bytes(b" ms\n");
                                    received += 1;
                                    reply_received = true;
                                }
                            }
                        }
                    }
                }
                loops += 1;
            }

            if !reply_received {
                io.write_bytes(b"Request timeout for icmp_seq=");
                print_u16(io, seq);
                io.write_byte(b'\n');
            }

            // Inter-packet delay (~1 second worth of poll loops)
            if seq < count as u16 {
                busy_wait(1_000_000);
            }
        }

        // ── Statistics (Linux format) ─────────────────────────────────────────
        io.write_bytes(b"\n--- ");
        print_ip(io, &dest);
        io.write_bytes(b" ping statistics ---\n");
        print_usize(io, transmitted);
        io.write_bytes(b" packets transmitted, ");
        print_usize(io, received);
        io.write_bytes(b" received, ");
        let loss = if transmitted > 0 { (transmitted - received) * 100 / transmitted } else { 100 };
        print_usize(io, loss);
        io.write_bytes(b"% packet loss\n");

        socket::close(fd);
        if received == 0 { 1 } else { 0 }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse "A.B.C.D" into a 4-byte array.
fn parse_ip(s: &[u8]) -> Option<[u8; 4]> {
    let mut ip = [0u8; 4];
    let mut idx = 0;
    let mut acc = 0u32;
    let mut dots = 0;
    for &b in s {
        if b == b'.' {
            if dots >= 3 || acc > 255 { return None; }
            ip[idx] = acc as u8; idx += 1; acc = 0; dots += 1;
        } else if b >= b'0' && b <= b'9' {
            acc = acc * 10 + (b - b'0') as u32;
        } else {
            return None;
        }
    }
    if dots != 3 || acc > 255 { return None; }
    ip[idx] = acc as u8;
    Some(ip)
}

fn parse_u32(s: &[u8]) -> u32 {
    let mut v = 0u32;
    for &b in s {
        if b >= b'0' && b <= b'9' { v = v.wrapping_mul(10).wrapping_add((b - b'0') as u32); }
    }
    v.max(1)
}

fn print_ip(io: &mut dyn ShellIo, ip: &[u8; 4]) {
    for i in 0..4 {
        print_u16(io, ip[i] as u16);
        if i < 3 { io.write_byte(b'.'); }
    }
}

fn print_u16(io: &mut dyn ShellIo, n: u16) {
    print_u64(io, n as u64);
}

fn print_usize(io: &mut dyn ShellIo, n: usize) {
    print_u64(io, n as u64);
}

fn print_u64(io: &mut dyn ShellIo, n: u64) {
    if n == 0 { io.write_byte(b'0'); return; }
    let mut buf = [0u8; 20];
    let mut pos = 20;
    let mut v = n;
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    io.write_bytes(&buf[pos..]);
}

fn busy_wait(iters: u64) {
    let mut x: u64 = 0;
    for i in 0..iters { x = x.wrapping_add(i); }
    // Prevent optimizer from removing loop
    unsafe { core::ptr::write_volatile(&mut x as *mut u64, x); }
}
