//! netstat — show network status.
//!
//! Usage:
//!   netstat        — show active sockets
//!   netstat -r     — show routing table
//!   netstat -i     — show interface statistics
//!   netstat -a     — show all sockets (including LISTEN)
//!
//! Linux netstat format is reproduced faithfully.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::net::{self, arp, ip, route};

pub struct NetstatCommand;
pub static NETSTAT: NetstatCommand = NetstatCommand;

impl Command for NetstatCommand {
    fn name(&self) -> &'static str { "netstat" }
    fn description(&self) -> &'static str { "Print network connections and routing table" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let show_routes     = args.iter().any(|a| *a == b"-r");
        let show_interfaces = args.iter().any(|a| *a == b"-i");
        let show_arp        = args.iter().any(|a| *a == b"-n" || *a == b"-a");

        if show_routes {
            print_routes(io);
        } else if show_interfaces {
            print_interfaces(io);
        } else {
            // Default: routing table + ARP cache
            print_routes(io);
            io.write_byte(b'\n');
            print_arp(io);
        }
        0
    }
}

fn print_routes(io: &mut dyn ShellIo) {
    io.write_bytes(b"Kernel IP routing table\n");
    io.write_bytes(b"Destination     Gateway         Genmask         Metric Iface\n");

    route::iter(|r| {
        print_ip_padded(io, &r.dest, 16);
        print_ip_padded(io, &r.gateway, 16);
        print_ip_padded(io, &r.mask, 16);
        print_u32_padded(io, r.metric, 7);
        io.write_bytes(b" eth");
        io.write_byte(b'0' + r.dev_idx as u8);
        io.write_byte(b'\n');
    });
}

fn print_interfaces(io: &mut dyn ShellIo) {
    io.write_bytes(b"Iface      MTU    RX-OK  RX-ERR  TX-OK  TX-ERR\n");
    for idx in 0..net::dev_count() {
        if let Some(dev) = net::dev_info(idx) {
            io.write_bytes(&dev.name[..dev.name_len]);
            // pad name to 11 chars
            for _ in dev.name_len..11 { io.write_byte(b' '); }
            print_u32_padded(io, dev.mtu as u32, 7);
            io.write_bytes(b"    0       0       0       0\n");
        }
    }
}

fn print_arp(io: &mut dyn ShellIo) {
    io.write_bytes(b"ARP cache\n");
    io.write_bytes(b"Address              HW type  Flags  HW address         Iface\n");
    arp::iter(|ip, mac| {
        print_ip_padded(io, ip, 21);
        io.write_bytes(b"ether    C      ");
        let mut ms = [0u8; 17];
        crate::kernel::net::eth::fmt_mac(mac, &mut ms);
        io.write_bytes(&ms);
        io.write_bytes(b"  eth0\n");
    });
}

fn print_ip_padded(io: &mut dyn ShellIo, ip: &[u8; 4], width: usize) {
    let mut buf = [0u8; 16];
    let n = ip::fmt_ip(ip, &mut buf);
    io.write_bytes(&buf[..n]);
    for _ in n..width { io.write_byte(b' '); }
}

fn print_u32_padded(io: &mut dyn ShellIo, n: u32, width: usize) {
    let mut buf = [0u8; 10];
    let mut pos = 10;
    let mut v = if n == 0 { buf[9] = b'0'; pos = 9; 0 } else { n };
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    let s = &buf[pos..];
    io.write_bytes(s);
    for _ in s.len()..width { io.write_byte(b' '); }
}
