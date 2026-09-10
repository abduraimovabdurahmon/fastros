//! ifconfig — show or configure network interfaces.
//!
//! Usage:
//!   ifconfig              — list all interfaces
//!   ifconfig <iface>      — show specific interface
//!
//! Output format mirrors classic BSD/Linux ifconfig.

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::kernel::net::{self, eth, ip};

pub struct IfconfigCommand;
pub static IFCONFIG: IfconfigCommand = IfconfigCommand;

impl Command for IfconfigCommand {
    fn name(&self) -> &'static str { "ifconfig" }
    fn description(&self) -> &'static str { "Show or configure network interfaces" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        let filter: Option<&[u8]> = args.first().copied();

        let count = net::dev_count();
        if count == 0 {
            io.write_bytes(b"ifconfig: no network interfaces found\n");
            return 1;
        }

        let mut found = false;
        for idx in 0..count {
            let dev = match net::dev_info(idx) { Some(d) => d, None => continue };

            if let Some(f) = filter {
                if &dev.name[..dev.name_len] != f { continue; }
            }
            found = true;
            print_iface(io, idx, &dev);
        }

        if !found {
            if let Some(name) = filter {
                io.write_bytes(b"ifconfig: ");
                io.write_bytes(name);
                io.write_bytes(b": error fetching interface information: Device not found\n");
                return 1;
            }
        }
        0
    }
}

fn print_iface(io: &mut dyn ShellIo, _idx: usize, dev: &net::DevInfo) {
    // ── First line: name + flags + MTU ───────────────────────────────────────
    io.write_bytes(&dev.name[..dev.name_len]);
    io.write_bytes(b": flags=4163<UP,BROADCAST,RUNNING,MULTICAST>");
    io.write_bytes(b"  mtu ");
    print_u32(io, dev.mtu as u32);
    io.write_byte(b'\n');

    // ── inet line ─────────────────────────────────────────────────────────────
    io.write_bytes(b"        inet ");
    print_ip(io, &dev.ip);
    io.write_bytes(b"  netmask ");
    print_ip(io, &dev.netmask);

    // Broadcast = ip | ~mask
    let bcast = [
        dev.ip[0] | !dev.netmask[0],
        dev.ip[1] | !dev.netmask[1],
        dev.ip[2] | !dev.netmask[2],
        dev.ip[3] | !dev.netmask[3],
    ];
    if !dev.loopback {
        io.write_bytes(b"  broadcast ");
        print_ip(io, &bcast);
    }
    io.write_byte(b'\n');

    // ── ether line ────────────────────────────────────────────────────────────
    if !dev.loopback {
        io.write_bytes(b"        ether ");
        let mut mac_str = [0u8; 17];
        eth::fmt_mac(&dev.mac, &mut mac_str);
        io.write_bytes(&mac_str);
        io.write_bytes(b"  txqueuelen 1000  (Ethernet)\n");
    }

    // ── RX/TX stats (stub — no counters yet) ─────────────────────────────────
    io.write_bytes(b"        RX packets 0  bytes 0\n");
    io.write_bytes(b"        TX packets 0  bytes 0\n");
    io.write_byte(b'\n');
}

fn print_ip(io: &mut dyn ShellIo, ip: &[u8; 4]) {
    let mut buf = [0u8; 16];
    let n = ip::fmt_ip(ip, &mut buf);
    io.write_bytes(&buf[..n]);
}

fn print_u32(io: &mut dyn ShellIo, n: u32) {
    if n == 0 { io.write_byte(b'0'); return; }
    let mut buf = [0u8; 10];
    let mut pos = 10;
    let mut v = n;
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    io.write_bytes(&buf[pos..]);
}
