//! Network user commands: ping, ip, ifconfig, route, arp, netstat, ss, nc,
//! nslookup, host, dig, and the `fw` firewall CLI.

use crate::net::dns;
use crate::net::socket::{TcpListener, TcpStream, UdpSocket};
use crate::shell::ctx::{parse_opts, Ctx, OptSpec};
use crate::outln;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

fn resolve_host(host: &str) -> Result<Ipv4Address, String> {
    if let Some(ip) = dns::parse_ipv4(host) {
        return Ok(ip);
    }
    dns::resolve(host).ok().and_then(|v| v.first().copied()).ok_or_else(|| alloc::format!("{host}: Name or service not known"))
}

// ── ping ─────────────────────────────────────────────────────────────────

/// Internet checksum (RFC 1071).
fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.push(8); // type: echo request
    p.push(0); // code
    p.extend_from_slice(&[0, 0]); // checksum placeholder
    p.extend_from_slice(&ident.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(payload);
    let c = checksum(&p);
    p[2..4].copy_from_slice(&c.to_be_bytes());
    p
}

pub fn ping(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec {
        flags: "qnvD",
        values: "cisWtw",
        long: &[("count", 'c', true), ("interval", 'i', true), ("quiet", 'q', false)],
    };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return ctx.fail(e),
    };
    let Some(host) = p.operands.first().cloned() else {
        ctx.eprint("ping: usage error: Destination address required\n");
        return 2;
    };
    let ip = match resolve_host(&host) {
        Ok(ip) => ip,
        Err(e) => {
            ctx.eprint(&alloc::format!("ping: {e}\n"));
            return 2;
        }
    };
    let count: Option<u64> = p.value('c').and_then(|c| c.parse().ok());
    let interval_ms: u64 = p.value('i').and_then(|c| c.parse::<Secs>().ok()).map(|f| f.ms()).unwrap_or(1000);
    let wait_ms: u64 = p.value('W').and_then(|c| c.parse::<Secs>().ok()).map(|f| f.ms()).unwrap_or(1000);
    let size: usize = p.value('s').and_then(|c| c.parse().ok()).unwrap_or(56);
    let quiet = p.has('q');

    let sock = match crate::net::socket::IcmpSocket::new() {
        Ok(s) => s,
        Err(e) => return ctx.fail_errno("socket", e),
    };
    outln!(ctx, "PING {} ({}) {}({}) bytes of data.", host, dns::fmt(ip), size, size + 28);
    ctx.flush();

    let (mut tx, mut rx) = (0u64, 0u64);
    let mut rtts: Vec<u64> = Vec::new();
    let mut payload = alloc::vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    // Warm up the neighbour cache: on an Ethernet medium even 127.0.0.1 is
    // reached via ARP, and smoltcp drops the first packet while it resolves.
    // This uncounted probe (seq 0) primes it so no real request is lost.
    let warm = build_echo(sock.ident, 0, &payload[..8.min(size)]);
    let _ = sock.send(&warm, IpAddress::Ipv4(ip));
    let warm_deadline = crate::time::now_ns() + 300_000_000;
    let mut wbuf = [0u8; 256];
    while crate::time::now_ns() < warm_deadline {
        crate::net::poll_now();
        let step = (crate::time::now_ns() + 20_000_000).min(warm_deadline);
        match sock.recv(&mut wbuf, step) {
            Ok((_, _)) => break,
            Err(crate::errno::Errno::EINTR) => break,
            _ => {}
        }
    }
    let start = crate::time::now_ns();
    let mut seq = 0u16;
    loop {
        if let Some(c) = count {
            if seq as u64 >= c {
                break;
            }
        }
        if crate::proc::interrupted() {
            break;
        }
        seq += 1;
        let sent_ns = crate::time::now_ns();
        // Embed the send time in the payload's first 8 bytes.
        payload[..8.min(size)].copy_from_slice(&sent_ns.to_be_bytes()[..8.min(size)]);
        let pkt = build_echo(sock.ident, seq, &payload);
        if sock.send(&pkt, IpAddress::Ipv4(ip)).is_ok() {
            tx += 1;
        }
        // Wait for the matching reply (ignore stale sequence numbers). Drive
        // the stack ourselves in short steps: a loopback reply is only
        // produced by a poll, and nothing else polls while we wait.
        let deadline = crate::time::now_ns() + wait_ms * 1_000_000;
        let mut buf = [0u8; 2048];
        loop {
            crate::net::poll_now();
            let step = (crate::time::now_ns() + 20_000_000).min(deadline);
            match sock.recv(&mut buf, step) {
                Ok((n, from)) if n >= 8 => {
                    let rseq = u16::from_be_bytes([buf[6], buf[7]]);
                    if buf[0] == 0 && rseq == seq {
                        let rtt = crate::time::now_ns() - sent_ns;
                        rtts.push(rtt);
                        rx += 1;
                        if !quiet {
                            outln!(ctx, "{} bytes from {}: icmp_seq={} ttl=64 time={} ms", n, fmt_addr(from), seq, ms_str(rtt));
                            ctx.flush();
                        }
                        break;
                    }
                    // Not ours (old seq); keep waiting until the deadline.
                }
                Ok(_) => {}
                Err(crate::errno::Errno::EINTR) => break,
                Err(_) => {}
            }
            if crate::proc::interrupted() || crate::time::now_ns() >= deadline {
                break;
            }
        }
        if crate::proc::interrupted() {
            break;
        }
        if count.map(|c| seq as u64 >= c).unwrap_or(false) {
            break;
        }
        if !crate::sched::sleep_ms(interval_ms) {
            break; // interrupted
        }
    }

    let elapsed = (crate::time::now_ns() - start) / 1_000_000;
    outln!(ctx);
    outln!(ctx, "--- {} ping statistics ---", host);
    let loss = if tx > 0 { (tx - rx) * 100 / tx } else { 0 };
    outln!(ctx, "{} packets transmitted, {} received, {}% packet loss, time {}ms", tx, rx, loss, elapsed);
    if !rtts.is_empty() {
        let min = *rtts.iter().min().unwrap();
        let max = *rtts.iter().max().unwrap();
        let avg = rtts.iter().sum::<u64>() / rtts.len() as u64;
        let var = rtts.iter().map(|&r| (r as i64 - avg as i64).unsigned_abs()).sum::<u64>() / rtts.len() as u64;
        outln!(ctx, "rtt min/avg/max/mdev = {}/{}/{}/{} ms", ms_str(min), ms_str(avg), ms_str(max), ms_str(var));
    }
    if rx == 0 {
        1
    } else {
        0
    }
}

/// Nanoseconds as `0.123` milliseconds.
fn ms_str(ns: u64) -> String {
    let us = ns / 1000;
    alloc::format!("{}.{:03}", us / 1000, us % 1000)
}

fn fmt_addr(a: IpAddress) -> String {
    match a {
        IpAddress::Ipv4(v) => dns::fmt(v),
    }
}

/// A tiny fixed-point seconds parser (`0.2`, `1`, `2.5`) → milliseconds.
struct Secs(u64);
impl Secs {
    fn ms(&self) -> u64 {
        self.0
    }
}
impl core::str::FromStr for Secs {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let (i, f) = s.split_once('.').unwrap_or((s, ""));
        let whole: u64 = if i.is_empty() { 0 } else { i.parse().map_err(|_| ())? };
        let mut ms = whole * 1000;
        let mut scale = 100;
        for c in f.chars().take(3) {
            ms += c.to_digit(10).ok_or(())? as u64 * scale;
            scale /= 10;
        }
        Ok(Secs(ms))
    }
}

// ── ip / ifconfig / route / arp ────────────────────────────────────────────

/// Parse `/proc/net/dev` for one interface's counters.
fn iface_counters(name: &str) -> Option<(u64, u64, u64, u64, u64, u64)> {
    let text = crate::net::procfs("dev");
    for line in text.lines().skip(2) {
        let (ifn, rest) = line.split_once(':')?;
        if ifn.trim() != name {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        // rx: bytes packets errs drop ...  tx starts at index 8
        return Some((f[0], f[1], f[2], f[8], f[9], f[10]));
    }
    None
}

fn cidr_prefix(mask: Ipv4Address) -> u8 {
    u32::from_be_bytes(mask.octets()).count_ones() as u8
}

pub fn ip(ctx: &mut Ctx) -> i32 {
    let args: Vec<String> = ctx.args[1..].to_vec();
    let obj = args.first().map(|s| s.as_str()).unwrap_or("addr");
    let sub = args.get(1).map(|s| s.as_str()).unwrap_or("show");
    match obj {
        "a" | "addr" | "address" => ip_addr(ctx),
        "l" | "link" => ip_link(ctx),
        "r" | "route" => {
            if sub == "add" || sub == "del" {
                ip_route_change(ctx, sub, &args[2..])
            } else {
                ip_route(ctx)
            }
        }
        "n" | "neigh" | "neighbour" => ip_neigh(ctx),
        _ => {
            ctx.eprint(&alloc::format!("ip: Object \"{obj}\" is unknown, try \"ip help\".\n"));
            2
        }
    }
}

fn link_flags(up: bool) -> String {
    if up {
        "<BROADCAST,MULTICAST,UP,LOWER_UP>".to_string()
    } else {
        "<BROADCAST,MULTICAST>".to_string()
    }
}

fn ip_link(ctx: &mut Ctx) -> i32 {
    let mac = crate::net::stack().lock().mac();
    let up = crate::net::config().addr.is_some();
    outln!(ctx, "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000");
    outln!(ctx, "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00");
    outln!(ctx, "2: eth0: {} mtu 1500 qdisc fq_codel state {} mode DEFAULT group default qlen 1000", link_flags(up), if up { "UP" } else { "DOWN" });
    outln!(ctx, "    link/ether {} brd ff:ff:ff:ff:ff:ff", crate::net::fmt_mac(&mac));
    0
}

fn ip_addr(ctx: &mut Ctx) -> i32 {
    let cfg = crate::net::config();
    let mac = crate::net::stack().lock().mac();
    outln!(ctx, "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000");
    outln!(ctx, "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00");
    outln!(ctx, "    inet 127.0.0.1/8 scope host lo");
    outln!(ctx, "       valid_lft forever preferred_lft forever");
    let up = cfg.addr.is_some();
    outln!(ctx, "2: eth0: {} mtu 1500 qdisc fq_codel state {} group default qlen 1000", link_flags(up), if up { "UP" } else { "DOWN" });
    outln!(ctx, "    link/ether {} brd ff:ff:ff:ff:ff:ff", crate::net::fmt_mac(&mac));
    if let Some(a) = cfg.addr {
        let bcast = broadcast(a.address(), a.prefix_len());
        outln!(ctx, "    inet {}/{} brd {} scope global {} eth0", dns::fmt(a.address()), a.prefix_len(), dns::fmt(bcast), if cfg.dhcp { "dynamic" } else { "static" });
        outln!(ctx, "       valid_lft {} preferred_lft {}", if cfg.dhcp { alloc::format!("{}sec", cfg.lease_secs) } else { "forever".to_string() }, if cfg.dhcp { alloc::format!("{}sec", cfg.lease_secs) } else { "forever".to_string() });
    }
    0
}

fn broadcast(addr: Ipv4Address, prefix: u8) -> Ipv4Address {
    let a = u32::from_be_bytes(addr.octets());
    let host = if prefix >= 32 { 0 } else { (!0u32) >> prefix };
    Ipv4Address::from((a | host).to_be_bytes())
}

fn ip_route(ctx: &mut Ctx) -> i32 {
    let cfg = crate::net::config();
    if let Some(gw) = cfg.gateway {
        outln!(ctx, "default via {} dev eth0{}", dns::fmt(gw), if cfg.dhcp { " proto dhcp" } else { "" });
    }
    if let Some(a) = cfg.addr {
        let net = network(a.address(), a.prefix_len());
        outln!(ctx, "{}/{} dev eth0 proto kernel scope link src {}", dns::fmt(net), a.prefix_len(), dns::fmt(a.address()));
    }
    0
}

fn network(addr: Ipv4Address, prefix: u8) -> Ipv4Address {
    let a = u32::from_be_bytes(addr.octets());
    let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    Ipv4Address::from((a & mask).to_be_bytes())
}

fn ip_route_change(ctx: &mut Ctx, op: &str, args: &[String]) -> i32 {
    if !ctx.cred().is_root() {
        ctx.eprint("ip: Operation not permitted\n");
        return 2;
    }
    // Support: ip route add/del default via GW
    let mut gw = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "via" {
            gw = args.get(i + 1).and_then(|s| dns::parse_ipv4(s));
            i += 1;
        }
        i += 1;
    }
    let mut st = crate::net::stack().lock();
    match op {
        "add" => {
            if let Some(g) = gw {
                let _ = st.iface.routes_mut().add_default_ipv4_route(g);
                st.cfg.gateway = Some(g);
                0
            } else {
                drop(st);
                ctx.eprint("ip: route add: need 'via GATEWAY'\n");
                2
            }
        }
        "del" => {
            st.iface.routes_mut().remove_default_ipv4_route();
            st.cfg.gateway = None;
            0
        }
        _ => 2,
    }
}

fn ip_neigh(ctx: &mut Ctx) -> i32 {
    // The smoltcp neighbour cache is not enumerable; show the gateway as the
    // one reachable neighbour when configured.
    let cfg = crate::net::config();
    if let Some(gw) = cfg.gateway {
        let mac = crate::net::stack().lock().mac();
        let _ = mac;
        outln!(ctx, "{} dev eth0 lladdr 52:54:00:12:35:02 REACHABLE", dns::fmt(gw));
    }
    0
}

pub fn ifconfig(ctx: &mut Ctx) -> i32 {
    let cfg = crate::net::config();
    let mac = crate::net::stack().lock().mac();
    let up = cfg.addr.is_some();
    // eth0
    let flags = if up { "UP,BROADCAST,RUNNING,MULTICAST" } else { "BROADCAST,MULTICAST" };
    outln!(ctx, "eth0: flags=4163<{}>  mtu 1500", flags);
    if let Some(a) = cfg.addr {
        let mask = netmask(a.prefix_len());
        outln!(ctx, "        inet {}  netmask {}  broadcast {}", dns::fmt(a.address()), dns::fmt(mask), dns::fmt(broadcast(a.address(), a.prefix_len())));
    }
    outln!(ctx, "        ether {}  txqueuelen 1000  (Ethernet)", crate::net::fmt_mac(&mac));
    if let Some((rb, rp, re, tb, tp, te)) = iface_counters("eth0") {
        outln!(ctx, "        RX packets {}  bytes {}", rp, rb);
        outln!(ctx, "        RX errors {}  dropped 0  overruns 0  frame 0", re);
        outln!(ctx, "        TX packets {}  bytes {}", tp, tb);
        outln!(ctx, "        TX errors {}  dropped 0 overruns 0  carrier 0  collisions 0", te);
    }
    outln!(ctx);
    // lo
    outln!(ctx, "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536");
    outln!(ctx, "        inet 127.0.0.1  netmask 255.0.0.0");
    outln!(ctx, "        loop  txqueuelen 1000  (Local Loopback)");
    if let Some((rb, rp, _, tb, tp, _)) = iface_counters("lo") {
        outln!(ctx, "        RX packets {}  bytes {}", rp, rb);
        outln!(ctx, "        TX packets {}  bytes {}", tp, tb);
    }
    0
}

fn netmask(prefix: u8) -> Ipv4Address {
    let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
    Ipv4Address::from(mask.to_be_bytes())
}

pub fn route(ctx: &mut Ctx) -> i32 {
    let numeric = ctx.args.iter().any(|a| a == "-n");
    let cfg = crate::net::config();
    outln!(ctx, "Kernel IP routing table");
    outln!(ctx, "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface");
    let show = |a: Ipv4Address| dns::fmt(a);
    if let Some(gw) = cfg.gateway {
        let dest = if numeric { "0.0.0.0".to_string() } else { "default".to_string() };
        outln!(ctx, "{:<15} {:<15} {:<15} UG    100    0        0 eth0", dest, show(gw), "0.0.0.0");
    }
    if let Some(a) = cfg.addr {
        let net = network(a.address(), a.prefix_len());
        let dest = if numeric { show(net) } else { show(net) };
        outln!(ctx, "{:<15} {:<15} {:<15} U     0      0        0 eth0", dest, "0.0.0.0", show(netmask(a.prefix_len())));
    }
    0
}

pub fn arp(ctx: &mut Ctx) -> i32 {
    let cfg = crate::net::config();
    outln!(ctx, "Address                  HWtype  HWaddress           Flags Mask            Iface");
    if let Some(gw) = cfg.gateway {
        outln!(ctx, "{:<24} ether   52:54:00:12:35:02   C                     eth0", dns::fmt(gw));
    }
    0
}

// ── netstat / ss ───────────────────────────────────────────────────────────

fn ep_str(ep: Option<(IpAddress, u16)>, numeric: bool, listen: bool) -> String {
    match ep {
        Some((a, p)) => {
            let host = match a {
                IpAddress::Ipv4(v) if v.octets() == [0, 0, 0, 0] => if numeric { "0.0.0.0".to_string() } else { "*".to_string() },
                IpAddress::Ipv4(v) => dns::fmt(v),
            };
            let port = if p == 0 || (listen && p == 0) { "*".to_string() } else { p.to_string() };
            alloc::format!("{host}:{port}")
        }
        None => "*:*".to_string(),
    }
}

pub fn netstat(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "tulnprais", values: "", long: &[("tcp", 't', false), ("udp", 'u', false), ("listening", 'l', false), ("numeric", 'n', false), ("route", 'r', false), ("all", 'a', false), ("interfaces", 'i', false), ("statistics", 's', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return ctx.fail(e),
    };
    if p.has('r') {
        return route(ctx);
    }
    if p.has('i') {
        return netstat_iface(ctx);
    }
    let numeric = p.has('n');
    let listen_only = p.has('l');
    let all = p.has('a');
    let want_tcp = p.has('t') || !(p.has('u'));
    let want_udp = p.has('u');
    outln!(ctx, "Active Internet connections ({})", if listen_only { "only servers" } else if all { "servers and established" } else { "w/o servers" });
    outln!(ctx, "Proto Recv-Q Send-Q Local Address           Foreign Address         State");
    if want_tcp {
        let rows = { let st = crate::net::stack().lock(); crate::net::socket::tcp_table(&st) };
        for r in rows {
            let is_listen = r.state_code == 0x0A;
            if listen_only && !is_listen {
                continue;
            }
            if !listen_only && !all && is_listen {
                continue;
            }
            let local = ep_str(r.local_ep, numeric, is_listen);
            let foreign = ep_str(r.remote_ep, numeric, false);
            outln!(ctx, "{:<5} {:>6} {:>6} {:<23} {:<23} {}", "tcp", r.rx_queue, r.tx_queue, local, foreign, r.state);
        }
    }
    if want_udp {
        // No enumerable UDP table yet.
    }
    0
}

fn netstat_iface(ctx: &mut Ctx) -> i32 {
    outln!(ctx, "Kernel Interface table");
    outln!(ctx, "Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg");
    for (name, mtu) in [("eth0", 1500), ("lo", 65536)] {
        if let Some((_, rp, re, _, tp, te)) = iface_counters(name) {
            let flg = if name == "lo" { "LRU" } else { "BMRU" };
            outln!(ctx, "{:<10} {:<6} {:>6} {:>6} 0      0      {:>6} {:>6} 0      0      {}", name, mtu, rp, re, tp, te, flg);
        }
    }
    0
}

pub fn ss(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "tulnpa", values: "", long: &[("tcp", 't', false), ("udp", 'u', false), ("listening", 'l', false), ("numeric", 'n', false), ("all", 'a', false)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return ctx.fail(e),
    };
    let numeric = p.has('n');
    let listen_only = p.has('l');
    let all = p.has('a') || listen_only;
    outln!(ctx, "{:<5}{:<12}{:<7}{:<7}{:<24}{:<24}", "Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port");
    let rows = { let st = crate::net::stack().lock(); crate::net::socket::tcp_table(&st) };
    for r in rows {
        let is_listen = r.state_code == 0x0A;
        if listen_only && !is_listen {
            continue;
        }
        if !all && is_listen {
            continue;
        }
        let state = if is_listen { "LISTEN" } else { r.state };
        let local = ep_str(r.local_ep, numeric, is_listen);
        let peer = ep_str(r.remote_ep, numeric, false);
        outln!(ctx, "{:<5}{:<12}{:<7}{:<7}{:<24}{:<24}", "tcp", state, r.rx_queue, r.tx_queue, local, peer);
    }
    0
}

// ── nc ───────────────────────────────────────────────────────────────────

pub fn nc(ctx: &mut Ctx) -> i32 {
    const SPEC: OptSpec = OptSpec { flags: "lukvnz", values: "wp", long: &[("listen", 'l', false), ("udp", 'u', false), ("verbose", 'v', false), ("wait", 'w', true)] };
    let p = match parse_opts(&ctx.args, &SPEC) {
        Ok(p) => p,
        Err(e) => return ctx.fail(e),
    };
    let timeout_ms = p.value('w').and_then(|w| w.parse::<u64>().ok()).map(|s| s * 1000);
    let verbose = p.has('v');

    if p.has('z') {
        // Port scan: nc -z host port[-port]
        let host = p.operands.first().cloned().unwrap_or_default();
        let ip = match resolve_host(&host) {
            Ok(ip) => ip,
            Err(e) => return ctx.fail(e),
        };
        let (lo, hi) = match p.operands.get(1).map(|s| parse_port_range(s)) {
            Some(Some(r)) => r,
            _ => return ctx.fail("missing port"),
        };
        let mut any = 1;
        for port in lo..=hi {
            match TcpStream::connect(IpEndpoint::new(IpAddress::Ipv4(ip), port), timeout_ms.unwrap_or(3000)) {
                Ok(s) => {
                    s.shutdown();
                    outln!(ctx, "Connection to {} {} port [tcp/*] succeeded!", host, port);
                    any = 0;
                }
                Err(_) if verbose => {
                    ctx.eprint(&alloc::format!("nc: connect to {} port {} (tcp) failed: Connection refused\n", host, port));
                }
                Err(_) => {}
            }
        }
        return any;
    }

    if p.has('l') {
        let port = match p.operands.iter().rev().find_map(|s| s.parse::<u16>().ok()) {
            Some(p) => p,
            None => return ctx.fail("missing listen port"),
        };
        let listener = match TcpListener::bind(port, 1) {
            Ok(l) => l,
            Err(e) => return ctx.fail_errno("bind", e),
        };
        if verbose {
            ctx.eprint(&alloc::format!("Listening on 0.0.0.0 {port}\n"));
        }
        let (stream, peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) => return ctx.fail_errno("accept", e),
        };
        if verbose {
            ctx.eprint(&alloc::format!("Connection received on {}\n", fmt_addr(peer.addr)));
        }
        return pump(ctx, Arc::new(stream));
    }

    // Connect mode.
    let host = p.operands.first().cloned().unwrap_or_default();
    let Some(port) = p.operands.get(1).and_then(|s| s.parse::<u16>().ok()) else {
        ctx.eprint("nc: missing port\n");
        return 2;
    };
    let ip = match resolve_host(&host) {
        Ok(ip) => ip,
        Err(e) => return ctx.fail(e),
    };
    let stream = match TcpStream::connect(IpEndpoint::new(IpAddress::Ipv4(ip), port), timeout_ms.unwrap_or(10000)) {
        Ok(s) => s,
        Err(e) => {
            ctx.eprint(&alloc::format!("nc: connect to {host} port {port} (tcp) failed: {e}\n"));
            return 1;
        }
    };
    if verbose {
        ctx.eprint(&alloc::format!("Connection to {host} {port} port [tcp/*] succeeded!\n"));
    }
    pump(ctx, Arc::new(stream))
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    if let Some((a, b)) = s.split_once('-') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        let p: u16 = s.parse().ok()?;
        Some((p, p))
    }
}

/// Bidirectional copy between stdin/stdout and a TCP stream.
fn pump(ctx: &mut Ctx, stream: Arc<TcpStream>) -> i32 {
    ctx.flush();
    let stdin = ctx.stdin();
    let stdout = ctx.stdout();
    // stdin → socket in its own task.
    let s2 = stream.clone();
    let writer = crate::sched::spawn("nc-stdin", move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if s2.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(crate::errno::Errno::EINTR) => break,
                Err(_) => break,
            }
        }
        s2.shutdown();
    });
    // socket → stdout in this task.
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(crate::errno::Errno::EINTR) => {
                if !crate::proc::absorb_signals() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    stream.shutdown();
    writer.join();
    0
}

// ── nslookup / host / dig ──────────────────────────────────────────────────

pub fn nslookup(ctx: &mut Ctx) -> i32 {
    let Some(name) = ctx.args.get(1).cloned() else {
        ctx.eprint("usage: nslookup HOST\n");
        return 1;
    };
    let server = crate::net::config().dns.first().map(|d| dns::fmt(*d)).unwrap_or_else(|| "10.0.2.3".to_string());
    outln!(ctx, "Server:\t\t{server}");
    outln!(ctx, "Address:\t{server}#53");
    outln!(ctx);
    if let Some(ip) = dns::parse_ipv4(&name) {
        outln!(ctx, "{}.in-addr.arpa\tname = {}.", reverse(ip), name);
        return 0;
    }
    match dns::resolve(&name) {
        Ok(ips) if !ips.is_empty() => {
            outln!(ctx, "Non-authoritative answer:");
            for ip in ips {
                outln!(ctx, "Name:\t{name}");
                outln!(ctx, "Address: {}", dns::fmt(ip));
            }
            0
        }
        _ => {
            outln!(ctx, "** server can't find {name}: NXDOMAIN");
            1
        }
    }
}

fn reverse(ip: Ipv4Address) -> String {
    let o = ip.octets();
    alloc::format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

pub fn host(ctx: &mut Ctx) -> i32 {
    let Some(name) = ctx.args.get(1).cloned() else {
        ctx.eprint("Usage: host NAME\n");
        return 1;
    };
    match dns::resolve(&name) {
        Ok(ips) if !ips.is_empty() => {
            for ip in ips {
                outln!(ctx, "{} has address {}", name, dns::fmt(ip));
            }
            0
        }
        _ => {
            outln!(ctx, "Host {name} not found: 3(NXDOMAIN)");
            1
        }
    }
}

pub fn dig(ctx: &mut Ctx) -> i32 {
    // Accept `dig NAME`, `dig NAME A`, `dig @server NAME`.
    let mut name = None;
    for a in &ctx.args[1..] {
        if a.starts_with('@') || a.starts_with('+') || a == "A" || a == "AAAA" {
            continue;
        }
        name = Some(a.clone());
    }
    let Some(name) = name else {
        ctx.eprint("usage: dig NAME\n");
        return 1;
    };
    let server = crate::net::config().dns.first().map(|d| dns::fmt(*d)).unwrap_or_else(|| "10.0.2.3".to_string());
    outln!(ctx, "; <<>> DiG 9.18-fastros <<>> {name}");
    outln!(ctx, ";; global options: +cmd");
    let ips = dns::resolve(&name).unwrap_or_default();
    let status = if ips.is_empty() { "NXDOMAIN" } else { "NOERROR" };
    outln!(ctx, ";; Got answer:");
    outln!(ctx, ";; ->>HEADER<<- opcode: QUERY, status: {}, id: {}", status, crate::crypto::rng::u32() & 0xffff);
    outln!(ctx, ";; QUESTION SECTION:");
    outln!(ctx, ";{}.\t\t\tIN\tA", name);
    if !ips.is_empty() {
        outln!(ctx);
        outln!(ctx, ";; ANSWER SECTION:");
        for ip in &ips {
            outln!(ctx, "{}.\t\t300\tIN\tA\t{}", name, dns::fmt(*ip));
        }
    }
    outln!(ctx);
    outln!(ctx, ";; SERVER: {server}#53({server})");
    if ips.is_empty() {
        1
    } else {
        0
    }
}

// ── fw ─────────────────────────────────────────────────────────────────────

pub fn fw(ctx: &mut Ctx) -> i32 {
    use fastros_netfilter as nf;
    let sub = ctx.args.get(1).map(|s| s.as_str()).unwrap_or("status");
    let now_ms = crate::time::now_ns() / 1_000_000;
    match sub {
        "status" | "list" | "" => {
            let r = crate::firewall::with(|fw| {
                let mut s = String::new();
                use core::fmt::Write;
                let _ = writeln!(s, "Firewall: {}", if fw.enabled { "enabled" } else { "disabled" });
                let _ = writeln!(s, "Default policy: in {} / out {}", fw.policy_in.name(), fw.policy_out.name());
                let c = &fw.counters;
                let _ = writeln!(s, "Packets: {} accepted in, {} out; {} dropped in, {} out", c.accepted_in, c.accepted_out, c.dropped_in, c.dropped_out);
                let _ = writeln!(s, "Blocked: {} spoofed, {} malformed, {} syn-flood, {} port-scans, {} banned hits", c.spoofed, c.malformed, c.syn_flood, c.scans_detected, c.banned);
                let _ = writeln!(s, "Active flows: {}, bans issued: {}", fw.flow_count(), c.bans_issued);
                let _ = writeln!(s, "\nnum  dir  action proto           dport  hits    comment");
                for (i, rule) in fw.rules.iter().enumerate() {
                    let proto = rule.proto.map(|p| p.name()).unwrap_or("any");
                    let dport = rule.dport.map(|d| if d.lo == d.hi { d.lo.to_string() } else { alloc::format!("{}-{}", d.lo, d.hi) }).unwrap_or_else(|| "*".to_string());
                    let _ = writeln!(s, "{:<4} {:<4} {:<6} {:<15} {:<6} {:<7} {}", i, rule.dir.name(), rule.action.name(), proto, dport, rule.hits, rule.comment);
                }
                let bans = fw.bans(now_ms);
                if !bans.is_empty() {
                    let _ = writeln!(s, "\nBanned addresses:");
                    for (ip, ban) in bans {
                        let _ = writeln!(s, "  {:<16} {}s left  ({}, {} strikes)", nf::fmt_ip(ip), ban.until_ms.saturating_sub(now_ms) / 1000, ban.reason, ban.strikes);
                    }
                }
                s
            });
            match r {
                Some(s) => {
                    ctx.print(&s);
                    0
                }
                None => ctx.fail("firewall not initialized"),
            }
        }
        "allow" | "open" => fw_port(ctx, true),
        "deny" | "close" => fw_port(ctx, false),
        "ban" => {
            if !ctx.cred().is_root() {
                return ctx.fail("Operation not permitted");
            }
            let Some(ip) = ctx.args.get(2).and_then(|s| nf::parse_ip(s)) else {
                return ctx.fail("usage: fw ban IP [seconds]");
            };
            let secs: u64 = ctx.args.get(3).and_then(|s| s.parse().ok()).unwrap_or(600);
            crate::firewall::ban(ip, secs * 1000, "manual ban");
            outln!(ctx, "banned {} for {}s", nf::fmt_ip(ip), secs);
            0
        }
        "unban" => {
            if !ctx.cred().is_root() {
                return ctx.fail("Operation not permitted");
            }
            let Some(ip) = ctx.args.get(2).and_then(|s| nf::parse_ip(s)) else {
                return ctx.fail("usage: fw unban IP");
            };
            let removed = crate::firewall::with(|fw| fw.unban(ip)).unwrap_or(false);
            if removed {
                outln!(ctx, "unbanned {}", nf::fmt_ip(ip));
                0
            } else {
                ctx.fail(alloc::format!("{} is not banned", nf::fmt_ip(ip)))
            }
        }
        "bans" => {
            let list = crate::firewall::with(|fw| fw.bans(now_ms)).unwrap_or_default();
            if list.is_empty() {
                outln!(ctx, "No active bans.");
            }
            for (ip, ban) in list {
                outln!(ctx, "{:<16} {}s  {}", nf::fmt_ip(ip), ban.until_ms.saturating_sub(now_ms) / 1000, ban.reason);
            }
            0
        }
        _ => {
            ctx.eprint("usage: fw [status | allow PROTO PORT | deny PROTO PORT | ban IP [s] | unban IP | bans]\n");
            2
        }
    }
}

fn fw_port(ctx: &mut Ctx, allow: bool) -> i32 {
    use fastros_netfilter::Proto;
    if !ctx.cred().is_root() {
        return ctx.fail("Operation not permitted");
    }
    let proto = match ctx.args.get(2).map(|s| s.as_str()) {
        Some("tcp") => Proto::Tcp,
        Some("udp") => Proto::Udp,
        _ => return ctx.fail("usage: fw allow tcp|udp PORT"),
    };
    let Some(port) = ctx.args.get(3).and_then(|s| s.parse::<u16>().ok()) else {
        return ctx.fail("usage: fw allow tcp|udp PORT");
    };
    if allow {
        crate::firewall::open_port(proto, port, "manual (fw allow)");
        outln!(ctx, "opened {} port {}", if matches!(proto, Proto::Tcp) { "tcp" } else { "udp" }, port);
    } else {
        use fastros_netfilter::PortRange;
        crate::firewall::with(|fw| fw.rules.retain(|r| !(r.proto == Some(proto) && r.dport == Some(PortRange { lo: port, hi: port }) && r.action == fastros_netfilter::Action::Accept)));
        outln!(ctx, "closed {} port {}", if matches!(proto, Proto::Tcp) { "tcp" } else { "udp" }, port);
    }
    0
}
