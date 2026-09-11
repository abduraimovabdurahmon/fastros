//! FastROS packet filter.
//!
//! Evaluation order for every frame (first decision wins):
//!
//! 1. **sanity** — malformed IPv4, fragments, impossible TCP flag sets
//!    (NULL/XMAS/SYN+FIN/SYN+RST scans) and spoofed sources (loopback or our
//!    own address arriving from the wire) are dropped;
//! 2. **bans** — sources on the ban list (manual, brute-force or port-scan
//!    detection) are dropped;
//! 3. **connection tracking** — packets of a known flow are accepted;
//! 4. **rules** — first matching rule decides (optionally rate limited);
//! 5. **policy** — the direction's default action.
//!
//! Inbound new TCP connections are additionally limited per source (SYN
//! flood protection), and a source touching many closed ports in a short
//! window is banned automatically (port-scan protection). All of this is
//! on by default — Linux ships with every one of these switched off.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub type Ip = [u8; 4];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl Proto {
    pub fn number(self) -> u8 {
        match self {
            Proto::Icmp => 1,
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Other(n) => n,
        }
    }
    pub fn from_number(n: u8) -> Proto {
        match n {
            1 => Proto::Icmp,
            6 => Proto::Tcp,
            17 => Proto::Udp,
            n => Proto::Other(n),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Other(_) => "ip",
        }
    }
}

pub mod tcpf {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// The fields of an IPv4 packet the filter looks at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet {
    pub src: Ip,
    pub dst: Ip,
    pub proto: Proto,
    pub sport: u16,
    pub dport: u16,
    pub tcp_flags: u8,
    pub icmp_type: u8,
    pub len: usize,
    pub fragment: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
    Ipv4(Packet),
    Arp,
    /// IPv4 whose header could not be parsed.
    Malformed,
    Other,
}

pub fn parse_ethernet(frame: &[u8]) -> Frame {
    if frame.len() < 14 {
        return Frame::Malformed;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x0806 => Frame::Arp,
        0x0800 => parse_ipv4(&frame[14..]),
        _ => Frame::Other,
    }
}

pub fn parse_ipv4(p: &[u8]) -> Frame {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return Frame::Malformed;
    }
    let ihl = (p[0] & 0x0F) as usize * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total < ihl || total > p.len() {
        return Frame::Malformed;
    }
    let frag = u16::from_be_bytes([p[6], p[7]]);
    let more_fragments = frag & 0x2000 != 0;
    let offset = frag & 0x1FFF;
    let proto = Proto::from_number(p[9]);
    let src = [p[12], p[13], p[14], p[15]];
    let dst = [p[16], p[17], p[18], p[19]];
    let l4 = &p[ihl..total];
    let mut pkt = Packet {
        src,
        dst,
        proto,
        sport: 0,
        dport: 0,
        tcp_flags: 0,
        icmp_type: 0,
        len: total,
        fragment: more_fragments || offset != 0,
    };
    if pkt.fragment {
        return Frame::Ipv4(pkt);
    }
    match proto {
        Proto::Tcp => {
            if l4.len() < 20 {
                return Frame::Malformed;
            }
            pkt.sport = u16::from_be_bytes([l4[0], l4[1]]);
            pkt.dport = u16::from_be_bytes([l4[2], l4[3]]);
            pkt.tcp_flags = l4[13] & 0x3F;
        }
        Proto::Udp => {
            if l4.len() < 8 {
                return Frame::Malformed;
            }
            pkt.sport = u16::from_be_bytes([l4[0], l4[1]]);
            pkt.dport = u16::from_be_bytes([l4[2], l4[3]]);
        }
        Proto::Icmp => {
            if l4.len() < 8 {
                return Frame::Malformed;
            }
            pkt.icmp_type = l4[0];
            // Echo id doubles as a "port" so replies match their request.
            pkt.sport = u16::from_be_bytes([l4[4], l4[5]]);
            pkt.dport = pkt.sport;
        }
        Proto::Other(_) => {}
    }
    Frame::Ipv4(pkt)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: Ip,
    pub prefix: u8,
}

impl Cidr {
    pub fn contains(&self, ip: Ip) -> bool {
        if self.prefix == 0 {
            return true;
        }
        let mask = u32::MAX << (32 - self.prefix as u32);
        u32::from_be_bytes(self.addr) & mask == u32::from_be_bytes(ip) & mask
    }
    pub fn parse(s: &str) -> Option<Cidr> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok().filter(|&p| p <= 32)?),
            None => (s, 32),
        };
        let addr = parse_ip(a)?;
        Some(Cidr { addr, prefix: p })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.addr;
        if self.prefix == 32 {
            write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        } else {
            write!(f, "{}.{}.{}.{}/{}", a[0], a[1], a[2], a[3], self.prefix)
        }
    }
}

pub fn parse_ip(s: &str) -> Option<Ip> {
    let mut o = [0u8; 4];
    let mut n = 0;
    for part in s.split('.') {
        if n == 4 || part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        o[n] = part.parse().ok()?;
        n += 1;
    }
    (n == 4).then_some(o)
}

pub fn fmt_ip(a: Ip) -> String {
    alloc::format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> Option<PortRange> {
        match s.split_once(['-', ':']) {
            Some((a, b)) => {
                let (lo, hi) = (a.parse().ok()?, b.parse().ok()?);
                (lo <= hi).then_some(PortRange { lo, hi })
            }
            None => {
                let p = s.parse().ok()?;
                Some(PortRange { lo: p, hi: p })
            }
        }
    }
    pub fn contains(&self, p: u16) -> bool {
        (self.lo..=self.hi).contains(&p)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    In,
    Out,
}

impl Dir {
    pub fn name(self) -> &'static str {
        match self {
            Dir::In => "in",
            Dir::Out => "out",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
        }
    }
}

/// Token bucket: `rate` tokens per second, up to `burst`.
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    pub rate: u32,
    pub burst: u32,
    tokens_milli: u64,
    last_ms: u64,
}

impl Bucket {
    pub fn new(rate: u32, burst: u32) -> Bucket {
        Bucket { rate, burst, tokens_milli: burst as u64 * 1000, last_ms: 0 }
    }
    pub fn take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms;
        self.tokens_milli = (self.tokens_milli + elapsed * self.rate as u64).min(self.burst as u64 * 1000);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub dir: Dir,
    pub action: Action,
    pub proto: Option<Proto>,
    pub src: Option<Cidr>,
    pub dst: Option<Cidr>,
    pub sport: Option<PortRange>,
    pub dport: Option<PortRange>,
    pub icmp_type: Option<u8>,
    /// Rate limit: packets beyond it fall through to the next rule.
    pub limit: Option<Bucket>,
    pub comment: String,
    pub hits: u64,
    pub bytes: u64,
    /// Installed by the system (container port mappings, defaults).
    pub system: bool,
}

impl Rule {
    pub fn new(dir: Dir, action: Action) -> Rule {
        Rule {
            dir,
            action,
            proto: None,
            src: None,
            dst: None,
            sport: None,
            dport: None,
            icmp_type: None,
            limit: None,
            comment: String::new(),
            hits: 0,
            bytes: 0,
            system: false,
        }
    }

    fn matches(&self, dir: Dir, p: &Packet) -> bool {
        self.dir == dir
            && self.proto.is_none_or(|x| x == p.proto)
            && self.src.is_none_or(|c| c.contains(p.src))
            && self.dst.is_none_or(|c| c.contains(p.dst))
            && self.sport.is_none_or(|r| r.contains(p.sport))
            && self.dport.is_none_or(|r| r.contains(p.dport))
            && self.icmp_type.is_none_or(|t| t == p.icmp_type)
    }

    /// Rule text in `fw add` syntax.
    pub fn describe(&self) -> String {
        let mut s = alloc::format!("{} {}", self.dir.name(), self.action.name());
        if let Some(p) = self.proto {
            s.push(' ');
            s.push_str(p.name());
        }
        if let Some(c) = self.src {
            s.push_str(&alloc::format!(" from {c}"));
        }
        if let Some(c) = self.dst {
            s.push_str(&alloc::format!(" to {c}"));
        }
        if let Some(r) = self.sport {
            s.push_str(&alloc::format!(" sport {r}"));
        }
        if let Some(r) = self.dport {
            s.push_str(&alloc::format!(" port {r}"));
        }
        if let Some(t) = self.icmp_type {
            s.push_str(&alloc::format!(" type {t}"));
        }
        if let Some(b) = self.limit {
            s.push_str(&alloc::format!(" limit {}/s", b.rate));
        }
        s
    }
}

// ── connection tracking ─────────────────────────────────────────────────────

/// A flow as seen from this host: (protocol, local ip:port, remote ip:port).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowKey {
    pub proto: u8,
    pub local: (Ip, u16),
    pub remote: (Ip, u16),
}

#[derive(Clone, Copy, Debug)]
pub struct Flow {
    pub created_ms: u64,
    pub last_ms: u64,
    pub packets: u64,
    pub bytes: u64,
    /// A packet travelled in the direction opposite to the opener.
    pub replied: bool,
    pub opened_by: Dir,
    pub closing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop(Reason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Malformed,
    Fragment,
    BadFlags,
    Spoofed,
    Banned,
    SynFlood,
    Rule(usize),
    Policy,
}

impl Reason {
    pub fn name(self) -> &'static str {
        match self {
            Reason::Malformed => "malformed",
            Reason::Fragment => "fragment",
            Reason::BadFlags => "bad-tcp-flags",
            Reason::Spoofed => "spoofed-source",
            Reason::Banned => "banned",
            Reason::SynFlood => "syn-flood",
            Reason::Rule(_) => "rule",
            Reason::Policy => "policy",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ban {
    pub until_ms: u64,
    pub reason: String,
    pub strikes: u32,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub accepted_in: u64,
    pub accepted_out: u64,
    pub dropped_in: u64,
    pub dropped_out: u64,
    pub malformed: u64,
    pub spoofed: u64,
    pub banned: u64,
    pub syn_flood: u64,
    pub scans_detected: u64,
    pub bans_issued: u64,
}

struct ScanTracker {
    window_start_ms: u64,
    ports: Vec<u16>,
}

/// Tunables (all enabled by default).
#[derive(Clone, Copy, Debug)]
pub struct Protections {
    /// New inbound TCP connections per source per second (0 = off).
    pub syn_rate: u32,
    pub syn_burst: u32,
    /// Distinct refused ports from one source within `scan_window_ms` that
    /// trigger a ban (0 = off).
    pub scan_ports: usize,
    pub scan_window_ms: u64,
    pub scan_ban_ms: u64,
    pub drop_fragments: bool,
}

impl Default for Protections {
    fn default() -> Self {
        Protections { syn_rate: 20, syn_burst: 40, scan_ports: 20, scan_window_ms: 10_000, scan_ban_ms: 3_600_000, drop_fragments: true }
    }
}

pub struct Firewall {
    pub rules: Vec<Rule>,
    pub policy_in: Action,
    pub policy_out: Action,
    pub protections: Protections,
    pub enabled: bool,
    flows: BTreeMap<FlowKey, Flow>,
    max_flows: usize,
    bans: BTreeMap<Ip, Ban>,
    syn_buckets: BTreeMap<Ip, Bucket>,
    scans: BTreeMap<Ip, ScanTracker>,
    /// Addresses of this host (anti-spoofing, direction of flows).
    pub local_ips: Vec<Ip>,
    /// Trusted sources never banned automatically.
    pub allowlist: Vec<Cidr>,
    pub counters: Counters,
    /// Drops worth reporting, drained by the kernel's logger.
    pub log: Vec<(Dir, Packet, Reason)>,
    pub log_drops: bool,
}

const TCP_EST_TIMEOUT_MS: u64 = 3_600_000;
const TCP_CLOSE_TIMEOUT_MS: u64 = 10_000;
const TCP_NEW_TIMEOUT_MS: u64 = 60_000;
const UDP_TIMEOUT_MS: u64 = 30_000;
const UDP_STREAM_TIMEOUT_MS: u64 = 180_000;
const ICMP_TIMEOUT_MS: u64 = 30_000;

impl Firewall {
    /// The secure default rule set: inbound closed except SSH, ping, DHCP
    /// replies and traffic of connections this host (or an accepted
    /// inbound rule) opened. Outbound open.
    pub fn with_defaults() -> Firewall {
        let mut fw = Firewall {
            rules: Vec::new(),
            policy_in: Action::Drop,
            policy_out: Action::Accept,
            protections: Protections::default(),
            enabled: true,
            flows: BTreeMap::new(),
            max_flows: 32768,
            bans: BTreeMap::new(),
            syn_buckets: BTreeMap::new(),
            scans: BTreeMap::new(),
            local_ips: Vec::new(),
            allowlist: Vec::new(),
            counters: Counters::default(),
            log: Vec::new(),
            log_drops: true,
        };
        let mut ssh = Rule::new(Dir::In, Action::Accept);
        ssh.proto = Some(Proto::Tcp);
        ssh.dport = Some(PortRange { lo: 22, hi: 22 });
        ssh.comment = String::from("ssh");
        ssh.system = true;
        fw.rules.push(ssh);
        let mut ping = Rule::new(Dir::In, Action::Accept);
        ping.proto = Some(Proto::Icmp);
        ping.icmp_type = Some(8);
        ping.limit = Some(Bucket::new(10, 20));
        ping.comment = String::from("ping (rate limited)");
        ping.system = true;
        fw.rules.push(ping);
        let mut dhcp = Rule::new(Dir::In, Action::Accept);
        dhcp.proto = Some(Proto::Udp);
        dhcp.sport = Some(PortRange { lo: 67, hi: 67 });
        dhcp.dport = Some(PortRange { lo: 68, hi: 68 });
        dhcp.comment = String::from("dhcp client");
        dhcp.system = true;
        fw.rules.push(dhcp);
        fw
    }

    fn flow_key(dir: Dir, p: &Packet) -> FlowKey {
        match dir {
            Dir::Out => FlowKey { proto: p.proto.number(), local: (p.src, p.sport), remote: (p.dst, p.dport) },
            Dir::In => FlowKey { proto: p.proto.number(), local: (p.dst, p.dport), remote: (p.src, p.sport) },
        }
    }

    fn flow_timeout(proto: u8, f: &Flow) -> u64 {
        match proto {
            6 if f.closing => TCP_CLOSE_TIMEOUT_MS,
            6 if f.replied => TCP_EST_TIMEOUT_MS,
            6 => TCP_NEW_TIMEOUT_MS,
            17 if f.replied => UDP_STREAM_TIMEOUT_MS,
            17 => UDP_TIMEOUT_MS,
            _ => ICMP_TIMEOUT_MS,
        }
    }

    fn sanity(&self, dir: Dir, p: &Packet) -> Option<Reason> {
        if p.fragment && self.protections.drop_fragments {
            return Some(Reason::Fragment);
        }
        if p.proto == Proto::Tcp {
            let f = p.tcp_flags;
            let syn = f & tcpf::SYN != 0;
            let bad = f & (tcpf::FIN | tcpf::SYN | tcpf::RST | tcpf::ACK | tcpf::PSH | tcpf::URG) == 0 // NULL scan
                || f & (tcpf::FIN | tcpf::PSH | tcpf::URG) == (tcpf::FIN | tcpf::PSH | tcpf::URG) && !syn && f & tcpf::ACK == 0 // XMAS
                || (syn && f & tcpf::FIN != 0)
                || (syn && f & tcpf::RST != 0);
            if bad {
                return Some(Reason::BadFlags);
            }
        }
        if dir == Dir::In && (p.src[0] == 127 || self.local_ips.contains(&p.src) || p.src[0] == 0) {
            return Some(Reason::Spoofed);
        }
        None
    }

    fn allowlisted(&self, ip: Ip) -> bool {
        self.allowlist.iter().any(|c| c.contains(ip))
    }

    /// Filter one Ethernet frame.
    pub fn check_frame(&mut self, dir: Dir, frame: &[u8], now_ms: u64) -> Verdict {
        match parse_ethernet(frame) {
            Frame::Ipv4(p) => self.check(dir, &p, now_ms),
            Frame::Malformed => {
                self.counters.malformed += 1;
                self.count(dir, false);
                Verdict::Drop(Reason::Malformed)
            }
            Frame::Arp | Frame::Other => Verdict::Accept,
        }
    }

    fn count(&mut self, dir: Dir, accepted: bool) {
        match (dir, accepted) {
            (Dir::In, true) => self.counters.accepted_in += 1,
            (Dir::Out, true) => self.counters.accepted_out += 1,
            (Dir::In, false) => self.counters.dropped_in += 1,
            (Dir::Out, false) => self.counters.dropped_out += 1,
        }
    }

    pub fn check(&mut self, dir: Dir, p: &Packet, now_ms: u64) -> Verdict {
        let v = self.decide(dir, p, now_ms);
        match v {
            Verdict::Accept => self.count(dir, true),
            Verdict::Drop(r) => {
                self.count(dir, false);
                if self.log_drops && self.log.len() < 64 && !matches!(r, Reason::Policy) {
                    self.log.push((dir, *p, r));
                }
            }
        }
        v
    }

    fn decide(&mut self, dir: Dir, p: &Packet, now_ms: u64) -> Verdict {
        if !self.enabled {
            return Verdict::Accept;
        }
        if let Some(r) = self.sanity(dir, p) {
            if r == Reason::Spoofed {
                self.counters.spoofed += 1;
            }
            return Verdict::Drop(r);
        }
        let remote = if dir == Dir::In { p.src } else { p.dst };
        if let Some(b) = self.bans.get(&remote) {
            if b.until_ms > now_ms {
                self.counters.banned += 1;
                return Verdict::Drop(Reason::Banned);
            }
            self.bans.remove(&remote);
        }

        // Known flow?
        let key = Self::flow_key(dir, p);
        if let Some(f) = self.flows.get_mut(&key) {
            if now_ms.saturating_sub(f.last_ms) <= Self::flow_timeout(key.proto, f) {
                f.last_ms = now_ms;
                f.packets += 1;
                f.bytes += p.len as u64;
                if dir != f.opened_by {
                    f.replied = true;
                }
                if p.proto == Proto::Tcp && p.tcp_flags & (tcpf::FIN | tcpf::RST) != 0 {
                    f.closing = true;
                }
                return Verdict::Accept;
            }
            self.flows.remove(&key);
        }
        // Replies to ICMP echo we sent: the echo id is the key on both sides.
        // (Handled by the flow table above since sport == dport == id.)

        // A new inbound TCP connection must start with a SYN (no ACK).
        let new_tcp_in = dir == Dir::In && p.proto == Proto::Tcp && p.tcp_flags & tcpf::SYN != 0 && p.tcp_flags & tcpf::ACK == 0;
        if dir == Dir::In && p.proto == Proto::Tcp && !new_tcp_in {
            // Stray segment of no known connection (e.g. after a reboot): drop quietly.
            return Verdict::Drop(Reason::Policy);
        }

        let mut decision = None;
        for (i, r) in self.rules.iter_mut().enumerate() {
            if !r.matches(dir, p) {
                continue;
            }
            if let Some(b) = r.limit.as_mut() {
                if !b.take(now_ms) {
                    continue;
                }
            }
            r.hits += 1;
            r.bytes += p.len as u64;
            decision = Some((r.action, Reason::Rule(i)));
            break;
        }
        let (action, reason) = decision.unwrap_or((if dir == Dir::In { self.policy_in } else { self.policy_out }, Reason::Policy));

        if action == Action::Drop {
            if dir == Dir::In {
                self.note_refused(p, now_ms);
            }
            return Verdict::Drop(reason);
        }
        if new_tcp_in && self.protections.syn_rate > 0 && !self.allowlisted(p.src) {
            let (rate, burst) = (self.protections.syn_rate, self.protections.syn_burst);
            let b = self.syn_buckets.entry(p.src).or_insert_with(|| Bucket::new(rate, burst));
            if !b.take(now_ms) {
                self.counters.syn_flood += 1;
                return Verdict::Drop(Reason::SynFlood);
            }
        }
        self.track(key, dir, p, now_ms);
        Verdict::Accept
    }

    fn track(&mut self, key: FlowKey, dir: Dir, p: &Packet, now_ms: u64) {
        if self.flows.len() >= self.max_flows {
            self.expire(now_ms);
            if self.flows.len() >= self.max_flows {
                // Evict the stalest flow.
                if let Some(k) = self.flows.iter().min_by_key(|(_, f)| f.last_ms).map(|(k, _)| *k) {
                    self.flows.remove(&k);
                }
            }
        }
        self.flows.insert(
            key,
            Flow { created_ms: now_ms, last_ms: now_ms, packets: 1, bytes: p.len as u64, replied: false, opened_by: dir, closing: false },
        );
    }

    /// Record an inbound packet refused by policy; ban sources that sweep ports.
    fn note_refused(&mut self, p: &Packet, now_ms: u64) {
        if self.protections.scan_ports == 0 || self.allowlisted(p.src) || !matches!(p.proto, Proto::Tcp | Proto::Udp) {
            return;
        }
        let t = self.scans.entry(p.src).or_insert(ScanTracker { window_start_ms: now_ms, ports: Vec::new() });
        if now_ms.saturating_sub(t.window_start_ms) > self.protections.scan_window_ms {
            t.window_start_ms = now_ms;
            t.ports.clear();
        }
        if !t.ports.contains(&p.dport) {
            t.ports.push(p.dport);
        }
        if t.ports.len() >= self.protections.scan_ports {
            self.scans.remove(&p.src);
            self.counters.scans_detected += 1;
            let ms = self.protections.scan_ban_ms;
            self.ban(p.src, now_ms, ms, "port scan");
        }
    }

    /// Ban `ip` for `duration_ms` (repeat offenders get doubled durations).
    pub fn ban(&mut self, ip: Ip, now_ms: u64, duration_ms: u64, reason: &str) -> u64 {
        if self.allowlisted(ip) || self.local_ips.contains(&ip) {
            return 0;
        }
        let strikes = self.bans.get(&ip).map_or(0, |b| b.strikes) + 1;
        let dur = duration_ms.saturating_mul(1 << (strikes - 1).min(6));
        self.bans.insert(ip, Ban { until_ms: now_ms + dur, reason: String::from(reason), strikes });
        self.counters.bans_issued += 1;
        // Existing flows of the offender die with the ban.
        self.flows.retain(|k, _| k.remote.0 != ip);
        dur
    }

    pub fn unban(&mut self, ip: Ip) -> bool {
        self.bans.remove(&ip).is_some()
    }

    pub fn bans(&self, now_ms: u64) -> Vec<(Ip, Ban)> {
        self.bans.iter().filter(|(_, b)| b.until_ms > now_ms).map(|(ip, b)| (*ip, b.clone())).collect()
    }

    pub fn is_banned(&self, ip: Ip, now_ms: u64) -> bool {
        self.bans.get(&ip).is_some_and(|b| b.until_ms > now_ms)
    }

    /// Drop expired flows, stale limiter and scan state.
    pub fn expire(&mut self, now_ms: u64) {
        self.flows.retain(|k, f| now_ms.saturating_sub(f.last_ms) <= Self::flow_timeout(k.proto, f));
        self.bans.retain(|_, b| b.until_ms > now_ms);
        self.syn_buckets.retain(|_, b| now_ms.saturating_sub(b.last_ms) < 60_000);
        let w = self.protections.scan_window_ms;
        self.scans.retain(|_, t| now_ms.saturating_sub(t.window_start_ms) <= w);
    }

    pub fn flows(&self) -> impl Iterator<Item = (&FlowKey, &Flow)> {
        self.flows.iter()
    }

    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Insert a rule before the first rule of the same direction that is a
    /// catch-all, or append.
    pub fn add_rule(&mut self, r: Rule) -> usize {
        self.rules.push(r);
        self.rules.len() - 1
    }

    pub fn remove_rule(&mut self, idx: usize) -> Option<Rule> {
        (idx < self.rules.len()).then(|| self.rules.remove(idx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ip = [10, 0, 2, 15];
    const PEER: Ip = [93, 184, 216, 34];

    fn tcp(src: Ip, dst: Ip, sport: u16, dport: u16, flags: u8) -> Packet {
        Packet { src, dst, proto: Proto::Tcp, sport, dport, tcp_flags: flags, icmp_type: 0, len: 60, fragment: false }
    }

    fn fw() -> Firewall {
        let mut f = Firewall::with_defaults();
        f.local_ips.push(ME);
        f
    }

    #[test]
    fn inbound_closed_except_ssh() {
        let mut f = fw();
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 5000, 22, tcpf::SYN), 1), Verdict::Accept);
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 5001, 80, tcpf::SYN), 2), Verdict::Drop(Reason::Policy));
    }

    #[test]
    fn replies_to_outbound_connections_pass() {
        let mut f = fw();
        assert_eq!(f.check(Dir::Out, &tcp(ME, PEER, 40000, 443, tcpf::SYN), 1), Verdict::Accept);
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 443, 40000, tcpf::SYN | tcpf::ACK), 2), Verdict::Accept);
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 443, 40000, tcpf::ACK | tcpf::PSH), 3), Verdict::Accept);
        // Same peer, different port: not part of the flow.
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 443, 40001, tcpf::ACK), 4), Verdict::Drop(Reason::Policy));
    }

    #[test]
    fn scans_and_spoofing_are_dropped() {
        let mut f = fw();
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 1, 22, 0), 1), Verdict::Drop(Reason::BadFlags));
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 1, 22, tcpf::FIN | tcpf::PSH | tcpf::URG), 1), Verdict::Drop(Reason::BadFlags));
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 1, 22, tcpf::SYN | tcpf::FIN), 1), Verdict::Drop(Reason::BadFlags));
        assert_eq!(f.check(Dir::In, &tcp([127, 0, 0, 1], ME, 1, 22, tcpf::SYN), 1), Verdict::Drop(Reason::Spoofed));
        assert_eq!(f.check(Dir::In, &tcp(ME, ME, 1, 22, tcpf::SYN), 1), Verdict::Drop(Reason::Spoofed));
    }

    #[test]
    fn port_sweep_gets_banned() {
        let mut f = fw();
        for port in 1000..1025 {
            f.check(Dir::In, &tcp(PEER, ME, 5555, port, tcpf::SYN), 100);
        }
        assert!(f.is_banned(PEER, 200));
        // Even the open SSH port is now closed to the scanner.
        assert_eq!(f.check(Dir::In, &tcp(PEER, ME, 5000, 22, tcpf::SYN), 300), Verdict::Drop(Reason::Banned));
        assert!(!f.is_banned(PEER, 100 + 3_600_001));
    }

    #[test]
    fn syn_flood_is_rate_limited() {
        let mut f = fw();
        let mut accepted = 0;
        for i in 0..200u16 {
            if f.check(Dir::In, &tcp(PEER, ME, 10000 + i, 22, tcpf::SYN), 1000) == Verdict::Accept {
                accepted += 1;
            }
        }
        assert_eq!(accepted, 40, "burst allowance");
        // A second later the bucket has refilled `rate` tokens.
        let mut later = 0;
        for i in 0..200u16 {
            if f.check(Dir::In, &tcp(PEER, ME, 20000 + i, 22, tcpf::SYN), 2000) == Verdict::Accept {
                later += 1;
            }
        }
        assert_eq!(later, 20);
    }

    #[test]
    fn repeat_bans_escalate() {
        let mut f = fw();
        assert_eq!(f.ban(PEER, 0, 1000, "test"), 1000);
        assert_eq!(f.ban(PEER, 0, 1000, "test"), 2000);
        assert_eq!(f.ban(PEER, 0, 1000, "test"), 4000);
        f.allowlist.push(Cidr::parse("192.168.0.0/16").unwrap());
        assert_eq!(f.ban([192, 168, 1, 1], 0, 1000, "test"), 0);
    }

    #[test]
    fn parses_real_frames() {
        // Ethernet + IPv4 + TCP SYN to port 22.
        let mut f = vec![0u8; 14 + 20 + 20];
        f[12] = 0x08;
        let ip = &mut f[14..];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&PEER);
        ip[16..20].copy_from_slice(&ME);
        let t = &mut ip[20..];
        t[0..2].copy_from_slice(&1234u16.to_be_bytes());
        t[2..4].copy_from_slice(&22u16.to_be_bytes());
        t[13] = tcpf::SYN;
        match parse_ethernet(&f) {
            Frame::Ipv4(p) => {
                assert_eq!((p.src, p.dst, p.proto, p.sport, p.dport, p.tcp_flags), (PEER, ME, Proto::Tcp, 1234, 22, tcpf::SYN))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(parse_ethernet(&f[..20]), Frame::Malformed);
    }

    #[test]
    fn cidr_and_ports() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains([10, 200, 3, 4]));
        assert!(!c.contains([11, 0, 0, 1]));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains([8, 8, 8, 8]));
        assert_eq!(Cidr::parse("300.1.1.1"), None);
        assert_eq!(PortRange::parse("8000-8080"), Some(PortRange { lo: 8000, hi: 8080 }));
        assert_eq!(PortRange::parse("90-80"), None);
    }
}
