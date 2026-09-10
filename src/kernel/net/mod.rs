//! Network subsystem — Layer 2 (kernel).
//!
//! Implements the Linux-style protocol stack:
//!
//!   RX: driver → receive_frame() → eth_rcv() → arp_rcv() | ip_rcv()
//!                                                           └→ icmp_rcv() | udp_rcv() | tcp_rcv()
//!
//!   TX: send_ipv4() → route → arp_resolve() → eth_build() → SEND_FN (driver callback)
//!
//! Architecture constraint: kernel/net/ cannot import drivers/net/ directly.
//! Drivers register a send callback (like Linux's ndo_start_xmit function pointer).
//!
//! Linux equivalent: net/core/dev.c  net/ipv4/af_inet.c

pub mod arp;
pub mod checksum;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod route;
pub mod socket;
pub mod ssh;
pub mod tcp;
pub mod udp;

use crate::kernel::sync::spinlock::SpinLock;

// ── Network device registry ───────────────────────────────────────────────────
//
// Up to MAX_DEVS devices may be registered.
// Each entry stores the device's MAC + IP config + a TX function pointer.
// This is how kernel/net/ calls into drivers without importing drivers/.

const MAX_DEVS: usize = 4;

type SendFn = fn(frame: &[u8]) -> bool;

struct NetDev {
    pub name:    [u8; 16],
    pub name_len: usize,
    pub mac:     [u8; 6],
    pub ip:      [u8; 4],
    pub netmask: [u8; 4],
    pub gateway: [u8; 4],
    pub mtu:     u16,
    pub up:      bool,
    pub loopback: bool,
    send:        Option<SendFn>,
}

impl NetDev {
    const fn empty() -> Self {
        Self {
            name: [0;16], name_len: 0,
            mac: [0;6], ip: [0;4], netmask: [0;4], gateway: [0;4],
            mtu: 1500, up: false, loopback: false, send: None,
        }
    }
}

static NET_LOCK: SpinLock = SpinLock::new();
static mut DEVS: [NetDev; MAX_DEVS] = [const { NetDev::empty() }; MAX_DEVS];
static mut DEV_COUNT: usize = 0;

// ── Device registration ───────────────────────────────────────────────────────

pub struct DevConfig<'a> {
    pub name:     &'a [u8],
    pub mac:      [u8; 6],
    pub ip:       [u8; 4],
    pub netmask:  [u8; 4],
    pub gateway:  [u8; 4],
    pub mtu:      u16,
    pub loopback: bool,
    pub send_fn:  SendFn,
}

/// Register a network device. Called by drivers during their init.
/// Returns the assigned device index, or None if table is full.
pub fn register_device(cfg: DevConfig) -> Option<usize> {
    NET_LOCK.lock();
    let idx = unsafe {
        if DEV_COUNT >= MAX_DEVS { NET_LOCK.unlock(); return None; }
        let d = &mut DEVS[DEV_COUNT];
        let nlen = cfg.name.len().min(15);
        d.name[..nlen].copy_from_slice(&cfg.name[..nlen]);
        d.name_len = nlen;
        d.mac      = cfg.mac;
        d.ip       = cfg.ip;
        d.netmask  = cfg.netmask;
        d.gateway  = cfg.gateway;
        d.mtu      = cfg.mtu;
        d.loopback = cfg.loopback;
        d.send     = Some(cfg.send_fn);
        d.up       = true;
        let i = DEV_COUNT;
        DEV_COUNT += 1;
        i
    };
    NET_LOCK.unlock();

    // Add routes for this device
    let (ip, mask, gw, lo) = unsafe {
        let d = &DEVS[idx];
        (d.ip, d.netmask, d.gateway, d.loopback)
    };

    // Local network route (directly connected)
    let net = [
        ip[0] & mask[0], ip[1] & mask[1],
        ip[2] & mask[2], ip[3] & mask[3],
    ];
    route::add(net, mask, [0,0,0,0], idx, 0);

    if lo {
        // Loopback route: 127.0.0.0/8
        route::add([127,0,0,0], [255,0,0,0], [0,0,0,0], idx, 0);
    } else if gw != [0u8;4] {
        // Default gateway (0.0.0.0/0)
        route::add([0,0,0,0], [0,0,0,0], gw, idx, 100);
    }

    Some(idx)
}

// ── Public accessors ──────────────────────────────────────────────────────────

pub struct DevInfo {
    pub name:     [u8; 16],
    pub name_len: usize,
    pub mac:      [u8; 6],
    pub ip:       [u8; 4],
    pub netmask:  [u8; 4],
    pub gateway:  [u8; 4],
    pub mtu:      u16,
    pub up:       bool,
    pub loopback: bool,
}

pub fn dev_count() -> usize { unsafe { DEV_COUNT } }

pub fn dev_info(idx: usize) -> Option<DevInfo> {
    unsafe {
        if idx >= DEV_COUNT { return None; }
        let d = &DEVS[idx];
        Some(DevInfo {
            name: d.name, name_len: d.name_len,
            mac: d.mac, ip: d.ip, netmask: d.netmask, gateway: d.gateway,
            mtu: d.mtu, up: d.up, loopback: d.loopback,
        })
    }
}

/// Get the primary (non-loopback) device's IP address.
pub fn primary_ip() -> [u8; 4] {
    unsafe {
        for i in 0..DEV_COUNT {
            if !DEVS[i].loopback && DEVS[i].up {
                return DEVS[i].ip;
            }
        }
    }
    [0, 0, 0, 0]
}

/// Get the primary device's MAC address.
pub fn primary_mac() -> [u8; 6] {
    unsafe {
        for i in 0..DEV_COUNT {
            if !DEVS[i].loopback && DEVS[i].up {
                return DEVS[i].mac;
            }
        }
    }
    [0; 6]
}

// ── Transmit path ─────────────────────────────────────────────────────────────

/// Single static TX scratch buffer (safe: single-threaded kernel).
static mut TX_BUF: [u8; 1600] = [0; 1600];

/// Send an IPv4 packet. Handles routing, ARP resolution, and Ethernet framing.
/// `payload` is the IP payload (ICMP/UDP/TCP already in buf beyond IP header).
/// `protocol` is IPPROTO_ICMP/TCP/UDP.
///
/// Linux analogue: ip_output() → ip_finish_output() → neigh_output() → dev_queue_xmit()
pub fn send_ipv4(
    dst_ip:   &[u8; 4],
    protocol: u8,
    payload:  &[u8],
) -> bool {
    // 1. Route lookup
    let hop = match route::lookup(dst_ip) {
        Some(h) => h,
        None    => return false,   // no route to host
    };

    let (our_ip, our_mac, our_mtu) = unsafe {
        let d = &DEVS[hop.dev_idx];
        (d.ip, d.mac, d.mtu)
    };

    let total = eth::ETH_HLEN + ip::IP_HLEN + payload.len();
    if total > our_mtu as usize + eth::ETH_HLEN { return false; }

    // 2. Determine next-hop IP for ARP
    let nexthop_ip: &[u8; 4] = if hop.gateway == [0u8; 4] {
        dst_ip
    } else {
        &hop.gateway
    };

    // 3. ARP resolution — if not cached, send ARP request and return false
    //    (caller must retry; Linux uses neighbour queue but we keep it simple)
    let dst_mac = match arp::lookup(nexthop_ip) {
        Some(m) => m,
        None    => {
            // Send ARP request and signal "not ready yet"
            unsafe {
                let n = arp::build_request(
                    &mut TX_BUF, &our_mac, &our_ip, nexthop_ip
                );
                raw_send(hop.dev_idx, &TX_BUF[..n]);
            }
            return false;
        }
    };

    // 4. Build Ethernet + IP + payload
    let frame_len = eth::ETH_HLEN + ip::IP_HLEN + payload.len();
    unsafe {
        eth::build(&mut TX_BUF, &dst_mac, &our_mac, eth::ETH_P_IP);
        ip::build(
            &mut TX_BUF[eth::ETH_HLEN..],
            &our_ip, dst_ip, protocol,
            payload.len(),
            ip::next_id(), ip::TTL_DEFAULT,
        );
        TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..frame_len]
            .copy_from_slice(payload);
        raw_send(hop.dev_idx, &TX_BUF[..frame_len])
    }
}

/// Send an ARP frame directly (no IP layer).
pub fn send_arp(dev_idx: usize, frame: &[u8]) -> bool {
    raw_send(dev_idx, frame)
}

/// Send data on an established TCP connection identified by socket fd.
/// Builds a TCP PSH+ACK segment and sends it via the routing table.
/// Returns true on success.
///
/// Linux analogue: tcp_sendmsg() → tcp_write_xmit()
pub fn tcp_send(fd: usize, data: &[u8]) -> bool {
    if data.is_empty() { return true; }

    // Snapshot the socket state we need (avoid holding borrow during send)
    let (peer_ip, peer_port, local_port, snd_nxt, rcv_nxt) = {
        let s = match socket::get_mut(fd) { Some(s) => s, None => return false };
        if s.tcp_state != tcp::TcpState::Established { return false; }
        (s.peer_ip, s.peer_port, s.local_port, s.snd_nxt, s.rcv_nxt)
    };

    // Route lookup
    let hop = match route::lookup(&peer_ip) { Some(h) => h, None => return false };
    let nexthop: [u8; 4] = if hop.gateway == [0u8; 4] { peer_ip } else { hop.gateway };
    let dst_mac = match arp::lookup(&nexthop) { Some(m) => m, None => return false };

    let our_ip  = unsafe { DEVS[hop.dev_idx].ip };
    let our_mac = unsafe { DEVS[hop.dev_idx].mac };

    let seg_len = (tcp::TCP_HLEN + data.len()) as u16;
    let pseudo  = ip::pseudo_header_acc(&our_ip, &peer_ip, ip::IPPROTO_TCP, seg_len);

    let sent = unsafe {
        let tcp_len = tcp::build(
            &mut TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..],
            local_port, peer_port,
            snd_nxt, rcv_nxt,
            tcp::TCP_ACK | tcp::TCP_PSH, tcp::TCP_WINDOW_DEFAULT,
            data, pseudo,
        );
        if tcp_len == 0 { return false; }
        // Copy TCP segment to temp buffer to avoid aliasing TX_BUF
        let mut tmp = [0u8; 1500];
        tmp[..tcp_len].copy_from_slice(
            &TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..eth::ETH_HLEN + ip::IP_HLEN + tcp_len]
        );
        let n = build_ip_frame(
            &mut TX_BUF, &our_mac, &dst_mac, &our_ip, &peer_ip,
            ip::IPPROTO_TCP, &tmp[..tcp_len],
        );
        raw_send(hop.dev_idx, &TX_BUF[..n])
    };

    if sent {
        // Advance send sequence number
        if let Some(s) = socket::get_mut(fd) {
            s.snd_nxt = s.snd_nxt.wrapping_add(data.len() as u32);
        }
    }
    sent
}

/// Bypass IP stack and send a raw Ethernet frame via device `dev_idx`.
fn raw_send(dev_idx: usize, frame: &[u8]) -> bool {
    unsafe {
        if dev_idx >= DEV_COUNT { return false; }
        if let Some(f) = DEVS[dev_idx].send {
            return f(frame);
        }
    }
    false
}

// ── Receive path ──────────────────────────────────────────────────────────────

/// Static RX dispatch scratch — avoids stack allocation in interrupt context.
static mut RX_SCRATCH: [u8; 1600] = [0; 1600];

/// Called by NIC drivers when a frame arrives.
/// Dispatches to ARP or IP protocol handlers.
///
/// Linux analogue: netif_receive_skb() → deliver_skb() → eth_type_trans()
pub fn receive_frame(frame: &[u8], dev_idx: usize) {
    let (eth_hdr, payload) = match eth::parse(frame) {
        Some(x) => x,
        None    => return,
    };

    match eth_hdr.ethertype {
        eth::ETH_P_ARP => eth_rcv_arp(payload, dev_idx, &eth_hdr.dst),
        eth::ETH_P_IP  => {
            // Linux: neigh_update() is called on every received packet.
            // Learn the sender's IP→MAC mapping so we can reply without ARP.
            if let Some((ref ip_hdr, _)) = ip::parse(payload) {
                arp::cache_update(&ip_hdr.src, &eth_hdr.src);
            }
            eth_rcv_ip(payload, dev_idx)
        }
        _              => {}   // unknown ethertype — drop
    }
}

fn eth_rcv_arp(payload: &[u8], dev_idx: usize, dst_mac: &[u8; 6]) {
    let pkt = match arp::parse(payload) {
        Some(p) => p,
        None    => return,
    };

    let our_ip = unsafe {
        if dev_idx >= DEV_COUNT { return; }
        DEVS[dev_idx].ip
    };

    // If this ARP request targets us, send a reply
    if pkt.op == arp::ARP_OP_REQUEST && &pkt.tpa == &our_ip {
        let our_mac = unsafe { DEVS[dev_idx].mac };
        unsafe {
            let n = arp::build_reply(
                &mut TX_BUF, &our_mac, &our_ip, &pkt.sha, &pkt.spa
            );
            raw_send(dev_idx, &TX_BUF[..n]);
        }
    }
    // Cache is already updated inside arp::parse()
    let _ = dst_mac;
}

fn eth_rcv_ip(payload: &[u8], dev_idx: usize) {
    let (ip_hdr, ip_payload) = match ip::parse(payload) {
        Some(x) => x,
        None    => return,
    };

    // Drop fragments — we don't support reassembly
    if ip_hdr.is_fragment() { return; }

    let our_ip = unsafe {
        if dev_idx >= DEV_COUNT { return; }
        DEVS[dev_idx].ip
    };

    // Accept unicast to our IP, broadcasts, and loopback
    let loopback = unsafe { DEVS[dev_idx].loopback };
    let is_for_us = &ip_hdr.dst == &our_ip
        || ip_hdr.dst == [255,255,255,255]
        || (loopback && ip_hdr.dst[0] == 127);

    if !is_for_us { return; }

    match ip_hdr.protocol {
        ip::IPPROTO_ICMP => rcv_icmp(&ip_hdr, ip_payload, dev_idx),
        ip::IPPROTO_UDP  => rcv_udp(&ip_hdr, ip_payload),
        ip::IPPROTO_TCP  => rcv_tcp(&ip_hdr, ip_payload, dev_idx),
        _                => {}
    }
}

// ── ICMP receive ──────────────────────────────────────────────────────────────

static mut ICMP_RX: [u8; 1600] = [0; 1600];

fn rcv_icmp(ip_hdr: &ip::IpHdr, payload: &[u8], dev_idx: usize) {
    let (icmp, data) = match icmp::parse(payload) {
        Some(x) => x,
        None    => return,
    };

    if !icmp::verify_checksum(payload) { return; }

    match icmp.type_ {
        icmp::ICMP_ECHO_REQUEST => {
            // Build and send echo reply
            let our_ip = unsafe { DEVS[dev_idx].ip };
            let reply_len = icmp::build_echo_reply(
                unsafe { &mut ICMP_RX[ip::IP_HLEN..] },
                icmp.id(), icmp.seq(), data,
            );
            if reply_len == 0 { return; }

            // Copy original ICMP payload into scratch to avoid borrow issues
            let frame_total = eth::ETH_HLEN + ip::IP_HLEN + reply_len;
            let dst_ip = ip_hdr.src;
            let hop = match route::lookup(&dst_ip) { Some(h) => h, None => return };
            let our_mac = unsafe { DEVS[dev_idx].mac };

            let nexthop: &[u8; 4] = if hop.gateway == [0u8;4] { &dst_ip } else { &hop.gateway };
            let dst_mac = match arp::lookup(nexthop) { Some(m) => m, None => return };

            unsafe {
                let _ = frame_total;
                let n = build_ip_frame(
                    &mut TX_BUF,
                    &our_mac, &dst_mac,
                    &our_ip, &dst_ip,
                    ip::IPPROTO_ICMP,
                    &ICMP_RX[ip::IP_HLEN..ip::IP_HLEN + reply_len],
                );
                raw_send(dev_idx, &TX_BUF[..n]);
            }
        }
        icmp::ICMP_ECHO_REPLY => {
            // Deliver to raw sockets listening for ICMP
            if let Some(fd) = socket::find_raw(socket::IPPROTO_ICMP) {
                if let Some(s) = socket::get_mut(fd) {
                    s.rx_push(payload);
                }
            }
        }
        _ => {}
    }
}

// ── UDP receive ───────────────────────────────────────────────────────────────

fn rcv_udp(ip_hdr: &ip::IpHdr, payload: &[u8]) {
    let (udp_hdr, data) = match udp::parse(payload) {
        Some(x) => x,
        None    => return,
    };

    if let Some(fd) = socket::find_udp(udp_hdr.dst_port) {
        if let Some(s) = socket::get_mut(fd) {
            // Deliver payload with 4-byte src_ip prefix for recvfrom()
            s.rx_push(&ip_hdr.src);
            s.rx_push(&udp_hdr.src_port.to_be_bytes());
            s.rx_push(data);
        }
    }
}

// ── TCP receive ───────────────────────────────────────────────────────────────

fn rcv_tcp(ip_hdr: &ip::IpHdr, payload: &[u8], dev_idx: usize) {
    let (tcp_hdr, data) = match tcp::parse(payload) {
        Some(x) => x,
        None    => return,
    };

    // Find or create connection
    let fd = socket::find_tcp(
        &ip_hdr.dst, tcp_hdr.dst_port,
        &ip_hdr.src, tcp_hdr.src_port,
    );

    let fd = match fd {
        Some(f) => f,
        None    => {
            // No socket — send RST
            send_tcp_rst(ip_hdr, &tcp_hdr, dev_idx);
            return;
        }
    };

    // Linux-style: LISTEN socket stays in LISTEN; SYN creates a child socket.
    // Read state and local_port with a shared (immutable) borrow, then release it.
    let (is_listen, local_port) = {
        let s = match socket::get(fd) { Some(s) => s, None => return };
        (s.tcp_state == tcp::TcpState::Listen, s.local_port)
    };

    if is_listen {
        // Only respond to SYN; everything else is silently dropped on LISTEN.
        if tcp_hdr.has_flag(tcp::TCP_SYN) {
            tcp_handle_syn(ip_hdr, &tcp_hdr, local_port, dev_idx);
        }
        return;
    }

    let s = match socket::get_mut(fd) { Some(s) => s, None => return };

    // Run the TCP state machine
    tcp_input(s, &tcp_hdr, data, ip_hdr, dev_idx);
}

/// Handle an incoming SYN on a LISTEN socket.
/// Linux equivalent: tcp_conn_request() — creates a child (request) socket
/// and sends SYN-ACK; the LISTEN socket is untouched.
fn tcp_handle_syn(
    ip_hdr:     &ip::IpHdr,
    hdr:        &tcp::TcpHdr,
    local_port: u16,
    dev_idx:    usize,
) {
    // Allocate a fresh socket for this connection (the "child" socket).
    let child_fd = match socket::socket(
        socket::AF_INET, socket::SOCK_STREAM, socket::IPPROTO_TCP,
    ) {
        Some(f) => f,
        None    => return,   // socket pool exhausted
    };

    if let Some(child) = socket::get_mut(child_fd) {
        child.local_ip   = ip_hdr.dst;
        child.local_port = local_port;
        child.peer_ip    = ip_hdr.src;
        child.peer_port  = hdr.src_port;
        child.rcv_nxt    = hdr.seq.wrapping_add(1);
        child.snd_nxt    = 0x12345678; // ISN
        child.snd_una    = child.snd_nxt;
        child.tcp_state  = tcp::TcpState::SynRcvd;

        tcp_send_flags(child, ip_hdr, dev_idx, tcp::TCP_SYN | tcp::TCP_ACK, &[]);
        child.snd_nxt = child.snd_nxt.wrapping_add(1);
    }
}

/// Minimal TCP input state machine (RFC 793 §3.9).
fn tcp_input(
    s:       &mut socket::Socket,
    hdr:     &tcp::TcpHdr,
    data:    &[u8],
    ip_hdr:  &ip::IpHdr,
    dev_idx: usize,
) {
    use tcp::{TcpState, TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST};

    match s.tcp_state {
        // LISTEN is handled in rcv_tcp via tcp_handle_syn() before tcp_input is
        // called, so this branch should never be reached.
        TcpState::Listen => {}

        // ── SYN_SENT: we sent SYN, waiting for SYN-ACK ──────────────────────
        TcpState::SynSent => {
            if !hdr.has_flag(TCP_SYN) || !hdr.has_flag(TCP_ACK) { return; }
            s.rcv_nxt   = hdr.seq.wrapping_add(1);
            s.snd_una   = hdr.ack_seq;
            s.tcp_state = TcpState::Established;
            // Send ACK
            tcp_send_flags(s, ip_hdr, dev_idx, TCP_ACK, &[]);
        }

        // ── SYN_RCVD: we sent SYN-ACK, waiting for ACK ──────────────────────
        TcpState::SynRcvd => {
            if hdr.has_flag(TCP_ACK) {
                s.snd_una   = hdr.ack_seq;
                s.tcp_state = TcpState::Established;
            }
        }

        // ── ESTABLISHED ──────────────────────────────────────────────────────
        TcpState::Established => {
            if hdr.has_flag(TCP_RST) {
                s.tcp_state = TcpState::Closed;
                return;
            }
            if hdr.has_flag(TCP_ACK) {
                s.snd_una = hdr.ack_seq;
            }
            if !data.is_empty() {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(data.len() as u32);
                s.rx_push(data);
                // Send ACK
                tcp_send_flags(s, ip_hdr, dev_idx, TCP_ACK, &[]);
            }
            if hdr.has_flag(TCP_FIN) {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                s.tcp_state = TcpState::CloseWait;
                tcp_send_flags(s, ip_hdr, dev_idx, TCP_ACK, &[]);
            }
        }

        // ── CLOSE_WAIT: we received FIN, waiting for app to close ────────────
        TcpState::CloseWait => {
            if hdr.has_flag(TCP_ACK) { s.snd_una = hdr.ack_seq; }
        }

        // ── LAST_ACK: we sent FIN, waiting for final ACK ─────────────────────
        TcpState::LastAck => {
            if hdr.has_flag(TCP_ACK) {
                s.tcp_state = TcpState::Closed;
            }
        }

        // ── FIN_WAIT_1: we sent FIN, waiting for ACK ─────────────────────────
        TcpState::FinWait1 => {
            if hdr.has_flag(TCP_ACK) {
                s.snd_una   = hdr.ack_seq;
                s.tcp_state = TcpState::FinWait2;
            }
            if hdr.has_flag(TCP_FIN) {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                tcp_send_flags(s, ip_hdr, dev_idx, TCP_ACK, &[]);
                s.tcp_state = TcpState::TimeWait;
            }
        }

        // ── FIN_WAIT_2: our FIN acked, waiting for peer's FIN ────────────────
        TcpState::FinWait2 => {
            if hdr.has_flag(TCP_FIN) {
                s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
                tcp_send_flags(s, ip_hdr, dev_idx, TCP_ACK, &[]);
                s.tcp_state = TcpState::TimeWait;
            }
        }

        _ => {}
    }
}

/// Build and send a TCP segment with given flags and payload.
fn tcp_send_flags(
    s:      &mut socket::Socket,
    ip_hdr: &ip::IpHdr,
    dev_idx: usize,
    flags:  u8,
    data:   &[u8],
) {
    let our_ip  = unsafe { DEVS[dev_idx].ip };
    let our_mac = unsafe { DEVS[dev_idx].mac };

    let nexthop: [u8;4] = unsafe {
        match route::lookup(&ip_hdr.src) {
            Some(h) => if h.gateway == [0u8;4] { ip_hdr.src } else { h.gateway },
            None    => return,
        }
    };
    let dst_mac = match arp::lookup(&nexthop) { Some(m) => m, None => return };

    let seg_len = (tcp::TCP_HLEN + data.len()) as u16;
    let pseudo  = ip::pseudo_header_acc(&our_ip, &ip_hdr.src, ip::IPPROTO_TCP, seg_len);

    unsafe {
        let tcp_len = tcp::build(
            &mut TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..],
            s.local_port, s.peer_port,
            s.snd_nxt, s.rcv_nxt,
            flags, tcp::TCP_WINDOW_DEFAULT,
            data, pseudo,
        );
        if tcp_len == 0 { return; }
        let n = build_ip_frame(
            &mut TX_BUF,
            &our_mac, &dst_mac,
            &our_ip, &ip_hdr.src,
            ip::IPPROTO_TCP,
            &{
                // copy tcp segment into local array to avoid aliasing
                let mut tmp = [0u8; 1500];
                tmp[..tcp_len].copy_from_slice(
                    &TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..eth::ETH_HLEN + ip::IP_HLEN + tcp_len]
                );
                tmp
            }[..tcp_len],
        );
        raw_send(dev_idx, &TX_BUF[..n]);
    }
}

/// Send RST in response to an unexpected TCP segment.
fn send_tcp_rst(ip_hdr: &ip::IpHdr, tcp_hdr: &tcp::TcpHdr, dev_idx: usize) {
    let our_ip  = unsafe { DEVS[dev_idx].ip };
    let our_mac = unsafe { DEVS[dev_idx].mac };
    let nexthop = if let Some(h) = route::lookup(&ip_hdr.src) {
        if h.gateway == [0u8;4] { ip_hdr.src } else { h.gateway }
    } else { return };
    let dst_mac = match arp::lookup(&nexthop) { Some(m) => m, None => return };

    let seg_len = tcp::TCP_HLEN as u16;
    let pseudo  = ip::pseudo_header_acc(&our_ip, &ip_hdr.src, ip::IPPROTO_TCP, seg_len);
    unsafe {
        let ack = tcp_hdr.seq.wrapping_add(1);
        let tcp_len = tcp::build(
            &mut TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..],
            tcp_hdr.dst_port, tcp_hdr.src_port,
            0, ack,
            tcp::TCP_RST | tcp::TCP_ACK, 0,
            &[], pseudo,
        );
        let tmp: [u8; 20] = TX_BUF[eth::ETH_HLEN + ip::IP_HLEN..eth::ETH_HLEN + ip::IP_HLEN + 20]
            .try_into().unwrap_or([0;20]);
        let n = build_ip_frame(
            &mut TX_BUF, &our_mac, &dst_mac,
            &our_ip, &ip_hdr.src, ip::IPPROTO_TCP, &tmp[..tcp_len],
        );
        raw_send(dev_idx, &TX_BUF[..n]);
    }
}

// ── Frame building helper ─────────────────────────────────────────────────────

/// Build Ethernet + IPv4 frame into `buf`. Returns total frame length.
fn build_ip_frame(
    buf:      &mut [u8],
    src_mac:  &[u8; 6],
    dst_mac:  &[u8; 6],
    src_ip:   &[u8; 4],
    dst_ip:   &[u8; 4],
    proto:    u8,
    payload:  &[u8],
) -> usize {
    eth::build(buf, dst_mac, src_mac, eth::ETH_P_IP);
    ip::build(
        &mut buf[eth::ETH_HLEN..],
        src_ip, dst_ip, proto,
        payload.len(), ip::next_id(), ip::TTL_DEFAULT,
    );
    let off = eth::ETH_HLEN + ip::IP_HLEN;
    buf[off..off + payload.len()].copy_from_slice(payload);
    off + payload.len()
}

// ── Initialization ────────────────────────────────────────────────────────────

/// Called from kernel_main after drivers are initialised.
pub fn init() {
    // Routes are added in register_device().
    // Drivers call register_device() from drivers::net::init().
    // Nothing else to do here — device-specific setup is in drivers/.
}

/// Poll all registered network drivers for incoming frames.
/// Called from the shell loop and from ping to receive replies.
/// (Avoids circular dependency: kernel/net → drivers/net via fn pointer)
pub fn poll_drivers() {
    // The actual driver poll is registered as a separate callback.
    // For now, call the global poll hook if set.
    if let Some(f) = unsafe { POLL_FN } { f(); }
}

type PollFn = fn();
static mut POLL_FN: Option<PollFn> = None;

/// Called by drivers::net to register their poll function.
pub fn register_poll(f: PollFn) {
    unsafe { POLL_FN = Some(f); }
}
