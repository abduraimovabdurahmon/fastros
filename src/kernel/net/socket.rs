//! BSD socket API.
//!
//! Provides the socket(), bind(), connect(), send(), recv(), close() interface.
//! Sockets are allocated from a fixed-size static pool.
//!
//! Linux equivalent: net/socket.c  include/linux/net.h

use super::tcp::TcpState;

// ── Address families and socket types ─────────────────────────────────────────

pub const AF_INET:     u8 = 2;
pub const SOCK_STREAM: u8 = 1;   // TCP
pub const SOCK_DGRAM:  u8 = 2;   // UDP
pub const SOCK_RAW:    u8 = 3;   // Raw IP (for ping)

pub const IPPROTO_IP:   u8 = 0;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP:  u8 = 6;
pub const IPPROTO_UDP:  u8 = 17;

// ── Socket ────────────────────────────────────────────────────────────────────

const MAX_SOCKETS: usize = 16;
const SOCK_BUF:    usize = 8192;

#[derive(Copy, Clone, PartialEq)]
enum SockKind {
    Free,
    Udp,
    Tcp,
    Raw,
}

pub struct Socket {
    kind:       SockKind,
    pub proto:  u8,

    pub local_ip:   [u8; 4],
    pub local_port: u16,
    pub peer_ip:    [u8; 4],
    pub peer_port:  u16,

    pub tcp_state:  TcpState,
    pub snd_nxt:    u32,
    pub rcv_nxt:    u32,
    pub snd_una:    u32,
    pub snd_wnd:    u16,

    rx_buf:  [u8; SOCK_BUF],
    rx_head: usize,
    rx_tail: usize,
}

impl Socket {
    const fn new() -> Self {
        Self {
            kind: SockKind::Free,
            proto: 0,
            local_ip: [0;4], local_port: 0,
            peer_ip: [0;4],  peer_port: 0,
            tcp_state: TcpState::Closed,
            snd_nxt: 0, rcv_nxt: 0, snd_una: 0, snd_wnd: 0,
            rx_buf: [0; SOCK_BUF], rx_head: 0, rx_tail: 0,
        }
    }

    // ── RX ring buffer ────────────────────────────────────────────────────────

    pub fn rx_push(&mut self, data: &[u8]) {
        for &b in data {
            let next = (self.rx_tail + 1) % SOCK_BUF;
            if next != self.rx_head {
                self.rx_buf[self.rx_tail] = b;
                self.rx_tail = next;
            }
        }
    }

    pub fn rx_pop(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() && self.rx_head != self.rx_tail {
            out[n] = self.rx_buf[self.rx_head];
            self.rx_head = (self.rx_head + 1) % SOCK_BUF;
            n += 1;
        }
        n
    }

    pub fn rx_available(&self) -> usize {
        (self.rx_tail + SOCK_BUF - self.rx_head) % SOCK_BUF
    }
}

static mut POOL: [Socket; MAX_SOCKETS] = [const { Socket::new() }; MAX_SOCKETS];

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate a new socket. Returns socket file descriptor (index) or None.
///
/// Linux: sys_socket(AF_INET, SOCK_STREAM/DGRAM/RAW, proto)
pub fn socket(family: u8, type_: u8, proto: u8) -> Option<usize> {
    if family != AF_INET { return None; }
    unsafe {
        for (i, s) in POOL.iter_mut().enumerate() {
            if s.kind == SockKind::Free {
                *s = Socket::new();
                s.kind = match type_ {
                    SOCK_STREAM => SockKind::Tcp,
                    SOCK_DGRAM  => SockKind::Udp,
                    SOCK_RAW    => SockKind::Raw,
                    _           => return None,
                };
                s.proto = proto;
                return Some(i);
            }
        }
    }
    None
}

/// Close a socket.
pub fn close(fd: usize) {
    if fd < MAX_SOCKETS {
        unsafe { POOL[fd].kind = SockKind::Free; }
    }
}

pub fn get(fd: usize) -> Option<&'static Socket> {
    if fd >= MAX_SOCKETS { return None; }
    unsafe {
        let s = &POOL[fd];
        if s.kind != SockKind::Free { Some(s) } else { None }
    }
}

pub fn get_mut(fd: usize) -> Option<&'static mut Socket> {
    if fd >= MAX_SOCKETS { return None; }
    unsafe {
        let s = &mut POOL[fd];
        if s.kind != SockKind::Free { Some(s) } else { None }
    }
}

/// Find a UDP socket listening on the given local port.
pub fn find_udp(local_port: u16) -> Option<usize> {
    unsafe {
        for (i, s) in POOL.iter().enumerate() {
            if s.kind == SockKind::Udp && s.local_port == local_port {
                return Some(i);
            }
        }
    }
    None
}

/// Find a TCP socket matching the 4-tuple.
pub fn find_tcp(local_ip: &[u8;4], local_port: u16, peer_ip: &[u8;4], peer_port: u16)
    -> Option<usize>
{
    unsafe {
        for (i, s) in POOL.iter().enumerate() {
            if s.kind == SockKind::Tcp
                && s.local_port == local_port
                && &s.local_ip == local_ip
                && s.peer_port == peer_port
                && &s.peer_ip  == peer_ip
            {
                return Some(i);
            }
        }
        // Also check listening socket (peer = 0:0)
        for (i, s) in POOL.iter().enumerate() {
            if s.kind == SockKind::Tcp
                && s.local_port == local_port
                && s.tcp_state  == TcpState::Listen
            {
                return Some(i);
            }
        }
    }
    None
}

/// Find the first TCP socket on `local_port` that is past the LISTEN state
/// (i.e. SYN_RCVD or ESTABLISHED). Used by the SSH server to detect
/// incoming connections without requiring an exact 4-tuple match.
pub fn find_tcp_established(local_port: u16) -> Option<usize> {
    use super::tcp::TcpState;
    unsafe {
        for (i, s) in POOL.iter().enumerate() {
            if s.kind == SockKind::Tcp
                && s.local_port == local_port
                && matches!(s.tcp_state, TcpState::SynRcvd | TcpState::Established)
            {
                return Some(i);
            }
        }
    }
    None
}

/// Find a RAW socket for the given protocol.
pub fn find_raw(proto: u8) -> Option<usize> {
    unsafe {
        for (i, s) in POOL.iter().enumerate() {
            if s.kind == SockKind::Raw && s.proto == proto {
                return Some(i);
            }
        }
    }
    None
}
