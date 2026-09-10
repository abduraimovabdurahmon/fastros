//! TCP — Transmission Control Protocol (RFC 793).
//!
//! Full RFC 793 state machine:
//!
//!   CLOSED ──► LISTEN ──► SYN_RCVD ──► ESTABLISHED ──► CLOSE_WAIT ──► LAST_ACK
//!          └──► SYN_SENT ──────────────────────────────► FIN_WAIT_1
//!                                                             └──► FIN_WAIT_2 ──► TIME_WAIT
//!
//! Linux equivalent: net/ipv4/tcp.c  net/ipv4/tcp_input.c  net/ipv4/tcp_output.c

use super::checksum;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const TCP_HLEN: usize = 20;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

pub const TCP_WINDOW_DEFAULT: u16 = 65535;

// ── State machine ─────────────────────────────────────────────────────────────

/// RFC 793 §3.2 connection states.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl TcpState {
    pub fn as_str(self) -> &'static str {
        match self {
            TcpState::Closed      => "CLOSED",
            TcpState::Listen      => "LISTEN",
            TcpState::SynSent     => "SYN_SENT",
            TcpState::SynRcvd     => "SYN_RCVD",
            TcpState::Established => "ESTABLISHED",
            TcpState::FinWait1    => "FIN_WAIT1",
            TcpState::FinWait2    => "FIN_WAIT2",
            TcpState::CloseWait   => "CLOSE_WAIT",
            TcpState::Closing     => "CLOSING",
            TcpState::LastAck     => "LAST_ACK",
            TcpState::TimeWait    => "TIME_WAIT",
        }
    }
}

// ── Parsed header ─────────────────────────────────────────────────────────────

pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq:      u32,
    pub ack_seq:  u32,
    pub data_off: u8,      // header length in 32-bit words (min 5)
    pub flags:    u8,
    pub window:   u16,
    pub checksum: u16,
    pub urgent:   u16,
}

impl TcpHdr {
    pub fn header_len(&self) -> usize { (self.data_off as usize) * 4 }
    pub fn has_flag(&self, f: u8) -> bool { self.flags & f != 0 }
}

/// Parse a TCP header from raw bytes.
pub fn parse(buf: &[u8]) -> Option<(TcpHdr, &[u8])> {
    if buf.len() < TCP_HLEN { return None; }
    let data_off = (buf[12] >> 4).max(5);
    let hlen = (data_off as usize) * 4;
    if buf.len() < hlen { return None; }

    let hdr = TcpHdr {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq:      u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_seq:  u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        data_off,
        flags:    buf[13],
        window:   u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent:   u16::from_be_bytes([buf[18], buf[19]]),
    };
    Some((hdr, &buf[hlen..]))
}

// ── Packet building ───────────────────────────────────────────────────────────

/// Build a TCP segment into `buf`.
/// `pseudo_acc` = IP pseudo-header accumulator (ip::pseudo_header_acc).
/// Returns bytes written.
pub fn build(
    buf:        &mut [u8],
    src_port:   u16,
    dst_port:   u16,
    seq:        u32,
    ack_seq:    u32,
    flags:      u8,
    window:     u16,
    payload:    &[u8],
    pseudo_acc: u32,
) -> usize {
    let total = TCP_HLEN + payload.len();
    if buf.len() < total { return 0; }

    buf[0..2].copy_from_slice(&src_port.to_be_bytes());
    buf[2..4].copy_from_slice(&dst_port.to_be_bytes());
    buf[4..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..12].copy_from_slice(&ack_seq.to_be_bytes());
    buf[12] = 5 << 4;                                  // data offset = 5 words = 20 bytes
    buf[13] = flags;
    buf[14..16].copy_from_slice(&window.to_be_bytes());
    buf[16..18].copy_from_slice(&[0, 0]);               // checksum placeholder
    buf[18..20].copy_from_slice(&[0, 0]);               // urgent pointer

    if !payload.is_empty() {
        buf[TCP_HLEN..total].copy_from_slice(payload);
    }

    // TCP checksum = pseudo-header + TCP segment
    let acc = checksum::accumulate(&buf[..total], pseudo_acc);
    let ck  = checksum::fold(acc);
    buf[16..18].copy_from_slice(&ck.to_be_bytes());
    total
}

// ── Connection control block ──────────────────────────────────────────────────

const RX_BUF_SIZE: usize = 4096;
const TX_BUF_SIZE: usize = 4096;

/// TCP connection control block (like Linux's struct tcp_sock).
pub struct TcpCb {
    pub state:     TcpState,
    pub local_ip:  [u8; 4],
    pub local_port: u16,
    pub peer_ip:   [u8; 4],
    pub peer_port: u16,

    // Send sequence variables (RFC 793 §3.2)
    pub snd_una:   u32,   // oldest unacknowledged seq
    pub snd_nxt:   u32,   // next seq to send
    pub snd_wnd:   u16,   // send window (peer's window)

    // Receive sequence variables
    pub rcv_nxt:   u32,   // next seq expected from peer
    pub rcv_wnd:   u16,   // our receive window

    // Buffers
    pub rx_buf:    [u8; RX_BUF_SIZE],
    pub rx_head:   usize,
    pub rx_tail:   usize,
    pub tx_buf:    [u8; TX_BUF_SIZE],
    pub tx_head:   usize,
    pub tx_tail:   usize,

    /// Device index used for sending replies
    pub dev_idx:   usize,
}

impl TcpCb {
    pub const fn new() -> Self {
        Self {
            state: TcpState::Closed,
            local_ip: [0;4], local_port: 0,
            peer_ip: [0;4],  peer_port: 0,
            snd_una: 0, snd_nxt: 0, snd_wnd: 0,
            rcv_nxt: 0, rcv_wnd: TCP_WINDOW_DEFAULT,
            rx_buf: [0; RX_BUF_SIZE], rx_head: 0, rx_tail: 0,
            tx_buf: [0; TX_BUF_SIZE], tx_head: 0, tx_tail: 0,
            dev_idx: 0,
        }
    }

    // RX ring buffer helpers
    pub fn rx_available(&self) -> usize {
        (self.rx_tail + RX_BUF_SIZE - self.rx_head) % RX_BUF_SIZE
    }

    pub fn rx_push(&mut self, data: &[u8]) {
        for &b in data {
            let next = (self.rx_tail + 1) % RX_BUF_SIZE;
            if next != self.rx_head {
                self.rx_buf[self.rx_tail] = b;
                self.rx_tail = next;
            }
        }
    }

    pub fn rx_pop(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n < buf.len() && self.rx_head != self.rx_tail {
            buf[n] = self.rx_buf[self.rx_head];
            self.rx_head = (self.rx_head + 1) % RX_BUF_SIZE;
            n += 1;
        }
        n
    }
}
