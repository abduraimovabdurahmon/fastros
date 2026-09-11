//! Minimal HTTP/1.1 client over TCP.
//!
//! Supports GET requests with arbitrary headers.
//! Response headers are parsed for Status-Code and Content-Length.
//! Body is buffered up to HTTP_BUF_SIZE bytes (8 KiB) — enough for manifests.
//!
//! Supports both plain HTTP and HTTPS (TLS 1.3 via tls.rs).

use crate::kernel::net::{self, tcp};
use super::Output;

pub const HTTP_BUF_SIZE: usize = 8192;

/// Result of a successful HTTP request.
pub struct HttpResp {
    pub status: u16,
    /// Response body (up to HTTP_BUF_SIZE bytes).
    pub body:   [u8; HTTP_BUF_SIZE],
    pub body_len: usize,
}

impl HttpResp {
    pub const fn empty() -> Self {
        Self { status: 0, body: [0; HTTP_BUF_SIZE], body_len: 0 }
    }
    pub fn body(&self) -> &[u8] { &self.body[..self.body_len] }
}

// ── Static buffers (single-threaded kernel) ───────────────────────────────────

static mut REQ_BUF:  [u8; 1024]         = [0; 1024];
static mut RESP_BUF: [u8; HTTP_BUF_SIZE] = [0; HTTP_BUF_SIZE];

// ── Public API ────────────────────────────────────────────────────────────────

/// Perform an HTTP GET request.
///
/// `extra_headers` must end with `\r\n` for each header, or be empty.
/// Returns None on connection failure or timeout.
pub fn get(
    peer_ip:       [u8; 4],
    peer_port:     u16,
    host:          &[u8],
    path:          &[u8],
    extra_headers: &[u8],
    out:           &mut dyn Output,
) -> Option<HttpResp> {
    let fd = connect_wait(peer_ip, peer_port, out)?;

    let req_len = unsafe { build_request(&mut REQ_BUF, host, path, extra_headers) };
    if req_len == 0 || !net::tcp_send(fd, unsafe { &REQ_BUF[..req_len] }) {
        net::tcp_close(fd);
        return None;
    }

    let resp = read_response(fd);
    net::tcp_close(fd);
    resp
}

/// Perform an HTTPS GET request (TLS 1.3).
pub fn get_tls(
    peer_ip:       [u8; 4],
    peer_port:     u16,
    host:          &[u8],
    path:          &[u8],
    extra_headers: &[u8],
    out:           &mut dyn Output,
) -> Option<HttpResp> {
    let fd = connect_wait(peer_ip, peer_port, out)?;

    let mut conn = match super::tls::handshake(fd, host) {
        Some(c) => c,
        None => {
            out.print(b"TLS handshake failed\n");
            net::tcp_close(fd);
            return None;
        }
    };

    let req_len = unsafe { build_request(&mut REQ_BUF, host, path, extra_headers) };
    if req_len == 0 || !super::tls::send(fd, &mut conn, unsafe { &REQ_BUF[..req_len] }) {
        net::tcp_close(fd);
        return None;
    }

    let n = super::tls::recv(fd, &mut conn, unsafe { &mut RESP_BUF });
    net::tcp_close(fd);

    if n < 8 { return None; }
    parse_response_buf(unsafe { &RESP_BUF[..n] })
}

// ── Connection helper ─────────────────────────────────────────────────────────

/// Connect and wait up to ~5 s for ESTABLISHED state.
/// On the first attempt ARP may not be resolved; we retry the SYN a few
/// times while polling the network stack.
fn connect_wait(ip: [u8; 4], port: u16, _out: &mut dyn Output) -> Option<usize> {
    let fd = net::tcp_connect(ip, port)?;

    // Up to 5 retry attempts (each ~500 ms of polling).
    // ARP may not be resolved on the first SYN; retry_syn re-sends the SYN
    // once ARP resolves and the gateway MAC appears in the ARP cache.
    for _ in 0..5u32 {
        for _ in 0..500_000u64 { net::poll_drivers(); }
        match net::tcp_state_of(fd) {
            tcp::TcpState::Established => return Some(fd),
            tcp::TcpState::Closed      => { net::tcp_close(fd); return None; }
            tcp::TcpState::SynSent     => { net::tcp_retry_syn(fd); }
            _ => {}
        }
    }

    // Final extended wait: up to 3 s
    for _ in 0..3_000_000u64 {
        net::poll_drivers();
        match net::tcp_state_of(fd) {
            tcp::TcpState::Established => return Some(fd),
            tcp::TcpState::Closed      => { net::tcp_close(fd); return None; }
            tcp::TcpState::SynSent     => { net::tcp_retry_syn(fd); }
            _ => {}
        }
    }

    net::tcp_close(fd);
    None
}

// ── Request builder ───────────────────────────────────────────────────────────

/// Build an HTTP/1.1 GET request into `buf`.  Returns bytes written (0 = error).
fn build_request(buf: &mut [u8; 1024], host: &[u8], path: &[u8], extra: &[u8]) -> usize {
    let mut w = BufWriter::new(buf);
    w.write(b"GET ");
    w.write(path);
    w.write(b" HTTP/1.1\r\nHost: ");
    w.write(host);
    w.write(b"\r\nUser-Agent: fastman/0.1 (FastROS)\r\nConnection: close\r\nAccept: */*\r\n");
    w.write(extra);
    w.write(b"\r\n");
    w.pos
}

// ── Response reader ───────────────────────────────────────────────────────────

/// Read HTTP response (headers + body) from an ESTABLISHED TCP socket.
fn read_response(fd: usize) -> Option<HttpResp> {
    let mut total = 0usize;

    // Fill RESP_BUF from socket until connection closes or buffer is full
    'recv: for _ in 0..10_000_000u64 {
        net::poll_drivers();

        let n = net::tcp_recv(fd, unsafe { &mut RESP_BUF[total..] });
        total += n;

        if total >= HTTP_BUF_SIZE { break 'recv; }

        let state = net::tcp_state_of(fd);
        if matches!(state, tcp::TcpState::CloseWait | tcp::TcpState::Closed
                         | tcp::TcpState::FinWait1  | tcp::TcpState::FinWait2
                         | tcp::TcpState::TimeWait) {
            if n == 0 { break 'recv; }
        }
    }

    if total < 8 { return None; }
    parse_response_buf(unsafe { &RESP_BUF[..total] })
}

/// Parse an HTTP/1.1 response from a raw byte buffer.
fn parse_response_buf(raw: &[u8]) -> Option<HttpResp> {
    let sep = find_crlfcrlf(raw)?;
    let header_section = &raw[..sep];
    let body_start     = sep + 4;
    let body_raw       = if body_start < raw.len() { &raw[body_start..] } else { &[] };

    let mut resp = HttpResp::empty();
    resp.status = parse_status(header_section)?;

    let body_len = if let Some(cl) = content_length(header_section) {
        cl.min(body_raw.len()).min(HTTP_BUF_SIZE)
    } else {
        body_raw.len().min(HTTP_BUF_SIZE)
    };

    resp.body[..body_len].copy_from_slice(&body_raw[..body_len]);
    resp.body_len = body_len;
    Some(resp)
}

// ── Header parsers ────────────────────────────────────────────────────────────

fn find_crlfcrlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_status(headers: &[u8]) -> Option<u16> {
    // "HTTP/1.1 200 " — status is at byte 9 for HTTP/1.1, 8 for HTTP/1.0
    let sp = headers.iter().position(|&b| b == b' ')?;
    let after = &headers[sp + 1..];
    let mut val = 0u16;
    let mut found = false;
    for &b in after {
        if b >= b'0' && b <= b'9' { val = val * 10 + (b - b'0') as u16; found = true; }
        else if found { break; }
    }
    if found { Some(val) } else { None }
}

fn content_length(headers: &[u8]) -> Option<usize> {
    // Case-insensitive scan for "content-length:"
    let needle = b"content-length:";
    'outer: for i in 0..headers.len() {
        if i + needle.len() > headers.len() { break; }
        for (j, &nb) in needle.iter().enumerate() {
            if headers[i + j].to_ascii_lowercase() != nb { continue 'outer; }
        }
        // Found at i; parse number after it
        let after = &headers[i + needle.len()..];
        let mut val = 0usize;
        let mut found = false;
        for &b in after {
            if (b == b' ' || b == b'\t') && !found { continue; }
            if b >= b'0' && b <= b'9' { val = val * 10 + (b - b'0') as usize; found = true; }
            else { break; }
        }
        if found { return Some(val); }
    }
    None
}

// ── BufWriter helper ──────────────────────────────────────────────────────────

struct BufWriter<'a> {
    buf: &'a mut [u8; 1024],
    pos: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8; 1024]) -> Self { Self { buf, pos: 0 } }
    fn write(&mut self, s: &[u8]) {
        let n = s.len().min(1024 - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&s[..n]);
        self.pos += n;
    }
}
