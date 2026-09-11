//! Blocking kernel sockets over the host stack.
//!
//! All waits are interruptible (a signal makes them return EINTR) and take
//! optional deadlines. Dropping a stream closes it gracefully; the stack
//! keeps the socket until the FIN handshake completes.

use super::{poll_now, stack, Stack, SOCK_WQ};
use crate::errno::{Errno, KResult};
use crate::sync::WaitResult;
use alloc::vec;
use alloc::vec::Vec;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Duration;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

const TCP_BUF: usize = 64 * 1024;

fn wait_err(r: WaitResult) -> Errno {
    match r {
        WaitResult::Interrupted => Errno::EINTR,
        WaitResult::TimedOut => Errno::ETIMEDOUT,
    }
}

fn deadline(timeout_ms: Option<u64>) -> Option<u64> {
    timeout_ms.map(|ms| crate::time::now_ns() + ms * 1_000_000)
}

/// Run `f` on the TCP socket under the stack lock; retry after every stack
/// poll until it yields `Some`.
fn tcp_wait<R>(h: SocketHandle, dl: Option<u64>, mut f: impl FnMut(&mut tcp::Socket) -> Option<KResult<R>>) -> KResult<R> {
    let r = SOCK_WQ.wait_until_interruptible(
        || {
            let mut s = stack().lock();
            f(s.sockets.get_mut::<tcp::Socket>(h))
        },
        dl,
    );
    r.map_err(wait_err)?
}

pub struct TcpStream {
    h: SocketHandle,
    closed: core::sync::atomic::AtomicBool,
}

fn new_tcp_socket() -> tcp::Socket<'static> {
    let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0; TCP_BUF]), tcp::SocketBuffer::new(vec![0; TCP_BUF]));
    s.set_nagle_enabled(false);
    s.set_keep_alive(Some(Duration::from_secs(60)));
    s.set_timeout(Some(Duration::from_secs(600)));
    s
}

impl TcpStream {
    pub fn connect(remote: IpEndpoint, timeout_ms: u64) -> KResult<TcpStream> {
        let h = {
            let mut st = stack().lock();
            if st.cfg.addr.is_none() && !matches!(remote.addr, IpAddress::Ipv4(a) if a.octets()[0] == 127) {
                return Err(Errno::ENETUNREACH);
            }
            let mut sock = new_tcp_socket();
            let local = super::ephemeral_port();
            let Stack { iface, sockets, .. } = &mut *st;
            sock.connect(iface.context(), remote, local).map_err(|_| Errno::EINVAL)?;
            sockets.add(sock)
        };
        poll_now();
        let stream = TcpStream { h, closed: core::sync::atomic::AtomicBool::new(false) };
        let r = tcp_wait(h, deadline(Some(timeout_ms)), |s| match s.state() {
            tcp::State::Established => Some(Ok(())),
            tcp::State::Closed => Some(Err(Errno::ECONNREFUSED)),
            _ => None,
        });
        match r {
            Ok(()) => Ok(stream),
            Err(e) => {
                stack().lock().sockets.get_mut::<tcp::Socket>(h).abort();
                Err(e)
            }
        }
    }

    /// Read up to `buf.len()` bytes; `Ok(0)` at end of stream.
    pub fn read_timeout(&self, buf: &mut [u8], timeout_ms: Option<u64>) -> KResult<usize> {
        let n = tcp_wait(self.h, deadline(timeout_ms), |s| {
            if s.can_recv() {
                return Some(s.recv_slice(buf).map_err(|_| Errno::ECONNRESET));
            }
            if !s.may_recv() {
                return Some(Ok(0)); // peer closed (FIN) or connection gone
            }
            None
        })?;
        if n > 0 {
            poll_now(); // window update
        }
        Ok(n)
    }

    pub fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        self.read_timeout(buf, None)
    }

    /// Queue as much of `data` as fits (blocking until at least one byte does).
    pub fn write(&self, data: &[u8]) -> KResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let n = tcp_wait(self.h, None, |s| {
            if !s.may_send() {
                return Some(Err(Errno::EPIPE));
            }
            if s.can_send() {
                return Some(s.send_slice(data).map_err(|_| Errno::EPIPE));
            }
            None
        })?;
        poll_now();
        Ok(n)
    }

    pub fn write_all(&self, mut data: &[u8]) -> KResult<()> {
        while !data.is_empty() {
            let n = self.write(data)?;
            data = &data[n..];
        }
        Ok(())
    }

    /// Bytes queued but not yet acknowledged by the peer.
    pub fn send_queue(&self) -> usize {
        stack().lock().sockets.get::<tcp::Socket>(self.h).send_queue()
    }

    pub fn can_read(&self) -> bool {
        let st = stack().lock();
        let s = st.sockets.get::<tcp::Socket>(self.h);
        s.can_recv() || !s.may_recv()
    }

    pub fn is_open(&self) -> bool {
        let st = stack().lock();
        let s = st.sockets.get::<tcp::Socket>(self.h);
        s.may_recv() || s.may_send()
    }

    pub fn peer(&self) -> Option<IpEndpoint> {
        stack().lock().sockets.get::<tcp::Socket>(self.h).remote_endpoint()
    }

    pub fn local(&self) -> Option<IpEndpoint> {
        stack().lock().sockets.get::<tcp::Socket>(self.h).local_endpoint()
    }

    /// Send FIN (no more writes); reads continue until the peer closes.
    pub fn shutdown(&self) {
        stack().lock().sockets.get_mut::<tcp::Socket>(self.h).close();
        poll_now();
    }

    /// Hard reset.
    pub fn abort(&self) {
        stack().lock().sockets.get_mut::<tcp::Socket>(self.h).abort();
        self.closed.store(true, core::sync::atomic::Ordering::Relaxed);
        poll_now();
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // Drop may run with spinlocks held: only take the (sleeping) stack
        // lock if it is free right now, otherwise leave it to the reaper.
        if let Some(mut st) = stack().try_lock() {
            let s = st.sockets.get_mut::<tcp::Socket>(self.h);
            if !self.closed.load(core::sync::atomic::Ordering::Relaxed) {
                s.close();
            }
            st.orphan(self.h);
        } else {
            super::defer_orphan(self.h);
        }
        super::kick();
    }
}

/// A listening port with a small backlog of pre-armed sockets.
pub struct TcpListener {
    port: u16,
    backlog: crate::sync::SpinLock<Vec<SocketHandle>>,
}

impl TcpListener {
    pub fn bind(port: u16, backlog: usize) -> KResult<TcpListener> {
        let mut hs = Vec::new();
        {
            let mut st = stack().lock();
            let in_use = st.sockets.iter().any(|(_, s)| match s {
                smoltcp::socket::Socket::Tcp(t) => t.is_listening() && t.listen_endpoint().port == port,
                _ => false,
            });
            if in_use {
                return Err(Errno::EADDRINUSE);
            }
            for _ in 0..backlog.max(1) {
                let mut s = new_tcp_socket();
                s.listen(IpListenEndpoint { addr: None, port }).map_err(|_| Errno::EINVAL)?;
                hs.push(st.sockets.add(s));
            }
        }
        Ok(TcpListener { port, backlog: crate::sync::SpinLock::new(hs) })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wait for a connection; returns it with its remote endpoint.
    pub fn accept(&self) -> KResult<(TcpStream, IpEndpoint)> {
        let handles = self.backlog.lock().clone();
        let (h, peer) = SOCK_WQ
            .wait_until_interruptible(
                || {
                    let st = stack().lock();
                    handles.iter().find_map(|&h| {
                        let s = st.sockets.get::<tcp::Socket>(h);
                        match s.state() {
                            tcp::State::Established | tcp::State::CloseWait => s.remote_endpoint().map(|p| (h, p)),
                            _ => None,
                        }
                    })
                },
                None,
            )
            .map_err(wait_err)?;
        // Re-arm: replace the accepted socket with a fresh listener.
        {
            let mut st = stack().lock();
            let mut s = new_tcp_socket();
            let _ = s.listen(IpListenEndpoint { addr: None, port: self.port });
            let nh = st.sockets.add(s);
            let mut bl = self.backlog.lock();
            if let Some(slot) = bl.iter_mut().find(|x| **x == h) {
                *slot = nh;
            }
        }
        Ok((TcpStream { h, closed: core::sync::atomic::AtomicBool::new(false) }, peer))
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let hs = core::mem::take(&mut *self.backlog.lock());
        let mut st = stack().lock();
        for h in hs {
            st.sockets.get_mut::<tcp::Socket>(h).abort();
            st.orphan(h);
        }
    }
}

/// UDP datagram socket.
pub struct UdpSocket {
    h: SocketHandle,
    port: u16,
}

impl UdpSocket {
    pub fn bind(port: Option<u16>) -> KResult<UdpSocket> {
        let port = port.unwrap_or_else(super::ephemeral_port);
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]),
        );
        sock.bind(port).map_err(|_| Errno::EADDRINUSE)?;
        let h = stack().lock().sockets.add(sock);
        Ok(UdpSocket { h, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn send_to(&self, data: &[u8], to: IpEndpoint) -> KResult<()> {
        stack().lock().sockets.get_mut::<udp::Socket>(self.h).send_slice(data, to).map_err(|_| Errno::ENOBUFS)?;
        poll_now();
        Ok(())
    }

    pub fn recv_from(&self, buf: &mut [u8], timeout_ms: Option<u64>) -> KResult<(usize, IpEndpoint)> {
        SOCK_WQ
            .wait_until_interruptible(
                || {
                    let mut st = stack().lock();
                    let s = st.sockets.get_mut::<udp::Socket>(self.h);
                    if s.can_recv() {
                        s.recv_slice(buf).ok().map(|(n, meta)| (n, meta.endpoint))
                    } else {
                        None
                    }
                },
                deadline(timeout_ms),
            )
            .map_err(|e| if e == WaitResult::TimedOut { Errno::EAGAIN } else { Errno::EINTR })
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        if let Some(mut st) = stack().try_lock() {
            st.sockets.remove(self.h);
        }
    }
}

/// ICMP echo socket (for `ping`).
pub struct IcmpSocket {
    h: SocketHandle,
    pub ident: u16,
}

impl IcmpSocket {
    pub fn new() -> KResult<IcmpSocket> {
        let ident = crate::crypto::rng::u32() as u16;
        let mut sock = icmp::Socket::new(
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
            icmp::PacketBuffer::new(vec![icmp::PacketMetadata::EMPTY; 8], vec![0; 8192]),
        );
        sock.bind(icmp::Endpoint::Ident(ident)).map_err(|_| Errno::EADDRINUSE)?;
        let h = stack().lock().sockets.add(sock);
        Ok(IcmpSocket { h, ident })
    }

    pub fn send(&self, packet: &[u8], to: IpAddress) -> KResult<()> {
        stack().lock().sockets.get_mut::<icmp::Socket>(self.h).send_slice(packet, to).map_err(|_| Errno::ENOBUFS)?;
        poll_now();
        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8], deadline_ns: u64) -> KResult<(usize, IpAddress)> {
        SOCK_WQ
            .wait_until_interruptible(
                || {
                    let mut st = stack().lock();
                    let s = st.sockets.get_mut::<icmp::Socket>(self.h);
                    if s.can_recv() {
                        s.recv_slice(buf).ok()
                    } else {
                        None
                    }
                },
                Some(deadline_ns),
            )
            .map_err(|e| if e == WaitResult::TimedOut { Errno::ETIMEDOUT } else { Errno::EINTR })
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        if let Some(mut st) = stack().try_lock() {
            st.sockets.remove(self.h);
        }
    }
}

/// One row of `/proc/net/tcp` / `netstat`.
pub struct TcpRow {
    pub local: alloc::string::String,
    pub remote: alloc::string::String,
    pub state_code: u8,
    pub state: &'static str,
    pub tx_queue: usize,
    pub rx_queue: usize,
    pub local_ep: Option<(IpAddress, u16)>,
    pub remote_ep: Option<(IpAddress, u16)>,
}

fn hex_ep(addr: Option<IpAddress>, port: u16) -> alloc::string::String {
    let v = match addr {
        Some(IpAddress::Ipv4(a)) => u32::from_le_bytes(a.octets()),
        None => 0,
    };
    alloc::format!("{:08X}:{:04X}", v, port)
}

pub fn tcp_table(st: &Stack) -> Vec<TcpRow> {
    let mut out = Vec::new();
    for (_, s) in st.sockets.iter() {
        let smoltcp::socket::Socket::Tcp(t) = s else { continue };
        let (code, name) = match t.state() {
            tcp::State::Established => (0x01, "ESTABLISHED"),
            tcp::State::SynSent => (0x02, "SYN_SENT"),
            tcp::State::SynReceived => (0x03, "SYN_RECV"),
            tcp::State::FinWait1 => (0x04, "FIN_WAIT1"),
            tcp::State::FinWait2 => (0x05, "FIN_WAIT2"),
            tcp::State::TimeWait => (0x06, "TIME_WAIT"),
            tcp::State::Closed => continue,
            tcp::State::CloseWait => (0x08, "CLOSE_WAIT"),
            tcp::State::LastAck => (0x09, "LAST_ACK"),
            tcp::State::Listen => (0x0A, "LISTEN"),
            tcp::State::Closing => (0x0B, "CLOSING"),
        };
        let (local, local_ep) = match t.local_endpoint() {
            Some(ep) => (hex_ep(Some(ep.addr), ep.port), Some((ep.addr, ep.port))),
            None => {
                let l = t.listen_endpoint();
                (hex_ep(l.addr, l.port), l.addr.map(|a| (a, l.port)).or(Some((IpAddress::v4(0, 0, 0, 0), l.port))))
            }
        };
        let (remote, remote_ep) = match t.remote_endpoint() {
            Some(ep) => (hex_ep(Some(ep.addr), ep.port), Some((ep.addr, ep.port))),
            None => (hex_ep(None, 0), None),
        };
        // Pre-armed listeners share a port: show each listening port once.
        if code == 0x0A && out.iter().any(|r: &TcpRow| r.state_code == 0x0A && r.local == local) {
            continue;
        }
        out.push(TcpRow { local, remote, state_code: code, state: name, tx_queue: t.send_queue(), rx_queue: t.recv_queue(), local_ep, remote_ep });
    }
    out
}
