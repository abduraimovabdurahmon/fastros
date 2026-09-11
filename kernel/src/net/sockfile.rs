//! BSD socket file descriptions.
//!
//! A `SocketFile` implements the [`File`] trait over the kernel TCP/UDP stack
//! (`net::socket`), so a socket is an ordinary descriptor in the process fd
//! table: `read`/`write`/`close`/`poll` work on it, and the socket-specific
//! syscalls (`bind`/`listen`/`accept`/`connect`/`sendto`/`recvfrom`) go through
//! the helper methods here.
//!
//! Only `AF_INET` (IPv4) with `SOCK_STREAM` (TCP) and `SOCK_DGRAM` (UDP) is
//! supported. Containers currently share the host network stack (host-network
//! style); per-container network namespaces are a follow-up.

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Poll};
use crate::fs::{FileType, Metadata, Timespec};
use crate::net::socket::{TcpListener, TcpStream, UdpSocket};
use crate::net::{IpEndpoint, SOCK_WQ};
use crate::sync::{SpinLock, WaitQueue};
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const AF_INET: u16 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
/// Type flags OR-ed into the `socket()`/`accept4()` type argument.
pub const SOCK_NONBLOCK: i32 = 0o4000; // == O_NONBLOCK
pub const SOCK_CLOEXEC: i32 = 0o2000000; // == O_CLOEXEC

/// `shutdown(2)` directions.
pub const SHUT_RD: i32 = 0;
pub const SHUT_WR: i32 = 1;
pub const SHUT_RDWR: i32 = 2;

/// The connection state of a socket.
enum Sock {
    /// `socket()` created, not yet bound/connected/listening.
    TcpIdle,
    /// `bind()`ed to a local port, awaiting `listen()`.
    TcpBound(u16),
    /// `listen()`ing.
    Listen(Arc<TcpListener>),
    /// Connected stream (from `connect()` or `accept()`).
    Conn(Arc<TcpStream>),
    /// UDP, not yet bound.
    UdpIdle,
    /// UDP, bound to a local port.
    Udp(Arc<UdpSocket>),
}

static NEXT_SOCK_INO: AtomicU64 = AtomicU64::new(1);

pub struct SocketFile {
    inner: SpinLock<Sock>,
    flags: AtomicU32,
    ino: u64,
}

impl SocketFile {
    pub fn new(dgram: bool, nonblock: bool) -> Arc<SocketFile> {
        Arc::new(SocketFile {
            inner: SpinLock::new(if dgram { Sock::UdpIdle } else { Sock::TcpIdle }),
            flags: AtomicU32::new(flags::O_RDWR | if nonblock { flags::O_NONBLOCK } else { 0 }),
            ino: NEXT_SOCK_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Wrap an already-connected stream (used by `accept`).
    fn from_stream(stream: Arc<TcpStream>, nonblock: bool) -> Arc<SocketFile> {
        Arc::new(SocketFile {
            inner: SpinLock::new(Sock::Conn(stream)),
            flags: AtomicU32::new(flags::O_RDWR | if nonblock { flags::O_NONBLOCK } else { 0 }),
            ino: NEXT_SOCK_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn is_nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0
    }

    /// `bind(2)`: record the local port. For UDP this creates the socket now.
    pub fn bind(&self, port: u16) -> KResult<()> {
        let mut g = self.inner.lock();
        match &*g {
            Sock::TcpIdle => {
                *g = Sock::TcpBound(port);
                Ok(())
            }
            Sock::UdpIdle => {
                let sock = UdpSocket::bind(if port == 0 { None } else { Some(port) })?;
                *g = Sock::Udp(Arc::new(sock));
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `listen(2)`: start listening on the bound (or unbound → ephemeral) port.
    pub fn listen(&self, backlog: usize) -> KResult<()> {
        let mut g = self.inner.lock();
        let port = match &*g {
            Sock::TcpBound(p) => *p,
            Sock::TcpIdle => return Err(Errno::EDESTADDRREQ),
            Sock::Listen(_) => return Ok(()),
            _ => return Err(Errno::EINVAL),
        };
        let l = TcpListener::bind(port, backlog.clamp(1, 128))?;
        *g = Sock::Listen(Arc::new(l));
        Ok(())
    }

    /// `connect(2)`: establish a TCP connection to `remote`.
    pub fn connect(&self, remote: IpEndpoint) -> KResult<()> {
        {
            let g = self.inner.lock();
            match &*g {
                Sock::TcpIdle | Sock::TcpBound(_) => {}
                Sock::Conn(_) => return Err(Errno::EISCONN),
                _ => return Err(Errno::EINVAL),
            }
        }
        // connect() blocks on the handshake — never hold the state lock across it.
        let stream = TcpStream::connect(remote, 15_000)?;
        *self.inner.lock() = Sock::Conn(Arc::new(stream));
        Ok(())
    }

    /// `accept(2)`: return the next connection and its remote endpoint.
    pub fn accept(&self, nonblock: bool) -> KResult<(Arc<SocketFile>, IpEndpoint)> {
        let listener = {
            let g = self.inner.lock();
            match &*g {
                Sock::Listen(l) => l.clone(),
                _ => return Err(Errno::EINVAL),
            }
        };
        let (stream, peer) = if nonblock || self.is_nonblock() {
            listener.try_accept().ok_or(Errno::EAGAIN)?
        } else {
            listener.accept()?
        };
        Ok((SocketFile::from_stream(Arc::new(stream), nonblock), peer))
    }

    /// The local endpoint (`getsockname`).
    pub fn local_addr(&self) -> Option<IpEndpoint> {
        let g = self.inner.lock();
        match &*g {
            Sock::Conn(s) => s.local(),
            Sock::Listen(l) => Some(IpEndpoint::new(crate::net::IpAddress::v4(0, 0, 0, 0), l.port())),
            Sock::TcpBound(p) => Some(IpEndpoint::new(crate::net::IpAddress::v4(0, 0, 0, 0), *p)),
            Sock::Udp(u) => Some(IpEndpoint::new(crate::net::IpAddress::v4(0, 0, 0, 0), u.port())),
            _ => None,
        }
    }

    /// The remote endpoint (`getpeername`).
    pub fn peer_addr(&self) -> Option<IpEndpoint> {
        let g = self.inner.lock();
        match &*g {
            Sock::Conn(s) => s.peer(),
            _ => None,
        }
    }

    /// `sendto(2)` for UDP (a connected TCP socket ignores the address).
    pub fn sendto(&self, data: &[u8], to: Option<IpEndpoint>) -> KResult<usize> {
        let sock = {
            let g = self.inner.lock();
            match &*g {
                Sock::Conn(s) => return s.write(data),
                Sock::Udp(u) => u.clone(),
                Sock::UdpIdle => {
                    drop(g);
                    // An unbound UDP socket sends from an ephemeral port.
                    let u = Arc::new(UdpSocket::bind(None)?);
                    *self.inner.lock() = Sock::Udp(u.clone());
                    u
                }
                _ => return Err(Errno::ENOTCONN),
            }
        };
        let to = to.ok_or(Errno::EDESTADDRREQ)?;
        sock.send_to(data, to)?;
        Ok(data.len())
    }

    /// `recvfrom(2)`: returns bytes and the source endpoint (UDP) or the peer.
    pub fn recvfrom(&self, buf: &mut [u8]) -> KResult<(usize, Option<IpEndpoint>)> {
        let state = {
            let g = self.inner.lock();
            match &*g {
                Sock::Conn(s) => Ok(s.clone()),
                Sock::Udp(u) => Err(u.clone()),
                _ => return Err(Errno::ENOTCONN),
            }
        };
        match state {
            Ok(s) => {
                let n = if self.is_nonblock() { s.try_read(buf)? } else { s.read(buf)? };
                Ok((n, s.peer()))
            }
            Err(u) => {
                let (n, ep) = if self.is_nonblock() { u.try_recv_from(buf)? } else { u.recv_from(buf, None)? };
                Ok((n, Some(ep)))
            }
        }
    }

    /// `shutdown(2)`.
    pub fn shutdown(&self, _how: i32) -> KResult<()> {
        let g = self.inner.lock();
        match &*g {
            Sock::Conn(s) => {
                s.shutdown();
                Ok(())
            }
            _ => Err(Errno::ENOTCONN),
        }
    }
}

impl File for SocketFile {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let stream = {
            let g = self.inner.lock();
            match &*g {
                Sock::Conn(s) => s.clone(),
                Sock::Udp(_) => {
                    drop(g);
                    return self.recvfrom(buf).map(|(n, _)| n);
                }
                _ => return Err(Errno::ENOTCONN),
            }
        };
        if self.is_nonblock() {
            stream.try_read(buf)
        } else {
            stream.read(buf)
        }
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let stream = {
            let g = self.inner.lock();
            match &*g {
                Sock::Conn(s) => s.clone(),
                _ => return Err(Errno::ENOTCONN),
            }
        };
        if self.is_nonblock() {
            stream.try_write(buf)
        } else {
            stream.write(buf)
        }
    }

    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata {
            dev: 0,
            ino: self.ino,
            kind: FileType::Socket,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            blksize: 4096,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    }

    fn poll(&self) -> Poll {
        let g = self.inner.lock();
        match &*g {
            Sock::Listen(l) => {
                if l.pending() {
                    Poll::IN
                } else {
                    Poll(0)
                }
            }
            Sock::Conn(s) => {
                let mut p = Poll(0);
                if s.can_read() {
                    p = p | Poll::IN;
                }
                if s.can_write() {
                    p = p | Poll::OUT;
                }
                if !s.is_open() {
                    p = p | Poll::HUP;
                }
                p
            }
            Sock::Udp(u) => {
                let mut p = Poll::OUT;
                if u.can_recv() {
                    p = p | Poll::IN;
                }
                p
            }
            _ => Poll::OUT,
        }
    }

    fn wait_queue(&self) -> Option<&WaitQueue> {
        Some(&SOCK_WQ)
    }

    fn ioctl(&self, req: u32, arg: usize) -> KResult<usize> {
        const FIONBIO: u32 = 0x5421;
        const FIONREAD: u32 = 0x541B;
        const FIOASYNC: u32 = 0x5452;
        match req {
            FIOASYNC => Ok(0), // SIGIO not delivered; accept so servers proceed
            FIONBIO => {
                let on: u32 = crate::uaccess::read_obj(arg)?;
                let old = self.flags.load(Ordering::Relaxed);
                let new = if on != 0 { old | flags::O_NONBLOCK } else { old & !flags::O_NONBLOCK };
                self.flags.store(new, Ordering::Relaxed);
                Ok(0)
            }
            FIONREAD => {
                let n: u32 = {
                    let g = self.inner.lock();
                    match &*g {
                        Sock::Conn(s) if s.can_read() => 1,
                        _ => 0,
                    }
                };
                crate::uaccess::write_obj(arg, &n)?;
                Ok(0)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_flags(&self, f: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !flags::SETFL_MASK) | (f & flags::SETFL_MASK), Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
