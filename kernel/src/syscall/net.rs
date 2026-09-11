//! Socket system calls, backed by [`crate::net::sockfile::SocketFile`] over the
//! kernel TCP/UDP stack, plus a level-triggered `epoll` implementation.

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Poll};
use crate::net::sockfile::{self, SocketFile};
use crate::net::{IpAddress, IpEndpoint, SOCK_WQ};
use crate::proc;
use crate::sync::SpinLock;
use crate::uaccess;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

fn fdt_get(fd: i32) -> KResult<Arc<dyn File>> {
    proc::current().fds.lock().get(fd)
}

/// Run `f` with the `SocketFile` behind `fd` (all socket methods take `&self`).
fn with_sock<R>(fd: i32, f: impl FnOnce(&SocketFile) -> KResult<R>) -> KResult<R> {
    let file = fdt_get(fd)?;
    let s = file.as_any().downcast_ref::<SocketFile>().ok_or(Errno::ENOTSOCK)?;
    f(s)
}

fn install(f: Arc<dyn File>, cloexec: bool) -> KResult<usize> {
    Ok(proc::current().fds.lock().alloc(f, cloexec, 0)? as usize)
}

// ── sockaddr_in <-> IpEndpoint ──────────────────────────────────────────────

/// Parse a `struct sockaddr_in` (16 bytes) from user memory.
fn read_sockaddr(addr: usize, len: usize) -> KResult<IpEndpoint> {
    if addr == 0 || len < 16 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 16];
    uaccess::copy_from(addr, &mut b)?;
    let family = u16::from_ne_bytes([b[0], b[1]]);
    if family != sockfile::AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes([b[2], b[3]]);
    let ip = IpAddress::v4(b[4], b[5], b[6], b[7]);
    Ok(IpEndpoint::new(ip, port))
}

/// Write a `struct sockaddr_in` back to user memory, honouring the caller's
/// buffer length and updating the `addrlen` out-parameter.
fn write_sockaddr(ep: IpEndpoint, addr: usize, addrlen: usize) -> KResult<()> {
    if addr == 0 || addrlen == 0 {
        return Ok(());
    }
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&sockfile::AF_INET.to_ne_bytes());
    b[2..4].copy_from_slice(&ep.port.to_be_bytes());
    let octets = match ep.addr {
        IpAddress::Ipv4(a) => a.octets(),
    };
    b[4..8].copy_from_slice(&octets);
    let cap: u32 = uaccess::read_obj(addrlen)?;
    let n = (cap as usize).min(b.len());
    uaccess::copy_to(addr, &b[..n])?;
    uaccess::write_obj(addrlen, &(16u32))?;
    Ok(())
}

// ── socket syscalls ─────────────────────────────────────────────────────────

pub fn socket(domain: i32, ty: i32, _protocol: i32) -> KResult<usize> {
    if domain != sockfile::AF_INET as i32 {
        return Err(Errno::EAFNOSUPPORT);
    }
    let dgram = match ty & 0xff {
        sockfile::SOCK_STREAM => false,
        sockfile::SOCK_DGRAM => true,
        _ => return Err(Errno::EINVAL),
    };
    let nonblock = ty & sockfile::SOCK_NONBLOCK != 0;
    let cloexec = ty & sockfile::SOCK_CLOEXEC != 0;
    install(SocketFile::new(dgram, nonblock), cloexec)
}

pub fn bind(fd: i32, addr: usize, len: usize) -> KResult<usize> {
    let ep = read_sockaddr(addr, len)?;
    with_sock(fd, |s| s.bind(ep.port))?;
    Ok(0)
}

pub fn listen(fd: i32, backlog: i32) -> KResult<usize> {
    with_sock(fd, |s| s.listen(backlog.max(0) as usize))?;
    Ok(0)
}

pub fn connect(fd: i32, addr: usize, len: usize) -> KResult<usize> {
    let ep = read_sockaddr(addr, len)?;
    with_sock(fd, |s| s.connect(ep))?;
    Ok(0)
}

fn do_accept(fd: i32, addr: usize, addrlen: usize, flags: i32) -> KResult<usize> {
    let nonblock = flags & sockfile::SOCK_NONBLOCK != 0;
    let cloexec = flags & sockfile::SOCK_CLOEXEC != 0;
    let (child, peer) = with_sock(fd, |s| s.accept(nonblock))?;
    if addr != 0 {
        write_sockaddr(peer, addr, addrlen)?;
    }
    install(child, cloexec)
}

pub fn accept(fd: i32, addr: usize, addrlen: usize) -> KResult<usize> {
    do_accept(fd, addr, addrlen, 0)
}

pub fn accept4(fd: i32, addr: usize, addrlen: usize, flags: i32) -> KResult<usize> {
    do_accept(fd, addr, addrlen, flags)
}

/// `socketpair(2)`: a connected bidirectional stream pair. Callers (nginx's
/// master↔worker channel, libc) use AF_UNIX SOCK_STREAM; we return a duplex
/// pipe pair regardless of the address family.
pub fn socketpair(_domain: i32, ty: i32, _protocol: i32, sv: usize) -> KResult<usize> {
    let (a, b) = crate::fs::pipe::socketpair();
    if ty & sockfile::SOCK_NONBLOCK != 0 {
        a.set_flags(flags::O_NONBLOCK);
        b.set_flags(flags::O_NONBLOCK);
    }
    let cloexec = ty & sockfile::SOCK_CLOEXEC != 0;
    let t = proc::current();
    let mut fds = t.fds.lock();
    let fd0 = fds.alloc(a, cloexec, 0)? as i32;
    let fd1 = fds.alloc(b, cloexec, 0)? as i32;
    drop(fds);
    uaccess::write_obj(sv, &fd0)?;
    uaccess::write_obj(sv + 4, &fd1)?;
    Ok(0)
}

pub fn getsockname(fd: i32, addr: usize, addrlen: usize) -> KResult<usize> {
    let ep = with_sock(fd, |s| Ok(s.local_addr()))?.unwrap_or_else(|| IpEndpoint::new(IpAddress::v4(0, 0, 0, 0), 0));
    write_sockaddr(ep, addr, addrlen)?;
    Ok(0)
}

pub fn getpeername(fd: i32, addr: usize, addrlen: usize) -> KResult<usize> {
    let ep = with_sock(fd, |s| s.peer_addr().ok_or(Errno::ENOTCONN))?;
    write_sockaddr(ep, addr, addrlen)?;
    Ok(0)
}

pub fn shutdown(fd: i32, how: i32) -> KResult<usize> {
    with_sock(fd, |s| s.shutdown(how))?;
    Ok(0)
}

/// `setsockopt`: accepted as a no-op. Options like `SO_REUSEADDR`,
/// `TCP_NODELAY` and `SO_KEEPALIVE` already match the stack's behaviour, so
/// acknowledging them is safe and lets servers start.
pub fn setsockopt(fd: i32, _level: i32, _optname: i32, _optval: usize, _optlen: usize) -> KResult<usize> {
    with_sock(fd, |_| Ok(()))?;
    Ok(0)
}

pub fn getsockopt(fd: i32, level: i32, optname: i32, optval: usize, optlen: usize) -> KResult<usize> {
    with_sock(fd, |_| Ok(()))?;
    const SOL_SOCKET: i32 = 1;
    const SO_TYPE: i32 = 3;
    // Report no pending error (0), or SOCK_STREAM for SO_TYPE — enough for libc.
    let val: u32 = if level == SOL_SOCKET && optname == SO_TYPE { sockfile::SOCK_STREAM as u32 } else { 0 };
    if optval != 0 && optlen != 0 {
        let cap: u32 = uaccess::read_obj(optlen)?;
        if cap >= 4 {
            uaccess::write_obj(optval, &val)?;
            uaccess::write_obj(optlen, &4u32)?;
        }
    }
    Ok(0)
}

pub fn sendto(fd: i32, buf: usize, len: usize, _flags: i32, addr: usize, addrlen: usize) -> KResult<usize> {
    let mut data = alloc::vec![0u8; len.min(1 << 20)];
    uaccess::copy_from(buf, &mut data)?;
    let to = if addr != 0 && addrlen >= 16 { Some(read_sockaddr(addr, addrlen)?) } else { None };
    with_sock(fd, |s| s.sendto(&data, to))
}

pub fn recvfrom(fd: i32, buf: usize, len: usize, _flags: i32, addr: usize, addrlen: usize) -> KResult<usize> {
    let mut data = alloc::vec![0u8; len.min(1 << 20)];
    let (n, from) = with_sock(fd, |s| s.recvfrom(&mut data))?;
    uaccess::copy_to(buf, &data[..n])?;
    if addr != 0 {
        if let Some(ep) = from {
            write_sockaddr(ep, addr, addrlen)?;
        }
    }
    Ok(n)
}

// ── epoll ───────────────────────────────────────────────────────────────────

const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
/// Bits reported unconditionally (Linux always delivers these).
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;

#[derive(Clone, Copy)]
struct Interest {
    fd: i32,
    events: u32,
    data: u64,
}

/// A `struct epoll_event` is packed on x86_64: u32 events, then u64 data (12 B).
fn read_epoll_event(ptr: usize) -> KResult<(u32, u64)> {
    let events: u32 = uaccess::read_obj(ptr)?;
    let data: u64 = uaccess::read_obj(ptr + 4)?;
    Ok((events, data))
}

fn write_epoll_event(ptr: usize, events: u32, data: u64) -> KResult<()> {
    uaccess::write_obj(ptr, &events)?;
    uaccess::write_obj(ptr + 4, &data)?;
    Ok(())
}

static NEXT_EPOLL_INO: AtomicU64 = AtomicU64::new(1);

pub struct EpollFile {
    interest: SpinLock<Vec<Interest>>,
    ino: u64,
}

impl EpollFile {
    fn new() -> Arc<EpollFile> {
        Arc::new(EpollFile { interest: SpinLock::new(Vec::new()), ino: NEXT_EPOLL_INO.fetch_add(1, Ordering::Relaxed) })
    }
}

impl File for EpollFile {
    fn stat(&self) -> KResult<crate::fs::Metadata> {
        let now = crate::fs::Timespec::now();
        Ok(crate::fs::Metadata {
            dev: 0,
            ino: self.ino,
            kind: crate::fs::FileType::Regular,
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
        Poll(0)
    }
    fn flags(&self) -> u32 {
        crate::fs::file::flags::O_RDWR
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn with_epoll<R>(epfd: i32, f: impl FnOnce(&EpollFile) -> KResult<R>) -> KResult<R> {
    let file = fdt_get(epfd)?;
    let ep = file.as_any().downcast_ref::<EpollFile>().ok_or(Errno::EINVAL)?;
    f(ep)
}

pub fn epoll_create1(flags: i32) -> KResult<usize> {
    let cloexec = flags & sockfile::SOCK_CLOEXEC != 0;
    install(EpollFile::new(), cloexec)
}

pub fn epoll_create(_size: i32) -> KResult<usize> {
    install(EpollFile::new(), false)
}

pub fn epoll_ctl(epfd: i32, op: i32, fd: i32, event: usize) -> KResult<usize> {
    with_epoll(epfd, |ep| {
        let mut list = ep.interest.lock();
        match op {
            EPOLL_CTL_ADD => {
                let (events, data) = read_epoll_event(event)?;
                if list.iter().any(|i| i.fd == fd) {
                    return Err(Errno::EEXIST);
                }
                list.push(Interest { fd, events, data });
                Ok(0)
            }
            EPOLL_CTL_MOD => {
                let (events, data) = read_epoll_event(event)?;
                let it = list.iter_mut().find(|i| i.fd == fd).ok_or(Errno::ENOENT)?;
                it.events = events;
                it.data = data;
                Ok(0)
            }
            EPOLL_CTL_DEL => {
                let before = list.len();
                list.retain(|i| i.fd != fd);
                if list.len() == before {
                    Err(Errno::ENOENT)
                } else {
                    Ok(0)
                }
            }
            _ => Err(Errno::EINVAL),
        }
    })
}

/// Ready events for one interest against its fd's current poll state.
fn ready_events(it: &Interest) -> u32 {
    let Ok(f) = fdt_get(it.fd) else {
        // Linux removes a closed descriptor from every epoll set automatically,
        // so a gone fd yields no events (rather than a synthesised ERR|HUP that
        // a poll loop would spin on or mis-handle).
        return 0;
    };
    let p = f.poll();
    let mut r = 0u32;
    if p.contains(Poll::IN) {
        r |= EPOLLIN;
    }
    if p.contains(Poll::OUT) {
        r |= EPOLLOUT;
    }
    if p.contains(Poll::ERR) {
        r |= EPOLLERR;
    }
    if p.contains(Poll::HUP) {
        r |= EPOLLHUP;
    }
    // Errors and hangups are always delivered; other bits are masked by interest.
    r & (it.events | EPOLLERR | EPOLLHUP)
}

pub fn epoll_wait(epfd: i32, events: usize, maxevents: i32, timeout_ms: i32) -> KResult<usize> {
    let interests = with_epoll(epfd, |ep| Ok(ep.interest.lock().clone()))?;
    let maxevents = maxevents.max(0) as usize;
    if maxevents == 0 {
        return Err(Errno::EINVAL);
    }
    let deadline = if timeout_ms < 0 { None } else { Some(crate::time::now_ns() + timeout_ms as u64 * 1_000_000) };

    let collect = || -> Vec<(u64, u32)> {
        let mut out = Vec::new();
        for it in interests.iter() {
            let r = ready_events(it);
            if r != 0 {
                out.push((it.data, r));
                if out.len() >= maxevents {
                    break;
                }
            }
        }
        out
    };

    let ready = match SOCK_WQ.wait_until_interruptible(
        || {
            let out = collect();
            if out.is_empty() {
                None
            } else {
                Some(out)
            }
        },
        deadline,
    ) {
        Ok(v) => v,
        Err(crate::sync::WaitResult::TimedOut) => Vec::new(),
        Err(crate::sync::WaitResult::Interrupted) => return Err(Errno::EINTR),
    };
    for (i, (data, revents)) in ready.iter().enumerate() {
        write_epoll_event(events + i * 12, *revents, *data)?;
    }
    Ok(ready.len())
}

// ── sendfile ────────────────────────────────────────────────────────────────

/// `sendfile(out_fd, in_fd, offset*, count)`: copy up to `count` bytes from
/// `in_fd` (a seekable file) to `out_fd` (a socket) via a bounce buffer.
pub fn sendfile(out_fd: i32, in_fd: i32, off_ptr: usize, count: usize) -> KResult<usize> {
    let out = fdt_get(out_fd)?;
    let inf = fdt_get(in_fd)?;
    if !out.writable() || !inf.readable() {
        return Err(Errno::EBADF);
    }
    let mut off: Option<u64> = if off_ptr != 0 { Some(uaccess::read_obj::<u64>(off_ptr)?) } else { None };
    let mut sent = 0usize;
    let mut buf = alloc::vec![0u8; 65536];
    while sent < count {
        let want = (count - sent).min(buf.len());
        let n = match off {
            Some(o) => inf.pread(o, &mut buf[..want])?,
            None => inf.read(&mut buf[..want])?,
        };
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        sent += n;
        if let Some(o) = off.as_mut() {
            *o += n as u64;
        }
    }
    if off_ptr != 0 {
        if let Some(o) = off {
            uaccess::write_obj(off_ptr, &o)?;
        }
    }
    Ok(sent)
}
