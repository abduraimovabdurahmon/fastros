//! Pipes and FIFOs: a bounded byte queue between writers and readers.

use super::file::{flags, File, Poll};
use super::{Errno, FileType, KResult, Metadata, Timespec};
use crate::sync::{SpinLock, WaitQueue, WaitResult};
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const PIPE_CAPACITY: usize = 65536;
/// Writes up to this size are atomic (never interleaved with other writers).
pub const PIPE_BUF: usize = 4096;

struct Inner {
    data: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

pub struct Pipe {
    inner: SpinLock<Inner>,
    wq: WaitQueue,
    ino: u64,
}

static NEXT_PIPE_INO: AtomicU64 = AtomicU64::new(1);

impl Pipe {
    pub fn new() -> Arc<Pipe> {
        Arc::new(Pipe {
            inner: SpinLock::new(Inner { data: VecDeque::new(), readers: 0, writers: 0 }),
            wq: WaitQueue::new(),
            ino: NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    /// Open one end (used by `pipe()` and by FIFO opens).
    pub fn open(self: &Arc<Self>, write: bool, nonblock: bool) -> Arc<PipeEnd> {
        {
            let mut g = self.inner.lock();
            if write {
                g.writers += 1;
            } else {
                g.readers += 1;
            }
        }
        self.wq.wake_all();
        let acc = if write { flags::O_WRONLY } else { flags::O_RDONLY };
        Arc::new(PipeEnd {
            pipe: self.clone(),
            write,
            flags: AtomicU32::new(acc | if nonblock { flags::O_NONBLOCK } else { 0 }),
        })
    }

    pub fn has_readers(&self) -> bool {
        self.inner.lock().readers > 0
    }
    pub fn has_writers(&self) -> bool {
        self.inner.lock().writers > 0
    }
    pub fn wait_queue(&self) -> &WaitQueue {
        &self.wq
    }
}

/// Open a FIFO end with POSIX semantics: a blocking open waits for the other
/// side; a non-blocking open for writing with no reader fails with ENXIO.
pub fn open_fifo(pipe: &Arc<Pipe>, fl: u32) -> KResult<Arc<dyn File>> {
    let write = fl & flags::O_ACCMODE != flags::O_RDONLY;
    let nonblock = fl & flags::O_NONBLOCK != 0;
    if nonblock && write && !pipe.has_readers() {
        return Err(Errno::ENXIO);
    }
    let end = pipe.open(write, nonblock);
    if !nonblock {
        pipe.wq
            .wait_until_interruptible(|| (if write { pipe.has_readers() } else { pipe.has_writers() }).then_some(()), None)
            .map_err(interrupted)?;
    }
    Ok(end)
}

/// FIFOs living on disk filesystems share one pipe per (device, inode).
static NAMED: SpinLock<alloc::collections::BTreeMap<(u64, u64), alloc::sync::Weak<Pipe>>> =
    SpinLock::new(alloc::collections::BTreeMap::new());

pub fn open_named(dev: u64, ino: u64, fl: u32) -> KResult<Arc<dyn File>> {
    let pipe = {
        let mut named = NAMED.lock();
        named.retain(|_, w| w.strong_count() > 0);
        match named.get(&(dev, ino)).and_then(|w| w.upgrade()) {
            Some(p) => p,
            None => {
                let p = Pipe::new();
                named.insert((dev, ino), Arc::downgrade(&p));
                p
            }
        }
    };
    open_fifo(&pipe, fl)
}

/// `pipe(2)`: (read end, write end).
pub fn pipe() -> (Arc<PipeEnd>, Arc<PipeEnd>) {
    let p = Pipe::new();
    (p.open(false, false), p.open(true, false))
}

pub struct PipeEnd {
    pipe: Arc<Pipe>,
    write: bool,
    flags: AtomicU32,
}

fn interrupted(r: WaitResult) -> Errno {
    match r {
        WaitResult::Interrupted => Errno::EINTR,
        WaitResult::TimedOut => Errno::EAGAIN,
    }
}

impl File for PipeEnd {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if self.write {
            return Err(Errno::EBADF);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let nonblock = self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0;
        let n = loop {
            {
                let mut g = self.pipe.inner.lock();
                if !g.data.is_empty() {
                    let n = buf.len().min(g.data.len());
                    for (i, b) in g.data.drain(..n).enumerate() {
                        buf[i] = b;
                    }
                    break n;
                }
                if g.writers == 0 {
                    return Ok(0); // EOF
                }
            }
            if nonblock {
                return Err(Errno::EAGAIN);
            }
            self.pipe
                .wq
                .wait_until_interruptible(
                    || {
                        let g = self.pipe.inner.lock();
                        (!g.data.is_empty() || g.writers == 0).then_some(())
                    },
                    None,
                )
                .map_err(interrupted)?;
        };
        self.pipe.wq.wake_all();
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        if !self.write {
            return Err(Errno::EBADF);
        }
        let nonblock = self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0;
        let mut written = 0;
        while written < buf.len() {
            let rest = &buf[written..];
            // Atomic writes need all of their bytes to fit at once.
            let need = if rest.len() <= PIPE_BUF { rest.len() } else { 1 };
            let r = self.pipe.wq.wait_until_interruptible(
                || {
                    let g = self.pipe.inner.lock();
                    (g.readers == 0 || PIPE_CAPACITY - g.data.len() >= need).then_some(())
                },
                if nonblock { Some(0) } else { None },
            );
            if let Err(e) = r {
                if written > 0 {
                    return Ok(written);
                }
                return Err(interrupted(e));
            }
            {
                let mut g = self.pipe.inner.lock();
                if g.readers == 0 {
                    drop(g);
                    crate::proc::signal_current(crate::proc::signal::SIGPIPE);
                    return if written > 0 { Ok(written) } else { Err(Errno::EPIPE) };
                }
                let n = rest.len().min(PIPE_CAPACITY - g.data.len());
                g.data.extend(&rest[..n]);
                written += n;
            }
            self.pipe.wq.wake_all();
        }
        Ok(written)
    }

    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata {
            dev: 0,
            ino: self.pipe.ino,
            kind: FileType::Fifo,
            perm: 0o600,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            blksize: PIPE_BUF as u32,
            rdev: 0,
            atime: now,
            mtime: now,
            ctime: now,
        })
    }

    fn poll(&self) -> Poll {
        let g = self.pipe.inner.lock();
        if self.write {
            if g.readers == 0 {
                Poll::ERR | Poll::OUT
            } else if PIPE_CAPACITY - g.data.len() >= PIPE_BUF {
                Poll::OUT
            } else {
                Poll(0)
            }
        } else {
            let mut p = Poll(0);
            if !g.data.is_empty() {
                p = p | Poll::IN;
            }
            if g.writers == 0 {
                p = p | Poll::HUP;
            }
            p
        }
    }

    fn wait_queue(&self) -> Option<&WaitQueue> {
        Some(&self.pipe.wq)
    }

    fn ioctl(&self, req: u32, arg: usize) -> KResult<usize> {
        const FIONREAD: u32 = 0x541B;
        if req == FIONREAD {
            let n = self.pipe.inner.lock().data.len() as u32;
            crate::uaccess::write_obj(arg, &n)?;
            return Ok(0);
        }
        Err(Errno::ENOTTY)
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

/// One end of a `socketpair(2)`: a bidirectional stream built from two pipes
/// (read from one, write to the other). Used for AF_UNIX SOCK_STREAM pairs,
/// which servers like nginx use for their master↔worker command channel.
pub struct Duplex {
    rx: Arc<PipeEnd>,
    tx: Arc<PipeEnd>,
    flags: AtomicU32,
    ino: u64,
}

/// A connected pair of duplex stream endpoints.
pub fn socketpair() -> (Arc<Duplex>, Arc<Duplex>) {
    let a = Pipe::new();
    let b = Pipe::new();
    let e0 = Arc::new(Duplex {
        rx: a.open(false, false),
        tx: b.open(true, false),
        flags: AtomicU32::new(flags::O_RDWR),
        ino: NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed),
    });
    let e1 = Arc::new(Duplex {
        rx: b.open(false, false),
        tx: a.open(true, false),
        flags: AtomicU32::new(flags::O_RDWR),
        ino: NEXT_PIPE_INO.fetch_add(1, Ordering::Relaxed),
    });
    (e0, e1)
}

impl File for Duplex {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        self.rx.set_flags(self.flags.load(Ordering::Relaxed));
        self.rx.read(buf)
    }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        self.tx.set_flags(self.flags.load(Ordering::Relaxed));
        self.tx.write(buf)
    }
    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata { dev: 0, ino: self.ino, kind: FileType::Socket, perm: 0o600, nlink: 1, uid: 0, gid: 0, size: 0, blocks: 0, blksize: PIPE_BUF as u32, rdev: 0, atime: now, mtime: now, ctime: now })
    }
    fn poll(&self) -> Poll {
        let mut p = Poll(0);
        let r = self.rx.poll();
        if r.contains(Poll::IN) {
            p = p | Poll::IN;
        }
        if r.contains(Poll::HUP) {
            p = p | Poll::HUP;
        }
        if self.tx.poll().contains(Poll::OUT) {
            p = p | Poll::OUT;
        }
        p
    }
    fn wait_queue(&self) -> Option<&WaitQueue> {
        self.rx.wait_queue()
    }
    fn ioctl(&self, req: u32, arg: usize) -> KResult<usize> {
        self.rx.ioctl(req, arg)
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

impl Drop for PipeEnd {
    fn drop(&mut self) {
        {
            let mut g = self.pipe.inner.lock();
            if self.write {
                g.writers -= 1;
            } else {
                g.readers -= 1;
            }
        }
        self.pipe.wq.wake_all();
    }
}
