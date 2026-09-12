//! AF_UNIX stream sockets (filesystem-named and abstract).
//!
//! A connected pair is just a [`crate::fs::pipe::Duplex`] (two pipes), so reads
//! and writes are in-memory and never touch the TCP stack. `bind`+`listen`
//! registers a path in a global table; `connect` looks it up, makes a Duplex
//! pair, hands one end to the client and queues the other for `accept`. This is
//! what postgres uses by default (its `.s.PGSQL.<port>` socket and the initdb
//! temp server), and what most local services prefer over TCP.

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Poll};
use crate::fs::pipe::{socketpair, Duplex};
use crate::fs::{FileType, Metadata, Timespec};
use crate::sync::{SpinLock, WaitQueue, WaitResult};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const AF_UNIX: u16 = 1;

/// A listening AF_UNIX socket: a queue of connected server-side endpoints.
pub struct UnixListener {
    path: String,
    backlog: usize,
    queue: SpinLock<VecDeque<Arc<Duplex>>>,
    wq: WaitQueue,
}

impl UnixListener {
    fn pending(&self) -> bool {
        !self.queue.lock().is_empty()
    }
}

/// path → listener. A bound, listening socket is discoverable here by `connect`.
static BINDINGS: SpinLock<BTreeMap<String, Arc<UnixListener>>> = SpinLock::new(BTreeMap::new());
static NEXT_INO: AtomicU64 = AtomicU64::new(1);

enum State {
    Idle,
    Bound(String),
    Listen(Arc<UnixListener>),
    Conn(Arc<Duplex>),
}

pub struct UnixSocketFile {
    inner: SpinLock<State>,
    flags: AtomicU32,
    ino: u64,
}

impl UnixSocketFile {
    pub fn new(nonblock: bool) -> Arc<UnixSocketFile> {
        Arc::new(UnixSocketFile {
            inner: SpinLock::new(State::Idle),
            flags: AtomicU32::new(flags::O_RDWR | if nonblock { flags::O_NONBLOCK } else { 0 }),
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn from_conn(d: Arc<Duplex>, nonblock: bool) -> Arc<UnixSocketFile> {
        Arc::new(UnixSocketFile {
            inner: SpinLock::new(State::Conn(d)),
            flags: AtomicU32::new(flags::O_RDWR | if nonblock { flags::O_NONBLOCK } else { 0 }),
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn is_nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0
    }

    pub fn bind(&self, path: &str) -> KResult<()> {
        if path.is_empty() {
            return Err(Errno::EINVAL);
        }
        if BINDINGS.lock().contains_key(path) {
            return Err(Errno::EADDRINUSE);
        }
        let mut g = self.inner.lock();
        match &*g {
            State::Idle => {
                *g = State::Bound(String::from(path));
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    pub fn listen(&self, backlog: usize) -> KResult<()> {
        let mut g = self.inner.lock();
        let path = match &*g {
            State::Bound(p) => p.clone(),
            State::Listen(_) => return Ok(()),
            _ => return Err(Errno::EINVAL),
        };
        let l = Arc::new(UnixListener {
            path: path.clone(),
            backlog: backlog.clamp(1, 512),
            queue: SpinLock::new(VecDeque::new()),
            wq: WaitQueue::new(),
        });
        BINDINGS.lock().insert(path, l.clone());
        *g = State::Listen(l);
        Ok(())
    }

    pub fn connect(&self, path: &str) -> KResult<()> {
        {
            let g = self.inner.lock();
            if matches!(&*g, State::Conn(_)) {
                return Err(Errno::EISCONN);
            }
        }
        let listener = BINDINGS.lock().get(path).cloned().ok_or(Errno::ECONNREFUSED)?;
        {
            let q = listener.queue.lock();
            if q.len() >= listener.backlog {
                return Err(Errno::EAGAIN);
            }
        }
        let (client, server) = socketpair();
        listener.queue.lock().push_back(server);
        listener.wq.wake_all();
        crate::net::wake_pollers();
        *self.inner.lock() = State::Conn(client);
        Ok(())
    }

    pub fn accept(&self, nonblock: bool) -> KResult<Arc<UnixSocketFile>> {
        let listener = {
            let g = self.inner.lock();
            match &*g {
                State::Listen(l) => l.clone(),
                _ => return Err(Errno::EINVAL),
            }
        };
        let nb = nonblock || self.is_nonblock();
        let conn = if nb {
            listener.queue.lock().pop_front().ok_or(Errno::EAGAIN)?
        } else {
            match listener.wq.wait_until_interruptible(|| listener.queue.lock().pop_front(), None) {
                Ok(c) => c,
                Err(WaitResult::Interrupted) => return Err(Errno::EINTR),
                Err(WaitResult::TimedOut) => return Err(Errno::EAGAIN),
            }
        };
        Ok(UnixSocketFile::from_conn(conn, nonblock))
    }

    /// The bound path, for `getsockname`.
    pub fn local_path(&self) -> Option<String> {
        match &*self.inner.lock() {
            State::Bound(p) => Some(p.clone()),
            State::Listen(l) => Some(l.path.clone()),
            _ => None,
        }
    }
}

impl File for UnixSocketFile {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let d = match &*self.inner.lock() {
            State::Conn(d) => d.clone(),
            _ => return Err(Errno::ENOTCONN),
        };
        d.set_flags(self.flags.load(Ordering::Relaxed));
        d.read(buf)
    }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let d = match &*self.inner.lock() {
            State::Conn(d) => d.clone(),
            _ => return Err(Errno::ENOTCONN),
        };
        d.set_flags(self.flags.load(Ordering::Relaxed));
        d.write(buf)
    }
    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata { dev: 0, ino: self.ino, kind: FileType::Socket, perm: 0o600, nlink: 1, uid: 0, gid: 0, size: 0, blocks: 0, blksize: 4096, rdev: 0, atime: now, mtime: now, ctime: now })
    }
    fn poll(&self) -> Poll {
        match &*self.inner.lock() {
            State::Conn(d) => d.poll(),
            State::Listen(l) => {
                if l.pending() {
                    Poll::IN
                } else {
                    Poll(0)
                }
            }
            _ => Poll(0),
        }
    }
    fn wait_queue(&self) -> Option<&WaitQueue> {
        // Socket readiness (connect/accept/data) wakes the universal poll queue.
        Some(&crate::net::SOCK_WQ)
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

impl Drop for UnixSocketFile {
    fn drop(&mut self) {
        // Unregister a listening path so the name can be re-bound.
        if let State::Listen(l) = &*self.inner.lock() {
            let mut b = BINDINGS.lock();
            if b.get(&l.path).is_some_and(|cur| Arc::ptr_eq(cur, l)) {
                b.remove(&l.path);
            }
        }
    }
}
