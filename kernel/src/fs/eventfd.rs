//! `eventfd(2)`: a descriptor wrapping a 64-bit counter used for wait/notify.
//!
//! A write adds to the counter; a read returns it (and clears it, or decrements
//! by one in semaphore mode) and blocks while it is zero. Servers (nginx's
//! thread-pool and notification path) create one and watch it with epoll.

use super::file::{flags, File, Poll};
use super::{Errno, FileType, KResult, Metadata, Timespec};
use crate::sync::{SpinLock, WaitQueue, WaitResult};
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_CLOEXEC: u32 = 0o2000000;
pub const EFD_NONBLOCK: u32 = 0o4000;

static NEXT_INO: AtomicU64 = AtomicU64::new(1);

pub struct EventFd {
    count: SpinLock<u64>,
    semaphore: bool,
    flags: AtomicU32,
    wq: WaitQueue,
    ino: u64,
}

impl EventFd {
    pub fn new(initval: u32, flags: u32) -> Arc<EventFd> {
        Arc::new(EventFd {
            count: SpinLock::new(initval as u64),
            semaphore: flags & EFD_SEMAPHORE != 0,
            flags: AtomicU32::new(super::file::flags::O_RDWR | if flags & EFD_NONBLOCK != 0 { super::file::flags::O_NONBLOCK } else { 0 }),
            wq: WaitQueue::new(),
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0
    }
}

impl File for EventFd {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let val = loop {
            {
                let mut c = self.count.lock();
                if *c > 0 {
                    let v = if self.semaphore {
                        *c -= 1;
                        1
                    } else {
                        core::mem::replace(&mut *c, 0)
                    };
                    break v;
                }
            }
            if self.nonblock() {
                return Err(Errno::EAGAIN);
            }
            self.wq
                .wait_until_interruptible(|| (*self.count.lock() > 0).then_some(()), None)
                .map_err(|e| if e == WaitResult::Interrupted { Errno::EINTR } else { Errno::EAGAIN })?;
        };
        self.wq.wake_all();
        crate::net::wake_pollers();
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        Ok(8)
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        if buf.len() < 8 {
            return Err(Errno::EINVAL);
        }
        let add = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        if add == u64::MAX {
            return Err(Errno::EINVAL);
        }
        loop {
            {
                let mut c = self.count.lock();
                // The counter maxes out at u64::MAX-1; block if adding overflows.
                if u64::MAX - 1 - *c >= add {
                    *c += add;
                    break;
                }
            }
            if self.nonblock() {
                return Err(Errno::EAGAIN);
            }
            self.wq
                .wait_until_interruptible(|| (u64::MAX - 1 - *self.count.lock() >= add).then_some(()), None)
                .map_err(|e| if e == WaitResult::Interrupted { Errno::EINTR } else { Errno::EAGAIN })?;
        }
        self.wq.wake_all();
        crate::net::wake_pollers();
        Ok(8)
    }

    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata { dev: 0, ino: self.ino, kind: FileType::Regular, perm: 0o600, nlink: 1, uid: 0, gid: 0, size: 0, blocks: 0, blksize: 4096, rdev: 0, atime: now, mtime: now, ctime: now })
    }

    fn poll(&self) -> Poll {
        let c = *self.count.lock();
        let mut p = Poll(0);
        if c > 0 {
            p = p | Poll::IN;
        }
        if c < u64::MAX - 1 {
            p = p | Poll::OUT;
        }
        p
    }

    fn wait_queue(&self) -> Option<&WaitQueue> {
        Some(&self.wq)
    }

    fn ioctl(&self, req: u32, arg: usize) -> KResult<usize> {
        const FIONBIO: u32 = 0x5421;
        const FIOASYNC: u32 = 0x5452;
        match req {
            FIONBIO => {
                let on: u32 = crate::uaccess::read_obj(arg)?;
                let old = self.flags.load(Ordering::Relaxed);
                let new = if on != 0 { old | flags::O_NONBLOCK } else { old & !flags::O_NONBLOCK };
                self.flags.store(new, Ordering::Relaxed);
                Ok(0)
            }
            FIOASYNC => Ok(0),
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
