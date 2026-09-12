//! `signalfd(2)`: read pending signals as data through a descriptor.
//!
//! Servers (postgres) block a set of signals and drain them via a signalfd
//! watched with epoll, instead of asynchronous handlers. We report the current
//! process's pending signals that fall in the fd's mask; `poll` is readable
//! while such a signal is pending, and `read` dequeues one as a
//! `signalfd_siginfo`.

use super::file::{flags, File, Poll};
use super::{Errno, FileType, KResult, Metadata, Timespec};
use crate::sync::WaitQueue;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub const SFD_NONBLOCK: u32 = 0o4000;
pub const SFD_CLOEXEC: u32 = 0o2000000;

static NEXT_INO: AtomicU64 = AtomicU64::new(1);

pub struct SignalFd {
    mask: AtomicU64,
    flags: AtomicU32,
    ino: u64,
}

impl SignalFd {
    pub fn new(mask: u64, flags: u32) -> Arc<SignalFd> {
        Arc::new(SignalFd {
            mask: AtomicU64::new(mask),
            flags: AtomicU32::new(super::file::flags::O_RDONLY | if flags & SFD_NONBLOCK != 0 { super::file::flags::O_NONBLOCK } else { 0 }),
            ino: NEXT_INO.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub fn set_mask(&self, mask: u64) {
        self.mask.store(mask, Ordering::Relaxed);
    }

    fn nonblock(&self) -> bool {
        self.flags.load(Ordering::Relaxed) & flags::O_NONBLOCK != 0
    }

    /// Pending signals of the current task that this fd watches.
    fn ready(&self) -> u64 {
        let mask = self.mask.load(Ordering::Relaxed);
        crate::sched::with_current(|t| t.pending_signals()) & mask
    }
}

impl File for SignalFd {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if buf.len() < 128 {
            return Err(Errno::EINVAL);
        }
        let sig = loop {
            let r = self.ready();
            if r != 0 {
                let sig = r.trailing_zeros() + 1;
                crate::sched::with_current(|t| t.clear_signal(sig));
                break sig;
            }
            if self.nonblock() {
                return Err(Errno::EAGAIN);
            }
            // A delivered signal wakes the task from this sleep.
            if !crate::sched::sleep_ms(1000) {
                // Interrupted (a signal arrived): loop and re-check the mask.
                crate::proc::absorb_signals();
            }
        };
        // struct signalfd_siginfo: ssi_signo (u32) at offset 0; rest zeroed.
        buf[..128].fill(0);
        buf[0..4].copy_from_slice(&sig.to_le_bytes());
        Ok(128)
    }

    fn write(&self, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::EINVAL)
    }

    fn stat(&self) -> KResult<Metadata> {
        let now = Timespec::now();
        Ok(Metadata { dev: 0, ino: self.ino, kind: FileType::Regular, perm: 0o600, nlink: 1, uid: 0, gid: 0, size: 0, blocks: 0, blksize: 4096, rdev: 0, atime: now, mtime: now, ctime: now })
    }

    fn poll(&self) -> Poll {
        if self.ready() != 0 {
            Poll::IN
        } else {
            Poll(0)
        }
    }

    fn wait_queue(&self) -> Option<&WaitQueue> {
        // Signals wake the task directly; epoll re-polls on that wake.
        Some(&crate::net::SOCK_WQ)
    }

    fn ioctl(&self, _req: u32, _arg: usize) -> KResult<usize> {
        Ok(0)
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
