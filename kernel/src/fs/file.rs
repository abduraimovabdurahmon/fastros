//! Open file descriptions.

use super::path::PathRef;
use super::{DirEntry, Errno, FileType, InodeRef, KResult, Metadata, SetAttr};
use crate::sync::{SpinLock, WaitQueue};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

/// `open(2)` flags (Linux x86_64 values).
pub mod flags {
    pub const O_RDONLY: u32 = 0;
    pub const O_WRONLY: u32 = 1;
    pub const O_RDWR: u32 = 2;
    pub const O_ACCMODE: u32 = 3;
    pub const O_CREAT: u32 = 0o100;
    pub const O_EXCL: u32 = 0o200;
    pub const O_NOCTTY: u32 = 0o400;
    pub const O_TRUNC: u32 = 0o1000;
    pub const O_APPEND: u32 = 0o2000;
    pub const O_NONBLOCK: u32 = 0o4000;
    pub const O_DIRECTORY: u32 = 0o200000;
    pub const O_NOFOLLOW: u32 = 0o400000;
    pub const O_CLOEXEC: u32 = 0o2000000;
    pub const O_PATH: u32 = 0o10000000;
    /// Flags `fcntl(F_SETFL)` may change.
    pub const SETFL_MASK: u32 = O_APPEND | O_NONBLOCK;
}

/// Readiness bits (same values as Linux `POLL*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Poll(pub u16);
impl Poll {
    pub const IN: Poll = Poll(0x001);
    pub const PRI: Poll = Poll(0x002);
    pub const OUT: Poll = Poll(0x004);
    pub const ERR: Poll = Poll(0x008);
    pub const HUP: Poll = Poll(0x010);
    pub const NVAL: Poll = Poll(0x020);
    pub fn contains(self, o: Poll) -> bool {
        self.0 & o.0 == o.0
    }
    pub fn intersects(self, o: Poll) -> bool {
        self.0 & o.0 != 0
    }
}
impl core::ops::BitOr for Poll {
    type Output = Poll;
    fn bitor(self, o: Poll) -> Poll {
        Poll(self.0 | o.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Whence {
    Set(i64),
    Cur(i64),
    End(i64),
}

pub trait File: Send + Sync + Any {
    fn read(&self, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::EBADF)
    }
    fn write(&self, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::EBADF)
    }
    fn pread(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::ESPIPE)
    }
    fn pwrite(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::ESPIPE)
    }
    fn seek(&self, _w: Whence) -> KResult<u64> {
        Err(Errno::ESPIPE)
    }
    fn stat(&self) -> KResult<Metadata>;
    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        Err(Errno::ENOTDIR)
    }
    fn ioctl(&self, _req: u32, _arg: usize) -> KResult<usize> {
        Err(Errno::ENOTTY)
    }
    /// Current readiness.
    fn poll(&self) -> Poll {
        Poll::IN | Poll::OUT
    }
    /// Queue woken whenever readiness may have changed (for poll/select).
    fn wait_queue(&self) -> Option<&WaitQueue> {
        None
    }
    fn path(&self) -> Option<PathRef> {
        None
    }
    fn truncate(&self, _len: u64) -> KResult<()> {
        Err(Errno::EINVAL)
    }
    fn sync(&self) -> KResult<()> {
        Ok(())
    }
    /// Status flags (`O_APPEND | O_NONBLOCK` + access mode).
    fn flags(&self) -> u32;
    fn set_flags(&self, _f: u32) {}
    /// The terminal behind this file, if it is one.
    fn tty(&self) -> Option<Arc<crate::tty::Tty>> {
        None
    }
    /// The shared page set for a `MAP_SHARED` mapping of this file (POSIX shm),
    /// or `None` for a private mapping. See [`crate::fs::Inode::shared_mmap`].
    fn shared_mmap(&self) -> Option<Arc<crate::mm::aspace::SharedAnon>> {
        None
    }
    fn as_any(&self) -> &dyn Any;
}

impl dyn File {
    pub fn readable(&self) -> bool {
        self.flags() & flags::O_ACCMODE != flags::O_WRONLY
    }
    pub fn writable(&self) -> bool {
        self.flags() & flags::O_ACCMODE != flags::O_RDONLY
    }
    pub fn nonblocking(&self) -> bool {
        self.flags() & flags::O_NONBLOCK != 0
    }
    /// Write everything (retrying short writes).
    pub fn write_all(&self, mut buf: &[u8]) -> KResult<()> {
        while !buf.is_empty() {
            let n = self.write(buf)?;
            if n == 0 {
                return Err(Errno::EIO);
            }
            buf = &buf[n..];
        }
        Ok(())
    }
    /// Read until EOF.
    pub fn read_to_end(&self, out: &mut Vec<u8>) -> KResult<usize> {
        let mut buf = alloc::vec![0u8; 8192];
        let start = out.len();
        loop {
            let n = self.read(&mut buf)?;
            if n == 0 {
                return Ok(out.len() - start);
            }
            out.extend_from_slice(&buf[..n]);
        }
    }
}

/// A file or directory opened through the VFS.
pub struct InodeFile {
    pub node: PathRef,
    inode: InodeRef,
    offset: SpinLock<u64>,
    flags: AtomicU32,
}

impl InodeFile {
    pub fn new(node: PathRef, flags: u32) -> Arc<InodeFile> {
        let inode = node.inode.clone();
        Arc::new(InodeFile { node, inode, offset: SpinLock::new(0), flags: AtomicU32::new(flags) })
    }
}

impl File for InodeFile {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        if !(self as &dyn File).readable() {
            return Err(Errno::EBADF);
        }
        let kind = self.inode.kind()?;
        if kind == FileType::Directory {
            return Err(Errno::EISDIR);
        }
        let off = *self.offset.lock();
        let n = self.inode.read_at(off, buf)?;
        *self.offset.lock() = off + n as u64;
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        if !(self as &dyn File).writable() {
            return Err(Errno::EBADF);
        }
        let off = if self.flags() & flags::O_APPEND != 0 {
            self.inode.metadata()?.size
        } else {
            *self.offset.lock()
        };
        let n = self.inode.write_at(off, buf)?;
        *self.offset.lock() = off + n as u64;
        Ok(n)
    }

    fn pread(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.inode.read_at(off, buf)
    }
    fn pwrite(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.inode.write_at(off, buf)
    }

    fn seek(&self, w: Whence) -> KResult<u64> {
        // Filesystem calls may sleep: never make them under the offset spinlock.
        let size = match w {
            Whence::End(_) => self.inode.metadata()?.size as i64,
            _ => 0,
        };
        let mut off = self.offset.lock();
        let new = match w {
            Whence::Set(p) => p,
            Whence::Cur(d) => (*off as i64).checked_add(d).ok_or(Errno::EOVERFLOW)?,
            Whence::End(d) => size.checked_add(d).ok_or(Errno::EOVERFLOW)?,
        };
        if new < 0 {
            return Err(Errno::EINVAL);
        }
        *off = new as u64;
        Ok(*off)
    }

    fn stat(&self) -> KResult<Metadata> {
        self.inode.metadata()
    }
    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        self.inode.readdir()
    }
    fn path(&self) -> Option<PathRef> {
        Some(self.node.clone())
    }
    fn truncate(&self, len: u64) -> KResult<()> {
        if !(self as &dyn File).writable() {
            return Err(Errno::EBADF);
        }
        self.inode.set_attr(&SetAttr { size: Some(len), mtime: Some(super::Timespec::now()), ..Default::default() })
    }
    fn sync(&self) -> KResult<()> {
        self.inode.sync()
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn set_flags(&self, f: u32) {
        let old = self.flags.load(Ordering::Relaxed);
        self.flags.store((old & !flags::SETFL_MASK) | (f & flags::SETFL_MASK), Ordering::Relaxed);
    }
    fn shared_mmap(&self) -> Option<Arc<crate::mm::aspace::SharedAnon>> {
        self.inode.shared_mmap()
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}
