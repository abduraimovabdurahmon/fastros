//! Character and block device files (`/dev/null`, `/dev/urandom`, `/dev/sda`...).

use crate::drivers::block::BlockDevice;
use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Whence};
use crate::fs::{major, makedev, minor, FileType, Metadata, Timespec};
use crate::sync::SpinLock;
use alloc::sync::Arc;
use alloc::vec;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

pub const MEM_MAJOR: u32 = 1;
pub const TTY_MAJOR: u32 = 5;
pub const PTS_MAJOR: u32 = 136;
pub const SD_MAJOR: u32 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mem {
    Null,
    Zero,
    Full,
    Random,
    Kmsg,
}

struct MemDev {
    kind: Mem,
    rdev: u64,
    flags: AtomicU32,
}

fn dev_meta(rdev: u64, perm: u16, kind: FileType, size: u64) -> Metadata {
    let now = Timespec::now();
    Metadata {
        dev: 5,
        ino: rdev,
        kind,
        perm,
        nlink: 1,
        uid: 0,
        gid: 0,
        size,
        blocks: 0,
        blksize: 4096,
        rdev,
        atime: now,
        mtime: now,
        ctime: now,
    }
}

impl File for MemDev {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        match self.kind {
            Mem::Null => Ok(0),
            Mem::Zero | Mem::Full => {
                buf.fill(0);
                Ok(buf.len())
            }
            Mem::Random => {
                crate::crypto::rng::fill(buf);
                Ok(buf.len())
            }
            Mem::Kmsg => {
                let mut text = alloc::string::String::new();
                for r in crate::log::records() {
                    use core::fmt::Write;
                    let _ = writeln!(text, "{},{},{};{}: {}", r.level as u8, r.seq, r.time_ns / 1000, r.facility, r.text);
                }
                let n = buf.len().min(text.len());
                buf[..n].copy_from_slice(&text.as_bytes()[..n]);
                Ok(n)
            }
        }
    }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        match self.kind {
            Mem::Full => Err(Errno::ENOSPC),
            Mem::Random => {
                crate::crypto::rng::add_entropy(buf);
                Ok(buf.len())
            }
            Mem::Kmsg => {
                let s = alloc::string::String::from_utf8_lossy(buf);
                crate::log::log(crate::log::Level::Notice, "user", format_args!("{}", s.trim_end()));
                Ok(buf.len())
            }
            _ => Ok(buf.len()),
        }
    }
    fn pread(&self, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.read(buf)
    }
    fn pwrite(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        self.write(buf)
    }
    fn seek(&self, _w: Whence) -> KResult<u64> {
        Ok(0)
    }
    fn stat(&self) -> KResult<Metadata> {
        let perm = if self.kind == Mem::Kmsg { 0o644 } else { 0o666 };
        Ok(dev_meta(self.rdev, perm, FileType::CharDevice, 0))
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

/// A block device opened as a file: byte-addressed reads/writes with
/// read-modify-write of partial sectors.
struct BlockFile {
    dev: Arc<dyn BlockDevice>,
    rdev: u64,
    off: SpinLock<u64>,
    flags: AtomicU32,
}

impl BlockFile {
    fn size(&self) -> u64 {
        self.dev.sectors() * 512
    }
    fn io(&self, off: u64, buf: &mut [u8], data: Option<&[u8]>) -> KResult<usize> {
        let size = self.size();
        if off >= size {
            return Ok(0);
        }
        let len = (buf.len().max(data.map_or(0, |d| d.len())) as u64).min(size - off) as usize;
        let first = off / 512;
        let last = (off + len as u64).div_ceil(512);
        let mut bounce = vec![0u8; ((last - first) * 512) as usize];
        self.dev.read(first, &mut bounce).map_err(|_| Errno::EIO)?;
        let start = (off - first * 512) as usize;
        match data {
            None => buf[..len].copy_from_slice(&bounce[start..start + len]),
            Some(d) => {
                bounce[start..start + len].copy_from_slice(&d[..len]);
                self.dev.write(first, &bounce).map_err(|_| Errno::EIO)?;
            }
        }
        Ok(len)
    }
}

impl File for BlockFile {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let off = *self.off.lock();
        let n = self.io(off, buf, None)?;
        *self.off.lock() = off + n as u64;
        Ok(n)
    }
    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let off = *self.off.lock();
        let mut dummy = [];
        let n = self.io(off, &mut dummy, Some(buf))?;
        *self.off.lock() = off + n as u64;
        Ok(n)
    }
    fn pread(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.io(off, buf, None)
    }
    fn pwrite(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut dummy = [];
        self.io(off, &mut dummy, Some(buf))
    }
    fn seek(&self, w: Whence) -> KResult<u64> {
        let mut off = self.off.lock();
        let new = match w {
            Whence::Set(p) => p,
            Whence::Cur(d) => *off as i64 + d,
            Whence::End(d) => self.size() as i64 + d,
        };
        if new < 0 {
            return Err(Errno::EINVAL);
        }
        *off = new as u64;
        Ok(*off)
    }
    fn stat(&self) -> KResult<Metadata> {
        Ok(dev_meta(self.rdev, 0o660, FileType::BlockDevice, self.size()))
    }
    fn sync(&self) -> KResult<()> {
        self.dev.flush().map_err(|_| Errno::EIO)
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub fn open_char(rdev: u64, fl: u32) -> KResult<Arc<dyn File>> {
    let mem = |kind| -> KResult<Arc<dyn File>> { Ok(Arc::new(MemDev { kind, rdev, flags: AtomicU32::new(fl) })) };
    match (major(rdev), minor(rdev)) {
        (MEM_MAJOR, 3) => mem(Mem::Null),
        (MEM_MAJOR, 5) => mem(Mem::Zero),
        (MEM_MAJOR, 7) => mem(Mem::Full),
        (MEM_MAJOR, 8) | (MEM_MAJOR, 9) => mem(Mem::Random),
        (MEM_MAJOR, 11) => mem(Mem::Kmsg),
        (TTY_MAJOR, 0) => {
            let tty = crate::proc::current().ctty.lock().clone().ok_or(Errno::ENXIO)?;
            Ok(crate::tty::TtyFile::new(tty, fl))
        }
        (TTY_MAJOR, 1) => {
            let tty = crate::console::tty().ok_or(Errno::ENXIO)?;
            Ok(crate::tty::TtyFile::new(tty, fl))
        }
        (PTS_MAJOR, n) => {
            let name = alloc::format!("pts/{n}");
            let tty = crate::tty::ptys().into_iter().find(|t| t.name == name).ok_or(Errno::ENXIO)?;
            Ok(crate::tty::TtyFile::new(tty, fl))
        }
        _ => Err(Errno::ENXIO),
    }
}

pub fn open_block(rdev: u64, fl: u32) -> KResult<Arc<dyn File>> {
    if major(rdev) != SD_MAJOR {
        return Err(Errno::ENXIO);
    }
    let name = alloc::format!("sd{}", (b'a' + (minor(rdev) / 16) as u8) as char);
    let dev = crate::drivers::block::get(&name).ok_or(Errno::ENXIO)?;
    Ok(Arc::new(BlockFile { dev, rdev, off: SpinLock::new(0), flags: AtomicU32::new(fl) }))
}

/// Device number of a registered disk (`sda` → 8:0, `sdb` → 8:16).
pub fn disk_rdev(name: &str) -> Option<u64> {
    let letter = name.strip_prefix("sd")?.bytes().next()?;
    Some(makedev(SD_MAJOR, (letter - b'a') as u32 * 16))
}
