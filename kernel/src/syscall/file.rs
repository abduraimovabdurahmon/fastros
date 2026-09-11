//! File and descriptor system calls, routed through the process's descriptor
//! table and the VFS (`fs::ops`).

use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File, Whence};
use crate::fs::{ops, FileType, Metadata};
use crate::proc;
use crate::uaccess;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_EMPTY_PATH: i32 = 0x1000;

fn fdt_get(fd: i32) -> KResult<Arc<dyn File>> {
    proc::current().fds.lock().get(fd)
}

/// Read a user path string (capped at PATH_MAX).
fn user_path(addr: usize) -> KResult<String> {
    let space = proc::current_aspace().ok_or(Errno::EFAULT)?;
    let bytes = space.read_cstr(addr, 4096)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Resolve an `*at` path: absolute paths ignore `dirfd`; AT_FDCWD uses the cwd.
fn at_path(dirfd: i32, path: &str) -> KResult<String> {
    if path.starts_with('/') || dirfd == AT_FDCWD {
        return Ok(String::from(path));
    }
    let f = fdt_get(dirfd)?;
    let base = f.path().ok_or(Errno::ENOTDIR)?.path();
    Ok(if path.is_empty() { base } else { alloc::format!("{base}/{path}") })
}

pub fn read(fd: i32, buf: usize, len: usize) -> KResult<usize> {
    let f = fdt_get(fd)?;
    if !f.readable() {
        return Err(Errno::EBADF);
    }
    let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
    let n = f.read(&mut tmp)?;
    uaccess::copy_to(buf, &tmp[..n])?;
    Ok(n)
}

pub fn write(fd: i32, buf: usize, len: usize) -> KResult<usize> {
    let f = fdt_get(fd)?;
    if !f.writable() {
        return Err(Errno::EBADF);
    }
    let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
    uaccess::copy_from(buf, &mut tmp)?;
    f.write(&tmp)
}

pub fn pread(fd: i32, buf: usize, len: usize, off: u64) -> KResult<usize> {
    let f = fdt_get(fd)?;
    let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
    let n = f.pread(off, &mut tmp)?;
    uaccess::copy_to(buf, &tmp[..n])?;
    Ok(n)
}

pub fn pwrite(fd: i32, buf: usize, len: usize, off: u64) -> KResult<usize> {
    let f = fdt_get(fd)?;
    let mut tmp = alloc::vec![0u8; len.min(1 << 20)];
    uaccess::copy_from(buf, &mut tmp)?;
    f.pwrite(off, &tmp)
}

/// One `struct iovec` { base, len }.
fn read_iovec(ptr: usize, cnt: usize) -> KResult<Vec<(usize, usize)>> {
    let mut v = Vec::with_capacity(cnt);
    for i in 0..cnt {
        let base: u64 = uaccess::read_obj(ptr + i * 16)?;
        let len: u64 = uaccess::read_obj(ptr + i * 16 + 8)?;
        v.push((base as usize, len as usize));
    }
    Ok(v)
}

pub fn readv(fd: i32, iov: usize, cnt: usize) -> KResult<usize> {
    let mut total = 0;
    for (base, len) in read_iovec(iov, cnt)? {
        let n = read(fd, base, len)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

pub fn writev(fd: i32, iov: usize, cnt: usize) -> KResult<usize> {
    let mut total = 0;
    for (base, len) in read_iovec(iov, cnt)? {
        if len == 0 {
            continue;
        }
        let n = write(fd, base, len)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

fn do_open(path: &str, flags: u32, mode: u16) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let f = ops::open(&ctx, path, flags, mode & !(p.fs.lock().umask))?;
    let cloexec = flags & crate::fs::file::flags::O_CLOEXEC != 0;
    let fd = p.fds.lock().alloc(f, cloexec, 0)?;
    Ok(fd as usize)
}

pub fn open(path: usize, flags: u32, mode: u16) -> KResult<usize> {
    do_open(&user_path(path)?, flags, mode)
}

pub fn openat(dirfd: i32, path: usize, flags: u32, mode: u16) -> KResult<usize> {
    let path = at_path(dirfd, &user_path(path)?)?;
    do_open(&path, flags, mode)
}

pub fn close(fd: i32) -> KResult<usize> {
    proc::current().fds.lock().close(fd)?;
    Ok(0)
}

pub fn lseek(fd: i32, off: i64, whence: u32) -> KResult<usize> {
    let f = fdt_get(fd)?;
    let w = match whence {
        0 => Whence::Set(off),
        1 => Whence::Cur(off),
        2 => Whence::End(off),
        _ => return Err(Errno::EINVAL),
    };
    Ok(f.seek(w)? as usize)
}

pub fn dup(fd: i32) -> KResult<usize> {
    let f = fdt_get(fd)?;
    Ok(proc::current().fds.lock().alloc(f, false, 0)? as usize)
}

pub fn dup2(old: i32, new: i32) -> KResult<usize> {
    if fdt_get(old).is_err() {
        return Err(Errno::EBADF);
    }
    if old == new {
        return Ok(new as usize);
    }
    Ok(proc::current().fds.lock().dup2(old, new)? as usize)
}

pub fn dup3(old: i32, new: i32, flags: u32) -> KResult<usize> {
    if old == new {
        return Err(Errno::EINVAL);
    }
    let fd = dup2(old, new)?;
    if flags & crate::fs::file::flags::O_CLOEXEC != 0 {
        proc::current().fds.lock().set_cloexec(new, true)?;
    }
    Ok(fd)
}

pub fn fcntl(fd: i32, cmd: u32, arg: usize) -> KResult<usize> {
    const F_DUPFD: u32 = 0;
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    const F_GETFL: u32 = 3;
    const F_SETFL: u32 = 4;
    const F_DUPFD_CLOEXEC: u32 = 1030;
    let p = proc::current();
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let f = fdt_get(fd)?;
            let nfd = p.fds.lock().alloc(f, cmd == F_DUPFD_CLOEXEC, arg)?;
            Ok(nfd as usize)
        }
        F_GETFD => Ok(p.fds.lock().entry(fd)?.cloexec as usize),
        F_SETFD => {
            p.fds.lock().set_cloexec(fd, arg & 1 != 0)?;
            Ok(0)
        }
        F_GETFL => Ok(fdt_get(fd)?.flags() as usize),
        F_SETFL => {
            fdt_get(fd)?.set_flags(arg as u32);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
}

pub fn ioctl(fd: i32, req: u32, arg: usize) -> KResult<usize> {
    fdt_get(fd)?.ioctl(req, arg)
}

pub fn pipe(fds: usize, flags: u32) -> KResult<usize> {
    let (r, w) = crate::fs::pipe::pipe();
    let cloexec = flags & crate::fs::file::flags::O_CLOEXEC != 0;
    let p = proc::current();
    let mut t = p.fds.lock();
    let rfd = t.alloc(r, cloexec, 0)?;
    let wfd = t.alloc(w, cloexec, 0)?;
    drop(t);
    uaccess::write_obj(fds, &(rfd))?;
    uaccess::write_obj(fds + 4, &(wfd))?;
    Ok(0)
}

// ── stat family ──────────────────────────────────────────────────────────

/// Linux x86_64 `struct stat` (144 bytes).
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KStat {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    _pad0: u32,
    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,
    atime: i64,
    atime_ns: i64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
    _unused: [i64; 3],
}

fn to_kstat(m: &Metadata) -> KStat {
    KStat {
        dev: m.dev,
        ino: m.ino,
        nlink: m.nlink as u64,
        mode: m.kind.mode_bits() | m.perm as u32,
        uid: m.uid,
        gid: m.gid,
        rdev: m.rdev,
        size: m.size as i64,
        blksize: m.blksize as i64,
        blocks: m.blocks as i64,
        atime: m.atime.sec,
        atime_ns: m.atime.nsec as i64,
        mtime: m.mtime.sec,
        mtime_ns: m.mtime.nsec as i64,
        ctime: m.ctime.sec,
        ctime_ns: m.ctime.nsec as i64,
        ..Default::default()
    }
}

pub fn stat(path: usize, buf: usize, follow: bool) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let m = ops::stat(&ctx, &user_path(path)?, follow)?;
    uaccess::write_obj(buf, &to_kstat(&m))?;
    Ok(0)
}

pub fn fstat(fd: i32, buf: usize) -> KResult<usize> {
    let m = fdt_get(fd)?.stat()?;
    uaccess::write_obj(buf, &to_kstat(&m))?;
    Ok(0)
}

pub fn newfstatat(dirfd: i32, path: usize, buf: usize, flags: i32) -> KResult<usize> {
    let path = user_path(path)?;
    if path.is_empty() && flags & AT_EMPTY_PATH != 0 {
        return fstat(dirfd, buf);
    }
    let full = at_path(dirfd, &path)?;
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let m = ops::stat(&ctx, &full, flags & AT_SYMLINK_NOFOLLOW == 0)?;
    uaccess::write_obj(buf, &to_kstat(&m))?;
    Ok(0)
}

pub fn access(path: usize, mode: u32) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::access(&ctx, &user_path(path)?, mode)?;
    Ok(0)
}

pub fn faccessat(dirfd: i32, path: usize, mode: u32) -> KResult<usize> {
    let full = at_path(dirfd, &user_path(path)?)?;
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::access(&ctx, &full, mode)?;
    Ok(0)
}

// ── ownership ──────────────────────────────────────────────────────────────

pub fn chown(path: usize, uid: u32, gid: u32, follow: bool) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let (u, g) = (opt_id(uid), opt_id(gid));
    ops::chown(&ctx, &user_path(path)?, u, g, follow)?;
    Ok(0)
}

pub fn fchown(fd: i32, uid: u32, gid: u32) -> KResult<usize> {
    let f = fdt_get(fd)?;
    // Ownership only applies to inode-backed files; ignore it for pipes/sockets.
    let Some(path) = f.path() else { return Ok(0) };
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::chown(&ctx, &path.path(), opt_id(uid), opt_id(gid), true)?;
    Ok(0)
}

pub fn fchownat(dirfd: i32, path: usize, uid: u32, gid: u32, flags: i32) -> KResult<usize> {
    let pathstr = user_path(path)?;
    if pathstr.is_empty() && flags & AT_EMPTY_PATH != 0 {
        return fchown(dirfd, uid, gid);
    }
    let full = at_path(dirfd, &pathstr)?;
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::chown(&ctx, &full, opt_id(uid), opt_id(gid), flags & AT_SYMLINK_NOFOLLOW == 0)?;
    Ok(0)
}

/// `chown`'s convention: `-1` (0xffffffff) means "leave this id unchanged".
fn opt_id(id: u32) -> Option<u32> {
    if id == u32::MAX {
        None
    } else {
        Some(id)
    }
}

// ── statfs ─────────────────────────────────────────────────────────────────

/// Linux x86_64 `struct statfs` (120 bytes).
fn write_statfs(buf: usize, s: &crate::fs::StatFs) -> KResult<()> {
    let mut out = [0u8; 120];
    let mut put = |off: usize, v: u64| out[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(0, s.fs_type);
    put(8, s.block_size);
    put(16, s.blocks);
    put(24, s.blocks_free);
    put(32, s.blocks_avail);
    put(40, s.files);
    put(48, s.files_free);
    // 56: f_fsid (8 bytes, left zero)
    put(64, s.name_max);
    put(72, s.block_size); // f_frsize
    uaccess::copy_to(buf, &out)?;
    Ok(())
}

pub fn statfs(path: usize, buf: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let (s, _) = ops::statfs(&ctx, &user_path(path)?)?;
    write_statfs(buf, &s)?;
    Ok(0)
}

pub fn fstatfs(fd: i32, buf: usize) -> KResult<usize> {
    let f = fdt_get(fd)?;
    let path = f.path().ok_or(Errno::EBADF)?;
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let (s, _) = ops::statfs(&ctx, &path.path())?;
    write_statfs(buf, &s)?;
    Ok(0)
}

// ── directory / namespace operations ───────────────────────────────────────

pub fn getcwd(buf: usize, len: usize) -> KResult<usize> {
    let cwd = proc::current().fs.lock().cwd.path();
    let bytes = cwd.as_bytes();
    if bytes.len() + 1 > len {
        return Err(Errno::ERANGE);
    }
    uaccess::copy_to(buf, bytes)?;
    uaccess::copy_to(buf + bytes.len(), &[0u8])?;
    Ok(bytes.len() + 1)
}

pub fn chdir(path: usize) -> KResult<usize> {
    let p = proc::current();
    ops::chdir(&p, &user_path(path)?)?;
    Ok(0)
}

pub fn fchdir(fd: i32) -> KResult<usize> {
    let path = fdt_get(fd)?.path().ok_or(Errno::ENOTDIR)?.path();
    let p = proc::current();
    ops::chdir(&p, &path)?;
    Ok(0)
}

pub fn mkdir(path: usize, mode: u16) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::mkdir(&ctx, &user_path(path)?, mode & !(p.fs.lock().umask))?;
    Ok(0)
}

pub fn rmdir(path: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::rmdir(&ctx, &user_path(path)?)?;
    Ok(0)
}

pub fn unlink(path: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::unlink(&ctx, &user_path(path)?)?;
    Ok(0)
}

pub fn rename(from: usize, to: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::rename(&ctx, &user_path(from)?, &user_path(to)?)?;
    Ok(0)
}

pub fn link(target: usize, path: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::link(&ctx, &user_path(target)?, &user_path(path)?)?;
    Ok(0)
}

pub fn symlink(target: usize, path: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::symlink(&ctx, &user_path(target)?, &user_path(path)?)?;
    Ok(0)
}

pub fn readlink(path: usize, buf: usize, len: usize) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    let target = ops::readlink(&ctx, &user_path(path)?)?;
    let bytes = target.as_bytes();
    let n = bytes.len().min(len);
    uaccess::copy_to(buf, &bytes[..n])?;
    Ok(n)
}

pub fn chmod(path: usize, mode: u16) -> KResult<usize> {
    let p = proc::current();
    let ctx = ops::Ctx::of(&p);
    ops::chmod(&ctx, &user_path(path)?, mode, true)?;
    Ok(0)
}

// ── getdents64 ─────────────────────────────────────────────────────────────

pub fn getdents64(fd: i32, buf: usize, len: usize) -> KResult<usize> {
    let f = fdt_get(fd)?;
    // A directory offset selects where to resume; we page through the snapshot.
    let entries = f.readdir()?;
    let start = f.seek(Whence::Cur(0)).unwrap_or(0) as usize;
    let mut out: Vec<u8> = Vec::new();
    let mut consumed = start;
    for e in entries.iter().skip(start) {
        let name = e.name.as_bytes();
        let reclen = (19 + name.len() + 1 + 7) & !7; // align to 8
        if out.len() + reclen > len {
            break;
        }
        let dtype = match e.kind {
            FileType::Fifo => 1,
            FileType::CharDevice => 2,
            FileType::Directory => 4,
            FileType::BlockDevice => 6,
            FileType::Regular => 8,
            FileType::Symlink => 10,
            FileType::Socket => 12,
        };
        out.extend_from_slice(&e.ino.to_le_bytes());
        out.extend_from_slice(&((consumed + 1) as u64).to_le_bytes());
        out.extend_from_slice(&(reclen as u16).to_le_bytes());
        out.push(dtype);
        out.extend_from_slice(name);
        out.resize(out.len() + (reclen - 19 - name.len()), 0);
        consumed += 1;
    }
    if !out.is_empty() {
        uaccess::copy_to(buf, &out)?;
        f.seek(Whence::Set(consumed as i64))?;
    } else if consumed < entries.len() {
        return Err(Errno::EINVAL); // buffer too small for even one entry
    }
    Ok(out.len())
}
