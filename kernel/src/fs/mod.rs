//! Virtual filesystem.
//!
//! * [`Inode`] — a filesystem object (file, directory, symlink, device...);
//!   every filesystem (ext2, tmpfs, procfs, devfs, overlay) implements it.
//! * [`path`] — resolution of path strings to [`path::PathRef`]s (a
//!   dentry-like chain of (mount, inode, name) that knows its parent, so
//!   `..`, mount crossing and `getcwd` are exact).
//! * [`mount`] — per-namespace mount tables (containers get their own).
//! * [`file`] — open file descriptions and descriptor tables.
//! * [`perm`] — POSIX permission checks against process credentials.

pub mod bcache;
pub mod boot;
pub mod devfs;
pub mod ext2fs;
pub mod file;
pub mod mount;
pub mod ops;
pub mod overlayfs;
pub mod path;
pub mod perm;
pub mod pipe;
pub mod procfs;
pub mod tmpfs;

pub use crate::errno::{Errno, KResult};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

pub type InodeRef = Arc<dyn Inode>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

impl FileType {
    /// `S_IFMT` bits.
    pub fn mode_bits(self) -> u32 {
        match self {
            FileType::Fifo => 0o010000,
            FileType::CharDevice => 0o020000,
            FileType::Directory => 0o040000,
            FileType::BlockDevice => 0o060000,
            FileType::Regular => 0o100000,
            FileType::Symlink => 0o120000,
            FileType::Socket => 0o140000,
        }
    }
    pub fn from_mode(mode: u32) -> Option<FileType> {
        Some(match mode & 0o170000 {
            0o010000 => FileType::Fifo,
            0o020000 => FileType::CharDevice,
            0o040000 => FileType::Directory,
            0o060000 => FileType::BlockDevice,
            0o100000 => FileType::Regular,
            0o120000 => FileType::Symlink,
            0o140000 => FileType::Socket,
            _ => return None,
        })
    }
    /// The type letter `ls -l` prints.
    pub fn letter(self) -> char {
        match self {
            FileType::Regular => '-',
            FileType::Directory => 'd',
            FileType::Symlink => 'l',
            FileType::CharDevice => 'c',
            FileType::BlockDevice => 'b',
            FileType::Fifo => 'p',
            FileType::Socket => 's',
        }
    }
    /// `d_type` values of `getdents64`.
    pub fn dirent_type(self) -> u8 {
        match self {
            FileType::Fifo => 1,
            FileType::CharDevice => 2,
            FileType::Directory => 4,
            FileType::BlockDevice => 6,
            FileType::Regular => 8,
            FileType::Symlink => 10,
            FileType::Socket => 12,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

impl Timespec {
    pub fn now() -> Timespec {
        let (s, n) = crate::time::wall_clock();
        Timespec { sec: s as i64, nsec: n }
    }
    pub const fn from_secs(sec: i64) -> Timespec {
        Timespec { sec, nsec: 0 }
    }
}

#[derive(Clone, Debug)]
pub struct Metadata {
    pub dev: u64,
    pub ino: u64,
    pub kind: FileType,
    /// Permission bits including setuid/setgid/sticky (`0o7777`).
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Allocated size in 512-byte units.
    pub blocks: u64,
    pub blksize: u32,
    pub rdev: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

impl Metadata {
    /// Full `st_mode` (type + permission bits).
    pub fn mode(&self) -> u32 {
        self.kind.mode_bits() | self.perm as u32
    }
}

/// Attribute changes (`chmod`, `chown`, `truncate`, `utimes`).
#[derive(Clone, Debug, Default)]
pub struct SetAttr {
    pub perm: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Option<Timespec>,
    pub mtime: Option<Timespec>,
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub kind: FileType,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StatFs {
    pub fs_type: u64,
    pub block_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_avail: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u64,
}

/// `major:minor` → Linux's `dev_t` encoding.
pub const fn makedev(major: u32, minor: u32) -> u64 {
    ((major as u64 & 0xFFF) << 8) | (minor as u64 & 0xFF) | ((minor as u64 & !0xFF) << 12)
}
pub const fn major(dev: u64) -> u32 {
    ((dev >> 8) & 0xFFF) as u32
}
pub const fn minor(dev: u64) -> u32 {
    ((dev & 0xFF) | ((dev >> 12) & !0xFF)) as u32
}

pub trait FileSystem: Send + Sync {
    fn root(&self) -> InodeRef;
    /// `ext2`, `tmpfs`, `proc`...
    fn fs_type(&self) -> &'static str;
    fn statfs(&self) -> StatFs;
    fn sync(&self) -> KResult<()> {
        Ok(())
    }
    fn dev(&self) -> u64;
}

/// A filesystem object. Methods default to the error a non-supporting
/// object type would produce, so each implementation only provides what
/// makes sense for it.
pub trait Inode: Send + Sync + Any {
    fn metadata(&self) -> KResult<Metadata>;

    fn set_attr(&self, _attr: &SetAttr) -> KResult<()> {
        Err(Errno::EPERM)
    }
    fn read_at(&self, _off: u64, _buf: &mut [u8]) -> KResult<usize> {
        Err(Errno::EINVAL)
    }
    fn write_at(&self, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(Errno::EINVAL)
    }

    fn lookup(&self, _name: &str) -> KResult<InodeRef> {
        Err(Errno::ENOTDIR)
    }
    /// Create a regular file, directory, device node or fifo.
    fn create(&self, _name: &str, _kind: FileType, _perm: u16, _uid: u32, _gid: u32, _rdev: u64) -> KResult<InodeRef> {
        Err(Errno::ENOTDIR)
    }
    fn symlink(&self, _name: &str, _target: &str, _uid: u32, _gid: u32) -> KResult<InodeRef> {
        Err(Errno::ENOTDIR)
    }
    /// Hard link `target` (same filesystem) into this directory as `name`.
    fn link(&self, _name: &str, _target: &InodeRef) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Remove a non-directory entry.
    fn unlink(&self, _name: &str) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Remove an empty directory entry.
    fn rmdir(&self, _name: &str) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Move `old` in this directory to `new` in `new_dir` (same filesystem).
    fn rename(&self, _old: &str, _new_dir: &InodeRef, _new: &str) -> KResult<()> {
        Err(Errno::ENOTDIR)
    }
    /// Directory entries, without `.` and `..`.
    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        Err(Errno::ENOTDIR)
    }
    fn readlink(&self) -> KResult<String> {
        Err(Errno::EINVAL)
    }
    fn sync(&self) -> KResult<()> {
        Ok(())
    }
    /// Special files (devices, fifos, generated files) open to their own
    /// [`file::File`]; `None` means "a normal inode-backed file".
    fn open_special(self: Arc<Self>, _flags: u32) -> KResult<Option<Arc<dyn file::File>>> {
        Ok(None)
    }
    fn as_any(&self) -> &dyn Any;
}

impl dyn Inode {
    pub fn kind(&self) -> KResult<FileType> {
        Ok(self.metadata()?.kind)
    }
    pub fn is_dir(&self) -> bool {
        self.metadata().is_ok_and(|m| m.kind == FileType::Directory)
    }
    /// Identity used for mount points and hard-link checks.
    pub fn id(&self) -> (u64, u64) {
        self.metadata().map(|m| (m.dev, m.ino)).unwrap_or((u64::MAX, u64::MAX))
    }
    /// Read the whole object (small files only: config, /proc).
    pub fn read_all(&self) -> KResult<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = alloc::vec![0u8; 16384];
        let mut off = 0u64;
        loop {
            let n = self.read_at(off, &mut buf)?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
        }
        Ok(out)
    }
}

