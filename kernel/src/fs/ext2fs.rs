//! ext2 mounted into the VFS: `fastros_ext2` behind one sleeping lock,
//! over the block cache, with an inode cache so every open of the same inode
//! shares one [`Ext2Node`] — which is what lets an unlinked-but-open file
//! keep its data until the last reference goes away.

use super::bcache::{BlockCache, CachedDevice};
use super::{DirEntry, Errno, FileSystem, FileType, Inode, InodeRef, KResult, Metadata, SetAttr, StatFs, Timespec};
use crate::drivers::block::BlockDevice;
use crate::sync::{Mutex, SpinLock};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use fastros_ext2 as e2;

const EXT2_MAGIC: u64 = 0xEF53;

pub struct Ext2Fs {
    inner: Mutex<e2::Ext2<CachedDevice>>,
    dev_id: u64,
    block_size: u32,
    icache: SpinLock<BTreeMap<u32, Weak<Ext2Node>>>,
    /// Unlinked inodes whose last reference dropped; freed at the next
    /// operation that may block (Drop can run while spinlocks are held).
    pending_evict: SpinLock<Vec<u32>>,
    this: Weak<Ext2Fs>,
}

pub struct Ext2Node {
    fs: Arc<Ext2Fs>,
    ino: u32,
}

fn clock() -> u32 {
    crate::time::unix_now() as u32
}

pub fn map_err(e: e2::Error) -> Errno {
    match e {
        e2::Error::Io => Errno::EIO,
        e2::Error::Corrupt => Errno::EIO,
        e2::Error::Unsupported => Errno::EINVAL,
        e2::Error::NotFound => Errno::ENOENT,
        e2::Error::Exists => Errno::EEXIST,
        e2::Error::NotDir => Errno::ENOTDIR,
        e2::Error::IsDir => Errno::EISDIR,
        e2::Error::NotEmpty => Errno::ENOTEMPTY,
        e2::Error::NoSpace => Errno::ENOSPC,
        e2::Error::NameTooLong => Errno::ENAMETOOLONG,
        e2::Error::TooManyLinks => Errno::EMLINK,
        e2::Error::ReadOnly => Errno::EROFS,
        e2::Error::Invalid => Errno::EINVAL,
        e2::Error::FileTooBig => Errno::EFBIG,
    }
}

/// Outcome of probing a disk for ext2.
pub enum Probe {
    Mounted(Arc<Ext2Fs>),
    NotExt2,
    Failed(Errno),
}

impl Ext2Fs {
    pub fn mount(dev: Arc<dyn BlockDevice>, dev_id: u64) -> Probe {
        let cache = BlockCache::new(dev, super::bcache::default_capacity());
        match e2::Ext2::open(CachedDevice(cache), clock) {
            Ok(fs) => {
                if !fs.was_clean() {
                    crate::kwarn!("ext2", "filesystem was not cleanly unmounted");
                }
                let bs = fs.block_size() as u32;
                Probe::Mounted(Arc::new_cyclic(|w| Ext2Fs {
                    inner: Mutex::new(fs),
                    dev_id,
                    block_size: bs,
                    icache: SpinLock::new(BTreeMap::new()),
                    pending_evict: SpinLock::new(Vec::new()),
                    this: w.clone(),
                }))
            }
            Err(e2::Error::Corrupt) => Probe::NotExt2,
            Err(e) => Probe::Failed(map_err(e)),
        }
    }

    /// Create a fresh filesystem on `dev` (destroys its contents).
    pub fn format(dev: Arc<dyn BlockDevice>, label: &str) -> KResult<()> {
        let mut cd = CachedDevice(BlockCache::new(dev, 1024));
        let opts = e2::FormatOptions {
            label,
            uuid: crate::crypto::rng::array(),
            now: clock(),
            bytes_per_inode: 16384,
        };
        e2::format(&mut cd, &opts).map_err(map_err)
    }

    fn node(&self, ino: u32) -> Arc<Ext2Node> {
        let mut ic = self.icache.lock();
        if let Some(n) = ic.get(&ino).and_then(|w| w.upgrade()) {
            return n;
        }
        let n = Arc::new(Ext2Node { fs: self.this.upgrade().expect("fs alive"), ino });
        ic.insert(ino, Arc::downgrade(&n));
        n
    }

    fn in_use(&self, ino: u32) -> bool {
        self.icache.lock().get(&ino).is_some_and(|w| w.strong_count() > 0)
    }

    /// Lock the filesystem, first releasing inodes whose last user went away.
    fn lock(&self) -> crate::sync::MutexGuard<'_, e2::Ext2<CachedDevice>> {
        let mut g = self.inner.lock();
        let pending = core::mem::take(&mut *self.pending_evict.lock());
        for ino in pending {
            if !self.in_use(ino) {
                if let Err(e) = g.evict(ino) {
                    crate::kerr!("ext2", "evicting inode {ino}: {:?}", e);
                }
            }
        }
        g
    }

    pub fn unmount(&self) -> KResult<()> {
        self.lock().unmount().map_err(map_err)
    }

    pub fn label(&self) -> String {
        self.lock().label()
    }
}

impl FileSystem for Ext2Fs {
    fn root(&self) -> InodeRef {
        self.node(e2::ROOT_INO)
    }
    fn fs_type(&self) -> &'static str {
        "ext2"
    }
    fn dev(&self) -> u64 {
        self.dev_id
    }
    fn statfs(&self) -> StatFs {
        let s = self.lock().stats();
        StatFs {
            fs_type: EXT2_MAGIC,
            block_size: s.block_size as u64,
            blocks: s.blocks,
            blocks_free: s.free_blocks,
            blocks_avail: s.free_blocks.saturating_sub(s.reserved_blocks),
            files: s.inodes,
            files_free: s.free_inodes,
            name_max: 255,
        }
    }
    fn sync(&self) -> KResult<()> {
        self.lock().sync().map_err(map_err)
    }
}

impl Drop for Ext2Node {
    fn drop(&mut self) {
        let mut ic = self.fs.icache.lock();
        if ic.get(&self.ino).is_some_and(|w| w.strong_count() == 0) {
            ic.remove(&self.ino);
        }
        drop(ic);
        self.fs.pending_evict.lock().push(self.ino);
    }
}

fn kind_of(mode: u16) -> FileType {
    FileType::from_mode(mode as u32).unwrap_or(FileType::Regular)
}

impl Inode for Ext2Node {
    fn metadata(&self) -> KResult<Metadata> {
        let i = self.fs.lock().read_inode(self.ino).map_err(map_err)?;
        let kind = kind_of(i.mode());
        Ok(Metadata {
            dev: self.fs.dev_id,
            ino: self.ino as u64,
            kind,
            perm: i.mode() & 0o7777,
            nlink: i.links() as u32,
            uid: i.uid(),
            gid: i.gid(),
            size: i.size(),
            blocks: i.sectors() as u64,
            blksize: self.fs.block_size,
            rdev: if matches!(kind, FileType::CharDevice | FileType::BlockDevice) { i.rdev() as u64 } else { 0 },
            atime: Timespec::from_secs(i.atime() as i64),
            mtime: Timespec::from_secs(i.mtime() as i64),
            ctime: Timespec::from_secs(i.ctime() as i64),
        })
    }

    fn set_attr(&self, a: &SetAttr) -> KResult<()> {
        let attr = e2::Attr {
            mode: a.perm,
            uid: a.uid,
            gid: a.gid,
            size: a.size,
            atime: a.atime.map(|t| t.sec as u32),
            mtime: a.mtime.map(|t| t.sec as u32),
            ctime: None,
        };
        self.fs.lock().set_attr(self.ino, &attr).map_err(map_err)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.fs.lock().read(self.ino, off, buf).map_err(map_err)
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        self.fs.lock().write(self.ino, off, buf).map_err(map_err)
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let ino = self.fs.lock().lookup(self.ino, name).map_err(map_err)?;
        Ok(self.fs.node(ino))
    }

    fn create(&self, name: &str, kind: FileType, perm: u16, uid: u32, gid: u32, rdev: u64) -> KResult<InodeRef> {
        let mode = kind.mode_bits() as u16 | (perm & 0o7777);
        let ino = {
            let mut fs = self.fs.lock();
            if kind == FileType::Directory {
                fs.mkdir(self.ino, name, mode, uid, gid)
            } else {
                fs.create(self.ino, name, mode, uid, gid, rdev as u32)
            }
            .map_err(map_err)?
        };
        Ok(self.fs.node(ino))
    }

    fn symlink(&self, name: &str, target: &str, uid: u32, gid: u32) -> KResult<InodeRef> {
        let ino = self.fs.lock().symlink(self.ino, name, target, uid, gid).map_err(map_err)?;
        Ok(self.fs.node(ino))
    }

    fn link(&self, name: &str, target: &InodeRef) -> KResult<()> {
        let t = target.as_any().downcast_ref::<Ext2Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&t.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        self.fs.lock().link(self.ino, name, t.ino).map_err(map_err)
    }

    fn unlink(&self, name: &str) -> KResult<()> {
        let mut fs = self.fs.lock();
        let ino = fs.lookup(self.ino, name).map_err(map_err)?;
        let in_use = self.fs.in_use(ino);
        fs.unlink(self.ino, name, in_use).map_err(map_err)?;
        Ok(())
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        self.fs.lock().rmdir(self.ino, name).map_err(map_err)
    }

    fn rename(&self, old: &str, new_dir: &InodeRef, new: &str) -> KResult<()> {
        let nd = new_dir.as_any().downcast_ref::<Ext2Node>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&nd.fs, &self.fs) {
            return Err(Errno::EXDEV);
        }
        self.fs.lock().rename(self.ino, old, nd.ino, new).map_err(map_err)
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        let entries = self.fs.lock().readdir(self.ino).map_err(map_err)?;
        Ok(entries
            .into_iter()
            .filter(|e| e.name != "." && e.name != "..")
            .map(|e| DirEntry {
                name: e.name,
                ino: e.ino as u64,
                kind: match e.file_type {
                    e2::ft::DIR => FileType::Directory,
                    e2::ft::SYMLINK => FileType::Symlink,
                    e2::ft::CHR => FileType::CharDevice,
                    e2::ft::BLK => FileType::BlockDevice,
                    e2::ft::FIFO => FileType::Fifo,
                    e2::ft::SOCK => FileType::Socket,
                    _ => FileType::Regular,
                },
            })
            .collect())
    }

    fn readlink(&self) -> KResult<String> {
        self.fs.lock().readlink(self.ino).map_err(map_err)
    }

    fn sync(&self) -> KResult<()> {
        self.fs.lock().sync().map_err(map_err)
    }

    fn open_special(self: Arc<Self>, flags: u32) -> KResult<Option<Arc<dyn super::file::File>>> {
        let m = self.metadata()?;
        match m.kind {
            FileType::CharDevice => crate::device::open_char(m.rdev, flags).map(Some),
            FileType::BlockDevice => crate::device::open_block(m.rdev, flags).map(Some),
            FileType::Fifo => crate::fs::pipe::open_named(self.fs.dev_id, m.ino, flags).map(Some),
            _ => Ok(None),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
