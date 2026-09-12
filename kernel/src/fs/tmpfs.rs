//! tmpfs: an in-memory filesystem (also the base of devfs and the rootfs
//! fallback when no disk is attached).
//!
//! Regular files store data in a sparse map of 4 KiB pages, so large files
//! never need huge contiguous buffers and holes cost nothing. An optional
//! byte limit (`size=` mount option) bounds memory use.

use super::file::File;
use super::pipe::Pipe;
use super::{DirEntry, Errno, FileSystem, FileType, Inode, InodeRef, KResult, Metadata, SetAttr, StatFs, Timespec};
use crate::sync::SpinLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

const PAGE: usize = 4096;
const TMPFS_MAGIC: u64 = 0x0102_1994;

static NEXT_DEV: AtomicU64 = AtomicU64::new(0x100);

pub struct TmpFs {
    dev: u64,
    root: Arc<TmpNode>,
    shared: Arc<Shared>,
    /// `tmpfs`, or `devtmpfs` for /dev.
    type_name: &'static str,
}

struct Shared {
    dev: u64,
    next_ino: AtomicU64,
    used: AtomicU64,
    limit: u64,
    inodes: AtomicU64,
}

enum Data {
    File { pages: BTreeMap<u64, Box<[u8; PAGE]>>, size: u64 },
    Dir(BTreeMap<String, Arc<TmpNode>>),
    Symlink(String),
    Fifo(Arc<Pipe>),
    Device,
}

struct Meta {
    kind: FileType,
    perm: u16,
    uid: u32,
    gid: u32,
    nlink: u32,
    rdev: u64,
    atime: Timespec,
    mtime: Timespec,
    ctime: Timespec,
}

pub struct TmpNode {
    ino: u64,
    shared: Arc<Shared>,
    meta: SpinLock<Meta>,
    data: SpinLock<Data>,
    this: Weak<TmpNode>,
    /// Shared page set for `MAP_SHARED` mappings of this file (POSIX shm),
    /// created on first mmap and shared by every process that maps it.
    mmap_shared: SpinLock<Option<Arc<crate::mm::aspace::SharedAnon>>>,
}

impl TmpFs {
    /// `limit` in bytes (0 = unlimited).
    pub fn new(limit: u64) -> Arc<TmpFs> {
        Self::named(limit, "tmpfs")
    }
    /// A tmpfs reporting another type name (`devtmpfs`).
    pub fn named(limit: u64, type_name: &'static str) -> Arc<TmpFs> {
        let dev = NEXT_DEV.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(Shared { dev, next_ino: AtomicU64::new(2), used: AtomicU64::new(0), limit, inodes: AtomicU64::new(1) });
        let root = TmpNode::new(&shared, 1, FileType::Directory, 0o755, 0, 0, 0, Data::Dir(BTreeMap::new()));
        root.meta.lock().nlink = 2;
        Arc::new(TmpFs { dev, root, shared, type_name })
    }
    pub fn root_node(&self) -> Arc<TmpNode> {
        self.root.clone()
    }
}

impl FileSystem for TmpFs {
    fn root(&self) -> InodeRef {
        self.root.clone()
    }
    fn fs_type(&self) -> &'static str {
        self.type_name
    }
    fn dev(&self) -> u64 {
        self.dev
    }
    fn statfs(&self) -> StatFs {
        let used = self.shared.used.load(Ordering::Relaxed);
        let (_, free_frames) = crate::mm::frame::counts();
        let limit = if self.shared.limit > 0 { self.shared.limit } else { used + free_frames as u64 * PAGE as u64 / 2 };
        let blocks = limit / PAGE as u64;
        let free = limit.saturating_sub(used) / PAGE as u64;
        StatFs {
            fs_type: TMPFS_MAGIC,
            block_size: PAGE as u64,
            blocks,
            blocks_free: free,
            blocks_avail: free,
            files: 1 << 20,
            files_free: (1 << 20) - self.shared.inodes.load(Ordering::Relaxed),
            name_max: 255,
        }
    }
}

impl TmpNode {
    #[allow(clippy::too_many_arguments)]
    fn new(shared: &Arc<Shared>, ino: u64, kind: FileType, perm: u16, uid: u32, gid: u32, rdev: u64, data: Data) -> Arc<TmpNode> {
        let now = Timespec::now();
        Arc::new_cyclic(|w| TmpNode {
            ino,
            shared: shared.clone(),
            meta: SpinLock::new(Meta { kind, perm, uid, gid, nlink: 1, rdev, atime: now, mtime: now, ctime: now }),
            data: SpinLock::new(data),
            this: w.clone(),
            mmap_shared: SpinLock::new(None),
        })
    }

    fn arc(&self) -> Arc<TmpNode> {
        self.this.upgrade().expect("tmpfs node alive")
    }

    fn charge(&self, bytes: u64) -> KResult<()> {
        let s = &self.shared;
        let used = s.used.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if s.limit > 0 && used > s.limit {
            s.used.fetch_sub(bytes, Ordering::Relaxed);
            return Err(Errno::ENOSPC);
        }
        Ok(())
    }
    fn uncharge(&self, bytes: u64) {
        self.shared.used.fetch_sub(bytes, Ordering::Relaxed);
    }

    fn touch_mc(&self) {
        let now = Timespec::now();
        let mut m = self.meta.lock();
        m.mtime = now;
        m.ctime = now;
    }

    /// Insert a child into this directory.
    fn add_child(&self, name: &str, node: Arc<TmpNode>) -> KResult<()> {
        let mut d = self.data.lock();
        let Data::Dir(map) = &mut *d else { return Err(Errno::ENOTDIR) };
        if map.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        map.insert(name.to_string(), node);
        drop(d);
        self.touch_mc();
        Ok(())
    }

    fn truncate(&self, size: u64) -> KResult<()> {
        let mut d = self.data.lock();
        let Data::File { pages, size: cur } = &mut *d else { return Err(Errno::EISDIR) };
        if size < *cur {
            let first_dead = size.div_ceil(PAGE as u64);
            let dead: Vec<u64> = pages.range(first_dead..).map(|(&k, _)| k).collect();
            for k in &dead {
                pages.remove(k);
            }
            self.uncharge(dead.len() as u64 * PAGE as u64);
            // Zero the tail of the last partial page.
            let off = (size % PAGE as u64) as usize;
            if off != 0 {
                if let Some(p) = pages.get_mut(&(size / PAGE as u64)) {
                    p[off..].fill(0);
                }
            }
        }
        *cur = size;
        Ok(())
    }

    fn is_empty_dir(&self) -> bool {
        matches!(&*self.data.lock(), Data::Dir(m) if m.is_empty())
    }
}

impl Drop for TmpNode {
    fn drop(&mut self) {
        let d = self.data.get_mut();
        if let Data::File { pages, .. } = d {
            self.shared.used.fetch_sub(pages.len() as u64 * PAGE as u64, Ordering::Relaxed);
        }
        self.shared.inodes.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Inode for TmpNode {
    fn metadata(&self) -> KResult<Metadata> {
        let m = self.meta.lock();
        let (size, blocks) = match &*self.data.lock() {
            Data::File { pages, size } => (*size, pages.len() as u64 * (PAGE as u64 / 512)),
            Data::Dir(map) => ((map.len() as u64 + 2) * 20, 0),
            Data::Symlink(t) => (t.len() as u64, 0),
            _ => (0, 0),
        };
        Ok(Metadata {
            dev: self.shared.dev,
            ino: self.ino,
            kind: m.kind,
            perm: m.perm,
            nlink: m.nlink,
            uid: m.uid,
            gid: m.gid,
            size,
            blocks,
            blksize: PAGE as u32,
            rdev: m.rdev,
            atime: m.atime,
            mtime: m.mtime,
            ctime: m.ctime,
        })
    }

    fn set_attr(&self, a: &SetAttr) -> KResult<()> {
        if let Some(size) = a.size {
            self.truncate(size)?;
        }
        let mut m = self.meta.lock();
        if let Some(p) = a.perm {
            m.perm = p & 0o7777;
        }
        if let Some(u) = a.uid {
            m.uid = u;
        }
        if let Some(g) = a.gid {
            m.gid = g;
        }
        if let Some(t) = a.atime {
            m.atime = t;
        }
        if let Some(t) = a.mtime {
            m.mtime = t;
        }
        m.ctime = Timespec::now();
        Ok(())
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = self.data.lock();
        match &*d {
            Data::File { pages, size } => {
                if off >= *size {
                    return Ok(0);
                }
                let n = buf.len().min((*size - off) as usize);
                let mut done = 0;
                while done < n {
                    let pos = off + done as u64;
                    let pi = pos / PAGE as u64;
                    let po = (pos % PAGE as u64) as usize;
                    let chunk = (PAGE - po).min(n - done);
                    match pages.get(&pi) {
                        Some(p) => buf[done..done + chunk].copy_from_slice(&p[po..po + chunk]),
                        None => buf[done..done + chunk].fill(0),
                    }
                    done += chunk;
                }
                Ok(n)
            }
            Data::Dir(_) => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let end = off.checked_add(buf.len() as u64).ok_or(Errno::EFBIG)?;
        if end > (1u64 << 40) {
            return Err(Errno::EFBIG);
        }
        let mut d = self.data.lock();
        let Data::File { pages, size } = &mut *d else { return Err(Errno::EISDIR) };
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let pi = pos / PAGE as u64;
            let po = (pos % PAGE as u64) as usize;
            let chunk = (PAGE - po).min(buf.len() - done);
            if !pages.contains_key(&pi) {
                self.charge(PAGE as u64)?;
                pages.insert(pi, Box::new([0u8; PAGE]));
            }
            pages.get_mut(&pi).expect("just inserted")[po..po + chunk].copy_from_slice(&buf[done..done + chunk]);
            done += chunk;
        }
        if end > *size {
            *size = end;
        }
        drop(d);
        self.touch_mc();
        Ok(buf.len())
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match &*self.data.lock() {
            Data::Dir(map) => map.get(name).cloned().map(|n| n as InodeRef).ok_or(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn create(&self, name: &str, kind: FileType, perm: u16, uid: u32, gid: u32, rdev: u64) -> KResult<InodeRef> {
        let data = match kind {
            FileType::Regular => Data::File { pages: BTreeMap::new(), size: 0 },
            FileType::Directory => Data::Dir(BTreeMap::new()),
            FileType::Fifo => Data::Fifo(Pipe::new()),
            FileType::CharDevice | FileType::BlockDevice | FileType::Socket => Data::Device,
            FileType::Symlink => return Err(Errno::EINVAL),
        };
        let ino = self.shared.next_ino.fetch_add(1, Ordering::Relaxed);
        let node = TmpNode::new(&self.shared, ino, kind, perm & 0o7777, uid, gid, rdev, data);
        if kind == FileType::Directory {
            node.meta.lock().nlink = 2;
        }
        self.add_child(name, node.clone())?;
        self.shared.inodes.fetch_add(1, Ordering::Relaxed);
        if kind == FileType::Directory {
            self.meta.lock().nlink += 1;
        }
        Ok(node)
    }

    fn symlink(&self, name: &str, target: &str, uid: u32, gid: u32) -> KResult<InodeRef> {
        let ino = self.shared.next_ino.fetch_add(1, Ordering::Relaxed);
        let node = TmpNode::new(&self.shared, ino, FileType::Symlink, 0o777, uid, gid, 0, Data::Symlink(target.to_string()));
        self.add_child(name, node.clone())?;
        self.shared.inodes.fetch_add(1, Ordering::Relaxed);
        Ok(node)
    }

    fn link(&self, name: &str, target: &InodeRef) -> KResult<()> {
        let t = target.as_any().downcast_ref::<TmpNode>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&t.shared, &self.shared) {
            return Err(Errno::EXDEV);
        }
        if t.meta.lock().kind == FileType::Directory {
            return Err(Errno::EPERM);
        }
        self.add_child(name, t.arc())?;
        let mut m = t.meta.lock();
        m.nlink += 1;
        m.ctime = Timespec::now();
        Ok(())
    }

    fn unlink(&self, name: &str) -> KResult<()> {
        let mut d = self.data.lock();
        let Data::Dir(map) = &mut *d else { return Err(Errno::ENOTDIR) };
        let child = map.get(name).ok_or(Errno::ENOENT)?;
        if child.meta.lock().kind == FileType::Directory {
            return Err(Errno::EISDIR);
        }
        let child = map.remove(name).expect("checked");
        drop(d);
        let mut m = child.meta.lock();
        m.nlink = m.nlink.saturating_sub(1);
        m.ctime = Timespec::now();
        drop(m);
        self.touch_mc();
        Ok(())
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        let mut d = self.data.lock();
        let Data::Dir(map) = &mut *d else { return Err(Errno::ENOTDIR) };
        let child = map.get(name).ok_or(Errno::ENOENT)?;
        if child.meta.lock().kind != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if !child.is_empty_dir() {
            return Err(Errno::ENOTEMPTY);
        }
        let child = map.remove(name).expect("checked");
        drop(d);
        child.meta.lock().nlink = 0;
        self.meta.lock().nlink -= 1;
        self.touch_mc();
        Ok(())
    }

    fn rename(&self, old: &str, new_dir: &InodeRef, new: &str) -> KResult<()> {
        let nd = new_dir.as_any().downcast_ref::<TmpNode>().ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&nd.shared, &self.shared) {
            return Err(Errno::EXDEV);
        }
        let same = core::ptr::eq(nd, self);
        let node = match &*self.data.lock() {
            Data::Dir(m) => m.get(old).cloned().ok_or(Errno::ENOENT)?,
            _ => return Err(Errno::ENOTDIR),
        };
        let is_dir = node.meta.lock().kind == FileType::Directory;
        // Existing target: must be compatible and (if a directory) empty.
        let existing = match &*nd.data.lock() {
            Data::Dir(m) => m.get(new).cloned(),
            _ => return Err(Errno::ENOTDIR),
        };
        if let Some(ex) = &existing {
            if Arc::ptr_eq(ex, &node) {
                return Ok(());
            }
            let ex_dir = ex.meta.lock().kind == FileType::Directory;
            if is_dir && !ex_dir {
                return Err(Errno::ENOTDIR);
            }
            if !is_dir && ex_dir {
                return Err(Errno::EISDIR);
            }
            if ex_dir && !ex.is_empty_dir() {
                return Err(Errno::ENOTEMPTY);
            }
        }
        if let Data::Dir(m) = &mut *self.data.lock() {
            m.remove(old);
        }
        if let Data::Dir(m) = &mut *nd.data.lock() {
            m.insert(new.to_string(), node.clone());
        }
        if let Some(ex) = existing {
            let mut em = ex.meta.lock();
            em.nlink = if em.kind == FileType::Directory { 0 } else { em.nlink.saturating_sub(1) };
            if em.kind == FileType::Directory {
                drop(em);
                nd.meta.lock().nlink -= 1;
            }
        }
        if is_dir && !same {
            self.meta.lock().nlink -= 1;
            nd.meta.lock().nlink += 1;
        }
        node.meta.lock().ctime = Timespec::now();
        self.touch_mc();
        if !same {
            nd.touch_mc();
        }
        Ok(())
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        match &*self.data.lock() {
            Data::Dir(map) => Ok(map
                .iter()
                .map(|(name, n)| DirEntry { name: name.clone(), ino: n.ino, kind: n.meta.lock().kind })
                .collect()),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn readlink(&self) -> KResult<String> {
        match &*self.data.lock() {
            Data::Symlink(t) => Ok(t.clone()),
            _ => Err(Errno::EINVAL),
        }
    }

    fn open_special(self: Arc<Self>, flags: u32) -> KResult<Option<Arc<dyn File>>> {
        let (kind, rdev) = {
            let m = self.meta.lock();
            (m.kind, m.rdev)
        };
        match kind {
            FileType::CharDevice => crate::device::open_char(rdev, flags).map(Some),
            FileType::BlockDevice => crate::device::open_block(rdev, flags).map(Some),
            FileType::Fifo => {
                let pipe = match &*self.data.lock() {
                    Data::Fifo(p) => p.clone(),
                    _ => return Err(Errno::EINVAL),
                };
                super::pipe::open_fifo(&pipe, flags).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn shared_mmap(&self) -> Option<Arc<crate::mm::aspace::SharedAnon>> {
        // Only regular files back a shared mapping; created once and reused.
        if self.meta.lock().kind != FileType::Regular {
            return None;
        }
        let mut g = self.mmap_shared.lock();
        Some(g.get_or_insert_with(crate::mm::aspace::SharedAnon::new).clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
