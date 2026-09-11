//! overlayfs: a union of a read-only *lower* tree (an image rootfs) and a
//! writable *upper* tree (the container's own layer), with copy-up on write.
//!
//! This is what makes a container start instantly: nothing is copied up front.
//! Reads fall through to the lower layer; the first write to a lower file copies
//! just that file into the upper layer and then edits the copy, so the image is
//! never mutated and each container is fully isolated. Deleting a file that
//! exists only in the lower layer records a *whiteout* (`.wh.<name>`) in the
//! upper layer so it disappears from the merged view.
//!
//! The upper layer is an ordinary writable filesystem (a per-container tmpfs by
//! default). Because copy-up is per-file and lazy, only the bytes a container
//! actually writes ever get copied.

use super::file::File;
use super::{DirEntry, Errno, FileSystem, FileType, Inode, InodeRef, KResult, Metadata, SetAttr, StatFs, Timespec};
use crate::sync::SpinLock;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

const OVERLAY_MAGIC: u64 = 0x794c_7630; // "yLv0"
const WH_PREFIX: &str = ".wh.";
static NEXT_DEV: AtomicU64 = AtomicU64::new(0x900);

/// Upper inos are offset into a disjoint range from lower (ext2) inos so the
/// merged view never reports two different files with the same (dev, ino).
const UPPER_INO_BIT: u64 = 1 << 48;

pub struct OverlayFs {
    dev: u64,
    root: Arc<OverlayNode>,
    _upper: Arc<dyn FileSystem>,
}

struct Shared {
    dev: u64,
    /// Root of the writable upper filesystem (a directory inode).
    upper_root: InodeRef,
}

impl OverlayFs {
    /// Build an overlay of `lower` (read-only image rootfs) over `upper` (a
    /// fresh writable filesystem, e.g. a tmpfs). Both roots must be directories.
    pub fn new(lower: InodeRef, upper: Arc<dyn FileSystem>) -> Arc<OverlayFs> {
        let dev = NEXT_DEV.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(Shared { dev, upper_root: upper.root() });
        let root = OverlayNode::new(&shared, Some(lower), Some(upper.root()), Weak::new(), String::new(), FileType::Directory);
        Arc::new(OverlayFs { dev, root, _upper: upper })
    }
}

impl FileSystem for OverlayFs {
    fn root(&self) -> InodeRef {
        self.root.clone()
    }
    fn fs_type(&self) -> &'static str {
        "overlay"
    }
    fn dev(&self) -> u64 {
        self.dev
    }
    fn statfs(&self) -> StatFs {
        // The writable upper layer decides how much a container can consume;
        // report a generous fixed budget (the upper tmpfs enforces the real one).
        StatFs { fs_type: OVERLAY_MAGIC, block_size: 4096, blocks: 1 << 20, blocks_free: 1 << 19, blocks_avail: 1 << 19, files: 1 << 20, files_free: 1 << 19, name_max: 255 }
    }
}

pub struct OverlayNode {
    shared: Arc<Shared>,
    lower: SpinLock<Option<InodeRef>>,
    upper: SpinLock<Option<InodeRef>>,
    parent: Weak<OverlayNode>,
    name: String,
    kind: FileType,
    /// Cached merged children, so a node's identity (and its copied-up state)
    /// is stable across repeated lookups.
    children: SpinLock<BTreeMap<String, Arc<OverlayNode>>>,
    this: Weak<OverlayNode>,
}

impl OverlayNode {
    fn new(shared: &Arc<Shared>, lower: Option<InodeRef>, upper: Option<InodeRef>, parent: Weak<OverlayNode>, name: String, kind: FileType) -> Arc<OverlayNode> {
        Arc::new_cyclic(|w| OverlayNode {
            shared: shared.clone(),
            lower: SpinLock::new(lower),
            upper: SpinLock::new(upper),
            parent,
            name,
            kind,
            children: SpinLock::new(BTreeMap::new()),
            this: w.clone(),
        })
    }

    fn arc(&self) -> Arc<OverlayNode> {
        this_up(&self.this)
    }

    /// Clone the layer inode out from under its lock. Inode methods can sleep
    /// (ext2 reads block on disk), so the SpinLock must never be held across a
    /// call into the underlying inode — always take the ref out first.
    fn lower_ref(&self) -> Option<InodeRef> {
        self.lower.lock().clone()
    }
    fn upper_ref(&self) -> Option<InodeRef> {
        self.upper.lock().clone()
    }

    /// The active inode for data/metadata: upper if it exists, else lower.
    fn active(&self) -> KResult<InodeRef> {
        if let Some(u) = self.upper_ref() {
            return Ok(u);
        }
        self.lower_ref().ok_or(Errno::ENOENT)
    }

    fn upper_meta_source(&self) -> KResult<Metadata> {
        self.active()?.metadata()
    }

    /// Ensure this directory exists in the upper layer (recursively creating
    /// parents), returning its upper inode.
    fn ensure_upper_dir(&self) -> KResult<InodeRef> {
        if let Some(u) = self.upper_ref() {
            return Ok(u);
        }
        // The root always has an upper (set at construction), so a node without
        // one always has a parent.
        let parent = self.parent.upgrade().ok_or(Errno::ENOENT)?;
        let pupper = parent.ensure_upper_dir()?;
        // Remove any stale whiteout hiding this name, then create the dir.
        let _ = pupper.unlink(&whiteout_name(&self.name));
        let (perm, uid, gid) = self.lower_ref().and_then(|l| l.metadata().ok()).map(|m| (m.perm, m.uid, m.gid)).unwrap_or((0o755, 0, 0));
        let u = match pupper.lookup(&self.name) {
            Ok(existing) => existing,
            Err(_) => pupper.create(&self.name, FileType::Directory, perm, uid, gid, 0)?,
        };
        *self.upper.lock() = Some(u.clone());
        Ok(u)
    }

    /// Copy this file/symlink into the upper layer if it is still lower-only.
    fn copy_up(&self) -> KResult<InodeRef> {
        if let Some(u) = self.upper_ref() {
            return Ok(u);
        }
        let lower = self.lower_ref().ok_or(Errno::ENOENT)?;
        let m = lower.metadata()?;
        let parent = self.parent.upgrade().ok_or(Errno::ENOENT)?;
        let pupper = parent.ensure_upper_dir()?;
        let _ = pupper.unlink(&whiteout_name(&self.name));
        let u = match m.kind {
            FileType::Symlink => {
                let target = lower.readlink()?;
                pupper.symlink(&self.name, &target, m.uid, m.gid)?
            }
            FileType::Regular => {
                let u = pupper.create(&self.name, FileType::Regular, m.perm, m.uid, m.gid, 0)?;
                let mut off = 0u64;
                let mut buf = alloc::vec![0u8; 256 * 1024];
                loop {
                    let n = lower.read_at(off, &mut buf)?;
                    if n == 0 {
                        break;
                    }
                    let mut w = 0;
                    while w < n {
                        w += u.write_at(off + w as u64, &buf[w..n])?;
                    }
                    off += n as u64;
                    crate::sched::cond_resched();
                }
                u
            }
            _ => pupper.create(&self.name, m.kind, m.perm, m.uid, m.gid, m.rdev)?,
        };
        *self.upper.lock() = Some(u.clone());
        Ok(u)
    }

    /// Is `name` whited-out in the upper directory?
    fn is_whiteout(upper_dir: &InodeRef, name: &str) -> bool {
        upper_dir.lookup(&whiteout_name(name)).is_ok()
    }

    /// Build (and cache) the child node for `name`, merging the layers.
    fn child(&self, name: &str) -> KResult<Arc<OverlayNode>> {
        if name == "." {
            return Ok(self.arc());
        }
        if let Some(c) = self.children.lock().get(name) {
            return Ok(c.clone());
        }
        let upper_dir = self.upper_ref();
        let lower_dir = self.lower_ref();

        let upper_child = upper_dir.as_ref().and_then(|d| d.lookup(name).ok());
        // A whiteout in the upper hides anything below it.
        let whited = upper_dir.as_ref().is_some_and(|d| Self::is_whiteout(d, name));
        let lower_child = if whited { None } else { lower_dir.as_ref().and_then(|d| d.lookup(name).ok()) };

        if upper_child.is_none() && lower_child.is_none() {
            return Err(Errno::ENOENT);
        }
        // Kind comes from the upper if present, else the lower. If the upper is
        // a file shadowing a lower directory (or vice versa), the upper wins and
        // the lower is not merged.
        let (kind, lower_for_child) = match (&upper_child, &lower_child) {
            (Some(u), Some(l)) => {
                let uk = u.metadata()?.kind;
                let lk = l.metadata()?.kind;
                if uk == FileType::Directory && lk == FileType::Directory {
                    (FileType::Directory, lower_child.clone())
                } else {
                    (uk, None)
                }
            }
            (Some(u), None) => (u.metadata()?.kind, None),
            (None, Some(l)) => (l.metadata()?.kind, lower_child.clone()),
            (None, None) => unreachable!(),
        };
        let node = OverlayNode::new(&self.shared, lower_for_child, upper_child, self.this.clone(), name.to_string(), kind);
        self.children.lock().insert(name.to_string(), node.clone());
        Ok(node)
    }

    fn stable_ino(&self) -> u64 {
        if let Some(l) = self.lower_ref() {
            if let Ok(m) = l.metadata() {
                return m.ino;
            }
        }
        if let Some(u) = self.upper_ref() {
            if let Ok(m) = u.metadata() {
                return m.ino | UPPER_INO_BIT;
            }
        }
        0
    }
}

fn this_up(w: &Weak<OverlayNode>) -> Arc<OverlayNode> {
    w.upgrade().expect("overlay node alive")
}

fn whiteout_name(name: &str) -> String {
    alloc::format!("{WH_PREFIX}{name}")
}

impl Inode for OverlayNode {
    fn metadata(&self) -> KResult<Metadata> {
        let mut m = self.upper_meta_source()?;
        m.dev = self.shared.dev;
        m.ino = self.stable_ino();
        Ok(m)
    }

    fn set_attr(&self, attr: &SetAttr) -> KResult<()> {
        let target = if self.kind == FileType::Directory { self.ensure_upper_dir()? } else { self.copy_up()? };
        target.set_attr(attr)
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.active()?.read_at(off, buf)
    }

    fn write_at(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let u = self.copy_up()?;
        u.write_at(off, buf)
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        Ok(self.child(name)? as InodeRef)
    }

    fn create(&self, name: &str, kind: FileType, perm: u16, uid: u32, gid: u32, rdev: u64) -> KResult<InodeRef> {
        let updir = self.ensure_upper_dir()?;
        // Drop any whiteout so the new name is visible, then create in upper.
        let _ = updir.unlink(&whiteout_name(name));
        let u = updir.create(name, kind, perm, uid, gid, rdev)?;
        let node = OverlayNode::new(&self.shared, None, Some(u), self.this.clone(), name.to_string(), kind);
        self.children.lock().insert(name.to_string(), node.clone());
        Ok(node)
    }

    fn symlink(&self, name: &str, target: &str, uid: u32, gid: u32) -> KResult<InodeRef> {
        let updir = self.ensure_upper_dir()?;
        let _ = updir.unlink(&whiteout_name(name));
        let u = updir.symlink(name, target, uid, gid)?;
        let node = OverlayNode::new(&self.shared, None, Some(u), self.this.clone(), name.to_string(), FileType::Symlink);
        self.children.lock().insert(name.to_string(), node.clone());
        Ok(node)
    }

    fn link(&self, name: &str, target: &InodeRef) -> KResult<()> {
        // Hard links are supported only within the upper layer: copy the target
        // up, then link the upper inode.
        let t = target.as_any().downcast_ref::<OverlayNode>().ok_or(Errno::EXDEV)?;
        let tu = t.copy_up()?;
        let updir = self.ensure_upper_dir()?;
        let _ = updir.unlink(&whiteout_name(name));
        updir.link(name, &tu)?;
        self.children.lock().remove(name);
        Ok(())
    }

    fn unlink(&self, name: &str) -> KResult<()> {
        let child = self.child(name)?;
        let in_lower = child.lower.lock().is_some();
        let updir = self.ensure_upper_dir()?;
        // Remove the upper copy if there is one (ignore if only in lower).
        if child.upper.lock().is_some() {
            let _ = updir.unlink(name);
        }
        // If the name still exists in the lower layer, hide it with a whiteout.
        if in_lower {
            let _ = updir.create(&whiteout_name(name), FileType::Regular, 0o000, 0, 0, 0);
        }
        self.children.lock().remove(name);
        Ok(())
    }

    fn rmdir(&self, name: &str) -> KResult<()> {
        let child = self.child(name)?;
        if child.metadata()?.kind != FileType::Directory {
            return Err(Errno::ENOTDIR);
        }
        if !child.readdir()?.is_empty() {
            return Err(Errno::ENOTEMPTY);
        }
        let in_lower = child.lower.lock().is_some();
        let updir = self.ensure_upper_dir()?;
        if child.upper.lock().is_some() {
            let _ = updir.rmdir(name);
        }
        if in_lower {
            let _ = updir.create(&whiteout_name(name), FileType::Regular, 0o000, 0, 0, 0);
        }
        self.children.lock().remove(name);
        Ok(())
    }

    fn rename(&self, old: &str, new_dir: &InodeRef, new: &str) -> KResult<()> {
        let nd = new_dir.as_any().downcast_ref::<OverlayNode>().ok_or(Errno::EXDEV)?;
        let child = self.child(old)?;
        let kind = child.metadata()?.kind;
        // Materialise the source in the upper layer (whole subtree for a dir).
        copy_up_recursive(&child)?;
        let src_upper = self.ensure_upper_dir()?;
        let dst_upper = nd.ensure_upper_dir()?;
        let _ = dst_upper.unlink(&whiteout_name(new));
        src_upper.rename(old, &dst_upper, new)?;
        // Leave a whiteout where the source used to be if the lower still has it.
        if child.lower.lock().is_some() {
            let _ = src_upper.create(&whiteout_name(old), FileType::Regular, 0o000, 0, 0, 0);
        }
        self.children.lock().remove(old);
        nd.children.lock().remove(new);
        let _ = kind;
        Ok(())
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        let mut out: Vec<DirEntry> = Vec::new();
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        let mut whiteouts: BTreeMap<String, ()> = BTreeMap::new();

        if let Some(u) = self.upper_ref() {
            for e in u.readdir()? {
                if let Some(hidden) = e.name.strip_prefix(WH_PREFIX) {
                    whiteouts.insert(hidden.to_string(), ());
                    continue;
                }
                if e.name == "." || e.name == ".." {
                    continue;
                }
                seen.insert(e.name.clone(), ());
                out.push(e);
            }
        }
        if let Some(l) = self.lower_ref() {
            for e in l.readdir()? {
                if e.name == "." || e.name == ".." {
                    continue;
                }
                if seen.contains_key(&e.name) || whiteouts.contains_key(&e.name) {
                    continue;
                }
                out.push(e);
            }
        }
        Ok(out)
    }

    fn readlink(&self) -> KResult<String> {
        self.active()?.readlink()
    }

    fn open_special(self: Arc<Self>, flags: u32) -> KResult<Option<Arc<dyn File>>> {
        // Devices/FIFOs are served by the layer that currently holds the node.
        let active = self.active()?;
        active.open_special(flags)
    }

    fn sync(&self) -> KResult<()> {
        if let Some(u) = self.upper_ref() {
            u.sync()?;
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Copy up a whole subtree (used before renaming a lower directory).
fn copy_up_recursive(node: &Arc<OverlayNode>) -> KResult<()> {
    if node.metadata()?.kind == FileType::Directory {
        node.ensure_upper_dir()?;
        for e in node.readdir()? {
            let c = node.child(&e.name)?;
            copy_up_recursive(&c)?;
        }
    } else {
        node.copy_up()?;
    }
    Ok(())
}
