//! Mount namespaces and mount tables.

use super::path::{PathNode, PathRef};
use super::{Errno, FileSystem, InodeRef, KResult};
use crate::sync::SpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountFlags {
    pub read_only: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
}

impl MountFlags {
    pub const RW: MountFlags = MountFlags { read_only: false, nosuid: false, nodev: false, noexec: false };
    pub const RO: MountFlags = MountFlags { read_only: true, nosuid: false, nodev: false, noexec: false };
    /// Options column of /proc/mounts.
    pub fn describe(&self) -> String {
        let mut s = String::from(if self.read_only { "ro" } else { "rw" });
        for (on, name) in [(self.nosuid, "nosuid"), (self.nodev, "nodev"), (self.noexec, "noexec")] {
            if on {
                s.push(',');
                s.push_str(name);
            }
        }
        s
    }
}

pub struct Mount {
    pub id: u32,
    pub fs: Arc<dyn FileSystem>,
    pub root: InodeRef,
    pub source: String,
    pub flags: SpinLock<MountFlags>,
    /// (parent mount id, mountpoint inode identity); `None` for a namespace root.
    pub parent: Option<(u32, (u64, u64))>,
    /// The mountpoint as seen in the parent (for paths and `..`).
    pub point: Option<PathRef>,
}

impl Mount {
    pub fn read_only(&self) -> bool {
        self.flags.lock().read_only
    }
}

static NEXT_MOUNT_ID: AtomicU32 = AtomicU32::new(1);
static NEXT_NS_ID: AtomicU32 = AtomicU32::new(1);

pub struct MountNamespace {
    pub id: u32,
    mounts: SpinLock<Vec<Arc<Mount>>>,
    root: PathRef,
}

impl MountNamespace {
    /// A namespace whose root is `fs`.
    pub fn new(fs: Arc<dyn FileSystem>, source: &str, flags: MountFlags) -> Arc<MountNamespace> {
        let m = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root: fs.root(),
            fs,
            source: String::from(source),
            flags: SpinLock::new(flags),
            parent: None,
            point: None,
        });
        let root = Arc::new(PathNode { mount: m.clone(), inode: m.root.clone(), name: String::new(), parent: None });
        Arc::new(MountNamespace { id: NEXT_NS_ID.fetch_add(1, Ordering::Relaxed), mounts: SpinLock::new(alloc::vec![m]), root })
    }

    pub fn root(&self) -> PathRef {
        self.root.clone()
    }

    /// The mount stacked on `(parent mount, inode)`, if any (last one wins).
    pub fn mounted_on(&self, parent: u32, ino: (u64, u64)) -> Option<Arc<Mount>> {
        self.mounts.lock().iter().rev().find(|m| m.parent == Some((parent, ino))).cloned()
    }

    pub fn mount(&self, at: &PathRef, fs: Arc<dyn FileSystem>, source: &str, flags: MountFlags) -> KResult<()> {
        if !at.inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let m = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root: fs.root(),
            fs,
            source: String::from(source),
            flags: SpinLock::new(flags),
            parent: Some((at.mount.id, at.inode.id())),
            point: Some(at.clone()),
        });
        self.mounts.lock().push(m);
        Ok(())
    }

    /// Bind mount: make the subtree at `src` visible at `at` as well.
    pub fn bind(&self, at: &PathRef, src: &PathRef, flags: MountFlags) -> KResult<()> {
        if !at.inode.is_dir() || !src.inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let m = Arc::new(Mount {
            id: NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed),
            root: src.inode.clone(),
            fs: src.mount.fs.clone(),
            source: src.mount.source.clone(),
            flags: SpinLock::new(flags),
            parent: Some((at.mount.id, at.inode.id())),
            point: Some(at.clone()),
        });
        self.mounts.lock().push(m);
        Ok(())
    }

    /// Detach the filesystem mounted at `at` (which must be a mount root).
    pub fn umount(&self, at: &PathRef) -> KResult<Arc<Mount>> {
        let mut mounts = self.mounts.lock();
        let idx = mounts.iter().position(|m| m.id == at.mount.id).ok_or(Errno::EINVAL)?;
        if !Arc::ptr_eq(&mounts[idx].root, &at.inode) {
            return Err(Errno::EINVAL); // not a mount point
        }
        if mounts[idx].parent.is_none() {
            return Err(Errno::EBUSY); // the namespace root
        }
        let id = mounts[idx].id;
        if mounts.iter().any(|m| m.parent.is_some_and(|(p, _)| p == id)) {
            return Err(Errno::EBUSY);
        }
        Ok(mounts.remove(idx))
    }

    /// Every mount with its absolute path, in mount order.
    pub fn list(&self) -> Vec<(String, Arc<Mount>)> {
        self.mounts
            .lock()
            .iter()
            .map(|m| (m.point.as_ref().map(|p| p.path()).unwrap_or_else(|| String::from("/")), m.clone()))
            .collect()
    }

    pub fn find_mount_by_path(&self, path: &str) -> Option<Arc<Mount>> {
        self.list().into_iter().rev().find(|(p, _)| p == path).map(|(_, m)| m)
    }
}

static INIT_NS: crate::sync::Once<Arc<MountNamespace>> = crate::sync::Once::new();

/// The initial (host) mount namespace.
pub fn init_ns() -> Arc<MountNamespace> {
    INIT_NS.expect_init().clone()
}

pub fn set_init_ns(ns: Arc<MountNamespace>) {
    INIT_NS.call_once(|| ns);
}

pub fn init() {}
