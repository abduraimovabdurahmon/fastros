//! `/dev`: a tmpfs populated with the standard device nodes at boot;
//! `/dev/pts/N` nodes come and go with pseudo-terminals.

use super::tmpfs::TmpFs;
use super::{makedev, FileType, Inode};
use crate::device::{MEM_MAJOR, PTS_MAJOR, TTY_MAJOR};
use crate::sync::Once;
use alloc::sync::Arc;

static DEVFS: Once<Arc<TmpFs>> = Once::new();

pub fn create() -> Arc<TmpFs> {
    let fs = TmpFs::new(0);
    let root: Arc<dyn Inode> = fs.root_node();
    let chr = |name: &str, maj: u32, min: u32, perm: u16, gid: u32| {
        let _ = root.create(name, FileType::CharDevice, perm, 0, gid, makedev(maj, min));
    };
    chr("null", MEM_MAJOR, 3, 0o666, 0);
    chr("zero", MEM_MAJOR, 5, 0o666, 0);
    chr("full", MEM_MAJOR, 7, 0o666, 0);
    chr("random", MEM_MAJOR, 8, 0o666, 0);
    chr("urandom", MEM_MAJOR, 9, 0o666, 0);
    chr("kmsg", MEM_MAJOR, 11, 0o644, 0);
    chr("tty", TTY_MAJOR, 0, 0o666, 5);
    chr("console", TTY_MAJOR, 1, 0o600, 0);
    let _ = root.create("pts", FileType::Directory, 0o755, 0, 0, 0);
    let _ = root.create("shm", FileType::Directory, 0o1777, 0, 0, 0);
    let _ = root.symlink("fd", "/proc/self/fd", 0, 0);
    let _ = root.symlink("stdin", "/proc/self/fd/0", 0, 0);
    let _ = root.symlink("stdout", "/proc/self/fd/1", 0, 0);
    let _ = root.symlink("stderr", "/proc/self/fd/2", 0, 0);
    for d in crate::drivers::block::all() {
        if let Some(rdev) = crate::device::disk_rdev(d.name()) {
            let _ = root.create(d.name(), FileType::BlockDevice, 0o660, 0, 6, rdev);
        }
    }
    DEVFS.call_once(|| fs.clone());
    fs
}

fn pts_dir() -> Option<Arc<dyn Inode>> {
    DEVFS.get()?.root_node().lookup("pts").ok()
}

/// Create `/dev/pts/N` owned by the session user.
pub fn add_pts(n: u32, uid: u32) {
    if let Some(d) = pts_dir() {
        let _ = d.create(&alloc::format!("{n}"), FileType::CharDevice, 0o620, uid, 5, makedev(PTS_MAJOR, n));
    }
}

pub fn remove_pts(n: u32) {
    if let Some(d) = pts_dir() {
        let _ = d.unlink(&alloc::format!("{n}"));
    }
}
