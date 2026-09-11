//! `/bin`: a read-only filesystem exposing every native command as an
//! executable file, so `ls /bin`, `which`, `test -x` and `PATH` lookup work
//! exactly as on a conventional system.

use crate::errno::{Errno, KResult};
use crate::fs::{DirEntry, FileSystem, FileType, Inode, InodeRef, Metadata, StatFs, Timespec};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

const DEV: u64 = 0x60;

pub struct BinFs;

impl BinFs {
    pub fn new() -> Arc<BinFs> {
        Arc::new(BinFs)
    }
}

impl FileSystem for BinFs {
    fn root(&self) -> InodeRef {
        Arc::new(Node { index: None })
    }
    fn fs_type(&self) -> &'static str {
        "binfs"
    }
    fn dev(&self) -> u64 {
        DEV
    }
    fn statfs(&self) -> StatFs {
        StatFs { fs_type: 0x62696e, block_size: 4096, files: super::cmds::all().len() as u64, name_max: 255, ..Default::default() }
    }
}

struct Node {
    /// Index into the command table; `None` = the directory.
    index: Option<usize>,
}

fn content(i: usize) -> String {
    let c = &super::cmds::all()[i];
    alloc::format!("#!/bin/fsh\n# FastROS native command: {} - {}\n", c.name, c.about)
}

fn boot_time() -> Timespec {
    Timespec::from_secs((crate::time::unix_now() - crate::time::uptime_secs()) as i64)
}

impl Inode for Node {
    fn metadata(&self) -> KResult<Metadata> {
        let t = boot_time();
        Ok(match self.index {
            None => Metadata {
                dev: DEV,
                ino: 1,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                size: 4096,
                blocks: 8,
                blksize: 4096,
                rdev: 0,
                atime: t,
                mtime: t,
                ctime: t,
            },
            Some(i) => Metadata {
                dev: DEV,
                ino: i as u64 + 2,
                kind: FileType::Regular,
                perm: 0o755,
                nlink: 1,
                uid: 0,
                gid: 0,
                size: content(i).len() as u64,
                blocks: 8,
                blksize: 4096,
                rdev: 0,
                atime: t,
                mtime: t,
                ctime: t,
            },
        })
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let Some(i) = self.index else { return Err(Errno::EISDIR) };
        let c = content(i);
        let b = c.as_bytes();
        if off >= b.len() as u64 {
            return Ok(0);
        }
        let n = buf.len().min(b.len() - off as usize);
        buf[..n].copy_from_slice(&b[off as usize..off as usize + n]);
        Ok(n)
    }

    fn write_at(&self, _: u64, _: &[u8]) -> KResult<usize> {
        Err(Errno::EROFS)
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if self.index.is_some() {
            return Err(Errno::ENOTDIR);
        }
        let i = super::cmds::all().iter().position(|c| c.name == name).ok_or(Errno::ENOENT)?;
        Ok(Arc::new(Node { index: Some(i) }))
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        if self.index.is_some() {
            return Err(Errno::ENOTDIR);
        }
        Ok(super::cmds::all()
            .iter()
            .enumerate()
            .map(|(i, c)| DirEntry { name: String::from(c.name), ino: i as u64 + 2, kind: FileType::Regular })
            .collect())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
