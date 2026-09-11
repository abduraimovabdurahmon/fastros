//! Credentials and POSIX permission checks.

use super::{Errno, FileType, KResult, Metadata};
use alloc::vec::Vec;

pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;

/// Process credentials (the fields of Linux's `struct cred` that matter).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cred {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub groups: Vec<u32>,
}

impl Cred {
    pub fn root() -> Cred {
        Cred::default()
    }
    pub fn user(uid: u32, gid: u32, groups: Vec<u32>) -> Cred {
        Cred { uid, gid, euid: uid, egid: gid, suid: uid, sgid: gid, groups }
    }
    pub fn is_root(&self) -> bool {
        self.euid == 0
    }
    pub fn in_group(&self, gid: u32) -> bool {
        self.egid == gid || self.groups.contains(&gid)
    }
}

/// `inode_permission`: may `cred` access an object with `meta` for `mask`?
pub fn check(cred: &Cred, meta: &Metadata, mask: u32) -> KResult<()> {
    if cred.is_root() {
        // Root bypasses read/write checks; execute still needs some x bit
        // on non-directories (CAP_DAC_OVERRIDE semantics).
        if mask & MAY_EXEC != 0 && meta.kind != FileType::Directory && meta.perm & 0o111 == 0 {
            return Err(Errno::EACCES);
        }
        return Ok(());
    }
    let p = meta.perm as u32;
    let bits = if meta.uid == cred.euid {
        (p >> 6) & 7
    } else if cred.in_group(meta.gid) {
        (p >> 3) & 7
    } else {
        p & 7
    };
    if bits & mask == mask {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

/// Sticky-directory rule for removing/renaming `victim` out of `dir`.
pub fn may_delete(cred: &Cred, dir: &Metadata, victim: &Metadata) -> KResult<()> {
    check(cred, dir, MAY_WRITE | MAY_EXEC)?;
    if dir.perm & 0o1000 != 0 && !cred.is_root() && cred.euid != victim.uid && cred.euid != dir.uid {
        return Err(Errno::EPERM);
    }
    Ok(())
}

/// Only the owner (or root) may chmod / utime; only root may give files away.
pub fn is_owner(cred: &Cred, meta: &Metadata) -> bool {
    cred.is_root() || cred.euid == meta.uid
}
