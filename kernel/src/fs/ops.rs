//! POSIX file operations with full permission, mount-flag and sticky-bit
//! checks — the one API both native commands and the Linux syscall layer use.

use super::file::{flags::*, File, InodeFile};
use super::path::{PathRef, Resolver};
use super::perm::{self, Cred, MAY_EXEC, MAY_READ, MAY_WRITE};
use super::{DirEntry, Errno, FileType, KResult, Metadata, SetAttr, StatFs, Timespec};
use crate::proc::Process;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A snapshot of a process's filesystem view.
pub struct Ctx {
    pub fs: crate::proc::FsContext,
    pub cred: Cred,
}

impl Ctx {
    pub fn of(p: &Process) -> Ctx {
        Ctx { fs: p.fs.lock().clone(), cred: p.cred() }
    }
    pub fn current() -> Ctx {
        Ctx::of(&crate::proc::current())
    }
    fn resolver(&self) -> Resolver<'_> {
        Resolver { ns: &self.fs.ns, root: &self.fs.root, cwd: &self.fs.cwd, cred: &self.cred }
    }
    pub fn resolve(&self, path: &str, follow: bool) -> KResult<PathRef> {
        self.resolver().resolve(path, follow)
    }
    pub fn resolve_parent(&self, path: &str) -> KResult<(PathRef, String)> {
        self.resolver().resolve_parent(path)
    }
}

fn check_rw_mount(node: &PathRef) -> KResult<()> {
    if node.mount.read_only() {
        Err(Errno::EROFS)
    } else {
        Ok(())
    }
}

fn is_dot(name: &str) -> bool {
    name == "." || name == ".."
}

pub fn open(ctx: &Ctx, path: &str, flags: u32, mode: u16) -> KResult<Arc<dyn File>> {
    let acc = flags & O_ACCMODE;
    let want_write = acc == O_WRONLY || acc == O_RDWR || flags & O_TRUNC != 0;
    let node = if flags & O_CREAT != 0 {
        let (dir, name) = ctx.resolve_parent(path)?;
        match ctx.resolve(path, flags & O_NOFOLLOW == 0) {
            Ok(n) => {
                if flags & O_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                n
            }
            Err(Errno::ENOENT) => {
                if is_dot(&name) {
                    return Err(Errno::EISDIR);
                }
                let dmeta = dir.inode.metadata()?;
                perm::check(&ctx.cred, &dmeta, MAY_WRITE | MAY_EXEC)?;
                check_rw_mount(&dir)?;
                let gid = if dmeta.perm & 0o2000 != 0 { dmeta.gid } else { ctx.cred.egid };
                let perm = mode & !ctx.fs.umask & 0o7777;
                let inode = dir.inode.create(&name, FileType::Regular, perm, ctx.cred.euid, gid, 0)?;
                let n = dir.child(&name, inode);
                return Ok(InodeFile::new(n, flags & !(O_CREAT | O_EXCL | O_TRUNC)));
            }
            Err(e) => return Err(e),
        }
    } else {
        ctx.resolve(path, flags & O_NOFOLLOW == 0)?
    };
    let meta = node.inode.metadata()?;
    if meta.kind == FileType::Symlink {
        return Err(Errno::ELOOP);
    }
    if flags & O_DIRECTORY != 0 && meta.kind != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if meta.kind == FileType::Directory && want_write {
        return Err(Errno::EISDIR);
    }
    if flags & O_PATH == 0 {
        let mut mask = 0;
        if acc == O_RDONLY || acc == O_RDWR {
            mask |= MAY_READ;
        }
        if want_write {
            mask |= MAY_WRITE;
        }
        perm::check(&ctx.cred, &meta, mask)?;
    }
    if want_write && meta.kind == FileType::Regular {
        check_rw_mount(&node)?;
    }
    if matches!(meta.kind, FileType::CharDevice | FileType::BlockDevice) && node.mount.flags.lock().nodev {
        return Err(Errno::EACCES);
    }
    if let Some(f) = node.inode.clone().open_special(flags)? {
        return Ok(f);
    }
    if flags & O_TRUNC != 0 && meta.kind == FileType::Regular && meta.size != 0 {
        node.inode.set_attr(&SetAttr { size: Some(0), mtime: Some(Timespec::now()), ..Default::default() })?;
    }
    Ok(InodeFile::new(node, flags & !(O_CREAT | O_EXCL | O_TRUNC)))
}

pub fn stat(ctx: &Ctx, path: &str, follow: bool) -> KResult<Metadata> {
    ctx.resolve(path, follow)?.inode.metadata()
}

pub fn exists(ctx: &Ctx, path: &str) -> bool {
    ctx.resolve(path, true).is_ok()
}

pub fn access(ctx: &Ctx, path: &str, mask: u32) -> KResult<()> {
    let node = ctx.resolve(path, true)?;
    if mask & MAY_WRITE != 0 {
        check_rw_mount(&node)?;
    }
    perm::check(&ctx.cred, &node.inode.metadata()?, mask)
}

pub fn mkdir(ctx: &Ctx, path: &str, mode: u16) -> KResult<()> {
    let (dir, name) = ctx.resolve_parent(path)?;
    if is_dot(&name) {
        return Err(Errno::EEXIST);
    }
    if dir.inode.lookup(&name).is_ok() {
        return Err(Errno::EEXIST);
    }
    let dmeta = dir.inode.metadata()?;
    perm::check(&ctx.cred, &dmeta, MAY_WRITE | MAY_EXEC)?;
    check_rw_mount(&dir)?;
    let gid = if dmeta.perm & 0o2000 != 0 { dmeta.gid } else { ctx.cred.egid };
    let mut perm = mode & !ctx.fs.umask & 0o7777;
    if dmeta.perm & 0o2000 != 0 {
        perm |= 0o2000;
    }
    dir.inode.create(&name, FileType::Directory, perm, ctx.cred.euid, gid, 0)?;
    Ok(())
}

pub fn mknod(ctx: &Ctx, path: &str, kind: FileType, mode: u16, rdev: u64) -> KResult<()> {
    let (dir, name) = ctx.resolve_parent(path)?;
    if dir.inode.lookup(&name).is_ok() {
        return Err(Errno::EEXIST);
    }
    if matches!(kind, FileType::CharDevice | FileType::BlockDevice) && !ctx.cred.is_root() {
        return Err(Errno::EPERM);
    }
    perm::check(&ctx.cred, &dir.inode.metadata()?, MAY_WRITE | MAY_EXEC)?;
    check_rw_mount(&dir)?;
    dir.inode.create(&name, kind, mode & !ctx.fs.umask & 0o7777, ctx.cred.euid, ctx.cred.egid, rdev)?;
    Ok(())
}

pub fn rmdir(ctx: &Ctx, path: &str) -> KResult<()> {
    let (dir, name) = ctx.resolve_parent(path)?;
    if name == "." {
        return Err(Errno::EINVAL);
    }
    if name == ".." {
        return Err(Errno::ENOTEMPTY);
    }
    let victim = ctx.resolve(path, false)?;
    let vmeta = victim.inode.metadata()?;
    if vmeta.kind != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    if !Arc::ptr_eq(&victim.mount, &dir.mount) {
        return Err(Errno::EBUSY); // a mount point
    }
    perm::may_delete(&ctx.cred, &dir.inode.metadata()?, &vmeta)?;
    check_rw_mount(&dir)?;
    dir.inode.rmdir(&name)
}

pub fn unlink(ctx: &Ctx, path: &str) -> KResult<()> {
    let (dir, name) = ctx.resolve_parent(path)?;
    if is_dot(&name) {
        return Err(Errno::EISDIR);
    }
    let victim = dir.inode.lookup(&name)?;
    let vmeta = victim.metadata()?;
    if vmeta.kind == FileType::Directory {
        return Err(Errno::EISDIR);
    }
    perm::may_delete(&ctx.cred, &dir.inode.metadata()?, &vmeta)?;
    check_rw_mount(&dir)?;
    dir.inode.unlink(&name)
}

pub fn rename(ctx: &Ctx, from: &str, to: &str) -> KResult<()> {
    let (odir, oname) = ctx.resolve_parent(from)?;
    let (ndir, nname) = ctx.resolve_parent(to)?;
    if is_dot(&oname) || is_dot(&nname) {
        return Err(Errno::EBUSY);
    }
    if !Arc::ptr_eq(&odir.mount, &ndir.mount) {
        return Err(Errno::EXDEV);
    }
    let src = odir.inode.lookup(&oname)?;
    let smeta = src.metadata()?;
    perm::may_delete(&ctx.cred, &odir.inode.metadata()?, &smeta)?;
    perm::check(&ctx.cred, &ndir.inode.metadata()?, MAY_WRITE | MAY_EXEC)?;
    if let Ok(existing) = ndir.inode.lookup(&nname) {
        perm::may_delete(&ctx.cred, &ndir.inode.metadata()?, &existing.metadata()?)?;
    }
    check_rw_mount(&odir)?;
    if smeta.kind == FileType::Directory {
        // A directory may not move into its own subtree.
        let src_path = odir.child(&oname, src.clone()).path();
        let dst_parent = ndir.path();
        if dst_parent == src_path || dst_parent.starts_with(&(src_path.clone() + "/")) {
            return Err(Errno::EINVAL);
        }
    }
    odir.inode.rename(&oname, &ndir.inode, &nname)
}

pub fn link(ctx: &Ctx, target: &str, path: &str) -> KResult<()> {
    let t = ctx.resolve(target, false)?;
    let (dir, name) = ctx.resolve_parent(path)?;
    if !Arc::ptr_eq(&t.mount, &dir.mount) {
        return Err(Errno::EXDEV);
    }
    if t.inode.metadata()?.kind == FileType::Directory {
        return Err(Errno::EPERM);
    }
    if dir.inode.lookup(&name).is_ok() {
        return Err(Errno::EEXIST);
    }
    perm::check(&ctx.cred, &dir.inode.metadata()?, MAY_WRITE | MAY_EXEC)?;
    check_rw_mount(&dir)?;
    dir.inode.link(&name, &t.inode)
}

pub fn symlink(ctx: &Ctx, target: &str, path: &str) -> KResult<()> {
    if target.is_empty() {
        return Err(Errno::ENOENT);
    }
    let (dir, name) = ctx.resolve_parent(path)?;
    if dir.inode.lookup(&name).is_ok() {
        return Err(Errno::EEXIST);
    }
    perm::check(&ctx.cred, &dir.inode.metadata()?, MAY_WRITE | MAY_EXEC)?;
    check_rw_mount(&dir)?;
    dir.inode.symlink(&name, target, ctx.cred.euid, ctx.cred.egid)?;
    Ok(())
}

pub fn readlink(ctx: &Ctx, path: &str) -> KResult<String> {
    let n = ctx.resolve(path, false)?;
    if n.inode.metadata()?.kind != FileType::Symlink {
        return Err(Errno::EINVAL);
    }
    n.inode.readlink()
}

pub fn chmod(ctx: &Ctx, path: &str, mode: u16, follow: bool) -> KResult<()> {
    let n = ctx.resolve(path, follow)?;
    let m = n.inode.metadata()?;
    if !perm::is_owner(&ctx.cred, &m) {
        return Err(Errno::EPERM);
    }
    check_rw_mount(&n)?;
    let mut mode = mode & 0o7777;
    // Non-root may not set setgid on a file whose group they are not in.
    if !ctx.cred.is_root() && !ctx.cred.in_group(m.gid) {
        mode &= !0o2000;
    }
    n.inode.set_attr(&SetAttr { perm: Some(mode), ..Default::default() })
}

pub fn chown(ctx: &Ctx, path: &str, uid: Option<u32>, gid: Option<u32>, follow: bool) -> KResult<()> {
    let n = ctx.resolve(path, follow)?;
    let m = n.inode.metadata()?;
    if !ctx.cred.is_root() {
        // Only root gives files away; owners may change the group to one of theirs.
        if uid.is_some_and(|u| u != m.uid) || ctx.cred.euid != m.uid || gid.is_some_and(|g| !ctx.cred.in_group(g)) {
            return Err(Errno::EPERM);
        }
    }
    check_rw_mount(&n)?;
    let mut perm = None;
    if m.kind == FileType::Regular && m.perm & 0o6000 != 0 && (uid.is_some() || gid.is_some()) {
        perm = Some(m.perm & !0o6000); // clear setuid/setgid on ownership change
    }
    n.inode.set_attr(&SetAttr { uid, gid, perm, ..Default::default() })
}

pub fn truncate(ctx: &Ctx, path: &str, size: u64) -> KResult<()> {
    let n = ctx.resolve(path, true)?;
    let m = n.inode.metadata()?;
    if m.kind == FileType::Directory {
        return Err(Errno::EISDIR);
    }
    perm::check(&ctx.cred, &m, MAY_WRITE)?;
    check_rw_mount(&n)?;
    n.inode.set_attr(&SetAttr { size: Some(size), mtime: Some(Timespec::now()), ..Default::default() })
}

pub fn utimes(ctx: &Ctx, path: &str, atime: Option<Timespec>, mtime: Option<Timespec>, follow: bool) -> KResult<()> {
    let n = ctx.resolve(path, follow)?;
    let m = n.inode.metadata()?;
    if !perm::is_owner(&ctx.cred, &m) && perm::check(&ctx.cred, &m, MAY_WRITE).is_err() {
        return Err(Errno::EACCES);
    }
    check_rw_mount(&n)?;
    n.inode.set_attr(&SetAttr { atime, mtime, ..Default::default() })
}

pub fn list_dir(ctx: &Ctx, path: &str) -> KResult<Vec<DirEntry>> {
    let n = ctx.resolve(path, true)?;
    let m = n.inode.metadata()?;
    if m.kind != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    perm::check(&ctx.cred, &m, MAY_READ)?;
    n.inode.readdir()
}

pub fn statfs(ctx: &Ctx, path: &str) -> KResult<(StatFs, PathRef)> {
    let n = ctx.resolve(path, true)?;
    Ok((n.mount.fs.statfs(), n))
}

/// Read a whole file (configuration files, small data).
pub fn read_file(ctx: &Ctx, path: &str) -> KResult<Vec<u8>> {
    let f = open(ctx, path, O_RDONLY, 0)?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

/// Create or replace a whole file.
pub fn write_file(ctx: &Ctx, path: &str, data: &[u8], mode: u16) -> KResult<()> {
    let f = open(ctx, path, O_WRONLY | O_CREAT | O_TRUNC, mode)?;
    f.write_all(data)
}

/// `mkdir -p`.
pub fn mkdir_all(ctx: &Ctx, path: &str, mode: u16) -> KResult<()> {
    let mut cur = String::new();
    if path.starts_with('/') {
        cur.push('/');
    }
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        if !cur.is_empty() && !cur.ends_with('/') {
            cur.push('/');
        }
        cur.push_str(comp);
        match mkdir(ctx, &cur, mode) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    let m = stat(ctx, path, true)?;
    if m.kind != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    Ok(())
}

/// `rm -rf path` (never crosses into other mounts).
pub fn remove_tree(ctx: &Ctx, path: &str) -> KResult<()> {
    let meta = match stat(ctx, path, false) {
        Ok(m) => m,
        Err(Errno::ENOENT) => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.kind != FileType::Directory {
        return unlink(ctx, path);
    }
    let node = ctx.resolve(path, false)?;
    for e in node.inode.readdir()? {
        let child = alloc::format!("{}/{}", path.trim_end_matches('/'), e.name);
        let cn = ctx.resolve(&child, false)?;
        if !Arc::ptr_eq(&cn.mount, &node.mount) {
            return Err(Errno::EBUSY);
        }
        remove_tree(ctx, &child)?;
        crate::sched::cond_resched();
    }
    rmdir(ctx, path)
}

pub fn chdir(p: &Process, path: &str) -> KResult<PathRef> {
    let ctx = Ctx::of(p);
    let n = ctx.resolve(path, true)?;
    let m = n.inode.metadata()?;
    if m.kind != FileType::Directory {
        return Err(Errno::ENOTDIR);
    }
    perm::check(&ctx.cred, &m, MAY_EXEC)?;
    p.fs.lock().cwd = n.clone();
    Ok(n)
}
