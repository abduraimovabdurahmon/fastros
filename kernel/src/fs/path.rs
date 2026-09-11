//! Path resolution.
//!
//! A [`PathNode`] is one resolved component: the mount it is on, its inode,
//! its name and its parent node. Walking parents yields the absolute path, and
//! `..` is exact even across mount points and symlinks (physical resolution,
//! like Linux `openat`).

use super::mount::{Mount, MountNamespace};
use super::perm::{self, Cred, MAY_EXEC};
use super::{Errno, FileType, InodeRef, KResult};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

pub const MAX_SYMLINKS: u32 = 40;
pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;

pub struct PathNode {
    pub mount: Arc<Mount>,
    pub inode: InodeRef,
    pub name: String,
    pub parent: Option<PathRef>,
}

pub type PathRef = Arc<PathNode>;

impl PathNode {
    /// Absolute path of this node.
    pub fn path(&self) -> String {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur: Option<&PathNode> = Some(self);
        while let Some(n) = cur {
            if n.parent.is_some() {
                parts.push(&n.name);
            }
            cur = n.parent.as_deref();
        }
        if parts.is_empty() {
            return String::from("/");
        }
        let mut s = String::new();
        for p in parts.iter().rev() {
            s.push('/');
            s.push_str(p);
        }
        s
    }

    pub fn is_root(&self) -> bool {
        self.parent.is_none()
    }

    pub fn child(self: &Arc<Self>, name: &str, inode: InodeRef) -> PathRef {
        Arc::new(PathNode { mount: self.mount.clone(), inode, name: String::from(name), parent: Some(self.clone()) })
    }
}

/// Everything resolution depends on: namespace, root (chroot), cwd, creds.
pub struct Resolver<'a> {
    pub ns: &'a MountNamespace,
    pub root: &'a PathRef,
    pub cwd: &'a PathRef,
    pub cred: &'a Cred,
}

impl Resolver<'_> {
    /// Resolve `path`; the last component is followed if it is a symlink
    /// and `follow` is set.
    pub fn resolve(&self, path: &str, follow: bool) -> KResult<PathRef> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        if path.len() > PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut depth = 0;
        let must_be_dir = path.ends_with('/');
        let node = self.walk(self.cwd.clone(), path, follow || must_be_dir, &mut depth)?;
        if must_be_dir && !node.inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(node)
    }

    /// Resolve all but the last component: (parent directory, last name).
    /// The name is never `.` or `..` (those yield EINVAL / EISDIR-style errors
    /// at the caller); a path of `/` has no parent and yields EBUSY.
    pub fn resolve_parent(&self, path: &str) -> KResult<(PathRef, String)> {
        if path.is_empty() {
            return Err(Errno::ENOENT);
        }
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(Errno::EBUSY);
        }
        let (dir, name) = match trimmed.rfind('/') {
            Some(i) => (if i == 0 { "/" } else { &trimmed[..i] }, &trimmed[i + 1..]),
            None => (".", trimmed),
        };
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        let parent = self.resolve(dir, true)?;
        if !parent.inode.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok((parent, String::from(name)))
    }

    fn walk(&self, start: PathRef, path: &str, follow_last: bool, depth: &mut u32) -> KResult<PathRef> {
        let mut cur = if path.starts_with('/') { self.root.clone() } else { start };
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for (i, &c) in comps.iter().enumerate() {
            let last = i + 1 == comps.len();
            let meta = cur.inode.metadata()?;
            if meta.kind != FileType::Directory {
                return Err(Errno::ENOTDIR);
            }
            perm::check(self.cred, &meta, MAY_EXEC)?;
            match c {
                "." => {}
                ".." => {
                    if !Arc::ptr_eq(&cur, self.root) && !self.is_root_node(&cur) {
                        if let Some(p) = cur.parent.clone() {
                            cur = p;
                        }
                    }
                }
                name => {
                    if name.len() > NAME_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    let inode = cur.inode.lookup(name)?;
                    let mut node = cur.child(name, inode);
                    // Cross (possibly stacked) mount points.
                    while let Some(m) = self.ns.mounted_on(node.mount.id, node.inode.id()) {
                        node = Arc::new(PathNode {
                            mount: m.clone(),
                            inode: m.root.clone(),
                            name: node.name.clone(),
                            parent: node.parent.clone(),
                        });
                    }
                    if (!last || follow_last) && node.inode.kind()? == FileType::Symlink {
                        *depth += 1;
                        if *depth > MAX_SYMLINKS {
                            return Err(Errno::ELOOP);
                        }
                        let target = node.inode.readlink()?;
                        node = self.walk(cur.clone(), &target, true, depth)?;
                    }
                    cur = node;
                }
            }
        }
        Ok(cur)
    }

    /// Same inode identity as the resolver root (a chroot's root seen via another chain).
    fn is_root_node(&self, n: &PathRef) -> bool {
        n.parent.is_none() || (Arc::ptr_eq(&n.mount, &self.root.mount) && n.inode.id() == self.root.inode.id())
    }
}
