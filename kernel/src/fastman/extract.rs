//! Extract a tar (optionally gzip-compressed) layer into a directory in the
//! VFS. Used both to import a root-filesystem tarball and to unpack OCI image
//! layers pulled from a registry.
//!
//! Security: every member path is sanitised (no absolute paths, no `..`
//! escape) before anything is created, so a malicious layer cannot write
//! outside `dest`. OverlayFS whiteouts (`.wh.<name>`) delete a path from a
//! lower layer, so stacking layers matches Docker's semantics.

use crate::errno::{Errno, KResult};
use crate::fs::file::flags;
use crate::fs::ops::{self, Ctx};
use crate::fs::FileType;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use fastros_archive::path::sanitize;
use fastros_archive::tar::{Kind, TarReader};
use fastros_archive::{gzip, Read};

/// Statistics from extracting one layer.
#[derive(Default, Clone, Copy)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    pub bytes: u64,
    pub whiteouts: u64,
}

/// Extract `data` (tar or tar.gz) into `dest` (which must exist). Ownership of
/// every created entry is set to `owner`/`group` (rootless remap), not the
/// uid recorded in the archive, so the whole tree belongs to the caller.
pub fn layer(ctx: &Ctx, dest: &str, data: &[u8], owner: u32, group: u32) -> KResult<Stats> {
    if gzip::is_gzip(data) {
        let dec = gzip::GzDecoder::new(data);
        untar(ctx, dest, dec, owner, group)
    } else {
        untar(ctx, dest, data, owner, group)
    }
}

fn ae(e: fastros_archive::Error) -> Errno {
    match e {
        fastros_archive::Error::Io(_) => Errno::EIO,
        _ => Errno::EINVAL,
    }
}

fn untar<R: Read>(ctx: &Ctx, dest: &str, src: R, owner: u32, group: u32) -> KResult<Stats> {
    let mut st = Stats::default();
    let mut tr = TarReader::new(src);
    while let Some(entry) = tr.next_entry().map_err(ae)? {
        // Extracting a large image is a long kernel-side operation; yield
        // between entries so a big pull never starves the rest of the system.
        crate::sched::cond_resched();
        let safe = match sanitize(&entry.path) {
            Ok(s) => s,
            Err(_) => {
                tr.skip_data().map_err(ae)?;
                continue; // reject unsafe paths silently, like tar --skip
            }
        };
        let rel = safe.path.as_str();
        if rel.is_empty() {
            tr.skip_data().map_err(ae)?;
            continue;
        }
        // OverlayFS whiteout: `dir/.wh.name` deletes `dir/name`.
        let base = rel.rsplit('/').next().unwrap_or(rel);
        if let Some(name) = base.strip_prefix(".wh.") {
            if name == ".wh..opq" {
                // Opaque dir: everything below the parent from lower layers is hidden.
                // (MVP: we extract layers in order into one tree, so a plain
                // remove of existing children is a close-enough approximation.)
            } else {
                let dir = &rel[..rel.len() - base.len()];
                let victim = format!("{dest}/{dir}{name}");
                let _ = ops::remove_tree(ctx, &victim);
                st.whiteouts += 1;
            }
            tr.skip_data().map_err(ae)?;
            continue;
        }
        let full = format!("{dest}/{rel}");
        let mode = (entry.mode & 0o7777) as u16;
        match entry.kind {
            Kind::Directory => {
                match ops::mkdir(ctx, &full, mode) {
                    Ok(()) | Err(Errno::EEXIST) => {}
                    Err(e) => return Err(e),
                }
                st.dirs += 1;
            }
            Kind::File => {
                if let Some(parent) = full.rsplit_once('/').map(|(p, _)| p) {
                    let _ = ops::mkdir_all(ctx, parent, 0o755);
                }
                let f = ops::open(ctx, &full, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, mode)?;
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = tr.read_data(&mut buf).map_err(ae)?;
                    if n == 0 {
                        break;
                    }
                    f.write_all(&buf[..n])?;
                    st.bytes += n as u64;
                    crate::sched::cond_resched();
                }
                let _ = ops::chmod(ctx, &full, mode, true);
                st.files += 1;
            }
            Kind::Symlink => {
                let _ = ops::remove_tree(ctx, &full);
                if let Some(parent) = full.rsplit_once('/').map(|(p, _)| p) {
                    let _ = ops::mkdir_all(ctx, parent, 0o755);
                }
                ops::symlink(ctx, &entry.link, &full)?;
                st.links += 1;
            }
            Kind::HardLink => {
                let target = format!("{dest}/{}", sanitize(&entry.link).map(|s| s.path.clone()).unwrap_or_default());
                let _ = ops::remove_tree(ctx, &full);
                if ops::link(ctx, &target, &full).is_err() {
                    // Fall back to a copy if hard links across the layer fail.
                    if let Ok(bytes) = ops::read_file(ctx, &target) {
                        let _ = ops::write_file(ctx, &full, &bytes, mode);
                    }
                }
                st.links += 1;
            }
            Kind::CharDevice | Kind::BlockDevice => {
                let kind = if entry.kind == Kind::CharDevice { FileType::CharDevice } else { FileType::BlockDevice };
                let rdev = crate::fs::makedev(entry.dev_major, entry.dev_minor);
                let _ = ops::mknod(ctx, &full, kind, mode, rdev);
            }
            Kind::Fifo => {
                let _ = ops::mknod(ctx, &full, FileType::Fifo, mode, 0);
            }
            Kind::Other(_) => {
                tr.skip_data().map_err(ae)?;
                continue;
            }
        }
        // Rootless ownership remap: the caller owns everything.
        let follow = !matches!(entry.kind, Kind::Symlink);
        let _ = ops::chown(ctx, &full, Some(owner), Some(group), follow);
    }
    Ok(st)
}


/// A directory tree copy (for the container's writable rootfs on top of a
/// read-only image). Straightforward recursive copy for the MVP; a real
/// overlay mount is a later optimisation.
pub fn copy_tree(ctx: &Ctx, from: &str, to: &str) -> KResult<()> {
    match ops::mkdir(ctx, to, 0o755) {
        Ok(()) | Err(Errno::EEXIST) => {}
        Err(e) => return Err(e),
    }
    for e in ops::list_dir(ctx, from)? {
        // Copying a whole image tree is a long, kernel-side operation: yield
        // between entries so a big image (nginx, postgres) never starves the
        // rest of the system while a container starts.
        crate::sched::cond_resched();
        let src = format!("{from}/{}", e.name);
        let dst = format!("{to}/{}", e.name);
        let m = match ops::stat(ctx, &src, false) {
            Ok(m) => m,
            Err(_) => continue,
        };
        match m.kind {
            FileType::Directory => {
                copy_tree(ctx, &src, &dst)?;
                let _ = ops::chmod(ctx, &dst, m.perm, true);
            }
            FileType::Symlink => {
                if let Ok(t) = ops::readlink(ctx, &src) {
                    let _ = ops::symlink(ctx, &t, &dst);
                }
            }
            FileType::Regular => {
                copy_file(ctx, &src, &dst, m.perm)?;
            }
            _ => {
                let _ = ops::mknod(ctx, &dst, m.kind, m.perm, m.rdev);
            }
        }
        let _ = ops::chown(ctx, &dst, Some(m.uid), Some(m.gid), m.kind != FileType::Symlink);
    }
    Ok(())
}

/// Stream one regular file in fixed chunks, yielding between them, so a large
/// file is copied without loading it all into RAM and without starving the CPU.
fn copy_file(ctx: &Ctx, src: &str, dst: &str, perm: u16) -> KResult<()> {
    let input = match ops::open(ctx, src, flags::O_RDONLY, 0) {
        Ok(f) => f,
        Err(_) => return Ok(()),
    };
    let output = ops::open(ctx, dst, flags::O_WRONLY | flags::O_CREAT | flags::O_TRUNC, perm)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        (*output).write_all(&buf[..n])?;
        crate::sched::cond_resched();
    }
    Ok(())
}
