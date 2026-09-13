//! `fastman save` / `fastman load`: export and import an image as a single
//! gzip-compressed tar stream (a fastman-native format).
//!
//! The archive contains the image's flattened rootfs plus two metadata members,
//! `.fastman/repo` (the reference) and `.fastman/config` (the image config), so
//! `load` can re-register the image exactly as it was.

use super::{extract, image, store};
use crate::errno::{Errno, KResult};
use crate::fs::ops::{self, Ctx};
use crate::fs::FileType;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use fastros_archive::gzip::{self as gz, GzEncoder};
use fastros_archive::tar::{Entry, Kind, TarWriter};
use fastros_archive::Write as ArWrite;

/// An in-memory sink so the whole archive is built as a `Vec<u8>`.
struct VecSink(Vec<u8>);
impl ArWrite for VecSink {
    fn write_all(&mut self, buf: &[u8]) -> fastros_archive::Result<()> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

fn append(tw: &mut TarWriter<&mut dyn ArWrite>, path: &str, kind: Kind, mode: u32, link: &str, data: &[u8]) -> KResult<()> {
    let mut e = Entry::new(path, kind);
    e.mode = mode;
    e.link = link.to_string();
    e.size = data.len() as u64;
    tw.append(&e, data).map_err(|_| Errno::EIO)
}

/// Recursively append the rootfs subtree at `abs` (published under `rel`).
fn walk(ctx: &Ctx, tw: &mut TarWriter<&mut dyn ArWrite>, abs: &str, rel: &str) -> KResult<()> {
    for de in ops::list_dir(ctx, abs)? {
        if de.name == "." || de.name == ".." {
            continue;
        }
        let child = format!("{}/{}", abs.trim_end_matches('/'), de.name);
        let path = if rel.is_empty() { de.name.clone() } else { format!("{rel}/{}", de.name) };
        let md = ops::stat(ctx, &child, false)?; // lstat: keep symlinks
        match md.kind {
            FileType::Directory => {
                append(tw, &format!("{path}/"), Kind::Directory, md.perm as u32, "", &[])?;
                walk(ctx, tw, &child, &path)?;
            }
            FileType::Symlink => {
                let target = ops::readlink(ctx, &child).unwrap_or_default();
                append(tw, &path, Kind::Symlink, md.perm as u32, &target, &[])?;
            }
            FileType::Regular => {
                let data = ops::read_file(ctx, &child)?;
                append(tw, &path, Kind::File, md.perm as u32, "", &data)?;
            }
            _ => {} // devices/fifos/sockets are not carried in an image
        }
    }
    Ok(())
}

/// Serialize image `reference` to a gzip-compressed tar. Returns the bytes.
pub fn save(ctx: &Ctx, reference: &str) -> KResult<Vec<u8>> {
    let id = image::resolve(ctx, reference).ok_or(Errno::ENOENT)?;
    // Record the exact reference the user asked to save (normalised to a key),
    // not just any tag that happens to share the image id.
    let key = image::ImageRef::parse(reference).map(|r| r.key()).unwrap_or_else(|| reference.to_string());
    let config = ops::read_file(ctx, &image::config_path(ctx, &id)).unwrap_or_default();
    let rootfs = image::rootfs_path(ctx, &id);

    let mut enc = GzEncoder::new(VecSink(Vec::new()), 6, &gz::Header::default());
    let res = {
        let mut tw = TarWriter::new(&mut enc as &mut dyn ArWrite);
        append(&mut tw, ".fastman/repo", Kind::File, 0o644, "", key.as_bytes())
            .and_then(|_| append(&mut tw, ".fastman/config", Kind::File, 0o644, "", &config))
            .and_then(|_| walk(ctx, &mut tw, &rootfs, ""))
            .and_then(|_| tw.finish().map(|_| ()).map_err(|_| Errno::EIO))
    };
    res?;
    let (sink, _crc, _len) = enc.finish().map_err(|_| Errno::EIO)?;
    Ok(sink.0)
}

/// Load an image from a `save` archive. Returns the registered image.
pub fn load(ctx: &Ctx, data: &[u8]) -> KResult<image::Image> {
    let new_id = image::new_id();
    let dir = format!("{}/{new_id}", store::images_dir(ctx));
    ops::mkdir(ctx, &dir, 0o700)?;
    let rootfs = image::rootfs_path(ctx, &new_id);
    ops::mkdir(ctx, &rootfs, 0o755)?;
    let stats = extract::layer(ctx, &rootfs, data, ctx.cred.uid, ctx.cred.gid)?;

    // Recover the reference and config from the embedded metadata, then drop it.
    let meta = format!("{rootfs}/.fastman");
    let repo = ops::read_file(ctx, &format!("{meta}/repo"))
        .ok()
        .map(|d| String::from_utf8_lossy(&d).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("loaded-{}:latest", &new_id[..8.min(new_id.len())]));
    let cfg = ops::read_file(ctx, &format!("{meta}/config")).map(|d| image::ImageConfig::from_bytes(&d)).unwrap_or_else(|_| image::ImageConfig::defaults());
    let _ = ops::remove_tree(ctx, &meta);

    image::commit(ctx, &repo, &new_id, stats.bytes, &cfg)
}
