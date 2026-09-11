//! Image references, image configuration, and the on-disk image store.

use super::store;
use crate::errno::{Errno, KResult};
use crate::fs::ops::{self, Ctx};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A parsed image reference: `[registry/]name[:tag]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageRef {
    pub registry: Option<String>,
    pub name: String,
    pub tag: String,
}

impl ImageRef {
    /// Parse Docker-style references:
    /// `nginx` → docker.io/library/nginx:latest,
    /// `alpine:3.20`, `quay.io/prometheus/busybox:v1`, `10.0.2.2:5000/app:v2`.
    pub fn parse(s: &str) -> Option<ImageRef> {
        if s.is_empty() {
            return None;
        }
        // A leading component with a '.' or ':' or "localhost" is a registry.
        let (registry, rest) = match s.split_once('/') {
            Some((first, rest)) if first == "localhost" || first.contains('.') || first.contains(':') => (Some(first.to_string()), rest),
            _ => (None, s),
        };
        let (name, tag) = match rest.rsplit_once(':') {
            // Guard against a port colon being mistaken for a tag.
            Some((n, t)) if !t.contains('/') => (n.to_string(), t.to_string()),
            _ => (rest.to_string(), String::from("latest")),
        };
        if name.is_empty() {
            return None;
        }
        // Official images get the implicit `library/` namespace on Docker Hub.
        let name = if registry.is_none() && !name.contains('/') { format!("library/{name}") } else { name };
        Some(ImageRef { registry, name, tag })
    }

    /// The `name:tag` key used in the store index and `fastman images`.
    pub fn key(&self) -> String {
        let short = self.name.strip_prefix("library/").unwrap_or(&self.name);
        match &self.registry {
            Some(r) => format!("{r}/{}:{}", self.name, self.tag),
            None => format!("{short}:{}", self.tag),
        }
    }
}

/// The runtime configuration recorded with an image (a subset of the OCI
/// image config): what to run and in what environment.
#[derive(Clone, Debug, Default)]
pub struct ImageConfig {
    pub env: Vec<String>,
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub workdir: String,
}

impl ImageConfig {
    /// Sensible defaults for a bare rootfs import.
    pub fn defaults() -> ImageConfig {
        ImageConfig {
            env: alloc::vec![String::from("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")],
            entrypoint: Vec::new(),
            cmd: alloc::vec![String::from("/bin/sh")],
            workdir: String::from("/"),
        }
    }

    /// The argv a container runs: entrypoint + (override or image cmd).
    pub fn argv(&self, override_cmd: &[String]) -> Vec<String> {
        let mut v = self.entrypoint.clone();
        if !override_cmd.is_empty() {
            v.extend_from_slice(override_cmd);
        } else {
            v.extend_from_slice(&self.cmd);
        }
        v
    }

    fn encode(&self) -> String {
        // A tiny line format: KEY<TAB>item<TAB>item... (records never contain tabs).
        let mut s = String::new();
        s.push_str(&format!("workdir\t{}\n", self.workdir));
        for e in &self.env {
            s.push_str(&format!("env\t{e}\n"));
        }
        for e in &self.entrypoint {
            s.push_str(&format!("entrypoint\t{e}\n"));
        }
        for c in &self.cmd {
            s.push_str(&format!("cmd\t{c}\n"));
        }
        s
    }

    fn decode(text: &str) -> ImageConfig {
        let mut c = ImageConfig { workdir: String::from("/"), ..Default::default() };
        for line in text.lines() {
            let Some((k, v)) = line.split_once('\t') else { continue };
            match k {
                "workdir" => c.workdir = v.to_string(),
                "env" => c.env.push(v.to_string()),
                "entrypoint" => c.entrypoint.push(v.to_string()),
                "cmd" => c.cmd.push(v.to_string()),
                _ => {}
            }
        }
        if c.cmd.is_empty() && c.entrypoint.is_empty() {
            c.cmd.push(String::from("/bin/sh"));
        }
        c
    }
}

/// A stored image: id, reference key, config, and size on disk.
pub struct Image {
    pub id: String,
    pub key: String,
    pub created: u64,
    pub size: u64,
}

fn new_id() -> String {
    let b: [u8; 8] = crate::crypto::rng::array();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Read the name:tag → id index.
fn read_index(ctx: &Ctx) -> Vec<(String, String)> {
    let text = ops::read_file(ctx, &store::index_path(ctx)).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
    text.lines().filter_map(|l| l.split_once('\t').map(|(k, id)| (k.to_string(), id.to_string()))).collect()
}

fn write_index(ctx: &Ctx, index: &[(String, String)]) -> KResult<()> {
    let mut s = String::new();
    for (k, id) in index {
        s.push_str(&format!("{k}\t{id}\n"));
    }
    ops::write_file(ctx, &store::index_path(ctx), s.as_bytes(), 0o600)
}

pub fn config_path(ctx: &Ctx, id: &str) -> String {
    format!("{}/{id}/config", store::images_dir(ctx))
}

pub fn rootfs_path(ctx: &Ctx, id: &str) -> String {
    format!("{}/{id}/rootfs", store::images_dir(ctx))
}

pub fn load_config(ctx: &Ctx, id: &str) -> ImageConfig {
    ops::read_file(ctx, &config_path(ctx, id))
        .map(|d| ImageConfig::decode(&String::from_utf8_lossy(&d)))
        .unwrap_or_else(|_| ImageConfig::defaults())
}

/// Resolve a reference or id prefix to an image id.
pub fn resolve(ctx: &Ctx, name: &str) -> Option<String> {
    let index = read_index(ctx);
    let key = ImageRef::parse(name).map(|r| r.key()).unwrap_or_else(|| name.to_string());
    if let Some((_, id)) = index.iter().find(|(k, _)| *k == key) {
        return Some(id.clone());
    }
    // Fall back to an id (or id prefix) match.
    index.iter().map(|(_, id)| id).find(|id| id.starts_with(name)).cloned().or_else(|| {
        ops::list_dir(ctx, &store::images_dir(ctx)).ok()?.into_iter().map(|e| e.name).find(|n| n.starts_with(name) && n != "index")
    })
}

/// Import a root-filesystem tarball (tar or tar.gz) as an image.
pub fn import(ctx: &Ctx, reference: &str, data: &[u8], config: ImageConfig) -> KResult<Image> {
    let r = ImageRef::parse(reference).ok_or(Errno::EINVAL)?;
    super::store::ensure(ctx)?;
    let id = new_id();
    let dir = format!("{}/{id}", store::images_dir(ctx));
    ops::mkdir(ctx, &dir, 0o700)?;
    let rootfs = rootfs_path(ctx, &id);
    ops::mkdir(ctx, &rootfs, 0o755)?;
    let st = super::extract::layer(ctx, &rootfs, data, ctx.cred.uid, ctx.cred.gid)?;
    ops::write_file(ctx, &config_path(ctx, &id), config.encode().as_bytes(), 0o600)?;
    // Update the index (replacing any existing image with the same key).
    let mut index = read_index(ctx);
    index.retain(|(k, _)| *k != r.key());
    index.push((r.key(), id.clone()));
    write_index(ctx, &index)?;
    Ok(Image { id, key: r.key(), created: crate::time::unix_now(), size: st.bytes })
}

/// List images, newest first is not tracked yet; index order.
pub fn list(ctx: &Ctx) -> Vec<Image> {
    read_index(ctx)
        .into_iter()
        .filter_map(|(key, id)| {
            let dir = format!("{}/{id}", store::images_dir(ctx));
            let created = ops::stat(ctx, &dir, true).map(|m| m.mtime.sec as u64).unwrap_or(0);
            let size = tree_size(ctx, &rootfs_path(ctx, &id));
            Some(Image { id, key, created, size })
        })
        .collect()
}

/// Remove an image by reference or id.
pub fn remove(ctx: &Ctx, name: &str) -> KResult<()> {
    let id = resolve(ctx, name).ok_or(Errno::ENOENT)?;
    let mut index = read_index(ctx);
    index.retain(|(_, i)| *i != id);
    write_index(ctx, &index)?;
    ops::remove_tree(ctx, &format!("{}/{id}", store::images_dir(ctx)))
}

fn tree_size(ctx: &Ctx, dir: &str) -> u64 {
    let mut total = 0;
    let Ok(entries) = ops::list_dir(ctx, dir) else { return 0 };
    for e in entries {
        let p = format!("{dir}/{}", e.name);
        match ops::stat(ctx, &p, false) {
            Ok(m) if m.kind == crate::fs::FileType::Directory => total += tree_size(ctx, &p),
            Ok(m) => total += m.size,
            Err(_) => {}
        }
    }
    total
}
