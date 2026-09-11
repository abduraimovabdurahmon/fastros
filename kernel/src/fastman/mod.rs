//! fastman — the FastROS container engine.
//!
//! A Docker-compatible container runtime with a Kubernetes-style declarative
//! layer on top, built for the FastROS security model:
//!
//! * **Rootless.** Any user runs containers; no root is required. Images and
//!   containers live under a per-user store, owned by that user.
//! * **Sandboxed like Podman.** A container is an ordinary ring-3 process in
//!   its own mount namespace, chrooted to the image root filesystem. The path
//!   resolver clamps `..` at the namespace root, so a container can never
//!   reach a host file. It has its own `/proc`, `/dev` and `/tmp`, no host
//!   network by default, and only the memory-safe syscall surface.
//! * **Read-only images, writable upper layer.** Image layers are extracted
//!   once and never mutated; each container gets its own writable rootfs.
//!
//! Layout of the per-user store (`store::base`):
//! ```text
//! <base>/images/<id>/rootfs/      extracted, read-only image tree
//! <base>/images/<id>/config       ImageConfig (env, cmd, workdir)
//! <base>/images/index             name:tag -> image id
//! <base>/containers/<id>/rootfs/  the container's writable tree
//! <base>/containers/<id>/config   ContainerRecord
//! <base>/containers/<id>/log      combined stdout/stderr
//! ```

pub mod container;
pub mod extract;
pub mod image;
pub mod runtime;
pub mod store;

pub use container::{Container, State};
pub use image::{ImageConfig, ImageRef};

use crate::errno::KResult;

/// Create the per-user store directories if they do not exist.
pub fn ensure_store(ctx: &crate::fs::ops::Ctx) -> KResult<()> {
    store::ensure(ctx)
}
