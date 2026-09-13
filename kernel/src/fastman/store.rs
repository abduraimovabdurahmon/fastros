//! The per-user on-disk store. Rootless: each user owns their own tree under
//! `/var/lib/fastman/<uid>`, so no shared root-owned state is needed.

use crate::errno::KResult;
use crate::fs::ops::{self, Ctx};
use alloc::format;
use alloc::string::String;

/// Root of the current user's store.
pub fn base(ctx: &Ctx) -> String {
    format!("/var/lib/fastman/{}", ctx.cred.uid)
}

pub fn images_dir(ctx: &Ctx) -> String {
    format!("{}/images", base(ctx))
}

pub fn containers_dir(ctx: &Ctx) -> String {
    format!("{}/containers", base(ctx))
}

pub fn index_path(ctx: &Ctx) -> String {
    format!("{}/images/index", base(ctx))
}

/// Named volumes (Docker `volume create`): each is a directory here, bind-mounted
/// into containers via `-v <name>:/path`.
pub fn volumes_dir(ctx: &Ctx) -> String {
    format!("{}/volumes", base(ctx))
}

/// Named networks (Docker `network create`): one marker file per network.
pub fn networks_dir(ctx: &Ctx) -> String {
    format!("{}/networks", base(ctx))
}

/// Create the store directories, owned by the calling user (mode 0700 — a
/// user's containers are private).
pub fn ensure(ctx: &Ctx) -> KResult<()> {
    // The shared parent is world-writable + sticky (the /tmp model): every user
    // may create their OWN per-uid subtree, but the sticky bit stops them from
    // renaming/removing another user's. This is what makes fastman genuinely
    // rootless — a non-root user could not previously create its store under a
    // root-owned 0700 parent. Force the mode even if it pre-exists with old
    // perms (only root's chmod takes effect, which is exactly who should fix it).
    match ops::mkdir(ctx, "/var/lib/fastman", 0o1777) {
        Ok(()) | Err(crate::errno::Errno::EEXIST) => {}
        Err(e) => return Err(e),
    }
    let _ = ops::chmod(ctx, "/var/lib/fastman", 0o1777, true);

    // Each user's own tree is private (0700) and owned by them.
    for d in [&base(ctx), &images_dir(ctx), &containers_dir(ctx), &volumes_dir(ctx), &networks_dir(ctx)] {
        match ops::mkdir(ctx, d, 0o700) {
            Ok(()) | Err(crate::errno::Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    let _ = ops::chown(ctx, &base(ctx), Some(ctx.cred.uid), Some(ctx.cred.gid), true);
    Ok(())
}
