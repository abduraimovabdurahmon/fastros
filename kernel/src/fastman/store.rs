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

/// Create the store directories, owned by the calling user (mode 0700 — a
/// user's containers are private).
pub fn ensure(ctx: &Ctx) -> KResult<()> {
    for d in ["/var/lib/fastman", &base(ctx), &images_dir(ctx), &containers_dir(ctx)] {
        match ops::mkdir(ctx, d, 0o700) {
            Ok(()) | Err(crate::errno::Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    // The per-user root belongs to the user; the shared parent stays root:root.
    let _ = ops::chown(ctx, &base(ctx), Some(ctx.cred.uid), Some(ctx.cred.gid), true);
    Ok(())
}
