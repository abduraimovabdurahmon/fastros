//! fastman: registry pull + progress reporting.
use super::*;
use crate::fastman::image;
use crate::outln;
use crate::shell::ctx::Ctx;
use alloc::format;

/// Streams registry progress to the caller's terminal.
pub(super) struct CliProgress<'a> {
    pub(super) ctx: &'a mut Ctx,
}
impl crate::fastman::registry::Progress for CliProgress<'_> {
    fn line(&mut self, msg: &str) {
        self.ctx.print(msg);
        self.ctx.print("\n");
        self.ctx.flush();
    }
}

/// Pull `reference` from the registry and store it locally. Prints the same
/// progress Docker does. `Ok(())` on success, `Err(rc)` (already reported) on
/// failure. Shared by `fastman pull` and the auto-pull path of `fastman run`.
pub(super) fn pull_reference(ctx: &mut Ctx, reference: &str) -> Result<(), i32> {
    let r = match image::ImageRef::parse(reference) {
        Some(r) => r,
        None => return Err(ctx.fail(format!("invalid reference '{reference}'"))),
    };
    if !crate::net::is_up() {
        return Err(ctx.fail("no network"));
    }
    ctx.flush();
    let result = {
        let mut prog = CliProgress { ctx };
        crate::fastman::registry::pull(&r, &mut prog)
    };
    let pulled = match result {
        Ok(p) => p,
        Err(e) => return Err(ctx.fail(format!("pull {}: {}", r.key(), e.message()))),
    };
    let fc = fs_ctx(ctx);
    match image::store_layers(&fc, &r.key(), &pulled.layers, pulled.config) {
        Ok(img) => {
            outln!(ctx, "Status: Downloaded newer image for {}", r.key());
            outln!(ctx, "{}", img.key);
            crate::fastman::events::record("pull", &img.key);
            Ok(())
        }
        Err(e) => Err(ctx.fail_errno("store image", e)),
    }
}

/// Ensure an image is present locally, pulling it Docker-style if not. Used by
/// `fastman run` so `run <image>` works without a separate `pull`.
pub(super) fn ensure_image(ctx: &mut Ctx, image_name: &str) -> Result<(), i32> {
    let key = image::ImageRef::parse(image_name).map(|r| r.key()).unwrap_or_else(|| image_name.to_string());
    outln!(ctx, "Unable to find image '{key}' locally");
    pull_reference(ctx, image_name)
}

pub(super) fn pull(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(reference) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("pull requires an image reference");
    };
    match pull_reference(ctx, reference) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
