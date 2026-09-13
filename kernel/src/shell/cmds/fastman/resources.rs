//! fastman: `network` and `volume` management (Docker's resource commands).

use super::query::json_str;
use super::*;
use crate::fastman::container;
use crate::fastman::store;
use crate::outln;
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── networks ────────────────────────────────────────────────────────────────

/// The built-in networks that always exist and cannot be removed.
const BUILTIN_NETS: [&str; 3] = ["bridge", "host", "none"];

/// `fastman network <ls|create|rm|inspect>`.
pub(super) fn network(ctx: &mut Ctx, args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("ls");
    let rest = &args[args.len().min(1)..];
    match sub {
        "ls" | "list" => network_ls(ctx),
        "create" => network_create(ctx, rest),
        "rm" | "remove" => network_rm(ctx, rest),
        "inspect" => network_inspect(ctx, rest),
        other => ctx.fail(format!("unknown network command '{other}' (ls|create|rm|inspect)")),
    }
}

fn network_ls(ctx: &mut Ctx) -> i32 {
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);
    let mut t = Table::new(&["NAME", "DRIVER", "SCOPE"]);
    for n in BUILTIN_NETS {
        let driver = if n == "bridge" { "bridge" } else { n };
        t.row(alloc::vec![n.to_string(), driver.to_string(), "local".to_string()]);
    }
    for e in crate::fs::ops::list_dir(&fc, &store::networks_dir(&fc)).unwrap_or_default() {
        t.row(alloc::vec![e.name.clone(), "bridge".to_string(), "local".to_string()]);
    }
    t.render(ctx, &s);
    0
}

fn network_create(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let Some(name) = rest.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("network create requires a name");
    };
    if BUILTIN_NETS.contains(&name.as_str()) {
        return ctx.fail(format!("network '{name}' already exists"));
    }
    if name.contains('/') || name.is_empty() {
        return ctx.fail("invalid network name");
    }
    let fc = fs_ctx(ctx);
    let path = format!("{}/{name}", store::networks_dir(&fc));
    if crate::fs::ops::stat(&fc, &path, true).is_ok() {
        return ctx.fail(format!("network '{name}' already exists"));
    }
    match crate::fs::ops::write_file(&fc, &path, b"driver=bridge\n", 0o600) {
        Ok(()) => {
            outln!(ctx, "{name}");
            0
        }
        Err(e) => ctx.fail_errno("network create", e),
    }
}

fn network_rm(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let names: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("network rm requires a name");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in names {
        if BUILTIN_NETS.contains(&name.as_str()) {
            st = ctx.fail(format!("network '{name}' is predefined and cannot be removed"));
            continue;
        }
        // Refuse if a running container is still attached.
        if container::list(&fc).iter().any(|c| c.network == **name && c.is_alive()) {
            st = ctx.fail(format!("network '{name}' has active endpoints"));
            continue;
        }
        match crate::fs::ops::unlink(&fc, &format!("{}/{name}", store::networks_dir(&fc))) {
            Ok(()) => outln!(ctx, "{name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

fn network_inspect(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let names: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("network inspect requires a name");
    }
    let fc = fs_ctx(ctx);
    let mut objs: Vec<String> = Vec::new();
    let mut st = 0;
    for name in &names {
        let builtin = BUILTIN_NETS.contains(&name.as_str());
        let exists = builtin || crate::fs::ops::stat(&fc, &format!("{}/{name}", store::networks_dir(&fc)), true).is_ok();
        if !exists {
            st = ctx.fail(format!("no such network: {name}"));
            continue;
        }
        // Endpoints: running containers on this network, with their bridge IP.
        let mut eps: Vec<String> = Vec::new();
        for c in container::list(&fc).into_iter().filter(|c| c.network == ***name && c.is_alive()) {
            let ip = crate::net::netns::container_ip(&c.id).map(|a| a.to_string()).unwrap_or_default();
            eps.push(format!("{{ \"Name\": {}, \"IPv4Address\": {} }}", json_str(&c.name), json_str(&ip)));
        }
        let driver = if **name == "host" || **name == "none" { name.to_string() } else { "bridge".to_string() };
        let subnet = if driver == "bridge" { format!("10.88.0.0/{}", crate::net::bridge::BRIDGE_PREFIX) } else { String::new() };
        objs.push(format!(
            "  {{\n    \"Name\": {},\n    \"Driver\": {},\n    \"Scope\": \"local\",\n    \"Subnet\": {},\n    \"Containers\": [{}]\n  }}",
            json_str(name),
            json_str(&driver),
            json_str(&subnet),
            eps.join(", "),
        ));
    }
    if !objs.is_empty() {
        outln!(ctx, "[\n{}\n]", objs.join(",\n"));
    }
    st
}

// ── volumes ─────────────────────────────────────────────────────────────────

/// `fastman volume <ls|create|rm|inspect>`.
pub(super) fn volume(ctx: &mut Ctx, args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("ls");
    let rest = &args[args.len().min(1)..];
    match sub {
        "ls" | "list" => volume_ls(ctx),
        "create" => volume_create(ctx, rest),
        "rm" | "remove" => volume_rm(ctx, rest),
        "inspect" => volume_inspect(ctx, rest),
        other => ctx.fail(format!("unknown volume command '{other}' (ls|create|rm|inspect)")),
    }
}

fn volume_ls(ctx: &mut Ctx) -> i32 {
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);
    let mut t = Table::new(&["DRIVER", "VOLUME NAME"]);
    for e in crate::fs::ops::list_dir(&fc, &store::volumes_dir(&fc)).unwrap_or_default() {
        t.row(alloc::vec!["local".to_string(), e.name.clone()]);
    }
    t.render(ctx, &s);
    0
}

fn volume_create(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let Some(name) = rest.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("volume create requires a name");
    };
    if name.contains('/') || name.is_empty() {
        return ctx.fail("invalid volume name");
    }
    let fc = fs_ctx(ctx);
    match crate::fs::ops::mkdir(&fc, &format!("{}/{name}", store::volumes_dir(&fc)), 0o755) {
        Ok(()) | Err(crate::errno::Errno::EEXIST) => {
            outln!(ctx, "{name}");
            0
        }
        Err(e) => ctx.fail_errno("volume create", e),
    }
}

fn volume_rm(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let names: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("volume rm requires a name");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in names {
        let dir = format!("{}/{name}", store::volumes_dir(&fc));
        // Refuse if any container still references the volume (Docker's rule).
        if container::list(&fc).iter().any(|c| c.volumes.iter().any(|v| v.host == dir)) {
            st = ctx.fail(format!("volume '{name}' is in use"));
            continue;
        }
        match crate::fs::ops::remove_tree(&fc, &dir) {
            Ok(()) => outln!(ctx, "{name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

fn volume_inspect(ctx: &mut Ctx, rest: &[String]) -> i32 {
    let names: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("volume inspect requires a name");
    }
    let fc = fs_ctx(ctx);
    let mut objs: Vec<String> = Vec::new();
    let mut st = 0;
    for name in &names {
        let dir = format!("{}/{name}", store::volumes_dir(&fc));
        if crate::fs::ops::stat(&fc, &dir, true).is_err() {
            st = ctx.fail(format!("no such volume: {name}"));
            continue;
        }
        objs.push(format!(
            "  {{\n    \"Name\": {},\n    \"Driver\": \"local\",\n    \"Mountpoint\": {}\n  }}",
            json_str(name),
            json_str(&dir),
        ));
    }
    if !objs.is_empty() {
        outln!(ctx, "[\n{}\n]", objs.join(",\n"));
    }
    st
}
