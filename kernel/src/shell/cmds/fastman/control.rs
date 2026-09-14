//! fastman: container control commands (restart, cp, kill, pause, etc.).
use super::*;
use crate::fastman::container;
use crate::fastman::runtime;
use crate::outln;
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// `fastman start [-a] [-i] <container>...`: (re)start stopped containers.
/// Detached by default (prints each name, like `docker start`); with `-a`/`-i`
/// on a single container, attach to it and wait.
pub(super) fn start(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut attach = false;
    let mut interactive = false;
    let mut names: Vec<&String> = Vec::new();
    for a in args {
        match a.as_str() {
            "-a" | "--attach" => attach = true,
            "-i" | "--interactive" => interactive = true,
            "-ai" | "-ia" => {
                attach = true;
                interactive = true;
            }
            s if s.starts_with('-') => {}
            _ => names.push(a),
        }
    }
    if names.is_empty() {
        return ctx.fail("start requires a container");
    }
    let fc = fs_ctx(ctx);
    // Attach/interactive only makes sense for a single container.
    let want_attach = (attach || interactive) && names.len() == 1;
    let mut st = 0;
    for name in &names {
        let mut c = match container::find(&fc, name) {
            Ok(c) => c,
            Err(e) => {
                st = ctx.fail_errno(name, e);
                continue;
            }
        };
        // Already running: `docker start` is a no-op that still prints the name.
        if c.live_state() == container::State::Running {
            outln!(ctx, "{}", c.name);
            continue;
        }
        if want_attach {
            let itty = if interactive { interactive_tty(ctx) } else { None };
            let tee = if interactive { None } else { runtime::caller_stdout(&ctx.proc) };
            ctx.flush();
            match runtime::start(&fc, &mut c, tee, itty.as_ref()) {
                Ok((pid, _)) => return wait_attached(ctx, &fc, &c, pid, itty.as_ref()),
                Err(e) => return ctx.fail_errno(name, e),
            }
        }
        match runtime::start(&fc, &mut c, None, None) {
            Ok(_) => outln!(ctx, "{}", c.name),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// Build an interactive TTY handle from the caller's stdio (shared with `run`).
fn interactive_tty(ctx: &mut Ctx) -> Option<runtime::ExecTty> {
    let fds = ctx.proc.fds.lock();
    match (fds.get(0), fds.get(1), fds.get(2)) {
        (Ok(stdin), Ok(stdout), Ok(stderr)) => {
            drop(fds);
            Some(runtime::ExecTty {
                stdin,
                stdout,
                stderr,
                tty: ctx.proc.ctty.lock().clone(),
                pgid: ctx.proc.pgid.load(core::sync::atomic::Ordering::Relaxed),
            })
        }
        _ => None,
    }
}

/// Wait for an attached container's init to finish, returning its exit code.
fn wait_attached(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, c: &container::Container, pid: u32, itty: Option<&runtime::ExecTty>) -> i32 {
    let Some(p) = crate::proc::find(pid) else {
        return container::load(fc, &c.id).map(|c| c.exit_code).unwrap_or(0);
    };
    if let Some(t) = itty {
        if let Some(tty) = &t.tty {
            tty.set_fg_pgrp(pid);
        }
    }
    let code = p.tasks().into_iter().next().map(|task| task.join()).unwrap_or(0);
    if let Some(t) = itty {
        if let Some(tty) = &t.tty {
            tty.set_fg_pgrp(t.pgid);
        }
    }
    let _ = ctx;
    code
}

/// `fastman restart <container>...`: stop (SIGTERM, escalating to SIGKILL) then
/// start each container again — the same lifecycle Docker's `restart` runs.
pub(super) fn restart(ctx: &mut Ctx, args: &[String]) -> i32 {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("restart requires a container");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in names {
        // Stop it if it is running (a no-op for an already-exited container).
        let _ = runtime::stop(&fc, name, crate::proc::signal::SIGTERM);
        match container::find(&fc, name) {
            Ok(mut c) => match runtime::start(&fc, &mut c, None, None) {
                Ok(_) => outln!(ctx, "{}", name),
                Err(e) => st = ctx.fail_errno(name, e),
            },
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// The final path component (Docker `cp` appends this when the destination is
/// an existing directory).
pub(super) fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

/// The parent directory of a path (for `mkdir -p` before writing a file).
pub(super) fn parent_dir(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => t[..i].to_string(),
        None => ".".to_string(),
    }
}

/// If `arg` is `<container>:<path>` for an existing container, return it.
pub(super) fn split_container(fc: &crate::fs::ops::Ctx, arg: &str) -> Option<(container::Container, String)> {
    let (maybe, path) = arg.split_once(':')?;
    // A host path has slashes or is relative; a container ref is a bare name.
    if maybe.is_empty() || maybe.contains('/') {
        return None;
    }
    container::find(fc, maybe).ok().map(|c| (c, path.to_string()))
}

/// An `ops::Ctx` pointed at a *running* container's filesystem (its live
/// overlay). The writable layer is a tmpfs that exists only while the container
/// runs, so `cp` requires the container to be up.
pub(super) fn container_ctx(ctx: &Ctx, c: &container::Container) -> Result<crate::fs::ops::Ctx, i32> {
    if !c.is_alive() {
        return Err(-1);
    }
    // Access the container's filesystem as the caller — never as root — so `cp`
    // cannot read or write files (e.g. via a bind mount) the caller could not.
    let cred = ctx.fs().cred;
    match crate::proc::find(c.pid) {
        Some(init) => Ok(crate::fs::ops::Ctx { fs: init.fs.lock().clone(), cred }),
        None => Err(-1),
    }
}

/// Recursively copy `from:from_path` to `to:to_path` (files and directories).
pub(super) fn copy_tree(from: &crate::fs::ops::Ctx, from_path: &str, to: &crate::fs::ops::Ctx, to_path: &str) -> crate::errno::KResult<()> {
    use crate::fs::ops;
    let md = ops::stat(from, from_path, true)?;
    if md.kind == crate::fs::FileType::Directory {
        ops::mkdir_all(to, to_path, md.perm | 0o700)?;
        for e in ops::list_dir(from, from_path)? {
            if e.name == "." || e.name == ".." {
                continue;
            }
            copy_tree(from, &format!("{from_path}/{}", e.name), to, &format!("{to_path}/{}", e.name))?;
        }
    } else {
        // Regular file (symlinks/devices are dereferenced by stat's follow).
        let data = ops::read_file(from, from_path)?;
        ops::mkdir_all(to, &parent_dir(to_path), 0o755)?;
        ops::write_file(to, to_path, &data, md.perm & 0o777)?;
    }
    Ok(())
}

/// `fastman cp SRC DST` — copy between a container and the host, where exactly
/// one of SRC/DST is `<container>:<path>` (Docker's `docker cp`). The container
/// must be running.
pub(super) fn cp(ctx: &mut Ctx, args: &[String]) -> i32 {
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.len() != 2 {
        return ctx.fail("cp requires SRC and DST (one as <container>:<path>)");
    }
    let (src, dst) = (paths[0].as_str(), paths[1].as_str());
    let fc = fs_ctx(ctx);
    let src_c = split_container(&fc, src);
    let dst_c = split_container(&fc, dst);

    // Resolve the destination Docker-style: into an existing directory, append
    // the source's basename; otherwise the destination is the target name.
    let resolve_dst = |to: &crate::fs::ops::Ctx, from_path: &str, to_path: &str| -> String {
        match crate::fs::ops::stat(to, to_path, true) {
            Ok(m) if m.kind == crate::fs::FileType::Directory => format!("{}/{}", to_path.trim_end_matches('/'), basename(from_path)),
            _ => to_path.to_string(),
        }
    };

    let result = match (src_c, dst_c) {
        (Some((c, cpath)), None) => {
            // container -> host
            match container_ctx(ctx, &c) {
                Ok(cc) => {
                    let dstp = resolve_dst(&fc, &cpath, dst);
                    copy_tree(&cc, &cpath, &fc, &dstp)
                }
                Err(_) => return ctx.fail(format!("container {} is not running", c.name)),
            }
        }
        (None, Some((c, cpath))) => {
            // host -> container
            match container_ctx(ctx, &c) {
                Ok(cc) => {
                    let dstp = resolve_dst(&cc, src, &cpath);
                    copy_tree(&fc, src, &cc, &dstp)
                }
                Err(_) => return ctx.fail(format!("container {} is not running", c.name)),
            }
        }
        (Some(_), Some(_)) => return ctx.fail("copying between two containers is not supported"),
        (None, None) => return ctx.fail("one of SRC or DST must be <container>:<path>"),
    };
    match result {
        Ok(()) => 0,
        Err(e) => ctx.fail_errno("cp", e),
    }
}

/// `fastman kill [-s SIGNAL] <container>...` — send a signal (default SIGKILL).
pub(super) fn kill(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut sig = crate::proc::signal::SIGKILL;
    let mut names = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--signal" => {
                i += 1;
                match args.get(i).and_then(|s| crate::proc::signal::parse(s)) {
                    Some(s) => sig = s,
                    None => return ctx.fail("kill: invalid signal"),
                }
            }
            s if s.starts_with('-') && s.len() > 1 => {
                // `-9` / `-KILL` form.
                match crate::proc::signal::parse(&s[1..]) {
                    Some(x) => sig = x,
                    None => return ctx.fail(format!("kill: invalid signal '{s}'")),
                }
            }
            _ => names.push(args[i].clone()),
        }
        i += 1;
    }
    if names.is_empty() {
        return ctx.fail("kill requires a container");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in &names {
        match runtime::signal_container(&fc, name, sig) {
            Ok(_) => {
                // A manual kill suppresses the restart policy, like docker kill.
                if let Ok(mut c) = container::find(&fc, name) {
                    if !c.restart_policy.is_empty() && !c.stopped_by_user {
                        c.stopped_by_user = true;
                        let _ = c.save(&fc);
                    }
                }
                outln!(ctx, "{name}");
            }
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// Shared by `pause` (SIGSTOP) and `unpause` (SIGCONT).
pub(super) fn pause_cmd(ctx: &mut Ctx, args: &[String], sig: u32, verb: &str) -> i32 {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail(format!("{verb} requires a container"));
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in names {
        match runtime::signal_container(&fc, name, sig) {
            Ok(_) => outln!(ctx, "{name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// `fastman rename <old> <new>`.
pub(super) fn rename(ctx: &mut Ctx, args: &[String]) -> i32 {
    let a: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if a.len() != 2 {
        return ctx.fail("rename requires OLD and NEW names");
    }
    let fc = fs_ctx(ctx);
    match runtime::rename(&fc, a[0], a[1]) {
        Ok(()) => 0,
        Err(e) => ctx.fail_errno("rename", e),
    }
}

/// `fastman top <container>` — the processes running inside a container.
pub(super) fn top(ctx: &mut Ctx, args: &[String]) -> i32 {
    use crate::shell::cmds::procinfo as pi;
    let Some(name) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("top requires a container");
    };
    let fc = fs_ctx(ctx);
    let pids = match runtime::container_pids(&fc, name) {
        Ok(p) => p,
        Err(e) => return ctx.fail_errno(name, e),
    };
    if pids.is_empty() {
        return ctx.fail(format!("{name} is not running"));
    }
    let s = style_of(ctx);
    let procs = pi::list(&fc);
    let mut t = Table::new(&["PID", "PPID", "STAT", "TIME", "COMMAND"]);
    for p in &procs {
        if pids.contains(&p.pid) {
            t.row(alloc::vec![
                format!("{}", p.pid),
                format!("{}", p.ppid),
                p.stat_flags(),
                pi::fmt_time_plus(p.cpu_ticks()),
                p.args(),
            ]);
        }
    }
    t.render(ctx, &s);
    0
}

/// `fastman port <container>` — its published port mappings.
pub(super) fn port(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(name) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("port requires a container");
    };
    let fc = fs_ctx(ctx);
    let c = match container::find(&fc, name) {
        Ok(c) => c,
        Err(e) => return ctx.fail_errno(name, e),
    };
    for p in &c.ports {
        let proto = if p.udp { "udp" } else { "tcp" };
        outln!(ctx, "{}/{} -> 0.0.0.0:{}", p.container, proto, p.host);
    }
    0
}

/// `fastman wait <container>...` — block until each exits, printing its code.
pub(super) fn wait_cmd(ctx: &mut Ctx, args: &[String]) -> i32 {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("wait requires a container");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in names {
        match runtime::wait(&fc, name) {
            Ok(code) => outln!(ctx, "{code}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// `fastman update [-m SIZE] [--pids-limit N] <container>...` — change limits.
pub(super) fn update(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut mem = None;
    let mut pids = None;
    let mut names = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--memory" => {
                i += 1;
                match args.get(i).and_then(|s| parse_size(s).ok()) {
                    Some(m) => mem = Some(m),
                    None => return ctx.fail("update: -m needs a size (e.g. 256m)"),
                }
            }
            "--pids-limit" => {
                i += 1;
                match args.get(i).and_then(|s| s.parse().ok()) {
                    Some(p) => pids = Some(p),
                    None => return ctx.fail("update: --pids-limit needs a number"),
                }
            }
            s if s.starts_with('-') => return ctx.fail(format!("update: unknown option '{s}'")),
            _ => names.push(args[i].clone()),
        }
        i += 1;
    }
    if names.is_empty() {
        return ctx.fail("update requires a container");
    }
    if mem.is_none() && pids.is_none() {
        return ctx.fail("update: nothing to change (use -m or --pids-limit)");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in &names {
        match runtime::update_limits(&fc, name, mem, pids) {
            Ok(()) => outln!(ctx, "{name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

pub(super) fn exec(ctx: &mut Ctx, args: &[String]) -> i32 {
    // -i/-t/-it request an interactive session: wire the caller's terminal
    // straight to the container command (so `sh`/`bash`/`psql` are usable).
    let interactive = args.iter().any(|a| matches!(a.as_str(), "-i" | "-t" | "-it" | "-ti" | "--interactive" | "--tty"));
    let rest: Vec<String> = args.iter().filter(|a| !matches!(a.as_str(), "-i" | "-t" | "-it" | "-ti" | "--interactive" | "--tty")).cloned().collect();
    if rest.len() < 2 {
        return ctx.fail("exec requires a container and a command");
    }
    let name = rest[0].clone();
    let argv = rest[1..].to_vec();
    let fc = fs_ctx(ctx);
    let itty = if interactive {
        let fds = ctx.proc.fds.lock();
        match (fds.get(0), fds.get(1), fds.get(2)) {
            (Ok(stdin), Ok(stdout), Ok(stderr)) => {
                drop(fds);
                Some(runtime::ExecTty {
                    stdin,
                    stdout,
                    stderr,
                    tty: ctx.proc.ctty.lock().clone(),
                    pgid: ctx.proc.pgid.load(core::sync::atomic::Ordering::Relaxed),
                })
            }
            _ => None,
        }
    } else {
        None
    };
    let tee = if interactive { None } else { runtime::caller_stdout(&ctx.proc) };
    ctx.flush();
    match runtime::exec(&fc, &name, argv, tee, itty) {
        Ok(code) => code,
        Err(crate::errno::Errno::ENOTCONN) => ctx.fail(format!("container {name} is not running")),
        Err(e) => ctx.fail_errno("exec", e),
    }
}
