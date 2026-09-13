//! `fastman build` — build an image from a Dockerfile.
//!
//! The build runs each instruction against a single **overlay build
//! environment**: the base image's rootfs as a read-only lower layer and one
//! persistent writable tmpfs upper that accumulates every `RUN`/`COPY` change.
//! `RUN` spawns a real process (`/bin/sh -c …`) inside that overlay, exactly as
//! a container would run, so a step sees everything the previous steps wrote.
//! When the Dockerfile is exhausted the merged overlay tree is copied into a
//! fresh image rootfs and tagged.
//!
//! Supported instructions: FROM, RUN, COPY, ADD, ENV, ARG, WORKDIR, CMD,
//! ENTRYPOINT, USER, EXPOSE, LABEL. `$VAR` / `${VAR}` are expanded from ARG and
//! ENV in instruction arguments (shell `RUN` lines are left to the shell).

use super::image::{self, ImageConfig};
use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File};
use crate::fs::mount::{MountFlags, MountNamespace};
use crate::fs::ops::{self, Ctx};
use crate::fs::FileType;
use crate::proc::{self, FsContext, Spawn};
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// A single parsed Dockerfile instruction.
enum Insn {
    From(String),
    /// Shell form → run via `/bin/sh -c`; exec form → argv run directly.
    Run(Vec<String>, bool),
    Copy { srcs: Vec<String>, dest: String },
    Env(Vec<(String, String)>),
    Arg(String, Option<String>),
    Workdir(String),
    Cmd(Vec<String>),
    Entrypoint(Vec<String>),
    User(String),
    /// HEALTHCHECK: a shell command plus timings (seconds); empty cmd = NONE.
    Health { cmd: String, interval: u32, timeout: u32, retries: u32 },
    /// EXPOSE / LABEL / MAINTAINER / STOPSIGNAL / … — recorded but inert.
    Noop,
}

/// The result of a build: the new image plus a human-readable step log.
pub struct Built {
    pub image: image::Image,
}

/// Options parsed from the `fastman build` command line.
pub struct BuildOpts {
    /// `-t name:tag` (repeatable in Docker; we take the first).
    pub tag: String,
    /// `-f path` — Dockerfile path inside the build context (default `Dockerfile`).
    pub dockerfile: String,
    /// `--build-arg KEY=VALUE` overrides for ARG.
    pub build_args: Vec<(String, String)>,
}

impl Default for BuildOpts {
    fn default() -> BuildOpts {
        BuildOpts { tag: String::new(), dockerfile: String::from("Dockerfile"), build_args: Vec::new() }
    }
}

/// Build an image. `context` is a tar/tar.gz of the build context (containing
/// the Dockerfile). `out` receives the output of each `RUN` step (the caller's
/// stdout); when `None`, step output is discarded.
pub fn build(ctx: &Ctx, opts: &BuildOpts, context: &[u8], out: Option<Arc<dyn File>>) -> KResult<Built> {
    super::store::ensure(ctx)?;

    // 1. Extract the build context into a scratch directory in the store.
    let cid = image::new_id();
    let cdir = format!("{}/build-{cid}", super::store::base(ctx));
    ops::mkdir_all(ctx, &cdir, 0o700)?;
    let cleanup = |ctx: &Ctx| {
        let _ = ops::remove_tree(ctx, &cdir);
    };
    if let Err(e) = super::extract::layer(ctx, &cdir, context, ctx.cred.uid, ctx.cred.gid) {
        cleanup(ctx);
        return Err(e);
    }

    // 2. Read and parse the Dockerfile.
    let dfpath = format!("{cdir}/{}", opts.dockerfile.trim_start_matches('/'));
    let dftext = match ops::read_file(ctx, &dfpath) {
        Ok(d) => String::from_utf8_lossy(&d).into_owned(),
        Err(e) => {
            cleanup(ctx);
            return Err(e);
        }
    };
    let insns = parse(&dftext);
    let r = build_inner(ctx, opts, &cdir, &insns, out);
    cleanup(ctx);
    r
}

fn build_inner(ctx: &Ctx, opts: &BuildOpts, cdir: &str, insns: &[Insn], out: Option<Arc<dyn File>>) -> KResult<Built> {
    // The FROM must come first (after any leading ARGs).
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in &opts.build_args {
        vars.insert(k.clone(), v.clone());
    }

    // Locate FROM and resolve the base image.
    let mut idx = 0;
    // Leading ARG lines (before FROM) contribute to variable expansion of FROM.
    while idx < insns.len() {
        match &insns[idx] {
            Insn::Arg(k, dflt) => {
                if !vars.contains_key(k) {
                    if let Some(d) = dflt {
                        vars.insert(k.clone(), expand(d, &vars));
                    }
                }
                idx += 1;
            }
            Insn::Noop => idx += 1,
            _ => break,
        }
    }
    let base = match insns.get(idx) {
        Some(Insn::From(b)) => expand(b, &vars),
        _ => return Err(Errno::EINVAL),
    };
    idx += 1;

    let base_id = image::resolve(ctx, &base).ok_or(Errno::ENOENT)?;
    let base_cfg = image::load_config(ctx, &base_id);

    // Build state starts from the base image's config.
    let mut cfg = base_cfg.clone();
    for e in &cfg.env {
        if let Some((k, v)) = e.split_once('=') {
            vars.insert(k.to_string(), v.to_string());
        }
    }

    // 3. The overlay build environment: base rootfs (RO) + one persistent upper.
    let lower = ctx.resolve(&image::rootfs_path(ctx, &base_id), true)?;
    let upper = crate::fs::tmpfs::TmpFs::new(0);
    let overlay = crate::fs::overlayfs::OverlayFs::new(lower.inode.clone(), upper);

    // A namespace with /proc, /dev, /tmp for RUN commands.
    let run_ns = MountNamespace::new(overlay.clone(), "overlay", MountFlags::RW);
    let run_root = run_ns.root();
    let build_ctx = Ctx { fs: FsContext { ns: run_ns.clone(), root: run_root.clone(), cwd: run_root.clone(), umask: 0o022 }, cred: ctx.cred.clone() };
    for d in ["proc", "dev", "tmp", "sys"] {
        let _ = ops::mkdir(&build_ctx, &format!("/{d}"), 0o755);
    }
    let at = |path: &str| -> KResult<crate::fs::path::PathRef> {
        let r = crate::fs::path::Resolver { ns: &run_ns, root: &run_root, cwd: &run_root, cred: &ctx.cred };
        r.resolve(path, true)
    };
    let nodev = MountFlags { nosuid: true, nodev: true, ..MountFlags::RW };
    if let Ok(p) = at("/proc") {
        let _ = run_ns.mount(&p, crate::fs::procfs::ProcFs::new(), "proc", MountFlags { noexec: true, ..nodev });
    }
    if let Ok(p) = at("/dev") {
        let _ = run_ns.mount(&p, crate::fs::devfs::create(), "devtmpfs", MountFlags { nosuid: true, ..MountFlags::RW });
    }
    if let Ok(p) = at("/tmp") {
        let _ = run_ns.mount(&p, crate::fs::tmpfs::TmpFs::new(0), "tmpfs", nodev);
    }

    // 4. Execute each instruction in order.
    let mut workdir = if cfg.workdir.is_empty() { String::from("/") } else { cfg.workdir.clone() };
    for insn in &insns[idx..] {
        match insn {
            Insn::From(_) => return Err(Errno::EINVAL), // multi-stage not supported
            Insn::Arg(k, dflt) => {
                if !vars.contains_key(k) {
                    if let Some(d) = dflt {
                        vars.insert(k.clone(), expand(d, &vars));
                    }
                }
            }
            Insn::Env(pairs) => {
                for (k, v) in pairs {
                    let v = expand(v, &vars);
                    vars.insert(k.clone(), v.clone());
                    set_env(&mut cfg.env, k, &v);
                }
            }
            Insn::Workdir(w) => {
                let w = expand(w, &vars);
                workdir = join_path(&workdir, &w);
                ops::mkdir_all(&build_ctx, &workdir, 0o755)?;
                cfg.workdir = workdir.clone();
            }
            Insn::Copy { srcs, dest } => {
                run_copy(ctx, &build_ctx, cdir, srcs, dest, &workdir, &vars)?;
            }
            Insn::Run(argv, shell) => {
                let argv = build_run_argv(argv, *shell, &vars);
                let code = run_step(&build_ctx, &argv, &cfg.env, &workdir, out.clone())?;
                if code != 0 {
                    return Err(Errno::EIO);
                }
            }
            Insn::Cmd(v) => cfg.cmd = v.iter().map(|s| expand(s, &vars)).collect(),
            Insn::Entrypoint(v) => cfg.entrypoint = v.iter().map(|s| expand(s, &vars)).collect(),
            Insn::Health { cmd, interval, timeout, retries } => {
                cfg.health_cmd = expand(cmd, &vars);
                cfg.health_interval = *interval;
                cfg.health_timeout = *timeout;
                cfg.health_retries = *retries;
            }
            Insn::User(_) | Insn::Noop => {}
        }
    }

    // 5. Commit the merged overlay tree into a new image rootfs.
    let commit_ns = MountNamespace::new(overlay, "overlay", MountFlags::RW);
    let commit_root = commit_ns.root();
    let src = Ctx { fs: FsContext { ns: commit_ns.clone(), root: commit_root.clone(), cwd: commit_root.clone(), umask: 0 }, cred: ctx.cred.clone() };

    let new_id = image::new_id();
    let dir = format!("{}/{new_id}", super::store::images_dir(ctx));
    ops::mkdir(ctx, &dir, 0o700)?;
    let rootfs = image::rootfs_path(ctx, &new_id);
    ops::mkdir(ctx, &rootfs, 0o755)?;
    let mut bytes = 0u64;
    copy_tree(&src, "/", ctx, &rootfs, 0, &mut bytes)?;

    if cfg.cmd.is_empty() && cfg.entrypoint.is_empty() {
        cfg.cmd.push(String::from("/bin/sh"));
    }
    let img = image::commit(ctx, &opts.tag, &new_id, bytes, &cfg)?;
    Ok(Built { image: img })
}

/// Run one `RUN` step: spawn the program inside the overlay and wait for it.
fn run_step(bctx: &Ctx, argv: &[String], env: &[String], workdir: &str, out: Option<Arc<dyn File>>) -> KResult<i32> {
    if argv.is_empty() {
        return Ok(0);
    }
    // Resolve and load the program from inside the build overlay.
    let real = proc::elf::find_program(bctx, &argv[0])?;
    let (data, argv) = proc::elf::read_exec(bctx, &real, argv)?;
    let (space, frame) = proc::elf::load(bctx, &data, &argv, env)?;

    // stdin from /dev/null; stdout/stderr straight to the caller (build log).
    let null = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY)?;
    let sink: Arc<dyn File> = match out {
        Some(o) => o,
        None => crate::device::open_char(crate::fs::makedev(1, 3), flags::O_WRONLY)?,
    };
    let mut fds = crate::proc::fdtable::FdTable::new();
    fds.set(0, null, false);
    fds.set(1, sink.clone(), false);
    fds.set(2, sink, false);

    // The RUN step runs at the build working directory.
    let cwd = bctx.resolve(workdir, true).unwrap_or_else(|_| bctx.fs.root.clone());
    let fs = FsContext { ns: bctx.fs.ns.clone(), root: bctx.fs.root.clone(), cwd, umask: 0o022 };

    let spawn = Spawn {
        name: String::from("build"),
        args: argv,
        env: env_pairs(env),
        cred: bctx.cred.clone(),
        fs,
        fds,
        parent: crate::proc::kernel(),
        pgid: None,
        new_session: true,
        ctty: None,
        uts: crate::proc::kernel().uts.clone(),
        container: Some(String::from("build")),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
        pidns: Some(crate::proc::PidNs::new()),
        caps: crate::syscall::seccomp::default_caps(bctx.cred.uid),
        no_new_privs: false,
        seccomp: None,
        netns: None,
    };
    let child = proc::start_user(spawn, space, frame)?;
    let code = child.tasks().into_iter().next().map(|t| t.join()).unwrap_or(0);
    Ok(code)
}

/// COPY/ADD: copy each source (a path inside the build context) into the
/// overlay at `dest` (resolved against the current WORKDIR).
fn run_copy(host: &Ctx, bctx: &Ctx, cdir: &str, srcs: &[String], dest: &str, workdir: &str, vars: &BTreeMap<String, String>) -> KResult<()> {
    if srcs.is_empty() {
        return Err(Errno::EINVAL);
    }
    let dest = expand(dest, vars);
    let dest_abs = join_path(workdir, &dest);
    // A trailing slash, multiple sources, or an existing dir → dest is a directory.
    let dest_is_dir = dest.ends_with('/') || srcs.len() > 1 || matches!(ops::stat(bctx, &dest_abs, false), Ok(m) if m.kind == FileType::Directory);
    if dest_is_dir {
        ops::mkdir_all(bctx, &dest_abs, 0o755)?;
    } else if let Some(parent) = dest_abs.rsplit_once('/').map(|(p, _)| p) {
        if !parent.is_empty() {
            ops::mkdir_all(bctx, parent, 0o755)?;
        }
    }
    for src in srcs {
        let src = expand(src, vars);
        let sp = format!("{cdir}/{}", src.trim_start_matches('/'));
        let m = ops::stat(host, &sp, false)?;
        let target = if dest_is_dir {
            let base = src.trim_end_matches('/').rsplit('/').next().unwrap_or(&src);
            format!("{}/{base}", dest_abs.trim_end_matches('/'))
        } else {
            dest_abs.clone()
        };
        match m.kind {
            FileType::Directory => copy_tree(host, &sp, bctx, &target, 1, &mut 0)?,
            FileType::Symlink => {
                let t = ops::readlink(host, &sp)?;
                let _ = ops::symlink(bctx, &t, &target);
            }
            _ => {
                let data = ops::read_file(host, &sp)?;
                ops::write_file(bctx, &target, &data, m.perm & 0o7777)?;
                let _ = ops::chmod(bctx, &target, m.perm & 0o7777, false);
            }
        }
    }
    Ok(())
}

/// Recursively copy a tree from `src`/`spath` to `dst`/`dpath`. At depth 0 the
/// pseudo/mount directories (proc, dev, sys, tmp) are created but not recursed
/// into, so a build never bakes in the container-private mounts.
pub(super) fn copy_tree(src: &Ctx, spath: &str, dst: &Ctx, dpath: &str, depth: usize, bytes: &mut u64) -> KResult<()> {
    let _ = ops::mkdir(dst, dpath, 0o755);
    for e in ops::list_dir(src, spath)? {
        let sp = format!("{}/{}", spath.trim_end_matches('/'), e.name);
        let dp = format!("{}/{}", dpath.trim_end_matches('/'), e.name);
        let m = match ops::stat(src, &sp, false) {
            Ok(m) => m,
            Err(_) => continue,
        };
        match m.kind {
            FileType::Directory => {
                let _ = ops::mkdir(dst, &dp, m.perm & 0o7777);
                if depth == 0 && matches!(e.name.as_str(), "proc" | "dev" | "sys" | "tmp") {
                    continue;
                }
                copy_tree(src, &sp, dst, &dp, depth + 1, bytes)?;
                let _ = ops::chmod(dst, &dp, m.perm & 0o7777, false);
            }
            FileType::Regular => {
                let data = ops::read_file(src, &sp)?;
                *bytes += data.len() as u64;
                ops::write_file(dst, &dp, &data, m.perm & 0o7777)?;
                let _ = ops::chmod(dst, &dp, m.perm & 0o7777, false);
            }
            FileType::Symlink => {
                if let Ok(t) = ops::readlink(src, &sp) {
                    let _ = ops::symlink(dst, &t, &dp);
                }
            }
            other => {
                let _ = ops::mknod(dst, &dp, other, m.perm & 0o7777, m.rdev);
            }
        }
        crate::sched::cond_resched();
    }
    Ok(())
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn env_pairs(env: &[String]) -> Vec<(String, String)> {
    env.iter()
        .map(|e| match e.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (e.clone(), String::new()),
        })
        .collect()
}

fn set_env(env: &mut Vec<String>, key: &str, val: &str) {
    let prefix = format!("{key}=");
    env.retain(|e| !e.starts_with(&prefix));
    env.push(format!("{key}={val}"));
}

/// Join a base directory with a (possibly relative) path, normalising `.`/`..`.
fn join_path(base: &str, p: &str) -> String {
    let mut comps: Vec<&str> = Vec::new();
    let start = if p.starts_with('/') { p } else {
        // Seed with the base path's components.
        for c in base.split('/').filter(|c| !c.is_empty() && *c != ".") {
            comps.push(c);
        }
        p
    };
    for c in start.split('/').filter(|c| !c.is_empty()) {
        match c {
            "." => {}
            ".." => {
                comps.pop();
            }
            other => comps.push(other),
        }
    }
    let mut s = String::from("/");
    s.push_str(&comps.join("/"));
    s
}

/// Expand `$VAR` and `${VAR}` from `vars`; `$$` yields a literal `$`.
fn expand(s: &str, vars: &BTreeMap<String, String>) -> String {
    let b = s.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'$' && i + 1 < b.len() {
            if b[i + 1] == b'$' {
                out.push('$');
                i += 2;
                continue;
            }
            let (name, next) = if b[i + 1] == b'{' {
                let end = s[i + 2..].find('}').map(|e| i + 2 + e);
                match end {
                    Some(e) => (&s[i + 2..e], e + 1),
                    None => {
                        out.push('$');
                        i += 1;
                        continue;
                    }
                }
            } else {
                let mut j = i + 1;
                while j < b.len() && (b[j].is_ascii_alphanumeric() || b[j] == b'_') {
                    j += 1;
                }
                (&s[i + 1..j], j)
            };
            if name.is_empty() {
                out.push('$');
                i += 1;
                continue;
            }
            if let Some(v) = vars.get(name) {
                out.push_str(v);
            }
            i = next;
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

/// Build the argv for a RUN step: a shell-form line runs via `/bin/sh -c`;
/// an exec-form array's elements are expanded and run directly.
fn build_run_argv(argv: &[String], shell: bool, vars: &BTreeMap<String, String>) -> Vec<String> {
    if shell {
        // Shell form: the whole line is left for /bin/sh to expand.
        alloc::vec![String::from("/bin/sh"), String::from("-c"), argv.join(" ")]
    } else {
        argv.iter().map(|s| expand(s, vars)).collect()
    }
}

// ── Dockerfile parsing ───────────────────────────────────────────────────────

/// Parse a Dockerfile into a list of instructions. Handles `#` comments, blank
/// lines, and line continuations (`\` at end of line).
fn parse(text: &str) -> Vec<Insn> {
    let mut logical: Vec<String> = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        // Comments and blank lines only matter when not mid-continuation.
        if cur.is_empty() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        if let Some(stripped) = line.trim_end().strip_suffix('\\') {
            cur.push_str(stripped);
            cur.push(' ');
        } else {
            cur.push_str(line);
            logical.push(core::mem::take(&mut cur));
        }
    }
    if !cur.trim().is_empty() {
        logical.push(cur);
    }

    let mut insns = Vec::new();
    for l in logical {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        let (kw, rest) = match l.split_once(char::is_whitespace) {
            Some((k, r)) => (k, r.trim()),
            None => (l, ""),
        };
        let up = kw.to_ascii_uppercase();
        let insn = match up.as_str() {
            "FROM" => Insn::From(rest.to_string()),
            "RUN" => match parse_json_array(rest) {
                Some(v) => Insn::Run(v, false),
                None => Insn::Run(alloc::vec![rest.to_string()], true),
            },
            "CMD" => match parse_json_array(rest) {
                Some(v) => Insn::Cmd(v),
                None => Insn::Cmd(alloc::vec![String::from("/bin/sh"), String::from("-c"), rest.to_string()]),
            },
            "ENTRYPOINT" => match parse_json_array(rest) {
                Some(v) => Insn::Entrypoint(v),
                None => Insn::Entrypoint(alloc::vec![String::from("/bin/sh"), String::from("-c"), rest.to_string()]),
            },
            "COPY" | "ADD" => parse_copy(rest),
            "ENV" => Insn::Env(parse_env(rest)),
            "ARG" => {
                let (k, v) = match rest.split_once('=') {
                    Some((k, v)) => (k.trim().to_string(), Some(unquote(v.trim()).to_string())),
                    None => (rest.trim().to_string(), None),
                };
                Insn::Arg(k, v)
            }
            "WORKDIR" => Insn::Workdir(rest.to_string()),
            "USER" => Insn::User(rest.to_string()),
            "HEALTHCHECK" => parse_healthcheck(rest),
            _ => Insn::Noop, // EXPOSE, LABEL, MAINTAINER, VOLUME, STOPSIGNAL, …
        };
        insns.push(insn);
    }
    insns
}

/// Parse `HEALTHCHECK [--interval=..] [--timeout=..] [--retries=N] CMD <cmd>`
/// or `HEALTHCHECK NONE`. Durations accept an s/m/h suffix; the command may be
/// shell form or a JSON exec array (joined into a shell command).
fn parse_healthcheck(rest: &str) -> Insn {
    if rest.split_whitespace().next().map(|s| s.eq_ignore_ascii_case("none")).unwrap_or(false) {
        return Insn::Health { cmd: String::new(), interval: 0, timeout: 0, retries: 0 };
    }
    let dur = |v: &str| -> u32 {
        let (num, mult) = match v.chars().last() {
            Some('s') | Some('S') => (&v[..v.len() - 1], 1u32),
            Some('m') | Some('M') => (&v[..v.len() - 1], 60),
            Some('h') | Some('H') => (&v[..v.len() - 1], 3600),
            _ => (v, 1),
        };
        num.parse::<u32>().unwrap_or(0) * mult
    };
    let mut interval = 0u32;
    let mut timeout = 0u32;
    let mut retries = 0u32;
    for tok in rest.split_whitespace() {
        if tok.eq_ignore_ascii_case("cmd") {
            break;
        }
        if let Some(v) = tok.strip_prefix("--interval=") {
            interval = dur(v);
        } else if let Some(v) = tok.strip_prefix("--timeout=") {
            timeout = dur(v);
        } else if let Some(v) = tok.strip_prefix("--retries=") {
            retries = v.parse().unwrap_or(0);
        }
        // Any other --flag (e.g. --start-period=) is accepted and ignored.
    }
    // The command is everything after the CMD keyword (shell or JSON exec form).
    let cmd = match rest.to_ascii_uppercase().find("CMD ") {
        Some(pos) => {
            let after = rest[pos + 4..].trim();
            parse_json_array(after).map(|v| v.join(" ")).unwrap_or_else(|| after.to_string())
        }
        None => String::new(),
    };
    Insn::Health { cmd, interval, timeout, retries }
}

/// Parse `COPY [--chown=…] [--chmod=…] src... dest` (flags ignored).
fn parse_copy(rest: &str) -> Insn {
    // JSON array form: ["src", "dest"].
    if let Some(mut v) = parse_json_array(rest) {
        if v.len() >= 2 {
            let dest = v.pop().unwrap();
            return Insn::Copy { srcs: v, dest };
        }
        return Insn::Noop;
    }
    let mut toks: Vec<String> = rest.split_whitespace().filter(|t| !t.starts_with("--")).map(|t| t.to_string()).collect();
    if toks.len() < 2 {
        return Insn::Noop;
    }
    let dest = toks.pop().unwrap();
    Insn::Copy { srcs: toks, dest }
}

/// Parse `ENV KEY=VALUE KEY2=VALUE2` and the legacy `ENV KEY the rest…` form.
fn parse_env(rest: &str) -> Vec<(String, String)> {
    // Legacy form: exactly one token before a space and no '=' in the first token.
    if let Some((first, tail)) = rest.split_once(char::is_whitespace) {
        if !first.contains('=') {
            return alloc::vec![(first.to_string(), unquote(tail.trim()).to_string())];
        }
    }
    let mut out = Vec::new();
    for tok in split_respecting_quotes(rest) {
        if let Some((k, v)) = tok.split_once('=') {
            out.push((k.to_string(), unquote(v).to_string()));
        }
    }
    out
}

/// Split on whitespace but keep quoted substrings together.
fn split_respecting_quotes(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None::<char>;
    let mut any = false;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                any = true;
            }
            None if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(core::mem::take(&mut cur));
                    any = false;
                }
            }
            None => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Parse a JSON string array `["a", "b"]`; returns None if not that form.
fn parse_json_array(s: &str) -> Option<Vec<String>> {
    let s = s.trim();
    if !s.starts_with('[') || !s.ends_with(']') {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        // Skip whitespace and commas.
        while matches!(chars.peek(), Some(c) if c.is_whitespace() || *c == ',') {
            chars.next();
        }
        match chars.peek() {
            None => break,
            Some('"') => {
                chars.next();
                let mut item = String::new();
                let mut escaped = false;
                for c in chars.by_ref() {
                    if escaped {
                        item.push(match c {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            other => other,
                        });
                        escaped = false;
                    } else if c == '\\' {
                        escaped = true;
                    } else if c == '"' {
                        break;
                    } else {
                        item.push(c);
                    }
                }
                out.push(item);
            }
            Some(_) => return None, // not a well-formed string array
        }
    }
    Some(out)
}
