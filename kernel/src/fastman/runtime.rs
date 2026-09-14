//! Container lifecycle: create, start, stop, remove, exec and logs.
//!
//! A container runs as an ordinary user process in its own mount namespace,
//! rooted (chrooted) at its writable rootfs. It sees only its own `/proc`,
//! `/dev`, `/tmp` and any explicitly-bound volumes — never a host path. It
//! runs with the caller's credentials (rootless); no privilege is required.

use super::container::{Container, Port, State, Volume};
use super::image;
use crate::errno::{Errno, KResult};
use crate::fs::file::{flags, File};
use crate::fs::mount::{MountFlags, MountNamespace};
use crate::fs::ops::{self, Ctx};
use crate::fs::pipe;
use crate::proc::{self, FsContext, Process, Spawn};
use crate::tty::Tty;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Split `KEY=VALUE` strings into the `(key, value)` pairs Spawn stores.
fn env_pairs(env: &[String]) -> Vec<(String, String)> {
    env.iter()
        .map(|e| match e.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (e.clone(), String::new()),
        })
        .collect()
}

/// Options for creating a container.
#[derive(Default)]
pub struct RunOpts {
    pub name: Option<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    /// `--env-file` paths, read and merged into `env` before create (the shell
    /// `run`/`create` command expands these, as it has the caller's filesystem).
    pub env_files: Vec<String>,
    /// `--entrypoint`: override the image's ENTRYPOINT (the args become CMD).
    pub entrypoint: Option<String>,
    /// `--restart` policy: "", "always", "unless-stopped", or "on-failure".
    pub restart_policy: String,
    /// `--hostname`/-h: the container's UTS hostname (None = inherit host).
    pub hostname: Option<String>,
    /// `--label`/-l metadata (key, value).
    pub labels: Vec<(String, String)>,
    pub workdir: Option<String>,
    pub ports: Vec<Port>,
    pub volumes: Vec<Volume>,
    pub network: String,
    pub detach: bool,
    /// `--user uid[:gid]`: run the container process as this identity.
    pub user: Option<(u32, u32)>,
    /// Kubernetes pod port remap (declared, actual) — see [`Container::port_remap`].
    pub port_remap: Option<(u16, u16)>,
    /// Memory limit in bytes (`-m`), 0 = unlimited.
    pub mem_limit: u64,
    /// Max tasks (`--pids-limit`), 0 = unlimited.
    pub pids_limit: u32,
    /// Capabilities to add / drop (`--cap-add` / `--cap-drop`) as `CAP_*` masks.
    pub cap_add: u64,
    pub cap_drop: u64,
    /// `--rm`: remove the container automatically after it exits (foreground).
    pub rm: bool,
    /// Health check (`--health-cmd` etc. or a Dockerfile HEALTHCHECK). Empty
    /// command = none. Intervals/timeout in seconds; 0 = use defaults.
    pub health_cmd: String,
    pub health_interval: u32,
    pub health_timeout: u32,
    pub health_retries: u32,
}

/// Create a container from an image, building its writable rootfs.
pub fn create(ctx: &Ctx, image_name: &str, opts: RunOpts) -> KResult<Container> {
    super::store::ensure(ctx)?;

    // `--user` may only DROP privilege, never raise it: a non-root caller cannot
    // run a container as any identity other than its own (in particular not
    // uid 0). Without this, `--user 0:1` would give a real root process — a full
    // privilege escalation, since FastROS has no uid remapping. Root may pick
    // any identity (like dockerd). Checked before anything else so it fails fast.
    if let Some((u, g)) = opts.user {
        if !ctx.cred.is_root() && (u != ctx.cred.uid || g != ctx.cred.gid) {
            return Err(Errno::EPERM);
        }
    }

    let image_id = image::resolve(ctx, image_name).ok_or(Errno::ENOENT)?;
    let cfg = image::load_config(ctx, &image_id);
    let key = super::image::list(ctx).into_iter().find(|i| i.id == image_id).map(|i| i.key).unwrap_or_else(|| image_name.to_string());

    let id = super::container::new_id();
    // An explicit `--name` that already exists is an error (Docker: "name already
    // in use"). An auto-generated name is retried until it is free, so a run
    // never fails just because random_name() happened to collide with a leftover
    // container — the bug that made `fastman run <img>` intermittently EEXIST.
    let name = match opts.name.clone() {
        Some(n) => {
            if super::container::find(ctx, &n).is_ok() {
                return Err(Errno::EEXIST);
            }
            n
        }
        None => {
            let mut chosen = None;
            for _ in 0..100 {
                let n = super::container::random_name();
                if super::container::find(ctx, &n).is_err() {
                    chosen = Some(n);
                    break;
                }
            }
            chosen.ok_or(Errno::EEXIST)?
        }
    };
    let dir = format!("{}/{id}", super::store::containers_dir(ctx));
    ops::mkdir(ctx, &dir, 0o700)?;
    // No up-front copy: the writable rootfs is an overlay built at start time
    // (read-only image lower + a per-container writable upper), so a container
    // starts instantly regardless of image size and the image is never mutated.

    let mut env = cfg.env.clone();
    // Overrides win over image defaults for the same key.
    for e in &opts.env {
        let k = e.split('=').next().unwrap_or("");
        env.retain(|x| x.split('=').next() != Some(k));
        env.push(e.clone());
    }
    // Named volumes: a `-v <name>:/path` whose source has no slash refers to a
    // managed volume (Docker's model), not a host path. Expand it to the store
    // path and create it on demand.
    let mut volumes = opts.volumes;
    for v in &mut volumes {
        if !v.host.contains('/') {
            let dir = format!("{}/{}", super::store::volumes_dir(ctx), v.host);
            let _ = ops::mkdir_all(ctx, &dir, 0o755);
            v.host = dir;
        }
    }

    // Effective health check: `--health-cmd` wins, else the image's HEALTHCHECK.
    let hc: (String, u32, u32, u32) = if !opts.health_cmd.is_empty() {
        (opts.health_cmd.clone(), opts.health_interval, opts.health_timeout, opts.health_retries)
    } else {
        (cfg.health_cmd.clone(), cfg.health_interval, cfg.health_timeout, cfg.health_retries)
    };
    let c = Container {
        id,
        name,
        image_key: key,
        image_id,
        // `--entrypoint` overrides the image's ENTRYPOINT; the positional args
        // then form the command. Otherwise use the image's entrypoint + cmd.
        cmd: match &opts.entrypoint {
            Some(ep) => {
                let mut v = alloc::vec![ep.clone()];
                v.extend_from_slice(&opts.cmd);
                v
            }
            None => cfg.argv(&opts.cmd),
        },
        env,
        workdir: opts.workdir.unwrap_or(cfg.workdir),
        state: State::Created,
        pid: 0,
        exit_code: 0,
        created: crate::time::unix_now(),
        ports: opts.ports,
        volumes,
        network: if opts.network.is_empty() { String::from("bridge") } else { opts.network },
        detach: opts.detach,
        uid: opts.user.map(|u| u.0).unwrap_or(0),
        gid: opts.user.map(|u| u.1).unwrap_or(0),
        port_remap: opts.port_remap,
        mem_limit: opts.mem_limit,
        pids_limit: opts.pids_limit,
        cap_add: opts.cap_add,
        cap_drop: opts.cap_drop,
        // Health check: `--health-cmd` overrides; otherwise inherit the image's
        // Dockerfile HEALTHCHECK. Timings fall back to Docker-like defaults.
        health_cmd: hc.0.clone(),
        health_interval: if hc.1 != 0 { hc.1 } else { 30 },
        health_timeout: if hc.2 != 0 { hc.2 } else { 30 },
        health_retries: if hc.3 != 0 { hc.3 } else { 3 },
        health_status: if hc.0.is_empty() { String::new() } else { String::from("starting") },
        health_fails: 0,
        restart_policy: opts.restart_policy,
        stopped_by_user: false,
        hostname: opts.hostname.unwrap_or_default(),
        labels: opts.labels,
    };
    c.save(ctx)?;
    if let Some((d, a)) = c.port_remap {
        crate::net::set_pod_port(&c.id, d, a);
    }
    if c.mem_limit != 0 || c.pids_limit != 0 {
        crate::cgroup::create(&c.id, c.mem_limit, c.pids_limit);
    }
    super::events::record("create", &c.name);
    Ok(c)
}

/// Build the container's isolated mount namespace and filesystem context.
///
/// The root is an overlay of the read-only image rootfs (lower) and a fresh
/// writable tmpfs (upper), so nothing is copied and writes never touch the
/// image. `/proc`, `/dev`, `/tmp` are container-private mounts; volumes bind
/// explicit host paths in.
fn build_fs(ctx: &Ctx, c: &Container) -> KResult<FsContext> {
    let lower = ctx.resolve(&image::rootfs_path(ctx, &c.image_id), true)?;
    let upper = crate::fs::tmpfs::TmpFs::new(0);
    let overlay = crate::fs::overlayfs::OverlayFs::new(lower.inode.clone(), upper);
    let ns = MountNamespace::new(overlay, "overlay", MountFlags::RW);
    let root = ns.root();
    // A Ctx pointed at the overlay so ops:: helpers act inside the container.
    let oc = Ctx { fs: FsContext { ns: ns.clone(), root: root.clone(), cwd: root.clone(), umask: 0o022 }, cred: ctx.cred.clone() };
    let at = |path: &str| -> KResult<crate::fs::path::PathRef> {
        let r = crate::fs::path::Resolver { ns: &ns, root: &root, cwd: &root, cred: &ctx.cred };
        r.resolve(path, true)
    };
    // Ensure the standard mount points exist in the overlay (created in the
    // upper layer if the image did not ship them).
    for d in ["proc", "dev", "tmp", "sys"] {
        let _ = ops::mkdir(&oc, &format!("/{d}"), 0o755);
    }
    // Container-private /proc, /dev, /tmp.
    let nodev = MountFlags { nosuid: true, nodev: true, ..MountFlags::RW };
    if let Ok(p) = at("/proc") {
        let _ = ns.mount(&p, crate::fs::procfs::ProcFs::new(), "proc", MountFlags { noexec: true, ..nodev });
    }
    if let Ok(p) = at("/dev") {
        let _ = ns.mount(&p, crate::fs::devfs::create(), "devtmpfs", MountFlags { nosuid: true, ..MountFlags::RW });
    }
    if let Ok(p) = at("/tmp") {
        let _ = ns.mount(&p, crate::fs::tmpfs::TmpFs::new(0), "tmpfs", nodev);
    }
    // Volumes: bind host directories into the container (explicit opt-in).
    for v in &c.volumes {
        let src = match ctx.resolve(&v.host, true) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = ops::mkdir(&oc, &v.container, 0o755);
        if let Ok(dst) = at(&v.container) {
            let fl = if v.read_only { MountFlags::RO } else { MountFlags::RW };
            let _ = ns.bind(&dst, &src, fl);
        }
    }
    let cwd = at(&c.workdir).unwrap_or_else(|_| root.clone());
    Ok(FsContext { ns, root, cwd, umask: 0o022 })
}

/// The network namespace a container runs in:
/// - `none`/`private`   → a private, isolated loopback stack (no peers).
/// - a user network name → a private stack on that software bridge; containers
///   on the same network reach each other by IP.
/// - `bridge`/`host`/empty (default) → `None`, the shared host stack, preserving
///   published-port and host-network behaviour.
fn container_netns(c: &Container) -> Option<alloc::sync::Arc<crate::net::netns::NetNs>> {
    match c.network.as_str() {
        "none" | "private" => Some(crate::net::netns::create(&c.id)),
        "" | "bridge" | "host" => None,
        other => Some(crate::net::netns::create_bridged(&c.id, other)),
    }
}

/// The credentials the container process runs under: its `--user` identity, or
/// the caller's when unset.
fn container_cred(ctx: &Ctx, c: &Container) -> crate::fs::perm::Cred {
    if c.uid != 0 || c.gid != 0 {
        crate::fs::perm::Cred::user(c.uid, c.gid, Vec::new())
    } else {
        ctx.cred.clone()
    }
}

/// A logger task copies the container's stdout/stderr to its log file and,
/// for a foreground run, to the caller's terminal.
fn spawn_logger(id: String, uid: u32, gid: u32, reader: Arc<dyn File>, tee: Option<Arc<dyn File>>) -> alloc::sync::Arc<crate::sched::Task> {
    crate::sched::spawn("fm-logger", move || {
        let kctx = Ctx { fs: crate::proc::kernel().fs.lock().clone(), cred: crate::fs::perm::Cred::user(uid, gid, Vec::new()) };
        let path = format!("{}/{id}/log", super::store::containers_dir(&kctx));
        let logf = ops::open(&kctx, &path, flags::O_WRONLY | flags::O_CREAT | flags::O_APPEND, 0o600).ok();
        let mut buf = alloc::vec![0u8; 8192];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Some(f) = &logf {
                        let _ = f.write_all(&buf[..n]);
                    }
                    if let Some(t) = &tee {
                        let _ = t.write_all(&buf[..n]);
                    }
                }
                Err(Errno::EINTR) => {
                    crate::proc::absorb_signals();
                }
                Err(_) => break,
            }
        }
    })
}

/// Start a created container. Returns its init pid. For a foreground run,
/// `tee` receives a copy of the output; the caller then waits on the pid.
pub fn start(ctx: &Ctx, c: &mut Container, tee: Option<Arc<dyn File>>, itty: Option<&ExecTty>) -> KResult<(u32, Option<alloc::sync::Arc<crate::sched::Task>>)> {
    // Re-register the pod port remap (survives reboot: the controller restarts
    // pods from their persisted config, and bind() must translate again).
    if let Some((d, a)) = c.port_remap {
        crate::net::set_pod_port(&c.id, d, a);
    }
    if c.mem_limit != 0 || c.pids_limit != 0 {
        crate::cgroup::create(&c.id, c.mem_limit, c.pids_limit);
    }
    let fs = build_fs(ctx, c)?;
    // The container process runs as its configured user (`--user`), defaulting
    // to the caller's identity.
    let ccred = container_cred(ctx, c);
    // Resolve the program inside the container.
    let cctx = Ctx { fs: fs.clone(), cred: ccred.clone() };
    let argv = c.cmd.clone();
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }
    let real = proc::elf::find_program(&cctx, &argv[0])?;
    let (data, argv) = proc::elf::read_exec(&cctx, &real, &argv)?;
    let (space, frame) = proc::elf::load(&cctx, &data, &argv, &c.env)?;

    // stdio. Interactive (`run -it`): the container's init owns the caller's
    // terminal directly (keyboard in, screen out, no log capture) so `sh`/`bash`
    // are usable. Otherwise stdin is /dev/null and output is teed to the logger.
    let mut fds = crate::proc::fdtable::FdTable::new();
    let logger_read: Option<Arc<dyn File>> = if let Some(t) = itty {
        fds.set(0, t.stdin.clone(), false);
        fds.set(1, t.stdout.clone(), false);
        fds.set(2, t.stderr.clone(), false);
        None
    } else {
        let (r, w) = pipe::pipe();
        let w: Arc<dyn File> = w;
        let null = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY)?;
        fds.set(0, null, false);
        fds.set(1, w.clone(), false);
        fds.set(2, w, false);
        Some(r as Arc<dyn File>)
    };
    let interactive = itty.is_some();

    let spawn = Spawn {
        name: c.name.clone(),
        args: argv,
        env: env_pairs(&c.env),
        cred: ccred,
        fs,
        fds,
        parent: crate::proc::kernel(),
        pgid: None,
        // Interactive: its own foreground group under the caller's session, so
        // ^C reaches the container command via the terminal line discipline.
        new_session: !interactive,
        ctty: itty.and_then(|t| t.tty.clone()),
        uts: if c.hostname.is_empty() { crate::proc::kernel().uts.clone() } else { crate::proc::Uts::new(&c.hostname) },
        container: Some(c.id.clone()),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
        // A container's init starts a fresh PID namespace (it becomes vpid 1).
        pidns: Some(crate::proc::PidNs::new()),
        caps: c.effective_caps(),
        no_new_privs: false,
        seccomp: None,
        // A private network namespace ("none"/"private") gives the container its
        // own isolated loopback stack; the default "bridge" shares the host stack.
        netns: container_netns(c),
        init_fs_base: 0,
    };
    let child = proc::start_user(spawn, space, frame)?;
    child.set_exe(&real); // /proc/self/exe for the container's init
    let pid = child.pid;
    // Interactive: no logger (output goes straight to the terminal).
    let logger = logger_read.map(|r| spawn_logger(c.id.clone(), ctx.cred.uid, ctx.cred.gid, r, tee));

    c.pid = pid;
    c.state = State::Running;
    // Starting clears the manual-stop flag so the restart policy is active again.
    c.stopped_by_user = false;
    // A fresh run's health starts as "starting" (until the first probe).
    if !c.health_cmd.is_empty() {
        c.health_status = String::from("starting");
        c.health_fails = 0;
    }
    c.save(ctx)?;

    super::events::record("start", &c.name);

    // Periodic health check (Docker HEALTHCHECK), if configured.
    if !c.health_cmd.is_empty() {
        spawn_health_monitor(c, ctx.cred.uid, ctx.cred.gid);
    }

    // A container in a private network namespace binds its ports inside that
    // namespace, invisible to the host. Publish each `-p` mapping with a host
    // forwarding proxy so the port is reachable from outside (Docker's model).
    if !c.ports.is_empty() {
        if let Some(ns) = container_netns(c) {
            let target = ns.ip.map(crate::net::IpAddress::Ipv4).unwrap_or_else(|| crate::net::IpAddress::v4(127, 0, 0, 1));
            super::proxy::publish(ns, pid, c.ports.clone(), target);
        }
    }

    // Reap the container when its init exits: record the exit code and state.
    // Guarded by the pid of *this* run, so a restart (which gives the container
    // a new init pid) is never clobbered by the previous run's reaper.
    let id = c.id.clone();
    let uid = ctx.cred.uid;
    let gid = ctx.cred.gid;
    let watch_pid = pid;
    let task = child.tasks().into_iter().next();
    crate::sched::spawn("fm-wait", move || {
        let code = task.map(|t| t.join()).unwrap_or(0);
        let kctx = Ctx { fs: crate::proc::kernel().fs.lock().clone(), cred: crate::fs::perm::Cred::user(uid, gid, Vec::new()) };
        if let Ok(mut c) = super::container::load(&kctx, &id) {
            if c.pid == watch_pid {
                c.state = State::Exited;
                c.exit_code = code;
                c.pid = 0;
                let _ = c.save(&kctx);
                super::events::record("die", &c.name);
            }
        }
    });
    Ok((pid, logger))
}

/// `fastman run`: create + start. Foreground waits and returns the exit code;
/// detached returns 0 immediately (the caller prints the id).
pub fn run(ctx: &Ctx, image_name: &str, opts: RunOpts, tee: Option<Arc<dyn File>>, itty: Option<ExecTty>) -> KResult<(Container, i32)> {
    let detach = opts.detach;
    let mut c = create(ctx, image_name, opts)?;
    let (pid, logger) = start(ctx, &mut c, if detach { None } else { tee }, itty.as_ref())?;
    if detach {
        return Ok((c, 0));
    }
    // Interactive (`-it`): hand the terminal to the container's init and wait,
    // then take the terminal back — ^C flows through the line discipline.
    if let Some(t) = &itty {
        let code = if let Some(p) = proc::find(pid) {
            if let Some(tty) = &t.tty {
                tty.set_fg_pgrp(pid);
            }
            let code = p.tasks().into_iter().next().map(|task| task.join()).unwrap_or(0);
            if let Some(tty) = &t.tty {
                tty.set_fg_pgrp(t.pgid);
            }
            code
        } else {
            super::container::load(ctx, &c.id).map(|c| c.exit_code).unwrap_or(0)
        };
        return Ok((c, code));
    }
    // Foreground: wait for the init process.
    let child = proc::find(pid);
    let code = loop {
        match &child {
            Some(p) if p.is_zombie() => break p.exit_status().map(|s| s.shell_code()).unwrap_or(0),
            Some(p) => {
                if !crate::sched::sleep_ms(50) {
                    // Interrupted (^C): forward it to the container, then reap.
                    p.signal(crate::proc::signal::SIGINT);
                    if !crate::proc::absorb_signals() {
                        p.signal(crate::proc::signal::SIGKILL);
                    }
                }
            }
            None => break super::container::load(ctx, &c.id).map(|c| c.exit_code).unwrap_or(0),
        }
    };
    // Drain the logger so all container output reaches the caller before we
    // return (and the exec channel closes).
    if let Some(logger) = logger {
        logger.join();
    }
    Ok((c, code))
}

/// The live init process of a container, verified by its container id (so a
/// recycled pid is never mistaken for the container — it is parented to the
/// kernel and reaped the instant it exits).
fn init_process(c: &Container) -> Option<Arc<Process>> {
    let p = proc::find(c.pid)?;
    if p.is_zombie() {
        return None;
    }
    if p.container.lock().as_deref() == Some(c.id.as_str()) {
        Some(p)
    } else {
        None
    }
}

/// Signal a running container's init process and wait for it to exit,
/// escalating to SIGKILL. Operates on the process handle, never a raw pid.
pub fn stop(ctx: &Ctx, name: &str, sig: u32) -> KResult<Container> {
    let c = super::container::find(ctx, name)?;
    if let Some(p) = init_process(&c) {
        p.signal(sig);
        let mut killed = false;
        for i in 0..60 {
            if p.is_zombie() {
                break;
            }
            if !crate::sched::sleep_ms(50) {
                break;
            }
            if i == 40 && !killed {
                p.signal(crate::proc::signal::SIGKILL);
                killed = true;
            }
        }
    }
    let _ = ctx;
    // A manual stop suppresses the restart policy (Docker does not restart a
    // container stopped via `stop`/`kill`). Re-load so we don't clobber the
    // reaper's Exited state.
    if let Ok(mut c2) = super::container::find(ctx, name) {
        c2.stopped_by_user = true;
        let _ = c2.save(ctx);
    }
    super::events::record("stop", &c.name);
    Ok(c)
}

/// Send `sig` to every live process belonging to container `name` (not just
/// its init). Returns the number signalled. Used by `kill`, `pause`, `unpause`.
pub fn signal_container(ctx: &Ctx, name: &str, sig: u32) -> KResult<usize> {
    let c = super::container::find(ctx, name)?;
    if !c.is_alive() {
        return Err(Errno::ENOTCONN);
    }
    let mut n = 0;
    for p in crate::proc::all() {
        if p.container.lock().as_deref() == Some(c.id.as_str()) && !p.is_zombie() {
            p.signal(sig);
            n += 1;
        }
    }
    super::events::record("kill", &c.name);
    Ok(n)
}

/// Every live host pid belonging to container `name` (for `top`).
pub fn container_pids(ctx: &Ctx, name: &str) -> KResult<Vec<u32>> {
    let c = super::container::find(ctx, name)?;
    Ok(crate::proc::all()
        .into_iter()
        .filter(|p| p.container.lock().as_deref() == Some(c.id.as_str()) && !p.is_zombie())
        .map(|p| p.pid)
        .collect())
}

/// Give a container a new name (Docker's `rename`). The new name must be free.
pub fn rename(ctx: &Ctx, old: &str, new: &str) -> KResult<()> {
    if new.is_empty() || new.contains('/') || new.contains(':') {
        return Err(Errno::EINVAL);
    }
    if super::container::find(ctx, new).is_ok() {
        return Err(Errno::EEXIST);
    }
    let mut c = super::container::find(ctx, old)?;
    c.name = new.to_string();
    c.save(ctx)
}

/// Wait for a container's init process to exit and return its shell exit code.
pub fn wait(ctx: &Ctx, name: &str) -> KResult<i32> {
    let c = super::container::find(ctx, name)?;
    match init_process(&c) {
        Some(p) => {
            while !p.is_zombie() {
                if !crate::sched::sleep_ms(50) {
                    // ^C: stop waiting, report the current recorded code.
                    let _ = crate::proc::absorb_signals();
                    break;
                }
            }
            Ok(super::container::load(ctx, &c.id).map(|c| c.exit_code).unwrap_or(0))
        }
        None => Ok(super::container::load(ctx, &c.id).map(|c| c.exit_code).unwrap_or(c.exit_code)),
    }
}

/// Change a running container's cgroup limits in place (Docker's `update`).
pub fn update_limits(ctx: &Ctx, name: &str, mem: Option<u64>, pids: Option<u32>) -> KResult<()> {
    let mut c = super::container::find(ctx, name)?;
    if let Some(m) = mem {
        c.mem_limit = m;
    }
    if let Some(p) = pids {
        c.pids_limit = p;
    }
    // Apply live if the container is up and already has a cgroup.
    if c.is_alive() && (c.mem_limit != 0 || c.pids_limit != 0) {
        crate::cgroup::set_limits(&c.id, c.mem_limit, c.pids_limit);
    }
    c.save(ctx)
}

/// Remove a container (must not be running unless `force`).
pub fn remove(ctx: &Ctx, name: &str, force: bool) -> KResult<()> {
    let c = super::container::find(ctx, name)?;
    if let Some(p) = init_process(&c) {
        if !force {
            return Err(Errno::EBUSY);
        }
        p.signal(crate::proc::signal::SIGKILL);
        for _ in 0..40 {
            if p.is_zombie() {
                break;
            }
            if !crate::sched::sleep_ms(50) {
                break;
            }
        }
    }
    crate::net::clear_pod_port(&c.id);
    crate::net::netns::remove(&c.id);
    crate::cgroup::remove(&c.id);
    ops::remove_tree(ctx, &c.dir(ctx))?;
    super::events::record("destroy", &c.name);
    Ok(())
}

/// `fastman exec`: run another program inside a running container.
/// The caller's terminal, wired straight into an interactive (`-it`) exec so
/// the container command reads keystrokes and writes to the real screen.
pub struct ExecTty {
    pub stdin: Arc<dyn File>,
    pub stdout: Arc<dyn File>,
    pub stderr: Arc<dyn File>,
    /// The caller's controlling terminal (for window size, line discipline and
    /// routing ^C to the foreground command), if it has one.
    pub tty: Option<Arc<Tty>>,
    /// The caller's process group, restored as the terminal's foreground group
    /// once the interactive command exits.
    pub pgid: u32,
}

pub fn exec(ctx: &Ctx, name: &str, argv: Vec<String>, tee: Option<Arc<dyn File>>, itty: Option<ExecTty>) -> KResult<i32> {
    let c = super::container::find(ctx, name)?;
    if !c.is_alive() {
        return Err(Errno::ENOTCONN);
    }
    if argv.is_empty() {
        return Err(Errno::EINVAL);
    }
    // Reuse the running container's own mount namespace (its overlay), so exec
    // sees exactly the filesystem the init process sees — a rebuilt overlay
    // would have a fresh, empty writable layer.
    let init = proc::find(c.pid).ok_or(Errno::ESRCH)?;
    let fs = init.fs.lock().clone();
    let ccred = container_cred(ctx, &c);
    let cctx = Ctx { fs: fs.clone(), cred: ccred.clone() };
    let real = proc::elf::find_program(&cctx, &argv[0])?;
    let (data, argv) = proc::elf::read_exec(&cctx, &real, &argv)?;
    let (space, frame) = proc::elf::load(&cctx, &data, &argv, &c.env)?;

    let mut fds = crate::proc::fdtable::FdTable::new();
    // Interactive (`-it`): the container command owns the caller's terminal —
    // stdin from the keyboard, stdout/stderr to the screen, no log capture.
    // Otherwise stdin is /dev/null and output is teed to the caller and the log.
    let (logger, interactive) = if let Some(t) = &itty {
        fds.set(0, t.stdin.clone(), false);
        fds.set(1, t.stdout.clone(), false);
        fds.set(2, t.stderr.clone(), false);
        (None, true)
    } else {
        let (r, w) = pipe::pipe();
        let w: Arc<dyn File> = w;
        let null = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY)?;
        fds.set(0, null, false);
        fds.set(1, w.clone(), false);
        fds.set(2, w, false);
        (Some(r as Arc<dyn File>), false)
    };
    let spawn = Spawn {
        name: format!("exec:{}", c.name),
        args: argv,
        env: env_pairs(&c.env),
        cred: ccred,
        fs,
        fds,
        parent: crate::proc::kernel(),
        // Interactive: its own foreground group under the caller's session, so
        // ^C hits the command, not the fastman/shell waiting on it.
        pgid: None,
        new_session: !interactive,
        ctty: itty.as_ref().and_then(|t| t.tty.clone()),
        uts: if c.hostname.is_empty() { crate::proc::kernel().uts.clone() } else { crate::proc::Uts::new(&c.hostname) },
        container: Some(c.id.clone()),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
        // Join the running container's PID namespace.
        pidns: init.pidns.lock().clone(),
        caps: c.effective_caps(),
        no_new_privs: false,
        seccomp: None,
        // Join the running container's network namespace.
        netns: init.netns.lock().clone(),
        init_fs_base: 0,
    };
    let child = proc::start_user(spawn, space, frame)?;
    child.set_exe(&real); // /proc/self/exe for `fastman exec`
    let code = if let Some(t) = &itty {
        // Hand the terminal to the interactive command, then take it back.
        if let Some(tty) = &t.tty {
            tty.set_fg_pgrp(child.pid);
        }
        let code = child.tasks().into_iter().next().map(|task| task.join()).unwrap_or(0);
        if let Some(tty) = &t.tty {
            tty.set_fg_pgrp(t.pgid);
        }
        code
    } else {
        // Tee exec output straight to the caller (also captured in the log).
        let r = logger.unwrap();
        let logger = spawn_logger(c.id.clone(), ctx.cred.uid, ctx.cred.gid, r, tee);
        let code = child.tasks().into_iter().next().map(|task| task.join()).unwrap_or(0);
        logger.join();
        code
    };
    Ok(code)
}

/// Run the container's health command once (`/bin/sh -c <cmd>`), discarding
/// output, and report success (exit 0). Bounded by `timeout_ms`: a probe that
/// overruns is SIGKILLed and counts as a failure. Best-effort — any setup error
/// (no shell, load failure) is a failed probe.
fn health_probe(c: &Container, timeout_ms: u64, cred: &crate::fs::perm::Cred) -> bool {
    let Some(init) = proc::find(c.pid).filter(|p| !p.is_zombie()) else { return false };
    let fs = init.fs.lock().clone();
    let kctx = Ctx { fs: fs.clone(), cred: cred.clone() };
    let argv = alloc::vec![String::from("/bin/sh"), String::from("-c"), c.health_cmd.clone()];
    let Ok(real) = proc::elf::find_program(&kctx, &argv[0]) else { return false };
    let Ok((data, argv)) = proc::elf::read_exec(&kctx, &real, &argv) else { return false };
    let Ok((space, frame)) = proc::elf::load(&kctx, &data, &argv, &c.env) else { return false };
    let mut fds = crate::proc::fdtable::FdTable::new();
    if let Ok(n) = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY) {
        fds.set(0, n, false);
    }
    if let Ok(n) = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_WRONLY) {
        fds.set(1, n.clone(), false);
        fds.set(2, n, false);
    }
    let spawn = Spawn {
        name: format!("health:{}", c.name),
        args: argv,
        env: env_pairs(&c.env),
        cred: cred.clone(),
        fs,
        fds,
        parent: crate::proc::kernel(),
        pgid: None,
        new_session: true,
        ctty: None,
        uts: if c.hostname.is_empty() { crate::proc::kernel().uts.clone() } else { crate::proc::Uts::new(&c.hostname) },
        container: Some(c.id.clone()),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
        pidns: init.pidns.lock().clone(),
        caps: c.effective_caps(),
        no_new_privs: false,
        seccomp: None,
        netns: init.netns.lock().clone(),
        init_fs_base: 0,
    };
    let Ok(child) = proc::start_user(spawn, space, frame) else { return false };
    let task = child.tasks().into_iter().next();
    let deadline = crate::time::now_ns().saturating_add(timeout_ms * 1_000_000);
    loop {
        match &task {
            Some(t) if t.has_exited() => return t.exit_code.load(core::sync::atomic::Ordering::Acquire) == 0,
            Some(t) => {
                if crate::time::now_ns() >= deadline {
                    child.signal(crate::proc::signal::SIGKILL);
                    let _ = t.join();
                    return false;
                }
                crate::sched::sleep_ms(50);
            }
            None => return false,
        }
    }
}

/// Spawn the periodic health checker for a container (Docker HEALTHCHECK). It
/// runs the probe every `health_interval` seconds and records `health_status`
/// ("starting" → "healthy"/"unhealthy" after `health_retries` failures). Exits
/// when the container stops or is restarted (a new run spawns its own monitor).
fn spawn_health_monitor(c: &Container, uid: u32, gid: u32) {
    let id = c.id.clone();
    let watch_pid = c.pid;
    let interval = c.health_interval.max(1) as u64;
    let timeout_ms = (c.health_timeout.max(1) as u64) * 1000;
    let retries = c.health_retries.max(1);
    crate::sched::spawn("fm-health", move || {
        loop {
            for _ in 0..interval {
                if !crate::sched::sleep_ms(1000) {
                    let _ = crate::proc::absorb_signals();
                }
            }
            let kctx = Ctx { fs: crate::proc::kernel().fs.lock().clone(), cred: crate::fs::perm::Cred::user(uid, gid, Vec::new()) };
            let Ok(cur) = super::container::load(&kctx, &id) else { break };
            if cur.pid != watch_pid || !cur.is_alive() {
                break;
            }
            // Run the probe as the container's identity — its `--user` if set,
            // otherwise the launching user — never as root.
            let probe_cred = if cur.uid != 0 || cur.gid != 0 {
                crate::fs::perm::Cred::user(cur.uid, cur.gid, Vec::new())
            } else {
                crate::fs::perm::Cred::user(uid, gid, Vec::new())
            };
            let ok = health_probe(&cur, timeout_ms, &probe_cred);
            // Reload before writing so we patch only the health fields onto the
            // current record (never revert state/pid the reaper may have set).
            let Ok(mut fresh) = super::container::load(&kctx, &id) else { break };
            if fresh.pid != watch_pid {
                break;
            }
            if ok {
                fresh.health_status = String::from("healthy");
                fresh.health_fails = 0;
            } else {
                fresh.health_fails += 1;
                if fresh.health_fails >= retries {
                    fresh.health_status = String::from("unhealthy");
                } else if fresh.health_status != "healthy" {
                    fresh.health_status = String::from("starting");
                }
            }
            let _ = fresh.save(&kctx);
        }
    });
}

/// `fastman commit <container> <image>`: snapshot a running container's current
/// filesystem (its live overlay) into a new image. The container must be running
/// (its writable layer is a tmpfs that exists only while it runs). The new image
/// inherits the source image's config, updated with the container's cmd/env/
/// workdir — exactly what `docker commit` produces.
pub fn commit(ctx: &Ctx, name: &str, reference: &str) -> KResult<super::image::Image> {
    let c = super::container::find(ctx, name)?;
    if !c.is_alive() {
        return Err(Errno::ENOTCONN);
    }
    let init = proc::find(c.pid).ok_or(Errno::ESRCH)?;
    // The container's merged filesystem, seen through its own mount namespace,
    // accessed as the caller — never as root, so `commit` cannot read files the
    // caller could not (e.g. root-owned files on a bind mount).
    let src = Ctx { fs: init.fs.lock().clone(), cred: ctx.cred.clone() };

    let new_id = super::image::new_id();
    let dir = format!("{}/{new_id}", super::store::images_dir(ctx));
    ops::mkdir(ctx, &dir, 0o700)?;
    let rootfs = super::image::rootfs_path(ctx, &new_id);
    ops::mkdir(ctx, &rootfs, 0o755)?;
    let mut bytes = 0u64;
    super::build::copy_tree(&src, "/", ctx, &rootfs, 0, &mut bytes)?;

    // Config from the source image, updated with the container's runtime config.
    let base = super::image::load_config(ctx, &c.image_id);
    let cfg = super::image::ImageConfig {
        env: c.env.clone(),
        entrypoint: base.entrypoint.clone(),
        cmd: c.cmd.clone(),
        workdir: if c.workdir.is_empty() { base.workdir.clone() } else { c.workdir.clone() },
        health_cmd: c.health_cmd.clone(),
        health_interval: c.health_interval,
        health_timeout: c.health_timeout,
        health_retries: c.health_retries,
    };
    super::image::commit(ctx, reference, &new_id, bytes, &cfg)
}

/// Read a container's captured log.
pub fn logs(ctx: &Ctx, name: &str) -> KResult<Vec<u8>> {
    let c = super::container::find(ctx, name)?;
    match ops::read_file(ctx, &c.log_path(ctx)) {
        Ok(d) => Ok(d),
        Err(Errno::ENOENT) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Foreground stdout as a `File` (the caller's fd 1), for `run` without `-d`.
pub fn caller_stdout(proc: &Arc<Process>) -> Option<Arc<dyn File>> {
    proc.fds.lock().get(1).ok()
}

/// The controlling terminal, if any (for future `-it`).
pub fn caller_tty(proc: &Arc<Process>) -> Option<Arc<Tty>> {
    proc.ctty.lock().clone()
}
