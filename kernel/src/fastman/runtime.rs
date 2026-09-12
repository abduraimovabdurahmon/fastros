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
    pub workdir: Option<String>,
    pub ports: Vec<Port>,
    pub volumes: Vec<Volume>,
    pub network: String,
    pub detach: bool,
    /// `--user uid[:gid]`: run the container process as this identity.
    pub user: Option<(u32, u32)>,
}

/// Create a container from an image, building its writable rootfs.
pub fn create(ctx: &Ctx, image_name: &str, opts: RunOpts) -> KResult<Container> {
    super::store::ensure(ctx)?;
    let image_id = image::resolve(ctx, image_name).ok_or(Errno::ENOENT)?;
    let cfg = image::load_config(ctx, &image_id);
    let key = super::image::list(ctx).into_iter().find(|i| i.id == image_id).map(|i| i.key).unwrap_or_else(|| image_name.to_string());

    let id = super::container::new_id();
    let name = opts.name.clone().unwrap_or_else(super::container::random_name);
    if super::container::find(ctx, &name).is_ok() {
        return Err(Errno::EEXIST);
    }
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
    let c = Container {
        id,
        name,
        image_key: key,
        image_id,
        cmd: cfg.argv(&opts.cmd),
        env,
        workdir: opts.workdir.unwrap_or(cfg.workdir),
        state: State::Created,
        pid: 0,
        exit_code: 0,
        created: crate::time::unix_now(),
        ports: opts.ports,
        volumes: opts.volumes,
        network: if opts.network.is_empty() { String::from("bridge") } else { opts.network },
        detach: opts.detach,
        uid: opts.user.map(|u| u.0).unwrap_or(0),
        gid: opts.user.map(|u| u.1).unwrap_or(0),
    };
    c.save(ctx)?;
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
pub fn start(ctx: &Ctx, c: &mut Container, tee: Option<Arc<dyn File>>) -> KResult<(u32, alloc::sync::Arc<crate::sched::Task>)> {
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

    // stdio: /dev/null in, a pipe out to the logger.
    let (r, w) = pipe::pipe();
    let r: Arc<dyn File> = r;
    let w: Arc<dyn File> = w;
    let null = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY)?;
    let mut fds = crate::proc::fdtable::FdTable::new();
    fds.set(0, null, false);
    fds.set(1, w.clone(), false);
    fds.set(2, w, false);

    let spawn = Spawn {
        name: c.name.clone(),
        args: argv,
        env: env_pairs(&c.env),
        cred: ccred,
        fs,
        fds,
        parent: crate::proc::kernel(),
        pgid: None,
        new_session: true,
        ctty: None,
        uts: crate::proc::kernel().uts.clone(),
        container: Some(c.id.clone()),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
    };
    let child = proc::start_user(spawn, space, frame)?;
    let pid = child.pid;
    let logger = spawn_logger(c.id.clone(), ctx.cred.uid, ctx.cred.gid, r, tee);

    c.pid = pid;
    c.state = State::Running;
    c.save(ctx)?;

    // Reap the container when its init exits: record the exit code and state.
    let id = c.id.clone();
    let uid = ctx.cred.uid;
    let gid = ctx.cred.gid;
    let task = child.tasks().into_iter().next();
    crate::sched::spawn("fm-wait", move || {
        let code = task.map(|t| t.join()).unwrap_or(0);
        let kctx = Ctx { fs: crate::proc::kernel().fs.lock().clone(), cred: crate::fs::perm::Cred::user(uid, gid, Vec::new()) };
        if let Ok(mut c) = super::container::load(&kctx, &id) {
            c.state = State::Exited;
            c.exit_code = code;
            c.pid = 0;
            let _ = c.save(&kctx);
        }
    });
    Ok((pid, logger))
}

/// `fastman run`: create + start. Foreground waits and returns the exit code;
/// detached returns 0 immediately (the caller prints the id).
pub fn run(ctx: &Ctx, image_name: &str, opts: RunOpts, tee: Option<Arc<dyn File>>) -> KResult<(Container, i32)> {
    let detach = opts.detach;
    let mut c = create(ctx, image_name, opts)?;
    let (pid, logger) = start(ctx, &mut c, if detach { None } else { tee })?;
    if detach {
        return Ok((c, 0));
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
    logger.join();
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
    Ok(c)
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
    ops::remove_tree(ctx, &c.dir(ctx))
}

/// `fastman exec`: run another program inside a running container.
pub fn exec(ctx: &Ctx, name: &str, argv: Vec<String>, tee: Option<Arc<dyn File>>) -> KResult<i32> {
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

    let (r, w) = pipe::pipe();
    let r: Arc<dyn File> = r;
    let w: Arc<dyn File> = w;
    let null = crate::device::open_char(crate::fs::makedev(1, 3), flags::O_RDONLY)?;
    let mut fds = crate::proc::fdtable::FdTable::new();
    fds.set(0, null, false);
    fds.set(1, w.clone(), false);
    fds.set(2, w, false);
    let spawn = Spawn {
        name: format!("exec:{}", c.name),
        args: argv,
        env: env_pairs(&c.env),
        cred: ccred,
        fs,
        fds,
        parent: crate::proc::kernel(),
        pgid: None,
        new_session: true,
        ctty: None,
        uts: crate::proc::kernel().uts.clone(),
        container: Some(c.id.clone()),
        aspace: None,
        ignored: 0,
        sigactions: crate::proc::signal::default_table(),
        vfork: false,
    };
    let child = proc::start_user(spawn, space, frame)?;
    let pid = child.pid;
    // Tee exec output straight to the caller (also captured in the log).
    let logger = spawn_logger(c.id.clone(), ctx.cred.uid, ctx.cred.gid, r, tee);
    let code = child.tasks().into_iter().next().map(|t| t.join()).unwrap_or(0);
    logger.join();
    let _ = pid;
    Ok(code)
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
