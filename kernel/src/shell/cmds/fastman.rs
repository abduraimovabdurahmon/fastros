//! `fastman` — the FastROS container engine CLI: a Docker-compatible surface
//! with Kubernetes-style verbs, rootless and sandboxed by default.

use crate::fastman::container::{Port, State, Volume};
use crate::fastman::runtime::{self, RunOpts};
use crate::fastman::{container, image};
use crate::shell::ctx::Ctx;
use crate::{out, outln};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── colours (only when stdout is a terminal) ────────────────────────────────

struct Style {
    on: bool,
}
impl Style {
    fn bold(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn dim(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[90m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn green(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn red(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[31m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn cyan(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[36m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

/// A left-aligned table with a header row, like `docker ps` / `kubectl get`.
struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}
impl Table {
    fn new(headers: &[&str]) -> Table {
        Table { headers: headers.iter().map(|s| s.to_string()).collect(), rows: Vec::new() }
    }
    fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }
    fn render(&self, ctx: &mut Ctx, style: &Style) {
        let n = self.headers.len();
        let mut w = alloc::vec![0usize; n];
        for (i, h) in self.headers.iter().enumerate() {
            w[i] = visible_len(h);
        }
        for r in &self.rows {
            for (i, c) in r.iter().enumerate().take(n) {
                w[i] = w[i].max(visible_len(c));
            }
        }
        // Header (bold), then rows; three spaces between columns (docker style).
        let mut line = String::new();
        for (i, h) in self.headers.iter().enumerate() {
            let pad = w[i] - visible_len(h);
            line.push_str(&style.bold(h));
            if i + 1 < n {
                line.push_str(&" ".repeat(pad + 3));
            }
        }
        outln!(ctx, "{}", line.trim_end());
        for r in &self.rows {
            let mut line = String::new();
            for (i, c) in r.iter().enumerate().take(n) {
                let pad = w[i].saturating_sub(visible_len(c));
                line.push_str(c);
                if i + 1 < n {
                    line.push_str(&" ".repeat(pad + 3));
                }
            }
            outln!(ctx, "{}", line.trim_end());
        }
    }
}

/// Visible length ignoring ANSI SGR sequences.
fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut esc = false;
    for c in s.chars() {
        if esc {
            if c.is_ascii_alphabetic() {
                esc = false;
            }
        } else if c == '\x1b' {
            esc = true;
        } else {
            n += 1;
        }
    }
    n
}

fn human_size(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{}B", bytes)
    } else {
        let tenths = (v * 10.0) as u64;
        format!("{}.{}{}", tenths / 10, tenths % 10, U[i])
    }
}

/// "About a minute ago", "3 hours ago" — docker-style relative time.
fn ago(then: u64) -> String {
    let now = crate::time::unix_now();
    let d = now.saturating_sub(then);
    if d < 10 {
        String::from("Just now")
    } else if d < 60 {
        format!("{d} seconds ago")
    } else if d < 3600 {
        let m = d / 60;
        format!("{m} minute{} ago", if m == 1 { "" } else { "s" })
    } else if d < 86400 {
        let h = d / 3600;
        format!("{h} hour{} ago", if h == 1 { "" } else { "s" })
    } else {
        let days = d / 86400;
        format!("{days} day{} ago", if days == 1 { "" } else { "s" })
    }
}

fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

fn style_of(ctx: &Ctx) -> Style {
    Style { on: ctx.stdout_tty().is_some() }
}

// ── argument parsing ───────────────────────────────────────────────────────

fn fs_ctx(ctx: &Ctx) -> crate::fs::ops::Ctx {
    ctx.fs()
}

// ── the command ────────────────────────────────────────────────────────────

pub fn fastman(ctx: &mut Ctx) -> i32 {
    let args: Vec<String> = ctx.args[1..].to_vec();
    if args.is_empty() {
        return usage(ctx);
    }
    let fc = fs_ctx(ctx);
    if let Err(e) = crate::fastman::ensure_store(&fc) {
        return ctx.fail(format!("cannot initialise the store: {e}"));
    }
    match args[0].as_str() {
        "version" | "--version" | "-v" => version(ctx),
        "info" => info(ctx),
        "import" => import(ctx, &args[1..]),
        "build" => build(ctx, &args[1..]),
        "images" | "image" | "ls" => images(ctx),
        "tag" => tag(ctx, &args[1..]),
        "history" => history(ctx, &args[1..]),
        "rmi" => rmi(ctx, &args[1..]),
        "run" => run(ctx, &args[1..]),
        "ps" => ps(ctx, &args[1..]),
        "stop" => stop(ctx, &args[1..]),
        "rm" => rm(ctx, &args[1..]),
        "logs" => logs(ctx, &args[1..]),
        "inspect" => inspect(ctx, &args[1..]),
        "stats" => stats(ctx, &args[1..]),
        "restart" => restart(ctx, &args[1..]),
        "cp" => cp(ctx, &args[1..]),
        "kill" => kill(ctx, &args[1..]),
        "pause" => pause_cmd(ctx, &args[1..], crate::proc::signal::SIGSTOP, "pause"),
        "unpause" => pause_cmd(ctx, &args[1..], crate::proc::signal::SIGCONT, "unpause"),
        "rename" => rename(ctx, &args[1..]),
        "top" => top(ctx, &args[1..]),
        "port" => port(ctx, &args[1..]),
        "wait" => wait_cmd(ctx, &args[1..]),
        "update" => update(ctx, &args[1..]),
        "ip" => container_ip(ctx, &args[1..]),
        "exec" => exec(ctx, &args[1..]),
        "pull" => pull(ctx, &args[1..]),
        "system" => system(ctx, &args[1..]),
        "compose" => compose(ctx, &args[1..]),
        "kube" | "kubectl" | "k" => kube(ctx, &args[1..]),
        "apply" => kube(ctx, &{ let mut v = alloc::vec!["apply".to_string()]; v.extend_from_slice(&args[1..]); v }),
        "get" => kube(ctx, &{ let mut v = alloc::vec!["get".to_string()]; v.extend_from_slice(&args[1..]); v }),
        "help" | "-h" | "--help" => usage(ctx),
        other => {
            ctx.eprint(&format!("fastman: unknown command '{other}'\n"));
            usage(ctx);
            1
        }
    }
}

fn usage(ctx: &mut Ctx) -> i32 {
    let s = style_of(ctx);
    outln!(ctx, "{}", s.bold("fastman — the FastROS container engine (rootless, sandboxed)"));
    outln!(ctx);
    outln!(ctx, "{}", s.bold("Usage:"));
    outln!(ctx, "  fastman <command> [options]");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("Images:"));
    outln!(ctx, "  import <name[:tag]>        import a rootfs tarball from stdin");
    outln!(ctx, "  build -t <name[:tag]> -    build an image from a Dockerfile (context on stdin)");
    outln!(ctx, "  pull <ref>                 pull an image from a registry");
    outln!(ctx, "  images                     list images");
    outln!(ctx, "  tag <src> <dst>            add a new name for an image");
    outln!(ctx, "  history <image>            show an image's history");
    outln!(ctx, "  rmi <image>                remove an image (untags if shared)");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("Containers:"));
    outln!(ctx, "  run [opts] <image> [cmd]   create and start a container");
    outln!(ctx, "  ps [-a]                    list containers");
    outln!(ctx, "  logs [-f] <container>      show a container's output (-f: follow live)");
    outln!(ctx, "  inspect <container>...     print a container's config + state as JSON");
    outln!(ctx, "  stats [container...]       live resource usage (CPU, memory, PIDs)");
    outln!(ctx, "  exec [-it] <container> <cmd>  run a command in a container");
    outln!(ctx, "  cp SRC DST                 copy files to/from a container (<container>:<path>)");
    outln!(ctx, "  stop <container>           stop a container");
    outln!(ctx, "  restart <container>...     stop then start a container");
    outln!(ctx, "  kill [-s SIG] <container>  send a signal (default KILL)");
    outln!(ctx, "  pause / unpause <ctr>      freeze / resume a container");
    outln!(ctx, "  rename <old> <new>         rename a container");
    outln!(ctx, "  wait <container>...        wait for exit, print the code");
    outln!(ctx, "  update [-m..] <container>  change resource limits");
    outln!(ctx, "  rm [-f] <container>        remove a container");
    outln!(ctx, "  system df|info|prune       disk usage / info / clean exited");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("Compose (multi-container stacks):"));
    outln!(ctx, "  compose [-f file] up       start all services in a compose file");
    outln!(ctx, "  compose [-f file] ps       list the stack's containers");
    outln!(ctx, "  compose [-f file] logs <svc>  show a service's output");
    outln!(ctx, "  compose [-f file] down     stop and remove the stack");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("run options:"));
    outln!(ctx, "  -d                 detached (background)");
    outln!(ctx, "  -it                interactive: wire your terminal to the container (e.g. sh)");
    outln!(ctx, "  --rm               remove the container automatically when it exits");
    outln!(ctx, "  --name <name>      assign a name");
    outln!(ctx, "  -e KEY=VALUE       set an environment variable");
    outln!(ctx, "  -p HOST:CONT       publish a port");
    outln!(ctx, "  -v HOST:CONT[:ro]  bind-mount a volume");
    outln!(ctx, "  -u uid[:gid]       run as this user (e.g. for postgres)");
    outln!(ctx, "  --cap-add <cap>    grant a capability (e.g. NET_BIND_SERVICE, or ALL)");
    outln!(ctx, "  --cap-drop <cap>   drop a capability (e.g. NET_BIND_SERVICE, or ALL)");
    outln!(ctx, "  -w <dir>           working directory");
    outln!(ctx, "  --network <name>   network: bridge (shared, default) or none (private netns)");
    outln!(ctx, "  --health-cmd <cmd>   periodic health check (shell command)");
    outln!(ctx, "  --health-interval N[s|m]  time between checks (default 30s)");
    outln!(ctx, "  --health-retries N   failures before 'unhealthy' (default 3)");
    outln!(ctx);
    outln!(ctx, "{}", s.dim("Every container is a rootless sandbox: its own mount namespace, chrooted"));
    outln!(ctx, "{}", s.dim("to the image, with no access to host files, processes or network."));
    0
}

fn version(ctx: &mut Ctx) -> i32 {
    let s = style_of(ctx);
    outln!(ctx, "{} {}", s.bold("fastman"), crate::VERSION);
    outln!(ctx, " Engine:     FastROS container runtime");
    outln!(ctx, " Isolation:  mount namespace + chroot, rootless");
    outln!(ctx, " Kernel:     FastROS {} x86_64", crate::VERSION);
    0
}

fn info(ctx: &mut Ctx) -> i32 {
    let s = style_of(ctx);
    let fc = fs_ctx(ctx);
    let imgs = image::list(&fc).len();
    let cs = container::list(&fc);
    let running = cs.iter().filter(|c| c.live_state() == State::Running).count();
    outln!(ctx, "{}", s.bold("fastman — FastROS container engine"));
    outln!(ctx, " Containers:  {}", cs.len());
    outln!(ctx, "  Running:    {}", running);
    outln!(ctx, "  Stopped:    {}", cs.len() - running);
    outln!(ctx, " Images:      {}", imgs);
    outln!(ctx, " Storage:     {}", crate::fastman::store::base(&fc));
    outln!(ctx, " Rootless:    {}", s.green("yes"));
    outln!(ctx, " Security:    mount-namespace isolation, chroot, W^X, memory-safe kernel");
    outln!(ctx, " User:        uid {} ({})", fc.cred.uid, crate::users::user_name(fc.cred.uid));
    0
}

fn import(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(name) = args.first() else {
        return ctx.fail("import requires an image name (rootfs tarball on stdin)");
    };
    let data = match ctx.read_input("-") {
        Ok(d) => d,
        Err(e) => return ctx.fail_errno("stdin", e),
    };
    if data.is_empty() {
        return ctx.fail("no data on stdin (pipe a tar or tar.gz rootfs)");
    }
    let fc = fs_ctx(ctx);
    let cfg = image::ImageConfig::defaults();
    match image::import(&fc, name, &data, cfg) {
        Ok(img) => {
            outln!(ctx, "Imported {} ({})", img.key, short(&img.id));
            0
        }
        Err(e) => ctx.fail_errno("import", e),
    }
}

/// `fastman build -t name:tag [-f Dockerfile] [--build-arg K=V] -` — build an
/// image from a Dockerfile. The build context (a tar/tar.gz containing the
/// Dockerfile) is read from stdin.
fn build(ctx: &mut Ctx, args: &[String]) -> i32 {
    use crate::fastman::build::BuildOpts;
    let mut opts = BuildOpts::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--tag" => {
                i += 1;
                match args.get(i) {
                    Some(v) if opts.tag.is_empty() => opts.tag = v.clone(),
                    Some(_) => {}
                    None => return ctx.fail("-t needs a name[:tag]"),
                }
            }
            "-f" | "--file" => {
                i += 1;
                match args.get(i) {
                    Some(v) => opts.dockerfile = v.clone(),
                    None => return ctx.fail("-f needs a path"),
                }
            }
            "--build-arg" => {
                i += 1;
                match args.get(i).and_then(|s| s.split_once('=')) {
                    Some((k, v)) => opts.build_args.push((k.to_string(), v.to_string())),
                    None => return ctx.fail("--build-arg needs KEY=VALUE"),
                }
            }
            "-" => {}
            s if s.starts_with('-') => return ctx.fail(format!("unknown option '{s}'")),
            _ => {} // a build-context path (unused: context comes on stdin)
        }
        i += 1;
    }
    if opts.tag.is_empty() {
        return ctx.fail("build requires -t name[:tag]");
    }
    let data = match ctx.read_input("-") {
        Ok(d) => d,
        Err(e) => return ctx.fail_errno("stdin", e),
    };
    if data.is_empty() {
        return ctx.fail("no build context on stdin (pipe a tar or tar.gz containing the Dockerfile)");
    }
    let fc = fs_ctx(ctx);
    let tee = runtime::caller_stdout(&ctx.proc);
    ctx.flush();
    match crate::fastman::build::build(&fc, &opts, &data, tee) {
        Ok(built) => {
            outln!(ctx, "Successfully built {}", short(&built.image.id));
            outln!(ctx, "Successfully tagged {}", built.image.key);
            0
        }
        Err(crate::errno::Errno::ENOENT) => ctx.fail("build failed: base image not found (FROM) or a COPY source is missing"),
        Err(crate::errno::Errno::EINVAL) => ctx.fail("build failed: the Dockerfile must start with a FROM instruction"),
        Err(crate::errno::Errno::EIO) => ctx.fail("build failed: a RUN step exited non-zero"),
        Err(e) => ctx.fail_errno("build", e),
    }
}

/// `fastman ip <container>` — print the container's bridge-network IP address
/// (only meaningful for a container on a user-defined `--network`).
fn container_ip(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(name) = args.first() else {
        return ctx.fail("ip requires a container");
    };
    let fc = fs_ctx(ctx);
    let c = match container::find(&fc, name) {
        Ok(c) => c,
        Err(e) => return ctx.fail_errno(name, e),
    };
    match crate::net::netns::container_ip(&c.id) {
        Some(ip) => {
            outln!(ctx, "{}", ip);
            0
        }
        None => ctx.fail(format!("{name} is not on a bridge network")),
    }
}

fn images(ctx: &mut Ctx) -> i32 {
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);
    let mut t = Table::new(&["REPOSITORY", "TAG", "IMAGE ID", "CREATED", "SIZE"]);
    for img in image::list(&fc) {
        let (repo, tag) = img.key.rsplit_once(':').unwrap_or((img.key.as_str(), "latest"));
        t.row(alloc::vec![repo.to_string(), tag.to_string(), short(&img.id).to_string(), ago(img.created), human_size(img.size)]);
    }
    t.render(ctx, &s);
    0
}

/// `fastman tag <src> <dst>` — add a new name for an existing image.
fn tag(ctx: &mut Ctx, args: &[String]) -> i32 {
    let a: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if a.len() != 2 {
        return ctx.fail("tag requires SOURCE and TARGET image names");
    }
    let fc = fs_ctx(ctx);
    match image::tag(&fc, a[0], a[1]) {
        Ok(()) => 0,
        Err(e) => ctx.fail_errno("tag", e),
    }
}

/// `fastman history <image>` — the image's build history. fastman flattens each
/// image to a single rootfs, so this reports one entry (the image itself).
fn history(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(name) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("history requires an image");
    };
    let fc = fs_ctx(ctx);
    let Some(id) = image::resolve(&fc, name) else {
        return ctx.fail(format!("no such image: {name}"));
    };
    let cfg = image::load_config(&fc, &id);
    let img = image::list(&fc).into_iter().find(|i| i.id == id);
    let s = style_of(ctx);
    let created = img.as_ref().map(|i| ago(i.created)).unwrap_or_else(|| "-".into());
    let size = img.as_ref().map(|i| human_size(i.size)).unwrap_or_else(|| "-".into());
    let created_by = {
        let j = cfg.argv(&[]).join(" ");
        if j.len() > 40 { format!("{}…", &j[..39]) } else { j }
    };
    let mut t = Table::new(&["IMAGE", "CREATED", "CREATED BY", "SIZE"]);
    t.row(alloc::vec![short(&id).to_string(), created, created_by, size]);
    t.render(ctx, &s);
    0
}

/// `fastman system df|info` — a summary of images and containers.
fn system(ctx: &mut Ctx, args: &[String]) -> i32 {
    let sub = args.iter().find(|a| !a.starts_with('-')).map(|s| s.as_str()).unwrap_or("df");
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);
    match sub {
        "df" => {
            let images = image::list(&fc);
            let img_size: u64 = images.iter().map(|i| i.size).sum();
            let conts = container::list(&fc);
            let running = conts.iter().filter(|c| c.is_alive()).count();
            let mut t = Table::new(&["TYPE", "TOTAL", "ACTIVE", "SIZE"]);
            t.row(alloc::vec!["Images".into(), format!("{}", images.len()), format!("{running}"), human_size(img_size)]);
            t.row(alloc::vec!["Containers".into(), format!("{}", conts.len()), format!("{running}"), "-".into()]);
            t.render(ctx, &s);
            0
        }
        "info" => info(ctx),
        "prune" => {
            // Remove exited containers (safe, guest-local; images are kept).
            let mut n = 0;
            for c in container::list(&fc) {
                if !c.is_alive() {
                    if runtime::remove(&fc, &c.id, false).is_ok() {
                        n += 1;
                    }
                }
            }
            outln!(ctx, "Deleted Containers: {n}");
            0
        }
        other => ctx.fail(format!("unknown system command '{other}' (df|info|prune)")),
    }
}

fn rmi(ctx: &mut Ctx, args: &[String]) -> i32 {
    if args.is_empty() {
        return ctx.fail("rmi requires an image");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in args {
        match image::remove(&fc, name) {
            Ok(()) => outln!(ctx, "Untagged: {name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

fn parse_run(args: &[String]) -> Result<(RunOpts, bool, String, Vec<String>), String> {
    let mut o = RunOpts { network: String::from("bridge"), ..Default::default() };
    let mut interactive = false;
    let mut i = 0;
    let mut image = None;
    let mut cmd = Vec::new();
    while i < args.len() {
        let a = &args[i];
        if image.is_some() {
            cmd.push(a.clone());
            i += 1;
            continue;
        }
        match a.as_str() {
            "-d" | "--detach" => o.detach = true,
            "--rm" => o.rm = true,
            "-i" | "-t" | "-it" | "-ti" | "--interactive" | "--tty" => interactive = true,
            "--name" => {
                i += 1;
                o.name = Some(args.get(i).ok_or("--name needs a value")?.clone());
            }
            "-e" | "--env" => {
                i += 1;
                o.env.push(args.get(i).ok_or("-e needs KEY=VALUE")?.clone());
            }
            "-w" | "--workdir" => {
                i += 1;
                o.workdir = Some(args.get(i).ok_or("-w needs a directory")?.clone());
            }
            "-u" | "--user" => {
                i += 1;
                o.user = Some(parse_user(args.get(i).ok_or("-u needs a uid[:gid]")?)?);
            }
            "--network" | "--net" => {
                i += 1;
                o.network = args.get(i).ok_or("--network needs a value")?.clone();
            }
            "-p" | "--publish" => {
                i += 1;
                o.ports.push(parse_port(args.get(i).ok_or("-p needs HOST:CONT")?)?);
            }
            "-v" | "--volume" => {
                i += 1;
                o.volumes.push(parse_volume(args.get(i).ok_or("-v needs HOST:CONT")?)?);
            }
            "-m" | "--memory" => {
                i += 1;
                o.mem_limit = parse_size(args.get(i).ok_or("-m needs a size (e.g. 256m)")?)?;
            }
            "--pids-limit" => {
                i += 1;
                o.pids_limit = args.get(i).and_then(|s| s.parse().ok()).ok_or("--pids-limit needs a number")?;
            }
            "--cap-add" => {
                i += 1;
                let v = args.get(i).ok_or("--cap-add needs a capability")?;
                o.cap_add |= parse_caps(v)?;
            }
            "--cap-drop" => {
                i += 1;
                let v = args.get(i).ok_or("--cap-drop needs a capability")?;
                o.cap_drop |= parse_caps(v)?;
            }
            "--health-cmd" => {
                i += 1;
                o.health_cmd = args.get(i).ok_or("--health-cmd needs a command")?.clone();
            }
            "--health-interval" => {
                i += 1;
                o.health_interval = parse_secs(args.get(i).ok_or("--health-interval needs a duration")?)?;
            }
            "--health-timeout" => {
                i += 1;
                o.health_timeout = parse_secs(args.get(i).ok_or("--health-timeout needs a duration")?)?;
            }
            "--health-retries" => {
                i += 1;
                o.health_retries = args.get(i).and_then(|s| s.parse().ok()).ok_or("--health-retries needs a number")?;
            }
            "--no-healthcheck" => o.health_cmd = String::new(),
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s => image = Some(s.to_string()),
        }
        i += 1;
    }
    let image = image.ok_or("run requires an image")?;
    o.cmd = cmd.clone();
    // `-d` and `-it` are mutually exclusive (detached has no terminal).
    if interactive {
        o.detach = false;
    }
    Ok((o, interactive, image, cmd))
}

fn parse_port(s: &str) -> Result<Port, String> {
    let (spec, udp) = match s.strip_suffix("/udp") {
        Some(rest) => (rest, true),
        None => (s.strip_suffix("/tcp").unwrap_or(s), false),
    };
    let (h, c) = spec.split_once(':').ok_or("port must be HOST:CONTAINER")?;
    Ok(Port { host: h.parse().map_err(|_| "bad host port")?, container: c.parse().map_err(|_| "bad container port")?, udp })
}

/// `--user uid[:gid]` (numeric only; gid defaults to uid).
fn parse_user(s: &str) -> Result<(u32, u32), String> {
    let (u, g) = match s.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (s, None),
    };
    let uid: u32 = u.parse().map_err(|_| "user must be a numeric uid[:gid]")?;
    let gid: u32 = match g {
        Some(g) => g.parse().map_err(|_| "bad gid")?,
        None => uid,
    };
    Ok((uid, gid))
}

/// Parse a `--cap-add`/`--cap-drop` value: `ALL`, or a comma-separated list of
/// capability names (`NET_BIND_SERVICE`, `CAP_SYS_ADMIN`, …). Returns a bitmask.
fn parse_caps(s: &str) -> Result<u64, String> {
    let mut mask = 0u64;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part.eq_ignore_ascii_case("all") {
            return Ok(crate::syscall::seccomp::CAP_ALL);
        }
        let bit = crate::syscall::seccomp::cap_by_name(part).ok_or_else(|| format!("unknown capability '{part}'"))?;
        mask |= 1u64 << bit;
    }
    Ok(mask)
}

/// Parse a byte size with an optional k/m/g/t suffix (e.g. `256m`, `1g`).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1024u64),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some('t') | Some('T') => (&s[..s.len() - 1], 1024u64.pow(4)),
        Some('b') | Some('B') => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let n: u64 = num.trim().parse().map_err(|_| format!("bad size '{s}'"))?;
    Ok(n * mult)
}

/// Parse a duration in seconds: a bare number or an `Ns`/`Nm`/`Nh` suffix.
fn parse_secs(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') | Some('S') => (&s[..s.len() - 1], 1u32),
        Some('m') | Some('M') => (&s[..s.len() - 1], 60),
        Some('h') | Some('H') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    num.trim().parse::<u32>().map(|n| n * mult).map_err(|_| format!("bad duration '{s}'"))
}

fn parse_volume(s: &str) -> Result<Volume, String> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [host, cont] => Ok(Volume { host: host.to_string(), container: cont.to_string(), read_only: false }),
        [host, cont, "ro"] => Ok(Volume { host: host.to_string(), container: cont.to_string(), read_only: true }),
        [host, cont, "rw"] => Ok(Volume { host: host.to_string(), container: cont.to_string(), read_only: false }),
        _ => Err("volume must be HOST:CONTAINER[:ro]".to_string()),
    }
}

fn run(ctx: &mut Ctx, args: &[String]) -> i32 {
    let (opts, interactive, image_name, _cmd) = match parse_run(args) {
        Ok(v) => v,
        Err(e) => return ctx.fail(e),
    };
    let detach = opts.detach;
    let rm = opts.rm;
    let fc = fs_ctx(ctx);
    // Like `docker run`: if the image is not present locally, pull it from the
    // registry first, then run. Only a pull failure aborts the run.
    if image::resolve(&fc, &image_name).is_none() {
        if let Err(code) = ensure_image(ctx, &image_name) {
            return code;
        }
    }
    // Interactive (`-it`): wire the caller's terminal to the container's init
    // process so `sh`/`bash` are usable. Requires a real stdio triple.
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
    let tee = if detach || interactive { None } else { runtime::caller_stdout(&ctx.proc) };
    ctx.flush();
    match runtime::run(&fc, &image_name, opts, tee, itty) {
        Ok((c, code)) => {
            if detach {
                outln!(ctx, "{}", c.id);
                0
            } else {
                // `--rm`: discard the finished container (best-effort).
                if rm {
                    let _ = runtime::remove(&fc, &c.id, true);
                }
                code
            }
        }
        Err(crate::errno::Errno::ENOENT) => ctx.fail(format!("exec: command not found in image (cmd resolves to no executable)")),
        Err(e) => ctx.fail_errno("run", e),
    }
}

fn ps(ctx: &mut Ctx, args: &[String]) -> i32 {
    let all = args.iter().any(|a| a == "-a" || a == "--all");
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);
    let mut t = Table::new(&["CONTAINER ID", "IMAGE", "COMMAND", "CREATED", "STATUS", "PORTS", "NAMES"]);
    for c in container::list(&fc) {
        let state = c.live_state();
        if !all && state != State::Running {
            continue;
        }
        let cmd = {
            let j = c.cmd.join(" ");
            let j = if j.len() > 20 { format!("{}…", &j[..19]) } else { j };
            format!("\"{j}\"")
        };
        let status = match state {
            State::Running => {
                // Reflect the health check in the status, like Docker.
                let up = match c.health_status.as_str() {
                    "healthy" => String::from("Up (healthy)"),
                    "unhealthy" => String::from("Up (unhealthy)"),
                    "starting" => String::from("Up (health: starting)"),
                    _ => String::from("Up"),
                };
                s.green(&up)
            }
            State::Exited => s.dim(&format!("Exited ({})", c.exit_code)),
            State::Created => s.dim("Created"),
        };
        let ports = c.ports.iter().map(|p| format!("0.0.0.0:{}->{}/{}", p.host, p.container, if p.udp { "udp" } else { "tcp" })).collect::<Vec<_>>().join(", ");
        t.row(alloc::vec![short(&c.id).to_string(), c.image_key.clone(), cmd, ago(c.created), status, ports, c.name.clone()]);
    }
    t.render(ctx, &s);
    0
}

/// `fastman compose [-f file] [-p project] <up [-d]|down|ps|logs [svc]>`.
fn compose(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut file = None;
    let mut project = None;
    let mut sub = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--file" => {
                i += 1;
                file = args.get(i).cloned();
            }
            "-p" | "--project-name" => {
                i += 1;
                project = args.get(i).cloned();
            }
            s if sub.is_none() && !s.starts_with('-') => sub = Some(s.to_string()),
            s => rest.push(s.to_string()),
        }
        i += 1;
    }
    let sub = sub.unwrap_or_else(|| "up".to_string());
    let fc = fs_ctx(ctx);

    // Locate the compose file (explicit, then the usual defaults).
    let path = file.or_else(|| {
        ["fastman-compose.yaml", "fastman-compose.yml", "docker-compose.yaml", "docker-compose.yml", "compose.yaml"]
            .iter()
            .find(|p| crate::fs::ops::stat(&fc, p, true).is_ok())
            .map(|p| p.to_string())
    });
    let project = project.unwrap_or_else(|| String::from("fastman"));

    // `down`/`ps`/`logs` only need the project prefix; `up` needs the file.
    let prefix = format!("{project}_");
    match sub.as_str() {
        "up" => {
            let Some(path) = path else {
                return ctx.fail("no compose file (looked for fastman-compose.yaml / docker-compose.yml)");
            };
            let src = match crate::fs::ops::read_file(&fc, &path) {
                Ok(d) => String::from_utf8_lossy(&d).into_owned(),
                Err(e) => return ctx.fail_errno(&path, e),
            };
            let stack = match crate::fastman::compose::parse(&project, &src) {
                Ok(s) => s,
                Err(_) => return ctx.fail(format!("{path}: invalid compose file")),
            };
            let s = style_of(ctx);
            for svc in &stack.services {
                // Auto-pull a missing image if the network is up.
                if image::resolve(&fc, &svc.image).is_none() {
                    if crate::net::is_up() {
                        if let Some(r) = image::ImageRef::parse(&svc.image) {
                            outln!(ctx, "{} Pulling {}", s.dim(&svc.name), svc.image);
                            ctx.flush();
                            let res = {
                                let mut prog = CliProgress { ctx };
                                crate::fastman::registry::pull(&r, &mut prog)
                            };
                            if let Ok(p) = res {
                                let _ = image::store_layers(&fc, &r.key(), &p.layers, p.config);
                            }
                        }
                    }
                    if image::resolve(&fc, &svc.image).is_none() {
                        ctx.fail(format!("{}: image '{}' not found", svc.name, svc.image));
                        continue;
                    }
                }
                let cname = svc.opts.name.clone().unwrap_or_else(|| format!("{prefix}{}", svc.name));
                // Idempotent up: remove a previous instance of the same service.
                let _ = runtime::remove(&fc, &cname, true);
                let mut opts = clone_opts(&svc.opts);
                opts.detach = true;
                ctx.flush();
                match runtime::run(&fc, &svc.image, opts, None, None) {
                    Ok((c, _)) => outln!(ctx, "{} {} {}", s.green("Started"), svc.name, short(&c.id)),
                    Err(e) => {
                        ctx.fail_errno(&svc.name, e);
                    }
                }
            }
            0
        }
        "down" | "stop" | "rm" => {
            let fc = fs_ctx(ctx);
            let mut names: Vec<String> = container::list(&fc).into_iter().filter(|c| c.name.starts_with(&prefix)).map(|c| c.name).collect();
            names.sort();
            if names.is_empty() {
                outln!(ctx, "No containers for project {project}");
                return 0;
            }
            for name in &names {
                let _ = runtime::stop(&fc, name, crate::proc::signal::SIGTERM);
                match runtime::remove(&fc, name, true) {
                    Ok(()) => outln!(ctx, "Removed {name}"),
                    Err(e) => {
                        ctx.fail_errno(name, e);
                    }
                }
            }
            0
        }
        "ps" => {
            let fc = fs_ctx(ctx);
            let s = style_of(ctx);
            let mut t = Table::new(&["NAME", "IMAGE", "STATUS", "PORTS"]);
            for c in container::list(&fc).into_iter().filter(|c| c.name.starts_with(&prefix)) {
                let status = match c.live_state() {
                    State::Running => s.green("Up"),
                    State::Exited => s.dim(&format!("Exited ({})", c.exit_code)),
                    State::Created => s.dim("Created"),
                };
                let ports = c.ports.iter().map(|p| format!("0.0.0.0:{}->{}", p.host, p.container)).collect::<Vec<_>>().join(", ");
                t.row(alloc::vec![c.name.clone(), c.image_key.clone(), status, ports]);
            }
            t.render(ctx, &s);
            0
        }
        "logs" => {
            let fc = fs_ctx(ctx);
            let svc = rest.first().cloned().unwrap_or_default();
            let name = format!("{prefix}{svc}");
            match runtime::logs(&fc, &name) {
                Ok(data) => {
                    ctx.write(&data);
                    0
                }
                Err(e) => ctx.fail_errno(&name, e),
            }
        }
        other => ctx.fail(format!("unknown compose command '{other}' (up|down|ps|logs)")),
    }
}

/// `fastman kube <apply -f file | get [pods|deployments|services|all] | delete <name>>`.
fn kube(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut file = None;
    let mut sub = None;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--filename" => {
                i += 1;
                file = args.get(i).cloned();
            }
            s if sub.is_none() && !s.starts_with('-') => sub = Some(s.to_string()),
            s => rest.push(s.to_string()),
        }
        i += 1;
    }
    let fc = fs_ctx(ctx);
    let base = crate::fastman::store::base(&fc);
    let wdir = format!("{base}/kube/workloads");
    let sdir = format!("{base}/kube/services");
    let s = style_of(ctx);
    match sub.as_deref().unwrap_or("get") {
        "apply" => {
            let Some(path) = file else { return ctx.fail("apply requires -f <manifest>") };
            let src = match crate::fs::ops::read_file(&fc, &path) {
                Ok(d) => String::from_utf8_lossy(&d).into_owned(),
                Err(e) => return ctx.fail_errno(&path, e),
            };
            let m = crate::fastman::kube::parse(&src);
            if m.workloads.is_empty() && m.services.is_empty() {
                return ctx.fail(format!("{path}: no Deployment/Pod/Service found"));
            }
            let _ = crate::fs::ops::mkdir_all(&fc, &wdir, 0o700);
            let _ = crate::fs::ops::mkdir_all(&fc, &sdir, 0o700);
            for w in &m.workloads {
                if image::resolve(&fc, &w.image).is_none() {
                    ctx.fail(format!("{}: image '{}' not found", w.name, w.image));
                    continue;
                }
                let declared = w.opts.ports.first().map(|p| p.container);
                let rec = format!("{}\n{}\n{}\n", w.kind, w.replicas, w.image);
                let _ = crate::fs::ops::write_file(&fc, &format!("{wdir}/{}", w.name), rec.as_bytes(), 0o600);
                for n in 0..w.replicas {
                    let pod = crate::fastman::kube::pod_name(&w.name, n);
                    let _ = runtime::remove(&fc, &pod, true);
                    let mut opts = crate::fastman::kube::clone_opts(&w.opts, pod.clone());
                    // Give each replica a unique backend port for its declared
                    // container port, so N fixed-port pods can coexist.
                    if let Some(d) = declared {
                        opts.port_remap = Some((d, crate::fastman::kube::alloc_pod_port()));
                    }
                    ctx.flush();
                    match runtime::run(&fc, &w.image, opts, None, None) {
                        Ok(_) => outln!(ctx, "{} {}/{} created", s.green(&w.kind.to_lowercase()), w.name, pod),
                        Err(e) => {
                            ctx.fail_errno(&pod, e);
                        }
                    }
                }
            }
            for sv in &m.services {
                // Associate the service with a workload: same name, else the one
                // whose name matches the selector value, else the first.
                let wl = m
                    .workloads
                    .iter()
                    .find(|w| w.name == sv.name || sv.selector.contains(&w.name))
                    .or_else(|| m.workloads.first())
                    .map(|w| w.name.clone())
                    .unwrap_or_default();
                let rec = format!("{}\n{}\n{}\n{}\n", sv.port, sv.target, sv.selector, wl);
                let _ = crate::fs::ops::write_file(&fc, &format!("{sdir}/{}", sv.name), rec.as_bytes(), 0o600);
                // Start a ClusterIP-style load-balancing proxy on the service port.
                crate::fastman::kube::start_service_proxy(sv.name.clone(), sv.port, sv.target, wl);
                outln!(ctx, "{} {} created (:{} → {})", s.green("service"), sv.name, sv.port, sv.name);
            }
            0
        }
        "get" => {
            let what = rest.first().map(|s| s.as_str()).unwrap_or("all");
            if what == "nodes" || what == "node" || what == "no" {
                // A single-node "cluster": this FastROS host.
                let mut t = Table::new(&["NAME", "STATUS", "ROLES", "CPUS", "VERSION"]);
                let host = crate::proc::host_uts().hostname.lock().clone();
                t.row(alloc::vec![
                    host,
                    s.green("Ready"),
                    "control-plane".into(),
                    format!("{}", crate::smp::present_count()),
                    format!("fastros-{}", env!("CARGO_PKG_VERSION")),
                ]);
                t.render(ctx, &s);
                return 0;
            }
            let pods = what == "pods" || what == "po" || what == "all";
            let deps = what == "deployments" || what == "deploy" || what == "all";
            let svcs = what == "services" || what == "svc" || what == "all";
            let workloads = crate::fs::ops::list_dir(&fc, &wdir).unwrap_or_default();
            if deps {
                let mut t = Table::new(&["NAME", "KIND", "DESIRED", "READY"]);
                for e in &workloads {
                    let rec = crate::fs::ops::read_file(&fc, &format!("{wdir}/{}", e.name)).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    let mut it = rec.lines();
                    let kind = it.next().unwrap_or("Deployment").to_string();
                    let want: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    let ready = (0..want).filter(|n| container::find(&fc, &crate::fastman::kube::pod_name(&e.name, *n)).map(|c| c.live_state() == State::Running).unwrap_or(false)).count();
                    t.row(alloc::vec![e.name.clone(), kind, want.to_string(), format!("{ready}/{want}")]);
                }
                t.render(ctx, &s);
            }
            if pods {
                let mut t = Table::new(&["POD", "STATUS", "RESTARTS", "IMAGE"]);
                for e in &workloads {
                    let rec = crate::fs::ops::read_file(&fc, &format!("{wdir}/{}", e.name)).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    let mut it = rec.lines();
                    let _kind = it.next();
                    let want: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
                    for n in 0..want {
                        let pod = crate::fastman::kube::pod_name(&e.name, n);
                        if let Ok(c) = container::find(&fc, &pod) {
                            let status = match c.live_state() {
                                State::Running => s.green("Running"),
                                State::Exited => s.dim(&format!("Exited ({})", c.exit_code)),
                                State::Created => s.dim("Pending"),
                            };
                            let restarts = crate::fastman::kube::restart_count(&pod).to_string();
                            t.row(alloc::vec![pod, status, restarts, c.image_key.clone()]);
                        }
                    }
                }
                t.render(ctx, &s);
            }
            if svcs {
                let mut t = Table::new(&["SERVICE", "PORT", "TARGET", "SELECTOR"]);
                for e in crate::fs::ops::list_dir(&fc, &sdir).unwrap_or_default() {
                    let rec = crate::fs::ops::read_file(&fc, &format!("{sdir}/{}", e.name)).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
                    let mut it = rec.lines();
                    let port = it.next().unwrap_or("").to_string();
                    let target = it.next().unwrap_or("").to_string();
                    let sel = it.next().unwrap_or("").to_string();
                    t.row(alloc::vec![e.name.clone(), port, target, sel]);
                }
                t.render(ctx, &s);
            }
            0
        }
        "delete" => {
            let Some(name) = rest.iter().find(|a| !a.contains('/')).cloned().or_else(|| rest.first().cloned()) else {
                return ctx.fail("delete requires a name");
            };
            // Delete a workload's pods + record, or a service.
            let rec_path = format!("{wdir}/{name}");
            if let Ok(d) = crate::fs::ops::read_file(&fc, &rec_path) {
                let text = String::from_utf8_lossy(&d).into_owned();
                let want: usize = text.lines().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
                // Remove the record FIRST so the controller stops reconciling
                // these pods before we tear them down.
                let _ = crate::fs::ops::unlink(&fc, &rec_path);
                for n in 0..want {
                    let pod = crate::fastman::kube::pod_name(&name, n);
                    let _ = runtime::remove(&fc, &pod, true);
                    crate::fastman::kube::forget_pod(&pod);
                }
                outln!(ctx, "deployment \"{name}\" deleted");
                return 0;
            }
            if crate::fs::ops::unlink(&fc, &format!("{sdir}/{name}")).is_ok() {
                outln!(ctx, "service \"{name}\" deleted");
                return 0;
            }
            ctx.fail(format!("{name}: not found"))
        }
        "scale" => kube_scale(ctx, &fc, &wdir, &rest),
        "rollout" => kube_rollout(ctx, &fc, &wdir, &rest),
        "logs" => {
            let Some(pod) = rest.iter().find(|a| !a.starts_with('-')).cloned() else {
                return ctx.fail("logs requires a pod name");
            };
            match runtime::logs(&fc, &pod) {
                Ok(d) => {
                    ctx.write(&d);
                    0
                }
                Err(e) => ctx.fail_errno(&pod, e),
            }
        }
        "exec" => {
            // kube exec [-it] POD [--] CMD...
            let mut it_flag = false;
            let mut pod = None;
            let mut cmd: Vec<String> = Vec::new();
            let mut seen = false;
            for a in &rest {
                if !seen && matches!(a.as_str(), "-i" | "-t" | "-it" | "-ti") {
                    it_flag = true;
                } else if !seen && a == "--" {
                    seen = true;
                } else if pod.is_none() {
                    pod = Some(a.clone());
                } else {
                    cmd.push(a.clone());
                }
            }
            let Some(pod) = pod else { return ctx.fail("exec requires a pod name") };
            if cmd.is_empty() {
                cmd.push("sh".to_string());
            }
            let itty = if it_flag {
                let fds = ctx.proc.fds.lock();
                match (fds.get(0), fds.get(1), fds.get(2)) {
                    (Ok(i), Ok(o), Ok(e)) => {
                        drop(fds);
                        Some(runtime::ExecTty { stdin: i, stdout: o, stderr: e, tty: ctx.proc.ctty.lock().clone(), pgid: ctx.proc.pgid.load(core::sync::atomic::Ordering::Relaxed) })
                    }
                    _ => None,
                }
            } else {
                None
            };
            let tee = if it_flag { None } else { runtime::caller_stdout(&ctx.proc) };
            ctx.flush();
            match runtime::exec(&fc, &pod, cmd, tee, itty) {
                Ok(code) => code,
                Err(e) => ctx.fail_errno(&pod, e),
            }
        }
        "describe" => kube_describe(ctx, &fc, &wdir, &sdir, &rest),
        other => ctx.fail(format!("unknown kube command '{other}' (apply|get|delete|scale|rollout|logs|exec|describe)")),
    }
}

/// Strip a `kind/name` prefix (`deployment/web` → `web`).
fn bare_name(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

/// `kube scale <name> --replicas=N` (or `deployment/<name> N`).
fn kube_scale(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, rest: &[String]) -> i32 {
    let mut name = None;
    let mut replicas: Option<usize> = None;
    let mut i = 0;
    while i < rest.len() {
        let a = &rest[i];
        if let Some(v) = a.strip_prefix("--replicas=") {
            replicas = v.parse().ok();
        } else if a == "--replicas" || a == "-r" {
            i += 1;
            replicas = rest.get(i).and_then(|v| v.parse().ok());
        } else if name.is_none() {
            name = Some(bare_name(a));
        } else if replicas.is_none() {
            replicas = a.parse().ok();
        }
        i += 1;
    }
    let (Some(name), Some(want)) = (name, replicas) else {
        return ctx.fail("usage: kube scale <name> --replicas=N");
    };
    let rec_path = format!("{wdir}/{name}");
    let Ok(d) = crate::fs::ops::read_file(fc, &rec_path) else {
        return ctx.fail(format!("{name}: no such deployment"));
    };
    let text = String::from_utf8_lossy(&d).into_owned();
    let mut lines = text.lines();
    let kind = lines.next().unwrap_or("Deployment").to_string();
    let old: usize = lines.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let image = lines.next().unwrap_or("").to_string();
    if want > old {
        // Scale up: clone pod-0's container config into the new replicas.
        let template = container::find(fc, &crate::fastman::kube::pod_name(&name, 0)).ok();
        for n in old..want {
            let pod = crate::fastman::kube::pod_name(&name, n);
            let _ = runtime::remove(fc, &pod, true);
            let mut opts = match &template {
                Some(c) => crate::fastman::kube::opts_from_container(c, pod.clone()),
                None => runtime::RunOpts { name: Some(pod.clone()), detach: true, ..Default::default() },
            };
            // Each new replica needs its OWN backend port, not pod-0's.
            if let Some((declared, _)) = opts.port_remap {
                opts.port_remap = Some((declared, crate::fastman::kube::alloc_pod_port()));
            }
            ctx.flush();
            match runtime::run(fc, &image, opts, None, None) {
                Ok(_) => outln!(ctx, "pod {pod} created"),
                Err(e) => {
                    ctx.fail_errno(&pod, e);
                }
            }
        }
    } else if want < old {
        // Scale down: remove the excess pods.
        for n in want..old {
            let pod = crate::fastman::kube::pod_name(&name, n);
            let _ = runtime::remove(fc, &pod, true);
            crate::fastman::kube::forget_pod(&pod);
            outln!(ctx, "pod {pod} removed");
        }
    }
    let rec = format!("{kind}\n{want}\n{image}\n");
    let _ = crate::fs::ops::write_file(fc, &rec_path, rec.as_bytes(), 0o600);
    outln!(ctx, "deployment \"{name}\" scaled to {want}");
    0
}

/// `kube rollout restart <name>` — restart every pod of a deployment.
fn kube_rollout(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, rest: &[String]) -> i32 {
    let action = rest.first().map(|s| s.as_str()).unwrap_or("");
    if action != "restart" && action != "status" {
        return ctx.fail("usage: kube rollout <restart|status> <name>");
    }
    let Some(name) = rest.iter().skip(1).map(|s| bare_name(s)).next() else {
        return ctx.fail("rollout requires a deployment name");
    };
    let rec_path = format!("{wdir}/{name}");
    let Ok(d) = crate::fs::ops::read_file(fc, &rec_path) else {
        return ctx.fail(format!("{name}: no such deployment"));
    };
    let text = String::from_utf8_lossy(&d).into_owned();
    let want: usize = text.lines().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    if action == "status" {
        let ready = (0..want).filter(|n| container::find(fc, &crate::fastman::kube::pod_name(&name, *n)).map(|c| c.live_state() == State::Running).unwrap_or(false)).count();
        outln!(ctx, "deployment \"{name}\": {ready}/{want} pods ready");
        return 0;
    }
    for n in 0..want {
        let pod = crate::fastman::kube::pod_name(&name, n);
        if let Ok(mut c) = container::find(fc, &pod) {
            let _ = runtime::stop(fc, &pod, crate::proc::signal::SIGTERM);
            match runtime::start(fc, &mut c, None, None) {
                Ok(_) => outln!(ctx, "pod {pod} restarted"),
                Err(e) => {
                    ctx.fail_errno(&pod, e);
                }
            }
        }
    }
    outln!(ctx, "deployment \"{name}\" restarted");
    0
}

/// `kube describe <name>` — details of a deployment (its pods) or a service.
fn kube_describe(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, sdir: &str, rest: &[String]) -> i32 {
    let Some(name) = rest.iter().map(|s| bare_name(s)).next() else {
        return ctx.fail("describe requires a name");
    };
    if let Ok(d) = crate::fs::ops::read_file(fc, &format!("{wdir}/{name}")) {
        let text = String::from_utf8_lossy(&d).into_owned();
        let mut it = text.lines();
        let kind = it.next().unwrap_or("Deployment");
        let want: usize = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let image = it.next().unwrap_or("");
        outln!(ctx, "Name:      {name}");
        outln!(ctx, "Kind:      {kind}");
        outln!(ctx, "Image:     {image}");
        outln!(ctx, "Replicas:  {want} desired");
        outln!(ctx, "Pods:");
        for n in 0..want {
            let pod = crate::fastman::kube::pod_name(&name, n);
            match container::find(fc, &pod) {
                Ok(c) => {
                    let st = match c.live_state() {
                        State::Running => "Running",
                        State::Exited => "Exited",
                        State::Created => "Pending",
                    };
                    outln!(ctx, "  {pod}  {st}  pid={}  restarts={}", c.pid, crate::fastman::kube::restart_count(&pod));
                }
                Err(_) => outln!(ctx, "  {pod}  (missing)"),
            }
        }
        return 0;
    }
    if let Ok(d) = crate::fs::ops::read_file(fc, &format!("{sdir}/{name}")) {
        let text = String::from_utf8_lossy(&d).into_owned();
        let mut it = text.lines();
        outln!(ctx, "Name:      {name}");
        outln!(ctx, "Kind:      Service");
        outln!(ctx, "Port:      {}", it.next().unwrap_or(""));
        outln!(ctx, "TargetPort:{}", it.next().unwrap_or(""));
        outln!(ctx, "Selector:  {}", it.next().unwrap_or(""));
        return 0;
    }
    ctx.fail(format!("{name}: not found"))
}

/// Deep-copy RunOpts (it is not Clone: it owns Vecs the runtime consumes).
fn clone_opts(o: &RunOpts) -> RunOpts {
    RunOpts {
        name: o.name.clone(),
        cmd: o.cmd.clone(),
        env: o.env.clone(),
        workdir: o.workdir.clone(),
        ports: o.ports.clone(),
        volumes: o.volumes.clone(),
        network: o.network.clone(),
        detach: o.detach,
        user: o.user,
        port_remap: o.port_remap,
        mem_limit: o.mem_limit,
        pids_limit: o.pids_limit,
        cap_add: o.cap_add,
        cap_drop: o.cap_drop,
        rm: o.rm,
        health_cmd: o.health_cmd.clone(),
        health_interval: o.health_interval,
        health_timeout: o.health_timeout,
        health_retries: o.health_retries,
    }
}

fn stop(ctx: &mut Ctx, args: &[String]) -> i32 {
    if args.is_empty() {
        return ctx.fail("stop requires a container");
    }
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in args {
        match runtime::stop(&fc, name, crate::proc::signal::SIGTERM) {
            Ok(c) => outln!(ctx, "{}", c.name),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

fn rm(ctx: &mut Ctx, args: &[String]) -> i32 {
    let force = args.iter().any(|a| a == "-f" || a == "--force");
    let fc = fs_ctx(ctx);
    let mut st = 0;
    for name in args.iter().filter(|a| !a.starts_with('-')) {
        match runtime::remove(&fc, name, force) {
            Ok(()) => outln!(ctx, "{name}"),
            Err(crate::errno::Errno::EBUSY) => st = ctx.fail(format!("{name}: container is running (use -f)")),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

fn logs(ctx: &mut Ctx, args: &[String]) -> i32 {
    let follow = args.iter().any(|a| matches!(a.as_str(), "-f" | "--follow"));
    let Some(name) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("logs requires a container");
    };
    let fc = fs_ctx(ctx);
    let c = match container::find(&fc, name) {
        Ok(c) => c,
        Err(e) => return ctx.fail_errno(name, e),
    };
    if !follow {
        match runtime::logs(&fc, name) {
            Ok(data) => {
                ctx.write(&data);
                0
            }
            Err(e) => ctx.fail_errno(name, e),
        }
    } else {
        logs_follow(ctx, &fc, &c)
    }
}

/// `fastman logs -f`: stream the container's log, printing new output as it is
/// written, until the container exits (Docker's behaviour) or the caller hits
/// ^C. We track a byte offset and `pread` the tail each pass, so a growing log
/// is never re-read from the start.
fn logs_follow(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, c: &container::Container) -> i32 {
    let path = c.log_path(fc);
    let mut off: u64 = 0;
    let mut buf = [0u8; 4096];
    loop {
        // Drain whatever has been appended since the last pass.
        if let Ok(f) = crate::fs::ops::open(fc, &path, crate::fs::file::flags::O_RDONLY, 0) {
            loop {
                match f.pread(off, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        ctx.write(&buf[..n]);
                        off += n as u64;
                    }
                    Err(_) => break,
                }
            }
            ctx.flush();
        }
        // The container has exited and its log is fully drained — stop, like Docker.
        if !container::find(fc, &c.id).map(|c| c.is_alive()).unwrap_or(false) {
            break;
        }
        // Wait for more output; ^C (an interrupted sleep) ends the follow.
        if !crate::sched::sleep_ms(200) {
            let _ = crate::proc::absorb_signals();
            break;
        }
    }
    0
}

/// A JSON string literal with the mandatory escapes.
fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for ch in s.chars() {
        match ch {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// A JSON array of strings on one line: `["a", "b"]`.
fn json_str_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// `fastman inspect <container>...`: emit a Docker-style JSON array describing
/// each container's config, state and network. Faithful to the fields fastman
/// actually models (no invented Docker keys).
fn inspect(ctx: &mut Ctx, args: &[String]) -> i32 {
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if names.is_empty() {
        return ctx.fail("inspect requires a container");
    }
    let fc = fs_ctx(ctx);
    let mut objs: Vec<String> = Vec::new();
    let mut st = 0;
    for name in &names {
        let c = match container::find(&fc, name) {
            Ok(c) => c,
            Err(e) => {
                st = ctx.fail_errno(name, e);
                continue;
            }
        };
        let running = c.is_alive();
        let ports: Vec<String> = c
            .ports
            .iter()
            .map(|p| format!("{}:{}{}", p.host, p.container, if p.udp { "/udp" } else { "/tcp" }))
            .collect();
        let binds: Vec<String> = c
            .volumes
            .iter()
            .map(|v| format!("{}:{}{}", v.host, v.container, if v.read_only { ":ro" } else { "" }))
            .collect();
        let cap_add = crate::syscall::seccomp::cap_names(c.cap_add);
        let cap_drop = crate::syscall::seccomp::cap_names(c.cap_drop);
        let ip = crate::net::netns::container_ip(&c.id).map(|a| a.to_string()).unwrap_or_default();
        let health = if c.health_cmd.is_empty() {
            String::from("null")
        } else {
            format!("{{ \"Status\": {}, \"FailingStreak\": {} }}", json_str(if c.health_status.is_empty() { "starting" } else { &c.health_status }), c.health_fails)
        };
        let obj = format!(
            concat!(
                "  {{\n",
                "    \"Id\": {id},\n",
                "    \"Name\": {name},\n",
                "    \"Created\": {created},\n",
                "    \"State\": {{\n",
                "      \"Status\": {status},\n",
                "      \"Running\": {running},\n",
                "      \"Pid\": {pid},\n",
                "      \"ExitCode\": {exit},\n",
                "      \"Health\": {health}\n",
                "    }},\n",
                "    \"Image\": {image_id},\n",
                "    \"Config\": {{\n",
                "      \"Image\": {image_key},\n",
                "      \"Cmd\": {cmd},\n",
                "      \"Env\": {env},\n",
                "      \"WorkingDir\": {workdir},\n",
                "      \"User\": {user}\n",
                "    }},\n",
                "    \"HostConfig\": {{\n",
                "      \"NetworkMode\": {network},\n",
                "      \"Memory\": {mem},\n",
                "      \"PidsLimit\": {pids},\n",
                "      \"PortBindings\": {ports},\n",
                "      \"Binds\": {binds},\n",
                "      \"CapAdd\": {cap_add},\n",
                "      \"CapDrop\": {cap_drop}\n",
                "    }},\n",
                "    \"NetworkSettings\": {{\n",
                "      \"IPAddress\": {ip}\n",
                "    }}\n",
                "  }}"
            ),
            id = json_str(&c.id),
            name = json_str(&format!("/{}", c.name)),
            created = c.created,
            status = json_str(c.live_state().as_str()),
            running = running,
            pid = c.pid,
            exit = c.exit_code,
            health = health,
            image_id = json_str(&c.image_id),
            image_key = json_str(&c.image_key),
            cmd = json_str_array(&c.cmd),
            env = json_str_array(&c.env),
            workdir = json_str(if c.workdir.is_empty() { "/" } else { &c.workdir }),
            user = json_str(&format!("{}:{}", c.uid, c.gid)),
            network = json_str(&c.network),
            mem = c.mem_limit,
            pids = c.pids_limit,
            ports = json_str_array(&ports),
            binds = json_str_array(&binds),
            cap_add = json_str_array(&cap_add),
            cap_drop = json_str_array(&cap_drop),
            ip = json_str(&ip),
        );
        objs.push(obj);
    }
    if objs.is_empty() {
        return st;
    }
    outln!(ctx, "[\n{}\n]", objs.join(",\n"));
    st
}

/// The host pids belonging to a container: its init (`root`) plus every
/// descendant, walking the parent map built from a process snapshot.
fn proc_subtree(root: u32, children: &alloc::collections::BTreeMap<u32, Vec<u32>>) -> Vec<u32> {
    let mut out = alloc::vec![root];
    let mut stack = alloc::vec![root];
    while let Some(p) = stack.pop() {
        if let Some(kids) = children.get(&p) {
            for &k in kids {
                out.push(k);
                stack.push(k);
            }
        }
    }
    out
}

/// `fastman stats [container...]`: a one-shot resource snapshot (like
/// `docker stats --no-stream`) — CPU%, memory usage/limit, and PID count per
/// running container. CPU is sampled over a short window; memory comes from the
/// container's cgroup when it has limits, else from its processes' RSS.
fn stats(ctx: &mut Ctx, args: &[String]) -> i32 {
    use crate::shell::cmds::procinfo as pi;
    let names: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let fc = fs_ctx(ctx);
    let s = style_of(ctx);

    // Which containers to report: the named ones, else all running.
    let mut conts: Vec<container::Container> = Vec::new();
    if names.is_empty() {
        for c in container::list(&fc) {
            if c.is_alive() {
                conts.push(c);
            }
        }
    } else {
        for name in &names {
            match container::find(&fc, name) {
                Ok(c) => conts.push(c),
                Err(e) => return ctx.fail_errno(name, e),
            }
        }
    }

    // Two CPU-time samples across a short window.
    let s1 = pi::list(&fc);
    let t1 = crate::time::now_ns();
    let before: alloc::collections::BTreeMap<u32, u64> = s1.iter().map(|p| (p.pid, p.cpu_ticks())).collect();
    crate::sched::sleep_ms(500);
    let s2 = pi::list(&fc);
    let t2 = crate::time::now_ns();
    let elapsed_ticks = ((t2.saturating_sub(t1)) * crate::time::HZ as u64 / 1_000_000_000).max(1);

    // Parent → children and per-pid cpu/rss from the second sample.
    let mut children: alloc::collections::BTreeMap<u32, Vec<u32>> = alloc::collections::BTreeMap::new();
    let mut cpu_now: alloc::collections::BTreeMap<u32, u64> = alloc::collections::BTreeMap::new();
    let mut rss_pages: alloc::collections::BTreeMap<u32, u64> = alloc::collections::BTreeMap::new();
    for p in &s2 {
        children.entry(p.ppid).or_default().push(p.pid);
        cpu_now.insert(p.pid, p.cpu_ticks());
        rss_pages.insert(p.pid, p.rss_pages);
    }
    let total_ram = crate::mm::stats().total_bytes.max(1);

    let mut t = Table::new(&["CONTAINER ID", "NAME", "CPU %", "MEM USAGE / LIMIT", "MEM %", "PIDS"]);
    for c in &conts {
        if !c.is_alive() {
            t.row(alloc::vec![short(&c.id).to_string(), c.name.clone(), "--".into(), "-- / --".into(), "--".into(), "0".into()]);
            continue;
        }
        let tree = proc_subtree(c.pid, &children);
        let cpu_delta: u64 = tree.iter().map(|p| cpu_now.get(p).copied().unwrap_or(0).saturating_sub(before.get(p).copied().unwrap_or(0))).sum();
        let cpu_pm = cpu_delta * 1000 / elapsed_ticks; // per-mille of one core

        // Memory: prefer the cgroup counter, fall back to summed RSS.
        let (mem, limit, pids) = match crate::cgroup::usage(&c.id) {
            Some((m, l, p, _)) => (m, l, p as u64),
            None => {
                let rss: u64 = tree.iter().map(|p| rss_pages.get(p).copied().unwrap_or(0)).sum::<u64>() * 4096;
                (rss, c.mem_limit, tree.len() as u64)
            }
        };
        let denom = if limit > 0 { limit } else { total_ram };
        let mem_pm = mem * 1000 / denom;
        let limit_str = if limit > 0 { human_size(limit) } else { "∞".into() };

        t.row(alloc::vec![
            short(&c.id).to_string(),
            c.name.clone(),
            format!("{}.{}%", cpu_pm / 10, cpu_pm % 10),
            format!("{} / {}", human_size(mem), limit_str),
            format!("{}.{}%", mem_pm / 10, mem_pm % 10),
            format!("{pids}"),
        ]);
    }
    t.render(ctx, &s);
    0
}

/// `fastman restart <container>...`: stop (SIGTERM, escalating to SIGKILL) then
/// start each container again — the same lifecycle Docker's `restart` runs.
fn restart(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn basename(p: &str) -> &str {
    p.trim_end_matches('/').rsplit('/').next().unwrap_or(p)
}

/// The parent directory of a path (for `mkdir -p` before writing a file).
fn parent_dir(p: &str) -> String {
    let t = p.trim_end_matches('/');
    match t.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => t[..i].to_string(),
        None => ".".to_string(),
    }
}

/// If `arg` is `<container>:<path>` for an existing container, return it.
fn split_container(fc: &crate::fs::ops::Ctx, arg: &str) -> Option<(container::Container, String)> {
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
fn container_ctx(ctx: &Ctx, c: &container::Container) -> Result<crate::fs::ops::Ctx, i32> {
    if !c.is_alive() {
        return Err(-1);
    }
    match crate::proc::find(c.pid) {
        Some(init) => Ok(crate::fs::ops::Ctx { fs: init.fs.lock().clone(), cred: crate::fs::perm::Cred::root() }),
        None => Err(-1),
    }
}

/// Recursively copy `from:from_path` to `to:to_path` (files and directories).
fn copy_tree(from: &crate::fs::ops::Ctx, from_path: &str, to: &crate::fs::ops::Ctx, to_path: &str) -> crate::errno::KResult<()> {
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
fn cp(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn kill(ctx: &mut Ctx, args: &[String]) -> i32 {
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
            Ok(_) => outln!(ctx, "{name}"),
            Err(e) => st = ctx.fail_errno(name, e),
        }
    }
    st
}

/// Shared by `pause` (SIGSTOP) and `unpause` (SIGCONT).
fn pause_cmd(ctx: &mut Ctx, args: &[String], sig: u32, verb: &str) -> i32 {
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
fn rename(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn top(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn port(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn wait_cmd(ctx: &mut Ctx, args: &[String]) -> i32 {
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
fn update(ctx: &mut Ctx, args: &[String]) -> i32 {
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

fn exec(ctx: &mut Ctx, args: &[String]) -> i32 {
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

/// Streams registry progress to the caller's terminal.
struct CliProgress<'a> {
    ctx: &'a mut Ctx,
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
fn pull_reference(ctx: &mut Ctx, reference: &str) -> Result<(), i32> {
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
            Ok(())
        }
        Err(e) => Err(ctx.fail_errno("store image", e)),
    }
}

/// Ensure an image is present locally, pulling it Docker-style if not. Used by
/// `fastman run` so `run <image>` works without a separate `pull`.
fn ensure_image(ctx: &mut Ctx, image_name: &str) -> Result<(), i32> {
    let key = image::ImageRef::parse(image_name).map(|r| r.key()).unwrap_or_else(|| image_name.to_string());
    outln!(ctx, "Unable to find image '{key}' locally");
    pull_reference(ctx, image_name)
}

fn pull(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(reference) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("pull requires an image reference");
    };
    match pull_reference(ctx, reference) {
        Ok(()) => 0,
        Err(code) => code,
    }
}
