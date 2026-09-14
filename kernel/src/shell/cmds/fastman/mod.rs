//! `fastman` — the FastROS container engine CLI: a Docker-compatible surface
//! with Kubernetes-style verbs, rootless and sandboxed by default.

mod control;
mod orchestration;
mod pull;
mod query;
mod resources;

use control::*;
use orchestration::*;
use pull::*;
use query::*;
use resources::*;

use crate::fastman::container::{Port, State, Volume};
use crate::fastman::runtime::{self, RunOpts};
use crate::fastman::{container, image};
use crate::shell::ctx::Ctx;
use crate::outln;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ── colours (only when stdout is a terminal) ────────────────────────────────

pub(super) struct Style {
    on: bool,
}
impl Style {
    pub(super) fn bold(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[1m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub(super) fn dim(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[90m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    pub(super) fn green(&self, s: &str) -> String {
        if self.on {
            format!("\x1b[32m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

/// A left-aligned table with a header row, like `docker ps` / `kubectl get`.
pub(super) struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}
impl Table {
    pub(super) fn new(headers: &[&str]) -> Table {
        Table { headers: headers.iter().map(|s| s.to_string()).collect(), rows: Vec::new() }
    }
    pub(super) fn row(&mut self, cells: Vec<String>) {
        self.rows.push(cells);
    }
    pub(super) fn render(&self, ctx: &mut Ctx, style: &Style) {
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

pub(super) fn human_size(bytes: u64) -> String {
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
pub(super) fn ago(then: u64) -> String {
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

pub(super) fn short(id: &str) -> &str {
    &id[..id.len().min(12)]
}

pub(super) fn style_of(ctx: &Ctx) -> Style {
    Style { on: ctx.stdout_tty().is_some() }
}

// ── argument parsing ───────────────────────────────────────────────────────

pub(super) fn fs_ctx(ctx: &Ctx) -> crate::fs::ops::Ctx {
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
        "save" => save(ctx, &args[1..]),
        "load" => load(ctx, &args[1..]),
        "commit" => commit(ctx, &args[1..]),
        "run" => run(ctx, &args[1..]),
        "create" => create_cmd(ctx, &args[1..]),
        "ps" => ps(ctx, &args[1..]),
        "start" => start(ctx, &args[1..]),
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
        "events" => events(ctx, &args[1..]),
        "network" => network(ctx, &args[1..]),
        "volume" => volume(ctx, &args[1..]),
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
    outln!(ctx, "  commit <ctr> <image>       create an image from a container");
    outln!(ctx, "  save <image> [-o file]     export an image as a tar stream");
    outln!(ctx, "  load [-i file]             import an image from a save archive");
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
    outln!(ctx, "  network ls|create|rm|inspect   manage networks");
    outln!(ctx, "  volume ls|create|rm|inspect    manage volumes");
    outln!(ctx, "  events [--since N]          stream container lifecycle events");
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

/// `fastman events [--since <seq>]` — stream container lifecycle events (create,
/// start, die, kill, stop, destroy, pull). Shows the buffered recent events,
/// then follows live until interrupted (^C).
fn events(ctx: &mut Ctx, args: &[String]) -> i32 {
    // --since <seq>: only events after this sequence (default 0 = all buffered).
    let mut last = 0u64;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--since" {
            i += 1;
            last = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
        }
        i += 1;
    }
    loop {
        for e in crate::fastman::events::since(last) {
            outln!(ctx, "seq={} {} container {} {}", e.seq, e.time, e.action, e.actor);
            last = e.seq;
        }
        ctx.flush();
        // Follow: wake on the next event or ^C (an interrupted sleep).
        if !crate::sched::sleep_ms(300) {
            let _ = crate::proc::absorb_signals();
            break;
        }
    }
    0
}

/// `fastman save <image> [-o file]` — export an image as a tar stream (stdout by
/// default). `docker save img > file` and `save -o file` both work.
fn save(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut out_file = None;
    let mut name = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                out_file = args.get(i).cloned();
            }
            s if !s.starts_with('-') => name = Some(s.to_string()),
            _ => {}
        }
        i += 1;
    }
    let Some(name) = name else { return ctx.fail("save requires an image") };
    if out_file.is_none() && ctx.stdout_tty().is_some() {
        return ctx.fail("refusing to write an image to the terminal (use -o file or redirect)");
    }
    let fc = fs_ctx(ctx);
    let bytes = match crate::fastman::archive::save(&fc, &name) {
        Ok(b) => b,
        Err(e) => return ctx.fail_errno("save", e),
    };
    match out_file {
        Some(f) => match crate::fs::ops::write_file(&fc, &f, &bytes, 0o644) {
            Ok(()) => 0,
            Err(e) => ctx.fail_errno(&f, e),
        },
        None => {
            ctx.flush();
            ctx.write(&bytes);
            0
        }
    }
}

/// `fastman load [-i file]` — import an image from a `save` archive (stdin by
/// default).
fn load(ctx: &mut Ctx, args: &[String]) -> i32 {
    let mut in_file = None;
    let mut i = 0;
    while i < args.len() {
        if matches!(args[i].as_str(), "-i" | "--input") {
            i += 1;
            in_file = args.get(i).cloned();
        }
        i += 1;
    }
    let fc = fs_ctx(ctx);
    let data = match in_file {
        Some(f) => match crate::fs::ops::read_file(&fc, &f) {
            Ok(d) => d,
            Err(e) => return ctx.fail_errno(&f, e),
        },
        None => match ctx.read_input("-") {
            Ok(d) => d,
            Err(e) => return ctx.fail_errno("stdin", e),
        },
    };
    if data.is_empty() {
        return ctx.fail("no data (pipe a `fastman save` archive)");
    }
    match crate::fastman::archive::load(&fc, &data) {
        Ok(img) => {
            outln!(ctx, "Loaded image: {}", img.key);
            0
        }
        Err(e) => ctx.fail_errno("load", e),
    }
}

/// `fastman commit <container> <image>` — snapshot a running container's
/// filesystem into a new image.
fn commit(ctx: &mut Ctx, args: &[String]) -> i32 {
    let a: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if a.len() != 2 {
        return ctx.fail("commit requires CONTAINER and a new IMAGE name");
    }
    let fc = fs_ctx(ctx);
    match runtime::commit(&fc, a[0], a[1]) {
        Ok(img) => {
            outln!(ctx, "{}", img.id);
            0
        }
        Err(crate::errno::Errno::ENOTCONN) => ctx.fail(format!("container {} is not running", a[0])),
        Err(e) => ctx.fail_errno("commit", e),
    }
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
            "--env-file" => {
                i += 1;
                o.env_files.push(args.get(i).ok_or("--env-file needs a path")?.clone());
            }
            "--entrypoint" => {
                i += 1;
                o.entrypoint = Some(args.get(i).ok_or("--entrypoint needs a command")?.clone());
            }
            "--restart" => {
                i += 1;
                let v = args.get(i).ok_or("--restart needs a policy")?;
                // Accept `on-failure:N` (max retries) — we ignore the count.
                let policy = v.split(':').next().unwrap_or(v);
                match policy {
                    "no" | "" => o.restart_policy = String::new(),
                    "always" | "unless-stopped" | "on-failure" => o.restart_policy = policy.to_string(),
                    _ => return Err(format!("--restart: unknown policy '{v}' (no|always|unless-stopped|on-failure)")),
                }
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
pub(super) fn parse_size(s: &str) -> Result<u64, String> {
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

/// Expand any `--env-file` paths into `opts.env`, prepending them so an explicit
/// `-e` still wins. Returns `Err(exit_code)` if a file cannot be read.
fn expand_env_files(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, opts: &mut runtime::RunOpts) -> Result<(), i32> {
    if opts.env_files.is_empty() {
        return Ok(());
    }
    let mut merged = Vec::new();
    for path in &opts.env_files {
        match crate::fs::ops::read_file(fc, path) {
            Ok(data) => {
                for line in String::from_utf8_lossy(&data).lines() {
                    let t = line.trim();
                    if t.is_empty() || t.starts_with('#') || !t.contains('=') {
                        continue;
                    }
                    merged.push(t.to_string());
                }
            }
            Err(e) => return Err(ctx.fail_errno(path, e)),
        }
    }
    merged.extend(core::mem::take(&mut opts.env));
    opts.env = merged;
    Ok(())
}

/// `fastman create [opts] <image> [cmd]` — create a container without starting
/// it (like `docker create`); prints the new container id. `start` runs it.
fn create_cmd(ctx: &mut Ctx, args: &[String]) -> i32 {
    let (mut opts, _interactive, image_name, _cmd) = match parse_run(args) {
        Ok(v) => v,
        Err(e) => return ctx.fail(e),
    };
    let fc = fs_ctx(ctx);
    if let Err(code) = expand_env_files(ctx, &fc, &mut opts) {
        return code;
    }
    if let Some((u, g)) = opts.user {
        if !fc.cred.is_root() && (u != fc.cred.uid || g != fc.cred.gid) {
            return ctx.fail("--user: permission denied (only root may run as another identity)");
        }
    }
    if image::resolve(&fc, &image_name).is_none() {
        if let Err(code) = ensure_image(ctx, &image_name) {
            return code;
        }
    }
    let opts_name = opts.name.clone();
    match runtime::create(&fc, &image_name, opts) {
        Ok(c) => {
            outln!(ctx, "{}", c.id);
            0
        }
        Err(crate::errno::Errno::EEXIST) => {
            let existing = crate::fastman::container::find(&fc, opts_name.as_deref().unwrap_or("")).ok();
            match existing {
                Some(c) => ctx.fail(format!("the container name \"{}\" is already in use by {}", c.name, short(&c.id))),
                None => ctx.fail("a container with that name already exists (use a different --name)"),
            }
        }
        Err(e) => ctx.fail_errno("create", e),
    }
}

fn run(ctx: &mut Ctx, args: &[String]) -> i32 {
    let (mut opts, interactive, image_name, _cmd) = match parse_run(args) {
        Ok(v) => v,
        Err(e) => return ctx.fail(e),
    };
    let detach = opts.detach;
    let rm = opts.rm;
    let fc = fs_ctx(ctx);
    if let Err(code) = expand_env_files(ctx, &fc, &mut opts) {
        return code;
    }
    // Reject an unauthorized `--user` up front (before any auto-pull): a non-root
    // caller may only run as its own identity. runtime::create() enforces this
    // too; doing it here just fails fast with a clear message and no wasted pull.
    if let Some((u, g)) = opts.user {
        if !fc.cred.is_root() && (u != fc.cred.uid || g != fc.cred.gid) {
            return ctx.fail("--user: permission denied (only root may run as another identity)");
        }
    }
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
    let opts_name = opts.name.clone();
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
        Err(crate::errno::Errno::EEXIST) => {
            // A `--name` collision (Docker: "name already in use").
            let existing = crate::fastman::container::find(&fc, opts_name.as_deref().unwrap_or("")).ok();
            match existing {
                Some(c) => ctx.fail(format!(
                    "the container name \"{}\" is already in use by {} — remove it (fastman rm {}) or use a different --name",
                    c.name,
                    short(&c.id),
                    c.name
                )),
                None => ctx.fail("a container with that name already exists (use a different --name)"),
            }
        }
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
