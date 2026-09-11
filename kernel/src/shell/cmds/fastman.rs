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
        "images" | "image" | "ls" => images(ctx),
        "rmi" => rmi(ctx, &args[1..]),
        "run" => run(ctx, &args[1..]),
        "ps" => ps(ctx, &args[1..]),
        "stop" => stop(ctx, &args[1..]),
        "rm" => rm(ctx, &args[1..]),
        "logs" => logs(ctx, &args[1..]),
        "exec" => exec(ctx, &args[1..]),
        "pull" => pull(ctx, &args[1..]),
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
    outln!(ctx, "  pull <ref>                 pull an image from a registry");
    outln!(ctx, "  images                     list images");
    outln!(ctx, "  rmi <image>                remove an image");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("Containers:"));
    outln!(ctx, "  run [opts] <image> [cmd]   create and start a container");
    outln!(ctx, "  ps [-a]                    list containers");
    outln!(ctx, "  logs <container>           show a container's output");
    outln!(ctx, "  exec <container> <cmd>     run a command in a container");
    outln!(ctx, "  stop <container>           stop a container");
    outln!(ctx, "  rm [-f] <container>        remove a container");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("run options:"));
    outln!(ctx, "  -d                 detached (background)");
    outln!(ctx, "  --name <name>      assign a name");
    outln!(ctx, "  -e KEY=VALUE       set an environment variable");
    outln!(ctx, "  -p HOST:CONT       publish a port");
    outln!(ctx, "  -v HOST:CONT[:ro]  bind-mount a volume");
    outln!(ctx, "  -w <dir>           working directory");
    outln!(ctx, "  --network <name>   network (default: bridge)");
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

fn parse_run(args: &[String]) -> Result<(RunOpts, String, Vec<String>), String> {
    let mut o = RunOpts { network: String::from("bridge"), ..Default::default() };
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
            s if s.starts_with('-') => return Err(format!("unknown option '{s}'")),
            s => image = Some(s.to_string()),
        }
        i += 1;
    }
    let image = image.ok_or("run requires an image")?;
    o.cmd = cmd.clone();
    Ok((o, image, cmd))
}

fn parse_port(s: &str) -> Result<Port, String> {
    let (spec, udp) = match s.strip_suffix("/udp") {
        Some(rest) => (rest, true),
        None => (s.strip_suffix("/tcp").unwrap_or(s), false),
    };
    let (h, c) = spec.split_once(':').ok_or("port must be HOST:CONTAINER")?;
    Ok(Port { host: h.parse().map_err(|_| "bad host port")?, container: c.parse().map_err(|_| "bad container port")?, udp })
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
    let (opts, image_name, _cmd) = match parse_run(args) {
        Ok(v) => v,
        Err(e) => return ctx.fail(e),
    };
    let detach = opts.detach;
    let fc = fs_ctx(ctx);
    // Distinguish "no such image" from "command not found inside the image".
    if image::resolve(&fc, &image_name).is_none() {
        return ctx.fail(format!("Unable to find image '{image_name}' locally (try `fastman pull {image_name}`)"));
    }
    let tee = if detach { None } else { runtime::caller_stdout(&ctx.proc) };
    ctx.flush();
    match runtime::run(&fc, &image_name, opts, tee) {
        Ok((c, code)) => {
            if detach {
                outln!(ctx, "{}", c.id);
                0
            } else {
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
            State::Running => s.green("Up"),
            State::Exited => s.dim(&format!("Exited ({})", c.exit_code)),
            State::Created => s.dim("Created"),
        };
        let ports = c.ports.iter().map(|p| format!("0.0.0.0:{}->{}/{}", p.host, p.container, if p.udp { "udp" } else { "tcp" })).collect::<Vec<_>>().join(", ");
        t.row(alloc::vec![short(&c.id).to_string(), c.image_key.clone(), cmd, ago(c.created), status, ports, c.name.clone()]);
    }
    t.render(ctx, &s);
    0
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
    let Some(name) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("logs requires a container");
    };
    let fc = fs_ctx(ctx);
    match runtime::logs(&fc, name) {
        Ok(data) => {
            ctx.write(&data);
            0
        }
        Err(e) => ctx.fail_errno(name, e),
    }
}

fn exec(ctx: &mut Ctx, args: &[String]) -> i32 {
    // Skip -i/-t flags (accepted for compatibility; interactive TTY later).
    let rest: Vec<String> = args.iter().filter(|a| !matches!(a.as_str(), "-i" | "-t" | "-it" | "-ti" | "--interactive" | "--tty")).cloned().collect();
    if rest.len() < 2 {
        return ctx.fail("exec requires a container and a command");
    }
    let name = rest[0].clone();
    let argv = rest[1..].to_vec();
    let fc = fs_ctx(ctx);
    let tee = runtime::caller_stdout(&ctx.proc);
    ctx.flush();
    match runtime::exec(&fc, &name, argv, tee) {
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

fn pull(ctx: &mut Ctx, args: &[String]) -> i32 {
    let Some(reference) = args.iter().find(|a| !a.starts_with('-')) else {
        return ctx.fail("pull requires an image reference");
    };
    let r = match image::ImageRef::parse(reference) {
        Some(r) => r,
        None => return ctx.fail(format!("invalid reference '{reference}'")),
    };
    if !crate::net::is_up() {
        return ctx.fail("no network");
    }
    ctx.flush();
    let result = {
        let mut prog = CliProgress { ctx };
        crate::fastman::registry::pull(&r, &mut prog)
    };
    let pulled = match result {
        Ok(p) => p,
        Err(e) => return ctx.fail(format!("pull {}: {}", r.key(), e.message())),
    };
    let fc = fs_ctx(ctx);
    match image::store_layers(&fc, &r.key(), &pulled.layers, pulled.config) {
        Ok(img) => {
            outln!(ctx, "Status: Downloaded newer image for {}", r.key());
            outln!(ctx, "{}", img.key);
            0
        }
        Err(e) => ctx.fail_errno("store image", e),
    }
}
