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
    outln!(ctx, "{}", s.bold("Compose (multi-container stacks):"));
    outln!(ctx, "  compose [-f file] up       start all services in a compose file");
    outln!(ctx, "  compose [-f file] ps       list the stack's containers");
    outln!(ctx, "  compose [-f file] logs <svc>  show a service's output");
    outln!(ctx, "  compose [-f file] down     stop and remove the stack");
    outln!(ctx);
    outln!(ctx, "{}", s.bold("run options:"));
    outln!(ctx, "  -d                 detached (background)");
    outln!(ctx, "  --name <name>      assign a name");
    outln!(ctx, "  -e KEY=VALUE       set an environment variable");
    outln!(ctx, "  -p HOST:CONT       publish a port");
    outln!(ctx, "  -v HOST:CONT[:ro]  bind-mount a volume");
    outln!(ctx, "  -u uid[:gid]       run as this user (e.g. for postgres)");
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
                match runtime::run(&fc, &svc.image, opts, None) {
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
                let rec = format!("{}\n{}\n{}\n", w.kind, w.replicas, w.image);
                let _ = crate::fs::ops::write_file(&fc, &format!("{wdir}/{}", w.name), rec.as_bytes(), 0o600);
                for n in 0..w.replicas {
                    let pod = crate::fastman::kube::pod_name(&w.name, n);
                    let _ = runtime::remove(&fc, &pod, true);
                    let opts = crate::fastman::kube::clone_opts(&w.opts, pod.clone());
                    ctx.flush();
                    match runtime::run(&fc, &w.image, opts, None) {
                        Ok(_) => outln!(ctx, "{} {}/{} created", s.green(&w.kind.to_lowercase()), w.name, pod),
                        Err(e) => {
                            ctx.fail_errno(&pod, e);
                        }
                    }
                }
            }
            for sv in &m.services {
                let rec = format!("{}\n{}\n{}\n", sv.port, sv.target, sv.selector);
                let _ = crate::fs::ops::write_file(&fc, &format!("{sdir}/{}", sv.name), rec.as_bytes(), 0o600);
                outln!(ctx, "{} {} created", s.green("service"), sv.name);
            }
            0
        }
        "get" => {
            let what = rest.first().map(|s| s.as_str()).unwrap_or("all");
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
                let mut t = Table::new(&["POD", "STATUS", "IMAGE"]);
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
                            t.row(alloc::vec![pod, status, c.image_key.clone()]);
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
                for n in 0..want {
                    let _ = runtime::remove(&fc, &crate::fastman::kube::pod_name(&name, n), true);
                }
                let _ = crate::fs::ops::unlink(&fc, &rec_path);
                outln!(ctx, "deployment \"{name}\" deleted");
                return 0;
            }
            if crate::fs::ops::unlink(&fc, &format!("{sdir}/{name}")).is_ok() {
                outln!(ctx, "service \"{name}\" deleted");
                return 0;
            }
            ctx.fail(format!("{name}: not found"))
        }
        other => ctx.fail(format!("unknown kube command '{other}' (apply|get|delete)")),
    }
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
