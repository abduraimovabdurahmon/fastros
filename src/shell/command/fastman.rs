//! `fastman` shell command -- container image manager + runtime CLI.
//!
//! Subcommands:
//!   fastman pull   <image>             pull image from registry
//!   fastman images                     list locally available images
//!   fastman rmi    <image>             remove local image
//!   fastman inspect <image>            show manifest layers
//!   fastman run    [OPTIONS] <image>   create and start a container
//!   fastman ps     [-a]                list containers
//!   fastman stop   <id>                stop a running container
//!   fastman rm     [-f] <id>           remove a stopped container
//!   fastman exec   <id> <cmd>          run a command in a container
//!   fastman logs   <id>                show container logs

use super::Command;
use crate::shell::env::ShellEnv;
use crate::shell::io::ShellIo;
use crate::fastman;
use crate::fastman::store;
use crate::fastman::runtime;
use crate::fastman::container::{ContainerConfig, CState, PortMap};

// -- Command singleton ---------------------------------------------------------

pub struct FastmanCommand;
pub static FASTMAN: FastmanCommand = FastmanCommand;

impl Command for FastmanCommand {
    fn name(&self)        -> &'static str { "fastman" }
    fn description(&self) -> &'static str { "Container manager (pull, run, ps, stop, rm, ...)" }

    fn execute(&self, args: &[&[u8]], _env: &mut ShellEnv, io: &mut dyn ShellIo) -> i32 {
        if args.is_empty() {
            print_usage(io);
            return 1;
        }

        match args[0] {
            b"pull"    => cmd_pull(&args[1..], io),
            b"images"  => cmd_images(io),
            b"rmi"     => cmd_rmi(&args[1..], io),
            b"inspect" => cmd_inspect(&args[1..], io),
            b"run"     => cmd_run(&args[1..], io),
            b"ps"      => cmd_ps(&args[1..], io),
            b"stop"    => cmd_stop(&args[1..], io),
            b"rm"      => cmd_rm(&args[1..], io),
            b"exec"    => cmd_exec(&args[1..], io),
            b"logs"    => cmd_logs(&args[1..], io),
            b"help"    => { print_usage(io); 0 }
            other => {
                io.write_bytes(b"fastman: unknown subcommand '");
                io.write_bytes(other);
                io.write_bytes(b"'  (try 'fastman help')\n");
                1
            }
        }
    }
}

// -- Image subcommands ---------------------------------------------------------

fn cmd_pull(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman pull <image>[:<tag>]\n");
        return 1;
    }
    let mut out = IoOut(io);
    if fastman::pull(args[0], &mut out) { 0 } else { 1 }
}

fn cmd_images(io: &mut dyn ShellIo) -> i32 {
    let images = store::list();
    if images.is_empty() {
        io.write_bytes(b"No images. Use 'fastman pull <image>' to pull one.\n");
        return 0;
    }
    io.write_bytes(b"IMAGE ID      REPOSITORY                     TAG                SIZE\n");
    io.write_bytes(b"------------  -----------------------------  -----------------  --------\n");
    for img in images.iter().filter(|i| i.valid) {
        io.write_bytes(img.id());
        io.write_bytes(b"  ");
        pad_write(io, img.name(), 29);
        io.write_bytes(b"  ");
        pad_write(io, img.tag(), 17);
        io.write_bytes(b"  ");
        let mut buf = [0u8; 16];
        io.write_bytes(store::fmt_size(img.total_size, &mut buf));
        io.write_bytes(b"\n");
    }
    0
}

fn cmd_rmi(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman rmi <image>[:<tag>]\n");
        return 1;
    }
    let (name, tag) = split_name_tag(args[0]);
    let tag = tag.unwrap_or(b"latest");
    if store::remove(name, tag) {
        io.write_bytes(b"Deleted: "); io.write_bytes(name);
        io.write_bytes(b":"); io.write_bytes(tag); io.write_bytes(b"\n");
        0
    } else {
        io.write_bytes(b"fastman: image not found: "); io.write_bytes(args[0]); io.write_bytes(b"\n");
        1
    }
}

fn cmd_inspect(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman inspect <image>[:<tag>]\n");
        return 1;
    }
    let (name, tag) = split_name_tag(args[0]);
    let tag      = tag.unwrap_or(b"latest");
    let full     = full_image_name(name);
    let img = match store::find(full, tag).or_else(|| store::find(name, tag)) {
        Some(i) => i,
        None => { io.write_bytes(b"fastman: image not found (pull it first)\n"); return 1; }
    };
    io.write_bytes(b"Image: "); io.write_bytes(img.name());
    io.write_bytes(b":"); io.write_bytes(img.tag());
    io.write_bytes(b"\nID:    "); io.write_bytes(img.id());
    io.write_bytes(b"\nLayers:\n");
    for i in 0..img.layer_count {
        let layer = &img.layers[i];
        io.write_bytes(b"  ["); write_u64(io, i as u64 + 1); io.write_bytes(b"] ");
        io.write_bytes(layer.digest_str()); io.write_bytes(b"  ");
        let mut buf = [0u8; 16];
        io.write_bytes(store::fmt_size(layer.size, &mut buf)); io.write_bytes(b"\n");
    }
    let mut total_buf = [0u8; 16];
    io.write_bytes(b"Total: ");
    io.write_bytes(store::fmt_size(img.total_size, &mut total_buf));
    io.write_bytes(b"\n");
    0
}

// -- fastman run ---------------------------------------------------------------

fn cmd_run(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        print_run_usage(io);
        return 1;
    }

    let cfg = match parse_run_args(args) {
        Some(c) => c,
        None => { print_run_usage(io); return 1; }
    };

    let mut out = IoOut(io);
    match fastman::run(&cfg, &mut out) {
        Some(_id) => 0,
        None      => 1,
    }
}

fn parse_run_args(args: &[&[u8]]) -> Option<ContainerConfig> {
    let mut cfg = ContainerConfig::empty();
    let mut i   = 0usize;

    while i < args.len() {
        let arg = args[i];

        if arg == b"-d" || arg == b"--detach" {
            cfg.detach = true;
            i += 1;

        } else if arg == b"--rm" {
            cfg.auto_rm = true;
            i += 1;

        } else if arg == b"-p" || arg == b"--publish" {
            i += 1;
            if i >= args.len() { return None; }
            add_port_map(args[i], &mut cfg);
            i += 1;

        } else if arg.starts_with(b"-p=") {
            add_port_map(&arg[3..], &mut cfg);
            i += 1;

        } else if arg == b"-m" || arg == b"--memory" {
            i += 1;
            if i >= args.len() { return None; }
            cfg.memory_mb = parse_memory(args[i]);
            i += 1;

        } else if arg.starts_with(b"-m=") {
            cfg.memory_mb = parse_memory(&arg[3..]);
            i += 1;

        } else if arg.starts_with(b"--memory=") {
            cfg.memory_mb = parse_memory(&arg[9..]);
            i += 1;

        } else if arg == b"--cpu" || arg == b"--cpus" {
            i += 1;
            if i >= args.len() { return None; }
            cfg.cpu_pct = parse_pct(args[i]);
            i += 1;

        } else if arg.starts_with(b"--cpu=") {
            cfg.cpu_pct = parse_pct(&arg[6..]);
            i += 1;

        } else if arg == b"--name" {
            i += 1;
            if i >= args.len() { return None; }
            let nl = args[i].len().min(63);
            cfg.name_override[..nl].copy_from_slice(&args[i][..nl]);
            cfg.name_override_len = nl;
            i += 1;

        } else if arg.starts_with(b"--name=") {
            let n = &arg[7..];
            let nl = n.len().min(63);
            cfg.name_override[..nl].copy_from_slice(&n[..nl]);
            cfg.name_override_len = nl;
            i += 1;

        } else if arg == b"-e" || arg == b"--env" {
            // Accept but ignore env vars for now (stored when env table added)
            i += 2;

        } else if arg == b"-it" || arg == b"-ti" || arg == b"-i" || arg == b"-t" {
            // Interactive / TTY flags -- detach=false (already default)
            i += 1;

        } else if arg.starts_with(b"-") {
            // Unknown flag -- skip
            i += 1;

        } else {
            // First non-flag arg = IMAGE[:TAG]
            break;
        }
    }

    if i >= args.len() { return None; }

    // Parse image reference
    let image_str = args[i];
    i += 1;

    // Split host:port/name:tag properly using ImageRef logic
    // For the shell command, we do a simpler split: last ':' after last '/'
    let (name_part, tag_part) = split_name_tag(image_str);
    let tag = tag_part.unwrap_or(b"latest");

    let nl = name_part.len().min(127);
    cfg.image[..nl].copy_from_slice(&name_part[..nl]);
    cfg.image_len = nl;

    let tl = tag.len().min(63);
    cfg.tag[..tl].copy_from_slice(&tag[..tl]);
    cfg.tag_len = tl;

    // Rest of args = command
    let mut cmd_pos = 0usize;
    while i < args.len() {
        let part = args[i];
        if cmd_pos > 0 && cmd_pos < 255 {
            cfg.cmd[cmd_pos] = b' '; cmd_pos += 1;
        }
        let n = part.len().min(255 - cmd_pos);
        cfg.cmd[cmd_pos..cmd_pos + n].copy_from_slice(&part[..n]);
        cmd_pos += n;
        i += 1;
    }
    cfg.cmd_len = cmd_pos;

    if cfg.image_len == 0 { return None; }
    Some(cfg)
}

fn add_port_map(s: &[u8], cfg: &mut ContainerConfig) {
    if cfg.port_count >= crate::fastman::container::MAX_PORTS { return; }
    // Format: "host_port:container_port" or just "container_port"
    if let Some(col) = s.iter().position(|&b| b == b':') {
        let hp = parse_port(&s[..col]);
        let cp = parse_port(&s[col + 1..]);
        if hp > 0 && cp > 0 {
            cfg.ports[cfg.port_count] = PortMap { host_port: hp, container_port: cp };
            cfg.port_count += 1;
        }
    } else {
        let p = parse_port(s);
        if p > 0 {
            cfg.ports[cfg.port_count] = PortMap { host_port: p, container_port: p };
            cfg.port_count += 1;
        }
    }
}

fn parse_port(s: &[u8]) -> u16 {
    // Strip optional "0.0.0.0:" prefix
    let s = if let Some(p) = s.iter().rposition(|&b| b == b':') { &s[p + 1..] } else { s };
    let mut v = 0u32;
    for &b in s {
        if b >= b'0' && b <= b'9' { v = v * 10 + (b - b'0') as u32; }
        else { break; }
    }
    v.min(65535) as u16
}

fn parse_memory(s: &[u8]) -> u64 {
    // e.g. "512m", "1g", "256M", "1G", "1024"
    let mut v = 0u64;
    let mut i = 0;
    while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
        v = v * 10 + (s[i] - b'0') as u64;
        i += 1;
    }
    let unit = if i < s.len() { s[i].to_ascii_lowercase() } else { 0 };
    match unit {
        b'g' => v * 1024,
        b'm' => v,
        b'k' => v / 1024,
        _    => v / (1024 * 1024), // assume bytes
    }
}

fn parse_pct(s: &[u8]) -> u8 {
    let mut v = 0u32;
    for &b in s {
        if b >= b'0' && b <= b'9' { v = v * 10 + (b - b'0') as u32; }
        else { break; }
    }
    v.min(100) as u8
}

fn print_run_usage(io: &mut dyn ShellIo) {
    io.write_bytes(b"usage: fastman run [OPTIONS] IMAGE[:TAG] [COMMAND [ARG...]]\n\n");
    io.write_bytes(b"Options:\n");
    io.write_bytes(b"  -d, --detach        Run container in background\n");
    io.write_bytes(b"  -p HOST:CONTAINER   Publish a port  (e.g. -p 8080:80)\n");
    io.write_bytes(b"  -m SIZE             Memory limit    (e.g. -m 512m, -m 1g)\n");
    io.write_bytes(b"  --cpu PCT           CPU quota 0-100 (e.g. --cpu 50)\n");
    io.write_bytes(b"  --name NAME         Assign a name to the container\n");
    io.write_bytes(b"  --rm                Auto-remove container when it exits\n\n");
    io.write_bytes(b"Examples:\n");
    io.write_bytes(b"  fastman run nginx:latest\n");
    io.write_bytes(b"  fastman run -d -p 80:80 nginx:latest\n");
    io.write_bytes(b"  fastman run -d -m 512m --cpu 50 --name web nginx:latest\n");
    io.write_bytes(b"  fastman run -d quay.io/prometheus/prometheus:latest\n");
}

// -- fastman ps ----------------------------------------------------------------

fn cmd_ps(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    let show_all = args.iter().any(|&a| a == b"-a" || a == b"--all");

    // Header
    io.write_bytes(b"CONTAINER ID  IMAGE                          COMMAND     STATUS      PORTS                     NAMES\n");
    io.write_bytes(b"------------  -----------------------------  ----------  ----------  ------------------------  ---------------------\n");

    let mut shown = false;
    for rec in runtime::list().iter().filter(|r| r.valid) {
        match rec.state {
            CState::Exited(_) | CState::Created if !show_all => continue,
            _ => {}
        }
        shown = true;

        // CONTAINER ID
        io.write_bytes(rec.id());
        io.write_bytes(b"  ");

        // IMAGE
        let image_tag = format_image_tag(rec);
        pad_write(io, image_tag, 29);
        io.write_bytes(b"  ");

        // COMMAND
        let cmd = if rec.config.cmd_len > 0 { rec.config.cmd() } else { b"<default>" };
        pad_write(io, cmd, 10);
        io.write_bytes(b"  ");

        // STATUS
        pad_write(io, rec.state.label(), 10);
        io.write_bytes(b"  ");

        // PORTS
        if rec.config.port_count > 0 {
            let pm = &rec.config.ports[0];
            io.write_bytes(b"0.0.0.0:");
            write_u64(io, pm.host_port as u64);
            io.write_bytes(b"->");
            write_u64(io, pm.container_port as u64);
            io.write_bytes(b"/tcp");
            if rec.config.port_count > 1 {
                io.write_bytes(b", ...");
            }
            // Pad to 24
            let written = 8 + port_digits(pm.host_port) + 2
                + port_digits(pm.container_port) + 4
                + if rec.config.port_count > 1 { 5 } else { 0 };
            for _ in written..24 { io.write_bytes(b" "); }
        } else {
            pad_write(io, b"", 24);
        }
        io.write_bytes(b"  ");

        // NAMES
        io.write_bytes(rec.name());
        io.write_bytes(b"\n");
    }

    if !shown {
        if show_all {
            io.write_bytes(b"(no containers)\n");
        } else {
            io.write_bytes(b"(no running containers -- use 'fastman ps -a' to show all)\n");
        }
    }
    0
}

static mut IMG_TAG_BUF: [u8; 64] = [0; 64];

fn format_image_tag(rec: &crate::fastman::container::ContainerRecord) -> &[u8] {
    let buf = unsafe { &mut IMG_TAG_BUF };
    let il = rec.config.image_len.min(40);
    buf[..il].copy_from_slice(&rec.config.image[..il]);
    buf[il] = b':';
    let tl = rec.config.tag_len.min(20);
    buf[il + 1..il + 1 + tl].copy_from_slice(&rec.config.tag[..tl]);
    unsafe { &IMG_TAG_BUF[..il + 1 + tl] }
}

fn port_digits(p: u16) -> usize {
    if p >= 10000 { 5 }
    else if p >= 1000 { 4 }
    else if p >= 100  { 3 }
    else if p >= 10   { 2 }
    else              { 1 }
}

// -- fastman stop --------------------------------------------------------------

fn cmd_stop(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman stop <container>\n");
        return 1;
    }
    let mut out = IoOut(io);
    let mut rc  = 0i32;
    for &id in args.iter() {
        if !runtime::stop(id, &mut out) { rc = 1; }
    }
    rc
}

// -- fastman rm ----------------------------------------------------------------

fn cmd_rm(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman rm [-f] <container> [container...]\n");
        return 1;
    }
    let mut force = false;
    let mut out   = IoOut(io);
    let mut rc    = 0i32;
    for &a in args.iter() {
        if a == b"-f" || a == b"--force" { force = true; continue; }
        if !runtime::rm(a, force, &mut out) { rc = 1; }
    }
    rc
}

// -- fastman exec --------------------------------------------------------------

fn cmd_exec(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.len() < 2 {
        io.write_bytes(b"usage: fastman exec <container> <command> [args]\n");
        return 1;
    }
    // Build command string from remaining args
    let mut cmd_buf = [0u8; 256];
    let mut cmd_len = 0usize;
    for &part in &args[1..] {
        if cmd_len > 0 && cmd_len < 255 { cmd_buf[cmd_len] = b' '; cmd_len += 1; }
        let n = part.len().min(255 - cmd_len);
        cmd_buf[cmd_len..cmd_len + n].copy_from_slice(&part[..n]);
        cmd_len += n;
    }
    let mut out = IoOut(io);
    if runtime::exec(args[0], &cmd_buf[..cmd_len], &mut out) { 0 } else { 1 }
}

// -- fastman logs --------------------------------------------------------------

fn cmd_logs(args: &[&[u8]], io: &mut dyn ShellIo) -> i32 {
    if args.is_empty() {
        io.write_bytes(b"usage: fastman logs <container>\n");
        return 1;
    }
    // Skip flags like --follow, --tail, etc.
    let id = args.iter().find(|&&a| !a.starts_with(b"-")).copied();
    match id {
        Some(id) => {
            let mut out = IoOut(io);
            if runtime::logs(id, &mut out) { 0 } else { 1 }
        }
        None => {
            io.write_bytes(b"fastman: logs requires a container name or ID\n");
            1
        }
    }
}

// -- Usage ---------------------------------------------------------------------

fn print_usage(io: &mut dyn ShellIo) {
    io.write_bytes(b"fastman -- FastROS container manager\n\n");
    io.write_bytes(b"Usage: fastman <subcommand> [args]\n\n");
    io.write_bytes(b"Image management:\n");
    io.write_bytes(b"  pull  <image>[:tag]         Pull image from registry\n");
    io.write_bytes(b"  images                      List local images\n");
    io.write_bytes(b"  rmi   <image>[:tag]         Remove a local image\n");
    io.write_bytes(b"  inspect <image>[:tag]       Show layer details\n\n");
    io.write_bytes(b"Container lifecycle:\n");
    io.write_bytes(b"  run   [opts] <image> [cmd]  Create and start a container\n");
    io.write_bytes(b"  ps    [-a]                  List containers\n");
    io.write_bytes(b"  stop  <container>           Stop a running container\n");
    io.write_bytes(b"  rm    [-f] <container>      Remove a container\n");
    io.write_bytes(b"  exec  <container> <cmd>     Run a command in a container\n");
    io.write_bytes(b"  logs  <container>           Fetch container logs\n\n");
    io.write_bytes(b"Examples:\n");
    io.write_bytes(b"  fastman pull nginx:latest\n");
    io.write_bytes(b"  fastman run -d -p 80:80 nginx:latest\n");
    io.write_bytes(b"  fastman run -d -m 512m --name web nginx:latest\n");
    io.write_bytes(b"  fastman ps\n");
    io.write_bytes(b"  fastman logs web\n");
    io.write_bytes(b"  fastman stop web && fastman rm web\n\n");
    io.write_bytes(b"Isolation: pid/mnt/net namespaces + cgroups. No root required.\n");
    io.write_bytes(b"Registry:  plain HTTP (local) + TLS 1.3 (Docker Hub, quay.io).\n");
}

// -- Output adapter ------------------------------------------------------------

struct IoOut<'a>(&'a mut dyn ShellIo);

impl<'a> fastman::Output for IoOut<'a> {
    fn print(&mut self, s: &[u8]) {
        let mut start = 0;
        for (i, &b) in s.iter().enumerate() {
            if b == b'\n' {
                if i > start { self.0.write_bytes(&s[start..i]); }
                self.0.newline();
                start = i + 1;
            }
        }
        if start < s.len() { self.0.write_bytes(&s[start..]); }
    }
}

// -- Helpers -------------------------------------------------------------------

/// Split "name:tag" at the last ':' after the last '/'.
fn split_name_tag(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    let search_from = s.iter().rposition(|&b| b == b'/').map(|p| p + 1).unwrap_or(0);
    if let Some(rel) = s[search_from..].iter().position(|&b| b == b':') {
        let abs = search_from + rel;
        (&s[..abs], Some(&s[abs + 1..]))
    } else {
        (s, None)
    }
}

static mut NAME_BUF: [u8; 136] = [0; 136];
fn full_image_name(name: &[u8]) -> &'static [u8] {
    let buf = unsafe { &mut NAME_BUF };
    if name.contains(&b'/') {
        let nl = name.len().min(136);
        buf[..nl].copy_from_slice(&name[..nl]);
        return unsafe { &NAME_BUF[..nl] };
    }
    let prefix = b"library/";
    buf[..prefix.len()].copy_from_slice(prefix);
    let nl = name.len().min(127);
    buf[prefix.len()..prefix.len() + nl].copy_from_slice(&name[..nl]);
    let total = prefix.len() + nl;
    unsafe { &NAME_BUF[..total] }
}

fn pad_write(io: &mut dyn ShellIo, s: &[u8], width: usize) {
    let n = s.len().min(width);
    io.write_bytes(&s[..n]);
    for _ in n..width { io.write_bytes(b" "); }
}

fn write_u64(io: &mut dyn ShellIo, n: u64) {
    if n == 0 { io.write_bytes(b"0"); return; }
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    let mut v = n;
    while v > 0 { pos -= 1; buf[pos] = b'0' + (v % 10) as u8; v /= 10; }
    io.write_bytes(&buf[pos..]);
}
