//! fastman: container query commands (stop, rm, logs, inspect, stats).
use super::*;
use crate::fastman::container;
use crate::fastman::runtime;
use crate::outln;
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub(super) fn stop(ctx: &mut Ctx, args: &[String]) -> i32 {
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

pub(super) fn rm(ctx: &mut Ctx, args: &[String]) -> i32 {
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

pub(super) fn logs(ctx: &mut Ctx, args: &[String]) -> i32 {
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
pub(super) fn logs_follow(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, c: &container::Container) -> i32 {
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
pub(super) fn json_str(s: &str) -> String {
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
pub(super) fn json_str_array(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| json_str(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// `fastman inspect <container>...`: emit a Docker-style JSON array describing
/// each container's config, state and network. Faithful to the fields fastman
/// actually models (no invented Docker keys).
pub(super) fn inspect(ctx: &mut Ctx, args: &[String]) -> i32 {
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
pub(super) fn proc_subtree(root: u32, children: &alloc::collections::BTreeMap<u32, Vec<u32>>) -> Vec<u32> {
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
pub(super) fn stats(ctx: &mut Ctx, args: &[String]) -> i32 {
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
