//! fastman: compose + Kubernetes-style orchestration commands.
use super::pull::CliProgress;
use super::*;
use crate::fastman::container::{self, State};
use crate::fastman::image;
use crate::fastman::runtime::{self, RunOpts};
use crate::outln;
use crate::shell::ctx::Ctx;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// `fastman compose [-f file] [-p project] <up [-d]|down|ps|logs [svc]>`.
pub(super) fn compose(ctx: &mut Ctx, args: &[String]) -> i32 {
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
pub(super) fn kube(ctx: &mut Ctx, args: &[String]) -> i32 {
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
            if m.workloads.is_empty() && m.services.is_empty() && m.configs.is_empty() {
                return ctx.fail(format!("{path}: no Deployment/Pod/Service/ConfigMap/Secret found"));
            }
            let base = crate::fastman::store::base(&fc);
            let _ = crate::fs::ops::mkdir_all(&fc, &wdir, 0o700);
            let _ = crate::fs::ops::mkdir_all(&fc, &sdir, 0o700);
            // ConfigMaps/Secrets first, so workloads in the same file can use them.
            for cfgo in &m.configs {
                match crate::fastman::kube::save_config(&fc, &base, cfgo) {
                    Ok(()) => outln!(ctx, "{} {} created", s.green(&cfgo.kind), cfgo.name),
                    Err(e) => {
                        ctx.fail_errno(&cfgo.name, e);
                    }
                }
            }
            for w in &m.workloads {
                if image::resolve(&fc, &w.image).is_none() {
                    ctx.fail(format!("{}: image '{}' not found", w.name, w.image));
                    continue;
                }
                let declared = w.opts.ports.first().map(|p| p.container);
                // Resolve envFrom (configMapRef/secretRef) into concrete env vars.
                let mut injected: Vec<String> = Vec::new();
                for (kind, name) in &w.env_from {
                    match crate::fastman::kube::load_config_obj(&fc, &base, kind, name) {
                        Some(kvs) => injected.extend(kvs.into_iter().map(|(k, v)| format!("{k}={v}"))),
                        None => outln!(ctx, "{}: {kind} '{name}' not found", w.name),
                    }
                }
                let rec = format!("{}\n{}\n{}\n", w.kind, w.replicas, w.image);
                let _ = crate::fs::ops::write_file(&fc, &format!("{wdir}/{}", w.name), rec.as_bytes(), 0o600);
                for n in 0..w.replicas {
                    let pod = crate::fastman::kube::pod_name(&w.name, n);
                    let _ = runtime::remove(&fc, &pod, true);
                    let mut opts = crate::fastman::kube::clone_opts(&w.opts, pod.clone());
                    // envFrom is injected first so explicit `env:` (already in
                    // opts.env) takes precedence.
                    if !injected.is_empty() {
                        let mut merged = injected.clone();
                        merged.extend(core::mem::take(&mut opts.env));
                        opts.env = merged;
                    }
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
            if matches!(what, "configmaps" | "configmap" | "cm" | "secrets" | "secret") {
                let kind = if what.starts_with("secret") { "secret" } else { "configmap" };
                let base = crate::fastman::store::base(&fc);
                let dir = crate::fastman::kube::configs_dir(&base, kind);
                let mut t = Table::new(&["NAME", "KEYS"]);
                for e in crate::fs::ops::list_dir(&fc, &dir).unwrap_or_default() {
                    let keys = crate::fastman::kube::load_config_obj(&fc, &base, kind, &e.name).map(|kv| kv.len()).unwrap_or(0);
                    t.row(alloc::vec![e.name.clone(), format!("{keys}")]);
                }
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
            let base = crate::fastman::store::base(&fc);
            for kind in ["configmap", "secret"] {
                let p = format!("{}/{name}", crate::fastman::kube::configs_dir(&base, kind));
                if crate::fs::ops::unlink(&fc, &p).is_ok() {
                    outln!(ctx, "{kind} \"{name}\" deleted");
                    return 0;
                }
            }
            ctx.fail(format!("{name}: not found"))
        }
        "create" => kube_create(ctx, &fc, &rest),
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
        "port-forward" => kube_port_forward(ctx, &fc, &rest),
        other => ctx.fail(format!("unknown kube command '{other}' (apply|create|get|delete|scale|rollout|logs|exec|describe|port-forward)")),
    }
}

/// Strip a `kind/name` prefix (`deployment/web` → `web`).
pub(super) fn bare_name(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

/// `kube scale <name> --replicas=N` (or `deployment/<name> N`).
pub(super) fn kube_scale(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, rest: &[String]) -> i32 {
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
pub(super) fn kube_rollout(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, rest: &[String]) -> i32 {
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
pub(super) fn kube_describe(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, wdir: &str, sdir: &str, rest: &[String]) -> i32 {
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
pub(super) fn clone_opts(o: &RunOpts) -> RunOpts {
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


/// `fastman kube port-forward <pod|deployment> <local:remote>` — forward a local
/// port to a pod's port over the loopback (runs until ^C).
fn kube_port_forward(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, rest: &[String]) -> i32 {
    let a: Vec<&String> = rest.iter().filter(|s| !s.starts_with('-')).collect();
    if a.len() < 2 {
        return ctx.fail("port-forward requires POD and LOCAL:REMOTE");
    }
    let target = bare_name(a[0]);
    // Resolve to a container: an exact pod name, or a deployment's first pod.
    let cid = match container::find(fc, &target) {
        Ok(c) => c.id,
        Err(_) => match container::find(fc, &crate::fastman::kube::pod_name(&target, 0)) {
            Ok(c) => c.id,
            Err(e) => return ctx.fail_errno(&target, e),
        },
    };
    let (local, remote) = match a[1].split_once(':') {
        Some((l, r)) => (l.parse::<u16>().ok(), r.parse::<u16>().ok()),
        None => (a[1].parse::<u16>().ok(), a[1].parse::<u16>().ok()),
    };
    let (Some(local), Some(remote)) = (local, remote) else {
        return ctx.fail("port must be LOCAL:REMOTE");
    };
    // The pod's declared container port maps to a backend port on the host stack.
    let actual = crate::net::remap_pod_port(&cid, remote);
    outln!(ctx, "Forwarding from 127.0.0.1:{local} -> {remote}");
    ctx.flush();
    match crate::fastman::proxy::port_forward(local, actual) {
        Ok(()) => 0,
        Err(e) => ctx.fail_errno("port-forward", e),
    }
}

/// `fastman kube create configmap|secret [generic] NAME --from-literal=K=V ...`
fn kube_create(ctx: &mut Ctx, fc: &crate::fs::ops::Ctx, rest: &[String]) -> i32 {
    let mut it = rest.iter().peekable();
    let kind = match it.next().map(|s| s.as_str()) {
        Some("configmap") | Some("cm") => "configmap",
        Some("secret") => {
            // `secret generic NAME ...` — skip the optional type word.
            if it.peek().map(|s| s.as_str()) == Some("generic") {
                it.next();
            }
            "secret"
        }
        _ => return ctx.fail("usage: kube create configmap|secret NAME --from-literal=K=V ..."),
    };
    let rest2: Vec<&String> = it.collect();
    let Some(name) = rest2.iter().find(|a| !a.starts_with('-')).map(|s| s.to_string()) else {
        return ctx.fail("create requires a NAME");
    };
    let mut data: Vec<(String, String)> = Vec::new();
    for a in &rest2 {
        if let Some(kv) = a.strip_prefix("--from-literal=") {
            if let Some((k, v)) = kv.split_once('=') {
                data.push((k.to_string(), v.to_string()));
            }
        }
    }
    let base = crate::fastman::store::base(fc);
    let obj = crate::fastman::kube::ConfigObject { kind: kind.to_string(), name: name.clone(), data };
    let s = style_of(ctx);
    match crate::fastman::kube::save_config(fc, &base, &obj) {
        Ok(()) => {
            outln!(ctx, "{} {name} created", s.green(kind));
            0
        }
        Err(e) => ctx.fail_errno(&name, e),
    }
}
