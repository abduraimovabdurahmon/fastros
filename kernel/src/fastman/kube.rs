//! `fastman kube` — a small Kubernetes-style declarative layer over the
//! container runtime.
//!
//! Parses Kubernetes manifests (YAML, possibly multiple `---` documents) and
//! reconciles them to running containers:
//!
//! * **Deployment** → `spec.replicas` pods (containers) named
//!   `<name>-<n>`, from `spec.template.spec.containers[0]`.
//! * **Pod** → a single container.
//! * **Service** → recorded for `kube get services` (cross-pod routing needs
//!   per-pod network namespaces, a follow-up; a pod already binds its own port
//!   on the shared stack today).
//!
//! Pods carry the label prefix `<name>-` so `kube get pods` and `kube delete`
//! can find a workload's containers.

use super::compose::Yaml;
use super::container::{Port, Volume};
use super::runtime::RunOpts;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub struct Workload {
    pub kind: String, // "Deployment" or "Pod"
    pub name: String,
    pub replicas: usize,
    pub image: String,
    pub opts: RunOpts,
}

pub struct Service {
    pub name: String,
    pub port: u16,
    pub target: u16,
    pub selector: String,
}

#[derive(Default)]
pub struct Manifest {
    pub workloads: Vec<Workload>,
    pub services: Vec<Service>,
}

fn yaml_get<'a>(y: &'a Yaml, path: &[&str]) -> Option<&'a Yaml> {
    let mut cur = y;
    for k in path {
        cur = match cur {
            Yaml::Map(m) => m.iter().find(|(kk, _)| kk == k).map(|(_, v)| v)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn scalar<'a>(y: &'a Yaml, path: &[&str]) -> Option<&'a str> {
    match yaml_get(y, path)? {
        Yaml::Scalar(s) => Some(s),
        _ => None,
    }
}

fn as_list(y: &Yaml) -> &[Yaml] {
    match y {
        Yaml::List(l) => l,
        _ => &[],
    }
}

/// Build a container's RunOpts from a `containers[0]` spec.
fn container_opts(name: &str, c: &Yaml) -> (String, RunOpts) {
    let image = scalar(c, &["image"]).unwrap_or("").to_string();
    let mut opts = RunOpts { network: String::from("bridge"), detach: true, name: Some(name.to_string()), ..Default::default() };
    if let Some(cmd) = yaml_get(c, &["command"]) {
        opts.cmd = as_list(cmd).iter().filter_map(scalar_of).collect();
    }
    if let Some(args) = yaml_get(c, &["args"]) {
        opts.cmd.extend(as_list(args).iter().filter_map(scalar_of));
    }
    if let Some(env) = yaml_get(c, &["env"]) {
        for e in as_list(env) {
            if let (Some(k), Some(v)) = (scalar(e, &["name"]), scalar(e, &["value"])) {
                opts.env.push(alloc::format!("{k}={v}"));
            }
        }
    }
    if let Some(ports) = yaml_get(c, &["ports"]) {
        for p in as_list(ports) {
            if let Some(cp) = scalar(p, &["containerPort"]).and_then(|s| s.parse::<u16>().ok()) {
                // The pod binds its own port on the shared stack; record it so
                // `ps` shows it (host==container, best-effort without netns).
                opts.ports.push(Port { host: cp, container: cp, udp: false });
            }
        }
    }
    if let Some(vols) = yaml_get(c, &["volumeMounts"]) {
        // Best-effort: mountPath only (hostPath volumes are a follow-up).
        let _ = vols;
    }
    (image, opts)
}

fn scalar_of(y: &Yaml) -> Option<String> {
    match y {
        Yaml::Scalar(s) => Some(s.clone()),
        _ => None,
    }
}

/// Parse one or more manifest documents.
pub fn parse(src: &str) -> Manifest {
    let mut m = Manifest::default();
    for doc in split_documents(src) {
        let y = super::compose::parse_yaml(&doc);
        let kind = scalar(&y, &["kind"]).unwrap_or("").to_string();
        let name = scalar(&y, &["metadata", "name"]).unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        match kind.as_str() {
            "Deployment" => {
                let replicas = scalar(&y, &["spec", "replicas"]).and_then(|s| s.parse().ok()).unwrap_or(1);
                if let Some(c0) = yaml_get(&y, &["spec", "template", "spec", "containers"]).map(as_list).and_then(|l| l.first()) {
                    let (image, opts) = container_opts(&name, c0);
                    m.workloads.push(Workload { kind, name, replicas, image, opts });
                }
            }
            "Pod" => {
                if let Some(c0) = yaml_get(&y, &["spec", "containers"]).map(as_list).and_then(|l| l.first()) {
                    let (image, opts) = container_opts(&name, c0);
                    m.workloads.push(Workload { kind, name, replicas: 1, image, opts });
                }
            }
            "Service" => {
                let selector = scalar(&y, &["spec", "selector", "app"]).unwrap_or(&name).to_string();
                if let Some(p0) = yaml_get(&y, &["spec", "ports"]).map(as_list).and_then(|l| l.first()) {
                    let port = scalar(p0, &["port"]).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let target = scalar(p0, &["targetPort"]).and_then(|s| s.parse().ok()).unwrap_or(port);
                    m.services.push(Service { name, port, target, selector });
                }
            }
            _ => {}
        }
    }
    m
}

/// Split a YAML stream on `---` document separators.
fn split_documents(src: &str) -> Vec<String> {
    let mut docs = Vec::new();
    let mut cur = String::new();
    for line in src.lines() {
        if line.trim_start().starts_with("---") {
            if !cur.trim().is_empty() {
                docs.push(core::mem::take(&mut cur));
            }
            continue;
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        docs.push(cur);
    }
    docs
}

/// The pod (container) name for replica `i` of a workload.
pub fn pod_name(workload: &str, i: usize) -> String {
    alloc::format!("{workload}-{i}")
}

/// Clone RunOpts (it owns Vecs the runtime consumes) for each replica.
pub fn clone_opts(o: &RunOpts, name: String) -> RunOpts {
    RunOpts {
        name: Some(name),
        cmd: o.cmd.clone(),
        env: o.env.clone(),
        workdir: o.workdir.clone(),
        ports: o.ports.iter().map(|p| Port { host: p.host, container: p.container, udp: p.udp }).collect(),
        volumes: o.volumes.iter().map(|v| Volume { host: v.host.clone(), container: v.container.clone(), read_only: v.read_only }).collect(),
        network: o.network.clone(),
        detach: true,
        user: o.user,
    }
}

/// Build run options that faithfully clone an existing pod's container config
/// (command, env, ports, volumes, user) under a new pod name — used for
/// scaling a Deployment up.
pub fn opts_from_container(c: &super::container::Container, name: String) -> RunOpts {
    RunOpts {
        name: Some(name),
        cmd: c.cmd.clone(),
        env: c.env.clone(),
        workdir: if c.workdir.is_empty() { None } else { Some(c.workdir.clone()) },
        ports: c.ports.iter().map(|p| Port { host: p.host, container: p.container, udp: p.udp }).collect(),
        volumes: c.volumes.iter().map(|v| Volume { host: v.host.clone(), container: v.container.clone(), read_only: v.read_only }).collect(),
        network: c.network.clone(),
        detach: true,
        user: if c.uid == 0 && c.gid == 0 { None } else { Some((c.uid, c.gid)) },
    }
}

// ── self-healing controller ─────────────────────────────────────────────────

use crate::sync::SpinLock;
use alloc::collections::BTreeMap;

/// Per-pod restart counts, shown in `kube get pods` (like kubectl's RESTARTS).
static RESTARTS: SpinLock<BTreeMap<String, u32>> = SpinLock::new(BTreeMap::new());

pub fn restart_count(pod: &str) -> u32 {
    RESTARTS.lock().get(pod).copied().unwrap_or(0)
}

fn bump_restart(pod: &str) {
    *RESTARTS.lock().entry(pod.to_string()).or_insert(0) += 1;
}

/// Forget a pod's restart tally (on delete/scale-down).
pub fn forget_pod(pod: &str) {
    RESTARTS.lock().remove(pod);
}

/// Start the reconciliation loop: a background task that keeps each workload's
/// pods running, restarting any that have died — the core self-healing that
/// makes a Deployment a Deployment. Runs as root over `/var/lib/fastman/0`.
pub fn controller_start() {
    crate::sched::spawn("kube-controller", || loop {
        crate::sched::sleep_ms(3000);
        reconcile_once();
    });
}

fn reconcile_once() {
    let kctx = crate::fs::ops::Ctx::of(&crate::proc::kernel());
    let base = super::store::base(&kctx);
    let wdir = alloc::format!("{base}/kube/workloads");
    let Ok(list) = crate::fs::ops::list_dir(&kctx, &wdir) else { return };
    for e in list {
        let Ok(d) = crate::fs::ops::read_file(&kctx, &alloc::format!("{wdir}/{}", e.name)) else { continue };
        let rec = String::from_utf8_lossy(&d).into_owned();
        let replicas: usize = rec.lines().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
        for n in 0..replicas {
            let pod = pod_name(&e.name, n);
            if let Ok(mut c) = super::container::find(&kctx, &pod) {
                if c.live_state() != super::container::State::Running {
                    match super::runtime::start(&kctx, &mut c, None) {
                        Ok(_) => {
                            bump_restart(&pod);
                            crate::knotice!("kube", "restarted pod {} (self-healing)", pod);
                        }
                        Err(e) => crate::kwarn!("kube", "could not restart pod {}: {}", pod, e),
                    }
                }
            }
        }
    }
}
