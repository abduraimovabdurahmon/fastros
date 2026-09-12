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
use alloc::sync::Arc;
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

use core::sync::atomic::{AtomicU16, Ordering as AOrd};
static NEXT_POD_PORT: AtomicU16 = AtomicU16::new(30000);

/// Allocate a unique backend port for a pod's declared container port, so
/// replicas of a fixed-port image can coexist on the shared network stack.
pub fn alloc_pod_port() -> u16 {
    let p = NEXT_POD_PORT.fetch_add(1, AOrd::Relaxed);
    if p >= 39990 {
        NEXT_POD_PORT.store(30000, AOrd::Relaxed);
        return 30000;
    }
    p
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
        port_remap: o.port_remap,
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
        port_remap: c.port_remap,
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
    // Ensure each Service has a proxy running (idempotent; restores them after a
    // reboot, when only the records persist).
    let sdir = alloc::format!("{base}/kube/services");
    for e in crate::fs::ops::list_dir(&kctx, &sdir).unwrap_or_default() {
        let Ok(d) = crate::fs::ops::read_file(&kctx, &alloc::format!("{sdir}/{}", e.name)) else { continue };
        let text = String::from_utf8_lossy(&d).into_owned();
        let mut it = text.lines();
        let port: u16 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
        let target: u16 = it.next().and_then(|x| x.parse().ok()).unwrap_or(port);
        let _selector = it.next();
        let workload = it.next().unwrap_or("").to_string();
        if port != 0 && !workload.is_empty() {
            start_service_proxy(e.name.clone(), port, target, workload);
        }
    }
}

// ── Service: a userspace ClusterIP load balancer ────────────────────────────

use alloc::collections::BTreeSet;
use crate::net::socket::{TcpListener, TcpStream};
use crate::net::{IpAddress, IpEndpoint};

/// Services with a proxy already running (one per service; it adapts to scaled
/// pods on the fly, so re-apply doesn't spawn a duplicate).
static SERVICE_PROXIES: SpinLock<BTreeSet<String>> = SpinLock::new(BTreeSet::new());

/// Start a load-balancing proxy for a Service: listen on `port`, round-robin
/// each connection to a running pod of `workload` (at the pod's actual backend
/// port for the service's `target` port). Exits when the service is deleted.
pub fn start_service_proxy(name: String, port: u16, target: u16, workload: String) {
    if !SERVICE_PROXIES.lock().insert(name.clone()) {
        return; // already running
    }
    crate::sched::spawn("kube-svc", move || {
        let listener = match TcpListener::bind(port, 64) {
            Ok(l) => l,
            Err(e) => {
                crate::kwarn!("kube", "service {}: cannot listen on :{}: {}", name, port, e);
                SERVICE_PROXIES.lock().remove(&name);
                return;
            }
        };
        crate::kinfo!("kube", "service {} proxying :{} -> {} pods", name, port, workload);
        let kctx = crate::fs::ops::Ctx::of(&crate::proc::kernel());
        let sdir = alloc::format!("{}/kube/services", super::store::base(&kctx));
        let mut rr: usize = 0;
        loop {
            // Stop once the service record is gone (kube delete).
            if crate::fs::ops::stat(&kctx, &alloc::format!("{sdir}/{name}"), true).is_err() {
                break;
            }
            match listener.try_accept() {
                Some((client, _)) => {
                    let backends = running_backends(&kctx, &workload, target);
                    if backends.is_empty() {
                        client.shutdown();
                        continue;
                    }
                    let b = backends[rr % backends.len()];
                    rr = rr.wrapping_add(1);
                    let client = Arc::new(client);
                    crate::sched::spawn("kube-svc-conn", move || proxy_conn(client, b));
                }
                None => {
                    crate::sched::sleep_ms(150);
                }
            }
        }
        crate::knotice!("kube", "service {} proxy stopped", name);
        SERVICE_PROXIES.lock().remove(&name);
    });
}

/// The backend ports of a workload's running pods (its actual remapped port, or
/// the target port if the pod has no remap).
fn running_backends(kctx: &crate::fs::ops::Ctx, workload: &str, target: u16) -> Vec<u16> {
    let base = super::store::base(kctx);
    let rec = crate::fs::ops::read_file(kctx, &alloc::format!("{base}/kube/workloads/{workload}"))
        .map(|d| String::from_utf8_lossy(&d).into_owned())
        .unwrap_or_default();
    let replicas: usize = rec.lines().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    let mut out = Vec::new();
    for n in 0..replicas {
        if let Ok(c) = super::container::find(kctx, &pod_name(workload, n)) {
            if c.live_state() == super::container::State::Running {
                out.push(c.port_remap.map(|(_, a)| a).unwrap_or(target));
            }
        }
    }
    out
}

/// Splice one client connection to a backend pod, both directions, until close.
fn proxy_conn(client: Arc<TcpStream>, backend_port: u16) {
    let ep = IpEndpoint::new(IpAddress::v4(127, 0, 0, 1), backend_port);
    let server = match TcpStream::connect(ep, 5000) {
        Ok(s) => Arc::new(s),
        Err(_) => {
            client.shutdown();
            return;
        }
    };
    let (c2, s2) = (client.clone(), server.clone());
    crate::sched::spawn("kube-svc-up", move || splice(&c2, &s2));
    splice(&server, &client);
}

fn splice(from: &Arc<TcpStream>, to: &Arc<TcpStream>) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    to.shutdown();
}
