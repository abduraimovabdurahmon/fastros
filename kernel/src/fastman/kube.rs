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
