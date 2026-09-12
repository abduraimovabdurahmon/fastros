//! Container records: identity, configuration, lifecycle state, and on-disk
//! persistence. Rootless — every record lives under the owner's store.

use super::store;
use crate::errno::{Errno, KResult};
use crate::fs::ops::{self, Ctx};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Created,
    Running,
    Exited,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Created => "created",
            State::Running => "running",
            State::Exited => "exited",
        }
    }
    fn parse(s: &str) -> State {
        match s {
            "running" => State::Running,
            "exited" => State::Exited,
            _ => State::Created,
        }
    }
}

/// A published port: `host:container/proto`.
#[derive(Clone, Copy, Debug)]
pub struct Port {
    pub host: u16,
    pub container: u16,
    pub udp: bool,
}

/// A bind mount: a host directory made visible inside the container.
#[derive(Clone, Debug)]
pub struct Volume {
    pub host: String,
    pub container: String,
    pub read_only: bool,
}

#[derive(Clone, Debug)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image_key: String,
    pub image_id: String,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub workdir: String,
    pub state: State,
    pub pid: u32,
    pub exit_code: i32,
    pub created: u64,
    pub ports: Vec<Port>,
    pub volumes: Vec<Volume>,
    pub network: String,
    pub detach: bool,
    /// The uid/gid the container process runs as (0 = the caller's identity, the
    /// default). `--user` sets these so an image that refuses to run as root
    /// (postgres/initdb) can drop to its own user.
    pub uid: u32,
    pub gid: u32,
    /// Kubernetes pod port remap: (declared container port, actual backend port
    /// on the shared stack). Lets replicas of a fixed-port image coexist.
    pub port_remap: Option<(u16, u16)>,
}

impl Container {
    pub fn dir(&self, ctx: &Ctx) -> String {
        format!("{}/{}", store::containers_dir(ctx), self.id)
    }
    pub fn rootfs(&self, ctx: &Ctx) -> String {
        format!("{}/{}/rootfs", store::containers_dir(ctx), self.id)
    }
    pub fn log_path(&self, ctx: &Ctx) -> String {
        format!("{}/{}/log", store::containers_dir(ctx), self.id)
    }

    /// True if the init process is still alive.
    pub fn is_alive(&self) -> bool {
        self.pid != 0 && crate::proc::find(self.pid).is_some_and(|p| !p.is_zombie())
    }

    /// The state reconciled with reality (a running record whose process is
    /// gone is really exited).
    pub fn live_state(&self) -> State {
        if self.state == State::Running && !self.is_alive() {
            State::Exited
        } else {
            self.state
        }
    }

    fn encode(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("id\t{}\n", self.id));
        s.push_str(&format!("name\t{}\n", self.name));
        s.push_str(&format!("image_key\t{}\n", self.image_key));
        s.push_str(&format!("image_id\t{}\n", self.image_id));
        s.push_str(&format!("state\t{}\n", self.state.as_str()));
        s.push_str(&format!("pid\t{}\n", self.pid));
        s.push_str(&format!("exit_code\t{}\n", self.exit_code));
        s.push_str(&format!("created\t{}\n", self.created));
        s.push_str(&format!("workdir\t{}\n", self.workdir));
        s.push_str(&format!("network\t{}\n", self.network));
        s.push_str(&format!("detach\t{}\n", self.detach as u8));
        s.push_str(&format!("user\t{}\t{}\n", self.uid, self.gid));
        for c in &self.cmd {
            s.push_str(&format!("cmd\t{c}\n"));
        }
        for e in &self.env {
            s.push_str(&format!("env\t{e}\n"));
        }
        for p in &self.ports {
            s.push_str(&format!("port\t{}\t{}\t{}\n", p.host, p.container, p.udp as u8));
        }
        for v in &self.volumes {
            s.push_str(&format!("volume\t{}\t{}\t{}\n", v.host, v.container, v.read_only as u8));
        }
        if let Some((d, a)) = self.port_remap {
            s.push_str(&format!("remap\t{d}\t{a}\n"));
        }
        s
    }

    fn decode(text: &str) -> Option<Container> {
        let mut c = Container {
            id: String::new(),
            name: String::new(),
            image_key: String::new(),
            image_id: String::new(),
            cmd: Vec::new(),
            env: Vec::new(),
            workdir: String::from("/"),
            state: State::Created,
            pid: 0,
            exit_code: 0,
            created: 0,
            ports: Vec::new(),
            volumes: Vec::new(),
            network: String::from("bridge"),
            detach: false,
            uid: 0,
            gid: 0,
            port_remap: None,
        };
        for line in text.lines() {
            let mut it = line.split('\t');
            let key = it.next().unwrap_or("");
            let v = it.next().unwrap_or("");
            match key {
                "id" => c.id = v.to_string(),
                "name" => c.name = v.to_string(),
                "image_key" => c.image_key = v.to_string(),
                "image_id" => c.image_id = v.to_string(),
                "state" => c.state = State::parse(v),
                "pid" => c.pid = v.parse().unwrap_or(0),
                "exit_code" => c.exit_code = v.parse().unwrap_or(0),
                "created" => c.created = v.parse().unwrap_or(0),
                "workdir" => c.workdir = v.to_string(),
                "network" => c.network = v.to_string(),
                "detach" => c.detach = v == "1",
                "user" => {
                    c.uid = v.parse().unwrap_or(0);
                    c.gid = it.next().unwrap_or("0").parse().unwrap_or(0);
                }
                "cmd" => c.cmd.push(v.to_string()),
                "env" => c.env.push(v.to_string()),
                "port" => {
                    if let (Ok(h), Ok(cp)) = (v.parse(), it.next().unwrap_or("0").parse()) {
                        c.ports.push(Port { host: h, container: cp, udp: it.next() == Some("1") });
                    }
                }
                "volume" => {
                    let host = v.to_string();
                    let container = it.next().unwrap_or("").to_string();
                    c.volumes.push(Volume { host, container, read_only: it.next() == Some("1") });
                }
                "remap" => {
                    if let (Ok(d), Ok(a)) = (v.parse(), it.next().unwrap_or("0").parse()) {
                        c.port_remap = Some((d, a));
                    }
                }
                _ => {}
            }
        }
        if c.id.is_empty() {
            None
        } else {
            Some(c)
        }
    }

    pub fn save(&self, ctx: &Ctx) -> KResult<()> {
        ops::write_file(ctx, &format!("{}/config", self.dir(ctx)), self.encode().as_bytes(), 0o600)
    }
}

pub fn new_id() -> String {
    let b: [u8; 8] = crate::crypto::rng::array();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Docker-style `adjective_noun` name.
pub fn random_name() -> String {
    const ADJ: &[&str] = &[
        "brave", "clever", "eager", "fervent", "gallant", "happy", "jolly", "keen", "lucid", "mystic", "nimble", "optimistic", "peaceful", "quirky", "serene",
        "tender", "upbeat", "vibrant", "wizardly", "zealous", "bold", "cosmic", "dreamy", "elegant",
    ];
    const NOUN: &[&str] = &[
        "turing", "hopper", "lovelace", "ritchie", "torvalds", "knuth", "dijkstra", "curie", "newton", "tesla", "einstein", "galileo", "kepler", "darwin", "bohr",
        "hawking", "noether", "shannon", "babbage", "liskov", "kernel", "photon", "nebula", "comet",
    ];
    let a = ADJ[(crate::crypto::rng::u32() as usize) % ADJ.len()];
    let n = NOUN[(crate::crypto::rng::u32() as usize) % NOUN.len()];
    format!("{a}_{n}")
}

/// Load every container record for the calling user.
pub fn list(ctx: &Ctx) -> Vec<Container> {
    let mut out = Vec::new();
    let Ok(entries) = ops::list_dir(ctx, &store::containers_dir(ctx)) else { return out };
    for e in entries {
        let cfg = format!("{}/{}/config", store::containers_dir(ctx), e.name);
        if let Ok(data) = ops::read_file(ctx, &cfg) {
            if let Some(c) = Container::decode(&String::from_utf8_lossy(&data)) {
                out.push(c);
            }
        }
    }
    out.sort_by(|a, b| b.created.cmp(&a.created));
    out
}

/// Resolve a name or id (prefix) to a container.
pub fn find(ctx: &Ctx, name: &str) -> KResult<Container> {
    let all = list(ctx);
    all.iter()
        .find(|c| c.name == name || c.id == name)
        .or_else(|| all.iter().find(|c| c.id.starts_with(name)))
        .cloned()
        .ok_or(Errno::ENOENT)
}

pub fn load(ctx: &Ctx, id: &str) -> KResult<Container> {
    let cfg = format!("{}/{id}/config", store::containers_dir(ctx));
    let data = ops::read_file(ctx, &cfg)?;
    Container::decode(&String::from_utf8_lossy(&data)).ok_or(Errno::EINVAL)
}
