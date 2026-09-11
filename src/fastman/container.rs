//! Container record table — kernel-resident container catalogue.
//!
//! Tracks up to MAX_CONTAINERS live containers, each with:
//!   - unique 12-char hex ID and human-readable name
//!   - image reference, command override, resource limits, port maps
//!   - lifecycle state (Created → Running → Exited)
//!   - kernel PID of the container init thread
//!   - namespace group ID + cgroup ID
//!   - stdout/stderr log ring buffer

pub const MAX_CONTAINERS: usize = 16;
pub const MAX_PORTS:      usize = 8;
pub const LOG_SIZE:       usize = 8192;

// ── Port mapping ──────────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct PortMap {
    pub host_port:      u16,
    pub container_port: u16,
}

// ── Container configuration ───────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct ContainerConfig {
    pub image:     [u8; 128],
    pub image_len: usize,
    pub tag:       [u8; 64],
    pub tag_len:   usize,
    /// Command override (empty → use image default entrypoint).
    pub cmd:       [u8; 256],
    pub cmd_len:   usize,
    /// Memory limit in MiB. 0 = unlimited.
    pub memory_mb: u64,
    /// CPU quota 0-100 (%). 0 = unlimited.
    pub cpu_pct:   u8,
    /// Start detached (background).
    pub detach:    bool,
    /// Auto-remove container after it exits.
    pub auto_rm:   bool,
    pub ports:      [PortMap; MAX_PORTS],
    pub port_count: usize,
    /// Explicit name; zero-len → auto-generated.
    pub name_override:     [u8; 64],
    pub name_override_len: usize,
}

impl ContainerConfig {
    pub const fn empty() -> Self {
        Self {
            image:     [0; 128], image_len: 0,
            tag:       [0; 64],  tag_len:   0,
            cmd:       [0; 256], cmd_len:   0,
            memory_mb: 0,
            cpu_pct:   0,
            detach:    false,
            auto_rm:   false,
            ports:     [PortMap { host_port: 0, container_port: 0 }; MAX_PORTS],
            port_count: 0,
            name_override:     [0; 64],
            name_override_len: 0,
        }
    }

    pub fn image(&self) -> &[u8] { &self.image[..self.image_len] }
    pub fn tag(&self)   -> &[u8] { &self.tag[..self.tag_len]     }
    pub fn cmd(&self)   -> &[u8] { &self.cmd[..self.cmd_len]     }
}

// ── Container lifecycle state ─────────────────────────────────────────────────

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CState {
    Created,
    Running,
    Stopping,
    Exited(i32),
}

impl CState {
    pub fn label(&self) -> &'static [u8] {
        match self {
            CState::Created   => b"Created",
            CState::Running   => b"Running",
            CState::Stopping  => b"Stopping",
            CState::Exited(0) => b"Exited (0)",
            CState::Exited(_) => b"Exited",
        }
    }
    pub fn exit_code(&self) -> Option<i32> {
        if let CState::Exited(c) = self { Some(*c) } else { None }
    }
}

// ── Container record ──────────────────────────────────────────────────────────

#[derive(Copy, Clone)]
pub struct ContainerRecord {
    pub valid:      bool,
    /// Short 12-char lower-hex ID (e.g. "d3adb3ef8012").
    pub id:         [u8; 12],
    /// Human-readable name (adjective_noun, Docker-style).
    pub name:       [u8; 64],
    pub name_len:   usize,
    pub config:     ContainerConfig,
    pub state:      CState,
    /// Kernel-level PID of the container init thread.
    pub kernel_pid: u32,
    /// Unique namespace group ID (pid/mnt/net namespaces share this).
    pub ns_id:      u64,
    /// Cgroup identifier (ties the init thread to resource limits).
    pub cgroup_id:  u64,
    /// RDTSC timestamp at creation (for relative-time display).
    pub created_tsc: u64,
    /// Combined stdout + stderr ring buffer.
    pub log:        [u8; LOG_SIZE],
    pub log_len:    usize,
}

impl ContainerRecord {
    const fn empty() -> Self {
        Self {
            valid:       false,
            id:          [0; 12],
            name:        [0; 64], name_len: 0,
            config:      ContainerConfig::empty(),
            state:       CState::Created,
            kernel_pid:  0,
            ns_id:       0,
            cgroup_id:   0,
            created_tsc: 0,
            log:         [0; LOG_SIZE], log_len: 0,
        }
    }

    pub fn id(&self)   -> &[u8] { &self.id[..] }
    pub fn name(&self) -> &[u8] { &self.name[..self.name_len] }
}

// ── Global container table ────────────────────────────────────────────────────

static mut CONTAINERS: [ContainerRecord; MAX_CONTAINERS] =
    [const { ContainerRecord::empty() }; MAX_CONTAINERS];

static mut NS_COUNTER:     u64 = 1;
static mut CGROUP_COUNTER: u64 = 1;

// ── Allocation helpers ────────────────────────────────────────────────────────

pub fn alloc_ns_id()     -> u64 { unsafe { let v = NS_COUNTER;     NS_COUNTER += 1;     v } }
pub fn alloc_cgroup_id() -> u64 { unsafe { let v = CGROUP_COUNTER; CGROUP_COUNTER += 1; v } }

pub fn find_free_slot() -> Option<usize> {
    unsafe {
        for i in 0..MAX_CONTAINERS {
            if !CONTAINERS[i].valid { return Some(i); }
        }
        None
    }
}

// ── Table operations ──────────────────────────────────────────────────────────

pub fn insert(slot: usize, rec: ContainerRecord) {
    unsafe { CONTAINERS[slot] = rec; }
}

pub fn list() -> &'static [ContainerRecord] {
    unsafe { &CONTAINERS[..] }
}

/// Find a container by ID prefix (≥ 1 char). Returns slot index.
pub fn find_by_id(prefix: &[u8]) -> Option<usize> {
    unsafe {
        for i in 0..MAX_CONTAINERS {
            if !CONTAINERS[i].valid { continue; }
            if CONTAINERS[i].id.starts_with(prefix) { return Some(i); }
        }
        // Also try matching the name
        for i in 0..MAX_CONTAINERS {
            if !CONTAINERS[i].valid { continue; }
            if CONTAINERS[i].name()[..CONTAINERS[i].name_len.min(prefix.len())] == *prefix {
                return Some(i);
            }
        }
        None
    }
}

pub fn get_state(slot: usize) -> CState {
    unsafe { CONTAINERS[slot].state }
}

pub fn set_state(slot: usize, s: CState) {
    unsafe { CONTAINERS[slot].state = s; }
}

pub fn set_kernel_pid(slot: usize, pid: u32) {
    unsafe { CONTAINERS[slot].kernel_pid = pid; }
}

pub fn ns_id(slot: usize) -> u64 {
    unsafe { CONTAINERS[slot].ns_id }
}

pub fn cgroup_id(slot: usize) -> u64 {
    unsafe { CONTAINERS[slot].cgroup_id }
}

pub fn append_log(slot: usize, data: &[u8]) {
    unsafe {
        let rec   = &mut CONTAINERS[slot];
        let avail = LOG_SIZE - rec.log_len;
        let n     = data.len().min(avail);
        rec.log[rec.log_len..rec.log_len + n].copy_from_slice(&data[..n]);
        rec.log_len += n;
    }
}

pub fn get_log(slot: usize) -> &'static [u8] {
    unsafe { &CONTAINERS[slot].log[..CONTAINERS[slot].log_len] }
}

pub fn remove(slot: usize) {
    unsafe { CONTAINERS[slot] = ContainerRecord::empty(); }
}

pub fn config(slot: usize) -> ContainerConfig {
    unsafe { CONTAINERS[slot].config }
}

// ── ID generation ─────────────────────────────────────────────────────────────

/// Generate a 12-char lower-hex container ID from RDTSC + ns_id.
pub fn make_id(tsc: u64, ns_id: u64) -> [u8; 12] {
    let v   = tsc.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(ns_id);
    let hex = b"0123456789abcdef";
    let mut id = [0u8; 12];
    for i in 0..6 {
        let byte      = ((v >> (i * 8)) & 0xff) as u8;
        id[i * 2]     = hex[(byte >> 4) as usize];
        id[i * 2 + 1] = hex[(byte & 0xf) as usize];
    }
    id
}

// ── Name generation (Docker-style adjective_noun) ─────────────────────────────

static ADJECTIVES: &[&[u8]] = &[
    b"admiring", b"adoring", b"affectionate", b"agitated", b"amazing",
    b"awesome", b"blissful", b"bold", b"brave", b"busy",
    b"charming", b"clever", b"cool", b"dazzling", b"determined",
    b"dreamy", b"eager", b"ecstatic", b"elastic", b"elated",
    b"elegant", b"epic", b"exciting", b"fervent", b"festive",
    b"focused", b"friendly", b"frosty", b"funny", b"gallant",
    b"gifted", b"goofy", b"gracious", b"happy", b"hardcore",
    b"hopeful", b"inspiring", b"jolly", b"jovial", b"keen",
    b"kind", b"laughing", b"lucid", b"magical", b"nifty",
    b"objective", b"optimistic", b"peaceful", b"pensive", b"quirky",
    b"reverent", b"romantic", b"serene", b"sharp", b"silly",
    b"sleepy", b"stoic", b"sweet", b"tender", b"thirsty",
    b"trusting", b"upbeat", b"vibrant", b"vigilant", b"wonderful",
    b"xenodochial", b"youthful", b"zealous", b"zen", b"flamboyant",
];

static NOUNS: &[&[u8]] = &[
    b"babbage", b"bardeen", b"bartik", b"bell", b"bhaskara",
    b"blackwell", b"bohr", b"booth", b"borg", b"bouman",
    b"burnell", b"cannon", b"carson", b"cerf", b"chandrasekhar",
    b"cohen", b"cori", b"cray", b"curie", b"darwin",
    b"davinci", b"diffie", b"dijkstra", b"dirac", b"einstein",
    b"elion", b"engelbart", b"euler", b"faraday", b"fermat",
    b"fermi", b"feynman", b"franklin", b"galileo", b"galois",
    b"gauss", b"germain", b"goldwasser", b"goodall", b"hamilton",
    b"hawking", b"heisenberg", b"hellman", b"hopper", b"hypatia",
    b"jackson", b"jennings", b"johnson", b"kalam", b"kare",
    b"kepler", b"kilby", b"knuth", b"leavitt", b"lovelace",
    b"mcclintock", b"meitner", b"meninsky", b"morse", b"newton",
    b"nightingale", b"noether", b"pasteur", b"payne", b"ptolemy",
    b"ride", b"ritchie", b"roentgen", b"saha", b"sammet",
    b"shannon", b"shaw", b"solomon", b"stallman", b"tesla",
    b"thompson", b"torvalds", b"turing", b"vaughan", b"villani",
    b"wozniak", b"wright", b"wu", b"yonath", b"zhukovsky",
];

/// Generate a Docker-style "adjective_noun" name seeded by TSC.
pub fn generate_name(tsc: u64) -> ([u8; 64], usize) {
    let ai   = (tsc.wrapping_shr(16)) as usize % ADJECTIVES.len();
    let ni   = (tsc & 0xffff) as usize % NOUNS.len();
    let adj  = ADJECTIVES[ai];
    let noun = NOUNS[ni];
    let mut name = [0u8; 64];
    let al = adj.len().min(30);
    name[..al].copy_from_slice(&adj[..al]);
    name[al] = b'_';
    let nl = noun.len().min(32);
    name[al + 1..al + 1 + nl].copy_from_slice(&noun[..nl]);
    (name, al + 1 + nl)
}
