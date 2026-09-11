//! Process and system information read from `/proc` — FastROS's libprocps.
//!
//! Commands read through the VFS rather than kernel structures, so they
//! report exactly what `/proc` shows in their mount namespace: inside a
//! container they see the container's view, like Linux tools do.

use crate::fs::ops;
use crate::time::civil;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// Clock ticks per second of `/proc` time fields (Linux USER_HZ).
pub const HZ: u64 = 100;
/// `PF_KTHREAD` in the flags field of `/proc/<pid>/stat`.
const PF_KTHREAD: u64 = 0x0020_0000;

/// One process as `/proc/<pid>/{stat,status,cmdline}` describe it.
#[derive(Clone, Debug, Default)]
pub struct ProcEntry {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub tty_nr: u64,
    pub tpgid: i64,
    pub flags: u64,
    /// CPU time in ticks.
    pub utime: u64,
    pub stime: u64,
    pub priority: i64,
    pub nice: i64,
    pub threads: u64,
    /// Start time in ticks after boot.
    pub start_ticks: u64,
    pub vsize: u64,
    pub rss_pages: u64,
    pub uid: u32,
    pub gid: u32,
    /// Empty for kernel threads.
    pub cmdline: Vec<String>,
}

impl ProcEntry {
    pub fn is_kthread(&self) -> bool {
        self.flags & PF_KTHREAD != 0
    }
    pub fn cpu_ticks(&self) -> u64 {
        self.utime + self.stime
    }
    pub fn rss_kb(&self) -> u64 {
        self.rss_pages * 4
    }
    /// The full command line, or `[comm]` for kernel threads (as `ps` shows).
    pub fn args(&self) -> String {
        if self.cmdline.is_empty() {
            alloc::format!("[{}]", self.comm)
        } else {
            self.cmdline.join(" ")
        }
    }
    /// Controlling terminal name without `/dev/`, or `None`.
    pub fn tty(&self) -> Option<String> {
        tty_name(self.tty_nr)
    }
    pub fn is_session_leader(&self) -> bool {
        self.pid == self.sid
    }
    pub fn in_foreground(&self) -> bool {
        self.tty_nr != 0 && self.tpgid >= 0 && self.pgid as i64 == self.tpgid
    }
    /// BSD `STAT`: state letter plus `<`, `N`, `s`, `l`, `+` markers.
    pub fn stat_flags(&self) -> String {
        let mut s = String::new();
        s.push(self.state);
        if self.nice < 0 {
            s.push('<');
        } else if self.nice > 0 {
            s.push('N');
        }
        if self.is_session_leader() {
            s.push('s');
        }
        if self.threads > 1 {
            s.push('l');
        }
        if self.in_foreground() {
            s.push('+');
        }
        s
    }
}

/// `/dev` name of a terminal device number (`pts/0`, `ttyS0`, `console`).
pub fn tty_name(dev: u64) -> Option<String> {
    if dev == 0 {
        return None;
    }
    let (maj, min) = (crate::fs::major(dev), crate::fs::minor(dev));
    Some(match (maj, min) {
        (136..=143, n) => alloc::format!("pts/{}", (maj - 136) * 256 + n),
        (4, n) if n >= 64 => alloc::format!("ttyS{}", n - 64),
        (4, n) => alloc::format!("tty{n}"),
        (5, 0) => String::from("tty"),
        (5, 1) => String::from("console"),
        _ => alloc::format!("{maj}:{min}"),
    })
}

fn read_text(ctx: &ops::Ctx, path: &str) -> Option<String> {
    ops::read_file(ctx, path).ok().map(|d| String::from_utf8_lossy(&d).into_owned())
}

/// Parse the `stat` line. The command name may contain spaces and
/// parentheses, so it spans from the first `(` to the *last* `)`.
fn parse_stat(line: &str) -> Option<ProcEntry> {
    let open = line.find('(')?;
    let close = line.rfind(')')?;
    let pid = line[..open].trim().parse().ok()?;
    let comm = line[open + 1..close].to_string();
    let f: Vec<&str> = line[close + 1..].split_whitespace().collect();
    // f[0] is field 3 (state).
    let n = |i: usize| -> u64 { f.get(i).and_then(|v| v.parse().ok()).unwrap_or(0) };
    let s = |i: usize| -> i64 { f.get(i).and_then(|v| v.parse().ok()).unwrap_or(0) };
    Some(ProcEntry {
        pid,
        comm,
        state: f.first().and_then(|v| v.chars().next()).unwrap_or('?'),
        ppid: n(1) as u32,
        pgid: n(2) as u32,
        sid: n(3) as u32,
        tty_nr: n(4),
        tpgid: s(5),
        flags: n(6),
        utime: n(11),
        stime: n(12),
        priority: s(15),
        nice: s(16),
        threads: n(17),
        start_ticks: n(19),
        vsize: n(20),
        rss_pages: n(21),
        ..Default::default()
    })
}

/// Read one process; `None` if it vanished meanwhile.
pub fn read_proc(ctx: &ops::Ctx, pid: u32) -> Option<ProcEntry> {
    let stat = read_text(ctx, &alloc::format!("/proc/{pid}/stat"))?;
    let mut e = parse_stat(stat.trim_end())?;
    if let Some(status) = read_text(ctx, &alloc::format!("/proc/{pid}/status")) {
        for l in status.lines() {
            let first = |l: &str| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
            if l.starts_with("Uid:") {
                e.uid = first(l);
            } else if l.starts_with("Gid:") {
                e.gid = first(l);
            }
        }
    }
    if let Ok(raw) = ops::read_file(ctx, &alloc::format!("/proc/{pid}/cmdline")) {
        e.cmdline = raw
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
    }
    Some(e)
}

/// Every process visible in `/proc`, sorted by pid.
pub fn list(ctx: &ops::Ctx) -> Vec<ProcEntry> {
    let mut pids: Vec<u32> = ops::list_dir(ctx, "/proc")
        .map(|v| v.iter().filter_map(|e| e.name.parse().ok()).collect())
        .unwrap_or_default();
    pids.sort_unstable();
    pids.into_iter().filter_map(|p| read_proc(ctx, p)).collect()
}

/// `/proc/meminfo`, values in kB.
pub struct MemInfo(BTreeMap<String, u64>);

impl MemInfo {
    pub fn read(ctx: &ops::Ctx) -> MemInfo {
        let mut m = BTreeMap::new();
        for l in read_text(ctx, "/proc/meminfo").unwrap_or_default().lines() {
            if let Some((k, v)) = l.split_once(':') {
                let v = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
                m.insert(k.to_string(), v);
            }
        }
        MemInfo(m)
    }
    pub fn get(&self, k: &str) -> u64 {
        self.0.get(k).copied().unwrap_or(0)
    }
    pub fn total(&self) -> u64 {
        self.get("MemTotal")
    }
    pub fn free(&self) -> u64 {
        self.get("MemFree")
    }
    pub fn buffers(&self) -> u64 {
        self.get("Buffers")
    }
    /// Page cache + reclaimable slab, as `free` computes `buff/cache`.
    pub fn cache(&self) -> u64 {
        self.get("Cached") + self.get("SReclaimable")
    }
    pub fn available(&self) -> u64 {
        match self.0.get("MemAvailable") {
            Some(&v) => v,
            None => self.free() + self.buffers() + self.cache(),
        }
    }
    /// `free`'s "used": total - free - buffers - cache.
    pub fn used(&self) -> u64 {
        self.total().saturating_sub(self.free() + self.buffers() + self.cache())
    }
    pub fn shared(&self) -> u64 {
        self.get("Shmem")
    }
    pub fn swap_total(&self) -> u64 {
        self.get("SwapTotal")
    }
    pub fn swap_free(&self) -> u64 {
        self.get("SwapFree")
    }
}

/// The aggregate `cpu` line of `/proc/stat`, in ticks.
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }
    /// Per-field delta from an earlier sample.
    pub fn since(&self, old: &CpuTimes) -> CpuTimes {
        CpuTimes {
            user: self.user.saturating_sub(old.user),
            nice: self.nice.saturating_sub(old.nice),
            system: self.system.saturating_sub(old.system),
            idle: self.idle.saturating_sub(old.idle),
            iowait: self.iowait.saturating_sub(old.iowait),
            irq: self.irq.saturating_sub(old.irq),
            softirq: self.softirq.saturating_sub(old.softirq),
            steal: self.steal.saturating_sub(old.steal),
        }
    }
}

pub struct SysStat {
    pub cpu: CpuTimes,
    /// Per-CPU lines (`cpu0`, `cpu1`, ...).
    pub cpus: Vec<CpuTimes>,
    pub btime: u64,
    pub ctxt: u64,
    pub processes: u64,
    pub running: u64,
    pub blocked: u64,
}

impl SysStat {
    pub fn read(ctx: &ops::Ctx) -> SysStat {
        let mut st = SysStat { cpu: CpuTimes::default(), cpus: Vec::new(), btime: 0, ctxt: 0, processes: 0, running: 0, blocked: 0 };
        for l in read_text(ctx, "/proc/stat").unwrap_or_default().lines() {
            let mut f = l.split_whitespace();
            let Some(key) = f.next() else { continue };
            let nums: Vec<u64> = f.map(|x| x.parse().unwrap_or(0)).collect();
            let n = |i: usize| nums.get(i).copied().unwrap_or(0);
            match key {
                k if k.starts_with("cpu") => {
                    let t = CpuTimes { user: n(0), nice: n(1), system: n(2), idle: n(3), iowait: n(4), irq: n(5), softirq: n(6), steal: n(7) };
                    if key == "cpu" {
                        st.cpu = t;
                    } else {
                        st.cpus.push(t);
                    }
                }
                "btime" => st.btime = n(0),
                "ctxt" => st.ctxt = n(0),
                "processes" => st.processes = n(0),
                "procs_running" => st.running = n(0),
                "procs_blocked" => st.blocked = n(0),
                _ => {}
            }
        }
        if st.cpus.is_empty() {
            st.cpus.push(st.cpu);
        }
        st
    }
}

/// Seconds since boot, in hundredths (`/proc/uptime`).
pub fn uptime_centis(ctx: &ops::Ctx) -> u64 {
    let t = read_text(ctx, "/proc/uptime").unwrap_or_default();
    let first = t.split_whitespace().next().unwrap_or("0");
    let (i, f) = first.split_once('.').unwrap_or((first, "0"));
    let i: u64 = i.parse().unwrap_or(0);
    let f: u64 = alloc::format!("{:0<2}", &f[..f.len().min(2)]).parse().unwrap_or(0);
    i * 100 + f
}

/// `/proc/loadavg`: three averages in hundredths, then running/total tasks.
pub struct LoadAvg {
    pub avg: [u64; 3],
    pub running: u64,
    pub total: u64,
}

impl LoadAvg {
    pub fn read(ctx: &ops::Ctx) -> LoadAvg {
        let t = read_text(ctx, "/proc/loadavg").unwrap_or_default();
        let f: Vec<&str> = t.split_whitespace().collect();
        let centi = |s: &str| {
            let (i, d) = s.split_once('.').unwrap_or((s, "0"));
            i.parse::<u64>().unwrap_or(0) * 100 + alloc::format!("{:0<2}", &d[..d.len().min(2)]).parse::<u64>().unwrap_or(0)
        };
        let (running, total) = f
            .get(3)
            .and_then(|s| s.split_once('/'))
            .map(|(a, b)| (a.parse().unwrap_or(0), b.parse().unwrap_or(0)))
            .unwrap_or((0, 0));
        LoadAvg {
            avg: [centi(f.first().unwrap_or(&"0")), centi(f.get(1).unwrap_or(&"0")), centi(f.get(2).unwrap_or(&"0"))],
            running,
            total,
        }
    }
    /// `0.97, 2.06, 2.33`.
    pub fn text(&self, sep: &str) -> String {
        let v: Vec<String> = self.avg.iter().map(|c| alloc::format!("{}.{:02}", c / 100, c % 100)).collect();
        v.join(sep)
    }
}

// ── formatting shared by ps / top / w ─────────────────────────────────────

/// `[DD-]HH:MM:SS` (ps TIME).
pub fn fmt_time(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        alloc::format!("{d}-{h:02}:{m:02}:{s:02}")
    } else {
        alloc::format!("{h:02}:{m:02}:{s:02}")
    }
}

/// `M:SS` (BSD TIME column).
pub fn fmt_bsdtime(secs: u64) -> String {
    alloc::format!("{}:{:02}", secs / 60, secs % 60)
}

/// `[[DD-]HH:]MM:SS` (ps ELAPSED).
pub fn fmt_etime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        alloc::format!("{d}-{h:02}:{m:02}:{s:02}")
    } else if h > 0 {
        alloc::format!("{h:02}:{m:02}:{s:02}")
    } else {
        alloc::format!("{m:02}:{s:02}")
    }
}

/// `top`'s `TIME+`: `M:SS.hh` from ticks.
pub fn fmt_time_plus(ticks: u64) -> String {
    let centis = ticks * 100 / HZ;
    alloc::format!("{}:{:02}.{:02}", centis / 6000, centis / 100 % 60, centis % 100)
}

/// ps START/STIME: `HH:MM` today, `MonDD` this year, else the year.
pub fn fmt_start(start_unix: u64, now_unix: u64) -> String {
    let t = civil::from_unix(start_unix as i64);
    let now = civil::from_unix(now_unix as i64);
    if now_unix.saturating_sub(start_unix) < 86400 && t.day == now.day {
        alloc::format!("{:02}:{:02}", t.hour, t.min)
    } else if t.year == now.year {
        alloc::format!("{}{:02}", civil::MONTHS[(t.month - 1) as usize], t.day)
    } else {
        alloc::format!("{}", t.year)
    }
}

/// `up 7 days, 23:16` / `up 5 min` / `up 1 day, 3 min` (uptime, top, w).
pub fn fmt_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = secs / 3600 % 24;
    let mins = secs / 60 % 60;
    let mut s = String::from("up ");
    if days > 0 {
        s.push_str(&alloc::format!("{days} day{}, ", if days == 1 { "" } else { "s" }));
    }
    if hours > 0 {
        s.push_str(&alloc::format!("{hours:2}:{mins:02}"));
    } else {
        s.push_str(&alloc::format!("{mins} min"));
    }
    s
}

/// Tenths as `12.3`.
pub fn fmt_tenths(t: u64) -> String {
    alloc::format!("{}.{}", t / 10, t % 10)
}

/// Truncate a user name to a column, marking the cut with `+` (procps).
pub fn fit_name(name: &str, width: usize) -> String {
    if name.chars().count() <= width {
        name.to_string()
    } else {
        let mut s: String = name.chars().take(width.saturating_sub(1)).collect();
        s.push('+');
        s
    }
}
