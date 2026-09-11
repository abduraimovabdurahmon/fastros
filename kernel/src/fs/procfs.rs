//! `/proc`: live system state in the exact text formats Linux uses, so
//! `ps`, `top`, `htop`, `free`, `uptime`, `netdata`-style collectors — and
//! Linux binaries inside containers — read it unchanged.
//!
//! Files are generated when opened (a consistent snapshot per open, like
//! `seq_file`); directories are generated on lookup/readdir.

use super::file::{File, Whence};
use super::{DirEntry, Errno, FileSystem, FileType, Inode, InodeRef, KResult, Metadata, SetAttr, StatFs, Timespec};
use crate::proc::{self, Process};
use crate::sync::SpinLock;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

const PROC_MAGIC: u64 = 0x9fa0;
/// Linux reports CPU times in USER_HZ ticks.
const USER_HZ: u64 = 100;

pub struct ProcFs {
    dev: u64,
}

impl ProcFs {
    pub fn new() -> Arc<ProcFs> {
        Arc::new(ProcFs { dev: 0x50 })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Root,
    Dir(&'static str),
    PidDir(u32),
    FdDir(u32),
    PidFile(u32, &'static str),
    PidLink(u32, &'static str),
    FdLink(u32, i32),
    File(&'static str),
    SelfLink,
    SysFile(&'static str),
}

struct PInode {
    dev: u64,
    node: Node,
}

const ROOT_FILES: &[&str] = &[
    "cpuinfo", "meminfo", "stat", "uptime", "loadavg", "version", "filesystems", "interrupts", "diskstats",
    "partitions", "cmdline", "devices", "swaps", "vmstat", "buddyinfo", "slabinfo", "kmsg", "mounts",
];
const DIRS: &[&str] = &["net", "sys", "sys/kernel", "sys/vm", "sys/net", "sys/net/ipv4"];
const NET_FILES: &[&str] = &["dev", "route", "tcp", "udp", "arp", "sockstat", "snmp"];
const SYS_KERNEL: &[&str] = &["hostname", "domainname", "ostype", "osrelease", "version", "pid_max", "random"];
const PID_FILES: &[&str] = &["stat", "status", "cmdline", "comm", "environ", "statm", "io", "mounts", "limits"];
const PID_LINKS: &[&str] = &["cwd", "root", "exe"];

fn ino_of(n: &Node) -> u64 {
    // Stable, distinct inode numbers per node kind.
    let h = |s: &str| s.bytes().fold(1469598103934665603u64, |a, b| (a ^ b as u64).wrapping_mul(1099511628211)) & 0xFFFF;
    match n {
        Node::Root => 1,
        Node::Dir(d) => 0x1_0000 | h(d),
        Node::File(f) => 0x2_0000 | h(f),
        Node::SysFile(f) => 0x3_0000 | h(f),
        Node::SelfLink => 0x4_0000,
        Node::PidDir(p) => (*p as u64) << 16,
        Node::FdDir(p) => ((*p as u64) << 16) | 1,
        Node::PidFile(p, f) => ((*p as u64) << 16) | 2 | (h(f) & 0xFF00),
        Node::PidLink(p, f) => ((*p as u64) << 16) | 3 | (h(f) & 0xFF00),
        Node::FdLink(p, fd) => ((*p as u64) << 16) | 0x8000 | (*fd as u64 & 0x7FFF),
    }
}

impl ProcFs {
    fn inode(&self, node: Node) -> InodeRef {
        Arc::new(PInode { dev: self.dev, node })
    }
}

impl FileSystem for ProcFs {
    fn root(&self) -> InodeRef {
        self.inode(Node::Root)
    }
    fn fs_type(&self) -> &'static str {
        "proc"
    }
    fn dev(&self) -> u64 {
        self.dev
    }
    fn statfs(&self) -> StatFs {
        StatFs { fs_type: PROC_MAGIC, block_size: 4096, name_max: 255, ..Default::default() }
    }
}

fn task_exists(pid: u32) -> bool {
    proc::find(pid).is_some() || crate::sched::find(pid).is_some()
}

impl PInode {
    fn mk(&self, node: Node) -> InodeRef {
        Arc::new(PInode { dev: self.dev, node })
    }

    fn kind(&self) -> FileType {
        match self.node {
            Node::Root | Node::Dir(_) | Node::PidDir(_) | Node::FdDir(_) => FileType::Directory,
            Node::PidLink(..) | Node::FdLink(..) | Node::SelfLink => FileType::Symlink,
            _ => FileType::Regular,
        }
    }

    fn generate(&self) -> KResult<String> {
        match &self.node {
            Node::File(f) => gen_file(f),
            Node::SysFile(f) => gen_sys(f),
            Node::PidFile(pid, f) => gen_pid(*pid, f),
            _ => Err(Errno::EISDIR),
        }
    }
}

impl Inode for PInode {
    fn metadata(&self) -> KResult<Metadata> {
        let kind = self.kind();
        let (uid, gid, start) = match &self.node {
            Node::PidDir(p) | Node::FdDir(p) | Node::PidFile(p, _) | Node::PidLink(p, _) | Node::FdLink(p, _) => {
                match proc::find(*p) {
                    Some(pr) => {
                        let c = pr.cred();
                        (c.uid, c.gid, pr.start_ns)
                    }
                    None => (0, 0, 0),
                }
            }
            _ => (0, 0, 0),
        };
        let perm = match (&self.node, kind) {
            (Node::SysFile("hostname" | "domainname"), _) => 0o644,
            (_, FileType::Directory) => 0o555,
            (_, FileType::Symlink) => 0o777,
            (Node::PidFile(_, "environ"), _) => 0o400,
            _ => 0o444,
        };
        let boot = crate::time::unix_now() as i64 - crate::time::uptime_secs() as i64;
        let t = Timespec::from_secs(boot + (start / 1_000_000_000) as i64);
        Ok(Metadata {
            dev: self.dev,
            ino: ino_of(&self.node),
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid,
            gid,
            size: 0,
            blocks: 0,
            blksize: 1024,
            rdev: 0,
            atime: t,
            mtime: t,
            ctime: t,
        })
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let s = self.generate()?;
        let b = s.as_bytes();
        if off >= b.len() as u64 {
            return Ok(0);
        }
        let n = buf.len().min(b.len() - off as usize);
        buf[..n].copy_from_slice(&b[off as usize..off as usize + n]);
        Ok(n)
    }

    fn write_at(&self, _off: u64, buf: &[u8]) -> KResult<usize> {
        match self.node {
            Node::SysFile("hostname") | Node::SysFile("domainname") => {
                let me = proc::current();
                if !me.cred().is_root() {
                    return Err(Errno::EACCES);
                }
                let v = String::from_utf8_lossy(buf).trim_end_matches('\n').to_string();
                if v.len() > 64 {
                    return Err(Errno::EINVAL);
                }
                let slot = if self.node == Node::SysFile("hostname") { &me.uts.hostname } else { &me.uts.domainname };
                *slot.lock() = v;
                Ok(buf.len())
            }
            _ => Err(Errno::EACCES),
        }
    }

    fn set_attr(&self, a: &SetAttr) -> KResult<()> {
        // `echo name > /proc/sys/kernel/hostname` truncates first: allow it.
        if a.size == Some(0) && matches!(self.node, Node::SysFile("hostname" | "domainname")) {
            return Ok(());
        }
        Err(Errno::EPERM)
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match &self.node {
            Node::Root => {
                if name == "self" {
                    return Ok(self.mk(Node::SelfLink));
                }
                if let Ok(pid) = name.parse::<u32>() {
                    return if task_exists(pid) { Ok(self.mk(Node::PidDir(pid))) } else { Err(Errno::ENOENT) };
                }
                if let Some(f) = ROOT_FILES.iter().find(|&&f| f == name) {
                    return Ok(self.mk(Node::File(f)));
                }
                if let Some(d) = DIRS.iter().find(|&&d| d == name) {
                    return Ok(self.mk(Node::Dir(d)));
                }
                Err(Errno::ENOENT)
            }
            Node::Dir("net") => NET_FILES
                .iter()
                .find(|&&f| f == name)
                .map(|f| self.mk(Node::File(net_key(f))))
                .ok_or(Errno::ENOENT),
            Node::Dir("sys") => match name {
                "kernel" => Ok(self.mk(Node::Dir("sys/kernel"))),
                "vm" => Ok(self.mk(Node::Dir("sys/vm"))),
                "net" => Ok(self.mk(Node::Dir("sys/net"))),
                _ => Err(Errno::ENOENT),
            },
            Node::Dir("sys/net") if name == "ipv4" => Ok(self.mk(Node::Dir("sys/net/ipv4"))),
            Node::Dir("sys/net/ipv4") if name == "ip_forward" => Ok(self.mk(Node::SysFile("ip_forward"))),
            Node::Dir("sys/vm") if name == "overcommit_memory" || name == "swappiness" => {
                Ok(self.mk(Node::SysFile(if name == "swappiness" { "swappiness" } else { "overcommit_memory" })))
            }
            Node::Dir("sys/kernel") => SYS_KERNEL
                .iter()
                .find(|&&f| f == name)
                .map(|f| self.mk(Node::SysFile(f)))
                .ok_or(Errno::ENOENT),
            Node::PidDir(pid) => {
                if name == "fd" {
                    return Ok(self.mk(Node::FdDir(*pid)));
                }
                if let Some(f) = PID_FILES.iter().find(|&&f| f == name) {
                    return Ok(self.mk(Node::PidFile(*pid, f)));
                }
                if let Some(l) = PID_LINKS.iter().find(|&&l| l == name) {
                    return Ok(self.mk(Node::PidLink(*pid, l)));
                }
                Err(Errno::ENOENT)
            }
            Node::FdDir(pid) => {
                let fd: i32 = name.parse().map_err(|_| Errno::ENOENT)?;
                let p = proc::find(*pid).ok_or(Errno::ENOENT)?;
                p.fds.lock().get(fd).map_err(|_| Errno::ENOENT)?;
                Ok(self.mk(Node::FdLink(*pid, fd)))
            }
            Node::Dir(_) => Err(Errno::ENOENT),
            _ => Err(Errno::ENOTDIR),
        }
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        let e = |name: &str, node: Node, kind: FileType| DirEntry { name: name.to_string(), ino: ino_of(&node), kind };
        let mut out = Vec::new();
        match &self.node {
            Node::Root => {
                for f in ROOT_FILES {
                    out.push(e(f, Node::File(f), FileType::Regular));
                }
                out.push(e("net", Node::Dir("net"), FileType::Directory));
                out.push(e("sys", Node::Dir("sys"), FileType::Directory));
                out.push(e("self", Node::SelfLink, FileType::Symlink));
                let mut pids: Vec<u32> = proc::all().iter().map(|p| p.pid).collect();
                pids.extend(proc::kernel_threads().iter().map(|t| t.tid).filter(|&t| t != 0));
                pids.sort_unstable();
                pids.dedup();
                for p in pids {
                    out.push(e(&p.to_string(), Node::PidDir(p), FileType::Directory));
                }
            }
            Node::Dir("net") => {
                for f in NET_FILES {
                    out.push(e(f, Node::File(net_key(f)), FileType::Regular));
                }
            }
            Node::Dir("sys") => {
                for d in ["kernel", "net", "vm"] {
                    out.push(e(d, Node::Dir("sys"), FileType::Directory));
                }
            }
            Node::Dir("sys/kernel") => {
                for f in SYS_KERNEL {
                    out.push(e(f, Node::SysFile(f), FileType::Regular));
                }
            }
            Node::Dir("sys/net") => out.push(e("ipv4", Node::Dir("sys/net/ipv4"), FileType::Directory)),
            Node::Dir("sys/net/ipv4") => out.push(e("ip_forward", Node::SysFile("ip_forward"), FileType::Regular)),
            Node::Dir("sys/vm") => {
                out.push(e("overcommit_memory", Node::SysFile("overcommit_memory"), FileType::Regular));
                out.push(e("swappiness", Node::SysFile("swappiness"), FileType::Regular));
            }
            Node::PidDir(pid) => {
                for f in PID_FILES {
                    out.push(e(f, Node::PidFile(*pid, f), FileType::Regular));
                }
                for l in PID_LINKS {
                    out.push(e(l, Node::PidLink(*pid, l), FileType::Symlink));
                }
                out.push(e("fd", Node::FdDir(*pid), FileType::Directory));
            }
            Node::FdDir(pid) => {
                if let Some(p) = proc::find(*pid) {
                    for (fd, _) in p.fds.lock().iter() {
                        out.push(e(&fd.to_string(), Node::FdLink(*pid, fd), FileType::Symlink));
                    }
                }
            }
            _ => return Err(Errno::ENOTDIR),
        }
        Ok(out)
    }

    fn readlink(&self) -> KResult<String> {
        match &self.node {
            Node::SelfLink => Ok(proc::current().pid.to_string()),
            Node::PidLink(pid, what) => {
                let p = proc::find(*pid).ok_or(Errno::ENOENT)?;
                let fs = p.fs.lock();
                Ok(match *what {
                    "cwd" => fs.cwd.path(),
                    "root" => fs.root.path(),
                    _ => format!("/bin/{}", p.comm()),
                })
            }
            Node::FdLink(pid, fd) => {
                let p = proc::find(*pid).ok_or(Errno::ENOENT)?;
                let f = p.fds.lock().get(*fd).map_err(|_| Errno::ENOENT)?;
                Ok(describe_file(&f))
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn open_special(self: Arc<Self>, flags: u32) -> KResult<Option<Arc<dyn File>>> {
        match self.kind() {
            FileType::Regular => {
                // Writable sysctls keep inode semantics; everything else snapshots.
                if matches!(self.node, Node::SysFile("hostname" | "domainname"))
                    && flags & super::file::flags::O_ACCMODE != super::file::flags::O_RDONLY
                {
                    return Ok(None);
                }
                let data = self.generate()?.into_bytes();
                let meta = self.metadata()?;
                Ok(Some(Arc::new(Snapshot { data, off: SpinLock::new(0), meta, flags: AtomicU32::new(flags) })))
            }
            _ => Ok(None),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn net_key(f: &str) -> &'static str {
    match f {
        "dev" => "net/dev",
        "route" => "net/route",
        "tcp" => "net/tcp",
        "udp" => "net/udp",
        "arp" => "net/arp",
        "sockstat" => "net/sockstat",
        _ => "net/snmp",
    }
}

/// What `/proc/<pid>/fd/N` points at.
pub fn describe_file(f: &Arc<dyn File>) -> String {
    if let Some(p) = f.path() {
        return p.path();
    }
    if let Some(t) = f.tty() {
        return format!("/dev/{}", t.name);
    }
    match f.stat() {
        Ok(m) if m.kind == FileType::Fifo => format!("pipe:[{}]", m.ino),
        Ok(m) if m.kind == FileType::Socket => format!("socket:[{}]", m.ino),
        Ok(m) if m.kind == FileType::CharDevice => format!("/dev/char/{}:{}", super::major(m.rdev), super::minor(m.rdev)),
        _ => String::from("anon_inode:[unknown]"),
    }
}

/// Content captured at open time.
struct Snapshot {
    data: Vec<u8>,
    off: SpinLock<u64>,
    meta: Metadata,
    flags: AtomicU32,
}

impl File for Snapshot {
    fn read(&self, buf: &mut [u8]) -> KResult<usize> {
        let mut off = self.off.lock();
        let n = self.pread(*off, buf)?;
        *off += n as u64;
        Ok(n)
    }
    fn pread(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        if off >= self.data.len() as u64 {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - off as usize);
        buf[..n].copy_from_slice(&self.data[off as usize..off as usize + n]);
        Ok(n)
    }
    fn seek(&self, w: Whence) -> KResult<u64> {
        let mut off = self.off.lock();
        let new = match w {
            Whence::Set(p) => p,
            Whence::Cur(d) => *off as i64 + d,
            Whence::End(d) => self.data.len() as i64 + d,
        };
        if new < 0 {
            return Err(Errno::EINVAL);
        }
        *off = new as u64;
        Ok(*off)
    }
    fn stat(&self) -> KResult<Metadata> {
        Ok(self.meta.clone())
    }
    fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

// ── generators ──────────────────────────────────────────────────────────────

fn kb(bytes: u64) -> u64 {
    bytes / 1024
}

fn ticks(ns: u64) -> u64 {
    ns / (1_000_000_000 / USER_HZ)
}

pub fn gen_file(f: &str) -> KResult<String> {
    let mut s = String::new();
    match f {
        "uptime" => {
            let up = crate::time::now_ns();
            let (_, _, idle) = crate::sched::cpu_times();
            let _ = writeln!(s, "{}.{:02} {}.{:02}", up / 1_000_000_000, up / 10_000_000 % 100, idle / 1_000_000_000, idle / 10_000_000 % 100);
        }
        "loadavg" => {
            let l = crate::sched::loadavg();
            let st = crate::sched::stats();
            let _ = writeln!(
                s,
                "{}.{:02} {}.{:02} {}.{:02} {}/{} {}",
                l[0].0, l[0].1, l[1].0, l[1].1, l[2].0, l[2].1,
                st.runnable + 1,
                st.tasks,
                crate::sched::last_tid()
            );
        }
        "meminfo" => {
            let m = crate::mm::stats();
            let cache = crate::fs::bcache::cached_bytes();
            let avail = m.free_bytes + cache;
            let rows: [(&str, u64); 16] = [
                ("MemTotal", kb(m.total_bytes)),
                ("MemFree", kb(m.free_bytes)),
                ("MemAvailable", kb(avail)),
                ("Buffers", kb(cache)),
                ("Cached", 0),
                ("SwapCached", 0),
                ("Active", kb(m.heap_bytes)),
                ("Inactive", 0),
                ("SwapTotal", 0),
                ("SwapFree", 0),
                ("Dirty", kb(crate::fs::bcache::dirty_bytes())),
                ("Shmem", 0),
                ("Slab", kb(m.slab_bytes)),
                ("KernelStack", kb(crate::sched::stats().tasks as u64 * crate::sched::KSTACK_PAGES as u64 * 4096)),
                ("VmallocTotal", kb((crate::mm::VMALLOC_END - crate::mm::VMALLOC_START) as u64)),
                ("VmallocUsed", kb(m.vmalloc_bytes)),
            ];
            for (k, v) in rows {
                let _ = writeln!(s, "{:<16}{:>8} kB", format!("{k}:"), v);
            }
        }
        "stat" => {
            let (user, system, idle) = crate::sched::cpu_times();
            let irqs: u64 = crate::trap::irq_counts().iter().sum();
            let line = format!("{} 0 {} {} 0 0 0 0 0 0", ticks(user), ticks(system), ticks(idle));
            let _ = writeln!(s, "cpu  {line}");
            let _ = writeln!(s, "cpu0 {line}");
            let _ = write!(s, "intr {irqs}");
            for c in crate::trap::irq_counts() {
                let _ = write!(s, " {c}");
            }
            let _ = writeln!(s);
            let st = crate::sched::stats();
            let _ = writeln!(s, "ctxt {}", st.switches);
            let _ = writeln!(s, "btime {}", crate::time::unix_now() - crate::time::uptime_secs());
            let _ = writeln!(s, "processes {}", crate::sched::last_tid());
            let _ = writeln!(s, "procs_running {}", st.runnable + 1);
            let _ = writeln!(s, "procs_blocked 0");
        }
        "cpuinfo" => {
            let c1 = crate::arch::cpu::cpuid(1, 0);
            let v0 = crate::arch::cpu::cpuid(0, 0);
            let mut vendor = Vec::new();
            for w in [v0.ebx, v0.edx, v0.ecx] {
                vendor.extend_from_slice(&w.to_le_bytes());
            }
            let family = ((c1.eax >> 8) & 0xF) + if (c1.eax >> 8) & 0xF == 0xF { (c1.eax >> 20) & 0xFF } else { 0 };
            let model = ((c1.eax >> 4) & 0xF) | (((c1.eax >> 16) & 0xF) << 4);
            let mhz = crate::time::tsc_hz() / 1000;
            let _ = writeln!(s, "processor\t: 0");
            let _ = writeln!(s, "vendor_id\t: {}", String::from_utf8_lossy(&vendor));
            let _ = writeln!(s, "cpu family\t: {family}");
            let _ = writeln!(s, "model\t\t: {model}");
            let _ = writeln!(s, "model name\t: {}", crate::arch::cpu::model_name());
            let _ = writeln!(s, "stepping\t: {}", c1.eax & 0xF);
            let _ = writeln!(s, "cpu MHz\t\t: {}.{:03}", mhz / 1000, mhz % 1000);
            let _ = writeln!(s, "cache size\t: 512 KB");
            let _ = writeln!(s, "physical id\t: 0\nsiblings\t: 1\ncore id\t\t: 0\ncpu cores\t: 1");
            let _ = writeln!(s, "fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: {}\nwp\t\t: yes", v0.eax);
            let _ = writeln!(s, "flags\t\t: {}", cpu_flags());
            let _ = writeln!(s, "bogomips\t: {}.{:02}", mhz * 2 / 1000, mhz * 2 / 10 % 100);
            let _ = writeln!(s, "address sizes\t: 40 bits physical, 48 bits virtual\n");
        }
        "version" => {
            let _ = writeln!(s, "{}", crate::version_string());
        }
        "cmdline" => {
            let _ = writeln!(s, "{}", crate::boot::info().cmdline());
        }
        "filesystems" => s.push_str("nodev\tproc\nnodev\ttmpfs\nnodev\tdevtmpfs\nnodev\tdevpts\nnodev\toverlay\n\text2\n"),
        "interrupts" => {
            let _ = writeln!(s, "           CPU0");
            let names = ["timer", "i8042", "cascade", "", "ttyS0", "", "", "", "rtc0", "acpi", "", "eth0", "", "", "ata_piix", "ata_piix"];
            for (i, c) in crate::trap::irq_counts().iter().enumerate() {
                if *c > 0 || i == 0 {
                    let _ = writeln!(s, "{:>3}: {:>10}   XT-PIC  {}", i, c, names[i]);
                }
            }
            let _ = writeln!(s, "SPU: {:>10}   Spurious interrupts", crate::trap::spurious_count());
        }
        "diskstats" => {
            for d in crate::drivers::block::all() {
                let st = d.stats();
                let r = |a: &core::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
                let (maj, min) = crate::device::disk_rdev(d.name()).map(|r| (super::major(r), super::minor(r))).unwrap_or((0, 0));
                let _ = writeln!(
                    s,
                    "{:>4} {:>7} {} {} 0 {} {} {} 0 {} {} 0 {} {} 0 0 0 0 {} 0",
                    maj,
                    min,
                    d.name(),
                    r(&st.reads),
                    r(&st.sectors_read),
                    r(&st.read_ns) / 1_000_000,
                    r(&st.writes),
                    r(&st.sectors_written),
                    r(&st.write_ns) / 1_000_000,
                    r(&st.busy_ns) / 1_000_000,
                    (r(&st.read_ns) + r(&st.write_ns)) / 1_000_000,
                    r(&st.flushes)
                );
            }
        }
        "partitions" => {
            let _ = writeln!(s, "major minor  #blocks  name\n");
            for d in crate::drivers::block::all() {
                let (maj, min) = crate::device::disk_rdev(d.name()).map(|r| (super::major(r), super::minor(r))).unwrap_or((0, 0));
                let _ = writeln!(s, "{:>5} {:>5} {:>10} {}", maj, min, d.sectors() / 2, d.name());
            }
        }
        "devices" => s.push_str("Character devices:\n  1 mem\n  4 /dev/vc/0\n  5 /dev/tty\n  5 /dev/console\n136 pts\n\nBlock devices:\n  8 sd\n"),
        "swaps" => s.push_str("Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"),
        "vmstat" => {
            let m = crate::mm::stats();
            let _ = writeln!(s, "nr_free_pages {}", m.free_bytes / 4096);
            let _ = writeln!(s, "nr_slab_unreclaimable {}", m.slab_bytes / 4096);
            let _ = writeln!(s, "pgpgin {}", 0);
            let _ = writeln!(s, "pgpgout {}", 0);
            let _ = writeln!(s, "pswpin 0\npswpout 0");
        }
        "buddyinfo" => {
            let _ = write!(s, "Node 0, zone   Normal");
            for c in crate::mm::frame::free_blocks() {
                let _ = write!(s, " {c:>6}");
            }
            let _ = writeln!(s);
        }
        "slabinfo" => {
            let _ = writeln!(s, "slabinfo - version: 2.1\n# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>");
            for c in crate::mm::heap::slab_stats() {
                let _ = writeln!(s, "kmalloc-{:<9} {:>8} {:>8} {:>6}", c.size, c.objects_in_use, c.capacity, c.size);
            }
        }
        "kmsg" => {
            for r in crate::log::records() {
                let _ = writeln!(s, "<{}>[{:5}.{:06}] {}: {}", r.level as u8, r.time_ns / 1_000_000_000, r.time_ns / 1000 % 1_000_000, r.facility, r.text);
            }
        }
        "mounts" => s = mounts_text(&proc::current()),
        net if net.starts_with("net/") => s = crate::net::procfs(&net[4..]),
        _ => return Err(Errno::ENOENT),
    }
    Ok(s)
}

fn cpu_flags() -> String {
    use crate::arch::cpu::{feature, has};
    let mut v = alloc::vec!["fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic", "sep", "mtrr", "cmov", "pat", "clflush", "mmx", "fxsr", "sse", "sse2", "syscall", "lm"];
    let opt = [
        (feature::NX, "nx"),
        (feature::PDPE1GB, "pdpe1gb"),
        (feature::RDRAND, "rdrand"),
        (feature::RDSEED, "rdseed"),
        (feature::SMEP, "smep"),
        (feature::SMAP, "smap"),
        (feature::UMIP, "umip"),
        (feature::FSGSBASE, "fsgsbase"),
        (feature::XSAVE, "xsave"),
        (feature::X2APIC, "x2apic"),
        (feature::INVARIANT_TSC, "constant_tsc"),
    ];
    for (f, n) in opt {
        if has(f) {
            v.push(n);
        }
    }
    v.join(" ")
}

pub fn mounts_text(p: &Process) -> String {
    let mut s = String::new();
    let ns = p.fs.lock().ns.clone();
    for (path, m) in ns.list() {
        let _ = writeln!(s, "{} {} {} {} 0 0", m.source, path, m.fs.fs_type(), m.flags.lock().describe());
    }
    s
}

fn gen_sys(f: &str) -> KResult<String> {
    let me = proc::current();
    Ok(match f {
        "hostname" => format!("{}\n", me.uts.hostname.lock()),
        "domainname" => format!("{}\n", me.uts.domainname.lock()),
        "ostype" => String::from("FastROS\n"),
        "osrelease" => format!("{}\n", crate::VERSION),
        "version" => String::from("#1 SMP PREEMPT_DYNAMIC FastROS\n"),
        "pid_max" => String::from("4194304\n"),
        "random" => format!("{:032x}\n", crate::crypto::rng::u64() as u128 | (crate::crypto::rng::u64() as u128) << 64),
        "ip_forward" => String::from("1\n"),
        "overcommit_memory" => String::from("0\n"),
        "swappiness" => String::from("0\n"),
        _ => return Err(Errno::ENOENT),
    })
}

fn state_letter(pid: u32) -> char {
    if let Some(p) = proc::find(pid) {
        if p.is_zombie() {
            return 'Z';
        }
    }
    match crate::sched::find(pid).map(|t| t.state()) {
        Some(crate::sched::TaskState::Running) | Some(crate::sched::TaskState::Ready) => 'R',
        Some(crate::sched::TaskState::Blocked) => 'S',
        Some(crate::sched::TaskState::Dead) => 'X',
        None => 'Z',
    }
}

fn gen_pid(pid: u32, f: &str) -> KResult<String> {
    let p = proc::find(pid);
    let task = crate::sched::find(pid);
    if p.is_none() && task.is_none() {
        return Err(Errno::ESRCH);
    }
    let kthread = p.is_none();
    let comm = match (&p, &task) {
        (Some(p), _) => p.comm(),
        (None, Some(t)) => t.name(),
        _ => String::new(),
    };
    let cpu_ns = match (&p, &task) {
        (Some(p), _) => p.cpu_ns(),
        (None, Some(t)) => t.cpu_ns(),
        _ => 0,
    };
    let start_ns = match (&p, &task) {
        (Some(p), _) => p.start_ns,
        (None, Some(t)) => t.created_ns,
        _ => 0,
    };
    let (ppid, pgid, sid) = p
        .as_ref()
        .map(|p| (p.ppid.load(Ordering::Relaxed), p.pgid.load(Ordering::Relaxed), p.sid.load(Ordering::Relaxed)))
        .unwrap_or((0, 0, 0));
    let tty_nr = p
        .as_ref()
        .and_then(|p| p.ctty.lock().clone())
        .and_then(|t| t.name.strip_prefix("pts/").and_then(|n| n.parse::<u32>().ok()))
        .map(|n| super::makedev(136, n) as i64)
        .unwrap_or(0);
    let state = state_letter(pid);
    let mut s = String::new();
    match f {
        "stat" => {
            let flags: u32 = if kthread { 0x0020_0040 } else { 0x0040_0100 };
            let _ = writeln!(
                s,
                "{pid} ({comm}) {state} {ppid} {pgid} {sid} {tty_nr} -1 {flags} 0 0 0 0 {} 0 0 0 20 0 1 0 {} 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0",
                ticks(cpu_ns),
                ticks(start_ns)
            );
        }
        "status" => {
            let (uid, gid, groups) = p.as_ref().map(|p| {
                let c = p.cred();
                (c.uid, c.gid, c.groups.clone())
            }).unwrap_or((0, 0, Vec::new()));
            let state_name = match state {
                'R' => "R (running)",
                'S' => "S (sleeping)",
                'Z' => "Z (zombie)",
                _ => "I (idle)",
            };
            let _ = writeln!(s, "Name:\t{comm}");
            let _ = writeln!(s, "Umask:\t{:04o}", p.as_ref().map(|p| p.fs.lock().umask).unwrap_or(0o022));
            let _ = writeln!(s, "State:\t{state_name}");
            let _ = writeln!(s, "Tgid:\t{pid}\nNgid:\t0\nPid:\t{pid}\nPPid:\t{ppid}\nTracerPid:\t0");
            let _ = writeln!(s, "Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}");
            let _ = writeln!(s, "FDSize:\t64");
            let g: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
            let _ = writeln!(s, "Groups:\t{}", g.join(" "));
            let _ = writeln!(s, "NSpid:\t{pid}\nNSpgid:\t{pgid}\nNSsid:\t{sid}");
            let _ = writeln!(s, "VmRSS:\t       0 kB\nThreads:\t1");
            let _ = writeln!(s, "Seccomp:\t0\nNoNewPrivs:\t0");
            let _ = writeln!(s, "voluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0");
        }
        "cmdline" => {
            if let Some(p) = &p {
                for a in p.cmdline() {
                    s.push_str(&a);
                    s.push('\0');
                }
            }
        }
        "comm" => {
            let _ = writeln!(s, "{comm}");
        }
        "environ" => {
            if let Some(p) = &p {
                let me = proc::current();
                if !me.cred().is_root() && me.cred().euid != p.cred().uid {
                    return Err(Errno::EACCES);
                }
                for (k, v) in p.env.lock().iter() {
                    let _ = write!(s, "{k}={v}\0");
                }
            }
        }
        "statm" => s.push_str("0 0 0 0 0 0 0\n"),
        "io" => s.push_str("rchar: 0\nwchar: 0\nsyscr: 0\nsyscw: 0\nread_bytes: 0\nwrite_bytes: 0\ncancelled_write_bytes: 0\n"),
        "mounts" => {
            if let Some(p) = &p {
                s = mounts_text(p);
            }
        }
        "limits" => {
            s.push_str("Limit                     Soft Limit           Hard Limit           Units     \n");
            s.push_str("Max open files            1024                 1024                 files     \n");
            s.push_str("Max processes             unlimited            unlimited            processes \n");
        }
        _ => return Err(Errno::ENOENT),
    }
    Ok(s)
}
