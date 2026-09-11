//! `/sys`: a small generated tree with the kernel objects monitoring tools
//! read — network interfaces and their counters, block devices and their
//! I/O statistics, CPU topology.

use crate::errno::{Errno, KResult};
use crate::fs::{DirEntry, FileSystem, FileType, Inode, InodeRef, Metadata, StatFs, Timespec};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

const DEV: u64 = 0x51;

pub struct SysFs;

impl SysFs {
    pub fn new() -> Arc<SysFs> {
        Arc::new(SysFs)
    }
}

impl FileSystem for SysFs {
    fn root(&self) -> InodeRef {
        Arc::new(SNode { path: String::new() })
    }
    fn fs_type(&self) -> &'static str {
        "sysfs"
    }
    fn dev(&self) -> u64 {
        DEV
    }
    fn statfs(&self) -> StatFs {
        StatFs { fs_type: 0x6265_6572, block_size: 4096, name_max: 255, ..Default::default() }
    }
}

/// A node is identified by its path below /sys.
struct SNode {
    path: String,
}

enum Kind {
    Dir(Vec<String>),
    File(String),
    Link(String),
}

fn ifaces() -> Vec<String> {
    let mut v = alloc::vec![String::from("lo")];
    if crate::net::is_up() && crate::net::stack().lock().dev.has_nic() {
        v.push(String::from("eth0"));
    }
    v
}

fn net_attr(dev: &str, attr: &str) -> Option<String> {
    let st = crate::net::stack().lock();
    let nic = if dev == "eth0" { st.dev.nic_stats() } else { Some(st.dev.lo_stats) };
    let stats = nic?;
    Some(match attr {
        "address" => {
            if dev == "lo" {
                String::from("00:00:00:00:00:00")
            } else {
                crate::net::fmt_mac(&st.mac())
            }
        }
        "mtu" => if dev == "lo" { "65536" } else { "1500" }.to_string(),
        "operstate" => if dev == "lo" || st.dev.link_up() { "up" } else { "down" }.to_string(),
        "carrier" => "1".to_string(),
        "type" => if dev == "lo" { "772" } else { "1" }.to_string(),
        "speed" => if dev == "lo" { return None } else { "1000".to_string() },
        "statistics/rx_bytes" => stats.rx_bytes.to_string(),
        "statistics/tx_bytes" => stats.tx_bytes.to_string(),
        "statistics/rx_packets" => stats.rx_packets.to_string(),
        "statistics/tx_packets" => stats.tx_packets.to_string(),
        "statistics/rx_errors" => stats.rx_errors.to_string(),
        "statistics/tx_errors" => stats.tx_errors.to_string(),
        "statistics/rx_dropped" => stats.rx_dropped.to_string(),
        "statistics/tx_dropped" => stats.tx_dropped.to_string(),
        _ => return None,
    })
}

const NET_ATTRS: &[&str] = &["address", "mtu", "operstate", "carrier", "type", "speed"];
const NET_STATS: &[&str] = &["rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"];

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn classify(path: &str) -> Option<Kind> {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    Some(match parts.as_slice() {
        [] => Kind::Dir(names(&["block", "class", "devices", "fs", "kernel"])),
        ["class"] => Kind::Dir(names(&["net", "block"])),
        ["class", "net"] => Kind::Dir(ifaces()),
        ["class", "net", dev] if ifaces().iter().any(|d| d == dev) => {
            let mut v = names(NET_ATTRS);
            v.push(String::from("statistics"));
            Kind::Dir(v)
        }
        ["class", "net", _, "statistics"] => Kind::Dir(names(NET_STATS)),
        ["class", "net", dev, rest @ ..] => Kind::File(net_attr(dev, &rest.join("/"))? + "\n"),
        ["class", "block"] => Kind::Dir(crate::drivers::block::names()),
        ["class", "block", d] => Kind::Link(alloc::format!("../../block/{d}")),
        ["block"] => Kind::Dir(crate::drivers::block::names()),
        ["block", d] => {
            crate::drivers::block::get(d)?;
            Kind::Dir(names(&["size", "stat", "ro", "removable", "dev"]))
        }
        ["block", d, attr] => {
            let dev = crate::drivers::block::get(d)?;
            let s = dev.stats();
            let r = |a: &core::sync::atomic::AtomicU64| a.load(core::sync::atomic::Ordering::Relaxed);
            Kind::File(match *attr {
                "size" => alloc::format!("{}\n", dev.sectors()),
                "ro" | "removable" => String::from("0\n"),
                "dev" => {
                    let rd = crate::device::disk_rdev(d).unwrap_or(0);
                    alloc::format!("{}:{}\n", crate::fs::major(rd), crate::fs::minor(rd))
                }
                "stat" => alloc::format!(
                    "{:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8}\n",
                    r(&s.reads),
                    0,
                    r(&s.sectors_read),
                    r(&s.read_ns) / 1_000_000,
                    r(&s.writes),
                    0,
                    r(&s.sectors_written),
                    r(&s.write_ns) / 1_000_000,
                    0,
                    r(&s.busy_ns) / 1_000_000,
                    (r(&s.read_ns) + r(&s.write_ns)) / 1_000_000
                ),
                _ => return None,
            })
        }
        ["devices"] => Kind::Dir(names(&["system"])),
        ["devices", "system"] => Kind::Dir(names(&["cpu"])),
        ["devices", "system", "cpu"] => Kind::Dir(names(&["online", "possible", "present", "cpu0"])),
        ["devices", "system", "cpu", "online" | "possible" | "present"] => Kind::File(String::from("0\n")),
        ["devices", "system", "cpu", "cpu0"] => Kind::Dir(names(&["online"])),
        ["devices", "system", "cpu", "cpu0", "online"] => Kind::File(String::from("1\n")),
        ["fs"] => Kind::Dir(names(&["cgroup"])),
        ["fs", "cgroup"] => Kind::Dir(Vec::new()),
        ["kernel"] => Kind::Dir(names(&["hostname", "osrelease"])),
        ["kernel", "hostname"] => Kind::File(alloc::format!("{}\n", crate::proc::host_uts().hostname.lock())),
        ["kernel", "osrelease"] => Kind::File(alloc::format!("{}\n", crate::VERSION)),
        _ => return None,
    })
}

impl SNode {
    fn child_path(&self, name: &str) -> String {
        if self.path.is_empty() {
            String::from(name)
        } else {
            alloc::format!("{}/{}", self.path, name)
        }
    }
}

fn ino(path: &str) -> u64 {
    path.bytes().fold(1469598103934665603u64, |a, b| (a ^ b as u64).wrapping_mul(1099511628211)) >> 16
}

impl Inode for SNode {
    fn metadata(&self) -> KResult<Metadata> {
        let k = classify(&self.path).ok_or(Errno::ENOENT)?;
        let (kind, perm, size) = match &k {
            Kind::Dir(_) => (FileType::Directory, 0o755, 0),
            Kind::File(s) => (FileType::Regular, 0o444, s.len() as u64),
            Kind::Link(t) => (FileType::Symlink, 0o777, t.len() as u64),
        };
        let t = Timespec::from_secs((crate::time::unix_now() - crate::time::uptime_secs()) as i64);
        Ok(Metadata {
            dev: DEV,
            ino: ino(&self.path),
            kind,
            perm,
            nlink: 1,
            uid: 0,
            gid: 0,
            size,
            blocks: 0,
            blksize: 4096,
            rdev: 0,
            atime: t,
            mtime: t,
            ctime: t,
        })
    }

    fn read_at(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match classify(&self.path).ok_or(Errno::ENOENT)? {
            Kind::File(s) => {
                let b = s.as_bytes();
                if off >= b.len() as u64 {
                    return Ok(0);
                }
                let n = buf.len().min(b.len() - off as usize);
                buf[..n].copy_from_slice(&b[off as usize..off as usize + n]);
                Ok(n)
            }
            Kind::Dir(_) => Err(Errno::EISDIR),
            Kind::Link(_) => Err(Errno::EINVAL),
        }
    }

    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        match classify(&self.path) {
            Some(Kind::Dir(children)) if children.iter().any(|c| c == name) => Ok(Arc::new(SNode { path: self.child_path(name) })),
            Some(Kind::Dir(_)) => Err(Errno::ENOENT),
            Some(_) => Err(Errno::ENOTDIR),
            None => Err(Errno::ENOENT),
        }
    }

    fn readdir(&self) -> KResult<Vec<DirEntry>> {
        match classify(&self.path) {
            Some(Kind::Dir(children)) => Ok(children
                .into_iter()
                .map(|c| {
                    let p = self.child_path(&c);
                    let kind = match classify(&p) {
                        Some(Kind::Dir(_)) => FileType::Directory,
                        Some(Kind::Link(_)) => FileType::Symlink,
                        _ => FileType::Regular,
                    };
                    DirEntry { ino: ino(&p), name: c, kind }
                })
                .collect()),
            Some(_) => Err(Errno::ENOTDIR),
            None => Err(Errno::ENOENT),
        }
    }

    fn readlink(&self) -> KResult<String> {
        match classify(&self.path) {
            Some(Kind::Link(t)) => Ok(t),
            _ => Err(Errno::EINVAL),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
