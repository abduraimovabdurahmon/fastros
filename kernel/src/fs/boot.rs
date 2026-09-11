//! Root filesystem bring-up: mount the disk (formatting a blank one),
//! lay out the standard hierarchy, mount the virtual filesystems and seed
//! the configuration files a fresh system needs.

use super::ext2fs::{Ext2Fs, Probe};
use super::mount::{MountFlags, MountNamespace};
use super::ops::{self, Ctx};
use super::procfs::ProcFs;
use super::tmpfs::TmpFs;
use super::{Errno, FileSystem};
use alloc::sync::Arc;

/// Directories every FastROS system has (mode, path).
const LAYOUT: &[(u16, &str)] = &[
    (0o755, "/bin"),
    (0o755, "/dev"),
    (0o755, "/etc"),
    (0o755, "/etc/ssh"),
    (0o755, "/home"),
    (0o755, "/mnt"),
    (0o755, "/opt"),
    (0o555, "/proc"),
    (0o700, "/root"),
    (0o755, "/run"),
    (0o755, "/srv"),
    (0o555, "/sys"),
    (0o1777, "/tmp"),
    (0o755, "/usr"),
    (0o755, "/usr/local"),
    (0o755, "/usr/local/bin"),
    (0o755, "/usr/lib"),
    (0o755, "/usr/share"),
    (0o755, "/var"),
    (0o755, "/var/lib"),
    (0o755, "/var/log"),
    (0o755, "/var/cache"),
    (0o1777, "/var/tmp"),
];

/// Mount `/` and return the host mount namespace.
pub fn mount_root() -> Arc<MountNamespace> {
    let root: Arc<dyn FileSystem> = match crate::drivers::block::get("sda") {
        Some(disk) => {
            let rdev = crate::device::disk_rdev("sda").unwrap_or(0);
            match Ext2Fs::mount(disk.clone(), rdev) {
                Probe::Mounted(fs) => {
                    crate::kinfo!("fs", "mounted sda (ext2, label '{}') on /", fs.label());
                    fs
                }
                Probe::NotExt2 => {
                    crate::knotice!("fs", "sda has no ext2 filesystem: formatting ({} MiB)", disk.sectors() / 2048);
                    Ext2Fs::format(disk.clone(), "fastros").expect("mkfs on sda");
                    match Ext2Fs::mount(disk, rdev) {
                        Probe::Mounted(fs) => fs,
                        _ => panic!("sda unreadable right after formatting"),
                    }
                }
                Probe::Failed(e) => {
                    crate::kerr!("fs", "cannot mount sda: {e}; using a RAM root");
                    TmpFs::new(0)
                }
            }
        }
        None => {
            crate::kwarn!("fs", "no disk attached: root is a RAM filesystem (nothing persists)");
            TmpFs::new(0)
        }
    };
    super::bcache::register_syncable(&root);
    let source = if root.fs_type() == "ext2" { "/dev/sda" } else { "rootfs" };
    let ns = MountNamespace::new(root, source, MountFlags::RW);
    super::mount::set_init_ns(ns.clone());
    ns
}

/// Standard directories, virtual filesystems and default configuration.
pub fn populate(ns: &Arc<MountNamespace>) {
    let ctx = Ctx::current();
    for &(mode, dir) in LAYOUT {
        match ops::mkdir(&ctx, dir, mode) {
            Ok(()) => {
                // Sticky/world-writable modes must not be reduced by the umask.
                let _ = ops::chmod(&ctx, dir, mode, true);
            }
            Err(Errno::EEXIST) => {}
            Err(e) => crate::kerr!("fs", "mkdir {dir}: {e}"),
        }
    }
    for (link, target) in [("/sbin", "bin"), ("/usr/bin", "../bin"), ("/usr/sbin", "../bin"), ("/lib", "usr/lib")] {
        let _ = ops::symlink(&ctx, target, link);
    }
    let mount = |path: &str, fs: Arc<dyn FileSystem>, source: &str, flags: MountFlags| match ctx.resolve(path, true) {
        Ok(at) => {
            if let Err(e) = ns.mount(&at, fs, source, flags) {
                crate::kerr!("fs", "mount {source} on {path}: {e}");
            }
        }
        Err(e) => crate::kerr!("fs", "mount point {path}: {e}"),
    };
    let nodev = MountFlags { nodev: true, nosuid: true, ..MountFlags::RW };
    mount("/dev", super::devfs::create(), "devtmpfs", MountFlags { nosuid: true, ..MountFlags::RW });
    mount("/proc", ProcFs::new(), "proc", MountFlags { nodev: true, nosuid: true, noexec: true, read_only: false });
    mount("/sys", crate::sysfs::SysFs::new(), "sysfs", MountFlags { read_only: true, ..nodev });
    mount("/tmp", TmpFs::new(0), "tmpfs", nodev);
    mount("/run", TmpFs::new(64 << 20), "tmpfs", nodev);
    mount("/dev/shm", TmpFs::new(64 << 20), "tmpfs", nodev);
    mount("/bin", crate::shell::binfs::BinFs::new(), "binfs", MountFlags::RO);
    // The ownership fix-up of /tmp inside the new tmpfs roots.
    let _ = ops::chmod(&ctx, "/tmp", 0o1777, true);
    let _ = ops::chmod(&ctx, "/dev/shm", 0o1777, true);
    seed_etc(&ctx);
}

fn seed(ctx: &Ctx, path: &str, mode: u16, content: &str) {
    if ops::exists(ctx, path) {
        return;
    }
    if let Err(e) = ops::write_file(ctx, path, content.as_bytes(), mode) {
        crate::kerr!("fs", "seeding {path}: {e}");
    } else {
        let _ = ops::chmod(ctx, path, mode, true);
    }
}

fn seed_etc(ctx: &Ctx) {
    seed(ctx, "/etc/hostname", 0o644, "fastros\n");
    seed(
        ctx,
        "/etc/hosts",
        0o644,
        "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n127.0.1.1\tfastros\n",
    );
    seed(ctx, "/etc/resolv.conf", 0o644, "nameserver 10.0.2.3\n");
    seed(
        ctx,
        "/etc/os-release",
        0o644,
        &alloc::format!(
            "NAME=\"FastROS\"\nPRETTY_NAME=\"FastROS {v}\"\nID=fastros\nVERSION_ID=\"{v}\"\nHOME_URL=\"https://github.com/abduraimovabdurahmon/fastros\"\n",
            v = crate::VERSION
        ),
    );
    seed(ctx, "/etc/shells", 0o644, "/bin/sh\n/bin/fsh\n");
    seed(
        ctx,
        "/etc/profile",
        0o644,
        "# System-wide shell profile.\nexport PATH=/bin:/usr/local/bin\nalias ll='ls -l'\nalias la='ls -A'\n",
    );
    seed(ctx, "/etc/motd", 0o644, "");
    seed(ctx, "/etc/issue", 0o644, "FastROS \\r \\l\n\n");
    crate::users::seed_databases(ctx);
    // The hostname file decides the UTS name.
    if let Ok(h) = ops::read_file(ctx, "/etc/hostname") {
        let name = alloc::string::String::from_utf8_lossy(&h).trim().to_string();
        if !name.is_empty() {
            *crate::proc::host_uts().hostname.lock() = name;
        }
    }
}

use alloc::string::ToString;
