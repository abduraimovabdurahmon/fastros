//! Virtual filesystem tree — single source of truth for `ls` and `cd`.
//!
//! This is a static in-memory directory skeleton that mirrors a standard
//! Linux FHS (Filesystem Hierarchy Standard) layout.  When the real VFS /
//! tmpfs layer is wired up, this table will be replaced by real inode lookups.
//!
//! Format: (absolute_path, &[child_names])
//! Children listed here are the names shown by `ls`; subdirectories that have
//! their own entry in this table are navigable via `cd`.

pub const TREE: &[(&[u8], &[&[u8]])] = &[
    // ── Root ────────────────────────────────────────────────────────────────
    (b"/", &[
        b"bin", b"boot", b"dev", b"etc", b"home", b"lib", b"lib64",
        b"media", b"mnt", b"opt", b"proc", b"root", b"run", b"sbin",
        b"srv",  b"sys",  b"tmp", b"usr",  b"var",
    ]),

    // ── /bin — essential user binaries ──────────────────────────────────────
    (b"/bin", &[
        b"sh", b"bash", b"ls", b"echo", b"cat", b"cp", b"mv", b"rm",
        b"mkdir", b"rmdir", b"chmod", b"chown", b"kill", b"ps",
        b"grep", b"find", b"mount", b"umount", b"ln", b"pwd",
        b"date", b"sleep", b"true", b"false", b"uname",
    ]),

    // ── /boot ───────────────────────────────────────────────────────────────
    (b"/boot", &[b"vmlinuz", b"initrd.img", b"grub"]),
    (b"/boot/grub", &[b"grub.cfg", b"fonts", b"locale"]),

    // ── /dev — device files ─────────────────────────────────────────────────
    (b"/dev", &[
        b"null", b"zero", b"full", b"random", b"urandom",
        b"console", b"tty", b"tty0", b"tty1",
        b"serial0", b"stdin", b"stdout", b"stderr",
        b"sda", b"sda1", b"sda2", b"mem", b"kmem",
        b"pts",
    ]),
    (b"/dev/pts", &[]),

    // ── /etc — system configuration ─────────────────────────────────────────
    (b"/etc", &[
        b"hostname", b"os-release", b"fstab", b"passwd", b"group",
        b"shadow", b"hosts", b"resolv.conf", b"motd", b"shells",
        b"profile", b"environment", b"timezone", b"localtime",
        b"network", b"init.d", b"cron.d", b"cron.daily",
        b"cron.weekly", b"cron.monthly", b"sysctl.conf",
        b"ld.so.conf", b"nsswitch.conf", b"login.defs",
    ]),
    (b"/etc/network",      &[b"interfaces"]),
    (b"/etc/init.d",       &[]),
    (b"/etc/cron.d",       &[]),
    (b"/etc/cron.daily",   &[]),
    (b"/etc/cron.weekly",  &[]),
    (b"/etc/cron.monthly", &[]),

    // ── /home — user home directories ───────────────────────────────────────
    (b"/home", &[]),

    // ── /lib, /lib64 — shared libraries ─────────────────────────────────────
    (b"/lib",   &[b"modules", b"firmware"]),
    (b"/lib/modules",  &[]),
    (b"/lib/firmware", &[]),
    (b"/lib64", &[]),

    // ── /media — removable media mount points ───────────────────────────────
    (b"/media", &[b"cdrom", b"usb"]),
    (b"/media/cdrom", &[]),
    (b"/media/usb",   &[]),

    // ── /mnt — temporary mount points ───────────────────────────────────────
    (b"/mnt", &[]),

    // ── /opt — optional / third-party software ──────────────────────────────
    (b"/opt", &[]),

    // ── /proc — kernel process virtual FS ───────────────────────────────────
    (b"/proc", &[
        b"cpuinfo", b"meminfo", b"version", b"uptime", b"mounts",
        b"filesystems", b"cmdline", b"stat", b"loadavg", b"interrupts",
        b"ioports", b"iomem", b"devices", b"net", b"sys",
        b"1", b"2", b"self",
    ]),
    (b"/proc/net", &[b"dev", b"if_inet6", b"route", b"arp", b"tcp", b"udp"]),
    (b"/proc/sys", &[b"kernel", b"vm", b"net", b"fs"]),
    (b"/proc/1",    &[b"cmdline", b"status", b"maps", b"fd"]),
    (b"/proc/self", &[b"cmdline", b"status", b"maps", b"fd", b"environ"]),

    // ── /root — root user home ───────────────────────────────────────────────
    (b"/root", &[b".bashrc", b".profile", b".bash_history"]),

    // ── /run — runtime volatile data (tmpfs) ────────────────────────────────
    (b"/run", &[b"lock", b"user", b"systemd"]),
    (b"/run/lock", &[]),
    (b"/run/user", &[]),

    // ── /sbin — system administration binaries ───────────────────────────────
    (b"/sbin", &[
        b"init", b"shutdown", b"reboot", b"halt", b"poweroff",
        b"fdisk", b"mkfs", b"fsck", b"e2fsck", b"mkfs.ext2",
        b"ifconfig", b"route", b"iptables", b"ip",
        b"modprobe", b"insmod", b"rmmod", b"lsmod",
        b"sysctl", b"ldconfig", b"swapoff", b"swapon",
    ]),

    // ── /srv — service data ──────────────────────────────────────────────────
    (b"/srv", &[b"http", b"ftp"]),
    (b"/srv/http", &[]),
    (b"/srv/ftp",  &[]),

    // ── /sys — kernel sysfs ─────────────────────────────────────────────────
    (b"/sys", &[b"kernel", b"devices", b"block", b"bus", b"class", b"fs", b"power"]),
    (b"/sys/kernel",  &[b"debug", b"mm", b"slab"]),
    (b"/sys/devices", &[b"system", b"platform", b"pci0000:00"]),
    (b"/sys/block",   &[b"sda"]),
    (b"/sys/bus",     &[b"pci", b"usb", b"platform"]),
    (b"/sys/class",   &[b"net", b"block", b"tty", b"mem"]),
    (b"/sys/fs",      &[b"ext2", b"tmpfs"]),
    (b"/sys/power",   &[b"state", b"wakeup_count"]),

    // ── /tmp — temporary files (world-writable, cleared on boot) ────────────
    (b"/tmp", &[]),

    // ── /usr — secondary hierarchy ───────────────────────────────────────────
    (b"/usr", &[b"bin", b"lib", b"lib64", b"sbin", b"share", b"include", b"local", b"src"]),
    (b"/usr/bin", &[
        b"awk", b"sed", b"sort", b"uniq", b"cut", b"tr", b"wc",
        b"head", b"tail", b"diff", b"patch", b"tar", b"gzip",
        b"bzip2", b"xz", b"zip", b"unzip", b"curl", b"wget",
        b"ssh", b"scp", b"rsync", b"vi", b"nano", b"less",
        b"more", b"man", b"env", b"which", b"file", b"strings",
        b"nm", b"objdump", b"strace", b"ldd",
    ]),
    (b"/usr/lib",   &[b"os-release"]),
    (b"/usr/lib64", &[]),
    (b"/usr/sbin",  &[b"useradd", b"userdel", b"groupadd", b"passwd", b"chpasswd"]),
    (b"/usr/share", &[b"doc", b"man", b"locale", b"zoneinfo", b"misc"]),
    (b"/usr/share/doc",      &[]),
    (b"/usr/share/man",      &[b"man1", b"man2", b"man3", b"man5", b"man8"]),
    (b"/usr/share/locale",   &[]),
    (b"/usr/share/zoneinfo", &[b"UTC", b"Etc"]),
    (b"/usr/share/misc",     &[]),
    (b"/usr/include", &[]),
    (b"/usr/local",   &[b"bin", b"lib", b"sbin", b"etc", b"share", b"include"]),
    (b"/usr/local/bin",     &[]),
    (b"/usr/local/lib",     &[]),
    (b"/usr/local/sbin",    &[]),
    (b"/usr/local/etc",     &[]),
    (b"/usr/local/share",   &[]),
    (b"/usr/local/include", &[]),
    (b"/usr/src", &[b"linux"]),
    (b"/usr/src/linux", &[]),

    // ── /var — variable data ─────────────────────────────────────────────────
    (b"/var", &[b"log", b"run", b"tmp", b"lib", b"cache", b"spool", b"lock", b"mail", b"opt"]),
    (b"/var/log", &[
        b"syslog", b"kern.log", b"messages", b"auth.log",
        b"dmesg", b"lastlog", b"wtmp", b"btmp",
        b"cron.log", b"boot.log",
    ]),
    (b"/var/run",   &[]),
    (b"/var/tmp",   &[]),
    (b"/var/lib",   &[b"misc", b"dpkg", b"apt"]),
    (b"/var/lib/misc", &[]),
    (b"/var/lib/dpkg", &[]),
    (b"/var/lib/apt",  &[]),
    (b"/var/cache",    &[b"apt", b"man"]),
    (b"/var/cache/apt", &[]),
    (b"/var/cache/man", &[]),
    (b"/var/spool",     &[b"mail", b"cron", b"at"]),
    (b"/var/spool/mail", &[]),
    (b"/var/spool/cron", &[]),
    (b"/var/spool/at",   &[]),
    (b"/var/lock",  &[]),
    (b"/var/mail",  &[]),
    (b"/var/opt",   &[]),
];

/// Returns the children of `path`, or `None` if the path is not a known directory.
pub fn lookup(path: &[u8]) -> Option<&'static [&'static [u8]]> {
    for &(p, children) in TREE {
        if p == path {
            return Some(children);
        }
    }
    None
}

/// Returns `true` if `path` is a known directory.
pub fn is_dir(path: &[u8]) -> bool {
    lookup(path).is_some()
}
