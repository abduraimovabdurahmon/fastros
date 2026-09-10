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

/// Returns `true` if `path` is a known directory (static tree OR user-created).
pub fn is_dir(path: &[u8]) -> bool {
    lookup(path).is_some() || crate::shell::memdir::exists(path)
}

// ── Virtual file contents ─────────────────────────────────────────────────────

/// Return the static content of a known virtual file, or `None`.
pub fn get_content(path: &[u8]) -> Option<&'static [u8]> {
    // memfs takes priority — user-created / editor-saved files override statics
    if let Some(data) = crate::shell::memfs::read(path) {
        return Some(data);
    }
    match path {
        // /etc
        b"/etc/hostname"    => Some(b"fastros\n"),
        b"/etc/os-release"  => Some(
            b"NAME=FastROS\n\
              VERSION=0.1.0\n\
              ID=fastros\n\
              PRETTY_NAME=\"FastROS 0.1.0 (Container-Native)\"\n\
              HOME_URL=\"https://github.com/fastros\"\n\
              BUILD_ID=rust-no_std-x86_64\n"
        ),
        b"/etc/passwd"      => Some(
            b"root:x:0:0:Root:/root:/bin/sh\n\
              nobody:x:65534:65534:Nobody:/:/bin/false\n"
        ),
        b"/etc/group"       => Some(
            b"root:x:0:\n\
              nobody:x:65534:\n"
        ),
        b"/etc/shadow"      => Some(b"root:!:19000:0:99999:7:::\n"),
        b"/etc/hosts"       => Some(
            b"127.0.0.1   localhost\n\
              127.0.1.1   fastros\n\
              ::1         localhost ip6-localhost ip6-loopback\n"
        ),
        b"/etc/resolv.conf" => Some(
            b"# FastROS DNS configuration\n\
              nameserver 8.8.8.8\n\
              nameserver 8.8.4.4\n"
        ),
        b"/etc/fstab"       => Some(
            b"# <filesystem>  <mount>  <type>   <options>        <dump> <pass>\n\
              tmpfs           /tmp     tmpfs    defaults,nosuid  0      0\n\
              tmpfs           /run     tmpfs    defaults,nosuid  0      0\n"
        ),
        b"/etc/motd"        => Some(
            b"\n\
              Welcome to FastROS 0.1.0!\n\
              A container-native OS written in Rust.\n\n"
        ),
        b"/etc/shells"      => Some(b"/bin/sh\n/bin/bash\n"),
        b"/etc/profile"     => Some(
            b"# /etc/profile - system-wide shell configuration\n\
              export PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin\n\
              export HOME=/root\n\
              export TERM=vt100\n\
              umask 022\n"
        ),
        b"/etc/environment" => Some(b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\n"),
        b"/etc/timezone"    => Some(b"UTC\n"),
        b"/etc/sysctl.conf" => Some(
            b"# FastROS kernel parameters\n\
              kernel.hostname = fastros\n\
              vm.swappiness = 10\n"
        ),
        b"/etc/nsswitch.conf" => Some(
            b"passwd:   files\n\
              group:    files\n\
              shadow:   files\n\
              hosts:    files dns\n"
        ),
        b"/etc/login.defs"  => Some(
            b"PASS_MAX_DAYS  99999\n\
              PASS_MIN_DAYS  0\n\
              PASS_MIN_LEN   5\n\
              PASS_WARN_AGE  7\n\
              UID_MIN        1000\n\
              UID_MAX        60000\n"
        ),
        b"/etc/network/interfaces" => Some(
            b"# FastROS network interfaces\n\
              auto lo\n\
              iface lo inet loopback\n\n\
              auto eth0\n\
              iface eth0 inet dhcp\n"
        ),
        // /proc
        b"/proc/version"    => Some(
            b"FastROS 0.1.0 (Rust nightly x86_64-unknown-none) #1 SMP\n"
        ),
        b"/proc/cpuinfo"    => Some(
            b"processor\t: 0\n\
              vendor_id\t: GenuineIntel\n\
              model name\t: QEMU Virtual CPU version 2.5+\n\
              cpu MHz\t\t: 2400.000\n\
              cache size\t: 4096 KB\n\
              physical id\t: 0\n\
              siblings\t: 1\n\
              cpu cores\t: 1\n\
              flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep\n\
              bogomips\t: 4800.00\n"
        ),
        b"/proc/meminfo"    => Some(
            b"MemTotal:       262144 kB\n\
              MemFree:        258048 kB\n\
              MemAvailable:   258048 kB\n\
              Buffers:             0 kB\n\
              Cached:              0 kB\n\
              SwapTotal:           0 kB\n\
              SwapFree:            0 kB\n\
              Dirty:               0 kB\n\
              Writeback:           0 kB\n"
        ),
        b"/proc/uptime"     => Some(b"0.00 0.00\n"),
        b"/proc/cmdline"    => Some(b"fastros ro quiet\n"),
        b"/proc/mounts"     => Some(
            b"tmpfs / tmpfs rw,nosuid,nodev 0 0\n\
              tmpfs /tmp tmpfs rw,nosuid,nodev 0 0\n\
              tmpfs /run tmpfs rw,nosuid,nodev 0 0\n"
        ),
        b"/proc/filesystems" => Some(b"nodev\ttmpfs\n\text2\n\tfat32\n\toverlay\n"),
        b"/proc/loadavg"    => Some(b"0.00 0.00 0.00 1/1 1\n"),
        b"/proc/stat"       => Some(
            b"cpu  0 0 0 0 0 0 0 0 0 0\n\
              cpu0 0 0 0 0 0 0 0 0 0 0\n\
              intr 0\n\
              ctxt 0\n\
              btime 0\n\
              processes 1\n\
              procs_running 1\n\
              procs_blocked 0\n"
        ),
        b"/proc/interrupts" => Some(
            b"           CPU0\n\
                1:        42   PIC  i8042\n\
               14:         0   PIC  ata_piix\n"
        ),
        b"/proc/net/dev"    => Some(
            b"Inter-|   Receive                  |  Transmit\n\
               face |bytes packets errs drop|bytes packets errs drop\n\
                  lo:    0     0    0    0    0     0    0    0\n\
                eth0:    0     0    0    0    0     0    0    0\n"
        ),
        // /root
        b"/root/.bashrc"    => Some(
            b"# ~/.bashrc - FastROS root shell config\n\
              export PS1='root@fastros:\\w# '\n\
              export PATH=/bin:/sbin:/usr/bin:/usr/sbin\n\
              alias ll='ls -la'\n\
              alias la='ls -a'\n"
        ),
        b"/root/.profile"   => Some(
            b"# ~/.profile\n\
              [ -f ~/.bashrc ] && . ~/.bashrc\n"
        ),
        b"/root/.bash_history" => Some(
            b"ls /\ncat /etc/hostname\nps\nmem\nuname\n"
        ),
        // /usr
        b"/usr/lib/os-release" => Some(
            b"NAME=FastROS\n\
              VERSION=0.1.0\n\
              ID=fastros\n\
              PRETTY_NAME=\"FastROS 0.1.0\"\n"
        ),
        // /var/log
        b"/var/log/dmesg"   => Some(
            b"[    0.000000] FastROS kernel 0.1.0 starting\n\
              [    0.000001] GDT loaded\n\
              [    0.000002] IDT loaded\n\
              [    0.000003] PIC remapped: IRQ0-7 -> 0x20, IRQ8-15 -> 0x28\n\
              [    0.000004] PMM: 256 MiB detected\n\
              [    0.000005] VMM: page tables initialized\n\
              [    0.000006] Heap: ready\n\
              [    0.000007] PS/2 keyboard initialized\n\
              [    0.000008] VGA text mode 80x25 initialized\n\
              [    0.000009] Shell started\n"
        ),
        b"/var/log/messages" => Some(
            b"FastROS 0.1.0 kernel started.\n\
              Shell session opened.\n"
        ),
        b"/var/log/boot.log" => Some(
            b"[  OK  ] Started FastROS kernel\n\
              [  OK  ] Mounted virtual filesystems\n\
              [  OK  ] Started shell\n"
        ),
        // /proc/sys pseudo-files
        b"/proc/sys/kernel" => Some(b"/proc/sys/kernel: directory\n"),
        b"/sys/power/state"  => Some(b"freeze mem disk\n"),
        _ => None,
    }
}
