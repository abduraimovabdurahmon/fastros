"""date, df, mount/umount, lsblk, id/whoami/groups, hostname, dmesg,
lscpu, lspci, sysctl, stty/tty."""
import re


def test_date_formats(g):
    assert re.match(r"^\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d UTC \d{4}\n$", g.ok("date"))
    assert g.ok("date -d @0") == "Thu Jan  1 00:00:00 UTC 1970\n"
    assert g.ok("date -u -d '2026-09-11 07:05:09' '+%F %T %j %V %A %B %-d %_H %I %p %s %%'") == \
        "2026-09-11 07:05:09 254 37 Friday September 11  7 07 AM 1789110309 %\n"
    assert g.ok("date -d '2026-01-01 12:30' +%c") == "Thu Jan  1 12:30:00 2026\n"
    assert g.ok("date -d '2026-03-01 3 days ago' +%F") == "2026-02-26\n"
    assert g.ok("date -R -d @86400") == "Fri, 02 Jan 1970 00:00:00 +0000\n"
    assert g.ok("date -Iseconds -d @0") == "1970-01-01T00:00:00+00:00\n"
    out, err, st = g.run("date -d garbage")
    assert st == 1 and "invalid date 'garbage'" in err


def test_df(g):
    lines = g.ok("df").splitlines()
    # Column widths follow the data (df right-aligns to the widest value), so
    # compare header tokens rather than exact spacing.
    assert lines[0].split() == ["Filesystem", "1K-blocks", "Used", "Available", "Use%", "Mounted", "on"]
    root = [l for l in lines if l.endswith(" /")][0]
    assert re.match(r"^/dev/sda +\d+ +\d+ +\d+ +\d+% /$", root)
    h = g.ok("df -hT /").splitlines()
    assert h[0].split() == ["Filesystem", "Type", "Size", "Used", "Avail", "Use%", "Mounted", "on"]
    assert h[1].split()[:2] == ["/dev/sda", "ext2"]
    assert "proc" not in g.ok("df")
    assert g.ok("df -i /").splitlines()[0].split() == ["Filesystem", "Inodes", "IUsed", "IFree", "IUse%", "Mounted", "on"]


def test_mount_tmpfs_and_bind(g):
    out = g.ok("mkdir -p /mnt/t1 && mount -t tmpfs -o size=1M tmpfs /mnt/t1 && df -h /mnt/t1 | tail -1; "
               "mount | grep -c ' /mnt/t1 ' ; mount --bind /etc /mnt/t1 && ls /mnt/t1 | grep -c passwd; "
               "umount /mnt/t1; umount /mnt/t1; umount /mnt/t1; echo rc=$?")
    lines = out.splitlines()
    assert re.match(r"^tmpfs +1\.0M +0 +1\.0M +0% /mnt/t1$", lines[0]), lines[0]
    assert lines[-1] == "rc=1"
    err = g.run("umount /mnt/t1")[1]
    assert "umount: /mnt/t1: not mounted." in err
    assert "/dev/sda on / type ext2 (rw)" in g.ok("mount")
    assert "devtmpfs on /dev type devtmpfs" in g.ok("mount")


def test_lsblk(g):
    lines = g.ok("lsblk").splitlines()
    assert lines[0] == "NAME MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS"
    assert re.match(r"^sda    8:0    0 +\d+(\.\d)?G  0 disk /$", lines[1]), lines[1]


def test_identity(g):
    assert g.ok("id") == "uid=0(root) gid=0(root) groups=0(root),10(wheel)\n"
    assert g.ok("id -u; id -un; id -G; whoami; groups") == "0\nroot\n0 10\nroot\nroot wheel\n"
    out, err, st = g.run("id nosuchuser")
    assert st == 1 and "'nosuchuser': no such user" in err


def test_hostname(g):
    assert g.ok("hostname") == "fastros\n"
    assert re.match(r"^10\.0\.2\.15 \n$", g.ok("hostname -I"))
    assert g.ok("hostname tmp-name && hostname && cat /proc/sys/kernel/hostname && hostname fastros") == "tmp-name\ntmp-name\n"
    assert g.ok("hostname") == "fastros\n"
    assert "invalid" in g.run("hostname 'bad name'")[1]


def test_dmesg(g):
    first = g.ok("dmesg | head -1")
    assert re.match(r"^\[    0\.\d{6}\] boot: FastROS ", first)
    assert re.match(r"^kern  :info  : \[", g.ok("dmesg -x | head -1"))
    assert re.match(r"^\[\w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4}\] ", g.ok("dmesg -T | head -1"))


def test_lscpu_lspci_sysctl(g):
    cpu = g.ok("lscpu")
    assert cpu.startswith("Architecture:                     x86_64\n")
    assert re.search(r"^CPU\(s\): +1$", cpu, re.M)
    pci = g.ok("lspci")
    assert "00:01.1 IDE interface: Intel Corporation 82371SB PIIX3 IDE [Natoma/Triton II]" in pci
    assert "Ethernet controller" in pci
    assert "[8086:100e]" in g.ok("lspci -nn")
    assert g.ok("sysctl kernel.hostname") == "kernel.hostname = fastros\n"
    assert g.ok("sysctl -n kernel.ostype") == "FastROS\n"
    assert "kernel.pid_max = 4194304" in g.ok("sysctl -a")


def test_tty_without_terminal(g):
    out, _, st = g.run("tty")
    assert out == "not a tty\n" and st == 1


def test_stty_on_pty(pty):
    out = pty.cmd("stty size; tty")
    assert "24 80" in out and "/dev/pts/" in out
