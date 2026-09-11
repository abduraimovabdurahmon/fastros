"""useradd/usermod/userdel, groups, passwd, su, sudo — and the privilege
boundaries between them."""
import re

import pytest

from conftest import Guest, Term, connect


@pytest.fixture(scope="module")
def users(g):
    g.run("userdel -r tuser; userdel -r tadmin")
    g.ok("useradd -m tuser && useradd -m -G sudo tadmin")
    g.ok("echo 'tuser:Plain-Pass1' | chpasswd && echo 'tadmin:Admin-Pass1' | chpasswd")
    yield
    g.run("userdel -rf tuser; userdel -rf tadmin")


def test_useradd_results(g, users):
    assert re.match(r"^uid=\d+\(tadmin\) gid=\d+\(tadmin\) groups=\d+\(tadmin\),27\(sudo\)$", g.ok("id tadmin").strip())
    assert re.match(r"^drwxr-x--- 2 tuser tuser +\d+ .* /home/tuser$", g.ok("ls -ld /home/tuser").strip())
    assert g.ok("passwd -S tuser").split()[:2] == ["tuser", "P"]
    out, err, st = g.run("useradd tuser")
    assert st == 9 and "useradd: user 'tuser' already exists" in err
    out, err, st = g.run("useradd -u 0 other")
    assert st == 4 and "UID 0 is not unique" in err


def test_unprivileged_limits(users):
    u = Guest(connect("tuser", "Plain-Pass1"))
    out, err, st = u.run("cat /etc/shadow")
    assert st == 1 and "Permission denied" in err
    out, err, st = u.run("dmesg")
    assert st == 1 and "Operation not permitted" in err
    out, err, st = u.run("sudo id")
    assert st == 1 and "tuser is not in the sudoers file.  This incident will be reported." in err
    out, err, st = u.run("useradd x")
    assert st == 1 and "Permission denied" in err
    out, err, st = u.run("kill -9 2")
    assert st == 1


def test_sudo_flow(users):
    a = Guest(connect("tadmin", "Admin-Pass1"))
    out, err, st = a.run("echo Admin-Pass1 | sudo -S id -un")
    assert out == "root\n" and st == 0
    out, err, st = a.run("sudo -n true")
    assert st == 1 and "a password is required" in err  # exec sessions each get their own cache slot
    out, err, st = a.run("echo wrong | sudo -S true")
    assert st == 1
    assert "(ALL : ALL) ALL" in a.ok("sudo -l")
    out = a.ok("echo Admin-Pass1 | sudo -S sh -c 'echo $USER $HOME $SUDO_USER'")
    assert out == "root /root tadmin\n"


def test_su_rules(g, users):
    assert g.ok("su - tuser -c 'whoami; pwd; echo $HOME'") == "tuser\n/home/tuser\n/home/tuser\n"
    assert g.ok("su tuser -c 'whoami; pwd'") == "tuser\n/root\n"
    t = Term(connect("tuser", "Plain-Pass1"), cols=80, rows=24)
    t.wait_for(r"(?m)[#$]$")
    t.send("su -\r")
    t.wait_for("su: Permission denied")  # not in wheel/sudo
    t.close()
    t = Term(connect("tadmin", "Admin-Pass1"), cols=80, rows=24)
    t.wait_for(r"(?m)[#$]$")
    t.send("su -\r")
    t.wait_for("Password:")
    t.send("root\r")
    t.wait_for(r"root@fastros:~#")
    t.send("exit\r")
    t.wait_for(r"tadmin@fastros:~\$")
    t.close()


def test_passwd_interactive(users):
    t = Term(connect("tuser", "Plain-Pass1"), cols=80, rows=24)
    t.wait_for(r"(?m)[#$]$")
    t.send("passwd\r")
    t.wait_for("Current password:")
    t.send("Plain-Pass1\r")
    t.wait_for("New password:")
    t.send("short\r")
    t.wait_for("BAD PASSWORD: The password is shorter than 8 characters")
    t.send("Better-Pass2\r")
    t.wait_for("Retype new password:")
    t.send("Better-Pass2\r")
    t.wait_for("passwd: password updated successfully")
    t.close()
    Guest(connect("tuser", "Better-Pass2")).ok("true")


def test_usermod_and_groups(g, users):
    g.ok("usermod -aG wheel tuser")
    assert "10(wheel)" in g.ok("id tuser")
    assert g.ok("gpasswd -d tuser wheel") == "Removing user tuser from group wheel\n"
    assert "wheel" not in g.ok("id tuser")
    g.ok("usermod -s /bin/false tuser")
    out, err, st = g.run("su tuser -c true")
    assert st == 1 and "This account is currently not available." in err
    g.ok("usermod -s /bin/sh tuser")
    g.ok("groupadd tgrp")
    out, err, st = g.run("groupadd tgrp")
    assert st == 9 and "group 'tgrp' already exists" in err
    g.ok("groupdel tgrp")
    out, err, st = g.run("groupdel tuser")
    assert st == 8 and "cannot remove the primary group of user 'tuser'" in err
