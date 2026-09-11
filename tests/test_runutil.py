"""time, timeout, nohup, watch, help / --help / --version."""
import re


def test_time_reports(g):
    out, err, st = g.run("time sleep 0.2")
    assert st == 0
    m = re.search(r"\nreal\t0m0\.(\d{3})s\nuser\t0m\d\.\d{3}s\nsys\t0m0\.000s\n$", err)
    assert m and 150 <= int(m.group(1)) <= 900, err
    out, err, st = g.run("time -p false")
    assert st == 1 and re.match(r"^real \d+\.\d\d\nuser \d+\.\d\d\nsys 0\.00\n$", err)


def test_timeout(g):
    out, err, st = g.run("timeout 0.3 sleep 5")
    assert st == 124
    assert g.run("timeout 5 true")[2] == 0
    assert g.run("timeout -s KILL 0.2 sleep 5")[2] == 124
    assert g.run("timeout --preserve-status 0.2 sleep 5")[2] == 143
    out, err, st = g.run("timeout 1 nosuchcmd")
    assert st == 127


def test_nohup_ignores_hangup(g):
    out = g.ok("nohup sh -c 'kill -HUP $$; echo survived' 2>/dev/null")
    assert out == "survived\n"
    assert g.ok("sh -c 'trap \"\" HUP; sh -c \"kill -HUP \\$\\$; echo child-ok\"'") == "child-ok\n"


def test_help_everywhere(g):
    assert g.ok("ls --help").startswith("Usage: ls ")
    assert g.ok("free --version") == "free (FastROS) 0.2.0\n"
    assert g.ok("echo --help") == "--help\n"
    out = g.ok("help")
    assert "cd [DIR]" in out and "Programs in /bin:" in out
    assert g.ok("help cd").startswith("cd: cd [DIR]")
    assert g.run("help nosuch")[2] == 1


def test_watch_screen(client):
    from conftest import Term
    t = Term(client, cols=100, rows=20)
    t.wait_for(r"(?m)[#$]$")
    t.send("watch -n 0.5 'echo tick; uname'\r")
    t.wait_for("Every 0.5s: echo tick; uname")
    t.wait_for(r"(?m)^FastROS$")
    assert re.search(r"fastros: \w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d \d{4}$", t.line(0)), t.line(0)
    t.send("q")
    t.pump(0.5)
    t.send("echo back\r")
    t.wait_for("back")
    t.close()
