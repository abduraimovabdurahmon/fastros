"""ps, kill, pgrep/pkill/pidof/killall, free, uptime, w/who/last, vmstat."""
import re
import time


def test_ps_default_header(g):
    lines = g.ok("ps").splitlines()
    assert lines[0] == "    PID TTY          TIME CMD"
    assert any(l.endswith(" ps") for l in lines[1:])


def test_ps_ef_columns(g):
    lines = g.ok("ps -ef").splitlines()
    assert lines[0] == "UID          PID    PPID  C STIME TTY          TIME CMD"
    me = [l for l in lines if re.search(r"\d\d:\d\d:\d\d ps -ef$", l)]
    assert len(me) == 1, lines
    assert re.match(r"^root +\d+ +\d+ +\d+ \d\d:\d\d \?        \d\d:\d\d:\d\d ps -ef$", me[0])
    # Kernel threads appear in brackets.
    assert any(l.endswith("[kflushd]") for l in lines)


def test_ps_aux_columns(g):
    lines = g.ok("ps aux").splitlines()
    assert lines[0] == "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    row = [l for l in lines if re.search(r" \d+:\d\d ps aux$", l)][0]
    assert re.match(r"^root +\d+ +\d+\.\d +\d+\.\d +\d+ +\d+ \?        R\s+\d\d:\d\d +\d+:\d\d ps aux$", row), row


def test_ps_custom_format_and_sort(g):
    out = g.ok("ps -o pid=,comm= -p 2")
    assert out.split() == ["2", "kflushd"]
    lines = g.ok("ps -e -o pid,comm --sort=-pid").splitlines()
    pids = [int(l.split()[0]) for l in lines[1:]]
    assert pids == sorted(pids, reverse=True)


def test_ps_forest_and_missing_pid(g):
    out = g.ok("ps axf")
    assert re.search(r"\\_ ps axf$", out, re.M), out
    out, err, st = g.run("ps -p 999999")
    assert st == 1 and out.strip() == "PID TTY          TIME CMD"


def test_kill_signals_and_errors(g):
    out = g.ok("kill -l | head -1")
    assert out == " 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n"
    assert g.ok("kill -l 9; kill -l TERM; kill -l 137").split() == ["KILL", "15", "KILL"]
    out, err, st = g.run("kill 999999")
    assert st == 1 and "kill: (999999) - No such process" in err
    out = g.ok("sleep 30 & p=$!; kill -9 $p; wait $p; echo st=$?")
    assert out.strip() == "st=137"


def test_kill_job_spec(g):
    out = g.ok("sleep 30 & kill %1; wait; echo done")
    assert out.strip() == "done"


def test_pgrep_pkill_pidof_killall(g):
    out = g.ok("sleep 101 & sleep 102 & sleep 0.2; pgrep -l '^sleep$'; pidof sleep; "
               "pkill -e -x sleep; sleep 0.2; pgrep sleep; echo rc=$?")
    lines = out.splitlines()
    assert re.match(r"^\d+ sleep$", lines[0]) and re.match(r"^\d+ sleep$", lines[1])
    a, b = int(lines[0].split()[0]), int(lines[1].split()[0])
    assert lines[2] == f"{max(a, b)} {min(a, b)}"  # pidof: newest first
    assert sorted(lines[3:5]) == sorted([f"sleep killed (pid {a})", f"sleep killed (pid {b})"])
    assert lines[-1] == "rc=1"
    out, err, st = g.run("sleep 103 & sleep 0.2; killall -v sleep; killall nosuch")
    assert re.search(r"Killed sleep\(\d+\) with signal 15", err)
    assert "nosuch: no process found" in err and st == 1


def test_free_layout(g):
    lines = g.ok("free").splitlines()
    assert lines[0] == "               total        used        free      shared  buff/cache   available"
    assert re.match(r"^Mem: +\d+ +\d+ +\d+ +\d+ +\d+ +\d+$", lines[1])
    assert len(lines[1]) == len(lines[0])
    assert re.match(r"^Swap: +0 +0 +0$", lines[2])
    h = g.ok("free -h").splitlines()[1]
    assert re.match(r"^Mem: +\d+(\.\d)?Mi +", h), h


def test_uptime_formats(g):
    out = g.ok("uptime")
    assert re.match(r"^ \d\d:\d\d:\d\d up .+,  \d+ users?,  load average: \d+\.\d\d, \d+\.\d\d, \d+\.\d\d\n$", out), out
    assert g.ok("uptime -p").startswith("up ")
    assert re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\n$", g.ok("uptime -s"))


def test_w_who_last(g):
    out = g.ok("w")
    assert out.splitlines()[1] == "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT"
    assert "reboot   system boot" in g.ok("last")
    assert g.ok("who -b").startswith("         system boot  ")


def test_vmstat(g):
    lines = g.ok("vmstat").splitlines()
    assert lines[0] == "procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----"
    assert lines[1] == " r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st"
    assert len(lines[2].split()) == 17


def test_proc_stat_fields(g):
    # /proc/<pid>/stat has 52 fields and tpgid/rss are filled in.
    f = g.ok("cat /proc/self/stat").split()
    assert len(f) == 52
    assert g.ok("cat /proc/self/status").count("VmRSS:") == 1


def test_top_batch(g):
    out = g.ok("top -b -n 1")
    lines = out.splitlines()
    assert lines[0].startswith("top - ") and "load average:" in lines[0]
    assert re.match(r"^Tasks: +\d+ total, +\d+ running, +\d+ sleeping, +\d+ stopped, +\d+ zombie$", lines[1])
    assert lines[2].startswith("%Cpu(s): ")
    assert lines[3].startswith("MiB Mem : ")
    assert lines[6] == "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND"
    assert any(l.endswith(" top") for l in lines[7:])


def test_htop_screen(client):
    from conftest import Term
    t = Term(client, cols=100, rows=30)
    t.wait_for(r"(?m)[#$]$")
    t.send("htop\r")
    t.wait_for("F10Quit")
    t.pump(1.0)
    text = t.text()
    assert re.search(r"^  0\[.*%\]", text, re.M), text
    assert re.search(r"^Mem\[.*/.*\]", text, re.M)
    assert "Tasks: " in text and "Load average: " in text and "Uptime: " in text
    hdr = [n for n in range(30) if "PID USER" in t.line(n)][0]
    assert t.line(hdr).startswith("    PID USER       PRI  NI  VIRT   RES   SHR S  CPU% MEM%   TIME+  Command")
    assert t.screen.buffer[hdr][4].bg == "green"
    t.send("\x1b[21~")  # F10
    t.pump(1.0)
    t.send("echo back\r")
    t.wait_for("back")
    t.close()
