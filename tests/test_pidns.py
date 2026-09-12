"""PID namespaces: a container gets its own process-id view. Its init is pid 1,
it sees only its own processes in /proc (and ps/top), and ids are namespace-
local. The host's /proc is unaffected.
"""
import base64
import os
import subprocess
import tempfile

import pytest

NSTEST = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
int main(void){
    printf("pid=%d ppid=%d\n", getpid(), getppid());
    DIR* d = opendir("/proc"); struct dirent* e; int count=0; char pids[256]="";
    while (d && (e=readdir(d))){
        if (e->d_name[0]>='0' && e->d_name[0]<='9'){ count++;
            strncat(pids, e->d_name, sizeof pids-strlen(pids)-2); strncat(pids, " ", 2); }
    }
    printf("proc_pids: %s(count=%d)\n", pids, count);
    return 0;
}
"""

NSSLEEP = r"""
#include <time.h>
int main(void){ for(;;){ struct timespec t={1,0}; nanosleep(&t,0);} return 0; }
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def ns_image(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(NSTEST, os.path.join(root, "bin", "nstest"))
        _cc(NSSLEEP, os.path.join(root, "bin", "nssleep"))
        tar = os.path.join(d, "ns.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import nsimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    yield "nsimg:latest"
    g.run("for c in $(fastman ps -a | tail -n +2 | awk '{print $1}'); do fastman rm -f $c; done 2>/dev/null; true")


def test_container_init_is_pid1(g, ns_image):
    out = g.ok(f"fastman run {ns_image} /bin/nstest", timeout=60)
    assert "pid=1 ppid=0" in out, out
    # Only the container's own process is visible.
    assert "proc_pids: 1 (count=1)" in out, out


def test_container_pids_isolated_from_host(g, ns_image):
    host = g.ok("ls /proc").split()
    host_pids = [x for x in host if x.isdigit()]
    assert len(host_pids) >= 5, host  # the host has many processes
    out = g.ok(f"fastman run {ns_image} /bin/nstest", timeout=60)
    import re
    count = int(re.search(r"count=(\d+)", out).group(1))
    assert count < len(host_pids), f"container saw {count}, host has {len(host_pids)}"


def test_exec_sees_container_pids(g, ns_image):
    g.run("fastman rm -f nsc 2>/dev/null; true")
    g.ok(f"fastman run -d --name nsc {ns_image} /bin/nssleep", timeout=60)
    import time
    time.sleep(1)
    try:
        out = g.ok("fastman exec nsc /bin/nstest", timeout=40)
        # init (sleeper) is 1, the exec'd nstest is 2 — namespace-local ids.
        assert "proc_pids: 1 2 (count=2)" in out, out
    finally:
        g.run("fastman rm -f nsc 2>/dev/null; true")
