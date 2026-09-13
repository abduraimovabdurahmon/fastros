"""fastman: the container engine — import, run, ps, logs, exec, stop, rm,
volumes, env, and (most importantly) sandbox isolation.

A minimal image is built here from static binaries (the harness has gcc),
shipped in as a rootfs tarball, and driven through the whole lifecycle.
"""
import base64
import os
import subprocess
import tempfile

import pytest

HELLO = r"""
#include <stdio.h>
int main(){ printf("hello from a fastman container\n"); return 0; }
"""

PROBE = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
int main(int argc, char **argv, char **envp){
    char cwd[256]; getcwd(cwd, sizeof cwd);
    printf("argv:"); for(int i=0;i<argc;i++) printf(" %s", argv[i]); printf("\n");
    printf("cwd: %s\n", cwd);
    FILE *f = fopen("/etc/hostname","r"); char b[64]=""; if(f){ if(fgets(b,sizeof b,f)){} fclose(f);}
    printf("hostname: %s", b[0]?b:"(none)\n");
    printf("host_etc_shadow: %d\n", access("/etc/shadow", F_OK)==0);
    for(char **p=envp;*p;p++) if(!strncmp(*p,"MARK=",5)) printf("env %s\n", *p);
    if (argc>1 && !strcmp(argv[1],"lsvol")){ DIR*d=opendir("/data"); struct dirent*e;
        printf("vol:"); while(d&&(e=readdir(d))){ if(e->d_name[0]!='.') printf(" %s", e->d_name);} printf("\n"); }
    return 0;
}
"""

SLEEPER = r"""
#include <stdio.h>
#include <unistd.h>
int main(){ for(int i=0;;i++){ printf("tick %d\n", i); fflush(stdout); sleep(1);} }
"""

# Reads stdin and echoes it back — proves `exec -it` wires the caller's stdin
# (a non-interactive exec gives /dev/null, so this would read immediate EOF).
CATR = r"""
#include <stdio.h>
#include <unistd.h>
int main(){
    char b[256]; int n = read(0, b, sizeof b);
    if (n <= 0){ printf("STDIN_EOF\n"); return 0; }
    printf("GOT:%.*s", n, b); return 0;
}
"""


def _cc(src: str, out: str):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def image_tar():
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        os.makedirs(os.path.join(root, "etc"))
        _cc(HELLO, os.path.join(root, "bin", "hello"))
        _cc(PROBE, os.path.join(root, "bin", "probe"))
        _cc(SLEEPER, os.path.join(root, "bin", "sleeper"))
        _cc(CATR, os.path.join(root, "bin", "catr"))
        open(os.path.join(root, "etc", "hostname"), "w").write("container-host\n")
        tar = os.path.join(d, "rootfs.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        yield open(tar, "rb").read()


@pytest.fixture(scope="module")
def image(g, image_tar):
    b64 = base64.b64encode(image_tar).decode()
    g.ok("base64 -d | fastman import fmtest:latest", stdin=b64)
    yield "fmtest"
    for c in g.out("fastman ps -a").splitlines()[1:]:
        cid = c.split()[0]
        g.run(f"fastman rm -f {cid}")


def test_images_listing(g, image):
    out = g.ok("fastman images")
    assert out.splitlines()[0].split() == ["REPOSITORY", "TAG", "IMAGE", "ID", "CREATED", "SIZE"]
    assert any(l.startswith("fmtest") and "latest" in l for l in out.splitlines()[1:])


def test_run_foreground(g, image):
    out, err, st = g.run(f"fastman run {image} /bin/hello")
    assert out.strip() == "hello from a fastman container" and st == 0


def test_run_auto_pulls_missing_image(g):
    """Like `docker run`, `fastman run <image>` pulls a missing image from the
    registry before running it — no separate `pull` step needed.

    Network-dependent (real Docker Hub): skipped if the registry is unreachable
    from the dev VM, so it never produces a false failure.
    """
    g.run("fastman rmi alpine:latest")  # start from "not present" if possible
    out, err, st = g.run("fastman run alpine echo AUTO_PULL_OK", timeout=120)
    if st != 0 and ("no network" in (out + err) or "pull" in (out + err).lower()):
        pytest.skip("registry unreachable from dev VM")
    assert "Unable to find image 'alpine:latest' locally" in out
    assert "Pulling from library/alpine" in out
    assert "AUTO_PULL_OK" in out
    assert st == 0, (out, err)


def test_run_rm_removes_container(g, image):
    """`fastman run --rm` discards the container after it exits (like Docker)."""
    out = g.ok(f"fastman run --rm --name fmt_rm {image} /bin/hello")
    assert out.strip() == "hello from a fastman container"
    # The container must not linger in `ps -a`.
    assert "fmt_rm" not in g.ok("fastman ps -a")


def test_run_interactive_stdin(g, image):
    """`fastman run -i <img> <cmd>` wires the caller's stdin to the container
    process (Docker's `-i`), so a command that reads stdin sees real input
    rather than an immediate EOF."""
    out, err, st = g.run(f"fastman run -i {image} /bin/catr", stdin="ping-from-host")
    assert "GOT:ping-from-host" in out, (out, err)
    assert st == 0


def test_logs_follow_streams_live(g, image):
    """`fastman logs -f` streams output as it is produced (Docker's -f)."""
    g.ok(f"fastman run -d --name fmt_lfs {image} /bin/sleeper")
    import time
    time.sleep(1)
    # Follow for a bounded window; /bin/sleeper prints "tick N" once a second.
    out = g.out("timeout 4 fastman logs -f fmt_lfs")
    assert "tick 0" in out and "tick 1" in out, out
    g.run("fastman rm -f fmt_lfs")


def test_logs_follow_exits_with_container(g, image):
    """`logs -f` on a finished container prints its log and returns (no hang)."""
    g.ok(f"fastman run -d --name fmt_lfe {image} /bin/hello")
    import time
    time.sleep(1)
    out, err, st = g.run("fastman logs -f fmt_lfe", timeout=15)
    assert "hello from a fastman container" in out
    assert st == 0, (out, err)
    g.run("fastman rm -f fmt_lfe")


def test_inspect_json(g, image):
    """`fastman inspect` emits valid Docker-style JSON describing the container."""
    import json
    import time
    g.ok(f"fastman run -d --name fmt_insp -e K=V -m 64m {image} /bin/sleeper")
    time.sleep(1)
    data = json.loads(g.ok("fastman inspect fmt_insp"))
    assert isinstance(data, list) and len(data) == 1
    c = data[0]
    assert c["Name"] == "/fmt_insp"
    assert c["State"]["Running"] is True
    assert c["State"]["Pid"] > 0
    assert c["Config"]["Cmd"] == ["/bin/sleeper"]
    assert "K=V" in c["Config"]["Env"]
    assert c["HostConfig"]["Memory"] == 64 * 1024 * 1024
    g.run("fastman rm -f fmt_insp")


def test_restart(g, image):
    """`fastman restart` stops then starts a container (new pid, still running)."""
    import json
    import time
    g.ok(f"fastman run -d --name fmt_rs {image} /bin/sleeper")
    time.sleep(1)
    pid1 = json.loads(g.ok("fastman inspect fmt_rs"))[0]["State"]["Pid"]
    g.ok("fastman restart fmt_rs")
    time.sleep(1)
    c = json.loads(g.ok("fastman inspect fmt_rs"))[0]
    assert c["State"]["Running"] is True, c
    assert c["State"]["Pid"] != pid1, c
    g.run("fastman rm -f fmt_rs")


def test_restart_with_memory_limit(g, image):
    """Regression: restarting a container that has a memory cgroup must not
    inherit the dead run's stale charges (which left the new process unable to
    allocate and made it exit immediately)."""
    import json
    import time
    g.ok(f"fastman run -d --name fmt_rsm -m 32m {image} /bin/sleeper")
    time.sleep(1)
    g.ok("fastman restart fmt_rsm")
    time.sleep(1)
    assert json.loads(g.ok("fastman inspect fmt_rsm"))[0]["State"]["Running"] is True
    g.run("fastman rm -f fmt_rsm")


def test_stats(g, image):
    """`fastman stats` reports CPU/memory/PIDs for a running container."""
    import time
    g.ok(f"fastman run -d --name fmt_st -m 64m {image} /bin/sleeper")
    time.sleep(1)
    out = g.ok("fastman stats fmt_st")
    head = out.splitlines()[0].split()
    assert head[:2] == ["CONTAINER", "ID"] and "PIDS" in head, out
    row = [l for l in out.splitlines()[1:] if "fmt_st" in l]
    assert row, out
    fields = row[0].split()
    assert fields[1] == "fmt_st", row
    assert fields[2].endswith("%"), row  # CPU %
    # A memory limit was set, so a real limit (not ∞) is shown, e.g. "/ 67.1MB".
    assert "MB" in row[0] and "/" in row[0], row
    # Last column is the PID count: at least the container's init process.
    assert fields[-1].isdigit() and int(fields[-1]) >= 1, row
    g.run("fastman rm -f fmt_st")


def test_cp_host_to_container_and_back(g, image):
    """`fastman cp` copies files between the host FS and a running container,
    both directions (Docker's `docker cp`). Verified by round-trip, since the
    minimal test image ships no shell/cat to read files from inside."""
    import time
    g.ok(f"fastman run -d --name fmt_cp {image} /bin/sleeper")
    time.sleep(1)
    # host -> container (into /root, which the image doesn't ship: parent is made)
    g.ok("echo hello-from-host > /tmp/fmt_hf.txt")
    g.ok("fastman cp /tmp/fmt_hf.txt fmt_cp:/root/hf.txt")
    # container -> host: read the same bytes back out
    g.ok("fastman cp fmt_cp:/root/hf.txt /tmp/fmt_back.txt")
    assert g.ok("cat /tmp/fmt_back.txt").strip() == "hello-from-host"
    # container -> host of a file the image ships (/etc/hostname = container-host)
    g.ok("fastman cp fmt_cp:/etc/hostname /tmp/fmt_out.txt")
    assert "container-host" in g.ok("cat /tmp/fmt_out.txt")
    g.run("fastman rm -f fmt_cp")


def test_cp_into_existing_dir_appends_basename(g, image):
    """Copying into an existing directory keeps the source's basename."""
    import time
    g.ok(f"fastman run -d --name fmt_cpd {image} /bin/sleeper")
    time.sleep(1)
    g.ok("echo appended > /tmp/fmt_named.txt")
    g.ok("fastman cp /tmp/fmt_named.txt fmt_cpd:/etc")  # /etc exists -> /etc/fmt_named.txt
    # It must be readable back at /etc/fmt_named.txt exactly.
    g.ok("fastman cp fmt_cpd:/etc/fmt_named.txt /tmp/fmt_named_back.txt")
    assert g.ok("cat /tmp/fmt_named_back.txt").strip() == "appended"
    g.run("fastman rm -f fmt_cpd")


def test_cp_directory(g, image):
    """`fastman cp` copies a directory tree (container -> host)."""
    import time
    g.ok(f"fastman run -d --name fmt_cpdir {image} /bin/sleeper")
    time.sleep(1)
    g.run("rm -rf /tmp/fmt_bin")
    g.ok("fastman cp fmt_cpdir:/bin /tmp/fmt_bin")
    listing = g.ok("ls /tmp/fmt_bin")
    assert "hello" in listing and "sleeper" in listing, listing
    g.run("fastman rm -f fmt_cpdir")


def test_cp_requires_running_container(g, image):
    """cp on a stopped container fails cleanly (the writable layer is ephemeral)."""
    import time
    g.ok(f"fastman run -d --name fmt_cps {image} /bin/hello")  # exits at once
    time.sleep(1)
    g.ok("echo y > /tmp/fmt_cps_src.txt")
    out, err, st = g.run("fastman cp /tmp/fmt_cps_src.txt fmt_cps:/root/x")
    assert st != 0 and "not running" in (out + err)
    g.run("fastman rm -f fmt_cps")


def test_sandbox_isolation(g, image):
    # The container reads its OWN /etc/hostname and cannot see the host's
    # /etc/shadow — proof the chroot/mount-namespace sandbox holds.
    out = g.ok(f"fastman run -e MARK=secret -w / {image} /bin/probe alpha")
    assert "argv: /bin/probe alpha" in out
    assert "cwd: /" in out
    assert "hostname: container-host" in out
    assert "host_etc_shadow: 0" in out
    assert "env MARK=secret" in out


def test_detached_ps_logs_stop(g, image):
    cid = g.ok(f"fastman run -d --name fmt_ticker {image} /bin/sleeper").strip()
    assert len(cid) >= 12
    import time
    time.sleep(2)
    ps = g.ok("fastman ps")
    assert "fmt_ticker" in ps and "Up" in ps
    logs = g.ok("fastman logs fmt_ticker")
    assert "tick 0" in logs and "tick 1" in logs
    # exec into the running container shares its namespace.
    ex = g.ok("fastman exec fmt_ticker /bin/probe inside")
    assert "hostname: container-host" in ex
    g.ok("fastman stop fmt_ticker")
    time.sleep(1)
    psa = g.ok("fastman ps -a")
    assert "Exited" in [l for l in psa.splitlines() if "fmt_ticker" in l][0]
    g.ok("fastman rm fmt_ticker")
    assert "fmt_ticker" not in g.ok("fastman ps -a")


def test_volume_bind(g, image):
    g.ok("mkdir -p /root/fmvol && echo hi > /root/fmvol/marker")
    out = g.ok(f"fastman run -v /root/fmvol:/data:ro {image} /bin/probe lsvol")
    assert "vol: marker" in out


def test_exec_interactive_stdin(g, image):
    # `fastman exec -it` must wire the caller's stdin to the container command.
    # Before the fix stdin was /dev/null, so an interactive `sh` (or anything
    # reading stdin) saw immediate EOF and exited doing nothing.
    cid = g.ok(f"fastman run -d --name fmt_it {image} /bin/sleeper").strip()
    import time
    time.sleep(1)
    try:
        out = g.ok("fastman exec -it fmt_it /bin/catr", stdin="PING-42\n")
        assert "GOT:PING-42" in out, out
    finally:
        g.run("fastman rm -f fmt_it")


def test_rmi(g, image_tar):
    b64 = base64.b64encode(image_tar).decode()
    g.ok("base64 -d | fastman import throwaway:v1", stdin=b64)
    assert "throwaway" in g.ok("fastman images")
    g.ok("fastman rmi throwaway:v1")
    assert "throwaway" not in g.ok("fastman images")


def test_info(g, image):
    out = g.ok("fastman info")
    assert "container engine" in out.lower()
    assert "Rootless" in out and "yes" in out


DYN = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
    char *m = malloc(64); strcpy(m, "dynamic libc works");
    printf("dyn: %s argc=%d\n", m, argc);
    free(m);
    return 0;
}
"""


def test_dynamically_linked_binary(g):
    """A real dynamically-linked glibc binary (needs ld-linux + libc.so.6 via
    file-backed mmap) runs in a container — the basis for real Docker images."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "r")
        os.makedirs(os.path.join(root, "bin"))
        c = os.path.join(d, "dyn.c")
        open(c, "w").write(DYN)
        exe = os.path.join(root, "bin", "dyn")
        subprocess.run(["gcc", "-O2", "-o", exe, c], check=True, capture_output=True)
        ldd = subprocess.run(["ldd", exe], check=True, capture_output=True, text=True).stdout
        import re as _re
        for lib in _re.findall(r"/[^\s]+\.so[^\s]*", ldd):
            dest = root + lib
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            subprocess.run(["cp", lib, dest], check=True)
        tar = os.path.join(d, "r.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    b64 = base64.b64encode(data).decode()
    g.ok("base64 -d | fastman import dyntest:latest", stdin=b64)
    out, err, st = g.run("fastman run dyntest /bin/dyn x y")
    assert out.strip() == "dyn: dynamic libc works argc=3", (out, err)
    assert st == 0
    g.run("fastman rmi dyntest:latest")
