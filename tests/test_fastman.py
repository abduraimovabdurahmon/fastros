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
