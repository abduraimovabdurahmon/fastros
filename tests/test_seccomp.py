"""seccomp + capabilities: a container can lock its own syscall surface with a
cBPF filter, and privileged ports require CAP_NET_BIND_SERVICE.

These are the container-hardening primitives Docker/Kubernetes expose; here they
are enforced by the FastROS kernel itself.
"""
import base64
import os
import subprocess
import tempfile

import pytest

# Installs a seccomp filter that returns EPERM for getpid(2) [nr 39 on x86_64],
# then calls getpid and reports errno. Proves the cBPF filter runs and its ERRNO
# action takes effect, while other syscalls (write/printf) still work.
SECCOMP_PROG = r"""
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>

int main(void){
    struct sock_filter filter[] = {
        /* load syscall nr */
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* if nr == __NR_getpid -> return ERRNO(EPERM) */
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_getpid, 0, 1),
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        /* else allow */
        BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof(filter)/sizeof(filter[0]), .filter = filter };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("no_new_privs"); return 2; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("set_seccomp"); return 3; }

    /* write still works (printf) */
    errno = 0;
    long pid = syscall(__NR_getpid);
    printf("getpid=%ld errno=%d(%s)\n", pid, errno, errno==EPERM?"EPERM":strerror(errno));
    /* a non-filtered syscall still works */
    printf("alive after filter\n");
    return 0;
}
"""

# Binds a port given on argv and reports success/errno — used to prove the
# CAP_NET_BIND_SERVICE check on privileged ports.
BINDER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):80;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(s,(void*)&a,sizeof a)){ printf("bind %d FAIL errno=%d(%s)\n", port, errno, errno==EACCES?"EACCES":strerror(errno)); return 1; }
    printf("bind %d OK\n", port);
    return 0;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def secimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(SECCOMP_PROG, os.path.join(root, "bin", "secprog"))
        _cc(BINDER, os.path.join(root, "bin", "binder"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import secimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "secimg:latest"


def test_seccomp_filter_errno(g, secimg):
    """A cBPF filter that ERRNOs getpid() takes effect; other syscalls still run."""
    out = g.ok("fastman run secimg /bin/secprog", timeout=40)
    assert "getpid=-1 errno=1(EPERM)" in out, out
    assert "alive after filter" in out, out


def test_cap_net_bind_service(g, secimg):
    """A non-root container cannot bind a privileged port (no CAP_NET_BIND_SERVICE),
    but can bind an unprivileged one; --cap-add NET_BIND_SERVICE restores it."""
    # Non-root: privileged port denied (the binder exits non-zero — use g.out).
    out = g.out("fastman run -u 1000 secimg /bin/binder 80", timeout=40)
    assert "bind 80 FAIL errno=13(EACCES)" in out, out
    # Non-root: unprivileged port allowed.
    out = g.ok("fastman run -u 1000 secimg /bin/binder 8080", timeout=40)
    assert "bind 8080 OK" in out, out
    # Non-root WITH the capability added: privileged port allowed.
    out = g.ok("fastman run -u 1000 --cap-add NET_BIND_SERVICE secimg /bin/binder 81", timeout=40)
    assert "bind 81 OK" in out, out


def test_root_binds_privileged_by_default(g, secimg):
    """Root keeps CAP_NET_BIND_SERVICE by default (backward compatible)."""
    out = g.ok("fastman run secimg /bin/binder 82", timeout=40)
    assert "bind 82 OK" in out, out
    # ...unless it is explicitly dropped (the binder exits non-zero — use g.out).
    out = g.out("fastman run --cap-drop NET_BIND_SERVICE secimg /bin/binder 83", timeout=40)
    assert "bind 83 FAIL errno=13(EACCES)" in out, out
