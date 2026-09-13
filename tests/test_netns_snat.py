"""netns phase 3b — outbound SNAT.

A container on a bridge network reaching an address outside its namespace
egresses through the host stack (the connection is made from the host's
identity, like Docker's MASQUERADE). Proven here by reaching a server that lives
on the host stack from a bridge container; a `--network none` container, which
is fully isolated, cannot.

Real internet egress is verified on the public instance (the dev VM's user-mode
network has no outbound path).
"""
import base64
import os
import subprocess
import tempfile

import pytest

# The slirp guest address on the host stack (stable default for the dev VM).
HOST_IP = "10.0.2.15"

SRV = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):9500;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 3;}
    if(listen(ls,16)){perror("listen");return 4;}
    printf("host server up :%d\n", port); fflush(stdout);
    for(;;){ int c=accept(ls,0,0); if(c<0)continue; char b[128]; read(c,b,sizeof b); write(c,"reached host server\n",20); close(c); }
}
"""

CLI = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char**argv){
    if(argc<3){ printf("usage\n"); return 2; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &a.sin_addr);
    if(connect(s,(void*)&a,sizeof a)){ printf("connect FAIL\n"); return 1; }
    write(s,"hi",2);
    char b[128]; int n=read(s,b,sizeof b-1); if(n<0)n=0; b[n]=0;
    printf("%s", b);
    return 0;
}
"""

IDLE = r"""
#include <time.h>
int main(void){ for(;;){ struct timespec t={1,0}; nanosleep(&t,0); } }
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def snatimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(SRV, os.path.join(root, "bin", "srv"))
        _cc(CLI, os.path.join(root, "bin", "cli"))
        _cc(IDLE, os.path.join(root, "bin", "idle"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import snatimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "snatimg:latest"


def _wait_log(g, name, needle, tries=30):
    import time
    for _ in range(tries):
        if needle in g.out(f"fastman logs {name}"):
            return True
        time.sleep(0.4)
    return False


def test_bridge_egress_reaches_host(g, snatimg):
    """A bridge container reaches a host-stack server via the host (SNAT)."""
    for n in ("hsrv", "becli"):
        g.run(f"fastman rm -f {n} 2>/dev/null; true")
    try:
        # Server on the host stack (default network).
        g.ok("fastman run -d --name hsrv snatimg /bin/srv 9500")
        assert _wait_log(g, "hsrv", "host server up"), g.out("fastman logs hsrv")
        # A bridge container connects to the host address; egress routes it out
        # through the host stack.
        g.ok("fastman run -d --network snatnet --name becli snatimg /bin/idle")
        out = g.ok(f"fastman exec becli /bin/cli {HOST_IP} 9500", timeout=25)
        assert "reached host server" in out, out
    finally:
        for n in ("hsrv", "becli"):
            g.run(f"fastman rm -f {n} 2>/dev/null; true")


def test_none_network_has_no_egress(g, snatimg):
    """A `--network none` container is fully isolated: no outbound path."""
    for n in ("hsrv2", "nocli"):
        g.run(f"fastman rm -f {n} 2>/dev/null; true")
    try:
        g.ok("fastman run -d --name hsrv2 snatimg /bin/srv 9501")
        assert _wait_log(g, "hsrv2", "host server up"), g.out("fastman logs hsrv2")
        g.ok("fastman run -d --network none --name nocli snatimg /bin/idle")
        out = g.out(f"fastman exec nocli /bin/cli {HOST_IP} 9501", timeout=25)
        assert "reached host server" not in out, f"isolation broken: {out!r}"
    finally:
        for n in ("hsrv2", "nocli"):
            g.run(f"fastman rm -f {n} 2>/dev/null; true")
