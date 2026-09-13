"""netns phase 2 — a bridge network connects containers.

Two containers on the same `--network <name>` reach each other by IP through the
in-kernel software bridge, while a container on a different network (or none)
cannot. Each network is isolated; none can reach the host.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRV = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):8080;
    const char* tag = argc>2?argv[2]:"?";
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 3;}
    if(listen(ls,8)){perror("listen");return 4;}
    printf("listening :%d as %s\n", port, tag); fflush(stdout);
    char resp[64]; int rn=snprintf(resp,sizeof resp,"hello from %s\n",tag);
    for(;;){ int c=accept(ls,0,0); if(c<0)continue; char b[128]; read(c,b,sizeof b); write(c,resp,rn); close(c); }
}
"""

# Connect to <ip> <port>, print reply or a failure line.
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

# Idles so a container stays up to exec a client into it.
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
def brimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(SRV, os.path.join(root, "bin", "srv"))
        _cc(CLI, os.path.join(root, "bin", "cli"))
        _cc(IDLE, os.path.join(root, "bin", "idle"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import brimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "brimg:latest"


def _wait_listen(g, name, tries=30):
    import time
    for _ in range(tries):
        if "listening" in g.out(f"fastman logs {name}"):
            return True
        time.sleep(0.4)
    return False


def test_bridge_inter_container(g, brimg):
    for n in ("bsrv", "bcli"):
        g.run(f"fastman rm -f {n} 2>/dev/null; true")
    try:
        # Two containers on the same user network.
        g.ok("fastman run -d --network mynet --name bsrv brimg /bin/srv 8080 SRV")
        g.ok("fastman run -d --network mynet --name bcli brimg /bin/idle")
        assert _wait_listen(g, "bsrv"), g.out("fastman logs bsrv")

        srv_ip = g.ok("fastman ip bsrv").strip()
        assert srv_ip.startswith("10.88."), f"unexpected bridge ip: {srv_ip!r}"

        # The client container reaches the server by its bridge IP.
        out = g.ok(f"fastman exec bcli /bin/cli {srv_ip} 8080", timeout=25)
        assert "hello from SRV" in out, out
    finally:
        for n in ("bsrv", "bcli"):
            g.run(f"fastman rm -f {n} 2>/dev/null; true")


def test_bridge_isolation_between_networks(g, brimg):
    """A container on a different network cannot reach the server's bridge IP."""
    for n in ("isrv", "ocli"):
        g.run(f"fastman rm -f {n} 2>/dev/null; true")
    try:
        g.ok("fastman run -d --network neta --name isrv brimg /bin/srv 8080 ISO")
        g.ok("fastman run -d --network netb --name ocli brimg /bin/idle")
        assert _wait_listen(g, "isrv"), g.out("fastman logs isrv")
        srv_ip = g.ok("fastman ip isrv").strip()

        # ocli is on netb; the server is on neta — the connect must fail.
        out = g.out(f"fastman exec ocli /bin/cli {srv_ip} 8080", timeout=25)
        assert "hello from ISO" not in out, f"cross-network isolation broken: {out!r}"
        assert "connect FAIL" in out or out.strip() == "", out
    finally:
        for n in ("isrv", "ocli"):
            g.run(f"fastman rm -f {n} 2>/dev/null; true")
