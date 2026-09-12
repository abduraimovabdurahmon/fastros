"""Network namespaces: `--network none` gives a container its own isolated
loopback stack.

Two containers each bind 127.0.0.1:8080 at the same time — impossible on a shared
stack — and each reaches only its own server, proving independent port spaces and
loopback isolation. A client on the host stack cannot reach either.
"""
import base64
import os
import subprocess
import tempfile

import pytest

# Server: bind 127.0.0.1:<port>, reply "hello from <tag>" to each connection.
SRV = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):8080;
    const char* tag = argc>2?argv[2]:"?";
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 3;}
    if(listen(ls,8)){perror("listen");return 4;}
    printf("listening %s:%d as %s\n", "127.0.0.1", port, tag); fflush(stdout);
    char resp[64]; int rn=snprintf(resp,sizeof resp,"hello from %s\n",tag);
    for(;;){ int c=accept(ls,0,0); if(c<0)continue; char b[128]; read(c,b,sizeof b); write(c,resp,rn); close(c); }
}
"""

# Client: connect to 127.0.0.1:<port>, print the reply (or an error).
CLI = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):8080;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(s,(void*)&a,sizeof a)){ printf("connect FAIL\n"); return 1; }
    write(s,"hi",2);
    char b[128]; int n=read(s,b,sizeof b-1); if(n<0)n=0; b[n]=0;
    printf("%s", b);
    return 0;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def nsimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(SRV, os.path.join(root, "bin", "srv"))
        _cc(CLI, os.path.join(root, "bin", "cli"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import nsimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "nsimg:latest"


def _wait_listen(g, name, tries=30):
    import time
    for _ in range(tries):
        if "listening" in g.out(f"fastman logs {name}"):
            return True
        time.sleep(0.4)
    return False


def test_netns_isolated_ports(g, nsimg):
    for n in ("nsa", "nsb"):
        g.run(f"fastman rm -f {n} 2>/dev/null; true")
    try:
        # Both containers bind 127.0.0.1:8080 at the same time — only possible
        # because each has its own network namespace.
        a = g.ok("fastman run -d --network none --name nsa nsimg /bin/srv 8080 A")
        b = g.ok("fastman run -d --network none --name nsb nsimg /bin/srv 8080 B")
        assert a.strip() and b.strip()
        assert _wait_listen(g, "nsa"), g.out("fastman logs nsa")
        assert _wait_listen(g, "nsb"), g.out("fastman logs nsb")

        # A client inside each container reaches only its own server.
        ra = g.ok("fastman exec nsa /bin/cli 8080", timeout=20)
        assert "hello from A" in ra, ra
        rb = g.ok("fastman exec nsb /bin/cli 8080", timeout=20)
        assert "hello from B" in rb, rb
    finally:
        for n in ("nsa", "nsb"):
            g.run(f"fastman rm -f {n} 2>/dev/null; true")


def test_netns_host_cannot_reach(g, nsimg):
    """A server in a private netns is not reachable from the host stack."""
    g.run("fastman rm -f nsc 2>/dev/null; true")
    try:
        g.ok("fastman run -d --network none --name nsc nsimg /bin/srv 8087 C")
        assert _wait_listen(g, "nsc"), g.out("fastman logs nsc")
        # curl on the host loopback must not find the container's private port.
        out, err, st = g.run("curl -s -m 4 http://127.0.0.1:8087/", timeout=15)
        assert "hello from C" not in out, f"private netns port leaked to host: {out!r}"
    finally:
        g.run("fastman rm -f nsc 2>/dev/null; true")
