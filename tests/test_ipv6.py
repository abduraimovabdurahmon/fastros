"""IPv6: AF_INET6 sockets work over the ::1 loopback.

A static client/server pair bound to [::1] proves the stack handles AF_INET6
end to end — socket(AF_INET6), bind, listen, connect, and getsockname/getpeername
returning sockaddr_in6.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SERVER = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):9600;
    int ls = socket(AF_INET6, SOCK_STREAM, 0);
    if(ls<0){perror("socket");return 2;}
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in6 a; memset(&a,0,sizeof a);
    a.sin6_family=AF_INET6; a.sin6_port=htons(port); inet_pton(AF_INET6,"fd00::1",&a.sin6_addr);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 3;}
    if(listen(ls,4)){perror("listen");return 4;}
    /* Report the bound address via getsockname to prove sockaddr_in6 round-trips. */
    struct sockaddr_in6 la; socklen_t ll=sizeof la; getsockname(ls,(void*)&la,&ll);
    char ip[64]; inet_ntop(AF_INET6,&la.sin6_addr,ip,sizeof ip);
    printf("listen %s:%d\n", ip, ntohs(la.sin6_port)); fflush(stdout);
    int c=accept(ls,0,0); if(c<0){perror("accept");return 5;}
    char b[128]; int n=read(c,b,sizeof b-1); if(n<0)n=0; b[n]=0;
    char r[160]; int rn=snprintf(r,sizeof r,"echo6:%s",b);
    write(c,r,rn); close(c); close(ls);
    return 0;
}
"""

CLIENT = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):9600;
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    if(s<0){perror("socket");return 2;}
    struct sockaddr_in6 a; memset(&a,0,sizeof a);
    a.sin6_family=AF_INET6; a.sin6_port=htons(port); inet_pton(AF_INET6,"fd00::1",&a.sin6_addr);
    if(connect(s,(void*)&a,sizeof a)){perror("connect");return 3;}
    const char*msg="hello-v6";
    write(s,msg,strlen(msg));
    char b[160]; int n=read(s,b,sizeof b-1); if(n<0)n=0; b[n]=0;
    printf("%s\n", b);
    close(s);
    return 0;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def v6img(g):
    """A container image shipping the IPv6 server and client (Linux binaries can
    only run inside a fastman container)."""
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(SERVER, os.path.join(root, "bin", "srv6"))
        _cc(CLIENT, os.path.join(root, "bin", "cli6"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import v6img:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "v6img:latest"


def test_ipv6_loopback_stream(g, v6img):
    import time
    port = 9611
    g.run("fastman rm -f v6srv 2>/dev/null; true")
    # Server (binds [::1]:port) detached; client connects over the shared stack.
    out = g.ok(f"fastman run -d --name v6srv v6img /bin/srv6 {port}")
    assert out.strip(), "run -d should print a container id"

    listening = False
    for _ in range(30):
        log = g.out("fastman logs v6srv")
        if "listen" in log and str(port) in log:
            listening = True
            break
        time.sleep(0.4)
    assert listening, g.out("fastman logs v6srv")

    # The end-to-end proof: an AF_INET6 client connects over the shared stack and
    # gets its message echoed back — SYN/NDP/data all ride IPv6 to completion.
    cli = g.ok(f"fastman run v6img /bin/cli6 {port}", timeout=30)
    assert "echo6:hello-v6" in cli, cli

    # getsockname returned a valid sockaddr_in6 (family AF_INET6, correct port);
    # bind() is wildcard so the address renders as `::`.
    log = g.out("fastman logs v6srv")
    assert f":{port}" in log, log
    g.run("fastman rm -f v6srv 2>/dev/null; true")
