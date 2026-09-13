"""netns phase 3 — publishing a private-namespace container's port to the host.

A container in an isolated network namespace binds its port inside that namespace
(invisible to the host). `-p HOST:CONT` forwards the host port to it, so a client
on the host loopback reaches the container — including remapping the port number.
"""
import base64
import os
import subprocess
import tempfile

import pytest

HTTPD = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char**argv){
    int port = argc>1?atoi(argv[1]):80;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 3;}
    if(listen(ls,16)){perror("listen");return 4;}
    printf("listening :%d\n", port); fflush(stdout);
    const char* body="published from a private netns\n";
    char resp[192]; int rn=snprintf(resp,sizeof resp,
        "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",(int)strlen(body),body);
    for(;;){ int c=accept(ls,0,0); if(c<0)continue; char b[512]; read(c,b,sizeof b); write(c,resp,rn); close(c); }
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def pubimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(HTTPD, os.path.join(root, "bin", "httpd"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import pubimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "pubimg:latest"


def _wait_listen(g, name, tries=30):
    import time
    for _ in range(tries):
        if "listening" in g.out(f"fastman logs {name}"):
            return True
        time.sleep(0.4)
    return False


def test_publish_from_private_netns(g, pubimg):
    """Server bound :80 inside a private netns; -p 8091:80 reaches it from host."""
    g.run("fastman rm -f pweb 2>/dev/null; true")
    try:
        g.ok("fastman run -d --network none -p 8091:80 --name pweb pubimg /bin/httpd 80")
        assert _wait_listen(g, "pweb"), g.out("fastman logs pweb")
        import time
        # Give the proxy a moment to come up, then curl the published host port.
        ok = False
        for _ in range(15):
            body = g.out("curl -s -m 6 http://127.0.0.1:8091/", timeout=12)
            if "published from a private netns" in body:
                ok = True
                break
            time.sleep(0.6)
        assert ok, g.out("curl -s -m 6 http://127.0.0.1:8091/", timeout=12)
    finally:
        g.run("fastman rm -f pweb 2>/dev/null; true")


def test_publish_on_bridge_network(g, pubimg):
    """The same publish works for a container on a user bridge network."""
    g.run("fastman rm -f bweb 2>/dev/null; true")
    try:
        g.ok("fastman run -d --network pubnet -p 8092:80 --name bweb pubimg /bin/httpd 80")
        assert _wait_listen(g, "bweb"), g.out("fastman logs bweb")
        import time
        ok = False
        for _ in range(15):
            body = g.out("curl -s -m 6 http://127.0.0.1:8092/", timeout=12)
            if "published from a private netns" in body:
                ok = True
                break
            time.sleep(0.6)
        assert ok, g.out("curl -s -m 6 http://127.0.0.1:8092/", timeout=12)
    finally:
        g.run("fastman rm -f bweb 2>/dev/null; true")
