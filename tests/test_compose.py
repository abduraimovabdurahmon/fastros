"""fastman compose: bring a multi-service stack up from a compose file, verify
both services serve, then tear the stack down.
"""
import base64
import os
import subprocess
import tempfile

import pytest

# HTTP server whose listen port comes from argv[1] (so two services can run).
HTTPD = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char **argv){
    int port = argc > 1 ? atoi(argv[1]) : 8080;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(ls,(void*)&a,sizeof a)){ perror("bind"); return 1; }
    listen(ls, 16);
    char body[64]; int bl = snprintf(body, sizeof body, "service on port %d\n", port);
    char resp[256];
    int rn = snprintf(resp, sizeof resp,
      "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", bl, body);
    for(;;){ int c=accept(ls,0,0); if(c<0)continue; char b[1024]; read(c,b,sizeof b); write(c,resp,rn); close(c);}
}
"""

COMPOSE = """\
services:
  alpha:
    image: httpd:latest
    command: ["/bin/httpd", "8080"]
    ports:
      - "8080:8080"
  beta:
    image: httpd:latest
    command: ["/bin/httpd", "8081"]
    ports:
      - "8081:8081"
    environment:
      - ROLE=secondary
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def compose_setup(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(HTTPD, os.path.join(root, "bin", "httpd"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import httpd:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    g.ok("base64 -d > /tmp/fastman-compose.yaml", stdin=base64.b64encode(COMPOSE.encode()).decode())


def test_compose_up_ps_down(g, compose_setup):
    import time
    g.run("fastman compose -f /tmp/fastman-compose.yaml down 2>/dev/null; true")
    out = g.ok("fastman compose -f /tmp/fastman-compose.yaml up", timeout=60)
    assert "alpha" in out and "beta" in out, out

    time.sleep(2)
    ps = g.ok("fastman compose -f /tmp/fastman-compose.yaml ps")
    assert "fastman_alpha" in ps and "fastman_beta" in ps, ps

    a = g.out("curl -s -m 8 http://127.0.0.1:8080/", timeout=15)
    b = g.out("curl -s -m 8 http://127.0.0.1:8081/", timeout=15)
    assert "port 8080" in a, a
    assert "port 8081" in b, b

    down = g.ok("fastman compose -f /tmp/fastman-compose.yaml down")
    assert "Removed fastman_alpha" in down and "Removed fastman_beta" in down, down
    # After down, nothing left for the project.
    ps2 = g.ok("fastman compose -f /tmp/fastman-compose.yaml ps")
    assert "fastman_alpha" not in ps2 and "fastman_beta" not in ps2, ps2
