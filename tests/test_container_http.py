"""End-to-end container networking: a static HTTP server runs inside a fastman
container and is served to a client over the guest's loopback — exercising the
socket syscalls, epoll, container sandbox and port publishing together.
"""
import base64
import os
import subprocess
import tempfile

import pytest

HTTPD = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#define PORT 8080

int main(void){
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(ls, (struct sockaddr*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 16)){ perror("listen"); return 1; }

    int ep = epoll_create1(0);
    struct epoll_event ev; memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN; ev.data.fd = ls;
    epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev);

    const char *body = "Hello from a FastROS container!\n";
    char resp[256];
    int rn = snprintf(resp, sizeof resp,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
        (int)strlen(body), body);

    printf("httpd: listening on %d\n", PORT); fflush(stdout);
    for (;;){
        struct epoll_event out[8];
        int n = epoll_wait(ep, out, 8, -1);
        for (int i = 0; i < n; i++){
            if (out[i].data.fd != ls) continue;
            int c = accept(ls, NULL, NULL);
            if (c < 0) continue;
            char buf[1024];
            read(c, buf, sizeof buf);          // consume the request
            write(c, resp, rn);
            close(c);
        }
    }
    return 0;
}
"""


def _cc(src: str, out: str):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def httpd_image(g):
    """Build a minimal rootfs image containing the static httpd, ship it in as a
    tarball, and import it as `myhttpd:latest`."""
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(HTTPD, os.path.join(root, "bin", "httpd"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    b64 = base64.b64encode(data).decode()
    g.ok("base64 -d | fastman import myhttpd:latest", stdin=b64, timeout=120)
    return "myhttpd:latest"


def test_container_http_serves(g, httpd_image):
    # Clean any prior instance, then run the server detached with a port map.
    g.run("fastman rm -f web 2>/dev/null; true")
    out = g.ok("fastman run -d --name web -p 8080:8080 myhttpd /bin/httpd")
    assert out.strip(), "run -d should print a container id"

    # Give it a moment to bind, then fetch it over loopback.
    import time
    time.sleep(1.5)
    body, err, st = g.run("curl -s -m 10 http://127.0.0.1:8080/", timeout=20)
    g.run("fastman rm -f web 2>/dev/null; true")
    assert "Hello from a FastROS container" in body, f"out={body!r} err={err!r} st={st}"
