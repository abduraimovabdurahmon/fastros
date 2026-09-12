"""A connected AF_UNIX socket, made non-blocking and waited on with epoll for
incoming data — exactly how a postgres backend reads the startup packet. The
epoll must wake when the peer sends data. If it does not, the backend blocks
until its auth timeout (the observed symptom).
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <poll.h>
#include <time.h>
#include <sys/wait.h>

int main(void){
    const char *path = "/tmp/ued.sock";
    unlink(path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a; memset(&a,0,sizeof a);
    a.sun_family = AF_UNIX; strcpy(a.sun_path, path);
    if (bind(ls,(void*)&a,sizeof a)){ perror("bind"); return 1; }
    if (listen(ls,8)){ perror("listen"); return 1; }

    pid_t conn = fork();
    if (conn == 0){
        int cs = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un c; memset(&c,0,sizeof c);
        c.sun_family = AF_UNIX; strcpy(c.sun_path, path);
        if (connect(cs,(void*)&c,sizeof c)){ perror("connect"); _exit(2); }
        struct timespec ts={0,300000000}; nanosleep(&ts,0);  /* send AFTER server is in epoll_wait */
        write(cs, "STARTUP", 7);
        _exit(0);
    }

    struct pollfd pfd = { .fd = ls, .events = POLLIN };
    poll(&pfd, 1, 15000);
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }
    fcntl(cs, F_SETFL, O_NONBLOCK);            /* like the backend */

    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = cs } };
    epoll_ctl(ep, EPOLL_CTL_ADD, cs, &ev);
    struct epoll_event out[2];
    int r = epoll_wait(ep, out, 2, 10000);     /* must wake when peer writes */
    char buf[16]; int n = -1;
    if (r > 0) n = read(cs, buf, sizeof buf);
    int st; waitpid(conn, &st, 0);
    printf("epoll data: r=%d n=%d buf=%.7s\n", r, n, n>0?buf:"");
    return (r == 1 && n == 7) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_unix_epoll_data_ready(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/ued && chmod +x /tmp/ued", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/ued", timeout=60)
    assert "epoll data: r=1 n=7" in out, out + err
    assert st == 0
