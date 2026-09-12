"""epoll-based accept over loopback — exactly how postgres' postmaster waits for
connections (epoll_create1 + epoll_ctl(listen fd) + epoll_wait + accept4). If
epoll_wait does not wake when a connection arrives on the registered listen
socket, the server never accepts — which is the postgres symptom.
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/wait.h>

int main(void){
    int port = 55444;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (void*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 16)){ perror("listen"); return 1; }

    /* A latch: a self-pipe whose read end shares the epoll set, exactly like
       postgres. It stays empty here, so only the listen socket ever fires. */
    int lp[2]; if (pipe(lp)){ perror("pipe"); return 1; }

    int ep = epoll_create1(0);
    struct epoll_event lev = { .events = EPOLLIN, .data = { .fd = lp[0] } };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, lp[0], &lev)){ perror("epoll_ctl latch"); return 1; }
    struct epoll_event ev = { .events = EPOLLIN, .data = { .fd = ls } };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, ls, &ev)){ perror("epoll_ctl"); return 1; }

    /* Fork "aux workers" that inherit the listen socket, epoll fd and latch
       pipe, then close them all — exactly what postgres' ClosePostmasterPorts
       does in every child. They must not tear down the shared listener. */
    for (int k = 0; k < 4; k++){
        pid_t w = fork();
        if (w == 0){ close(ls); close(ep); close(lp[0]); close(lp[1]); pause(); _exit(0); }
    }

    pid_t pid = fork();
    if (pid == 0){
        usleep(100000);  /* let the parent reach epoll_wait first */
        int cs = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in c; memset(&c,0,sizeof c);
        c.sin_family = AF_INET; c.sin_port = htons(port); c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cs, (void*)&c, sizeof c)){ perror("connect"); _exit(2); }
        write(cs, "hi", 2);
        char b[4]; read(cs, b, 4);
        close(cs); _exit(0);
    }

    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, 15000);   /* must wake when the child connects */
    if (n <= 0){ printf("epoll_wait timeout n=%d\n", n); return 1; }
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }
    char buf[8]; int r = read(cs, buf, sizeof buf); buf[r>0?r:0]=0;
    write(cs, "ok!", 3);
    int st; waitpid(pid, &st, 0);
    printf("epoll accept got: %s\n", buf);
    return 0;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_epoll_accept_loopback(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/eacc && chmod +x /tmp/eacc", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/eacc", timeout=60)
    assert "epoll accept got: hi" in out, out + err
    assert st == 0
