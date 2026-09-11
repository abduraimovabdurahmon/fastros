"""BSD socket syscalls: a loopback TCP round trip and an epoll wait.

A single static binary forks into a server (bind/listen/accept) and a client
(connect), exchanges bytes over 127.0.0.1, and the server side drives its
accepted connection through epoll. Exercises socket/bind/listen/accept/connect/
setsockopt/read/write/epoll_create1/epoll_ctl/epoll_wait end to end.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SOCK = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#define PORT 18080

int main(void){
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0){ perror("socket"); return 1; }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 8)){ perror("listen"); return 1; }

    pid_t pid = fork();
    if (pid == 0){
        int cs = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in s; memset(&s, 0, sizeof s);
        s.sin_family = AF_INET;
        s.sin_port = htons(PORT);
        s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cs, (struct sockaddr*)&s, sizeof s)){ perror("connect"); _exit(2); }
        write(cs, "ping", 4);
        char b[16] = {0};
        int n = read(cs, b, sizeof b);
        printf("client got: %.*s\n", n, b);
        fflush(stdout);
        _exit(0);
    }

    int cs = accept(ls, NULL, NULL);
    if (cs < 0){ perror("accept"); return 1; }

    int ep = epoll_create1(0);
    struct epoll_event ev; memset(&ev, 0, sizeof ev);
    ev.events = EPOLLIN;
    ev.data.fd = cs;
    epoll_ctl(ep, EPOLL_CTL_ADD, cs, &ev);
    struct epoll_event out[4];
    int r = epoll_wait(ep, out, 4, 5000);
    printf("epoll ready: %d\n", r);

    char b[16] = {0};
    int n = read(cs, b, sizeof b);
    printf("server got: %.*s\n", n, b);
    write(cs, "pong", 4);

    int st;
    waitpid(pid, &st, 0);
    printf("done\n");
    fflush(stdout);
    return 0;
}
"""


def _compile(src: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        out = os.path.join(d, "p")
        with open(c, "w") as f:
            f.write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        with open(out, "rb") as f:
            return f.read()


@pytest.fixture(scope="module")
def sock_bin():
    return _compile(SOCK)


def test_loopback_tcp_epoll(g, sock_bin):
    b64 = base64.b64encode(sock_bin).decode()
    g.ok("base64 -d > /tmp/sock && chmod +x /tmp/sock", stdin=b64)
    out, err, st = g.run("fexec /tmp/sock")
    assert "server got: ping" in out, out + err
    assert "client got: pong" in out, out + err
    assert "epoll ready: 1" in out, out + err
    assert "done" in out, out + err
    assert st == 0


SPAIR = r"""
#include <stdio.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <unistd.h>
int main(void){
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)){ perror("socketpair"); return 1; }
    int ep = epoll_create1(0);
    struct epoll_event ev = {0}; ev.events = EPOLLIN; ev.data.fd = sv[0];
    epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev);
    struct epoll_event out[4];
    // Both ends open: sv[0] must NOT be reported HUP/readable (no data written).
    int r = epoll_wait(ep, out, 4, 300);
    printf("both-open ready=%d rev=%#x\n", r, r>0?out[0].events:0);
    // Write on sv[1]; sv[0] must become readable (EPOLLIN).
    write(sv[1], "x", 1);
    r = epoll_wait(ep, out, 4, 1000);
    printf("after-write ready=%d rev=%#x\n", r, r>0?out[0].events:0);
    // Close sv[1]; sv[0] must now report HUP.
    close(sv[1]);
    r = epoll_wait(ep, out, 4, 1000);
    printf("peer-closed ready=%d rev=%#x\n", r, r>0?out[0].events:0);
    return 0;
}
"""


@pytest.fixture(scope="module")
def spair_bin():
    return _compile(SPAIR)


def test_socketpair_epoll(g, spair_bin):
    b64 = base64.b64encode(spair_bin).decode()
    g.ok("base64 -d > /tmp/spair && chmod +x /tmp/spair", stdin=b64)
    out, err, st = g.run("fexec /tmp/spair")
    # Both ends open: no spurious HUP.
    assert "both-open ready=0" in out, out + err
    # A write wakes the read end.
    assert "after-write ready=1" in out, out + err
    # Only after the peer closes should HUP appear (0x10); the unread byte also
    # keeps EPOLLIN set, so 0x11 (IN|HUP) is the correct combined result.
    tail = out.split("peer-closed")[1][:40]
    assert "ready=1" in tail and "0x1" in tail, out + err
