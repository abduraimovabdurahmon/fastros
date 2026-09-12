"""Minimal TCP accept path: a server binds, listens, waits with poll() for the
listening socket to become readable, then accept()s and reads. A child connects
and sends a byte. This is exactly the loop postgres' postmaster runs; if it
hangs, the poll/accept wakeup for an incoming connection is broken.
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
#include <poll.h>
#include <sys/wait.h>

int main(void){
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    int port = 55432;
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (void*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 16)){ perror("listen"); return 1; }

    pid_t pid = fork();
    if (pid == 0){
        int cs = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in c; memset(&c,0,sizeof c);
        c.sin_family = AF_INET; c.sin_port = htons(port); c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cs, (void*)&c, sizeof c)){ perror("connect"); _exit(2); }
        write(cs, "hi", 2);
        char b[4]; read(cs, b, 4);            /* wait for server reply */
        close(cs); _exit(0);
    }

    struct pollfd pfd = { .fd = ls, .events = POLLIN };
    int r = poll(&pfd, 1, 15000);             /* wait for an incoming connection */
    if (r <= 0){ printf("poll timeout r=%d\n", r); return 1; }
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }
    char buf[8]; int n = read(cs, buf, sizeof buf);
    buf[n>0?n:0] = 0;
    write(cs, "ok!", 3);
    int st; waitpid(pid, &st, 0);
    printf("server got: %s\n", buf);
    return 0;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_poll_accept_loopback(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/acc && chmod +x /tmp/acc", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/acc", timeout=60)
    assert "server got: hi" in out, out + err
    assert st == 0
