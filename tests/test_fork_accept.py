"""postgres' postmaster pattern: accept a connection, fork a backend that does
all the socket I/O, and have the parent close its own copy of the accepted fd.
The forked child must still be able to read and write the inherited connection.
If the child cannot communicate after the parent closes its copy, that is the
exact failure that leaves psql hanging on the handshake.
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
    int port = 55433;
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (void*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 16)){ perror("listen"); return 1; }

    pid_t conn = fork();
    if (conn == 0){
        int cs = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in c; memset(&c,0,sizeof c);
        c.sin_family = AF_INET; c.sin_port = htons(port); c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cs, (void*)&c, sizeof c)){ perror("connect"); _exit(2); }
        write(cs, "PING", 4);
        char b[8]; int n = read(cs, b, sizeof b);   /* wait for the worker's reply */
        if (n == 4 && !memcmp(b, "PONG", 4)) _exit(0);
        _exit(3);
    }

    struct pollfd pfd = { .fd = ls, .events = POLLIN };
    if (poll(&pfd, 1, 15000) <= 0){ printf("accept poll timeout\n"); return 1; }
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }

    pid_t worker = fork();          /* backend that owns the connection */
    if (worker == 0){
        close(ls);
        char b[8]; int n = read(cs, b, sizeof b);   /* read PING over inherited fd */
        if (n == 4 && !memcmp(b, "PING", 4)) write(cs, "PONG", 4);
        _exit(0);
    }
    close(cs);                      /* parent drops its copy, like the postmaster */

    int st1, st2; waitpid(conn, &st1, 0); waitpid(worker, &st2, 0);
    int okc = WIFEXITED(st1) && WEXITSTATUS(st1) == 0;
    printf("handshake over forked socket: %s\n", okc ? "ok" : "FAILED");
    return okc ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_forked_backend_socket(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/fka && chmod +x /tmp/fka", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/fka", timeout=60)
    assert "handshake over forked socket: ok" in out, out + err
    assert st == 0
