"""AF_UNIX stream sockets: bind a filesystem path, listen, accept, and exchange
data with a client that connects to that path. This is how postgres' clients
(psql) reach the server by default, and how initdb's temp server is contacted.
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
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/wait.h>

int main(void){
    const char *path = "/tmp/us.sock";
    unlink(path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ls < 0){ perror("socket"); return 1; }
    struct sockaddr_un a; memset(&a,0,sizeof a);
    a.sun_family = AF_UNIX; strcpy(a.sun_path, path);
    if (bind(ls, (void*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 8)){ perror("listen"); return 1; }

    pid_t pid = fork();
    if (pid == 0){
        int cs = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un c; memset(&c,0,sizeof c);
        c.sun_family = AF_UNIX; strcpy(c.sun_path, path);
        if (connect(cs, (void*)&c, sizeof c)){ perror("connect"); _exit(2); }
        write(cs, "PING", 4);
        char b[8]; int n = read(cs, b, sizeof b);
        _exit(n == 4 && !memcmp(b, "PONG", 4) ? 0 : 3);
    }

    struct pollfd pfd = { .fd = ls, .events = POLLIN };
    if (poll(&pfd, 1, 15000) <= 0){ printf("accept poll timeout\n"); return 1; }
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }
    char buf[8]; int n = read(cs, buf, sizeof buf); buf[n>0?n:0]=0;
    write(cs, "PONG", 4);
    int st; waitpid(pid, &st, 0);
    int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
    printf("unix stream: got=%s child=%s\n", buf, ok ? "ok" : "FAIL");
    return ok ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_unix_stream_socket(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/us && chmod +x /tmp/us", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/us", timeout=60)
    assert "unix stream: got=PING child=ok" in out, out + err
    assert st == 0
