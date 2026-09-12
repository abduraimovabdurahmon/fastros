"""AF_UNIX accept → fork a worker that owns the connection → parent closes its
copy — postgres' postmaster pattern, but over a Unix socket (its default). The
forked worker must exchange data over the inherited connection. If it hangs,
that is why the postgres backend's auth stalls.
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
    const char *path = "/tmp/fu.sock";
    unlink(path);
    int ls = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un a; memset(&a,0,sizeof a);
    a.sun_family = AF_UNIX; strcpy(a.sun_path, path);
    if (bind(ls, (void*)&a, sizeof a)){ perror("bind"); return 1; }
    if (listen(ls, 8)){ perror("listen"); return 1; }

    pid_t conn = fork();
    if (conn == 0){
        int cs = socket(AF_UNIX, SOCK_STREAM, 0);
        struct sockaddr_un c; memset(&c,0,sizeof c);
        c.sun_family = AF_UNIX; strcpy(c.sun_path, path);
        if (connect(cs, (void*)&c, sizeof c)){ perror("connect"); _exit(2); }
        write(cs, "PING", 4);
        char b[8]; int n = read(cs, b, sizeof b);
        _exit(n == 4 && !memcmp(b, "PONG", 4) ? 0 : 3);
    }

    struct pollfd pfd = { .fd = ls, .events = POLLIN };
    if (poll(&pfd, 1, 15000) <= 0){ printf("accept timeout\n"); return 1; }
    int cs = accept(ls, 0, 0);
    if (cs < 0){ perror("accept"); return 1; }

    pid_t worker = fork();       /* backend owning the connection */
    if (worker == 0){
        close(ls);
        char b[8]; int n = read(cs, b, sizeof b);
        if (n == 4 && !memcmp(b, "PING", 4)) write(cs, "PONG", 4);
        _exit(0);
    }
    close(cs);                   /* parent drops its copy, like the postmaster */
    int st1, st2; waitpid(conn, &st1, 0); waitpid(worker, &st2, 0);
    int ok = WIFEXITED(st1) && WEXITSTATUS(st1) == 0;
    printf("unix fork handshake: %s\n", ok ? "ok" : "FAIL");
    return ok ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_unix_fork_handshake(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/fu && chmod +x /tmp/fu", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/fu", timeout=60)
    assert "unix fork handshake: ok" in out, out + err
    assert st == 0
