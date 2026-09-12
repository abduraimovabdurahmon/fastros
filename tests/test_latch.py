"""postgres-style latch: a process waits in poll() on a self-pipe; another
process sets the latch by sending it SIGURG; the SIGURG handler writes the
self-pipe, which must wake the poll(). This is exactly how postgres 16+ wakes a
checkpointer/postmaster/backend from WaitLatch. If the waiter only wakes on the
poll timeout, latch-driven work stalls for minutes (the observed symptom).
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <sys/wait.h>
#include <time.h>

static int wpipe;
static void on_sigurg(int s){ (void)s; char c = 1; write(wpipe, &c, 1); }

int main(void){
    int p[2]; if (pipe(p)){ perror("pipe"); return 1; }
    wpipe = p[1];

    struct sigaction sa = {0};
    sa.sa_handler = on_sigurg;
    sigaction(SIGURG, &sa, 0);      /* SIGURG is ignored by default; handler overrides */

    pid_t pid = fork();
    if (pid == 0){
        struct timespec ts = {0, 200000000}; nanosleep(&ts, 0);  /* 200 ms */
        kill(getppid(), SIGURG);    /* set the parent's latch */
        _exit(0);
    }

    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    int r;
    for (;;) {                        /* WaitLatch-style loop over EINTR */
        struct pollfd pfd = { .fd = p[0], .events = POLLIN };
        r = poll(&pfd, 1, 10000);
        if (r < 0) continue;          /* interrupted by the SIGURG delivery */
        break;
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    int st; waitpid(pid, &st, 0);
    printf("latch woke poll: r=%d after %ld ms\n", r, ms);
    return (r == 1 && ms < 5000) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_sigurg_latch_wakes_poll(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/latch && chmod +x /tmp/latch", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/latch", timeout=60)
    assert "latch woke poll: r=1" in out, out + err
    assert st == 0


# The same latch, but waited on with epoll (as postgres' WaitEventSet does).
ESRC = SRC.replace("#include <poll.h>", "#include <sys/epoll.h>").replace(
    r"""    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    int r;
    for (;;) {                        /* WaitLatch-style loop over EINTR */
        struct pollfd pfd = { .fd = p[0], .events = POLLIN };
        r = poll(&pfd, 1, 10000);
        if (r < 0) continue;          /* interrupted by the SIGURG delivery */
        break;
    }""",
    r"""    int ep = epoll_create1(0);
    struct epoll_event iev = { .events = EPOLLIN, .data = { .fd = p[0] } };
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &iev);
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    int r; struct epoll_event oev[2];
    for (;;) {                        /* WaitEventSet-style loop over EINTR */
        r = epoll_wait(ep, oev, 2, 10000);
        if (r < 0) continue;          /* interrupted by the SIGURG delivery */
        break;
    }""")


def test_sigurg_latch_wakes_epoll(g):
    binary = _compile(ESRC)
    g.ok("base64 -d > /tmp/latche && chmod +x /tmp/latche", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/latche", timeout=60)
    assert "latch woke poll: r=1" in out, out + err
    assert st == 0
