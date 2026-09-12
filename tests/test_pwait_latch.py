"""epoll_pwait with a signal mask that unblocks the latch signal during the wait
— the exact mechanism postgres' WaitEventSet uses. SIGURG is blocked normally;
epoll_pwait(..., &unblocked) must let the SIGURG (sent by another process) run
its handler and wake the wait via the self-pipe. If the wait only ends on its
timeout, latch-driven work (a postgres backend's startup, the checkpointer)
stalls for seconds/minutes.
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
#include <sys/epoll.h>
#include <time.h>
#include <sys/wait.h>

static int wpipe;
static void on_sigurg(int s){ (void)s; char c=1; write(wpipe, &c, 1); }

int main(void){
    int p[2]; if (pipe(p)){ perror("pipe"); return 1; }
    wpipe = p[1];
    struct sigaction sa = {0}; sa.sa_handler = on_sigurg; sigaction(SIGURG,&sa,0);

    sigset_t block, orig, unblocked;
    sigemptyset(&block); sigaddset(&block, SIGURG);
    sigprocmask(SIG_BLOCK, &block, &orig);   /* SIGURG blocked normally */
    sigemptyset(&unblocked);                 /* wait with everything unblocked */

    int ep = epoll_create1(0);
    struct epoll_event iev = { .events = EPOLLIN, .data = { .fd = p[0] } };
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &iev);

    pid_t pid = fork();
    if (pid == 0){
        struct timespec ts={0,300000000}; nanosleep(&ts,0);
        kill(getppid(), SIGURG);             /* set the parent's latch */
        _exit(0);
    }

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    struct epoll_event oev[2];
    int r;
    for (;;){
        r = epoll_pwait(ep, oev, 2, 10000, &unblocked);
        if (r < 0) continue;                 /* EINTR from the SIGURG delivery */
        break;
    }
    clock_gettime(CLOCK_MONOTONIC,&t1);
    long ms = (t1.tv_sec-t0.tv_sec)*1000 + (t1.tv_nsec-t0.tv_nsec)/1000000;
    int st; waitpid(pid,&st,0);
    printf("pwait latch: r=%d after %ld ms\n", r, ms);
    return (r == 1 && ms < 5000) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_epoll_pwait_sigmask_latch(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/pwl && chmod +x /tmp/pwl", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/pwl", timeout=60)
    assert "pwait latch: r=1" in out, out + err
    assert st == 0
