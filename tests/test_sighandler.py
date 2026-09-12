"""User-installed signal handlers: sigaction/rt_sigreturn, alarm/SIGALRM,
kill+SIGUSR1, and sigprocmask blocking. postgres depends on all of these
(statement-timeout SIGALRM, latch SIGUSR1, masked critical sections).
"""
import base64
import os
import subprocess
import tempfile

import pytest

# 1) A SIGALRM handler set with sigaction must run (not kill the process).
ALARM = r"""
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t got = 0;
static void on_alrm(int s){ (void)s; got = 1; }
int main(void){
    struct sigaction sa = {0};
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    alarm(1);
    for (int i = 0; i < 100 && !got; i++) pause();
    printf("alarm handler ran: %d\n", (int)got);
    return got ? 0 : 1;
}
"""

# 2) kill(self, SIGUSR1) delivered to a handler; 3) sigprocmask blocks it until
#    unblocked; the pending signal then fires exactly once on unblock.
USR1 = r"""
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t n = 0;
static void on_usr1(int s){ (void)s; n++; }
int main(void){
    struct sigaction sa = {0};
    sa.sa_handler = on_usr1;
    sigaction(SIGUSR1, &sa, 0);

    sigset_t set, old;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, &old);      // block SIGUSR1
    raise(SIGUSR1);                          // stays pending
    printf("while blocked: %d\n", (int)n);   // must be 0
    sigprocmask(SIG_UNBLOCK, &set, 0);       // now it fires
    printf("after unblock: %d\n", (int)n);   // must be 1

    raise(SIGUSR1);                          // fires immediately (unblocked)
    printf("final: %d\n", (int)n);           // must be 2
    return (n == 2) ? 0 : 1;
}
"""

# 4) SIGPIPE set to SIG_IGN: writing to a closed pipe returns EPIPE, no kill.
IGNPIPE = r"""
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
int main(void){
    signal(SIGPIPE, SIG_IGN);
    int fds[2]; pipe(fds);
    close(fds[0]);                       // reader gone
    ssize_t r = write(fds[1], "x", 1);   // would SIGPIPE by default
    printf("write=%zd errno=%s\n", r, r < 0 ? strerror(errno) : "ok");
    return (r < 0 && errno == EPIPE) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def _run(g, src, name):
    binary = _compile(src)
    g.ok(f"base64 -d > /tmp/{name} && chmod +x /tmp/{name}", stdin=base64.b64encode(binary).decode())
    return g.run(f"fexec /tmp/{name}")


def test_sigalrm_handler_runs(g):
    out, err, st = _run(g, ALARM, "sa_alrm")
    assert "alarm handler ran: 1" in out, out + err
    assert st == 0


def test_sigusr1_and_blocking(g):
    out, err, st = _run(g, USR1, "sa_usr1")
    assert "while blocked: 0" in out, out + err
    assert "after unblock: 1" in out, out + err
    assert "final: 2" in out, out + err
    assert st == 0


def test_sigpipe_ignored(g):
    out, err, st = _run(g, IGNPIPE, "sa_pipe")
    assert "errno=Broken pipe" in out, out + err
    assert st == 0
