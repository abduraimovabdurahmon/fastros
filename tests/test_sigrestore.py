"""Asynchronous signal register save/restore integrity. A periodic SIGALRM
(delivered off the timer interrupt, so it lands on arbitrary instructions)
must not perturb the interrupted computation by even one register. The main
loop keeps a running checksum across many registers/locals while the handler
fires hundreds of times; a single mis-restored register corrupts the result.
This is exactly the failure mode that garbles a program's heap under load.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>

static volatile sig_atomic_t ticks = 0;
static void on_alrm(int s){ (void)s; ticks++; }

#define N (256*1024)   /* 256K u64 = 2 MB, touched every pass (not optimizable) */

/* Checksum a heap array while mixing many live registers. The array read makes
   the loop un-eliminable; a mis-restored register after an async SIGALRM shows
   up as a checksum that differs between otherwise identical passes. */
__attribute__((noinline))
static uint64_t work(const uint64_t *arr){
    uint64_t a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8;
    for (int rep = 0; rep < 40; rep++){
        for (int i = 0; i < N; i++){
            uint64_t v = arr[i];
            a += v;  b ^= a;  c += b;  d ^= c;
            e += d;  f ^= e;  g += f;  h ^= g;
            a = (a<<7)|(a>>57);
        }
    }
    return a^b^c^d^e^f^g^h;
}

int main(void){
    uint64_t *arr = malloc(N*sizeof(uint64_t));
    for (int i = 0; i < N; i++) arr[i] = (uint64_t)i*2654435761u + 0x1234;

    uint64_t ref = work(arr);   /* reference, no timer armed */

    struct sigaction sa = {0};
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it;
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 4000; /* 4 ms */
    it.it_value = it.it_interval;
    setitimer(ITIMER_REAL, &it, 0);

    int bad = 0;
    for (int pass = 0; pass < 5; pass++){
        if (work(arr) != ref) bad++;   /* any async-corrupted pass differs */
    }

    struct itimerval off = {0};
    setitimer(ITIMER_REAL, &off, 0);

    printf("ticks=%d bad=%d\n", (int)ticks, bad);
    return (bad == 0 && ticks > 0) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_async_signal_preserves_registers(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/sigr && chmod +x /tmp/sigr", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/sigr", timeout=120)
    assert "bad=0" in out, out + err     # no interrupted pass was corrupted
    assert "ticks=0" not in out, out + err  # the async timer actually fired
    assert st == 0


# The same, but for XMM/FPU state: the interrupted loop accumulates in floating
# point (compiler keeps live values in XMM), and the handler itself does FP work
# to clobber those registers. Without the kernel saving/restoring FPU state
# across the handler, the interrupted result is corrupted.
FPSRC = r"""
#include <stdio.h>
#include <signal.h>
#include <sys/time.h>

static volatile sig_atomic_t ticks = 0;
static volatile double sink = 0;
/* Handler does bounded FP work to clobber XMM registers. */
static void on_alrm(int s){ (void)s; ticks++; double x = 0.5;
    for (int i=0;i<64;i++) x = x*0.7 + 0.11; sink = x; }

#define M (256*1024)
static double arr[M];

/* Memory-bound so it runs long enough for the async timer to fire, and keeps
   several FP accumulators live in XMM across each iteration. Values stay
   bounded (no inf/NaN), so the result is deterministic and the comparison is
   meaningful — if a signal handler clobbers XMM without the kernel saving it,
   an interrupted pass differs. */
__attribute__((noinline))
static double work(void){
    double a=0.1,b=0.2,c=0.3,d=0.4,e=0.5,f=0.6,g=0.7,h=0.8;
    for (int rep = 0; rep < 40; rep++){
        for (int i = 0; i < M; i++){
            double v = arr[i];
            a = a*0.5 + v*0.01;  b = b*0.5 + a*0.01;  c = c*0.5 + b*0.01;
            d = d*0.5 + c*0.01;  e = e*0.5 + d*0.01;  f = f*0.5 + e*0.01;
            g = g*0.5 + f*0.01;  h = h*0.5 + g*0.01;
        }
    }
    return a+b+c+d+e+f+g+h;
}

int main(void){
    for (int i = 0; i < M; i++) arr[i] = (double)((i % 97) + 1) * 0.013;
    double ref = work();

    struct sigaction sa = {0};
    sa.sa_handler = on_alrm;
    sigaction(SIGALRM, &sa, 0);
    struct itimerval it;
    it.it_interval.tv_sec = 0; it.it_interval.tv_usec = 4000;
    it.it_value = it.it_interval;
    setitimer(ITIMER_REAL, &it, 0);

    int bad = 0;
    for (int pass = 0; pass < 5; pass++){
        if (work() != ref) bad++;
    }
    struct itimerval off = {0};
    setitimer(ITIMER_REAL, &off, 0);

    printf("ticks=%d bad=%d\n", (int)ticks, bad);
    return (bad == 0 && ticks > 0) ? 0 : 1;
}
"""


def test_async_signal_preserves_fpu(g):
    binary = _compile(FPSRC)
    g.ok("base64 -d > /tmp/sigf && chmod +x /tmp/sigf", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/sigf", timeout=120)
    assert "bad=0" in out, out + err
    assert "ticks=0" not in out, out + err
    assert st == 0
