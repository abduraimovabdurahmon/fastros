"""FPU/SSE state must be preserved across context switches. Several processes
run floating-point work concurrently; the scheduler preempts them into each
other. If the kernel does not save/restore the FPU on switch, one process's XMM
registers leak into another and a computation that must be deterministic starts
returning different results between identical runs. Each child computes the same
bounded checksum many times and fails if any run disagrees with the first.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define M (128*1024)
static double arr[M];

__attribute__((noinline))
static double work(double seed){
    double a=seed, b=seed+1, c=seed+2, d=seed+3;
    double e=seed+4, f=seed+5, g=seed+6, h=seed+7;
    for (int rep = 0; rep < 12; rep++){
        for (int i = 0; i < M; i++){
            double v = arr[i];
            a = a*0.5 + v*0.01; b = b*0.5 + a*0.01; c = c*0.5 + b*0.01; d = d*0.5 + c*0.01;
            e = e*0.5 + d*0.01; f = f*0.5 + e*0.01; g = g*0.5 + f*0.01; h = h*0.5 + g*0.01;
        }
    }
    return a+b+c+d+e+f+g+h;
}

int main(void){
    for (int i = 0; i < M; i++) arr[i] = (double)((i % 89) + 1) * 0.017;

    int nkids = 4;
    for (int k = 0; k < nkids; k++){
        pid_t pid = fork();
        if (pid == 0){
            double seed = 0.1 * (k + 1);
            double ref = work(seed);
            for (int t = 0; t < 6; t++){
                if (work(seed) != ref) _exit(2);   // FPU leaked across a switch
            }
            _exit(0);
        }
    }
    int ok = 1;
    for (int k = 0; k < nkids; k++){
        int st; wait(&st);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) ok = 0;
    }
    printf("fpu ctxsw ok=%d\n", ok);
    return ok ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_fpu_preserved_across_context_switch(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/fpucs && chmod +x /tmp/fpucs", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/fpucs", timeout=120)
    assert "fpu ctxsw ok=1" in out, out + err
    assert st == 0
