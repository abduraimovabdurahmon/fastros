"""MAP_SHARED|MAP_ANONYMOUS memory must be shared across fork — a child's writes
are visible to the parent. This is what a database uses for its shared memory.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SHMEM = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
int main(void){
    volatile long *m = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED){ perror("mmap"); return 1; }
    m[0] = 100;
    m[1] = 0;
    pid_t pid = fork();
    if (pid == 0){
        m[0] += 23;       // modify shared memory in the child
        m[1] = 0xBEEF;    // a marker
        _exit(0);
    }
    int st; waitpid(pid, &st, 0);
    printf("shared[0]=%ld shared[1]=%#lx\n", m[0], m[1]);
    return 0;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


@pytest.fixture(scope="module")
def shmem_bin():
    return _compile(SHMEM)


def test_shared_anon_across_fork(g, shmem_bin):
    g.ok("base64 -d > /tmp/shm && chmod +x /tmp/shm", stdin=base64.b64encode(shmem_bin).decode())
    out, err, st = g.run("fexec /tmp/shm")
    # The child's writes must be visible in the parent.
    assert "shared[0]=123 shared[1]=0xbeef" in out, out + err
    assert st == 0
