"""MAP_SHARED of a tmpfs file is shared across processes (POSIX shared memory,
what postgres' dynamic shared memory / shm_open relies on). A child writes
through its own mapping of the same file and the parent sees it.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>

int main(void){
    const char *path = "/tmp/shmfile.dat";
    int fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd < 0){ perror("open"); return 1; }
    if (ftruncate(fd, 4096)){ perror("ftruncate"); return 1; }
    volatile long *m = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED){ perror("mmap"); return 1; }
    m[0] = 111; m[1] = 0;

    pid_t pid = fork();
    if (pid == 0){
        int f2 = open(path, O_RDWR);
        volatile long *c = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, f2, 0);
        if (c == MAP_FAILED) _exit(2);
        c[0] += 111;          /* 111 -> 222, visible to the parent */
        c[1] = 0xCAFE;
        _exit(0);
    }
    int st; waitpid(pid, &st, 0);
    printf("shared file: m0=%ld m1=%#lx\n", m[0], m[1]);
    return (m[0] == 222 && m[1] == 0xCAFE) ? 0 : 1;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_shared_file_mmap(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/shmf && chmod +x /tmp/shmf", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/shmf")
    assert "shared file: m0=222 m1=0xcafe" in out, out + err
    assert st == 0
