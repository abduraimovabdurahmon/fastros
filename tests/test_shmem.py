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


# System V shared memory (shmget/shmat/shmdt/shmctl) — postgres uses a small
# segment as its cross-postmaster interlock and reads shm_nattch from it.
SYSVSHM = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
int main(void){
    int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT|0600);
    if (id < 0){ perror("shmget"); return 1; }
    volatile long *m = shmat(id, 0, 0);
    if (m == (void*)-1){ perror("shmat"); return 1; }
    m[0] = 100;
    pid_t pid = fork();
    if (pid == 0){
        volatile long *c = shmat(id, 0, 0);   // attach again in the child
        if (c == (void*)-1){ perror("shmat-child"); _exit(2); }
        c[0] += 23;                            // write to the SAME segment
        shmdt((void*)c);
        _exit(0);
    }
    int st; waitpid(pid, &st, 0);
    struct shmid_ds ds;
    shmctl(id, IPC_STAT, &ds);
    printf("sysv[0]=%ld segsz=%lu nattch=%lu\n",
           m[0], (unsigned long)ds.shm_segsz, (unsigned long)ds.shm_nattch);
    shmdt((void*)m);
    shmctl(id, IPC_RMID, 0);
    return 0;
}
"""


@pytest.fixture(scope="module")
def sysvshm_bin():
    return _compile(SYSVSHM)


def test_sysv_shared_memory(g, sysvshm_bin):
    g.ok("base64 -d > /tmp/sysvshm && chmod +x /tmp/sysvshm",
         stdin=base64.b64encode(sysvshm_bin).decode())
    out, err, st = g.run("fexec /tmp/sysvshm")
    # Child's write to the same segment is visible; nattch counted the parent.
    assert "sysv[0]=123" in out, out + err
    assert "segsz=4096" in out, out + err
    assert "nattch=1" in out, out + err   # parent still attached at IPC_STAT time
    assert st == 0
