"""POSIX threads: clone(CLONE_VM|CLONE_THREAD|...) creates tasks sharing the
process address space, fds and signal handlers. Exercises thread creation,
a futex-backed mutex over shared memory, and pthread_join (which waits on the
CLONE_CHILD_CLEARTID futex and reads each thread's return value).
"""
import base64
import os
import subprocess
import tempfile

SRC = r"""
#include <pthread.h>
#include <stdio.h>
static long counter = 0;
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static void* worker(void* arg){
    long n = (long)arg;
    for (int i=0;i<100000;i++){ pthread_mutex_lock(&m); counter++; pthread_mutex_unlock(&m); }
    return (void*)(n*2);
}
int main(void){
    pthread_t t[4];
    for (long i=0;i<4;i++) if (pthread_create(&t[i],0,worker,(void*)i)){ printf("create failed\n"); return 2; }
    long sum=0;
    for (int i=0;i<4;i++){ void* r=0; pthread_join(t[i],&r); sum += (long)r; }
    printf("counter=%ld join_sum=%ld\n", counter, sum);
    return (counter==400000 && sum==12) ? 0 : 1;
}
"""

# A thread that exits while main is still going; then main returns (exit_group)
# must tear the whole process down cleanly (no hang).
SRC_EXITGROUP = r"""
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
static void* spin(void* a){ (void)a; for(;;){ struct timespec t={0,1000000}; nanosleep(&t,0);} return 0; }
int main(void){
    pthread_t t; pthread_create(&t,0,spin,0);
    struct timespec s={0,50000000}; nanosleep(&s,0);
    printf("main exiting with a live thread\n");
    return 0;  // glibc calls exit_group; the spinning thread must be killed
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-pthread", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_pthreads_mutex_join(g):
    b = _compile(SRC)
    g.ok("base64 -d > /tmp/thr && chmod +x /tmp/thr", stdin=base64.b64encode(b).decode())
    out, err, st = g.run("fexec /tmp/thr", timeout=60)
    assert "counter=400000 join_sum=12" in out, out + err
    assert st == 0


def test_exit_group_kills_threads(g):
    b = _compile(SRC_EXITGROUP)
    g.ok("base64 -d > /tmp/thrg && chmod +x /tmp/thrg", stdin=base64.b64encode(b).decode())
    out, err, st = g.run("fexec /tmp/thrg", timeout=30)
    assert "main exiting with a live thread" in out, out + err
    assert st == 0  # process exits cleanly despite the live thread
