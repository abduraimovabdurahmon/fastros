"""postgres 16+ latch on musl/alpine: SIGURG is blocked and drained through a
`signalfd` registered in an epoll set — there is NO handler and NO self-pipe.
Setting a latch is `kill(pid, SIGURG)`; the target's signalfd must become
readable so its epoll wakes. SIGURG's default disposition is *ignore*, so a
blocked-but-pending SIGURG must still be made pending (the ignore is applied
only at delivery, which a blocked signal never reaches) — otherwise every latch
wait stalls until its timeout. That was the real cause of postgres' 5-minute
recovery gap and its multi-user connection auth timeouts; the handler+self-pipe
tests in test_latch.py never exercised this path.
"""
import base64
import os
import subprocess
import tempfile

SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <time.h>

static int wait_latch(int sfd, int ep){
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    for(;;){
        struct epoll_event oev[4];
        int r=epoll_wait(ep,oev,4,5000);
        clock_gettime(CLOCK_MONOTONIC,&t1);
        long ms=(t1.tv_sec-t0.tv_sec)*1000+(t1.tv_nsec-t0.tv_nsec)/1000000;
        if(r==0){ fprintf(stderr,"TIMEOUT %ld ms\n",ms); return 1; }
        if(r<0){ if(errno==EINTR) continue; perror("epoll"); return 1; }
        struct signalfd_siginfo si; int n=read(sfd,&si,sizeof si);
        if(n!=(int)sizeof si || si.ssi_signo!=(unsigned)SIGURG){ fprintf(stderr,"bad read n=%d\n",n); return 1; }
        printf("woke %ld ms signo=%u\n", ms, si.ssi_signo);
        return 0;
    }
}

static int setup(int *sfd,int *ep){
    sigset_t m; sigemptyset(&m); sigaddset(&m,SIGURG);
    sigprocmask(SIG_BLOCK,&m,0);
    *sfd=signalfd(-1,&m,0);
    if(*sfd<0){perror("signalfd");return 1;}
    *ep=epoll_create1(0);
    struct epoll_event ev={.events=EPOLLIN,.data={.fd=*sfd}};
    return epoll_ctl(*ep,EPOLL_CTL_ADD,*sfd,&ev)?1:0;
}

int main(void){
    /* [A] a sibling sets the latch during the wait */
    int sfd,ep; if(setup(&sfd,&ep)) return 2;
    pid_t me=getpid();
    pid_t k=fork();
    if(k==0){ struct timespec ts={0,200000000}; nanosleep(&ts,0); kill(me,SIGURG); _exit(0); }
    int a=wait_latch(sfd,ep);
    int st; waitpid(k,&st,0);
    close(sfd); close(ep);

    /* [B] the latch is already set before the wait is entered */
    if(setup(&sfd,&ep)) return 2;
    kill(getpid(),SIGURG);
    int b=wait_latch(sfd,ep);
    close(sfd); close(ep);

    printf("signalfd latch: A=%s B=%s\n", a?"FAIL":"OK", b?"FAIL":"OK");
    return (a||b)?1:0;
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_signalfd_latch_wakes_epoll(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/sfdlatch && chmod +x /tmp/sfdlatch", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/sfdlatch", timeout=60)
    assert "signalfd latch: A=OK B=OK" in out, out + err
    assert st == 0
