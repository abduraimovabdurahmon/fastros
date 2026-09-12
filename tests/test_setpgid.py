"""setpgid(2): a job-control shell (bash) puts each pipeline in its own process
group by calling setpgid from BOTH the parent (after fork) and the child. When
the syscall was unimplemented bash printed "child setpgid: Function not
implemented" on every command run inside `fastman exec -it <c> bash`.
"""
import base64
import os
import subprocess
import tempfile

SRC = r"""
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
int main(void){
    pid_t c = fork();
    if (c == 0){                       /* child sets its own group, like bash's child */
        if (setpgid(0, 0)){ printf("child ERR %d\n", errno); _exit(1); }
        if (getpgid(0) != getpid()){ printf("child pgid wrong\n"); _exit(1); }
        _exit(0);
    }
    if (setpgid(c, c)){ printf("parent ERR %d\n", errno); return 1; }  /* parent, race-free */
    if (getpgid(c) != c){ printf("parent sees pgid %d != %d\n", getpgid(c), c); return 1; }
    /* cannot move an unrelated pid */
    if (setpgid(1, 1) == 0 || errno != ESRCH){ printf("unrelated allowed\n"); }
    int st; waitpid(c, &st, 0);
    printf("setpgid ok child=%d\n", WEXITSTATUS(st));
    return WEXITSTATUS(st);
}
"""


def _compile(src):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c"); out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


def test_setpgid_self_and_child(g):
    binary = _compile(SRC)
    g.ok("base64 -d > /tmp/spg && chmod +x /tmp/spg", stdin=base64.b64encode(binary).decode())
    out, err, st = g.run("fexec /tmp/spg", timeout=60)
    assert "setpgid ok child=0" in out, out + err
    assert st == 0
