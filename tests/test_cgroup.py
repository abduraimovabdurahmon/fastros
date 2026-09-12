"""Per-container resource limits (cgroups): --pids-limit caps the number of
tasks (fork returns EAGAIN over it), and -m caps resident memory (a page
commit over the cap fails, OOM-killing the offender). Enforced only for
containers that set a limit; unlimited ones are unaffected.
"""
import base64
import os
import subprocess
import tempfile

import pytest

FORKBOMB = r"""
#include <stdio.h>
#include <unistd.h>
#include <time.h>
int main(void){
    int n=0;
    for (int i=0;i<500;i++){
        pid_t p = fork();
        if (p==0){ struct timespec t={3,0}; nanosleep(&t,0); _exit(0); }  /* hold a slot during the loop */
        if (p<0) break;                    /* fork failed → hit the pid limit */
        n++;
    }
    printf("forked=%d\n", n); fflush(stdout);
    return 0;   /* children exit shortly after, so the container finishes */
}
"""

MEMHOG = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    int done=0;
    for (int mb=1; mb<=64; mb++){
        char *p = malloc(1024*1024);
        if (!p) break;
        memset(p, 1, 1024*1024);   /* touch → commit pages */
        done = mb;
        printf("at=%dMB\n", done); fflush(stdout);
    }
    printf("committed=%dMB\n", done); fflush(stdout);
    return 0;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def cg_image(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(FORKBOMB, os.path.join(root, "bin", "forkbomb"))
        _cc(MEMHOG, os.path.join(root, "bin", "memhog"))
        tar = os.path.join(d, "cg.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import cgimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    yield "cgimg:latest"
    g.run("for c in $(fastman ps -a | tail -n +2 | awk '{print $1}'); do fastman rm -f $c; done 2>/dev/null; true")


def test_pids_limit(g, cg_image):
    out = g.ok(f"fastman run --pids-limit 8 {cg_image} /bin/forkbomb", timeout=60)
    import re
    m = re.search(r"forked=(\d+)", out)
    assert m, out
    forked = int(m.group(1))
    # The cap (8 tasks incl. the main) stops fork well short of 500.
    assert 0 < forked < 20, f"expected the pid cap to bite, got forked={forked}"


def test_pids_unlimited(g, cg_image):
    # No limit → forks many more than the capped run (sanity that the cap, not a
    # bug, limited the previous test).
    out = g.ok(f"fastman run --pids-limit 64 {cg_image} /bin/forkbomb", timeout=60)
    import re
    forked = int(re.search(r"forked=(\d+)", out).group(1))
    assert forked > 20, out


def test_memory_limit(g, cg_image):
    # 20 MB cap: the hog is OOM-killed well before committing 64 MB.
    out, err, st = g.run(f"fastman run -m 20m {cg_image} /bin/memhog", timeout=60)
    assert "committed=64MB" not in out, out
    import re
    reached = [int(x) for x in re.findall(r"at=(\d+)MB", out)]
    top = max(reached) if reached else 0
    assert top < 40, f"memory cap did not bite (reached {top}MB)\n{out}{err}"


def test_memory_unlimited(g, cg_image):
    out = g.ok(f"fastman run {cg_image} /bin/memhog", timeout=60)
    assert "committed=64MB" in out, out
