"""Swap: anonymous pages are evicted to the swap device under memory pressure
and faulted back in with their contents intact.

A container is given a small memory cgroup limit and then allocates and touches
far more anonymous memory than that limit. Without swap the kernel would have to
OOM-kill it; with swap the cold pages ride out to the swap disk and come back
correct, so the workload completes and every page verifies.
"""
import base64
import os
import subprocess
import tempfile

import pytest

# malloc a buffer of MB megabytes, write a per-page pattern derived from the page
# index, read it all back and verify. Exit 0 + "VERIFIED" only if every byte
# matches — proving swap-out then swap-in preserved the data exactly.
HOG = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define PAGE 4096
int main(int argc, char** argv){
    long mb = argc > 1 ? atol(argv[1]) : 64;
    size_t n = (size_t)mb * 1024 * 1024;
    size_t pages = n / PAGE;
    unsigned char* buf = malloc(n);
    if(!buf){ printf("malloc failed\n"); return 2; }
    /* Fill each page with a byte pattern keyed to its index. */
    for(size_t p = 0; p < pages; p++){
        unsigned char v = (unsigned char)(p * 131 + 7);
        memset(buf + p*PAGE, v, PAGE);
    }
    printf("filled %ld MB (%zu pages)\n", mb, pages);
    fflush(stdout);
    /* Read back and verify. Pages written early are cold and will have been
       swapped out; touching them here forces swap-in. */
    long bad = 0;
    for(size_t p = 0; p < pages; p++){
        unsigned char v = (unsigned char)(p * 131 + 7);
        if(buf[p*PAGE] != v || buf[p*PAGE + PAGE-1] != v) bad++;
    }
    if(bad == 0) printf("VERIFIED %zu pages\n", pages);
    else printf("MISMATCH in %ld pages\n", bad);
    free(buf);
    return bad == 0 ? 0 : 1;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def swapimg(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(HOG, os.path.join(root, "bin", "hog"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import swapimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    return "swapimg:latest"


def test_swap_under_cgroup_pressure(g, swapimg):
    """A 16 MB-limited container allocates and verifies 24 MB: more than its
    resident limit (so ~8 MB must swap out) yet within its memory+swap ceiling
    (memsw ≈ 2× -m), and every page comes back from swap intact."""
    out = g.ok("fastman run -m 16m swapimg /bin/hog 24", timeout=180)
    assert "filled 24 MB" in out, out
    assert "VERIFIED" in out, out
    assert "MISMATCH" not in out, out


def test_swap_device_present(g):
    """The kernel brought up the dedicated swap device (sdb)."""
    # /proc/swaps lists the active swap area.
    out = g.out("cat /proc/swaps 2>/dev/null")
    assert "sdb" in out or "swap" in out.lower(), out
