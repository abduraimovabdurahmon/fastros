"""Positional and vectored I/O integrity — postgres does ALL of its disk I/O
through pread/pwrite/preadv/pwritev at explicit offsets, so any offset bug
silently corrupts data pages. This writes a multi-MB file in 8 KB blocks (the
postgres buffer pattern) at block-aligned offsets out of order, then reads each
block back and checks a per-block marker; it also exercises preadv/pwritev with
multiple iovecs at an offset.
"""
import base64
import os
import subprocess
import tempfile

import pytest

SRC = r"""
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <stdlib.h>

#define BLK 8192
#define N   256          /* 2 MB total */

int main(void){
    int fd = open("/tmp/iotest.dat", O_RDWR|O_CREAT|O_TRUNC, 0600);
    if (fd < 0){ perror("open"); return 1; }

    static char buf[BLK];
    /* Write blocks out of order (odd first, then even) via pwrite. */
    for (int pass = 0; pass < 2; pass++){
        for (int i = (pass==0); i < N; i += 2){
            memset(buf, 0, BLK);
            /* stamp the block number at start and end */
            snprintf(buf, 32, "BLK%08d", i);
            snprintf(buf+BLK-16, 16, "END%08d", i);
            off_t off = (off_t)i * BLK;
            if (pwrite(fd, buf, BLK, off) != BLK){ perror("pwrite"); return 1; }
        }
    }

    /* Read every block back and verify both markers. */
    for (int i = 0; i < N; i++){
        memset(buf, 0, BLK);
        off_t off = (off_t)i * BLK;
        if (pread(fd, buf, BLK, off) != BLK){ perror("pread"); return 1; }
        char a[32], b[16];
        snprintf(a, 32, "BLK%08d", i);
        snprintf(b, 16, "END%08d", i);
        if (memcmp(buf, a, strlen(a)) || memcmp(buf+BLK-16, b, strlen(b))){
            printf("MISMATCH at block %d: head=%.11s tail=%.11s\n", i, buf, buf+BLK-16);
            return 1;
        }
    }

    /* preadv/pwritev with several iovecs at a non-zero offset. */
    off_t off = (off_t)100 * BLK + 123;
    char w0[100], w1[200], w2[50];
    memset(w0,'A',sizeof w0); memset(w1,'B',sizeof w1); memset(w2,'C',sizeof w2);
    struct iovec wv[3] = {{w0,sizeof w0},{w1,sizeof w1},{w2,sizeof w2}};
    ssize_t wn = pwritev(fd, wv, 3, off);
    if (wn != sizeof w0 + sizeof w1 + sizeof w2){ perror("pwritev"); return 1; }

    char r0[100], r1[200], r2[50];
    struct iovec rv[3] = {{r0,sizeof r0},{r1,sizeof r1},{r2,sizeof r2}};
    ssize_t rn = preadv(fd, rv, 3, off);
    if (rn != wn){ perror("preadv"); return 1; }
    if (memcmp(w0,r0,sizeof w0)||memcmp(w1,r1,sizeof w1)||memcmp(w2,r2,sizeof w2)){
        printf("VECTOR MISMATCH\n"); return 1;
    }

    close(fd);
    printf("io integrity ok: %d blocks, vectored %zd bytes\n", N, rn);
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
def io_bin():
    return _compile(SRC)


def test_positional_io_integrity(g, io_bin):
    g.ok("base64 -d > /tmp/iot && chmod +x /tmp/iot", stdin=base64.b64encode(io_bin).decode())
    out, err, st = g.run("fexec /tmp/iot")
    assert "io integrity ok" in out, out + err
    assert st == 0
