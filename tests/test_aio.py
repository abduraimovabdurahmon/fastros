"""Linux AIO (io_setup/io_submit/io_getevents/io_destroy) via raw syscalls."""
import base64
import os
import subprocess
import tempfile

import pytest

AIO_C = r"""
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdio.h>
struct iocb { uint64_t data; uint32_t key; uint32_t rwf; uint16_t op; int16_t prio;
              uint32_t fd; uint64_t buf; uint64_t nbytes; int64_t off; uint64_t r2;
              uint32_t flags; uint32_t resfd; };
struct io_event { uint64_t data; uint64_t obj; int64_t res; int64_t res2; };
int main(void){
    unsigned long ctx = 0;
    if (syscall(206, 8, &ctx)) { printf("SETUP_FAIL\n"); return 1; }
    int fd = open("/tmp/aio.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) { printf("OPEN_FAIL\n"); return 1; }
    char w[15] = "AIO_PAYLOAD_ok";
    struct iocb cb; memset(&cb, 0, sizeof cb);
    cb.op = 1; cb.fd = fd; cb.buf = (uint64_t)(uintptr_t)w; cb.nbytes = 14; cb.off = 0;
    struct iocb *cbs[1] = { &cb };
    if (syscall(209, ctx, 1L, cbs) != 1) { printf("SUBMIT_FAIL\n"); return 1; }
    struct io_event ev;
    if (syscall(208, ctx, 1L, 1L, &ev, 0) != 1 || ev.res != 14) { printf("WRITE_RES=%ld\n",(long)ev.res); return 1; }
    char r[15]; memset(r, 0, sizeof r);
    struct iocb rb; memset(&rb, 0, sizeof rb);
    rb.op = 0; rb.fd = fd; rb.buf = (uint64_t)(uintptr_t)r; rb.nbytes = 14; rb.off = 0;
    struct iocb *rbs[1] = { &rb };
    syscall(209, ctx, 1L, rbs);
    if (syscall(208, ctx, 1L, 1L, &ev, 0) != 1 || ev.res != 14 || memcmp(r, w, 14)) { printf("READ_FAIL\n"); return 1; }
    syscall(207, ctx);
    printf("AIO_OK\n");
    return 0;
}
"""


@pytest.fixture(scope="module")
def aio_image(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        c = os.path.join(d, "aio.c")
        open(c, "w").write(AIO_C)
        subprocess.run(["gcc", "-static", "-O2", "-o", os.path.join(root, "bin", "aio"), c], check=True, capture_output=True)
        tar = os.path.join(d, "r.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        g.ok("base64 -d | fastman import aiotest:latest", stdin=base64.b64encode(open(tar, "rb").read()).decode())
    yield "aiotest:latest"
    g.run("fastman rmi aiotest:latest 2>/dev/null; true")


def test_aio_roundtrip(g, aio_image):
    """io_setup + io_submit(PWRITE) + io_getevents + PREAD round-trips correctly."""
    out = g.ok(f"fastman run --rm {aio_image} /bin/aio")
    assert "AIO_OK" in out, out
