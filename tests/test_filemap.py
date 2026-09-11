"""Private file-backed mmap must keep writes — including across an mprotect to
read-only (the RELRO pattern the dynamic linker uses when it relocates a shared
library's GOT and then write-protects it). If a write is lost, large dynamic
binaries read unrelocated pointers and crash.
"""
import base64
import os
import subprocess
import tempfile

import pytest

FILEMAP = r"""
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void){
    const char *path = "/tmp/mapf";
    int fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0644);
    char orig[8192];
    memset(orig, 0xAA, sizeof orig);
    write(fd, orig, sizeof orig);

    // Private file mapping, writable.
    unsigned char *m = mmap(0, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED){ perror("mmap"); return 1; }

    // Write a marker into two pages (like a relocation writing the GOT).
    m[0]    = 0xBB;
    m[4096] = 0xCC;
    printf("after-write: %02x %02x\n", m[0], m[4096]);

    // Write-protect the first page (RELRO), then read it back.
    if (mprotect(m, 4096, PROT_READ)){ perror("mprotect"); return 1; }
    printf("after-mprotect: %02x %02x\n", m[0], m[4096]);

    return 0;
}
"""


def _compile(src: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        out = os.path.join(d, "p")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        return open(out, "rb").read()


@pytest.fixture(scope="module")
def filemap_bin():
    return _compile(FILEMAP)


def test_private_filemap_survives_mprotect(g, filemap_bin):
    b64 = base64.b64encode(filemap_bin).decode()
    g.ok("base64 -d > /tmp/fmap && chmod +x /tmp/fmap", stdin=b64)
    out, err, st = g.run("fexec /tmp/fmap")
    assert "after-write: bb cc" in out, out + err
    # The written bytes MUST persist through the mprotect-to-read-only.
    assert "after-mprotect: bb cc" in out, out + err
    assert st == 0


# The dynamic linker reserves the whole library with one read-only mmap, then
# maps each segment with MAP_FIXED over it, relocates the data segment, and
# mprotects the RELRO part read-only. Reproduce that exact sequence.
LDPAT = r"""
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

int main(void){
    const char *path = "/tmp/mapf2";
    int fd = open(path, O_RDWR|O_CREAT|O_TRUNC, 0644);
    char orig[65536];
    memset(orig, 0xAA, sizeof orig);
    write(fd, orig, sizeof orig);

    // 1. Reserve the whole "library" read-only.
    unsigned char *base = mmap(0, 65536, PROT_READ, MAP_PRIVATE, fd, 0);
    if (base == MAP_FAILED){ perror("reserve"); return 1; }
    // 2. Map the "data segment" (second half) RW with MAP_FIXED over the reserve.
    unsigned char *data = base + 32768;
    unsigned char *d = mmap(data, 32768, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED, fd, 32768);
    if (d == MAP_FAILED){ perror("fixed"); return 1; }
    // 3. Relocate: write resolved pointers into the "GOT".
    d[0]      = 0x11;
    d[0x39a8] = 0x22;   // like the GLOB_DAT at 0x5839a8
    d[0x7000] = 0x33;
    // 4. RELRO: write-protect the relocated part.
    if (mprotect(d, 0x8000, PROT_READ)){ perror("mprotect"); return 1; }
    // 5. Read back.
    printf("ld-pattern: %02x %02x %02x (want 11 22 33)\n", d[0], d[0x39a8], d[0x7000]);
    return 0;
}
"""


@pytest.fixture(scope="module")
def ldpat_bin():
    return _compile(LDPAT)


def test_ld_reserve_fixed_relro(g, ldpat_bin):
    b64 = base64.b64encode(ldpat_bin).decode()
    g.ok("base64 -d > /tmp/ldp && chmod +x /tmp/ldp", stdin=b64)
    out, err, st = g.run("fexec /tmp/ldp")
    assert "ld-pattern: 11 22 33" in out, out + err
