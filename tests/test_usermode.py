"""Linux-ABI user mode: run real static x86_64 ELF binaries via `fexec`.

The binaries are compiled here (the harness image has gcc), shipped into the
guest base64-encoded, and executed. This exercises the ELF loader, the
address space (demand paging, COW fork), the SYSCALL path and the syscall
table end to end.
"""
import base64
import subprocess
import textwrap

import pytest

FREESTANDING = r"""
static long s(long n,long a,long b,long c){long r;
  __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c):"rcx","r11","memory");return r;}
static unsigned sl(const char*p){unsigned n=0;while(p[n])n++;return n;}
static void put(const char*m){s(1,1,(long)m,sl(m));}
void _start(void){
  long pid=s(57,0,0,0);              /* fork */
  if(pid==0){ put("child\n"); s(60,0,0,0); }
  int st=0; s(61,pid,(long)&st,0);   /* wait4 */
  put("parent\n");
  s(60,5,0,0);                       /* exit 5 */
}
"""

GLIBC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv){
  char *buf = malloc(64);
  strcpy(buf, "malloc+printf work");
  printf("argc=%d %s\n", argc, buf);
  free(buf);
  return 42;
}
"""


def _compile(src: str, args: list[str]) -> bytes:
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        out = os.path.join(d, "p")
        with open(c, "w") as f:
            f.write(src)
        subprocess.run(["gcc", *args, "-o", out, c], check=True, capture_output=True)
        with open(out, "rb") as f:
            return f.read()


def _ship_and_run(g, binary: bytes, path: str, args: str = ""):
    b64 = base64.b64encode(binary).decode()
    g.ok(f"base64 -d > {path} && chmod +x {path}", stdin=b64)
    return g.run(f"fexec {path} {args}")


@pytest.fixture(scope="module")
def freestanding_bin():
    return _compile(FREESTANDING, ["-static", "-nostdlib", "-fno-stack-protector"])


@pytest.fixture(scope="module")
def glibc_bin():
    return _compile(GLIBC, ["-static", "-O2"])


def test_freestanding_fork_exit(g, freestanding_bin):
    out, err, st = _ship_and_run(g, freestanding_bin, "/tmp/fs")
    assert "child" in out and "parent" in out
    assert out.index("child") < out.index("parent")
    assert st == 5


def test_static_glibc(g, glibc_bin):
    out, err, st = _ship_and_run(g, glibc_bin, "/tmp/hw", "a b c")
    assert out.strip() == "argc=4 malloc+printf work"
    assert st == 42


def test_glibc_reads_files(g, glibc_bin):
    # A glibc program that reads /etc/hostname through stdio.
    src = textwrap.dedent(r"""
        #include <stdio.h>
        int main(){ FILE*f=fopen("/etc/hostname","r"); if(!f)return 1;
          char b[64]; if(!fgets(b,sizeof b,f))return 2; printf("host=%s",b);
          fclose(f); return 0; }
    """)
    binary = _compile(src, ["-static", "-O2"])
    out, err, st = _ship_and_run(g, binary, "/tmp/rd")
    assert out.strip() == "host=fastros" and st == 0


def test_no_kernel_regression_after_user_runs(g):
    # The kernel is still healthy after running user processes.
    assert g.ok("echo alive").strip() == "alive"
    assert "MemFree" in g.ok("cat /proc/meminfo")
