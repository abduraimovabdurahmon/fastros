"""fastman build: build a real image from a Dockerfile.

The build context (a tar.gz containing a Dockerfile, a base rootfs image, and
files to COPY) is piped in on stdin. We build a small base image from static
binaries, then exercise FROM / RUN / COPY / ENV / WORKDIR / CMD by building on
top of it and running the result.
"""
import base64
import os
import subprocess
import tempfile

import pytest

# A base "shell": a tiny /bin/sh that runs `sh -c "<cmd>"` well enough for the
# Dockerfile RUN steps we use (it just execs /bin/busybox-like helpers we ship).
# To keep it real and simple, /bin/sh is a static program implementing the two
# things our RUN lines need: `>` redirection and `cp`. Rather than write a shell,
# we ship a static busybox-style multi-call binary as /bin/sh that understands
# `-c "echo TEXT > FILE"` and `-c "cat A > B"`.
SH = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
/* Minimal /bin/sh -c handler for the build test: supports
     echo WORDS > FILE
     cat SRC > FILE
   which is all the Dockerfile RUN lines below need. */
static int do_line(char *line){
    /* find redirection */
    char *gt = strchr(line, '>');
    char *out = NULL;
    if(gt){ *gt = 0; out = gt+1; while(*out==' ')out++; char*e=out; while(*e && *e!=' ' && *e!='\n')e++; *e=0; }
    /* tokenize command part */
    char *cmd = line; while(*cmd==' ')cmd++;
    if(strncmp(cmd,"echo ",5)==0){
        char *text = cmd+5;
        /* trim trailing spaces */
        int n=strlen(text); while(n>0 && (text[n-1]==' '||text[n-1]=='\n'))text[--n]=0;
        int fd = out?open(out,O_WRONLY|O_CREAT|O_TRUNC,0644):1;
        if(fd<0)return 1;
        write(fd,text,strlen(text)); write(fd,"\n",1);
        if(out)close(fd);
        return 0;
    }
    if(strncmp(cmd,"cat ",4)==0){
        char *src = cmd+4; int n=strlen(src); while(n>0 && (src[n-1]==' '))src[--n]=0;
        int in=open(src,O_RDONLY); if(in<0)return 1;
        int fd = out?open(out,O_WRONLY|O_CREAT|O_TRUNC,0644):1;
        char b[4096]; int r; while((r=read(in,b,sizeof b))>0) write(fd,b,r);
        close(in); if(out)close(fd);
        return 0;
    }
    /* true / no-op */
    return 0;
}
int main(int argc, char**argv){
    if(argc>=3 && strcmp(argv[1],"-c")==0){
        return do_line(argv[2]);
    }
    return 0;
}
"""

# A program the built image runs as CMD: prints a fixed banner + the contents of
# /etc/built (written by a RUN step) and /app/copied.txt (a COPY target).
APP = r"""
#include <stdio.h>
#include <stdlib.h>
int main(void){
    printf("APP up\n");
    FILE*f=fopen("/etc/built","r"); char b[128];
    if(f){ if(fgets(b,sizeof b,f)) printf("built=%s", b); fclose(f); }
    f=fopen("/app/copied.txt","r");
    if(f){ if(fgets(b,sizeof b,f)) printf("copied=%s", b); fclose(f); }
    char*e=getenv("BUILT_ENV"); if(e) printf("env=%s\n", e);
    return 0;
}
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def base_image(g):
    """Import a minimal base image `buildbase:latest` that ships /bin/sh + /bin/app."""
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        os.makedirs(os.path.join(root, "etc"))
        _cc(SH, os.path.join(root, "bin", "sh"))
        _cc(APP, os.path.join(root, "bin", "app"))
        tar = os.path.join(d, "base.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import buildbase:latest", stdin=base64.b64encode(data).decode(), timeout=120)


def _context_tar():
    """A build context: a Dockerfile plus a file to COPY."""
    DOCKERFILE = """\
FROM buildbase:latest
ENV BUILT_ENV=hello
WORKDIR /app
COPY copied.txt /app/copied.txt
RUN echo made-by-run > /etc/built
CMD ["/bin/app"]
"""
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "Dockerfile"), "w").write(DOCKERFILE)
        open(os.path.join(d, "copied.txt"), "w").write("this-was-copied\n")
        tar = os.path.join(d, "ctx.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", d, "Dockerfile", "copied.txt"], check=True)
        return open(tar, "rb").read()


def test_build_and_run(g, base_image):
    g.run("fastman rmi built:latest 2>/dev/null; true")
    data = _context_tar()
    out = g.ok("base64 -d | fastman build -t built:latest -", stdin=base64.b64encode(data).decode(), timeout=120)
    assert "Successfully built" in out, out
    assert "Successfully tagged built:latest" in out, out

    # The image shows up in `fastman images`.
    imgs = g.ok("fastman images")
    assert "built" in imgs, imgs

    # Run it: CMD, RUN result, COPY result and ENV must all be present.
    run = g.ok("fastman run built:latest", timeout=60)
    assert "APP up" in run, run
    assert "built=made-by-run" in run, run
    assert "copied=this-was-copied" in run, run
    assert "env=hello" in run, run

    g.run("fastman rmi built:latest 2>/dev/null; true")


def test_build_cache_reuse(g, base_image):
    """Rebuilding an unchanged context reuses cached layers (docker build cache)."""
    g.run("fastman rmi bc1 bc2 2>/dev/null; true")
    b64 = base64.b64encode(_context_tar()).decode()
    g.ok("base64 -d | fastman build -t bc1 -", stdin=b64, timeout=120)  # populate cache
    out2 = g.ok("base64 -d | fastman build -t bc2 -", stdin=b64, timeout=120)
    assert "Using cache" in out2, out2
    # A cached rebuild still yields a correct image.
    run = g.ok("fastman run bc2", timeout=60)
    assert "built=made-by-run" in run and "copied=this-was-copied" in run, run
    g.run("fastman rmi bc1 bc2 2>/dev/null; true")


def test_build_run_failure(g, base_image):
    """A RUN step that exits non-zero fails the build."""
    # `cat` of a missing file makes our minimal /bin/sh exit non-zero.
    DOCKERFILE = "FROM buildbase:latest\nRUN cat /no-such-file > /etc/x\n"
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "Dockerfile"), "w").write(DOCKERFILE)
        tar = os.path.join(d, "ctx.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", d, "Dockerfile"], check=True)
        data = open(tar, "rb").read()
    g.run("fastman rmi bad:latest 2>/dev/null; true")
    out, err, rc = g.run("base64 -d | fastman build -t bad:latest -", stdin=base64.b64encode(data).decode(), timeout=120)
    assert rc != 0, (out, err)
    combined = (out + err).lower()
    assert "build failed" in combined or "not found" in combined, (out, err)


def test_build_needs_from(g, base_image):
    """A Dockerfile without FROM is rejected."""
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "Dockerfile"), "w").write("RUN echo hi\n")
        tar = os.path.join(d, "ctx.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", d, "Dockerfile"], check=True)
        data = open(tar, "rb").read()
    out, err, rc = g.run("base64 -d | fastman build -t nofrom:latest -", stdin=base64.b64encode(data).decode(), timeout=60)
    assert rc != 0, (out, err)
