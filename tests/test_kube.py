"""fastman kube: apply a Kubernetes manifest (Deployments + Service), see pods
and deployments, reach a pod, then delete a deployment.
"""
import base64
import os
import subprocess
import tempfile

import pytest

HTTPD = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
int main(int argc, char **argv){
    int port = argc>1?atoi(argv[1]):8080;
    int ls=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 1;} listen(ls,16);
    char b[64]; int bn=snprintf(b,sizeof b,"kube pod alive pid=%d\n",(int)getpid());
    char r[192];
    int rn=snprintf(r,sizeof r,"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",bn,b);
    for(;;){int c=accept(ls,0,0); if(c<0)continue; char x[512]; read(c,x,sizeof x); write(c,r,rn); close(c);}
}
"""

WORKER = r"""
#include <time.h>
int main(void){ for(;;){ struct timespec t={1,0}; nanosleep(&t,0); } return 0; }
"""

# Prints and exits — usable as a `kube exec` target (the image has no shell).
INFO = r"""
#include <stdio.h>
int main(int argc, char **argv){ printf("info ran argc=%d\n", argc); return 0; }
"""

MANIFEST = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: appimg:latest
          command: ["/bin/httpd", "8080"]
          ports:
            - containerPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: worker
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: worker
          image: appimg:latest
          command: ["/bin/worker"]
---
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector:
    app: web
  ports:
    - port: 80
      targetPort: 8080
"""


def _cc(src, out):
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)


@pytest.fixture(scope="module")
def kube_setup(g):
    with tempfile.TemporaryDirectory() as d:
        root = os.path.join(d, "root")
        os.makedirs(os.path.join(root, "bin"))
        _cc(HTTPD, os.path.join(root, "bin", "httpd"))
        _cc(WORKER, os.path.join(root, "bin", "worker"))
        _cc(INFO, os.path.join(root, "bin", "info"))
        tar = os.path.join(d, "img.tar.gz")
        subprocess.run(["tar", "czf", tar, "-C", root, "."], check=True)
        data = open(tar, "rb").read()
    g.ok("base64 -d | fastman import appimg:latest", stdin=base64.b64encode(data).decode(), timeout=120)
    g.ok("base64 -d > /tmp/k8s.yaml", stdin=base64.b64encode(MANIFEST.encode()).decode())


def test_kube_apply_get_delete(g, kube_setup):
    import time
    # Clean any prior run.
    g.run("fastman kube delete web 2>/dev/null; fastman kube delete worker 2>/dev/null; true")

    out = g.ok("fastman kube apply -f /tmp/k8s.yaml", timeout=60)
    assert "web/web-0 created" in out, out
    assert "worker/worker-0 created" in out and "worker/worker-1 created" in out, out
    assert "service web created" in out, out

    assert _wait(lambda: all(_running(g, p) for p in ("web-0", "worker-0", "worker-1"))), g.ok("fastman kube get pods")

    assert _wait(lambda: "2/2" in "".join(l for l in g.ok("fastman kube get deployments").splitlines() if "worker" in l)), g.ok("fastman kube get deployments")
    deps = g.ok("fastman kube get deployments")
    assert "web" in deps and "1/1" in deps, deps

    svcs = g.ok("fastman kube get services")
    assert "web" in svcs and "80" in svcs, svcs

    # Reach the pod through its Service (port 80) — the pod's declared 8080 is
    # remapped to a unique backend port, so the Service is the entry point.
    assert _wait(lambda: "kube pod alive" in g.out("curl -s -m 8 http://127.0.0.1:80/", timeout=15), tries=10), "service curl"

    d = g.ok("fastman kube delete worker")
    assert 'deployment "worker" deleted' in d, d
    pods2 = g.ok("fastman kube get pods")
    assert "worker-0" not in pods2 and "web-0" in pods2, pods2

    g.run("fastman kube delete web 2>/dev/null; true")


HIVE = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: hive
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: hive
          image: appimg:latest
          command: ["/bin/worker"]
"""


# Timing helpers — the guest is slow/contended under full-suite TCG load, so
# poll for the desired state instead of sleeping a fixed amount.
def _running(g, pod):
    line = [l for l in g.ok("fastman kube get pods").splitlines() if l.startswith(pod + " ")]
    return bool(line) and "Running" in line[0]


def _absent(g, pod):
    return not any(l.startswith(pod + " ") for l in g.ok("fastman kube get pods").splitlines())


def _wait(pred, tries=30, delay=1.0):
    import time
    for _ in range(tries):
        if pred():
            return True
        time.sleep(delay)
    return False


@pytest.fixture
def hive(g, kube_setup):
    g.ok("base64 -d > /tmp/hive.yaml", stdin=base64.b64encode(HIVE.encode()).decode())
    g.run("fastman kube delete hive 2>/dev/null; true")
    g.ok("fastman kube apply -f /tmp/hive.yaml", timeout=60)
    assert _wait(lambda: _running(g, "hive-0") and _running(g, "hive-1")), g.ok("fastman kube get pods")
    yield
    g.run("fastman kube delete hive 2>/dev/null; true")


def test_kube_scale(g, hive):
    up = g.ok("fastman kube scale hive --replicas=3")
    assert 'scaled to 3' in up, up
    assert _wait(lambda: all(_running(g, p) for p in ("hive-0", "hive-1", "hive-2"))), g.ok("fastman kube get pods")
    dn = g.ok("fastman kube scale deployment/hive --replicas=1")
    assert 'scaled to 1' in dn, dn
    assert _wait(lambda: _running(g, "hive-0") and _absent(g, "hive-1") and _absent(g, "hive-2")), g.ok("fastman kube get pods")


def test_kube_self_healing(g, hive):
    import re, time
    # Find hive-0's pid, kill it, and confirm the controller brings it back.
    assert _wait(lambda: _running(g, "hive-0"))
    desc = g.ok("fastman kube describe hive")
    m = re.search(r"hive-0\s+Running\s+pid=(\d+)", desc)
    assert m, desc
    pid = m.group(1)
    g.run(f"kill -9 {pid}")
    # Controller reconciles every ~3s.
    healed = False
    for _ in range(6):
        time.sleep(3)
        pods = g.ok("fastman kube get pods")
        line = [l for l in pods.splitlines() if l.startswith("hive-0")]
        if line and "Running" in line[0]:
            # RESTARTS column (3rd) should be >= 1.
            cols = line[0].split()
            if len(cols) >= 3 and cols[2].isdigit() and int(cols[2]) >= 1:
                healed = True
                break
    assert healed, g.ok("fastman kube get pods") + "\n" + g.ok("fastman kube describe hive")


def test_kube_rollout_restart(g, hive):
    out = g.ok("fastman kube rollout restart hive")
    assert 'restarted' in out, out
    st = g.ok("fastman kube rollout status hive")
    assert "hive" in st and "ready" in st, st


def test_kube_logs_describe_exec(g, kube_setup):
    import time
    g.run("fastman kube delete web 2>/dev/null; true")
    g.ok("fastman kube apply -f /tmp/k8s.yaml", timeout=60)
    time.sleep(2)
    # describe shows pods + image
    desc = g.ok("fastman kube describe web")
    assert "web-0" in desc and "appimg:latest" in desc, desc
    # logs: the httpd pod prints nothing until hit; just ensure the command works
    g.run("curl -s -m 5 http://127.0.0.1:8080/ >/dev/null; true")
    # exec into a pod: run the quick-exit /bin/info and capture its output
    ex = g.ok("fastman kube exec web-0 -- /bin/info")
    assert "info ran" in ex, ex
    # logs command returns cleanly
    g.ok("fastman kube logs web-0")
    g.run("fastman kube delete web 2>/dev/null; fastman kube delete worker 2>/dev/null; true")


LB = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: lb
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: lb
          image: appimg:latest
          command: ["/bin/httpd", "8080"]
          ports:
            - containerPort: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: lb
spec:
  selector:
    app: lb
  ports:
    - port: 8090
      targetPort: 8080
"""


def test_kube_service_load_balancing(g, kube_setup):
    """Three replicas all "bind :8080" (remapped to unique backend ports, so no
    crash-loop), and a Service round-robins across them — proven by seeing more
    than one distinct pod pid answer the same service endpoint."""
    import re, time
    g.ok("base64 -d > /tmp/lb.yaml", stdin=base64.b64encode(LB.encode()).decode())
    g.run("fastman kube delete lb 2>/dev/null; true")
    try:
        g.ok("fastman kube apply -f /tmp/lb.yaml", timeout=60)
        time.sleep(3)
        # All three replicas run without colliding on the port (RESTARTS stay 0).
        pods = g.ok("fastman kube get pods")
        for p in ("lb-0", "lb-1", "lb-2"):
            line = [l for l in pods.splitlines() if l.startswith(p)]
            assert line and "Running" in line[0], pods
        # Hit the Service repeatedly; collect the answering pids.
        pids = set()
        for _ in range(12):
            out = g.out("curl -s -m 5 http://127.0.0.1:8090/", timeout=10)
            m = re.search(r"pid=(\d+)", out)
            if m:
                pids.add(m.group(1))
        assert len(pids) >= 2, f"expected load-balancing across pods, saw pids={pids}"
    finally:
        g.run("fastman kube delete lb 2>/dev/null; true")
