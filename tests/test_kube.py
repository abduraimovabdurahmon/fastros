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
int main(int argc, char **argv){
    int port = argc>1?atoi(argv[1]):8080;
    int ls=socket(AF_INET,SOCK_STREAM,0); int one=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof one);
    struct sockaddr_in a; memset(&a,0,sizeof a); a.sin_family=AF_INET; a.sin_port=htons(port); a.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(ls,(void*)&a,sizeof a)){perror("bind");return 1;} listen(ls,16);
    const char*b="kube pod alive\n"; char r[128];
    int rn=snprintf(r,sizeof r,"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",(int)strlen(b),b);
    for(;;){int c=accept(ls,0,0); if(c<0)continue; char x[512]; read(c,x,sizeof x); write(c,r,rn); close(c);}
}
"""

WORKER = r"""
#include <time.h>
int main(void){ for(;;){ struct timespec t={1,0}; nanosleep(&t,0); } return 0; }
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

    time.sleep(2)
    pods = g.ok("fastman kube get pods")
    for p in ("web-0", "worker-0", "worker-1"):
        assert p in pods, pods

    deps = g.ok("fastman kube get deployments")
    assert "worker" in deps and "2/2" in deps, deps
    assert "web" in deps and "1/1" in deps, deps

    svcs = g.ok("fastman kube get services")
    assert "web" in svcs and "80" in svcs, svcs

    body = g.out("curl -s -m 8 http://127.0.0.1:8080/", timeout=15)
    assert "kube pod alive" in body, body

    d = g.ok("fastman kube delete worker")
    assert 'deployment "worker" deleted' in d, d
    pods2 = g.ok("fastman kube get pods")
    assert "worker-0" not in pods2 and "web-0" in pods2, pods2

    g.run("fastman kube delete web 2>/dev/null; true")
