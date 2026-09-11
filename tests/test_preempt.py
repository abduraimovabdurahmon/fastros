"""A runaway userspace loop must never wedge the kernel: the scheduler must
preempt it so other tasks (and SSH) keep running.
"""
import base64
import os
import subprocess
import tempfile
import threading
import time

import pytest

SPIN = r"""
int main(void){ volatile long x=0; for(;;){ x++; } return 0; }
"""


def _compile(src: str) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "p.c")
        out = os.path.join(d, "p")
        with open(c, "w") as f:
            f.write(src)
        subprocess.run(["gcc", "-static", "-O2", "-o", out, c], check=True, capture_output=True)
        with open(out, "rb") as f:
            return f.read()


@pytest.fixture(scope="module")
def spin_bin():
    return _compile(SPIN)


def test_spin_does_not_wedge(g, spin_bin):
    b64 = base64.b64encode(spin_bin).decode()
    g.ok("base64 -d > /tmp/spin && chmod +x /tmp/spin", stdin=b64)

    # Launch the spinner on its own channel and DO NOT wait for it.
    tr = g.client.get_transport()
    spinner = tr.open_session()
    spinner.exec_command("fexec /tmp/spin")
    try:
        time.sleep(1.0)  # let it get going
        # The kernel must still schedule other work promptly.
        t0 = time.time()
        out, _, st = g.run("echo alive", timeout=15)
        dt = time.time() - t0
        assert out.strip() == "alive", out
        assert st == 0
        assert dt < 10, f"responsiveness degraded: {dt:.1f}s"
    finally:
        spinner.close()
        # Best-effort cleanup: kill any lingering spinner.
        g.run("pkill spin 2>/dev/null; kill %1 2>/dev/null; true", timeout=15)
