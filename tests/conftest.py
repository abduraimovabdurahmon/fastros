"""Integration tests: talk to a running FastROS guest over SSH.

Run with `tools/dev.sh test` (the harness container shares a Docker network
with the VM container `fastros-dev-vm`).
"""
import os
import re
import time

import paramiko
import pytest

HOST = os.environ.get("FASTROS_HOST", "fastros-dev-vm")
PORT = int(os.environ.get("FASTROS_PORT", "22"))
USER = os.environ.get("FASTROS_USER", "root")
PASSWORD = os.environ.get("FASTROS_PASSWORD", "root")

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|[\x01\x02]")


def strip_ansi(s: str) -> str:
    return ANSI.sub("", s)


def connect(user=USER, password=PASSWORD, retries=30):
    last = None
    for _ in range(retries):
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            c.connect(HOST, PORT, user, password, timeout=20, banner_timeout=30,
                      auth_timeout=30, allow_agent=False, look_for_keys=False)
            return c
        except paramiko.AuthenticationException:
            raise
        except Exception as e:  # not booted yet
            last = e
            time.sleep(2)
    raise last


class Guest:
    def __init__(self, client):
        self.client = client

    def run(self, cmd, timeout=60, stdin=None):
        """Run a command on an exec channel: (stdout, stderr, exit status)."""
        chan = self.client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(cmd)
        if stdin is not None:
            chan.sendall(stdin.encode() if isinstance(stdin, str) else stdin)
            chan.shutdown_write()
        out, err = b"", b""
        deadline = time.time() + timeout
        while True:
            if chan.recv_ready():
                out += chan.recv(65536)
            if chan.recv_stderr_ready():
                err += chan.recv_stderr(65536)
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if time.time() > deadline:
                raise TimeoutError(f"command timed out: {cmd!r}\nstdout so far: {out!r}")
            time.sleep(0.01)
        status = chan.recv_exit_status()
        chan.close()
        return out.decode(errors="replace"), err.decode(errors="replace"), status

    def ok(self, cmd, **kw):
        out, err, st = self.run(cmd, **kw)
        assert st == 0, f"{cmd!r} exited {st}\nstdout: {out}\nstderr: {err}"
        return out

    def out(self, cmd, **kw):
        return self.run(cmd, **kw)[0]


class Pty:
    """An interactive shell on a pseudo-terminal."""

    def __init__(self, client, width=80, height=24):
        self.chan = client.invoke_shell(term="xterm", width=width, height=height)
        self.chan.settimeout(30)
        self.buf = b""

    def read_until(self, pattern, timeout=20):
        rx = re.compile(pattern.encode() if isinstance(pattern, str) else pattern)
        deadline = time.time() + timeout
        while True:
            m = rx.search(self.buf)
            if m:
                data, self.buf = self.buf[: m.end()], self.buf[m.end():]
                return data.decode(errors="replace")
            if time.time() > deadline:
                raise TimeoutError(f"waiting for {pattern!r}, got {self.buf!r}")
            if self.chan.recv_ready():
                self.buf += self.chan.recv(65536)
            else:
                time.sleep(0.02)

    def prompt(self, timeout=20):
        return self.read_until(r"[#$] $", timeout)

    def send(self, s):
        self.chan.send(s)

    def cmd(self, line, timeout=30):
        """Type a line, return everything printed until the next prompt."""
        self.send(line + "\r")
        return self.read_until(r"[#$] $", timeout)

    def close(self):
        self.chan.close()


@pytest.fixture(scope="session")
def client():
    c = connect()
    yield c
    c.close()


@pytest.fixture(scope="session")
def g(client):
    return Guest(client)


@pytest.fixture
def pty(client):
    p = Pty(client)
    p.prompt()
    yield p
    p.close()


@pytest.fixture
def tmpdir_guest(g):
    d = g.ok("mktemp -d /tmp/t.XXXXXX").strip()
    yield d
    g.run(f"rm -rf {d}")
