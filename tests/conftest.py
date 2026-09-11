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
        """Read until `pattern` matches the ANSI-stripped output; returns the
        raw text consumed (escape sequences included)."""
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while True:
            text = self.buf.decode(errors="replace")
            # Match on stripped text, then map the end back to the raw buffer.
            stripped, index = [], []
            i = 0
            while i < len(text):
                m = ANSI.match(text, i)
                if m:
                    i = m.end()
                    continue
                stripped.append(text[i])
                index.append(i)
                i += 1
            m = rx.search("".join(stripped))
            if m:
                end = index[m.end() - 1] + 1 if m.end() > 0 else 0
                # Swallow escape sequences that directly follow the match.
                while True:
                    n = ANSI.match(text, end)
                    if not n:
                        break
                    end = n.end()
                consumed = text[:end]
                self.buf = text[end:].encode()
                return consumed
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


class Term:
    """An interactive pty rendered by a VT emulator: the screen a user sees.
    Needed for full-screen programs, where raw output is a stream of cursor
    moves and partial redraws."""

    def __init__(self, client, cols=100, rows=30):
        import pyte
        self.chan = client.invoke_shell(term="xterm-256color", width=cols, height=rows)
        self.chan.settimeout(30)
        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.ByteStream(self.screen)

    def pump(self, secs=0.3):
        """Feed everything that arrives within `secs` to the emulator."""
        deadline = time.time() + secs
        while time.time() < deadline:
            if self.chan.recv_ready():
                self.stream.feed(self.chan.recv(65536))
            else:
                time.sleep(0.02)

    def text(self):
        return "\n".join(line.rstrip() for line in self.screen.display)

    def wait_for(self, pattern, timeout=20):
        rx = re.compile(pattern)
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.pump(0.1)
            if rx.search(self.text()):
                return self.text()
        raise TimeoutError(f"waiting for {pattern!r}; screen:\n{self.text()}")

    def send(self, s):
        self.chan.send(s)

    def line(self, n):
        return self.screen.display[n].rstrip()

    def close(self):
        self.chan.close()


@pytest.fixture
def term(client):
    t = Term(client)
    t.wait_for(r"(?m)[#$]$")
    yield t
    t.close()


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
