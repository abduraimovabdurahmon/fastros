"""ftp: the built-in FTP client (kernel/src/net/ftp.rs + shell/cmds/ftp.rs).

A tiny stdlib FTP server runs here in the test container (which shares the dev
docker network with the guest); the guest reaches it through QEMU's user-net.
We drive ls / get / put over the real protocol (control + PASV data channel).
"""
import base64
import socket
import threading
import time

import pytest


class TinyFTP(threading.Thread):
    """A minimal passive-mode FTP server: USER/PASS (any), TYPE, PASV, LIST,
    RETR, STOR, PWD, CWD, QUIT. Files live in an in-memory dict."""

    def __init__(self):
        super().__init__(daemon=True)
        self.files = {"readme.txt": b"hello from tiny ftp\n"}
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("0.0.0.0", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        # the address the guest will dial (this container's dev-net IP)
        self.ip = socket.gethostbyname(socket.gethostname())
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(c,), daemon=True).start()

    def _open_pasv(self):
        d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        d.bind(("0.0.0.0", 0))
        d.listen(1)
        p = d.getsockname()[1]
        h = self.ip.replace(".", ",")
        return d, f"{h},{p >> 8},{p & 0xff}"

    def _session(self, c):
        f = c.makefile("rwb")
        def send(s): f.write(s.encode() + b"\r\n"); f.flush()
        send("220 tiny ftp ready")
        cwd = "/"
        data_listener = None
        while True:
            line = f.readline()
            if not line:
                break
            parts = line.decode(errors="replace").strip().split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""
            if cmd == "USER":
                send("331 need password")
            elif cmd == "PASS":
                send("230 logged in")
            elif cmd == "TYPE":
                send("200 ok")
            elif cmd == "PWD":
                send(f'257 "{cwd}"')
            elif cmd == "CWD":
                cwd = arg
                send("250 ok")
            elif cmd == "PASV":
                data_listener, spec = self._open_pasv()
                send(f"227 Entering Passive Mode ({spec})")
            elif cmd in ("LIST", "NLST"):
                send("150 here comes the listing")
                dc, _ = data_listener.accept()
                body = "".join(f"-rw-r--r-- 1 0 0 {len(v)} Jan 1 00:00 {k}\r\n" for k, v in self.files.items())
                dc.sendall(body.encode()); dc.close(); data_listener.close()
                send("226 done")
            elif cmd == "RETR":
                name = arg.rsplit("/", 1)[-1]
                if name not in self.files:
                    send("550 no such file"); continue
                send("150 sending")
                dc, _ = data_listener.accept()
                dc.sendall(self.files[name]); dc.close(); data_listener.close()
                send("226 done")
            elif cmd == "STOR":
                name = arg.rsplit("/", 1)[-1]
                send("150 ready")
                dc, _ = data_listener.accept()
                buf = b""
                while True:
                    chunk = dc.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                dc.close(); data_listener.close()
                self.files[name] = buf
                send("226 stored")
            elif cmd == "QUIT":
                send("221 bye"); break
            else:
                send("502 not implemented")
        c.close()

    def stop(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass


@pytest.fixture
def ftpd():
    s = TinyFTP()
    s.start()
    time.sleep(0.2)
    yield s
    s.stop()


def test_ftp_ls(g, ftpd):
    out, err, st = g.run(f"ftp ls ftp://u:p@{ftpd.ip}:{ftpd.port}/", timeout=40)
    assert st == 0, out + err
    assert "readme.txt" in out, out + err


def test_ftp_get(g, ftpd):
    out, err, st = g.run(
        f"ftp get ftp://u:p@{ftpd.ip}:{ftpd.port}/readme.txt /tmp/dl.txt && cat /tmp/dl.txt",
        timeout=40,
    )
    assert st == 0, out + err
    assert "hello from tiny ftp" in out, out + err


def test_ftp_put_roundtrip(g, ftpd):
    out, err, st = g.run(
        "printf 'uploaded-by-fastros\\n' > /tmp/up.txt && "
        f"ftp put /tmp/up.txt ftp://u:p@{ftpd.ip}:{ftpd.port}/saved.txt && "
        f"ftp get ftp://u:p@{ftpd.ip}:{ftpd.port}/saved.txt /tmp/back.txt && cat /tmp/back.txt",
        timeout=40,
    )
    assert st == 0, out + err
    assert "uploaded-by-fastros" in out, out + err
    assert ftpd.files.get("saved.txt") == b"uploaded-by-fastros\n"
