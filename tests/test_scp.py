"""scp / sftp against FastROS' sshd.

Modern `scp` and `sftp` speak the SFTP subsystem (kernel/src/shell/cmds/sftp.rs,
wired in ssh/server.rs); `scp -O` uses the legacy scp protocol
(kernel/src/shell/cmds/scp.rs). We drive real `scp`/`sftp` clients (present in
the test image) at the guest and confirm bytes land on / come from its fs.
"""
import os
import subprocess
import tempfile

import pytest

from conftest import HOST, PASSWORD, USER

SSHOPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
]


def _scp(args):
    return subprocess.run(
        ["sshpass", "-p", PASSWORD, "scp"] + SSHOPTS + args,
        capture_output=True, text=True, timeout=60,
    )


def _sftp_batch(script):
    # NB: not `sftp -b` — batch mode forces key-only auth (BatchMode=yes), which
    # refuses the password. Feed commands to interactive sftp's stdin instead.
    return subprocess.run(
        ["sshpass", "-p", PASSWORD, "sftp"] + SSHOPTS + [f"{USER}@{HOST}"],
        input=script, capture_output=True, text=True, timeout=60,
    )


def test_scp_upload_sftp(g):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("scp-upload-via-sftp\n")
        local = f.name
    r = _scp([local, f"{USER}@{HOST}:/tmp/scp_up.txt"])
    assert r.returncode == 0, r.stderr
    assert g.ok("cat /tmp/scp_up.txt").strip() == "scp-upload-via-sftp"


def test_scp_download_sftp(g):
    g.ok("printf 'scp-download-body\\n' > /tmp/scp_dl.txt")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "got.txt")
        r = _scp([f"{USER}@{HOST}:/tmp/scp_dl.txt", out])
        assert r.returncode == 0, r.stderr
        assert open(out).read().strip() == "scp-download-body"


def test_scp_legacy_protocol(g):
    """`scp -O` exercises the legacy scp -t/-f path, not SFTP."""
    with tempfile.TemporaryDirectory() as d:
        local = os.path.join(d, "legacy.txt")
        open(local, "w").write("legacy-scp-O\n")
        up = _scp(["-O", local, f"{USER}@{HOST}:/tmp/legacy.txt"])
        assert up.returncode == 0, up.stderr
        assert g.ok("cat /tmp/legacy.txt").strip() == "legacy-scp-O"
        back = os.path.join(d, "back.txt")
        dn = _scp(["-O", f"{USER}@{HOST}:/tmp/legacy.txt", back])
        assert dn.returncode == 0, dn.stderr
        assert open(back).read().strip() == "legacy-scp-O"


def test_sftp_put_get_ls(g):
    with tempfile.TemporaryDirectory() as d:
        local = os.path.join(d, "s.txt")
        open(local, "w").write("sftp-roundtrip\n")
        back = os.path.join(d, "b.txt")
        script = (
            f"put {local} /tmp/sftp_x.txt\n"
            f"get /tmp/sftp_x.txt {back}\n"
            "ls /tmp\n"
            "bye\n"
        )
        r = _sftp_batch(script)
        assert r.returncode == 0, r.stderr + r.stdout
        assert open(back).read().strip() == "sftp-roundtrip"
        assert g.ok("cat /tmp/sftp_x.txt").strip() == "sftp-roundtrip"
