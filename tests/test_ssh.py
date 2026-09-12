"""ssh client + outbound scp (kernel/src/ssh/client.rs, cmds/ssh.rs, cmds/scp.rs).

Driven against the guest's OWN sshd over loopback — fully self-contained, no
external server. This exercises the full client handshake (curve25519 kex,
ed25519 host-key verification, password auth, channel exec) and the scp
source/sink protocol over an SSH channel. (Interop with real OpenSSH is verified
manually; the test image can't spawn a docker sshd.)
"""


def test_ssh_exec(g):
    # SSHPASS supplies the password non-interactively.
    out, err, st = g.run("SSHPASS=root ssh root@127.0.0.1 'echo REMOTE_OK; id -u'", timeout=40)
    assert "REMOTE_OK" in out, out + err
    assert "0" in out, out + err  # id -u for root


def test_ssh_stdin_forwarding(g):
    out, err, st = g.run("echo piped-in | SSHPASS=root ssh root@127.0.0.1 'cat'", timeout=40)
    assert "piped-in" in out, out + err


def test_scp_upload_loopback(g):
    g.ok("printf 'scp-out-up\\n' > /tmp/so_src.txt")
    out, err, st = g.run("SSHPASS=root scp /tmp/so_src.txt root@127.0.0.1:/tmp/so_dst.txt", timeout=40)
    assert st == 0, out + err
    assert g.ok("cat /tmp/so_dst.txt").strip() == "scp-out-up"


def test_scp_download_loopback(g):
    g.ok("printf 'scp-out-down\\n' > /tmp/sd_src.txt")
    out, err, st = g.run(
        "SSHPASS=root scp root@127.0.0.1:/tmp/sd_src.txt /tmp/sd_dst.txt && cat /tmp/sd_dst.txt",
        timeout=40,
    )
    assert st == 0, out + err
    assert "scp-out-down" in out, out + err


def test_scp_local_only_errors(g):
    # No remote side → clear error, not a silent no-op.
    out, err, st = g.run("scp /tmp/a /tmp/b", timeout=20)
    assert st != 0
    assert "remote" in (out + err).lower()
