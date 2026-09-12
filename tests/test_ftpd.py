"""ftpd: the built-in FTP server (kernel/src/ftpd.rs), started at boot on port
21. Driven here through the guest's own `ftp` client over loopback, so it needs
no external server: list the real guest filesystem, download a guest file, and
upload one and confirm it lands on the guest fs.
"""


def test_ftpd_listening(g):
    out = g.ok("ps")
    assert "ftpd" in out
    dm = g.ok("dmesg")
    assert "ftpd: listening on port 21" in dm


def test_ftpd_list_root(g):
    out, err, st = g.run("ftp ls ftp://u:p@127.0.0.1/", timeout=40)
    assert st == 0, out + err
    # Real guest root directories served over FTP.
    assert "bin" in out and "etc" in out and "dev" in out, out + err


def test_ftpd_get(g):
    g.ok("printf 'served-by-ftpd\\n' > /tmp/srv.txt")
    out, err, st = g.run(
        "ftp get ftp://u:p@127.0.0.1/tmp/srv.txt /tmp/got.txt && cat /tmp/got.txt",
        timeout=40,
    )
    assert st == 0, out + err
    assert "served-by-ftpd" in out, out + err


def test_ftpd_put_lands_on_fs(g):
    g.ok("printf 'up-via-ftpd\\n' > /tmp/toput.txt")
    out, err, st = g.run(
        "ftp put /tmp/toput.txt ftp://u:p@127.0.0.1/tmp/landed.txt", timeout=40
    )
    assert st == 0, out + err
    # The file the server wrote is readable directly on the guest filesystem.
    assert g.ok("cat /tmp/landed.txt").strip() == "up-via-ftpd"
