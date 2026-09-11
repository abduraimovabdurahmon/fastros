"""gzip/gunzip/zcat, tar, zip/unzip — output formats, round trips, and
cross-checks against Python's reference implementations (gzip, tarfile,
zipfile) in both directions, plus the path-safety guarantees."""
import base64
import gzip
import io
import re
import tarfile
import time
import zipfile

import pytest

MTIME = 1_767_323_045  # 2026-01-02 03:04:05 UTC


def fetch(g, path) -> bytes:
    """Copy a guest file to the test harness (binary-safe)."""
    return base64.b64decode(g.ok(f"base64 {path}"))


def put(g, path, data: bytes):
    """Copy bytes into a guest file."""
    g.ok(f"base64 -d > {path}", stdin=base64.b64encode(data).decode() + "\n")


def seq(n):
    return "".join(f"{i}\n" for i in range(1, n + 1)).encode()


@pytest.fixture
def tree(g, tmpdir_guest):
    """src/ with a file, a sub-directory, a symlink and a hard link."""
    d = tmpdir_guest
    g.ok(
        f"cd {d} && mkdir -p src/sub && echo hello > src/a.txt && seq 1 3000 > src/sub/nums"
        f" && ln -s a.txt src/link && ln src/a.txt src/hard"
        f" && chmod 640 src/a.txt && chmod 750 src/sub"
        f" && touch -d @{MTIME} src/a.txt src/sub/nums src/sub src && touch -h -d @{MTIME} src/link"
    )
    return d


# ── gzip ──────────────────────────────────────────────────────────────────


def test_gzip_roundtrip_matches_python(g, tree):
    d = tree
    g.ok(f"cd {d} && gzip src/sub/nums")
    out, _, _ = g.run(f"ls {d}/src/sub")
    assert out.split() == ["nums.gz"], "the original is replaced"
    blob = fetch(g, f"{d}/src/sub/nums.gz")
    assert gzip.decompress(blob) == seq(3000)
    # FNAME and MTIME are recorded like GNU gzip does.
    assert blob[3] & 0x08 and blob[10:15] == b"nums\0"
    assert int.from_bytes(blob[4:8], "little") == MTIME
    g.ok(f"cd {d} && gunzip src/sub/nums.gz")
    assert g.ok(f"cat {d}/src/sub/nums").encode() == seq(3000)
    # Mode and mtime survive the round trip.
    assert g.ok(f"ls -l {d}/src/sub/nums").startswith("-rw-r--r-- 1 root root 13893 Jan  2  2026 ")


def test_gunzip_reads_python_multimember_and_restores_name(g, tmpdir_guest):
    d = tmpdir_guest
    a = gzip.compress(b"first\n", mtime=MTIME)
    buf = io.BytesIO()
    with gzip.GzipFile(filename="original.txt", mode="wb", fileobj=buf, mtime=MTIME) as f:
        f.write(b"second\n" * 1000)
    put(g, f"{d}/x.gz", a + buf.getvalue())
    assert g.ok(f"zcat {d}/x.gz") == "first\n" + "second\n" * 1000
    g.ok(f"cd {d} && gunzip -N x.gz")
    # -N takes the name stored in the first member (none here → keeps x).
    assert g.ok(f"ls {d}").split() == ["x"]
    put(g, f"{d}/y.gz", buf.getvalue())
    g.ok(f"cd {d} && gunzip -N y.gz")
    assert "original.txt" in g.ok(f"ls {d}").split()


def test_gzip_list_and_verbose_format(g, tree):
    d = tree
    out, err, st = g.run(f"cd {d} && gzip -v -k src/sub/nums")
    assert st == 0
    assert re.fullmatch(r"src/sub/nums:\t [ 0-9]\d\.\d% -- created src/sub/nums\.gz\n", err), err
    blob = fetch(g, f"{d}/src/sub/nums.gz")
    lines = g.ok(f"cd {d} && gzip -l src/sub/nums.gz").splitlines()
    assert lines[0] == "         compressed        uncompressed  ratio uncompressed_name"
    comp, raw = len(blob), 13893
    header = 10 + len(b"nums\0") + 8
    pct = 100.0 * (raw - (comp - header)) / raw
    assert lines[1] == f"{comp:>19} {raw:>19} {pct:5.1f}% src/sub/nums"
    # Two files add a totals line.
    g.ok(f"cd {d} && gzip -k src/a.txt")
    lines = g.ok(f"cd {d} && gzip -l src/a.txt.gz src/sub/nums.gz").splitlines()
    assert len(lines) == 4 and lines[3].endswith(" (totals)")
    assert g.ok(f"cd {d} && gzip -tv src/a.txt.gz 2>&1") == "src/a.txt.gz:\t OK\n"


def test_gzip_stdin_stdout_and_levels(g):
    for level in (1, 6, 9):
        assert g.ok(f"seq 1 2000 | gzip -{level} | gunzip | wc -l").strip() == "2000"
    blob = base64.b64decode(g.ok("seq 1 2000 | gzip -9 | base64"))
    assert gzip.decompress(blob) == seq(2000)
    assert blob[8] == 2, "XFL=2 marks maximum compression"


def test_gzip_errors_and_warnings(g, tmpdir_guest):
    d = tmpdir_guest
    good = gzip.compress(b"payload " * 100)
    bad = bytearray(good)
    bad[-8] ^= 0xFF
    put(g, f"{d}/bad.gz", bytes(bad))
    out, err, st = g.run(f"cd {d} && gunzip bad.gz")
    assert st == 1 and err == "gzip: bad.gz: invalid compressed data--crc error\n"
    assert g.ok(f"ls {d}").split() == ["bad.gz"], "partial output is removed"
    put(g, f"{d}/trunc.gz", good[:-5])
    _, err, st = g.run(f"cd {d} && gunzip trunc.gz")
    assert st == 1 and err == "gzip: trunc.gz: unexpected end of file\n"
    g.ok(f"echo plain > {d}/plain.gz")
    _, err, st = g.run(f"cd {d} && gunzip plain.gz")
    assert st == 1 and err == "gzip: plain.gz: not in gzip format\n"
    g.ok(f"echo x > {d}/noext")
    _, err, st = g.run(f"cd {d} && gunzip noext")
    assert st == 2 and err == "gzip: noext: unknown suffix -- ignored\n"
    put(g, f"{d}/ok.gz", good)
    _, err, st = g.run(f"cd {d} && gzip ok.gz")
    assert st == 2 and err == "gzip: ok.gz already has .gz suffix -- unchanged\n"
    g.ok(f"echo y > {d}/dup && echo old > {d}/dup.gz")
    _, err, st = g.run(f"cd {d} && gzip dup")
    assert st == 2 and err == "gzip: dup.gz already exists;\tnot overwritten\n"
    _, err, st = g.run(f"gzip {d}/missing")
    assert st == 1 and err == f"gzip: {d}/missing: No such file or directory\n"


# ── tar ───────────────────────────────────────────────────────────────────


def test_tar_create_is_read_by_python(g, tree):
    d = tree
    g.ok(f"cd {d} && tar cf a.tar src")
    blob = fetch(g, f"{d}/a.tar")
    assert len(blob) % 10240 == 0, "padded to GNU's record size"
    with tarfile.open(fileobj=io.BytesIO(blob)) as t:
        m = {x.name: x for x in t.getmembers()}
        assert set(m) == {"src", "src/a.txt", "src/hard", "src/link", "src/sub", "src/sub/nums"}
        assert m["src/a.txt"].mode == 0o640 and m["src/a.txt"].mtime == MTIME
        assert m["src/a.txt"].uname == "root" and m["src/a.txt"].gname == "root"
        assert m["src/sub"].isdir() and m["src/sub"].mode == 0o750
        assert m["src/link"].issym() and m["src/link"].linkname == "a.txt"
        assert m["src/hard"].islnk() and m["src/hard"].linkname == "src/a.txt"
        assert t.extractfile("src/sub/nums").read() == seq(3000)


def test_tar_tv_listing_format(g, tree):
    d = tree
    g.ok(f"cd {d} && tar czf a.tgz src/a.txt src/link src/sub")
    lines = g.ok(f"cd {d} && tar tvzf a.tgz").splitlines()
    assert lines == [
        "-rw-r----- root/root         6 2026-01-02 03:04 src/a.txt",
        "lrwxrwxrwx root/root         0 2026-01-02 03:04 src/link -> a.txt",
        "drwxr-x--- root/root         0 2026-01-02 03:04 src/sub/",
        "-rw-r--r-- root/root     13893 2026-01-02 03:04 src/sub/nums",
    ]
    # Auto-detection: -z is optional when reading.
    assert g.ok(f"cd {d} && tar tf a.tgz") == "src/a.txt\nsrc/link\nsrc/sub/\nsrc/sub/nums\n"


def test_tar_roundtrip_preserves_everything(g, tree):
    d = tree
    g.ok(f"cd {d} && mkfifo src/fifo && touch -d @{MTIME} src && tar czf all.tgz src && mkdir out && tar xzf all.tgz -C out")
    # `ls -lR` of the copy is identical to the original: types, modes,
    # link counts, owners, sizes, times and symlink targets.
    before = g.ok(f"cd {d}/src && ls -lR .")
    after = g.ok(f"cd {d}/out/src && ls -lR .")
    assert before == after
    assert g.ok(f"cat {d}/out/src/link") == "hello\n"
    assert g.ok(f"ls -l {d}/out/src/hard").startswith("-rw-r----- 2 root root 6 Jan  2  2026 ")
    assert g.ok(f"ls -l {d}/out/src/fifo").startswith("prw-r--r--")
    assert g.ok(f"ls -ld {d}/out/src/sub").startswith("drwxr-x--- 2 root root")
    assert g.ok(f"cat {d}/out/src/sub/nums").encode() == seq(3000)


def test_tar_bundled_flags_strip_and_stdout(g, tree):
    d = tree
    g.ok(f"cd {d} && tar czvf b.tgz src > /dev/null")
    assert g.ok(f"cd {d} && tar xzOf b.tgz src/a.txt") == "hello\n"
    g.ok(f"cd {d} && mkdir s && tar xzf b.tgz -C s --strip-components=1")
    assert sorted(g.ok(f"ls {d}/s").split()) == ["a.txt", "hard", "link", "sub"]
    out, err, st = g.run(f"cd {d} && tar tzf b.tgz nope src/a.txt")
    assert st == 2 and out == "src/a.txt\n"
    assert err == "tar: nope: Not found in archive\ntar: Exiting with failure status due to previous errors\n"
    _, err, st = g.run(f"cd {d} && tar cf empty.tar")
    assert st == 2 and err.startswith("tar: Cowardly refusing to create an empty archive\n")
    _, err, st = g.run(f"cd {d} && tar xf missing.tar")
    assert st == 2 and err == "tar: missing.tar: Cannot open: No such file or directory\ntar: Error is not recoverable: exiting now\n"


def test_tar_reads_python_gnu_and_pax_archives(g, tmpdir_guest):
    d = tmpdir_guest
    long = "deep/" + "d" * 120 + "/" + "f" * 110 + ".txt"
    for fmt, name in ((tarfile.GNU_FORMAT, "gnu.tgz"), (tarfile.PAX_FORMAT, "pax.tgz")):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=fmt) as t:
            ti = tarfile.TarInfo(long)
            data = b"long name content\n"
            ti.size, ti.mtime, ti.mode, ti.uid, ti.gid = len(data), MTIME, 0o600, 1234, 5678
            t.addfile(ti, io.BytesIO(data))
            s = tarfile.TarInfo("deep/sym")
            s.type, s.linkname, s.mtime = tarfile.SYMTYPE, "t" * 150, MTIME
            t.addfile(s)
        put(g, f"{d}/{name}", buf.getvalue())
        g.ok(f"cd {d} && mkdir {name}.out && tar xzf {name} -C {name}.out")
        assert g.ok(f"cat '{d}/{name}.out/{long}'") == "long name content\n"
        # Unknown ids are kept numerically (extracting as root).
        assert g.ok(f"ls -l '{d}/{name}.out/{long}'").startswith("-rw------- 1 1234 5678 18 ")
        assert g.ok(f"ls -l {d}/{name}.out/deep/sym").rstrip("\n").endswith(" -> " + "t" * 150)


def test_tar_writes_long_names_python_can_read(g, tmpdir_guest):
    d = tmpdir_guest
    long = "x" * 130 + "/" + "y" * 120
    g.ok(f"cd {d} && mkdir -p {'x' * 130} && echo z > {long} && tar cf l.tar {'x' * 130}")
    with tarfile.open(fileobj=io.BytesIO(fetch(g, f"{d}/l.tar"))) as t:
        assert long in t.getnames()
        assert t.extractfile(long).read() == b"z\n"


def test_tar_refuses_path_traversal(g, tmpdir_guest):
    d = tmpdir_guest
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for name, data in (("../evil", b"escaped\n"), ("ok/../../evil2", b"escaped\n"), ("/abs/file", b"abs\n"), ("good", b"good\n")):
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
        link = tarfile.TarInfo("lnk")
        link.type, link.linkname = tarfile.SYMTYPE, d
        t.addfile(link)
        pwn = tarfile.TarInfo("lnk/pwned")
        pwn.size = 4
        t.addfile(pwn, io.BytesIO(b"pwn\n"))
        hl = tarfile.TarInfo("hl")
        hl.type, hl.linkname = tarfile.LNKTYPE, "../../etc/passwd"
        t.addfile(hl)
    put(g, f"{d}/evil.tar", buf.getvalue())
    out, err, st = g.run(f"cd {d} && mkdir x && tar xf evil.tar -C x")
    assert st == 2
    assert "tar: ../evil: Member name contains '..'" in err
    assert "tar: ok/../../evil2: Member name contains '..'" in err
    assert "tar: Removing leading `/' from member names" in err
    assert "tar: lnk/pwned: Cannot open: path passes through a symbolic link" in err
    assert "tar: ../../etc/passwd: Member name contains '..'" in err
    assert sorted(g.ok(f"ls {d}").split()) == ["evil.tar", "x"], "nothing escaped the destination"
    assert g.ok(f"cat {d}/x/abs/file {d}/x/good") == "abs\ngood\n"
    assert g.run(f"ls {d}/pwned")[2] != 0
    # -P restores the unsafe traditional behaviour on request.
    out, err, st = g.run(f"cd {d}/x && tar xPf ../evil.tar ../evil")
    assert st == 0 and g.ok(f"cat {d}/evil") == "escaped\n"


def test_tar_corrupt_archive(g, tmpdir_guest):
    d = tmpdir_guest
    g.ok(f"echo 'not an archive' > {d}/junk.tar")
    _, err, st = g.run(f"cd {d} && tar tf junk.tar")
    assert st == 2 and err == "tar: This does not look like a tar archive\ntar: Exiting with failure status due to previous errors\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo("big")
        ti.size = 5000
        t.addfile(ti, io.BytesIO(b"q" * 5000))
    put(g, f"{d}/cut.tar", buf.getvalue()[:2048])
    _, err, st = g.run(f"cd {d} && tar tvf cut.tar > /dev/null")
    assert st == 2 and "tar: Unexpected EOF in archive" in err


# ── zip / unzip ───────────────────────────────────────────────────────────


def test_zip_is_read_by_python(g, tree):
    d = tree
    out = g.ok(f"cd {d} && zip -r a.zip src")
    assert out.splitlines() == [
        "  adding: src/ (stored 0%)",
        "  adding: src/a.txt (stored 0%)",
        "  adding: src/hard (stored 0%)",
        "  adding: src/link (stored 0%)",
        "  adding: src/sub/ (stored 0%)",
        re.match(r"  adding: src/sub/nums \(deflated \d+%\)", out.splitlines()[5]).group(0),
    ]
    with zipfile.ZipFile(io.BytesIO(fetch(g, f"{d}/a.zip"))) as z:
        assert z.testzip() is None
        assert z.read("src/sub/nums") == seq(3000)
        assert z.read("src/link") == b"hello\n", "symlinks are followed without -y"
        info = z.getinfo("src/a.txt")
        assert info.external_attr >> 16 == 0o100640
        assert info.date_time == (2026, 1, 2, 3, 4, 4)
    g.ok(f"cd {d} && zip -qry l.zip src/link")
    with zipfile.ZipFile(io.BytesIO(fetch(g, f"{d}/l.zip"))) as z:
        i = z.getinfo("src/link")
        assert (i.external_attr >> 16) & 0o170000 == 0o120000 and z.read(i) == b"a.txt"


def test_unzip_list_and_extract_python_archive(g, tmpdir_guest):
    d = tmpdir_guest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("dir/", (2026, 1, 2, 3, 4, 6)), b"")
        zi = zipfile.ZipInfo("dir/deflated.txt", (2026, 1, 2, 3, 4, 6))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o100600 << 16
        z.writestr(zi, b"compress me " * 200)
        z.writestr(zipfile.ZipInfo("stored.bin", (2026, 1, 2, 3, 4, 6)), bytes(range(256)))
    put(g, f"{d}/p.zip", buf.getvalue())
    out = g.ok(f"cd {d} && unzip -l p")
    assert out.splitlines() == [
        "Archive:  p.zip",
        "  Length      Date    Time    Name",
        "---------  ---------- -----   ----",
        "        0  2026-01-02 03:04   dir/",
        "     2400  2026-01-02 03:04   dir/deflated.txt",
        "      256  2026-01-02 03:04   stored.bin",
        "---------                     -------",
        "     2656                     3 files",
    ]
    out = g.ok(f"cd {d} && unzip p.zip -d ex")
    assert out.splitlines() == [
        "Archive:  p.zip",
        "   creating: dir/",
        "  inflating: dir/deflated.txt        ",
        " extracting: stored.bin              ",
    ]
    assert g.ok(f"cat {d}/ex/dir/deflated.txt") == "compress me " * 200
    assert g.ok(f"ls -l {d}/ex/dir/deflated.txt").startswith("-rw------- 1 root root 2400 Jan  2  2026 ")
    assert g.ok(f"unzip -p {d}/p.zip dir/deflated.txt") == "compress me " * 200
    assert g.ok(f"cd {d} && unzip -t p.zip").splitlines()[-1] == "No errors detected in compressed data of p.zip."
    # Existing files: -n keeps, -o replaces, no flag + EOF on stdin = [N]one.
    g.ok(f"echo mine > {d}/ex/stored.bin")
    g.ok(f"cd {d} && unzip -qn p.zip -d ex")
    assert g.ok(f"cat {d}/ex/stored.bin") == "mine\n"
    out, _, _ = g.run(f"cd {d} && unzip p.zip stored.bin -d ex < /dev/null")
    assert "replace ex/stored.bin? [y]es, [n]o, [A]ll, [N]one, [r]ename: NULL" in out
    g.ok(f"cd {d} && unzip -qo p.zip -d ex")
    assert fetch(g, f"{d}/ex/stored.bin") == bytes(range(256))


def test_zip_update_replaces_entries(g, tree):
    d = tree
    g.ok(f"cd {d} && zip -q u.zip src/a.txt src/sub/nums")
    g.ok(f"echo changed > {d}/src/a.txt")
    out = g.ok(f"cd {d} && zip u.zip src/a.txt")
    assert out == "updating: src/a.txt (stored 0%)\n"
    with zipfile.ZipFile(io.BytesIO(fetch(g, f"{d}/u.zip"))) as z:
        assert z.namelist() == ["src/a.txt", "src/sub/nums"]
        assert z.read("src/a.txt") == b"changed\n"
        assert z.read("src/sub/nums") == seq(3000)


def test_unzip_refuses_path_traversal_and_bad_crc(g, tmpdir_guest):
    d = tmpdir_guest
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.txt", b"escaped\n")
        z.writestr("/abs.txt", b"abs\n")
        z.writestr("fine.txt", b"fine\n")
    put(g, f"{d}/e.zip", buf.getvalue())
    out, err, st = g.run(f"cd {d} && mkdir x && cd x && unzip -q ../e.zip")
    assert st == 1
    assert "../evil.txt" in err and "refused: member name contains '..'" in err
    assert "warning:  stripped absolute path spec from /abs.txt" in err
    assert sorted(g.ok(f"ls {d}").split()) == ["e.zip", "x"]
    assert sorted(g.ok(f"ls {d}/x").split()) == ["abs.txt", "fine.txt"]
    raw = bytearray(buf.getvalue())
    at = raw.index(b"fine\n")
    raw[at] ^= 0x20
    put(g, f"{d}/c.zip", bytes(raw))
    out, err, st = g.run(f"cd {d} && mkdir y && unzip -o c.zip fine.txt -d y")
    assert st == 2 and re.search(r"extracting: fine\.txt\s+bad CRC [0-9a-f]{8}  \(should be [0-9a-f]{8}\)", out)
    assert g.ok(f"ls {d}/y") == ""
    _, err, st = g.run(f"unzip {d}/nothere")
    assert st == 9 and err == f"unzip:  cannot find or open {d}/nothere, {d}/nothere.zip or {d}/nothere.ZIP.\n"
