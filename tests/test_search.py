"""Search, viewing and editing commands: grep, find, xargs, locate, sed,
diff, stat, realpath, readlink, which, du, less, more.

Expected outputs were produced by GNU grep 3.11, findutils 4.10, sed 4.9,
diffutils 3.10 and coreutils 9.7 on the same inputs.
"""
import re

import pytest

from conftest import strip_ansi

TEXT = "alpha\\nbeta foo\\ngamma\\nfoo bar\\nFOO baz\\nlast line\\n"


@pytest.fixture
def d(g, tmpdir_guest):
    g.ok(f"cd {tmpdir_guest} && printf '{TEXT}' > a.txt && printf 'x\\nfoo\\n' > b.txt")
    return tmpdir_guest


def sh(g, d, cmd):
    """stdout+stderr of `cmd` run in directory d, plus the exit status."""
    out, err, st = g.run(f"cd {d} && {{ {cmd} ; }} 2>&1")
    return out, st


# ── grep ───────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cmd,expected,status", [
    ("grep foo a.txt", "beta foo\nfoo bar\n", 0),
    ("grep -nH foo a.txt b.txt", "a.txt:2:beta foo\na.txt:4:foo bar\nb.txt:2:foo\n", 0),
    ("grep -ic foo a.txt", "3\n", 0),
    ("grep -v o a.txt", "alpha\ngamma\nFOO baz\nlast line\n", 0),
    ("printf 'foobar\\nfoo bar\\nbarfoo\\n' | grep -w foo", "foo bar\n", 0),
    ("printf 'foo\\nfoo bar\\n' | grep -x foo", "foo\n", 0),
    ("echo abc123def456 | grep -o '[0-9]\\+'", "123\n456\n", 0),
    ("grep -E 'al|ga' a.txt", "alpha\ngamma\n", 0),
    ("echo ababab | grep -o '\\(ab\\)\\{2\\}'", "abab\n", 0),
    ("grep -C1 gamma a.txt", "beta foo\ngamma\nfoo bar\n", 0),
    ("seq 1 20 | grep -A1 -e '^5$' -e '^15$'", "5\n6\n--\n15\n16\n", 0),
    ("grep -l foo a.txt b.txt", "a.txt\nb.txt\n", 0),
    ("grep -q foo a.txt", "", 0),
    ("grep zzz a.txt", "", 1),
    ("grep foo nonexist", "grep: nonexist: No such file or directory\n", 2),
    ("grep -s foo nonexist", "", 2),
    ("seq 1 10 | grep -m2 1", "1\n10\n", 0),
    ("yes | grep -m1 y", "y\n", 0),
    ("echo 'a.b axb' | fgrep -o 'a.b'", "a.b\n", 0),
    ("echo 'x*y' | grep -F '*'", "x*y\n", 0),
    ("grep '\\(' a.txt", "grep: Unmatched ( or \\(\n", 2),
    ("echo 'a]b\\c' | grep -o '[]\\]'", "]\n\\\n", 0),
    ("echo 'ab12 CD' | grep -o '[[:upper:]]\\+'", "CD\n", 0),
    ("echo 'a*b' | grep -o '*b'", "*b\n", 0),
    ("printf 'x\\n\\ny\\n' | grep -c ''", "3\n", 0),
    ("grep -b foo a.txt", "6:beta foo\n21:foo bar\n", 0),
    ("printf 'abc\\000def\\n' > bin; grep abc bin", "grep: bin: binary file matches\n", 0),
])
def test_grep(g, d, cmd, expected, status):
    out, st = sh(g, d, cmd)
    assert (out, st) == (expected, status)


def test_grep_color(g, d):
    out, _ = sh(g, d, "grep --color=always -nH foo b.txt")
    assert out == ("\x1b[35m\x1b[Kb.txt\x1b[m\x1b[K\x1b[36m\x1b[K:\x1b[m\x1b[K"
                   "\x1b[32m\x1b[K2\x1b[m\x1b[K\x1b[36m\x1b[K:\x1b[m\x1b[K"
                   "\x1b[01;31m\x1b[Kfoo\x1b[m\x1b[K\n")


def test_grep_recursive(g, d):
    g.ok(f"cd {d} && mkdir -p r/e && echo foo > r/e/f && echo bar > r/g")
    assert sh(g, d, "grep -r foo r") == ("r/e/f:foo\n", 0)
    assert sh(g, d, "cd r && grep -r foo") == ("e/f:foo\n", 0)
    assert sh(g, d, "grep -rl foo --include='f' r") == ("r/e/f\n", 0)
    assert sh(g, d, "grep -r foo --exclude-dir=e r") == ("", 1)


def test_grep_alias_in_profile(g):
    assert "alias grep='grep --color=auto'" in g.out("cat /etc/profile")


# ── find / xargs ───────────────────────────────────────────────────────────

@pytest.fixture
def tree(g, tmpdir_guest):
    g.ok(f"cd {tmpdir_guest} && mkdir -p sub/deep empty && printf 'hello\\n' > a.txt && : > e.log"
         " && printf xxxxxxxxxx > sub/b.TXT && printf 'y\\n' > sub/deep/c.txt && ln -s a.txt link"
         " && chmod 600 a.txt && chmod 755 sub && touch -d 2020-01-01 old")
    return tmpdir_guest


@pytest.mark.parametrize("cmd,expected", [
    ("find . -name '*.txt' | sort", "./a.txt\n./sub/deep/c.txt\n"),
    ("find . -iname '*.txt' | sort", "./a.txt\n./sub/b.TXT\n./sub/deep/c.txt\n"),
    ("find . -type d | sort", ".\n./empty\n./sub\n./sub/deep\n"),
    ("find . -maxdepth 1 -type f | sort", "./a.txt\n./e.log\n./old\n"),
    ("find . -mindepth 2 | sort", "./sub/b.TXT\n./sub/deep\n./sub/deep/c.txt\n"),
    ("find . -path './sub/*' | sort", "./sub/b.TXT\n./sub/deep\n./sub/deep/c.txt\n"),
    ("find . \\( -name a.txt -o -name c.txt \\) -print | sort", "./a.txt\n./sub/deep/c.txt\n"),
    ("find . -empty | sort", "./e.log\n./empty\n./old\n"),
    ("find . -size +5c -type f | sort", "./a.txt\n./sub/b.TXT\n"),
    ("find . -perm 600", "./a.txt\n"),
    ("find . -name sub -prune -o -type f -print | sort", "./a.txt\n./e.log\n./old\n"),
    ("find . -name c.txt -exec cat {} \\;", "y\n"),
    ("find sub -name c.txt -printf '%f %s %d %p %h %m\\n'", "c.txt 2 2 sub/deep/c.txt sub/deep 644\n"),
    ("find . -regex '.*/[ab]\\..*' | sort", "./a.txt\n./sub/b.TXT\n"),
    ("find . -newer old -name '*.txt' | sort", "./a.txt\n./sub/deep/c.txt\n"),
    ("find . -name old -mtime +100", "./old\n"),
    ("find -L . -name link -type f", "./link\n"),
    ("find sub/ -maxdepth 0", "sub/\n"),
    ("find . -name '*.txt' -type f -exec echo X {} + | tr ' ' '\\n' | sort", "./a.txt\n./sub/deep/c.txt\nX\n"),
])
def test_find(g, tree, cmd, expected):
    assert sh(g, tree, cmd) == (expected, 0)


def test_find_errors_and_delete(g, tree):
    assert sh(g, tree, "find nope") == ("find: 'nope': No such file or directory\n", 1)
    assert sh(g, tree, "find . -bogus") == ("find: unknown predicate '-bogus'\n", 1)
    assert sh(g, tree, "mkdir -p del/x && touch del/x/y && find del -delete && ls del") == (
        "ls: cannot access 'del': No such file or directory\n", 2)


@pytest.mark.parametrize("cmd,expected,status", [
    ("printf 'a b\\nc\\n' | xargs echo", "a b c\n", 0),
    ("printf 'a b\\nc\\n' | xargs -n1 echo", "a\nb\nc\n", 0),
    ("printf 'a\\nb\\n' | xargs -I{} echo [{}]", "[a]\n[b]\n", 0),
    ("printf 'x y\\0z\\0' | xargs -0 -n1 echo", "x y\nz\n", 0),
    ("echo \"'a b' \\\"c d\\\" e\\\\ f\" | xargs -n1 echo", "a b\nc d\ne f\n", 0),
    ("printf '' | xargs -r echo nothing", "", 0),
    ("printf '' | xargs echo empty", "empty\n", 0),
    ("printf 'a\\n' | xargs false", "", 123),
    ("echo q | xargs -t echo", "echo q\nq\n", 0),
])
def test_xargs(g, d, cmd, expected, status):
    assert sh(g, d, cmd) == (expected, status)


# ── locate / updatedb ──────────────────────────────────────────────────────

def test_locate(g):
    g.ok("mkdir -p /srv/lt/secret && echo x > /srv/lt/secret/hid.den && chmod 700 /srv/lt/secret"
         " && echo y > /srv/lt/pub.lic && echo z > /srv/lt/gone.now && updatedb")
    assert g.out("stat -c '%a %U' /var/lib/locate/db") == "600 root\n"
    assert g.out("locate hid.den") == "/srv/lt/secret/hid.den\n"
    assert g.out("locate -b pub.lic") == "/srv/lt/pub.lic\n"
    # Deleted files never show: results are checked live.
    g.ok("rm /srv/lt/gone.now")
    assert g.run("locate gone.now")[2] == 1
    g.run("rm -rf /srv/lt")


# ── sed ────────────────────────────────────────────────────────────────────

N = "printf 'one\\ntwo\\nthree\\nfour\\nfive\\n' > n.txt;"


@pytest.mark.parametrize("cmd,expected", [
    ("sed 's/o/0/' n.txt", "0ne\ntw0\nthree\nf0ur\nfive\n"),
    ("sed 's/o/0/g' n.txt", "0ne\ntw0\nthree\nf0ur\nfive\n"),
    ("echo aaaa | sed 's/a/b/2'", "abaa\n"),
    ("echo aaaa | sed 's/a/b/2g'", "abbb\n"),
    ("echo Hello | sed 's/hello/bye/I'", "bye\n"),
    ("echo abc | sed 's/b/[&]/'", "a[b]c\n"),
    ("echo 'john smith' | sed 's/\\(.*\\) \\(.*\\)/\\2, \\1/'", "smith, john\n"),
    ("echo 'john smith' | sed -E 's/(\\w+) (\\w+)/\\2 \\1/'", "smith john\n"),
    ("echo 'hello world' | sed 's/\\w\\+/\\u&/g'", "Hello World\n"),
    ("sed -n '2,4p' n.txt", "two\nthree\nfour\n"),
    ("sed -n '/two/,/four/p' n.txt", "two\nthree\nfour\n"),
    ("sed -n '$p' n.txt", "five\n"),
    ("sed '1d;$d' n.txt", "two\nthree\nfour\n"),
    ("seq 10 | sed -n '1~3p'", "1\n4\n7\n10\n"),
    ("seq 10 | sed -n '/3/,+2p'", "3\n4\n5\n"),
    ("printf 'x\\ny\\nx\\n' | sed '0,/x/s//Z/'", "Z\ny\nx\n"),
    ("sed '2,3c changed' n.txt", "one\nchanged\nfour\nfive\n"),
    ("echo hello | sed 'y/abcdefghij/ABCDEFGHIJ/'", "HEllo\n"),
    ("sed -n '$=' n.txt", "5\n"),
    ("printf '1\\n2\\n3\\n' | sed 'N;P;D'", "1\n2\n3\n"),
    ("sed ':a;N;$!ba;s/\\n/,/g' n.txt", "one,two,three,four,five\n"),
    ("sed -n '1!G;h;$p' n.txt", "five\nfour\nthree\ntwo\none\n"),
    ("sed -n '3{p;q}' n.txt", "three\n"),
    ("printf 'aXb\\nab\\n' | sed 's/X/-/;t;s/$/ (no X)/'", "a-b\nab (no X)\n"),
    ("printf 'a\\tb\\\\c\\001\\n' | sed -n l", "a\\tb\\\\c\\001$\n"),
    ("printf 'a\\nb' | sed p", "a\na\nb\nb"),
    ("echo 'cat dog' | sed 's/cat\\|dog/pet/g'", "pet pet\n"),
    ("sed 's/a/b' n.txt", "sed: -e expression #1, char 5: unterminated `s' command\n"),
])
def test_sed(g, d, cmd, expected):
    out, _ = sh(g, d, N + cmd)
    assert out == expected


def test_sed_in_place(g, d):
    g.ok(f"cd {d} && {N} cp n.txt m.txt && sed -i 's/one/ONE/' m.txt && sed -i.bak 1d m.txt")
    assert g.out(f"cd {d} && head -1 m.txt m.txt.bak") == "==> m.txt <==\ntwo\n\n==> m.txt.bak <==\nONE\n"
    assert sh(g, d, "sed '2Q5' n.txt")[1] == 5


# ── diff ───────────────────────────────────────────────────────────────────

def test_diff(g, d):
    g.ok(f"cd {d} && printf 'a\\nb\\nc\\nd\\ne\\nf\\ng\\nh\\ni\\nj\\nk\\nl\\nm\\n' > o"
         " && printf 'a\\nB\\nc\\nd\\ne\\nf\\ng\\nh\\ni\\nj\\nk\\nl\\nm\\nn\\n' > n")
    assert sh(g, d, "diff o n") == ("2c2\n< b\n---\n> B\n13a14\n> n\n", 1)
    assert sh(g, d, "diff -u --label o --label n o n") == (
        "--- o\n+++ n\n@@ -1,5 +1,5 @@\n a\n-b\n+B\n c\n d\n e\n@@ -11,3 +11,4 @@\n k\n l\n m\n+n\n", 1)
    assert sh(g, d, "diff o o") == ("", 0)
    assert sh(g, d, "diff -q o n") == ("Files o and n differ\n", 1)
    assert sh(g, d, "diff o nope") == ("diff: nope: No such file or directory\n", 2)
    g.ok(f"cd {d} && printf 'x\\ny' > r && printf 'x\\ny\\n' > s")
    assert sh(g, d, "diff r s") == ("2c2\n< y\n\\ No newline at end of file\n---\n> y\n", 1)


def test_diff_recursive(g, d):
    g.ok(f"cd {d} && mkdir -p A/sub B/sub && echo 1 > A/f && echo 2 > B/f && echo x > A/only"
         " && echo s > A/sub/t && echo t > B/sub/t")
    assert sh(g, d, "diff -r A B") == (
        "diff -r A/f B/f\n1c1\n< 1\n---\n> 2\nOnly in A: only\n"
        "diff -r A/sub/t B/sub/t\n1c1\n< s\n---\n> t\n", 1)
    assert sh(g, d, "diff -rq A B") == ("Files A/f and B/f differ\nOnly in A: only\nFiles A/sub/t and B/sub/t differ\n", 1)


# ── stat / realpath / readlink / which / du ────────────────────────────────

def test_stat(g, d):
    out = g.out(f"cd {d} && stat a.txt")
    lines = out.splitlines()
    assert lines[0] == "  File: a.txt"
    assert re.fullmatch(r"  Size: 47        \tBlocks: \d+ +IO Block: \d+ +regular file", lines[1])
    assert re.fullmatch(r"Device: \d+,\d+\tInode: \d+ +Links: 1", lines[2])
    assert lines[3] == "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)"
    assert re.fullmatch(r"Modify: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{9} \+0000", lines[5])
    assert lines[7] == " Birth: -"
    assert g.out(f"cd {d} && stat -c '%n %s %F %a %A %U %G %h' a.txt") == "a.txt 47 regular file 644 -rw-r--r-- root root 1\n"
    assert "Device type: 1,3" in g.out("stat /dev/null")


def test_paths(g, d):
    g.ok(f"cd {d} && mkdir -p rp/x && ln -s rp/x lk")
    assert g.out(f"cd {d} && realpath lk") == f"{d}/rp/x\n"
    assert g.out(f"cd {d} && realpath -s lk") == f"{d}/lk\n"
    assert g.out(f"cd {d} && realpath -m a/b/../c") == f"{d}/a/c\n"
    assert sh(g, d, "realpath -e nonexist") == ("realpath: nonexist: No such file or directory\n", 1)
    assert g.out(f"cd {d} && readlink lk") == "rp/x\n"
    assert g.out(f"cd {d} && readlink -f lk") == f"{d}/rp/x\n"
    assert sh(g, d, "readlink a.txt") == ("", 1)
    assert g.out(f"realpath --relative-to={d}/rp {d}/rp/x {d}") == "x\n..\n"
    assert g.out("which ls") == "/bin/ls\n"
    assert g.run("which nonexistcmd")[2] == 1


def test_du(g, d):
    g.ok(f"cd {d} && mkdir -p du/a/b && printf hello > du/a/f")
    assert g.out(f"cd {d} && du -sb du/a/f") == "5\tdu/a/f\n"
    assert g.out(f"cd {d} && du -cb du/a/f du/a/f") == "5\tdu/a/f\n5\ttotal\n"
    out = g.out(f"cd {d} && du du")
    assert [l.split("\t")[1] for l in out.splitlines()] == ["du/a/b", "du/a", "du"]


# ── pagers ─────────────────────────────────────────────────────────────────

def test_pagers_without_tty(g, d):
    assert g.out(f"cd {d} && less b.txt") == "x\nfoo\n"
    assert g.out(f"cd {d} && more a.txt b.txt | tail -5") == "::::::::::::::\nb.txt\n::::::::::::::\nx\nfoo\n"


def test_less_interactive(pty):
    pty.send("seq 1 200 | less\r")
    screen = pty.read_until(r"23\s+:", timeout=30)
    assert "\x1b[?1049h" in screen                    # alternate screen
    assert "\r\n1\x1b[K" in screen or "\x1b[H1\x1b[K" in screen
    pty.send("/150\r")
    screen = pty.read_until(r":", timeout=30)
    top = strip_ansi(screen.split("\x1b[H")[-1]).split("\r\n")[0]
    assert top.strip() == "150"
    pty.send("G")
    screen = pty.read_until(r"\(END\)", timeout=30)
    assert "200" in strip_ansi(screen)
    pty.send("q")
    out = pty.read_until(r"[#$] $", timeout=30)
    assert "\x1b[?1049l" in out                       # screen restored
    # The terminal is back in canonical mode with echo: a command works.
    assert "hello-after-less" in strip_ansi(pty.cmd("echo hello-after-less"))


def test_more_interactive(pty):
    pty.send("seq 1 100 | more\r")
    pty.read_until(r"--More--", timeout=30)
    pty.send(" ")
    screen = pty.read_until(r"--More--", timeout=30)
    assert "46" in strip_ansi(screen)
    pty.send("q")
    pty.read_until(r"[#$] $", timeout=30)
    assert "ok-after-more" in strip_ansi(pty.cmd("echo ok-after-more"))
