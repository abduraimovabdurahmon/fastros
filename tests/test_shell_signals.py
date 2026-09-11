"""The shell as a command, traps, and signal semantics (bash-compatible)."""
import time


def test_sh_modes(g):
    g.ok("printf 'echo $0 $1 $#\\nexit 3\\n' > /tmp/s.sh")
    out, err, st = g.run("sh /tmp/s.sh a b")
    assert out == "/tmp/s.sh a 2\n" and st == 3
    assert g.ok("echo 'echo in $1' | sh -s x") == "in x\n"
    assert g.ok("sh -c 'echo $0-$1' zero one") == "zero-one\n"
    out, err, st = g.run("sh -e -c 'false; echo no'")
    assert out == "" and st == 1


def test_traps_and_default_actions(g):
    assert g.ok("sh -c 'trap \"echo caught\" TERM; kill -TERM $$; echo after'") == "caught\nafter\n"
    out, err, st = g.run("sh -c 'kill -TERM $$; echo unreachable'")
    assert out == "" and st == 143
    out, err, st = g.run("sh -c 'trap \"echo bye\" EXIT; kill -INT $$; echo no'")
    assert out == "bye\n" and st == 130
    assert g.ok("(sleep 5; echo x) & p=$!; sleep 0.3; kill $p; wait $p; echo $?") == "143\n"


def test_sigkill_cannot_be_trapped(g):
    out, err, st = g.run("sh -c 'trap \"echo nope\" KILL; kill -9 $$; echo alive'")
    assert "alive" not in out and st == 137


def test_ctrl_c_abandons_loop(term):
    term.send("for i in 1 2 3; do echo loop$i; sleep 3; done; echo finished\r")
    term.wait_for("loop1")
    time.sleep(0.5)
    term.send("\x03")
    term.pump(1.5)
    lines = [l.strip() for l in term.text().splitlines()]
    assert "loop1" in lines and "loop2" not in lines and "finished" not in lines, lines
    term.send("echo prompt-ok\r")
    term.wait_for("prompt-ok")
