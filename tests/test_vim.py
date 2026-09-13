"""The modal `vim` editor."""


def test_vim_insert_and_write_quit(term, g):
    g.run("rm -f /tmp/v.txt")
    term.send("vim /tmp/v.txt\r")
    term.wait_for("New File")
    term.send("i")            # insert mode
    term.wait_for("INSERT")
    term.send("hello vim")
    term.send("\x1b")         # ESC -> normal
    term.send(":wq\r")        # write + quit
    term.pump(0.6)
    assert g.ok("cat /tmp/v.txt").strip() == "hello vim"


def test_vim_dd_x_and_o(term, g):
    g.ok("printf 'alpha\\nbeta\\ngamma\\n' > /tmp/v2.txt")
    term.send("vim /tmp/v2.txt\r")
    term.wait_for("alpha")
    term.send("dd")           # delete line 'alpha'
    term.pump(0.3)
    term.send("x")            # delete 'b' of 'beta'
    term.pump(0.3)
    term.send("o")            # open line below -> insert
    term.wait_for("INSERT")
    term.send("new line")
    term.send("\x1b:wq\r")
    term.pump(0.6)
    out = g.ok("cat /tmp/v2.txt").splitlines()
    assert out[0] == "eta" and out[1] == "new line" and out[2] == "gamma", out


def test_vim_search_and_quit_bang(term, g):
    g.ok("printf 'one\\ntwo\\ntarget here\\nfour\\n' > /tmp/v3.txt")
    term.send("vim /tmp/v3.txt\r")
    term.wait_for("one")
    term.send("/target\r")    # search
    term.pump(0.3)
    term.send("x")            # delete 't' at match -> 'arget here'
    term.send(":q!\r")        # quit without saving
    term.pump(0.5)
    # :q! discards, file unchanged
    assert g.ok("cat /tmp/v3.txt").splitlines()[2] == "target here"
