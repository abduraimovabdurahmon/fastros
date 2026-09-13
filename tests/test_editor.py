"""The `nano` text editor (interactive, full-screen)."""


def test_nano_create_edit_save(term, g):
    g.run("rm -f /tmp/note.txt")
    term.send("nano /tmp/note.txt\r")
    term.wait_for("nano")  # title bar drawn
    term.send("hello from nano")
    term.pump(0.5)
    term.send("\x0f")  # ^O: save (named file writes directly)
    term.wait_for("Wrote")
    term.send("\x18")  # ^X: exit
    term.pump(0.5)
    assert g.ok("cat /tmp/note.txt").strip() == "hello from nano"


def test_nano_edit_existing(term, g):
    g.ok("printf 'line one\\nline two\\n' > /tmp/e.txt")
    term.send("nano /tmp/e.txt\r")
    term.wait_for("line one")
    # Cursor starts at top-left; type at the very start of line one.
    term.send("X")
    term.pump(0.3)
    term.send("\x0f")
    term.wait_for("Wrote")
    term.send("\x18")
    term.pump(0.3)
    assert g.ok("cat /tmp/e.txt").splitlines()[0] == "Xline one"
