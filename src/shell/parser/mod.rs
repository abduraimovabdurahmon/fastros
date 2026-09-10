//! Shell input parser
//!
//! Splits a raw line into command name, arguments, and optional I/O redirections.
//!
//! Grammar:
//!   line    ::= WS* token (WS+ token)* (WS+ redir)* NL?
//!   redir   ::= ('>' | '>>') WS* path
//!   token   ::= non-WS-char+  (not starting with '>' unless it IS '>' or '>>')
//!
//! Redirection tokens are stripped from the argument list and stored separately.

pub const MAX_ARGS: usize = 16;

pub struct ParsedCommand<'a> {
    /// Command name (first token).
    pub name: &'a [u8],
    /// Arguments (tokens after the name, excluding redirection).
    pub args: [&'a [u8]; MAX_ARGS],
    /// Number of valid entries in `args`.
    pub argc: usize,
    /// `>` redirect output target (None if not present).
    pub redir_out: Option<&'a [u8]>,
    /// `>>` — append mode (only meaningful when redir_out is Some).
    pub redir_append: bool,
}

pub fn parse(input: &[u8]) -> Option<ParsedCommand<'_>> {
    let mut tokens: [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
    let mut count  = 0usize;
    let mut i      = 0usize;
    let len        = input.len();

    // Tokenize (split by whitespace)
    while i < len && count < MAX_ARGS {
        while i < len && is_ws(input[i]) { i += 1; }
        if i >= len { break; }
        let start = i;
        while i < len && !is_ws(input[i]) { i += 1; }
        tokens[count] = &input[start..i];
        count += 1;
    }

    if count == 0 { return None; }

    // Scan tokens for `>` / `>>` redirection operators
    let mut args:         [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
    let mut argc:         usize             = 0;
    let mut redir_out:    Option<&[u8]>     = None;
    let mut redir_append: bool              = false;
    let mut skip_next:    bool              = false;

    for t in 1..count {          // start from 1 (index 0 = command name)
        if skip_next { skip_next = false; continue; }
        let tok = tokens[t];
        if tok == b">>" {
            redir_append = true;
            if t + 1 < count { redir_out = Some(tokens[t + 1]); skip_next = true; }
        } else if tok == b">" {
            redir_append = false;
            if t + 1 < count { redir_out = Some(tokens[t + 1]); skip_next = true; }
        } else if tok.starts_with(b">>") && tok.len() > 2 {
            // e.g. ">>file.txt" (no space)
            redir_append = true;
            redir_out    = Some(&tok[2..]);
        } else if tok.starts_with(b">") && tok.len() > 1 {
            // e.g. ">file.txt" (no space)
            redir_append = false;
            redir_out    = Some(&tok[1..]);
        } else {
            if argc < MAX_ARGS { args[argc] = tok; argc += 1; }
        }
    }

    Some(ParsedCommand {
        name: tokens[0],
        args,
        argc,
        redir_out,
        redir_append,
    })
}

#[inline]
fn is_ws(b: u8) -> bool { b == b' ' || b == b'\t' }
