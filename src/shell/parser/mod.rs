//! Shell input parser
//!
//! Pure function — no I/O, no global state, no allocations.
//! Splits a raw line into a command name and up to MAX_ARGS arguments.
//!
//! Grammar:
//!   line    ::= WS* (token WS*)* NL?
//!   token   ::= non-WS-char+
//!   WS      ::= ' ' | '\t'
//!
//! Only ASCII space/tab are treated as whitespace.
//! No quoting, no variable expansion — intentionally minimal.

/// Maximum number of arguments (including command name).
pub const MAX_ARGS: usize = 16;

/// Result of parsing one input line.
pub struct ParsedCommand<'a> {
    /// Command name (first token), as a slice of the original input.
    pub name: &'a [u8],
    /// Arguments (tokens after the name), packed from index 0.
    pub args: [&'a [u8]; MAX_ARGS],
    /// Number of valid entries in `args` (NOT counting `name`).
    pub argc: usize,
}

/// Parse `input` into a `ParsedCommand`.
///
/// Returns `None` if the line is empty or whitespace-only.
pub fn parse(input: &[u8]) -> Option<ParsedCommand<'_>> {
    let mut tokens: [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
    let mut count  = 0usize;
    let mut i      = 0usize;
    let len        = input.len();

    while i < len && count < MAX_ARGS {
        // Skip whitespace
        while i < len && is_ws(input[i]) { i += 1; }
        if i >= len { break; }

        // Scan token
        let start = i;
        while i < len && !is_ws(input[i]) { i += 1; }
        tokens[count] = &input[start..i];
        count += 1;
    }

    if count == 0 { return None; }

    let mut args = [b"" as &[u8]; MAX_ARGS];
    for j in 0..count.saturating_sub(1).min(MAX_ARGS) {
        args[j] = tokens[j + 1];
    }

    Some(ParsedCommand {
        name: tokens[0],
        args,
        argc: count.saturating_sub(1),
    })
}

#[inline]
fn is_ws(b: u8) -> bool { b == b' ' || b == b'\t' }
