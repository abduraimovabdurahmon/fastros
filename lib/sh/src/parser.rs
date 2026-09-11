//! Recursive-descent parser (scannerless: shell tokenisation depends on
//! context — keywords only count in command position, `}` ends a `${`
//! expansion but not a word, here-document bodies follow the next newline).

use crate::ast::*;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub msg: String,
    /// The input ended in the middle of a construct: an interactive shell
    /// should read another line and try again.
    pub incomplete: bool,
}

type R<T> = Result<T, ParseError>;

fn err<T>(msg: &str) -> R<T> {
    Err(ParseError { msg: msg.to_string(), incomplete: false })
}
fn incomplete<T>(msg: &str) -> R<T> {
    Err(ParseError { msg: msg.to_string(), incomplete: true })
}

/// Parse a whole program.
pub fn parse(src: &str) -> R<List> {
    let mut p = Parser { s: src.chars().collect(), i: 0 };
    let list = p.parse_list(&[])?;
    p.skip_space_nl();
    if p.i < p.s.len() {
        let rest: String = p.s[p.i..].iter().take(10).collect();
        return err(&alloc::format!("syntax error near unexpected token `{}'", rest.split_whitespace().next().unwrap_or("")));
    }
    Ok(list)
}

/// Parse the body of an expanding here-document (like `"..."` but `"` is literal).
pub fn parse_heredoc(body: &str) -> Word {
    let mut p = Parser { s: body.chars().collect(), i: 0 };
    let mut parts = Vec::new();
    let mut lit = String::new();
    while let Some(c) = p.peek() {
        match c {
            '\\' if matches!(p.peek_at(1), Some('$' | '`' | '\\' | '\n')) => {
                p.i += 1;
                let n = p.bump().unwrap_or('\\');
                if n != '\n' {
                    lit.push(n);
                }
            }
            '$' | '`' => {
                if !lit.is_empty() {
                    parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                }
                match if c == '$' { p.read_dollar() } else { p.read_backtick() } {
                    Ok(part) => parts.push(part),
                    Err(_) => {
                        p.i += 1;
                        lit.push(c);
                    }
                }
            }
            _ => {
                lit.push(c);
                p.i += 1;
            }
        }
    }
    if !lit.is_empty() {
        parts.push(WordPart::Quoted(lit));
    }
    Word(alloc::vec![WordPart::Double(parts)])
}

/// Parse a string as the inside of `"..."` (for `${x:-"..."}`-style reuse).
pub fn parse_word(src: &str) -> R<Word> {
    let mut p = Parser { s: src.chars().collect(), i: 0 };
    p.read_word_until(None)
}

const KEYWORDS: &[&str] = &["if", "then", "elif", "else", "fi", "do", "done", "case", "esac", "while", "until", "for", "in", "function", "{", "}", "!"];

pub fn is_name(s: &str) -> bool {
    let mut it = s.chars();
    matches!(it.next(), Some(c) if c == '_' || c.is_ascii_alphabetic()) && it.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

fn is_meta(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | '(' | ')')
}

struct Parser {
    s: Vec<char>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }
    fn peek_at(&self, n: usize) -> Option<char> {
        self.s.get(self.i + n).copied()
    }
    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }
    fn starts_with(&self, t: &str) -> bool {
        let mut j = self.i;
        for c in t.chars() {
            if self.s.get(j) != Some(&c) {
                return false;
            }
            j += 1;
        }
        true
    }
    fn eat(&mut self, t: &str) -> bool {
        if self.starts_with(t) {
            self.i += t.chars().count();
            true
        } else {
            false
        }
    }

    /// Blanks, line continuations and comments (not newlines).
    fn skip_blanks(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t') => self.i += 1,
                Some('\\') if self.peek_at(1) == Some('\n') => self.i += 2,
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                _ => return,
            }
        }
    }

    fn skip_space_nl(&mut self) {
        loop {
            self.skip_blanks();
            if self.peek() == Some('\n') {
                self.i += 1;
            } else {
                return;
            }
        }
    }

    /// The reserved word at the cursor, if one is there in command position.
    fn peek_keyword(&self) -> Option<&'static str> {
        for &k in KEYWORDS {
            if self.starts_with(k) {
                let next = self.s.get(self.i + k.chars().count()).copied();
                if next.is_none_or(|c| is_meta(c)) {
                    return Some(k);
                }
            }
        }
        None
    }

    fn expect_keyword(&mut self, k: &str) -> R<()> {
        self.skip_space_nl();
        if self.peek_keyword() == Some(match KEYWORDS.iter().find(|&&x| x == k) {
            Some(x) => x,
            None => return err("internal: unknown keyword"),
        }) {
            self.i += k.chars().count();
            return Ok(());
        }
        if self.peek().is_none() {
            return incomplete(&alloc::format!("syntax error: expected `{k}'"));
        }
        let tok: String = self.s[self.i..].iter().take_while(|c| !c.is_whitespace()).take(20).collect();
        err(&alloc::format!("syntax error near unexpected token `{tok}' (expected `{k}')"))
    }

    // ── lists ───────────────────────────────────────────────────────────

    fn parse_list(&mut self, terms: &[&str]) -> R<List> {
        let mut items = Vec::new();
        loop {
            self.skip_space_nl();
            match self.peek() {
                None | Some(')') => break,
                Some(';') if self.peek_at(1) == Some(';') => break,
                _ => {}
            }
            if let Some(k) = self.peek_keyword() {
                if terms.contains(&k) {
                    break;
                }
                if matches!(k, "then" | "elif" | "else" | "fi" | "do" | "done" | "esac" | "}" | "in") {
                    return err(&alloc::format!("syntax error near unexpected token `{k}'"));
                }
            }
            let and_or = self.parse_and_or()?;
            self.skip_blanks();
            let mut background = false;
            match self.peek() {
                Some('&') if self.peek_at(1) != Some('&') && self.peek_at(1) != Some('>') => {
                    self.i += 1;
                    background = true;
                }
                Some(';') if self.peek_at(1) != Some(';') => self.i += 1,
                Some('\n') => self.i += 1,
                _ => {}
            }
            items.push(Item { and_or, background });
        }
        Ok(List(items))
    }

    fn parse_and_or(&mut self) -> R<AndOr> {
        let first = self.parse_pipeline()?;
        let mut rest = Vec::new();
        loop {
            self.skip_blanks();
            let conn = if self.eat("&&") {
                Connector::And
            } else if self.eat("||") {
                Connector::Or
            } else {
                break;
            };
            self.skip_space_nl();
            if self.peek().is_none() {
                return incomplete("syntax error: command expected after `&&' or `||'");
            }
            rest.push((conn, self.parse_pipeline()?));
        }
        Ok(AndOr { first, rest })
    }

    fn parse_pipeline(&mut self) -> R<Pipeline> {
        self.skip_blanks();
        let mut negate = false;
        if self.peek_keyword() == Some("!") {
            self.i += 1;
            negate = true;
        }
        let mut cmds = alloc::vec![self.parse_command()?];
        loop {
            self.skip_blanks();
            if self.peek() == Some('|') && self.peek_at(1) != Some('|') {
                self.i += 1;
                self.skip_space_nl();
                if self.peek().is_none() {
                    return incomplete("syntax error: command expected after `|'");
                }
                cmds.push(self.parse_command()?);
            } else {
                break;
            }
        }
        Ok(Pipeline { negate, cmds })
    }

    // ── commands ────────────────────────────────────────────────────────

    fn parse_command(&mut self) -> R<Command> {
        self.skip_blanks();
        let cmd = match self.peek_keyword() {
            Some("if") => self.parse_if()?,
            Some("while") => self.parse_while(false)?,
            Some("until") => self.parse_while(true)?,
            Some("for") => self.parse_for()?,
            Some("case") => self.parse_case()?,
            Some("{") => {
                self.i += 1;
                let body = self.parse_list(&["}"])?;
                self.expect_keyword("}")?;
                Command::Group { body: Box::new(body), redirs: Vec::new() }
            }
            Some("function") => {
                self.i += "function".len();
                self.skip_blanks();
                let name = self.read_name().ok_or_else(|| ParseError { msg: "syntax error: function name expected".into(), incomplete: false })?;
                self.skip_blanks();
                if self.eat("(") {
                    self.skip_blanks();
                    if !self.eat(")") {
                        return err("syntax error: expected `)'");
                    }
                }
                self.skip_space_nl();
                return Ok(Command::FuncDef { name, body: Box::new(self.parse_command()?) });
            }
            Some(k) if matches!(k, "then" | "elif" | "else" | "fi" | "do" | "done" | "esac" | "}" | "in") => {
                return err(&alloc::format!("syntax error near unexpected token `{k}'"));
            }
            _ => {
                if self.peek() == Some('(') {
                    self.i += 1;
                    let body = self.parse_list(&[])?;
                    self.skip_space_nl();
                    if !self.eat(")") {
                        return if self.peek().is_none() { incomplete("syntax error: expected `)'") } else { err("syntax error: expected `)'") };
                    }
                    Command::Subshell { body: Box::new(body), redirs: Vec::new() }
                } else {
                    return self.parse_simple();
                }
            }
        };
        self.with_redirs(cmd)
    }

    /// Trailing redirections of a compound command.
    fn with_redirs(&mut self, mut cmd: Command) -> R<Command> {
        loop {
            self.skip_blanks();
            if !self.at_redir() {
                break;
            }
            let r = self.parse_redir()?;
            match &mut cmd {
                Command::Subshell { redirs, .. }
                | Command::Group { redirs, .. }
                | Command::If { redirs, .. }
                | Command::While { redirs, .. }
                | Command::For { redirs, .. }
                | Command::Case { redirs, .. }
                | Command::Simple { redirs, .. } => redirs.push(r),
                Command::FuncDef { .. } => return err("syntax error: redirection after function definition"),
            }
        }
        Ok(cmd)
    }

    fn parse_if(&mut self) -> R<Command> {
        self.i += 2;
        let mut branches = Vec::new();
        let cond = self.parse_list(&["then"])?;
        self.expect_keyword("then")?;
        let body = self.parse_list(&["elif", "else", "fi"])?;
        branches.push((cond, body));
        let mut else_body = None;
        loop {
            self.skip_space_nl();
            match self.peek_keyword() {
                Some("elif") => {
                    self.i += 4;
                    let c = self.parse_list(&["then"])?;
                    self.expect_keyword("then")?;
                    let b = self.parse_list(&["elif", "else", "fi"])?;
                    branches.push((c, b));
                }
                Some("else") => {
                    self.i += 4;
                    else_body = Some(Box::new(self.parse_list(&["fi"])?));
                    self.expect_keyword("fi")?;
                    break;
                }
                _ => {
                    self.expect_keyword("fi")?;
                    break;
                }
            }
        }
        if branches.iter().any(|(c, _)| c.is_empty()) {
            return err("syntax error: empty condition");
        }
        Ok(Command::If { branches, else_body, redirs: Vec::new() })
    }

    fn parse_while(&mut self, until: bool) -> R<Command> {
        self.i += 5; // "while" / "until"
        let cond = self.parse_list(&["do"])?;
        self.expect_keyword("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_keyword("done")?;
        Ok(Command::While { cond: Box::new(cond), body: Box::new(body), until, redirs: Vec::new() })
    }

    fn parse_for(&mut self) -> R<Command> {
        self.i += 3;
        self.skip_blanks();
        let var = self.read_name().ok_or_else(|| ParseError { msg: "syntax error: variable name expected after `for'".into(), incomplete: false })?;
        self.skip_space_nl();
        let mut items = None;
        if self.peek_keyword() == Some("in") {
            self.i += 2;
            let mut words = Vec::new();
            loop {
                self.skip_blanks();
                match self.peek() {
                    Some(';') | Some('\n') => {
                        self.i += 1;
                        break;
                    }
                    None => return incomplete("syntax error: expected `do'"),
                    _ => {}
                }
                match self.read_word()? {
                    Some(w) => words.push(w),
                    None => return err("syntax error in `for' word list"),
                }
            }
            items = Some(words);
        } else if self.peek() == Some(';') {
            self.i += 1;
        }
        self.expect_keyword("do")?;
        let body = self.parse_list(&["done"])?;
        self.expect_keyword("done")?;
        Ok(Command::For { var, items, body: Box::new(body), redirs: Vec::new() })
    }

    fn parse_case(&mut self) -> R<Command> {
        self.i += 4;
        self.skip_blanks();
        let word = self.read_word()?.ok_or_else(|| ParseError { msg: "syntax error: word expected after `case'".into(), incomplete: false })?;
        self.skip_space_nl();
        self.expect_keyword("in")?;
        let mut arms = Vec::new();
        loop {
            self.skip_space_nl();
            if self.peek_keyword() == Some("esac") {
                self.i += 4;
                break;
            }
            if self.peek().is_none() {
                return incomplete("syntax error: expected `esac'");
            }
            self.eat("(");
            let mut pats = Vec::new();
            loop {
                self.skip_blanks();
                let w = self.read_word()?.ok_or_else(|| ParseError { msg: "syntax error: pattern expected".into(), incomplete: false })?;
                pats.push(w);
                self.skip_blanks();
                if self.eat("|") {
                    continue;
                }
                if self.eat(")") {
                    break;
                }
                return err("syntax error: expected `)' after case pattern");
            }
            let body = self.parse_list(&["esac"])?;
            arms.push((pats, body));
            self.skip_space_nl();
            if self.eat(";;") {
                continue;
            }
            self.skip_space_nl();
            if self.peek_keyword() == Some("esac") {
                self.i += 4;
                break;
            }
            if self.peek().is_none() {
                return incomplete("syntax error: expected `;;' or `esac'");
            }
            return err("syntax error: expected `;;'");
        }
        Ok(Command::Case { word, arms, redirs: Vec::new() })
    }

    fn read_name(&mut self) -> Option<String> {
        let start = self.i;
        while self.peek().is_some_and(|c| c == '_' || c.is_ascii_alphanumeric()) {
            self.i += 1;
        }
        let n: String = self.s[start..self.i].iter().collect();
        if is_name(&n) {
            Some(n)
        } else {
            self.i = start;
            None
        }
    }

    fn parse_simple(&mut self) -> R<Command> {
        let mut assigns = Vec::new();
        let mut words: Vec<Word> = Vec::new();
        let mut redirs = Vec::new();
        loop {
            self.skip_blanks();
            match self.peek() {
                None | Some('\n' | ';' | '|' | ')') => break,
                Some('&') if !self.starts_with("&>") => break,
                Some('(') => {
                    // `name()` function definition.
                    if words.len() == 1 && assigns.is_empty() && redirs.is_empty() {
                        if let Some(name) = words[0].as_plain().filter(|n| is_name(n)).map(|n| n.to_string()) {
                            self.i += 1;
                            self.skip_blanks();
                            if !self.eat(")") {
                                return err("syntax error: expected `)'");
                            }
                            self.skip_space_nl();
                            let body = self.parse_command()?;
                            return Ok(Command::FuncDef { name, body: Box::new(body) });
                        }
                    }
                    return err("syntax error near unexpected token `('");
                }
                _ => {}
            }
            if self.at_redir() {
                redirs.push(self.parse_redir()?);
                continue;
            }
            let Some(w) = self.read_word()? else { break };
            if words.is_empty() {
                if let Some((name, value)) = split_assignment(&w) {
                    assigns.push((name, value));
                    continue;
                }
            }
            words.push(w);
        }
        if assigns.is_empty() && words.is_empty() && redirs.is_empty() {
            let tok = self.peek().map(|c| c.to_string()).unwrap_or_else(|| "newline".into());
            return err(&alloc::format!("syntax error near unexpected token `{tok}'"));
        }
        Ok(Command::Simple { assigns, words, redirs })
    }

    // ── redirections ────────────────────────────────────────────────────

    fn at_redir(&self) -> bool {
        let mut j = self.i;
        while self.s.get(j).is_some_and(|c| c.is_ascii_digit()) {
            j += 1;
        }
        match self.s.get(j) {
            Some('<' | '>') => true,
            Some('&') => j == self.i && self.s.get(j + 1) == Some(&'>'),
            _ => false,
        }
    }

    fn parse_redir(&mut self) -> R<Redir> {
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        let fd = if self.i > start {
            let s: String = self.s[start..self.i].iter().collect();
            Some(s.parse::<u32>().map_err(|_| ParseError { msg: "bad file descriptor".into(), incomplete: false })?)
        } else {
            None
        };
        let (op, strip) = if self.eat("<<<") {
            (RedirOp::HereString, false)
        } else if self.eat("<<-") {
            (RedirOp::HereDoc, true)
        } else if self.eat("<<") {
            (RedirOp::HereDoc, false)
        } else if self.eat("<>") {
            (RedirOp::ReadWrite, false)
        } else if self.eat("<&") {
            (RedirOp::DupIn, false)
        } else if self.eat("<") {
            (RedirOp::In, false)
        } else if self.eat(">>") {
            (RedirOp::Append, false)
        } else if self.eat(">|") {
            (RedirOp::Clobber, false)
        } else if self.eat(">&") {
            (RedirOp::DupOut, false)
        } else if self.eat(">") {
            (RedirOp::Out, false)
        } else if self.eat("&>>") {
            (RedirOp::AppendErr, false)
        } else if self.eat("&>") {
            (RedirOp::OutErr, false)
        } else {
            return err("syntax error in redirection");
        };
        self.skip_blanks();
        let target = match self.read_word()? {
            Some(w) => w,
            None => {
                return if self.peek().is_none() || self.peek() == Some('\n') {
                    err("syntax error near unexpected token `newline'")
                } else {
                    err("syntax error: file name expected after redirection")
                }
            }
        };
        let mut heredoc = None;
        if op == RedirOp::HereDoc {
            let delim = delimiter_text(&target);
            let expand = !target.has_quotes();
            heredoc = Some((self.take_heredoc_body(&delim, strip)?, expand));
        }
        Ok(Redir { fd, op, target, heredoc })
    }

    /// Cut the here-document body (the lines after the current line, up to
    /// the delimiter line) out of the source and return it.
    fn take_heredoc_body(&mut self, delim: &str, strip_tabs: bool) -> R<String> {
        let mut j = self.i;
        while j < self.s.len() && self.s[j] != '\n' {
            j += 1;
        }
        if j >= self.s.len() {
            return incomplete("here-document: body expected");
        }
        let body_start = j + 1;
        let mut k = body_start;
        let mut body = String::new();
        loop {
            if k >= self.s.len() {
                return incomplete(&alloc::format!("here-document delimited by end-of-file (wanted `{delim}')"));
            }
            let mut e = k;
            while e < self.s.len() && self.s[e] != '\n' {
                e += 1;
            }
            let mut line: String = self.s[k..e].iter().collect();
            if strip_tabs {
                line = line.trim_start_matches('\t').to_string();
            }
            let next = if e < self.s.len() { e + 1 } else { e };
            if line == delim {
                self.s.drain(body_start..next);
                return Ok(body);
            }
            body.push_str(&line);
            body.push('\n');
            k = next;
        }
    }

    // ── words ───────────────────────────────────────────────────────────

    fn read_word(&mut self) -> R<Option<Word>> {
        match self.peek() {
            None => return Ok(None),
            Some(c) if is_meta(c) => return Ok(None),
            _ => {}
        }
        let w = self.read_word_until(None)?;
        Ok(if w.0.is_empty() { None } else { Some(w) })
    }

    /// Read a word; stops at a metacharacter, or only at `stop` (unquoted)
    /// when given (the inside of `${...}` may contain blanks).
    fn read_word_until(&mut self, stop: Option<&[char]>) -> R<Word> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        let start = self.i;
        loop {
            let Some(c) = self.peek() else { break };
            match stop {
                Some(s) if s.contains(&c) => break,
                None if is_meta(c) => break,
                _ => {}
            }
            match c {
                '\\' => {
                    self.i += 1;
                    match self.bump() {
                        Some('\n') => {}
                        Some(n) => {
                            flush(&mut lit, &mut parts);
                            parts.push(WordPart::Quoted(n.to_string()));
                        }
                        None => lit.push('\\'),
                    }
                }
                '\'' => {
                    self.i += 1;
                    let mut q = String::new();
                    loop {
                        match self.bump() {
                            Some('\'') => break,
                            Some(ch) => q.push(ch),
                            None => return incomplete("unexpected EOF while looking for matching `''"),
                        }
                    }
                    flush(&mut lit, &mut parts);
                    parts.push(WordPart::Quoted(q));
                }
                '"' => {
                    self.i += 1;
                    flush(&mut lit, &mut parts);
                    let inner = self.read_double()?;
                    parts.push(WordPart::Double(inner));
                }
                '$' => {
                    flush(&mut lit, &mut parts);
                    let p = self.read_dollar()?;
                    parts.push(p);
                }
                '`' => {
                    flush(&mut lit, &mut parts);
                    let p = self.read_backtick()?;
                    parts.push(p);
                }
                '~' if self.i == start && stop.is_none() => {
                    self.i += 1;
                    let mut user = String::new();
                    while let Some(ch) = self.peek() {
                        if ch == '/' || is_meta(ch) || !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.') {
                            break;
                        }
                        user.push(ch);
                        self.i += 1;
                    }
                    parts.push(WordPart::Tilde(user));
                }
                _ => {
                    lit.push(c);
                    self.i += 1;
                }
            }
        }
        flush(&mut lit, &mut parts);
        Ok(Word(parts))
    }

    fn read_double(&mut self) -> R<Vec<WordPart>> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        loop {
            match self.peek() {
                None => return incomplete("unexpected EOF while looking for matching `\"'"),
                Some('"') => {
                    self.i += 1;
                    break;
                }
                Some('\\') => {
                    self.i += 1;
                    match self.bump() {
                        Some(c @ ('$' | '`' | '"' | '\\')) => lit.push(c),
                        Some('\n') => {}
                        Some(c) => {
                            lit.push('\\');
                            lit.push(c);
                        }
                        None => return incomplete("unexpected EOF in string"),
                    }
                }
                Some('$') => {
                    if !lit.is_empty() {
                        parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                    }
                    parts.push(self.read_dollar()?);
                }
                Some('`') => {
                    if !lit.is_empty() {
                        parts.push(WordPart::Quoted(core::mem::take(&mut lit)));
                    }
                    parts.push(self.read_backtick()?);
                }
                Some(c) => {
                    lit.push(c);
                    self.i += 1;
                }
            }
        }
        if !lit.is_empty() {
            parts.push(WordPart::Quoted(lit));
        }
        Ok(parts)
    }

    fn read_backtick(&mut self) -> R<WordPart> {
        self.i += 1;
        let mut src = String::new();
        loop {
            match self.bump() {
                Some('`') => break,
                Some('\\') => match self.bump() {
                    Some(c @ ('`' | '\\' | '$')) => src.push(c),
                    Some(c) => {
                        src.push('\\');
                        src.push(c);
                    }
                    None => return incomplete("unexpected EOF while looking for matching ``'"),
                },
                Some(c) => src.push(c),
                None => return incomplete("unexpected EOF while looking for matching ``'"),
            }
        }
        Ok(WordPart::Command(src))
    }

    fn read_dollar(&mut self) -> R<WordPart> {
        self.i += 1; // '$'
        match self.peek() {
            Some('{') => {
                self.i += 1;
                self.read_brace_param()
            }
            Some('(') if self.peek_at(1) == Some('(') => {
                self.i += 2;
                let mut depth = 0i32;
                let mut src = String::new();
                loop {
                    match self.bump() {
                        None => return incomplete("unexpected EOF in `$((...))'"),
                        Some('(') => {
                            depth += 1;
                            src.push('(');
                        }
                        Some(')') if depth == 0 => {
                            if self.bump() == Some(')') {
                                break;
                            }
                            return err("syntax error: expected `))'");
                        }
                        Some(')') => {
                            depth -= 1;
                            src.push(')');
                        }
                        Some(c) => src.push(c),
                    }
                }
                Ok(WordPart::Arith(src))
            }
            Some('(') => {
                self.i += 1;
                let src = self.read_balanced()?;
                Ok(WordPart::Command(src))
            }
            Some(c @ ('?' | '$' | '#' | '!' | '@' | '*' | '-' | '0'..='9')) => {
                self.i += 1;
                Ok(WordPart::Param(Param { name: c.to_string(), op: ParamOp::Plain }))
            }
            Some(c) if c == '_' || c.is_ascii_alphabetic() => {
                let name = self.read_name().unwrap_or_default();
                Ok(WordPart::Param(Param { name, op: ParamOp::Plain }))
            }
            _ => Ok(WordPart::Lit("$".into())),
        }
    }

    /// Source of `$( ... )` up to the matching `)`, honouring quotes.
    fn read_balanced(&mut self) -> R<String> {
        let mut depth = 0i32;
        let mut src = String::new();
        loop {
            let Some(c) = self.bump() else { return incomplete("unexpected EOF while looking for matching `)'") };
            match c {
                '(' => depth += 1,
                ')' if depth == 0 => return Ok(src),
                ')' => depth -= 1,
                '\'' => {
                    src.push(c);
                    loop {
                        let Some(q) = self.bump() else { return incomplete("unexpected EOF in `$(...)'") };
                        src.push(q);
                        if q == '\'' {
                            break;
                        }
                    }
                    continue;
                }
                '"' => {
                    src.push(c);
                    loop {
                        let Some(q) = self.bump() else { return incomplete("unexpected EOF in `$(...)'") };
                        src.push(q);
                        if q == '\\' {
                            if let Some(n) = self.bump() {
                                src.push(n);
                            }
                            continue;
                        }
                        if q == '"' {
                            break;
                        }
                    }
                    continue;
                }
                '\\' => {
                    src.push(c);
                    if let Some(n) = self.bump() {
                        src.push(n);
                    }
                    continue;
                }
                _ => {}
            }
            src.push(c);
        }
    }

    fn read_brace_param(&mut self) -> R<WordPart> {
        // ${#name} (length) vs ${#} (count)
        if self.peek() == Some('#') && self.peek_at(1).is_some_and(|c| c != '}') {
            self.i += 1;
            let name = self.read_param_name()?;
            if !self.eat("}") {
                return err("bad substitution");
            }
            return Ok(WordPart::Param(Param { name, op: ParamOp::Length }));
        }
        let name = self.read_param_name()?;
        let colon_ops = |p: &mut Parser, colon: bool| -> R<Option<ParamOp>> {
            let op = match p.peek() {
                Some('-') => 0,
                Some('=') => 1,
                Some('?') => 2,
                Some('+') => 3,
                _ => return Ok(None),
            };
            p.i += 1;
            let word = p.read_word_until(Some(&['}']))?;
            Ok(Some(match op {
                0 => ParamOp::Default { word, colon },
                1 => ParamOp::Assign { word, colon },
                2 => ParamOp::Error { word, colon },
                _ => ParamOp::Alternate { word, colon },
            }))
        };
        let op = match self.peek() {
            Some('}') => ParamOp::Plain,
            Some(':') => {
                self.i += 1;
                match colon_ops(self, true)? {
                    Some(op) => op,
                    None => {
                        let mut off = String::new();
                        while self.peek().is_some_and(|c| c != ':' && c != '}') {
                            off.push(self.bump().unwrap_or(' '));
                        }
                        let length = if self.eat(":") {
                            let mut l = String::new();
                            while self.peek().is_some_and(|c| c != '}') {
                                l.push(self.bump().unwrap_or(' '));
                            }
                            Some(l)
                        } else {
                            None
                        };
                        ParamOp::Substring { offset: off, length }
                    }
                }
            }
            Some('-' | '=' | '?' | '+') => colon_ops(self, false)?.unwrap_or(ParamOp::Plain),
            Some('%') => {
                self.i += 1;
                let longest = self.eat("%");
                ParamOp::TrimSuffix { pattern: self.read_word_until(Some(&['}']))?, longest }
            }
            Some('#') => {
                self.i += 1;
                let longest = self.eat("#");
                ParamOp::TrimPrefix { pattern: self.read_word_until(Some(&['}']))?, longest }
            }
            Some('/') => {
                self.i += 1;
                let all = self.eat("/");
                let pattern = self.read_word_until(Some(&['/', '}']))?;
                // `${x/pat}` (no replacement) deletes the match.
                let replacement = if self.eat("/") { self.read_word_until(Some(&['}']))? } else { Word::default() };
                ParamOp::Replace { pattern, replacement, all }
            }
            Some('^') => {
                self.i += 1;
                ParamOp::Case { upper: true, all: self.eat("^") }
            }
            Some(',') => {
                self.i += 1;
                ParamOp::Case { upper: false, all: self.eat(",") }
            }
            None => return incomplete("unexpected EOF in `${'"),
            _ => return err("bad substitution"),
        };
        if !self.eat("}") {
            return if self.peek().is_none() { incomplete("unexpected EOF in `${'") } else { err("bad substitution") };
        }
        Ok(WordPart::Param(Param { name, op }))
    }

    fn read_param_name(&mut self) -> R<String> {
        match self.peek() {
            Some(c @ ('?' | '$' | '#' | '!' | '@' | '*' | '-')) => {
                self.i += 1;
                Ok(c.to_string())
            }
            Some(c) if c.is_ascii_digit() => {
                let mut n = String::new();
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    n.push(self.bump().unwrap_or('0'));
                }
                Ok(n)
            }
            _ => self.read_name().ok_or_else(|| ParseError { msg: "bad substitution".into(), incomplete: self.peek().is_none() }),
        }
    }
}

fn flush(lit: &mut String, parts: &mut Vec<WordPart>) {
    if !lit.is_empty() {
        parts.push(WordPart::Lit(core::mem::take(lit)));
    }
}

/// `NAME=value` as the first part of a word → (NAME, value word).
fn split_assignment(w: &Word) -> Option<(String, Word)> {
    let WordPart::Lit(first) = w.0.first()? else { return None };
    let eq = first.find('=')?;
    let name = &first[..eq];
    if !is_name(name) {
        return None;
    }
    let mut value = Vec::new();
    let rest = &first[eq + 1..];
    if !rest.is_empty() {
        value.push(WordPart::Lit(rest.to_string()));
    }
    value.extend(w.0[1..].iter().cloned());
    Some((name.to_string(), Word(value)))
}

/// Literal text of a here-document delimiter word (quotes removed).
fn delimiter_text(w: &Word) -> String {
    let mut s = String::new();
    for p in &w.0 {
        match p {
            WordPart::Lit(t) | WordPart::Quoted(t) => s.push_str(t),
            WordPart::Double(inner) => {
                for q in inner {
                    if let WordPart::Quoted(t) | WordPart::Lit(t) = q {
                        s.push_str(t);
                    }
                }
            }
            _ => {}
        }
    }
    s
}
