//! Abstract syntax of the shell language (a POSIX sh subset plus the
//! common bash conveniences `&>`, `<<<`, `function`).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordPart {
    /// Unquoted text: subject to globbing (but not to field splitting).
    Lit(String),
    /// Text that must stay literal: `'...'`, `\x`, and plain text inside `"..."`.
    Quoted(String),
    /// `"..."`: its expansions are not field-split or globbed.
    Double(Vec<WordPart>),
    Param(Param),
    /// `$(...)` or `` `...` `` — the source, parsed when expanded.
    Command(String),
    /// `$((...))`.
    Arith(String),
    /// `~` or `~user` at the start of a word.
    Tilde(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Word(pub Vec<WordPart>);

impl Word {
    pub fn lit(s: &str) -> Word {
        Word(alloc::vec![WordPart::Lit(String::from(s))])
    }
    /// The word's text if it contains no expansions or quotes at all.
    pub fn as_plain(&self) -> Option<&str> {
        match self.0.as_slice() {
            [WordPart::Lit(s)] => Some(s),
            _ => None,
        }
    }
    /// True if any part is quoted (affects keyword recognition, heredoc expansion).
    pub fn has_quotes(&self) -> bool {
        self.0.iter().any(|p| matches!(p, WordPart::Quoted(_) | WordPart::Double(_)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    pub name: String,
    pub op: ParamOp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamOp {
    Plain,
    /// `${#x}`
    Length,
    /// `${x:-w}` (colon = also when empty)
    Default { word: Word, colon: bool },
    /// `${x:=w}`
    Assign { word: Word, colon: bool },
    /// `${x:?w}`
    Error { word: Word, colon: bool },
    /// `${x:+w}`
    Alternate { word: Word, colon: bool },
    /// `${x%w}` / `${x%%w}`
    TrimSuffix { pattern: Word, longest: bool },
    /// `${x#w}` / `${x##w}`
    TrimPrefix { pattern: Word, longest: bool },
    /// `${x/pat/rep}` / `${x//pat/rep}`
    Replace { pattern: Word, replacement: Word, all: bool },
    /// `${x:off}` / `${x:off:len}`
    Substring { offset: String, length: Option<String> },
    /// `${x^^}` / `${x,,}` (all) and `${x^}` / `${x,}` (first char)
    Case { upper: bool, all: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirOp {
    /// `<`
    In,
    /// `>`
    Out,
    /// `>>`
    Append,
    /// `>|`
    Clobber,
    /// `<>`
    ReadWrite,
    /// `<&`
    DupIn,
    /// `>&`
    DupOut,
    /// `<<` / `<<-`
    HereDoc,
    /// `<<<`
    HereString,
    /// `&>` (stdout and stderr)
    OutErr,
    /// `&>>`
    AppendErr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redir {
    /// Explicit descriptor (`2>`), or the operator's default.
    pub fd: Option<u32>,
    pub op: RedirOp,
    pub target: Word,
    /// Here-document body and whether it undergoes expansion.
    pub heredoc: Option<(String, bool)>,
}

impl Redir {
    pub fn default_fd(&self) -> u32 {
        match self.op {
            RedirOp::In | RedirOp::ReadWrite | RedirOp::DupIn | RedirOp::HereDoc | RedirOp::HereString => 0,
            _ => 1,
        }
    }
    pub fn fd(&self) -> u32 {
        self.fd.unwrap_or_else(|| self.default_fd())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Simple { assigns: Vec<(String, Word)>, words: Vec<Word>, redirs: Vec<Redir> },
    Subshell { body: Box<List>, redirs: Vec<Redir> },
    Group { body: Box<List>, redirs: Vec<Redir> },
    If { branches: Vec<(List, List)>, else_body: Option<Box<List>>, redirs: Vec<Redir> },
    While { cond: Box<List>, body: Box<List>, until: bool, redirs: Vec<Redir> },
    For { var: String, items: Option<Vec<Word>>, body: Box<List>, redirs: Vec<Redir> },
    Case { word: Word, arms: Vec<(Vec<Word>, List)>, redirs: Vec<Redir> },
    FuncDef { name: String, body: Box<Command> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub negate: bool,
    pub cmds: Vec<Command>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connector {
    And,
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AndOr {
    pub first: Pipeline,
    pub rest: Vec<(Connector, Pipeline)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub and_or: AndOr,
    pub background: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct List(pub Vec<Item>);

impl List {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
