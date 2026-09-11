//! Command history: in-memory list persisted to `~/.fsh_history`, with
//! bash-style `!!`, `!n`, `!-n` and `!prefix` expansion.

use crate::proc::Process;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const MAX: usize = 1000;

#[derive(Clone, Default)]
pub struct History {
    entries: Vec<String>,
    /// Number of the first entry (entries scroll off the front).
    base: usize,
    file: Option<String>,
    saved: usize,
}

impl History {
    pub fn new() -> History {
        History { entries: Vec::new(), base: 1, file: None, saved: 0 }
    }

    pub fn load(&mut self, p: &Process, path: &str) {
        self.file = Some(path.to_string());
        let ctx = crate::fs::ops::Ctx::of(p);
        if let Ok(data) = crate::fs::ops::read_file(&ctx, path) {
            for l in String::from_utf8_lossy(&data).lines() {
                if !l.is_empty() {
                    self.entries.push(l.to_string());
                }
            }
            self.trim();
        }
        self.saved = self.entries.len();
    }

    fn trim(&mut self) {
        if self.entries.len() > MAX {
            let drop = self.entries.len() - MAX;
            self.entries.drain(..drop);
            self.base += drop;
            self.saved = self.saved.saturating_sub(drop);
        }
    }

    pub fn push(&mut self, line: &str) {
        let line = line.trim_end_matches('\n');
        if line.trim().is_empty() || line.starts_with(' ') {
            return; // leading space: not recorded (HISTCONTROL=ignorespace)
        }
        if self.entries.last().is_some_and(|l| l == line) {
            return; // ignoredups
        }
        self.entries.push(line.to_string());
        self.trim();
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.saved = 0;
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, i: usize) -> Option<&str> {
        self.entries.get(i).map(|s| s.as_str())
    }

    /// Rewrite the history file (owner-only permissions).
    pub fn save(&mut self, p: &Process) -> crate::errno::KResult<()> {
        let Some(path) = self.file.clone() else { return Ok(()) };
        if self.saved == self.entries.len() {
            return Ok(());
        }
        let mut text = self.entries.join("\n");
        text.push('\n');
        let ctx = crate::fs::ops::Ctx::of(p);
        crate::fs::ops::write_file(&ctx, &path, text.as_bytes(), 0o600)?;
        self.saved = self.entries.len();
        Ok(())
    }

    /// Output of the `history` builtin.
    pub fn render(&self, last: Option<usize>) -> String {
        let start = last.map(|n| self.entries.len().saturating_sub(n)).unwrap_or(0);
        let mut s = String::new();
        for (i, e) in self.entries.iter().enumerate().skip(start) {
            s.push_str(&alloc::format!("{:>5}  {}\n", self.base + i, e));
        }
        s
    }

    /// Expand history references. `Ok(None)` if the line has none.
    pub fn expand_bang(&self, line: &str) -> Result<Option<String>, String> {
        if !line.contains('!') {
            return Ok(None);
        }
        let chars: Vec<char> = line.chars().collect();
        let mut out = String::new();
        let mut i = 0;
        let mut changed = false;
        let mut in_single = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '\'' {
                in_single = !in_single;
            }
            if c != '!' || in_single || i + 1 >= chars.len() || matches!(chars[i + 1], ' ' | '\t' | '=' | '(' | '"') {
                out.push(c);
                i += 1;
                continue;
            }
            let rest: String = chars[i + 1..].iter().collect();
            let (entry, used) = if rest.starts_with('!') {
                (self.entries.last().cloned(), 1)
            } else if let Some(num) = rest.strip_prefix('-') {
                let digits: String = num.chars().take_while(|c| c.is_ascii_digit()).collect();
                let n: usize = digits.parse().map_err(|_| String::from("!-: event not found"))?;
                (self.entries.len().checked_sub(n).and_then(|k| self.entries.get(k).cloned()), 1 + digits.len())
            } else if rest.starts_with(|c: char| c.is_ascii_digit()) {
                let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                let n: usize = digits.parse().unwrap_or(0);
                (n.checked_sub(self.base).and_then(|k| self.entries.get(k).cloned()), digits.len())
            } else {
                let word: String = rest.chars().take_while(|c| !c.is_whitespace() && *c != ';' && *c != '|').collect();
                (self.entries.iter().rev().find(|e| e.starts_with(&word)).cloned(), word.len())
            };
            match entry {
                Some(e) => {
                    out.push_str(&e);
                    changed = true;
                    i += 1 + used;
                }
                None => {
                    let ev: String = chars[i..(i + 1 + used).min(chars.len())].iter().collect();
                    return Err(alloc::format!("{ev}: event not found"));
                }
            }
        }
        Ok(changed.then_some(out))
    }
}
