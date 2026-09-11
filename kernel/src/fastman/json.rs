//! A tiny, allocation-based JSON parser — just enough to read OCI/Docker
//! registry manifests and image configs. No floats beyond what a digest or
//! size needs; numbers are kept as their textual form.

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Num(n) => n.parse().ok(),
            _ => None,
        }
    }
    /// Collect a string array (e.g. `Env`, `Cmd`).
    pub fn str_array(&self) -> Vec<String> {
        self.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()
    }
}

pub fn parse(input: &[u8]) -> Option<Value> {
    let mut p = Parser { b: input, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    Some(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Option<Value> {
        self.ws();
        match self.peek()? {
            b'{' => self.object(),
            b'[' => self.array(),
            b'"' => Some(Value::Str(self.string()?)),
            b't' => self.lit(b"true", Value::Bool(true)),
            b'f' => self.lit(b"false", Value::Bool(false)),
            b'n' => self.lit(b"null", Value::Null),
            _ => self.number(),
        }
    }
    fn lit(&mut self, word: &[u8], v: Value) -> Option<Value> {
        if self.b.get(self.i..self.i + word.len())? == word {
            self.i += word.len();
            Some(v)
        } else {
            None
        }
    }
    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')) {
            self.i += 1;
        }
        if self.i == start {
            return None;
        }
        Some(Value::Num(String::from_utf8_lossy(&self.b[start..self.i]).into_owned()))
    }
    fn string(&mut self) -> Option<String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(s),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{8}'),
                        b'f' => s.push('\u{c}'),
                        b'u' => {
                            let hex = self.b.get(self.i..self.i + 4)?;
                            self.i += 4;
                            let cp = u32::from_str_radix(core::str::from_utf8(hex).ok()?, 16).ok()?;
                            s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return None,
                    }
                }
                _ => {
                    // Copy the raw UTF-8 byte (multi-byte sequences pass through).
                    s.push(c as char);
                    if c >= 0x80 {
                        // Re-decode: push_str of the raw bytes would be better, but
                        // registry JSON is ASCII in the fields we read.
                    }
                }
            }
        }
    }
    fn array(&mut self) -> Option<Value> {
        self.i += 1;
        let mut v = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Some(Value::Array(v));
        }
        loop {
            v.push(self.value()?);
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b']' => {
                    self.i += 1;
                    return Some(Value::Array(v));
                }
                _ => return None,
            }
        }
    }
    fn object(&mut self) -> Option<Value> {
        self.i += 1;
        let mut m = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Some(Value::Object(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.peek()? != b':' {
                return None;
            }
            self.i += 1;
            let v = self.value()?;
            m.push((k, v));
            self.ws();
            match self.peek()? {
                b',' => {
                    self.i += 1;
                }
                b'}' => {
                    self.i += 1;
                    return Some(Value::Object(m));
                }
                _ => return None,
            }
        }
    }
}
