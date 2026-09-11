//! `$(( ... ))` arithmetic: 64-bit signed integers with C precedence,
//! assignments, `?:`, and checked division.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub trait Vars {
    fn get(&self, name: &str) -> Option<String>;
    fn set(&mut self, name: &str, value: &str);
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(i64),
    Name(String),
    Op(&'static str),
    LParen,
    RParen,
}

const OPS: &[&str] = &[
    "<<=", ">>=", "**", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "++",
    "--", "+", "-", "*", "/", "%", "<", ">", "&", "|", "^", "!", "~", "?", ":", "=", ",",
];

fn lex(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_digit() {
            let st = i;
            while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '#') {
                i += 1;
            }
            let t: String = c[st..i].iter().collect();
            out.push(Tok::Num(parse_num(&t)?));
        } else if ch == '_' || ch.is_ascii_alphabetic() {
            let st = i;
            while i < c.len() && (c[i] == '_' || c[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            out.push(Tok::Name(c[st..i].iter().collect()));
        } else if ch == '$' {
            // `$x` inside arithmetic is the same as `x`.
            i += 1;
        } else if ch == '(' {
            out.push(Tok::LParen);
            i += 1;
        } else if ch == ')' {
            out.push(Tok::RParen);
            i += 1;
        } else {
            let rest: String = c[i..c.len().min(i + 3)].iter().collect();
            let op = OPS.iter().find(|o| rest.starts_with(**o)).ok_or_else(|| alloc::format!("syntax error: invalid arithmetic operator (error token is \"{}\")", &rest))?;
            out.push(Tok::Op(op));
            i += op.len();
        }
    }
    Ok(out)
}

fn parse_num(t: &str) -> Result<i64, String> {
    let bad = || alloc::format!("value too great for base (error token is \"{t}\")");
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return i64::from_str_radix(h, 16).map_err(|_| bad());
    }
    if let Some((base, digits)) = t.split_once('#') {
        let b: u32 = base.parse().map_err(|_| bad())?;
        if !(2..=36).contains(&b) {
            return Err(bad());
        }
        return i64::from_str_radix(digits, b).map_err(|_| bad());
    }
    if t.len() > 1 && t.starts_with('0') {
        return i64::from_str_radix(&t[1..], 8).map_err(|_| bad());
    }
    t.parse().map_err(|_| bad())
}

struct P<'a, V: Vars> {
    t: Vec<Tok>,
    i: usize,
    vars: &'a mut V,
    /// Evaluate side effects (false in the skipped branch of `&&`, `||`, `?:`).
    live: bool,
}

type R = Result<i64, String>;

fn binding(op: &str) -> Option<(u8, bool)> {
    // (precedence, right-assoc)
    Some(match op {
        "," => (1, false),
        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "<<=" | ">>=" | "&=" | "|=" | "^=" => (2, true),
        "?" => (3, true),
        "||" => (4, false),
        "&&" => (5, false),
        "|" => (6, false),
        "^" => (7, false),
        "&" => (8, false),
        "==" | "!=" => (9, false),
        "<" | ">" | "<=" | ">=" => (10, false),
        "<<" | ">>" => (11, false),
        "+" | "-" => (12, false),
        "*" | "/" | "%" => (13, false),
        "**" => (14, true),
        _ => return None,
    })
}

impl<V: Vars> P<'_, V> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn var(&self, name: &str) -> R {
        match self.vars.get(name) {
            None => Ok(0),
            Some(v) if v.trim().is_empty() => Ok(0),
            Some(v) => parse_num(v.trim()).map_err(|_| alloc::format!("{v}: invalid number")),
        }
    }

    fn assign(&mut self, name: &str, v: i64) {
        if self.live {
            self.vars.set(name, &v.to_string());
        }
    }

    fn primary(&mut self) -> R {
        let tok = self.peek().cloned().ok_or_else(|| String::from("syntax error: operand expected"))?;
        self.i += 1;
        match tok {
            Tok::Num(n) => Ok(n),
            Tok::LParen => {
                let v = self.expr(0)?;
                if self.peek() != Some(&Tok::RParen) {
                    return Err("syntax error: missing `)'".into());
                }
                self.i += 1;
                Ok(v)
            }
            Tok::Name(n) => {
                if let Some(Tok::Op(op @ ("++" | "--"))) = self.peek().cloned() {
                    self.i += 1;
                    let v = self.var(&n)?;
                    self.assign(&n, if op == "++" { v.wrapping_add(1) } else { v.wrapping_sub(1) });
                    return Ok(v);
                }
                self.var(&n)
            }
            Tok::Op("-") => Ok(self.unary()?.wrapping_neg()),
            Tok::Op("+") => self.unary(),
            Tok::Op("!") => Ok((self.unary()? == 0) as i64),
            Tok::Op("~") => Ok(!self.unary()?),
            Tok::Op(op @ ("++" | "--")) => {
                let Some(Tok::Name(n)) = self.peek().cloned() else { return Err("syntax error: variable expected".into()) };
                self.i += 1;
                let v = self.var(&n)?;
                let nv = if op == "++" { v.wrapping_add(1) } else { v.wrapping_sub(1) };
                self.assign(&n, nv);
                Ok(nv)
            }
            Tok::Op(o) => Err(alloc::format!("syntax error: operand expected (error token is \"{o}\")")),
            Tok::RParen => Err("syntax error: operand expected (error token is \")\")".into()),
        }
    }

    fn unary(&mut self) -> R {
        self.primary()
    }

    fn apply(&self, op: &str, a: i64, b: i64) -> R {
        Ok(match op {
            "+" => a.wrapping_add(b),
            "-" => a.wrapping_sub(b),
            "*" => a.wrapping_mul(b),
            "/" | "%" => {
                if b == 0 {
                    return Err("division by 0".into());
                }
                if op == "/" {
                    a.wrapping_div(b)
                } else {
                    a.wrapping_rem(b)
                }
            }
            "**" => {
                if b < 0 {
                    return Err("exponent less than 0".into());
                }
                a.wrapping_pow(b.min(u32::MAX as i64) as u32)
            }
            "<<" => a.wrapping_shl(b as u32),
            ">>" => a.wrapping_shr(b as u32),
            "<" => (a < b) as i64,
            ">" => (a > b) as i64,
            "<=" => (a <= b) as i64,
            ">=" => (a >= b) as i64,
            "==" => (a == b) as i64,
            "!=" => (a != b) as i64,
            "&" => a & b,
            "|" => a | b,
            "^" => a ^ b,
            "," => b,
            _ => return Err(alloc::format!("unknown operator {op}")),
        })
    }

    fn expr(&mut self, min: u8) -> R {
        // Assignment needs the variable name: look ahead for `name op=`.
        if let (Some(Tok::Name(n)), Some(Tok::Op(op))) = (self.t.get(self.i).cloned(), self.t.get(self.i + 1).cloned()) {
            if let Some((prec, _)) = binding(op) {
                if prec == 2 && min <= 2 {
                    self.i += 2;
                    let rhs = self.expr(2)?;
                    let v = if op == "=" { rhs } else { self.apply(&op[..op.len() - 1], self.var(&n)?, rhs)? };
                    self.assign(&n, v);
                    return Ok(v);
                }
            }
        }
        let mut lhs = self.unary()?;
        loop {
            let Some(Tok::Op(op)) = self.peek().cloned() else { break };
            let Some((prec, right)) = binding(op) else { break };
            if prec < min || prec == 2 {
                break;
            }
            self.i += 1;
            if op == "?" {
                let saved = self.live;
                self.live = saved && lhs != 0;
                let a = self.expr(0)?;
                if self.peek() != Some(&Tok::Op(":")) {
                    return Err("syntax error: `:' expected for conditional expression".into());
                }
                self.i += 1;
                self.live = saved && lhs == 0;
                let b = self.expr(3)?;
                self.live = saved;
                lhs = if lhs != 0 { a } else { b };
                continue;
            }
            let next_min = if right { prec } else { prec + 1 };
            if op == "&&" || op == "||" {
                let saved = self.live;
                let short = (op == "&&" && lhs == 0) || (op == "||" && lhs != 0);
                self.live = saved && !short;
                let rhs = self.expr(next_min)?;
                self.live = saved;
                lhs = if op == "&&" { (lhs != 0 && rhs != 0) as i64 } else { (lhs != 0 || rhs != 0) as i64 };
                continue;
            }
            let rhs = self.expr(next_min)?;
            lhs = self.apply(op, lhs, rhs)?;
        }
        Ok(lhs)
    }
}

pub fn eval(src: &str, vars: &mut impl Vars) -> Result<i64, String> {
    let t = lex(src)?;
    if t.is_empty() {
        return Ok(0);
    }
    let mut p = P { t, i: 0, vars, live: true };
    let v = p.expr(0)?;
    if p.i != p.t.len() {
        return Err(alloc::format!("syntax error in expression (error token is \"{src}\")"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;

    struct M(BTreeMap<String, String>);
    impl Vars for M {
        fn get(&self, n: &str) -> Option<String> {
            self.0.get(n).cloned()
        }
        fn set(&mut self, n: &str, v: &str) {
            self.0.insert(n.to_string(), v.to_string());
        }
    }

    fn ev(s: &str) -> Result<i64, String> {
        eval(s, &mut M(BTreeMap::new()))
    }

    #[test]
    fn precedence_and_ops() {
        assert_eq!(ev("1 + 2 * 3"), Ok(7));
        assert_eq!(ev("(1 + 2) * 3"), Ok(9));
        assert_eq!(ev("2 ** 3 ** 2"), Ok(512));
        assert_eq!(ev("-2 * -3"), Ok(6));
        assert_eq!(ev("7 / 2"), Ok(3));
        assert_eq!(ev("-7 % 3"), Ok(-1));
        assert_eq!(ev("1 << 4 | 1"), Ok(17));
        assert_eq!(ev("3 > 2 && 2 > 1"), Ok(1));
        assert_eq!(ev("0 || 0"), Ok(0));
        assert_eq!(ev("!0"), Ok(1));
        assert_eq!(ev("~0"), Ok(-1));
        assert_eq!(ev("1 ? 10 : 20"), Ok(10));
        assert_eq!(ev("0 ? 10 : 0 ? 20 : 30"), Ok(30));
        assert_eq!(ev("0x1f + 010 + 2#101"), Ok(31 + 8 + 5));
        assert_eq!(ev(""), Ok(0));
        assert!(ev("1 / 0").is_err());
        assert!(ev("1 +").is_err());
    }

    #[test]
    fn variables_and_assignment() {
        let mut m = M(BTreeMap::new());
        m.set("x", "5");
        assert_eq!(eval("x * 2", &mut m), Ok(10));
        assert_eq!(eval("y = x + 1", &mut m), Ok(6));
        assert_eq!(m.get("y").as_deref(), Some("6"));
        assert_eq!(eval("y += 4", &mut m), Ok(10));
        assert_eq!(eval("x++", &mut m), Ok(5));
        assert_eq!(m.get("x").as_deref(), Some("6"));
        assert_eq!(eval("++x", &mut m), Ok(7));
        assert_eq!(eval("unset_var + 1", &mut m), Ok(1));
        // Short-circuit: the right side's assignment must not happen.
        assert_eq!(eval("0 && (z = 9)", &mut m), Ok(0));
        assert_eq!(m.get("z"), None);
    }
}
