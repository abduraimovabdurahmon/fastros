//! The FastROS shell language: parser, expansion, patterns, arithmetic.
//! Execution lives in the kernel (it needs processes, pipes and files);
//! everything here is pure and tested on the host.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod arith;
pub mod ast;
pub mod expand;
pub mod parser;
pub mod pattern;

pub use parser::{parse, ParseError};

/// Quote a string for safe re-use as one shell word.
pub fn quote(s: &str) -> alloc::string::String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "_-./=:@%+,".contains(c)) {
        return alloc::string::String::from(s);
    }
    let mut out = alloc::string::String::from("'");
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::ast::*;
    use super::expand::{expand_fields, expand_string, Env};
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    #[derive(Default)]
    struct TEnv {
        vars: BTreeMap<String, String>,
        args: Vec<String>,
    }

    impl Env for TEnv {
        fn var(&self, n: &str) -> Option<String> {
            self.vars.get(n).cloned()
        }
        fn set_var(&mut self, n: &str, v: &str) -> Result<(), String> {
            self.vars.insert(n.into(), v.into());
            Ok(())
        }
        fn special(&self, n: &str) -> Option<String> {
            match n {
                "?" => Some("0".into()),
                "#" => Some(self.args.len().to_string()),
                "$" => Some("42".into()),
                _ => None,
            }
        }
        fn positional(&self) -> Vec<String> {
            self.args.clone()
        }
        fn command_output(&mut self, src: &str) -> Result<String, String> {
            Ok(alloc::format!("<{src}>\n\n"))
        }
        fn home(&self, u: &str) -> Option<String> {
            (u == "bob").then(|| "/home/bob".into())
        }
        fn list_dir(&mut self, d: &str) -> Option<Vec<String>> {
            (d == ".").then(|| ["a.txt", "b.txt", "c.rs"].iter().map(|s| s.to_string()).collect())
        }
    }

    fn words_of(src: &str) -> Vec<Word> {
        match &parse(src).unwrap().0[0].and_or.first.cmds[0] {
            Command::Simple { words, .. } => words.clone(),
            c => panic!("{c:?}"),
        }
    }

    fn fields(src: &str, env: &mut TEnv) -> Vec<String> {
        expand_fields(&words_of(src), env).unwrap()
    }

    #[test]
    fn simple_commands_and_operators() {
        let l = parse("echo a b; ls -l | grep x && echo ok || echo no &").unwrap();
        assert_eq!(l.0.len(), 2);
        assert!(!l.0[0].background);
        assert!(l.0[1].background);
        let ao = &l.0[1].and_or;
        assert_eq!(ao.first.cmds.len(), 2);
        assert_eq!(ao.rest.len(), 2);
        assert_eq!(ao.rest[0].0, Connector::And);
        assert_eq!(ao.rest[1].0, Connector::Or);
    }

    #[test]
    fn redirections() {
        let l = parse("cmd >out 2>&1 <in >>log 2>/dev/null &>all").unwrap();
        let Command::Simple { redirs, words, .. } = &l.0[0].and_or.first.cmds[0] else { panic!() };
        assert_eq!(words.len(), 1);
        let ops: Vec<(u32, RedirOp)> = redirs.iter().map(|r| (r.fd(), r.op)).collect();
        assert_eq!(ops, vec![(1, RedirOp::Out), (2, RedirOp::DupOut), (0, RedirOp::In), (1, RedirOp::Append), (2, RedirOp::Out), (1, RedirOp::OutErr)]);
    }

    #[test]
    fn heredoc_bodies_are_cut_out() {
        let l = parse("cat <<EOF\nhello $USER\nEOF\necho after\ncat <<'X'\n$not\nX\n").unwrap();
        assert_eq!(l.0.len(), 3);
        let Command::Simple { redirs, .. } = &l.0[0].and_or.first.cmds[0] else { panic!() };
        assert_eq!(redirs[0].heredoc, Some(("hello $USER\n".into(), true)));
        let Command::Simple { redirs, .. } = &l.0[2].and_or.first.cmds[0] else { panic!() };
        assert_eq!(redirs[0].heredoc, Some(("$not\n".into(), false)));
        assert!(parse("cat <<EOF\nno end").unwrap_err().incomplete);
    }

    #[test]
    fn compound_commands() {
        parse("if true; then echo y; elif false; then echo n; else echo z; fi").unwrap();
        parse("for i in 1 2 3; do echo $i; done").unwrap();
        parse("for i\ndo\n echo $i\ndone").unwrap();
        parse("while read l; do echo $l; done < file").unwrap();
        parse("until false; do break; done").unwrap();
        parse("case $x in a|b) echo ab;; *) echo other;; esac").unwrap();
        parse("f() { echo hi; }; f").unwrap();
        parse("function g { echo g; }").unwrap();
        parse("(cd /tmp && ls) | wc -l").unwrap();
        parse("{ echo a; echo b; } > out").unwrap();
        parse("! grep -q x file").unwrap();
    }

    #[test]
    fn incomplete_input_is_flagged() {
        for src in ["echo 'abc", "echo \"abc", "if true; then", "for x in a; do", "echo a |", "echo a &&", "f() {", "$(echo", "case x in"] {
            let e = parse(src).unwrap_err();
            assert!(e.incomplete, "{src}: {e:?}");
        }
        for src in ["fi", "echo a; then", "done", ")", "echo >"] {
            let e = parse(src).unwrap_err();
            assert!(!e.incomplete, "{src}: {e:?}");
        }
    }

    #[test]
    fn quoting_and_splitting() {
        let mut env = TEnv::default();
        env.vars.insert("A".into(), "one two  three".into());
        env.vars.insert("E".into(), "".into());
        assert_eq!(fields("echo $A", &mut env), vec!["echo", "one", "two", "three"]);
        assert_eq!(fields("echo \"$A\"", &mut env), vec!["echo", "one two  three"]);
        assert_eq!(fields("echo '$A' \\$A", &mut env), vec!["echo", "$A", "$A"]);
        assert_eq!(fields("echo $E x", &mut env), vec!["echo", "x"]);
        assert_eq!(fields("echo \"$E\" x", &mut env), vec!["echo", "", "x"]);
        assert_eq!(fields("echo a\"b c\"d", &mut env), vec!["echo", "ab cd"]);
        assert_eq!(fields("echo pre$A", &mut env), vec!["echo", "preone", "two", "three"]);
    }

    #[test]
    fn parameter_operators() {
        let mut env = TEnv::default();
        env.vars.insert("F".into(), "/usr/lib/libc.so.6".into());
        env.vars.insert("N".into(), "hello".into());
        let e = |s: &str, env: &mut TEnv| expand_string(&parser::parse_word(s).unwrap(), env).unwrap();
        assert_eq!(e("${U:-def}", &mut env), "def");
        assert_eq!(e("${N:-def}", &mut env), "hello");
        assert_eq!(e("${N:+alt}", &mut env), "alt");
        assert_eq!(e("${#N}", &mut env), "5");
        assert_eq!(e("${F##*/}", &mut env), "libc.so.6");
        assert_eq!(e("${F%/*}", &mut env), "/usr/lib");
        assert_eq!(e("${F%.*}", &mut env), "/usr/lib/libc.so");
        assert_eq!(e("${F%%.*}", &mut env), "/usr/lib/libc");
        assert_eq!(e("${N/l/L}", &mut env), "heLlo");
        assert_eq!(e("${N//l/L}", &mut env), "heLLo");
        assert_eq!(e("${N:1:3}", &mut env), "ell");
        assert_eq!(e("${N^^}", &mut env), "HELLO");
        assert_eq!(e("${N^}", &mut env), "Hello");
        assert_eq!(e("${X:=set}", &mut env), "set");
        assert_eq!(env.vars.get("X").map(String::as_str), Some("set"));
        assert!(expand_string(&parser::parse_word("${Q:?missing}").unwrap(), &mut env).is_err());
    }

    #[test]
    fn substitutions_tilde_glob_positional() {
        let mut env = TEnv::default();
        env.vars.insert("HOME".into(), "/root".into());
        env.args = vec!["x y".into(), "z".into()];
        assert_eq!(fields("echo $(date) $((1+2*3))", &mut env), vec!["echo", "<date>", "7"]);
        assert_eq!(fields("echo ~ ~bob/x ~nobody", &mut env), vec!["echo", "/root", "/home/bob/x", "~nobody"]);
        assert_eq!(fields("ls *.txt", &mut env), vec!["ls", "a.txt", "b.txt"]);
        assert_eq!(fields("ls '*.txt' *.none", &mut env), vec!["ls", "*.txt", "*.none"]);
        assert_eq!(fields("printf \"$@\"", &mut env), vec!["printf", "x y", "z"]);
        assert_eq!(fields("printf $@", &mut env), vec!["printf", "x", "y", "z"]);
        assert_eq!(fields("echo $# $1", &mut env), vec!["echo", "2", "x", "y"]);
    }

    #[test]
    fn assignments_and_functions() {
        let l = parse("A=1 B=\"two words\" env").unwrap();
        let Command::Simple { assigns, words, .. } = &l.0[0].and_or.first.cmds[0] else { panic!() };
        assert_eq!(assigns.len(), 2);
        assert_eq!(assigns[0].0, "A");
        assert_eq!(words.len(), 1);
        let l = parse("echo A=1").unwrap();
        let Command::Simple { assigns, .. } = &l.0[0].and_or.first.cmds[0] else { panic!() };
        assert!(assigns.is_empty());
    }

    #[test]
    fn quote_roundtrip() {
        assert_eq!(quote("abc"), "abc");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }
}
