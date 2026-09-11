//! Shell pattern matching (`fnmatch`): `*`, `?`, `[...]` with ranges,
//! negation (`!` or `^`) and character classes; `\` escapes.

use alloc::string::String;
use alloc::vec::Vec;

/// Does `pat` match all of `s`?
pub fn matches(pat: &str, s: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = s.chars().collect();
    match_at(&p, 0, &t, 0)
}

fn match_at(p: &[char], mut pi: usize, t: &[char], mut ti: usize) -> bool {
    // Iterative with backtracking on the last `*` (linear for typical patterns).
    let mut star: Option<(usize, usize)> = None;
    loop {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    while pi < p.len() && p[pi] == '*' {
                        pi += 1;
                    }
                    if pi == p.len() {
                        return true;
                    }
                    star = Some((pi, ti));
                    continue;
                }
                '?' if ti < t.len() => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                '[' if ti < t.len() => {
                    if let Some((ok, next)) = bracket(p, pi, t[ti]) {
                        if ok {
                            pi = next;
                            ti += 1;
                            continue;
                        }
                    } else if t[ti] == '[' {
                        pi += 1;
                        ti += 1;
                        continue;
                    }
                }
                '\\' if pi + 1 < p.len() && ti < t.len() && p[pi + 1] == t[ti] => {
                    pi += 2;
                    ti += 1;
                    continue;
                }
                c if c != '*' && c != '?' && c != '[' && c != '\\' && ti < t.len() && c == t[ti] => {
                    pi += 1;
                    ti += 1;
                    continue;
                }
                _ => {}
            }
        } else if ti == t.len() {
            return true;
        }
        match star {
            Some((sp, st)) if st < t.len() => {
                pi = sp;
                ti = st + 1;
                star = Some((sp, st + 1));
            }
            _ => return false,
        }
    }
}

/// Match one char against the bracket expression at `p[pi]`.
/// Returns (matched, index after the expression), or None if unterminated.
fn bracket(p: &[char], pi: usize, c: char) -> Option<(bool, usize)> {
    let mut i = pi + 1;
    let negate = matches!(p.get(i), Some('!') | Some('^'));
    if negate {
        i += 1;
    }
    let mut hit = false;
    let mut first = true;
    loop {
        let ch = *p.get(i)?;
        if ch == ']' && !first {
            return Some((hit != negate, i + 1));
        }
        first = false;
        if ch == '[' && p.get(i + 1) == Some(&':') {
            let end = (i + 2..p.len().saturating_sub(1)).find(|&j| p[j] == ':' && p[j + 1] == ']')?;
            let class: String = p[i + 2..end].iter().collect();
            if class_match(&class, c) {
                hit = true;
            }
            i = end + 2;
            continue;
        }
        let lo = if ch == '\\' {
            i += 1;
            *p.get(i)?
        } else {
            ch
        };
        if p.get(i + 1) == Some(&'-') && p.get(i + 2).is_some_and(|&x| x != ']') {
            let hi = p[i + 2];
            if lo <= c && c <= hi {
                hit = true;
            }
            i += 3;
        } else {
            if c == lo {
                hit = true;
            }
            i += 1;
        }
    }
}

fn class_match(class: &str, c: char) -> bool {
    match class {
        "alpha" => c.is_alphabetic(),
        "digit" => c.is_ascii_digit(),
        "alnum" => c.is_alphanumeric(),
        "upper" => c.is_uppercase(),
        "lower" => c.is_lowercase(),
        "space" => c.is_whitespace(),
        "blank" => c == ' ' || c == '\t',
        "punct" => c.is_ascii_punctuation(),
        "xdigit" => c.is_ascii_hexdigit(),
        "cntrl" => c.is_control(),
        "print" => !c.is_control(),
        "graph" => !c.is_control() && c != ' ',
        _ => false,
    }
}

/// Does the (unescaped) text contain glob metacharacters?
pub fn has_magic(pat: &str) -> bool {
    let mut esc = false;
    for c in pat.chars() {
        if esc {
            esc = false;
            continue;
        }
        match c {
            '\\' => esc = true,
            '*' | '?' | '[' => return true,
            _ => {}
        }
    }
    false
}

/// Remove pattern escapes (`\*` → `*`).
pub fn unescape(pat: &str) -> String {
    let mut out = String::with_capacity(pat.len());
    let mut esc = false;
    for c in pat.chars() {
        if esc {
            out.push(c);
            esc = false;
        } else if c == '\\' {
            esc = true;
        } else {
            out.push(c);
        }
    }
    if esc {
        out.push('\\');
    }
    out
}

/// Pathname expansion: `list_dir(dir)` returns the entry names of a
/// directory (without `.`/`..`), or None if it cannot be read. Results are
/// sorted; hidden files only match patterns that start with `.`.
pub fn glob(pattern: &str, list_dir: &mut dyn FnMut(&str) -> Option<Vec<String>>) -> Vec<String> {
    let absolute = pattern.starts_with('/');
    let comps: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let mut paths = alloc::vec![if absolute { String::from("/") } else { String::new() }];
    for comp in &comps {
        let mut next = Vec::new();
        for base in &paths {
            let join = |name: &str| {
                if base.is_empty() {
                    String::from(name)
                } else if base.ends_with('/') {
                    alloc::format!("{base}{name}")
                } else {
                    alloc::format!("{base}/{name}")
                }
            };
            if !has_magic(comp) {
                let lit = unescape(comp);
                let cand = join(&lit);
                // Intermediate literal components must be directories; the
                // final one is kept only if it exists.
                let dir = if base.is_empty() { "." } else { base.as_str() };
                if let Some(entries) = list_dir(dir) {
                    if entries.iter().any(|e| *e == lit) || lit == "." || lit == ".." {
                        next.push(cand);
                    }
                }
                continue;
            }
            let dir = if base.is_empty() { "." } else { base.as_str() };
            let Some(mut entries) = list_dir(dir) else { continue };
            entries.sort();
            for e in entries {
                if e.starts_with('.') && !comp.starts_with('.') {
                    continue;
                }
                if matches(comp, &e) {
                    next.push(join(&e));
                }
            }
        }
        paths = next;
        if paths.is_empty() {
            break;
        }
    }
    if pattern.ends_with('/') {
        paths = paths.into_iter().map(|p| p + "/").collect();
    }
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_patterns() {
        assert!(matches("*.rs", "main.rs"));
        assert!(!matches("*.rs", "main.rc"));
        assert!(matches("a?c", "abc"));
        assert!(!matches("a?c", "ac"));
        assert!(matches("[a-c]x", "bx"));
        assert!(!matches("[!a-c]x", "bx"));
        assert!(matches("[^a-c]x", "dx"));
        assert!(matches("[[:digit:]]*", "7up"));
        assert!(matches("\\*", "*"));
        assert!(!matches("\\*", "a"));
        assert!(matches("*a*b*c*", "xxaxxbxxcxx"));
        assert!(!matches("*a*b*c*", "xxaxxcxxbxx"));
        assert!(matches("", ""));
        assert!(matches("*", ""));
        assert!(matches("[]]", "]"));
        assert!(matches("[", "["));
    }

    #[test]
    fn globbing_walks_directories() {
        let mut fs = |d: &str| -> Option<Vec<String>> {
            match d {
                "." => Some(["src", "Cargo.toml", ".git", "README.md"].iter().map(|s| s.to_string()).collect()),
                "src" => Some(["main.rs", "lib.rs", "x.txt"].iter().map(|s| s.to_string()).collect()),
                _ => None,
            }
        };
        assert_eq!(glob("*.md", &mut fs), vec!["README.md"]);
        assert_eq!(glob("src/*.rs", &mut fs), vec!["src/lib.rs", "src/main.rs"]);
        assert_eq!(glob("*", &mut fs), vec!["Cargo.toml", "README.md", "src"]);
        assert_eq!(glob(".*", &mut fs), vec![".git"]);
        assert!(glob("nomatch*", &mut fs).is_empty());
    }
}
