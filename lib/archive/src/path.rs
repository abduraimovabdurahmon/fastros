//! Member-name safety for extraction.
//!
//! Archive member names are attacker-controlled. By default an extractor
//! must never write outside its destination: absolute names are made
//! relative (as GNU tar and Info-ZIP do) and any `..` component is refused
//! outright (stricter than both, which only strip or warn in some modes).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// A `..` component could climb out of the destination.
    ParentReference,
    /// NUL bytes or an empty name.
    Invalid,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PathError::ParentReference => "member name contains '..'",
            PathError::Invalid => "invalid member name",
        })
    }
}

/// A normalized relative member name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SafePath {
    /// Components joined by `/`: no leading `/`, no `.`/`..`, no empty
    /// components; empty for the destination itself (`./`).
    pub path: String,
    /// Leading `/` characters were removed.
    pub stripped_root: bool,
    /// The name ended with `/` (a directory in tar/zip).
    pub trailing_slash: bool,
}

/// Normalize `name` for extraction under a destination directory.
pub fn sanitize(name: &str) -> Result<SafePath, PathError> {
    if name.is_empty() || name.contains('\0') {
        return Err(PathError::Invalid);
    }
    let stripped_root = name.starts_with('/');
    let trailing_slash = name.ends_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for c in name.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(PathError::ParentReference),
            c => parts.push(c),
        }
    }
    Ok(SafePath { path: parts.join("/"), stripped_root, trailing_slash })
}

/// Drop the first `n` components (tar `--strip-components`); `None` when
/// nothing is left.
pub fn strip_components(name: &str, n: usize) -> Option<String> {
    if n == 0 {
        return Some(String::from(name));
    }
    // Like GNU tar, a leading `/` is not a component and never survives.
    let parts: Vec<&str> = name.split('/').filter(|c| !c.is_empty()).collect();
    if parts.len() <= n {
        return None;
    }
    let mut s = parts[n..].join("/");
    if name.ends_with('/') {
        s.push('/');
    }
    Some(s)
}

/// Does `path` lie at or under `prefix` (component-wise)?
pub fn is_under(path: &str, prefix: &str) -> bool {
    let p = path.trim_end_matches('/');
    let q = prefix.trim_end_matches('/');
    q.is_empty() || p == q || (p.starts_with(q) && p.as_bytes().get(q.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_refuses() {
        let s = sanitize("./a//b/./c").unwrap();
        assert_eq!(s.path, "a/b/c");
        assert!(!s.stripped_root);
        let s = sanitize("/etc/passwd").unwrap();
        assert_eq!(s.path, "etc/passwd");
        assert!(s.stripped_root);
        assert_eq!(sanitize("dir/").unwrap(), SafePath { path: "dir".into(), stripped_root: false, trailing_slash: true });
        assert_eq!(sanitize("./").unwrap().path, "");
        for bad in ["..", "../x", "a/../../x", "a/..", "/../etc", "a/b/../c"] {
            assert_eq!(sanitize(bad), Err(PathError::ParentReference), "{bad}");
        }
        assert_eq!(sanitize(""), Err(PathError::Invalid));
        assert_eq!(sanitize("a\0b"), Err(PathError::Invalid));
        // Names that merely contain dots are fine.
        assert_eq!(sanitize("a/..b/c..").unwrap().path, "a/..b/c..");
    }

    #[test]
    fn strip() {
        assert_eq!(strip_components("a/b/c", 1).as_deref(), Some("b/c"));
        assert_eq!(strip_components("a/b/", 1).as_deref(), Some("b/"));
        assert_eq!(strip_components("a/", 1), None);
        assert_eq!(strip_components("/a/b", 1).as_deref(), Some("b"));
        assert_eq!(strip_components("a", 0).as_deref(), Some("a"));
    }

    #[test]
    fn under() {
        assert!(is_under("a/b", "a"));
        assert!(is_under("a", "a/"));
        assert!(!is_under("ab", "a"));
        assert!(is_under("x", ""));
    }
}
