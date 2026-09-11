//! `fastman compose` — declarative multi-container stacks from a compose file.
//!
//! Parses a Docker-Compose-style YAML subset and brings a whole stack up or
//! down with one command. Containers are named `<project>_<service>` so a
//! stack is a set of containers sharing that prefix.
//!
//! Supported per service: `image`, `command`, `ports`, `volumes`,
//! `environment` (list or map), `working_dir`, `restart`, `container_name`.

use super::container::{Port, Volume};
use super::runtime::RunOpts;
use crate::errno::{Errno, KResult};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

/// A parsed YAML value (the subset compose files use).
#[derive(Debug, Clone)]
pub enum Yaml {
    Scalar(String),
    List(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Scalar(s) => Some(s),
            _ => None,
        }
    }
    /// A value that may be written as a scalar, a `- ` list, or a `k: v` map,
    /// normalised to a list of strings (`environment`, `command`, `ports`...).
    fn as_string_list(&self) -> Vec<String> {
        match self {
            Yaml::Scalar(s) => split_command(s),
            Yaml::List(items) => items.iter().filter_map(|i| i.as_str().map(String::from)).collect(),
            Yaml::Map(m) => m.iter().map(|(k, v)| format_kv(k, v)).collect(),
        }
    }
}

fn format_kv(k: &str, v: &Yaml) -> String {
    match v.as_str() {
        Some(s) => alloc::format!("{k}={s}"),
        None => k.to_string(),
    }
}

/// Split a bare `command:` string into argv (whitespace, honouring simple quotes).
fn split_command(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote = None;
    for c in s.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(core::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\''))) {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// A cleaned line: (indentation columns, content) with comments/blank lines removed.
struct Line {
    indent: usize,
    text: String,
}

fn clean_lines(src: &str) -> Vec<Line> {
    let mut out = Vec::new();
    for raw in src.lines() {
        // Strip trailing comments (only when not inside quotes — keep it simple:
        // a ` #` sequence starts a comment).
        let no_comment = match raw.find(" #") {
            Some(i) => &raw[..i],
            None => raw,
        };
        let no_comment = if no_comment.trim_start().starts_with('#') { "" } else { no_comment };
        if no_comment.trim().is_empty() {
            continue;
        }
        let indent = no_comment.len() - no_comment.trim_start().len();
        out.push(Line { indent, text: no_comment.trim_end().to_string() });
    }
    out
}

/// Parse a block of lines at `>= base_indent` into a Yaml value, advancing `i`.
fn parse_block(lines: &[Line], i: &mut usize, base_indent: usize) -> Yaml {
    // Decide list vs map from the first line at this indent.
    let first = &lines[*i];
    if first.text.trim_start().starts_with("- ") || first.text.trim() == "-" {
        return parse_list(lines, i, base_indent);
    }
    parse_map(lines, i, base_indent)
}

fn parse_map(lines: &[Line], i: &mut usize, base_indent: usize) -> Yaml {
    let mut map = Vec::new();
    while *i < lines.len() {
        let ln = &lines[*i];
        if ln.indent < base_indent {
            break;
        }
        if ln.indent > base_indent {
            // Shouldn't happen at map level; skip defensively.
            *i += 1;
            continue;
        }
        let content = ln.text.trim();
        let Some((key, rest)) = content.split_once(':') else {
            *i += 1;
            continue;
        };
        let key = key.trim().to_string();
        let rest = rest.trim();
        *i += 1;
        if !rest.is_empty() {
            // Inline scalar or inline list `[a, b]`.
            map.push((key, parse_inline(rest)));
        } else if *i < lines.len() && lines[*i].indent > base_indent {
            let child_indent = lines[*i].indent;
            let v = parse_block(lines, i, child_indent);
            map.push((key, v));
        } else {
            map.push((key, Yaml::Scalar(String::new())));
        }
    }
    Yaml::Map(map)
}

fn parse_list(lines: &[Line], i: &mut usize, base_indent: usize) -> Yaml {
    let mut list = Vec::new();
    while *i < lines.len() {
        let ln = &lines[*i];
        if ln.indent != base_indent || !(ln.text.trim_start().starts_with("- ") || ln.text.trim() == "-") {
            break;
        }
        // Column where the item's content begins (after the dash and spaces).
        let after = &ln.text[ln.indent..]; // starts with '-'
        let rest = &after[1..];
        let content = rest.trim_start();
        let content_col = ln.indent + 1 + (rest.len() - content.len());

        // Gather this item's lines: the (optional) inline content at
        // `content_col`, plus every following deeper line — so a `- key: val`
        // item followed by more keys forms one map.
        let mut item_lines: Vec<Line> = Vec::new();
        if !content.is_empty() {
            item_lines.push(Line { indent: content_col, text: alloc::format!("{}{}", " ".repeat(content_col), content) });
        }
        *i += 1;
        while *i < lines.len() && lines[*i].indent > base_indent {
            let l = &lines[*i];
            item_lines.push(Line { indent: l.indent, text: l.text.clone() });
            *i += 1;
        }

        if item_lines.is_empty() {
            list.push(Yaml::Scalar(String::new()));
            continue;
        }
        // A single scalar item (no ':' mapping) stays a scalar.
        if item_lines.len() == 1 && !is_mapping_line(&item_lines[0].text) {
            list.push(parse_inline(item_lines[0].text.trim()));
            continue;
        }
        let mut j = 0;
        list.push(parse_block(&item_lines, &mut j, content_col));
    }
    Yaml::List(list)
}

/// Does a line look like a `key: value` mapping (vs a bare scalar/inline list)?
fn is_mapping_line(text: &str) -> bool {
    let t = text.trim();
    if t.starts_with('[') || t.starts_with('"') || t.starts_with('\'') {
        return false;
    }
    match t.split_once(':') {
        // "a: b" or "a:" is a mapping; "http://x" (colon then no space) is not.
        Some((_, rest)) => rest.is_empty() || rest.starts_with(' '),
        None => false,
    }
}

fn parse_inline(s: &str) -> Yaml {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let items = inner.split(',').map(|p| Yaml::Scalar(unquote(p))).filter(|y| y.as_str().map(|z| !z.is_empty()).unwrap_or(false)).collect();
        return Yaml::List(items);
    }
    Yaml::Scalar(unquote(s))
}

pub fn parse_yaml(src: &str) -> Yaml {
    let lines = clean_lines(src);
    if lines.is_empty() {
        return Yaml::Map(Vec::new());
    }
    let mut i = 0;
    parse_map(&lines, &mut i, 0)
}

// ── compose model ────────────────────────────────────────────────────────────

pub struct Service {
    pub name: String,
    pub image: String,
    pub opts: RunOpts,
}

pub struct Compose {
    pub project: String,
    pub services: Vec<Service>,
}

fn parse_port(s: &str) -> Option<Port> {
    let (spec, udp) = match s.strip_suffix("/udp") {
        Some(r) => (r, true),
        None => (s.strip_suffix("/tcp").unwrap_or(s), false),
    };
    let (h, c) = spec.split_once(':')?;
    Some(Port { host: h.trim().parse().ok()?, container: c.trim().parse().ok()?, udp })
}

fn parse_volume(s: &str) -> Option<Volume> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.as_slice() {
        [h, c] => Some(Volume { host: h.to_string(), container: c.to_string(), read_only: false }),
        [h, c, "ro"] => Some(Volume { host: h.to_string(), container: c.to_string(), read_only: true }),
        [h, c, _] => Some(Volume { host: h.to_string(), container: c.to_string(), read_only: false }),
        _ => None,
    }
}

/// Parse a compose document into a project.
pub fn parse(project: &str, src: &str) -> KResult<Compose> {
    let doc = parse_yaml(src);
    let services_node = doc.get("services").ok_or(Errno::EINVAL)?;
    let Yaml::Map(services) = services_node else {
        return Err(Errno::EINVAL);
    };
    let mut out = Vec::new();
    for (name, spec) in services {
        let image = spec.get("image").and_then(|v| v.as_str()).ok_or(Errno::EINVAL)?.to_string();
        let mut opts = RunOpts { network: String::from("bridge"), detach: true, ..Default::default() };
        opts.name = Some(spec.get("container_name").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| alloc::format!("{project}_{name}")));
        if let Some(c) = spec.get("command") {
            opts.cmd = c.as_string_list();
        }
        if let Some(e) = spec.get("environment") {
            opts.env = e.as_string_list();
        }
        if let Some(p) = spec.get("ports") {
            opts.ports = p.as_string_list().iter().filter_map(|s| parse_port(s)).collect();
        }
        if let Some(v) = spec.get("volumes") {
            opts.volumes = v.as_string_list().iter().filter_map(|s| parse_volume(s)).collect();
        }
        if let Some(w) = spec.get("working_dir").and_then(|v| v.as_str()) {
            opts.workdir = Some(w.to_string());
        }
        out.push(Service { name: name.clone(), image, opts });
    }
    Ok(Compose { project: project.to_string(), services: out })
}
