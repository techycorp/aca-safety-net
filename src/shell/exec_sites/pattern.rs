//! Name matching helpers: brace expansion, globs, and name-in-text search.

use once_cell::sync::Lazy;
use regex::Regex;

/// Upper bound on brace-expansion results for a single word.
const MAX_EXPANSIONS: usize = 256;

/// Whether `name` occurs in `text` as a word.
///
/// Case-insensitive. A preceding `.` disqualifies the match so file names
/// like `.env` or `.mise.toml` don't count as the tool.
pub fn contains_name(text: &str, name: &str) -> bool {
    let hay = text.to_lowercase();
    let bytes = hay.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut from = 0;
    while let Some(off) = hay[from..].find(name) {
        let start = from + off;
        let end = start + name.len();
        let before_ok = start == 0 || {
            let b = bytes[start - 1];
            !is_word(b) && b != b'.'
        };
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
        while !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// Expand `{a,b}` and `{x..y}` brace expressions. Unparseable braces stay literal.
pub fn expand_braces(word: &str) -> Vec<String> {
    let mut out = Vec::new();
    expand_into(word, &mut out);
    if out.is_empty() {
        out.push(word.to_string());
    }
    out
}

fn expand_into(word: &str, out: &mut Vec<String>) {
    if out.len() >= MAX_EXPANSIONS {
        return;
    }
    let Some((open, close, alts)) = find_brace(word) else {
        out.push(word.to_string());
        return;
    };
    let prefix = &word[..open];
    let suffix = &word[close + 1..];
    for alt in alts {
        expand_into(&format!("{prefix}{alt}{suffix}"), out);
        if out.len() >= MAX_EXPANSIONS {
            return;
        }
    }
}

/// Find the first expandable brace group: (open index, close index, alternatives).
fn find_brace(word: &str) -> Option<(usize, usize, Vec<String>)> {
    let chars: Vec<(usize, char)> = word.char_indices().collect();
    for (i, &(open, c)) in chars.iter().enumerate() {
        if c != '{' {
            continue;
        }
        let mut depth = 0;
        let mut commas = Vec::new();
        let mut close = None;
        for &(j, d) in &chars[i..] {
            match d {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(j);
                        break;
                    }
                }
                ',' if depth == 1 => commas.push(j),
                _ => {}
            }
        }
        let Some(close) = close else {
            continue;
        };
        let body = &word[open + 1..close];
        if !commas.is_empty() {
            let mut alts = Vec::new();
            let mut start = open + 1;
            for comma in commas {
                alts.push(word[start..comma].to_string());
                start = comma + 1;
            }
            alts.push(word[start..close].to_string());
            return Some((open, close, alts));
        }
        if let Some(alts) = sequence(body) {
            return Some((open, close, alts));
        }
    }
    None
}

fn sequence(body: &str) -> Option<Vec<String>> {
    let mut parts = body.splitn(3, "..");
    let a = parts.next()?;
    let b = parts.next()?;
    let mut ac = a.chars();
    let mut bc = b.chars();
    if let (Some(x), None, Some(y), None) = (ac.next(), ac.next(), bc.next(), bc.next())
        && !x.is_ascii_digit()
        && !y.is_ascii_digit()
    {
        let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
        return Some(
            (lo..=hi)
                .take(MAX_EXPANSIONS)
                .map(|c| c.to_string())
                .collect(),
        );
    }
    let x: i64 = a.parse().ok()?;
    let y: i64 = b.parse().ok()?;
    let (lo, hi) = if x <= y { (x, y) } else { (y, x) };
    Some(
        (lo..=hi)
            .take(MAX_EXPANSIONS)
            .map(|n| n.to_string())
            .collect(),
    )
}

/// Whether the shell glob `pattern` could match `name`. Supports `*`, `?`, `[...]`.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    glob_at(&p, &n)
}

fn glob_at(p: &[char], n: &[char]) -> bool {
    match p.first() {
        None => n.is_empty(),
        Some('*') => (0..=n.len()).any(|i| glob_at(&p[1..], &n[i..])),
        Some('?') => !n.is_empty() && glob_at(&p[1..], &n[1..]),
        Some('[') => match class_end(p) {
            Some(end) => {
                !n.is_empty() && class_matches(&p[1..end], n[0]) && glob_at(&p[end + 1..], &n[1..])
            }
            None => n.first() == Some(&'[') && glob_at(&p[1..], &n[1..]),
        },
        Some(c) => n.first() == Some(c) && glob_at(&p[1..], &n[1..]),
    }
}

fn class_end(p: &[char]) -> Option<usize> {
    let mut i = 1;
    if matches!(p.get(i), Some('!' | '^')) {
        i += 1;
    }
    if p.get(i) == Some(&']') {
        i += 1;
    }
    while i < p.len() {
        if p[i] == ']' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn class_matches(class: &[char], c: char) -> bool {
    let (negate, class) = match class.first() {
        Some('!' | '^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut hit = false;
    let mut i = 0;
    while i < class.len() {
        if i + 2 < class.len() && class[i + 1] == '-' {
            if class[i] <= c && c <= class[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if class[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    hit != negate
}

/// Code in an interpreter string that can start another process.
static EXEC_PRIMITIVE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)\b(system|exec[a-z_]*|popen[0-9]*|spawn[a-z_]*|subprocess|child_process|check_output|check_call|getoutput|getstatusoutput|run|call|qx|shell_exec|passthru|proc_open|execute|do\s+shell\s+script|runtime|processbuilder|command|open[0-9]*|pty|eval)\b|`|%x|\|\s*getline|\|&|print[^;\n]*\|",
    )
    .unwrap()
});

/// A sed `e` command or an `s///e` flag.
static SED_EXEC_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)((^|[;{}])\s*([0-9]+|\$|/[^/]*/)?\s*e(\s|;|$)|[/|#,:@!][gpiImM0-9]*e[gpiImMw0-9]*\s*($|[;}]))",
    )
    .unwrap()
});

/// How an interpreter code string is checked for process execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpKind {
    General,
    Sed,
}

pub fn has_exec_primitive(code: &str, kind: InterpKind) -> bool {
    match kind {
        InterpKind::General => EXEC_PRIMITIVE_RE.is_match(code),
        InterpKind::Sed => SED_EXEC_RE.is_match(code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_name_word() {
        assert!(contains_name("echo foo; mise env", "mise"));
        assert!(contains_name("@Infisical/cli", "infisical"));
        assert!(contains_name("${x:-mise}", "mise"));
    }

    #[test]
    fn test_contains_name_rejects_substrings_and_dotfiles() {
        assert!(!contains_name("promise", "mise"));
        assert!(!contains_name("cat .env", "env"));
        assert!(!contains_name("cat .mise.toml", "mise"));
        assert!(!contains_name("$MY_ENV_VAR", "env"));
    }

    #[test]
    fn test_brace_alternatives() {
        assert_eq!(expand_braces("{mise,x}"), vec!["mise", "x"]);
        assert_eq!(expand_braces("mi{s,z}e"), vec!["mise", "mize"]);
    }

    #[test]
    fn test_brace_nested_and_sequence() {
        assert!(expand_braces("{a,{mise,b}}").contains(&"mise".to_string()));
        assert!(expand_braces("mi{r..t}e").contains(&"mise".to_string()));
    }

    #[test]
    fn test_brace_literal() {
        assert_eq!(expand_braces("{}"), vec!["{}"]);
        assert_eq!(expand_braces("a{b"), vec!["a{b"]);
    }

    #[test]
    fn test_glob() {
        assert!(glob_match("mis?", "mise"));
        assert!(glob_match("*", "mise"));
        assert!(glob_match("m[a-z]se", "mise"));
        assert!(glob_match("m[!x]se", "mise"));
        assert!(!glob_match("m[!i]se", "mise"));
        assert!(!glob_match("mis", "mise"));
    }

    #[test]
    fn test_exec_primitives() {
        assert!(has_exec_primitive(
            "import os;os.system('x')",
            InterpKind::General
        ));
        assert!(has_exec_primitive("\"x\" | getline", InterpKind::General));
        assert!(!has_exec_primitive(
            "/mise/ { print $1 }",
            InterpKind::General
        ));
        assert!(has_exec_primitive("s/a/mise/e", InterpKind::Sed));
        assert!(has_exec_primitive("1e mise", InterpKind::Sed));
        assert!(!has_exec_primitive("s/mise/x/g", InterpKind::Sed));
    }
}
