//! Find the places where a shell command would execute a given tool.
//!
//! [`ExecSites::parse`] walks the command once, recursing into substitutions,
//! `bash -c` strings, wrappers (`sudo`, `xargs`, `find -exec`, ...) and
//! executed option values. [`ExecSites::invocations`] then reports every
//! site where one of the given tool names would run. A name that only
//! appears as data (`grep mise`, `cat src/rules/env.rs`) is not a site.
//!
//! Parsing fails closed: text that can't be parsed is searched for the name
//! anywhere.

mod commands;
mod parser;
mod pattern;

use pattern::{InterpKind, contains_name, expand_braces, glob_match, has_exec_primitive};

/// Commands whose arguments are data. The adjacency heuristic skips them.
const DATA_COMMANDS: &[&str] = &[
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "ls", "cat", "head", "tail",
    "wc",
];

/// A quote-removed shell word.
#[derive(Debug, Clone, Default)]
struct Word {
    /// Text after quote removal. Parameter expansions and substitutions are kept verbatim.
    text: String,
    /// Contains a parameter expansion or substitution.
    dynamic: bool,
    /// Contains an unquoted glob character.
    glob: bool,
    /// Contains an unquoted brace group.
    brace: bool,
    /// Contains any quoting or escaping.
    quoted: bool,
    /// Sources of the `$(...)`, backtick and `<(...)` substitutions in the word.
    subs: Vec<String>,
    /// Byte offset in `text` where the value of a `NAME=value` assignment starts.
    assign: Option<usize>,
}

impl Word {
    fn literal(&self) -> bool {
        !self.dynamic && !self.glob && !self.brace
    }

    fn assign_value(&self) -> Option<&str> {
        self.assign.map(|i| &self.text[i..])
    }
}

#[derive(Debug, Clone)]
enum Site {
    /// A simple command. `argv[0]` is in command position.
    Command { argv: Vec<Word>, adjacency: bool },
    /// A word that runs as a program if it names the tool (wrapper operands).
    Exact(Word),
    /// Text that runs the tool if the name appears in it (package specs, opaque code).
    Anywhere(String),
    /// Interpreter code that runs the tool if it names it and can start a process.
    Interp(String, InterpKind),
}

/// One place where a tool would run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Which of the requested names matched.
    pub name: String,
    /// The word after the tool, for choosing a block reason.
    pub captured: Option<String>,
    /// The subcommand, only when it is plainly written and certain. Used for allowlists.
    pub clean: Option<String>,
    /// The words after the tool when it is a plain command word; `None` for
    /// other sites. A word is `None` when it isn't literal (`$x`, globs).
    pub args: Option<Vec<Option<String>>>,
}

/// The execution sites of one shell command.
#[derive(Debug, Clone)]
pub struct ExecSites {
    sites: Vec<Site>,
}

impl ExecSites {
    /// Parse a command. Runs once with `#` comments and once treating `#` as
    /// text, so a misjudged comment can't hide a command.
    pub fn parse(raw: &str) -> Self {
        let mut sites = Vec::new();
        parser::parse_script_into(raw, 0, true, &mut sites);
        parser::parse_script_into(raw, 0, false, &mut sites);
        ExecSites { sites }
    }

    /// Every site where one of `names` would run. `subcommands` are the
    /// tool's known subcommands, used to spot `<unknown-cmd> ... tool sub`.
    pub fn invocations(&self, names: &[&str], subcommands: &[&str]) -> Vec<Invocation> {
        let mut out = Vec::new();
        for site in &self.sites {
            for &name in names {
                match_site(site, name, subcommands, &mut out);
            }
        }
        let mut unique: Vec<Invocation> = Vec::with_capacity(out.len());
        for inv in out {
            if !unique.contains(&inv) {
                unique.push(inv);
            }
        }
        unique
    }
}

fn match_site(site: &Site, name: &str, subcommands: &[&str], out: &mut Vec<Invocation>) {
    let hit = |captured: Option<String>, clean: Option<String>| Invocation {
        name: name.to_string(),
        captured,
        clean,
        args: None,
    };
    match site {
        Site::Command { argv, adjacency } => {
            if word_matches(&argv[0], name) {
                let next = argv.get(1).filter(|w| !w.text.starts_with('-'));
                let captured = next.map(|w| w.text.clone());
                let clean = next
                    .filter(|w| argv[0].literal() && w.literal())
                    .map(|w| w.text.clone());
                let args = argv[0].literal().then(|| {
                    argv[1..]
                        .iter()
                        .map(|w| w.literal().then(|| w.text.clone()))
                        .collect()
                });
                out.push(Invocation {
                    args,
                    ..hit(captured, clean)
                });
            }
            if *adjacency && !subcommands.is_empty() {
                for pair in argv[1..].windows(2) {
                    if word_matches(&pair[0], name)
                        && pair[1].literal()
                        && subcommands.contains(&pair[1].text.as_str())
                    {
                        out.push(hit(Some(pair[1].text.clone()), None));
                    }
                }
            }
        }
        Site::Exact(word) => {
            if word_matches(word, name) {
                out.push(hit(None, None));
            }
        }
        Site::Anywhere(text) => {
            if contains_name(text, name) {
                out.push(hit(None, None));
            }
        }
        Site::Interp(code, kind) => {
            if contains_name(code, name) && has_exec_primitive(code, *kind) {
                out.push(hit(None, None));
            }
        }
    }
}

/// Whether `word`, in command position, could resolve to the program `name`.
fn word_matches(word: &Word, name: &str) -> bool {
    if word.dynamic && contains_name(&word.text, name) {
        return true;
    }
    let candidates = if word.brace {
        expand_braces(&word.text)
    } else {
        vec![word.text.clone()]
    };
    candidates.iter().any(|c| {
        let n = normalize_command_name(c);
        if word.glob {
            glob_match(&n, name)
        } else {
            n == name
        }
    })
}

/// Reduce a quote-removed command word to the name the shell resolves.
///
/// Lowercases (macOS filesystems are case-insensitive), drops the zsh `=`
/// path-expansion prefix, and strips any directory prefix.
pub fn normalize_command_name(word: &str) -> String {
    let word = word.strip_prefix('=').unwrap_or(word);
    let base = word.rsplit('/').next().unwrap_or(word);
    base.to_lowercase()
}

#[cfg(test)]
mod tests;
