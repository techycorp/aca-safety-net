//! Shared helpers for analyzers that run on [`ExecSites`] invocations of
//! CLIs whose dangerous subcommands print secrets.
//!
//! Analyzers classify a word list `[tool, sub, sub, ..., flags...]`. Global
//! flags may sit before or between subcommands, so each invocation is tried
//! as written and with flags moved to the end. A flag the analyzer doesn't
//! know is tried both as a switch and as taking the next word as its value.

use crate::decision::Decision;
use crate::shell::exec_sites::{ExecSites, Invocation, SiteKind};

/// A rule match: (rule id, reason).
pub type Hit = (&'static str, String);

/// The word lists to classify for one invocation, each starting with the tool name.
pub fn candidates<'a>(inv: &'a Invocation, value_flags: &[&str]) -> Vec<Vec<&'a str>> {
    let raw: Vec<&str> = std::iter::once(inv.name.as_str())
        .chain(inv.argv.iter().map(String::as_str))
        .collect();
    let mut out = vec![raw];
    for unknown_takes_value in [false, true] {
        let c = reorder(inv, value_flags, unknown_takes_value);
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// `[tool, positionals..., flags...]`, keeping each flag's value next to it.
fn reorder<'a>(
    inv: &'a Invocation,
    value_flags: &[&str],
    unknown_takes_value: bool,
) -> Vec<&'a str> {
    let mut pos = vec![inv.name.as_str()];
    let mut flags = Vec::new();
    let mut words = inv.argv.iter().map(String::as_str);
    while let Some(w) = words.next() {
        if w == "--" {
            pos.extend(words.by_ref());
            break;
        }
        if w.len() < 2 || !w.starts_with('-') {
            pos.push(w);
            continue;
        }
        flags.push(w);
        if w.contains('=') {
            continue;
        }
        if value_flags.contains(&w) || unknown_takes_value {
            flags.extend(words.next());
        }
    }
    pos.extend(flags);
    pos
}

/// The block for a secret-printing CLI whose arguments can't all be seen:
/// a bare program word (`xargs gcloud`) or one that gets more arguments at
/// runtime (`... | xargs gcloud auth`).
fn unverifiable(inv: &Invocation, rule: &'static str) -> Option<Decision> {
    (inv.kind == SiteKind::Exact || inv.open).then(|| {
        Decision::block(
            rule,
            format!(
                "`{}` runs with arguments the hook can't see, so a secret-printing subcommand can't be ruled out",
                inv.name
            ),
        )
    })
}

/// A CLI analyzer: names, subcommands for the adjacency heuristic, global
/// value flags, the classifier, and, for CLIs that can print secrets, the
/// rule id that blocks invocations whose arguments can't be seen.
pub struct CliRule {
    pub names: &'static [&'static str],
    /// Names too common to trust outside command position (`k` for kubectl).
    pub command_only: &'static [&'static str],
    pub subcommands: &'static [&'static str],
    pub value_flags: &'static [&'static str],
    pub classify: fn(&[&str]) -> Option<Hit>,
    pub unverifiable_rule: Option<&'static str>,
}

impl CliRule {
    /// Block the first invocation the classifier flags, wherever it sits:
    /// `$()`, arguments, assignments and wrappers included.
    pub fn analyze(&self, sites: &ExecSites) -> Decision {
        for inv in sites.invocations(self.names, self.subcommands) {
            if let Some(d) = self.check(&inv) {
                return d;
            }
        }
        Decision::allow()
    }

    fn check(&self, inv: &Invocation) -> Option<Decision> {
        if inv.kind != SiteKind::Command && self.command_only.contains(&inv.name.as_str()) {
            return None;
        }
        if let Some(d) = self.unverifiable_rule.and_then(|r| unverifiable(inv, r)) {
            return Some(d);
        }
        candidates(inv, self.value_flags)
            .iter()
            .find_map(|c| (self.classify)(c))
            .map(|(rule, reason)| Decision::block(rule, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(argv: &[&str]) -> Invocation {
        ExecSites::parse(&format!("tool {}", argv.join(" ")))
            .invocations(&["tool"], &[])
            .remove(0)
    }

    #[test]
    fn test_candidates_move_flags_after_positionals() {
        let i = inv(&["--project", "p", "auth", "print"]);
        let c = candidates(&i, &["--project"]);
        assert!(c.contains(&vec!["tool", "auth", "print", "--project", "p"]));
    }

    #[test]
    fn test_candidates_unknown_flag_both_ways() {
        let i = inv(&["--x", "a", "b"]);
        let c = candidates(&i, &[]);
        assert!(c.contains(&vec!["tool", "a", "b", "--x"]));
        assert!(c.contains(&vec!["tool", "b", "--x", "a"]));
    }

    #[test]
    fn test_candidates_dashdash_ends_flags() {
        let i = inv(&["a", "--", "-b"]);
        let c = candidates(&i, &[]);
        assert!(c.contains(&vec!["tool", "a", "-b"]));
    }
}
