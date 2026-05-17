//! shadowenv analysis - blocks all shadowenv invocations.
//!
//! shadowenv (Shopify) loads per-directory environment from `.shadowenv.d/`
//! Lisp programs. The `shadowenv hook` subcommand emits shell code that
//! applies env mutations on every cd, and `shadowenv exec` runs commands
//! with that environment loaded. Same threat shape as direnv — block at
//! the top level rather than allow-listing safe subcommands.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Matches the first `shadowenv` word in a command, optionally capturing the
/// next identifier-like token as the subcommand. The character class is
/// limited to `[A-Za-z0-9_-]` so trailing shell metacharacters in
/// substitution contexts don't get glued onto the captured subcommand.
static SHADOWENV_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bshadowenv\b(?:\s+([A-Za-z0-9_-]+))?").unwrap());

const GENERIC_REASON: &str =
    "shadowenv loads per-directory environment from .shadowenv.d/; blocked entirely";

/// Shared subcommand-to-(rule, reason) lookup used by both the per-segment
/// dispatch and the raw analyzer.
fn shadowenv_subcommand_info(subcommand: &str) -> (&'static str, &'static str) {
    match subcommand {
        "hook" => (
            "shadowenv.hook",
            "shadowenv hook emits shell hook code that loads .shadowenv.d/ on every cd",
        ),
        "exec" => (
            "shadowenv.exec",
            "shadowenv exec loads .shadowenv.d/ and runs a command in that environment",
        ),
        "trust" | "diff" => (
            "shadowenv.config",
            "shadowenv trust/diff reveal loaded env config",
        ),
        _ => ("shadowenv.blocked", GENERIC_REASON),
    }
}

/// Per-segment dispatch: block any `shadowenv ...` invocation.
pub fn analyze_shadowenv(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.is_empty() {
        return Decision::allow();
    }

    let basename = words[0].rsplit('/').next().unwrap_or(words[0]);
    if basename != "shadowenv" {
        return Decision::allow();
    }

    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = shadowenv_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Raw-command analysis: catches `shadowenv` anywhere in the command,
/// including inside `$(...)` and after operators.
pub fn analyze_shadowenv_raw(raw_command: &str) -> Decision {
    let Some(caps) = SHADOWENV_RE.captures(raw_command) else {
        return Decision::allow();
    };
    let subcommand = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let (rule, reason) = shadowenv_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn cfg() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    // ── Per-segment dispatch ────────────────────────────────────────────────

    #[test]
    fn test_bare_shadowenv() {
        assert!(analyze_shadowenv(&tokenize("shadowenv"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_hook() {
        assert!(analyze_shadowenv(&tokenize("shadowenv hook bash"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_exec() {
        assert!(analyze_shadowenv(&tokenize("shadowenv exec -- ls"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_trust() {
        assert!(analyze_shadowenv(&tokenize("shadowenv trust"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_diff() {
        assert!(analyze_shadowenv(&tokenize("shadowenv diff"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_help_blocked() {
        assert!(analyze_shadowenv(&tokenize("shadowenv help"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shadowenv_path_invocation() {
        assert!(
            analyze_shadowenv(&tokenize("/opt/homebrew/bin/shadowenv hook"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_not_shadowenv() {
        assert!(!analyze_shadowenv(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    // ── Subcommand-specific reasons ─────────────────────────────────────────

    #[test]
    fn test_hook_reason() {
        let d = analyze_shadowenv(&tokenize("shadowenv hook bash"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "shadowenv.hook");
    }

    #[test]
    fn test_exec_reason() {
        let d = analyze_shadowenv(&tokenize("shadowenv exec -- ls"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "shadowenv.exec");
    }

    #[test]
    fn test_default_reason() {
        let d = analyze_shadowenv(&tokenize("shadowenv help"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "shadowenv.blocked");
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(analyze_shadowenv_raw("shadowenv hook bash").is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(analyze_shadowenv_raw(r#"eval "$(shadowenv hook bash)""#).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(analyze_shadowenv_raw("cd /tmp && shadowenv exec env").is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(analyze_shadowenv_raw(r#"bash -c "shadowenv hook bash""#).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!analyze_shadowenv_raw("ls -la").is_blocked());
    }

    #[test]
    fn test_raw_substring_safe() {
        // "shadow" alone isn't shadowenv.
        assert!(!analyze_shadowenv_raw("echo shadow ban").is_blocked());
    }
}
