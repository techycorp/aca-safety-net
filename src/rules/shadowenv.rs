//! shadowenv analysis - blocks all shadowenv invocations.
//!
//! shadowenv (Shopify) loads per-directory environment from `.shadowenv.d/`
//! Lisp programs. The `shadowenv hook` subcommand emits shell code that
//! applies env mutations on every cd, and `shadowenv exec` runs commands
//! with that environment loaded. Same threat shape as direnv — block at
//! the top level rather than allow-listing safe subcommands.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;
use crate::shell::exec_sites::ExecSites;

use super::tool_gate;

const TOOL: &str = "shadowenv";

/// Known subcommands, for spotting `<unknown wrapper> shadowenv <subcommand>`.
const SUBCOMMANDS: &[&str] = &["hook", "exec", "trust", "diff", "init", "prompt-widget"];

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

/// Per-segment dispatch: block any `shadowenv ...` invocation not allowed by
/// `[tools.shadowenv]`.
pub fn analyze_shadowenv(tokens: &[Token], config: &CompiledConfig) -> Decision {
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

    if tool_gate::allows(TOOL, tool_gate::segment_subcommand(&words), config) {
        return Decision::allow();
    }
    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = shadowenv_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Whole-command analysis: blocks every place the command would run
/// shadowenv, including substitutions, `bash -c` strings and wrappers. Every
/// invocation must be allowed by `[tools.shadowenv]` for the command to pass.
pub fn analyze_shadowenv_raw(sites: &ExecSites, config: &CompiledConfig) -> Decision {
    for inv in sites.invocations(&[TOOL], SUBCOMMANDS) {
        if !tool_gate::allows(TOOL, inv.clean.as_deref(), config) {
            let (rule, reason) = shadowenv_subcommand_info(inv.captured.as_deref().unwrap_or(""));
            return Decision::block(rule, reason);
        }
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn cfg() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    fn raw(cmd: &str, c: &CompiledConfig) -> Decision {
        analyze_shadowenv_raw(&ExecSites::parse(cmd), c)
    }

    #[test]
    fn test_secretless_profile_allows() {
        let c = Config {
            profile: Some("secretless".to_string()),
            ..Default::default()
        }
        .compile()
        .unwrap();
        assert!(!analyze_shadowenv(&tokenize("shadowenv trust"), &c).is_blocked());
        assert!(!raw(r#"eval "$(shadowenv hook bash)""#, &c).is_blocked());
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
        assert!(raw("shadowenv hook bash", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(raw(r#"eval "$(shadowenv hook bash)""#, &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(raw("cd /tmp && shadowenv exec env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(raw(r#"bash -c "shadowenv hook bash""#, &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!raw("ls -la", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_data_mentions_allowed() {
        assert!(!raw("brew install shadowenv", &cfg()).is_blocked());
        assert!(!raw("cat docs/shadowenv.md", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_substring_safe() {
        // "shadow" alone isn't shadowenv.
        assert!(!raw("echo shadow ban", &cfg()).is_blocked());
    }
}
