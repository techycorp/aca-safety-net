//! infisical analysis - blocks all infisical invocations.
//!
//! infisical (https://infisical.com) is a secrets-injection CLI. Its core
//! commands fetch secrets from the Infisical cloud and either inject them
//! into a child process's environment (`infisical run -- <cmd>`) or print
//! them to stdout (`infisical secrets get`, `infisical export`). Every use
//! involves real secret values, so we block at the top level.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Matches the first `infisical` word in a command, optionally capturing
/// the next identifier-like token as the subcommand.
static INFISICAL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\binfisical\b(?:\s+([A-Za-z0-9_-]+))?").unwrap());

const GENERIC_REASON: &str =
    "infisical fetches and injects secrets from the Infisical cloud; blocked entirely";

fn infisical_subcommand_info(subcommand: &str) -> (&'static str, &'static str) {
    match subcommand {
        "run" => (
            "infisical.run",
            "infisical run injects fetched secrets into a child process's environment",
        ),
        "secrets" => (
            "infisical.secrets",
            "infisical secrets prints secret values",
        ),
        "export" => (
            "infisical.export",
            "infisical export writes secrets to stdout / a file",
        ),
        "login" | "user" | "token" => (
            "infisical.auth",
            "infisical login/user/token reveals or sets auth credentials",
        ),
        _ => ("infisical.blocked", GENERIC_REASON),
    }
}

/// Per-segment dispatch: block any `infisical ...` invocation.
pub fn analyze_infisical(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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
    if basename != "infisical" {
        return Decision::allow();
    }

    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = infisical_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Raw-command analysis: catches `infisical` anywhere in the command.
pub fn analyze_infisical_raw(raw_command: &str) -> Decision {
    let Some(caps) = INFISICAL_RE.captures(raw_command) else {
        return Decision::allow();
    };
    let subcommand = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let (rule, reason) = infisical_subcommand_info(subcommand);
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
    fn test_bare_infisical() {
        assert!(analyze_infisical(&tokenize("infisical"), &cfg()).is_blocked());
    }

    #[test]
    fn test_infisical_run() {
        assert!(
            analyze_infisical(&tokenize("infisical run -- python script.py"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_infisical_secrets() {
        assert!(analyze_infisical(&tokenize("infisical secrets get FOO"), &cfg()).is_blocked());
    }

    #[test]
    fn test_infisical_export() {
        assert!(
            analyze_infisical(&tokenize("infisical export --format dotenv"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_infisical_login() {
        assert!(analyze_infisical(&tokenize("infisical login"), &cfg()).is_blocked());
    }

    #[test]
    fn test_infisical_init_blocked_too() {
        // Even seemingly-safe subcommands are blocked.
        assert!(analyze_infisical(&tokenize("infisical init"), &cfg()).is_blocked());
    }

    #[test]
    fn test_infisical_path_invocation() {
        assert!(
            analyze_infisical(&tokenize("/opt/homebrew/bin/infisical run"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_not_infisical() {
        assert!(!analyze_infisical(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    // ── Subcommand-specific reasons ─────────────────────────────────────────

    #[test]
    fn test_run_reason() {
        let d = analyze_infisical(&tokenize("infisical run -- ls"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "infisical.run");
    }

    #[test]
    fn test_secrets_reason() {
        let d = analyze_infisical(&tokenize("infisical secrets get X"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "infisical.secrets");
    }

    #[test]
    fn test_export_reason() {
        let d = analyze_infisical(&tokenize("infisical export"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "infisical.export");
    }

    #[test]
    fn test_default_reason() {
        let d = analyze_infisical(&tokenize("infisical init"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "infisical.blocked");
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(analyze_infisical_raw("infisical run -- ls").is_blocked());
    }

    #[test]
    fn test_raw_substitution() {
        assert!(analyze_infisical_raw("echo $(infisical secrets get TOKEN)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(analyze_infisical_raw("TOK=$(infisical export)").is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(analyze_infisical_raw("cd /tmp && infisical run -- ls").is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(analyze_infisical_raw(r#"bash -c "infisical run -- ls""#).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!analyze_infisical_raw("ls -la").is_blocked());
    }
}
