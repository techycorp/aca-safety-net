//! direnv analysis - blocks all direnv invocations.
//!
//! direnv loads `.envrc` files which routinely contain secrets. Even seemingly
//! innocuous subcommands (`direnv exec`, `direnv export`, `direnv dump`) emit
//! the loaded environment to stdout in some form. We block direnv at the top
//! level rather than allow-listing safe subcommands, because the cost of a
//! bypass is unbounded secret exposure.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

static DIRENV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bdirenv\b").unwrap());

/// Per-segment dispatch: block any `direnv ...` invocation.
pub fn analyze_direnv(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.is_empty() || words[0] != "direnv" {
        return Decision::allow();
    }

    let subcommand = words.get(1).copied().unwrap_or("");

    let (rule, reason) = match subcommand {
        "exec" => (
            "direnv.exec",
            "direnv exec loads .envrc and runs a command in that environment, exposing secrets",
        ),
        "export" => (
            "direnv.export",
            "direnv export emits all loaded environment variables as shell code",
        ),
        "dump" => (
            "direnv.dump",
            "direnv dump emits the entire loaded environment",
        ),
        _ => (
            "direnv.blocked",
            "direnv is blocked entirely because .envrc routinely contains secrets",
        ),
    };

    Decision::block(rule, reason)
}

/// Raw-command analysis: blocks any mention of `direnv` as a word, including
/// inside `$(...)` substitutions and after operators. We deliberately accept
/// false positives on the literal word "direnv" appearing in strings or
/// comments — direnv is too sensitive to allow case-by-case exceptions.
pub fn analyze_direnv_raw(raw_command: &str) -> Decision {
    if DIRENV_RE.is_match(raw_command) {
        Decision::block(
            "direnv.blocked",
            "direnv is blocked entirely because .envrc routinely contains secrets",
        )
    } else {
        Decision::allow()
    }
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
    fn test_bare_direnv() {
        assert!(analyze_direnv(&tokenize("direnv"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_exec_env() {
        assert!(analyze_direnv(&tokenize("direnv exec . env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_exec_arbitrary() {
        assert!(analyze_direnv(&tokenize("direnv exec /tmp/foo cat .env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_export_bash() {
        assert!(analyze_direnv(&tokenize("direnv export bash"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_export_zsh() {
        assert!(analyze_direnv(&tokenize("direnv export zsh"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_export_json() {
        assert!(analyze_direnv(&tokenize("direnv export json"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_dump() {
        assert!(analyze_direnv(&tokenize("direnv dump"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_allow_blocked_too() {
        // Even "safe" subcommands are blocked by policy.
        assert!(analyze_direnv(&tokenize("direnv allow"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_status_blocked_too() {
        assert!(analyze_direnv(&tokenize("direnv status"), &cfg()).is_blocked());
    }

    #[test]
    fn test_direnv_version_blocked_too() {
        assert!(analyze_direnv(&tokenize("direnv version"), &cfg()).is_blocked());
    }

    #[test]
    fn test_not_direnv() {
        // Other commands fall through.
        assert!(!analyze_direnv(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    // ── Subcommand-specific reasons ─────────────────────────────────────────

    #[test]
    fn test_exec_reason() {
        let d = analyze_direnv(&tokenize("direnv exec . env"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.exec");
    }

    #[test]
    fn test_export_reason() {
        let d = analyze_direnv(&tokenize("direnv export bash"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.export");
    }

    #[test]
    fn test_dump_reason() {
        let d = analyze_direnv(&tokenize("direnv dump"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.dump");
    }

    #[test]
    fn test_default_reason() {
        let d = analyze_direnv(&tokenize("direnv allow"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.blocked");
    }

    // ── Substitution-aware (raw) ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(analyze_direnv_raw("direnv exec . env").is_blocked());
    }

    #[test]
    fn test_raw_echo_substitution() {
        assert!(analyze_direnv_raw("echo $(direnv export bash)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(analyze_direnv_raw("ENV_BLOB=$(direnv dump)").is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(analyze_direnv_raw(r#"eval "$(direnv export bash)""#).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(analyze_direnv_raw("cd /tmp && direnv exec . env").is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!analyze_direnv_raw("ls -la").is_blocked());
    }

    #[test]
    fn test_raw_safe_argument_still_blocked() {
        // Even argument-use of direnv is blocked — no case-by-case exceptions.
        assert!(analyze_direnv_raw("some-cmd --opt $(direnv export bash)").is_blocked());
    }

    #[test]
    fn test_raw_path_invocation() {
        assert!(analyze_direnv_raw("/usr/local/bin/direnv exec . env").is_blocked());
    }
}
