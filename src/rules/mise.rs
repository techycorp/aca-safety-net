//! mise analysis - blocks all mise invocations.
//!
//! mise (formerly rtx) loads per-directory environment from `.mise.toml`,
//! `.mise.local.toml`, and `.env` files. Several subcommands dump that
//! environment (`mise env`, `mise hook-env`, `mise exec`, `mise shell`).
//! We block mise at the top level — same model as direnv — because the
//! cost of a bypass is unbounded secret exposure and there is no
//! agent-relevant use of mise that doesn't have a safer alternative.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Matches the first `mise` word in a command, optionally capturing the
/// next identifier-like token as the subcommand. The capture lets the raw
/// analyzer surface the same subcommand-specific reason that the
/// per-segment dispatch would have used. The character class is limited to
/// `[A-Za-z0-9_-]` so that trailing shell metacharacters (quotes, parens,
/// pipes) don't end up glued onto the captured subcommand in contexts like
/// `bash -c "mise env"` or `echo $(mise env)`.
static MISE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bmise\b(?:\s+([A-Za-z0-9_-]+))?").unwrap());

const GENERIC_REASON: &str =
    "mise is blocked entirely because .mise.toml routinely contains secrets";

/// Shared subcommand-to-(rule, reason) lookup used by both the per-segment
/// dispatch and the raw analyzer.
fn mise_subcommand_info(subcommand: &str) -> (&'static str, &'static str) {
    match subcommand {
        "env" => (
            "mise.env",
            "mise env dumps the loaded environment to stdout",
        ),
        "hook-env" => (
            "mise.hook_env",
            "mise hook-env emits env mutations as shell code",
        ),
        "exec" => (
            "mise.exec",
            "mise exec loads .mise.toml and runs a command in that environment, exposing secrets",
        ),
        "shell" => (
            "mise.shell",
            "mise shell modifies the current shell's environment from .mise.toml",
        ),
        "activate" => (
            "mise.activate",
            "mise activate emits shell hook code that exposes env on every cd",
        ),
        "settings" | "config" => (
            "mise.config",
            "mise settings/config can reveal loaded env config",
        ),
        _ => ("mise.blocked", GENERIC_REASON),
    }
}

/// Per-segment dispatch: block any `mise ...` invocation.
pub fn analyze_mise(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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
    if basename != "mise" {
        return Decision::allow();
    }

    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = mise_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Raw-command analysis: blocks any mention of `mise` as a word, including
/// inside `$(...)` substitutions and after operators. We deliberately accept
/// false positives on the literal word "mise" appearing in strings or
/// comments — mise is too sensitive to allow case-by-case exceptions.
///
/// When the next token after `mise` is a recognized subcommand, the raw
/// analyzer returns the same specific reason the dispatch would have used.
/// In substitution contexts where the next token includes trailing shell
/// metacharacters (e.g. `mise env)` inside `$(...)`), the capture won't
/// match any subcommand arm and we fall back to the generic reason.
pub fn analyze_mise_raw(raw_command: &str) -> Decision {
    let Some(caps) = MISE_RE.captures(raw_command) else {
        return Decision::allow();
    };
    let subcommand = caps.get(1).map(|m| m.as_str()).unwrap_or("");
    let (rule, reason) = mise_subcommand_info(subcommand);
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
    fn test_bare_mise() {
        assert!(analyze_mise(&tokenize("mise"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_env() {
        assert!(analyze_mise(&tokenize("mise env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_env_shell_bash() {
        assert!(analyze_mise(&tokenize("mise env -s bash"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_hook_env() {
        assert!(analyze_mise(&tokenize("mise hook-env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_exec() {
        assert!(analyze_mise(&tokenize("mise exec -- printenv"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_shell() {
        assert!(analyze_mise(&tokenize("mise shell python@3.12"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_activate() {
        assert!(analyze_mise(&tokenize("mise activate bash"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_settings() {
        assert!(analyze_mise(&tokenize("mise settings ls"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_config() {
        assert!(analyze_mise(&tokenize("mise config get"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_install_blocked_too() {
        // Even "version manager" commands are blocked by policy.
        assert!(analyze_mise(&tokenize("mise install"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_plugins_blocked_too() {
        assert!(analyze_mise(&tokenize("mise plugins"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_current_blocked_too() {
        assert!(analyze_mise(&tokenize("mise current"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_version_blocked_too() {
        assert!(analyze_mise(&tokenize("mise version"), &cfg()).is_blocked());
    }

    #[test]
    fn test_mise_path_invocation() {
        assert!(analyze_mise(&tokenize("/opt/homebrew/bin/mise env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_not_mise() {
        assert!(!analyze_mise(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    // ── Subcommand-specific reasons ─────────────────────────────────────────

    #[test]
    fn test_env_reason() {
        let d = analyze_mise(&tokenize("mise env"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.env");
    }

    #[test]
    fn test_hook_env_reason() {
        let d = analyze_mise(&tokenize("mise hook-env"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.hook_env");
    }

    #[test]
    fn test_exec_reason() {
        let d = analyze_mise(&tokenize("mise exec -- cat .env"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.exec");
    }

    #[test]
    fn test_activate_reason() {
        let d = analyze_mise(&tokenize("mise activate zsh"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.activate");
    }

    #[test]
    fn test_default_reason() {
        let d = analyze_mise(&tokenize("mise install"), &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.blocked");
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(analyze_mise_raw("mise env").is_blocked());
    }

    #[test]
    fn test_raw_echo_substitution() {
        assert!(analyze_mise_raw("echo $(mise env -s bash)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(analyze_mise_raw("BLOB=$(mise hook-env)").is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(analyze_mise_raw(r#"eval "$(mise activate bash)""#).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(analyze_mise_raw("cd /tmp && mise env").is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(analyze_mise_raw(r#"bash -c "mise env""#).is_blocked());
    }

    #[test]
    fn test_raw_safe_argument_still_blocked() {
        // Argument-use is still blocked — no case-by-case exceptions.
        assert!(analyze_mise_raw("some-cmd --opt $(mise env)").is_blocked());
    }

    #[test]
    fn test_raw_path_invocation() {
        assert!(analyze_mise_raw("/opt/homebrew/bin/mise env").is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!analyze_mise_raw("ls -la").is_blocked());
    }

    // ── False-positive guards (word boundary) ───────────────────────────────

    #[test]
    fn test_raw_promise_not_blocked() {
        assert!(!analyze_mise_raw("npm install promise").is_blocked());
    }

    #[test]
    fn test_raw_demise_not_blocked() {
        assert!(!analyze_mise_raw("echo the demise of foo").is_blocked());
    }

    #[test]
    fn test_raw_misery_not_blocked() {
        assert!(!analyze_mise_raw("grep misery file.txt").is_blocked());
    }

    #[test]
    fn test_raw_automise_not_blocked() {
        assert!(!analyze_mise_raw("cat automise.log").is_blocked());
    }

    // ── Quoting / substitution edge cases ───────────────────────────────────

    #[test]
    fn test_raw_backtick_substitution() {
        assert!(analyze_mise_raw("echo `mise env`").is_blocked());
    }

    #[test]
    fn test_raw_single_quoted_in_substitution() {
        // Single-quoted form inside $() — word boundary still matches
        // because `'` is a non-word char.
        assert!(analyze_mise_raw("echo $('mise env')").is_blocked());
    }

    // ── Subcommand reason surfaces from raw layer ───────────────────────────

    #[test]
    fn test_raw_env_returns_specific_reason() {
        let d = analyze_mise_raw("mise env");
        assert_eq!(d.block_info().unwrap().rule, "mise.env");
    }

    #[test]
    fn test_raw_hook_env_returns_specific_reason() {
        let d = analyze_mise_raw("mise hook-env");
        assert_eq!(d.block_info().unwrap().rule, "mise.hook_env");
    }

    #[test]
    fn test_raw_exec_returns_specific_reason() {
        let d = analyze_mise_raw("mise exec -- printenv");
        assert_eq!(d.block_info().unwrap().rule, "mise.exec");
    }

    #[test]
    fn test_raw_activate_returns_specific_reason() {
        let d = analyze_mise_raw("mise activate bash");
        assert_eq!(d.block_info().unwrap().rule, "mise.activate");
    }

    #[test]
    fn test_raw_bare_returns_generic_reason() {
        let d = analyze_mise_raw("mise");
        assert_eq!(d.block_info().unwrap().rule, "mise.blocked");
    }

    #[test]
    fn test_raw_unknown_subcommand_returns_generic() {
        let d = analyze_mise_raw("mise install");
        assert_eq!(d.block_info().unwrap().rule, "mise.blocked");
    }
}
