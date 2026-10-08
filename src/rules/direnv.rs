//! direnv analysis - blocks all direnv invocations.
//!
//! direnv loads `.envrc` files which routinely contain secrets. Even seemingly
//! innocuous subcommands (`direnv exec`, `direnv export`, `direnv dump`) emit
//! the loaded environment to stdout in some form. We block direnv at the top
//! level rather than allow-listing safe subcommands, because the cost of a
//! bypass is unbounded secret exposure.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;
use crate::shell::exec_sites::ExecSites;

use super::tool_gate;

const TOOL: &str = "direnv";

/// Known subcommands, for spotting `<unknown wrapper> direnv <subcommand>`.
const SUBCOMMANDS: &[&str] = &[
    "allow",
    "deny",
    "exec",
    "export",
    "dump",
    "edit",
    "hook",
    "reload",
    "status",
    "block",
    "revoke",
    "prune",
    "fetchurl",
    "apply_dump",
    "show_dump",
    "stdlib",
    "version",
    "watch",
];

const GENERIC_REASON: &str = "direnv is blocked entirely because .envrc routinely contains secrets";

/// Shared subcommand-to-(rule, reason) lookup used by both the per-segment
/// dispatch and the raw analyzer.
fn direnv_subcommand_info(subcommand: &str) -> (&'static str, &'static str) {
    match subcommand {
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
        _ => ("direnv.blocked", GENERIC_REASON),
    }
}

/// Per-segment dispatch: block any `direnv ...` invocation not allowed by
/// `[tools.direnv]`.
pub fn analyze_direnv(tokens: &[Token], config: &CompiledConfig) -> Decision {
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

    if tool_gate::allows(TOOL, tool_gate::segment_subcommand(&words), config) {
        return Decision::allow();
    }
    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = direnv_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Whole-command analysis: blocks every place the command would run direnv,
/// including substitutions, `bash -c` strings and wrappers. Every
/// invocation must be allowed by `[tools.direnv]` for the command to pass.
pub fn analyze_direnv_raw(sites: &ExecSites, config: &CompiledConfig) -> Decision {
    for inv in sites.invocations(&[TOOL], SUBCOMMANDS) {
        if !tool_gate::allows(TOOL, inv.clean.as_deref(), config) {
            let (rule, reason) = direnv_subcommand_info(inv.captured.as_deref().unwrap_or(""));
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
        analyze_direnv_raw(&ExecSites::parse(cmd), c)
    }

    #[test]
    fn test_disabled_allows_segment_and_raw() {
        let mut config = Config::default();
        config.tools.insert(
            "direnv".to_string(),
            crate::config::ToolConfig {
                enabled: false,
                allow_subcommands: vec![],
            },
        );
        let c = config.compile().unwrap();
        assert!(!analyze_direnv(&tokenize("direnv allow"), &c).is_blocked());
        assert!(!raw(r#"eval "$(direnv hook zsh)""#, &c).is_blocked());
    }

    #[test]
    fn test_allowlisted_subcommand() {
        let mut config = Config::default();
        config.tools.insert(
            "direnv".to_string(),
            crate::config::ToolConfig {
                enabled: true,
                allow_subcommands: vec!["allow".to_string()],
            },
        );
        let c = config.compile().unwrap();
        assert!(!analyze_direnv(&tokenize("direnv allow"), &c).is_blocked());
        assert!(!raw("direnv allow", &c).is_blocked());
        assert!(raw("direnv allow && direnv export bash", &c).is_blocked());
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
        assert!(raw("direnv exec . env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_echo_substitution() {
        assert!(raw("echo $(direnv export bash)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(raw("ENV_BLOB=$(direnv dump)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(raw(r#"eval "$(direnv export bash)""#, &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(raw("cd /tmp && direnv exec . env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!raw("ls -la", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_substitution_in_argument_blocked() {
        assert!(raw("some-cmd --opt $(direnv export bash)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_data_mentions_allowed() {
        assert!(!raw("brew install direnv", &cfg()).is_blocked());
        assert!(!raw("grep -rn direnv src", &cfg()).is_blocked());
        assert!(!raw("echo 'run direnv allow'", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_wrapped_blocked() {
        assert!(raw("sudo direnv allow", &cfg()).is_blocked());
        assert!(raw("xargs direnv", &cfg()).is_blocked());
        assert!(raw("unknown-wrapper direnv export bash", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_path_invocation() {
        assert!(raw("/usr/local/bin/direnv exec . env", &cfg()).is_blocked());
    }

    // ── Quoting / substitution edge cases ───────────────────────────────────

    #[test]
    fn test_raw_backtick_substitution() {
        assert!(raw("echo `direnv export bash`", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_single_quoted_in_substitution() {
        // Single-quoted form inside $() — word boundary still matches because
        // `'` is a non-word char.
        assert!(raw("echo $('direnv export bash')", &cfg()).is_blocked());
    }

    // ── Subcommand reason surfaces from raw layer ───────────────────────────

    #[test]
    fn test_raw_exec_returns_specific_reason() {
        let d = raw("direnv exec . env", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.exec");
    }

    #[test]
    fn test_raw_export_returns_specific_reason() {
        let d = raw("direnv export bash", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.export");
    }

    #[test]
    fn test_raw_bare_returns_generic_reason() {
        let d = raw("direnv", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.blocked");
    }

    #[test]
    fn test_raw_unknown_subcommand_returns_generic() {
        let d = raw("direnv allow", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "direnv.blocked");
    }
}
