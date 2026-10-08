//! mise analysis - blocks all mise invocations.
//!
//! mise (formerly rtx) loads per-directory environment from `.mise.toml`,
//! `.mise.local.toml`, and `.env` files. Several subcommands dump that
//! environment (`mise env`, `mise hook-env`, `mise exec`, `mise shell`).
//! We block mise at the top level — same model as direnv — because the
//! cost of a bypass is unbounded secret exposure and there is no
//! agent-relevant use of mise that doesn't have a safer alternative.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;
use crate::shell::exec_sites::ExecSites;

use super::tool_gate;

const TOOL: &str = "mise";

/// Known subcommands, for spotting `<unknown wrapper> mise <subcommand>`.
const SUBCOMMANDS: &[&str] = &[
    "env", "hook-env", "exec", "x", "shell", "activate", "settings", "config", "set", "install",
    "use", "run",
];

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

/// Per-segment dispatch: block any `mise ...` invocation not allowed by
/// `[tools.mise]`.
pub fn analyze_mise(tokens: &[Token], config: &CompiledConfig) -> Decision {
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

    if tool_gate::allows(TOOL, tool_gate::segment_subcommand(&words), config) {
        return Decision::allow();
    }
    let subcommand = words.get(1).copied().unwrap_or("");
    let (rule, reason) = mise_subcommand_info(subcommand);
    Decision::block(rule, reason)
}

/// Whole-command analysis: blocks every place the command would run mise,
/// including substitutions, `bash -c` strings and wrappers. Every
/// invocation must be allowed by `[tools.mise]` for the command to pass.
pub fn analyze_mise_raw(sites: &ExecSites, config: &CompiledConfig) -> Decision {
    for inv in sites.invocations(&[TOOL], SUBCOMMANDS) {
        if !tool_gate::allows(TOOL, inv.clean.as_deref(), config) {
            let (rule, reason) = mise_subcommand_info(inv.captured.as_deref().unwrap_or(""));
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
        analyze_mise_raw(&ExecSites::parse(cmd), c)
    }

    fn cfg_tool(enabled: bool, allow: &[&str]) -> CompiledConfig {
        let mut config = Config::default();
        config.tools.insert(
            "mise".to_string(),
            crate::config::ToolConfig {
                enabled,
                allow_subcommands: allow.iter().map(|s| s.to_string()).collect(),
            },
        );
        config.compile().unwrap()
    }

    // ── Config gating ───────────────────────────────────────────────────────

    #[test]
    fn test_disabled_allows_segment_and_raw() {
        let c = cfg_tool(false, &[]);
        assert!(!analyze_mise(&tokenize("mise exec -- ls"), &c).is_blocked());
        assert!(!raw("mise exec -- ls", &c).is_blocked());
        assert!(!raw("cat .mise.toml", &c).is_blocked());
    }

    #[test]
    fn test_allowlist_allows_listed_only() {
        let c = cfg_tool(true, &["install", "ls"]);
        assert!(!analyze_mise(&tokenize("mise install node@20"), &c).is_blocked());
        assert!(!raw("mise install node@20", &c).is_blocked());
        assert!(!raw("mise ls", &c).is_blocked());
        assert!(analyze_mise(&tokenize("mise exec -- ls"), &c).is_blocked());
        assert!(raw("mise exec -- ls", &c).is_blocked());
    }

    #[test]
    fn test_allowlist_checks_every_occurrence() {
        let c = cfg_tool(true, &["install"]);
        let d = raw("mise install && mise exec -- ls", &c);
        assert_eq!(d.block_info().unwrap().rule, "mise.exec");
    }

    #[test]
    fn test_allowlist_sees_through_quotes_and_nesting() {
        let c = cfg_tool(true, &["install"]);
        assert!(!raw(r#"mise "install""#, &c).is_blocked());
        assert!(!raw("echo $(mise install)", &c).is_blocked());
        assert!(!raw(r#"bash -c "mise install""#, &c).is_blocked());
    }

    #[test]
    fn test_allowlist_blocks_unclean_subcommands() {
        let c = cfg_tool(true, &["install", "env"]);
        assert!(raw("mise --cd /x install", &c).is_blocked());
        assert!(raw("mise $SUB", &c).is_blocked());
        assert!(raw("$(mise install)", &c).is_blocked());
        assert!(raw("mis? install", &c).is_blocked());
        assert!(raw("unknown-wrapper mise install", &c).is_blocked());
        assert!(analyze_mise(&tokenize("mise --cd /x install"), &c).is_blocked());
    }

    #[test]
    fn test_mise_env_still_blocked_by_env_analyzer_when_disabled() {
        let c = cfg_tool(false, &[]);
        assert!(!raw("mise env", &c).is_blocked());
        assert!(crate::rules::analyze_command("mise env", &c, None).is_blocked());
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
        assert!(raw("mise env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_echo_substitution() {
        assert!(raw("echo $(mise env -s bash)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(raw("BLOB=$(mise hook-env)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_eval_substitution() {
        assert!(raw(r#"eval "$(mise activate bash)""#, &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(raw("cd /tmp && mise env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(raw(r#"bash -c "mise env""#, &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_substitution_in_argument_blocked() {
        assert!(raw("some-cmd --opt $(mise env)", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_data_mentions_allowed() {
        assert!(!raw("rg mise", &cfg()).is_blocked());
        assert!(!raw("brew bundle add mise", &cfg()).is_blocked());
        assert!(!raw(r#"git commit -m "drop mise env""#, &cfg()).is_blocked());
        assert!(!raw("ls # mise env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_path_invocation() {
        assert!(raw("/opt/homebrew/bin/mise env", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!raw("ls -la", &cfg()).is_blocked());
    }

    // ── False-positive guards (word boundary) ───────────────────────────────

    #[test]
    fn test_raw_promise_not_blocked() {
        assert!(!raw("npm install promise", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_demise_not_blocked() {
        assert!(!raw("echo the demise of foo", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_misery_not_blocked() {
        assert!(!raw("grep misery file.txt", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_automise_not_blocked() {
        assert!(!raw("cat automise.log", &cfg()).is_blocked());
    }

    // ── Quoting / substitution edge cases ───────────────────────────────────

    #[test]
    fn test_raw_backtick_substitution() {
        assert!(raw("echo `mise env`", &cfg()).is_blocked());
    }

    #[test]
    fn test_raw_single_quoted_in_substitution() {
        // Single-quoted form inside $() — word boundary still matches
        // because `'` is a non-word char.
        assert!(raw("echo $('mise env')", &cfg()).is_blocked());
    }

    // ── Subcommand reason surfaces from raw layer ───────────────────────────

    #[test]
    fn test_raw_env_returns_specific_reason() {
        let d = raw("mise env", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.env");
    }

    #[test]
    fn test_raw_hook_env_returns_specific_reason() {
        let d = raw("mise hook-env", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.hook_env");
    }

    #[test]
    fn test_raw_exec_returns_specific_reason() {
        let d = raw("mise exec -- printenv", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.exec");
    }

    #[test]
    fn test_raw_activate_returns_specific_reason() {
        let d = raw("mise activate bash", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.activate");
    }

    #[test]
    fn test_raw_bare_returns_generic_reason() {
        let d = raw("mise", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.blocked");
    }

    #[test]
    fn test_raw_unknown_subcommand_returns_generic() {
        let d = raw("mise install", &cfg());
        assert_eq!(d.block_info().unwrap().rule, "mise.blocked");
    }
}
