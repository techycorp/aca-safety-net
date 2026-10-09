//! infisical analysis - blocks all infisical invocations.
//!
//! infisical (https://infisical.com) is a secrets-injection CLI. Its core
//! commands fetch secrets from the Infisical cloud and either inject them
//! into a child process's environment (`infisical run -- <cmd>`) or print
//! them to stdout (`infisical secrets get`, `infisical export`). Every use
//! involves real secret values, so we block at the top level.

use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

/// Known subcommands, for spotting `<unknown wrapper> infisical <subcommand>`.
const SUBCOMMANDS: &[&str] = &[
    "login",
    "logout",
    "init",
    "run",
    "export",
    "secrets",
    "dynamic-secrets",
    "scan",
    "agent",
    "agent-vault",
    "cert-manager",
    "gateway",
    "relay",
    "proxy",
    "kmip",
    "pam",
    "bootstrap",
    "org",
    "profile",
    "vault",
    "token",
    "service-token",
    "user",
    "reset",
    "ssh",
];

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

/// Whole-command analysis: blocks every place the command would run
/// infisical, including substitutions, `bash -c` strings and wrappers.
pub fn analyze_infisical_raw(sites: &ExecSites) -> Decision {
    let Some(inv) = sites
        .invocations(&["infisical"], SUBCOMMANDS)
        .into_iter()
        .next()
    else {
        return Decision::allow();
    };
    let (rule, reason) = infisical_subcommand_info(inv.captured.as_deref().unwrap_or(""));
    Decision::block(rule, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_infisical_raw(&ExecSites::parse(cmd))
    }

    // ── Per-segment dispatch ────────────────────────────────────────────────

    #[test]
    fn test_bare_infisical() {
        assert!(raw("infisical").is_blocked());
    }

    #[test]
    fn test_infisical_run() {
        assert!(raw("infisical run -- python script.py").is_blocked());
    }

    #[test]
    fn test_infisical_secrets() {
        assert!(raw("infisical secrets get FOO").is_blocked());
    }

    #[test]
    fn test_infisical_export() {
        assert!(raw("infisical export --format dotenv").is_blocked());
    }

    #[test]
    fn test_infisical_login() {
        assert!(raw("infisical login").is_blocked());
    }

    #[test]
    fn test_infisical_init_blocked_too() {
        // Even seemingly-safe subcommands are blocked.
        assert!(raw("infisical init").is_blocked());
    }

    #[test]
    fn test_infisical_path_invocation() {
        assert!(raw("/opt/homebrew/bin/infisical run").is_blocked());
    }

    #[test]
    fn test_not_infisical() {
        assert!(!raw("ls -la").is_blocked());
    }

    // ── Subcommand-specific reasons ─────────────────────────────────────────

    #[test]
    fn test_run_reason() {
        let d = raw("infisical run -- ls");
        assert_eq!(d.block_info().unwrap().rule, "infisical.run");
    }

    #[test]
    fn test_secrets_reason() {
        let d = raw("infisical secrets get X");
        assert_eq!(d.block_info().unwrap().rule, "infisical.secrets");
    }

    #[test]
    fn test_export_reason() {
        let d = raw("infisical export");
        assert_eq!(d.block_info().unwrap().rule, "infisical.export");
    }

    #[test]
    fn test_default_reason() {
        let d = raw("infisical init");
        assert_eq!(d.block_info().unwrap().rule, "infisical.blocked");
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(raw("infisical run -- ls").is_blocked());
    }

    #[test]
    fn test_raw_substitution() {
        assert!(raw("echo $(infisical secrets get TOKEN)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(raw("TOK=$(infisical export)").is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(raw("cd /tmp && infisical run -- ls").is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(raw(r#"bash -c "infisical run -- ls""#).is_blocked());
    }

    #[test]
    fn test_raw_unrelated() {
        assert!(!raw("ls -la").is_blocked());
    }

    #[test]
    fn test_raw_data_mentions_allowed() {
        for cmd in [
            "brew bundle add infisical",
            "grep -i infisical src",
            r#"git commit -m "fix infisical""#,
            "ls # infisical run",
            "echo 'infisical export' > notes.md",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_raw_execution_sites_blocked() {
        for cmd in [
            "cd x && infisical run",
            "cd x\ninfisical run",
            "echo `infisical export`",
            "bash -lc 'infisical run'",
            "eval infisical",
            "sudo -u root infisical",
            "timeout 5 infisical",
            "xargs infisical",
            r"find . -exec infisical {} \;",
            "Infisical run",
            "'infi''sical' run",
            r"$'\x69nfisical'",
            "{infisical,x}",
            "infisica?",
            "echo 'infisical run' | sh",
            "bash <<EOF\ninfisical run\nEOF",
            "npx @infisical/cli",
            "git -c alias.x='!infisical run' x",
            "GIT_SSH_COMMAND='infisical run' git fetch",
            r#"python -c 'import os;os.system("infisical")'"#,
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_raw_reason_from_wrapped_subcommand() {
        let d = raw("sudo infisical export");
        assert_eq!(d.block_info().unwrap().rule, "infisical.export");
    }
}
