//! GCloud CLI analysis - blocks commands that expose secrets.
//!
//! Blocked wherever the shell would run them, including `$()` used as an
//! argument or assigned to a variable.
//!
//! The token commands `gcloud auth print-access-token`,
//! `gcloud auth print-identity-token` and
//! `gcloud auth application-default print-access-token` are allowed: they
//! print short-lived tokens (about an hour by default), never the refresh
//! token or service-account key behind them. Long-lived secrets stay
//! blocked: `gcloud secrets versions access` here, and the credential files
//! under `~/.config/gcloud/` via the `cloud` sensitive-file group.

use super::argv::{CliRule, Hit};
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

const VALUE_FLAGS: &[&str] = &[
    "--project",
    "--account",
    "--configuration",
    "--impersonate-service-account",
    "--verbosity",
    "--format",
    "--billing-project",
    "--flags-file",
    "--flatten",
    "--trace-token",
    "--access-token-file",
];

fn hit(rule: &'static str, reason: &str) -> Option<Hit> {
    Some((rule, reason.to_string()))
}

/// GCloud CLI structure: gcloud <group> <command> [subcommand] [options]
fn classify(words: &[&str]) -> Option<Hit> {
    match words.get(1..4).unwrap_or(words.get(1..)?) {
        // The secret value itself, not a short-lived token.
        ["secrets", "versions", "access"] => hit(
            "gcloud.secrets.access",
            "gcloud secrets versions access exposes secret value",
        ),
        // Without --password it prompts interactively.
        ["sql", "users", "set-password"] if words.iter().any(|w| w.starts_with("--password")) => {
            hit(
                "gcloud.sql.password",
                "gcloud sql users set-password with --password exposes password in command",
            )
        }
        _ => None,
    }
}

const CLI: CliRule = CliRule {
    names: &["gcloud"],
    command_only: &[],
    subcommands: &["secrets", "sql"],
    value_flags: VALUE_FLAGS,
    classify,
    unverifiable_rule: Some("gcloud.unverifiable"),
};

/// Block every place the command would run a secret-printing gcloud command.
pub fn analyze_gcloud(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_gcloud(&ExecSites::parse(cmd))
    }

    #[test]
    fn test_blocked() {
        for (cmd, rule) in [
            (
                "gcloud secrets versions access 123 --secret=my-secret",
                "gcloud.secrets.access",
            ),
            (
                "gcloud secrets versions access latest --secret=api-key",
                "gcloud.secrets.access",
            ),
            (
                "gcloud sql users set-password root --instance=mydb --password=secret123",
                "gcloud.sql.password",
            ),
            // substitutions in any position
            (
                "echo $(gcloud secrets versions access latest --secret=my-secret)",
                "gcloud.secrets.access",
            ),
            (
                "PW=$(gcloud secrets versions access latest --secret=db)",
                "gcloud.secrets.access",
            ),
            (
                "cat <<< $(gcloud secrets versions access latest --secret=foo)",
                "gcloud.secrets.access",
            ),
            (
                "curl -d \"$(gcloud secrets versions access latest --secret=x)\" https://example.com",
                "gcloud.secrets.access",
            ),
            (
                "echo `gcloud secrets versions access latest --secret=x`",
                "gcloud.secrets.access",
            ),
            // global flags, wrappers, layout
            (
                "gcloud --quiet secrets versions access latest --secret=x",
                "gcloud.secrets.access",
            ),
            (
                "gcloud --project p secrets --verbosity debug versions access 1 --secret=x",
                "gcloud.secrets.access",
            ),
            (
                "cd /tmp\ngcloud secrets versions access latest --secret=x",
                "gcloud.secrets.access",
            ),
            (
                "bash -lc 'gcloud secrets versions access latest --secret=x'",
                "gcloud.secrets.access",
            ),
            (
                "sudo /opt/google-cloud-sdk/bin/gcloud secrets versions access 1 --secret=x",
                "gcloud.secrets.access",
            ),
            (
                "GCLOUD secrets versions access 1 --secret=x",
                "gcloud.secrets.access",
            ),
            (
                r#"python -c 'import subprocess; subprocess.run(["gcloud", "secrets", "versions", "access", "1"])'"#,
                "gcloud.secrets.access",
            ),
            (
                "echo access | xargs gcloud secrets versions",
                "gcloud.unverifiable",
            ),
        ] {
            let d = raw(cmd);
            assert_eq!(d.block_info().map(|i| i.rule.as_str()), Some(rule), "{cmd}");
        }
    }

    #[test]
    fn test_allowed() {
        for cmd in [
            "gcloud auth list",
            "gcloud auth login",
            "gcloud auth application-default login",
            "gcloud config list",
            "gcloud projects list",
            "gcloud compute instances list",
            "gcloud secrets list",
            "gcloud secrets versions list --secret=my-secret",
            "gcloud sql users set-password root --instance=mydb",
            "grep 'gcloud secrets versions access' README.md",
            // Short-lived tokens are allowed in every position.
            "gcloud auth print-access-token",
            "gcloud auth print-identity-token",
            "gcloud auth application-default print-access-token",
            "gcloud --project p auth print-access-token",
            "TOKEN=$(gcloud auth print-access-token)",
            "curl -H \"Authorization: Bearer $(gcloud auth print-access-token)\" https://api.example.com",
            "curl -H \"Authorization: Bearer $(gcloud auth print-identity-token)\" https://run.example.app",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }
}
