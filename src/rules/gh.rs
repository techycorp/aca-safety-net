//! GitHub CLI analysis - blocks commands that print the login token.
//!
//! Like `heroku auth:token`, the gh token is long-lived and carries every
//! scope of the login (repo, org, workflow). gh reads it itself, so nothing
//! the agent does with gh needs it printed:
//!
//! - `gh auth token` prints it.
//! - `gh auth status --show-token` / `-t` prints it.
//! - `gh auth git-credential get` is the git credential helper; it prints it.
//! - `gh alias set` with an `auth` expansion would hide either form behind a
//!   new name, so it is blocked too.
//!
//! `gh secret` is allowed: GitHub returns secret names, never values.

use super::argv::{CliRule, Hit};
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

fn hit(rule: &'static str, reason: &str) -> Option<Hit> {
    Some((rule, reason.to_string()))
}

/// `-t`, `--show-token` (unless `=false`), or `-t` inside a short-flag group.
fn shows_token(flag: &str) -> bool {
    if let Some(long) = flag.strip_prefix("--") {
        return long == "show-token"
            || long
                .strip_prefix("show-token=")
                .is_some_and(|v| v != "false");
    }
    flag.strip_prefix('-')
        .is_some_and(|short| short.chars().all(|c| c.is_ascii_alphabetic()) && short.contains('t'))
}

fn classify(words: &[&str]) -> Option<Hit> {
    match (words.get(1).copied(), words.get(2).copied()) {
        (Some("auth"), Some("token")) => hit(
            "gh.auth.token",
            "gh auth token prints the long-lived GitHub login token",
        ),
        (Some("auth"), Some("status")) if words[3..].iter().any(|w| shows_token(w)) => hit(
            "gh.auth.token",
            "gh auth status --show-token prints the long-lived GitHub login token",
        ),
        (Some("auth"), Some("git-credential")) => hit(
            "gh.auth.token",
            "gh auth git-credential is a credential helper that prints the GitHub login token",
        ),
        (Some("alias"), Some("set")) if words[3..].iter().any(|w| w.contains("auth")) => hit(
            "gh.alias.auth",
            "gh alias set with an `auth` expansion could hide a token-printing command",
        ),
        _ => None,
    }
}

const CLI: CliRule = CliRule {
    names: &["gh"],
    command_only: &[],
    subcommands: &["auth", "alias"],
    value_flags: &["-R", "--repo", "-h", "--hostname"],
    classify,
    unverifiable_rule: Some("gh.unverifiable"),
};

/// Block every place the command would run a token-printing gh command,
/// including `$()` used as an argument or assigned to a variable.
pub fn analyze_gh(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_gh(&ExecSites::parse(cmd))
    }

    #[test]
    fn test_token_printing_blocked() {
        for cmd in [
            "gh auth token",
            "gh auth token -h github.com",
            "gh auth token --hostname github.com --user someone",
            "gh auth status -t",
            "gh auth status --show-token",
            "gh auth status --show-token=true",
            "gh auth status -h github.com -t",
            "gh auth status -at",
            "gh auth git-credential get",
            "gh auth git-credential",
            "gh alias set tok 'auth token'",
            "gh alias set --shell tok 'gh auth status -t'",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_bypass_forms_blocked() {
        for cmd in [
            "echo $(gh auth token)",
            "TOKEN=$(gh auth token)",
            "curl -H \"Authorization: Bearer $(gh auth token)\" https://api.github.com/user",
            "cd x && gh auth token",
            "gh auth token | pbcopy",
            "bash -c 'gh auth token'",
            "sudo gh auth token",
            "/opt/homebrew/bin/gh auth token",
            "echo auth token | xargs gh",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_normal_use_allowed() {
        for cmd in [
            "gh auth status",
            "gh auth status -h github.com",
            "gh auth status --show-token=false",
            "gh auth login",
            "gh auth refresh -s workflow",
            "gh pr list",
            "gh pr create --title t --body b",
            "gh repo list techycorp",
            "gh secret list",
            "gh secret set FOO --body x",
            "gh api repos/techycorp/mordor",
            "gh run view 123 --log",
            "gh alias set prs 'pr list'",
            "gh alias list",
            "grep 'gh auth token' notes.md",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_reason() {
        let d = raw("gh auth token");
        assert_eq!(d.block_info().unwrap().rule, "gh.auth.token");
    }
}
