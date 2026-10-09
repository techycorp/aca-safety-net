//! Heroku CLI analysis - blocks commands that expose secrets.
//!
//! Unlike the short-lived cloud tokens allowed for gcloud, az and aws sts,
//! `heroku auth:token` prints the long-lived API token from the login
//! session, so it stays blocked.

use super::argv::{CliRule, Hit};
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

fn hit(rule: &'static str, reason: &str) -> Option<Hit> {
    Some((rule, reason.to_string()))
}

fn classify(words: &[&str]) -> Option<Hit> {
    if words.len() < 2 {
        return None;
    }

    // Check subcommand (words[1])
    match words[1] {
        // The long-lived API token from the login session; it does not expire
        // on its own the way gcloud/az access tokens do.
        "auth:token" => hit(
            "heroku.auth.token",
            "heroku auth:token exposes authentication token",
        ),

        // Config/env var exposure
        "config" => hit(
            "heroku.config",
            "heroku config exposes environment variables which may contain secrets",
        ),
        "config:get" => hit(
            "heroku.config.get",
            "heroku config:get exposes environment variable values",
        ),

        // Database credentials
        "pg:credentials" => hit(
            "heroku.pg.credentials",
            "heroku pg:credentials exposes database credentials",
        ),
        "pg:credentials:url" => hit(
            "heroku.pg.credentials",
            "heroku pg:credentials:url exposes database connection string with credentials",
        ),

        // Redis credentials
        "redis:credentials" => hit(
            "heroku.redis.credentials",
            "heroku redis:credentials exposes Redis credentials",
        ),

        // Allow all other commands
        _ => None,
    }
}

const CLI: CliRule = CliRule {
    names: &["heroku"],
    command_only: &[],
    subcommands: &[
        "auth:token",
        "config",
        "config:get",
        "pg:credentials",
        "pg:credentials:url",
        "redis:credentials",
    ],
    value_flags: &["-a", "--app", "-r", "--remote"],
    classify,
    unverifiable_rule: Some("heroku.unverifiable"),
};

/// Block every place the command would run a secret-printing Heroku CLI command,
/// including `$()` used as an argument or assigned to a variable.
pub fn analyze_heroku(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_heroku(&ExecSites::parse(cmd))
    }

    // Blocked commands

    #[test]
    fn test_auth_token() {
        let decision = raw("heroku auth:token");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_heroku_config() {
        let decision = raw("heroku config");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_heroku_config_with_app() {
        let decision = raw("heroku config -a myapp");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_config_get() {
        let decision = raw("heroku config:get DATABASE_URL");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_pg_credentials() {
        let decision = raw("heroku pg:credentials");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_pg_credentials_url() {
        let decision = raw("heroku pg:credentials:url");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_redis_credentials() {
        let decision = raw("heroku redis:credentials");
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_apps_allowed() {
        let decision = raw("heroku apps");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_ps_allowed() {
        let decision = raw("heroku ps");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_logs_allowed() {
        let decision = raw("heroku logs --tail");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_info_allowed() {
        let decision = raw("heroku info");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_run_allowed() {
        let decision = raw("heroku run bash");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_bypass_forms_blocked() {
        for cmd in [
            "echo $(heroku auth:token)",
            "curl -H \"Authorization: Bearer $(heroku auth:token)\" https://api.heroku.com",
            "URL=$(heroku config:get DATABASE_URL -a app)",
            "heroku -a app config",
            "cd x && heroku pg:credentials:url",
            "bash -c 'heroku redis:credentials'",
            "/usr/local/bin/heroku config",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_data_mentions_allowed() {
        for cmd in ["grep 'heroku config' notes.md", "heroku config:set FOO=1"] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }
}
