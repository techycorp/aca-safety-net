//! `env` / `printenv` / `gprintenv` analysis — block commands that dump
//! environment variables.
//!
//! `env` (with no command) and `printenv` (with or without an argument) both
//! emit environment variables to stdout. `gprintenv` is the GNU-prefixed
//! variant installed by `brew install coreutils`. We treat all three the
//! same: block any invocation, including substitution and chained forms.
//!
//! `env FOO=bar cmd` (the wrapper form) is technically safe in isolation,
//! but shell already supports inline assignment (`FOO=bar cmd`) as a safer
//! equivalent, so we block the wrapper form too to keep the rule simple.

use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

const NAMES: &[&str] = &["env", "printenv", "gprintenv"];

const ENV_RULE: &str = "env.blocked";
const ENV_REASON: &str =
    "env exposes environment variables; use inline assignment (`FOO=bar cmd`) instead";
const PRINTENV_RULE: &str = "printenv.blocked";
const PRINTENV_REASON: &str = "printenv dumps environment variables to stdout";

/// Pick the right (rule, reason) pair given the matched command basename.
fn info_for(matched: &str) -> (&'static str, &'static str) {
    match matched {
        "printenv" | "gprintenv" => (PRINTENV_RULE, PRINTENV_REASON),
        _ => (ENV_RULE, ENV_REASON),
    }
}

/// Whole-command analysis: blocks every place the command would run `env`,
/// `printenv` or `gprintenv`, including substitutions, `bash -c` strings,
/// wrappers and path-prefixed forms. Also blocks `mise env`, which dumps the
/// same data, so it stays blocked when `[tools.mise]` is disabled.
pub fn analyze_env_raw(sites: &ExecSites) -> Decision {
    if let Some(inv) = sites.invocations(NAMES, &[]).into_iter().next() {
        let (rule, reason) = info_for(&inv.name);
        return Decision::block(rule, reason);
    }
    let mise_env = sites
        .invocations(&["mise"], &["env", "e"])
        .iter()
        .any(super::mise::is_mise_env);
    if mise_env {
        return Decision::block(ENV_RULE, ENV_REASON);
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_env_raw(&ExecSites::parse(cmd))
    }

    // ── Per-segment dispatch ────────────────────────────────────────────────

    #[test]
    fn test_bare_env() {
        assert!(raw("env").is_blocked());
    }

    #[test]
    fn test_env_with_options() {
        assert!(raw("env -0").is_blocked());
    }

    #[test]
    fn test_env_with_assignment_no_cmd() {
        assert!(raw("env FOO=bar").is_blocked());
    }

    #[test]
    fn test_env_as_wrapper() {
        // We block this too — user should use `FOO=bar npm test`.
        assert!(raw("env FOO=bar npm test").is_blocked());
    }

    #[test]
    fn test_env_path_prefixed() {
        assert!(raw("/usr/bin/env python script.py").is_blocked());
    }

    #[test]
    fn test_not_env_pyenv() {
        assert!(!raw("pyenv versions").is_blocked());
    }

    #[test]
    fn test_not_env_rbenv() {
        assert!(!raw("rbenv install").is_blocked());
    }

    #[test]
    fn test_not_env_unrelated() {
        assert!(!raw("ls -la").is_blocked());
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(raw("env").is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(raw("cd /tmp && env").is_blocked());
    }

    #[test]
    fn test_raw_substitution() {
        assert!(raw("echo $(env)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(raw("DUMP=$(env)").is_blocked());
    }

    #[test]
    fn test_raw_pipe() {
        assert!(raw("env | grep TOKEN").is_blocked());
    }

    #[test]
    fn test_raw_redirect() {
        assert!(raw("env > /tmp/leak").is_blocked());
    }

    #[test]
    fn test_raw_path_form() {
        assert!(raw("/usr/bin/env python -c 'pass'").is_blocked());
    }

    #[test]
    fn test_raw_pyenv_not_blocked() {
        assert!(!raw("pyenv install 3.12").is_blocked());
    }

    #[test]
    fn test_raw_environment_word_not_blocked() {
        // "environment" doesn't match \benv\b
        assert!(!raw("echo environment is set").is_blocked());
    }

    #[test]
    fn test_raw_env_var_underscore_not_blocked() {
        assert!(!raw("echo $MY_ENV_VAR").is_blocked());
    }

    // ── Quoted bypass guards (gap 1) ────────────────────────────────────────

    #[test]
    fn test_raw_single_quoted_in_substitution() {
        assert!(raw("echo $('env')").is_blocked());
    }

    #[test]
    fn test_raw_double_quoted_in_substitution() {
        assert!(raw(r#"echo $("env")"#).is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(raw(r#"bash -c "env""#).is_blocked());
    }

    // ── printenv / gprintenv variants ───────────────────────────────────────

    #[test]
    fn test_raw_printenv() {
        assert!(raw("printenv").is_blocked());
    }

    #[test]
    fn test_raw_gprintenv() {
        assert!(raw("gprintenv").is_blocked());
    }

    #[test]
    fn test_raw_printenv_with_arg() {
        assert!(raw("printenv PATH").is_blocked());
    }

    #[test]
    fn test_raw_printenv_after_chain() {
        // The case the old anchored deny rule `^\s*printenv` missed.
        assert!(raw("cd /tmp && printenv").is_blocked());
    }

    #[test]
    fn test_raw_gprintenv_pipe() {
        assert!(raw("gprintenv | grep TOKEN").is_blocked());
    }

    #[test]
    fn test_raw_printenv_reason() {
        let d = raw("printenv");
        let info = d.block_info().unwrap();
        assert_eq!(info.rule, "printenv.blocked");
        assert!(info.reason.contains("printenv"));
    }

    #[test]
    fn test_raw_gprintenv_reason() {
        // gprintenv uses the same rule tag and reason as printenv.
        let d = raw("gprintenv FOO");
        assert_eq!(d.block_info().unwrap().rule, "printenv.blocked");
    }

    #[test]
    fn test_dispatch_bare_printenv() {
        assert!(raw("printenv").is_blocked());
    }

    #[test]
    fn test_dispatch_gprintenv_path() {
        assert!(raw("/opt/homebrew/bin/gprintenv").is_blocked());
    }

    #[test]
    fn test_raw_data_mentions_allowed() {
        for cmd in [
            "cat src/rules/env.rs",
            "grep env file",
            "rg -n 'env' src",
            "ls env/",
            "cat .env.example",
            "git commit -m 'drop env usage'",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_raw_wrapped_and_nested() {
        for cmd in [
            "sudo env",
            "xargs env",
            "nohup printenv",
            "env FOO=1 ls",
            "mise exec -- env",
            "direnv exec . env",
            "echo `printenv`",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_raw_mise_env() {
        assert!(raw("mise env").is_blocked());
        assert!(raw("cd x && mise env -s bash").is_blocked());
        assert!(!raw("mise install").is_blocked());
    }

    // Negative — make sure we don't catch substrings.

    #[test]
    fn test_raw_printenv_not_in_word() {
        // `myprintenv` (no separator before) shouldn't match.
        assert!(!raw("/usr/bin/myprintenv").is_blocked());
    }
}
