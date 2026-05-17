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

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Matches `env`, `printenv`, or `gprintenv` as a command word, capturing
/// which one in group 1. The leading character class restricts to shell
/// positions where a command can start: start-of-string, whitespace, shell
/// operators, `$(`, backtick, `/` for path-prefixed `/usr/bin/env`, and
/// quote chars so quoted forms inside `$(...)` (e.g. `echo $('env')`) don't
/// bypass the check. This deliberately avoids matching `.env`,
/// `.env.example`, `pyenv`, etc.
static ENV_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:^|[\s;&|<>(`/'"])(env|g?printenv)\b"#).unwrap());

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

/// Per-segment dispatch: block when the command name is `env`, `printenv`,
/// or `gprintenv`.
pub fn analyze_env(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let cmd = tokens.iter().find_map(|t| match t {
        Token::Word(w) => Some(w.as_str()),
        _ => None,
    });

    let Some(cmd) = cmd else {
        return Decision::allow();
    };

    let basename = cmd.rsplit('/').next().unwrap_or(cmd);
    if matches!(basename, "env" | "printenv" | "gprintenv") {
        let (rule, reason) = info_for(basename);
        Decision::block(rule, reason)
    } else {
        Decision::allow()
    }
}

/// Raw-command analysis: catches `env` / `printenv` / `gprintenv` anywhere
/// in the command, including inside `$(...)`, after operators, and as
/// path-prefixed invocations.
pub fn analyze_env_raw(raw_command: &str) -> Decision {
    let Some(caps) = ENV_RE.captures(raw_command) else {
        return Decision::allow();
    };
    let matched = caps.get(1).map(|m| m.as_str()).unwrap_or("env");
    let (rule, reason) = info_for(matched);
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
    fn test_bare_env() {
        assert!(analyze_env(&tokenize("env"), &cfg()).is_blocked());
    }

    #[test]
    fn test_env_with_options() {
        assert!(analyze_env(&tokenize("env -0"), &cfg()).is_blocked());
    }

    #[test]
    fn test_env_with_assignment_no_cmd() {
        assert!(analyze_env(&tokenize("env FOO=bar"), &cfg()).is_blocked());
    }

    #[test]
    fn test_env_as_wrapper() {
        // We block this too — user should use `FOO=bar npm test`.
        assert!(analyze_env(&tokenize("env FOO=bar npm test"), &cfg()).is_blocked());
    }

    #[test]
    fn test_env_path_prefixed() {
        assert!(analyze_env(&tokenize("/usr/bin/env python script.py"), &cfg()).is_blocked());
    }

    #[test]
    fn test_not_env_pyenv() {
        assert!(!analyze_env(&tokenize("pyenv versions"), &cfg()).is_blocked());
    }

    #[test]
    fn test_not_env_rbenv() {
        assert!(!analyze_env(&tokenize("rbenv install"), &cfg()).is_blocked());
    }

    #[test]
    fn test_not_env_unrelated() {
        assert!(!analyze_env(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    // ── Raw / substitution-aware ────────────────────────────────────────────

    #[test]
    fn test_raw_standalone() {
        assert!(analyze_env_raw("env").is_blocked());
    }

    #[test]
    fn test_raw_after_and() {
        assert!(analyze_env_raw("cd /tmp && env").is_blocked());
    }

    #[test]
    fn test_raw_substitution() {
        assert!(analyze_env_raw("echo $(env)").is_blocked());
    }

    #[test]
    fn test_raw_variable_assignment() {
        assert!(analyze_env_raw("DUMP=$(env)").is_blocked());
    }

    #[test]
    fn test_raw_pipe() {
        assert!(analyze_env_raw("env | grep TOKEN").is_blocked());
    }

    #[test]
    fn test_raw_redirect() {
        assert!(analyze_env_raw("env > /tmp/leak").is_blocked());
    }

    #[test]
    fn test_raw_path_form() {
        assert!(analyze_env_raw("/usr/bin/env python -c 'pass'").is_blocked());
    }

    #[test]
    fn test_raw_pyenv_not_blocked() {
        assert!(!analyze_env_raw("pyenv install 3.12").is_blocked());
    }

    #[test]
    fn test_raw_environment_word_not_blocked() {
        // "environment" doesn't match \benv\b
        assert!(!analyze_env_raw("echo environment is set").is_blocked());
    }

    #[test]
    fn test_raw_env_var_underscore_not_blocked() {
        assert!(!analyze_env_raw("echo $MY_ENV_VAR").is_blocked());
    }

    // ── Quoted bypass guards (gap 1) ────────────────────────────────────────

    #[test]
    fn test_raw_single_quoted_in_substitution() {
        assert!(analyze_env_raw("echo $('env')").is_blocked());
    }

    #[test]
    fn test_raw_double_quoted_in_substitution() {
        assert!(analyze_env_raw(r#"echo $("env")"#).is_blocked());
    }

    #[test]
    fn test_raw_bash_c_quoted() {
        assert!(analyze_env_raw(r#"bash -c "env""#).is_blocked());
    }

    // ── printenv / gprintenv variants ───────────────────────────────────────

    #[test]
    fn test_raw_printenv() {
        assert!(analyze_env_raw("printenv").is_blocked());
    }

    #[test]
    fn test_raw_gprintenv() {
        assert!(analyze_env_raw("gprintenv").is_blocked());
    }

    #[test]
    fn test_raw_printenv_with_arg() {
        assert!(analyze_env_raw("printenv PATH").is_blocked());
    }

    #[test]
    fn test_raw_printenv_after_chain() {
        // The case the old anchored deny rule `^\s*printenv` missed.
        assert!(analyze_env_raw("cd /tmp && printenv").is_blocked());
    }

    #[test]
    fn test_raw_gprintenv_pipe() {
        assert!(analyze_env_raw("gprintenv | grep TOKEN").is_blocked());
    }

    #[test]
    fn test_raw_printenv_reason() {
        let d = analyze_env_raw("printenv");
        let info = d.block_info().unwrap();
        assert_eq!(info.rule, "printenv.blocked");
        assert!(info.reason.contains("printenv"));
    }

    #[test]
    fn test_raw_gprintenv_reason() {
        // gprintenv uses the same rule tag and reason as printenv.
        let d = analyze_env_raw("gprintenv FOO");
        assert_eq!(d.block_info().unwrap().rule, "printenv.blocked");
    }

    #[test]
    fn test_dispatch_bare_printenv() {
        assert!(analyze_env(&tokenize("printenv"), &cfg()).is_blocked());
    }

    #[test]
    fn test_dispatch_gprintenv_path() {
        assert!(analyze_env(&tokenize("/opt/homebrew/bin/gprintenv"), &cfg()).is_blocked());
    }

    // Negative — make sure we don't catch substrings.

    #[test]
    fn test_raw_printenv_not_in_word() {
        // `myprintenv` (no separator before) shouldn't match.
        assert!(!analyze_env_raw("/usr/bin/myprintenv").is_blocked());
    }
}
