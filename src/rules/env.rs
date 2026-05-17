//! `env` analysis - blocks the env command entirely.
//!
//! `env` (with no command) prints every environment variable. `env` as a
//! wrapper (`env FOO=bar cmd`) is technically safe in isolation, but the bare
//! variant is the more dangerous case and shell already supports inline
//! assignment (`FOO=bar cmd`) as a safer equivalent. We block both for the
//! same reason we block direnv: the failure mode is unbounded secret exposure
//! and there's no operationally-necessary use that lacks a safer form.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Matches `env` as a command word. The leading character class restricts to
/// shell positions where a command can start: start-of-string, whitespace,
/// shell operators, `$(`, backtick, `/` for path-prefixed `/usr/bin/env`,
/// and quote chars so quoted forms inside `$(...)` (e.g. `echo $('env')`)
/// don't bypass the check. This deliberately avoids matching `.env`,
/// `.env.example`, `pyenv`, etc. The trade-off is that a literal filename
/// like `cat "env.txt"` will be blocked — acceptable given a real file
/// named `env` is rare and the strict stance is intentional.
static ENV_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?:^|[\s;&|<>(`/'"])env\b"#).unwrap());

const RULE: &str = "env.blocked";
const REASON: &str =
    "env exposes environment variables; use inline assignment (`FOO=bar cmd`) instead";

/// Per-segment dispatch: block when the command name is `env`.
pub fn analyze_env(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let cmd = tokens.iter().find_map(|t| match t {
        Token::Word(w) => Some(w.as_str()),
        _ => None,
    });

    let Some(cmd) = cmd else {
        return Decision::allow();
    };

    let basename = cmd.rsplit('/').next().unwrap_or(cmd);
    if basename == "env" {
        Decision::block(RULE, REASON)
    } else {
        Decision::allow()
    }
}

/// Raw-command analysis: catches `env` anywhere in the command, including
/// inside `$(...)`, after operators, and as a path-prefixed invocation.
pub fn analyze_env_raw(raw_command: &str) -> Decision {
    if ENV_RE.is_match(raw_command) {
        Decision::block(RULE, REASON)
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
}
