//! pipenv CLI analysis — blocks commands that install packages without
//! updating Pipfile (parallel to the `uv` rule).
//!
//! pipenv is the canonical Python virtualenv + lockfile tool. We do NOT
//! block `pipenv run` or `pipenv shell`: the only leak vector there is
//! that pipenv auto-loads `.env` into the child process's environment,
//! and any further leak requires the child to do something with those
//! vars (e.g. `python -c "print(os.environ)"`). That's the same shape as
//! the documented "Indirect file access" limitation in README.md, so
//! special-casing pipenv would be inconsistent.
//!
//! What we DO block are the Pipfile-bypass forms — they're parallel to
//! `uv pip install` / `uv run --with`, where the agent installs a
//! dependency without recording it in the project's canonical dep file.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze pipenv CLI commands for Pipfile-bypass installs.
pub fn analyze_pipenv(tokens: &[Token], _config: &CompiledConfig) -> Decision {
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
    if basename != "pipenv" {
        return Decision::allow();
    }

    if words.len() < 2 {
        return Decision::allow();
    }

    let subcommand = words[1];

    if subcommand != "install" {
        // pipenv lock/sync/update/run/shell/graph/check/etc. all pass through.
        return Decision::allow();
    }

    // Inside `pipenv install ...`, look for Pipfile-bypass flags.
    let has_flag = |flag: &str| {
        words
            .iter()
            .any(|w| *w == flag || w.starts_with(&format!("{flag}=")))
    };

    if has_flag("--skip-lock") {
        return Decision::block(
            "pipenv.install.skip_lock",
            "pipenv install --skip-lock bypasses Pipfile.lock. \
             Use 'pipenv install' or 'pipenv lock' to keep the lockfile in sync.",
        );
    }
    if has_flag("--ignore-pipfile") {
        return Decision::block(
            "pipenv.install.ignore_pipfile",
            "pipenv install --ignore-pipfile bypasses Pipfile. \
             Use 'pipenv install <package>' to record dependencies in Pipfile.",
        );
    }
    if has_flag("-r") || has_flag("--requirements") {
        return Decision::block(
            "pipenv.install.requirements",
            "pipenv install -r installs from a requirements file without updating Pipfile. \
             Use 'pipenv install <package>' to add deps instead.",
        );
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

    // ── Blocked: Pipfile-bypass forms ───────────────────────────────────────

    #[test]
    fn test_install_skip_lock() {
        assert!(analyze_pipenv(&tokenize("pipenv install --skip-lock"), &cfg()).is_blocked());
    }

    #[test]
    fn test_install_skip_lock_with_pkg() {
        assert!(
            analyze_pipenv(&tokenize("pipenv install --skip-lock requests"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_install_ignore_pipfile() {
        assert!(analyze_pipenv(&tokenize("pipenv install --ignore-pipfile"), &cfg()).is_blocked());
    }

    #[test]
    fn test_install_short_requirements() {
        assert!(
            analyze_pipenv(&tokenize("pipenv install -r requirements.txt"), &cfg()).is_blocked()
        );
    }

    #[test]
    fn test_install_long_requirements() {
        assert!(
            analyze_pipenv(
                &tokenize("pipenv install --requirements requirements.txt"),
                &cfg()
            )
            .is_blocked()
        );
    }

    #[test]
    fn test_install_requirements_equals_syntax() {
        assert!(
            analyze_pipenv(
                &tokenize("pipenv install --requirements=requirements.txt"),
                &cfg()
            )
            .is_blocked()
        );
    }

    // ── Allowed: canonical Pipfile-respecting workflow ──────────────────────

    #[test]
    fn test_install_no_args() {
        assert!(!analyze_pipenv(&tokenize("pipenv install"), &cfg()).is_blocked());
    }

    #[test]
    fn test_install_package() {
        assert!(!analyze_pipenv(&tokenize("pipenv install requests"), &cfg()).is_blocked());
    }

    #[test]
    fn test_install_editable() {
        assert!(!analyze_pipenv(&tokenize("pipenv install -e ./local"), &cfg()).is_blocked());
    }

    #[test]
    fn test_install_dev() {
        assert!(!analyze_pipenv(&tokenize("pipenv install --dev pytest"), &cfg()).is_blocked());
    }

    #[test]
    fn test_lock() {
        assert!(!analyze_pipenv(&tokenize("pipenv lock"), &cfg()).is_blocked());
    }

    #[test]
    fn test_sync() {
        assert!(!analyze_pipenv(&tokenize("pipenv sync"), &cfg()).is_blocked());
    }

    #[test]
    fn test_update() {
        assert!(!analyze_pipenv(&tokenize("pipenv update"), &cfg()).is_blocked());
    }

    #[test]
    fn test_graph() {
        assert!(!analyze_pipenv(&tokenize("pipenv graph"), &cfg()).is_blocked());
    }

    #[test]
    fn test_check() {
        assert!(!analyze_pipenv(&tokenize("pipenv check"), &cfg()).is_blocked());
    }

    #[test]
    fn test_requirements_subcommand() {
        // `pipenv requirements` (the subcommand, not -r flag) is allowed.
        assert!(!analyze_pipenv(&tokenize("pipenv requirements"), &cfg()).is_blocked());
    }

    // ── Explicitly out of scope per README "Known Limitations" ──────────────

    #[test]
    fn test_run_allowed_out_of_scope() {
        // `pipenv run python -c "print(os.environ)"` is the same shape as
        // the documented "Indirect file access" limitation. Not blocked
        // here; the env analyzer catches `pipenv run env` separately via
        // the standalone `env` match.
        assert!(!analyze_pipenv(&tokenize("pipenv run python -V"), &cfg()).is_blocked());
    }

    #[test]
    fn test_shell_allowed_out_of_scope() {
        // Interactive shell; not a programmatic leak vector on its own.
        assert!(!analyze_pipenv(&tokenize("pipenv shell"), &cfg()).is_blocked());
    }

    // ── Negative — other commands fall through ──────────────────────────────

    #[test]
    fn test_not_pipenv() {
        assert!(!analyze_pipenv(&tokenize("ls -la"), &cfg()).is_blocked());
    }

    #[test]
    fn test_pipenv_bare() {
        // `pipenv` with no subcommand — allow (prints help).
        assert!(!analyze_pipenv(&tokenize("pipenv"), &cfg()).is_blocked());
    }

    #[test]
    fn test_pipenv_path_install_skip_lock() {
        // Path-prefixed invocation should still match.
        assert!(
            analyze_pipenv(
                &tokenize("/opt/homebrew/bin/pipenv install --skip-lock"),
                &cfg()
            )
            .is_blocked()
        );
    }
}
