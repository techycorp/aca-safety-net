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

use super::argv::{CliRule, Hit};
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

fn hit(rule: &'static str, reason: &str) -> Option<Hit> {
    Some((rule, reason.to_string()))
}

fn classify(words: &[&str]) -> Option<Hit> {
    if words.is_empty() {
        return None;
    }

    let basename = words[0].rsplit('/').next().unwrap_or(words[0]);
    if basename != "pipenv" {
        return None;
    }

    if words.len() < 2 {
        return None;
    }

    let subcommand = words[1];

    if subcommand != "install" {
        // pipenv lock/sync/update/run/shell/graph/check/etc. all pass through.
        return None;
    }

    // Inside `pipenv install ...`, look for Pipfile-bypass flags.
    let has_flag = |flag: &str| {
        words
            .iter()
            .any(|w| *w == flag || w.starts_with(&format!("{flag}=")))
    };

    if has_flag("--skip-lock") {
        return hit(
            "pipenv.install.skip_lock",
            "pipenv install --skip-lock bypasses Pipfile.lock. \
             Use 'pipenv install' or 'pipenv lock' to keep the lockfile in sync.",
        );
    }
    if has_flag("--ignore-pipfile") {
        return hit(
            "pipenv.install.ignore_pipfile",
            "pipenv install --ignore-pipfile bypasses Pipfile. \
             Use 'pipenv install <package>' to record dependencies in Pipfile.",
        );
    }
    if has_flag("-r") || has_flag("--requirements") {
        return hit(
            "pipenv.install.requirements",
            "pipenv install -r installs from a requirements file without updating Pipfile. \
             Use 'pipenv install <package>' to add deps instead.",
        );
    }

    None
}

const CLI: CliRule = CliRule {
    names: &["pipenv"],
    command_only: &[],
    subcommands: &["install"],
    value_flags: &[],
    classify,
    unverifiable_rule: None,
};

/// Check every place the command would run pipenv, including nested and
/// wrapped forms.
pub fn analyze_pipenv(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_pipenv(&ExecSites::parse(cmd))
    }

    // ── Blocked: Pipfile-bypass forms ───────────────────────────────────────

    #[test]
    fn test_install_skip_lock() {
        assert!(raw("pipenv install --skip-lock").is_blocked());
    }

    #[test]
    fn test_install_skip_lock_with_pkg() {
        assert!(raw("pipenv install --skip-lock requests").is_blocked());
    }

    #[test]
    fn test_install_ignore_pipfile() {
        assert!(raw("pipenv install --ignore-pipfile").is_blocked());
    }

    #[test]
    fn test_install_short_requirements() {
        assert!(raw("pipenv install -r requirements.txt").is_blocked());
    }

    #[test]
    fn test_install_long_requirements() {
        assert!(raw("pipenv install --requirements requirements.txt").is_blocked());
    }

    #[test]
    fn test_install_requirements_equals_syntax() {
        assert!(raw("pipenv install --requirements=requirements.txt").is_blocked());
    }

    // ── Allowed: canonical Pipfile-respecting workflow ──────────────────────

    #[test]
    fn test_install_no_args() {
        assert!(!raw("pipenv install").is_blocked());
    }

    #[test]
    fn test_install_package() {
        assert!(!raw("pipenv install requests").is_blocked());
    }

    #[test]
    fn test_install_editable() {
        assert!(!raw("pipenv install -e ./local").is_blocked());
    }

    #[test]
    fn test_install_dev() {
        assert!(!raw("pipenv install --dev pytest").is_blocked());
    }

    #[test]
    fn test_lock() {
        assert!(!raw("pipenv lock").is_blocked());
    }

    #[test]
    fn test_sync() {
        assert!(!raw("pipenv sync").is_blocked());
    }

    #[test]
    fn test_update() {
        assert!(!raw("pipenv update").is_blocked());
    }

    #[test]
    fn test_graph() {
        assert!(!raw("pipenv graph").is_blocked());
    }

    #[test]
    fn test_check() {
        assert!(!raw("pipenv check").is_blocked());
    }

    #[test]
    fn test_requirements_subcommand() {
        // `pipenv requirements` (the subcommand, not -r flag) is allowed.
        assert!(!raw("pipenv requirements").is_blocked());
    }

    // ── Explicitly out of scope per README "Known Limitations" ──────────────

    #[test]
    fn test_run_allowed_out_of_scope() {
        // `pipenv run python -c "print(os.environ)"` is the same shape as
        // the documented "Indirect file access" limitation. Not blocked
        // here; the env analyzer catches `pipenv run env` separately via
        // the standalone `env` match.
        assert!(!raw("pipenv run python -V").is_blocked());
    }

    #[test]
    fn test_shell_allowed_out_of_scope() {
        // Interactive shell; not a programmatic leak vector on its own.
        assert!(!raw("pipenv shell").is_blocked());
    }

    // ── Negative — other commands fall through ──────────────────────────────

    #[test]
    fn test_not_pipenv() {
        assert!(!raw("ls -la").is_blocked());
    }

    #[test]
    fn test_pipenv_bare() {
        // `pipenv` with no subcommand — allow (prints help).
        assert!(!raw("pipenv").is_blocked());
    }

    #[test]
    fn test_pipenv_path_install_skip_lock() {
        // Path-prefixed invocation should still match.
        assert!(raw("/opt/homebrew/bin/pipenv install --skip-lock").is_blocked());
    }

    #[test]
    fn test_nested_forms_blocked() {
        for cmd in [
            "cd x && pipenv install --skip-lock",
            "bash -c 'pipenv install -r requirements.txt'",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
        assert!(!raw("grep 'pipenv install --skip-lock' README.md").is_blocked());
    }
}
