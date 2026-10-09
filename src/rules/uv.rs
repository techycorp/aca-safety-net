//! uv CLI analysis - blocks commands that install packages without modifying pyproject.toml.

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

    let subcommand = words[1];

    match subcommand {
        // uv run --with <pkg> installs packages into an ephemeral environment
        // Also catches --with=pkg (equals syntax) and --with-requirements
        "run" => {
            if words.iter().any(|w| {
                *w == "--with" || w.starts_with("--with=") || w.starts_with("--with-requirements")
            }) {
                hit(
                    "uv.run.with",
                    "uv run --with installs packages without modifying pyproject.toml. \
                     Use 'uv add <package>' to add dependencies instead",
                )
            } else {
                None
            }
        }

        // uv pip install installs packages directly without updating pyproject.toml
        "pip" => {
            if words.len() >= 3 && words[2] == "install" {
                hit(
                    "uv.pip.install",
                    "uv pip install installs packages without modifying pyproject.toml. \
                     Use 'uv add <package>' to add dependencies instead",
                )
            } else {
                None
            }
        }

        _ => None,
    }
}

const CLI: CliRule = CliRule {
    names: &["uv"],
    command_only: &[],
    subcommands: &["run", "pip"],
    value_flags: &["--directory", "--project", "--cache-dir", "--config-file"],
    classify,
    unverifiable_rule: None,
};

/// Check every place the command would run uv, including nested and
/// wrapped forms.
pub fn analyze_uv(sites: &ExecSites) -> Decision {
    CLI.analyze(sites)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_uv(&ExecSites::parse(cmd))
    }

    // Blocked commands

    #[test]
    fn test_uv_run_with_package() {
        let decision = raw("uv run --with browser-cookie3");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_multiple_packages() {
        let decision = raw("uv run --with browser-cookie3 --with requests python script.py");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_package_and_command() {
        let decision = raw("uv run --with flask python -m flask run");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install() {
        let decision = raw("uv pip install flask");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_requirements() {
        let decision = raw("uv pip install -r requirements.txt");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_editable() {
        let decision = raw("uv pip install -e .");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_upgrade() {
        let decision = raw("uv pip install --upgrade flask");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_equals_syntax() {
        let decision = raw("uv run --with=browser-cookie3 python script.py");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_requirements() {
        let decision = raw("uv run --with-requirements requirements.txt python script.py");
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_requirements_equals() {
        let decision = raw("uv run --with-requirements=requirements.txt python script.py");
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_uv_run_without_with() {
        let decision = raw("uv run python script.py");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_run_pytest() {
        let decision = raw("uv run pytest");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_add() {
        let decision = raw("uv add flask");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_sync() {
        let decision = raw("uv sync");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_lock() {
        let decision = raw("uv lock");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_list() {
        let decision = raw("uv pip list");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_show() {
        let decision = raw("uv pip show flask");
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_nested_forms_blocked() {
        for cmd in [
            "cd x && uv pip install flask",
            "bash -c 'uv pip install flask'",
            "/opt/homebrew/bin/uv run --with rich script.py",
            "uv --directory sub pip install flask",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
        assert!(!raw("grep 'uv pip install' README.md").is_blocked());
    }
}
