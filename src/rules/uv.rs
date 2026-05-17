//! uv CLI analysis - blocks commands that install packages without modifying pyproject.toml.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze uv CLI commands for package installation that bypasses dependency files.
pub fn analyze_uv(tokens: &[Token], _config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.len() < 2 {
        return Decision::allow();
    }

    let subcommand = words[1];

    match subcommand {
        // uv run --with <pkg> installs packages into an ephemeral environment
        // Also catches --with=pkg (equals syntax) and --with-requirements
        "run" => {
            if words.iter().any(|w| {
                *w == "--with" || w.starts_with("--with=") || w.starts_with("--with-requirements")
            }) {
                Decision::block(
                    "uv.run.with",
                    "uv run --with installs packages without modifying pyproject.toml. \
                     Use 'uv add <package>' to add dependencies instead",
                )
            } else {
                Decision::allow()
            }
        }

        // uv pip install installs packages directly without updating pyproject.toml
        "pip" => {
            if words.len() >= 3 && words[2] == "install" {
                Decision::block(
                    "uv.pip.install",
                    "uv pip install installs packages without modifying pyproject.toml. \
                     Use 'uv add <package>' to add dependencies instead",
                )
            } else {
                Decision::allow()
            }
        }

        _ => Decision::allow(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::shell::tokenize;

    fn test_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    // Blocked commands

    #[test]
    fn test_uv_run_with_package() {
        let config = test_config();
        let tokens = tokenize("uv run --with browser-cookie3");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_multiple_packages() {
        let config = test_config();
        let tokens = tokenize("uv run --with browser-cookie3 --with requests python script.py");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_package_and_command() {
        let config = test_config();
        let tokens = tokenize("uv run --with flask python -m flask run");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install() {
        let config = test_config();
        let tokens = tokenize("uv pip install flask");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_requirements() {
        let config = test_config();
        let tokens = tokenize("uv pip install -r requirements.txt");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_editable() {
        let config = test_config();
        let tokens = tokenize("uv pip install -e .");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_install_upgrade() {
        let config = test_config();
        let tokens = tokenize("uv pip install --upgrade flask");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_equals_syntax() {
        let config = test_config();
        let tokens = tokenize("uv run --with=browser-cookie3 python script.py");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_requirements() {
        let config = test_config();
        let tokens = tokenize("uv run --with-requirements requirements.txt python script.py");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_uv_run_with_requirements_equals() {
        let config = test_config();
        let tokens = tokenize("uv run --with-requirements=requirements.txt python script.py");
        let decision = analyze_uv(&tokens, &config);
        assert!(decision.is_blocked());
    }

    // Allowed commands

    #[test]
    fn test_uv_run_without_with() {
        let config = test_config();
        let tokens = tokenize("uv run python script.py");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_run_pytest() {
        let config = test_config();
        let tokens = tokenize("uv run pytest");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_add() {
        let config = test_config();
        let tokens = tokenize("uv add flask");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_sync() {
        let config = test_config();
        let tokens = tokenize("uv sync");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_lock() {
        let config = test_config();
        let tokens = tokenize("uv lock");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_list() {
        let config = test_config();
        let tokens = tokenize("uv pip list");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_uv_pip_show() {
        let config = test_config();
        let tokens = tokenize("uv pip show flask");
        let decision = analyze_uv(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
