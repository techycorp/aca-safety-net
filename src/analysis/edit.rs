//! Edit tool analysis.

use crate::config::CompiledConfig;
use crate::decision::{AskInfo, Decision};
use crate::input::EditInput;
use crate::rules::{check_custom_rules, check_sensitive_path, check_ssh_write};

/// Analyze an Edit tool invocation.
pub fn analyze_edit(input: &EditInput, config: &CompiledConfig) -> Decision {
    let path = &input.file_path;

    // 1. Check explicit deny rules
    for (rule, re) in &config.deny_patterns {
        if rule.tool == "Edit" && re.is_match(path) {
            return Decision::block(&rule.reason, &rule.reason);
        }
    }

    // 2. Check custom rules
    let custom_decision = check_custom_rules("Edit", path, config);
    if custom_decision.is_blocked() {
        return custom_decision;
    }

    // 3. Check dependency file patterns (ask for approval)
    let decision = check_ssh_write(path, config);
    if decision.is_blocked() {
        return decision;
    }

    let decision = check_sensitive_path(path, config);
    if decision.is_blocked() {
        return decision;
    }

    if config.is_dependency_file(path) {
        let mut ask = AskInfo::new(
            "dependencies.edit",
            format!("Editing dependency file: {}", path),
        );
        if let Some(suggestion) = config.dependency_suggestion() {
            ask = ask.with_suggestion(suggestion);
        }
        return Decision::Ask(ask);
    }

    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    fn config_with_deps_disabled() -> CompiledConfig {
        let mut config = Config::default();
        config.dependencies.enabled = false;
        config.compile().unwrap()
    }

    #[test]
    fn test_edit_cargo_toml_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "Cargo.toml".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_nested_cargo_toml_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "/home/user/project/Cargo.toml".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_package_json_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "package.json".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_pyproject_toml_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "pyproject.toml".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_requirements_txt_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "requirements.txt".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_go_mod_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "go.mod".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_gemfile_asks() {
        let config = test_config();
        let input = EditInput {
            file_path: "Gemfile".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_edit_normal_file_allowed() {
        let config = test_config();
        let input = EditInput {
            file_path: "src/main.rs".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(!decision.is_blocked() && !decision.is_ask());
    }

    #[test]
    fn test_edit_deps_disabled_allows() {
        let config = config_with_deps_disabled();
        let input = EditInput {
            file_path: "Cargo.toml".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        assert!(!decision.is_blocked() && !decision.is_ask());
    }

    #[test]
    fn test_ask_includes_suggestion() {
        let config = test_config();
        let input = EditInput {
            file_path: "Cargo.toml".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let decision = analyze_edit(&input, &config);
        if let Decision::Ask(info) = decision {
            assert!(info.suggestion.is_some());
            assert!(info.suggestion.unwrap().contains("cargo add"));
        } else {
            panic!("Expected Ask decision");
        }
    }
}
