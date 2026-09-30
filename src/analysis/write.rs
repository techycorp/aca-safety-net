//! Write tool analysis.

use crate::config::CompiledConfig;
use crate::decision::{AskInfo, Decision};
use crate::input::WriteInput;
use crate::rules::{check_custom_rules, check_sensitive_path, check_ssh_write};

/// Analyze a Write tool invocation.
pub fn analyze_write(input: &WriteInput, config: &CompiledConfig) -> Decision {
    let path = &input.file_path;

    // 1. Check explicit deny rules
    for (rule, re) in &config.deny_patterns {
        if rule.tool == "Write" && re.is_match(path) {
            return Decision::block(&rule.reason, &rule.reason);
        }
    }

    // 2. Check custom rules
    let custom_decision = check_custom_rules("Write", path, config);
    if custom_decision.is_blocked() {
        return custom_decision;
    }

    // 3. Check sensitive file patterns
    let decision = check_ssh_write(path, config);
    if decision.is_blocked() {
        return decision;
    }
    let decision = check_sensitive_path(path, config);
    if decision.is_blocked() {
        return decision;
    }

    // 4. Check dependency file patterns (ask for approval)
    if config.is_dependency_file(path) {
        let mut ask = AskInfo::new(
            "dependencies.write",
            format!("Writing dependency file: {}", path),
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

    #[test]
    fn test_write_cargo_toml_asks() {
        let config = test_config();
        let input = WriteInput {
            file_path: "Cargo.toml".to_string(),
            content: "[package]\nname = \"test\"".to_string(),
        };
        let decision = analyze_write(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_write_package_json_asks() {
        let config = test_config();
        let input = WriteInput {
            file_path: "package.json".to_string(),
            content: "{}".to_string(),
        };
        let decision = analyze_write(&input, &config);
        assert!(decision.is_ask());
    }

    #[test]
    fn test_write_normal_file_allowed() {
        let config = test_config();
        let input = WriteInput {
            file_path: "src/main.rs".to_string(),
            content: "fn main() {}".to_string(),
        };
        let decision = analyze_write(&input, &config);
        assert!(!decision.is_blocked() && !decision.is_ask());
    }

    #[test]
    fn test_write_nested_pyproject_asks() {
        let config = test_config();
        let input = WriteInput {
            file_path: "/home/user/project/pyproject.toml".to_string(),
            content: "[project]".to_string(),
        };
        let decision = analyze_write(&input, &config);
        assert!(decision.is_ask());
    }
}
