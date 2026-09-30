//! Analysis for tools identified only by the paths they touch (Grep, Glob,
//! NotebookEdit, and any other tool routed to the hook).

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::rules::{check_custom_rules, check_sensitive_path, check_ssh_write};

/// Analyze a tool invocation by the paths and path globs in its input.
pub fn analyze_path_tool(tool: &str, paths: &[String], config: &CompiledConfig) -> Decision {
    for path in paths {
        for (rule, re) in &config.deny_patterns {
            if rule.tool == tool && re.is_match(path) {
                return Decision::block(&rule.reason, &rule.reason);
            }
        }

        let decision = check_custom_rules(tool, path, config);
        if decision.is_blocked() {
            return decision;
        }

        if let Some(pattern) = config.matches_paranoid(path) {
            return Decision::block(
                "paranoid.sensitive_file",
                format!("path matches sensitive pattern '{}'", pattern),
            );
        }

        if !READ_ONLY_TOOLS.contains(&tool) {
            let decision = check_ssh_write(path, config);
            if decision.is_blocked() {
                return decision;
            }
        }

        let decision = check_sensitive_path(path, config);
        if decision.is_blocked() {
            return decision;
        }
    }
    Decision::allow()
}

/// Tools that only read, so the readable ~/.ssh files stay reachable.
const READ_ONLY_TOOLS: &[&str] = &["Grep", "Glob"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    fn check(tool: &str, paths: &[&str]) -> Decision {
        let paths: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        analyze_path_tool(tool, &paths, &cfg())
    }

    #[test]
    fn test_grep_in_ssh_dir_blocked() {
        assert!(check("Grep", &["/home/u/.ssh"]).is_blocked());
        assert!(check("Grep", &["/home/u/.ssh/"]).is_blocked());
    }

    #[test]
    fn test_glob_for_keys_blocked() {
        assert!(check("Glob", &["/home/u", "**/id_ed25519"]).is_blocked());
        assert!(check("Glob", &["**/.ssh/*"]).is_blocked());
    }

    #[test]
    fn test_grep_ssh_config_allowed() {
        assert!(!check("Grep", &["/home/u/.ssh/config"]).is_blocked());
    }

    #[test]
    fn test_notebook_in_ssh_blocked() {
        assert!(check("NotebookEdit", &["/home/u/.ssh/config"]).is_blocked());
    }

    #[test]
    fn test_notebook_normal_allowed() {
        assert!(!check("NotebookEdit", &["analysis.ipynb"]).is_blocked());
    }

    #[test]
    fn test_grep_normal_allowed() {
        assert!(!check("Grep", &["src/", "*.rs"]).is_blocked());
    }
}
