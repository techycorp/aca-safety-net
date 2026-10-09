//! Bash tool analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::input::BashInput;
use crate::rules::{
    analyze_command, check_custom_rules, check_sensitive_path, check_ssh_bash_write,
    check_strict_mentions,
};
use crate::shell::{Token, split_commands, strip_wrappers, tokenize};

/// Analyze a Bash tool invocation.
pub fn analyze_bash(input: &BashInput, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    let command = &input.command;

    // 1. Check explicit deny rules
    for (rule, re) in &config.deny_patterns {
        if rule.tool == "Bash" && re.is_match(command) {
            return Decision::block(&rule.reason, &rule.reason);
        }
    }

    // 2. Check custom rules
    let custom_decision = check_custom_rules("Bash", command, config);
    if custom_decision.is_blocked() {
        return custom_decision;
    }

    // 3. Paranoid mode check
    if let Some(pattern) = config.matches_paranoid(command) {
        return Decision::block(
            "paranoid.sensitive_mention",
            format!("command mentions sensitive pattern '{}'", pattern),
        );
    }

    // 4. Check read commands + sensitive files
    // Only check when the actual command (first word) is a read command
    let segments = split_commands(command);
    for segment in &segments {
        let stripped = strip_wrappers(&segment.command);
        let tokens = tokenize(&stripped);

        // Get the command name (first word)
        let cmd_name = tokens.iter().find_map(|t| match t {
            Token::Word(w) if !w.starts_with('-') => Some(w.as_str()),
            _ => None,
        });

        // Only check sensitive files if this segment starts with a read command
        if let Some(cmd) = cmd_name
            && config.is_read_command(cmd)
        {
            // Check all words that look like paths
            for token in &tokens {
                if let Token::Word(word) = token {
                    // Skip if it looks like an option
                    if word.starts_with('-') {
                        continue;
                    }
                    // Check if it matches sensitive pattern
                    let decision = check_sensitive_path(word, config);
                    if decision.is_blocked() {
                        return decision;
                    }
                }
            }
        }
    }

    // 5. Built-in rules for every place the command runs a program
    let decision = analyze_command(command, config, cwd);
    if decision.is_blocked() {
        return decision;
    }

    let decision = check_strict_mentions(command, config);
    if decision.is_blocked() {
        return decision;
    }

    check_ssh_bash_write(command, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, DenyRule, ParanoidConfig};

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![r"\.env\b".to_string(), r"id_rsa".to_string()],
            read_commands: Some(r"\b(cat|head|tail|grep)\b".to_string()),
            deny: vec![DenyRule {
                tool: "Bash".to_string(),
                pattern: r"^printenv".to_string(),
                reason: "Exposes environment variables".to_string(),
            }],
            paranoid: ParanoidConfig {
                enabled: false,
                extra_patterns: vec![],
            },
            git: crate::config::GitConfig {
                block_add_sensitive: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    fn paranoid_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            paranoid: ParanoidConfig {
                enabled: true,
                extra_patterns: vec![],
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_deny_rule() {
        let config = test_config();
        let input = BashInput {
            command: "printenv PATH".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_read_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "cat .env".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_grep_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "grep password ~/.ssh/id_rsa".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_paranoid_mode() {
        let config = paranoid_config();
        let input = BashInput {
            command: "ls .env".to_string(), // Not a read command, but mentions .env
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let input = BashInput {
            command: "git add .env".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_safe_command() {
        let config = test_config();
        let input = BashInput {
            command: "ls -la".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_cat_normal_file() {
        let config = test_config();
        let input = BashInput {
            command: "cat src/main.rs".to_string(),
            timeout: None,
            description: None,
        };
        let decision = analyze_bash(&input, &config, None);
        assert!(!decision.is_blocked());
    }
}
