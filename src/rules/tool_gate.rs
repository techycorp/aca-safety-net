//! Config-driven relaxation for env-loading tool analyzers.
//!
//! Each gated tool is blocked by default. The user config can disable the
//! block entirely (`[tools.<name>] enabled = false`) or allow specific
//! subcommands (`allow_subcommands`). A subcommand only counts when it parses
//! cleanly; anything ambiguous stays blocked, so there is no way to disable
//! the catch-all block short of disabling the tool.

use crate::config::CompiledConfig;

/// The subcommand of a tokenized segment, if it is a plain word.
pub fn segment_subcommand<'a>(words: &[&'a str]) -> Option<&'a str> {
    words.get(1).copied().filter(|w| !w.starts_with('-'))
}

/// Whether the config allows this invocation of `tool`.
pub fn allows(tool: &str, subcommand: Option<&str>, config: &CompiledConfig) -> bool {
    let tool_config = config.raw.tool_config(tool);
    if !tool_config.enabled {
        return true;
    }
    subcommand.is_some_and(|s| tool_config.allow_subcommands.iter().any(|a| a == s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, ToolConfig};

    #[test]
    fn test_segment_subcommand_skips_flags() {
        assert_eq!(segment_subcommand(&["foo", "--cd"]), None);
        assert_eq!(segment_subcommand(&["foo", "ls"]), Some("ls"));
    }

    fn cfg_with(tool: &str, tc: ToolConfig) -> CompiledConfig {
        let mut config = Config::default();
        config.tools.insert(tool.to_string(), tc);
        config.compile().unwrap()
    }

    #[test]
    fn test_default_blocks() {
        let config = Config::default().compile().unwrap();
        assert!(!allows("mise", Some("install"), &config));
    }

    #[test]
    fn test_disabled_allows_all() {
        let config = cfg_with(
            "mise",
            ToolConfig {
                enabled: false,
                allow_subcommands: vec![],
            },
        );
        assert!(allows("mise", None, &config));
        assert!(allows("mise", Some("env"), &config));
    }

    #[test]
    fn test_allowlist() {
        let config = cfg_with(
            "mise",
            ToolConfig {
                enabled: true,
                allow_subcommands: vec!["install".to_string()],
            },
        );
        assert!(allows("mise", Some("install"), &config));
        assert!(!allows("mise", Some("env"), &config));
        assert!(!allows("mise", None, &config));
    }

    #[test]
    fn test_non_configurable_tool_ignored() {
        let config = cfg_with(
            "infisical",
            ToolConfig {
                enabled: false,
                allow_subcommands: vec![],
            },
        );
        assert!(!allows("infisical", Some("run"), &config));
    }
}
