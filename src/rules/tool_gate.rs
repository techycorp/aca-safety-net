//! Config-driven relaxation for env-loading tool analyzers.
//!
//! Each gated tool is blocked by default. The user config can disable the
//! block entirely (`[tools.<name>] enabled = false`) or allow specific
//! subcommands (`allow_subcommands`). A subcommand only counts when it parses
//! cleanly; anything ambiguous stays blocked, so there is no way to disable
//! the catch-all block short of disabling the tool.

use regex::Regex;

use crate::config::CompiledConfig;

/// One occurrence of a tool word in a raw command.
pub struct RawOccurrence<'a> {
    /// The identifier-like token after the tool word, used for the reason.
    pub captured: Option<&'a str>,
    /// `captured`, but only when it is followed by whitespace or end of
    /// input. `mise env)` or `mise "env"` yield `None`.
    pub clean: Option<&'a str>,
}

/// Find every occurrence of a tool word in a raw command. `re` must capture
/// the following subcommand token in group 1.
pub fn raw_occurrences<'a>(re: &Regex, raw: &'a str) -> Vec<RawOccurrence<'a>> {
    re.captures_iter(raw)
        .map(|caps| {
            let captured = caps.get(1);
            let clean = captured.filter(|m| {
                raw[m.end()..]
                    .chars()
                    .next()
                    .is_none_or(|c| c.is_whitespace())
            });
            RawOccurrence {
                captured: captured.map(|m| m.as_str()),
                clean: clean.map(|m| m.as_str()),
            }
        })
        .collect()
}

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

    fn re() -> Regex {
        Regex::new(r"\bfoo\b(?:\s+([A-Za-z0-9_-]+))?").unwrap()
    }

    #[test]
    fn test_clean_capture() {
        let occ = raw_occurrences(&re(), "foo install");
        assert_eq!(occ[0].clean, Some("install"));
    }

    #[test]
    fn test_capture_followed_by_paren_not_clean() {
        let occ = raw_occurrences(&re(), "echo $(foo env)");
        assert_eq!(occ[0].captured, Some("env"));
        assert_eq!(occ[0].clean, None);
    }

    #[test]
    fn test_quoted_subcommand_not_captured() {
        let occ = raw_occurrences(&re(), r#"foo "env""#);
        assert_eq!(occ[0].captured, None);
        assert_eq!(occ[0].clean, None);
    }

    #[test]
    fn test_all_occurrences() {
        let occ = raw_occurrences(&re(), "foo install && foo env");
        assert_eq!(occ.len(), 2);
        assert_eq!(occ[1].clean, Some("env"));
    }

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
