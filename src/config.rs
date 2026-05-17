//! Configuration loading and merging.

use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur when loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("invalid regex pattern '{pattern}': {source}")]
    Regex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

/// Main configuration structure.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Regex patterns matching sensitive file paths.
    pub sensitive_files: Vec<String>,

    /// Regex patterns for files that are allowed even if they match sensitive_files.
    /// For example, `.env.example` matches `\.env\b` but is safe to read.
    pub allowed_files: Vec<String>,

    /// Regex matching commands that read file content.
    pub read_commands: Option<String>,

    /// Explicit deny rules.
    pub deny: Vec<DenyRule>,

    /// Custom user-defined rules.
    #[serde(default)]
    pub rules: Vec<CustomRule>,

    /// Paranoid mode configuration.
    #[serde(default)]
    pub paranoid: ParanoidConfig,

    /// Git-specific settings.
    #[serde(default)]
    pub git: GitConfig,

    /// rm-specific settings.
    #[serde(default)]
    pub rm: RmConfig,

    /// Audit logging settings.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Dependency file protection settings.
    #[serde(default)]
    pub dependencies: DependencyConfig,
}

/// Default sensitive file patterns.
/// These patterns match files that commonly contain secrets or credentials.
const DEFAULT_SENSITIVE_FILES: &[&str] = &[
    // Environment files
    r"\.env\b",
    r"\.envrc\b",
    r"\.direnv\b",
    // Credentials
    r"credentials",
    r"secrets",
    r"\.netrc\b",
    r"\.npmrc\b",
    r"\.pypirc\b",
    // Keys and certs
    r"\.pem\b",
    r"\.key\b",
    r"id_rsa",
    r"id_ed25519",
    r"id_ecdsa",
    r"\.git-credentials",
    // Cloud configs
    r"\.kube/config",
    r"kubeconfig",
    r"\.aws/credentials",
    r"\.config/gcloud/",
    r"\.config/gh/hosts\.yml",
    // History files
    r"_history\b",
    r"\.bash_history",
    r"\.zsh_history",
];

/// Default allowed file patterns (exempt from sensitive file blocking).
/// These are well-known placeholder/template files that don't contain real secrets.
const DEFAULT_ALLOWED_FILES: &[&str] = &[
    r"\.env(\.[a-zA-Z0-9_-]+)*\.example",
    r"\.env(\.[a-zA-Z0-9_-]+)*\.sample",
    r"\.env(\.[a-zA-Z0-9_-]+)*\.template",
    r"\.env(\.[a-zA-Z0-9_-]+)*\.dist",
];

/// Default read commands that can expose file contents.
const DEFAULT_READ_COMMANDS: &[&str] = &[
    "cat", "head", "tail", "less", "more", "grep", "rg", "ag", "sed", "awk", "strings", "xxd",
    "hexdump", "bat", "view",
];

/// Default deny rules: (tool, pattern, reason)
const DEFAULT_DENY_RULES: &[(&str, &str, &str)] = &[
    // Environment exposure
    ("Bash", r"^\s*printenv", "Exposes environment variables"),
    ("Bash", r"^\s*set\s*$", "Exposes shell variables"),
    ("Bash", r"^\s*declare\s+-x", "Exposes exported variables"),
    ("Bash", r"^\s*export\s*$", "Exposes exported variables"),
    ("Bash", r"/proc/.*/environ", "Exposes process environment"),
    ("Bash", r"\bps\b.*(-E|auxe)", "Exposes process environment"),
    // History exposure
    ("Bash", r"^\s*history\b", "Exposes command history"),
    // Container environment
    (
        "Bash",
        r"\b(docker|podman)\s+(exec|run)\b.*\benv\b",
        "Exposes container environment",
    ),
    (
        "Bash",
        r"\b(docker|podman)\s+inspect\b",
        "Exposes container configuration",
    ),
    (
        "Bash",
        r"\b(docker-compose|docker\s+compose)\s+exec\b.*\benv\b",
        "Exposes container environment",
    ),
];

impl Default for Config {
    fn default() -> Self {
        Self {
            sensitive_files: DEFAULT_SENSITIVE_FILES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            allowed_files: DEFAULT_ALLOWED_FILES
                .iter()
                .map(|s| s.to_string())
                .collect(),
            read_commands: Some(format!(r"\b({})\b", DEFAULT_READ_COMMANDS.join("|"))),
            deny: DEFAULT_DENY_RULES
                .iter()
                .map(|(tool, pattern, reason)| DenyRule {
                    tool: tool.to_string(),
                    pattern: pattern.to_string(),
                    reason: reason.to_string(),
                })
                .collect(),
            rules: vec![],
            paranoid: ParanoidConfig::default(),
            git: GitConfig::default(),
            rm: RmConfig::default(),
            audit: AuditConfig::default(),
            dependencies: DependencyConfig::default(),
        }
    }
}

/// Explicit deny rule.
#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    /// Tool name to match (e.g., "Bash", "Read").
    pub tool: String,
    /// Regex pattern to match against command/path.
    pub pattern: String,
    /// Human-readable reason for blocking.
    pub reason: String,
}

/// Custom user-defined rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CustomRule {
    /// Rule name for logging.
    pub name: String,
    /// Tool name to match.
    pub tool: String,
    /// Regex pattern to match.
    pub pattern: String,
    /// Action: "block" or "allow".
    #[serde(default = "default_action")]
    pub action: String,
    /// Reason (for blocks).
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_action() -> String {
    "block".to_string()
}

/// Paranoid mode configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ParanoidConfig {
    /// Enable paranoid mode (block ANY mention of sensitive files).
    pub enabled: bool,
    /// Additional patterns for paranoid mode only.
    pub extra_patterns: Vec<String>,
}

/// Git-specific configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct GitConfig {
    /// Block destructive git commands.
    pub block_destructive: bool,
    /// Block git add on sensitive files.
    pub block_add_sensitive: bool,
    /// Allowed branches for force push (empty = block all).
    pub force_push_allowed_branches: Vec<String>,
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            block_destructive: true,
            block_add_sensitive: true,
            force_push_allowed_branches: vec![],
        }
    }
}

/// rm-specific configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RmConfig {
    /// Block rm -rf outside cwd.
    pub block_outside_cwd: bool,
    /// Allowed paths for rm -rf (in addition to cwd).
    pub allowed_paths: Vec<String>,
}

impl Default for RmConfig {
    fn default() -> Self {
        Self {
            block_outside_cwd: true,
            allowed_paths: vec!["/tmp".to_string(), "/var/tmp".to_string()],
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging.
    pub enabled: bool,
    /// Path to audit log file.
    pub path: Option<String>,
}

/// Dependency file protection configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DependencyConfig {
    /// Enable dependency file protection (requires user approval for edits).
    pub enabled: bool,
    /// Regex patterns matching dependency files.
    pub patterns: Vec<String>,
    /// Suggestion message shown to user.
    pub suggestion: Option<String>,
}

impl Default for DependencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                r"(^|/)Cargo\.toml$".to_string(),
                r"(^|/)pyproject\.toml$".to_string(),
                r"(^|/)package\.json$".to_string(),
                r"(^|/)requirements\.txt$".to_string(),
                r"(^|/)Gemfile$".to_string(),
                r"(^|/)go\.mod$".to_string(),
                r"(^|/)pom\.xml$".to_string(),
                r"(^|/)build\.gradle(\.kts)?$".to_string(),
                r"(^|/)composer\.json$".to_string(),
                r"(^|/)Package\.swift$".to_string(),
            ],
            suggestion: Some(
                "Use package manager CLI (cargo add, uv add, npm install, etc.) instead of editing directly"
                    .to_string(),
            ),
        }
    }
}

/// Compiled configuration with pre-built regexes.
pub struct CompiledConfig {
    /// The raw config.
    pub raw: Config,
    /// Compiled sensitive file patterns.
    pub sensitive_patterns: Vec<Regex>,
    /// Compiled allowed file patterns (exempt from sensitive blocking).
    pub allowed_patterns: Vec<Regex>,
    /// Compiled read commands pattern.
    pub read_commands_re: Option<Regex>,
    /// Compiled deny rules.
    pub deny_patterns: Vec<(DenyRule, Regex)>,
    /// Compiled paranoid patterns.
    pub paranoid_patterns: Vec<Regex>,
    /// Compiled dependency file patterns.
    pub dependency_patterns: Vec<Regex>,
}

impl Config {
    /// Load configuration, merging user and project configs.
    pub fn load(cwd: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = Config::default();

        // Load user config (~/.config/aca-safety-net/config.toml)
        if let Some(user_config) = Self::load_user_config()? {
            config.merge(user_config);
        }

        // Load and merge project config (.security-hook.toml in cwd)
        if let Some(cwd) = cwd
            && let Some(project_config) = Self::load_project_config(cwd)?
        {
            config.merge(project_config);
        }

        Ok(config)
    }

    /// Load user-level config from ~/.config/aca-safety-net/config.toml
    fn load_user_config() -> Result<Option<Self>, ConfigError> {
        let path = Self::user_config_path();
        if let Some(path) = path
            && path.exists()
        {
            let content = fs::read_to_string(&path)?;
            return Ok(Some(toml::from_str(&content)?));
        }
        Ok(None)
    }

    /// Load project-level config from .security-hook.toml
    fn load_project_config(cwd: &Path) -> Result<Option<Self>, ConfigError> {
        let path = cwd.join(".security-hook.toml");
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            return Ok(Some(toml::from_str(&content)?));
        }
        Ok(None)
    }

    /// Get user config path.
    /// Respects ACO_SAFETY_NET_CONFIG env var for testing.
    fn user_config_path() -> Option<PathBuf> {
        // Check for override env var first (useful for testing)
        if let Ok(path) = std::env::var("ACO_SAFETY_NET_CONFIG") {
            return Some(PathBuf::from(path));
        }
        dirs::home_dir().map(|h| h.join(".config/aca-safety-net/config.toml"))
    }

    /// Merge another config into this one (other takes precedence for scalars).
    fn merge(&mut self, other: Config) {
        // Extend arrays
        self.sensitive_files.extend(other.sensitive_files);
        self.allowed_files.extend(other.allowed_files);
        self.deny.extend(other.deny);
        self.rules.extend(other.rules);
        self.paranoid
            .extra_patterns
            .extend(other.paranoid.extra_patterns);
        self.rm.allowed_paths.extend(other.rm.allowed_paths);
        self.git
            .force_push_allowed_branches
            .extend(other.git.force_push_allowed_branches);

        // Override scalars if set in project config
        if other.read_commands.is_some() {
            self.read_commands = other.read_commands;
        }
        if other.paranoid.enabled {
            self.paranoid.enabled = true;
        }
        if other.audit.enabled {
            self.audit.enabled = true;
            if other.audit.path.is_some() {
                self.audit.path = other.audit.path;
            }
        }

        // Dependencies: if other config explicitly disables, respect that
        // This allows users to opt-out of dependency protection
        if !other.dependencies.enabled {
            self.dependencies.enabled = false;
        }
        self.dependencies
            .patterns
            .extend(other.dependencies.patterns);
        if other.dependencies.suggestion.is_some() {
            self.dependencies.suggestion = other.dependencies.suggestion;
        }
    }

    /// Compile all regex patterns for faster matching.
    pub fn compile(self) -> Result<CompiledConfig, ConfigError> {
        let sensitive_patterns = self
            .sensitive_files
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| ConfigError::Regex {
                    pattern: p.clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let allowed_patterns = self
            .allowed_files
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| ConfigError::Regex {
                    pattern: p.clone(),
                    source: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let read_commands_re = self
            .read_commands
            .as_ref()
            .map(|p| {
                Regex::new(p).map_err(|e| ConfigError::Regex {
                    pattern: p.clone(),
                    source: e,
                })
            })
            .transpose()?;

        let deny_patterns = self
            .deny
            .iter()
            .map(|rule| {
                let re = Regex::new(&rule.pattern).map_err(|e| ConfigError::Regex {
                    pattern: rule.pattern.clone(),
                    source: e,
                })?;
                Ok((rule.clone(), re))
            })
            .collect::<Result<Vec<_>, ConfigError>>()?;

        let mut paranoid_patterns = sensitive_patterns.clone();
        for p in &self.paranoid.extra_patterns {
            paranoid_patterns.push(Regex::new(p).map_err(|e| ConfigError::Regex {
                pattern: p.clone(),
                source: e,
            })?);
        }

        let dependency_patterns = if self.dependencies.enabled {
            self.dependencies
                .patterns
                .iter()
                .map(|p| {
                    Regex::new(p).map_err(|e| ConfigError::Regex {
                        pattern: p.clone(),
                        source: e,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![]
        };

        Ok(CompiledConfig {
            raw: self,
            sensitive_patterns,
            allowed_patterns,
            read_commands_re,
            deny_patterns,
            paranoid_patterns,
            dependency_patterns,
        })
    }
}

impl CompiledConfig {
    /// Check if a path matches any sensitive file pattern.
    /// Returns `None` if the path matches an allowed pattern (e.g., `.env.example`).
    pub fn is_sensitive_path(&self, path: &str) -> Option<&str> {
        // Check allowlist first — allowed files are exempt from sensitive blocking
        if self.allowed_patterns.iter().any(|re| re.is_match(path)) {
            return None;
        }

        for (i, re) in self.sensitive_patterns.iter().enumerate() {
            if re.is_match(path) {
                return Some(&self.raw.sensitive_files[i]);
            }
        }
        None
    }

    /// Check if a command is a read command.
    pub fn is_read_command(&self, command: &str) -> bool {
        self.read_commands_re
            .as_ref()
            .map(|re| re.is_match(command))
            .unwrap_or(false)
    }

    /// Check if text matches any paranoid pattern.
    pub fn matches_paranoid(&self, text: &str) -> Option<&str> {
        if !self.raw.paranoid.enabled {
            return None;
        }
        for (i, re) in self.paranoid_patterns.iter().enumerate() {
            if re.is_match(text) {
                if i < self.raw.sensitive_files.len() {
                    return Some(&self.raw.sensitive_files[i]);
                } else {
                    let extra_idx = i - self.raw.sensitive_files.len();
                    return Some(&self.raw.paranoid.extra_patterns[extra_idx]);
                }
            }
        }
        None
    }

    /// Check if a path matches any dependency file pattern.
    pub fn is_dependency_file(&self, path: &str) -> bool {
        if !self.raw.dependencies.enabled {
            return false;
        }
        self.dependency_patterns.iter().any(|re| re.is_match(path))
    }

    /// Get the suggestion message for dependency files.
    pub fn dependency_suggestion(&self) -> Option<&str> {
        self.raw.dependencies.suggestion.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        // Default should include hardcoded security patterns
        assert!(!config.sensitive_files.is_empty());
        assert!(config.sensitive_files.iter().any(|p| p.contains(".env")));
        assert!(config.sensitive_files.iter().any(|p| p.contains("id_rsa")));
        assert!(config.read_commands.is_some());
        assert!(!config.deny.is_empty());
        assert!(config.deny.iter().any(|r| r.pattern.contains("printenv")));
        assert!(!config.paranoid.enabled);
    }

    #[test]
    fn test_compile_config() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            read_commands: Some(r"\b(cat|head)\b".to_string()),
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.is_sensitive_path("environment").is_none());
        assert!(compiled.is_read_command("cat file"));
        assert!(!compiled.is_read_command("ls file"));
    }

    #[test]
    fn test_invalid_regex() {
        let config = Config {
            sensitive_files: vec!["[invalid".to_string()],
            ..Default::default()
        };
        assert!(config.compile().is_err());
    }

    #[test]
    fn test_paranoid_mode() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            paranoid: ParanoidConfig {
                enabled: true,
                extra_patterns: vec![r"secret".to_string()],
            },
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(compiled.matches_paranoid("cat .env").is_some());
        assert!(compiled.matches_paranoid("echo secret").is_some());
        assert!(compiled.matches_paranoid("ls").is_none());
    }

    #[test]
    fn test_default_allowed_files() {
        let config = Config::default();
        assert!(!config.allowed_files.is_empty());
        assert!(config.allowed_files.iter().any(|p| p.contains("example")));
        assert!(config.allowed_files.iter().any(|p| p.contains("sample")));
        assert!(config.allowed_files.iter().any(|p| p.contains("template")));
        assert!(config.allowed_files.iter().any(|p| p.contains("dist")));
    }

    #[test]
    fn test_allowed_files_bypass_sensitive() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        // .env itself should still be blocked
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.is_sensitive_path(".env.local").is_some());
        // But allowed variants should pass
        assert!(compiled.is_sensitive_path(".env.example").is_none());
        assert!(compiled.is_sensitive_path(".env.sample").is_none());
        assert!(compiled.is_sensitive_path(".env.template").is_none());
        assert!(compiled.is_sensitive_path(".env.dist").is_none());
    }

    #[test]
    fn test_allowed_files_with_path_prefix() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(
            compiled
                .is_sensitive_path("/project/.env.example")
                .is_none()
        );
        assert!(compiled.is_sensitive_path("src/.env.sample").is_none());
    }

    #[test]
    fn test_allowed_files_with_extra_segments() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        // .env.test should still be blocked (no safe suffix)
        assert!(compiled.is_sensitive_path(".env.test").is_some());
        assert!(compiled.is_sensitive_path(".env.production").is_some());
        // But safe suffixes with extra segments should pass
        assert!(compiled.is_sensitive_path(".env.test.example").is_none());
        assert!(
            compiled
                .is_sensitive_path(".env.production.sample")
                .is_none()
        );
        assert!(
            compiled
                .is_sensitive_path(".env.staging.template")
                .is_none()
        );
        assert!(compiled.is_sensitive_path(".env.local.dist").is_none());
        // Multiple extra segments
        assert!(
            compiled
                .is_sensitive_path(".env.test.local.example")
                .is_none()
        );
        // With path prefix
        assert!(
            compiled
                .is_sensitive_path("/project/.env.test.example")
                .is_none()
        );
        // Hyphens and underscores in segments
        assert!(
            compiled
                .is_sensitive_path(".env.staging-v2.example")
                .is_none()
        );
        assert!(
            compiled
                .is_sensitive_path(".env.test_local.sample")
                .is_none()
        );
    }
}
