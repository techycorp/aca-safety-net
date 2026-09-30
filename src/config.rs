//! Configuration loading and merging.

use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeMap;
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
    /// Extra regex patterns matching sensitive file paths, on top of the
    /// enabled built-in groups in `SENSITIVE_GROUPS`.
    pub sensitive_files: Vec<String>,

    /// Per-group toggles for the built-in sensitive file patterns.
    /// Missing groups are enabled unless the active profile disables them.
    /// Honored from user config only.
    pub sensitive_groups: BTreeMap<String, bool>,

    /// Per-tool settings for env-loading tool analyzers (see
    /// `CONFIGURABLE_TOOLS`). Honored from user config only.
    pub tools: BTreeMap<String, ToolConfig>,

    /// Named preset of group/tool toggles (see `PROFILES`).
    /// Honored from user config only.
    pub profile: Option<String>,

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

    /// Non-fatal config problems collected during load and compile.
    #[serde(skip)]
    pub warnings: Vec<String>,
}

/// Built-in sensitive file patterns, grouped so each group can be toggled
/// via `[sensitive_groups]`.
pub const SENSITIVE_GROUPS: &[(&str, &[&str])] = &[
    ("env_files", &[r"\.env\b", r"\.envrc\b"]),
    ("direnv", &[r"\.direnv\b", r"\bdirenvrc\b", r"\bdirenv/"]),
    ("mise", &[r"\.mise\b", r"\bmise\.toml\b", r"\bmise/"]),
    ("shadowenv", &[r"\.shadowenv\.d\b"]),
    (
        "credentials",
        &[
            r"credentials",
            r"secrets",
            r"\.netrc\b",
            r"\.npmrc\b",
            r"\.pypirc\b",
            r"\.git-credentials",
        ],
    ),
    (
        "keys",
        &[
            r"\.pem\b",
            r"\.key\b",
            r"id_rsa",
            r"id_ed25519",
            r"id_ecdsa",
        ],
    ),
    (
        "cloud",
        &[
            r"\.kube/config",
            r"kubeconfig",
            r"\.aws/credentials",
            r"\.config/gcloud/",
            r"\.config/gh/hosts\.yml",
        ],
    ),
    (
        "history",
        &[r"_history\b", r"\.bash_history", r"\.zsh_history"],
    ),
];

/// Group name reported for patterns from the user's `sensitive_files`.
pub const USER_GROUP: &str = "user";

/// Tools whose analyzers can be relaxed via `[tools.<name>]`.
/// `infisical` and `env`/`printenv` are intentionally absent.
pub const CONFIGURABLE_TOOLS: &[&str] = &["direnv", "mise", "shadowenv"];

/// A named preset of disabled groups and tools.
pub struct Profile {
    pub name: &'static str,
    pub disabled_groups: &'static [&'static str],
    pub disabled_tools: &'static [&'static str],
}

/// Built-in profiles. `secretless` is for setups where secrets are injected
/// at runtime (e.g. `infisical run`) and env files hold no secrets.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "default",
        disabled_groups: &[],
        disabled_tools: &[],
    },
    Profile {
        name: "secretless",
        disabled_groups: &["env_files", "direnv", "mise", "shadowenv"],
        disabled_tools: &["direnv", "mise", "shadowenv"],
    },
];

fn find_profile(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

fn builtin_group_of(pattern: &str) -> Option<&'static str> {
    SENSITIVE_GROUPS
        .iter()
        .find(|(_, patterns)| patterns.contains(&pattern))
        .map(|(name, _)| *name)
}

/// Paths of the hook's own config files, protected from agent writes.
const CONFIG_FILE_PATH_RE: &str = r"(\.security-hook\.toml|\.config/aca-safety-net/config\.toml)";

const CONFIG_FILE_REASON: &str = "Modifies aca-safety-net config; ask the user to edit it";

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
    // Environment exposure — `env`, `printenv`, `gprintenv` are handled by
    // the env analyzer (src/rules/env.rs) which catches them anywhere in
    // the command, not just anchored at start.
    ("Bash", r"^\s*set\s*$", "Exposes shell variables"),
    ("Bash", r"^\s*declare\s+-x", "Exposes exported variables"),
    ("Bash", r"^\s*export\s*$", "Exposes exported variables"),
    ("Bash", r"/proc/.*/environ", "Exposes process environment"),
    ("Bash", r"\bps\b.*(-E|auxe)", "Exposes process environment"),
    // History exposure
    ("Bash", r"^\s*history\b", "Exposes command history"),
    // Self-protection: agents must not rewrite the hook's own config
    ("Edit", CONFIG_FILE_PATH_RE, CONFIG_FILE_REASON),
    ("Write", CONFIG_FILE_PATH_RE, CONFIG_FILE_REASON),
    (
        "Bash",
        r"(>|\b(tee|cp|mv|ln|install|rsync|dd|truncate|perl)\b|\bsed\b.*\s-i).*(\.security-hook\.toml|\.config/aca-safety-net/config\.toml)",
        CONFIG_FILE_REASON,
    ),
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
            sensitive_files: vec![],
            sensitive_groups: BTreeMap::new(),
            tools: BTreeMap::new(),
            profile: None,
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
            warnings: vec![],
        }
    }
}

/// Settings for one env-loading tool analyzer.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ToolConfig {
    /// When false, the tool's analyzer allows every invocation.
    pub enabled: bool,
    /// Subcommands allowed while the tool is otherwise blocked.
    pub allow_subcommands: Vec<String>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_subcommands: vec![],
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

/// A compiled sensitive file pattern and the group it came from.
pub struct SensitivePattern {
    /// The regex source, as configured.
    pub source: String,
    /// Built-in group name, or `USER_GROUP` for user extras.
    pub group: &'static str,
    pub re: Regex,
}

/// Compiled configuration with pre-built regexes.
pub struct CompiledConfig {
    /// The raw config.
    pub raw: Config,
    /// Compiled sensitive file patterns (enabled built-in groups + user extras).
    pub sensitive_patterns: Vec<SensitivePattern>,
    /// Compiled allowed file patterns (exempt from sensitive blocking).
    pub allowed_patterns: Vec<Regex>,
    /// Compiled read commands pattern.
    pub read_commands_re: Option<Regex>,
    /// Compiled deny rules.
    pub deny_patterns: Vec<(DenyRule, Regex)>,
    /// Compiled paranoid patterns, keyed by their source.
    pub paranoid_patterns: Vec<(String, Regex)>,
    /// Compiled dependency file patterns.
    pub dependency_patterns: Vec<Regex>,
    /// Non-fatal config problems, surfaced on stderr by the binary.
    pub warnings: Vec<String>,
}

fn compile_regex(pattern: &str) -> Result<Regex, ConfigError> {
    Regex::new(pattern).map_err(|e| ConfigError::Regex {
        pattern: pattern.to_string(),
        source: e,
    })
}

impl Config {
    /// Load configuration, merging user and project configs.
    pub fn load(cwd: Option<&Path>) -> Result<Self, ConfigError> {
        let mut config = Config::default();

        // Load user config (~/.config/aca-safety-net/config.toml)
        if let Some(user_config) = Self::load_user_config()? {
            config.merge_user(user_config);
        }

        // Load and merge project config (.security-hook.toml in cwd)
        if let Some(cwd) = cwd
            && let Some(project_config) = Self::load_project_config(cwd)?
        {
            config.merge_project(project_config);
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

    /// Merge the user config. The user config may relax protections.
    fn merge_user(&mut self, other: Config) {
        self.sensitive_groups.extend(other.sensitive_groups.clone());
        self.tools.extend(other.tools.clone());
        if other.profile.is_some() {
            self.profile = other.profile.clone();
        }
        self.merge(other);
    }

    /// Merge a project config (`.security-hook.toml`). Project config lives in
    /// the repo the agent is working in, so it may only tighten: relaxing
    /// settings are dropped with a warning.
    fn merge_project(&mut self, mut other: Config) {
        let defaults = Config::default();
        let mut ignored = vec![];

        if !other.sensitive_groups.is_empty() {
            ignored.push("sensitive_groups");
        }
        if !other.tools.is_empty() {
            ignored.push("tools");
        }
        if other.profile.is_some() {
            ignored.push("profile");
        }
        if other.allowed_files != defaults.allowed_files {
            ignored.push("allowed_files");
        }
        other.allowed_files = vec![];
        if other.read_commands != defaults.read_commands {
            ignored.push("read_commands");
        }
        other.read_commands = None;
        if !other.dependencies.enabled {
            ignored.push("dependencies.enabled");
            other.dependencies.enabled = true;
        }
        if other.rm.allowed_paths != defaults.rm.allowed_paths {
            ignored.push("rm.allowed_paths");
        }
        other.rm.allowed_paths = vec![];
        if !other.git.force_push_allowed_branches.is_empty() {
            ignored.push("git.force_push_allowed_branches");
            other.git.force_push_allowed_branches = vec![];
        }

        if !ignored.is_empty() {
            self.warnings.push(format!(
                ".security-hook.toml can only tighten protections; ignored: {}",
                ignored.join(", ")
            ));
        }
        self.merge(other);
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
    pub fn compile(mut self) -> Result<CompiledConfig, ConfigError> {
        let mut warnings = std::mem::take(&mut self.warnings);
        warnings.extend(self.validate());

        let mut sensitive_patterns = vec![];
        for (group, patterns) in SENSITIVE_GROUPS {
            if !self.sensitive_group_enabled(group) {
                continue;
            }
            for p in *patterns {
                sensitive_patterns.push(SensitivePattern {
                    source: p.to_string(),
                    group,
                    re: compile_regex(p)?,
                });
            }
        }
        for p in &self.sensitive_files {
            if let Some(group) = builtin_group_of(p) {
                if self.sensitive_group_enabled(group) {
                    continue;
                }
                warnings.push(format!(
                    "sensitive_files entry '{}' duplicates built-in group '{}', which is \
                     disabled; it stays blocked until removed from sensitive_files",
                    p, group
                ));
            }
            sensitive_patterns.push(SensitivePattern {
                source: p.clone(),
                group: USER_GROUP,
                re: compile_regex(p)?,
            });
        }

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

        let mut paranoid_patterns: Vec<(String, Regex)> = sensitive_patterns
            .iter()
            .map(|p| (p.source.clone(), p.re.clone()))
            .collect();
        for p in &self.paranoid.extra_patterns {
            paranoid_patterns.push((p.clone(), compile_regex(p)?));
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
            warnings,
        })
    }

    /// Report unknown group, tool, and profile names. Unknown names are
    /// ignored (protection stays on) rather than erroring, because a config
    /// error makes the hook fail open.
    fn validate(&self) -> Vec<String> {
        let mut warnings = vec![];
        for name in self.sensitive_groups.keys() {
            if !SENSITIVE_GROUPS.iter().any(|(g, _)| g == name) {
                warnings.push(format!(
                    "unknown sensitive_groups entry '{}'; ignored",
                    name
                ));
            }
        }
        for name in self.tools.keys() {
            if !CONFIGURABLE_TOOLS.contains(&name.as_str()) {
                warnings.push(format!("tools.{} is not configurable; ignored", name));
            }
        }
        if let Some(name) = &self.profile
            && find_profile(name).is_none()
        {
            warnings.push(format!("unknown profile '{}'; ignored", name));
        }
        warnings
    }

    fn active_profile(&self) -> Option<&'static Profile> {
        self.profile.as_deref().and_then(find_profile)
    }

    /// Whether a built-in sensitive group is enabled. An explicit
    /// `[sensitive_groups]` entry wins over the profile.
    pub fn sensitive_group_enabled(&self, group: &str) -> bool {
        if let Some(enabled) = self.sensitive_groups.get(group) {
            return *enabled;
        }
        !self
            .active_profile()
            .is_some_and(|p| p.disabled_groups.contains(&group))
    }

    /// Effective settings for a configurable tool. An explicit `[tools.<name>]`
    /// entry wins over the profile. Non-configurable tools always get the
    /// default (fully blocked) settings.
    pub fn tool_config(&self, tool: &str) -> ToolConfig {
        if !CONFIGURABLE_TOOLS.contains(&tool) {
            return ToolConfig::default();
        }
        if let Some(cfg) = self.tools.get(tool) {
            return cfg.clone();
        }
        let disabled = self
            .active_profile()
            .is_some_and(|p| p.disabled_tools.contains(&tool));
        ToolConfig {
            enabled: !disabled,
            allow_subcommands: vec![],
        }
    }
}

impl CompiledConfig {
    /// Check if a path matches any sensitive file pattern.
    /// Returns `None` if the path matches an allowed pattern (e.g., `.env.example`).
    pub fn is_sensitive_path(&self, path: &str) -> Option<&SensitivePattern> {
        // Check allowlist first — allowed files are exempt from sensitive blocking
        if self.allowed_patterns.iter().any(|re| re.is_match(path)) {
            return None;
        }

        self.sensitive_patterns.iter().find(|p| p.re.is_match(path))
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
        self.paranoid_patterns
            .iter()
            .find(|(_, re)| re.is_match(text))
            .map(|(source, _)| source.as_str())
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
        // Built-in patterns live in groups, not in the user extras list
        assert!(config.sensitive_files.is_empty());
        let compiled = config.clone().compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.is_sensitive_path("/home/u/.ssh/id_rsa").is_some());
        assert!(config.read_commands.is_some());
        assert!(!config.deny.is_empty());
        // `set` (with no args) is still a deny-rule entry; printenv moved
        // to the env analyzer (src/rules/env.rs).
        assert!(config.deny.iter().any(|r| r.pattern.contains("set")));
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

    // ── Sensitive groups ────────────────────────────────────────────────────

    fn with_groups(groups: &[(&str, bool)]) -> Config {
        let mut config = Config::default();
        for (g, v) in groups {
            config.sensitive_groups.insert(g.to_string(), *v);
        }
        config
    }

    #[test]
    fn test_every_group_enabled_by_default() {
        let config = Config::default();
        for (group, _) in SENSITIVE_GROUPS {
            assert!(config.sensitive_group_enabled(group), "{}", group);
        }
    }

    #[test]
    fn test_default_block_reports_group() {
        let compiled = Config::default().compile().unwrap();
        assert_eq!(
            compiled.is_sensitive_path(".envrc").unwrap().group,
            "env_files"
        );
        assert_eq!(
            compiled.is_sensitive_path("server.pem").unwrap().group,
            "keys"
        );
    }

    #[test]
    fn test_env_files_group_off() {
        let compiled = with_groups(&[("env_files", false)]).compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_none());
        assert!(compiled.is_sensitive_path(".env.local").is_none());
        assert!(compiled.is_sensitive_path(".envrc").is_none());
        // Other groups unaffected
        assert!(compiled.is_sensitive_path(".direnv/cache").is_some());
        assert!(compiled.is_sensitive_path("id_rsa").is_some());
        assert!(compiled.is_sensitive_path(".aws/credentials").is_some());
    }

    #[test]
    fn test_each_group_off_only_affects_itself() {
        for (group, patterns) in SENSITIVE_GROUPS {
            let config = with_groups(&[(group, false)]);
            let compiled = config.compile().unwrap();
            assert!(
                compiled
                    .sensitive_patterns
                    .iter()
                    .all(|p| p.group != *group),
                "{}",
                group
            );
            let enabled_count: usize = SENSITIVE_GROUPS
                .iter()
                .filter(|(g, _)| g != group)
                .map(|(_, p)| p.len())
                .sum();
            assert_eq!(compiled.sensitive_patterns.len(), enabled_count);
            assert!(!patterns.is_empty());
        }
    }

    #[test]
    fn test_unknown_group_warns_and_keeps_protection() {
        let compiled = with_groups(&[("env_file", false)]).compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.warnings.iter().any(|w| w.contains("env_file")));
    }

    #[test]
    fn test_duplicate_of_disabled_group_warns_and_stays_blocked() {
        let mut config = with_groups(&[("env_files", false)]);
        config.sensitive_files = vec![r"\.env\b".to_string()];
        let compiled = config.compile().unwrap();
        let hit = compiled.is_sensitive_path(".env").unwrap();
        assert_eq!(hit.group, USER_GROUP);
        assert!(compiled.warnings.iter().any(|w| w.contains("duplicates")));
    }

    #[test]
    fn test_duplicate_of_enabled_group_is_silent() {
        let config = Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            ..Default::default()
        };
        let compiled = config.compile().unwrap();
        assert!(compiled.warnings.is_empty());
        assert_eq!(
            compiled.is_sensitive_path(".env").unwrap().group,
            "env_files"
        );
    }

    // ── Profiles and tools ──────────────────────────────────────────────────

    #[test]
    fn test_secretless_profile() {
        let config = Config {
            profile: Some("secretless".to_string()),
            ..Default::default()
        };
        assert!(!config.sensitive_group_enabled("env_files"));
        assert!(!config.sensitive_group_enabled("mise"));
        assert!(config.sensitive_group_enabled("keys"));
        assert!(!config.tool_config("mise").enabled);
        assert!(config.tool_config("infisical").enabled);
        let compiled = config.compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_none());
        assert!(compiled.is_sensitive_path("id_ed25519").is_some());
    }

    #[test]
    fn test_explicit_keys_override_profile() {
        let mut config = with_groups(&[("env_files", true)]);
        config.profile = Some("secretless".to_string());
        config.tools.insert(
            "mise".to_string(),
            ToolConfig {
                enabled: true,
                allow_subcommands: vec!["install".to_string()],
            },
        );
        assert!(config.sensitive_group_enabled("env_files"));
        assert!(config.tool_config("mise").enabled);
        assert!(!config.tool_config("direnv").enabled);
    }

    #[test]
    fn test_unknown_profile_and_tool_warn() {
        let mut config = Config {
            profile: Some("yolo".to_string()),
            ..Default::default()
        };
        config.tools.insert(
            "infisical".to_string(),
            ToolConfig {
                enabled: false,
                allow_subcommands: vec![],
            },
        );
        assert!(config.tool_config("infisical").enabled);
        let compiled = config.compile().unwrap();
        assert!(compiled.warnings.iter().any(|w| w.contains("yolo")));
        assert!(
            compiled
                .warnings
                .iter()
                .any(|w| w.contains("tools.infisical"))
        );
        assert!(compiled.is_sensitive_path(".env").is_some());
    }

    #[test]
    fn test_toml_shape() {
        let config: Config = toml::from_str(
            r#"
profile = "secretless"
[sensitive_groups]
env_files = true
[tools.mise]
allow_subcommands = ["install"]
"#,
        )
        .unwrap();
        assert_eq!(config.profile.as_deref(), Some("secretless"));
        assert!(config.sensitive_group_enabled("env_files"));
        let mise = config.tool_config("mise");
        assert!(mise.enabled);
        assert_eq!(mise.allow_subcommands, vec!["install"]);
    }

    // ── User vs project merge ───────────────────────────────────────────────

    fn project(toml_src: &str) -> Config {
        let mut base = Config::default();
        base.merge_project(toml::from_str(toml_src).unwrap());
        base
    }

    #[test]
    fn test_project_cannot_relax() {
        let merged = project(
            r#"
profile = "secretless"
allowed_files = ['.*']
read_commands = 'nothing'
[sensitive_groups]
env_files = false
[tools.mise]
enabled = false
[dependencies]
enabled = false
[rm]
allowed_paths = ['/']
[git]
force_push_allowed_branches = ['main']
"#,
        );
        assert!(merged.sensitive_group_enabled("env_files"));
        assert!(merged.tool_config("mise").enabled);
        assert!(merged.dependencies.enabled);
        assert!(!merged.rm.allowed_paths.contains(&"/".to_string()));
        assert!(merged.git.force_push_allowed_branches.is_empty());
        assert_eq!(merged.read_commands, Config::default().read_commands);
        let compiled = merged.compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_some());
        assert!(compiled.is_read_command("cat"));
        let warning = &compiled.warnings[0];
        for key in [
            "sensitive_groups",
            "tools",
            "profile",
            "allowed_files",
            "read_commands",
        ] {
            assert!(warning.contains(key), "{}", key);
        }
    }

    #[test]
    fn test_project_can_tighten() {
        let merged = project(
            r#"
sensitive_files = ['internal-token']
[paranoid]
enabled = true
"#,
        );
        assert!(merged.warnings.is_empty());
        let compiled = merged.compile().unwrap();
        assert!(compiled.is_sensitive_path("internal-token.txt").is_some());
        assert!(compiled.raw.paranoid.enabled);
    }

    #[test]
    fn test_user_can_relax() {
        let mut base = Config::default();
        base.merge_user(
            toml::from_str(
                r#"
[sensitive_groups]
env_files = false
"#,
            )
            .unwrap(),
        );
        let compiled = base.compile().unwrap();
        assert!(compiled.is_sensitive_path(".env").is_none());
        assert!(compiled.warnings.is_empty());
    }

    // ── Self-protection ─────────────────────────────────────────────────────

    #[test]
    fn test_config_files_protected() {
        let compiled = Config::default().compile().unwrap();
        let denied = |tool: &str, text: &str| {
            compiled
                .deny_patterns
                .iter()
                .any(|(r, re)| r.tool == tool && re.is_match(text))
        };
        assert!(denied("Edit", "/home/u/.config/aca-safety-net/config.toml"));
        assert!(denied("Write", "/repo/.security-hook.toml"));
        assert!(denied(
            "Bash",
            "echo 'profile = \"x\"' >> ~/.config/aca-safety-net/config.toml"
        ));
        assert!(denied("Bash", "sed -i '' 's/a/b/' .security-hook.toml"));
        assert!(denied("Bash", "cp /tmp/x .security-hook.toml"));
        // The repo's example config is not the installed one
        assert!(!denied("Edit", "/home/u/src/aca-safety-net/config.toml"));
        assert!(!denied("Bash", "cat .security-hook.toml"));
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
