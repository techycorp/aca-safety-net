//! Sensitive file and secrets detection.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::{CompiledConfig, SensitivePattern};
use crate::decision::{BlockInfo, Decision};
use crate::shell::{Token, split_commands, strip_wrappers, tokenize};

const ENV_TIP: &str = "Tip: .env(.*).(example|sample|template|dist) are allowed. \
    If env files hold no secrets, the user can set `[sensitive_groups] env_files = false` \
    in their aca-safety-net user config";

/// Shown for anything under ~/.ssh and for private key files.
pub const SSH_TIP: &str = "~/.ssh and SSH private keys are off-limits to agents: do not \
    read, copy, list, or pass them to any command. To connect to a host, run \
    `ssh <host-alias>` using an alias from ~/.ssh/config (which is readable, as are \
    *.pub and known_hosts). If a host needs a key that is not configured, ask the \
    user to add a Host entry to ~/.ssh/config";

/// Build a block for a sensitive pattern match. The rule ID carries the
/// pattern's group so users can see which toggle applies.
pub fn sensitive_block(rule_prefix: &str, action: &str, pattern: &SensitivePattern) -> Decision {
    let mut block = BlockInfo::new(
        format!("{}.{}", rule_prefix, pattern.group),
        format!(
            "{} sensitive file matching '{}' (group '{}')",
            action, pattern.source, pattern.group
        ),
    );
    if pattern.group == "env_files" {
        block = block.with_details(ENV_TIP);
    } else if pattern.strict {
        block = block.with_details(SSH_TIP);
    }
    Decision::Block(block)
}

/// Splits a raw command on whitespace, quotes, and shell/assignment
/// punctuation, so paths inside `-c "..."` strings, `$(...)`, `--opt=path`,
/// and redirections become separate words.
static RAW_WORD_SPLIT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"[\s;&|<>()`'"=,:{}\[\]]+"#).unwrap());

/// Block any Bash command that mentions a strict sensitive pattern (SSH keys,
/// ~/.ssh) anywhere, whatever the command. Checks both the tokenizer's words
/// (quotes resolved, so `.s''sh` becomes `.ssh`) and a punctuation split of the
/// raw command (so embedded paths are isolated from surrounding text).
pub fn check_strict_mentions(command: &str, config: &CompiledConfig) -> Decision {
    let mut words: Vec<String> = RAW_WORD_SPLIT
        .split(command)
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect();
    for segment in split_commands(command) {
        for token in tokenize(&strip_wrappers(&segment.command)) {
            match token {
                Token::Word(w) | Token::Redirect(w) => words.push(w),
                Token::Assignment(_, v) => words.push(v),
            }
        }
    }
    for word in &words {
        if let Some(pattern) = config.is_strict_sensitive(word) {
            return sensitive_block("secrets.sensitive_file", "command mentions", pattern);
        }
    }
    Decision::allow()
}

/// Check if a file path matches sensitive patterns.
pub fn check_sensitive_path(path: &str, config: &CompiledConfig) -> Decision {
    if let Some(pattern) = config.is_sensitive_path(path) {
        return sensitive_block("secrets.sensitive_file", "access to", pattern);
    }
    Decision::allow()
}

/// Check if git add is targeting sensitive files.
pub fn check_git_add_sensitive(paths: &[&str], config: &CompiledConfig) -> Decision {
    if !config.raw.git.block_add_sensitive {
        return Decision::allow();
    }

    for path in paths {
        if let Some(pattern) = config.is_sensitive_path(path) {
            return sensitive_block("git.add.sensitive", "git add on", pattern);
        }
    }

    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![
                r"\.env\b".to_string(),
                r"\.pem$".to_string(),
                r"id_rsa".to_string(),
            ],
            git: crate::config::GitConfig {
                block_add_sensitive: true,
                ..Default::default()
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_sensitive_env() {
        let config = test_config();
        let decision = check_sensitive_path(".env", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_env_local() {
        let config = test_config();
        let decision = check_sensitive_path(".env.local", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_pem() {
        let config = test_config();
        let decision = check_sensitive_path("/etc/ssl/private/server.pem", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_sensitive_ssh_key() {
        let config = test_config();
        let decision = check_sensitive_path("/home/user/.ssh/id_rsa", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_not_sensitive() {
        let config = test_config();
        let decision = check_sensitive_path("src/main.rs", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_environment_not_env() {
        let config = test_config();
        let decision = check_sensitive_path("environment.ts", &config);
        assert!(!decision.is_blocked()); // .env\b should not match environment
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let decision = check_git_add_sensitive(&[".env", "src/main.rs"], &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_normal() {
        let config = test_config();
        let decision = check_git_add_sensitive(&["src/main.rs", "Cargo.toml"], &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_block_has_tip() {
        let config = test_config();
        let decision = check_sensitive_path(".env", &config);
        let info = decision.block_info().unwrap();
        assert!(
            info.details
                .as_ref()
                .unwrap()
                .contains("example|sample|template|dist")
        );
    }

    #[test]
    fn test_pem_block_has_no_env_tip() {
        let config = test_config();
        let decision = check_sensitive_path("server.pem", &config);
        let info = decision.block_info().unwrap();
        assert!(info.details.is_none());
    }

    #[test]
    fn test_env_example_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.example", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_sample_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.sample", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_template_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.template", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_dist_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.dist", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_git_add_env_example_allowed() {
        let config = test_config();
        let decision = check_git_add_sensitive(&[".env.example"], &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_test_example_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.test.example", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_production_sample_allowed() {
        let config = test_config();
        let decision = check_sensitive_path(".env.production.sample", &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_env_test_still_blocked() {
        let config = test_config();
        let decision = check_sensitive_path(".env.test", &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_env_test_example_allowed() {
        let config = test_config();
        let decision = check_git_add_sensitive(&[".env.test.example"], &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_git_add_env_test_blocked() {
        let config = test_config();
        let decision = check_git_add_sensitive(&[".env.test"], &config);
        assert!(decision.is_blocked());
    }

    // ── .direnv cache directory (gap 5) ─────────────────────────────────────

    fn default_config() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    #[test]
    fn test_default_blocks_direnv_dir() {
        assert!(check_sensitive_path(".direnv", &default_config()).is_blocked());
    }

    #[test]
    fn test_default_blocks_direnv_cache_file() {
        assert!(
            check_sensitive_path(".direnv/python-3.12/bin/python", &default_config()).is_blocked()
        );
    }

    #[test]
    fn test_default_blocks_nested_direnv() {
        assert!(
            check_sensitive_path("/home/user/proj/.direnv/cache/foo", &default_config())
                .is_blocked()
        );
    }

    #[test]
    fn test_default_blocks_dot_direnvrc() {
        // `\bdirenvrc\b` is intentionally added so the rarely-seen
        // dotted variant `.direnvrc` is also caught — the leading `.`
        // is a non-word char so the boundary holds.
        assert!(check_sensitive_path(".direnvrc", &default_config()).is_blocked());
    }

    // ── .mise config + cache ────────────────────────────────────────────────

    #[test]
    fn test_default_blocks_mise_toml() {
        assert!(check_sensitive_path(".mise.toml", &default_config()).is_blocked());
    }

    #[test]
    fn test_default_blocks_mise_local_toml() {
        assert!(check_sensitive_path(".mise.local.toml", &default_config()).is_blocked());
    }

    #[test]
    fn test_default_blocks_mise_cache_file() {
        assert!(check_sensitive_path(".mise/cache/foo", &default_config()).is_blocked());
    }

    // ── Global / no-dot config locations ────────────────────────────────────

    #[test]
    fn test_default_blocks_mise_toml_no_dot() {
        // mise also accepts `mise.toml` (no leading dot) as project config.
        assert!(check_sensitive_path("mise.toml", &default_config()).is_blocked());
    }

    #[test]
    fn test_default_blocks_mise_global_config() {
        assert!(
            check_sensitive_path("/home/u/.config/mise/config.toml", &default_config())
                .is_blocked()
        );
    }

    #[test]
    fn test_default_blocks_mise_conf_d() {
        assert!(
            check_sensitive_path("/home/u/.config/mise/conf.d/extra.toml", &default_config())
                .is_blocked()
        );
    }

    #[test]
    fn test_default_blocks_global_direnvrc() {
        assert!(
            check_sensitive_path("/home/u/.config/direnv/direnvrc", &default_config()).is_blocked()
        );
    }

    #[test]
    fn test_default_blocks_direnv_lib() {
        assert!(
            check_sensitive_path("/home/u/.config/direnv/lib/foo.sh", &default_config())
                .is_blocked()
        );
    }

    #[test]
    fn test_default_does_not_block_promise_toml() {
        // Negative: word boundary on `\bmise\.toml\b` shouldn't match
        // a file called `promise.toml` (word chars before `mise`).
        assert!(!check_sensitive_path("promise.toml", &default_config()).is_blocked());
    }

    #[test]
    fn test_default_does_not_block_promise_dir() {
        // Negative: word boundary on `\bmise/` shouldn't match `promise/foo`.
        assert!(!check_sensitive_path("promise/foo.txt", &default_config()).is_blocked());
    }

    // ── shadowenv config dir ────────────────────────────────────────────────

    #[test]
    fn test_default_blocks_shadowenv_dir() {
        assert!(
            check_sensitive_path("/proj/.shadowenv.d/000-aaa.lisp", &default_config()).is_blocked()
        );
    }

    #[test]
    fn test_default_does_not_block_shadow_other() {
        // Negative — bare `shadow.txt` shouldn't match `\.shadowenv\.d`.
        assert!(!check_sensitive_path("shadow.txt", &default_config()).is_blocked());
    }
}
