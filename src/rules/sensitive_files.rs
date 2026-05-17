//! Sensitive file and secrets detection.

use crate::config::CompiledConfig;
use crate::decision::{BlockInfo, Decision};

const ENV_TIP: &str = "Tip: .env(.*).(example|sample|template|dist) are allowed";

/// Check if a file path matches sensitive patterns.
pub fn check_sensitive_path(path: &str, config: &CompiledConfig) -> Decision {
    if let Some(pattern) = config.is_sensitive_path(path) {
        let mut block = BlockInfo::new(
            "secrets.sensitive_file",
            format!("access to sensitive file matching '{}'", pattern),
        );
        if pattern.contains(r"\.env") {
            block = block.with_details(ENV_TIP);
        }
        return Decision::Block(block);
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
            let mut block = BlockInfo::new(
                "git.add.sensitive",
                format!("git add on sensitive file matching '{}'", pattern),
            );
            if pattern.contains(r"\.env") {
                block = block.with_details(ENV_TIP);
            }
            return Decision::Block(block);
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
}
