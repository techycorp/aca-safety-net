//! rm command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::exec_sites::{ExecSites, Invocation, SiteKind};
use std::path::Path;

/// Check every place the command would run rm, including `$()`, code
/// strings, and commands run by `xargs`, `find -exec` and `parallel`.
pub fn analyze_rm(sites: &ExecSites, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    for inv in sites.invocations(&["rm"], &[]) {
        let decision = analyze_rm_invocation(&inv, config, cwd);
        if decision.is_blocked() {
            return decision;
        }
    }
    Decision::allow()
}

/// Targets supplied at runtime can't be checked, so any such rm is blocked.
fn unknown_targets(inv: &Invocation) -> bool {
    inv.open || inv.kind == SiteKind::Exact || inv.argv.iter().any(|w| w.contains("{}"))
}

fn analyze_rm_invocation(inv: &Invocation, config: &CompiledConfig, cwd: Option<&str>) -> Decision {
    if unknown_targets(inv) {
        return Decision::block(
            "rm.unknown_targets",
            "rm with targets supplied at runtime (xargs, find -exec, parallel) can delete arbitrary files",
        );
    }
    let words: Vec<&str> = std::iter::once("rm")
        .chain(inv.argv.iter().map(String::as_str))
        .collect();

    // Check for recursive flag (force flag tracked for future use)
    let mut has_recursive = false;
    let mut paths = Vec::new();

    for word in &words[1..] {
        if word.starts_with('-') && !word.starts_with("--") {
            // Short options
            if word.contains('r') || word.contains('R') {
                has_recursive = true;
            }
            // Note: -f (force) tracked but not currently used for blocking decisions
        } else if *word == "-r" || *word == "-R" || *word == "--recursive" {
            has_recursive = true;
        } else if *word == "-f" || *word == "--force" {
            // Force flag - not currently blocking on its own
        } else if *word == "--" {
            // Everything after -- is a path
            continue;
        } else if !word.starts_with('-') {
            paths.push(*word);
        }
    }

    // Only check paths if rm -rf or rm -r
    if !has_recursive {
        return Decision::allow();
    }

    // Check each path
    for path in &paths {
        if let Some(decision) = check_rm_path(path, config, cwd) {
            return decision;
        }
    }

    Decision::allow()
}

fn check_rm_path(path: &str, config: &CompiledConfig, cwd: Option<&str>) -> Option<Decision> {
    // Normalize path for analysis
    let path_obj = Path::new(path);

    // Check for obviously dangerous paths
    let dangerous_paths = [
        "/", "/home", "/etc", "/usr", "/var", "/root", "/boot", "/sys", "/proc",
    ];

    // Get canonical-ish path (without actually resolving symlinks)
    let normalized = if path_obj.is_absolute() {
        path.to_string()
    } else if let Some(cwd) = cwd {
        Path::new(cwd).join(path).to_string_lossy().to_string()
    } else {
        path.to_string()
    };

    // Block rm -rf on root or system directories
    for dangerous in &dangerous_paths {
        if normalized == *dangerous
            || normalized.starts_with(&format!("{}/", dangerous))
                && normalized.len() <= dangerous.len() + 2
        {
            return Some(Decision::block(
                "rm.dangerous_path",
                format!("rm -rf on system path '{}' is blocked", path),
            ));
        }
    }

    // Block any path starting with .. (parent escape) - always dangerous
    if path.starts_with("..") {
        return Some(Decision::block(
            "rm.parent_escape",
            format!("rm -rf with parent traversal '{}' is blocked", path),
        ));
    }

    // Check if path is outside cwd (if cwd is known)
    if config.raw.rm.block_outside_cwd
        && let Some(cwd) = cwd
        && !is_path_within(path, cwd, &config.raw.rm.allowed_paths)
    {
        return Some(Decision::block(
            "rm.outside_cwd",
            format!("rm -rf outside working directory: '{}'", path),
        ));
    }

    None
}

fn is_path_within(path: &str, cwd: &str, allowed_paths: &[String]) -> bool {
    let path_obj = Path::new(path);

    // Absolute path check
    if path_obj.is_absolute() {
        // Check if under cwd
        if path.starts_with(cwd) {
            return true;
        }

        // Check allowed paths (like /tmp)
        for allowed in allowed_paths {
            if path.starts_with(allowed.as_str()) {
                return true;
            }
        }

        return false;
    }

    // Relative path - check for parent traversal
    let components: Vec<&str> = path.split('/').collect();
    let mut depth: i32 = 0;

    for component in components {
        match component {
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false; // Escaped cwd
                }
            }
            "." | "" => {}
            _ => depth += 1,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> CompiledConfig {
        Config {
            rm: crate::config::RmConfig {
                block_outside_cwd: true,
                allowed_paths: vec!["/tmp".to_string()],
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_rm_rf_root() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf /"),
            &config,
            Some("/home/user/project"),
        );
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_rm_rf_home() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf /home"),
            &config,
            Some("/home/user/project"),
        );
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_rm_rf_outside_cwd() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf /var/log"),
            &config,
            Some("/home/user/project"),
        );
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_rm_rf_in_cwd() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf build/"),
            &config,
            Some("/home/user/project"),
        );
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_rm_rf_tmp() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf /tmp/cache"),
            &config,
            Some("/home/user/project"),
        );
        assert!(!decision.is_blocked()); // /tmp is allowed
    }

    #[test]
    fn test_rm_rf_parent_escape() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm -rf ../../.."),
            &config,
            Some("/home/user/project"),
        );
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_rm_no_recursive() {
        let config = test_config();
        let decision = analyze_rm(
            &ExecSites::parse("rm /etc/passwd"),
            &config,
            Some("/home/user/project"),
        );
        assert!(!decision.is_blocked()); // Not recursive
    }

    fn rule(cmd: &str) -> Option<String> {
        analyze_rm(
            &ExecSites::parse(cmd),
            &test_config(),
            Some("/home/user/project"),
        )
        .block_info()
        .map(|i| i.rule.clone())
    }

    #[test]
    fn test_runtime_targets_blocked() {
        for cmd in [
            "xargs rm",
            "xargs rm -rf",
            "xargs -I {} rm {}",
            "find . -name '*.log' -exec rm {} ;",
            "find . -name '*.log' -exec rm {} +",
            "find . -name '*.tmp' -execdir rm {} \\;",
            "find . -name '*.tmp' -ok rm {} ;",
            "find . -exec /bin/rm {} +",
            "parallel rm {}",
            "parallel rm -rf {}",
            "parallel rm ::: a b",
            "ls | xargs sudo rm",
        ] {
            assert_eq!(rule(cmd).as_deref(), Some("rm.unknown_targets"), "{cmd}");
        }
    }

    #[test]
    fn test_nested_and_wrapped() {
        for cmd in [
            "cd x && rm -rf /",
            "echo ok\nrm -rf /etc",
            "echo $(rm -rf /)",
            "bash -lc 'rm -rf /'",
            "sudo /bin/rm -rf /",
            "RM -rf /",
            r#"python -c 'import os; os.system("rm -rf /")'"#,
        ] {
            assert!(rule(cmd).is_some(), "{cmd}");
        }
    }

    #[test]
    fn test_safe_allowed() {
        for cmd in [
            "rm file.txt",
            "rm -rf build/",
            "xargs cat",
            "xargs -I {} echo {}",
            "parallel echo {}",
            "parallel gzip {}",
            "find . -name '*.txt' -exec cat {} ;",
            "grep 'rm -rf /' notes.md",
        ] {
            assert_eq!(rule(cmd), None, "{cmd}");
        }
    }
}
