//! Git command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::Token;

/// Analyze a git command for dangerous operations.
pub fn analyze_git(tokens: &[Token], config: &CompiledConfig) -> Decision {
    let words: Vec<&str> = tokens
        .iter()
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.as_str()),
            _ => None,
        })
        .collect();

    if words.len() < 2 {
        return Decision::allow();
    }

    let subcommand = words[1];
    let args = &words[2..];

    match subcommand {
        "checkout" => analyze_git_checkout(args, config),
        "reset" => analyze_git_reset(args, config),
        "push" => analyze_git_push(args, config),
        "branch" => analyze_git_branch(args, config),
        "stash" => analyze_git_stash(args, config),
        "clean" => analyze_git_clean(args, config),
        "add" => analyze_git_add(args, config),
        _ => Decision::allow(),
    }
}

fn analyze_git_checkout(args: &[&str], _config: &CompiledConfig) -> Decision {
    // Block: git checkout -- <paths> (discards changes)
    if args.contains(&"--") {
        return Decision::block(
            "git.checkout",
            "git checkout -- discards uncommitted changes",
        );
    }

    // Block: git checkout -f / --force
    if args.contains(&"-f") || args.contains(&"--force") {
        return Decision::block(
            "git.checkout.force",
            "git checkout --force discards uncommitted changes",
        );
    }

    Decision::allow()
}

fn analyze_git_reset(args: &[&str], _config: &CompiledConfig) -> Decision {
    // Block: git reset --hard
    if args.contains(&"--hard") {
        return Decision::block(
            "git.reset.hard",
            "git reset --hard discards all uncommitted changes",
        );
    }

    Decision::allow()
}

fn analyze_git_push(args: &[&str], config: &CompiledConfig) -> Decision {
    // Check for force push
    let is_force = args.iter().any(|a| {
        *a == "-f"
            || *a == "--force"
            || *a == "--force-with-lease"
            || a.starts_with("--force-with-lease=")
    });

    if !is_force {
        return Decision::allow();
    }

    // Find the branch being pushed
    // git push [remote] [branch] or git push -f origin main
    let mut remote = None;
    let mut branch = None;
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            // Skip option arguments
            if matches!(*arg, "-u" | "--set-upstream" | "-o" | "--push-option") {
                skip_next = true;
            }
            continue;
        }
        if remote.is_none() {
            remote = Some(*arg);
        } else if branch.is_none() {
            branch = Some(*arg);
        }
    }

    // Block force push to main/master unless explicitly allowed
    let target_branch = branch.unwrap_or("HEAD");
    let protected_branches = ["main", "master", "develop", "release"];

    // Check if branch is in allowed list
    if config
        .raw
        .git
        .force_push_allowed_branches
        .iter()
        .any(|b| b == target_branch)
    {
        return Decision::allow();
    }

    // Block protected branches
    if protected_branches.contains(&target_branch) {
        return Decision::block(
            "git.push.force",
            format!(
                "force push to protected branch '{}' is blocked",
                target_branch
            ),
        );
    }

    // Allow force push to other branches
    Decision::allow()
}

fn analyze_git_branch(args: &[&str], _config: &CompiledConfig) -> Decision {
    // Block: git branch -D (force delete)
    if args.contains(&"-D") {
        // Find branch name
        let branch = args.iter().find(|a| !a.starts_with('-'));
        return Decision::block(
            "git.branch.force_delete",
            format!(
                "git branch -D force-deletes branch{}",
                branch.map(|b| format!(" '{}'", b)).unwrap_or_default()
            ),
        );
    }

    Decision::allow()
}

fn analyze_git_stash(args: &[&str], _config: &CompiledConfig) -> Decision {
    if args.is_empty() {
        return Decision::allow();
    }

    match args[0] {
        "drop" => Decision::block(
            "git.stash.drop",
            "git stash drop permanently deletes stashed changes",
        ),
        "clear" => Decision::block(
            "git.stash.clear",
            "git stash clear deletes ALL stashed changes",
        ),
        _ => Decision::allow(),
    }
}

fn analyze_git_clean(args: &[&str], _config: &CompiledConfig) -> Decision {
    // git clean -f is required to actually clean, but still dangerous
    if args.contains(&"-f") || args.contains(&"--force") {
        // Extra dangerous with -d (directories) or -x (ignored files)
        if args.contains(&"-d") || args.contains(&"-x") || args.contains(&"-X") {
            return Decision::block(
                "git.clean.force",
                "git clean -fd/-fx permanently deletes untracked files/directories",
            );
        }
        return Decision::block(
            "git.clean",
            "git clean -f permanently deletes untracked files",
        );
    }

    Decision::allow()
}

fn analyze_git_add(args: &[&str], config: &CompiledConfig) -> Decision {
    if !config.raw.git.block_add_sensitive {
        return Decision::allow();
    }

    for arg in args {
        if arg.starts_with('-') {
            continue;
        }

        // Check if path matches sensitive pattern
        if let Some(pattern) = config.is_sensitive_path(arg) {
            let mut block = crate::decision::BlockInfo::new(
                "git.add.sensitive",
                format!("git add on sensitive file matching '{}'", pattern),
            );
            if pattern.contains(r"\.env") {
                block =
                    block.with_details("Tip: .env(.*).(example|sample|template|dist) are allowed");
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
    use crate::shell::tokenize;

    fn test_config() -> CompiledConfig {
        Config {
            sensitive_files: vec![r"\.env\b".to_string()],
            git: crate::config::GitConfig {
                block_destructive: true,
                block_add_sensitive: true,
                force_push_allowed_branches: vec!["feature-test".to_string()],
            },
            ..Default::default()
        }
        .compile()
        .unwrap()
    }

    #[test]
    fn test_git_checkout_discard() {
        let config = test_config();
        let tokens = tokenize("git checkout -- file.txt");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_reset_hard() {
        let config = test_config();
        let tokens = tokenize("git reset --hard HEAD~1");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_push_force_main() {
        let config = test_config();
        let tokens = tokenize("git push -f origin main");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_push_force_allowed_branch() {
        let config = test_config();
        let tokens = tokenize("git push -f origin feature-test");
        let decision = analyze_git(&tokens, &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_git_branch_delete() {
        let config = test_config();
        let tokens = tokenize("git branch -D feature");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_stash_drop() {
        let config = test_config();
        let tokens = tokenize("git stash drop");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let tokens = tokenize("git add .env");
        let decision = analyze_git(&tokens, &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_normal() {
        let config = test_config();
        let tokens = tokenize("git add src/main.rs");
        let decision = analyze_git(&tokens, &config);
        assert!(!decision.is_blocked());
    }
}
