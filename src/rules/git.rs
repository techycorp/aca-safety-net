//! Git command analysis.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

/// Subcommands with checks, for the `<unknown-cmd> ... git sub` heuristic.
const SUBCOMMANDS: &[&str] = &[
    "checkout", "reset", "push", "branch", "stash", "clean", "add",
];

/// Global options before the subcommand that take a separate value.
const GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
];

/// Check every place the command would run git, including nested and
/// wrapped forms.
pub fn analyze_git(sites: &ExecSites, config: &CompiledConfig) -> Decision {
    for inv in sites.invocations(&["git"], SUBCOMMANDS) {
        let words: Vec<&str> = inv.argv.iter().map(String::as_str).collect();
        let decision = analyze_git_words(&words, config);
        if decision.is_blocked() {
            return decision;
        }
    }
    Decision::allow()
}

/// `words` are the arguments after `git`.
fn analyze_git_words(words: &[&str], config: &CompiledConfig) -> Decision {
    let mut i = 0;
    while let Some(w) = words.get(i).filter(|w| w.starts_with('-')) {
        i += if GLOBAL_VALUE_FLAGS.contains(w) { 2 } else { 1 };
    }
    let Some(&subcommand) = words.get(i) else {
        return Decision::allow();
    };
    let args = &words[i + 1..];

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

/// Whether a short option `-c` is given, alone or in a cluster like `-fd`.
fn has_short(args: &[&str], c: char) -> bool {
    args.iter()
        .any(|a| a.len() > 1 && a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
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
    if has_short(args, 'f') || args.contains(&"--force") {
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
        *a == "--force" || *a == "--force-with-lease" || a.starts_with("--force-with-lease=")
    }) || has_short(args, 'f');

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
    let delete = has_short(args, 'd') || args.contains(&"--delete");
    let force = has_short(args, 'f') || args.contains(&"--force");
    if has_short(args, 'D') || (delete && force) {
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
    if has_short(args, 'f') || args.contains(&"--force") {
        // Extra dangerous with -d (directories) or -x (ignored files)
        if has_short(args, 'd') || has_short(args, 'x') || has_short(args, 'X') {
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
            return super::sensitive_files::sensitive_block(
                "git.add.sensitive",
                "git add on",
                pattern,
            );
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
        let decision = analyze_git(&ExecSites::parse("git checkout -- file.txt"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_reset_hard() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git reset --hard HEAD~1"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_push_force_main() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git push -f origin main"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_push_force_allowed_branch() {
        let config = test_config();
        let decision = analyze_git(
            &ExecSites::parse("git push -f origin feature-test"),
            &config,
        );
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_git_branch_delete() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git branch -D feature"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_stash_drop() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git stash drop"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_sensitive() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git add .env"), &config);
        assert!(decision.is_blocked());
    }

    #[test]
    fn test_git_add_normal() {
        let config = test_config();
        let decision = analyze_git(&ExecSites::parse("git add src/main.rs"), &config);
        assert!(!decision.is_blocked());
    }

    #[test]
    fn test_global_flags_and_nesting() {
        let config = test_config();
        for cmd in [
            "git -C repo reset --hard",
            "git -c core.x=y --no-pager reset --hard",
            "cd x\ngit reset --hard",
            "echo $(git stash clear)",
            "bash -lc 'git push --force origin main'",
            "/usr/bin/git clean -fd",
            "git push -fu origin main",
            "git branch -d -f feature",
            "git checkout -qf main",
        ] {
            assert!(
                analyze_git(&ExecSites::parse(cmd), &config).is_blocked(),
                "{cmd}"
            );
        }
        for cmd in [
            "git -C repo status",
            "git commit -m 'avoid git reset --hard'",
            "grep 'git push -f' notes.md",
        ] {
            assert!(
                !analyze_git(&ExecSites::parse(cmd), &config).is_blocked(),
                "{cmd}"
            );
        }
    }
}
