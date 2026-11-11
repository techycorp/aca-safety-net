//! `ps` analysis — block forms that print other processes' environments.
//!
//! A process started under `infisical run` (or any secret injector) holds its
//! secrets in its environment, and `ps` will print that environment for any
//! process owned by the same user:
//!
//! - `-E` (macOS) in a dashed option group: `ps -E`, `ps -Eww -p 123`.
//! - `e` in a dash-less BSD option group: `ps eww`, `ps axe`, `ps auxe`
//!   (macOS and Linux procps both honour it).
//!
//! Dashed `-e` means "all processes" on both macOS and Linux, so `ps -e` and
//! `ps -ef` stay allowed. Values of options that take an argument
//! (`-o pid,etime`, `-u user`) are skipped, so an `e` in them doesn't count.

use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

const RULE: &str = "ps.environment";
const REASON: &str = "ps with -E or a dash-less `e` option prints process environments, \
     which hold injected secrets";

/// Dashed short options whose value may be the next word.
const DASHED_TAKES_VALUE: &str = "oOpUuGgtkCqMNW";
/// Dash-less BSD options whose value may be the next word.
const BSD_TAKES_VALUE: &str = "oOptUk";

/// Check every place the command would run ps.
pub fn analyze_ps(sites: &ExecSites) -> Decision {
    let shows_env = sites
        .invocations(&["ps"], &[])
        .iter()
        .any(|inv| argv_shows_env(&inv.argv));
    if shows_env {
        return Decision::block(RULE, REASON);
    }
    Decision::allow()
}

fn argv_shows_env(argv: &[String]) -> bool {
    let mut skip_value = false;
    for word in argv {
        if skip_value {
            skip_value = false;
            continue;
        }
        if word == "--" {
            break;
        }
        if word.starts_with("--") {
            continue;
        }
        if let Some(group) = word.strip_prefix('-') {
            if let Some(letters) = option_letters(group, DASHED_TAKES_VALUE) {
                if letters.0.contains('E') {
                    return true;
                }
                skip_value = letters.1;
            }
            continue;
        }
        if let Some(letters) = option_letters(word, BSD_TAKES_VALUE) {
            if letters.0.contains('e') {
                return true;
            }
            skip_value = letters.1;
        }
    }
    false
}

/// The option letters of a group, up to the first one that takes a value,
/// and whether that value is the next word. `None` if the group isn't
/// letters (a pid, a path, a `$var`).
fn option_letters<'a>(group: &'a str, takes_value: &str) -> Option<(&'a str, bool)> {
    if group.is_empty() || !group.chars().next()?.is_ascii_alphabetic() {
        return None;
    }
    for (i, c) in group.char_indices() {
        if takes_value.contains(c) {
            let rest = &group[i + c.len_utf8()..];
            return Some((&group[..i + c.len_utf8()], rest.is_empty()));
        }
        if !c.is_ascii_alphabetic() {
            return None;
        }
    }
    Some((group, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_ps(&ExecSites::parse(cmd))
    }

    #[test]
    fn test_ps_env_forms_blocked() {
        for cmd in [
            "ps -E",
            "ps -Eww -p 123",
            "ps -ww -E -p 123",
            "ps -axE",
            "ps eww 123",
            "ps eww -p 123",
            "ps e",
            "ps axe",
            "ps auxe",
            "ps auxww e",
            "ps -p 123 e",
            "ps -o pid,command -E",
            "/bin/ps eww 123",
            "sudo ps axe",
            "cd /tmp && ps eww $(pgrep -f uvicorn)",
            "ps axe | grep uvicorn",
            "echo $(ps -E -p 1)",
            r#"bash -c "ps eww 123""#,
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_ps_safe_forms_allowed() {
        for cmd in [
            "ps",
            "ps aux",
            "ps auxww",
            "ps -e",
            "ps -ef",
            "ps -ax",
            "ps -o pid,etime,command -p 123",
            "ps -eo pid,etime",
            "ps axo pid,etime,command",
            "ps -u venky",
            "ps -U venky",
            "ps -p 123",
            "ps 123",
            "ps -ww -p 123",
            "pgrep -fl uvicorn",
            "grep -E pattern steps.txt",
            "echo ps eww",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_ps_reason() {
        let d = raw("ps eww 1");
        assert_eq!(d.block_info().unwrap().rule, "ps.environment");
    }
}
