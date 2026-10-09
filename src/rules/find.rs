//! find command analysis.
//!
//! `rm` run by `-exec`/`-execdir`/`-ok`/`-okdir` is an rm invocation and is
//! checked by the rm rule.

use crate::decision::Decision;
use crate::shell::exec_sites::ExecSites;

/// Check every place the command would run find for `-delete`.
pub fn analyze_find(sites: &ExecSites) -> Decision {
    let delete = sites
        .invocations(&["find"], &[])
        .iter()
        .any(|inv| inv.argv.iter().any(|w| w == "-delete"));
    if delete {
        return Decision::block(
            "find.delete",
            "find -delete permanently deletes matching files",
        );
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(cmd: &str) -> Decision {
        analyze_find(&ExecSites::parse(cmd))
    }

    #[test]
    fn test_find_delete() {
        for cmd in [
            "find . -name '*.tmp' -delete",
            "cd x && find . -delete",
            "sudo find / -name core -delete",
            "echo $(find . -delete)",
        ] {
            assert!(raw(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_find_safe() {
        for cmd in [
            "find . -name '*.rs' -print",
            "find . -name '*.txt' -exec cat {} ;",
            "grep -- -delete notes.md",
        ] {
            assert!(!raw(cmd).is_blocked(), "{cmd}");
        }
    }
}
