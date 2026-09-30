//! SSH analysis: human-only key management commands and explicit key
//! selection.
//!
//! `ssh-add`, `ssh-keygen`, and `ssh-copy-id` manage keys and are left to the
//! user. Agents connect with `ssh <host-alias>` and let `~/.ssh/config` or
//! ssh-agent pick the key, so `-i` / `IdentityFile` are blocked too. All of
//! this is governed by the `ssh` sensitive group.

use once_cell::sync::Lazy;
use regex::Regex;

use crate::config::CompiledConfig;
use crate::decision::{BlockInfo, Decision};
use crate::shell::{Token, tokenize};

use super::sensitive_files::SSH_TIP;

const GROUP: &str = "ssh";

/// Key management commands anywhere in the command, including inside
/// `$(...)`, quotes, and path-prefixed forms.
static HUMAN_ONLY_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?:^|[\s;&|(`'"/])(ssh-add|ssh-keygen|ssh-copy-id)\b"#).unwrap());

/// An ssh command set through an env var or git config that picks a key.
static SSH_COMMAND_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(GIT_SSH_COMMAND|RSYNC_RSH|core\.sshCommand)\b.*(\s-\w*i\b|IdentityFile)")
        .unwrap()
});

/// A Bash write, move, copy, or delete that targets something under `.ssh`.
static SSH_WRITE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)(>|\b(tee|cp|mv|ln|install|rsync|dd|truncate|rm|chmod|chown|perl)\b|\bsed\b.*\s-i)[^;&|]*\.ssh\b",
    )
    .unwrap()
});

/// Any path under `.ssh`, for Edit/Write-style tools.
static SSH_PATH_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\.ssh\b").unwrap());

fn ssh_write_block() -> Decision {
    Decision::Block(
        BlockInfo::new(
            "ssh.write",
            "changing anything under ~/.ssh (including config and authorized_keys) is a human-only operation",
        )
        .with_details(
            "Do not modify it or work around it. Ask the user to make the change \
             themselves, and show them the exact lines to add if helpful",
        ),
    )
}

/// Block Edit/Write-style tools from modifying anything under `.ssh`. The
/// readable exceptions (config, authorized_keys, ...) are not writable: a
/// config entry can run commands and an authorized_keys entry grants access.
pub fn check_ssh_write(path: &str, config: &CompiledConfig) -> Decision {
    if config.raw.sensitive_group_enabled(GROUP) && SSH_PATH_RE.is_match(path) {
        return ssh_write_block();
    }
    Decision::allow()
}

/// ssh/scp/sftp options that take an argument. `i` and `o` are handled
/// separately.
const OPTS_WITH_ARG: &str = "BbcDEeFIJLlmOPpQRSsWw";

const IDENTITY_RULE: &str = "ssh.identity";
const IDENTITY_REASON: &str = "choosing an SSH key directly (-i / IdentityFile) is not allowed";

fn identity_block() -> Decision {
    Decision::Block(BlockInfo::new(IDENTITY_RULE, IDENTITY_REASON).with_details(SSH_TIP))
}

fn human_only_block(cmd: &str) -> Decision {
    Decision::Block(
        BlockInfo::new(
            "ssh.human_only",
            format!("`{}` manages SSH keys and is a human-only operation", cmd),
        )
        .with_details(format!(
            "Do not run it or work around it. Ask the user to run it themselves, \
             e.g. by typing `! {} ...` in the prompt",
            cmd
        )),
    )
}

/// Raw-command analysis: human-only commands and key-selecting ssh commands
/// set via env var or git config.
pub fn analyze_ssh_raw(raw_command: &str, config: &CompiledConfig) -> Decision {
    if !config.raw.sensitive_group_enabled(GROUP) {
        return Decision::allow();
    }
    if let Some(caps) = HUMAN_ONLY_RE.captures(raw_command) {
        return human_only_block(&caps[1]);
    }
    if SSH_COMMAND_KEY_RE.is_match(raw_command) {
        return identity_block();
    }
    Decision::allow()
}

/// Block Bash commands that write, move, copy, or delete under `.ssh`. Runs
/// after the key-mention check so reads of keys get the key message.
pub fn check_ssh_bash_write(raw_command: &str, config: &CompiledConfig) -> Decision {
    if config.raw.sensitive_group_enabled(GROUP) && SSH_WRITE_RE.is_match(raw_command) {
        return ssh_write_block();
    }
    Decision::allow()
}

/// Per-segment analysis: `-i` / `-o IdentityFile` on ssh, scp, and sftp, and
/// the same inside rsync's `-e` / `--rsh`.
pub fn analyze_ssh_segment(tokens: &[Token], config: &CompiledConfig) -> Decision {
    if !config.raw.sensitive_group_enabled(GROUP) {
        return Decision::allow();
    }
    // Leading assignments are env vars; later ones are arguments such as
    // `IdentityFile=key` that the tokenizer splits into name and value.
    let owned: Vec<String> = tokens
        .iter()
        .skip_while(|t| matches!(t, Token::Assignment(_, _)))
        .filter_map(|t| match t {
            Token::Word(w) => Some(w.clone()),
            Token::Assignment(k, v) => Some(format!("{}={}", k, v)),
            Token::Redirect(_) => None,
        })
        .collect();
    let words: Vec<&str> = owned.iter().map(String::as_str).collect();
    let Some(cmd) = words.first() else {
        return Decision::allow();
    };
    let selects_key = match cmd.rsplit('/').next().unwrap_or(cmd) {
        "ssh" | "scp" | "sftp" => ssh_args_select_key(&words[1..]),
        "rsync" => rsync_selects_key(&words[1..]),
        _ => false,
    };
    if selects_key {
        identity_block()
    } else {
        Decision::allow()
    }
}

fn is_identity_option(value: &str) -> bool {
    value.to_ascii_lowercase().starts_with("identityfile")
}

/// Scan ssh-style options. Options may follow the destination
/// (`ssh host -i key`), so scanning continues past the first operand and
/// stops at the second, where the remote command starts.
fn ssh_args_select_key(args: &[&str]) -> bool {
    let mut i = 0;
    let mut operands = 0;
    while i < args.len() {
        let arg = args[i];
        if arg == "--" {
            return false;
        }
        if !arg.starts_with('-') || arg.len() < 2 {
            operands += 1;
            if operands > 1 {
                return false;
            }
            i += 1;
            continue;
        }
        let flags: Vec<char> = arg[1..].chars().collect();
        for (pos, c) in flags.iter().enumerate() {
            let rest: String = flags[pos + 1..].iter().collect();
            if *c == 'i' {
                return true;
            }
            if *c == 'o' {
                let value = if rest.is_empty() {
                    i += 1;
                    args.get(i).copied().unwrap_or("")
                } else {
                    rest.as_str()
                };
                if is_identity_option(value) {
                    return true;
                }
                break;
            }
            if OPTS_WITH_ARG.contains(*c) {
                if rest.is_empty() {
                    i += 1;
                }
                break;
            }
        }
        i += 1;
    }
    false
}

fn rsync_selects_key(args: &[&str]) -> bool {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let rsh = if *arg == "-e" || *arg == "--rsh" {
            iter.next().copied()
        } else {
            arg.strip_prefix("--rsh=")
                .or_else(|| arg.strip_prefix("-e"))
        };
        if let Some(rsh) = rsh.filter(|r| !r.is_empty()) {
            let words: Vec<String> = tokenize(rsh)
                .into_iter()
                .filter_map(|t| match t {
                    Token::Word(w) => Some(w),
                    _ => None,
                })
                .collect();
            let refs: Vec<&str> = words.iter().map(String::as_str).collect();
            if refs.len() > 1 && ssh_args_select_key(&refs[1..]) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    fn cfg_ssh_off() -> CompiledConfig {
        let mut config = Config::default();
        config.sensitive_groups.insert("ssh".to_string(), false);
        config.compile().unwrap()
    }

    fn seg(cmd: &str) -> Decision {
        analyze_ssh_segment(&tokenize(cmd), &cfg())
    }

    // ── Human-only commands ─────────────────────────────────────────────────

    #[test]
    fn test_human_only_commands_blocked() {
        for cmd in [
            "ssh-add",
            "ssh-add -l",
            "ssh-keygen -t ed25519",
            "ssh-copy-id host",
            "/usr/bin/ssh-add -D",
            "echo $(ssh-keygen -y -f k)",
            r#"bash -c "ssh-add""#,
            "cd /tmp && ssh-keygen -R host",
        ] {
            let d = analyze_ssh_raw(cmd, &cfg());
            assert_eq!(d.block_info().unwrap().rule, "ssh.human_only", "{}", cmd);
        }
    }

    #[test]
    fn test_human_only_message_asks_user() {
        let d = analyze_ssh_raw("ssh-add -l", &cfg());
        let info = d.block_info().unwrap();
        assert!(info.reason.contains("ssh-add"));
        assert!(info.details.as_ref().unwrap().contains("Ask the user"));
    }

    #[test]
    fn test_keyscan_allowed() {
        assert!(!analyze_ssh_raw("ssh-keyscan github.com", &cfg()).is_blocked());
    }

    #[test]
    fn test_plain_ssh_allowed() {
        assert!(!analyze_ssh_raw("ssh prod-box uptime", &cfg()).is_blocked());
        assert!(!seg("ssh prod-box uptime").is_blocked());
        assert!(!seg("ssh -p 2222 -l deploy prod-box").is_blocked());
        assert!(!seg("scp -P 2222 file prod-box:/tmp/").is_blocked());
    }

    // ── Key selection ───────────────────────────────────────────────────────

    #[test]
    fn test_identity_flag_blocked() {
        for cmd in [
            "ssh -i key host",
            "ssh -ikey host",
            "ssh -vi key host",
            "ssh -p 22 -i key host",
            "ssh host -i key",
            "ssh -o IdentityFile=key host",
            "ssh -oIdentityFile=key host",
            "ssh -o identityfile key host",
            "scp -i key f host:/tmp",
            "sftp -i key host",
            "/usr/bin/ssh -i key host",
            "rsync -e 'ssh -i key' a host:b",
            "rsync --rsh='ssh -i key' a host:b",
        ] {
            let d = seg(cmd);
            assert_eq!(
                d.block_info().map(|i| i.rule.as_str()),
                Some(IDENTITY_RULE),
                "{}",
                cmd
            );
        }
    }

    #[test]
    fn test_remote_command_flags_ignored() {
        // -i after the host belongs to the remote command
        assert!(!seg("ssh host grep -i error /var/log/syslog").is_blocked());
        assert!(!seg("ssh -p 22 host -- sed -i s/a/b/ f").is_blocked());
        // rsync's own -i is --itemize-changes
        assert!(!seg("rsync -ai src/ host:dst/").is_blocked());
    }

    #[test]
    fn test_ssh_command_env_blocked() {
        for cmd in [
            "GIT_SSH_COMMAND='ssh -i key' git push",
            "git -c core.sshCommand='ssh -i key' fetch",
            "RSYNC_RSH='ssh -o IdentityFile=key' rsync a b:c",
        ] {
            let d = analyze_ssh_raw(cmd, &cfg());
            assert_eq!(d.block_info().unwrap().rule, IDENTITY_RULE, "{}", cmd);
        }
        assert!(!analyze_ssh_raw("GIT_SSH_COMMAND='ssh -v' git fetch", &cfg()).is_blocked());
    }

    #[test]
    fn test_identity_block_explains_alias() {
        let info = seg("ssh -i key host").block_info().unwrap().clone();
        assert!(info.details.unwrap().contains("ssh <host-alias>"));
    }

    // ── Writes under ~/.ssh ─────────────────────────────────────────────────

    #[test]
    fn test_bash_writes_blocked() {
        for cmd in [
            "echo 'Host x' >> ~/.ssh/config",
            "echo key >> ~/.ssh/authorized_keys",
            "cat k.pub | tee -a ~/.ssh/authorized_keys",
            "sed -i '' 's/a/b/' ~/.ssh/config",
            "rm ~/.ssh/known_hosts",
            "cp /tmp/cfg ~/.ssh/config",
            "chmod 644 ~/.SSH/id_rsa",
        ] {
            let d = check_ssh_bash_write(cmd, &cfg());
            assert_eq!(d.block_info().unwrap().rule, "ssh.write", "{}", cmd);
        }
    }

    #[test]
    fn test_bash_reads_of_config_not_write_blocked() {
        assert!(!check_ssh_bash_write("cat ~/.ssh/config", &cfg()).is_blocked());
        assert!(!check_ssh_bash_write("grep Host ~/.ssh/config", &cfg()).is_blocked());
        assert!(!check_ssh_bash_write("cat ~/.ssh/config > /tmp/x", &cfg()).is_blocked());
    }

    #[test]
    fn test_edit_write_paths() {
        assert!(check_ssh_write("/home/u/.ssh/config", &cfg()).is_blocked());
        assert!(check_ssh_write("/home/u/.ssh/authorized_keys", &cfg()).is_blocked());
        assert!(!check_ssh_write("src/ssh_client.rs", &cfg()).is_blocked());
        assert!(!check_ssh_write("/home/u/.ssh/config", &cfg_ssh_off()).is_blocked());
    }

    // ── Group toggle ────────────────────────────────────────────────────────

    #[test]
    fn test_group_off_allows() {
        let c = cfg_ssh_off();
        assert!(!analyze_ssh_raw("ssh-add -l", &c).is_blocked());
        assert!(!analyze_ssh_segment(&tokenize("ssh -i key host"), &c).is_blocked());
    }
}
