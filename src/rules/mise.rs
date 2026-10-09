//! mise analysis - blocks the mise subcommands that can expose secrets.
//!
//! mise loads per-directory environment from `mise.toml`, `.mise.local.toml`
//! and `.env` files, which routinely hold secrets. Subcommands that print
//! that environment, print tokens, or run commands or tasks with it loaded
//! are blocked. Everything else (installing and listing tools, etc.) is
//! allowed. Unknown subcommands are blocked because `mise <name>` runs the
//! task of that name.
//!
//! The subcommand lists match `mise --help` for mise 2026.10.3.

use crate::config::CompiledConfig;
use crate::decision::Decision;
use crate::shell::exec_sites::{ExecSites, Invocation, SiteKind};

use super::tool_gate;

const TOOL: &str = "mise";

/// Subcommands that never print environment values, tokens or task bodies,
/// and don't run commands with the environment loaded. Canonical names.
const SAFE_SUBCOMMANDS: &[&str] = &[
    "activate",
    "backends",
    "bin-paths",
    "cache",
    "completion",
    "deactivate",
    "fmt",
    "help",
    "implode",
    "install",
    "install-into",
    "latest",
    "link",
    "lock",
    "ls",
    "ls-remote",
    "outdated",
    "packslip",
    "patrons",
    "plugins",
    "prune",
    "registry",
    "reshim",
    "search",
    "self-update",
    "shell",
    "shell-alias",
    "skills",
    "sponsors",
    "sync",
    "tool",
    "tool-alias",
    "trust",
    "uninstall",
    "unset",
    "untrust",
    "unuse",
    "upgrade",
    "use",
    "version",
    "where",
    "which",
];

/// Sensitive subcommands as written, for spotting `<unknown wrapper> mise <subcommand>`.
const SUBCOMMANDS: &[&str] = &[
    "env", "e", "hook-env", "exec", "x", "en", "run", "r", "watch", "w", "tasks", "task", "t",
    "set", "ev", "env-vars", "config", "cfg", "toml", "token", "mcp",
];

/// Global flags that take a value.
const GLOBAL_VALUE_FLAGS: &[&str] = &["-C", "--cd", "-E", "--env", "-j", "--jobs"];

/// Global flags without a value.
const GLOBAL_FLAGS: &[&str] = &[
    "-q",
    "--quiet",
    "-v",
    "-vv",
    "--verbose",
    "-y",
    "--yes",
    "--no-config",
    "--no-env",
    "--no-hooks",
    "--raw",
    "--locked",
    "--silent",
];

fn canonical(sub: &str) -> &str {
    match sub {
        "e" => "env",
        "x" => "exec",
        "r" => "run",
        "w" => "watch",
        "t" | "task" => "tasks",
        "cfg" | "toml" => "config",
        "ev" | "env-vars" => "set",
        "sh" => "shell",
        "b" | "backend" | "backend-list" => "backends",
        "complete" | "completions" => "completion",
        "dr" => "doctor",
        "gen" | "g" => "generate",
        "i" => "install",
        "ln" => "link",
        "list" => "ls",
        "list-all" | "list-remote" => "ls-remote",
        "p" | "plugin" | "plugin-list" => "plugins",
        "bs" => "bootstrap",
        "daemon" => "daemons",
        "dep" | "prepare" => "deps",
        "dot" => "dotfiles",
        "skill" => "skills",
        "alias" | "aliases" => "tool-alias",
        "rm" | "remove" => "unuse",
        "up" => "upgrade",
        "u" => "use",
        "v" => "version",
        other => other,
    }
}

/// What the words after `mise` say about its subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Subcommand {
    /// A subcommand, by canonical name.
    Named(String),
    /// No subcommand: plain `mise`, possibly with global flags.
    Bare,
    /// Can't be determined before the command runs: a non-literal word
    /// (`$SUB`, `$(...)`), an unknown flag that may take the subcommand as
    /// its value, or arguments supplied at runtime (`xargs mise`).
    Unknown,
}

impl Subcommand {
    fn name(&self) -> Option<&str> {
        match self {
            Subcommand::Named(s) => Some(s),
            _ => None,
        }
    }
}

/// The subcommand from the words after `mise`, skipping global flags. A
/// `None` word is one that isn't literal.
fn resolve_subcommand(args: &[Option<&str>]) -> Subcommand {
    let mut i = 0;
    loop {
        let Some(&word) = args.get(i) else {
            return Subcommand::Bare;
        };
        let Some(a) = word else {
            return Subcommand::Unknown;
        };
        match a {
            "--version" | "-V" => return Subcommand::Named("version".to_string()),
            "-h" | "--help" => return Subcommand::Named("help".to_string()),
            _ if GLOBAL_VALUE_FLAGS.contains(&a) => i += 2,
            _ if GLOBAL_FLAGS.contains(&a) => i += 1,
            _ if a
                .split_once('=')
                .is_some_and(|(k, _)| k.starts_with("--") && GLOBAL_VALUE_FLAGS.contains(&k)) =>
            {
                i += 1
            }
            _ if a.starts_with('-') => return Subcommand::Unknown,
            _ => return Subcommand::Named(canonical(a).to_string()),
        }
    }
}

fn invocation_subcommand(inv: &Invocation) -> Subcommand {
    if inv.open || inv.kind == SiteKind::Exact {
        return Subcommand::Unknown;
    }
    match (&inv.args, inv.kind) {
        (Some(args), _) => {
            let args: Vec<Option<&str>> = args.iter().map(|a| a.as_deref()).collect();
            resolve_subcommand(&args)
        }
        // The words found after the name in another command's arguments or in code.
        (None, SiteKind::Adjacent | SiteKind::Opaque) => {
            let args: Vec<Option<&str>> = inv.argv.iter().map(|a| Some(a.as_str())).collect();
            resolve_subcommand(&args)
        }
        // A command word that isn't literal (`mis?`, `$M`).
        (None, _) => Subcommand::Unknown,
    }
}

/// Whether this invocation is `mise env`, in any alias or global-flag form.
pub(crate) fn is_mise_env(inv: &Invocation) -> bool {
    invocation_subcommand(inv).name() == Some("env")
}

/// Blocked whatever the config says, including `profile = "secretless"`,
/// `enabled = false` and `allow_subcommands`. `token` prints the git
/// provider token (e.g. GitHub), which isn't an env-file secret. `mcp` runs
/// a server that hands mise's env and config to whoever talks to it.
const ALWAYS_BLOCKED: &[&str] = &["token", "mcp"];

fn allowed(subcommand: &Subcommand, config: &CompiledConfig) -> bool {
    match subcommand {
        Subcommand::Named(s) if ALWAYS_BLOCKED.contains(&s.as_str()) => false,
        // It might be an always-blocked subcommand, so no config can allow it.
        Subcommand::Unknown => false,
        Subcommand::Named(s) => {
            SAFE_SUBCOMMANDS.contains(&s.as_str()) || tool_gate::allows(TOOL, Some(s), config)
        }
        Subcommand::Bare => tool_gate::allows(TOOL, None, config),
    }
}

fn mise_subcommand_info(subcommand: Option<&str>) -> (&'static str, String) {
    let Some(sub) = subcommand else {
        return (
            "mise.blocked",
            "mise is only allowed with a known safe subcommand, and this one could not be determined"
                .to_string(),
        );
    };
    let (rule, reason) = match sub {
        "env" => (
            "mise.env",
            "mise env dumps the loaded environment to stdout",
        ),
        "hook-env" => (
            "mise.hook_env",
            "mise hook-env emits the loaded environment as shell code",
        ),
        "exec" | "en" => (
            "mise.exec",
            "mise exec/en runs a command or shell with the mise environment loaded, exposing secrets",
        ),
        "run" | "watch" | "tasks" => (
            "mise.run",
            "mise run/watch/tasks run project tasks with the mise environment loaded, or print their definitions",
        ),
        "set" => (
            "mise.set",
            "mise set lists or reads environment variable values from mise.toml",
        ),
        "config" => ("mise.config", "mise config get reads values from mise.toml"),
        "token" => ("mise.token", "mise token prints git provider tokens"),
        "mcp" => (
            "mise.mcp",
            "mise mcp serves the environment, including secrets, to its client",
        ),
        "ssh" | "bootstrap" | "deps" | "daemons" | "oci" | "tool-stub" | "test-tool" => (
            "mise.exec",
            "this mise subcommand runs commands or hooks with the mise environment loaded",
        ),
        "doctor" | "settings" | "generate" | "edit" | "dotfiles" => (
            "mise.config",
            "this mise subcommand may show config or file contents and is not verified safe",
        ),
        _ => {
            return (
                "mise.task",
                format!(
                    "`mise {sub}` is not a known safe subcommand; mise runs unknown names as tasks with the mise environment loaded"
                ),
            );
        }
    };
    (rule, reason.to_string())
}

/// Whole-command analysis: checks every place the command would run mise,
/// including substitutions, `bash -c` strings and wrappers. Each invocation
/// must be a safe subcommand or allowed by `[tools.mise]`.
pub fn analyze_mise_raw(sites: &ExecSites, config: &CompiledConfig) -> Decision {
    for inv in sites.invocations(&[TOOL], SUBCOMMANDS) {
        let subcommand = invocation_subcommand(&inv);
        if !allowed(&subcommand, config) {
            let shown = subcommand
                .name()
                .or_else(|| inv.captured.as_deref().map(canonical));
            let (rule, reason) = mise_subcommand_info(shown);
            return Decision::block(rule, reason);
        }
    }
    Decision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> CompiledConfig {
        Config::default().compile().unwrap()
    }

    fn raw(cmd: &str, c: &CompiledConfig) -> Decision {
        analyze_mise_raw(&ExecSites::parse(cmd), c)
    }

    fn segment(cmd: &str) -> Decision {
        raw(cmd, &cfg())
    }

    fn rule(d: Decision) -> String {
        d.block_info().unwrap().rule.clone()
    }

    fn cfg_tool(enabled: bool, allow: &[&str]) -> CompiledConfig {
        let mut config = Config::default();
        config.tools.insert(
            "mise".to_string(),
            crate::config::ToolConfig {
                enabled,
                allow_subcommands: allow.iter().map(|s| s.to_string()).collect(),
            },
        );
        config.compile().unwrap()
    }

    // ── Default policy ──────────────────────────────────────────────────────

    #[test]
    fn test_safe_subcommands_allowed() {
        for cmd in [
            "mise install",
            "mise install node@20",
            "mise i",
            "mise use -g node@20",
            "mise u node@20",
            "mise ls",
            "mise list",
            "mise ls-remote node",
            "mise which node",
            "mise where node",
            "mise latest node",
            "mise outdated",
            "mise upgrade",
            "mise up",
            "mise plugins ls",
            "mise prune",
            "mise reshim",
            "mise trust",
            "mise activate zsh",
            "mise shell node@20",
            "mise version",
            "mise --version",
            "mise help",
            "mise --help",
            "mise tool node",
            "mise unuse node",
            "mise lock",
            "mise -C /x install",
            "mise --cd=/x install",
            "mise -q -y install",
            r#"mise "install""#,
            "/opt/homebrew/bin/mise install",
        ] {
            assert!(!raw(cmd, &cfg()).is_blocked(), "{cmd}");
            assert!(!segment(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_secret_exposing_subcommands_blocked() {
        for cmd in [
            "mise env",
            "mise e",
            "mise env -s bash",
            "mise hook-env",
            "mise exec -- ls",
            "mise x node@20 -- node app.js",
            "mise en",
            "mise run build",
            "mise r build",
            "mise watch build",
            "mise tasks info build",
            "mise t ls",
            "mise set",
            "mise set API_KEY",
            "mise ev",
            "mise config get env.API_KEY",
            "mise cfg ls",
            "mise token github",
            "mise mcp",
            "mise ssh host",
            "mise bootstrap",
            "mise deps",
            "mise daemons start",
            "mise oci run",
            "mise tool-stub x",
            "mise test-tool node",
            "mise doctor",
            "mise settings",
            "mise generate task-docs",
            "mise edit",
            "mise dotfiles diff",
            "mise build",
            "mise",
            "mise -C /x env",
            "mise --unknown-flag install",
        ] {
            assert!(raw(cmd, &cfg()).is_blocked(), "{cmd}");
            assert!(segment(cmd).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_unresolvable_invocations_blocked() {
        for cmd in [
            "mise $SUB",
            "$(mise install)",
            "mis? install",
            r#"eval "$(mise activate bash)""#,
            "unknown-wrapper mise env",
        ] {
            assert!(raw(cmd, &cfg()).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_nested_and_wrapped() {
        assert!(!raw("cd x && mise install", &cfg()).is_blocked());
        assert!(!raw("echo $(mise which node)", &cfg()).is_blocked());
        assert!(!raw(r#"bash -c "mise install""#, &cfg()).is_blocked());
        assert!(!raw("sudo mise install", &cfg()).is_blocked());
        assert!(!raw("unknown-wrapper mise install", &cfg()).is_blocked());
        assert!(raw("mise install && mise env", &cfg()).is_blocked());
        assert!(raw("echo $(mise env)", &cfg()).is_blocked());
        assert!(raw(r#"bash -c "mise exec -- ls""#, &cfg()).is_blocked());
        assert!(raw("sudo mise run deploy", &cfg()).is_blocked());
    }

    // ── Config gating ───────────────────────────────────────────────────────

    #[test]
    fn test_disabled_allows_segment_and_raw() {
        let c = cfg_tool(false, &[]);
        assert!(!raw("mise exec -- ls", &c).is_blocked());
        assert!(!raw("mise exec -- ls", &c).is_blocked());
        assert!(!raw("mise run build", &c).is_blocked());
    }

    #[test]
    fn test_allowlist_extends_safe_set() {
        let c = cfg_tool(true, &["run"]);
        assert!(!raw("mise run build", &c).is_blocked());
        assert!(!raw("mise run build", &c).is_blocked());
        assert!(!raw("mise r build", &c).is_blocked());
        assert!(!raw("mise install", &c).is_blocked());
        assert!(raw("mise exec -- ls", &c).is_blocked());
    }

    #[test]
    fn test_allowlist_checks_every_occurrence() {
        let c = cfg_tool(true, &["run"]);
        let d = raw("mise run build && mise exec -- ls", &c);
        assert_eq!(rule(d), "mise.exec");
    }

    #[test]
    fn test_always_blocked_ignores_config() {
        let secretless = Config {
            profile: Some("secretless".to_string()),
            ..Default::default()
        }
        .compile()
        .unwrap();
        // Everything else is still relaxed.
        assert!(!raw("mise run build", &secretless).is_blocked());
        for c in [
            cfg_tool(false, &[]),
            cfg_tool(true, &["token", "mcp"]),
            secretless,
        ] {
            for cmd in [
                "mise token github",
                "mise -q token",
                "echo $(mise token)",
                "mise mcp",
            ] {
                assert!(raw(cmd, &c).is_blocked(), "{cmd}");
            }
        }
    }

    #[test]
    fn test_unknown_subcommand_blocked_under_any_config() {
        let secretless = Config {
            profile: Some("secretless".to_string()),
            ..Default::default()
        }
        .compile()
        .unwrap();
        for c in [cfg_tool(false, &[]), secretless] {
            for cmd in [
                "mise $SUB",
                "mise $(echo token)",
                "mise \"$X\" github",
                "mise --unknown-flag token",
                "mis? token",
                "echo token | xargs mise",
            ] {
                assert!(raw(cmd, &c).is_blocked(), "{cmd}");
            }
            for cmd in [
                "mise",
                "mise -q",
                "mise run build",
                "mise -C dir use node@20",
                r#"python -c 'import subprocess; subprocess.run(["mise", "install"])'"#,
            ] {
                assert!(!raw(cmd, &c).is_blocked(), "{cmd}");
            }
        }
    }

    #[test]
    fn test_mise_env_still_blocked_by_env_analyzer_when_disabled() {
        let c = cfg_tool(false, &[]);
        assert!(!raw("mise env", &c).is_blocked());
        assert!(crate::rules::analyze_command("mise env", &c, None).is_blocked());
        assert!(crate::rules::analyze_command("mise -C /x e", &c, None).is_blocked());
    }

    // ── Reasons ─────────────────────────────────────────────────────────────

    #[test]
    fn test_reasons() {
        assert_eq!(rule(raw("mise env", &cfg())), "mise.env");
        assert_eq!(rule(raw("mise e", &cfg())), "mise.env");
        assert_eq!(rule(raw("mise hook-env", &cfg())), "mise.hook_env");
        assert_eq!(rule(raw("mise x -- ls", &cfg())), "mise.exec");
        assert_eq!(rule(raw("mise run build", &cfg())), "mise.run");
        assert_eq!(rule(raw("mise set", &cfg())), "mise.set");
        assert_eq!(rule(raw("mise token github", &cfg())), "mise.token");
        assert_eq!(rule(raw("mise mcp", &cfg())), "mise.mcp");
        assert_eq!(rule(raw("mise build", &cfg())), "mise.task");
        assert_eq!(rule(raw("mise", &cfg())), "mise.blocked");
        assert_eq!(rule(segment("mise exec -- cat .env")), "mise.exec");
        assert_eq!(rule(raw("unknown-wrapper mise env", &cfg())), "mise.env");
    }

    #[test]
    fn test_task_reason_names_the_task() {
        let d = raw("mise deploy", &cfg());
        assert!(d.block_info().unwrap().reason.contains("mise deploy"));
    }

    // ── Data mentions and substrings ────────────────────────────────────────

    #[test]
    fn test_raw_data_mentions_allowed() {
        for cmd in [
            "rg mise",
            "brew bundle add mise",
            r#"git commit -m "drop mise env""#,
            "ls # mise env",
            "npm install promise",
            "echo the demise of foo",
            "grep misery file.txt",
            "cat automise.log",
            "ls -la",
        ] {
            assert!(!raw(cmd, &cfg()).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_substitution_forms_blocked() {
        for cmd in [
            "echo $(mise env -s bash)",
            "BLOB=$(mise hook-env)",
            "some-cmd --opt $(mise env)",
            "echo `mise env`",
            "echo $('mise env')",
            "/opt/homebrew/bin/mise env",
        ] {
            assert!(raw(cmd, &cfg()).is_blocked(), "{cmd}");
        }
    }

    #[test]
    fn test_not_mise() {
        assert!(!segment("ls -la").is_blocked());
    }
}
