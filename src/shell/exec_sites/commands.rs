//! Per-command knowledge: wrappers that run another command, shells and
//! interpreters that run code strings, and options whose values are executed.

use super::parser::parse_script_into;
use super::pattern::InterpKind;
use super::{DATA_COMMANDS, Site, Word, normalize_command_name};

/// Maximum nesting of wrappers (`sudo nice timeout 5 ...`).
const MAX_LEVEL: usize = 16;

/// How a command treats its stdin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdinUse {
    /// Data.
    None,
    /// Shell code (`... | sh`).
    Anywhere,
    /// Interpreter code (`... | python`).
    Interp,
}

impl StdinUse {
    pub fn site(self, text: String) -> Option<Site> {
        match self {
            StdinUse::None => None,
            StdinUse::Anywhere => Some(Site::Anywhere(text)),
            StdinUse::Interp => Some(Site::Interp(text, InterpKind::General)),
        }
    }
}

/// Where analysis results go.
pub struct Cx<'s> {
    sites: &'s mut Vec<Site>,
    depth: usize,
    comments: bool,
    /// Count of inner commands and scripts entered, to tell wrappers apart.
    wraps: usize,
    /// Commands analyzed now get more arguments at runtime (`xargs`, `find -exec`).
    open: bool,
}

impl<'s> Cx<'s> {
    pub fn new(sites: &'s mut Vec<Site>, depth: usize, comments: bool) -> Self {
        Cx {
            sites,
            depth,
            comments,
            wraps: 0,
            open: false,
        }
    }

    fn script(&mut self, text: &str) {
        self.wraps += 1;
        parse_script_into(text, self.depth + 1, self.comments, self.sites);
    }

    fn inner(&mut self, argv: &[Word], level: usize) -> StdinUse {
        self.wraps += 1;
        analyze_argv(argv, self, level + 1)
    }

    /// Like [`Cx::inner`], for a command that gets more arguments at runtime.
    fn inner_open(&mut self, argv: &[Word], level: usize) -> StdinUse {
        let prev = self.open;
        self.open = true;
        let stdin = self.inner(argv, level);
        self.open = prev;
        stdin
    }

    fn anywhere(&mut self, text: &str) {
        self.sites.push(Site::Anywhere(text.to_string()));
    }

    fn interp(&mut self, code: &str, kind: InterpKind) {
        self.sites.push(Site::Interp(code.to_string(), kind));
    }

    fn exact(&mut self, word: &Word) {
        self.sites.push(Site::Exact(word.clone()));
    }

    fn exact_text(&mut self, text: &str) {
        self.exact(&Word {
            text: text.to_string(),
            ..Word::default()
        });
    }
}

/// Analyze one simple command.
pub fn analyze(argv: &[Word], herestrings: &[String], cx: &mut Cx) -> StdinUse {
    let stdin = analyze_argv(argv, cx, 0);
    for h in herestrings {
        if let Some(site) = stdin.site(h.clone()) {
            cx.sites.push(site);
        }
    }
    stdin
}

fn analyze_argv(argv: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let Some(cmd) = argv.first() else {
        return StdinUse::None;
    };
    if level > MAX_LEVEL {
        cx.anywhere(&join(argv));
        return StdinUse::None;
    }
    let name = normalize_command_name(&cmd.text);
    let idx = cx.sites.len();
    cx.sites.push(Site::Command {
        argv: argv.to_vec(),
        adjacency: false,
        open: cx.open,
    });
    if cmd.dynamic {
        for s in &cmd.subs {
            cx.anywhere(s);
        }
    }
    if cmd.text.chars().any(char::is_whitespace) {
        cx.script(&cmd.text);
    }
    let wraps = cx.wraps;
    let stdin = dispatch(&name, &argv[1..], cx, level);
    let wrapped = cx.wraps > wraps;
    if let Site::Command { adjacency, .. } = &mut cx.sites[idx] {
        *adjacency = !wrapped && !DATA_COMMANDS.contains(&name.as_str());
    }
    stdin
}

fn dispatch(name: &str, args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    use StdinUse::None as N;
    match name {
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "mksh" | "ash" | "yash" | "posh" | "rbash"
        | "tcsh" | "csh" => shell(args, cx),
        "fish" => fish(args, cx),
        "busybox" => cx.inner(args, level),
        "eval" => {
            cx.script(&join(args));
            N
        }
        "source" | "." => source(args, cx),
        "exec" => prefix(args, &["-a"], 0, cx, level),
        "command" => {
            let o = parse_opts(args, &[]);
            if o.has("-v") || o.has("-V") {
                N
            } else {
                cx.inner(&args[o.rest..], level)
            }
        }
        "builtin" | "noglob" | "nocorrect" | "-" | "nohup" | "chronic" | "with-contenv"
        | "setsid" | "unbuffer" | "valgrind" | "firejail" => prefix(args, &[], 0, cx, level),
        "time" => prefix(args, &["-f", "--format", "-o", "--output"], 0, cx, level),
        "sudo" => sudo(args, cx, level),
        "doas" => prefix(args, &["-u", "-C"], 0, cx, level),
        "pkexec" => prefix(args, &["--user"], 0, cx, level),
        "nice" => prefix(args, &["-n", "--adjustment"], 0, cx, level),
        "ionice" => prefix(
            args,
            &[
                "-c",
                "-n",
                "-p",
                "-P",
                "-u",
                "--class",
                "--classdata",
                "--pid",
                "--pgid",
                "--uid",
            ],
            0,
            cx,
            level,
        ),
        "timeout" | "gtimeout" => prefix(
            args,
            &["-s", "--signal", "-k", "--kill-after"],
            1,
            cx,
            level,
        ),
        "stdbuf" | "gstdbuf" => prefix(
            args,
            &["-i", "-o", "-e", "--input", "--output", "--error"],
            0,
            cx,
            level,
        ),
        "chrt" | "taskset" => {
            const VALS: &[&str] = &[
                "-T",
                "-P",
                "-D",
                "--sched-runtime",
                "--sched-period",
                "--sched-deadline",
            ];
            if parse_opts(args, VALS).has("-p") {
                N
            } else {
                prefix(args, VALS, 1, cx, level)
            }
        }
        "numactl" => prefix(
            args,
            &[
                "-C",
                "-N",
                "-m",
                "-p",
                "-i",
                "-P",
                "-w",
                "--cpunodebind",
                "--membind",
                "--physcpubind",
                "--interleave",
                "--preferred",
                "--weighted-interleave",
            ],
            0,
            cx,
            level,
        ),
        "unshare" => prefix(
            args,
            &[
                "-S", "-G", "-R", "-w", "--setuid", "--setgid", "--root", "--wd",
            ],
            0,
            cx,
            level,
        ),
        "nsenter" => prefix(
            args,
            &["-t", "--target", "-S", "-G", "--setuid", "--setgid"],
            0,
            cx,
            level,
        ),
        "chroot" => prefix(args, &["--userspec", "--groups"], 1, cx, level),
        "flock" => {
            let codes = scan_values(args, &["-c", "--command"]);
            if codes.is_empty() {
                return prefix(
                    args,
                    &["-w", "--timeout", "-E", "--conflict-exit-code"],
                    1,
                    cx,
                    level,
                );
            }
            for c in &codes {
                cx.script(c);
            }
            N
        }
        "caffeinate" => prefix(args, &["-t", "-w"], 0, cx, level),
        "arch" => arch(args, cx, level),
        "sandbox-exec" => prefix(args, &["-f", "-n", "-p", "-D"], 0, cx, level),
        "script" => {
            let codes = scan_values(args, &["-c", "--command"]);
            if codes.is_empty() {
                return prefix(
                    args,
                    &["-t", "-T", "-I", "-O", "-B", "-E", "-m"],
                    1,
                    cx,
                    level,
                );
            }
            for c in &codes {
                cx.script(c);
            }
            N
        }
        "watch" => {
            let o = parse_opts(args, &["-n", "--interval", "-q", "--equexit"]);
            let rest = &args[o.rest..];
            if o.has("-x") || o.has("--exec") {
                cx.inner(rest, level);
            } else {
                cx.script(&join(rest));
            }
            N
        }
        "entr" => {
            let o = parse_opts(args, &[]);
            let rest = &args[o.rest..];
            if o.has("-s") {
                cx.script(&join(rest));
            } else {
                cx.inner(rest, level);
            }
            N
        }
        "xargs" | "gxargs" => xargs(args, cx, level),
        "parallel" => parallel(args, cx, level),
        "find" | "gfind" => {
            exec_clauses(args, &["-exec", "-execdir", "-ok", "-okdir"], cx, level);
            N
        }
        "fd" | "fdfind" => {
            exec_clauses(args, &["-x", "--exec", "-X", "--exec-batch"], cx, level);
            N
        }
        "strace" => prefix(
            args,
            &[
                "-e", "-o", "-p", "-s", "-u", "-a", "-b", "-E", "-I", "-P", "-S", "-X", "-O",
            ],
            0,
            cx,
            level,
        ),
        "ltrace" => prefix(
            args,
            &[
                "-e", "-o", "-p", "-s", "-u", "-a", "-n", "-l", "-w", "-x", "-A", "-D", "-F",
            ],
            0,
            cx,
            level,
        ),
        "dtruss" => prefix(args, &["-b", "-n", "-p", "-t"], 0, cx, level),
        "gdb" => gdb(args, cx, level),
        "lldb" => {
            let end = dashdash(args).unwrap_or(args.len());
            for v in scan_values(
                &args[..end],
                &["-o", "--one-line", "-O", "--one-line-before-file", "-k"],
            ) {
                cx.anywhere(&v);
            }
            for w in &args[..end] {
                if !w.text.starts_with('-') {
                    cx.exact(w);
                }
            }
            if end < args.len() {
                cx.inner(&args[end + 1..], level);
            }
            N
        }
        "systemd-run" => prefix(
            args,
            &[
                "-u",
                "--unit",
                "-p",
                "--property",
                "-M",
                "--machine",
                "-H",
                "--host",
                "--description",
                "--slice",
                "-E",
                "--setenv",
                "--uid",
                "--gid",
                "--nice",
                "--working-directory",
                "--on-active",
                "--on-calendar",
                "--on-boot",
                "--timer-property",
                "--path-property",
                "--socket-property",
                "--service-type",
            ],
            0,
            cx,
            level,
        ),
        "dbus-run-session" => prefix(args, &["--config-file", "--dbus-daemon"], 0, cx, level),
        "ssh-agent" => prefix(args, &["-a", "-E", "-t", "-P", "-O"], 0, cx, level),
        "tini" | "tini-static" => prefix(args, &["-p", "-e"], 0, cx, level),
        "dumb-init" => prefix(args, &["-r", "--rewrite"], 0, cx, level),
        "env" | "genv" => env_cmd(args, cx, level),
        "runuser" | "su" => su(name, args, cx, level),
        "sg" => {
            let codes = scan_values(args, &["-c"]);
            for c in &codes {
                cx.script(c);
            }
            if codes.is_empty() && args.len() > 1 {
                cx.script(&join(&args[1..]));
            }
            N
        }
        "op" => match verb(args, &["--account", "--config", "--encoding", "--session"]) {
            Some(("run", k)) => after_dashdash_or(
                &args[k + 1..],
                &["--env-file", "--account", "--cache"],
                0,
                cx,
                level,
            ),
            _ => N,
        },
        "aws-vault" => match verb(args, &["--backend", "--keychain"]) {
            Some(("exec", k)) => after_dashdash_or(
                &args[k + 1..],
                &[
                    "-d",
                    "--duration",
                    "--region",
                    "-t",
                    "--mfa-token",
                    "--prompt",
                    "--ec2-server",
                ],
                1,
                cx,
                level,
            ),
            _ => N,
        },
        "doppler" => match verb(args, &["--token", "--config-dir", "--scope"]) {
            Some(("run", k)) => {
                let rest = &args[k + 1..];
                for c in scan_values(rest, &["--command"]) {
                    cx.script(&c);
                }
                after_dashdash_or(
                    rest,
                    &[
                        "-p",
                        "--project",
                        "-c",
                        "--config",
                        "-t",
                        "--token",
                        "--scope",
                        "--fallback",
                        "--mount",
                        "--mount-format",
                        "--mount-template",
                        "--name-transformer",
                        "--command",
                    ],
                    0,
                    cx,
                    level,
                )
            }
            _ => N,
        },
        "chamber" => match verb(args, &["-r", "--retries", "-b", "--backend"]) {
            Some(("exec", k)) => {
                let rest = &args[k + 1..];
                match dashdash(rest) {
                    Some(_) => after_dashdash_or(rest, &[], 0, cx, level),
                    None => {
                        for w in rest {
                            cx.exact(w);
                        }
                        N
                    }
                }
            }
            _ => N,
        },
        "envchain" => {
            let o = parse_opts(args, &[]);
            if o.has("--set") || o.has("-s") {
                N
            } else {
                prefix(args, &[], 1, cx, level)
            }
        }
        "dotenv" => {
            let o = parse_opts(args, &["-f", "--file", "-e", "-c", "-v"]);
            match args.get(o.rest) {
                Some(w) if w.text == "run" => {
                    after_dashdash_or(&args[o.rest + 1..], &[], 0, cx, level)
                }
                _ => after_dashdash_or(args, &["-f", "--file", "-e", "-c", "-v"], 0, cx, level),
            }
        }
        "dotenvx" => match verb(args, &[]) {
            Some(("run", k)) => after_dashdash_or(
                &args[k + 1..],
                &[
                    "-f",
                    "--env-file",
                    "-e",
                    "--env",
                    "-fk",
                    "--env-keys-file",
                    "--convention",
                ],
                0,
                cx,
                level,
            ),
            _ => N,
        },
        "npx" => runner(
            args,
            &["-p", "--package", "-c", "--call", "--cache", "--registry"],
            &["-p", "--package"],
            &["-c", "--call"],
            true,
            cx,
            level,
        ),
        "bunx" => runner(
            args,
            &["-p", "--package"],
            &["-p", "--package"],
            &[],
            true,
            cx,
            level,
        ),
        "uvx" => runner(args, UVX_VALS, UVX_PKG, &[], true, cx, level),
        "pnpm" | "yarn" => pnpm_yarn(args, cx, level),
        "npm" => match verb(args, &["--prefix", "-w", "--workspace"]) {
            Some(("exec" | "x", k)) => runner(
                &args[k + 1..],
                &["--package", "-c", "--call"],
                &["--package"],
                &["-c", "--call"],
                true,
                cx,
                level,
            ),
            _ => N,
        },
        "pipx" => match verb(args, &[]) {
            Some(("run", k)) => runner(
                &args[k + 1..],
                &["--spec", "--python", "--pip-args", "--index-url"],
                &["--spec"],
                &[],
                true,
                cx,
                level,
            ),
            _ => N,
        },
        "uv" => uv(args, cx, level),
        "poetry" | "pipenv" | "pdm" | "hatch" | "rye" => match verb(args, &["-C", "--directory"]) {
            Some(("run", k)) => after_dashdash_or(&args[k + 1..], &["-e", "--env"], 0, cx, level),
            _ => N,
        },
        "bundle" | "bundler" => match verb(args, &["--gemfile"]) {
            Some(("exec", k)) => prefix(&args[k + 1..], &["--gemfile"], 0, cx, level),
            _ => N,
        },
        "brew" => match (args.first(), args.get(1)) {
            (Some(a), Some(b)) if a.text == "bundle" && b.text == "exec" => {
                prefix(&args[2..], &["--file"], 0, cx, level)
            }
            _ => N,
        },
        "mise" | "rtx" => match verb(args, &["-C", "--cd", "-E", "--env", "-j", "--jobs"]) {
            Some(("exec" | "x", k)) => {
                let rest = &args[k + 1..];
                for c in scan_values(rest, &["-c", "--command"]) {
                    cx.script(&c);
                }
                match dashdash(rest) {
                    Some(_) => after_dashdash_or(rest, &[], 0, cx, level),
                    None => {
                        for w in rest {
                            cx.exact(w);
                        }
                        N
                    }
                }
            }
            _ => N,
        },
        "asdf" => match verb(args, &[]) {
            Some(("exec", k)) => cx.inner(&args[k + 1..], level),
            _ => N,
        },
        "direnv" => match verb(args, &[]) {
            Some(("exec", k)) => prefix(&args[k + 1..], &[], 1, cx, level),
            _ => N,
        },
        "shadowenv" => match verb(args, &[]) {
            Some(("exec", k)) => after_dashdash_or(&args[k + 1..], &["--dir"], 0, cx, level),
            _ => N,
        },
        "infisical" => match verb(args, &["--domain", "--token"]) {
            Some(("run", k)) => {
                let rest = &args[k + 1..];
                for c in scan_values(rest, &["--command"]) {
                    cx.script(&c);
                }
                after_dashdash_or(
                    rest,
                    &[
                        "--env",
                        "--path",
                        "--projectId",
                        "--token",
                        "--tags",
                        "--command",
                        "--domain",
                    ],
                    0,
                    cx,
                    level,
                )
            }
            _ => N,
        },
        "conda" | "mamba" | "micromamba" => match verb(args, &[]) {
            Some(("run", k)) => prefix(
                &args[k + 1..],
                &["-n", "--name", "-p", "--prefix", "--cwd"],
                0,
                cx,
                level,
            ),
            _ => N,
        },
        "devbox" => match verb(args, &[]) {
            Some(("run", k)) => after_dashdash_or(
                &args[k + 1..],
                &["-c", "--config", "-e", "--env", "--env-file"],
                0,
                cx,
                level,
            ),
            _ => N,
        },
        "nix" => nix(args, cx, level),
        "nix-shell" => {
            let mut i = 0;
            while let Some(w) = args.get(i) {
                if matches!(w.text.as_str(), "--run" | "--command") {
                    if let Some(v) = args.get(i + 1) {
                        cx.script(&v.text);
                    }
                    i += 2;
                    continue;
                }
                if !w.text.starts_with('-') {
                    cx.anywhere(&w.text);
                }
                i += 1;
            }
            N
        }
        "docker" | "podman" | "nerdctl" => docker(args, cx, level),
        "docker-compose" | "podman-compose" => compose(args, cx, level),
        "kubectl" | "oc" => kubectl(args, cx, level),
        "ssh" => ssh(args, cx),
        "scp" | "sftp" => {
            for v in scan_values(args, &["-S"]) {
                cx.script(&v);
            }
            ssh_o_values(args, cx);
            N
        }
        "rsync" => {
            for v in scan_values(args, &["-e", "--rsh", "--rsync-path"]) {
                cx.script(&v);
            }
            N
        }
        "screen" => screen(args, cx, level),
        "tmux" => tmux(args, cx),
        "git" => git(args, cx, level),
        "tar" | "gtar" | "bsdtar" => {
            for v in scan_values(
                args,
                &[
                    "--to-command",
                    "-I",
                    "--use-compress-program",
                    "--rsh-command",
                    "--info-script",
                    "-F",
                    "--new-volume-script",
                ],
            ) {
                cx.script(&v);
            }
            for v in scan_values(args, &["--checkpoint-action"]) {
                if let Some(c) = v.strip_prefix("exec=") {
                    cx.script(c);
                }
            }
            N
        }
        "rg" => {
            for v in scan_values(args, &["--pre"]) {
                cx.script(&v);
            }
            N
        }
        "man" => {
            for v in scan_values(args, &["-P", "--pager"]) {
                cx.script(&v);
            }
            N
        }
        "vim" | "nvim" | "vi" | "view" | "gvim" | "vimdiff" | "ex" | "mvim" => {
            for v in scan_values(args, &["-c", "--cmd"]) {
                cx.anywhere(&v);
            }
            for w in args {
                if let Some(c) = w.text.strip_prefix('+')
                    && !c.is_empty()
                {
                    cx.anywhere(c);
                }
            }
            N
        }
        "sqlite3" => {
            for w in args {
                if w.text.contains(".shell") || w.text.contains(".system") || w.text.contains('|') {
                    cx.anywhere(&w.text);
                }
            }
            N
        }
        "hyperfine" => {
            for w in args {
                if !w.text.starts_with('-') {
                    cx.script(&w.text);
                }
            }
            N
        }
        "nodemon" => {
            for v in scan_values(args, &["--exec", "-x"]) {
                cx.script(&v);
            }
            N
        }
        "cargo" => {
            if args.first().is_some_and(|w| w.text == "watch") {
                for v in scan_values(&args[1..], &["-s", "--shell", "-x", "--exec"]) {
                    cx.script(&v);
                }
            }
            N
        }
        "pwsh" | "powershell" => {
            cx.anywhere(&join(args));
            N
        }
        "export" | "local" | "declare" | "typeset" | "readonly" => {
            for w in args {
                if let Some(v) = w.assign_value() {
                    cx.script(v);
                }
            }
            N
        }
        "alias" => {
            for w in args {
                if let Some((_, v)) = w.text.split_once('=') {
                    cx.script(v);
                }
            }
            N
        }
        "trap" => {
            let o = parse_opts(args, &[]);
            if let Some(w) = args.get(o.rest) {
                cx.script(&w.text);
            }
            N
        }
        "awk" | "gawk" | "mawk" | "nawk" => awk(args, cx),
        "sed" | "gsed" => sed(args, cx),
        "perl" => cluster_code_interpreter(args, "eE", "IMmxil0CdDV", cx),
        "ruby" => cluster_code_interpreter(args, "e", "IrxCEKTW0l", cx),
        "node" | "nodejs" | "bun" => interpreter(
            args,
            &["-e", "--eval", "-p", "--print"],
            &[
                "-r",
                "--require",
                "--import",
                "--loader",
                "-C",
                "--conditions",
                "--input-type",
            ],
            cx,
        ),
        "deno" => {
            if args.first().is_some_and(|w| w.text == "eval") {
                cx.interp(&join(&args[1..]), InterpKind::General);
            }
            N
        }
        "php" => {
            if parse_opts(args, &["-c", "-d", "-f", "-z", "-t"]).has("-f") {
                return N;
            }
            interpreter(
                args,
                &["-r", "-B", "-R", "-E"],
                &["-c", "-d", "-z", "-t"],
                cx,
            )
        }
        "lua" | "luajit" => interpreter(args, &["-e"], &["-l"], cx),
        "osascript" => interpreter(args, &["-e"], &["-l", "-s"], cx),
        "expect" => interpreter(args, &["-c"], &[], cx),
        _ if is_python(name) => {
            if parse_opts(args, &["-c", "-m", "-W", "-X", "-Q"]).has("-m") {
                return N;
            }
            interpreter(args, &["-c"], &["-W", "-X", "-Q"], cx)
        }
        _ => N,
    }
}

const UVX_VALS: &[&str] = &[
    "--from",
    "--with",
    "--with-editable",
    "--with-requirements",
    "-p",
    "--python",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "-c",
    "--constraints",
    "--overrides",
];
const UVX_PKG: &[&str] = &["--from", "--with", "--with-editable"];

fn is_python(name: &str) -> bool {
    let rest = name
        .strip_prefix("python")
        .or_else(|| name.strip_prefix("pypy"));
    match rest {
        Some(r) => r.chars().all(|c| c.is_ascii_digit() || c == '.'),
        None => name == "py",
    }
}

fn join(args: &[Word]) -> String {
    args.iter()
        .map(|w| w.text.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn dashdash(args: &[Word]) -> Option<usize> {
    args.iter().position(|w| w.text == "--")
}

/// Parsed leading options.
struct Opts {
    found: Vec<(String, Option<String>)>,
    /// Index of the first operand (past a `--`).
    rest: usize,
}

impl Opts {
    fn has(&self, name: &str) -> bool {
        self.found.iter().any(|(k, _)| k == name)
    }

    fn values<'a>(&'a self, names: &'a [&str]) -> impl Iterator<Item = &'a str> + 'a {
        self.found
            .iter()
            .filter(move |(k, _)| names.contains(&k.as_str()))
            .filter_map(|(_, v)| v.as_deref())
    }
}

/// Parse options up to the first operand. `vals` lists options that take a
/// value (`-u root`, `-uroot`, `--user root`, `--user=root`).
fn parse_opts(args: &[Word], vals: &[&str]) -> Opts {
    let mut found = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].text.as_str();
        if a == "--" {
            return Opts { found, rest: i + 1 };
        }
        if !a.starts_with('-') || a == "-" {
            break;
        }
        if vals.contains(&a) {
            found.push((a.to_string(), args.get(i + 1).map(|w| w.text.clone())));
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            match a.split_once('=') {
                Some((k, v)) => found.push((k.to_string(), Some(v.to_string()))),
                None => found.push((a.to_string(), None)),
            }
            i += 1;
            continue;
        }
        let mut consumed_next = false;
        for (j, ch) in a[1..].char_indices() {
            let opt = format!("-{ch}");
            if vals.contains(&opt.as_str()) {
                let attached = &a[1 + j + ch.len_utf8()..];
                if attached.is_empty() {
                    found.push((opt, args.get(i + 1).map(|w| w.text.clone())));
                    consumed_next = true;
                } else {
                    found.push((opt, Some(attached.to_string())));
                }
                break;
            }
            found.push((opt, None));
        }
        i += if consumed_next { 2 } else { 1 };
    }
    Opts {
        found,
        rest: i.min(args.len()),
    }
}

/// Values of the named options anywhere before a `--`.
fn scan_values(args: &[Word], names: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].text.as_str();
        if a == "--" {
            break;
        }
        if names.contains(&a) {
            if let Some(v) = args.get(i + 1) {
                out.push(v.text.clone());
            }
            i += 2;
            continue;
        }
        if a.starts_with("--") {
            if let Some((k, v)) = a.split_once('=')
                && names.contains(&k)
            {
                out.push(v.to_string());
            }
        } else if a.starts_with('-') && a.len() > 2 {
            for (j, ch) in a[1..].char_indices() {
                let opt = format!("-{ch}");
                if names.contains(&opt.as_str()) {
                    let attached = &a[1 + j + ch.len_utf8()..];
                    if attached.is_empty() {
                        if let Some(v) = args.get(i + 1) {
                            out.push(v.text.clone());
                            i += 1;
                        }
                    } else {
                        out.push(attached.to_string());
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    out
}

/// The first operand after leading options, and its index.
fn verb<'a>(args: &'a [Word], global_vals: &[&str]) -> Option<(&'a str, usize)> {
    let o = parse_opts(args, global_vals);
    args.get(o.rest).map(|w| (w.text.as_str(), o.rest))
}

/// `wrapper [opts] [skip operands] cmd args...`. Skipped operands are checked
/// as programs too.
fn prefix(args: &[Word], vals: &[&str], skip: usize, cx: &mut Cx, level: usize) -> StdinUse {
    let o = parse_opts(args, vals);
    let mut i = o.rest;
    for _ in 0..skip {
        if let Some(w) = args.get(i) {
            cx.exact(w);
            i += 1;
        }
    }
    cx.inner(&args[i.min(args.len())..], level)
}

/// The command after `--` if there is one, otherwise like [`prefix`].
fn after_dashdash_or(
    args: &[Word],
    vals: &[&str],
    skip: usize,
    cx: &mut Cx,
    level: usize,
) -> StdinUse {
    match dashdash(args) {
        Some(k) => {
            for w in &args[..k] {
                if !w.text.starts_with('-') {
                    cx.exact(w);
                }
            }
            cx.inner(&args[k + 1..], level)
        }
        None => prefix(args, vals, skip, cx, level),
    }
}

/// Package runners: the package spec runs, so the name anywhere in it counts.
fn runner(
    args: &[Word],
    vals: &[&str],
    pkg_opts: &[&str],
    script_opts: &[&str],
    operand_is_pkg: bool,
    cx: &mut Cx,
    level: usize,
) -> StdinUse {
    let o = parse_opts(args, vals);
    for v in o.values(pkg_opts) {
        cx.anywhere(v);
    }
    for c in o.values(script_opts) {
        let c = c.to_string();
        cx.script(&c);
    }
    if operand_is_pkg && let Some(w) = args.get(o.rest) {
        cx.anywhere(&w.text);
    }
    cx.inner(&args[o.rest..], level)
}

fn shell(args: &[Word], cx: &mut Cx) -> StdinUse {
    let mut i = 0;
    let mut has_c = false;
    let mut has_s = false;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if a == "--" || a == "-" {
            i += 1;
            break;
        }
        if !(a.starts_with('-') || a.starts_with('+')) {
            break;
        }
        if a.starts_with("--") {
            i += if matches!(a, "--rcfile" | "--init-file") {
                2
            } else {
                1
            };
            continue;
        }
        let flags = &a[1..];
        has_c |= flags.contains('c');
        has_s |= flags.contains('s');
        i += if flags.ends_with('o') || flags.ends_with('O') {
            2
        } else {
            1
        };
    }
    if has_c {
        if let Some(w) = args.get(i) {
            cx.script(&w.text);
        }
        return StdinUse::None;
    }
    let Some(file) = args.get(i).filter(|_| !has_s) else {
        return StdinUse::Anywhere;
    };
    cx.exact(file);
    for s in &file.subs {
        cx.anywhere(s);
    }
    StdinUse::None
}

fn fish(args: &[Word], cx: &mut Cx) -> StdinUse {
    const CODE: &[&str] = &["-c", "--command", "-C", "--init-command"];
    let codes = scan_values(args, CODE);
    for c in &codes {
        cx.script(c);
    }
    let o = parse_opts(
        args,
        &[
            "-c",
            "--command",
            "-C",
            "--init-command",
            "-d",
            "--debug",
            "-o",
            "--debug-output",
            "--features",
        ],
    );
    if !codes.is_empty() {
        return StdinUse::None;
    }
    match args.get(o.rest) {
        None => StdinUse::Anywhere,
        Some(file) => {
            cx.exact(file);
            StdinUse::None
        }
    }
}

fn source(args: &[Word], cx: &mut Cx) -> StdinUse {
    let Some(f) = args.first() else {
        return StdinUse::None;
    };
    if matches!(
        f.text.as_str(),
        "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0" | "-"
    ) {
        return StdinUse::Anywhere;
    }
    for s in &f.subs {
        cx.anywhere(s);
    }
    StdinUse::None
}

fn sudo(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const VALS: &[&str] = &[
        "-u",
        "-g",
        "-h",
        "-p",
        "-C",
        "-D",
        "-r",
        "-t",
        "-U",
        "-T",
        "-R",
        "--user",
        "--group",
        "--host",
        "--prompt",
        "--close-from",
        "--chdir",
        "--role",
        "--type",
        "--other-user",
        "--command-timeout",
        "--chroot",
    ];
    let o = parse_opts(args, VALS);
    if o.has("-e") || o.has("--edit") {
        return StdinUse::None;
    }
    let mut i = o.rest;
    while let Some(v) = args.get(i).and_then(Word::assign_value) {
        cx.script(v);
        i += 1;
    }
    cx.inner(&args[i..], level)
}

fn env_cmd(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let o = parse_opts(
        args,
        &[
            "-u",
            "--unset",
            "-C",
            "--chdir",
            "-S",
            "--split-string",
            "-P",
        ],
    );
    for s in o.values(&["-S", "--split-string"]) {
        let s = s.to_string();
        cx.script(&s);
    }
    let mut i = o.rest;
    if args.get(i).is_some_and(|w| w.text == "-") {
        i += 1;
    }
    while let Some(v) = args.get(i).and_then(Word::assign_value) {
        cx.script(v);
        i += 1;
    }
    cx.inner(&args[i.min(args.len())..], level)
}

fn su(name: &str, args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    for c in scan_values(args, &["-c", "--command", "--session-command"]) {
        cx.script(&c);
    }
    for s in scan_values(args, &["-s", "--shell"]) {
        cx.exact_text(&s);
    }
    if name == "runuser" {
        let o = parse_opts(
            args,
            &[
                "-u",
                "--user",
                "-g",
                "--group",
                "-G",
                "--supp-group",
                "-s",
                "--shell",
                "-w",
                "--whitelist-environment",
                "-c",
                "--command",
            ],
        );
        if o.has("-u") || o.has("--user") {
            return cx.inner(&args[o.rest..], level);
        }
    }
    StdinUse::None
}

fn arch(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if matches!(a, "-arch" | "-e" | "-d") {
            i += 2;
        } else if a == "--" {
            i += 1;
            break;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    cx.inner(&args[i.min(args.len())..], level)
}

fn xargs(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const VALS: &[&str] = &[
        "-a",
        "-d",
        "-E",
        "-I",
        "-L",
        "-n",
        "-P",
        "-s",
        "--arg-file",
        "--delimiter",
        "--eof",
        "--replace",
        "--max-lines",
        "--max-args",
        "--max-procs",
        "--max-chars",
        "--process-slot-var",
    ];
    let o = parse_opts(args, VALS);
    let rest = &args[o.rest..];
    cx.inner_open(rest, level);
    let replace = o
        .found
        .iter()
        .find(|(k, _)| matches!(k.as_str(), "-I" | "--replace" | "-i"))
        .map(|(_, v)| v.clone().unwrap_or_else(|| "{}".to_string()));
    let cmd_from_input = rest
        .first()
        .zip(replace)
        .is_some_and(|(cmd, r)| !r.is_empty() && cmd.text.contains(&r));
    if cmd_from_input {
        StdinUse::Anywhere
    } else {
        StdinUse::None
    }
}

fn parallel(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const VALS: &[&str] = &[
        "-j",
        "--jobs",
        "-P",
        "-S",
        "--sshlogin",
        "--sshloginfile",
        "-a",
        "--arg-file",
        "--colsep",
        "-C",
        "-d",
        "--delimiter",
        "-I",
        "--delay",
        "--results",
        "--joblog",
        "--tmpdir",
        "--timeout",
        "-n",
        "--max-args",
        "-N",
        "-L",
        "--max-lines",
        "--basefile",
        "--env",
        "--workdir",
        "--wd",
        "--tagstring",
        "--halt",
        "--memfree",
        "--load",
        "--retries",
        "-E",
        "--eof",
    ];
    let o = parse_opts(args, VALS);
    let rest = &args[o.rest..];
    let sep = rest.iter().position(|w| w.text.starts_with(":::"));
    let cmd = &rest[..sep.unwrap_or(rest.len())];
    if cmd.is_empty() {
        let Some(sep) = sep else {
            return StdinUse::Anywhere;
        };
        for w in &rest[sep..] {
            if !w.text.starts_with(":::") {
                cx.script(&w.text);
            }
        }
        return StdinUse::None;
    }
    cx.inner_open(cmd, level);
    cx.script(&join(cmd));
    StdinUse::None
}

/// `find -exec cmd ... ;` and similar: each clause runs until `;` or `+`.
fn exec_clauses(args: &[Word], flags: &[&str], cx: &mut Cx, level: usize) {
    let mut i = 0;
    while i < args.len() {
        if flags.contains(&args[i].text.as_str()) {
            let start = i + 1;
            let end = args[start..]
                .iter()
                .position(|w| w.text == ";" || w.text == "+")
                .map_or(args.len(), |p| start + p);
            cx.inner_open(&args[start..end], level);
            i = end + 1;
        } else {
            i += 1;
        }
    }
}

fn gdb(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        match a {
            "--args" | "-args" => {
                cx.inner(&args[i + 1..], level);
                return StdinUse::None;
            }
            "-ex"
            | "--ex"
            | "-iex"
            | "--iex"
            | "-eval-command"
            | "--eval-command"
            | "-init-eval-command"
            | "--init-eval-command" => {
                if let Some(v) = args.get(i + 1) {
                    cx.anywhere(&v.text);
                }
                i += 2;
            }
            "-e" | "-exec" | "--exec" | "-se" => {
                if let Some(v) = args.get(i + 1) {
                    cx.exact(v);
                }
                i += 2;
            }
            "-x" | "-ix" | "-p" | "-pid" | "--pid" | "-c" | "-core" | "--core" | "-cd" | "--cd"
            | "-d" | "-directory" | "--directory" | "-s" | "-symbols" | "--symbols" | "-b"
            | "-tty" | "--tty" | "-D" | "-data-directory" | "--data-directory" => i += 2,
            _ if a.contains("eval-command=") => {
                if let Some((_, v)) = a.split_once('=') {
                    cx.anywhere(v);
                }
                i += 1;
            }
            _ if a.starts_with('-') => i += 1,
            _ => {
                cx.exact(w);
                i += 1;
            }
        }
    }
    StdinUse::None
}

fn pnpm_yarn(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let Some((v, k)) = verb(args, &["--filter", "-F", "-C", "--dir", "--cwd"]) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "dlx" | "exec" => {
            let o = parse_opts(rest, &["--package", "-p"]);
            if v == "dlx" {
                for p in o.values(&["--package", "-p"]) {
                    cx.anywhere(p);
                }
                if let Some(w) = rest.get(o.rest) {
                    cx.anywhere(&w.text);
                }
            }
            if o.has("-c") || o.has("--shell-mode") {
                cx.script(&join(&rest[o.rest..]));
                StdinUse::None
            } else {
                cx.inner(&rest[o.rest..], level)
            }
        }
        _ => {
            cx.exact(&args[k]);
            StdinUse::None
        }
    }
}

fn uv(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const GLOBAL: &[&str] = &[
        "--directory",
        "--project",
        "--config-file",
        "--cache-dir",
        "--color",
    ];
    let Some((v, k)) = verb(args, GLOBAL) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "run" => runner(
            rest,
            &[
                "--with",
                "--with-editable",
                "--with-requirements",
                "-p",
                "--python",
                "--project",
                "--directory",
                "--env-file",
                "--package",
                "--extra",
                "--group",
                "--index",
                "--index-url",
                "--extra-index-url",
            ],
            &["--with", "--with-editable"],
            &[],
            false,
            cx,
            level,
        ),
        "tool" if rest.first().is_some_and(|w| w.text == "run") => {
            runner(&rest[1..], UVX_VALS, UVX_PKG, &[], true, cx, level)
        }
        _ => StdinUse::None,
    }
}

fn nix(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let Some((v, k)) = verb(args, &["--extra-experimental-features"]) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "run" => {
            let end = dashdash(rest).unwrap_or(rest.len());
            for w in &rest[..end] {
                if !w.text.starts_with('-') {
                    cx.anywhere(&w.text);
                }
            }
            StdinUse::None
        }
        "shell" | "develop" => {
            let c = rest
                .iter()
                .position(|w| w.text == "-c" || w.text == "--command");
            for w in &rest[..c.unwrap_or(rest.len())] {
                if !w.text.starts_with('-') {
                    cx.anywhere(&w.text);
                }
            }
            match c {
                Some(c) => cx.inner(&rest[c + 1..], level),
                None => StdinUse::None,
            }
        }
        _ => StdinUse::None,
    }
}

const DOCKER_RUN_VALS: &[&str] = &[
    "-a",
    "--attach",
    "--add-host",
    "--annotation",
    "--blkio-weight",
    "--cap-add",
    "--cap-drop",
    "--cgroup-parent",
    "--cgroupns",
    "--cidfile",
    "--cpu-period",
    "--cpu-quota",
    "--cpu-rt-period",
    "--cpu-rt-runtime",
    "-c",
    "--cpu-shares",
    "--cpus",
    "--cpuset-cpus",
    "--cpuset-mems",
    "--device",
    "--device-cgroup-rule",
    "--device-read-bps",
    "--device-read-iops",
    "--device-write-bps",
    "--device-write-iops",
    "--dns",
    "--dns-option",
    "--dns-search",
    "--domainname",
    "--entrypoint",
    "-e",
    "--env",
    "--env-file",
    "--expose",
    "--gpus",
    "--group-add",
    "--health-cmd",
    "--health-interval",
    "--health-retries",
    "--health-start-period",
    "--health-timeout",
    "-h",
    "--hostname",
    "--ip",
    "--ip6",
    "--ipc",
    "--isolation",
    "--kernel-memory",
    "-l",
    "--label",
    "--label-file",
    "--link",
    "--link-local-ip",
    "--log-driver",
    "--log-opt",
    "--mac-address",
    "-m",
    "--memory",
    "--memory-reservation",
    "--memory-swap",
    "--memory-swappiness",
    "--mount",
    "--name",
    "--network",
    "--net",
    "--network-alias",
    "--oom-score-adj",
    "--pid",
    "--pids-limit",
    "--platform",
    "-p",
    "--publish",
    "--pull",
    "--restart",
    "--runtime",
    "--security-opt",
    "--shm-size",
    "--stop-signal",
    "--stop-timeout",
    "--storage-opt",
    "--sysctl",
    "--tmpfs",
    "--ulimit",
    "-u",
    "--user",
    "--userns",
    "--uts",
    "-v",
    "--volume",
    "--volume-driver",
    "--volumes-from",
    "-w",
    "--workdir",
    "--detach-keys",
];

const DOCKER_EXEC_VALS: &[&str] = &[
    "-e",
    "--env",
    "--env-file",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--detach-keys",
    "--index",
];

fn docker(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const GLOBAL: &[&str] = &[
        "-H",
        "--host",
        "--context",
        "-c",
        "--config",
        "-l",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
        "--url",
        "--connection",
    ];
    let Some((v, k)) = verb(args, GLOBAL) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "run" | "create" => docker_run(rest, cx, level),
        "exec" => prefix(rest, DOCKER_EXEC_VALS, 1, cx, level),
        "container" => match rest.first().map(|w| w.text.as_str()) {
            Some("run" | "create") => docker_run(&rest[1..], cx, level),
            Some("exec") => prefix(&rest[1..], DOCKER_EXEC_VALS, 1, cx, level),
            _ => StdinUse::None,
        },
        "compose" => compose(rest, cx, level),
        _ => StdinUse::None,
    }
}

fn docker_run(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let o = parse_opts(args, DOCKER_RUN_VALS);
    for (k, v) in &o.found {
        let Some(v) = v else { continue };
        match k.as_str() {
            "--entrypoint" => {
                cx.exact_text(v);
                cx.script(v);
            }
            "--health-cmd" => cx.script(v),
            _ => {}
        }
    }
    let Some(image) = args.get(o.rest) else {
        return StdinUse::None;
    };
    cx.anywhere(&image.text);
    cx.inner(&args[o.rest + 1..], level)
}

fn compose(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const GLOBAL: &[&str] = &[
        "-f",
        "--file",
        "-p",
        "--project-name",
        "--profile",
        "--env-file",
        "--project-directory",
        "--ansi",
        "--parallel",
    ];
    let Some((v, k)) = verb(args, GLOBAL) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "run" => {
            let o = parse_opts(
                rest,
                &[
                    "-e",
                    "--env",
                    "-u",
                    "--user",
                    "-w",
                    "--workdir",
                    "--name",
                    "-v",
                    "--volume",
                    "-p",
                    "--publish",
                    "--entrypoint",
                    "-l",
                    "--label",
                    "--cap-add",
                    "--cap-drop",
                ],
            );
            for e in o.values(&["--entrypoint"]) {
                let e = e.to_string();
                cx.script(&e);
            }
            prefix(&rest[o.rest.min(rest.len())..], &[], 1, cx, level)
        }
        "exec" => prefix(rest, DOCKER_EXEC_VALS, 1, cx, level),
        _ => StdinUse::None,
    }
}

fn kubectl(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    const GLOBAL: &[&str] = &[
        "-n",
        "--namespace",
        "--context",
        "--kubeconfig",
        "--cluster",
        "--user",
        "-s",
        "--server",
        "--token",
        "--as",
        "--as-group",
    ];
    let Some((v, k)) = verb(args, GLOBAL) else {
        return StdinUse::None;
    };
    let rest = &args[k + 1..];
    match v {
        "exec" | "debug" | "run" | "attach" => {
            if let Some(d) = dashdash(rest) {
                return cx.inner(&rest[d + 1..], level);
            }
            if v == "exec" {
                return prefix(
                    rest,
                    &[
                        "-c",
                        "--container",
                        "-n",
                        "--namespace",
                        "-f",
                        "--filename",
                        "--pod-running-timeout",
                        "--context",
                        "--kubeconfig",
                    ],
                    1,
                    cx,
                    level,
                );
            }
            StdinUse::None
        }
        _ => StdinUse::None,
    }
}

fn ssh_o_values(args: &[Word], cx: &mut Cx) {
    for v in scan_values(args, &["-o"]) {
        let split = v.find(|c: char| c == '=' || c.is_whitespace());
        let Some(at) = split else { continue };
        let key = v[..at].trim().to_lowercase();
        if matches!(
            key.as_str(),
            "proxycommand" | "localcommand" | "knownhostscommand" | "remotecommand"
        ) {
            let val = v[at + 1..].trim_start_matches(|c: char| c == '=' || c.is_whitespace());
            cx.script(val);
        }
    }
}

fn ssh(args: &[Word], cx: &mut Cx) -> StdinUse {
    const VALS: &[&str] = &[
        "-b", "-B", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o",
        "-p", "-Q", "-R", "-S", "-W", "-w",
    ];
    ssh_o_values(args, cx);
    let o = parse_opts(args, VALS);
    if args.get(o.rest).is_none() {
        return StdinUse::None;
    }
    let remote = &args[o.rest + 1..];
    if remote.is_empty() {
        return StdinUse::Anywhere;
    }
    cx.script(&join(remote));
    StdinUse::None
}

fn screen(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if a == "-X" {
            cx.anywhere(&join(&args[i + 1..]));
            return StdinUse::None;
        }
        if matches!(
            a,
            "-S" | "-c" | "-e" | "-h" | "-p" | "-T" | "-t" | "-s" | "-Logfile"
        ) {
            i += 2;
            continue;
        }
        if !a.starts_with('-') {
            break;
        }
        let takes_value = a.len() > 2
            && !a.starts_with("--")
            && matches!(
                a.chars().last(),
                Some('S' | 'c' | 'e' | 'h' | 'p' | 'T' | 't' | 's')
            );
        i += if takes_value { 2 } else { 1 };
    }
    cx.inner(&args[i.min(args.len())..], level)
}

fn tmux(args: &[Word], cx: &mut Cx) -> StdinUse {
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if !a.starts_with('-') {
            break;
        }
        if a == "-c" {
            if let Some(v) = args.get(i + 1) {
                cx.script(&v.text);
            }
            i += 2;
        } else if matches!(a, "-L" | "-S" | "-f" | "-T") {
            i += 2;
        } else {
            i += 1;
        }
    }
    let Some(v) = args.get(i) else {
        return StdinUse::None;
    };
    let rest = &args[i + 1..];
    match v.text.as_str() {
        "new" | "new-session" | "new-window" | "neww" | "split-window" | "splitw"
        | "respawn-pane" | "respawnp" | "respawn-window" | "respawnw" | "display-popup"
        | "popup" | "run-shell" | "run" | "if-shell" | "if" | "pipe-pane" | "pipep" => {
            let o = parse_opts(
                rest,
                &[
                    "-t", "-s", "-n", "-c", "-e", "-F", "-x", "-y", "-l", "-p", "-T", "-S",
                ],
            );
            cx.script(&join(&rest[o.rest..]));
        }
        "send-keys" | "send" => cx.anywhere(&join(rest)),
        _ => {}
    }
    StdinUse::None
}

fn git(args: &[Word], cx: &mut Cx, level: usize) -> StdinUse {
    let mut i = 0;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if a == "-c" {
            if let Some(kv) = args.get(i + 1)
                && let Some((_, v)) = kv.text.split_once('=')
            {
                cx.script(v.strip_prefix('!').unwrap_or(v));
            }
            i += 2;
        } else if matches!(
            a,
            "-C" | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--config-env"
                | "--exec-path"
        ) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            break;
        }
    }
    let Some(sub) = args.get(i) else {
        return StdinUse::None;
    };
    let rest = &args[i + 1..];
    match sub.text.as_str() {
        "rebase" => {
            for v in scan_values(rest, &["-x", "--exec"]) {
                cx.script(&v);
            }
        }
        "bisect" if rest.first().is_some_and(|w| w.text == "run") => {
            cx.inner(&rest[1..], level);
        }
        "submodule" => {
            if let Some(k) = rest.iter().position(|w| w.text == "foreach") {
                let after = &rest[k + 1..];
                let o = parse_opts(after, &[]);
                cx.script(&join(&after[o.rest..]));
            }
        }
        "filter-branch" => {
            for v in scan_values(
                rest,
                &[
                    "--env-filter",
                    "--tree-filter",
                    "--index-filter",
                    "--parent-filter",
                    "--msg-filter",
                    "--commit-filter",
                    "--tag-name-filter",
                ],
            ) {
                cx.script(&v);
            }
        }
        "difftool" | "mergetool" => {
            for v in scan_values(rest, &["-x", "--extcmd"]) {
                cx.script(&v);
            }
        }
        _ => {}
    }
    StdinUse::None
}

fn awk(args: &[Word], cx: &mut Cx) -> StdinUse {
    let o = parse_opts(
        args,
        &[
            "-F",
            "-v",
            "-f",
            "-i",
            "-l",
            "-e",
            "-E",
            "--field-separator",
            "--assign",
            "--file",
            "--include",
            "--load",
            "--source",
            "--exec",
        ],
    );
    let mut has_source = false;
    for c in o.values(&["-e", "--source"]) {
        cx.interp(c, InterpKind::General);
        has_source = true;
    }
    if o.has("-f") || o.has("--file") || o.has("-E") || o.has("--exec") || has_source {
        return StdinUse::None;
    }
    if let Some(p) = args.get(o.rest) {
        cx.interp(&p.text, InterpKind::General);
    }
    StdinUse::None
}

fn sed(args: &[Word], cx: &mut Cx) -> StdinUse {
    let scripts = scan_values(args, &["-e", "--expression"]);
    for s in &scripts {
        cx.interp(s, InterpKind::Sed);
    }
    let o = parse_opts(
        args,
        &["-e", "-f", "--expression", "--file", "-l", "--line-length"],
    );
    if !scripts.is_empty() || o.has("-f") || o.has("--file") {
        return StdinUse::None;
    }
    if let Some(s) = args[o.rest..].iter().find(|w| !w.text.is_empty()) {
        cx.interp(&s.text, InterpKind::Sed);
    }
    StdinUse::None
}

/// Interpreters with code options like `-e CODE`. With no code and no
/// script file, the code comes from stdin.
fn interpreter(args: &[Word], code_opts: &[&str], vals: &[&str], cx: &mut Cx) -> StdinUse {
    let codes = scan_values(args, code_opts);
    for c in &codes {
        cx.interp(c, InterpKind::General);
    }
    if !codes.is_empty() {
        return StdinUse::None;
    }
    let o = parse_opts(args, vals);
    match args.get(o.rest) {
        None => StdinUse::Interp,
        Some(w) if w.text == "-" => StdinUse::Interp,
        Some(w) => {
            for s in &w.subs {
                cx.anywhere(s);
            }
            StdinUse::None
        }
    }
}

/// perl/ruby: code flags can sit inside a cluster (`-ne CODE`, `-pe CODE`).
/// `attached` lists flags whose value is glued on, which end the cluster.
fn cluster_code_interpreter(args: &[Word], code: &str, attached: &str, cx: &mut Cx) -> StdinUse {
    let mut i = 0;
    let mut found = false;
    while let Some(w) = args.get(i) {
        let a = w.text.as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with('-') || a == "-" || a.starts_with("--") {
            if a.starts_with("--") {
                i += 1;
                continue;
            }
            break;
        }
        for (j, ch) in a[1..].char_indices() {
            if code.contains(ch) {
                let rest = &a[1 + j + ch.len_utf8()..];
                if rest.is_empty() {
                    if let Some(v) = args.get(i + 1) {
                        cx.interp(&v.text, InterpKind::General);
                        i += 1;
                    }
                } else {
                    cx.interp(rest, InterpKind::General);
                }
                found = true;
                break;
            }
            if attached.contains(ch) {
                break;
            }
        }
        i += 1;
    }
    if found {
        return StdinUse::None;
    }
    match args.get(i) {
        None => StdinUse::Interp,
        Some(w) if w.text == "-" => StdinUse::Interp,
        Some(_) => StdinUse::None,
    }
}
