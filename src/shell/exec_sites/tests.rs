use super::*;

const INFISICAL_SUBS: &[&str] = &["login", "run", "export", "secrets"];
const MISE_SUBS: &[&str] = &["env", "exec", "x", "install", "use", "run"];

fn subs_for(name: &str) -> &'static [&'static str] {
    match name {
        "infisical" => INFISICAL_SUBS,
        "mise" => MISE_SUBS,
        _ => &[],
    }
}

fn invocations(cmd: &str, name: &str) -> Vec<Invocation> {
    ExecSites::parse(cmd).invocations(&[name], subs_for(name))
}

fn assert_hits(name: &str, cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            !invocations(cmd, name).is_empty(),
            "expected `{name}` site in: {cmd}"
        );
    }
}

fn assert_no_hits(name: &str, cmds: &[&str]) {
    for cmd in cmds {
        assert!(
            invocations(cmd, name).is_empty(),
            "unexpected `{name}` site in: {cmd}: {:?}",
            invocations(cmd, name)
        );
    }
}

// ── Normalization ───────────────────────────────────────────────────────────

#[test]
fn test_normalize_command_name() {
    assert_eq!(normalize_command_name("mise"), "mise");
    assert_eq!(normalize_command_name("/opt/homebrew/bin/mise"), "mise");
    assert_eq!(normalize_command_name("./bin/mise"), "mise");
    assert_eq!(normalize_command_name("MiSe"), "mise");
    assert_eq!(normalize_command_name("=mise"), "mise");
}

// ── Mentions as data are allowed ────────────────────────────────────────────

#[test]
fn test_data_mentions_allowed() {
    assert_no_hits(
        "infisical",
        &[
            "brew bundle add infisical",
            "brew install infisical",
            "grep -i infisical src",
            r#"git commit -m "fix infisical""#,
            "git commit -m 'infisical run is blocked'",
            "ls # infisical run",
            "echo infisical run",
            "rg 'infisical run' src",
            "cat infisical.md",
            "awk '/infisical/ { print $1 }' f",
            "sed 's/infisical/x/g' f",
            "python -c 'print(\"infisical\")'",
            "for x in infisical mise; do echo $x; done",
            "case $x in infisical) echo hi;; esac",
            "echo \"$(echo infisical)\"",
        ],
    );
    assert_no_hits(
        "env",
        &[
            "cat src/rules/env.rs",
            "grep env file",
            "cat .env.example",
            "echo $MY_ENV_VAR",
            "pyenv install 3.12",
            "ls -la env/",
        ],
    );
    assert_no_hits(
        "mise",
        &[
            "rg mise",
            "npm install promise",
            "cat .mise.toml",
            "ls mise.toml",
        ],
    );
}

// ── Command position ────────────────────────────────────────────────────────

#[test]
fn test_command_positions() {
    assert_hits(
        "infisical",
        &[
            "infisical",
            "infisical run -- ls",
            "cd x && infisical run",
            "cd x; infisical run",
            "cd x\ninfisical run",
            "true || infisical run",
            "ls | infisical run",
            "ls |& infisical run",
            "sleep 1 & infisical run",
            "(infisical run)",
            "{ infisical run; }",
            "if true; then infisical run; fi",
            "while true; do infisical run; done",
            "! infisical run",
            "X=1 infisical run",
            "> out infisical run",
            "2>&1 infisical run",
            "f() { infisical run; }",
            "function f { infisical run; }",
            "case x in a) infisical run;; esac",
            "for x in a; do infisical run; done",
            "coproc infisical run",
            "/opt/homebrew/bin/infisical run",
            "Infisical run",
            "INFISICAL run",
        ],
    );
}

#[test]
fn test_substitutions() {
    assert_hits(
        "infisical",
        &[
            "$(infisical export)",
            "echo $(infisical export)",
            "echo `infisical export`",
            "echo \"$(infisical export)\"",
            "TOK=$(infisical export)",
            "echo ${x:-$(infisical export)}",
            "diff <(infisical export) f",
            "tee >(infisical run) < f",
            "echo $(echo $(infisical export))",
            "echo $( (infisical run) )",
            "echo $(case x in a) infisical run;; esac)",
            "echo $((1 + $(infisical export)))",
        ],
    );
}

#[test]
fn test_quoting_obfuscation() {
    assert_hits(
        "infisical",
        &[
            "'infi''sical' run",
            "\"infisical\" run",
            "infi\\sical run",
            "\\infisical run",
            "$'\\x69nfisical' run",
            "$'\\151nfisical' run",
            "$'\\u0069nfisical' run",
            "$\"infisical\" run",
            "{infisical,x} run",
            "infisica? run",
            "infi* run",
            "infisic[a-z]l run",
            "infi\\\nsical run",
            "${x:-infisical} run",
            "$(echo infisical) run",
            "=infisical run",
        ],
    );
}

#[test]
fn test_comments_parsed_both_ways() {
    // In the no-comment pass, `foo # infisical run` has `infisical run` as adjacent arguments.
    assert_hits("infisical", &["foo # infisical run"]);
    assert_no_hits("infisical", &["ls # infisical run", "echo hi # infisical"]);
}

// ── Wrappers ────────────────────────────────────────────────────────────────

#[test]
fn test_wrappers() {
    assert_hits(
        "infisical",
        &[
            "sudo infisical run",
            "sudo -u root infisical run",
            "sudo -E FOO=1 infisical run",
            "doas infisical run",
            "nohup infisical run",
            "nice -n 5 infisical run",
            "timeout 5 infisical run",
            "timeout -s KILL 5 infisical run",
            "gtimeout 5s infisical",
            "time infisical run",
            "stdbuf -oL infisical run",
            "env infisical run",
            "env -i FOO=1 infisical run",
            "env -u HOME infisical",
            "env -S 'infisical run'",
            "command infisical run",
            "builtin infisical",
            "exec infisical run",
            "exec -a x infisical run",
            "xargs infisical",
            "xargs -n1 infisical run",
            "xargs -I{} infisical run {}",
            "find . -exec infisical {} \\;",
            "find . -execdir infisical run {} +",
            "fd . -x infisical run",
            "parallel infisical ::: run",
            "parallel ::: 'infisical run'",
            "watch infisical run",
            "watch -n 1 'infisical run'",
            "strace -f -o out infisical run",
            "gdb --args infisical run",
            "gdb infisical",
            "valgrind --tool=memcheck infisical",
            "caffeinate -i infisical run",
            "arch -arm64 infisical run",
            "chroot /x infisical",
            "flock /tmp/l infisical run",
            "flock /tmp/l -c 'infisical run'",
            "setsid infisical run",
            "systemd-run --user infisical run",
            "ssh-agent infisical run",
            "tini -- infisical run",
            "sudo sudo infisical",
            "timeout infisical run",
            "op run -- infisical run",
            "aws-vault exec prof -- infisical run",
            "doppler run -- infisical run",
            "doppler run --command 'infisical run'",
            "chamber exec svc -- infisical run",
            "envchain ns infisical run",
            "dotenv run infisical run",
            "dotenvx run -f .env -- infisical run",
            "uv run infisical",
            "poetry run infisical run",
            "pipenv run infisical run",
            "bundle exec infisical run",
            "brew bundle exec infisical run",
            "mise exec -- infisical run",
            "asdf exec infisical run",
            "direnv exec . infisical run",
            "nix develop -c infisical run",
            "devbox run infisical run",
            "docker run --rm img infisical run",
            "docker exec -it c infisical run",
            "docker compose exec web infisical run",
            "kubectl exec pod -- infisical run",
            "screen -dmS s infisical run",
            "busybox infisical",
        ],
    );
}

#[test]
fn test_package_runners() {
    assert_hits(
        "infisical",
        &[
            "npx @infisical/cli run",
            "npx -p @infisical/cli run",
            "bunx @infisical/cli",
            "pnpm dlx @infisical/cli",
            "yarn dlx @infisical/cli",
            "npm exec --package=@infisical/cli -- x",
            "uvx infisical-python",
            "uv tool run --from infisical-python x",
            "pipx run infisical",
            "nix run nixpkgs#infisical",
            "nix shell nixpkgs#infisical -c ls",
            "nix-shell -p infisical",
            "docker run infisical/cli",
            "pnpm infisical run",
        ],
    );
    assert_no_hits(
        "env",
        &["npx eslint src/rules/env.rs", "npx prettier --write env.md"],
    );
}

// ── Shells and code strings ─────────────────────────────────────────────────

#[test]
fn test_shell_code_strings() {
    assert_hits(
        "infisical",
        &[
            "bash -c 'infisical run'",
            "bash -lc 'infisical run'",
            "sh -c \"cd x && infisical run\"",
            "zsh -c 'infisical run'",
            "bash -o pipefail -c 'infisical run'",
            "fish -c 'infisical run'",
            "eval infisical run",
            "eval 'infisical run'",
            "eval \"$(infisical export)\"",
            "su -c 'infisical run' root",
            "su - root -c 'infisical run'",
            "runuser -u x -- infisical run",
            "sg grp -c 'infisical run'",
            "trap 'infisical run' EXIT",
            "alias x='infisical run'",
            "GIT_SSH_COMMAND='infisical run' git fetch",
            "PROMPT_COMMAND='infisical run'",
            "export PROMPT_COMMAND='infisical run'",
            "X=infisical",
            "arr=(infisical run)",
            "ssh host infisical run",
            "ssh -p 22 host 'infisical run'",
            "ssh -o ProxyCommand='infisical run' host",
            "ssh -oProxyCommand=infisical host",
            "scp -o 'ProxyCommand infisical run' a b:",
            "git -c alias.x='!infisical run' x",
            "git -c core.sshCommand=infisical fetch",
            "git rebase -x 'infisical run' main",
            "git bisect run infisical run",
            "git submodule foreach 'infisical run'",
            "rsync -e 'infisical run' a b:",
            "rsync --rsync-path='infisical run' a b:",
            "scp -S infisical a b:",
            "tar --to-command='infisical run' -xf a.tar",
            "tar -I infisical -xf a.tar",
            "tar --checkpoint-action=exec='infisical run' -cf a.tar x",
            "rg --pre infisical x",
            "man -P 'infisical run' ls",
            "vim -c '!infisical run'",
            "vim '+!infisical run'",
            "gdb -ex 'shell infisical run'",
            "sqlite3 db '.shell infisical run'",
            "hyperfine 'infisical run'",
            "nodemon --exec 'infisical run'",
            "cargo watch -s 'infisical run'",
            "nix-shell --run 'infisical run'",
            "npx -c 'infisical run'",
            "tmux new-session -d 'infisical run'",
            "tmux send-keys -t x 'infisical run' Enter",
            "tmux run-shell 'infisical run'",
            "screen -X stuff 'infisical run'",
            "entr -s 'infisical run'",
            "docker run --entrypoint infisical img",
            "pwsh -c 'infisical run'",
        ],
    );
}

#[test]
fn test_stdin_into_shell() {
    assert_hits(
        "infisical",
        &[
            "echo 'infisical run' | sh",
            "echo 'infisical run' | bash -s",
            "printf 'infisical run' | sudo bash",
            "echo infisical run | grep y | sh",
            "echo infisical | xargs -I{} {} run",
            "echo 'infisical run' | . /dev/stdin",
            "echo 'infisical run' | source /dev/stdin",
            "source <(echo infisical run)",
            "bash <(echo infisical run)",
            "bash <<< 'infisical run'",
            "bash <<EOF\ninfisical run\nEOF",
            "bash <<'EOF'\ninfisical run\nEOF",
            "bash <<-EOF\n\tinfisical run\n\tEOF",
            "cat <<EOF | sh\ninfisical run\nEOF",
            "echo 'infisical run' | ssh host",
            "echo 'infisical run' | parallel",
        ],
    );
    assert_no_hits(
        "infisical",
        &[
            "echo 'infisical run' | grep x",
            "cat <<EOF\ninfisical run\nEOF",
            "cat <<EOF > notes.md\ninfisical run\nEOF",
        ],
    );
}

#[test]
fn test_heredoc_substitutions() {
    assert_hits("infisical", &["cat <<EOF\n$(infisical export)\nEOF"]);
    assert_no_hits("infisical", &["cat <<'EOF'\n$(infisical export)\nEOF"]);
}

#[test]
fn test_interpreters() {
    assert_hits(
        "infisical",
        &[
            "python -c 'import os;os.system(\"infisical run\")'",
            "python3 -c 'import subprocess; subprocess.run([\"infisical\"])'",
            "perl -e 'system(\"infisical run\")'",
            "perl -ne 'print `infisical run`'",
            "ruby -e '`infisical run`'",
            "node -e 'require(\"child_process\").execSync(\"infisical run\")'",
            "php -r 'shell_exec(\"infisical run\");'",
            "lua -e 'os.execute(\"infisical run\")'",
            "osascript -e 'do shell script \"infisical run\"'",
            "awk 'BEGIN { system(\"infisical run\") }'",
            "awk '{ \"infisical export\" | getline x }'",
            "sed 's/.*/infisical run/e' f",
            "sed -e '1e infisical run' f",
            "echo 'import os; os.system(\"infisical\")' | python",
            "python - <<EOF\nimport os\nos.system('infisical run')\nEOF",
        ],
    );
}

// ── Adjacency heuristic ─────────────────────────────────────────────────────

#[test]
fn test_adjacency_unknown_wrapper() {
    assert_hits(
        "infisical",
        &[
            "mywrapper infisical run",
            "with-secrets --x infisical login",
        ],
    );
    assert_no_hits(
        "infisical",
        &[
            "mywrapper infisical",
            "echo infisical run",
            "grep infisical run",
        ],
    );
}

// ── Captured and clean subcommands ──────────────────────────────────────────

#[test]
fn test_clean_subcommand() {
    let inv = invocations("mise install", "mise");
    assert_eq!(inv[0].clean.as_deref(), Some("install"));
    let inv = invocations(r#"mise "install""#, "mise");
    assert_eq!(inv[0].clean.as_deref(), Some("install"));
    let inv = invocations("cd x && mise install", "mise");
    assert_eq!(inv[0].clean.as_deref(), Some("install"));
}

#[test]
fn test_unclean_subcommand() {
    let inv = invocations("mise --cd /x install", "mise");
    assert_eq!(inv[0].captured, None);
    assert_eq!(inv[0].clean, None);
    let inv = invocations("mise $SUB", "mise");
    assert_eq!(inv[0].clean, None);
    let inv = invocations("mis? install", "mise");
    assert_eq!(inv[0].clean, None);
    // `$(mise install)` as the command word runs the output too.
    assert!(
        invocations("$(mise install)", "mise")
            .iter()
            .any(|i| i.clean.is_none())
    );
}

#[test]
fn test_invocation_name() {
    let sites = ExecSites::parse("ls && printenv PATH");
    let inv = sites.invocations(&["env", "printenv"], &[]);
    assert_eq!(inv.len(), 1);
    assert_eq!(inv[0].name, "printenv");
}

fn first(cmd: &str, name: &str, subs: &[&str]) -> Invocation {
    ExecSites::parse(cmd).invocations(&[name], subs).remove(0)
}

#[test]
fn test_invocation_argv_and_kind() {
    let inv = first("sudo gcloud --project p auth list", "gcloud", &[]);
    assert_eq!(inv.kind, SiteKind::Command);
    assert_eq!(inv.argv, ["--project", "p", "auth", "list"]);
    assert!(!inv.open);

    let inv = first("mytool gcloud auth list", "gcloud", &["auth"]);
    assert_eq!(inv.kind, SiteKind::Adjacent);
    assert_eq!(inv.argv, ["auth", "list"]);

    let inv = first(
        r#"python -c 'subprocess.run(["gcloud", "auth", "list"])'"#,
        "gcloud",
        &[],
    );
    assert_eq!(inv.kind, SiteKind::Opaque);
    assert_eq!(&inv.argv[..2], ["auth", "list"]);

    let inv = first("docker run amazon/aws-cli s3 ls", "aws", &[]);
    assert_eq!(inv.kind, SiteKind::Exact);
    assert!(inv.argv.is_empty());

    // Non-literal words keep their text in `argv`.
    let inv = first("gcloud $SUB list", "gcloud", &[]);
    assert_eq!(inv.argv, ["$SUB", "list"]);
}

#[test]
fn test_invocation_open_args() {
    for cmd in [
        "ls | xargs rm",
        "xargs -I {} sudo rm {}",
        "find . -exec rm {} +",
        "find . -ok rm {} ;",
        "parallel rm ::: a b",
    ] {
        assert!(first(cmd, "rm", &[]).open, "{cmd}");
    }
    for cmd in ["rm a", "sudo rm a", "echo $(rm a)", "xargs sh -c 'rm a'"] {
        assert!(!first(cmd, "rm", &[]).open, "{cmd}");
    }
}

// ── Fail closed ─────────────────────────────────────────────────────────────

#[test]
fn test_parse_errors_fall_back_to_anywhere() {
    assert_hits(
        "infisical",
        &[
            "echo 'unterminated infisical",
            "echo \"$(infisical",
            "echo )infisical",
            "echo `infisical",
        ],
    );
}

#[test]
fn test_deep_nesting_falls_back() {
    let mut cmd = "infisical run".to_string();
    for _ in 0..40 {
        cmd = format!("echo $({cmd})");
    }
    assert_hits("infisical", &[&cmd]);
    let cmd = format!("{}infisical run", "eval ".repeat(40));
    assert_hits("infisical", &[&cmd]);
}

#[test]
fn test_pathological_input_terminates() {
    let cmd = "${".repeat(5000);
    let _ = ExecSites::parse(&cmd);
    let cmd = "$(".repeat(5000);
    let _ = ExecSites::parse(&cmd);
    let cmd = "a=(".repeat(5000);
    let _ = ExecSites::parse(&cmd);
}
