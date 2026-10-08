# Autonomous Coding Agent (ACA) Safety Net

> **Note:** This project is a hard fork of [claude-code-safety-net](https://github.com/kenryu42/claude-code-safety-net) by kenryu42. Primary attribution goes to the original project.
>
> **Inherited from original:** Two-level config system (user + project with merging), secrets protection, destructive command detection, shell-aware parsing, custom rules, fail-open design.
>
> **New in this fork:** Claude-driven rewrite in Rust (original is Python), TOML config format (original uses JSON), cloud CLI protection (Heroku, AWS, GCloud), dependency file protection, audit logging.

A fast, Rust-based security hook for autonomous coding agents. Blocks access to sensitive files, dangerous commands, and environment variable exposure.

**Currently supports Claude Code.** We plan to add support for [opencode](https://github.com/sst/opencode) and other autonomous coding tools. Contributions welcome!

## Features

- **Zero Config**: Works out of the box with pretty good defaults—no configuration required
- **Fast**: <5ms execution (vs 50-100ms for Python alternatives)
- **Secrets Protection**: Blocks read access to `.env`, credentials, SSH keys, API tokens
- **Cloud CLI Protection**: Blocks secret-exposing commands from Heroku, AWS, and GCloud CLIs
- **Destructive Command Detection**: Blocks `rm -rf` outside working directory, dangerous git operations
- **Shell-Aware**: Parses command chains (`&&`, `||`, `|`, `;`), strips wrappers (`sudo`, `env`, `bash -c`)
- **Configurable**: Optional TOML config to extend defaults with custom rules
- **Dependency Protection**: Prompts for approval before editing package manifests (supply chain defense)
- **Paranoid Mode**: Optional strict mode that blocks ANY mention of sensitive files

## Quick Start

### 1. Build and Install

```bash
just install
# Installs binary to ~/.local/bin/ and config to ~/.config/aca-safety-net/
# Ensure ~/.local/bin is in your PATH
```

### 2. Configure Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|Grep|Glob|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "aca-safety-net",
            "timeout": 1
          }
        ]
      }
    ]
  }
}
```

## Configuration

**No configuration required.** The hook includes hardcoded security defaults that protect against common threats out of the box.

### Hardcoded Defaults

The following protections are always active:

- **Sensitive files**, in toggleable groups:
  - `env_files`: `.env`, `.envrc`
  - `direnv`: `.direnv/`, `direnvrc`, `~/.config/direnv/`
  - `mise`: `.mise*`, `mise.toml`, `~/.config/mise/`
  - `shadowenv`: `.shadowenv.d/`
  - `credentials`: `credentials`, `secrets`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`
  - `keys`: `.pem`, `.key`, `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519` (case-insensitive)
  - `ssh`: everything under `.ssh/` except `*.pub`, `config`, `known_hosts`, `authorized_keys` (readable, never writable)
  - `cloud`: `.kube/config`, `kubeconfig`, `.aws/credentials`, `.config/gcloud/`, `.config/gh/hosts.yml`
  - `history`: `_history`, `.bash_history`, `.zsh_history`
- **Env-loading tools** (toggleable): `direnv`, `mise`, `shadowenv`
- **Always locked**: `infisical`, `env`, `printenv`
- **Read commands**: `cat`, `head`, `tail`, `less`, `more`, `grep`, `rg`, `ag`, `sed`, `awk`, `strings`, `xxd`, `hexdump`, `bat`, `view`
- **Deny rules**: `set`, `declare -x`, `export`, `history`, `/proc/*/environ`, `ps -E`/`ps auxe`, docker/podman env exposure and inspect, agent writes to the hook's own config files
- **Dependency protection**: Enabled for all standard package manifests

### Optional Config Files

To add custom rules or override settings, create config files that are loaded and merged in order:

1. `~/.config/aca-safety-net/config.toml` (user-level, global)
2. `.security-hook.toml` (project-level, in cwd)

**Merge behavior:**
- Arrays (`sensitive_files`, `deny`, `patterns`) are **extended** (your patterns added to defaults)
- Scalars (`enabled` flags) can be **overridden**
- **Project config can only tighten.** Relaxing keys in `.security-hook.toml` (`sensitive_groups`, `tools`, `profile`, `allowed_files`, `read_commands`, `dependencies.enabled = false`, `rm.allowed_paths`, `git.force_push_allowed_branches`) are ignored with a warning, since the agent works inside the project. Put them in the user config.

`just install` only writes the user config if it doesn't exist yet.

### SSH Keys

SSH private keys get stricter treatment than other sensitive files, governed by the `ssh` group (on by default, not part of `secretless`):

- **Any Bash command** that mentions `.ssh` or a default key name (`id_rsa`, `id_ed25519`, ...) is blocked, not just read commands. This covers `cp`, `tar`, `scp`, `base64`, `python -c "open(...)"`, `$(...)`, globs (`~/.ssh/*`), `ls ~/.ssh`, and `cd ~/.ssh && ...`.
- **Readable:** `~/.ssh/config`, `known_hosts`, `authorized_keys`, and any `*.pub`. Nothing under `.ssh` is writable by an agent (Edit, Write, NotebookEdit, or Bash `>`, `tee`, `cp`, `mv`, `rm`, `sed -i`, ...).
- **No explicit keys:** `ssh`/`scp`/`sftp -i`, `-o IdentityFile=`, `rsync -e 'ssh -i ...'`, and `GIT_SSH_COMMAND` / `core.sshCommand` with a key are blocked. Agents connect with `ssh <host-alias>` and let `~/.ssh/config` or ssh-agent pick the key.
- **Human-only commands:** `ssh-add`, `ssh-keygen`, and `ssh-copy-id` are blocked anywhere in a command, with a message telling the agent to ask the user to run them. `ssh-keyscan` is allowed.
- **File tools:** Read, Edit, Write, Grep (`path`, `glob`), Glob (`path`, `pattern`), and NotebookEdit are all checked. Add `Grep|Glob|NotebookEdit` to the hook matcher (see Installation) for the last three.

If your private keys live outside the filesystem (1Password SSH agent, Secretive), you can turn this off with `[sensitive_groups] ssh = false`. The `keys` group still covers key-named files.

**Limits:** the hook matches command text. It cannot see paths assembled at runtime (e.g. from base64), `find ~ -name 'id_*' -exec cat {} +`, or file access through MCP servers.

### Relaxing Env-File Protection

If secrets never touch disk (e.g. they are injected at runtime with `infisical run`), env files and the tools that load them are just config. Turn their protection off in the **user config**:

```toml
# All at once
profile = "secretless"

# Or piecemeal
[sensitive_groups]
env_files = false        # .env, .envrc readable/stageable

[tools.direnv]
enabled = false          # allow all direnv commands

[tools.mise]
allow_subcommands = ["install", "use", "ls"]   # allow only these
```

- Explicit `[sensitive_groups]` / `[tools]` entries override the profile.
- `allow_subcommands` matches the literal word right after the tool (`mise install`, `mise "install"`, also inside `$(...)` or `bash -c`). Flag-prefixed (`mise --cd x install`), variable, glob and command-word-substitution forms stay blocked.
- `mise env` stays blocked even with mise disabled, because the `env` analyzer is always on.
- Unknown group, tool or profile names produce a warning and leave protection on.
- If your user config lists a built-in pattern in `sensitive_files` (older installs copied all defaults there), that copy keeps blocking after its group is disabled. A warning tells you which to remove.

### Example Config

```toml
# Add extra sensitive file patterns (merged with the enabled built-in groups)
sensitive_files = [
    'my-company-secrets',
]

# Add custom deny rules (merged with defaults)
[[deny]]
tool = "Bash"
pattern = 'curl.*-d\\s+@'
reason = "Blocks curl file uploads"

# Allow force push to specific branches (default: block all)
[git]
force_push_allowed_branches = ["feature/*"]

# Enable paranoid mode (blocks ANY mention of sensitive files)
[paranoid]
enabled = true

# Enable audit logging
[audit]
enabled = true
path = "~/.config/aca-safety-net/audit.log"
```

## What Gets Blocked

### Sensitive Files (Read + Bash)

- `.env`, `.envrc`, `.env.local`, `.env.production`, `.env.test`
- Safe variants are **allowed**: `.env.example`, `.env.sample`, `.env.template`, `.env.dist` (including with extra segments like `.env.test.example`, `.env.production.sample`)
- SSH keys: `id_rsa`, `id_ed25519`, `id_ecdsa`
- Credentials: `.aws/credentials`, `.config/gcloud/`, `.netrc`, `.npmrc`
- Certificates: `*.pem`, `*.key`
- History files: `.bash_history`, `.zsh_history`

### Env-Loading Tools (Bash)

`infisical`, `direnv`, `mise`, `shadowenv`, `env`, `printenv` and `gprintenv` are blocked wherever the shell would **run** them, and allowed where they only appear as data (`grep -i mise src`, `brew install direnv`, `git commit -m "fix infisical"`, `cat src/rules/env.rs`).

The command is parsed, not regex-matched:

- **Command positions:** after `;` `&&` `||` `|` `&` newlines and `(`, past leading assignments, redirections and reserved words (`if`, `do`, `!`, `{`, ...). `for`/`case`/`select` word lists and `function` names are data.
- **Substitutions:** `$(...)`, backticks, `<(...)`, `>(...)`, also inside double quotes, `${...}` and unquoted heredocs, are parsed recursively.
- **Obfuscation:** quote removal (`'infi''sical'`), backslash escapes, `$'\x69...'`, case (`Infisical`), paths (`/opt/bin/mise`, `=mise`), brace expansion (`{mise,x}`) and globs (`mis?`) are resolved before matching.
- **Wrappers:** `sudo`, `timeout`, `nohup`, `xargs`, `find -exec`, `env`, `nice`, `strace`, `gdb --args`, `docker run|exec`, `kubectl exec`, `npx`/`uvx`/`pnpm dlx` (the package spec counts), `uv run`, `op run`, `mise exec`, `direnv exec`, `nix shell -c`, and more are looked through.
- **Code strings:** `bash -c`, `eval`, `su -c`, `ssh host CMD`, `watch`, `trap`, `alias`, assignment values (`GIT_SSH_COMMAND=...`), `git -c alias.x=!...`, `ssh -o ProxyCommand=...`, `rsync -e`, `tar --to-command`, and similar are parsed as shell. Text piped or redirected into a shell (`... | sh`, `bash <<EOF`) is searched for the name anywhere. Interpreter code (`python -c`, `perl -e`, `awk`, `sed .../e`, ...) is blocked when it names the tool and can start a process.
- **Unknown wrappers:** `somewrapper mise install` is blocked when the tool is followed by one of its known subcommands.
- **Fail closed:** text that can't be parsed, or nests too deeply, is searched for the name anywhere. Comments are checked both as comments and as code.

Side effects of failing closed: an assignment whose value is the tool name (`X=mise`) is blocked, and a comment that mentions the tool and contains an unbalanced quote may be blocked.

### Environment Exposure (Bash)

- `printenv`, `set`, `export`, `declare -x`
- `history` (exposes command history which may contain secrets)
- `/proc/*/environ`
- `ps auxe`, `ps -E`
- `docker inspect`, `docker exec ... env`

### Destructive Git Operations

- `git checkout --` (discards changes)
- `git reset --hard` (discards all uncommitted changes)
- `git push -f` to main/master/develop/release
- `git branch -D` (force delete)
- `git stash drop`, `git stash clear`
- `git clean -f`
- `git add .env` (blocks staging sensitive files)

### Dangerous rm Operations

- `rm -rf /` or system directories (`/home`, `/etc`, `/usr`, etc.)
- `rm -rf` outside current working directory
- `rm -rf ../../..` (parent traversal)
- Allowed: `rm -rf` in cwd or `/tmp`

### Dangerous find/xargs/parallel

- `find -delete`
- `find -exec rm`
- `xargs rm`
- `parallel rm`

### Cloud CLI Secret Exposure

#### Heroku
- `heroku auth:token` (exposes auth token)
- `heroku config` / `heroku config:get` (exposes env vars)
- `heroku pg:credentials` / `heroku redis:credentials` (database credentials)

#### AWS
- `aws secretsmanager get-secret-value` (retrieves secrets)
- `aws ssm get-parameter --with-decryption` (decrypts parameters)
- `aws kms decrypt` (decrypts data)
- `aws iam list-access-keys` / `aws iam create-access-key` (access key exposure)
- `aws sts get-session-token` / `aws sts assume-role` (temporary credentials)
- `aws configure export-credentials` (exports credentials)

#### GCloud
- `gcloud auth print-access-token` / `gcloud auth print-identity-token` (token exposure)
- `gcloud auth application-default print-access-token` (ADC token)
- `gcloud secrets versions access` (retrieves secret values)

**Allowed**: Non-secret queries like `aws s3 ls`, `gcloud config list`, `heroku apps`

## Dependency File Protection

This hook intercepts Edit/Write operations on package manifests and requires user approval before changes are applied. Because hooks operate at a lower layer than the UI, this protection works even when "accept edits" is enabled in Claude Code.

### Why This Matters

**1. LLM Training Lag**

LLMs have a knowledge cutoff date, meaning they suggest package versions that were current during training—often months or years behind. When an agent adds `requests==2.28.0` but the current version is `2.31.0`, you miss security patches and bug fixes. Worse, the agent may suggest packages that have been deprecated, renamed, or superseded entirely.

**2. Software Supply Chain Attacks**

Supply chain attacks have become one of the most critical vectors for compromising systems:

- **Typosquatting**: Malicious packages with names similar to popular ones (`reqeusts` vs `requests`)
- **Dependency confusion**: Attackers publish malicious packages to public registries that shadow private package names
- **Compromised maintainers**: Legitimate packages taken over by malicious actors
- **Version injection**: Specific versions containing malware

An agent editing `package.json` or `Cargo.toml` directly bypasses your opportunity to review what's being added. ACA Safety Net forces the agent to ask you before editing these files every time, even with "accept edits" enabled.

### Recommended: Soft Policy

ACA Safety Net provides the **hard policy** (the hook that forces approval). However, we highly recommend also adding a **soft policy** via agent instructions. This is not part of aca-safety-net, but complements it well.

Add to your `~/.claude/CLAUDE.md` or project's `CLAUDE.md`:

```markdown
## Supply Chain Security

You must NEVER add packages directly by editing dependency files.
Always use the package manager's CLI:

- cargo: `cargo add <package>`
- npm/yarn/pnpm: `npm install <package>`, `yarn add`, `pnpm add`
- uv: `uv add <package>`
- poetry: `poetry add <package>`
- bundler: `bundle add <gem>`
- go: `go get <package>`
```

This instructs the agent to use CLI commands instead of editing files directly. To complete the protection, we highly recommend adding these commands to the `ask` section in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "ask": [
      "Bash(cargo add:*)",
      "Bash(npm install:*)",
      "Bash(yarn add:*)",
      "Bash(pnpm add:*)",
      "Bash(pip install:*)",
      "Bash(uv add:*)",
      "Bash(gem install:*)",
      "Bash(bundle add:*)",
      "Bash(go get:*)",
      "Bash(brew install:*)",
      "Bash(brew tap:*)",
      "Bash(mise install:*)"
    ]
  }
}
```

This defers package installation approval back to you, letting you review exactly what's being installed before it happens.

**Why both?** The soft policy reduces friction—the agent learns to use CLI commands and won't trigger the aca-safety-net approval prompt unnecessarily. The hard policy (aca-safety-net) is your safety net when the agent ignores instructions or makes mistakes.

### Why Ask, Not Deny?

We use "ask" mode instead of blocking outright because agents can still add legitimate value to package manifests:

- Editing `[package]` metadata in `Cargo.toml`
- Configuring build settings, features, or workspace options
- Updating `[tool.pytest]` or `[tool.ruff]` sections in `pyproject.toml`
- Modifying `scripts` in `package.json`

A hard deny would prevent all of these. Ask mode lets you approve configuration changes while catching dependency additions.

### Protected Files

By default, the hook protects:

| File | Ecosystem |
|------|-----------|
| `Cargo.toml` | Rust |
| `pyproject.toml` | Python |
| `requirements.txt` | Python |
| `package.json` | Node.js |
| `Gemfile` | Ruby |
| `go.mod` | Go |
| `pom.xml` | Java (Maven) |
| `build.gradle` / `build.gradle.kts` | Java/Kotlin (Gradle) |
| `composer.json` | PHP |
| `Package.swift` | Swift |

### Configuration

```toml
[dependencies]
enabled = true  # set to false to disable
patterns = [
    '(^|/)Cargo\.toml$',
    '(^|/)pyproject\.toml$',
    '(^|/)package\.json$',
    # ... add custom patterns
]
```

## Paranoid Mode

Enable paranoid mode to block ANY command that mentions sensitive files, not just read commands:

```toml
[paranoid]
enabled = true
extra_patterns = [
    'secret',
    'password',
]
```

With paranoid mode enabled, even `ls .env` or `echo ".env created"` will be blocked. Paranoid mode uses the enabled sensitive groups, so a disabled group is not checked here either.

## Custom Rules

Add custom rules to block or allow specific patterns:

```toml
[[rules]]
name = "block_curl_upload"
tool = "Bash"
pattern = 'curl.*-d\\s+@'
action = "block"
reason = "Blocks curl file uploads"

[[rules]]
name = "allow_safe_api"
tool = "Bash"
pattern = 'curl.*api\\.example\\.com'
action = "allow"
```

## How It Works

1. Claude Code invokes the hook via stdin (JSON with `tool_name`, `tool_input`)
2. Hook loads hardcoded defaults, then merges optional config from `~/.config/aca-safety-net/config.toml` (may relax) + `.security-hook.toml` (may only tighten). Config warnings are printed to stderr.
3. For Bash: parses command, strips wrappers, checks deny rules + sensitive patterns
4. For Read: checks file path against sensitive patterns
5. For Edit/Write: checks if file matches dependency patterns (returns "ask" for approval)
6. Exit 0 = allow, Exit 2 = block (message shown to Claude)

### Fail-Open Design

The hook fails open (allows) on:
- Stdin read errors
- JSON parse errors
- Invalid regex patterns in custom config

**Note:** Missing config files do NOT cause fail-open. Hardcoded defaults always apply, ensuring protection even without any configuration.

This design prevents the hook from breaking Claude Code if misconfigured while maintaining baseline security.

## Architecture

```
stdin JSON → Parse HookInput → Load Config
                                    ↓
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
               Bash Tool                       Read Tool
                    │                               │
      1. Check deny rules              1. Check deny rules
      2. Paranoid mode check           2. Sensitive patterns
      3. Read cmd + sensitive          3. Decision
      4. Git add sensitive                     ↓
      5. Split commands              Allow or Block
      6. Analyze segments
            │
      ┌─────┴─────┐
      ▼           ▼
   git/rm/    Recursive
   find/xargs  bash -c
```

## Known Limitations

Cannot detect or prevent:
- Variable expansion: `rm -rf $VAR`
- Symlink traversal
- Indirect file access: `python -c "open('.env')"`
- Network exfiltration: `curl -d @.env`
- Shell aliases
- Encoded/obfuscated commands

For the env-loading tools specifically, these are out of scope:
- Execution from files: `source f`, scripts, Makefiles, `just` recipes, `package.json` scripts, git config aliases, container image entrypoints, cron
- A variable as the command: `X=mise; $X env` (the assignment itself is blocked, but `$X` from the environment is not)
- Names assembled at runtime: `$(printf 'mi%s' 'se')`, base64, `rev`
- Renamed or copied binaries, and shell functions or aliases defined earlier in the session
- History re-execution (`!!`, `fc`)
- Remote environment semantics: a command run over `ssh` or in a container is checked as if it ran locally

This is static analysis only - it cannot execute commands to determine their actual behavior.

## Development

```bash
just test      # Run tests
just release   # Build release
just install   # Build and install
just ci        # Full CI check (fmt, lint, test)
```

## License

MIT
