# Installed Binary Audit — Env-Exposure Threat Surface

**Date:** 2026-05-17
**Host:** joenap's macOS laptop
**Scope:** every executable on `$PATH` (3157 unique names)
**Trigger:** after shipping direnv + mise blocking, we wanted to know
what other locally-installed tools have the same threat shape (load
env from project config / dump env to stdout / inject secrets into
child processes).

## Method

Two attempts:

1. **First attempt (rejected):** spawn `--help` on every binary, grep
   the output for env-related strings. Took minutes, produced zero
   matches (most `--help` outputs go to stderr, open man pages, or
   timeout), and wasted the model's existing knowledge of well-known
   CLIs. Also unnecessary process churn (3140 subprocesses for what is
   essentially a classification task).

2. **Second attempt (kept):** one-shot enumerate `$PATH` into a name
   list (no execution), then have the model triage from prior
   knowledge. Only fall back to external lookup (web search, man page)
   for genuinely unfamiliar names.

The lesson: for "what's installed and what does each thing do," the
model is the index — don't invoke every binary as if you have no prior
information. Reserve execution for verification, not discovery.

The enumeration command:

```bash
printf '%s\n' "$PATH" | tr ':' '\n' \
  | while IFS= read -r d; do [ -d "$d" ] && ls "$d" 2>/dev/null; done \
  | sort -u
```

3157 unique names, dominated by:

- coreutils + GNU `g*` variants
- compilers and language toolchains (gcc/clang/cargo/python3.{9..14}/perl/ruby/go)
- image processing (netpbm, libheif, exr*, pdf*)
- container/VM tooling (docker, podman, lima, qemu, VBox*, virsh)
- macOS system tools

Almost all benign. The interesting set is small.

## Findings

### Already blocked

- `direnv` — full block (commit `deb678a`)
- `mise` — full block (commit `d86ba08`)
- `env`, `printenv` — full block via env analyzer
- `aws`, `gcloud`, `az`, `kubectl`, `heroku` — secret-subcommand blocks
- `docker exec/run … env`, `docker inspect`, `docker-compose exec … env` —
  deny rules in `DEFAULT_DENY_RULES`

### Tier 1 — clear gaps

Mix of two shapes: hard-block tools whose entire purpose is env loading
or secret injection (direnv-style), and one narrow-block tool that
should be partially restricted (uv-style).

| Tool | Shape | Mechanism | Notes |
|---|---|---|---|
| `gprintenv` | hard block | GNU printenv variant | **Bug in existing hook.** Rule `^\s*printenv` doesn't match `gprintenv`. Fix: fold into the env analyzer so `printenv`/`gprintenv` get the same treatment as `env`. |
| `shadowenv` | hard block | Per-directory shell env loader (Shopify) | Direct direnv analog. `shadowenv hook`, `shadowenv exec`. |
| `infisical` | hard block | Secrets-injection CLI | `infisical run --` literally exists to inject secrets fetched from their cloud into a child process. No safe form. |
| `pipenv` | uv-style narrow block | Python virtualenv tool | Block only Pipfile-bypass forms (`install --skip-lock`, `install --ignore-pipfile`, `install -r requirements.txt`). Allow normal dep workflow (`install <pkg>`, `lock`, `sync`, `update`, `graph`, `requirements`, `check`). **Do not block `pipenv run` / `pipenv shell`** — the "auto-loads `.env`" framing is misleading; the actual leak (`pipenv run python -c "print(os.environ)"`) is the same shape as the README's documented "Indirect file access" limitation. Special-casing pipenv for it would be inconsistent with how we treat plain `python -c`. |

**Excluded from Tier 1 (originally listed, on reflection don't fit):**

- `asdf` — pure version manager, no built-in env-injection. Parallel to
  `pyenv` / `rbenv` / `nodenv` which we explicitly allow (negative
  tests in `src/rules/env.rs`). The `asdf-direnv` plugin does load env,
  but the actual `direnv` invocation it makes is caught by our existing
  direnv block. Treat like pyenv: allow.

### Tier 2 — secret-exposure as side effect

Tools where the binary itself is legitimate but specific subcommands
dump credentials or tokens. Consistent with the existing aws/gcloud
pattern (block only the leaky subcommands, not the whole tool).

| Tool | Risky subcommands |
|---|---|
| `security` (macOS) | `security find-generic-password -w`, `security dump-keychain`, `security find-internet-password` |
| `gh` | `gh auth token`, `gh secret list/get`, `gh api … /secrets` |
| `twilio` | `twilio profiles list`, `twilio api:core:accounts` (creds in output) |
| `influx` / `influxdb3` | `influx auth list/show`, token-printing flows |
| `git-credential-manager`, `git-credential-gcloud.sh`, `docker-credential-gcloud` | All are credential helpers — their job is to print creds when asked. Block invocation from agent context entirely. |

### Tier 3 — situational / defer

Real but lower-likelihood, or shape doesn't quite fit the existing
rules.

| Tool | Concern |
|---|---|
| `pyenv`, `rbenv`, `nodenv` | Version managers. `*-init` emits `eval "$( … )"` hooks; `*-exec` runs in managed env. No project-local secrets like mise/direnv, but the shell-hook pattern is similar. Lower priority. |
| `chezmoi` | Dotfile manager with template-driven secret decryption. `chezmoi data`, `chezmoi secret`. Used rarely from an agent. |
| `gpg`, `gpg-agent`, `gpg-connect-agent` | Decryption tool. `gpg -d secrets.gpg` is the textbook leak; already mitigated by sensitive-file patterns on the *input* but not as a command verb. |
| `lima`, `colima`, `*.lima` (`apptainer`, `docker`, `kubectl`, `nerdctl`, `podman`), `multipass`, `virsh`, `virt-*`, `qemu-*`, `VBox*`, `VirtualBox` | Container/VM tools. Each can `exec env`-style inside a guest. Existing rules catch `docker/podman exec … env`; not extended to these. |
| `helm`, `helmfile` | Can read k8s secrets (`helm get values`, …). Adjacent to kubectl. |

### Unfamiliar to me — confirm before flagging

Names in PATH that I can't classify with high confidence from prior
knowledge:

- `aiounifi` — Python CLI for Unifi controllers? Could store controller creds.
- `crewai` — Python multi-agent framework CLI. API keys in config likely.
- `evennia` — MUD framework. Probably safe.
- `goose` — Block's agentic CLI. Tool-using by design.
- `mcp-server-git` — MCP server. Server, not user-facing.
- `rpk` — Redpanda Kafka CLI. Auth tokens.
- `now-cli` — old Vercel CLI. `now secrets list`.
- `livekit-cli` — `livekit-cli token` generates JWT tokens.
- `rover` — Apollo's GraphQL rover. API keys in config.
- `kdash`, `kubetui`, `k9s`, `lk` — interactive k8s tools. Lower
  agent-invocation risk because they're TUIs.
- `wezterm` — terminal emulator (not a leak).
- `tailspin` — log highlighter (not a leak).

A web lookup pass would settle these; not blocking-critical.

## Recommended next steps

1. **Tier 1 (ship soon):** four items, two shapes.
   - `gprintenv` — fold into the env analyzer (bugfix on the existing
     `printenv` deny rule, which doesn't match the `g` prefix and is
     anchored at start-of-command).
   - `shadowenv`, `infisical` — new modules mirroring `src/rules/mise.rs`
     (full block).
   - `pipenv` — new module mirroring `src/rules/uv.rs` (narrow block on
     Pipfile-bypass flags only; allow normal dep workflow).

2. **Tier 2 (decide first):** for `security`, `gh`, `twilio`, `influx*`,
   credential helpers — choose between (a) block the whole binary like
   direnv, (b) block only the leaky subcommands like the existing
   aws/gcloud rules. Existing precedent leans toward (b) for "useful
   tools with narrow leak surface" and (a) for "tools whose entire
   purpose is sensitive data handling."

3. **Tier 3:** revisit after Tier 1/2 ship. Worth a separate decision
   pass on the container/VM tools as a group.

## Methodology takeaway

When scanning a system for "what's here that could be a problem":

- The model already knows what `git`, `npm`, `aws`, `kubectl`, `tar`,
  `ssh`, `curl`, `python`, `vim`, and the other thousand household
  names are. Running them just to confirm wastes effort and risks
  side effects.
- Enumerate names with one safe command. Classify in-context. Only
  spawn external lookups for names that resist classification.
- Treat the model as the **index**, not the **scanner**.
