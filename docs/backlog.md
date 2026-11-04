# Backlog

## Audit log path is unrestricted

`[audit] path` can point anywhere, and the hook appends a JSON line (including
the command text) on every decision. A `.security-hook.toml` in a cloned repo
can set it to a file such as `~/.bashrc` and turn on appends to it. Options:
restrict the path to a fixed directory, make `[audit]` user-config only, or
refuse paths outside `~/.local/state`.
