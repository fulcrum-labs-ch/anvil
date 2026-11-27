# Plugin authoring

A plugin adds one out-of-tree hardening step without recompiling anvil. It
becomes a regular module: the engine renders its probe/apply scripts, the
marker protocol and two-phase apply work unchanged, and it participates in
ordering and results as `plugin::<name>`.

## Layout

```
~/.config/anvil/plugins/<name>/
├── plugin.toml   # manifest (required)
├── apply.sh      # converge step (required)
└── check.sh      # detect step (optional)
```

(`$XDG_CONFIG_HOME` is honored if set.)

## Manifest

```toml
# plugin.toml
name = "backup-agent"          # must equal the directory name
section = "backup_agent"       # the config table this plugin binds
order = 42                     # optional ordering hints…
before = ["updates"]
after = ["sshd"]
secrets = ["token"]            # keys whose values --dry-run masks
```

`section` is the TOML table in the *user's* config that enables the plugin —
present means enabled, exactly like built-in modules:

```toml
# harden.toml
[backup_agent]
target = "s3://backups/host1"
```

A plugin may not bind a built-in module's section name or a structural key
(`host`, `hosts`, `execution_order`, `profile`, `include`).

## Scripts and `{{VAR}}` substitution

`check.sh` is the *detect* expression: exit `0` when the host is already
converged, non-zero when the plugin needs to act. Without a `check.sh` the
plugin always converges. `apply.sh` makes the change. Both run under
`bash -euo pipefail` on the target (via sudo when the login user isn't
root): `check.sh` in its own `bash -euo pipefail -c`, so any failing line
reports drift, `apply.sh` in a subshell of the engine's script.

`check.sh` must be **total**: a non-zero exit is read as "drift" and triggers
`apply.sh`. If the check itself is buggy or trips on a missing binary, that
non-zero exit is indistinguishable from real drift, so `apply.sh` will run —
write the check defensively (exit `0`/non-zero only on the converge question,
never because the check crashed). The plugin directory's parent (`plugins/`)
is also trust-checked: it must be owned by you and not group/world-writable,
or another user could swap a plugin directory and bypass the per-file checks.

`{{key}}` placeholders in both scripts are substituted from the bound config
section before rendering:

```bash
# apply.sh
backup-agent enroll --target {{target}}
```

Three guarantees:

- Substituted values are **shell-escaped** — a value like `$(rm -rf /)`
  arrives as inert text, never as an expansion — **provided the placeholder
  is unquoted.** Write `{{target}}`, not `"{{target}}"` or `'{{target}}'`:
  inside double quotes the escaping quotes are literal and `$(…)` would
  expand again; inside single quotes they close the string and leave the
  value bare.
- A placeholder inside an open single or double quote on its line is a
  **hard error** at load time.
- An undefined variable is a **hard error** at load time, never an empty
  string.

## Ordering

Plugins default to running after every built-in module but before `updates`.
Manifest hints (`order`, `before`, `after`) refine that, subject to the same
hard safety edges as built-ins — nothing may run after `updates`, and hints
that contradict a safety edge are errors.

## Trust rules

Discovery refuses (and reports, with a reason — see `anvil plugins list`)
any plugin where:

- the name (or bound section) doesn't match `^[A-Za-z0-9_-]+$`,
- the manifest `name` doesn't equal the directory name,
- the plugin directory or any of its files is not owned by you,
- anything is group- or world-writable,
- any path is a symlink.

A malformed or insecure plugin is *skipped with a warning on stderr*;
discovery never aborts the run.

## Results

In `apply`/`check`/`status` output the plugin appears as
`plugin::<name>` with the same status vocabulary as built-in modules.
Rollback of a command-only plugin is a no-op (there are no managed files to
restore).
