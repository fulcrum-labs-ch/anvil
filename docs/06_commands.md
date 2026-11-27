# Command reference

Commands that work on hosts or a config read it from `-c/--config` (default
`harden.toml`). Stdout carries only the requested output; every diagnostic
goes to stderr, so `--output json` pipes stay parseable. One host failing never
aborts the others; the exit code reflects the aggregate.

## Shared flags

| Flag | Commands | Meaning |
|---|---|---|
| `--output human\|json\|ndjson` | apply, check, status, diff, rollback, score, report, plugins list, profiles list | `ndjson` streams one object per line. `report` also takes `markdown` (its default); no other command does |
| `--parallel N` | apply, check, status, rollback, score | `1` sequential (default), `0` all hosts at once, `N` caps concurrency |
| `--host a,b` / `--exclude a,b` | every fleet command | select hosts by address, in config order; an unknown address or an empty selection is a hard error |
| `--only mod1,mod2` | apply, check, diff, rollback | narrow to these modules; an unknown or disabled id is a hard error |
| `--timeout SECONDS` | apply, check, status, diff, rollback, score, report, doctor | kill and report a stalled remote or local call instead of hanging |
| `--dry-run` | apply, rollback | print the exact scripts; nothing connects |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — nothing failed (and for `check`: nothing drifted) |
| `1` | Any module/host failed; `validate` found an invalid config; `check` found drift; `score --threshold` not met |
| `2` | Command-line usage error (clap) |

Note the deliberate asymmetry between the two probe commands: **`check`
treats drift as actionable** (exit `1`), **`status` treats it as
informational** (exit `0`; only probe *failures* are non-zero).

## `validate`

Parse and validate the config, resolve plugins and ordering — without
connecting anywhere. Prints host/module counts and the resolved run order.
Safety violations (for example an `execution_order` that puts the firewall
before `sshd`) are rejected here, before any connection.

## `apply`

Two-phase converge:

1. **Probe** (read-only) every selected module.
2. **Converge** only the modules that reported drift; aligned modules are
   reported `ok` untouched.

Flags: `--dry-run` prints the exact scripts instead of connecting;
`--no-check` skips the probe and converges everything (results then carry no
`drift` field — nothing was probed); `--only mod1,mod2` narrows selection;
`--verbose` includes each module's remote output (indented) in human mode.

**Failure containment:** if `sshd`/`ssh_crypto`/`tailscale` fails, the firewall
(and `hetzner`) step is skipped (`"status": "skipped"` with a reason naming the failed dependency);
`updates` only runs after a clean run.

```json
[{ "host": "10.0.0.9", "modules": [
  { "module": "sshd", "status": "changed", "drift": "drifted" },
  { "module": "firewall", "status": "skipped", "reason": "…sshd…" }
]}]
```

`status` vocabulary (stable, for machines): `changed`, `ok`, `failed`,
`skipped`, `dry-run`. A `failed` entry carries a `reason`.

## `check`

Read-only drift probe. Exit `1` on any drift or probe failure.

```json
[{ "host": "10.0.0.9", "modules": [
  { "module": "sshd", "status": "drifted", "reasons": ["…"] }
]}]
```

`status` vocabulary (stable, for machines): `aligned`, `drifted`, `failed`. A
`drifted` entry carries `reasons`; a `failed` entry carries `error`. This
matches `apply`/`rollback` in always emitting `status` — the one field a
consumer reads for the outcome.

## `status`

The same probe, presented as an informational summary: exit `0` unless a
probe *fails* (unreachable host, remote error). Same JSON shape as `check`.

## `diff`

Per-file unified diffs of every managed file: the declared desired content
versus what is currently on the host (read over SSH, base64-framed). Files
with host-computed content are reported as `"change": "computed"` (no local
diff is possible). Change vocabulary: `create`, `modify`, `none`, `computed`.

```json
[{ "host": "10.0.0.9", "files": [
  { "module": "sshd", "path": "/etc/ssh/sshd_config.d/05-anvil.conf",
    "change": "create", "diff": "--- a/… (absent)\n+++ b/… (desired)\n…" }
]}]
```

An unreadable host yields `{ "host": …, "error": … }` and exit `1`.

## `rollback`

Return each selected module to how the host was **before anvil first touched
it**: restore original files, delete files anvil created, and reload the
affected services. Commands are not undone. Details: [02_concepts.md](02_concepts.md).

- `--only a,b` rolls back just those modules; `--dry-run` prints the scripts
  without connecting.
- Refused (exit 1) when it would remove `users` the host logs in as.

```json
[{ "host": "10.0.0.9", "modules": [ { "module": "sshd", "status": "changed" } ]}]
```

## `score`

Run a Lynis audit on each host and parse the hardening index.
`--threshold <N>` gates the exit code: every host must reach the index.
A host whose output contains no recognizable index never passes.

```json
[{ "host": "10.0.0.9", "index": 66, "threshold": 50, "pass": true, "error": null }]
```

## `report`

CIS-category coverage table of available vs enabled modules (default output:
markdown). `--check` probes each enabled module and overlays a live drift
verdict (`aligned` / `drifted` / `failed`); probe failures make the exit code
`1`.

```json
{ "available": 24, "enabled": 3, "checked": true, "categories": [
  { "category": "5 Access, Authentication and Authorization",
    "modules": [ { "module": "sshd", "enabled": true, "drift": "aligned" } ] }
]}
```

## `init`

Print a starter config (`--output <path>` writes it instead).
`--profile <name>` embeds a profile reference; `--full` emits a reference
config with **every** section present with example values — it always
validates, and it is the fixture the test suite's bash-parse gate is built
from.

## `doctor`

Preflight checks before a real `apply`: the config parses/validates, the plan
resolves, plugins are trusted, and each host is reachable over SSH (and
`sudo -n` works for non-root users). Honors `--host`/`--exclude` and
`--timeout`. Exits non-zero if any check fails — run it in CI or after a fleet
change to catch breakages before they hit `apply`.

## `profiles list` / `plugins list`

Enumerate built-in + custom profiles, and discovered plugins (valid and
skipped, each skip with its reason). Both support `--output json`.
