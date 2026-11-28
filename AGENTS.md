# Working in anvil

Rules for any coding agent (Claude, Codex, OpenCode, Cursor, …) and a quick
map for humans. `CLAUDE.md` only points here. Humans: see also
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Never, without the person you work for

- **A push, a PR, a merge, a tag or a release.** Commits stay local.
- **Anything against a real host**: `scripts/acceptance.sh`, `anvil apply` /
  `rollback`, or ssh to any server. A wrong sshd/firewall step locks people
  out. Only disposable test boxes, and only when asked.
- **Paid resources**: creating cloud servers, firewalls, DNS records.
- **Renaming a shipped drop-in, unit or TOML field.** Drift, rollback and users'
  configs key on them.
- **Rewriting history or deleting data.**

When the task is unclear, stop and ask.

## Working

- Tests first: write the tests the change needs and see them fail for the
  right reason before writing production code.
- One change per commit; touch only the paths it needs.
- Gate before every commit (CI runs the same):
  `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run && cargo test --doc`.
  New logic should also survive `cargo mutants --in-diff <(git diff main)`.
- Work is tracked in GitHub issues; reference them as `#N`.
- Commits, PRs and issues are public: never include real hostnames, IPs,
  tokens or personal details.
- Personal agent files stay out of git: `*.local.md`, `.claude/skills/`,
  `.opencode/` are ignored. If `AGENTS.local.md` exists, read it too.
- Answer first and keep replies short. Name a real risk in your change without
  being asked.

## Layers

```text
cli.rs ─────────────► config/ ─► (schema, load, validation)
  │                     │
  ├─► order.rs ◄────────┘          safety edges are hard edges
  ├─► modules/<id>.rs ─► engine.rs ─► escape.rs
  ├─► plugin.rs ─────► engine.rs
  ├─► diff.rs, report.rs ─► engine.rs (typed results)
  └─► ssh.rs | local.rs           transport: thin, no logic
```

- Modules depend on `engine` and their own config section only — never on
  `cli`, `ssh`, `local` or another module (shared runner helpers live in
  `modules/runner_common.rs`).
- Only `ssh.rs` and `local.rs` spawn processes against a host.
- External integrations (`hcloud`, runner APIs, apt repos) live in the module
  that needs them, never in the engine.
- `.github/workflows/` is a security boundary; its invariants are pinned by
  tests in `tests/`.

## Build & test

```bash
cargo build
cargo nextest run          # or `cargo test`; CI runs nextest + `cargo test --doc`
cargo clippy --all-targets -- -D warnings
cargo fmt
```

Keep all four green before committing. The test suite includes a `bash -n` gate
that parses every generated script — quoting/heredoc mistakes fail there.

Mutation testing: `cargo mutants` (config in `.cargo/mutants.toml`; excludes
the deliberately-thin ssh/local/main layers). CI runs `cargo mutants --in-diff`
against the PR diff — new logic whose tests can't fail gets flagged there.
For a quick local check of just your changes:
`cargo mutants --in-diff <(git diff main)`.

Real host: `scripts/acceptance.sh <user@host>` hardens an existing
disposable Debian 13 / Ubuntu 26.04 box (apply, idempotency, CIS, reboot, PAM,
drift, port move, rollback; `--dry-run` prints every command). It is the only
test that touches a real apt/sshd/systemd — run it after changing any module's
install or detect logic. Every step's host effect: `docs/design/acceptance.md`.

## Repository layout

- `src/engine.rs` — the declarative core: `ManagedFile` (static or
  host-computed content), `ManagedCommand`, `ReloadGuard`, `Declaration`, the
  probe/apply/rollback renderers, typed results (`Verdict`, `ApplyStatus`), and
  the marker protocol.
- `src/modules/` — one file per hardening subsystem implementing `Module`;
  `mod.rs` is the registry mapping enabled config sections to instances.
- `src/config/` — `schema.rs` (TOML section structs), `load.rs` (parse →
  resolve includes → apply profile → deserialize), `mod.rs` (hosts + validation).
- `src/order.rs` — execution-order resolver: topo sort, stable tie-break,
  safety constraints as hard edges.
- `src/ssh.rs` — SSH transport (multiplexed, `sudo -n` for non-root users).
  `src/local.rs` — local execution for `runs_locally` declarations (hetzner).
- `src/plugin.rs` — out-of-tree plugin subsystem: discovery from
  `~/.config/anvil/plugins/<name>/` (a `plugin.toml` manifest plus
  `apply.sh`/optional `check.sh`), trust checks, and `{{VAR}}` substitution
  from the bound config section. An enabled plugin becomes a regular
  `Declaration` addressed as `plugin::<name>` in ordering and results.
- `src/cli.rs` — clap CLI and command handlers. `src/escape.rs`, `src/error.rs`,
  `src/diff.rs`, `src/report.rs` — quoting, `AnvilError`, diff/report renderers.
- `docs/diagrams/` — diagram sources (`*.html`, inline SVG) and stills
  (`*.png`) used by `docs/08_architecture.md` and the README. Edit the HTML,
  then re-export the PNG (see `docs/09_development.md`).

## The engine model

A module never hand-writes probe or apply bash. It builds a `Declaration` of
what it owns — `ManagedFile`s and idempotent `ManagedCommand`s (`detect` exits 0
when converged; `converge` makes the change) — and the engine renders every
script from that one declaration, so probe and apply can never disagree.

- File content is `FileContent::Static` (exact bytes, base64-embedded) or
  `FileContent::Computed { generator }` — a bash snippet run on the target that
  prints the desired content (used when correctness depends on the host, e.g.
  filtering crypto algorithms). Probe and apply share the same materialization.
- A `Declaration` marked `.local()` runs on the operator's machine (plain
  `bash -s`, no ssh/sudo) — only `hetzner` does this, to drive `hcloud`.
- `apply` is two-phase by default: read-only probe first, converge only drifted
  modules; `--no-check` forces all. Keep probes strictly read-only.

To add a module: create `src/modules/<id>.rs` with a struct wrapping its
`<Name>Section`, `impl Module { fn id(); fn declaration(); }`, register it in
`src/modules/mod.rs`, and give it a default wave in `src/order.rs`.

## Load-bearing rules

- **System `ssh` only.** Remote execution shells out to the system `ssh` binary
  via `std::process::Command` — never a Rust SSH crate. Scripts run under
  `bash -euo pipefail`.
- **Escaping.** Any config-derived value interpolated into `detect`/`converge`
  bash (or a `Computed` generator) MUST go through `escape::shell_escape`.
  Static `ManagedFile` content is base64-embedded and needs no escaping.
- **Drop-in naming.** `sshd_config.d` is first-match-wins — our drop-ins use
  LOW prefixes (`05-anvil*.conf`) so they beat distro files like
  `50-cloud-init.conf`. Last-match-wins directories (`sysctl.d`, `modprobe.d`,
  `resolved.conf.d`, `jail.d`, audit `rules.d`) use HIGH prefixes
  (`99-anvil*`). Never rename a drop-in once shipped — drift, diff, and
  rollback key on the path.
- **Backups are the engine's job.** It copies to `<path>.anvil.bak` before
  overwriting and records a per-run manifest under `/var/lib/anvil/runs/`. Do
  not add file writes that bypass the engine, or `rollback` cannot undo them.
- **Safety edges are immovable** (encoded in `order.rs`): firewall after
  `sshd`, with the effective SSH port allowed before enable; `sshd`/`ssh_crypto`
  reloads wrapped in a `ReloadGuard` (`sshd -t`, auto-revert restores backups
  and removes files created that run); `updates` and any reboot last.
- **PAM is never hand-edited** — write `pwquality.conf`/`faillock.conf` and
  login defaults; activate modules only through `pam-auth-update` (package
  profiles or our profiles in `/usr/share/pam-configs/`), verified after.
  Nothing may write, sed, cp or rm under `/etc/pam.d/`.
- **Sections are opt-in.** Absent `[section]` = disabled. Section and field
  names are the public TOML contract (`deny_unknown_fields`); renaming breaks
  users' configs.
- **Errors.** Return `AnvilError` (thiserror) via `?`; no `.unwrap()`/
  `.expect()` outside tests. `anyhow` only at the CLI boundary, mapped to exit
  codes.
- **Marker vocabulary** (`CHANGED:` / `DRIFTED:` / `OK:` / `FAILED:`) is defined
  once in `engine.rs` and parsed by the control plane — don't reword it.
- **Plugin trust checks are mandatory** (`plugin.rs`, R93): names match
  `^[A-Za-z0-9_-]+$`, plugin files must be owned by the invoking user and not
  group/world-writable, symlinked paths are rejected, `{{VAR}}` substitutions
  are shell-escaped, and an undefined variable is a hard error. A malformed or
  insecure plugin is skipped with a reason — discovery never aborts.

## Test conventions

- Unit-test the behavioral contract of generated scripts (required commands and
  paths present, backup precedes write, probe agrees with apply) next to each
  module; factor pure script/content builders into testable functions.
- `tests/generated_bash.rs` is the gate: every probe/apply/rollback script from
  a wide config must parse under `bash -n`, and every static desired content
  must survive into the apply script (the diff contract). The wide config is
  built from `init --full` and `wide_config_covers_every_implemented_module`
  pins that every registered module is gated — so a new module must be added
  to the `init --full` template (`FULL_EXTRA` in `cli.rs`) to pass.
- Safety edges (R56/R57/R58) are tested adversarially in `order.rs` — with
  hostile `order`/`before` overrides, not just default waves. Keep it that way
  when adding edges.
- `tests/cli.rs` covers exit codes, stderr/stdout, and JSON output of the
  binary end-to-end (no host needed); extend it for new CLI surface.
- No network in tests. SSH/local execution paths are not unit-tested; keep them
  thin (they are excluded from mutation testing for the same reason).
