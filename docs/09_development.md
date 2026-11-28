# Development guide

How the pieces fit, with diagrams: [08_architecture.md](08_architecture.md). The
numbered behavioral spec: [`DESIGN.md`](../DESIGN.md). Contributor
conventions: `AGENTS.md`.

## Build & test

```bash
cargo build
cargo nextest run                        # or `cargo test`
cargo clippy --all-targets -- -D warnings
cargo fmt
```

All four must be green before committing. CI runs the same plus
`cargo test --doc` and mutation-tests each PR's diff.

No test touches the network. The remote transport is exercised through a
**fake-ssh shim**: `src/ssh.rs` resolves `ssh` from `PATH`, so integration
tests (tests/cli.rs) put a small script first on the spawned process's
`PATH` that answers probes/converges with marker lines (`OK:`, `DRIFTED:`,
`CHANGED:`, `FAILED:`) or refuses the connection. This drives the two-phase
apply, failure containment, exit codes, and JSON shapes end-to-end with no
DNS and deterministic timing.

### The bash-parse gate

`tests/generated_bash.rs` builds a config from `anvil init --full` (every
module enabled), renders every probe/apply/rollback script, and parses each
under `bash -n`. A companion test pins that every id in the module registry
is planned and gated — a new module cannot silently escape. The gate also
asserts the diff contract: every static desired content must survive
base64-embedded into the apply script.

### The real-host acceptance test

Everything above mocks `ssh`. `scripts/acceptance.sh` is the one test that
talks to a real apt, sshd and systemd. It runs against an existing,
**disposable** Debian 13 or Ubuntu 26.04 box reachable with key login on port
22. It applies tutorial step 1 (creating the sudo user `ops`), checks
idempotency (re-apply all `ok`, `check` exit 0, `diff` empty), applies CIS
Level 1 and records the Lynis score, reboots, runs a pamtester lockout test,
hand-edits a managed file to prove drift detection, moves SSH to 2222, rolls
back everything but `users`, and re-applies. The box ends hardened, not
restored.

```bash
scripts/acceptance.sh --dry-run root@203.0.113.10   # print every command; connects to nothing
scripts/acceptance.sh root@203.0.113.10             # run (asks you to type the host)
scripts/acceptance.sh --yes --containers --beszel root@203.0.113.10   # plus opt-in module stages
```

Needs `jq`, `ssh` and a key pair (`ANVIL_ACCEPT_KEY`, default
`~/.ssh/id_ed25519.pub`). Fixtures live in `scripts/acceptance/`. Read
[design/acceptance.md](design/acceptance.md) before the first run: it lists
every step's commands, what each one changes on the host, and the lockout
guards. Run it before a release and after touching any module's install or
detect path: the bugs it finds (a detect that never converges, a reboot that
fails on the hardened config, a port move that leaves sshd behind) are
invisible to the unit suite by construction.

### Mutation testing

```bash
cargo mutants                            # full run (~900 mutants, ~40 min with -j 4)
cargo mutants --in-diff <(git diff main) # just your changes (what CI does on PRs)
```

Config lives in `.cargo/mutants.toml` (nextest as the runner; the
deliberately-thin `ssh.rs`/`local.rs`/`main.rs` are excluded). Treat a
surviving mutant in safety-relevant code as a missing test. A few known
near-equivalent survivors are expected — don't chase those.

## Adding a module

1. Create `src/modules/<id>.rs`: a struct wrapping its `<Name>Section`,
   implementing `Module { fn id(); fn declaration(); }`. Build a
   `Declaration` of `ManagedFile`s and idempotent `ManagedCommand`s — never
   hand-write probe or apply bash; the engine renders both from the one
   declaration so they cannot disagree.
2. Add the config section struct in `src/config/schema.rs`
   (`deny_unknown_fields`, serde defaults = the hardening contract), the
   `Option<Section>` field on `Config`, and the id in `MODULE_IDS`.
3. Register it in `src/modules/mod.rs` (`build_module`) and give it a wave
   in `src/order.rs::default_order`.
4. Add the section (with example values) to the `init --full` template
   (`FULL_EXTRA` in `src/cli.rs`) — the gate's completeness test fails until
   you do.
5. Unit-test the behavioral contract of the rendered scripts next to the
   module: required commands/paths present, backup precedes write, probe
   agrees with apply, config values shell-escaped (feed adversarial input),
   and — if the module owns a drop-in — the prefix contract.
6. Update the canonical-order test in `src/order.rs`, the schema-defaults
   test in `src/config/schema.rs`, and `docs/` (configuration + modules).

Rules that are load-bearing (violations have bitten before): every
config-derived value interpolated into bash goes through
`escape::shell_escape`; never rename a shipped drop-in path; file writes go
through the engine (or `rollback` can't undo them); reloads of risky
services sit behind a `ReloadGuard` with a validate command.

## Diagrams

`docs/diagrams/*.html` are the sources: self-contained pages with one inline
SVG each, drawn with the `diagram-design` skill (default style guide). The
`*.png` beside each is the still embedded in the docs. To change one, edit the
SVG in the HTML (keep connectors orthogonal and labels masked), then
re-export the still at 2x:

```bash
python3 <diagram-design>/scripts/self_check.py docs/diagrams/<name>.html
python3 <diagram-design>/scripts/export_png.py docs/diagrams/<name>.html docs/diagrams/<name>.png
```

Commit the HTML and the fresh PNG together.

## Release checklist

- `cargo nextest run`, clippy, fmt — green.
- `cargo mutants` full run — no *new* missed mutants outside the catalogued
  near-equivalents.
- `scripts/acceptance.sh` green on Debian 13 and Ubuntu 26.04.
- `anvil init --full | anvil validate -c /dev/stdin` still passes.
- Docs updated: `docs/05_configuration.md` for schema changes,
  `docs/04_modules.md` for behavior/path changes, `DESIGN.md` for contract
  changes, `docs/08_architecture.md` and its diagrams for flow changes.
