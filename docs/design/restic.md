# Design: the `restic` backup module

Status: implemented. This page records the decisions behind `[restic]`
and which upstream facts were checked against restic v0.19.1 and the
distro archives (2026-10-31) and which are assumptions still to be
confirmed on a real host.

## Goal

One `[restic]` section gives a host scheduled, pruned, encrypted backups
and lets `check` warn when the newest snapshot is too old. Restore stays
a manual, documented procedure.

## What the module owns

| Path | Kind | Mode | Notes |
|---|---|---|---|
| `/etc/restic/env` | computed | 0600 | `export KEY='value'` lines: repository, password, backend credentials. Computed, so `diff` never prints it. |
| `/etc/restic/paths` | static | 0640 | One path per line, read with `--files-from-verbatim`. |
| `/etc/restic/excludes` | static | 0640 | Built-in defaults plus `exclude`, read with `--exclude-file`. |
| `/usr/local/sbin/anvil-restic` | static | 0750 | Wrapper: sources the env file, sets `RESTIC_CACHE_DIR=/var/cache/restic` (a system service has no `$HOME`, so restic would otherwise run without a cache), then `exec restic "$@"`. Operators use it for restores. |
| `/etc/systemd/system/anvil-restic.service` | static | 0644 | `Type=oneshot`: optional `ExecStartPre=` hooks, `backup`, then `forget --prune`. |
| `/etc/systemd/system/anvil-restic.timer` | static | 0644 | `OnCalendar=<schedule>`, `Persistent=true`, `RandomizedDelaySec=1h`. |

The env file is sourced by bash, not read through systemd's
`EnvironmentFile=`. `shell_escape` quotes any byte exactly, which
systemd's env-file parser does not promise (it has its own quote and
escape rules).

## Install

- Minimum version: **0.17.1**. Safe, idempotent `init` needs exit code 10
  ("repository does not exist", since 0.17.0). Exit code 12 ("wrong
  password") arrived in 0.17.1.
- `detect`: `restic version` reports a version `>= 0.17.1`
  (`dpkg --compare-versions`).
- `converge`: if the apt candidate is `>= 0.17.1`, install the distro
  package. Otherwise download the pinned release
  `restic_0.19.1_linux_{amd64,arm64}.bz2` from GitHub. Its SHA-256 is
  compiled into anvil and checked with `sha256sum -c` before
  `bunzip2` → `/usr/local/bin/restic`. Other architectures fail with a
  clear message. Nothing is piped to a shell, and no vendor apt repo is
  added.

| Release | Distro restic | Result |
|---|---|---|
| Debian 12 bookworm | 0.14.0 | pinned release |
| Debian 13 trixie | 0.18.0 | distro package |
| Ubuntu 22.04 jammy | 0.12.1 | pinned release |
| Ubuntu 24.04 noble | 0.16.4 | pinned release |
| Ubuntu 26.04 resolute | 0.18.1 | distro package |

## Engine fit

The engine runs commands **before** files. Repository init needs the env
file, and starting a backup needs the units. So both work like vector's
restart flag: a command's `detect` does the real check, its `converge`
only sets a shell flag, and the `ReloadGuard` acts on the flag. The guard
runs after every file is written.

Commands, in order:

1. **restic installed (>= 0.17.1)**: real install, described above.
2. **repository initialized**: `restic cat config` with the desired
   credentials inlined in a subshell (the env file may not exist yet).
   `converge` sets `__restic_init=1`.
3. **snapshot of this host exists**: any `anvil` snapshot of this host.
   `converge` sets `__restic_backup=1`, so `apply` starts a backup only on
   first install or against a new repository (the backup decision).
4. **snapshot newer than `max_age_hours`, last run succeeded**: see
   Probe. Report-only: `converge` is a no-op, a stale snapshot is never
   retried.
5. **timer enabled and active**: `converge` is a no-op. The guard
   always enables it.

Guard:

- `validate`: `systemd-analyze verify` on the service and timer, plus
  `bash -n` on the wrapper. Each check is skipped when its file is absent
  (as after rollback).
- `reload`: `daemon-reload`, then `enable --now` the timer. If the init
  flag is set, run `anvil-restic cat config`: rc 0 → nothing, rc 10 →
  `restic init`, any other rc → `FAILED:` and exit 1, which reverts the
  files written this run. A wrong password or an unreachable backend
  therefore never triggers `init`. If the backup flag is set, run
  `systemctl start --no-block anvil-restic.service`. `apply` never waits
  for a backup to finish.

## Probe (read-only)

```
restic --no-lock --no-cache snapshots --json --tag anvil --host "$(uname -n)" --latest 1
```

The probe takes the newest `"time"` value, drops the fractional seconds,
converts it with `date -d` and compares it with `now - max_age_hours`.
`--no-lock` (no lock file written to the repository) and `--no-cache` (no
local cache written) keep the probe from writing anywhere. No snapshots,
an unreachable repository or a missing restic all report `DRIFTED`
(command 3).

The freshness check also reads `systemctl show -p Result,ExecMainStatus
anvil-restic.service`. A stale snapshot reports `DRIFTED: restic: newest
snapshot is <N>h old (max <M>h); last run: <result>`. A failed last run
(`Result` other than `success`) reports `DRIFTED: restic: last backup run
failed (<result>, status <n>), see journalctl -u anvil-restic; newest
snapshot age <N>h`, whatever the snapshot age. It is drift, not `FAILED:`
or a probe exit: a failed `apply` skips `updates`, and a failing probe
would stop `apply` from writing a config fix. The drift clears after the
next successful run (`systemctl start anvil-restic.service`).
Why no retry: with a daily `Persistent=true` timer a stale snapshot
almost always means scheduled runs fail; a silent retry would hide that.

The
`anvil` tag and `--host` keep other hosts sharing the repository out of
both the freshness check and `forget`.

## Retention

`forget --prune --tag anvil --host %H --keep-daily 7 --keep-weekly 4
--keep-monthly 6` (defaults). A keep value of 0 is omitted. At least one
keep value must be > 0: restic refuses an empty policy anyway.
`SuccessExitStatus=3` means a backup with unreadable files (restic still
writes the snapshot) does not skip `forget`.

## Excludes and Docker

The defaults are things that are rebuildable, volatile or unsafe to copy:
`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/apt/lists`,
`/var/lib/snapd/snaps`, `/var/lib/lxcfs`, `/root/.cache`, `/home/*/.cache`.
`--exclude-caches` is also passed, which skips restic's own cache because
it carries `CACHEDIR.TAG`. Set `default_excludes = false` to drop them.
Restic expands `$VAR` in exclude files, so anvil writes `$` as `$$`.

Docker volumes: `docker_volumes = true` swaps the `/var/lib/docker`
exclude for `/var/lib/docker/*` + `!/var/lib/docker/volumes`, the
negation pattern restic documents. File-level copies of a running
database are only crash-consistent. The docs recommend a `pre_backup`
hook that dumps the database (or stops the container) first. Anvil does
not orchestrate containers.

## Hooks

`pre_backup = ["/usr/local/bin/dump-db"]` becomes one `ExecStartPre=` line
per entry. Each entry must be an absolute path with no whitespace or
control characters, and `%` is escaped as `%%`. There is no shell and no
argument parsing. A failing hook stops that run, so no backup is taken.

## Rollback

The engine removes the six files above (or restores pre-existing
originals from `.anvil.bak`). A module rollback script stops and disables
the timer and removes its `timers.target.wants` symlink. The guard's
`daemon-reload` then forgets the units. A backup already running is left
to finish. Rollback **never** runs restic and never touches the
repository or its snapshots. Packages and data are never removed: the
restic apt package (or the pinned `/usr/local/bin/restic`) stays installed,
as with every other module's packages (the rollback rule).

## Secrets

Values come from `${ENV}` interpolation at load time. They travel only in
the script sent over SSH on stdin, inside bash builtins (`export`,
`printf`), so they never appear in a process's argv. They land in the
0600 env file. `diff` reports that file as "content computed on host".
Known limitation, shared with `tailscale.auth_key`: `apply --dry-run`
prints the rendered script, secrets included.

## Restore (manual)

```
sudo anvil-restic snapshots
sudo anvil-restic restore latest --target /root/restore --include /etc/nginx
sudo anvil-restic mount /mnt/restic   # needs fuse3
```

## Verified vs assumed

Verified (upstream docs/source at v0.19.1, archive APIs):

- The release assets and SHA-256 sums: the published `SHA256SUMS` matches
  the hashes of the downloaded files, and `SHA256SUMS.asc` is a good
  signature by key `CF8F 18F2 8445 7597 3F79 D4E1 91A6 868B D3F7 A907`,
  the fingerprint published in restic's installation docs.
- Exit codes 3/10/11/12 and the versions that introduced them.
- `--no-lock`, `--no-cache`, `--files-from-verbatim`, `--exclude-file`
  (with `$` expansion), `--exclude-caches`, `!` negation, and
  `forget --tag/--host`.
- `restic version` prints `restic X.Y.Z compiled with …`.
- `snapshots --json` is emitted by Go's `json.Encoder` (compact `"time":"…"`).
- Distro versions (sources.debian.org, Launchpad).

Run on a real host (Debian 13, restic 0.18.0 from apt, 2026-10-31):
check → apply → first backup → check → re-apply → diff → restore →
wrong-password apply → rollback, all as designed:

- `systemd-analyze verify` accepts the units.
- GNU `date -d` parses restic's timestamps, so `check` reports aligned
  after the first backup.
- `%H` matches `uname -n`: the probe finds the snapshots the timer made.
- A wrong password fails the apply with exit 12, skips `init` and reverts
  the env file.
- Rollback removes all six files and the timer symlink. The repository
  keeps its snapshots.
- The live run found one bug, now fixed: without `$HOME` the service ran
  without a cache. The wrapper now sets `RESTIC_CACHE_DIR`.

Still assumed:

- Restic warns and continues (exit 3) when one configured path is absent.
  It wasn't exercised: every default path exists on the test host.
- Debian 12 and Ubuntu 22.04/24.04, which take the pinned-release install
  path, have not been run.
