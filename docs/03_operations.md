# Operations cookbook

Task-shaped recipes. The reference material lives in
[06_commands.md](06_commands.md) and [05_configuration.md](05_configuration.md).

## First run on a fresh host

```bash
anvil init --output harden.toml     # starter config: sshd, firewall, updates
$EDITOR harden.toml                  # set [host] address/user; add sections
anvil validate -c harden.toml       # parse, validate, show resolved run order
anvil apply -c harden.toml --dry-run | less   # read the exact bash it will run
anvil diff -c harden.toml           # per-file preview (most files: "create")
anvil apply -c harden.toml          # converge
anvil check -c harden.toml          # should now exit 0, everything aligned
```

Two things to check before the first `apply`:

- **Your login must survive the config.** If you log in as root with a
  password, note that `[sshd]` defaults disable both root login and password
  auth — create your key-based admin user in the same run (`[users]` with
  `sudo = true` and your public key; `users` runs first in the resolved
  order, before `sshd` tightens anything).
- **Non-root users need passwordless sudo.** The whole script runs under
  `sudo -n`; a missing `NOPASSWD` rule fails fast with a clear error rather
  than hanging on a password prompt.

What lands on the host: the managed files listed in
[04_modules.md](04_modules.md), a `<path>.anvil.bak` backup next to every file
that existed before, and a run manifest under `/var/lib/anvil/runs/`.

Re-running `apply` is the idempotency check: the second run probes, finds
no drift, and reports every module `ok` without touching anything.

## Watching for drift

`check` exits `1` on any drift or probe failure, so it slots directly into
cron/systemd timers or CI:

```bash
anvil check -c harden.toml --output json > drift.json || notify …

# Which modules drifted, and why:
jq -r '.[] | .host as $h | .modules[]
       | select(.status == "drifted")
       | "\($h) \(.module): \(.reasons | join("; "))"' drift.json
```

When drift is real, `anvil diff` shows the file-level story, and
`anvil apply` converges only the drifted modules (that's the default
two-phase behavior). When the drift is *intentional* — someone changed a
value on purpose — change the config to match instead, so the config stays
the single source of truth.

`status` is the same probe with informational semantics (exit `0` on drift,
`1` only when a probe fails) — use it for dashboards, and `check` for gates.

## Rolling out to a fleet

Keep one baseline and give each host only its identity:

```toml
# fleet.toml
include = ["baseline.toml"]     # sections: sshd, firewall, updates, …

[[hosts]]
address = "10.0.1.11"
user = "ops"

[[hosts]]
address = "10.0.1.12"
user = "ops"
identity_file = "~/.ssh/fleet_ed25519"
```

Canary first, then the fleet:

```bash
# 1. Point a canary config (same include) at one representative host.
anvil apply -c canary.toml && anvil check -c canary.toml

# 2. Fleet, bounded parallelism; one JSON line per host for your tooling.
anvil apply -c fleet.toml --parallel 4 --output ndjson

# 3. Verify everywhere, all hosts at once.
anvil check -c fleet.toml --parallel 0
```

One host failing never aborts the others; the exit code reflects the
aggregate, and each host's JSON document tells you which modules failed or
were skipped and why.

## Changing the SSH port safely

The port move is the classic self-lockout, and most of the tool's safety
edges exist for it. Set the new port in `[sshd]` and apply:

```toml
[host]
address = "203.0.113.10"
user = "admin"
port = 22          # still the OLD port — this run connects on it

[sshd]
port = 2222        # the new, hardened port
[firewall]
```

In one run, in enforced order: `sshd` moves to 2222 behind an `sshd -t`
validation guard (auto-revert on failure), and the firewall allows 2222
*before* it enables. With `[hetzner]`, the cloud firewall keeps TCP 22 open
during the cutover. After verifying you can log in on 2222, update
`[host] port = 2222` for future runs (and optionally drop the 22 allowance
from your Hetzner rules on the next apply).

## When a run fails partway

Failure containment is built in: if `sshd`, `ssh_crypto` or `tailscale` fails, the
firewall (and `hetzner`) is `skipped` (its JSON entry names the failed dependency), and
`updates` only runs after a clean run. A failed sshd change reverts itself —
modified files restored from backup, files created by the failed run
removed, no reload — so the daemon keeps running on its previous config.

Recovery is normally just: read the failed module's `reason`, fix the cause
(or the config), and re-run `apply`. Modules that already converged report
`ok` and are not touched again.

## Rolling back

What rollback restores, and why it is safe on preconfigured servers, is in
[02_concepts.md](02_concepts.md). The recipe:

```bash
anvil rollback -c harden.toml --dry-run   # read the exact restore scripts
anvil rollback -c harden.toml             # restore backups, delete created files
anvil rollback -c harden.toml --only sshd # or just one module
```

Before you run it on a live host:

- **Commands are not undone.** Installed packages, created users and ufw
  rules stay.
- **Rolling back `sshd` re-allows root and password login at once**, if the
  original config allowed them. Keep a second session open.
- **`users` is refused** while anvil logs in as an account it created,
  because that would delete its key and sudo rule. Roll back the other
  modules with `--only`, or log in as another account first.
- **Firewall:** the restored SSH port stays allowed, so a rollback cannot
  lock you out of SSH.
- **Tailscale:** if `tailnet_only_ssh` closed public SSH, rollback (also
  `--only tailscale`) opens that port to the world again before removing the
  tailnet-only rule. The node stays joined to the tailnet; remove it in the
  admin console or with `tailscale logout`.

## Backups and restore

`[restic]` backs the host up on a timer (see
[05_configuration.md](05_configuration.md#restic)). `anvil check` reports
`restic` as drifted when the newest snapshot is older than
`max_age_hours`, so a dead backup job shows up next to every other drift.
On the host, `anvil-restic` is restic with the repository and password
already set:

```bash
sudo systemctl list-timers anvil-restic.timer    # next run
sudo journalctl -u anvil-restic.service -n 50    # last run's log
sudo systemctl start anvil-restic.service        # back up now
sudo anvil-restic snapshots                      # what is in the repository
```

Restore is manual on purpose. Restore into a scratch directory first,
check the result, then copy back what you need:

```bash
sudo anvil-restic restore latest --target /root/restore --include /etc/nginx
sudo diff -r /root/restore/etc/nginx /etc/nginx
sudo anvil-restic restore 4bba301e --target /root/restore   # a specific snapshot
```

On a new machine, without anvil, use the repository URL and password
from your password manager:

```bash
export RESTIC_REPOSITORY='sftp:backup@nas.example.com:/srv/restic/web-1'
export RESTIC_PASSWORD='…'
restic snapshots --host web-1
restic restore latest --host web-1 --target /root/restore
```

**Databases and Docker volumes.** A file copy of a running database is
only crash-consistent. Add a `pre_backup` script that dumps the database
(for example `docker exec db pg_dumpall > /var/backups/pg.sql`) and back
up the dump. Or set `docker_volumes = true` for volumes whose apps
tolerate that. Images and containers are not backed up: rebuild them.

`rollback` removes the timer, unit, wrapper and `/etc/restic/` files. It
never touches the repository or its snapshots. The restic binary and the
cache in `/var/cache/restic` stay; the cache is safe to delete.

## Gating CI / compliance on a hardening score

```bash
# Fail the pipeline if any host scores below 80:
anvil score -c fleet.toml --parallel 0 --threshold 80 --output json

# Human-readable coverage report with live drift, for the audit folder:
anvil report -c harden.toml --check --output markdown > compliance.md
```

A host whose Lynis output yields no recognizable index never passes a
threshold — unreachable is not compliant.

## Debugging a module

```bash
anvil apply -c harden.toml --dry-run --only sshd   # print exactly its scripts
anvil apply -c harden.toml --only sshd --verbose   # run it, show remote output
anvil check -c harden.toml --only sshd             # just its probe
```

The scripts are ordinary bash — reading the dry-run output is the fastest
way to understand what a module will do to a host.

## Next

- [04_modules.md](04_modules.md): what each module changes, and which files it owns.
- Reference: [05_configuration.md](05_configuration.md), [06_commands.md](06_commands.md).
