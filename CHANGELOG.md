# Changelog

Release notes are taken from this file by the release workflow: the section
whose heading matches the pushed `vX.Y.Z` tag becomes the GitHub Release body.

## [Unreleased]

### Breaking

- `[greptimedb]` runs as the internal compose project `greptimedb`
  (`/etc/anvil/compose/greptimedb/compose.yaml`,
  `anvil-compose-greptimedb.service`, replacing `greptimedb.service`; use the
  new name with `systemctl`/`journalctl`) instead of a `docker run` unit, so a
  dockerd restart no longer restarts it. Config fields are unchanged and the
  container keeps the name `greptimedb`. **Migration:** the next apply backs
  up `/etc/systemd/system/greptimedb.service` to `.anvil.bak`, stops,
  disables and removes it, then starts the compose project on the same
  `data_dir` (a bind mount: no data moves, no volume is deleted, the two
  never run at once). `rollback` takes the project down and restores and
  restarts the old unit. `[containers.compose.greptimedb]` is now reserved.

- `[coding_agents]`'s Orca server unit is
  `/etc/systemd/user/orca-server.service` (`orca-server.service`, was
  `anvil-orca-server.service`; use the new name with `systemctl`/`journalctl`).
  Config fields are unchanged. **Migration:** the next apply backs the old
  unit up to `.anvil.bak`, stops, disables and removes it, then starts the new
  one; `rollback` restores and restarts the old one.

- `ci-runner` profile: now enables `[firewall]` (default-deny inbound, allow
  outbound, SSH kept open), since a CI host needs no other inbound port.
  Hosts on this profile that serve other inbound ports need
  `[[firewall.allow]]` rules before the next apply.
- `[tailscale]`: `tailnet_only_ssh = true` without `[firewall]` is now a
  validation error; it was a silent no-op that left public SSH open.
- `[beszel]`: downloads are checked against SHA-256s compiled in for the
  default version (0.21.1) instead of the release's own checksums file; an
  overridden `version` now needs a `sha256` table with each tarball's hash
  (new field), or `validate` rejects it.
- `[beszel]`: a non-loopback hub (plain HTTP) is accepted only when it is
  reached over the tailnet; a `hub_allow_from` outside `100.64.0.0/10` /
  `fd7a:115c:a1e0::/48` is rejected. Use `[caddy]` or `[tls]` in front of a
  loopback hub instead.
- `[beszel]`: a hub on a non-loopback `hub_listen` needs `admin_email` and
  `admin_password` (new), so the first visitor can no longer claim the admin
  account. The hub creates that admin on its first start.
- `[containers]`: while Docker manages iptables (`[docker] iptables_off =
  false`, or no `[docker]` section), apply refuses and reverts a compose
  project that publishes a port on anything but `127.0.0.1`/`::1`, since
  Docker's rules bypass ufw. Bind to loopback and front it with `[caddy]` or
  `[tls]`.
- `headscale.headplane_listen` defaults to `127.0.0.1:3000` (was
  `0.0.0.0:3000`, which Docker published past ufw to the internet). Headplane
  no longer mounts the Docker socket unless `headplane_docker_socket = true`.
- `[docker]` adds `live-restore: true` to `daemon.json` by default
  (`live_restore = false` to opt out, e.g. for Swarm). Existing hosts restart
  dockerd once on the next apply.

- `rollback` refuses to run `users` when it would delete the SSH key and sudo
  rule of the account anvil logs in as. Roll back the other modules with
  `--only`, or log in as another account first.
- `crowdsec.bouncer_mode` is optional. When unset, the distro package picks the
  firewall backend. CrowdSec now installs from the Debian/Ubuntu packages, not
  the vendor apt repository.
- `--output markdown` is accepted only by `report`.
- Stricter config validation: values that used to reach host files unchecked
  (sysctl values, jail names, domains, webroots, Hetzner ports, ordering hints,
  headscale and greptimedb addresses) are rejected at load time. Config that
  was accepted before may now fail with `invalid config`.

### Added

- `[github_runner] sandbox_packages` (ephemeral mode): apt packages baked into the sandbox image, e.g. `["build-essential", "pkg-config"]`.
- `[github_runner] mode = "ephemeral"`: every job runs in a fresh
  sysbox sandbox with its own Docker, minted per job with a GitHub App
  (`app_id`, `installation_id`, `app_key`, `runner_group_id`), `capacity`
  slots per runner, per-sandbox `sandbox_cpus`/`sandbox_memory`/
  `sandbox_pids`/`sandbox_disk` and `sandbox_runtime` (`"sysbox-runc"`).
  Org runners only, amd64. `mode = "persistent"` (default) is unchanged.
  See docs/04_modules.md.
- `[ci_resources]`: one systemd slice, `ci.slice`, holding every
  `[github_runner]` and `[forgejo_runner]` unit (`Slice=ci.slice`). A dash-free
  name makes it a direct child of `-.slice`, next to `system.slice`/`user.slice`,
  so its `CPUWeight=` counts on its own; the older `anvil-ci.slice` and its
  `anvil.slice` drop-in are backed up (`.anvil.bak`) and removed on the next
  apply, and rollback restores both.
  An old config that lists `anvil.slice/**` in `[vector] cgroups_include`
  must change it to `ci.slice/**`; load now refuses the old value.
  CI history from before the rename stays under the old cgroup name, so it
  does not show in the updated dashboards.
  `cpu_quota`/`memory_max`/`tasks_max` cap all CI work together, each
  runner's own caps still apply inside it, and `cpu_weight` (default 50)
  keeps sshd and other system services ahead under load. Runs before the
  runners (hard edge); rollback removes the slice. Enabling or removing it
  restarts the runners once (their unit files change). `docker = "group"`
  job containers stay under dockerd's cgroup, outside the slice; every
  command warns when both are set.
- `[apps_resources]`: one systemd slice, `apps.slice`, holding the
  host's own applications — Caddy (a `Slice=apps.slice` drop-in), Vector (in
  its unit) and Forgejo/GreptimeDB (native unit, compose or Quadlet) — and an
  optional `MemoryLow=` on `system.slice` (`system_memory_low`, drop-in
  `system.slice.d/99-anvil-memory-low.conf`) so sshd and other system
  services stay out of the kernel's first reclaim. `cpu_quota`/`memory_max`/
  `tasks_max` cap all apps together; `cpu_weight` defaults to systemd's 100.
  Forgejo's and GreptimeDB's generated compose files set
  `cgroup_parent: apps.slice` on every service, so their containers land in
  the slice instead of `system.slice/docker-*.scope` (needs Docker's systemd
  cgroup driver); user `[containers.compose.*]` services must set it
  themselves. Runs before the apps (hard edge); enabling or removing it
  restarts the moved units once. `[vector]`'s default `cgroups_include` now
  also scrapes `apps.slice/**`. Rollback removes the slice and drop-in.
- `[github_runner] disk_max = "150G"`: each runner's `_work` lives on
  its own sparse ext4 loop volume (`/var/lib/anvil-ci/github-runner-<name>.img`,
  mounted `nodev,nosuid`, required by the runner unit), so a full disk fails
  the job, not the host. Created once, never resized (`FAILED:` on a size
  change); `check` drifts at 90% full. Rollback deletes the image only if
  anvil created it. Existing `_work` content is hidden under the new mount,
  not freed.
- `[github_runner] diag_retention_days` (default 14): a daily
  `anvil-github-runner-prune.timer` deletes old `_diag/*.log` and, with
  `disk_max`, wipes `_tool`/`_actions` caches past half the cap. Every
  existing `[github_runner]` gains the timer on its next apply. The
  job-completed hook now keeps `lost+found`.
- `[docker] source = "vendor" | "distro"`: `"distro"` installs Ubuntu's
  `docker.io` + `docker-compose-v2` instead of Docker's apt repo (`FAILED:` on
  other distros). The default stays `"vendor"`. An installed engine is never
  switched; a mismatch is kept and warned about.
- `[containers.compose.<name>] file = "compose/app.yaml"`: read the compose
  file at load, relative to the config file that sets it, instead of inline
  `content` (exactly one of the two). Held to the include trust checks: owned
  by you, not group/world-writable, no symlink.
- `[beszel] docker = true` / `smart = true`: opt-in container stats
  (agent joins the `docker` group, root-equivalent; apply refuses unless
  Docker and its group exist) and SMART data (smartmontools, `disk` group,
  ambient `CAP_SYS_RAWIO`; SATA/SAS only, NVMe needs `CAP_SYS_ADMIN`, which
  is not granted). Both off by default; the default agent unit is unchanged.

- `[containers] runtime = "podman"`: rootful Podman Quadlet units from
  `[containers.quadlet.<name>]` (`/etc/containers/systemd/anvil-<name>.container`),
  Podman from the distro package. Refused per host below Podman 4.4 with a
  `FAILED:` reason (Debian 12, Ubuntu 22.04). `PublishPort=` must bind
  loopback (validated at load); a unit Quadlet cannot convert is reverted;
  rollback removes only anvil's units, never images, volumes or the package.
  Docker stays the default. `filesystem`/`suid` scans now skip
  `/var/lib/containers`.
- `[netcup]` (T12): manages the netcup SCP firewall from the operator's
  machine (`curl` + `jq`, `NETCUP_SCP_REFRESH_TOKEN`). One anvil-owned
  policy, attached next to existing ones; R61 SSH guard and
  `keep_public_ssh` as for `[hetzner]`, except that a source-restricted SSH
  rule counts as the guard; every SCP request is checked
  against a fixed allowlist; rollback restores the previously attached
  policy set. Load warns about caddy/beszel ports as for hetzner.

- `[forgejo_runner]`: a Forgejo Actions runner (pinned, SHA-256-verified
  forgejo-runner 13.2.1, registered via `server.connections` with the UUID
  and token from Forgejo, hardened systemd unit, `docker = "none"` by
  default). With `[forgejo]` in the same config it defaults to that instance
  and requires `forgejo.actions = true` (GR12).
- `[forgejo]`: config load warns when no `[tls]` domain or `[[caddy.site]]`
  serves `forgejo.domain`, or the caddy site proxies to a port other than
  `http_port` (FJ7).
- `[hetzner] keep_public_ssh` (default `true`): `false` stops adding the
  SSH-from-anywhere rules to the cloud firewall after a tailnet cutover.
  Requires `[tailscale] tailnet_only_ssh = true`; `hetzner` then runs after
  `tailscale` and is skipped unless anvil reaches the host over the tailnet.
- `[hetzner]`: `check`/`diff`/`apply` warn when `[caddy]` is enabled but no
  rule allows its `http_port`/`https_port` (default 80/443) over tcp, and when a public
  `beszel.hub_addresses` entry has no rule on `listen_port`. anvil still adds
  no provider rules itself.
- `[github_runner]` gains `cpu_quota`, `memory_max` and `tasks_max`, rendered
  as systemd `CPUQuota=`/`MemoryMax=`/`TasksMax=` in each runner unit, so a
  heavy job cannot starve the host.
- `[[headscale.auth_keys]]` gain `tags` and `ephemeral`; a key is re-created
  on the next apply once it is older than `expiration` or its flags changed.
  `expiration` is now validated (a duration of at least `1m`). The first
  apply after upgrading re-creates every existing key once (no flags were
  recorded for them).
- `headscale.base_domain` (default `"headscale.internal"`, unchanged) sets the
  MagicDNS suffix. `validate` warns when `server_url` is not `https://` or
  `listen_addr` is not loopback; docs show headscale behind `[caddy]`.
- `scripts/acceptance.sh <user@host>`: the real-host acceptance test against
  an existing disposable Debian 13 / Ubuntu 26.04 box, replacing the
  Hetzner-only `scripts/smoke.sh`. Covers the CIS apply, a reboot, PAM
  lockout, drift, an SSH port move and the rollback cycle; `--containers` and
  `--beszel` add module stages, and `--dry-run` prints every command. Steps
  and host effects: `docs/design/acceptance.md`.
- `[forgejo]`: a Forgejo git forge (pinned 15.0.11 LTS binary, SHA-256
  checked) under systemd, on `127.0.0.1` behind `[tls]`'s nginx, with git
  over SSH on Forgejo's own port (2222). Secrets come from `${ENV}`, and
  registration is off. Forgejo Actions is off unless `actions = true`
  (anvil installs no runner yet). Rollback removes the binary only if anvil
  installed it and never deletes `/var/lib/forgejo`. See
  `examples/forgejo.toml` and `docs/design/forgejo.md`.
- `[tls]`'s HTTPS server block includes `/etc/nginx/anvil-tls.d/*.conf`.
  Existing hosts show one-time drift on `anvil-tls.conf`.
- `[containers.compose.<name>]`: Docker Compose projects as managed files plus
  one systemd unit each, with drift detection, reload only on change, a
  `docker compose config` guard and rollback. Secrets go in `env` (written to
  a 0600 `.env`, never printed by `diff`). See `examples/containers.toml`.
- `docs/design/container-runtime.md`: Docker vs Podman study (recommends
  Docker only, for now).
- Load-time warnings for risky container setups: compose projects with
  `[docker] iptables_off = true` (no outbound internet), and a public
  `headplane_listen` that Docker publishes past ufw.
- `scripts/smoke.sh` runs a compose project and checks it answers.
- `[caddy]` module: Caddy reverse proxy with automatic HTTPS for localhost
  services (`[[caddy.site]] domain/upstream`, optional IP allow-list and basic
  auth), installed from Caddy's apt repo with an embedded signing key, reloads
  guarded by `caddy validate`, ufw opened for 80/443 and HTTP/3. Enabling it
  with `[tls]` on the same ports is a validation error. Example:
  `examples/caddy-proxy.toml`.
- `[beszel]` module: Beszel monitoring — the agent, the hub (web UI), or
  both on one host (`hub = true`; they talk over `127.0.0.1`). Pinned
  releases, SHA-256 checked, each service as its own unprivileged user under
  a sandboxed systemd unit. No port is ever world-open: a remote agent
  connects out (`hub_url` + `token`) or is reachable only from
  `hub_addresses` / `tailscale0`, and a non-loopback hub only from
  `hub_allow_from` / `tailscale0`. The agent token is kept in a root-only
  `0600` file. Examples: `examples/monitoring-single-vm.toml`,
  `examples/monitored-server.toml`.
- `[restic]` module: scheduled restic backups with `forget --prune`
  retention, repository init when missing, a first backup started by
  `apply` only while the host has no snapshot yet, and a `check` drift
  signal when the newest snapshot is older than `max_age_hours` (reported
  with the last run's result, never retried; a failed last run drifts
  too). Secrets come from `${ENV}` and are stored only in a root-only
  env file. Rollback never touches the repository and leaves the restic
  package installed. See `examples/backup.toml` and the restore steps
  in `docs/03_operations.md`.
- `docs/08_architecture.md` with diagrams of the architecture, the `apply`
  workflow, the SSH sequence, TOML-to-host data flow and the managed-file
  lifecycle.
- Command reference has a shared-flags table.
- Tutorial and concepts pages: a fresh-VPS walkthrough with real output, the
  PAM policy, drift detection with `diff`, and what rollback undoes.
- `[github_runner]`: self-hosted GitHub Actions runners for private repos.
  Pinned, SHA-256-verified actions/runner tarball, an unprivileged
  `github-runner` user, one-time registration with a `${ENV}` token (passed by
  environment, never on the command line), a hardened systemd unit per runner,
  workspace cleanup after each job, optional `docker = "group"`, and rollback
  that deregisters when `remove_token` is set. Design:
  `docs/design/github-actions-runner.md`.

### Changed

- `/etc/docker/daemon.json` is one anvil `ManagedFile` (backup, diff,
  rollback) instead of a jq merge: json-file logs capped at `max-size=10m`,
  `max-file=3`, the `[docker]` keys and, on v2 runner hosts, the sysbox
  runtime, `bip` and `default-address-pools`. A v2 runner owns the file when
  enabled. Hand-added keys are replaced (the original stays in `.anvil.bak`).
  dockerd is never restarted while a v2 sandbox runs; apply warns instead.
- Generated file headers no longer carry issue numbers, so the first apply
  after upgrading rebuilds the runner sandbox images (GitHub, Forgejo,
  Podman) and restarts the Orca server (`coding_agents`).
- `[github_runner]`/`[forgejo_runner]` units set `OOMPolicy=continue`: a job
  OOM-killed under `MemoryMax` no longer stops and restarts the runner.
- Ordering: `hetzner` now always runs after `tailscale` (new hard edge). An
  `order_override`/`execution_order` that puts hetzner first is an error.
- `[github_runner]` rollback removes the `github-runner` user and group once
  no runner is left, but only if anvil created them (recorded in
  `/var/lib/anvil/created` from now on; users created by older versions stay).
  Packages and `/var/lib/github-runner` are never removed.
- `[github_runner]` rollback without a `remove_token` ends `OK` with a
  warning that GitHub deletes the offline runner after 14 days.
- `[github_runner]` re-runs the runner's `installdependencies.sh` when any of
  its five libraries is missing (was: only krb5, zlib or ICU), so a host
  without OpenSSL or LTTng gets them.
- `rollback` undoes modules in reverse apply order (last applied, first
  undone), except that `sshd` and `ssh_crypto` are undone before `firewall`.
  Fixes containers orphaned when `[docker]` was undone first.
- `[docker]` on a host without Docker yet writes `daemon.json` without a
  failing restart; rollback deletes a `daemon.json` anvil created and restarts
  dockerd so the restored config applies; restarts clear systemd's start
  limit, so an apply followed by a rollback cannot trip `start-limit-hit`.
- A command-edited file that anvil created from scratch is deleted on
  rollback (it used to be left behind).
- greptimedb and Headplane containers run with `--userns=host`, so they keep
  working when `[docker] userns_remap` is on (the default).
- Headplane's port works with any `headplane_listen`: it now always listens on
  `0.0.0.0:3000` inside its container, the target of the published port.
- Port moves on socket-activated hosts (Ubuntu 22.10+) restart `ssh.socket`,
  so sshd listens on the new port instead of 22.
- A failed reload after `sshd -t` passes now reverts every write from the run.
- `rollback` reloads services and restores sysctl and `/tmp` mount state
  immediately, not at next boot.
- `updates.security_only` is security-only on Debian too.
- `diff` matches `check` and `apply` on trailing newlines, CRLF, mode and owner,
  and non-UTF-8 content.
- `process` no longer forces `ENCRYPT_METHOD SHA512` over the yescrypt hashes
  PAM uses.

### Fixed

- `github_runner` ephemeral: on Ubuntu 24.04+, apply adds a sysbox-fs mount rule to `/etc/apparmor.d/local/fusermount3` (existing lines kept, rollback restores) and reloads the profile; its AppArmor profile denied the mount and no sandbox started.
- `github_runner` ephemeral: apply never restarts a slot over its sandbox (it killed a running job). A new image, minter or limits take effect from the next job; a changed slot unit restarts the slot after its job. On a host from before this fix, restart idle slots once after the first apply.
- `github_runner`: a root-owned job-started hook sets `TMPDIR=$RUNNER_TEMP`, so tools that run binaries from `$TMPDIR` work although CIS mounts `/tmp` `noexec`; the next apply restarts each runner once for the new unit.
- `suid`/`filesystem`: scans skip `/var/lib/containerd` and `/var/lib/sysbox`; Docker 29 keeps image layers there, and an apply would strip setuid bits and chmod files inside image layers.
- `github_runner` ephemeral: JIT runners get the default labels `self-hosted`, `Linux` and `X64`/`ARM64`; with only the configured labels, `runs-on: [self-hosted, …]` never matched.
- `github_runner` ephemeral: the sandbox no longer prints the runner's diag trace to the journal, only its terminal lines.
- `github_runner`: apply restarts a runner only when its own unit, hook, mount or registration changed; adding a second runner restarted (and killed the job on) the first.
- `github_runner`: each runner gets its own `HOME=/var/lib/github-runner/<name>` and may write only its own home and dir, so parallel runners no longer share `~/.rustup`/`~/.cargo` (a toolchain update on one broke `cargo` on the other). The next apply restarts each runner once for the new unit; the old shared home stays.
- A failed reload no longer leaves modified files changed when anvil cannot rewrite its created-files list (read-only or full `/var/lib/anvil`): that bookkeeping step aborted the revert under `set -e`. Found running CI on a self-hosted runner.
- Parent directories anvil creates for a managed file are now `0755` whatever the host umask; under the CIS umask they came out `0750`, so the `github_runner` job hook in `/usr/local/libexec/anvil` was invisible to the runner user and every job failed with "File doesn't exist". Existing `0750` directories are not changed: `chmod 755` them once.
- `[process]`: with `disable_core_dumps`, apport's units are disabled and stopped where installed (Ubuntu), so `fs.suid_dumpable=0` and the core_pattern no longer revert at boot; rollback re-enables only the units anvil disabled. No-op on Debian.
- `rollback` after an SSH port move no longer locks out new logins: sshd is
  restored before the firewall, whose rollback then allows the restored port
  (it ran first and allowed the old one).
- `[suid]`: an allowlisted path that is a symlink also allows its target, so the sweep no longer strips sudo-rs on Ubuntu 26.04 (`/usr/bin/sudo` → `/usr/lib/cargo/bin/sudo`).
- `[github_runner]` rollback no longer ends with `FAILED: github runner
  services restored config did not validate or reload` after removing a
  runner: the reload guard now skips runners whose unit is gone.
- `[docker]`: a later `daemon.json` change no longer overwrites
  `daemon.json.anvil.bak`, so `rollback` restores the pre-anvil original.
- `[containers]`: `rollback` stops and disables a compose project's unit
  before deleting its files, so `ExecStop` no longer fails on a missing
  compose file.
- `[containers]`: `env` values may contain `'`. `.env` lines are now
  written double-quoted and escaped (`KEY="v"`, was `KEY='v'`), so existing
  `.env` files drift once and each project gets one `reload-or-restart`
  (`up -d` recreates nothing).
- `[containers]` installs Compose v2 on Debian 13 with the distro `docker.io`
  by falling back to Debian's `docker-compose` (2.26, ships the `docker
  compose` plugin).
- `rollback` now undoes `tailscale.tailnet_only_ssh`: for every
  tailnet-only SSH rule it re-opens the port to the world first, then removes
  the scoped rule, so `rollback --only tailscale` can no longer leave public
  SSH closed. The node stays joined to the tailnet.

- `tailscale.tailnet_only_ssh` no longer drops public SSH just because the node
  has a tailnet IP. It now requires an established SSH connection arriving on
  the node's own tailnet address (anvil's session when `[host] address` is the
  tailnet name/IP); otherwise public SSH stays open and the run says why.
  Before, an operator not yet on the tailnet (or denied by an ACL) was locked
  out on the next login.
- With `[tailscale]` enabled, fail2ban (`ignoreip`) and crowdsec (a parser
  whitelist) never ban tailnet addresses (`100.64.0.0/10`,
  `fd7a:115c:a1e0::/48`), which may be the operator's only way in.

- `tailscale` and `vector` install failed on a hardened host (`umask 027`,
  e.g. the CIS profile): the downloaded apt key and source landed `0640`, and
  apt on Debian 13 verifies signatures as `_apt`, which could not read the key.
  Both files are now `chmod 0644` before apt runs.
- SSH lockouts: login user checked against `PermitRootLogin` and `AllowUsers`;
  a live SSH port other than 22 stays open on the Hetzner cloud firewall;
  `--only firewall` without `[sshd]` is a usage error, so the firewall is never
  applied without its sshd ordering.
- Rollback: `suid` keeps every stripped-binary record across runs; the firewall
  rollback keeps the restored SSH port open (rules themselves stay); `/etc/login.defs` backups are per module; a distro file
  that anvil only chmod/chowned is no longer deleted; `filesystem` `/tmp`
  rollback removes its drop-in.
- Module behavior: `pam` pwquality and faillock are wired into PAM; firewall
  `from` rules and tailscale `tailnet_only_ssh` no longer report drift forever;
  crowdsec refreshes its package lists and installs its collections; lynis and
  AIDE install failures are reported; tailscale installs without `curl | sh`;
  `tls` installs its ACME client first.
- `suid` allowlist keeps `newuidmap`/`newgidmap` and the stock snap and mount
  helpers.
- `headscale` user lookup matches the exact name.
- `report --check` shows the plugin verdicts that decide its exit code.
- Failure messages show the real error from the script.
- Config: `include` duplicate arrays and rename-swap, `${A:-${B}}` nested env
  expansion, `init --profile` names, and `validate_hhmm` leading `+`.
- Generated scripts no longer pipe into `grep -q` under `pipefail`.
- SSH multiplexing works on macOS (socket path under the limit).

### Security

- `[github_runner]`, `[forgejo_runner]`: the runner unit adds
  `PrivateDevices=yes` (private `/dev` and `/dev/shm`) and an empty
  `CapabilityBoundingSet=`, so even a job that became root holds no
  capabilities and cannot undo the read-only mounts. The next apply rewrites
  the unit and restarts the runner.
- `[github_runner]`: the job-completed hook also deletes the runner
  user's entries in the unit's private `/tmp` and `/var/tmp`, so a job's
  temp files no longer reach the next job on the same runner. A failure
  there never fails the job.

- `[forgejo]`: the downloaded binary's `.asc` signature is verified
  with `gpg` in a throwaway keyring against Forgejo's release key (pinned
  fingerprint `EB114F5E…5923710`; key fetched from keys.openpgp.org) and
  fails closed. `version` can now change without `sha256_amd64`/
  `sha256_arm64`; the built-in 15.0.11 checksums are still checked. Install
  needs outbound HTTPS to keys.openpgp.org.

- `[tailscale]`: `auth_key` no longer appears in the host's process list
  during `tailscale up`. It goes to a 0600 file in anvil's root-only run
  directory, is passed as `--auth-key file:<path>` (Tailscale v1.16.0+), and
  is deleted after the run, failed or not.
- `[caddy]` serves its admin API on the unix socket
  `/var/lib/caddy/admin.sock` instead of TCP `localhost:2019`, so other local
  users can no longer reconfigure Caddy. The first apply restarts Caddy once.
- A failed `tailscale` step skips later `firewall` and `hetzner` steps in the
  same run, like a failed `sshd`, so a broken tailnet join cannot be followed
  by a fence that closes the public SSH path.
- Plugin `{{VAR}}` substitutions are inert inside double quotes; a value that
  would break out of a quoted string is refused.
- Includes get the same ancestor-directory rename-swap check plugins already
  had, so an include cannot be redirected to attacker-chosen config.
- Plugin trust check fails closed when its uid probe file already exists.
- Config values that reach `ExecStart`, sysctl, jail or domain fields are
  validated before rendering.

### Docs

- `DESIGN.md` trimmed of pre-implementation hedging.

### Baseline (since the first commit; never released)

- 24 hardening modules on one declarative engine: probe, apply, diff and
  rollback are rendered from a single per-module declaration, so check and
  apply cannot disagree.
- Commands: `apply` (two-phase, converges only drifted modules), `validate`,
  `check`, `diff`, `rollback`, `status`, `score`, `report`, `doctor`, `init`,
  `profiles`, `plugins`; `--dry-run`, `--output json|ndjson`, `--parallel`,
  `--host`/`--exclude`, `--timeout`.
- Lockout guards: enforced run order (firewall after sshd, updates last),
  SSH port allowed before `ufw enable`, `sshd -t` validation with auto-revert,
  Hetzner cloud firewall keeps SSH open during a port cutover.
- Backups and a per-run manifest for every managed file; `rollback` restores
  them and removes created files.
- Profiles (`minimal`, `cis-level1`, `web-server`, `ci-runner`), `include`
  composition, `${ENV}` substitution, out-of-tree plugins with trust checks.
- Keyring-pinned vendor apt repositories for docker and vector (crowdsec now
  uses the distro's packages, see Breaking).
- `scripts/smoke.sh`: end-to-end test on a throwaway Hetzner Cloud VM.

Known defects are tracked in the GitHub issues.
