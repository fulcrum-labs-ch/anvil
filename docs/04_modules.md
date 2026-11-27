# Module catalog

What each module actually does on the host, and which files it owns. Every
overwrite of an owned file is preceded by a `<path>.anvil.bak` backup, and
a per-run manifest is recorded under `/var/lib/anvil/runs/` — `rollback`
restores the backups and removes files the tool created.

Drop-in naming is deliberate and load-bearing: `sshd_config.d` is
**first-match-wins**, so anvil uses low `05-` prefixes to beat distro files
like `50-cloud-init.conf`; last-match-wins directories (`sysctl.d`,
`modprobe.d`, `resolved.conf.d`, `jail.d`, audit `rules.d`) get high
`99-anvil*` prefixes. These paths never change once shipped — drift, diff,
and rollback key on them.

## Run order

Modules run in a topologically sorted order seeded by per-module waves:

```
users → packages → sshd → ssh_crypto → kernel → kernel_modules → pam →
process → dns → suid → filesystem → auditd → fail2ban → crowdsec →
firewall → docker → apps_resources → tls → caddy → ci_resources → containers → forgejo → github_runner →
forgejo_runner → headscale → tailscale → greptimedb → vector → beszel → restic → hetzner →
netcup → coding_agents → lynis → updates
```

These constraints are **hard edges** that no `order_override` or
`[execution_order]` can defeat (violations are errors, never reorderings):

1. `sshd` before `firewall` — the firewall must know the effective SSH port.
2. `sshd` before `ssh_crypto`.
3. `ssh_crypto` before `firewall` — the firewall comes after every SSH change.
4. `tailscale` before `hetzner` and `netcup` — the provider edge may rely on
   the tailnet for SSH (`keep_public_ssh = false`).
5. `ci_resources` before `github_runner` and `forgejo_runner` — their units
   run in the slice it writes.
6. `apps_resources` before `caddy`, `forgejo`, `greptimedb`, `vector` and
   `containers` — their units/drop-ins name `apps.slice`.
7. `forgejo` before `fail2ban` — the forgejo jail needs Forgejo's log file.
8. `updates` (and any reboot) last — after every module and plugin.

## Access & authentication

- **sshd** — hardened drop-in at `/etc/ssh/sshd_config.d/05-anvil.conf`
  (`PermitRootLogin no`, `PasswordAuthentication no`, port, auth tries, keep-
  alives, optional `AllowUsers`). Validated with `sshd -t` behind a reload
  guard: on failure the modified files are restored from backup, files
  created that run are deleted, and no reload happens.
- **ssh_crypto** — separate drop-in `/etc/ssh/sshd_config.d/05-anvil-crypto.conf`
  with strong `KexAlgorithms`/`Ciphers`/`MACs`/`HostKeyAlgorithms`. The
  algorithm lists are **computed on the host**, filtered to what its OpenSSH
  supports (post-quantum KEX kept where available). Same `sshd -t` guard.
- **pam** — `/etc/security/pwquality.conf`, `/etc/security/faillock.conf`,
  a `/etc/profile.d/99-anvil-hardening.sh` (TMOUT), and the `UMASK` line in
  `/etc/login.defs` (its original recorded for rollback). Makes the policy
  active: installs `libpam-pwquality` (which registers `pam_pwquality`) and
  enables two anvil profiles in `/usr/share/pam-configs/` for
  `pam_faillock` with `pam-auth-update`; the merged stack is verified and
  backed out if it isn't preauth → pam_unix → authfail. Never hand-edits
  `/etc/pam.d/`; root is never locked.
- **users** — `useradd` missing accounts, `/etc/sudoers.d/<name>` drop-ins
  (mode `0440`), synced `~/.ssh/authorized_keys` (dir `0700`, file `0600`).

## Network

- **firewall** — ufw defaults, user allow/deny rules, then `ufw --force
  enable` — with the effective SSH port allowed (rate-limited via `ufw
  limit` by default) *before* enable.
- **fail2ban** — jail config at `/etc/fail2ban/jail.d/99-anvil.conf`; the
  sshd jail watches the effective SSH port automatically. With `[tailscale]`
  enabled, tailnet addresses are never banned (`ignoreip`). With `[forgejo]`,
  a `forgejo` jail bans failed web logins (`/var/lib/forgejo/log/forgejo.log`,
  filter `anvil-forgejo`) on the HTTPS and git-SSH ports — tailnet clients
  included; only loopback is exempt.
- **crowdsec** — CrowdSec agent + firewall bouncer from the distro's own
  archive (the bouncer registers itself and picks nftables/iptables to match
  the system; `bouncer_mode` forces one), plus the configured collections.
  With `[tailscale]` enabled, a parser whitelist
  (`/etc/crowdsec/parsers/s02-enrich/anvil-tailnet-whitelist.yaml`) keeps
  tailnet addresses from being banned.
- **dns** — systemd-resolved drop-in `/etc/systemd/resolved.conf.d/99-anvil.conf`
  (DNS-over-TLS to Quad9/Cloudflare by default).
- **kernel** — network-hardening sysctls in `/etc/sysctl.d/99-anvil-kernel.conf`
  (plus `dmesg`/kptr restrictions and `extra_sysctl`); keys the running
  kernel rejects are tolerated.
- **hetzner** — the one **local** module: drives the `hcloud` CLI to create/
  update a Hetzner Cloud firewall and apply it to the server. Keeps the
  effective SSH port open, and TCP 22 during a port cutover, unless
  `keep_public_ssh = false` (tailnet-only nodes; see
  [05_configuration.md](05_configuration.md#hetzner--runs-locally-drives-hcloud)). Requires
  `hcloud`, `jq`, and `HCLOUD_TOKEN` on the operator machine (preflighted).
  It adds no rules for other modules: load warns when `[caddy]`'s HTTP/HTTPS
  ports have no inbound tcp rule, or a public `beszel.hub_addresses` entry
  (outside RFC1918, loopback, link-local, `100.64.0.0/10`, `fd00::/8`; v4 and v6) is
  not covered by a rule's `source_ips` on `listen_port`.
- **netcup** — also **local**: manages the netcup SCP firewall over the SCP
  REST API with `curl` + `jq`. anvil owns one user policy (`policy`, by
  name): it creates it, converges its rules (R61 SSH guard and
  `keep_public_ssh` as hetzner, except that your own source-restricted SSH
  rule counts as the guard) and attaches it to the server's single public
  interface next to whatever is already attached. Other policies are never
  edited, deleted or detached. Needs `curl`, `jq` and
  `NETCUP_SCP_REFRESH_TOKEN` on the operator machine; every request is
  checked against a fixed allowlist (token refresh, userinfo, server
  lookup, the interface firewall, the user's firewall policies). Rollback
  restores the attached policy set snapshotted before the first attach. Same
  caddy/beszel load warnings as hetzner, prefixed `netcup:`. See
  [05_configuration.md](05_configuration.md#netcup--runs-locally-drives-the-scp-rest-api).

## System

- **kernel_modules** — blacklist at `/etc/modprobe.d/99-anvil-blacklist.conf`
  (`install <mod> /bin/false`), then `update-initramfs -u`.
- **process** — core dumps off (`/etc/security/limits.d/99-anvil-coredump.conf`
  + `/etc/systemd/coredump.conf.d/99-anvil.conf`, `fs.suid_dumpable=0`; where
  apport is installed (Ubuntu) its enabled units are disabled and stopped so
  the setting survives reboot — rollback re-enables only units anvil
  disabled), `kernel.sysrq=0`,
  password aging in `/etc/login.defs` (first-change backup), optional
  `hidepid=2` via `/etc/systemd/system/anvil-hidepid.service`.
- **suid** — scans for setuid/setgid binaries, strips bits not on the stock
  allowlist + `extra_whitelist`; records prior modes in
  `/var/lib/anvil/suid.state` so drift and rollback stay exact.
- **filesystem** — `/tmp` `noexec,nosuid,nodev` via
  `/etc/systemd/system/tmp.mount.d/60-anvil.conf`, sticky-bit and
  world-writable scans, optional AIDE baseline.
- **packages** — apt install/purge with a dpkg lock timeout; each package's
  state verified afterwards.
- **updates** — unattended-upgrades via `99-anvil*` drop-ins under
  `/etc/apt/apt.conf.d/` (a high prefix wins over later regens and never
  clobbers the distro's stock `20auto-upgrades`/`50unattended-upgrades`).
  Always last.

## Auditing

- **auditd** — CIS level-1 rules at `/etc/audit/rules.d/99-anvil.rules`,
  loaded via `augenrules` behind a validation guard (bad rules revert the
  file). The file header always names the rule set actually installed. On
  arm64 the 64-bit rules leave out the syscalls aarch64 lacks (`open`,
  `creat`, `chmod`, `unlink`, `rename`).
- **lynis** — installs Lynis; `anvil score` runs the audit and parses the
  hardening index.

## Services & observability

- **docker** — owns `/etc/docker/daemon.json`: its keys plus json-file
  logs capped at 3 × 10 MB per container (hand-added keys are replaced; the
  original stays in `.anvil.bak`). Restarts dockerd only when the file
  changed, never while v2 runner sandboxes run (then it warns). Installs the
  engine if missing (rollback keeps it). `source` picks where the
  engine comes from: Docker's apt repo (default) or,
  on Ubuntu, `docker.io` + `docker-compose-v2`. Without `[docker]`, a module
  that installs Docker enables it logs-only: anvil creates a capped
  `daemon.json`, an existing one is kept. Not on a Podman host:
  [Docker or Podman](modules/container-engines.md).
- **containers** — Docker Compose projects. Each `[containers.compose.<name>]`
  becomes `/etc/anvil/compose/<name>/compose.yaml` (0640), an optional `.env`
  (0600, never shown by `diff`) and `anvil-compose-<name>.service`, which runs
  `docker compose up -d`. A project is reloaded only when its own files
  changed; a file that fails `docker compose config` is reverted. Rollback
  takes removed projects down (volumes are kept). Published ports skip ufw:
  publish on `127.0.0.1` — see `examples/containers.toml`. While Docker owns
  iptables (`[docker] iptables_off = false` or no `[docker]`), a project that
  publishes on any other address fails validation (checked on
  `docker compose config`) and is reverted.
  One engine per host: [Docker or Podman](modules/container-engines.md).
  With `runtime = "podman"` it runs Podman Quadlets instead: each
  `[containers.quadlet.<name>]` becomes
  `/etc/containers/systemd/anvil-<name>.container` (rootful) and the
  generated `anvil-<name>.service`. Podman comes from the distro package;
  `containers.conf.d/99-anvil.conf` sets netavark's iptables driver so
  containers reach the internet past ufw's routed-deny. The
  probe refuses a host below Podman 4.4 with `FAILED:` (Debian 12 ships 4.3.1,
  Ubuntu 22.04 3.4.4 — use Docker there). Every `PublishPort=` must bind
  `127.0.0.1`/`::1` (rootful netavark skips ufw like Docker), checked at load.
  A unit that `quadlet -dryrun` cannot convert is reverted. Add `[Install]
  WantedBy=multi-user.target` for start at boot. Rollback stops and removes
  anvil's units; images, volumes and the `podman` package stay. Live-tested
  on Debian 13 and Ubuntu 26.04 (arm64), 2026-11-03.
- **tls** — certbot/acme.sh certificates plus a hardened nginx TLS block at
  `/etc/nginx/conf.d/anvil-tls.conf`, guarded by `nginx -t` with revert. The
  HTTPS block includes `/etc/nginx/anvil-tls.d/*.conf`, where modules such as
  `forgejo` put their `location` blocks.
- **caddy** — Caddy reverse proxy with automatic HTTPS for localhost services
  (`[[caddy.site]]`). Owns `/etc/caddy/Caddyfile`, guarded by `caddy validate`
  with revert; opens 80/tcp, 443/tcp, 443/udp in ufw (`listen = "tailnet"`:
  443 on `tailscale0` only); `tls = "tailscale"` sites use tailscaled's
  `*.ts.net` certificate (caddy then runs after tailscale); `tls = "dns"`
  sites run a pinned host-built Caddy with the DNS provider (removed with its
  token file once no site uses `dns`); admin API on a
  root/caddy-only unix socket. An alternative to `tls`
  for the same ports — enable one per host. See `docs/design/caddy.md`.
- **forgejo** — a Forgejo git forge (signature-verified upstream binary, or
  the digest-pinned rootless image with `deploy = "compose"`) on
  `127.0.0.1:3000` behind `[caddy]`/`[tls]`, git over SSH on its own port
  2222. Rollback never deletes `/var/lib/forgejo`. Guide:
  [Forgejo](modules/forgejo.md).
- **headscale** — SHA-256-verified `.deb` at pinned version, `/etc/headscale/config.yaml`,
  optional ACL policy, systemd unit, pre-auth keys; optional Headplane UI.
  Headscale serves plain HTTP: put `[caddy]` (or `[tls]`) in front.
- **tailscale** — install + `tailscale up` (login server, auth key, routes).
  `tailnet_only_ssh` re-scopes the firewall's SSH allow to `tailscale0` only
  once SSH is proven to work over the tailnet (anvil's own session arrives on
  the node's tailnet address).
- **greptimedb** — GreptimeDB as the internal compose project `greptimedb`
  (`/etc/anvil/compose/greptimedb/`, `anvil-compose-greptimedb.service`,
  same machinery as **containers**), ports loopback-bound by default. A host
  still on the old `greptimedb.service` (`docker run`) is migrated on the
  next apply: the old unit is backed up, stopped and removed, then the
  compose project starts on the same `data_dir`; rollback brings the old
  unit back. `[containers.compose.greptimedb]` is reserved. Imports four
  Perses dashboards (`/etc/anvil/greptimedb-dashboards/`) after each start.
- **vector** — Vector config `/etc/vector/vector.toml` + unit, shipping
  the journal, host and cgroup metrics into GreptimeDB (pinned apt repo —
  never `curl | sh`); rollback stops it. See [Monitoring](modules/monitoring.md).
- **beszel** — [Beszel](https://github.com/henrygd/beszel) monitoring: the
  agent, the hub (web UI), or both on one host. Pinned release checked
  against a SHA-256 compiled into anvil (or set in `sha256` for another
  `version`), binaries in `/usr/local/bin`, each service
  as its own unprivileged user (`beszel`, `beszel-hub`) under a sandboxed
  unit (`beszel-agent.service`, `beszel-hub.service`). The agent's settings
  and token live in `/etc/default/beszel-agent` (root-only, `0600`); the hub's
  optional first-admin credentials in `/etc/default/beszel-hub`. On one
  host the agent and hub talk over `127.0.0.1` with no setup beyond adding
  the system in the UI. Ports beyond loopback are opened in ufw only from
  listed addresses or on `tailscale0`. The agent gets no `docker` or `disk`
  group unless `docker = true` / `smart = true` opt in (both
  root-equivalent). Rollback removes services, rules,
  binaries and users anvil created, and keeps the hub's database.
- **restic** — nightly encrypted backups: restic (distro package if
  ≥ 0.17.1, else the pinned, SHA-256-verified upstream release), a 0600
  `/etc/restic/env` with the repository and secrets, `anvil-restic.service`
  + `.timer` (backup, then `forget --prune`), and repository init if
  missing. `apply` starts a first backup only while the repository has no
  snapshot of this host. `check` drifts when the newest snapshot is older
  than `max_age_hours` or the last run failed, reporting the age and the
  run's result; a stale snapshot is never retried. Rollback removes the
  units and files; packages and data are never removed (the repository
  and the restic package stay). Restore: [03_operations.md](03_operations.md#backups-and-restore).
- **github_runner** — self-hosted GitHub Actions runners for **private repos
  only**: a pinned, verified runner as an unprivileged user in a hardened unit
  (no sudo, read-only system, workspace wiped after each job), optionally
  capped in CPU, memory and disk. `mode = "ephemeral"` instead runs each job
  in a fresh sysbox sandbox with its own Docker, minted with a GitHub App. See
  the [GitHub Actions runner guide](modules/github-runner.md).
- **ci_resources** — one systemd slice, `/etc/systemd/system/ci.slice`,
  holding every `github_runner` and `forgejo_runner` unit (they get
  `Slice=ci.slice` while the section is set): a dash-free name puts it under
  `-.slice`, next to `system.slice`/`user.slice`, so its weight counts there.
  `cpu_quota`/`memory_max`/`tasks_max` are the total share of the host for all
  CI work, each runner's own caps still apply inside it, and `cpu_weight`
  (default 50, below systemd's 100) lets sshd and other system services win
  under load. Applied with `daemon-reload` (the slice is never restarted); a
  older host's `anvil-ci.slice` and `anvil.slice` drop-in are backed up and
  removed on apply; rollback removes the slice and restores them. **Limit:**
  job containers of `docker = "group"` run under dockerd's cgroup, outside the
  slice (every command warns about it).
- **apps_resources** — one systemd slice, `/etc/systemd/system/apps.slice`,
  holding the host's own applications: Caddy (a
  `caddy.service.d/99-anvil-slice.conf` drop-in), Vector (in its unit's
  `[Service]`), Forgejo (native unit, compose unit or Quadlet) and
  GreptimeDB (the compose unit and container, or the Quadlet). Forgejo's and
  GreptimeDB's generated compose files give every service
  `cgroup_parent: apps.slice`, because Docker otherwise starts containers in
  `system.slice/docker-*.scope` regardless of the compose unit's slice; this
  needs Docker's **systemd cgroup driver** (a `.slice` name is a systemd
  slice, not a raw cgroupfs path). `system_memory_low` writes
  `system.slice.d/99-anvil-memory-low.conf` (`MemoryLow=`), so the kernel
  reclaims from user, CI and app work before system services such as sshd.
  Applied with `daemon-reload`; the moved units restart once (their unit or
  drop-in changed). Rollback removes the slice and the drop-in; each app
  module's rollback removes its own `Slice=` line or drop-in. **Limit:**
  containers of a user-declared `[containers.compose.*]` project stay in
  Docker's own scope; add `cgroup_parent: apps.slice` to their services
  yourself.
- **forgejo_runner** — one Forgejo Actions runner: pinned, SHA-256-verified
  `forgejo-runner` binary in `/usr/local/bin`, an unprivileged
  `forgejo-runner` user, its config (with the runner token) in
  `/etc/forgejo-runner/config.yml`, and a hardened
  `anvil-forgejo-runner.service`, optionally capped like `github_runner`.
  See the [Forgejo runner guide](modules/forgejo-runner.md).
- **coding_agents** — Claude Code and OpenCode v2 from their official
  installers, run as and self-updating for one no-sudo `[users]` account; skills, plugins and MCP servers installed as that user,
  linger, optional slice caps, optional rootless Docker/Podman as the user (`docker = "rootless"`). See the [coding agents guide](modules/coding-agents.md).

## GitHub Actions runner

Setup (registration token, `runs-on`), limits, security and troubleshooting:
[docs/modules/github-runner.md](modules/github-runner.md).

## Forgejo Actions runner

Jobs run on the host as `forgejo-runner` (`:host` labels) or in containers:
root-equivalent with `docker = "group"` (Docker host), rootless as
`forgejo-runner` with `docker = "rootless"` (either engine; `"podman"` on a
Podman host). Why, setup, security
and troubleshooting: [docs/modules/forgejo-runner.md](modules/forgejo-runner.md).

## Next

- Reference: [05_configuration.md](05_configuration.md) for every field and default,
  [06_commands.md](06_commands.md) for the CLI, [07_plugins.md](07_plugins.md) to add your
  own steps.
