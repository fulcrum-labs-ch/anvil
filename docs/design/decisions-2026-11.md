# Decisions — 2026-11

Design decisions, 2026-11-01. One entry per question (or group):
the decision, the reason, and the follow-up task if any. "Skip" / "don't know"
are recorded as given.

<!-- entries are appended in the order the questions were asked -->

## When Debian 12 / Ubuntu 22.04 leave the support matrix (CR20)

- **Decision:** Don't wait for a drop date. Start the Podman work now;
  Debian 12 and Ubuntu 22.04 stay in the matrix for everything else.
- **Reason:** Waiting until Ubuntu 22.04's standard EOL (~2027-04/05) blocks
  Podman for ~6 months for the sake of two releases. Debian 12 is already
  LTS-only (regular security support ended 2026-06-10).
- **Follow-up:** `runtime = "podman"` is refused per host, not
  globally: the probe reads the host's release / Podman version and, below
  the Quadlet minimum, reports `FAILED:` with an actionable reason (e.g.
  "Podman runtime needs Podman >= 4.4 for Quadlets; this host (Debian 12)
  ships 4.3.1 — use runtime = \"docker\""). Docker stays the default. Document
  the unsupported releases in `container-runtime.md` and the module docs.
  Reconcile the minimum version (the decision says 4.9, the design study says 4.4).

## Caddy: pin a version or track stable (CA2)

- **Decision:** Track Caddy's stable apt channel (current behaviour).
- **Reason:** Maintainer's choice; Caddy's stable channel is the supported
  upgrade path, and pinning adds per-release upkeep.
- **Follow-up:** none.

## github_runner: GHES in v1? (GR14)

- **Decision:** github.com only for now; GHES deferred.
- **Reason:** Maintainer's choice; keeps v1 free of configurable API/URL bases.
- **Follow-up:** reject non-github.com URLs at config validation with a clear
  message; leave a GHES item for v2.

## Rename `__anvil_forget`? (T20)

- **Decision:** Close as moot, no rename.
- **Reason:** No banned-word rule exists in the repo, and the module shipped
  as `forgejo`, so no substring rule on "forge" can be in force.
- **Follow-up:** none.

## ufw vs Docker publishes with `iptables=false` (CR12)

- **Decision:** Not a decision; move it into the acceptance run.
- **Reason:** It needs a real host; it belongs with the other live checks.
- **Follow-up:** add two steps to the acceptance run / `scripts/acceptance.sh`: (1) a
  `0.0.0.0` publish is blocked by ufw from another host unless allowed;
  (2) whether containers keep outbound internet with `iptables=false`.

## Provider firewall rules for caddy / beszel (CA3, T17)

- **Decision:** No automatic rules. Provider firewall rules stay explicit in
  the `[hetzner]` and `[netcup]` blocks. The only implicit rules
  remain the R61 SSH lockout guard. Add a **warning** instead.
- **Reason:** The operator decides what is exposed; anvil never edits the
  TOML, and implicit rules would make the cloud firewall harder to reason
  about. A warning still catches the forgotten rule.
- **Follow-up:** `check`/`diff` warn when `[caddy]` is enabled and
  `[hetzner].rules` allows no 80/tcp + 443/tcp (443/udp optional), and when
  `beszel.hub_addresses` / `hub_allow_from` contain public addresses not
  covered by a `[hetzner]` rule (public-vs-private/tailnet address test to
  confirm in implementation). Wording e.g. `hetzner: [caddy] is enabled
  but no rule allows 443/tcp — the site and ACME will be unreachable`. Same
  warning for `[netcup]`.

## Forgejo: database provisioning (FJ2)

- **Decision:** Offer three database modes, plus Compose as a second install
  path for Forgejo itself:
  1. SQLite (default, today).
  2. Local PostgreSQL from apt: anvil installs it and provisions role + DB.
  3. Containerized PostgreSQL (Docker), Forgejo still the systemd binary.
  4. Compose install: Forgejo + PostgreSQL together in one compose project,
     as an alternative to the systemd binary.
- **Reason:** Different operators want different trade-offs (no extra
  service; distro Postgres; isolated Postgres; everything in containers).
- **Follow-up:** design first (it's a big change, not just a database option): extend `forgejo.md` with how each mode
  is selected in config, backups (`pg_dump` on host vs inside the container),
  updates (pinned image tags), rollback (what is removed, data never), and
  how the Compose path reuses the containers/Docker module. Implement 2 and 3
  before 4.

## How long GitHub keeps offline runners (GR16)

- **Decision:** Rollback without a `remove_token` succeeds and warns; it does
  not fail.
- **Reason:** Verified in GitHub Docs ("Removing self-hosted runners"): a
  self-hosted runner that has not connected for more than 14 days is removed
  automatically; an ephemeral runner after 1 day. The leftover entry is
  harmless and self-cleaning. (github.com behaviour; GHES is out of scope per
the GHES decision.)
- **Follow-up:** github_runner rollback prints e.g. `OK: github_runner <name>:
  removed from this host, but still registered on GitHub (no remove_token). It
  shows as Offline and GitHub deletes it after 14 days; remove it sooner under
  Settings → Actions → Runners.` Replace the "not verified" note in
  `github-actions-runner.md`.

## Restic: start a backup when the snapshot is stale? (RS1)

- **Decision:** Option C. `apply` starts a backup only when the repository
  has no anvil snapshot of this host at all (first install / new repo).
  Otherwise a stale snapshot is reported, not retried. The priority is
  surfacing a *failing* backup.
- **Reason:** With a daily timer (`Persistent=true`) and a 36h threshold, a
  stale snapshot almost always means the scheduled backups are failing; a
  silent background retry hides that, does not converge (`check` right after
  still drifts) and is an unrequested load spike on production.
- **Follow-up:** restic probe reports the snapshot age together with the last
  run's result (`systemctl show -p Result,ExecMainStatus
  anvil-restic.service`); a failed last run reports `FAILED: restic: last
  backup run failed (<result>), see journalctl -u anvil-restic`. Apply runs
  `systemctl start --no-block` only in the no-snapshot case.

## What rollback removes (RS3, FJ5, GR15)

- **Decision:** One rule for every module: rollback removes what anvil
  **created on this host** — files, binaries, units, system users/groups —
  and only when recorded as created by anvil. It never removes data
  (repositories, databases, snapshots, hub data) or apt packages.
- **Reason:** Matches the existing beszel precedent (binary via the created
  list, user via marker) and the engine's created list. Packages are the
  risky part (shared dependencies, apt cascades, the operator may use them
  since); a leftover package with no config or unit is inert.
- **Follow-up:**
  - restic: package stays; document it. No code change.
  - forgejo: record `/usr/local/bin/forgejo` with `__anvil_remember`
    when anvil installs it; rollback removes it only if `__anvil_created`.
  - github_runner: record the `github-runner` user when anvil runs
    `useradd`; rollback removes it (and its group) only then, after the
    runners are gone.
  - Record created users in `/var/lib/anvil/created` (move beszel's own marker
    to it when touched next).
  - Docs: rollback section states "packages and data are never removed".

## Forgejo: git over the host sshd (FJ4)

- **Decision:** Option A: keep Forgejo's built-in SSH server on its own port
  (default 2222). No `ssh = "host"` passthrough for now.
- **Reason:** Passthrough would make the host sshd hardening depend on
  Forgejo (`git` in `AllowUsers`, a shell for `git`, an sshd drop-in), clash
  with `tailnet_only_ssh`, and route git clients' bad keys and CI fetches into
  host-SSH rate limiting, `MaxAuthTries` and fail2ban. The gain is cosmetic
  (no `:2222` in URLs); `~/.ssh/config` `Port 2222` hides it client-side.
- **Follow-up:** none now. Revisit if users ask for port-22 URLs; prefer
  Forgejo's built-in server on a second IP's port 22 over host passthrough.

## Forgejo: Actions off by default (FJ6)

- **Decision:** Option A: new `[forgejo] actions` field, default `false`,
  always written explicitly as `[actions] ENABLED = <actions>` in `app.ini`.
- **Reason:** anvil installs no runner yet, so with upstream's default
  every push with workflow files queues jobs that never run, every repo shows
  an Actions UI that does nothing, and repo owners can attach runners the
  operator doesn't know about. Writing the value explicitly makes anvil
  independent of the upstream default; flipping a default later would
  silently change running servers, so the default stays `false`.
- **Follow-up:** add the field (public TOML contract) + `init --full`
  template + test; when `forgejo_runner` lands, its validation requires
  `forgejo.actions = true`.

## github_runner: dependency install (GR13)

- **Decision:** Option A: run upstream `bin/installdependencies.sh` from the
  checksum-verified tarball (current design).
- **Reason:** Package names (ICU, OpenSSL, LTTng) change per distro release;
  upstream maintains the mapping with each runner release, so anvil has no
  per-release upkeep and always matches what that runner version needs. Same
  trust model as the verified runner binary itself; the script only calls apt.
- **Follow-up:** (1) extend the detect to all five libraries (krb5, zlib,
  ICU, OpenSSL, LTTng), not just krb5/zlib/ICU; (2) when bumping the pinned
  runner version, review the `installdependencies.sh` diff as part of the bump
  (note it in `github-actions-runner.md`).

## Docker on Ubuntu: distro packages or vendor repo? (CR14)

- **Decision:** Default stays Docker's vendor apt repo on every distro
  (option A), plus an **opt-in** to use distro packages (`docker.io` +
  `docker-compose-v2`) on Ubuntu.
- **Reason:** Debian needs the vendor repo anyway (bookworm has no Compose v2;
  Debian's Docker lacks the 127.0.0.1-publish fix), so one default path keeps
  the test matrix small. The opt-in serves operators who don't want a
  third-party repo on Ubuntu, where `-updates` carries 29.1.3 / 2.40.3.
- **Follow-up:** add `source = "vendor" | "distro"` (default `"vendor"`) read
  by `ensure_docker_engine()` and all its callers (containers, greptimedb,
  headscale, github_runner); settle the section in implementation (`[docker]`
  is the candidate, but it is read even when `[docker]` hardening is
  absent). On a non-Ubuntu host, `"distro"` reports `FAILED:` with a reason.
  Never switch an installed engine: if `docker-ce` is present with
  `"distro"` (or `docker.io` with `"vendor"`), keep it and warn — the
  packages conflict and apt would remove one. Update
  `container-runtime.md` §3 / open question 2. Test both paths in the
  acceptance run.
