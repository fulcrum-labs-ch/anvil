# Design: container runtime (Docker, Podman, or both)

Status: proposal, 2026-10-31. It audits how anvil handles containers today,
compares Docker and Podman on the five target releases, and recommends one
runtime. **Verified** means checked against an upstream doc or package index
(links in §7). **Assumed** means inferred and not checked on a real host.

## TL;DR

- **Recommendation: Docker only, for now.** Don't add Podman yet, and don't
  support both.
- **Why:** Podman's systemd story (Quadlets) needs Podman ≥ 4.4. Debian 12
  ships 4.3.1 and Ubuntu 22.04 ships 3.4.4, so two of the five target releases
  would get a weaker Podman path. Lynis has container tests for Docker only.
  Two anvil modules (greptimedb, headscale's Headplane) are built on Docker
  today.
- **Install source:** keep Docker's own apt repo (keyring-pinned), as an
  explicit exception to the distro-package rule. Debian's `docker.io` is 20.10
  (bookworm) or 26.1 (trixie), and Debian 12 has no Compose v2 package. Neither
  has Docker 28's fix that blocks LAN neighbours from reaching ports published
  on 127.0.0.1.
- **Fix first:** the `[docker]` defaults break the Docker modules anvil itself
  ships (§1.3). That matters more than the runtime choice.
- **Compose:** a new `[containers]` section, with `[containers.compose.<name>]`
  projects. Each project is a managed file plus a systemd unit. It is
  runtime-neutral by name, and it ships in this change (§5).
- **Revisit Podman** once Debian 12 and Ubuntu 22.04 leave the support matrix.
  Then every target has Podman ≥ 4.9 with Quadlets.

## 1. How containers are handled today

### 1.1 Where Docker comes from

| Piece | What it does | Where |
|---|---|---|
| `ensure_docker_engine()` | `command -v docker` or install `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin` from `download.docker.com`, with a pinned key and `signed-by=` | `src/modules/mod.rs:136-167` |
| `[docker]` | **Never installs Docker.** It merges `iptables=false` and `userns-remap="default"` into `/etc/docker/daemon.json` with `jq` (and does not overwrite your own keys). It restarts dockerd only when the merge changed something, behind a `jq empty` guard. `rootless = true` adds `uidmap` and `dbus-user-session` | `src/modules/docker.rs` |
| `[greptimedb]` | Hand-written systemd unit that runs `docker run`. All ports are bound to `listen_address` (127.0.0.1 by default). Data dir is created `0750 root:root` | `src/modules/greptimedb.rs:41-95` |
| `[headscale] headplane` | Hand-written unit running the Headplane container. Publishes `headplane_listen` (default `0.0.0.0:3000`) and **mounts `/var/run/docker.sock`** | `src/modules/headscale.rs:38`, `:228-260` |

So Docker is installed only as a side effect of greptimedb or headscale.
`[docker]` alone hardens a daemon that may not exist.

### 1.2 Other modules that know about containers

- `suid` whitelists `newuidmap`/`newgidmap` (needed by rootless Docker and
  Podman) and skips `/var/lib/docker` when scanning (`suid.rs:50-52`, `:97`).
- `filesystem` skips `/var/lib/docker` and `/var/lib/lxc` in its scans
  (`filesystem.rs:37`). Podman's storage (`/var/lib/containers`,
  `~/.local/share/containers`) is **not** skipped. That is a gap if Podman is
  ever added.
- `order.rs` puts `docker` at wave 55 (after firewall at 50). headscale runs at
  60 and greptimedb at 62. No hard edge ties them to `docker`.
- `firewall` (ufw) has **no Docker awareness at all**.

### 1.3 Problems the audit found

1. **Docker bypasses ufw.** This is verified, and it is the real interaction
   with `firewall.rs`. Docker sends published ports through the `nat` table
   before they reach the INPUT chain that ufw filters. So
   `ufw default deny incoming` does not cover a container started with
   `-p 0.0.0.0:3000:3000`. **Headplane's default `0.0.0.0:3000` is therefore
   reachable from the internet even with `[firewall]` on**, unless
   `[docker] iptables_off = true` is also set.
2. **`iptables_off = true` (the `[docker]` default) has a cost.** Verified:
   with it set, Docker no longer adds NAT rules, so containers lose outbound
   internet. Docker's docs also warn that the ports then become reachable from
   the local network. Assumed: published ports still work through
   `docker-proxy`, which listens on the host, so ufw's INPUT rules do apply.
   That is the effect `iptables_off` is meant to have. Net: "ufw protects
   published ports, but containers can't reach the internet."
3. **`userns_remap = true` (the default) breaks anvil's own containers.**
   This is assumed from how userns-remap works and has not been run on a
   host. Root inside the container maps to an unprivileged subordinate uid. So:
   - greptimedb cannot write its `0750 root:root` data dir;
   - Headplane cannot open `docker.sock` (`root:docker 0660`).

   Enabling `[docker]` next to `[greptimedb]` or `headplane` with default
   settings probably gives a broken service.
4. **The Docker socket is root.** Verified: Docker's docs say the `docker`
   group "grants root-level privileges". Headplane mounting the socket makes a
   web UI root-equivalent. `docs/design/tailscale-headscale.md` already flags
   this.
5. **A daemon.json change restarts every container.** `live-restore` is not
   set, so containers stop and start again when dockerd restarts.

## 2. Docker vs Podman

| Axis | Docker | Podman | Edge |
|---|---|---|---|
| Daemon / socket | Rootful `dockerd`. The socket is root-equivalent (verified). Rootless mode exists but is per-user setup | No daemon. Rootless-first. The API socket is optional | Podman |
| ufw / firewall | Rootful publishing skips ufw (verified). `iptables=false` breaks outbound. Docker 29 adds an nftables backend, still **experimental** (verified) | Rootless pasta/slirp4netns bind host sockets (verified), so ufw should apply (assumed). Rootful netavark DNATs like Docker (verified); nftables is the default on trixie/26.04 (verified) | Podman (rootless) |
| Distro packages | `docker.io`: bookworm 20.10.24, trixie 26.1.5, jammy/noble/resolute 29.1.3 in `-updates` (verified). Vendor repo on all five | `podman`: 4.3.1 / 5.4.2 / 3.4.4 / 4.9.3 / 5.7.0 (verified), all distro, no vendor repo needed | Podman on 3 of 5, Docker on Ubuntu |
| Compose | Compose v2 plugin, the reference implementation. Distro: `docker-compose-v2` on Ubuntu (2.40.3); trixie `docker-compose` 2.26.1 (Go); **bookworm only v1 1.29.2** (verified) | `podman compose` (≥ 4.7) is only a wrapper around `docker-compose` or `podman-compose` (verified). `podman-compose` is Python, 1.0.x–1.5.0, and not packaged for jammy | Docker |
| systemd | Units that call `docker compose`/`docker run` (what anvil does now) | Quadlets: `.container/.volume/.network/.kube` ≥ 4.4, `.pod` ≥ 5.0, `.build` ≥ 5.2 (verified). **Not on bookworm or jammy.** Quadlets do not read compose files (verified by absence) | Podman on new releases |
| CIS / Lynis | CIS Docker Benchmark v1.9.0 (verified to exist; contents not checked). Lynis CONT-8102…8108 are Docker-only (verified) | No Lynis tests (verified). Whether the CIS benchmark covers Podman: not checked | Docker |
| Operator familiarity | Default in most guides, CI and vendor docs | Smaller, mostly the RHEL world | Docker |
| Fit with this codebase | greptimedb and Headplane already use it | Headplane's integration expects a Docker API socket (`podman.socket` emulates it, as root again) | Docker |

### What "both" would cost

- **Every container module twice.** greptimedb and Headplane need a runtime
  switch for the CLI path and `--security-opt` differences. Unit dependencies
  differ too: `Requires=docker.service` for Docker, Quadlet units for Podman.
- **Compose twice.** Compose v2 for Docker, `podman-compose` quirks or a
  compose→Quadlet translation for Podman. The translation is a project of its
  own.
- **Install and hardening twice.** `daemon.json` merging for Docker;
  `containers.conf`, `registries.conf`, `storage.conf` and subuid ranges for
  Podman.
- **Rollback twice.** Different teardown commands and storage paths.
- **Tests:** another `bash -n` gate config plus a second smoke matrix, which
  doubles `scripts/smoke.sh` time on five releases.
- **Estimate:** about 2× the container code (today ≈ 1,300 lines across
  docker/greptimedb/headscale), about 3–4 weeks of work, and a permanent
  maintenance tax. Not worth it while two targets lack Quadlets.

### Recommendation

**Docker, from Docker's repo, as the only runtime for now.** Reasons, in order:

1. It works the same on all five releases.
2. Compose v2 is available everywhere.
3. anvil's existing modules already run on it.
4. Lynis can audit it.

The security gap (root socket, ufw bypass) is real. Close it with hardening,
not a second runtime:

- loopback-only publishes, enforced by validation;
- a fixed `[docker]` default story (§4);
- `live-restore`;
- no socket mounts by default.

**Revisit Podman** when bookworm and jammy are dropped. Then make it the
*default* runtime rather than a second one. At that point compose projects
should become Quadlets, and the config shape below already allows that.

## 3. Install source: why the vendor repo stays

The project prefers distro packages; CrowdSec moved to them. Docker is an
exception with concrete reasons:

- **bookworm has no Compose v2 package** (`docker-compose` is the v1 Python
  tool), so compose projects cannot work from distro packages there.
- **The 127.0.0.1-publish fix is missing from Debian's packages.** Docker 28.0
  blocks LAN neighbours from reaching ports published on 127.0.0.1. Debian's
  20.10 and 26.1 do not have it, and greptimedb relies on loopback binds.
- **Ubuntu's `-updates` pocket carries 29.1.3**, which is fine. So Ubuntu
  hosts may opt in with `[docker] source = "distro"` (`docker.io` +
  `docker-compose-v2`). The default stays the vendor repo
  everywhere; `"distro"` off Ubuntu reports `FAILED:`, and an installed engine
  is never switched (kept, with a warning).

`ensure_docker_engine()` keeps the key pinned and never pipes a script to a
shell. Keep that.

## 4. Proposed config and migration

```toml
[docker]                     # unchanged: daemon.json hardening (Docker only)
iptables_off = true
userns_remap = true
rootless = false

[containers]
# runtime = "docker"         # reserved; "podman" only after a decision
[containers.compose.app]     # shipped in this change
content = '''
services: ...
'''
env = { DB_PASSWORD = "${APP_DB_PASSWORD}" }
```

- **Migration:** none needed. `[docker]` keeps its meaning and fields. A future
  `runtime = "podman"` together with `[docker]` would be a validation error.
- **`[docker]` defaults:** the defaults break containers (§1.3). Options:
  - (a) make `[docker]` presence install Docker and add `live-restore: true`;
  - (b) reject `userns_remap = true` next to `[greptimedb]`/`headplane`, or
    pass `--userns=host` in their units;
  - (c) warn when `iptables_off = true` is combined with a compose project or
    module that needs outbound internet.

  Changing a default is breaking, so each needs a CHANGELOG `Breaking` entry
  (open question 1).
- **greptimedb / Headplane on the new base:** turn their hand-written units
  into internal compose projects built with the same helpers
  (`containers::unit_content` and friends). Then restart-on-change, validation
  and rollback come from one place. For Headplane, drop the socket mount
  unless an explicit `headplane_docker = true` is set, and default
  `headplane_listen` to `127.0.0.1:3000`.
- **Rollback semantics** (implemented for compose): rollback restores or
  removes the files.
  - A **restored** project is re-applied with `up -d`.
  - A **removed** project is stopped and taken down by project name
    (`docker compose -p <name> down`; its file is already gone), its enable
    symlink and empty directory are removed, and any `.env` you added by hand
    is left in place.
  - Volumes are **never** deleted (no `down -v`), so rollback cannot lose
    data.

## 5. What ships in this change (runtime-independent)

`[containers.compose.<name>]` with `content` (required) and `env` (optional).
Per project:

| Path | Mode | Notes |
|---|---|---|
| `/etc/anvil/compose/<name>/` | 0750 | created by a command; removed on rollback if empty |
| `…/compose.yaml` | 0640 root | static, diffable; anvil never expands `${VAR}` in it |
| `…/.env` | 0600 root | from `env`; values expanded from the operator's shell; a *computed* file, so `diff` never prints it |
| `/etc/systemd/system/anvil-compose-<name>.service` | 0644 | oneshot, `up -d` / `reload` = `up -d` / `down` |

- **Drift:** file content, mode and owner, plus `systemctl is-active` for the
  unit.
- **Restart only on change:** a project is reloaded only when *its* files
  changed this run, or its unit is inactive. Reloading runs
  `systemctl reload-or-restart`, which runs `up -d`, so only changed services
  are recreated.
- **Guard:** before anything is reloaded, every project's file must pass
  `docker compose config -q`, and each `.env` must not be world-readable. If
  either check fails, the change is reverted.

`file = "compose/app.yaml"` replaces `content` with a compose file read
at load, relative to the TOML file that names it, under the include trust
checks (owner, not group/world-writable, no symlink). It becomes `content`
before deserialization, so everything above applies unchanged.

## 6. Tasks

| # | Task | Size | Status |
|---|---|---|---|
| 1 | `[docker]` defaults (§4): (b) `--userns=host` on greptimedb/Headplane, (c) load-time warnings | S | done |
| 2 | Headplane: no socket mount by default, loopback listen by default | S | done (Breaking) |
| 3 | Add `live-restore: true` to the `[docker]` merge | S | done (`live_restore`) |
| 4 | Move greptimedb to an internal compose project via `containers` helpers | M | done: keeps `container_name: greptimedb`; migration in the guarded reload; not yet run live |
| 5 | Move Headplane the same way | M | deferred, as 4 |
| 6 | ufw ↔ Docker: validate "publish on 127.0.0.1 only" in compose content, or manage `DOCKER-USER` rules | M / L | docs + warnings only; validation needs a YAML parser |
| 7 | Add `[containers.compose]` to `scripts/smoke.sh` | S | done (not yet run) |
| 8 | Podman runtime (Quadlets, `filesystem`/`suid` storage paths) | L | done (rootful; rootless deferred) — §8 |

## 7. Open questions

1. Which `[docker]` default fix (§4 a/b/c) do you want, and can it be a
   breaking change in the next release?
2. ~~Should `ensure_docker_engine()` use distro `docker.io` +
   `docker-compose-v2` on Ubuntu?~~ Decided: vendor stays the default;
   `[docker] source = "distro"` opts in on Ubuntu (§3).
3. Is dropping Debian 12 and Ubuntu 22.04 on a timeline? That date is when
   Podman becomes worth it.
4. Should anvil reject `0.0.0.0` publishes in compose content? Parsing YAML
   in Rust means adding a dependency.

### Verified sources

- Package versions: `qa.debian.org/madison.php`, Ubuntu archive madison,
  `sources.debian.org` (`debian/control` and `debian/rules` for docker-compose
  and netavark).
- Docker and ufw, and `iptables=false`:
  docs.docker.com/engine/network/packet-filtering-firewalls/.
- nftables backend (experimental): docs.docker.com/engine/network/firewall-nftables/,
  release notes 29.0.0.
- Loopback-publish fix: release notes 28.0.0 (moby#49325).
- Docker group = root: docs.docker.com/engine/install/linux-postinstall/.
- Podman features by version: podman releases 4.4.0 / 4.7.0 / 4.8.0 / 5.0.0 /
  5.2.0, `podman-compose(1)`, `podman-systemd.unit(5)`.
- Lynis container tests: CISOfy/lynis `include/tests_containers`.

### Verified live (2026-10-31, Debian 13 host, Docker 29.9.2, Compose v5.6.1)

- With `iptables=false` + userns-remap, a `127.0.0.1` publish still answers
  (docker-proxy).
- Apply, re-apply (no-op), check and diff are clean, and `.env` is never
  printed. A change recreates only the changed service. Broken YAML is
  reverted by the guard.
- live-restore keeps containers up across a dockerd restart, but only once the
  compose unit uses `Wants=docker.service`. With `Requires=`, systemd
  restarted the unit, which ran `down` and then `up`.
- Rollback removes containers, network, unit, enable symlink and directories,
  but only when it runs in reverse order. Undoing `[docker]` first hid the
  userns-remapped containers from the daemon and orphaned them.
- Found and fixed along the way:
  - `[docker]` failed on a host without Docker yet;
  - rollback left a `daemon.json` that anvil had created;
  - repeated restarts tripped systemd's `start-limit-hit`;
  - Compose's default `127.0.0.1:8080` collides with crowdsec's API.

### Assumed (not verified on a host)

- Publishing through `docker-proxy` with `iptables=false` goes through ufw's
  INPUT chain. A loopback publish works (verified live); public reachability
  through ufw was not tested.
- Rootless pasta ports are filtered by ufw.
- userns-remap breaks greptimedb and Headplane (§1.3); `--userns=host` was
  added but not run live.
- The Headplane unit (`docker run`, `Requires=docker.service`) still
  restarts with dockerd; live-restore only helps once it moves to compose
  (task 5). greptimedb moved (task 4).

## 8. Podman runtime

The decision started Podman without waiting for Debian 12 / Ubuntu 22.04 to
leave the matrix: `runtime = "podman"` is refused **per host**, Docker stays
the default.

**Minimum: Podman 4.4.** The decision said 4.9 (the lowest version on the supported
releases that have it), this study said 4.4. 4.4 is the lowest that works for
what anvil uses: Quadlet itself, `.container` files in
`/etc/containers/systemd`, `PublishPort=`, `[Install]` and `quadlet -dryrun`
all ship in 4.4.0 (release notes: "Introduce Quadlet"; `cmd/quadlet/main.go`
at `v4.4.0` has `-dryrun` printing `---<unit>.service---` per converted unit).
Quadlet only exits non-zero on bad files from 4.6.0, so the guard checks the
dry-run output for the unit instead of the exit code. No release ships 4.4–4.8,
so the choice changes only the message:

| Release | `podman` (verified 2026-11-02) | Runtime |
|---|---|---|
| Debian 12 bookworm | 4.3.1+ds1-8+deb12u1 | refused |
| Debian 13 trixie | 5.4.2+ds1-2 | ok |
| Ubuntu 22.04 jammy | 3.4.4+ds1-1ubuntu1.22.04.3 | refused |
| Ubuntu 24.04 noble | 4.9.3+ds1-1ubuntu0.2 | ok |
| Ubuntu 26.04 resolute | 5.7.0+ds2-3build1 | ok |

Sources: `qa.debian.org/madison.php?package=podman`, Ubuntu archive madison
(`people.canonical.com/~ubuntu-archive/madison.cgi?package=podman`), podman
`RELEASE_NOTES.md` (4.4.0, 4.6.0), `packages.debian.org` / `packages.ubuntu.com`
file lists (`/usr/libexec/podman/quadlet`, the `podman-system-generator`).

**Shape.** `[containers.quadlet.<name>] content` is a `.container` file,
written verbatim to `/etc/containers/systemd/anvil-<name>.container`; the
generator makes `anvil-<name>.service`. Compose projects are not translated
(Quadlets do not read compose files), so `runtime = "podman"` with
`[containers.compose.*]` or with `[docker]` is a validation error.
greptimedb and Headplane stay on Docker.

**Safety, as on the Docker path.** Rootful netavark DNATs past ufw like
Docker, so every `PublishPort=` must bind `127.0.0.1`/`::1` and `PodmanArgs=`
may not publish — checked at load, since the INI needs no YAML parser. A unit
`quadlet -dryrun` cannot convert is reverted. Rollback stops anvil's units
while their files exist, removes the files and reloads systemd; images,
volumes, `/var/lib/containers` and the `podman` package stay.

**Deferred:** rootless Quadlets (`/etc/containers/systemd/users/`, Podman
≥ 4.6, plus a user, subuids and linger), `.volume`/`.network`/`.pod` units,
compose → Quadlet translation.
