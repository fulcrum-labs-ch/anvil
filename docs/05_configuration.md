# Configuration reference

One TOML file describes the target host(s) and the desired hardening state.
**A module is enabled by the presence of its `[section]`** — an absent section
is never touched. Unknown section or field names are rejected (they are
almost always typos, and a misspelled hardening key that parsed silently
would be a hardening step that never happens).

Every value below shows its default; an empty `[section]` applies all of
them. Fields marked **required** have no default.

```toml
[host]
address = "203.0.113.10"
user = "admin"

[sshd]            # enable with defaults…
[firewall]        # …sections are independent
```

## Hosts

A single `[host]` table, one or more `[[hosts]]` entries, or both (the
merged list is `[host]` first, then each `[[hosts]]` in order).

| Field | Default | Notes |
|---|---|---|
| `address` | **required** | Hostname or IP; your `~/.ssh/config` applies |
| `user` | **required** | `root`, or a user with `NOPASSWD` sudo |
| `port` | `22` | SSH port to connect to |
| `identity_file` | – | Passed as `ssh -i` |
| `ssh_options` | `[]` | Extra `-o` options appended to the ssh command |

## Secrets: `${ENV}` substitution

Any string value in the config may reference an environment variable:
`${VAR}` expands to its value, `${VAR:-default}` falls back to `default` when
`VAR` is unset *or* empty (shell `:-` semantics). An undefined `${VAR}` with no
default is a hard error at load — a missing secret fails loudly rather than
half-configuring a host with an empty value. Nothing runs; every missing
variable is listed with the key and line that use it:

```text
invalid config: environment variables not set (or empty):
  $TAILSCALE_AUTH_KEY for [tailscale] auth_key  (host.toml:27)
export each one before running anvil; `${NAME:-}` allows an empty value
```
 A default may not itself contain
`${…}` (`${A:-${B}}` is rejected at load), and there is no escape for a literal
`${NAME}` in config values. Use this for credentials
(`tailscale.auth_key`, `beszel.token`, `beszel.admin_password`, `headscale.auth_keys`, plugin `{{VAR}}` sources) so they
need not be committed to the config file:

```toml
[tailscale]
auth_key = "${TAILSCALE_AUTH_KEY}"
```

This keeps secrets out of the config file (and your git history). The expanded
value still reaches the target in the rendered script (over ssh stdin)
— the host needs it — but `--dry-run` shows built-in modules' secrets as
`<redacted>`. Prefer a shell alias or a secrets manager to export the variable
rather than putting it on the command line.

## Composition: `profile` and `include`

- `profile = "<name>"` applies a preset's values under yours — your keys win,
  and your arrays *replace* the profile's. Built-ins: `minimal`,
  `cis-level1`, `web-server`, `ci-runner` (hardened SSH, a default-deny
  inbound firewall with only SSH open, full updates, no auto-reboot).
  Custom profiles are discovered
  from `~/.config/anvil/profiles/<name>.toml` (must be owned by you, not
  group/world-writable; built-in names cannot be shadowed).
- `include = ["base.toml", …]` merges files left-to-right before the main
  file: tables deep-merge, arrays *concatenate*. Include cycles are errors. A
  file reached through several includes (A includes B and C, both include D)
  is merged once, where it first appears. Included files are held to the same
  trust rules as custom profiles — they must be regular files owned by you,
  not group/world-writable, and so must the directory that contains them (a
  symlinked or swappable include could inject module config). Absolute or `..` paths
  trigger a warning; prefer paths relative to the config file.

## Per-host module sets (fleet limitation)

Module sections are **global**: every `[[hosts]]` entry gets the same enabled
modules from one config. You cannot yet say "host A gets `[docker]`, host B
gets `[greptimedb]`" in a single file. For a heterogeneous fleet today, use one
config per role and target it with `--host`/`--exclude`:

```bash
anvil apply -c web.toml            # the web tier (docker, tls, …)
anvil apply -c db.toml --host db-2 # the db tier, one box at a time
```

`-c` belongs after the subcommand (`anvil apply -c …`), not before it.

A shared `_base.toml` (included by each role file) keeps the common modules and
host list in one place. A native per-host overlay (a per-host module allowlist)
is a tracked future enhancement.

## Ordering

Run order is resolved automatically from each module's default wave, with
hard safety edges that user configuration cannot override (see
[04_modules.md](04_modules.md#run-order)). To refine it:

- Per-section: `order_override` (`order = <i64>`, `before = [ids]`,
  `after = [ids]`) — every section accepts it.
- Globally: `[execution_order] modules = ["dns", "kernel", …]` pins relative
  order for the listed modules. Unknown ids are rejected at validation;
  entries for modules that aren't enabled are ignored.

Anything that contradicts a safety edge (firewall before `sshd`, `hetzner`
before `tailscale`, anything after `updates`) is a hard error, never silently reordered.

## Module sections

### `[sshd]`

| Field | Default |
|---|---|
| `disable_root_login` | `true` |
| `disable_password_auth` | `true` |
| `disable_empty_passwords` | `true` |
| `port` | `22` (this is the **effective SSH port** other modules key on) |
| `max_auth_tries` | `3` |
| `login_grace_time` | `30` |
| `client_alive_interval` | `300` |
| `client_alive_count_max` | `2` |
| `allow_users` | `[]` (empty = no `AllowUsers` line) |
| `strong_ciphers` | `true` |
| `disable_x11_forwarding` | `true` |

### `[firewall]` (ufw)

| Field | Default |
|---|---|
| `default_incoming` | `"deny"` (`deny`/`allow`/`reject`) |
| `default_outgoing` | `"allow"` |
| `restrict_ssh` | `true` (rate-limit SSH via `ufw limit`; `false` = plain allow) |
| `allow` / `deny` | `[]` — arrays of rules |

Rule (`[[firewall.allow]]` / `[[firewall.deny]]`): `port` (**required**,
string — `"443"` or a range), `proto`, `from`, `comment`. The effective SSH
port is always permitted *before* `ufw enable`; that rule is built in, never
listed.

### `[fail2ban]`

| Field | Default |
|---|---|
| `bantime` | `"10m"` |
| `findtime` | `"10m"` |
| `maxretry` | `5` |
| `jails` | sshd jail, watching the effective SSH port |

Per-jail override: `[fail2ban.jails.<name>]` with `enabled`, `port`,
`maxretry`, `bantime` (all optional; an unset jail `port` inherits the
effective SSH port for the sshd jail). With `[forgejo]` enabled, a
`forgejo` jail is added the same way (port: Caddy's `https_port` or 443, plus
`ssh_port`); `[fail2ban.jails.forgejo]` overrides or disables it.

With `[tailscale]` enabled, `ignoreip` exempts loopback and the tailnet ranges
(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`): after a tailnet-only cutover every
SSH client is a tailnet address, and a few failed logins must not ban the
operator.

### `[updates]` (unattended-upgrades — always runs last)

| Field | Default |
|---|---|
| `security_only` | `true` |
| `auto_reboot` | `false` |
| `reboot_time` | `"02:00"` (validated `HH:MM`) |
| `remove_unused_deps` | `false` |

### `[users]`

`create = [{ name = "deploy", sudo = true, shell = "/bin/bash", ssh_authorized_keys = ["ssh-ed25519 …"] }, …]`

`name` is **required** (letters/digits/`_`/`-`, must start with a letter or
`_`, max 32 chars). `sudo = true` writes a `NOPASSWD` sudoers drop-in.

### `[kernel]` (sysctl)

| Field | Default |
|---|---|
| `harden_network` | `true` |
| `restrict_dmesg` | `true` |
| `restrict_kernel_pointers` | `true` |
| `disable_ipv6` | `false` (opt-in — breaks dual-stack hosts) |
| `extra_sysctl` | `{}` (map of `key = "value"`) |

### `[kernel_modules]` (modprobe blacklist)

`blacklist_filesystems`, `blacklist_squashfs`, `blacklist_vfat`,
`blacklist_usb_storage`, `blacklist_network_protocols` — all `true`.

### `[ssh_crypto]`

No fields (beyond `order_override`). Writes a separate sshd drop-in with
strong KEX/ciphers/MACs/host-key algorithms, **filtered on the host** to what
its OpenSSH supports (post-quantum KEX kept where available).

### `[suid]`

| Field | Default |
|---|---|
| `scan_paths` | `["/"]` |
| `exclude_paths` | `[]` |
| `extra_whitelist` | `[]` (paths allowed to keep setuid/setgid beyond the stock allowlist) |

### `[dns]` (systemd-resolved)

| Field | Default |
|---|---|
| `dns_servers` | Quad9 + Cloudflare: `["9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1"]` |
| `fallback_servers` | `[]` |
| `dnssec_strict` | `false` (`DNSSEC=allow-downgrade` unless set) |
| `dns_over_tls` | `true` |

### `[process]`

| Field | Default |
|---|---|
| `disable_core_dumps` | `true` |
| `disable_sysrq` | `true` |
| `pass_max_days` / `pass_min_days` / `pass_warn_age` | `365` / `1` / `7` |
| `hidepid` | `false` (remounts `/proc` with `hidepid=2` + boot unit) |

### `[pam]`

Writes the policy files and activates them through `pam-auth-update`
(`libpam-pwquality`, plus anvil's `pam_faillock` profiles in
`/usr/share/pam-configs/`). **Never** hand-edits `/etc/pam.d/`.

| Field | Default |
|---|---|
| `minlen` | `14` |
| `require_uppercase` / `_lowercase` / `_digit` / `_special` | `true` |
| `enable_faillock` | `true` |
| `deny` | `5` |
| `unlock_time` | `900` |
| `umask` | `"027"` |
| `tmout` | `900` (shell auto-logout, seconds) |

### `[packages]`

`install = []`, `remove = []` — Debian package names, validated against the
apt charset before ever reaching a command line.

### `[crowdsec]`

| Field | Default |
|---|---|
| `collections` | `["crowdsecurity/linux", "crowdsecurity/sshd"]` |
| `bouncer_mode` | unset: the distro package picks the backend matching the system (nftables on nf_tables, iptables on iptables-legacy). Set `"iptables"`/`"nftables"` to force one |

Installed from the distro's own archive (`crowdsec`, `crowdsec-firewall-bouncer`),
never from CrowdSec's vendor repo. With `[tailscale]` enabled, a parser
whitelist exempts the tailnet ranges (same reason as fail2ban's `ignoreip`),
validated with `crowdsec -t` before the reload.

### `[auditd]`

`rule_set = "cis-level1"` — the only set shipped today. The admissible names
and the shipped rule bodies are locked to each other; the written rules
file's header always names the set actually installed.

### `[lynis]`

No fields. Installs Lynis; the `score` command runs the audit.

### `[filesystem]`

| Field | Default |
|---|---|
| `tmp_noexec` | `true` (`/tmp` `noexec,nosuid,nodev` via a `tmp.mount` drop-in) |
| `check_sticky_bits` | `true` |
| `check_world_writable` | `true` |
| `aide_baseline` | `false` (install AIDE + initialize baseline) |

### `[docker]`

| Field | Default |
|---|---|
| `iptables_off` | `true` |
| `userns_remap` | `true` |
| `rootless` | `false` |
| `live_restore` | `true` (containers keep running while dockerd restarts; not for Swarm) |
| `source` | `"vendor"` — Docker's keyring-pinned apt repo, on every distro. `"distro"`: Ubuntu's `docker.io` + `docker-compose-v2` (`FAILED:` on other distros) |
| `log_driver` | `"json-file"` (10m × 3 per container). `"journald"`: containers log to the journal (capped by journald's `SystemMaxUse`), [Vector](modules/monitoring.md) ships them, `docker logs` still works. Reaches containers created after the change |

`[docker]` installs the engine if it is missing (`rollback` keeps it, like
every engine install). `source` decides where it comes from, also for a
module that needs Docker (`[containers]` compose, `[greptimedb]`, Headplane,
a runner with `docker = "group"`); without `[docker]` it is `"vendor"`, and the `docker` module still
runs to cap container logs: it creates `daemon.json` with only the log keys,
or leaves an existing one as it is. Setting `source` means writing
`[docker]`, which also writes the `daemon.json` keys above — set them to
`false` to opt out. On a host whose Docker already has images or
containers, a defaulted `userns_remap` stops `check`/`apply` with `FAILED:`
(it would hide them); set it to `true` or `false` ([Docker or
Podman](modules/container-engines.md#docker-defaults)). An installed engine is never switched: `docker-ce` and
`docker.io` conflict, so with the other source's engine present apply keeps it
and prints `anvil: warning: docker: …`. Switch by hand (`apt purge` one, then
apply).

`iptables_off = true` keeps published ports behind ufw but leaves containers
without outbound internet. With `false`, Docker's published ports skip ufw, so
publish on `127.0.0.1` only: apply then refuses (and reverts) any compose
project that publishes a port on another address — including a bare `"80"`,
which Docker maps to a random public port. anvil warns about risky
combinations at load.

### `[podman]`

Makes the host a Podman host ([one engine per host](modules/container-engines.md)):
not with `[docker]` or `[containers] runtime = "docker"`. Writes
`/etc/containers/containers.conf.d/99-anvil.conf`; installs nothing itself
(Quadlets install Podman ≥ 4.4 from the distro). New settings reach
containers started after the change.

| Field | Default |
|---|---|
| `log_driver` | `"k8s-file"` — `podman logs` reads it, capped at 10 MiB per container. `"journald"`: capped by journald's own limits |
| `source` | `"distro"` (the only source) |

```toml
[podman]

[containers.quadlet.web]                   # runtime may be left unset
content = "[Container]\nImage=docker.io/library/nginx:alpine\nPublishPort=127.0.0.1:8080:80\n"
```

→ `run order: podman -> containers`.

### `[containers]`

One table per Docker Compose project; the name (`[a-z0-9][a-z0-9_-]*`) is the
directory, unit and compose project name.

| Field (`[containers.compose.<name>]`) | Default |
|---|---|
| `content` | **required** unless `file` is set — the compose file. anvil does **not** expand `${VAR}` here; docker compose does, on the host, from `.env` |
| `file` | unset — instead of `content`: a path to the compose file, relative to the TOML file that sets it, read at load. Held to the include trust checks: owned by you, not group/world-writable, no symlink. Set exactly one of `file`/`content` |
| `env` | `{}` — written to `.env` (0600). Values **are** expanded from your shell, e.g. `{ DB_PASSWORD = "${APP_DB_PASSWORD}" }`; written double-quoted and escaped, so docker compose reads them literally; no newlines |

| Field (`[containers]`) | Default |
|---|---|
| `runtime` | unset: `"podman"` with `[podman]`, else `"docker"`. `"podman"`: Quadlet units below instead of compose projects; not with `[docker]`, a v2 `[github_runner]`, a runner with `docker = "group"`, `forgejo.deploy = "compose"` or `headplane_docker_socket` (all need Docker; `[greptimedb]` and Headplane run as Quadlets; [matrix](modules/container-engines.md)); refused per host below Podman 4.4 (Debian 12, Ubuntu 22.04) |

| Field (`[containers.quadlet.<name>]`, `runtime = "podman"`) | Default |
|---|---|
| `content` | **required** — the Quadlet `.container` file, written verbatim to `/etc/containers/systemd/anvil-<name>.container`. `PublishPort=` must bind `127.0.0.1`/`::1`; no `-p`/`--publish` in `PodmanArgs=`. Add `[Install]` `WantedBy=multi-user.target` to start at boot |

```toml
[containers]
runtime = "podman"

[containers.quadlet.web]
content = '''
[Container]
Image=docker.io/library/nginx:alpine
PublishPort=127.0.0.1:18080:80

[Install]
WantedBy=multi-user.target
'''
```

### `[forgejo]`

Setup, security, operations and troubleshooting: [Forgejo guide](modules/forgejo.md).
Never lose `secret_key`: stored 2FA secrets become unreadable.

```toml
[forgejo]
domain = "git.example.com"
secret_key = "${FORGEJO_SECRET_KEY}"       # forgejo generate secret SECRET_KEY
internal_token = "${FORGEJO_INTERNAL_TOKEN}"
jwt_secret = "${FORGEJO_JWT_SECRET}"
```

| Field | Default |
|---|---|
| `domain` | **required** — public hostname; `ROOT_URL = https://<domain>/`. In `tls.domains` → nginx snippet written |
| `version` | `"15.0.11"` (LTS). Any release works: its `.asc` is verified against Forgejo's pinned signing key. Optional `sha256_amd64`/`sha256_arm64` add a checksum check (built in for 15.0.11) |
| `deploy` | `"native"` (binary + systemd), `"compose"` (rootless image under Docker Compose; needs `[docker]` or a v2 `[github_runner]`) or `"quadlet"` (the same image as a Podman Quadlet; needs a Podman host). Same `app.ini`, secrets and `/var/lib/forgejo`; switching restarts in the other mode |
| `image_digest` | compose only: `"sha256:<hex>"` of `<version>-rootless`; built in for 15.0.11, required for another `version` |
| `http_port` | `3000`, always on `127.0.0.1` |
| `ssh_port` | `2222` (Forgejo's built-in SSH server; `0` = off; ≥ 1024) |
| `listen` | `"public"` (open `ssh_port` in `[firewall]` yourself) or `"tailnet"` (anvil adds `ufw allow in on tailscale0`; needs `[tailscale]`) |
| `require_signin_view` | `false` (`true` hides everything from anonymous visitors) |
| `actions` | `false` — Forgejo Actions, always written as `[actions] ENABLED`; `true` is required by `[forgejo_runner]` in the same config |
| `database` | `"sqlite3"` or `"postgres"` (an existing server; anvil does not install it) |
| `db_host` / `db_name` / `db_user` / `db_ssl_mode` | `"127.0.0.1:5432"` / `"forgejo"` / `"forgejo"` / `"disable"` |
| `db_password` | required for postgres |
| `secret_key`, `internal_token` | **required**, from `${ENV}` |
| `jwt_secret` | **required**: base64url of 32 bytes (`forgejo generate secret JWT_SECRET`) |
| `admin_username`, `admin_email`, `admin_password` | – (all or none; created once with a forced password change at first login; password ≥ 8 characters, never reset) |

### `[tls]`

| Field | Default |
|---|---|
| `provider` | `"certbot"` (`certbot`/`acme.sh`) |
| `domains` | `[]` |
| `email` | – |
| `webroot` | – (webroot mode when set, standalone otherwise) |

### `[caddy]`

Caddy fronts services that listen on localhost and gets their certificates
itself. Use it *instead of* `[tls]` on a host: both bind 80/443, so enabling
both on the default ports is a validation error.

```toml
[caddy]
email = "ops@example.com"

[[caddy.site]]
domain = "git.example.com"
upstream = "127.0.0.1:3000"     # e.g. Forgejo
allow = ["100.64.0.0/10"]       # optional: only these client IPs (others get 403)
basic_auth = { user = "ops", password_hash = "${GIT_PASSWORD_HASH}" }   # optional
```

| Field | Default |
|---|---|
| `email` | – (ACME account contact) |
| `ca` | `"public"` (Let's Encrypt/ZeroSSL); `"staging"` (Let's Encrypt staging, for tests); `"internal"` (Caddy's local CA) |
| `http_port` / `https_port` | `80` / `443` (public ACME needs these) |
| `hsts` | `true` (two years, no preload) |
| `listen` | `"public"`; `"tailnet"`: only 443 tcp/udp, on `tailscale0` (needs `[tailscale]` and `[firewall]`; no `acme` sites). Switching removes the other mode's caddy ufw rules; ones also in `[firewall] allow` stay |
| `site[].domain` / `site[].upstream` | required: hostname, `host:port` |
| `site[].allow` | `[]` (everyone) — IPs/CIDRs |
| `site[].basic_auth` | – `{ user, password_hash }`; hash from `caddy hash-password`, best passed as `${ENV}` |
| `site[].tls` | `"acme"` (the `ca` above); `"tailscale"`: a `*.ts.net` name, certificate from tailscaled (enable MagicDNS and HTTPS Certificates in the tailnet); `"dns"`: ACME DNS-01, works with `listen = "tailnet"` |
| `site[].dns_provider` / `site[].dns_token` | `tls = "dns"` only: `"infomaniak"`; the API token, as `${INFOMANIAK_API_TOKEN}`; Infomaniak scopes `dns:read`, `dns:write` and `domain:read` (without `domain:read` the ACME challenge fails with HTTP 403) |

Installed from Caddy's official apt repo (distros ship 2.6.2 from 2022); the
signing key is built into anvil. The admin API listens only on the unix
socket `/var/lib/caddy/admin.sock` (root and the `caddy` user only), not on
TCP `localhost:2019`; `systemctl reload caddy` uses it. Password hashes are written on the host
to `/etc/caddy/anvil-auth/<domain>.caddy` (`0640 root:caddy`) and never shown
by `diff`. Rollback restores the previous Caddyfile and never deletes
certificates in `/var/lib/caddy`. With `listen = "public"`, open TCP 80, TCP 443 and UDP 443 in the
provider firewall (Hetzner, netcup) too. A `tailscale` site adds
`TS_PERMIT_CERT_UID=caddy` to tailscaled (drop-in
`/etc/systemd/system/tailscaled.service.d/99-anvil-caddy.conf`) and restarts it
when that file changes — a brief tailnet blip. A `dns` site makes the host
build a pinned, SHA-256-checked Caddy with the provider module
(`/usr/local/bin/caddy-anvil`; ~1.5 GB RAM, a few minutes, once); the token
goes to `/etc/caddy/anvil-dns.env` (`0600`), the Caddyfile only says
`{env.INFOMANIAK_API_TOKEN}`. See `docs/design/caddy.md`.

### `[hetzner]` — runs **locally**, drives `hcloud`

| Field | Default |
|---|---|
| `server_name` | **required** (must not be empty) |
| `firewall_name` | `"anvil"` |
| `rules` | `[]` |
| `keep_public_ssh` | `true` — see below |

Rule (`[[hetzner.rules]]`): `direction` + `protocol` (**required**), `port`,
`source_ips`, `description`. The effective SSH port is kept open from
anywhere, and TCP 22 stays open during a port cutover.

`keep_public_ssh = false` drops those SSH-from-anywhere rules, so only your
own `rules` reach the cloud firewall (public SSH closed at the edge). Use it
only once SSH over the tailnet is proven on this node. It is refused unless
`[tailscale] tailnet_only_ssh = true`, and at apply time `hetzner` is skipped
unless every address `[host] address` resolves to is a tailnet address
(`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) — that is, anvil itself is
connected over the tailnet. It also runs after `tailscale` (hard edge), is
skipped when `tailscale` fails in the same run, and `--only hetzner` needs
`tailscale` in `--only` too. Recovery from a mistake is the Hetzner console.

### `[netcup]` — runs **locally**, drives the SCP REST API

| Field | Default |
|---|---|
| `server` | **required** — SCP server id (digits), or its name or nickname |
| `policy` | `"anvil"` — the one user firewall policy anvil owns |
| `rules` | `[]` |
| `keep_public_ssh` | `true` — same meaning and validation as `[hetzner]` |

Rules have the `[hetzner]` shape: `direction` (`in`/`out`) + `protocol`
(`tcp`, `udp`, `icmp`, `icmpv6`) **required**, `port` (`N` or `N-M`, tcp/udp
only), `source_ips` (sources for `in`, destinations for `out`; empty =
any), `description`. Every rule is an SCP `ACCEPT` rule.

SSH guard: as for `[hetzner]`, the effective SSH port (and 22 / live ports
during a port move) is always allowed — but here an inbound tcp rule of
yours on that exact port counts as the guard **even when `source_ips`
restricts it**. So a box that only admits your own IP stays that way:

```toml
[[netcup.rules]]
direction = "in"
protocol = "tcp"
port = "22"
source_ips = ["198.51.100.7/32"]   # SSH only from here; no world-open rule added
```

Without such a rule, SSH is opened from anywhere. If the listed source
changes (dynamic IP), recovery is the SCP console.

Credentials: export `NETCUP_SCP_REFRESH_TOKEN` (an offline refresh token from
the SCP device flow, `client_id=scp`, scope `offline_access openid`). The
token has the account's full SCP rights, so anvil only ever calls the OIDC
token and userinfo endpoints, `GET /api/v1/servers`, `GET
/api/v1/servers/{id}`, `GET`/`PUT` on the interface firewall, and
`GET`/`POST`/`PUT` on the user's firewall policies — enforced in code. The
token is never in argv or output (0600 temp files, removed on exit). netcup
refresh tokens are reusable and stay valid while used at least every 30
days; if the token endpoint hands out a different one, apply prints a
warning (visible with `--verbose`) and keeps using the exported token.

What apply does: create or update the policy named `policy` (drift = its
rules differ), then attach it to the server's single non-VLAN interface,
keeping every policy already attached and the firewall's `active` flag as
they are. It does **not** switch the SCP firewall on or set the implicit
ingress rule; do that once in the SCP console (`ingressImplicitRule:
DROP_ALL`). Firewall changes are applied by SCP asynchronously (HTTP 202).
Before its first attach, anvil saves the attached user-policy ids to
`$XDG_STATE_HOME/anvil/netcup/<server-id>-<mac>.json` (default
`~/.local/state`); `rollback` puts that set back and leaves anvil's policy
in place, detached.

`keep_public_ssh = false` works exactly as for `[hetzner]` (tailnet gate,
hard edge after `tailscale`, skipped when `tailscale` fails, `--only netcup`
needs `tailscale`). Recovery from a mistake is the SCP console.

### `[headscale]`

| Field | Default |
|---|---|
| `version` | `"0.23.0"`. The `.deb` is SHA-256-verified before install; another version needs `sha256_amd64` and `sha256_arm64` (from the release's `checksums.txt`) |
| `server_url` | `""` (validated URL) |
| `listen_addr` | `"0.0.0.0:8080"` — plain HTTP; use `"127.0.0.1:8080"` behind a reverse proxy (warned otherwise) |
| `db_path` | `"/var/lib/headscale/db.sqlite"` |
| `base_domain` | `"headscale.internal"` — MagicDNS suffix (`<node>.<base_domain>`); must not contain the `server_url` host |
| `acl_policy` / `acl_policy_path` | – (inline HuJSON, or a file to install) |
| `auth_keys` | `[]` — `{ name, reusable = false, expiration = "24h", tags = [], ephemeral = false }`; see below |
| `headplane` | `false` (web UI) |
| `headplane_version` | – |
| `headplane_listen` | `"127.0.0.1:3000"` (ports published by Docker or Podman skip ufw; keep it on loopback behind a reverse proxy or the tailnet) |
| `headplane_docker_socket` | `false` — mounting the socket gives Headplane root on the host; Docker hosts only |

Pre-auth keys (`[[headscale.auth_keys]]`): `name` is also the headscale
user; `expiration` is a duration of at least `1m`, largest unit first (`"24h"`,
`"7d"`, `"1h30m"`); `tags` (`["tag:server"]`, lowercase) are given to nodes
that join with the key; `ephemeral = true` removes those nodes once they go
offline. anvil keeps the key in `/var/lib/headscale/preauth-<name>.key` and
creates a new one on the next apply after it expires or its flags change
(the old key is not revoked; it simply expires). Hand it to the other nodes
yourself, e.g.
`TAILSCALE_AUTH_KEY=$(ssh admin@headscale-host sudo cat /var/lib/headscale/preauth-servers.key)`,
then `anvil apply` there with `[tailscale] auth_key = "${TAILSCALE_AUTH_KEY}"`.

anvil configures no TLS in headscale itself, and Tailscale clients need
`https://` on `server_url` (`validate` warns about `http://`). Front it with
`[caddy]`, keep headscale on loopback, and open only 80/tcp and 443/tcp
(`[caddy]` does that in ufw; add them in the provider firewall too). 8080 and
the loopback-only gRPC (50443) and metrics (9090) ports stay closed:

```toml
[headscale]
server_url = "https://headscale.example.com"
listen_addr = "127.0.0.1:8080"
base_domain = "tailnet.example.com"

[caddy]
[[caddy.site]]
domain = "headscale.example.com"
upstream = "127.0.0.1:8080"
```

### `[tailscale]`

| Field | Default |
|---|---|
| `login_server` | `""` (e.g. your headscale URL) |
| `auth_key` | `""` — not needed once the node is logged in; without it, a logged-out node fails `apply` after 30 s instead of waiting for a browser login |
| `hostname` | – |
| `accept_routes` | `false` |
| `tailnet_only_ssh` | `false` — see below |

`tailnet_only_ssh = true` replaces the world-open SSH firewall rule with one
scoped to the `tailscale0` interface — but only once SSH is **proven to work
over the tailnet**: an established SSH connection must arrive on the node's own
tailnet address. That is anvil's own session when `[host] address` is the
node's tailnet name or IP. A node that merely has a tailnet IP is not enough
(you may not be on the tailnet yet, or an ACL may deny you). Until then the
world rule stays (lockout guard). So the cutover is: join with
`tailnet_only_ssh = false`, verify `ssh` over the tailnet works, switch
`[host] address` to the tailnet name/IP, then set `tailnet_only_ssh = true`
and apply. `anvil rollback` (or `--only tailscale`) undoes it: public SSH is
re-opened before the tailnet-only rule is removed. It requires `[firewall]`
(the cutover edits ufw rules); without it, `validate` fails.

### `[greptimedb]`

| Field | Default |
|---|---|
| `http_port` / `grpc_port` / `mysql_port` / `postgres_port` | `4000`–`4003` |
| `data_dir` | `"/var/lib/greptimedb"` — absolute, no whitespace or `:` (it is embedded in the compose volume entry) |
| `listen_address` | `"127.0.0.1"` (loopback-bound by default) |
| `version` | `"v1.3.0"` — must be a pinned `vMAJOR.MINOR.PATCH`; `"latest"` and other floating tags are rejected at validation. v1.x cannot open data written before v0.16: apply refuses (`FAILED:`) to replace an older running container; pin its version, or remove it and set a new `data_dir` |
| `retention` | unset (TTLs untouched) — `"30d"` (`h`/`d`/`w`): every apply sets it as the TTL of every database, so older rows expire; needs `version` ≥ `"v0.12.0"`. Rollback leaves the TTL |
| `memory_max` | unset — container memory limit, e.g. `"2G"` (`K`/`M`/`G`/`T`): compose `mem_limit`, Quadlet `MemoryMax=` |

### `[ci_resources]`

One systemd slice, `ci.slice`, for every CI runner and its jobs. It sits next
to `system.slice`/`user.slice` under `-.slice`, so `cpu_weight` counts there.
With it set, the `[github_runner]` and `[forgejo_runner]` units run in the slice;
their own caps stay, per runner, inside it.

| Field | Default |
|---|---|
| `cpu_quota` | unset — `CPUQuota=` for all CI work together: `"800%"` = 8 cores |
| `memory_max` | unset — `MemoryMax=`: `"20G"` (K/M/G/T suffix) or `"60%"` of RAM |
| `tasks_max` | unset (systemd's default) — `TasksMax=`, processes and threads in all of CI |
| `cpu_weight` | `50` — `CPUWeight=` (1–10000); below the default 100, so system services such as sshd win under contention. Docker-rootless CI sandboxes run outside the slice (under their slot users), so the caps above don't bound them; their slot users' slices get this weight instead |

`docker = "group"` job containers run under dockerd's cgroup and are **not**
capped by the slice; anvil warns when both are set. `docker = "rootless"`
and `"podman"` containers run inside the runner's unit, so the slice caps them.

### `[apps_resources]`

One systemd slice, `apps.slice`, for the host's own applications: Caddy,
Vector, Forgejo and GreptimeDB. It sits next to `system.slice`/`user.slice`
under `-.slice`, so `cpu_weight` counts there. With it set, Caddy gets a
`Slice=apps.slice` drop-in, Vector's unit carries the line, Forgejo and
GreptimeDB (native unit, compose or Quadlet) join the slice, and every
`[containers.compose.*]` compose unit itself runs in it.

| Field | Default |
|---|---|
| `cpu_quota` | unset — `CPUQuota=` for all apps together: `"400%"` = 4 cores |
| `memory_max` | unset — `MemoryMax=`: `"6G"` (K/M/G/T suffix) or `"60%"` of RAM |
| `tasks_max` | unset (systemd's default) — `TasksMax=`, processes and threads in all apps |
| `cpu_weight` | `100` — systemd's default `CPUWeight=` (1–10000); lower makes the other slices win under contention |
| `system_memory_low` | unset — `MemoryLow=` for `system.slice` (`"2G"` or `"20%"`): memory that stays protected from reclaim under pressure, so the kernel takes user, CI and app work first. Written to `/etc/systemd/system/system.slice.d/99-anvil-memory-low.conf` (a high prefix: `.d` directories are last-wins) |

The moved units restart once: a `Slice=` change needs a restart, not a reload.
Forgejo's and GreptimeDB's generated compose files give every service
`cgroup_parent: apps.slice`, because Docker otherwise starts containers in
`system.slice/docker-*.scope` whatever the compose unit's slice is. That
value needs Docker's **systemd cgroup driver**, where it names a systemd
slice; with the cgroupfs driver it is a raw cgroup path. A user-declared
`[containers.compose.<name>]` project gets `Slice=apps.slice` on its unit,
but its containers stay in Docker's own scope — add
`cgroup_parent: apps.slice` to each service that should be capped too.
Rollback removes `apps.slice` and the `MemoryLow` drop-in; each app module's
rollback removes its own line or drop-in. Unsetting `system_memory_low`
removes its drop-in on the next apply. Removing the whole `[apps_resources]`
section is not a cleanup — the module is not built, so `apps.slice` and the
`MemoryLow` drop-in stay; to undo, run
`anvil rollback --only apps_resources` before removing the section.

### `[github_runner]`

How to set it up and operate it: [GitHub Actions runner guide](modules/github-runner.md).

| Field | Default |
|---|---|
| `auto_update` | `true` — `false` registers with `--disableupdate`; re-apply within 30 days of each runner release |
| `docker` | `"none"`; `"rootless"` runs container jobs on the host's engine, rootless as the runner user, inside its unit (rootless dockerd needs `[docker] source = "vendor"`); `"group"` adds the runner user to `docker` (jobs become root-equivalent; Docker host); `"podman"` is `"rootless"` on a Podman host |
| `clean_workspace` | `true` — wipe `_work` (except `_actions`/`_tool`) after every job |
| `proxy` | `""` — `http(s)://` proxy for runner traffic; required when `[firewall] default_outgoing` is not `"allow"` |
| `version` / `sha256` | anvil's pinned runner (`2.338.2`); override only together, `sha256` for this host's architecture |
| `cpu_quota` | unset — systemd `CPUQuota=` per runner, jobs included: `"400%"` = 4 cores |
| `memory_max` | unset — systemd `MemoryMax=`: `"8G"` (K/M/G/T suffix) or `"50%"` of RAM; a job past it is OOM-killed, not the host |
| `tasks_max` | unset (systemd's default) — `TasksMax=`, processes and threads per runner |
| `disk_max` | unset — `"150G"` (G/T suffix): each runner's `_work` on its own capped loop volume; never resized ([details](modules/github-runner.md#limits)) |
| `diag_retention_days` | `14` — a daily timer deletes older `_diag` logs; with `disk_max` it also trims the `_tool`/`_actions` caches |
| `home_cache_max` | `"20G"` — the same timer wipes a runner's `~/.cache`, `~/.cargo`, `~/.rustup`, `~/.npm` once together past this, only while no job runs |

`mode = "ephemeral"` ([guide](modules/github-runner.md#v2-ephemeral-runners-mode--ephemeral))
rejects the fields above except `auto_update`, `clean_workspace` and
`diag_retention_days` (ignored there; sandboxes leave no caches) and uses these instead (all rejected
in the default `mode = "persistent"`):

| Field | Default |
|---|---|
| `app_id` / `installation_id` | required — the GitHub App and its org installation |
| `app_key` | required — the App's PEM private key, use `"${GITHUB_APP_KEY}"` |
| `runner_group_id` | required — org runner group the runners join |
| `capacity` | `1` — sandboxes waiting or running at once, per runner (1–32) |
| `sandbox_cpus` / `sandbox_memory` / `sandbox_pids` | `"2"` / `"4g"` / `2048` — per sandbox |
| `sandbox_disk` | `"40G"` — per slot, for the sandbox's Docker data and `_work`; never resized |
| `sandbox_packages` | `[]` — apt packages baked into the sandbox image, e.g. `["build-essential"]` |
| `sandbox_runtime` | `"docker-rootless"` (default on a Docker host): each slot's sandbox runs privileged in its own slot user's rootless dockerd ([details](modules/github-runner.md#docker-rootless)); `"sysbox-runc"`; `"podman"` (default on a Podman host) |

Ephemeral runners need an org `url` and `labels`; `token`, `remove_token`
and `group` are rejected.

Each `[github_runner.runners.<name>]` (name: `[a-z0-9][a-z0-9_-]*`, used as
directory, unit and GitHub runner name — don't rename once applied):

| Field | Default |
|---|---|
| `url` | required — `https://github.com/<org>` or `https://github.com/<org>/<repo>` |
| `token` | `""` — one-hour registration token, use `"${GITHUB_RUNNER_TOKEN:-}"`; only needed to (re-)register |
| `remove_token` | `""` — one-hour remove token; lets `rollback` deregister on GitHub |
| `labels` | `[]` — added to `self-hosted`, `Linux`, `X64`/`ARM64`; `[A-Za-z0-9._-]+` |
| `group` | `""` — runner group, org runners only |

### `[forgejo_runner]`

| Field | Default |
|---|---|
| `url` | `""` = `https://<forgejo.domain>/` of `[forgejo]` in the same config; otherwise required, `https://` |
| `mode` | `"persistent"` — one daemon on the host; `"ephemeral"` runs each job in a fresh sysbox sandbox with a runner registered for that job ([guide](modules/forgejo-runner.md#a-sandbox-per-job-mode--ephemeral)) |
| `api_token` | ephemeral only, required — Forgejo API token that registers the per-job runners, use `"${FORGEJO_API_TOKEN:-}"`; apply fails while empty |
| `owner` | ephemeral only — `"<org>"` or `"<owner>/<repo>"` the runners serve; omitted = instance-wide (site-admin token) |
| `sandbox_cpus` / `sandbox_memory` / `sandbox_pids` / `sandbox_disk` | ephemeral only — per sandbox: `"2"`, `"4g"`, `2048`, `"40G"` (as `[github_runner]`) |
| `sandbox_runtime` | ephemeral only — `"docker-rootless"` (default): each slot's sandbox runs privileged in its own slot user's rootless dockerd ([details](modules/forgejo-runner.md#sandbox_runtime--docker-rootless)); or `"sysbox-runc"` |
| `uuid` | persistent: required — the runner UUID Forgejo shows on *Create new runner* |
| `token` | `""` — the runner token shown with it, use `"${FORGEJO_RUNNER_TOKEN:-}"`; apply fails while empty |
| `labels` | required — `<name>:host` or `<name>:docker://<image>` (the latter needs `docker = "rootless"`, `"podman"` or `"group"`) |
| `capacity` | `1` — jobs run at the same time |
| `docker` | `"none"`; `"rootless"` runs container jobs on the host's engine, rootless as the runner user, inside its unit (rootless dockerd needs `[docker] source = "vendor"`); `"group"` adds the runner user to `docker` (jobs become root-equivalent; Docker host); `"podman"` is `"rootless"` on a Podman host |
| `version` / `sha256` | anvil's pinned forgejo-runner (`13.2.1`); override only together, `sha256` for this host's architecture |
| `cpu_quota` / `memory_max` / `tasks_max` | unset — systemd caps for the runner and its jobs, as for `[github_runner]` |
| `home_cache_max` | `"20G"` — daily `anvil-forgejo-runner-prune.timer` wipes `~/.cache` (act's clones, cache server), `~/.cargo`, `~/.rustup`, `~/.npm` past this, only while no job runs |

### `[coding_agents]`

| Field | Default |
|---|---|
| `user` | `"agent"` — a `[users].create` account with `sudo = false`, in `sshd.allow_users` when that is set; never a runner, `beszel`, `git` or `root` |
| `claude_code` | `"stable"` — the native installer's channel; `"latest"` or `"none"` |
| `opencode` | `"latest"`; a version for the v2 installer's `--version` (used at install), or `"none"` |
| `skills` | `[]` — `{ source = "owner/repo" or https URL, names = [...], agents = ["claude-code", "opencode"] }` |
| `claude_marketplaces`, `claude_plugins`, `opencode_plugins`, `opencode_mcp` | empty — plugins as `<name>@<marketplace>`; `opencode_mcp = { name = ["cmd", "arg"] }` |
| `setup` | unset — `{ url = "https://…", rev = "<40 hex>", run = "<relative path>" }`, run as the user after the lists |
| `cpu_quota` / `memory_max` / `tasks_max` | unset — caps on the user's `user-<uid>.slice` |
| `docker` | `"none"`; `"rootless"` runs the host's engine as the user (rootless dockerd, or rootless Podman on a Podman host) with `DOCKER_HOST` set; needs `[docker] source = "vendor"` on a Docker host |

Needs `firewall.default_outgoing = "allow"`. See the
[coding agents guide](modules/coding-agents.md).

### `[vector]`

| Field | Default |
|---|---|
| `greptimedb_host` | `"127.0.0.1"` |
| `greptimedb_grpc_port` / `greptimedb_http_port` | `4001` / `4000` |
| `db_name` | `"public"` |
| `extra_log_files` | `[]` |
| `scrape_interval_secs` | `15` |
| `cgroups_include` | `["system.slice/docker-*.scope", "ci.slice/**", "apps.slice/**", "user.slice/user-*.slice", "system.slice/*.service"]` — cgroups whose CPU/memory Vector collects (globs relative to `/sys/fs/cgroup`; parents are added): containers, CI (`ci.slice`), apps (`apps.slice`), users, system services. `[]`: every cgroup |

What lands where, dashboards and queries: [Monitoring](modules/monitoring.md).

### `[beszel]` (monitoring: agent and/or hub)

Beszel has two parts: the **hub** (web dashboard + database, one per fleet)
and the **agent** (one per monitored server, reports to the hub). This
section can run either or both on a host.

| Field | Default |
|---|---|
| `agent` | `true` — run the agent here |
| `hub` | `false` — run the hub here |
| `version` | `"0.21.1"` — a pinned `MAJOR.MINOR.PATCH` release (hub and agent); its SHA-256s are built in |
| `sha256` | `{}` — tarball SHA-256s for any other `version`, keyed by file name from the release's `beszel_<version>_checksums.txt`: `beszel-agent_linux_amd64.tar.gz` and `…_arm64` for the agent, `beszel_linux_amd64.tar.gz` and `…_arm64` for the hub. **Required** for every service enabled when `version` is overridden |
| `hub_listen` | `"127.0.0.1:8090"` — hub web UI/API address (`IP:port`) |
| `hub_allow_from` | `[]` — IPs/CIDRs allowed to reach a non-loopback `hub_listen`; tailnet addresses only (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) unless `hub_listen` is itself a tailnet address |
| `key` | agent only, hub elsewhere: **required** — the hub's SSH public key (`ssh-ed25519 AAAA…`) from its "Add system" dialog |
| `hub_url` / `token` | agent only, hub elsewhere: set both to have the agent connect out to the hub; nothing then listens |
| `listen_port` | `45876` — the agent's port (bound to `127.0.0.1` when the hub is on the same host) |
| `hub_addresses` | `[]` — agent only, hub elsewhere: IPs/CIDRs allowed to reach `listen_port` |
| `docker` | `false` — agent only: container stats. Adds the agent to the `docker` group, which is **root-equivalent** (the Docker socket can start a privileged container). Apply fails unless Docker and its `docker` group exist; enable `[docker]` or install it first |
| `smart` | `false` — agent only: SMART disk data. Installs `smartmontools` (Debian also enables its `smartd` root daemon) and gives the agent the `disk` group (raw access to every block device: treat it as root-equivalent too) plus `CAP_SYS_RAWIO` for SATA/SAS pass-through. NVMe drives need `CAP_SYS_ADMIN`, which anvil does not grant, so they report no SMART data. Rollback leaves the package installed |
| `admin_email` / `admin_password` | unset — hub only: the first admin, created when the hub first starts on an empty database. **Required** when `hub_listen` is not loopback. Pass the password as `"${BESZEL_ADMIN_PASSWORD}"`; at least 8 characters, no quotes, backslashes, `$`, backticks or control characters |

The hub serves plain HTTP. Off loopback it may only be reached over the
tailnet (WireGuard-encrypted): `validate` rejects a `hub_allow_from` outside
the tailnet ranges. To serve it over the internet or a LAN, keep
`hub_listen = "127.0.0.1:8090"` and front it with `[caddy]` (a
`[[caddy.site]]` with `upstream = "127.0.0.1:8090"`) or `[tls]`.

On a fresh hub, whoever opens the UI first creates the admin. With
`admin_email`/`admin_password` anvil writes them to `/etc/default/beszel-hub`
(root-only, `0600`, never shown by `diff`) and the hub creates that admin on
its first start, which closes the sign-up page. They have no effect on a hub
that already has a database: change the password in the UI then.

No Beszel port is ever left open to the world; `validate` rejects config
that would (no `[firewall]`, `default_incoming = "allow"`, or no scope). A
`[[firewall.allow]]` rule of your own for these ports without `from` would
still open them to everyone.

**One server, monitoring itself** (hub and agent on the same machine):

```toml
[beszel]
hub = true
```

Everything stays on `127.0.0.1`; no firewall rule is added. anvil creates
the hub's key and gives the agent its public half. After `apply`:

1. Open the UI through an SSH tunnel:
   `ssh -L 8090:127.0.0.1:8090 admin@your-server`, then
   <http://localhost:8090>.
2. Create the admin account. Whoever opens a fresh hub first becomes its
   admin, so do this before exposing the hub anywhere.
3. **Add system**: host `127.0.0.1`, port `45876`. The key shown in the
   dialog is the one the agent already trusts.

**Hub reachable from other servers**, e.g. over the tailnet. `[firewall]` is
required; ufw opens the hub port only from `hub_allow_from`, or on
`tailscale0` when that is empty and `[tailscale]` is enabled:

```toml
[firewall]
[tailscale]
[beszel]
hub = true
hub_listen = "0.0.0.0:8090"
admin_email = "ops@example.com"
admin_password = "${BESZEL_ADMIN_PASSWORD}"
```

**Agent reporting to a hub on another machine**, either connecting out
(simplest, nothing listens) …

```toml
[beszel]
key = "ssh-ed25519 AAAA…"
hub_url = "http://100.64.0.1:8090"
token = "${BESZEL_TOKEN}"
```

… or reached by the hub on `listen_port`, which ufw opens only from
`hub_addresses` (or on `tailscale0` when that is empty and `[tailscale]` is
enabled):

```toml
[firewall]
[tailscale]
[beszel]
key = "ssh-ed25519 AAAA…"
```

`hub = true, agent = false` runs a hub that only monitors other machines.

A Hetzner/netcup provider firewall needs no inbound rule for Beszel when
everything is on one machine, the agent connects out, or traffic stays on
the tailnet. Only ports opened to `hub_addresses`/`hub_allow_from` over the
public internet must also be allowed there.

Rollback stops and disables the services, deletes their ufw rules, and
removes the binaries and users anvil created. It keeps the hub's database
(`/var/lib/beszel-hub`).

### `[restic]`

```toml
[restic]
repository = "sftp:backup@nas.example.com:/srv/restic/web-1"
password   = "${RESTIC_PASSWORD}"   # from your shell, never written in the file
```

| Field | Default |
|---|---|
| `repository` | required — local path, `sftp:`, `s3:`, `b2:`, `rest:` … URL |
| `password` | required — use `"${RESTIC_PASSWORD}"`; lose it and the backups are unreadable |
| `env` | `{}` — backend credentials, e.g. `{ AWS_ACCESS_KEY_ID = "${AWS_ACCESS_KEY_ID}", AWS_SECRET_ACCESS_KEY = "${AWS_SECRET_ACCESS_KEY}" }` |
| `paths` | `/etc /home /root /srv /opt /usr/local /var/lib /var/spool /var/backups` |
| `exclude` | `[]` — extra restic patterns, added to the defaults |
| `default_excludes` | `true` — `/var/lib/docker`, `/var/lib/containerd`, apt lists, snap packages, `/var/lib/lxcfs`, `~/.cache`; dirs with `CACHEDIR.TAG` are always skipped |
| `docker_volumes` | `false` — `true` backs up `/var/lib/docker/volumes` (the rest of `/var/lib/docker` stays excluded) |
| `schedule` | `"daily"` — systemd `OnCalendar=` (e.g. `"*-*-* 03:00"`); runs up to 1h late at random |
| `keep_daily` / `keep_weekly` / `keep_monthly` / `keep_yearly` | `7` / `4` / `6` / `0` (0 = not used; at least one > 0) |
| `max_age_hours` | `36` — `check` reports drift when the newest snapshot is older (reported, never retried); raise it for a weekly `schedule` |
| `pre_backup` | `[]` — absolute paths of programs run before each backup (e.g. a database dump). They must already exist on the host (apply checks the unit); a failing hook skips that run |

The values end up in `/etc/restic/env` (root-only, 0600). `diff` never
prints that file and `--dry-run` shows the values as `<redacted>`.

