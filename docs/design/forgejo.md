# Design: the `forgejo` module

Status: proposal, 2026-10-31. **Verified** means checked against Forgejo's
docs, release API or a package index (sources in §8). **Assumed** means
inferred and not yet run on a host.

## TL;DR

- **Two deploy modes, same config and data.** `deploy = "native"` (default):
  the upstream binary under a sandboxed systemd unit, no Docker needed.
  `deploy = "compose"`: the rootless image pinned by digest under Docker
  Compose, for an install that is identical on every host. §1.
- **Pinned and signature-verified:** default `15.0.11`, the current LTS
  (supported until 2027-07-15). Every download's `.asc` must be signed by
  Forgejo's release key (fingerprint pinned); SHA-256 for amd64 and arm64 of
  the default version is checked as well. Another `version` needs no new
  checksums (`sha256_amd64`/`sha256_arm64` stay optional extras).
- **HTTP on `127.0.0.1:3000` only.** Put a TLS proxy in front: `[tls]`
  (nginx, wired automatically through a new include hook) or the `[caddy]`
  module being built in parallel (a site with upstream `127.0.0.1:3000`).
- **Git over SSH: Forgejo's built-in SSH server on its own port (default
  2222).** The host's sshd, its `AllowUsers`, `tailnet_only_ssh` and the
  fail2ban sshd jail are not involved.
- **Secrets only from `${ENV}`**, written to 0640 `root:git` files that
  `app.ini` points to with `*_URI` keys. `app.ini` itself holds no secret, so
  `diff` shows it.
- **Rollback stops and removes the service and config. It never deletes
  `/var/lib/forgejo`** (repositories, database, LFS, avatars).

## 1. Binary or container?

| | Upstream binary + systemd | Compose (`codeberg.org/forgejo/forgejo:<v>-rootless`) |
|---|---|---|
| Install | One static Go binary, `.asc` per asset (verified) | Needs Docker from Docker's apt repo |
| Firewall | Host sockets, so ufw applies | Published ports skip ufw (container study §1.3); anvil uses the host network instead, so ufw applies |
| `[docker]` defaults | n/a | `userns_remap = true` (the default) would break the bind-mounted data dir; anvil sets `userns_mode: host` |
| Git over SSH | Built-in server or host sshd, both direct | Built-in server behind a public Docker publish, or a host shim that `docker exec`s into the container |
| Sandboxing | systemd (`ProtectSystem=strict`, `NoNewPrivileges`, …) | Container isolation, but the Docker socket is root |
| Upgrades | Change `version` (+ hashes); restart | Change the tag; `up -d` |

**Choice: both**: containers are consistent and repeatable;
native needs no Docker. Compose avoids both objections in the table:

- **Host network, no published port.** The container binds exactly what
  `app.ini` says (HTTP on the host's 127.0.0.1, SSH on `ssh_port`), so ufw,
  fail2ban and CrowdSec apply as in native mode and `listen = "tailnet"` is
  one ufw rule (`allow in on tailscale0`) for both modes. The cost is no
  network namespace; the container is still read-only, `cap_drop: [ALL]`,
  `no-new-privileges`, non-root, with memory/pids limits and a CPU weight.
- **`userns_mode: host`, `user: <git uid>:<gid>`** (from a computed
  `/etc/forgejo/compose.env`), so the bind-mounted `/var/lib/forgejo` keeps
  its `git` ownership despite `[docker] userns_remap`.
- **Same files:** `app.ini`, the secret files (`/etc/forgejo` mounted
  read-only) and `/var/lib/forgejo` at the same paths. The image's entrypoint
  (which writes its own `app.ini`) is bypassed: `/app/gitea/gitea web`.
- **One unit name.** `forgejo.service` is a oneshot running `docker compose
  up -d --wait` / `down`; Docker restarts a crashed container
  (`restart: unless-stopped`), systemd owns start, stop and boot. Switching
  `deploy` is a unit change, so the next apply restarts in the other mode
  (native first takes the compose project down); data is not migrated or
  touched. The native binary stays installed.
- **Pinned:** `codeberg.org/forgejo/forgejo:<version>-rootless@sha256:…`;
  the 15.0.11 index digest is built in, another `version` requires
  `image_digest`. The digest is in `compose.yaml`, so an image change is a
  `diff` and a restart.
- **Docker comes from `[docker]` or a v2 `[github_runner]`** (validated);
  the module installs the same engine if it runs first. Podman: not supported yet.
- **Runner coexistence:** neither runner prunes Docker globally; they only
  remove their own containers and `anvil-github-runner` images. A job with
  `docker = "group"` is root-equivalent and could; data is a bind mount, so
  at worst the image is re-pulled.

Native details: there is no Debian or Ubuntu `forgejo` package (verified: not in Debian's
archive, no Launchpad source), so the upstream release is the only source.
The release key's fingerprint `EB114F5E6C0DC2BCDD183550A4B61A2DC5923710`
(from `forgejo.org/download/`) is pinned in anvil. At install the key is
fetched from `keys.openpgp.org/vks/v1/by-fingerprint/<fpr>` (its signing
subkeys rotate about yearly, so a snapshot would go stale), imported into a
throwaway `gpg --homedir`, and the `.asc` must yield a `VALIDSIG` whose
primary-key fingerprint is the pinned one. Anything else — download, import
or verify failure, another key — prints `FAILED:` and installs nothing.
Built-in checksums (default version only) are pinned in anvil and never
fetched from the same server. Without a checksum, the probe identifies the
installed binary by its `forgejo --version` (`<version>+gitea-…`).

## 2. HTTP and TLS

- `[server] HTTP_ADDR = 127.0.0.1`, `HTTP_PORT = http_port` (default 3000).
  Not configurable to a public address.
- `[tls]` today writes one hardened nginx server for its domains, with no
  `location`. This change adds one line to its 443 block:
  `include /etc/nginx/anvil-tls.d/*.conf;` (the directory is created by the
  same step). Debian's stock `include sites-enabled/*;` shows an empty glob
  is fine.
- `forgejo` owns `/etc/nginx/anvil-tls.d/forgejo.conf`: `location /` with
  `proxy_pass http://127.0.0.1:<http_port>` and the headers from Forgejo's
  reverse-proxy guide (verified), plus `client_max_body_size 512M`.
- The snippet is written only when `[tls]` is enabled and `forgejo.domain`
  is one of `tls.domains`. That vhost serves all of them, so Forgejo is the
  site.
- Otherwise anvil writes no proxy config. Front Forgejo with `[caddy]`
  (`[[caddy.site]]` with this domain and upstream `127.0.0.1:<http_port>`) or
  your own proxy. Either way `ROOT_URL` is `https://<domain>/`, so `domain`
  must be the public name the proxy serves.
- `ROOT_URL = https://<domain>/`. Forgejo trusts `X-Forwarded-For` from
  `127.0.0.0/8` by default (`REVERSE_PROXY_TRUSTED_PROXIES`, verified), so it
  logs the real client IP.
- Existing `[tls]` hosts see one-time drift (the include line) on the next
  apply.

## 3. Git over SSH

**Choice: Forgejo's built-in SSH server** (`START_SSH_SERVER = true`,
`SSH_LISTEN_PORT = SSH_PORT = ssh_port`, default 2222; `ssh_port = 0`
disables SSH).

Why not passthrough via the host's sshd:

- `[sshd] allow_users` would have to include `git`, so anvil's sshd hardening
  depends on Forgejo.
- `[tailscale] tailnet_only_ssh` closes the host SSH port to the internet,
  so git would be tailnet-only too.
- `[firewall] restrict_ssh` (`ufw limit`, on by default) rate-limits the SSH
  port. CI that fetches often would be throttled.
- Every bad key a git client offers counts toward the fail2ban sshd jail and
  `MaxAuthTries`, so a developer can get their IP banned from host SSH.
- `git` would need a login shell and a Forgejo-managed `authorized_keys`.

Built-in server consequences:

- Open the port yourself: `[[firewall.allow]] port = "2222"`. anvil warns if
  `[firewall]` is on and the port is missing. Add it to a `[hetzner]` cloud
  firewall too.
- `git` runs as a system user with `/usr/sbin/nologin` and no password, so
  the host's sshd never accepts it.
- fail2ban/CrowdSec: the built-in server accepts public keys only (verified:
  `modules/ssh/ssh.go` sets only `PublicKeyHandler`), so no SSH jail. Web
  logins: with `[fail2ban]`, a `forgejo` jail reads `[log]`'s file
  `/var/lib/forgejo/log/forgejo.log` (same path in both deploy modes) for
  `Failed authentication attempt for <user> from <ip>:<port>`
  (`routers/web/auth/auth.go`, v15.0.11). `REVERSE_PROXY_TRUSTED_PROXIES`
  makes that the client IP from the proxy's `X-Forwarded-For` (port `0`).
  The username is unescaped, so a crafted name can forge a line.

## 4. Configuration

```toml
[forgejo]
domain = "git.example.com"            # the public name; ROOT_URL = https://<domain>/
# version = "15.0.11"                 # any release; the signature is checked
# http_port = 3000                    # on 127.0.0.1 only
# ssh_port = 2222                     # 0 = no git over SSH
# require_signin_view = false
# actions = false                    # [actions] ENABLED, always written
# database = "sqlite3"                # or "postgres"
secret_key = "${FORGEJO_SECRET_KEY}"
internal_token = "${FORGEJO_INTERNAL_TOKEN}"
jwt_secret = "${FORGEJO_JWT_SECRET}"   # forgejo generate secret JWT_SECRET
admin_username = "forgeadmin"
admin_email = "admin@example.com"
admin_password = "${FORGEJO_ADMIN_PASSWORD}"
```

Postgres: `database = "postgres"` plus `db_host` (default `127.0.0.1:5432`),
`db_name`/`db_user` (default `forgejo`), `db_password`, `db_ssl_mode`
(default `disable`). anvil does **not** install or create the database; point
it at one that exists (open question 2).

Fixed security defaults in `app.ini` (verified key names):

| Key | Value |
|---|---|
| `[security] INSTALL_LOCK` | `true` (web installer off) |
| `[security] SECRET_KEY_URI`, `INTERNAL_TOKEN_URI` | `file:/etc/forgejo/secret_key`, `…/internal_token` |
| `[oauth2] JWT_SECRET_URI` | `file:/etc/forgejo/jwt_secret` |
| `[server] LFS_START_SERVER` | `false` (LFS would need one more secret) |
| `[database] PASSWD_URI` | `file:/etc/forgejo/db_password` (postgres only) |
| `[service] DISABLE_REGISTRATION` | `true` |
| `[service] REQUIRE_SIGNIN_VIEW` | `require_signin_view` |
| `[actions] ENABLED` | `actions` (default `false`: no runner module yet; upstream defaults to on) |
| `[server] OFFLINE_MODE` | `true` (no CDN / Gravatar calls) |
| `[security] DISABLE_GIT_HOOKS` | `true` (upstream default, pinned: git hooks are code execution on the host) |
| `[session] COOKIE_SECURE` | `true` |

All three `*_URI` keys are needed. Verified in the v15.0.11 source
(`modules/setting/security.go`, `oauth2.go`): with `INSTALL_LOCK = true`, an
empty `INTERNAL_TOKEN` or an invalid `JWT_SECRET` is generated and **saved
into `app.ini`**, and a failed save is fatal. `app.ini` is read-only to
Forgejo here, so every secret must come from a file. Forgejo trims
whitespace from secret files and refuses empty ones. `jwt_secret` must be
base64url (no padding) for exactly 32 bytes; anvil checks this at load.

Validation rejects: a `domain` that is not a hostname; `version` not
`X.Y.Z`; non-hex or wrong-length
checksums; `admin_username` outside `[A-Za-z0-9._-]`; `db_*` values with
whitespace, control characters or quotes (they land in `app.ini`); empty
secrets; and a partial admin (all three fields, or none).

## 5. What the module owns

| Path | Mode / owner | Kind |
|---|---|---|
| `/usr/local/bin/forgejo` | 0755 root | command: signature- (and for the default version checksum-) verified download |
| user/group `git` | system, nologin, home `/var/lib/forgejo` | command |
| `/var/lib/forgejo` | 0750 git:git | command (data; never removed) |
| `/etc/forgejo` | 0750 root:git | command |
| `/etc/forgejo/app.ini` | 0640 root:git | static file (diffable) |
| `/etc/forgejo/secret_key`, `internal_token`, `jwt_secret`, `db_password` | 0640 root:git | computed (never shown by `diff`) |
| `/etc/systemd/system/forgejo.service` | 0644 | static file; based on upstream `contrib/systemd` + sandboxing |
| `/etc/nginx/anvil-tls.d/forgejo.conf` | 0644 | static file, only with `[tls]` covering `domain` |
| `/etc/forgejo/compose.yaml` | 0644 | static file, compose only |
| `/etc/forgejo/compose.env` | 0644 | computed (`git` uid/gid), compose only |
| ufw `allow in on tailscale0 … ssh_port` | | command, `listen = "tailnet"` only |

- **Restart only on change:** Forgejo restarts when its binary, `app.ini`, a
  secret or the unit changed this run; nginx reloads only when its snippet
  changed (`nginx -t` first).
- **Admin user:** after start, the reload waits for `GET /api/healthz` on
  loopback (registered outside the sign-in middleware, so it works with
  `require_signin_view`; verified in `routers/web/web.go`), then runs
  `forgejo admin user create --admin --must-change-password` as `git` if
  `admin user list` does not list the name (any role, so a name clash never
  fails the apply). It never resets the password: `admin_password` (at least
  8 characters) is a bootstrap value. The flag is explicit because Forgejo
  exempts the *first* admin from the forced change by default (verified in
  `cmd/admin_user_create.go`). The password is on that one
  command line for a moment (visible in `ps`); there is no file option
  (verified against the CLI help).
- **Probe stays read-only:** the admin check only runs the CLI when the
  service is already active, as `git`, never as root.
- **Order:** wave 58, after `tls` (56) and `firewall` (50). nginx comes from
  `[packages]` or your own setup; without nginx the snippet is written but
  not loaded.

## 6. Rollback

The engine restores or removes the files above. Then:

- compose: `docker compose -p forgejo down` (the image stays; re-apply
  starts from it);
- unit gone → `systemctl stop` + `disable`; `CHANGED: forgejo stopped`;
- unit restored (it existed before anvil) → restarted with the old config;
- nginx revalidated and reloaded without the snippet;
- `/usr/local/bin/forgejo` removed if anvil installed it (recorded in
  `/var/lib/anvil/created`) and no pre-anvil unit was restored; a binary that
  was there before anvil stays.

**Never removed:** `/var/lib/forgejo`, the `git` user (it owns the data),
apt packages (`git`). Re-apply
brings the service back on the same data. The secret files are deleted, but
their values live in your environment/secret store. **Keep
`FORGEJO_SECRET_KEY`**: losing it makes stored 2FA secrets unreadable.

## 7. Backups (for the restic module)

- `/var/lib/forgejo`: repositories, `data/forgejo.db` (+ `-wal`/`-shm`), LFS,
  attachments, avatars, `data/jwt/private.pem`. Copy the SQLite DB while the
  service is stopped, or use `forgejo dump` (as `git`) for a consistent
  archive.
- Postgres: `pg_dump` of `db_name`.
- `/etc/forgejo` is rebuilt by anvil; the secrets must be in your secret store.
- Actions runners are out of scope here (separate design); a runner
  registration lives in the runner's own files.

## 8. Open questions

1. ~~Verify the `.asc` signatures?~~ Done: pinned key fingerprint, see §1.
2. Should anvil also install and provision a local PostgreSQL (role + DB)?
3. ~~Ship a fail2ban jail for Forgejo web logins?~~ Done (§3); check the
   log line on a real host.
4. Passthrough via host sshd as an opt-in (`ssh = "host"`), for one-port
   setups?
5. Forgejo Actions runner: out of scope; see the runner design.

### Verified sources

- Releases and LTS: `codeberg.org/api/v1/repos/forgejo/forgejo/releases`,
  `forgejo.org/releases/` (15.0.11 LTS until 2027-07-15; 17.0.1 stable).
- Checksums: `forgejo-15.0.11-linux-{amd64,arm64}.sha256` from the release.
- Signing key: fingerprint from `forgejo.org/download/` ("Verify GPG
  signature"); the 15.0.11 amd64 `.asc` verifies with it (subkey
  `C4186DF66F4B6750`).
- Keys and defaults: `forgejo.org/docs/latest/admin/config-cheat-sheet/`;
  secret loading in `modules/setting/{security,oauth2,lfs}.go` and the SSH
  server in `modules/ssh/ssh.go` at tag v15.0.11; `/api/healthz`.
- CLI: `forgejo.org/docs/latest/admin/command-line/` (`admin user create`,
  `admin user list`), `cmd/admin_user_create.go` (first-admin exemption).
- Binary layout and unit: `…/admin/installation/binary/`,
  `contrib/systemd/forgejo.service`.
- nginx recipe: `…/admin/setup/reverse-proxy/`.
- No distro package: `qa.debian.org/madison.php?package=forgejo` (empty),
  Launchpad `+source/forgejo` (404).

### Assumed (check with the live test)

- Forgejo starts with a read-only `app.ini` when every secret has a `*_URI`
  (the save paths are verified; no other write path was looked for).
- `/api/healthz` answers only once migrations are done (the endpoint and its
  pass/fail codes are verified; the timing is not).
- `nologin` is enough for the `git` user with the built-in SSH server.
- Compose: Forgejo accepts `RUN_USER = git` when the container uid has no
  passwd entry (it falls back to `$USER`, set to `git`), and starts with the
  read-only root plus the two tmpfs mounts.
- Compose: the admin `create` runs through `docker exec`, so its password
  stays in `docker inspect` of that exec until the container is recreated
  (readable only by Docker-socket holders, who can read the secrets anyway).
