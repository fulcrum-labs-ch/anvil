# Design: `[caddy]` — reverse proxy with automatic HTTPS

Status: **proposed 2026-10-31**, implemented alongside this note.

## TL;DR

- `[caddy]` installs Caddy and fronts **localhost services** (Forgejo, beszel, …)
  with automatic HTTPS. One `[[caddy.site]]` per public hostname:

  ```toml
  [caddy]
  email = "ops@example.com"

  [[caddy.site]]
  domain = "git.example.com"
  upstream = "127.0.0.1:3000"
  ```

- anvil owns `/etc/caddy/Caddyfile` wholesale (static content, so `diff` shows
  it), validates it with `caddy validate` inside a `ReloadGuard` (auto-revert),
  and runs `systemctl reload caddy` only when a file changed.
- `[tls]` (certbot/acme.sh + nginx) stays. Both bind 80/443, so enabling both
  on the default ports is a **validation error**.

## 1. `[caddy]` or `[tls]`?

| Pick | When |
|---|---|
| `[caddy]` | You want to publish one or more localhost services. Caddy gets and renews certificates itself; no certbot, no cron, no nginx. Default choice for new hosts. |
| `[tls]` | nginx is already your web server (static sites, PHP, hand-written nginx config), or you need certbot/acme.sh certificate files on disk for other software. |

They are alternatives for the same job: the public front door on ports 80/443.
`anvil validate` rejects a config with both `[tls]` and `[caddy]` unless
`caddy.http_port`/`caddy.https_port` are moved off 80 and 443 (useful only
behind another proxy, or with `ca = "internal"`; public ACME needs 80/443).

Forgejo (binds 127.0.0.1:3000) needs no nginx: one `[[caddy.site]]` publishes it.

## 2. Install: vendor repo, key pinned in the binary

Verified 2026-10-31:

| Source | Caddy version |
|---|---|
| Debian 12 bookworm | 2.6.2 (`2.6.2-5`) |
| Debian 13 trixie | 2.6.2 (`2.6.2-12+deb13u1`); 2.11.2 only in trixie-backports |
| Ubuntu 22.04 jammy | no package |
| Ubuntu 24.04 noble | 2.6.2 (`2.6.2-6ubuntu0.24.04.3`) |
| Upstream | v2.11.7 (2026-10-03) |

2.6.2 dates from October 2022 and is missing four years of upstream fixes;
jammy has no package at all. So the
distro package is **not** current enough. anvil uses Caddy's official signed apt
repository (Cloudsmith), the one in Caddy's install docs:

```
deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.asc] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main
```

- The armored signing key is **embedded in anvil** (`src/modules/caddy-stable.asc`),
  fingerprint `65760C51EDEA2017CEA2CA15155B6D79CA56EA34`
  (`Caddy Web Server <contact@caddyserver.com>`, no expiry). Nothing is fetched
  to bootstrap trust: no `curl | gpg`, no `curl | sh`. A unit test pins the
  fingerprint. apt reads armored `.asc` keys via `signed-by=` (the Docker
  module relies on the same).
- Key and source are written with `chmod 0644` — under the CIS `umask 027` they
  would land 0640 and apt's `_apt` verifier could not read them (the
  tailscale/vector fix in `75809c2`).
- An existing distro 2.6.2 gets upgraded by apt, since the repo version is
  higher.
- Version is not pinned: apt installs the repo's current stable and
  `unattended-upgrades` (if enabled) keeps it current. Packages stay installed
  on rollback (`docs/02_concepts.md`).

### DNS-01 (`tls = "dns"`): a pinned build on the host

The apt Caddy has no DNS-provider modules, and caddyserver.com's download API
(also behind `caddy add-package`) is unsigned and not pinnable. anvil builds on
the host, only when a site uses `tls = "dns"`:

- Go from `go.dev/dl`, SHA-256 pinned per arch; modules via proxy.golang.org,
  checked against sum.golang.org; `main.go`/`go.mod` are embedded in anvil.
- `go build -trimpath -buildvcs=false -ldflags='-s -w'` with CGO off is
  reproducible, so the result is checked against a pinned SHA-256 before it is
  installed as `/usr/local/bin/caddy-anvil`. Any mismatch installs nothing.
- Built in the run dir (~1 GB, ~1.5 GB RAM, a few minutes), removed afterwards.
  apt's `/usr/bin/caddy` is untouched; a caddy.service drop-in points
  `ExecStart`/`ExecReload` at the build (without `--environ`, which logs the
  environment) and loads `/etc/caddy/anvil-dns.env` (`0600 root:root`).
  Rollback removes the drop-in, so Caddy is back on the apt binary; the build
  stays on disk.
- The build's Caddy version is pinned (not apt's): bump it with the pins.

To add a provider or bump a version: edit `DNS_PROVIDERS`/`DNS_BUILD_CADDY`/
`GO_*` in `src/modules/caddy.rs`, build the printed `main.go`/`go.mod` with the
same flags for linux/amd64 and linux/arm64, and update `DNS_BUILD_SHA256`.

## 3. What anvil writes

| Path | Content | Mode |
|---|---|---|
| `/etc/caddy/Caddyfile` | Static, generated from `[[caddy.site]]`. No secrets. | `0644 root:root` |
| `/etc/caddy/anvil-auth/<domain>.caddy` | Only for sites with `basic_auth`: the `basic_auth` block, **computed on the host** so the password hash never shows in `diff`. | `0640 root:caddy` |

Generated Caddyfile (one site with an allow-list):

```
# Managed by anvil — do not edit by hand
{
	admin unix//var/lib/caddy/admin.sock
	email ops@example.com
}

(anvil_headers) {
	header {
		Strict-Transport-Security "max-age=63072000"
		?X-Content-Type-Options "nosniff"
		?X-Frame-Options "SAMEORIGIN"
		?Referrer-Policy "strict-origin-when-cross-origin"
		-Server
	}
}

git.example.com {
	import anvil_headers
	@anvil_denied not remote_ip 100.64.0.0/10
	route {
		respond @anvil_denied 403
		reverse_proxy 127.0.0.1:3000
	}
}
```

Security defaults:

- **Admin API on a unix socket** (`/var/lib/caddy/admin.sock`, CA1). `admin
  off` is not offered: the packaged unit's `ExecReload` is `caddy reload`,
  which talks to the admin API, so `off` would break every reload. Caddy's
  default TCP `localhost:2019` would let any local user reconfigure Caddy; the
  socket is connectable only by root and the `caddy` user. `caddy reload`
  dials the admin address of the config it loads, so the first apply after the
  switch (and a rollback across it) falls back to `systemctl restart caddy`.
- **HSTS** (`hsts = true` by default, two years, no `preload`). `?` headers
  are defaults only, so an upstream that sets its own wins. `Server` is removed.
- **HTTP→HTTPS redirect and TLS 1.2+/modern ciphers** are Caddy defaults; anvil
  adds nothing there.
- **ACME:** `email` sets the account contact. `ca = "staging"` points at Let's
  Encrypt staging (for tests; untrusted certs, generous rate limits);
  `ca = "internal"` uses Caddy's local CA (`local_certs` + `skip_install_trust`,
  so the system trust store is never touched). Default `ca = "public"` keeps
  Caddy's defaults (Let's Encrypt, ZeroSSL fallback).
- **Allow-lists** (`allow = [CIDR…]`) use `remote_ip`, i.e. the TCP peer.
  Inside `route`, the 403 runs before `basic_auth` and the proxy; without
  `route`, Caddy's directive order would run `basic_auth` first.
- **Basic auth** takes a `user` and a bcrypt/argon2id `password_hash`
  (`caddy hash-password`), normally as `${ENV}`. Validation restricts both to
  token-safe characters.

## 4. Apply, reload, rollback

Order inside the declaration (commands run before files):

1. Install command (repo + `apt-get install caddy`).
2. ufw rules: `allow <http_port>/tcp`, `<https_port>/tcp`, `<https_port>/udp`
   (HTTP/3). Short-circuited when ufw is absent, so `[caddy]` works with or
   without `[firewall]` — the tailscale module's pattern. Wave 57, after
   `firewall` (50), so ports are open before Caddy asks for certificates.
3. "caddy is active" check (vector's pattern): a dead Caddy reads as drift.
4. Files (Caddyfile, auth snippets).
5. Guard: `caddy validate --config /etc/caddy/Caddyfile`, then `systemctl
   reload caddy` only if a file changed, `restart` if the service was down.
   A failed validate or reload restores the previous files.

Rollback:

- The package ships a default `/etc/caddy/Caddyfile`, so the first write leaves
  `.anvil.bak`: rollback restores it. Auth snippets were created by anvil, so
  rollback deletes them. Then the guard reloads Caddy with the restored file.
- **Certificates in `/var/lib/caddy` are never deleted.** They are Caddy state,
  not anvil config; deleting them would force re-issuance and can hit Let's
  Encrypt rate limits. Nothing in the module touches that directory, so there
  is no "trivially safe" case worth special-casing.
- Not undone (same as other modules): the package, the apt repo, ufw rules.
  The firewall's 80/443 rules stay open; remove them by hand if Caddy goes.
- An auth snippet for a site later removed from the config is orphaned
  (rollback only knows files in the current declaration). It is harmless —
  nothing imports it.

## 5. Provider firewalls

ufw is only the host layer. Hetzner Cloud and netcup firewalls must also allow
TCP 80, TCP 443 and UDP 443, or ACME and visitors never reach the host. With
`[hetzner]`, add them to `hetzner.rules`; netcup's SCP firewall is manual.

## 6. Not doing (now)

- Wildcard sites.
- Static file serving, `php_fastcgi`, arbitrary Caddyfile snippets.
- Admin over a unix socket.
- Pinning a Caddy version.
