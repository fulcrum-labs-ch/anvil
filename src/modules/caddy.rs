//! The `caddy` module: Caddy as the public front door (reverse proxy with
//! automatic HTTPS) for localhost services, one `[[caddy.site]]` each. Design
//! and rationale: `docs/design/caddy.md`.
//!
//! - Install from Caddy's official apt repo, trusted through a signing key
//!   **embedded in this binary** (no key download, no pipe-to-shell).
//! - `/etc/caddy/Caddyfile` is static managed content (so `diff` shows it); it
//!   holds no secrets. Basic-auth hashes live in per-site snippets computed on
//!   the host (`0640 root:caddy`), imported by path.
//! - ufw gets 80/tcp, 443/tcp and 443/udp (HTTP/3) when ufw is installed;
//!   `listen = "tailnet"` allows only 443 tcp/udp, on `tailscale0`.
//! - `tls = "tailscale"` sites get their cert from tailscaled, which a
//!   drop-in permits for the caddy user (`TS_PERMIT_CERT_UID`).
//! - `tls = "dns"` sites need a DNS-provider module the packaged Caddy lacks:
//!   the host builds [`DNS_CADDY_BIN`] from pinned sources with a pinned Go
//!   toolchain, and installs it only if it matches the pinned SHA-256. A
//!   caddy.service drop-in runs it, reading the token from [`DNS_ENV`]; the
//!   Caddyfile only says `{env.…}`.
//! - `caddy validate` guards every reload; a failure restores the previous
//!   files. Certificates under `/var/lib/caddy` are never touched.
//!
//! Every config value reaching the Caddyfile is charset-validated in
//! `config::validate_caddy`; the ones reaching bash go through
//! [`shell_escape`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::config::schema::{CaddySection, CaddySite, WallRule};
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_FAILED,
};
use crate::error::{AnvilError, Result};
use crate::escape::{shell_escape, shell_escape_join};

use super::{apt_install, Module};

/// The Caddyfile this module owns (Fixed Contract for drift/rollback).
pub const CADDYFILE: &str = "/etc/caddy/Caddyfile";
/// Admin API socket (CA1): a unix socket only root and the caddy user can
/// connect to, instead of TCP `localhost:2019` open to every local user.
pub const ADMIN_SOCKET: &str = "/var/lib/caddy/admin.sock";
/// Directory of the per-site basic-auth snippets.
pub const AUTH_DIR: &str = "/etc/caddy/anvil-auth";
/// Same paths as Caddy's install docs, so a host set up by hand is overwritten
/// in place instead of gaining a second, conflicting source.
const KEYRING_PATH: &str = "/usr/share/keyrings/caddy-stable-archive-keyring.asc";
const APT_LIST_PATH: &str = "/etc/apt/sources.list.d/caddy-stable.list";
/// Verified 2026-10-31 against `https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt`.
const APT_SOURCE: &str = "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.asc] \
https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n";
/// Caddy's apt signing key (`https://dl.cloudsmith.io/public/caddy/stable/gpg.key`),
/// primary fingerprint [`SIGNING_KEY_FINGERPRINT`], no expiry.
const SIGNING_KEY: &str = include_str!("caddy-stable.asc");
pub const SIGNING_KEY_FINGERPRINT: &str = "65760C51EDEA2017CEA2CA15155B6D79CA56EA34";
/// Lets the caddy user fetch this node's certificate from tailscaled.
pub const TAILSCALED_DROPIN: &str = "/etc/systemd/system/tailscaled.service.d/99-anvil-caddy.conf";
const TAILSCALED_DROPIN_CONTENT: &str =
    "# Managed by anvil — lets Caddy fetch this node's Tailscale certificate\n\
     [Service]\nEnvironment=TS_PERMIT_CERT_UID=caddy\n";
/// A DNS-provider module compiled into [`DNS_CADDY_BIN`]. Adding one is an
/// entry here plus new [`DNS_BUILD_SHA256`] hashes (see `docs/design/caddy.md`).
pub struct DnsProvider {
    pub name: &'static str,
    module: &'static str,
    version: &'static str,
    /// Holds the token; the Caddyfile reads `{env.<env>}`.
    env: &'static str,
}

pub const DNS_PROVIDERS: &[DnsProvider] = &[DnsProvider {
    name: "infomaniak",
    module: "github.com/caddy-dns/infomaniak",
    version: "v1.0.2",
    env: "INFOMANIAK_API_TOKEN",
}];

/// The DNS-capable Caddy (outside `/usr/bin`, so apt's caddy stays untouched).
pub const DNS_CADDY_BIN: &str = "/usr/local/bin/caddy-anvil";
/// `KEY=token` lines for caddy.service; root-only, systemd reads it as PID 1.
pub const DNS_ENV: &str = "/etc/caddy/anvil-dns.env";
pub const CADDY_DROPIN: &str = "/etc/systemd/system/caddy.service.d/99-anvil-dns.conf";
/// `[apps_resources]`: moves caddy (and its site processes) into `apps.slice`.
pub const SLICE_DROPIN: &str = "/etc/systemd/system/caddy.service.d/99-anvil-slice.conf";
const SLICE_DROPIN_CONTENT: &str = "# Managed by anvil — Caddy in apps.slice\n\
[Service]\nSlice=apps.slice\n";
/// The packaged unit's ExecStart minus `--environ`, which would log the token.
const CADDY_DROPIN_CONTENT: &str = "# Managed by anvil — Caddy with DNS-provider modules\n\
[Service]\nEnvironmentFile=/etc/caddy/anvil-dns.env\n\
ExecStart=\nExecStart=/usr/local/bin/caddy-anvil run --config /etc/caddy/Caddyfile\n\
ExecReload=\nExecReload=/usr/local/bin/caddy-anvil reload --config /etc/caddy/Caddyfile --force\n";
const DNS_BUILD_CADDY: &str = "v2.11.7";
/// From `https://go.dev/dl/?mode=json` (2026-11-03); (amd64, arm64).
const GO_VERSION: &str = "1.27.3";
const GO_SHA256: (&str, &str) = (
    "65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40",
    "a06e99309dbcbdca1a8ccd2282c3ee146e55930886e26b4f1193269587165f49",
);
/// sha256 of the reproducible build of [`dns_go_mod`] + [`dns_main_go`]
/// (`go mod tidy`, `go build -trimpath -buildvcs=false -ldflags='-s -w'`,
/// CGO off, Go [`GO_VERSION`]); (amd64, arm64).
const DNS_BUILD_SHA256: (&str, &str) = (
    "fa1f19cc26581a3fb7c5e003d510a77463e19daa3589368bde52e124ae0ede8b",
    "7511a51355b2f16e814c2ec84b7a2ee5d9d3dffc37012ac715c70d1f7fdc5347",
);

fn dns_provider(name: &str) -> Option<&'static DnsProvider> {
    DNS_PROVIDERS.iter().find(|p| p.name == name)
}

/// The build's `main.go`: standard Caddy plus every provider in the table.
fn dns_main_go() -> String {
    let mut s = String::from(
        "package main\n\nimport (\n\tcaddycmd \"github.com/caddyserver/caddy/v2/cmd\"\n\n",
    );
    for p in DNS_PROVIDERS {
        s.push_str(&format!("\t_ \"{}\"\n", p.module));
    }
    s.push_str(
        "\t_ \"github.com/caddyserver/caddy/v2/modules/standard\"\n)\n\n\
         func main() {\n\tcaddycmd.Main()\n}\n",
    );
    s
}

/// The build's `go.mod` before `go mod tidy` (MVS makes the rest deterministic).
fn dns_go_mod() -> String {
    let mut s = String::from("module caddy\n\ngo 1.26.0\n\nrequire (\n");
    for p in DNS_PROVIDERS {
        s.push_str(&format!("\t{} {}\n", p.module, p.version));
    }
    s.push_str(&format!(
        "\tgithub.com/caddyserver/caddy/v2 {DNS_BUILD_CADDY}\n)\n"
    ));
    s
}

/// `[[caddy.site]]` DNS fields, from `config::validate_caddy`. `tokens`:
/// provider → token so far; one env var per provider means one token.
pub fn validate_dns<'a>(
    s: &'a CaddySite,
    tokens: &mut std::collections::BTreeMap<&'a str, &'a str>,
) -> Result<()> {
    let err = |m: String| {
        Err(AnvilError::Validation(format!(
            "caddy.site {:?}: {m}",
            s.domain
        )))
    };
    if s.tls != "dns" {
        if s.dns_provider.is_some() || s.dns_token.is_some() {
            return err("dns_provider/dns_token need tls = \"dns\"".into());
        }
        return Ok(());
    }
    let names: Vec<&str> = DNS_PROVIDERS.iter().map(|p| p.name).collect();
    let Some(provider) = s
        .dns_provider
        .as_deref()
        .filter(|n| dns_provider(n).is_some())
    else {
        return err(format!(
            "tls = \"dns\" needs dns_provider, one of {names:?}"
        ));
    };
    // The token lands on a `KEY=value` line of a systemd EnvironmentFile.
    let token = s.dns_token.as_deref().unwrap_or_default();
    if token.is_empty()
        || !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+/=-".contains(c))
    {
        return err("dns_token is missing or not [A-Za-z0-9._+/=-] (value not shown)".into());
    }
    if tokens.insert(provider, token).is_some_and(|t| t != token) {
        return err(format!("sites using {provider} must share one dns_token"));
    }
    Ok(())
}

const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// True in rollback (no change arrays) or when one of `paths` was written
/// this run.
fn changed_or_rollback(paths: &[&str]) -> String {
    let mut s = String::from("! declare -p __creates >/dev/null 2>&1");
    for p in paths {
        s.push_str(&format!(
            " || [[ \" ${{__creates[*]-}} ${{__reverts[*]-}} \" == *\" {p} \"* ]]"
        ));
    }
    s
}

pub struct CaddyModule {
    cfg: CaddySection,
    /// `[firewall] allow` rules as ufw needles: never deleted as caddy's.
    firewall_allows: Vec<String>,
    /// `[apps_resources]`: write the `Slice=apps.slice` drop-in.
    in_apps_slice: bool,
}

impl CaddyModule {
    pub fn new(cfg: CaddySection) -> Self {
        Self {
            cfg,
            firewall_allows: Vec::new(),
            in_apps_slice: false,
        }
    }

    /// `[apps_resources]`: caddy joins `apps.slice`.
    pub fn in_apps_slice(mut self, on: bool) -> Self {
        self.in_apps_slice = on;
        self
    }

    /// Rules `[firewall] allow` owns, so a `listen` switch leaves them alone.
    pub fn firewall_allows(mut self, rules: &[WallRule]) -> Self {
        self.firewall_allows = rules
            .iter()
            .map(|r| super::firewall::rule_needle("allow", r))
            .collect();
        self
    }

    fn auth_path(site: &CaddySite) -> String {
        format!("{AUTH_DIR}/{}.caddy", site.domain)
    }

    /// The whole Caddyfile, tab-indented as `caddy fmt` writes it.
    pub fn caddyfile(&self) -> String {
        let c = &self.cfg;
        let mut s = String::from("# Managed by anvil — do not edit by hand\n{\n");
        // Never `admin off`: the packaged ExecReload (`caddy reload`) uses it.
        s.push_str(&format!("\tadmin unix/{ADMIN_SOCKET}\n"));
        if let Some(e) = &c.email {
            s.push_str(&format!("\temail {e}\n"));
        }
        if c.http_port != 80 {
            s.push_str(&format!("\thttp_port {}\n", c.http_port));
        }
        if c.https_port != 443 {
            s.push_str(&format!("\thttps_port {}\n", c.https_port));
        }
        match c.ca.as_str() {
            "staging" => s.push_str(&format!("\tacme_ca {LE_STAGING}\n")),
            "internal" => s.push_str("\tlocal_certs\n\tskip_install_trust\n"),
            _ => {}
        }
        s.push_str("}\n\n(anvil_headers) {\n\theader {\n");
        if c.hsts {
            s.push_str("\t\tStrict-Transport-Security \"max-age=63072000\"\n");
        }
        // `?` = default only: an upstream that sets its own value wins.
        s.push_str(
            "\t\t?X-Content-Type-Options \"nosniff\"\n\
             \t\t?X-Frame-Options \"SAMEORIGIN\"\n\
             \t\t?Referrer-Policy \"strict-origin-when-cross-origin\"\n\
             \t\t-Server\n\t}\n}\n",
        );
        for site in &c.sites {
            s.push_str(&format!("\n{} {{\n\timport anvil_headers\n", site.domain));
            if !site.allow.is_empty() {
                s.push_str(&format!(
                    "\t@anvil_denied not remote_ip {}\n",
                    site.allow.join(" ")
                ));
            }
            // `route` keeps written order: the 403 runs before basic_auth
            // (which Caddy would otherwise sort first) and the proxy.
            if site.tls == "tailscale" {
                s.push_str("\ttls {\n\t\tget_certificate tailscale\n\t}\n");
            }
            if let Some(p) = site.dns_provider.as_deref().and_then(dns_provider) {
                s.push_str(&format!(
                    "\ttls {{\n\t\tdns {} {{env.{}}}\n\t}}\n",
                    p.name, p.env
                ));
            }
            s.push_str("\troute {\n");
            if !site.allow.is_empty() {
                s.push_str("\t\trespond @anvil_denied 403\n");
            }
            if site.basic_auth.is_some() {
                s.push_str(&format!("\t\timport {}\n", Self::auth_path(site)));
            }
            s.push_str(&format!("\t\treverse_proxy {}\n\t}}\n}}\n", site.upstream));
        }
        s
    }

    /// Prints the site's `basic_auth` block on the host, so the hash only
    /// exists there and `diff` cannot show it.
    fn auth_generator(site: &CaddySite) -> Option<String> {
        site.basic_auth.as_ref().map(|b| {
            format!(
                "printf 'basic_auth {{\\n\\t%s %s\\n}}\\n' {} {}",
                shell_escape(&b.user),
                shell_escape(&b.password_hash)
            )
        })
    }

    /// Repo + package. Key and source are written from content embedded here
    /// and chmod'ed 0644 (under `umask 027` apt's `_apt` could not read them).
    fn install_command(&self) -> ManagedCommand {
        let key = shell_escape(&B64.encode(SIGNING_KEY));
        let src = shell_escape(&B64.encode(APT_SOURCE));
        ManagedCommand::new(
            "install caddy (official apt repo, embedded signing key)",
            format!(
                "command -v caddy >/dev/null 2>&1 \
                 && cmp -s {KEYRING_PATH} <(printf '%s' {key} | base64 -d) \
                 && cmp -s {APT_LIST_PATH} <(printf '%s' {src} | base64 -d)"
            ),
            format!(
                "install -d -m 0755 /usr/share/keyrings\n\
                 printf '%s' {key} | base64 -d > {KEYRING_PATH}\n\
                 printf '%s' {src} | base64 -d > {APT_LIST_PATH}\n\
                 chmod 0644 {KEYRING_PATH} {APT_LIST_PATH}\n\
                 {install}",
                install = apt_install(&["caddy"]),
            ),
        )
    }

    fn uses_tailscale_certs(&self) -> bool {
        self.cfg.sites.iter().any(|s| s.tls == "tailscale")
    }

    fn uses_dns(&self) -> bool {
        self.cfg.sites.iter().any(|s| s.tls == "dns")
    }

    /// Prints the env file on the host, so tokens never reach `diff`.
    fn dns_env_generator(&self) -> String {
        let mut seen = std::collections::BTreeSet::new();
        let mut g = Vec::new();
        for s in &self.cfg.sites {
            if let (Some(p), Some(t)) = (
                s.dns_provider.as_deref().and_then(dns_provider),
                &s.dns_token,
            ) {
                if seen.insert(p.env) {
                    g.push(format!("printf '%s=%s\\n' {} {}", p.env, shell_escape(t)));
                }
            }
        }
        g.join("; ")
    }

    /// Builds [`DNS_CADDY_BIN`] in the run dir when it does not match the pin:
    /// SHA-checked Go tarball, sum.golang.org-verified modules, SHA-checked
    /// result. Nothing is installed on any mismatch.
    fn dns_build_command() -> ManagedCommand {
        let bin = DNS_CADDY_BIN;
        let pick = format!(
            "case \"$(dpkg --print-architecture)\" in \
             amd64) __cd_arch=amd64; __cd_go={}; __cd_sha={} ;; \
             arm64) __cd_arch=arm64; __cd_go={}; __cd_sha={} ;; \
             *) __cd_arch=''; __cd_go=''; __cd_sha='' ;; esac",
            GO_SHA256.0, DNS_BUILD_SHA256.0, GO_SHA256.1, DNS_BUILD_SHA256.1
        );
        let fail = |what: &str| {
            format!(
                "{{ printf '{MARK_FAILED} caddy dns build: %s, not installed\\n' {}; exit 1; }}",
                shell_escape(what)
            )
        };
        ManagedCommand::new(
            format!("caddy with DNS providers at {bin} (pinned build, SHA-256 checked)"),
            format!(
                "{{ {pick}; [ -n \"$__cd_arch\" ] && \
                 printf '%s  %s\\n' \"$__cd_sha\" {bin} | sha256sum -c --status - 2>/dev/null; }}"
            ),
            format!(
                "{pick}\n\
                 [ -n \"$__cd_arch\" ] || {unsupported}\n\
                 command -v curl >/dev/null 2>&1 || {{ {curl}; }}\n\
                 __cd_dir=\"$__rundir/caddy-build\"\n\
                 mkdir -p \"$__cd_dir/src\" \"$__cd_dir/tmp\"\n\
                 curl -fsSL -o \"$__cd_dir/go.tgz\" \"https://go.dev/dl/go{GO_VERSION}.linux-${{__cd_arch}}.tar.gz\" || {dl}\n\
                 printf '%s  %s\\n' \"$__cd_go\" \"$__cd_dir/go.tgz\" | sha256sum -c --status - || {go_sha}\n\
                 tar -C \"$__cd_dir\" -xzf \"$__cd_dir/go.tgz\"\n\
                 printf '%s' {main} | base64 -d > \"$__cd_dir/src/main.go\"\n\
                 printf '%s' {gomod} | base64 -d > \"$__cd_dir/src/go.mod\"\n\
                 # A clean environment: the host's GOFLAGS/GOPROXY must not change the build.
                 __cd_go_env=(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=\"$__cd_dir\" \
                 GOPATH=\"$__cd_dir/gopath\" GOCACHE=\"$__cd_dir/cache\" GOTMPDIR=\"$__cd_dir/tmp\" GOTOOLCHAIN=local \
                 GOFLAGS=-modcacherw CGO_ENABLED=0 GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org \
                 \"$__cd_dir/go/bin/go\")\n\
                 if ! ( cd \"$__cd_dir/src\" && \"${{__cd_go_env[@]}}\" mod tidy && \
                 \"${{__cd_go_env[@]}}\" build -trimpath -buildvcs=false -ldflags='-s -w' -o \"$__cd_dir/caddy\" . ) \
                 > \"$__cd_dir/build.log\" 2>&1; then tail -n 20 \"$__cd_dir/build.log\" >&2; {build}; fi\n\
                 printf '%s  %s\\n' \"$__cd_sha\" \"$__cd_dir/caddy\" | sha256sum -c --status - || {out_sha}\n\
                 install -m 0755 -o root -g root \"$__cd_dir/caddy\" {bin}\n\
                 rm -rf \"$__cd_dir\"\n\
                 __caddy_restart=1",
                unsupported = fail("unsupported architecture (amd64 and arm64 only)"),
                curl = apt_install(&["curl"]),
                dl = fail("could not download the Go toolchain"),
                go_sha = fail("Go toolchain SHA-256 mismatch"),
                build = fail("go build failed (needs ~1.5 GB RAM and ~1 GB free in /var/lib/anvil)"),
                out_sha = fail("built binary does not match the pinned SHA-256"),
                main = shell_escape(&B64.encode(dns_main_go())),
                gomod = shell_escape(&B64.encode(dns_go_mod())),
            ),
        )
    }

    /// Once no site needs `paths` (and their backups), remove them and
    /// set `flag` so the guard restarts the service that loaded them. Not
    /// restorable by rollback on purpose: the DNS token must not come back.
    fn leftovers_removed(what: &str, paths: &[&str], flag: &str) -> ManagedCommand {
        let all: Vec<String> = paths
            .iter()
            .flat_map(|p| [p.to_string(), format!("{p}{BACKUP_SUFFIX}")])
            .collect();
        let detect = all
            .iter()
            .map(|p| format!("[ ! -e {} ]", shell_escape(p)))
            .collect::<Vec<_>>()
            .join(" && ");
        ManagedCommand::new(
            format!("no leftover {what}"),
            detect,
            format!(
                "for __f in {}; do rm -f \"$__f\"; __anvil_forget \"$__f\"; done\n{flag}=1",
                shell_escape_join(&all)
            ),
        )
    }

    /// ufw rules for HTTP, HTTPS and HTTP/3; aligned when ufw is absent.
    /// Needles match `ufw show added` exactly like the firewall module's.
    /// Tailnet: no ACME site is allowed there, so HTTP stays shut.
    /// Switching `listen` deletes the other mode's rules.
    fn ufw_commands(&self) -> Vec<ManagedCommand> {
        let c = &self.cfg;
        let public = [
            (c.http_port, "tcp"),
            (c.https_port, "tcp"),
            (c.https_port, "udp"),
        ]
        .map(|(port, proto)| (format!("allow {port}/{proto}"), ""));
        // The comment keeps tailscale's rollback (which re-opens every bare
        // `… proto tcp` tailscale0 rule as world-open SSH) off these ports,
        // and marks the rule as caddy's for the delete below.
        let tailnet = ["tcp", "udp"].map(|proto| {
            (
                format!(
                    "allow in on tailscale0 to any port {} proto {proto}",
                    c.https_port
                ),
                " comment 'anvil caddy'",
            )
        });
        let (add, stale): (&[_], &[_]) = if c.listen == "tailnet" {
            (&tailnet, &public)
        } else {
            (&public, &tailnet)
        };
        let adds = add.iter().map(|(rule, comment)| {
            ManagedCommand::new(
                format!("firewall {rule} (caddy)"),
                format!(
                    "! command -v ufw >/dev/null 2>&1 || \
                     ufw show added 2>/dev/null | grep -wF {} >/dev/null",
                    shell_escape(rule)
                ),
                format!("ufw {rule}{comment} >/dev/null"),
            )
        });
        // Only the exact line caddy added (`-x`: a user's commented rule on
        // the same port differs), and never a rule [firewall] declares too.
        // shortcut: a bare rule the user added by hand outside anvil is
        // indistinguishable from caddy's and is removed; declare it in
        // [firewall] allow to keep it.
        let deletes = stale
            .iter()
            .filter(|(rule, _)| !self.firewall_allows.contains(rule))
            .map(|(rule, comment)| {
                ManagedCommand::new(
                    format!("firewall remove {rule} (caddy, listen = {:?})", c.listen),
                    format!(
                        "! command -v ufw >/dev/null 2>&1 || \
                         ! ufw show added 2>/dev/null | grep -xF {} >/dev/null",
                        shell_escape(&format!("ufw {rule}{comment}"))
                    ),
                    format!("ufw delete {rule} >/dev/null"),
                )
            });
        adds.chain(deletes).collect()
    }

    /// Restart tailscaled when its drop-in changed (or always in rollback,
    /// which may have removed it), so its permission matches the file.
    /// `try-restart`: never start a tailscaled someone stopped.
    fn tailscaled_restart() -> String {
        // Last and --no-block: over the tailnet the restart drops anvil's SSH
        // session, which must not cut off the caddy reload before it.
        format!(
            "; if {}; then systemctl daemon-reload && systemctl --no-block try-restart tailscaled; fi",
            changed_or_rollback(&[TAILSCALED_DROPIN])
        )
    }

    fn reload_guard(&self) -> ReloadGuard {
        // A unit property never applies on `caddy reload`: the caddy process
        // must restart to leave system.slice.
        let slice = if self.in_apps_slice {
            format!(
                "if {}; then systemctl daemon-reload; __caddy_restart=1; fi; ",
                changed_or_rollback(&[SLICE_DROPIN])
            )
        } else {
            // The drop-in was just removed: only a restart leaves the slice.
            "if [ \"${__caddy_slice_gone:-0}\" = 1 ]; then systemctl daemon-reload; __caddy_restart=1; fi; "
                .to_string()
        };
        ReloadGuard {
            describe: "caddy configuration".into(),
            // With the drop-in present systemd runs the DNS build: validate with it.
            validate: if self.uses_dns() {
                format!(
                    "__cv=caddy; [ ! -f {CADDY_DROPIN} ] || __cv={DNS_CADDY_BIN}; \
                     ! [ -e {CADDYFILE} ] || \"$__cv\" validate --config {CADDYFILE} --adapter caddyfile"
                )
            } else {
                format!(
                    "! [ -e {CADDYFILE} ] || caddy validate --config {CADDYFILE} --adapter caddyfile"
                )
            },
            // Start a stopped caddy; otherwise reload only when a file changed
            // this run. Rollback declares no change arrays: always reload there.
            // `caddy reload` dials the admin address of the *new* config, so a
            // switch between TCP and the socket needs a restart instead.
            reload: slice
                + &(if self.uses_dns() {
                    // Binary, unit or token changed: only a restart picks them up.
                    format!(
                        "if {}; then systemctl daemon-reload; __caddy_restart=1; fi; ",
                        changed_or_rollback(&[CADDY_DROPIN, DNS_ENV])
                    )
                } else {
                    // The DNS unit drop-in was just removed: back to the apt binary.
                    "if [ \"${__caddy_dns_gone:-0}\" = 1 ]; then systemctl daemon-reload; __caddy_restart=1; fi; "
                        .to_string()
                })
                + "systemctl enable caddy >/dev/null 2>&1 || true; \
                     if ! systemctl is-active --quiet caddy || [ \"${__caddy_restart:-0}\" = 1 ]; \
                     then systemctl restart caddy; \
                     elif ! declare -p __creates >/dev/null 2>&1 \
                     || [ \"${#__creates[@]}\" -gt 0 ] || [ \"${#__reverts[@]}\" -gt 0 ]; \
                     then systemctl reload caddy || systemctl restart caddy; fi"
                + &(if self.uses_tailscale_certs() {
                    Self::tailscaled_restart()
                } else {
                    "; if [ \"${__caddy_ts_gone:-0}\" = 1 ]; then \
                     systemctl daemon-reload && systemctl --no-block try-restart tailscaled; fi"
                        .to_string()
                }),
        }
    }
}

impl Module for CaddyModule {
    fn id(&self) -> &'static str {
        "caddy"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("caddy").command(self.install_command());
        for t in self.cfg.sites.iter().filter_map(|s| s.dns_token.as_ref()) {
            decl = decl.secret(t);
        }
        for c in self.ufw_commands() {
            decl = decl.command(c);
        }
        decl = decl.command(if self.uses_dns() {
            Self::dns_build_command()
        } else {
            Self::leftovers_removed(
                "DNS build, unit drop-in or token",
                &[DNS_CADDY_BIN, CADDY_DROPIN, DNS_ENV],
                "__caddy_dns_gone",
            )
        });
        if !self.uses_tailscale_certs() {
            decl = decl.command(Self::leftovers_removed(
                "tailscaled cert drop-in",
                &[TAILSCALED_DROPIN],
                "__caddy_ts_gone",
            ));
        }
        // The section is gone, so this build no longer declares the
        // drop-in; remove it or caddy stays in a slice nothing writes.
        if !self.in_apps_slice {
            decl = decl.command(Self::leftovers_removed(
                "apps.slice drop-in",
                &[SLICE_DROPIN],
                "__caddy_slice_gone",
            ));
        }
        // Probe-visible: a dead caddy is drift. The guarded reload starts it,
        // after the new files are written and validated.
        decl = decl.command(ManagedCommand::new(
            "caddy service is active",
            "systemctl is-active --quiet caddy",
            ": # started by the guarded reload below",
        ));
        let auth_sites: Vec<&CaddySite> = self
            .cfg
            .sites
            .iter()
            .filter(|s| s.basic_auth.is_some())
            .collect();
        if !auth_sites.is_empty() {
            // The caddy user must traverse it; the engine's mkdir would leave
            // it 0750 root:root under umask 027.
            let dir = shell_escape(AUTH_DIR);
            decl = decl
                .command(ManagedCommand::new(
                    format!("{AUTH_DIR} is 0750 root:caddy"),
                    format!("[ \"$(stat -c '%a %U:%G' {dir} 2>/dev/null)\" = '750 root:caddy' ]"),
                    format!("install -d -m 0750 -o root -g caddy {dir}"),
                ))
                .rollback_script(format!(
                    "\nif rmdir {dir} 2>/dev/null; then printf 'CHANGED: removed empty %s\\n' {dir}; \
                     else printf 'OK: %s kept (absent or not empty)\\n' {dir}; fi\n"
                ));
        }
        decl = decl.file(ManagedFile::new(
            CADDYFILE,
            self.caddyfile(),
            "0644",
            "root:root",
        ));
        for site in auth_sites {
            if let Some(generator) = Self::auth_generator(site) {
                decl = decl.file(ManagedFile::computed(
                    Self::auth_path(site),
                    generator,
                    "0640",
                    "root:caddy",
                ));
            }
        }
        if self.uses_dns() {
            decl = decl
                .file(ManagedFile::computed(
                    DNS_ENV,
                    self.dns_env_generator(),
                    "0600",
                    "root:root",
                ))
                .file(ManagedFile::new(
                    CADDY_DROPIN,
                    CADDY_DROPIN_CONTENT,
                    "0644",
                    "root:root",
                ));
        }
        if self.uses_tailscale_certs() {
            decl = decl.file(ManagedFile::new(
                TAILSCALED_DROPIN,
                TAILSCALED_DROPIN_CONTENT,
                "0644",
                "root:root",
            ));
        }
        if self.in_apps_slice {
            decl = decl.file(ManagedFile::new(
                SLICE_DROPIN,
                SLICE_DROPIN_CONTENT,
                "0644",
                "root:root",
            ));
        }
        decl.guarded_reload(self.reload_guard())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::CaddyBasicAuth;
    use crate::engine::FileContent;

    const HASH: &str = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG";

    fn site(domain: &str, upstream: &str) -> CaddySite {
        CaddySite {
            domain: domain.into(),
            upstream: upstream.into(),
            allow: Vec::new(),
            basic_auth: None,
            tls: "acme".into(),
            dns_provider: None,
            dns_token: None,
        }
    }

    fn module(mutate: impl FnOnce(&mut CaddySection)) -> CaddyModule {
        let mut cfg = CaddySection {
            email: None,
            ca: "public".into(),
            http_port: 80,
            https_port: 443,
            hsts: true,
            listen: "public".into(),
            sites: vec![site("git.example.com", "127.0.0.1:3000")],
            order_override: Default::default(),
        };
        mutate(&mut cfg);
        CaddyModule::new(cfg)
    }

    fn with_auth(c: &mut CaddySection) {
        c.sites[0].basic_auth = Some(CaddyBasicAuth {
            user: "ops".into(),
            password_hash: HASH.into(),
        });
    }

    #[test]
    fn default_caddyfile_is_exact() {
        // Pins the whole file: the diff contract shows exactly these bytes.
        let expected = "# Managed by anvil — do not edit by hand\n{\n\tadmin unix//var/lib/caddy/admin.sock\n}\n\n\
(anvil_headers) {\n\theader {\n\t\tStrict-Transport-Security \"max-age=63072000\"\n\
\t\t?X-Content-Type-Options \"nosniff\"\n\t\t?X-Frame-Options \"SAMEORIGIN\"\n\
\t\t?Referrer-Policy \"strict-origin-when-cross-origin\"\n\t\t-Server\n\t}\n}\n\n\
git.example.com {\n\timport anvil_headers\n\troute {\n\t\treverse_proxy 127.0.0.1:3000\n\t}\n}\n";
        assert_eq!(module(|_| {}).caddyfile(), expected);
    }

    #[test]
    fn global_options_follow_config() {
        let f = module(|c| {
            c.email = Some("ops@example.com".into());
            c.ca = "staging".into();
            c.http_port = 8080;
            c.https_port = 8443;
            c.hsts = false;
        })
        .caddyfile();
        for needle in [
            "\temail ops@example.com\n",
            "\thttp_port 8080\n",
            "\thttps_port 8443\n",
            "\tacme_ca https://acme-staging-v02.api.letsencrypt.org/directory\n",
        ] {
            assert!(f.contains(needle), "missing {needle:?}:\n{f}");
        }
        assert!(!f.contains("Strict-Transport-Security"));
        assert!(!f.contains("local_certs"));

        let internal = module(|c| c.ca = "internal".into()).caddyfile();
        assert!(internal.contains("\tlocal_certs\n\tskip_install_trust\n"));
        assert!(!internal.contains("acme_ca"));
        // Default ports are not spelled out; admin is always the local socket.
        assert!(!internal.contains("http_port"));
        assert!(internal.contains("\tadmin unix//var/lib/caddy/admin.sock\n"));
        assert!(!internal.contains("admin off"));
        assert!(!internal.contains("2019"), "no TCP admin listener");
    }

    #[test]
    fn allow_list_denies_before_auth_and_proxy() {
        let f = module(|c| {
            with_auth(c);
            c.sites[0].allow = vec!["100.64.0.0/10".into(), "10.0.0.1".into()];
        })
        .caddyfile();
        assert!(f.contains("\t@anvil_denied not remote_ip 100.64.0.0/10 10.0.0.1\n"));
        let deny = f.find("respond @anvil_denied 403").expect("deny");
        let auth = f
            .find("import /etc/caddy/anvil-auth/git.example.com.caddy")
            .expect("auth import");
        let proxy = f.find("reverse_proxy 127.0.0.1:3000").expect("proxy");
        let route = f.find("\troute {").expect("route");
        assert!(route < deny && deny < auth && auth < proxy);
    }

    #[test]
    fn several_sites_each_get_a_block() {
        let f = module(|c| c.sites.push(site("stats.example.com", "127.0.0.1:8090"))).caddyfile();
        assert!(f.contains("\ngit.example.com {\n"));
        assert!(f.contains("\nstats.example.com {\n"));
        assert!(f.contains("reverse_proxy 127.0.0.1:8090"));
        assert_eq!(f.matches("import anvil_headers").count(), 2);
    }

    #[test]
    fn basic_auth_hash_is_computed_on_host_never_static() {
        let m = module(with_auth);
        assert!(!m.caddyfile().contains(HASH), "hash must not be diffable");
        let decl = m.declaration();
        let snippet = decl
            .files
            .iter()
            .find(|f| f.path == "/etc/caddy/anvil-auth/git.example.com.caddy")
            .expect("auth snippet");
        assert_eq!(
            (snippet.mode.as_str(), snippet.owner.as_str()),
            ("0640", "root:caddy")
        );
        let FileContent::Computed { generator } = &snippet.content else {
            panic!("auth snippet must be computed");
        };
        assert!(
            generator.contains(&format!("'ops' '{HASH}'")),
            "{generator}"
        );
        // The snippet dir is traversable by caddy, and created before files.
        let apply = decl.render_apply();
        let dir = apply
            .find("install -d -m 0750 -o root -g caddy '/etc/caddy/anvil-auth'")
            .expect("auth dir");
        assert!(dir < apply.find("# file: /etc/caddy/Caddyfile").expect("file"));
        assert!(decl
            .render_rollback()
            .contains("rmdir '/etc/caddy/anvil-auth'"));
    }

    #[test]
    fn auth_generator_prints_the_block() {
        let Some(generator) = CaddyModule::auth_generator(&module(with_auth).cfg.sites[0]) else {
            panic!("generator");
        };
        let Ok(out) = std::process::Command::new("bash")
            .args(["-c", &generator])
            .output()
        else {
            return; // no bash on this machine
        };
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("basic_auth {{\n\tops {HASH}\n}}\n")
        );
    }

    #[test]
    fn no_auth_means_no_snippets_or_dir() {
        let decl = module(|_| {}).declaration();
        assert_eq!(decl.files.len(), 1);
        assert!(!decl.render_apply().contains(AUTH_DIR));
        assert!(decl.rollback.is_none());
    }

    #[test]
    fn install_uses_embedded_key_and_no_download() {
        assert!(SIGNING_KEY.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let decl = module(|_| {}).declaration();
        let apply = decl.render_apply();
        for s in [decl.render_probe(), apply.clone()] {
            assert!(!s.contains("curl"), "no download:\n{s}");
            assert!(!s.contains("| sh") && !s.contains("| bash"));
        }
        assert!(apply.contains(&B64.encode(SIGNING_KEY)));
        assert!(apply.contains(&B64.encode(APT_SOURCE)));
        let chmod = apply
            .find(&format!("chmod 0644 {KEYRING_PATH} {APT_LIST_PATH}"))
            .expect("world-readable key and source");
        let list = apply.find(&format!("> {APT_LIST_PATH}")).expect("source");
        let install = apply.find("install -y -- 'caddy'").expect("install");
        assert!(list < chmod && chmod < install);
        assert!(apply.contains("apt-get -o DPkg::Lock::Timeout=600 update -qq"));
    }

    #[test]
    fn embedded_key_has_the_pinned_fingerprint() {
        // Skips when gpg is missing; CI images and dev machines usually have it.
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let Ok(mut child) = Command::new("gpg")
            .args(["--show-keys", "--with-colons"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(SIGNING_KEY.as_bytes()).expect("write key");
        }
        let out = child.wait_with_output().expect("gpg");
        let text = String::from_utf8_lossy(&out.stdout);
        let first_fpr = text
            .lines()
            .find_map(|l| l.strip_prefix("fpr:::::::::"))
            .and_then(|r| r.split(':').next());
        assert_eq!(first_fpr, Some(SIGNING_KEY_FINGERPRINT));
    }

    #[test]
    fn apt_source_is_the_verified_line() {
        assert_eq!(
            APT_SOURCE,
            "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.asc] \
             https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main\n"
        );
    }

    #[test]
    fn ufw_opens_http_https_and_http3() {
        let apply = module(|c| {
            c.http_port = 8080;
            c.https_port = 8443;
        })
        .declaration()
        .render_apply();
        for rule in ["allow 8080/tcp", "allow 8443/tcp", "allow 8443/udp"] {
            assert!(
                apply.contains(&format!("grep -wF '{rule}' >/dev/null")),
                "{rule}"
            );
            assert!(apply.contains(&format!("ufw {rule} >/dev/null")), "{rule}");
        }
        assert!(apply.contains("! command -v ufw >/dev/null 2>&1 ||"));
    }

    /// Run each ufw command (converge only when detect fails) against a stub
    /// `ufw` whose `show added` prints `added`; returns the mutating calls.
    fn run_ufw(m: &CaddyModule, added: &[&str]) -> String {
        let mut script = format!(
            "ufw() {{ if [ \"$1 $2\" = 'show added' ]; then printf '%s\\n' {}; else echo \"ufw $*\" >&3; fi; }}\nexec 3>&1\n",
            added.iter().map(|l| shell_escape(l)).collect::<Vec<_>>().join(" ")
        );
        for c in m.ufw_commands() {
            script.push_str(&format!(
                "if ! {{ {}; }}; then {}; fi\n",
                c.detect, c.converge
            ));
        }
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn listen_switch_removes_only_caddys_old_rules() {
        let ports = |c: &mut CaddySection| {
            c.http_port = 8080;
            c.https_port = 8443;
        };
        // public -> tailnet: caddy's bare rules go; a user's commented rule
        // on the same port and rules [firewall] declares stay.
        let added = [
            "ufw allow 8080/tcp",
            "ufw allow 8443/tcp",
            "ufw allow 8443/udp",
            "ufw allow 8443/tcp comment 'web'",
            "ufw allow 22/tcp",
        ];
        let to_tailnet = module(|c| {
            ports(c);
            tailnet(c);
        });
        let calls = run_ufw(&to_tailnet, &added);
        for rule in ["allow 8080/tcp", "allow 8443/tcp", "allow 8443/udp"] {
            assert!(
                calls.contains(&format!("ufw delete {rule}\n")),
                "{rule}: {calls}"
            );
        }
        assert!(
            !calls.contains("delete allow 22/tcp") && !calls.contains("delete allow in"),
            "{calls}"
        );
        assert!(
            calls.contains(
                "ufw allow in on tailscale0 to any port 8443 proto tcp comment anvil caddy"
            ),
            "{calls}"
        );
        let apply = to_tailnet.declaration().render_apply();
        assert!(apply.contains("grep -xF 'ufw allow 8080/tcp' >/dev/null"));
        assert!(apply.contains("ufw delete allow 8443/udp >/dev/null"));
        // Converged: nothing left to remove.
        assert_eq!(
            run_ufw(
                &to_tailnet,
                &[
                    "ufw allow in on tailscale0 to any port 8443 proto tcp comment 'anvil caddy'",
                    "ufw allow in on tailscale0 to any port 8443 proto udp comment 'anvil caddy'"
                ]
            ),
            ""
        );

        // [firewall] allow = 8443/tcp is the user's: kept.
        let owned = to_tailnet.firewall_allows(&[WallRule {
            port: "8443".into(),
            proto: Some("tcp".into()),
            from: None,
            comment: None,
        }]);
        let calls = run_ufw(&owned, &added);
        assert!(
            calls.contains("ufw delete allow 8080/tcp")
                && calls.contains("ufw delete allow 8443/udp"),
            "{calls}"
        );
        assert!(!calls.contains("ufw delete allow 8443/tcp"), "{calls}");

        // tailnet -> public: only the tailscale0 rules caddy commented go.
        let mine = "ufw allow in on tailscale0 to any port 8443 proto tcp comment 'anvil caddy'";
        let users = "ufw allow in on tailscale0 to any port 8443 proto udp";
        let to_public = module(ports);
        let calls = run_ufw(
            &to_public,
            &[
                mine,
                users,
                "ufw allow 8080/tcp",
                "ufw allow 8443/tcp",
                "ufw allow 8443/udp",
            ],
        );
        assert_eq!(
            calls,
            "ufw delete allow in on tailscale0 to any port 8443 proto tcp\n"
        );
        let apply = to_public.declaration().render_apply();
        assert!(apply.contains(&format!("grep -xF {} >/dev/null", shell_escape(mine))));
        assert!(!apply.contains("ufw delete allow 8"));
    }

    #[test]
    fn reload_is_validated_and_gated_on_change() {
        let decl = module(|_| {}).declaration();
        let apply = decl.render_apply();
        let validate = apply
            .find("caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile")
            .expect("validate");
        let reload = apply.find("systemctl reload caddy").expect("reload");
        assert!(validate < reload);
        assert!(apply.contains(r#"[ "${#__creates[@]}" -gt 0 ] || [ "${#__reverts[@]}" -gt 0 ]"#));
        assert!(apply.contains(
            "if ! systemctl is-active --quiet caddy || [ \"${__caddy_restart:-0}\" = 1 ]; \
                 then systemctl restart caddy"
        ));
        let probe = decl.render_probe();
        assert!(probe.contains("systemctl is-active --quiet caddy"));
        assert!(!probe.contains("caddy validate") && !probe.contains("systemctl reload"));
    }

    /// Runs the real reload snippet against a stub `systemctl` and returns
    /// the calls it made.
    fn run_reload(prelude: &str, active: bool) -> Option<String> {
        run_reload_of(&module(|_| {}).reload_guard().reload, prelude, active)
    }

    fn run_reload_of(reload: &str, prelude: &str, active: bool) -> Option<String> {
        let dir = std::env::temp_dir().join(format!(
            "anvil-caddy-reload-{}-{}",
            std::process::id(),
            prelude.len() + reload.len() + active as usize
        ));
        std::fs::create_dir_all(&dir).ok()?;
        let log = dir.join("log");
        let stub = dir.join("systemctl");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\necho \"$*\" >> '{}'\n[ \"$1\" = is-active ] && exit {}\nexit 0\n",
                log.display(),
                if active { 0 } else { 3 }
            ),
        )
        .ok()?;
        std::process::Command::new("chmod")
            .args(["+x", &stub.to_string_lossy()])
            .status()
            .ok()?;
        let script = format!(
            "set -euo pipefail\nPATH='{}':$PATH\n{prelude}\n{}",
            dir.display(),
            reload
        );
        let ok = std::process::Command::new("bash")
            .args(["-c", &script])
            .status()
            .ok()?
            .success();
        assert!(ok, "reload snippet failed");
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        Some(calls)
    }

    #[test]
    fn reload_snippet_behaviour() {
        // Apply, nothing changed: no reload.
        let Some(calls) = run_reload("__creates=(); __reverts=()", true) else {
            return;
        };
        assert!(
            !calls.contains("reload") && !calls.contains("restart"),
            "{calls}"
        );
        // Apply, a file changed: reload.
        let calls = run_reload("__creates=(); __reverts=(/etc/caddy/Caddyfile)", true).unwrap();
        assert!(calls.contains("reload caddy"), "{calls}");
        assert!(!calls.contains("restart caddy"), "{calls}");
        // A reload that cannot reach the old admin address falls back to restart.
        let calls = run_reload(
            "__creates=(); __reverts=(x)\nsystemctl() { command systemctl \"$@\"; [ \"$1\" != reload ]; }",
            true,
        )
        .unwrap();
        assert!(calls.contains("reload caddy\nrestart caddy"), "{calls}");
        // Service down: restart, not reload.
        let calls = run_reload("__creates=(); __reverts=()", false).unwrap();
        assert!(calls.contains("restart caddy") && !calls.contains("reload caddy"));
        // Rollback (no change arrays): always reload.
        let calls = run_reload(":", true).unwrap();
        assert!(calls.contains("reload caddy"), "{calls}");
    }

    fn tailnet(c: &mut CaddySection) {
        c.listen = "tailnet".into();
        c.sites[0].domain = "n1.tail1.ts.net".into();
        c.sites[0].tls = "tailscale".into();
    }

    #[test]
    fn tailnet_opens_only_https_on_tailscale0() {
        let apply = module(tailnet).declaration().render_apply();
        for proto in ["tcp", "udp"] {
            let rule = format!("allow in on tailscale0 to any port 443 proto {proto}");
            assert!(
                apply.contains(&format!("grep -wF '{rule}' >/dev/null")),
                "{rule}"
            );
            assert!(
                apply.contains(&format!("ufw {rule} comment 'anvil caddy' >/dev/null")),
                "{rule}"
            );
        }
        assert!(!apply.contains("port 80 "), "no HTTP on the tailnet");
        assert!(
            !apply.contains("ufw allow 443/tcp >") && !apply.contains("ufw allow 80/tcp >"),
            "nothing public"
        );
        // Public listen keeps its bare rules (no comment churn on existing hosts).
        assert!(!module(|_| {})
            .declaration()
            .render_apply()
            .contains("comment 'anvil caddy'"));
    }

    #[test]
    fn tailscale_site_gets_cert_from_tailscaled() {
        let m = module(tailnet);
        let f = m.caddyfile();
        assert!(
            f.contains("\nn1.tail1.ts.net {\n\timport anvil_headers\n\ttls {\n\t\tget_certificate tailscale\n\t}\n\troute {\n"),
            "{f}"
        );
        let decl = m.declaration();
        let dropin = decl
            .files
            .iter()
            .find(|f| f.path == TAILSCALED_DROPIN)
            .expect("tailscaled drop-in");
        assert_eq!(dropin.static_content(), Some(TAILSCALED_DROPIN_CONTENT));
        assert!(
            TAILSCALED_DROPIN_CONTENT.contains("[Service]\nEnvironment=TS_PERMIT_CERT_UID=caddy\n")
        );
        // An ACME site gets neither.
        let acme = module(|_| {});
        assert!(!acme.caddyfile().contains("get_certificate"));
        let d = acme.declaration();
        assert!(!d.files.iter().any(|f| f.path == TAILSCALED_DROPIN));
        assert!(!d
            .render_apply()
            .contains(&changed_or_rollback(&[TAILSCALED_DROPIN])));
    }

    #[test]
    fn apps_slice_dropin_only_with_apps_resources_and_restarts_to_move() {
        // A unit property change never applies on `caddy reload`: the process
        // must restart to leave system.slice.
        let on = module(|_| {}).in_apps_slice(true);
        let d = on.declaration();
        let f = d
            .files
            .iter()
            .find(|f| f.path == SLICE_DROPIN)
            .expect("slice drop-in");
        assert_eq!(f.static_content(), Some(SLICE_DROPIN_CONTENT));
        assert_eq!(f.mode, "0644");
        let reload = &d.reload.as_ref().unwrap().reload;
        assert!(reload.contains(SLICE_DROPIN), "{reload}");
        assert!(reload.contains("__caddy_restart=1"), "{reload}");

        let off = module(|_| {}).declaration();
        assert!(!off.files.iter().any(|f| f.path == SLICE_DROPIN));
        assert!(!off.reload.as_ref().unwrap().reload.contains("apps.slice"));
    }

    #[test]
    fn leaving_apps_slice_removes_the_dropin_and_restarts_only_then() {
        // Removing `[apps_resources]` builds caddy without the drop-in; the
        // leftover must be removed or caddy stays in a slice nothing manages.
        let off = module(|_| {}).declaration();
        let leftovers = off
            .commands
            .iter()
            .find(|c| c.describe.contains("apps.slice drop-in"))
            .expect("leftover command");
        assert_eq!(
            leftovers.detect,
            format!("[ ! -e '{SLICE_DROPIN}' ] && [ ! -e '{SLICE_DROPIN}.anvil.bak' ]")
        );
        assert!(
            leftovers.converge.contains("rm -f \"$__f\""),
            "{}",
            leftovers.converge
        );
        assert!(leftovers.converge.contains("__caddy_slice_gone=1"));
        // The probe drifts while the file is still there.
        assert!(off
            .render_probe()
            .contains(&format!("[ ! -e '{SLICE_DROPIN}' ]")));
        // Apply removes it before the reload, whose restart waits for the flag.
        let apply = off.render_apply();
        let rm = apply.find("__caddy_slice_gone=1").expect("removal runs");
        let gate = apply
            .find("if [ \"${__caddy_slice_gone:-0}\" = 1 ]; then systemctl daemon-reload; __caddy_restart=1; fi;")
            .expect("restart is gated on the removal");
        assert!(rm < gate, "{apply}");
        // With the section on, the drop-in is declared, not removed.
        let on = module(|_| {}).in_apps_slice(true).declaration();
        assert!(
            !on.commands
                .iter()
                .any(|c| c.describe.contains("apps.slice drop-in")),
            "no leftovers command while the drop-in is ours"
        );
    }

    #[test]
    fn tailscaled_restarts_only_when_its_dropin_changed() {
        let reload = module(tailnet).reload_guard().reload;
        let Some(calls) = run_reload_of(
            &reload,
            "__creates=(); __reverts=(/etc/caddy/Caddyfile)",
            true,
        ) else {
            return;
        };
        assert!(!calls.contains("tailscaled"), "{calls}");
        let calls = run_reload_of(
            &reload,
            &format!("__creates=({TAILSCALED_DROPIN}); __reverts=()"),
            true,
        )
        .unwrap();
        let restart = calls
            .find("daemon-reload\n--no-block try-restart tailscaled")
            .expect(&calls);
        assert!(
            restart > calls.find("reload caddy").expect(&calls),
            "{calls}"
        );
        // Rollback may have removed it: always restart there.
        let calls = run_reload_of(&reload, ":", true).unwrap();
        assert!(
            calls.contains("--no-block try-restart tailscaled"),
            "{calls}"
        );
    }

    const TOKEN: &str = "tok3n-Secret_value";

    fn dns(c: &mut CaddySection) {
        c.sites[0].tls = "dns".into();
        c.sites[0].dns_provider = Some("infomaniak".into());
        c.sites[0].dns_token = Some(TOKEN.into());
    }

    #[test]
    fn dns_site_reads_its_token_from_the_env_file_only() {
        let m = module(dns);
        let f = m.caddyfile();
        assert!(
            f.contains("\ttls {\n\t\tdns infomaniak {env.INFOMANIAK_API_TOKEN}\n\t}\n\troute {"),
            "{f}"
        );
        let decl = m.declaration();
        for file in &decl.files {
            assert!(
                !file.static_content().unwrap_or_default().contains(TOKEN),
                "{}",
                file.path
            );
        }
        let env = decl
            .files
            .iter()
            .find(|f| f.path == DNS_ENV)
            .expect("env file");
        assert_eq!(
            (env.mode.as_str(), env.owner.as_str()),
            ("0600", "root:root")
        );
        let FileContent::Computed { generator } = &env.content else {
            panic!("env file must be computed");
        };
        let Ok(out) = std::process::Command::new("bash")
            .args(["-c", generator])
            .output()
        else {
            return;
        };
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("INFOMANIAK_API_TOKEN={TOKEN}\n")
        );
        let dropin = decl
            .files
            .iter()
            .find(|f| f.path == CADDY_DROPIN)
            .expect("drop-in");
        let unit = dropin.static_content().expect("static");
        assert!(unit.contains("EnvironmentFile=/etc/caddy/anvil-dns.env\n"));
        assert!(unit.contains("ExecStart=\nExecStart=/usr/local/bin/caddy-anvil run --config"));
        assert!(unit.contains("ExecReload=\nExecReload=/usr/local/bin/caddy-anvil reload"));
        assert!(!unit.contains("--environ"), "would log the token");
    }

    #[test]
    fn env_file_has_one_line_per_provider() {
        let m = module(|c| {
            dns(c);
            c.sites.push(c.sites[0].clone());
            c.sites[1].domain = "b.example.com".into();
        });
        assert_eq!(m.dns_env_generator().matches("printf").count(), 1);
    }

    #[test]
    fn dns_build_inputs_are_pinned() {
        // These bytes produced DNS_BUILD_SHA256: change them and the hashes.
        assert_eq!(
            dns_main_go(),
            "package main\n\nimport (\n\tcaddycmd \"github.com/caddyserver/caddy/v2/cmd\"\n\n\
             \t_ \"github.com/caddy-dns/infomaniak\"\n\
             \t_ \"github.com/caddyserver/caddy/v2/modules/standard\"\n)\n\n\
             func main() {\n\tcaddycmd.Main()\n}\n"
        );
        assert_eq!(
            dns_go_mod(),
            "module caddy\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/caddy-dns/infomaniak v1.0.2\n\
             \tgithub.com/caddyserver/caddy/v2 v2.11.7\n)\n"
        );
    }

    #[test]
    fn dns_build_installs_only_a_verified_binary() {
        let apply = module(dns).declaration().render_apply();
        let at = |n: &str| apply.find(n).unwrap_or_else(|| panic!("missing {n}"));
        assert!(apply.contains(&format!(
            "amd64) __cd_arch=amd64; __cd_go={}; __cd_sha={}",
            GO_SHA256.0, DNS_BUILD_SHA256.0
        )));
        assert!(apply.contains(&format!(
            "arm64) __cd_arch=arm64; __cd_go={}; __cd_sha={}",
            GO_SHA256.1, DNS_BUILD_SHA256.1
        )));
        let dl = at("https://go.dev/dl/go1.27.3.linux-${__cd_arch}.tar.gz");
        let go_sha = at("\"$__cd_go\" \"$__cd_dir/go.tgz\" | sha256sum -c --status - ||");
        let untar = at("tar -C \"$__cd_dir\" -xzf");
        let build = at("build -trimpath -buildvcs=false -ldflags='-s -w'");
        let out_sha = at("\"$__cd_sha\" \"$__cd_dir/caddy\" | sha256sum -c --status - ||");
        let install =
            at("install -m 0755 -o root -g root \"$__cd_dir/caddy\" /usr/local/bin/caddy-anvil");
        assert!(
            dl < go_sha && go_sha < untar && untar < build && build < out_sha && out_sha < install
        );
        assert!(apply.contains("env -i PATH=") && apply.contains("GOTOOLCHAIN=local"));
        assert!(apply.contains("GOSUMDB=sum.golang.org"));
        // /tmp is noexec under [filesystem].
        assert!(apply.contains("GOTMPDIR=\"$__cd_dir/tmp\""));
        assert!(apply[install..].contains("__caddy_restart=1"));
        // Drop-in and env file are written by the engine after the build.
        assert!(install < at("# file: /etc/caddy/anvil-dns.env"));
        // Detect: the installed binary's hash, nothing else.
        let probe = module(dns).declaration().render_probe();
        assert!(probe.contains(
            "printf '%s  %s\\n' \"$__cd_sha\" /usr/local/bin/caddy-anvil | sha256sum -c"
        ));
        assert!(!probe.contains("go.dev"), "probe stays read-only");
    }

    #[test]
    fn hosts_without_dns_sites_get_no_build() {
        for m in [module(|_| {}), module(tailnet)] {
            let decl = m.declaration();
            let all = decl.render_apply() + &decl.render_rollback();
            // Only the leftover cleanup may name the DNS paths.
            for needle in ["go.dev", "caddy-build", "__cv="] {
                assert!(!all.contains(needle), "{needle}");
            }
            assert!(!decl
                .files
                .iter()
                .any(|f| f.path == DNS_ENV || f.path == CADDY_DROPIN));
        }
    }

    #[test]
    fn dns_restarts_caddy_when_unit_or_token_changed() {
        let g = module(dns).reload_guard();
        assert!(g.validate.contains(
            "__cv=caddy; [ ! -f /etc/systemd/system/caddy.service.d/99-anvil-dns.conf ] || __cv=/usr/local/bin/caddy-anvil;"
        ));
        let Some(calls) = run_reload_of(
            &g.reload,
            "__creates=(); __reverts=(/etc/caddy/Caddyfile)",
            true,
        ) else {
            return;
        };
        assert!(
            calls.contains("reload caddy") && !calls.contains("restart caddy"),
            "{calls}"
        );
        for changed in [CADDY_DROPIN, DNS_ENV] {
            let calls = run_reload_of(
                &g.reload,
                &format!("__creates=(); __reverts=({changed})"),
                true,
            )
            .unwrap();
            assert!(
                calls.contains("daemon-reload\n") && calls.contains("restart caddy"),
                "{calls}"
            );
            assert!(!calls.contains("reload caddy"), "{calls}");
        }
        // A new binary (the build sets the flag) also restarts.
        let calls = run_reload_of(
            &g.reload,
            "__creates=(); __reverts=(); __caddy_restart=1",
            true,
        )
        .unwrap();
        assert!(calls.contains("restart caddy"), "{calls}");
        // Rollback may have removed the drop-in: back to the packaged binary.
        let calls = run_reload_of(&g.reload, ":", true).unwrap();
        assert!(
            calls.contains("daemon-reload\n") && calls.contains("restart caddy"),
            "{calls}"
        );
    }

    #[test]
    fn rollback_restores_caddyfile_and_never_touches_certificates() {
        let decl = module(with_auth).declaration();
        let rollback = decl.render_rollback();
        assert!(rollback.contains("'/etc/caddy/Caddyfile'"));
        assert!(rollback.contains("caddy validate"));
        for s in [decl.render_probe(), decl.render_apply(), rollback] {
            assert!(!s.contains("/var/lib/caddy"), "certificates are off-limits");
        }
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let decl = module(|c| {
            with_auth(c);
            c.sites[0].allow = vec!["10.0.0.0/8".into()];
            c.ca = "internal".into();
            c.sites.push(c.sites[0].clone());
            c.sites[1].domain = "n.t.ts.net".into();
            c.sites[1].tls = "tailscale".into();
            c.sites.push(c.sites[0].clone());
            c.sites[2].domain = "dns.example.com".into();
            c.sites[2].basic_auth = None;
            dns(c);
        })
        .declaration();
        for s in [
            decl.render_probe(),
            decl.render_apply(),
            decl.render_rollback(),
        ] {
            let Ok(mut child) = Command::new("bash")
                .arg("-n")
                .stdin(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
            else {
                return;
            };
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(s.as_bytes()).expect("write");
            }
            assert!(child.wait().expect("bash").success(), "bash -n:\n{s}");
        }
    }

    /// The converge of the command described `what`, or None.
    fn converge_of(decl: &Declaration, what: &str) -> Option<String> {
        decl.commands
            .iter()
            .find(|c| c.describe == what)
            .map(|c| c.converge.clone())
    }

    #[test]
    fn entering_dns_mode_builds_and_writes_the_token_file() {
        let decl = module(dns).declaration();
        let apply = decl.render_apply();
        assert!(apply.contains("__cd_dir=\"$__rundir/caddy-build\""));
        assert!(apply.contains(&format!("__path={}", shell_escape(DNS_ENV))));
        assert!(apply.contains(&format!("__path={}", shell_escape(CADDY_DROPIN))));
        assert!(!apply.contains("no leftover DNS"), "{apply}");
        assert!(!apply.contains("__caddy_dns_gone"));
    }

    /// Leaving dns mode removes the build, unit drop-in, token file
    /// and their backups, then the guard restarts caddy on the apt binary.
    #[test]
    fn leaving_dns_mode_removes_build_dropin_and_token() {
        let decl = module(|_| {}).declaration();
        let apply = decl.render_apply();
        assert!(!apply.contains("caddy-build"), "{apply}");
        assert!(!apply.contains(&format!("__path={}", shell_escape(DNS_ENV))));
        let what = "no leftover DNS build, unit drop-in or token";
        let converge = converge_of(&decl, what).expect("leftover command");
        assert!(apply.contains(&converge));
        assert!(decl
            .render_probe()
            .contains("[ ! -e '/etc/caddy/anvil-dns.env' ]"));
        // Run it against real files under a temp root.
        let root = std::env::temp_dir().join(format!("anvil-caddy-gone-{}", std::process::id()));
        let r = root.display().to_string();
        let paths = [DNS_CADDY_BIN, CADDY_DROPIN, DNS_ENV];
        let mut setup = String::from("__anvil_forget() { echo \"$1\" >> \"$__forgot\"; }\n");
        setup.push_str(&format!("__forgot='{r}/forgot'\n"));
        let mut conv = converge.clone();
        for p in paths {
            let bak = format!("{r}{p}{BACKUP_SUFFIX}");
            setup.push_str(&format!(
                "mkdir -p \"$(dirname '{r}{p}')\"; : > '{r}{p}'; : > '{bak}'\n"
            ));
            conv = conv.replace(&shell_escape(p), &shell_escape(&format!("{r}{p}")));
            conv = conv.replace(
                &shell_escape(&format!("{p}{BACKUP_SUFFIX}")),
                &shell_escape(&bak),
            );
        }
        let reload = decl.reload.as_ref().unwrap().reload.clone();
        let prelude = format!("__creates=(); __reverts=()\n{setup}{conv}");
        let Some(calls) = run_reload_of(&reload, &prelude, true) else {
            return;
        };
        assert!(
            calls.contains("daemon-reload\nenable caddy\nis-active --quiet caddy\nrestart caddy"),
            "{calls}"
        );
        assert!(!calls.contains("tailscaled"), "{calls}");
        for p in paths {
            assert!(
                !std::path::Path::new(&format!("{r}{p}")).exists(),
                "{p} left"
            );
            assert!(!std::path::Path::new(&format!("{r}{p}{BACKUP_SUFFIX}")).exists());
        }
        let forgot = std::fs::read_to_string(root.join("forgot")).unwrap();
        assert_eq!(forgot.lines().count(), 6, "{forgot}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn leaving_tailscale_certs_removes_the_tailscaled_dropin() {
        assert!(converge_of(
            &module(tailnet).declaration(),
            "no leftover tailscaled cert drop-in"
        )
        .is_none());
        let decl = module(|_| {}).declaration();
        let converge = converge_of(&decl, "no leftover tailscaled cert drop-in").unwrap();
        assert!(
            converge.contains(&shell_escape(TAILSCALED_DROPIN)),
            "{converge}"
        );
        assert!(converge.ends_with("__caddy_ts_gone=1"));
        let reload = decl.reload.as_ref().unwrap().reload.clone();
        let Some(calls) = run_reload_of(
            &reload,
            "__creates=(); __reverts=()\n__caddy_ts_gone=1",
            true,
        ) else {
            return;
        };
        assert!(
            calls.ends_with("daemon-reload\n--no-block try-restart tailscaled\n"),
            "{calls}"
        );
        let calls = run_reload_of(&reload, ":", true).unwrap();
        assert!(
            !calls.contains("tailscaled"),
            "rollback never touches it: {calls}"
        );
    }
}
