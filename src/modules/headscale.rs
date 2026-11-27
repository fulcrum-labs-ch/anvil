//! The `headscale` module (R83): install a pinned, SHA-256-verified headscale (arch-selected at
//! runtime), write its `config.yaml` (+ optional ACL policy), a systemd unit,
//! and provision pre-auth keys; optionally run a pinned Headplane (web UI)
//! with its own `/etc/headplane/config.yaml`. Services are (re)started behind
//! a guarded reload, and only when their unit/config actually changed.
//!
//! Values that reach the shell — the pinned `version` and `.deb` SHA-256, and each pre-auth key's
//! `name`/`expiration`/`tags` used in `headscale` sub-commands — are passed through
//! [`shell_escape`] (R55). Everything else lives in base64-embedded file
//! content and cannot inject. The Headplane `cookie_secret` never leaves the
//! host: it is generated there on first apply and re-extracted from the
//! existing file on later ones (a [`crate::engine::FileContent::Computed`]
//! generator shared by probe and apply, so the two always agree).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::config::schema::{AuthKeySpec, HeadscaleSection};
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_FAILED,
};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::{containers, Module};
use crate::config::Engine;

/// Files this module owns (Fixed Contract for drift/rollback).
/// Pinned release and its `.deb` checksums (from the release's checksums.txt).
pub const DEFAULT_VERSION: &str = "0.23.0";
/// Every headscale CLI call runs as the service user: as root, `configtest`
/// (and any command that opens the state) creates `db.sqlite` and
/// `noise_private.key` root-owned, and `headscale serve` then cannot read them.
const HS: &str = "runuser -u headscale -- headscale";
const DEFAULT_SHA256_AMD64: &str =
    "3a610d3941de367a57b63b277054e02dee90084d3a6f6112a57709ec5cdd7b75";
const DEFAULT_SHA256_ARM64: &str =
    "d6f8e6562fa0efeba7c21df34148a7e7968cbcee0c3a3b247ef345db5a6e7b68";

/// Load-time check: pins are 64 hex, and a non-default `version` needs both.
pub fn validate_pins(c: &HeadscaleSection) -> Result<()> {
    for (f, v) in [
        ("sha256_amd64", &c.sha256_amd64),
        ("sha256_arm64", &c.sha256_arm64),
    ] {
        match v {
            Some(v) if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                return Err(AnvilError::Validation(format!(
                    "headscale.{f} = {v:?} must be 64 hex characters"
                )))
            }
            None if c.version != DEFAULT_VERSION => {
                return Err(AnvilError::Validation(format!(
                    "headscale.version = {:?} needs headscale.{f} (from the release's \
                     checksums.txt); only {DEFAULT_VERSION} is built in",
                    c.version
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

pub const CONFIG_PATH: &str = "/etc/headscale/config.yaml";
pub const ACL_PATH: &str = "/etc/headscale/acl.hujson";
pub const UNIT_PATH: &str = "/etc/systemd/system/headscale.service";
pub const HEADPLANE_UNIT_PATH: &str = "/etc/systemd/system/headplane.service";
pub const HEADPLANE_CONFIG_PATH: &str = "/etc/headplane/config.yaml";
/// Podman host: the Quadlet that generates the same `headplane.service`.
pub const HEADPLANE_QUADLET_PATH: &str = "/etc/containers/systemd/headplane.container";

/// Container image for the optional Headplane UI.
const HEADPLANE_IMAGE: &str = "ghcr.io/tale/headplane";
/// Default (pinned) Headplane image tag; overridable via `headplane_version`.
/// A floating "latest" is never the default.
const HEADPLANE_DEFAULT_VERSION: &str = "0.6.0";
/// Docker control socket mounted into the Headplane container so the UI can
/// manage the headscale integration.
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
/// Placeholder in the Headplane config template that the on-host generator
/// substitutes with the (generated or re-extracted) cookie secret.
const HEADPLANE_SECRET_PLACEHOLDER: &str = "__ANVIL_HEADPLANE_COOKIE_SECRET__";

pub struct HeadscaleModule {
    cfg: HeadscaleSection,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
    engine: Engine,
}

/// Escape a string as a YAML double-quoted scalar.
fn yaml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl HeadscaleModule {
    pub fn new(cfg: HeadscaleSection) -> Self {
        Self {
            cfg,
            docker_distro: false,
            engine: Engine::Docker,
        }
    }

    /// The host engine: on Podman, Headplane runs as a Quadlet.
    pub fn engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    fn podman(&self) -> bool {
        self.cfg.headplane && self.engine == Engine::Podman
    }

    /// `[docker] source = "distro"`: install the engine from Ubuntu's packages.
    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }

    /// The inline ACL policy to write, if any (an explicit `acl_policy_path`
    /// takes precedence and means we write nothing).
    fn inline_acl(&self) -> Option<&str> {
        let external = self
            .cfg
            .acl_policy_path
            .as_deref()
            .filter(|p| !p.is_empty());
        if external.is_some() {
            return None;
        }
        self.cfg.acl_policy.as_deref().filter(|p| !p.is_empty())
    }

    /// The path headscale should load its policy from, if configured.
    fn policy_path(&self) -> Option<String> {
        if let Some(p) = self
            .cfg
            .acl_policy_path
            .as_deref()
            .filter(|p| !p.is_empty())
        {
            return Some(p.to_string());
        }
        if self.inline_acl().is_some() {
            return Some(ACL_PATH.to_string());
        }
        None
    }

    /// Render `config.yaml`. The `server_url`/`listen_addr`/`db_path` values are
    /// the hardening contract (R83); the surrounding shape is ours.
    pub fn config_content(&self) -> String {
        let c = &self.cfg;
        let mut s = String::new();
        s.push_str("# Managed by anvil — do not edit by hand\n");
        s.push_str(&format!("server_url: {}\n", yaml_str(&c.server_url)));
        s.push_str(&format!("listen_addr: {}\n", yaml_str(&c.listen_addr)));
        s.push_str("metrics_listen_addr: \"127.0.0.1:9090\"\n");
        s.push_str("grpc_listen_addr: \"127.0.0.1:50443\"\n");
        s.push_str("grpc_allow_insecure: false\n\n");
        s.push_str("private_key_path: /var/lib/headscale/private.key\n");
        s.push_str("noise:\n");
        s.push_str("  private_key_path: /var/lib/headscale/noise_private.key\n\n");
        s.push_str("prefixes:\n");
        s.push_str("  v4: 100.64.0.0/10\n");
        s.push_str("  v6: fd7a:115c:a1e0::/48\n\n");
        s.push_str("database:\n");
        s.push_str("  type: sqlite\n");
        s.push_str("  sqlite:\n");
        s.push_str(&format!("    path: {}\n\n", yaml_str(&c.db_path)));
        // headscale has no default DERP map and exits with "initial DERPMap
        // is empty": Tailscale's public relays, refreshed daily.
        s.push_str("derp:\n");
        s.push_str("  server:\n");
        s.push_str("    enabled: false\n");
        s.push_str("  urls:\n");
        s.push_str("    - https://controlplane.tailscale.com/derpmap/default\n");
        s.push_str("  paths: []\n");
        s.push_str("  auto_update_enabled: true\n");
        s.push_str("  update_frequency: 24h\n\n");
        s.push_str("log:\n");
        s.push_str("  level: info\n\n");
        s.push_str("dns:\n");
        s.push_str("  magic_dns: true\n");
        s.push_str(&format!("  base_domain: {}\n", c.base_domain));
        if let Some(path) = self.policy_path() {
            s.push_str("\npolicy:\n");
            s.push_str("  mode: file\n");
            s.push_str(&format!("  path: {}\n", yaml_str(&path)));
        }
        s
    }

    /// The systemd unit running `headscale serve`. State and runtime dirs as
    /// upstream's unit: systemd makes them the `headscale` user's on every
    /// start (the `.deb` ships `/var/lib/headscale` root-owned; `/run` is
    /// empty after a reboot, and the default socket lives in it).
    pub fn unit_content(&self) -> String {
        "# Managed by anvil — do not edit by hand\n\
         [Unit]\n\
         Description=headscale coordination server (anvil-managed)\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         User=headscale\n\
         Group=headscale\n\
         ExecStart=/usr/bin/headscale serve\n\
         Restart=always\n\
         RestartSec=5\n\
         WorkingDirectory=/var/lib/headscale\n\
         StateDirectory=headscale\n\
         StateDirectoryMode=0750\n\
         RuntimeDirectory=headscale\n\
         RuntimeDirectoryMode=0750\n\
         AmbientCapabilities=CAP_NET_BIND_SERVICE\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
            .to_string()
    }

    /// The Headplane image tag: operator-pinned, or the module's pinned
    /// default — never a floating "latest".
    fn headplane_version(&self) -> &str {
        self.cfg
            .headplane_version
            .as_deref()
            .filter(|v| !v.is_empty())
            .unwrap_or(HEADPLANE_DEFAULT_VERSION)
    }

    /// Headplane's `config.yaml`, with the cookie secret as a placeholder the
    /// on-host generator substitutes (see [`Self::headplane_config_generator`]).
    fn headplane_config_template(&self) -> String {
        let c = &self.cfg;
        let cookie_secure = c.server_url.starts_with("https://");
        let mut s = String::new();
        s.push_str("# Managed by anvil — do not edit by hand\n");
        s.push_str("server:\n");
        // Inside the container: bind all interfaces on 3000, the target of
        // the unit's `-p <headplane_listen>:3000` (a 127.0.0.1 bind in here
        // would be unreachable through the published port).
        s.push_str("  host: \"0.0.0.0\"\n");
        s.push_str("  port: 3000\n");
        s.push_str(&format!(
            "  cookie_secret: \"{HEADPLANE_SECRET_PLACEHOLDER}\"\n"
        ));
        s.push_str(&format!("  cookie_secure: {cookie_secure}\n"));
        s.push_str("headscale:\n");
        s.push_str(&format!("  url: {}\n", yaml_str(&c.server_url)));
        s.push_str(&format!("  config_path: {}\n", yaml_str(CONFIG_PATH)));
        // Required by Headplane's schema (no default): without it Headplane
        // exits at load. Strict: a config it cannot validate only degrades it.
        s.push_str("  config_strict: true\n");
        if c.headplane_docker_socket {
            s.push_str("integration:\n");
            s.push_str("  docker:\n");
            s.push_str("    enabled: true\n");
            s.push_str(&format!(
                "    socket: {}\n",
                yaml_str(&format!("unix://{DOCKER_SOCKET}"))
            ));
        }
        s
    }

    /// On-host generator for [`HEADPLANE_CONFIG_PATH`]: re-extracts the
    /// existing `cookie_secret` when the file already holds one (so the
    /// secret survives re-applies and probe agrees with apply), otherwise
    /// generates 32 random alphanumerics from /dev/urandom. The rest of the
    /// config is base64-embedded, so config-derived values stay inert to the
    /// shell (R55).
    fn headplane_config_generator(&self) -> String {
        let b64 = B64.encode(self.headplane_config_template().as_bytes());
        format!(
            "__hp_secret=\"\"\n\
             if [ -f {path} ]; then\n\
             \x20 __hp_secret=$(sed -n 's/^  cookie_secret: \"\\([A-Za-z0-9]\\{{32\\}}\\)\".*$/\\1/p' {path} | head -n 1)\n\
             fi\n\
             if [ -z \"$__hp_secret\" ]; then\n\
             \x20 __hp_secret=$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 32)\n\
             fi\n\
             printf '%s' {b64} | base64 -d | sed \"s/{placeholder}/$__hp_secret/\"",
            path = HEADPLANE_CONFIG_PATH,
            b64 = shell_escape(&b64),
            placeholder = HEADPLANE_SECRET_PLACEHOLDER,
        )
    }

    /// systemd unit for the optional Headplane container, publishing its port
    /// as configured by `headplane_listen` and mounting its config (read-only).
    /// The docker socket (root-equivalent) is mounted only with
    /// `headplane_docker_socket = true`; `--userns=host` keeps it usable when
    /// `[docker] userns_remap` is on.
    fn headplane_unit_content(&self) -> String {
        let version = self.headplane_version();
        let listen = &self.cfg.headplane_listen;
        let socket = if self.cfg.headplane_docker_socket {
            format!(" \\\n  -v {DOCKER_SOCKET}:{DOCKER_SOCKET}")
        } else {
            String::new()
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Headplane UI (anvil-managed)\n\
             After=docker.service headscale.service network-online.target\n\
             Requires=docker.service\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             Restart=always\n\
             RestartSec=5\n\
             ExecStartPre=-/usr/bin/docker rm -f headplane\n\
             ExecStart=/usr/bin/docker run --rm --name headplane --userns=host \\\n\
             \x20 -p {listen}:3000 \\\n\
             \x20 -v {config}:{config}:ro \\\n\
             \x20 -v /etc/headscale:/etc/headscale:ro{socket} \\\n\
             \x20 {HEADPLANE_IMAGE}:{version}\n\
             ExecStop=/usr/bin/docker stop headplane\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            config = HEADPLANE_CONFIG_PATH,
        )
    }

    /// The Podman Quadlet: the Docker unit's `docker run` flags as keys
    /// (rootful Podman maps no user namespace by default). The Docker socket
    /// integration is refused on a Podman host at load.
    pub fn headplane_quadlet_content(&self) -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Headplane UI (anvil-managed)\n\
             After=headscale.service network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Container]\n\
             Image={HEADPLANE_IMAGE}:{version}\n\
             ContainerName=headplane\n\
             PublishPort={listen}:3000\n\
             Volume={config}:{config}:ro\n\
             Volume=/etc/headscale:/etc/headscale:ro\n\
             \n\
             [Service]\n\
             Restart=always\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            version = self.headplane_version(),
            listen = self.cfg.headplane_listen,
            config = HEADPLANE_CONFIG_PATH,
        )
    }

    /// Per-arch `.deb` checksums: configured, else built in for the default
    /// version; `validate_pins` guarantees one of the two.
    fn checksums(&self) -> (String, String) {
        let pick = |o: &Option<String>, d: &str| o.clone().unwrap_or_else(|| d.into());
        (
            pick(&self.cfg.sha256_amd64, DEFAULT_SHA256_AMD64),
            pick(&self.cfg.sha256_arm64, DEFAULT_SHA256_ARM64),
        )
    }

    /// Download, SHA-256-verify and install the pinned headscale `.deb`,
    /// selecting the release asset by the host's runtime architecture
    /// (amd64/arm64); anything else fails fast instead of 404-ing.
    fn install_command(&self) -> ManagedCommand {
        let ver = shell_escape(&self.cfg.version);
        let (amd64, arm64) = self.checksums();
        let (amd64, arm64) = (shell_escape(&amd64), shell_escape(&arm64));
        // Plain `grep -F` (not `-q`) reads all input, so it never closes the
        // pipe early and trips `pipefail` via SIGPIPE on the producer.
        let detect = format!("headscale version 2>/dev/null | grep -F -- {ver} >/dev/null 2>&1");
        let converge = format!(
            "__hs_ver={ver}\n\
             __hs_arch=$(dpkg --print-architecture)\n\
             case \"$__hs_arch\" in\n\
             \x20 amd64) __hs_sha={amd64} ;;\n\
             \x20 arm64) __hs_sha={arm64} ;;\n\
             \x20 *) printf '{MARK_FAILED} headscale: unsupported architecture %s (release .debs exist for amd64 and arm64 only)\\n' \"$__hs_arch\"; exit 1 ;;\n\
             esac\n\
             __hs_tmp=\"$(mktemp -p \"$__rundir\")\"\n\
             curl -fsSL -o \"$__hs_tmp\" \
             \"https://github.com/juanfont/headscale/releases/download/v${{__hs_ver}}/\
             headscale_${{__hs_ver}}_linux_${{__hs_arch}}.deb\"\n\
             if ! printf '%s  %s\\n' \"$__hs_sha\" \"$__hs_tmp\" | sha256sum -c --status -; then\n\
             \x20 rm -f \"$__hs_tmp\"\n\
             \x20 printf '{MARK_FAILED} headscale %s: SHA-256 mismatch, not installed\\n' \"$__hs_ver\"\n\
             \x20 exit 1\n\
             fi\n\
             dpkg -i \"$__hs_tmp\" || apt-get -f install -y\n\
             rm -f \"$__hs_tmp\""
        );
        ManagedCommand::new(
            format!("install headscale {}", self.cfg.version),
            detect,
            converge,
        )
    }

    /// Ensure the `headscale` system account and state/config directories exist.
    fn ensure_user(&self) -> ManagedCommand {
        ManagedCommand::new(
            "headscale system user and directories",
            // The .deb ships /var/lib/headscale as root:root and never chowns it.
            "id -u headscale >/dev/null 2>&1 && \
             [ \"$(stat -c %U:%G /var/lib/headscale 2>/dev/null)\" = headscale:headscale ] && \
             [ -z \"$(find /var/lib/headscale -mindepth 1 ! -user headscale ! -name 'preauth-*' -print -quit)\" ]",
            "getent group headscale >/dev/null 2>&1 || groupadd --system headscale\n\
             id -u headscale >/dev/null 2>&1 || useradd --system --gid headscale \
             --home-dir /var/lib/headscale --shell /usr/sbin/nologin headscale\n\
             install -d -m 0750 -o headscale -g headscale /var/lib/headscale\n\
             find /var/lib/headscale -mindepth 1 ! -user headscale ! -name 'preauth-*' \
             -exec chown headscale:headscale {} +\n\
             install -d -m 0755 /etc/headscale",
        )
    }

    fn ensure_docker(&self) -> ManagedCommand {
        crate::modules::ensure_engine(self.engine, self.docker_distro)
    }

    /// The probe-visible service check: drift when headscale is not active.
    /// The converge is a no-op because the guarded reload below is what
    /// actually starts the service — the config must be written first, and
    /// the reload's start-if-inactive branch keeps apply in agreement with
    /// this probe.
    fn service_active_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "headscale service active",
            "systemctl is-active --quiet headscale",
            ": # started by the guarded reload once config is in place",
        )
    }

    /// Build the guarded reload: start/restart headscale (restart only when
    /// its unit/config changed this run — changed-flag pattern over the
    /// engine's created/modified registers), wait for its socket, provision
    /// users + pre-auth keys idempotently, and likewise start/restart
    /// Headplane if enabled.
    fn reload_script(&self) -> String {
        let mut r = String::new();
        // Changed flags: scan the paths this apply created or modified so a
        // service is restarted only when a file it consumes changed.
        r.push_str("__hs_changed=0\n__hp_changed=0\n");
        r.push_str(&format!(
            "for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do\n\
             \x20 case \"$__p\" in\n\
             \x20\x20 {CONFIG_PATH}|{ACL_PATH}|{UNIT_PATH}) __hs_changed=1 ;;\n\
             \x20\x20 {HEADPLANE_CONFIG_PATH}|{HEADPLANE_UNIT_PATH}|{HEADPLANE_QUADLET_PATH}) __hp_changed=1 ;;\n\
             \x20 esac\n\
             done\n"
        ));
        r.push_str("systemctl daemon-reload\n");
        r.push_str("systemctl enable headscale >/dev/null 2>&1 || true\n");
        r.push_str(
            "if [ \"$__hs_changed\" = 1 ]; then\n\
             \x20 systemctl restart headscale\n\
             elif ! systemctl is-active --quiet headscale; then\n\
             \x20 systemctl start headscale\n\
             fi\n",
        );
        if !self.cfg.auth_keys.is_empty() {
            r.push_str(&format!(
                "for __i in $(seq 1 15); do {HS} users list >/dev/null 2>&1 && break; \
                 sleep 1; done\n"
            ));
            for k in &self.cfg.auth_keys {
                let name = shell_escape(&k.name);
                let marker = shell_escape(&key_path(&k.name));
                r.push_str(&format!(
                    "{HS} users list 2>/dev/null | awk -F'|' -v n={name} \
                     '{{gsub(/^[ \\t]+|[ \\t]+$/, \"\", $2)}} $2==n {{f=1}} END {{exit !f}}' \
                     || {HS} users create {name}\n"
                ));
                // Into a temp file first: a failed create never leaves a
                // marker that would pass the freshness check.
                r.push_str(&format!(
                    "if ! {fresh}; then\n\
                     \x20 {HS} preauthkeys create --user {name} {args} > {marker}.tmp\n\
                     \x20 mv -f {marker}.tmp {marker}\n\
                     \x20 printf '%s\\n' {spec} > {spec_path}\n\
                     fi\n",
                    fresh = key_fresh(k),
                    args = key_args(k),
                    spec = shell_escape(&key_args(k)),
                    spec_path = shell_escape(&spec_path(&k.name)),
                ));
            }
        }
        if self.cfg.headplane {
            r.push_str("systemctl enable headplane >/dev/null 2>&1 || true\n");
            r.push_str(
                "if [ \"$__hp_changed\" = 1 ]; then\n\
                 \x20 systemctl restart headplane\n\
                 elif ! systemctl is-active --quiet headplane; then\n\
                 \x20 systemctl start headplane\n\
                 fi",
            );
        }
        // Trim any trailing newline for a tidy script.
        while r.ends_with('\n') {
            r.pop();
        }
        r
    }
}

/// Where the pre-auth key for `name` is kept (fetch it for `[tailscale]`).
pub fn key_path(name: &str) -> String {
    format!("/var/lib/headscale/preauth-{name}.key")
}

/// The `create` flags the key was made with, so a changed spec re-creates it.
fn spec_path(name: &str) -> String {
    format!("/var/lib/headscale/preauth-{name}.spec")
}

/// Escaped `preauthkeys create` flags after `--user` (v0.23.0 syntax).
fn key_args(k: &AuthKeySpec) -> String {
    let mut a = format!("--expiration {}", shell_escape(&k.expiration));
    if k.reusable {
        a.push_str(" --reusable");
    }
    if k.ephemeral {
        a.push_str(" --ephemeral");
    }
    if !k.tags.is_empty() {
        a.push_str(&format!(" --tags {}", shell_escape(&k.tags.join(","))));
    }
    a
}

/// Read-only test: the key exists, is younger than its expiration and was
/// created with the current flags. Shared by probe and the reload.
fn key_fresh(k: &AuthKeySpec) -> String {
    let marker = shell_escape(&key_path(&k.name));
    // Load validation guarantees a parseable expiration of at least 1m.
    let minutes = k.expiration_secs().unwrap_or(0) / 60;
    format!(
        "{{ [ -s {marker} ] && [ -z \"$(find {marker} -mmin +{minutes} 2>/dev/null)\" ] \
         && [ \"$(cat {spec} 2>/dev/null)\" = {args} ]; }}",
        spec = shell_escape(&spec_path(&k.name)),
        args = shell_escape(&key_args(k)),
    )
}

impl Module for HeadscaleModule {
    fn id(&self) -> &'static str {
        "headscale"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("headscale")
            .command(self.install_command())
            .command(self.ensure_user());
        if self.cfg.headplane {
            let eng = if self.engine == Engine::Podman {
                "podman"
            } else {
                "docker"
            };
            let image = shell_escape(&format!("{HEADPLANE_IMAGE}:{}", self.headplane_version()));
            // Pulled before the (re)start, so the old image is released by it.
            decl = decl
                .command(self.ensure_docker())
                .command(ManagedCommand::new(
                    format!(
                        "headplane image {HEADPLANE_IMAGE}:{}",
                        self.headplane_version()
                    ),
                    format!("{eng} image inspect {image} >/dev/null 2>&1"),
                    format!("{eng} pull -q {image} >/dev/null"),
                ));
            decl =
                super::prune_superseded(decl, "headplane", eng, &format!("printf '%s\\n' {image}"));
        }
        decl = decl.command(self.service_active_command());
        for k in &self.cfg.auth_keys {
            decl = decl.command(ManagedCommand::new(
                format!("pre-auth key {} is current", k.name),
                key_fresh(k),
                ": # (re)created by the reload below, once headscale is up",
            ));
        }
        decl = decl.file(ManagedFile::new(
            CONFIG_PATH,
            self.config_content(),
            "0644",
            "root:root",
        ));
        if let Some(acl) = self.inline_acl() {
            decl = decl.file(ManagedFile::new(ACL_PATH, acl, "0644", "root:root"));
        }
        decl = decl.file(ManagedFile::new(
            UNIT_PATH,
            self.unit_content(),
            "0644",
            "root:root",
        ));
        if self.cfg.headplane {
            // The secret lives only on the host, so the config is computed
            // there; 0600 because it holds the session cookie secret.
            decl = decl.file(ManagedFile::computed(
                HEADPLANE_CONFIG_PATH,
                self.headplane_config_generator(),
                "0600",
                "root:root",
            ));
            decl = decl.file(if self.podman() {
                ManagedFile::new(
                    HEADPLANE_QUADLET_PATH,
                    self.headplane_quadlet_content(),
                    "0644",
                    "root:root",
                )
            } else {
                ManagedFile::new(
                    HEADPLANE_UNIT_PATH,
                    self.headplane_unit_content(),
                    "0644",
                    "root:root",
                )
            });
        }
        let mut validate = format!("{HS} configtest -c {CONFIG_PATH}");
        if self.podman() {
            validate.push_str(" && ");
            validate.push_str(&containers::quadlet_converts(
                HEADPLANE_QUADLET_PATH,
                "headplane.service",
            ));
        }
        if self.podman() {
            // Stop while the Quadlet exists (ExecStop removes the container).
            decl = decl.rollback_first(format!(
                "\n# rollback (before files): stop headplane\n\
                 if [ ! -f {q}{BACKUP_SUFFIX} ] && __anvil_created {q} && systemctl is-active --quiet headplane 2>/dev/null; then\n\
                 \x20 systemctl stop headplane >/dev/null 2>&1 || true\n\
                 \x20 printf 'CHANGED: headplane stopped\\n'\n\
                 fi\n",
                q = HEADPLANE_QUADLET_PATH,
            ));
        }
        let guard = ReloadGuard {
            describe: "headscale service".into(),
            validate,
            reload: self.reload_script(),
        };
        decl.guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::AuthKeySpec;
    use crate::engine::FileContent;

    fn base() -> HeadscaleSection {
        HeadscaleSection {
            version: DEFAULT_VERSION.into(),
            sha256_amd64: None,
            sha256_arm64: None,
            server_url: "https://hs.example.com".into(),
            listen_addr: "0.0.0.0:8080".into(),
            db_path: "/var/lib/headscale/db.sqlite".into(),
            base_domain: "headscale.internal".into(),
            acl_policy: None,
            acl_policy_path: None,
            auth_keys: Vec::new(),
            headplane: false,
            headplane_version: None,
            headplane_listen: "127.0.0.1:3000".into(),
            headplane_docker_socket: false,
            order_override: Default::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut HeadscaleSection)) -> HeadscaleModule {
        let mut cfg = base();
        mutate(&mut cfg);
        HeadscaleModule::new(cfg)
    }

    #[test]
    fn config_has_core_fields() {
        let conf = module(|_| {}).config_content();
        assert!(conf.contains("server_url: \"https://hs.example.com\""));
        assert!(conf.contains("listen_addr: \"0.0.0.0:8080\""));
        assert!(conf.contains("path: \"/var/lib/headscale/db.sqlite\""));
        // No policy block when none is configured.
        assert!(!conf.contains("policy:"));
        // Without a DERP map headscale 0.23 refuses to serve (live test).
        assert!(conf.contains(
            "derp:\n  server:\n    enabled: false\n  urls:\n    \
             - https://controlplane.tailscale.com/derpmap/default\n  paths: []\n  \
             auto_update_enabled: true\n  update_frequency: 24h\n"
        ));
        assert!(conf.contains("  base_domain: headscale.internal\n"));
        let custom = module(|c| c.base_domain = "ts.example.net".into()).config_content();
        assert!(
            custom.contains("  base_domain: ts.example.net\n"),
            "{custom}"
        );
    }

    #[test]
    fn inline_acl_is_written_and_referenced() {
        let m = module(|c| c.acl_policy = Some("{ \"acls\": [] }".into()));
        let conf = m.config_content();
        assert!(conf.contains("policy:"));
        assert!(conf.contains(&format!("path: \"{ACL_PATH}\"")));
        let decl = m.declaration();
        let acl = decl.files.iter().find(|f| f.path == ACL_PATH);
        assert!(acl.is_some(), "inline ACL file must be declared");
    }

    #[test]
    fn external_acl_path_wins_and_writes_no_file() {
        let m = module(|c| {
            c.acl_policy = Some("ignored".into());
            c.acl_policy_path = Some("/etc/headscale/custom.hujson".into());
        });
        let conf = m.config_content();
        assert!(conf.contains("path: \"/etc/headscale/custom.hujson\""));
        let decl = m.declaration();
        assert!(
            decl.files.iter().all(|f| f.path != ACL_PATH),
            "must not write the inline ACL file when a path is given"
        );
    }

    /// Run the real install converge with stub `curl` (writes "hello") and
    /// `dpkg` (arch `$arch`; `-i` logs INSTALLED).
    fn run_install(m: &HeadscaleModule, arch: &str) -> String {
        let stubs = format!(
            "curl() {{ printf hello > \"$3\"; }}\n\
             dpkg() {{ [ \"$1\" = --print-architecture ] && echo {arch} || echo INSTALLED; }}\n\
             apt-get() {{ :; }}\n"
        );
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("{stubs}{}", m.install_command().converge))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn deb_is_checksum_verified_before_install() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains(DEFAULT_SHA256_AMD64) && apply.contains(DEFAULT_SHA256_ARM64));
        let check = apply.find("sha256sum -c --status -").unwrap();
        assert!(check < apply.find("dpkg -i").unwrap(), "verify before dpkg");
        if std::process::Command::new("sha256sum")
            .arg("--version")
            .output()
            .is_err()
        {
            return; // no coreutils sha256sum on this machine
        }
        // sha256("hello"): the configured pin matches, so dpkg runs.
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let m = module(|c| {
            c.sha256_amd64 = Some(good.into());
            c.sha256_arm64 = Some("0".repeat(64));
        });
        assert_eq!(run_install(&m, "amd64"), "INSTALLED\n");
        // Fail closed: mismatch on arm64, and the built-in pin on amd64.
        let out = run_install(&m, "arm64");
        assert!(
            out.contains("FAILED: headscale 0.23.0: SHA-256 mismatch")
                && !out.contains("INSTALLED"),
            "{out}"
        );
        let out = run_install(&module(|_| {}), "amd64");
        assert!(
            out.contains("SHA-256 mismatch") && !out.contains("INSTALLED"),
            "{out}"
        );
    }

    #[test]
    fn validate_pins_requires_hashes_off_the_default_version() {
        let hex = "a".repeat(64);
        assert!(validate_pins(&base()).is_ok());
        let mut c = base();
        c.version = "0.24.1".into();
        let e = validate_pins(&c).unwrap_err().to_string();
        assert!(e.contains("headscale.sha256_amd64"), "{e}");
        c.sha256_amd64 = Some(hex.clone());
        let e = validate_pins(&c).unwrap_err().to_string();
        assert!(e.contains("headscale.sha256_arm64"), "{e}");
        c.sha256_arm64 = Some(hex.clone());
        assert!(validate_pins(&c).is_ok());
        c.sha256_arm64 = Some("g".repeat(64));
        assert!(validate_pins(&c).is_err(), "non-hex");
        c.sha256_arm64 = Some("a".repeat(63));
        assert!(validate_pins(&c).is_err(), "short");
    }

    #[test]
    fn install_pins_version_in_url_and_detect() {
        let apply = module(|c| c.version = "0.24.1".into())
            .declaration()
            .render_apply();
        assert!(apply.contains("grep -F -- '0.24.1'"));
        assert!(apply.contains("__hs_ver='0.24.1'"));
        assert!(apply.contains("releases/download/v${__hs_ver}/"));
    }

    #[test]
    fn docker_engine_is_keyring_pinned_not_pipe_to_shell() {
        // The headplane container host installs docker from a keyring-pinned
        // apt repo, never get.docker.com | sh. (ensure_docker runs only when
        // headplane is enabled.)
        let apply = module(|c| c.headplane = true).declaration().render_apply();
        assert!(
            !apply.contains("get.docker.com"),
            "no pipe-to-shell:\n{apply}"
        );
        assert!(
            apply
                .match_indices("| sh")
                .all(|(i, _)| apply[i..].starts_with("| sha256sum")),
            "no pipe-to-sh:\n{apply}"
        );
        assert!(apply.contains("signed-by=/etc/apt/keyrings/docker.asc"));
        // The distro id is a printf *argument*, never inside the format.
        assert!(apply.contains("download.docker.com/linux/%s %s stable"));
        assert!(apply.contains("\"$ID\" \"$VERSION_CODENAME\""));
    }

    #[test]
    fn preauth_keys_are_provisioned_idempotently_and_escaped() {
        let apply = module(|c| {
            c.auth_keys = vec![
                AuthKeySpec {
                    name: "ci".into(),
                    reusable: true,
                    expiration: "24h".into(),
                    tags: Vec::new(),
                    ephemeral: false,
                },
                AuthKeySpec {
                    name: "laptop".into(),
                    reusable: false,
                    expiration: "90d".into(),
                    tags: Vec::new(),
                    ephemeral: false,
                },
            ];
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("runuser -u headscale -- headscale users create 'ci'"));
        // Never as root: that creates db.sqlite / noise_private.key root-owned
        // and serve cannot read them (the live test).
        for sub in ["configtest", "users ", "preauthkeys "] {
            let all = apply.matches(&format!("headscale {sub}")).count();
            let as_user = apply.matches(&format!("{HS} {sub}")).count();
            assert!(
                all > 0 && all == as_user,
                "{sub}: {as_user}/{all} as headscale"
            );
        }
        assert!(apply.contains("--user 'ci' --expiration '24h' --reusable >"));
        assert!(apply.contains("--user 'laptop' --expiration '90d' >"));
        // Not reusable => no flag.
        assert!(!apply.contains("--user 'laptop' --expiration '90d' --reusable"));
        // Idempotency guards.
        assert!(apply.contains("awk -F'|' -v n='ci'"));
        assert!(apply.contains("preauth-ci.key"));
    }

    #[test]
    fn preauth_key_tags_ephemeral_and_rotation() {
        let key = AuthKeySpec {
            name: "srv".into(),
            reusable: true,
            expiration: "1h30m".into(),
            tags: vec!["tag:server".into(), "tag:prod".into()],
            ephemeral: true,
        };
        let d = module(|c| c.auth_keys = vec![key.clone()]).declaration();
        let apply = d.render_apply();
        assert!(
            apply.contains("--user 'srv' --expiration '1h30m' --reusable --ephemeral --tags 'tag:server,tag:prod' >"),
            "{apply}"
        );
        // Stale after 90 minutes; the probe sees it (read-only).
        let probe = d.render_probe();
        assert!(
            probe.contains("find '/var/lib/headscale/preauth-srv.key' -mmin +90"),
            "{probe}"
        );
        assert!(!probe.contains("preauthkeys create"));

        // Behaviour of the shared freshness test on a real directory.
        let dir = std::env::temp_dir().join(format!("anvil-hs-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fresh = |spec: &str| {
            let t = key_fresh(&key).replace("/var/lib/headscale", &dir.to_string_lossy());
            let _ = std::fs::write(dir.join("preauth-srv.spec"), spec);
            std::process::Command::new("bash")
                .args(["-c", &t])
                .status()
                .is_ok_and(|s| s.success())
        };
        assert!(!fresh(&key_args(&key)), "no key yet");
        std::fs::write(dir.join("preauth-srv.key"), "k").unwrap();
        assert!(
            fresh(&format!("{}\n", key_args(&key))),
            "new key, same spec"
        );
        assert!(!fresh("--expiration '1h30m'\n"), "flags changed");
        let old = std::process::Command::new("touch")
            .args([
                "-d",
                "-2 hours",
                &dir.join("preauth-srv.key").to_string_lossy(),
            ])
            .status()
            .is_ok_and(|s| s.success());
        if old {
            assert!(!fresh(&format!("{}\n", key_args(&key))), "expired");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn user_lookup_matches_the_exact_name_column() {
        // An existing `web-prod` must not satisfy the lookup for `web`.
        // Runs the rendered users-list line against a stubbed `headscale`.
        let apply = module(|c| {
            c.auth_keys = vec![AuthKeySpec {
                name: "web".into(),
                reusable: false,
                expiration: "1h".into(),
                tags: Vec::new(),
                ephemeral: false,
            }];
        })
        .declaration()
        .render_apply();
        let line = apply
            .lines()
            .find(|l| l.contains("headscale users list 2>/dev/null"))
            .expect("user lookup line")
            .trim();
        let run = |table: &str| {
            let script = format!(
                "runuser() {{ shift 3; \"$@\"; }}\nheadscale() {{ if [ \"$1\" = users ] && [ \"$2\" = list ]; then printf '%s' {t}; else echo CREATED; fi; }}\n{line}\n",
                t = shell_escape(table)
            );
            let out = std::process::Command::new("bash")
                .args(["-c", &script])
                .output()
                .expect("run bash");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let header = "ID | Name     | Created\n";
        assert!(run(&format!("{header}1  | web-prod | 2024\n")).contains("CREATED"));
        assert!(
            !run(&format!("{header}1  | web-prod | 2024\n2  | web | 2024\n")).contains("CREATED")
        );
    }

    #[test]
    fn hostile_auth_key_name_is_neutralized() {
        let apply = module(|c| {
            c.auth_keys = vec![AuthKeySpec {
                name: "x'; reboot #".into(),
                reusable: false,
                expiration: "1h".into(),
                tags: Vec::new(),
                ephemeral: false,
            }];
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("'x'\\''; reboot #'"));
        assert!(!apply.contains("create x'; reboot"));
    }

    #[test]
    fn headplane_is_opt_in() {
        let off = module(|_| {}).declaration();
        assert!(off.files.iter().all(|f| f.path != HEADPLANE_UNIT_PATH));
        assert!(off.files.iter().all(|f| f.path != HEADPLANE_CONFIG_PATH));

        let m = module(|c| {
            c.headplane = true;
            c.headplane_version = Some("0.5.0".into());
        });
        let decl = m.declaration();
        let hp = decl
            .files
            .iter()
            .find(|f| f.path == HEADPLANE_UNIT_PATH)
            .expect("headplane unit present when enabled");
        // Image + port live in the unit file content (base64-embedded in apply).
        let hp_content = hp.static_content().expect("static unit content");
        assert!(hp_content.contains("ghcr.io/tale/headplane:0.5.0"));
        assert!(hp_content.contains("-p 127.0.0.1:3000:3000"));
        // The restart is a command, so it is literal in the apply script.
        assert!(decl.render_apply().contains("systemctl restart headplane"));
    }

    #[test]
    fn install_selects_deb_by_runtime_arch() {
        let apply = module(|_| {}).declaration().render_apply();
        // The asset name comes from `dpkg --print-architecture`, never a
        // hardcoded platform literal.
        assert!(apply.contains("dpkg --print-architecture"));
        assert!(apply.contains("linux_${__hs_arch}.deb"));
        assert!(!apply.contains("linux_amd64"), "no hardcoded amd64 asset");
        // Anything but amd64/arm64 fails fast with a clear message.
        assert!(apply.contains("amd64) __hs_sha=") && apply.contains("arm64) __hs_sha="));
        assert!(apply.contains("unsupported architecture"));
    }

    #[test]
    fn headplane_version_is_pinned_by_default() {
        let m = module(|c| c.headplane = true);
        let unit = m.headplane_unit_content();
        assert!(unit.contains("ghcr.io/tale/headplane:0.6.0"));
        assert!(!unit.contains("latest"), "no floating default tag");
        // Operator override still wins.
        let pinned = module(|c| {
            c.headplane = true;
            c.headplane_version = Some("0.7.1".into());
        });
        assert!(pinned
            .headplane_unit_content()
            .contains("ghcr.io/tale/headplane:0.7.1"));
    }

    #[test]
    fn headplane_config_template_has_required_keys() {
        let m = module(|c| {
            c.headplane = true;
            c.headplane_listen = "127.0.0.1:8443".into();
            c.headplane_docker_socket = true;
        });
        let t = m.headplane_config_template();
        assert!(t.contains("server:"));
        // In-container bind is fixed: the unit publishes <listen> → :3000.
        assert!(t.contains("host: \"0.0.0.0\""));
        assert!(t.contains("port: 3000\n"));
        assert!(m
            .headplane_unit_content()
            .contains("-p 127.0.0.1:8443:3000"));
        assert!(t.contains(&format!(
            "cookie_secret: \"{HEADPLANE_SECRET_PLACEHOLDER}\""
        )));
        assert!(t.contains("url: \"https://hs.example.com\""));
        // Headplane 0.6 requires it (no default) and exits without it.
        assert!(t.contains(&format!(
            "  config_path: \"{CONFIG_PATH}\"\n  config_strict: true\n"
        )));
        assert!(t.contains("integration:"));
        assert!(t.contains("enabled: true"));
        assert!(t.contains(&format!("socket: \"unix://{DOCKER_SOCKET}\"")));
    }

    #[test]
    fn headplane_cookie_secret_is_generated_once_and_reused() {
        let m = module(|c| c.headplane = true);
        let decl = m.declaration();
        let cfg_file = decl
            .files
            .iter()
            .find(|f| f.path == HEADPLANE_CONFIG_PATH)
            .expect("headplane config declared when enabled");
        assert_eq!(cfg_file.mode, "0600", "holds a secret");
        let generator = match &cfg_file.content {
            FileContent::Computed { generator } => generator,
            other => panic!("must be computed on the host, got {other:?}"),
        };
        // Re-use path: the existing secret is extracted from the current file…
        assert!(generator.contains(&format!("if [ -f {HEADPLANE_CONFIG_PATH} ]")));
        assert!(generator.contains("cookie_secret"));
        // …and only when absent is a fresh 32-char alphanumeric one generated.
        assert!(generator.contains("if [ -z \"$__hp_secret\" ]"));
        assert!(generator.contains("/dev/urandom"));
        assert!(generator.contains("tr -dc 'A-Za-z0-9'"));
        assert!(generator.contains("head -c 32"));
        // Probe and apply share the exact same materialization, so drift
        // checks agree with what apply would write.
        let assignment = format!("__desired=$({generator})");
        assert!(decl.render_probe().contains(&assignment));
        assert!(decl.render_apply().contains(&assignment));
    }

    #[test]
    fn headplane_unit_mounts_config_and_docker_socket() {
        let m = module(|c| {
            c.headplane = true;
            c.headplane_docker_socket = true;
        });
        let unit = m.headplane_unit_content();
        assert!(unit.contains(&format!(
            "-v {HEADPLANE_CONFIG_PATH}:{HEADPLANE_CONFIG_PATH}:ro"
        )));
        assert!(unit.contains(&format!("-v {DOCKER_SOCKET}:{DOCKER_SOCKET}")));
        assert!(unit.contains("--userns=host"));
    }

    #[test]
    fn headplane_has_no_docker_socket_by_default() {
        let m = module(|c| c.headplane = true);
        assert!(!m.headplane_unit_content().contains(DOCKER_SOCKET));
        let t = m.headplane_config_template();
        assert!(!t.contains("integration:") && !t.contains(DOCKER_SOCKET));
    }

    #[test]
    fn headplane_image_is_pulled_and_pruned_by_the_host_engine() {
        for (engine, eng, other) in [
            (Engine::Docker, "docker", "podman"),
            (Engine::Podman, "podman", "docker"),
        ] {
            let d = module(|c| c.headplane = true).engine(engine).declaration();
            let pull = d
                .commands
                .iter()
                .find(|c| c.describe.starts_with("headplane image "))
                .unwrap();
            assert!(
                pull.converge.starts_with(&format!("{eng} pull -q ")),
                "{}",
                pull.converge
            );
            assert!(!pull.detect.contains(other));
            assert!(d
                .commands
                .iter()
                .any(|c| c.describe == "superseded headplane images removed"));
        }
    }

    #[test]
    fn headplane_runs_as_a_quadlet_on_podman() {
        let m = module(|c| {
            c.headplane = true;
            c.headplane_listen = "127.0.0.1:8443".into();
        })
        .engine(Engine::Podman);
        let q = m.headplane_quadlet_content();
        for needle in [
            "Image=ghcr.io/tale/headplane:0.6.0\n",
            "ContainerName=headplane\n",
            "PublishPort=127.0.0.1:8443:3000\n",
            &format!("Volume={HEADPLANE_CONFIG_PATH}:{HEADPLANE_CONFIG_PATH}:ro\n"),
            "Volume=/etc/headscale:/etc/headscale:ro\n",
            "After=headscale.service",
            "Restart=always\n",
        ] {
            assert!(q.contains(needle), "missing {needle:?}");
        }
        assert!(!q.contains("docker"));
        let d = m.declaration();
        assert!(d.files.iter().any(|f| f.path == HEADPLANE_QUADLET_PATH));
        assert!(d.files.iter().all(|f| f.path != HEADPLANE_UNIT_PATH));
        let g = d.reload.as_ref().unwrap();
        assert!(g.validate.starts_with(&format!("{HS} configtest")));
        assert!(g.validate.contains("---headplane.service---"));
        let apply = d.render_apply();
        assert!(apply.contains("a Podman host needs Podman >= 4.4"));
        assert!(!apply.contains("download.docker.com"));
        // Same service name: the reload's restart logic is unchanged.
        assert!(apply.contains("systemctl restart headplane"));
        let rb = d.render_rollback();
        let stop = rb.find("systemctl stop headplane").unwrap();
        let rm = rb
            .find(&format!("# rollback: {HEADPLANE_QUADLET_PATH}"))
            .unwrap();
        assert!(stop < rm, "stopped while the Quadlet exists:\n{rb}");
        assert!(rb.contains(&format!("__anvil_created {HEADPLANE_QUADLET_PATH}")));
        assert!(!module(|c| c.headplane = true)
            .declaration()
            .render_rollback()
            .contains("systemctl stop headplane"));
        // Without headplane, Podman changes nothing.
        let plain = module(|_| {}).engine(Engine::Podman).declaration();
        assert!(!plain.reload.unwrap().validate.contains("quadlet"));
    }

    #[test]
    fn service_restarts_are_gated_on_change() {
        let apply = module(|c| c.headplane = true).declaration().render_apply();
        // The reload derives per-service changed flags from the engine's
        // created/modified registers…
        assert!(apply.contains("for __p in \"${__creates[@]:-}\" \"${__reverts[@]:-}\""));
        assert!(apply.contains(&format!(
            "{CONFIG_PATH}|{ACL_PATH}|{UNIT_PATH}) __hs_changed=1"
        )));
        assert!(apply.contains(&format!(
            "{HEADPLANE_CONFIG_PATH}|{HEADPLANE_UNIT_PATH}|{HEADPLANE_QUADLET_PATH}) __hp_changed=1"
        )));
        // …and each restart runs only under its flag, else start-if-inactive.
        assert!(apply.contains("if [ \"$__hs_changed\" = 1 ]"));
        assert!(apply.contains("elif ! systemctl is-active --quiet headscale"));
        assert!(apply.contains("if [ \"$__hp_changed\" = 1 ]"));
        assert!(apply.contains("elif ! systemctl is-active --quiet headplane"));
    }

    #[test]
    fn probe_requires_active_service() {
        let decl = module(|_| {}).declaration();
        let probe = decl.render_probe();
        assert!(probe.contains("systemctl is-active --quiet headscale"));
        // The probe stays read-only: the matching converge is a no-op that
        // defers to the guarded reload.
        assert!(!probe.contains("systemctl start"));
        assert!(!probe.contains("systemctl restart"));
    }

    #[test]
    fn unit_and_guard_reference_the_service() {
        let decl = module(|_| {}).declaration();
        let apply = decl.render_apply();
        assert!(apply.contains(UNIT_PATH));
        assert!(apply.contains("systemctl restart headscale"));
        // The guard really validates the config, not just its presence.
        assert!(apply.contains(&format!("headscale configtest -c {CONFIG_PATH}")));
        assert!(!apply.contains(&format!("test -s {CONFIG_PATH}")));
    }

    #[test]
    fn state_dir_belongs_to_headscale() {
        // The .deb ships /var/lib/headscale root-owned: serve could not
        // create noise_private.key and restarted forever (the live test).
        let m = module(|_| {});
        assert!(m.unit_content().contains(
            "StateDirectory=headscale\nStateDirectoryMode=0750\n\
             RuntimeDirectory=headscale\nRuntimeDirectoryMode=0750\n"
        ));
        let user = m.ensure_user();
        assert!(user.detect.contains(
            "[ \"$(stat -c %U:%G /var/lib/headscale 2>/dev/null)\" = headscale:headscale ]"
        ));
        assert!(user
            .converge
            .contains("install -d -m 0750 -o headscale -g headscale /var/lib/headscale"));
    }
}
