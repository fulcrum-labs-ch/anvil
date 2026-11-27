//! Per-module configuration sections.
//!
//! **Fixed Contract:** every TOML section name and field name in this file is a
//! public config key taken verbatim from the spec. The Rust *type* names are
//! this implementation's own choice.
//!
//! Each section also accepts a nested `order_override` table
//! (`order`/`before`/`after`) consumed by the ordering resolver.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Ordering hints a section may carry. Nested under `order_override`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrderOverride {
    /// Explicit absolute order key; lower runs earlier.
    pub order: Option<i64>,
    /// Module ids this section must run before.
    #[serde(default)]
    pub before: Vec<String>,
    /// Module ids this section must run after.
    #[serde(default)]
    pub after: Vec<String>,
}

// --- small default helpers --------------------------------------------------

fn t() -> bool {
    true
}
pub(super) fn d_ssh_port() -> u16 {
    22
}

// --- [sshd] (R23) -----------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshdSection {
    #[serde(default = "t")]
    pub disable_root_login: bool,
    #[serde(default = "t")]
    pub disable_password_auth: bool,
    #[serde(default = "t")]
    pub disable_empty_passwords: bool,
    #[serde(default = "d_ssh_port")]
    pub port: u16,
    #[serde(default = "SshdSection::d_max_auth_tries")]
    pub max_auth_tries: u8,
    #[serde(default = "SshdSection::d_login_grace_time")]
    pub login_grace_time: u16,
    #[serde(default = "SshdSection::d_client_alive_interval")]
    pub client_alive_interval: u16,
    #[serde(default = "SshdSection::d_client_alive_count_max")]
    pub client_alive_count_max: u8,
    #[serde(default)]
    pub allow_users: Vec<String>,
    /// Hardened by default: enabling `[sshd]` should not silently keep weak
    /// ciphers.
    #[serde(default = "t")]
    pub strong_ciphers: bool,
    /// X11 forwarding is a lateral-movement channel; off by default (schema
    /// only — module wiring lands in a later phase).
    #[serde(default = "t")]
    pub disable_x11_forwarding: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl SshdSection {
    fn d_max_auth_tries() -> u8 {
        3
    }
    fn d_login_grace_time() -> u16 {
        30
    }
    fn d_client_alive_interval() -> u16 {
        300
    }
    fn d_client_alive_count_max() -> u8 {
        2
    }
}

impl Default for SshdSection {
    fn default() -> Self {
        Self {
            disable_root_login: true,
            disable_password_auth: true,
            disable_empty_passwords: true,
            port: 22,
            max_auth_tries: 3,
            login_grace_time: 30,
            client_alive_interval: 300,
            client_alive_count_max: 2,
            allow_users: Vec::new(),
            strong_ciphers: true,
            disable_x11_forwarding: true,
            order_override: OrderOverride::default(),
        }
    }
}

// --- [firewall] (R24) -------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WallRule {
    pub port: String,
    #[serde(default)]
    pub proto: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSection {
    #[serde(default = "FirewallSection::d_incoming")]
    pub default_incoming: String,
    #[serde(default = "FirewallSection::d_outgoing")]
    pub default_outgoing: String,
    #[serde(default = "t")]
    pub restrict_ssh: bool,
    #[serde(default)]
    pub allow: Vec<WallRule>,
    #[serde(default)]
    pub deny: Vec<WallRule>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl FirewallSection {
    fn d_incoming() -> String {
        "deny".into()
    }
    fn d_outgoing() -> String {
        "allow".into()
    }
}

// --- [fail2ban] (R25) -------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JailDef {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub maxretry: Option<u8>,
    #[serde(default)]
    pub bantime: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fail2banSection {
    #[serde(default = "Fail2banSection::d_bantime")]
    pub bantime: String,
    #[serde(default = "Fail2banSection::d_findtime")]
    pub findtime: String,
    #[serde(default = "Fail2banSection::d_maxretry")]
    pub maxretry: u8,
    #[serde(default)]
    pub jails: BTreeMap<String, JailDef>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl Fail2banSection {
    fn d_bantime() -> String {
        "10m".into()
    }
    fn d_findtime() -> String {
        "10m".into()
    }
    fn d_maxretry() -> u8 {
        5
    }
}

// --- [updates] (R26) --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdatesSection {
    #[serde(default = "t")]
    pub security_only: bool,
    #[serde(default)]
    pub auto_reboot: bool,
    #[serde(default = "UpdatesSection::d_reboot_time")]
    pub reboot_time: String,
    #[serde(default)]
    pub remove_unused_deps: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl UpdatesSection {
    fn d_reboot_time() -> String {
        "02:00".into()
    }
}

// --- [users] (R27) ----------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    #[serde(default)]
    pub sudo: bool,
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default)]
    pub ssh_authorized_keys: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UsersSection {
    #[serde(default)]
    pub create: Vec<Account>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [kernel] (R28) ---------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelSection {
    #[serde(default = "t")]
    pub harden_network: bool,
    #[serde(default = "t")]
    pub restrict_dmesg: bool,
    #[serde(default = "t")]
    pub restrict_kernel_pointers: bool,
    /// Opt-in (default off): disabling IPv6 breaks dual-stack hosts, so the
    /// operator must ask for it explicitly.
    #[serde(default)]
    pub disable_ipv6: bool,
    #[serde(default)]
    pub extra_sysctl: BTreeMap<String, String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [kernel_modules] (R29) -------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelModulesSection {
    #[serde(default = "t")]
    pub blacklist_filesystems: bool,
    #[serde(default = "t")]
    pub blacklist_squashfs: bool,
    #[serde(default = "t")]
    pub blacklist_vfat: bool,
    #[serde(default = "t")]
    pub blacklist_usb_storage: bool,
    #[serde(default = "t")]
    pub blacklist_network_protocols: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [ssh_crypto] (R30) -----------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SshCryptoSection {
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [suid] (R31) -----------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SuidSection {
    #[serde(default)]
    pub extra_whitelist: Vec<String>,
    #[serde(default = "SuidSection::d_scan_paths")]
    pub scan_paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl SuidSection {
    /// Scan the whole filesystem by default — a setuid binary dropped outside
    /// the system paths is exactly the kind the scan must catch (module-side
    /// pruning of pseudo-filesystems lands in a later phase).
    fn d_scan_paths() -> Vec<String> {
        vec!["/".into()]
    }
}

// --- [dns] (R32) ------------------------------------------------------------

/// Presence of `[dns]` gives a working hardened resolver out of the box:
/// Quad9 (primary) plus Cloudflare, over TLS.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsSection {
    #[serde(default = "DnsSection::d_dns_servers")]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub fallback_servers: Vec<String>,
    #[serde(default)]
    pub dnssec_strict: bool,
    #[serde(default = "t")]
    pub dns_over_tls: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl DnsSection {
    fn d_dns_servers() -> Vec<String> {
        vec![
            "9.9.9.9".into(),
            "149.112.112.112".into(),
            "1.1.1.1".into(),
            "1.0.0.1".into(),
        ]
    }
}

impl Default for DnsSection {
    fn default() -> Self {
        Self {
            dns_servers: Self::d_dns_servers(),
            fallback_servers: Vec::new(),
            dnssec_strict: false,
            dns_over_tls: true,
            order_override: OrderOverride::default(),
        }
    }
}

// --- [process] (R33) --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSection {
    #[serde(default = "t")]
    pub disable_core_dumps: bool,
    #[serde(default = "t")]
    pub disable_sysrq: bool,
    #[serde(default = "ProcessSection::d_pass_max_days")]
    pub pass_max_days: u32,
    #[serde(default = "ProcessSection::d_pass_min_days")]
    pub pass_min_days: u32,
    #[serde(default = "ProcessSection::d_pass_warn_age")]
    pub pass_warn_age: u32,
    #[serde(default)]
    pub hidepid: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl ProcessSection {
    fn d_pass_max_days() -> u32 {
        365
    }
    fn d_pass_min_days() -> u32 {
        1
    }
    fn d_pass_warn_age() -> u32 {
        7
    }
}

// --- [pam] (R34) ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PamSection {
    #[serde(default = "PamSection::d_minlen")]
    pub minlen: u32,
    #[serde(default = "t")]
    pub require_uppercase: bool,
    #[serde(default = "t")]
    pub require_lowercase: bool,
    #[serde(default = "t")]
    pub require_digit: bool,
    #[serde(default = "t")]
    pub require_special: bool,
    #[serde(default = "t")]
    pub enable_faillock: bool,
    #[serde(default = "PamSection::d_deny")]
    pub deny: u32,
    #[serde(default = "PamSection::d_unlock_time")]
    pub unlock_time: u32,
    #[serde(default = "PamSection::d_umask")]
    pub umask: String,
    #[serde(default = "PamSection::d_tmout")]
    pub tmout: u32,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl PamSection {
    fn d_minlen() -> u32 {
        14
    }
    fn d_deny() -> u32 {
        5
    }
    fn d_unlock_time() -> u32 {
        900
    }
    fn d_umask() -> String {
        "027".into()
    }
    fn d_tmout() -> u32 {
        900
    }
}

// --- [packages] (R35) -------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackagesSection {
    #[serde(default)]
    pub install: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [crowdsec] (R36) -------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdsecSection {
    /// A CrowdSec install without collections detects nothing; default to the
    /// baseline Linux + sshd scenarios.
    #[serde(default = "CrowdsecSection::d_collections")]
    pub collections: Vec<String>,
    /// Firewall backend for the bouncer. Unset: the distro package picks the
    /// one matching the system (nftables on nf_tables, iptables on legacy).
    #[serde(default)]
    pub bouncer_mode: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl CrowdsecSection {
    fn d_collections() -> Vec<String> {
        vec!["crowdsecurity/linux".into(), "crowdsecurity/sshd".into()]
    }
}

// --- [auditd] (R37) ---------------------------------------------------------

/// The rule sets the auditd module actually ships. Single source of truth:
/// config validation admits exactly these names, and `auditd::rule_body`
/// must have a body for each (pinned by a test in `modules/auditd.rs`) —
/// adding a name here without a body cannot ship silently.
pub const AUDITD_RULE_SETS: &[&str] = &["cis-level1"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditdSection {
    #[serde(default = "AuditdSection::d_rule_set")]
    pub rule_set: String,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl AuditdSection {
    fn d_rule_set() -> String {
        "cis-level1".into()
    }
}

// --- [lynis] (R38) ----------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LynisSection {
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [filesystem] (R39) -----------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSection {
    #[serde(default = "t")]
    pub tmp_noexec: bool,
    #[serde(default = "t")]
    pub check_sticky_bits: bool,
    #[serde(default = "t")]
    pub check_world_writable: bool,
    #[serde(default)]
    pub aide_baseline: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [docker] (R40) ---------------------------------------------------------

/// Presence of `[docker]` hardens by default: both daemon keys are on unless
/// explicitly disabled. `None` = defaulted (on): the docker probe refuses to
/// flip a defaulted `userns_remap` on a host that already has images.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DockerSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iptables_off: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userns_remap: Option<bool>,
    #[serde(default)]
    pub rootless: bool,
    /// `live-restore`: containers keep running while dockerd restarts (e.g.
    /// on a daemon.json change). Not compatible with Swarm mode.
    #[serde(default = "t")]
    pub live_restore: bool,
    /// Where the engine comes from when a module installs it: `"vendor"`
    /// (Docker's keyring-pinned apt repo, default) or `"distro"` (Ubuntu's
    /// `docker.io` + `docker-compose-v2`; `FAILED:` on other distros). An
    /// installed engine is never switched.
    #[serde(default = "DockerSection::d_source")]
    pub source: String,
    /// `"json-file"` (default; capped at 10m × 3 per container) or
    /// `"journald"` (containers log to the journal, capped by journald).
    /// Reaches containers created after dockerd restarts.
    #[serde(default = "DockerSection::d_log_driver")]
    pub log_driver: String,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl DockerSection {
    pub fn iptables_off(&self) -> bool {
        self.iptables_off.unwrap_or(true)
    }
    pub fn userns_remap(&self) -> bool {
        self.userns_remap.unwrap_or(true)
    }
    fn d_source() -> String {
        "vendor".into()
    }
    fn d_log_driver() -> String {
        "json-file".into()
    }
    /// `source = "distro"`, the only alternative to the vendor repo.
    pub fn distro(&self) -> bool {
        self.source == "distro"
    }
}

impl Default for DockerSection {
    fn default() -> Self {
        Self {
            iptables_off: None,
            userns_remap: None,
            rootless: false,
            live_restore: true,
            source: Self::d_source(),
            log_driver: Self::d_log_driver(),
            order_override: OrderOverride::default(),
        }
    }
}

/// `[podman]`: marks a Podman host and caps container logs (the counterpart
/// of `[docker]`'s daemon.json log limits).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PodmanSection {
    /// `"k8s-file"` (default; `podman logs` reads it, capped at 10 MiB per
    /// container) or `"journald"` (capped by journald's own limits).
    #[serde(default = "PodmanSection::d_log_driver")]
    pub log_driver: String,
    /// Where Podman comes from: `"distro"` (the only source; Podman >= 4.4).
    #[serde(default = "PodmanSection::d_source")]
    pub source: String,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl PodmanSection {
    fn d_log_driver() -> String {
        "k8s-file".into()
    }
    fn d_source() -> String {
        "distro".into()
    }
}

impl Default for PodmanSection {
    fn default() -> Self {
        Self {
            log_driver: Self::d_log_driver(),
            source: Self::d_source(),
            order_override: OrderOverride::default(),
        }
    }
}

// --- [containers] -----------------------------------------------------------

/// Container workloads: Docker Compose projects (`runtime = "docker"`, the
/// default) or Podman Quadlet `.container` units (`runtime = "podman"`), each
/// run by its own systemd unit.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainersSection {
    /// `"docker"` or `"podman"` (Quadlets; refused per host below Podman
    /// 4.4). Unset: the host engine (`"podman"` with `[podman]`, else Docker).
    #[serde(default)]
    pub runtime: Option<String>,
    /// Project name → project. The name is a path segment, a unit name and the
    /// compose project name (validated: lowercase, digits, `-`, `_`).
    #[serde(default)]
    pub compose: BTreeMap<String, ComposeProject>,
    /// Name → Quadlet `.container` unit (`runtime = "podman"` only).
    #[serde(default)]
    pub quadlet: BTreeMap<String, QuadletContainer>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComposeProject {
    /// The compose file, verbatim. anvil does **not** expand `${VAR}` here:
    /// docker compose resolves it on the host from the project's `.env`.
    /// `file = "<path>"` in the TOML is read into this at load (CR16).
    pub content: String,
    /// Written to the project's `.env` (0600). Values *are* expanded from the
    /// operator's environment at load, so secrets stay out of the config file.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl ContainersSection {
    /// `runtime = "podman"` set explicitly (see `Config::host_engine`).
    pub fn is_podman(&self) -> bool {
        self.runtime.as_deref() == Some("podman")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuadletContainer {
    /// The `.container` file, verbatim (`[Container]`, `[Install]`, …).
    pub content: String,
}

// --- [forgejo] --------------------------------------------------------------

/// A Forgejo git forge: the pinned upstream binary under systemd (or the
/// digest-pinned rootless image under Docker Compose), HTTP on 127.0.0.1
/// only, git over SSH via Forgejo's built-in server on `ssh_port`.
/// Secrets come from `${ENV}` and are written to 0640 files, never to app.ini.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForgejoSection {
    /// Public hostname; `ROOT_URL = https://<domain>/`.
    pub domain: String,
    #[serde(default = "ForgejoSection::d_version")]
    pub version: String,
    /// Required when `version` is not the built-in default.
    #[serde(default)]
    pub sha256_amd64: Option<String>,
    #[serde(default)]
    pub sha256_arm64: Option<String>,
    /// `"native"` (binary + systemd), `"compose"` (Docker Compose) or
    /// `"quadlet"` (Podman).
    #[serde(default = "ForgejoSection::d_deploy")]
    pub deploy: String,
    /// `sha256:<hex>` of the `<version>-rootless` image index; compose mode,
    /// required when `version` is not the built-in default.
    #[serde(default)]
    pub image_digest: Option<String>,
    /// `ssh_port` reachability: `"public"` or `"tailnet"` (tailscale0 only).
    #[serde(default = "ForgejoSection::d_listen")]
    pub listen: String,
    #[serde(default = "ForgejoSection::d_http_port")]
    pub http_port: u16,
    /// Built-in SSH server port; 0 disables git over SSH.
    #[serde(default = "ForgejoSection::d_ssh_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub require_signin_view: bool,
    /// Forgejo Actions; always written explicitly (upstream defaults to on).
    #[serde(default)]
    pub actions: bool,
    /// `sqlite3` or `postgres` (an existing server; anvil does not install it).
    #[serde(default = "ForgejoSection::d_database")]
    pub database: String,
    #[serde(default = "ForgejoSection::d_db_host")]
    pub db_host: String,
    #[serde(default = "ForgejoSection::d_forgejo")]
    pub db_name: String,
    #[serde(default = "ForgejoSection::d_forgejo")]
    pub db_user: String,
    #[serde(default)]
    pub db_password: Option<String>,
    #[serde(default = "ForgejoSection::d_db_ssl_mode")]
    pub db_ssl_mode: String,
    pub secret_key: String,
    pub internal_token: String,
    /// base64url (no padding) of 32 bytes: `forgejo generate secret JWT_SECRET`.
    pub jwt_secret: String,
    #[serde(default)]
    pub admin_username: Option<String>,
    #[serde(default)]
    pub admin_email: Option<String>,
    #[serde(default)]
    pub admin_password: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl ForgejoSection {
    fn d_version() -> String {
        crate::modules::forgejo::DEFAULT_VERSION.into()
    }
    fn d_deploy() -> String {
        "native".into()
    }
    fn d_listen() -> String {
        "public".into()
    }
    fn d_http_port() -> u16 {
        3000
    }
    fn d_ssh_port() -> u16 {
        2222
    }
    fn d_database() -> String {
        "sqlite3".into()
    }
    fn d_db_host() -> String {
        "127.0.0.1:5432".into()
    }
    fn d_forgejo() -> String {
        "forgejo".into()
    }
    fn d_db_ssl_mode() -> String {
        "disable".into()
    }
}

// --- [tls] (R41) ------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSection {
    #[serde(default = "TlsSection::d_provider")]
    pub provider: String,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub webroot: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl TlsSection {
    fn d_provider() -> String {
        "certbot".into()
    }
}

// --- [hetzner] (R42) --------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudEdgeRule {
    pub direction: String,
    pub protocol: String,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default)]
    pub source_ips: Vec<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HetznerSection {
    #[serde(default)]
    pub server_name: String,
    #[serde(default = "HetznerSection::d_firewall_name")]
    pub firewall_name: String,
    #[serde(default)]
    pub rules: Vec<CloudEdgeRule>,
    /// Add the R61 SSH-from-anywhere guard rules (T10). `false` only with
    /// `[tailscale] tailnet_only_ssh = true` (validated).
    #[serde(default = "t")]
    pub keep_public_ssh: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl HetznerSection {
    fn d_firewall_name() -> String {
        "anvil".into()
    }
}

// --- [netcup] (T12) ---------------------------------------------------------

/// The netcup SCP firewall: one anvil-owned user policy, attached to the
/// server's public interface. Rules reuse the hetzner shape (all ACCEPT).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetcupSection {
    /// SCP server id (digits) or server name/nickname.
    #[serde(default)]
    pub server: String,
    /// Name of the user firewall policy anvil owns (created if absent).
    #[serde(default = "HetznerSection::d_firewall_name")]
    pub policy: String,
    #[serde(default)]
    pub rules: Vec<CloudEdgeRule>,
    /// Add the R61 SSH-from-anywhere guard rules, as for `[hetzner]` (T10).
    #[serde(default = "t")]
    pub keep_public_ssh: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [headscale] (R43) ------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthKeySpec {
    pub name: String,
    #[serde(default)]
    pub reusable: bool,
    /// Pre-auth key lifetime; a short default is the safe one. The key is
    /// re-created once it is older than this.
    #[serde(default = "AuthKeySpec::d_expiration")]
    pub expiration: String,
    /// ACL tags given to nodes that join with this key (`tag:server`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Nodes joining with this key are removed once they go offline.
    #[serde(default)]
    pub ephemeral: bool,
}

impl AuthKeySpec {
    fn d_expiration() -> String {
        "24h".into()
    }

    /// `expiration` in seconds, parsed like headscale's (Prometheus) duration:
    /// one or more `<n><unit>`, largest first, units `y w d h m s` (`"1h30m"`).
    pub fn expiration_secs(&self) -> Option<u64> {
        let mut rest = self.expiration.as_str();
        let mut total: u64 = 0;
        let mut last = u64::MAX;
        if rest.is_empty() {
            return None;
        }
        while !rest.is_empty() {
            let digits = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            let n: u64 = rest[..digits].parse().ok()?;
            let unit = rest[digits..].chars().next()?;
            let mult = match unit {
                'y' => 365 * 86_400,
                'w' => 7 * 86_400,
                'd' => 86_400,
                'h' => 3_600,
                'm' => 60,
                's' => 1,
                _ => return None,
            };
            // Largest unit first, each once (as Prometheus requires).
            if mult >= last {
                return None;
            }
            last = mult;
            total = total.checked_add(n.checked_mul(mult)?)?;
            rest = &rest[digits + 1..];
        }
        Some(total)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeadscaleSection {
    #[serde(default = "HeadscaleSection::d_version")]
    pub version: String,
    /// `.deb` checksums; built in for the default version, required otherwise.
    #[serde(default)]
    pub sha256_amd64: Option<String>,
    #[serde(default)]
    pub sha256_arm64: Option<String>,
    #[serde(default)]
    pub server_url: String,
    #[serde(default = "HeadscaleSection::d_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "HeadscaleSection::d_db_path")]
    pub db_path: String,
    /// MagicDNS suffix for node names (`<node>.<base_domain>`). Must not
    /// contain `server_url`'s host.
    #[serde(default = "HeadscaleSection::d_base_domain")]
    pub base_domain: String,
    #[serde(default)]
    pub acl_policy: Option<String>,
    #[serde(default)]
    pub acl_policy_path: Option<String>,
    #[serde(default)]
    pub auth_keys: Vec<AuthKeySpec>,
    #[serde(default)]
    pub headplane: bool,
    #[serde(default)]
    pub headplane_version: Option<String>,
    #[serde(default = "HeadscaleSection::d_headplane_listen")]
    pub headplane_listen: String,
    /// Mount the docker socket for Headplane's docker integration. Off by
    /// default: the socket is root-equivalent on the host.
    #[serde(default)]
    pub headplane_docker_socket: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl HeadscaleSection {
    fn d_version() -> String {
        crate::modules::headscale::DEFAULT_VERSION.into()
    }
    fn d_listen_addr() -> String {
        "0.0.0.0:8080".into()
    }
    fn d_db_path() -> String {
        "/var/lib/headscale/db.sqlite".into()
    }
    fn d_base_domain() -> String {
        "headscale.internal".into()
    }
    fn d_headplane_listen() -> String {
        "127.0.0.1:3000".into()
    }
}

// --- [tailscale] (R44) ------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TailscaleSection {
    #[serde(default)]
    pub login_server: String,
    #[serde(default)]
    pub auth_key: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub accept_routes: bool,
    #[serde(default)]
    pub tailnet_only_ssh: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

// --- [greptimedb] (R45) -----------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GreptimedbSection {
    #[serde(default = "GreptimedbSection::d_http_port")]
    pub http_port: u16,
    #[serde(default = "GreptimedbSection::d_grpc_port")]
    pub grpc_port: u16,
    #[serde(default = "GreptimedbSection::d_mysql_port")]
    pub mysql_port: u16,
    #[serde(default = "GreptimedbSection::d_postgres_port")]
    pub postgres_port: u16,
    #[serde(default = "GreptimedbSection::d_data_dir")]
    pub data_dir: String,
    #[serde(default = "GreptimedbSection::d_listen_address")]
    pub listen_address: String,
    #[serde(default = "GreptimedbSection::d_version")]
    pub version: String,
    /// TTL set on every database at apply, e.g. `"30d"`
    /// (`<n>h`/`d`/`w`; needs `version` >= v0.12). Unset: TTLs untouched.
    #[serde(default)]
    pub retention: Option<String>,
    /// Container memory limit, e.g. `"2G"` (K/M/G/T). Unset: none.
    #[serde(default)]
    pub memory_max: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl GreptimedbSection {
    fn d_http_port() -> u16 {
        4000
    }
    fn d_grpc_port() -> u16 {
        4001
    }
    fn d_mysql_port() -> u16 {
        4002
    }
    fn d_postgres_port() -> u16 {
        4003
    }
    fn d_data_dir() -> String {
        "/var/lib/greptimedb".into()
    }
    fn d_listen_address() -> String {
        "127.0.0.1".into()
    }
    fn d_version() -> String {
        "v1.3.0".into()
    }
}

// --- [vector] (R46) ---------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VectorSection {
    /// GreptimeDB runs loopback-bound on the same host by default (R85).
    #[serde(default = "VectorSection::d_host")]
    pub greptimedb_host: String,
    #[serde(default = "VectorSection::d_grpc_port")]
    pub greptimedb_grpc_port: u16,
    #[serde(default = "VectorSection::d_http_port")]
    pub greptimedb_http_port: u16,
    /// GreptimeDB's default database name.
    #[serde(default = "VectorSection::d_db_name")]
    pub db_name: String,
    #[serde(default)]
    pub extra_log_files: Vec<String>,
    #[serde(default = "VectorSection::d_scrape_interval")]
    pub scrape_interval_secs: u16,
    /// Cgroups whose CPU/memory are collected (globs on the path below
    /// /sys/fs/cgroup). Default: Docker containers, `ci.slice` (CI),
    /// user slices. `[]`: every cgroup.
    #[serde(default = "VectorSection::d_cgroups_include")]
    pub cgroups_include: Vec<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl VectorSection {
    fn d_host() -> String {
        "127.0.0.1".into()
    }
    fn d_grpc_port() -> u16 {
        4001
    }
    fn d_http_port() -> u16 {
        4000
    }
    fn d_db_name() -> String {
        "public".into()
    }
    fn d_scrape_interval() -> u16 {
        15
    }
    fn d_cgroups_include() -> Vec<String> {
        [
            "system.slice/docker-*.scope",
            "ci.slice/**",
            "apps.slice/**",
            "user.slice/user-*.slice",
            "system.slice/*.service",
        ]
        .map(String::from)
        .to_vec()
    }
}

// --- [caddy] ------------------------------------------------------------------

/// Caddy reverse proxy with automatic HTTPS (docs/design/caddy.md).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaddySection {
    /// ACME account contact.
    #[serde(default)]
    pub email: Option<String>,
    /// `public` (Caddy's default CAs), `staging` (Let's Encrypt staging) or
    /// `internal` (Caddy's local CA).
    #[serde(default = "CaddySection::d_ca")]
    pub ca: String,
    #[serde(default = "CaddySection::d_http_port")]
    pub http_port: u16,
    #[serde(default = "CaddySection::d_https_port")]
    pub https_port: u16,
    #[serde(default = "t")]
    pub hsts: bool,
    /// `public` (ports open to all) or `tailnet` (ports on `tailscale0` only).
    #[serde(default = "CaddySection::d_listen")]
    pub listen: String,
    /// `[[caddy.site]]` tables.
    #[serde(default, rename = "site")]
    pub sites: Vec<CaddySite>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl CaddySection {
    fn d_ca() -> String {
        "public".into()
    }
    fn d_http_port() -> u16 {
        80
    }
    fn d_https_port() -> u16 {
        443
    }
    fn d_listen() -> String {
        "public".into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaddySite {
    pub domain: String,
    /// `host:port` of the local service, e.g. `127.0.0.1:3000`.
    pub upstream: String,
    /// Client IPs/CIDRs allowed in; empty = everyone.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub basic_auth: Option<CaddyBasicAuth>,
    /// `acme` (the `ca` above), `tailscale` (a `*.ts.net` name, cert from
    /// tailscaled) or `dns` (ACME DNS-01 via `dns_provider`).
    #[serde(default = "CaddySite::d_tls")]
    pub tls: String,
    /// `tls = "dns"`: provider name, e.g. `infomaniak`.
    #[serde(default)]
    pub dns_provider: Option<String>,
    /// `tls = "dns"`: provider API token; pass it as `${ENV}`.
    #[serde(default)]
    pub dns_token: Option<String>,
}

impl CaddySite {
    fn d_tls() -> String {
        "acme".into()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaddyBasicAuth {
    pub user: String,
    /// Output of `caddy hash-password`; pass it as `${ENV}`.
    pub password_hash: String,
}

// --- [beszel] ---------------------------------------------------------------

/// Beszel monitoring: the **agent** (default) and/or the **hub** (web UI).
/// With both on one machine the agent listens on loopback and trusts the
/// local hub's key. A remote agent either dials the hub (`hub_url` + `token`,
/// nothing listens) or is dialed on a firewalled `listen_port`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BeszelSection {
    #[serde(default = "BeszelSection::d_version")]
    pub version: String,
    /// SHA-256 per release tarball (`"beszel-agent_linux_amd64.tar.gz" = "…"`),
    /// required for a non-default `version`; the default's are built in.
    #[serde(default)]
    pub sha256: BTreeMap<String, String>,
    /// Run the agent on this machine.
    #[serde(default = "t")]
    pub agent: bool,
    /// Run the hub on this machine.
    #[serde(default)]
    pub hub: bool,
    /// Hub HTTP address (`IP:port`); loopback by default.
    #[serde(default = "BeszelSection::d_hub_listen")]
    pub hub_listen: String,
    /// Addresses (IP or CIDR) allowed to reach a non-loopback `hub_listen`.
    #[serde(default)]
    pub hub_allow_from: Vec<String>,
    /// The hub's SSH public key (`ssh-ed25519 AAAA…`), shown in the hub's
    /// "Add system" dialog. Public, but may still come from `${ENV}`.
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub hub_url: String,
    /// Registration token — a secret; use `"${BESZEL_TOKEN}"`.
    #[serde(default)]
    pub token: String,
    #[serde(default = "BeszelSection::d_listen_port")]
    pub listen_port: u16,
    /// Addresses (IP or CIDR) allowed to reach `listen_port`.
    #[serde(default)]
    pub hub_addresses: Vec<String>,
    /// The hub's first admin, created when the hub first starts on an empty
    /// database (so no visitor can claim it). Requires `admin_password`.
    #[serde(default)]
    pub admin_email: String,
    /// A secret; use `"${BESZEL_ADMIN_PASSWORD}"`.
    #[serde(default)]
    pub admin_password: String,
    /// Agent: container stats via the `docker` group (root-equivalent).
    #[serde(default)]
    pub docker: bool,
    /// Agent: SMART data via smartctl, the `disk` group and `CAP_SYS_RAWIO`.
    #[serde(default)]
    pub smart: bool,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl BeszelSection {
    fn d_version() -> String {
        crate::modules::beszel::DEFAULT_VERSION.into()
    }
    fn d_listen_port() -> u16 {
        45876
    }
    fn d_hub_listen() -> String {
        "127.0.0.1:8090".into()
    }
    /// Outbound WebSocket mode: the agent dials the hub, nothing listens.
    pub fn outbound(&self) -> bool {
        !self.hub_url.is_empty()
    }
}

// --- [restic] ---------------------------------------------------------------

/// Scheduled restic backups (see docs/design/restic.md). `password` and the
/// `env` values are secrets: supply them as `${ENV}` references. `Debug`
/// redacts them.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResticSection {
    /// restic repository URL: a local path, `sftp:`, `s3:`, `b2:`, `rest:`, …
    pub repository: String,
    pub password: String,
    /// Extra environment for the backend, e.g. `AWS_ACCESS_KEY_ID`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "ResticSection::d_paths")]
    pub paths: Vec<String>,
    /// Extra exclude patterns, appended to the built-in defaults.
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "t")]
    pub default_excludes: bool,
    /// Back up `/var/lib/docker/volumes` (the rest of `/var/lib/docker` stays excluded).
    #[serde(default)]
    pub docker_volumes: bool,
    /// systemd `OnCalendar=` expression.
    #[serde(default = "ResticSection::d_schedule")]
    pub schedule: String,
    #[serde(default = "ResticSection::d_keep_daily")]
    pub keep_daily: u32,
    #[serde(default = "ResticSection::d_keep_weekly")]
    pub keep_weekly: u32,
    #[serde(default = "ResticSection::d_keep_monthly")]
    pub keep_monthly: u32,
    #[serde(default)]
    pub keep_yearly: u32,
    /// `check` reports drift when the newest snapshot is older than this.
    #[serde(default = "ResticSection::d_max_age_hours")]
    pub max_age_hours: u32,
    /// Absolute paths of executables run (as `ExecStartPre=`) before each backup.
    #[serde(default)]
    pub pre_backup: Vec<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl std::fmt::Debug for ResticSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResticSection")
            .field("repository", &self.repository)
            .field("password", &"<redacted>")
            .field("env", &self.env.keys().collect::<Vec<_>>())
            .field("paths", &self.paths)
            .field("schedule", &self.schedule)
            .finish_non_exhaustive()
    }
}

impl ResticSection {
    fn d_paths() -> Vec<String> {
        [
            "/etc",
            "/home",
            "/root",
            "/srv",
            "/opt",
            "/usr/local",
            "/var/lib",
            "/var/spool",
            "/var/backups",
        ]
        .map(String::from)
        .to_vec()
    }
    fn d_schedule() -> String {
        "daily".into()
    }
    fn d_keep_daily() -> u32 {
        7
    }
    fn d_keep_weekly() -> u32 {
        4
    }
    fn d_keep_monthly() -> u32 {
        6
    }
    fn d_max_age_hours() -> u32 {
        36
    }
}

// --- [github_runner] --------------------------------------------------------

/// Self-hosted GitHub Actions runners (docs/design/github-actions-runner.md).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRunnerSection {
    /// `false` registers with `--disableupdate`: GitHub then stops queueing
    /// jobs 30 days after a newer runner release unless you re-apply.
    #[serde(default = "t")]
    pub auto_update: bool,
    /// `"none"`, `"group"` (runner user joins `docker` = root-equivalent, Docker
    /// host) or `"podman"` (rootless Podman as the runner user, Podman host).
    #[serde(default = "GithubRunnerSection::d_docker")]
    pub docker: String,
    /// Wipe checkouts after every job (keeps `_actions`/`_tool` caches).
    #[serde(default = "t")]
    pub clean_workspace: bool,
    /// Optional `http(s)://` proxy for all runner traffic.
    #[serde(default)]
    pub proxy: String,
    /// Override anvil's pinned runner version; requires `sha256`.
    #[serde(default)]
    pub version: Option<String>,
    /// SHA-256 of the tarball for `version` and this host's architecture.
    #[serde(default)]
    pub sha256: Option<String>,
    /// systemd `CPUQuota=` for each runner and its jobs, e.g. `"400%"` = 4 cores.
    #[serde(default)]
    pub cpu_quota: Option<String>,
    /// systemd `MemoryMax=` (`"8G"`): jobs past it are OOM-killed, not the host.
    #[serde(default)]
    pub memory_max: Option<String>,
    /// systemd `TasksMax=`: processes/threads per runner.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// GR23: cap each runner's `_work` on its own loop-mounted ext4 volume of
    /// this size (`"150G"`, G/T suffix). Never resized once created.
    #[serde(default)]
    pub disk_max: Option<String>,
    /// GR23: a daily timer deletes `_diag/*.log` older than this many days.
    #[serde(default = "GithubRunnerSection::d_diag_retention_days")]
    pub diag_retention_days: u32,
    /// The daily timer wipes a runner's HOME caches (`~/.cache`,
    /// `~/.cargo`, `~/.rustup`, `~/.npm`) past this size while it is idle.
    /// Default `"20G"`.
    #[serde(default)]
    pub home_cache_max: Option<String>,
    /// Runner name → runner. The name is a directory, unit and GitHub name.
    #[serde(default)]
    pub runners: BTreeMap<String, GithubRunner>,
    /// GR9: `"persistent"` (v1) or `"ephemeral"` (one job per sysbox
    /// sandbox, minted with a GitHub App). The fields below are ephemeral-only.
    #[serde(default = "GithubRunnerSection::d_mode")]
    pub mode: String,
    #[serde(default)]
    pub app_id: Option<u64>,
    #[serde(default)]
    pub installation_id: Option<u64>,
    /// The App's private key (PEM); use `"${GITHUB_APP_KEY}"`.
    #[serde(default)]
    pub app_key: Option<String>,
    #[serde(default)]
    pub runner_group_id: Option<u64>,
    /// Sandboxes waiting or running at once, per runner (default 1).
    #[serde(default)]
    pub capacity: Option<u32>,
    /// `docker run --cpus` per sandbox (default `"2"`).
    #[serde(default)]
    pub sandbox_cpus: Option<String>,
    /// `docker run --memory` per sandbox (default `"4g"`).
    #[serde(default)]
    pub sandbox_memory: Option<String>,
    /// `docker run --pids-limit` per sandbox (default 2048).
    #[serde(default)]
    pub sandbox_pids: Option<u32>,
    /// Capped volume per sandbox for its Docker data and `_work` (default `"40G"`).
    #[serde(default)]
    pub sandbox_disk: Option<String>,
    /// Sandbox runtime: `"docker-rootless"` (default on a Docker host: a
    /// privileged sandbox in its slot user's rootless dockerd), `"sysbox-runc"`,
    /// or `"podman"` (default on a Podman host).
    #[serde(default)]
    pub sandbox_runtime: Option<String>,
    /// Apt packages baked into the sandbox image, e.g. `["build-essential"]`.
    #[serde(default)]
    pub sandbox_packages: Vec<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl GithubRunnerSection {
    fn d_docker() -> String {
        "none".into()
    }

    fn d_mode() -> String {
        "persistent".into()
    }

    pub fn ephemeral(&self) -> bool {
        self.mode == "ephemeral"
    }

    pub fn capacity(&self) -> u32 {
        self.capacity.unwrap_or(1)
    }

    pub fn sandbox_cpus(&self) -> &str {
        self.sandbox_cpus.as_deref().unwrap_or("2")
    }

    pub fn sandbox_memory(&self) -> &str {
        self.sandbox_memory.as_deref().unwrap_or("4g")
    }

    pub fn sandbox_pids(&self) -> u32 {
        self.sandbox_pids.unwrap_or(2048)
    }

    /// The runtime on a host of `engine` ([`Config::host_engine`]).
    pub fn sandbox_runtime(&self, engine: super::Engine) -> &str {
        let default = match engine {
            // A per-slot rootless dockerd; sysbox only when asked for.
            super::Engine::Docker => "docker-rootless",
            super::Engine::Podman => "podman",
        };
        self.sandbox_runtime.as_deref().unwrap_or(default)
    }

    pub fn sandbox_disk(&self) -> &str {
        self.sandbox_disk.as_deref().unwrap_or("40G")
    }

    fn d_diag_retention_days() -> u32 {
        14
    }

    /// `home_cache_max` in bytes (default 20G); `None` when invalid.
    pub fn home_cache_max_bytes(&self) -> Option<u64> {
        size_bytes(self.home_cache_max.as_deref().unwrap_or(HOME_CACHE_MAX))
    }

    /// `disk_max` in bytes ([`size_bytes`]), `None` when unset or invalid.
    pub fn disk_max_bytes(&self) -> Option<u64> {
        size_bytes(self.disk_max.as_deref()?)
    }
}

/// Default `home_cache_max` of both runner sections.
pub const HOME_CACHE_MAX: &str = "20G";

/// `"150G"` / `"1T"` in bytes (`truncate -s` units: G = 2^30), `None` unless
/// a positive whole number of G or T.
pub fn size_bytes(s: &str) -> Option<u64> {
    let (n, shift) = match s.strip_suffix('G') {
        Some(n) => (n, 30),
        None => (s.strip_suffix('T')?, 40),
    };
    // `parse` alone would take "+5".
    if !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse::<u64>()
        .ok()
        .filter(|&n| n > 0)?
        .checked_mul(1u64 << shift)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubRunner {
    /// `https://github.com/<org>` or `https://github.com/<org>/<repo>`.
    pub url: String,
    /// One-hour registration token, needed only to (re-)register.
    #[serde(default)]
    pub token: String,
    /// One-hour remove token; lets `rollback` deregister the runner.
    #[serde(default)]
    pub remove_token: String,
    #[serde(default)]
    pub labels: Vec<String>,
    /// Runner group (org runners only).
    #[serde(default)]
    pub group: String,
}

// --- [ci_resources] ---------------------------------------------------------

/// One systemd slice, `ci.slice`, holding every CI runner unit: the
/// total share of the host for all CI work (GR22).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CiResourcesSection {
    /// systemd `CPUQuota=` for all CI work, e.g. `"800%"` = 8 cores.
    #[serde(default)]
    pub cpu_quota: Option<String>,
    /// systemd `MemoryMax=` for all CI work (`"20G"`).
    #[serde(default)]
    pub memory_max: Option<String>,
    /// systemd `TasksMax=` for all CI work.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// systemd `CPUWeight=` (1–10000); below the default 100 so system
    /// services such as sshd win under contention.
    #[serde(default = "CiResourcesSection::d_cpu_weight")]
    pub cpu_weight: u32,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl CiResourcesSection {
    fn d_cpu_weight() -> u32 {
        50
    }
}

// --- [apps_resources] -------------------------------------------------------

/// One systemd slice, `apps.slice`, for the host's own applications (Caddy,
/// Vector, Forgejo, GreptimeDB), plus an optional `MemoryLow=` for
/// `system.slice`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppsResourcesSection {
    /// systemd `CPUQuota=` for all applications together, e.g. `"400%"` = 4 cores.
    #[serde(default)]
    pub cpu_quota: Option<String>,
    /// systemd `MemoryMax=` for all applications together (`"6G"`).
    #[serde(default)]
    pub memory_max: Option<String>,
    /// systemd `TasksMax=` for all applications together.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// systemd `CPUWeight=` (1–10000); 100 is systemd's default, so the
    /// kernel splits CPU between `apps.slice`, `system.slice` and the rest.
    #[serde(default = "AppsResourcesSection::d_cpu_weight")]
    pub cpu_weight: u32,
    /// systemd `MemoryLow=` for `system.slice`: usage below it is reclaimed
    /// from other slices first under pressure, so system services keep their
    /// share (`"2G"`).
    #[serde(default)]
    pub system_memory_low: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl AppsResourcesSection {
    fn d_cpu_weight() -> u32 {
        100
    }
}

// --- [forgejo_runner] -------------------------------------------------------

/// A Forgejo Actions runner (`forgejo-runner daemon`), one per host
/// (docs/design/github-actions-runner.md §5).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForgejoRunnerSection {
    /// Forgejo instance; empty = `https://<forgejo.domain>/` of this config's `[forgejo]`.
    #[serde(default)]
    pub url: String,
    /// Runner UUID from "Create new runner" (or `forgejo-cli actions register`).
    #[serde(default)]
    pub uuid: String,
    /// Runner token shown with the UUID; use `"${FORGEJO_RUNNER_TOKEN:-}"`.
    #[serde(default)]
    pub token: String,
    /// `name:host` or `name:docker://image` (docker needs `docker = "group"` or `"podman"`).
    pub labels: Vec<String>,
    /// Jobs run at the same time.
    #[serde(default = "ForgejoRunnerSection::d_capacity")]
    pub capacity: u32,
    /// `"none"`, `"group"` (runner user joins `docker` = root-equivalent, Docker
    /// host) or `"podman"` (rootless Podman as the runner user, Podman host).
    #[serde(default = "GithubRunnerSection::d_docker")]
    pub docker: String,
    /// Override anvil's pinned forgejo-runner version; requires `sha256`.
    #[serde(default)]
    pub version: Option<String>,
    /// SHA-256 of the binary for `version` and this host's architecture.
    #[serde(default)]
    pub sha256: Option<String>,
    /// systemd `CPUQuota=` for the runner and its jobs, e.g. `"400%"` = 4 cores.
    #[serde(default)]
    pub cpu_quota: Option<String>,
    /// systemd `MemoryMax=` (`"8G"`).
    #[serde(default)]
    pub memory_max: Option<String>,
    /// systemd `TasksMax=`.
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// A daily timer wipes the runner's HOME caches (`~/.cache` with
    /// act's clones and the cache server, `~/.cargo`, `~/.rustup`, `~/.npm`)
    /// past this size while no job runs. Default `"20G"`.
    #[serde(default)]
    pub home_cache_max: Option<String>,
    /// `"persistent"` (one daemon on the host) or `"ephemeral"` (one
    /// job per sysbox sandbox, an ephemeral runner registered per job).
    #[serde(default = "GithubRunnerSection::d_mode")]
    pub mode: String,
    /// Ephemeral: Forgejo API token that registers the per-job runners;
    /// use `"${FORGEJO_API_TOKEN:-}"`.
    #[serde(default)]
    pub api_token: Option<String>,
    /// Ephemeral: `"org"` or `"owner/repo"` the runners serve; absent =
    /// instance-wide (needs a site-admin token).
    #[serde(default)]
    pub owner: Option<String>,
    /// Ephemeral: `"docker-rootless"` (default; a privileged dind
    /// sandbox in a rootless dockerd of its own slot user) or `"sysbox-runc"`.
    #[serde(default)]
    pub sandbox_runtime: Option<String>,
    /// Ephemeral: `docker run --cpus` per sandbox (default `"2"`).
    #[serde(default)]
    pub sandbox_cpus: Option<String>,
    /// Ephemeral: `docker run --memory` per sandbox (default `"4g"`).
    #[serde(default)]
    pub sandbox_memory: Option<String>,
    /// Ephemeral: `docker run --pids-limit` per sandbox (default 2048).
    #[serde(default)]
    pub sandbox_pids: Option<u32>,
    /// Ephemeral: capped volume per slot for the sandbox's Docker data and
    /// workspace (default `"40G"`).
    #[serde(default)]
    pub sandbox_disk: Option<String>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

impl ForgejoRunnerSection {
    pub fn ephemeral(&self) -> bool {
        self.mode == "ephemeral"
    }

    pub fn sandbox_cpus(&self) -> &str {
        self.sandbox_cpus.as_deref().unwrap_or("2")
    }

    pub fn sandbox_memory(&self) -> &str {
        self.sandbox_memory.as_deref().unwrap_or("4g")
    }

    pub fn sandbox_pids(&self) -> u32 {
        self.sandbox_pids.unwrap_or(2048)
    }

    pub fn sandbox_disk(&self) -> &str {
        self.sandbox_disk.as_deref().unwrap_or("40G")
    }

    /// Sandboxes run in per-slot rootless dockerds (the default), not sysbox.
    pub fn docker_rootless(&self) -> bool {
        self.sandbox_runtime.as_deref() != Some("sysbox-runc")
    }

    fn d_capacity() -> u32 {
        1
    }

    /// `home_cache_max` in bytes (default 20G); `None` when invalid.
    pub fn home_cache_max_bytes(&self) -> Option<u64> {
        size_bytes(self.home_cache_max.as_deref().unwrap_or(HOME_CACHE_MAX))
    }
}

// --- [coding_agents] ------------------------------------------------

/// Claude Code and OpenCode for one unprivileged login user
/// (docs/design/coding-agents.md).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CodingAgentsSection {
    /// A `[users]` account with `sudo = false`.
    #[serde(default = "CodingAgentsSection::d_user")]
    pub user: String,
    /// `"stable"`, `"latest"` or `"none"`.
    #[serde(default = "CodingAgentsSection::d_claude_code")]
    pub claude_code: String,
    /// `"latest"`, a version for the v2 installer's `--version`, or `"none"`.
    #[serde(default = "CodingAgentsSection::d_opencode")]
    pub opencode: String,
    #[serde(default)]
    pub skills: Vec<SkillSource>,
    #[serde(default)]
    pub claude_marketplaces: Vec<String>,
    /// `<name>@<marketplace>`.
    #[serde(default)]
    pub claude_plugins: Vec<String>,
    #[serde(default)]
    pub opencode_plugins: Vec<String>,
    /// MCP server name → command and arguments.
    #[serde(default)]
    pub opencode_mcp: BTreeMap<String, Vec<String>>,
    /// A setup repo run after the lists, at a pinned commit.
    #[serde(default)]
    pub setup: Option<AgentSetup>,
    #[serde(default)]
    pub cpu_quota: Option<String>,
    #[serde(default)]
    pub memory_max: Option<String>,
    #[serde(default)]
    pub tasks_max: Option<u32>,
    /// `"none"` or `"rootless"`: the host's engine, rootless as the user.
    #[serde(default = "CodingAgentsSection::d_docker")]
    pub docker: String,
    /// `[coding_agents.orca_server]`: a Remote Orca Server for the user,
    /// reachable on the tailnet only. Absent = off.
    #[serde(default)]
    pub orca_server: Option<OrcaServer>,
    #[serde(default)]
    pub order_override: OrderOverride,
}

/// `orca-ide serve` as the agent user.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrcaServer {
    /// Not 6768: an Orca SSH-target runtime already holds 127.0.0.1:6768.
    #[serde(default = "OrcaServer::d_port")]
    pub port: u16,
    #[serde(default = "OrcaServer::d_version")]
    pub version: String,
    /// `.deb` checksums; built in for the default version, required otherwise.
    #[serde(default)]
    pub sha256_amd64: Option<String>,
    #[serde(default)]
    pub sha256_arm64: Option<String>,
}

impl OrcaServer {
    fn d_port() -> u16 {
        6769
    }
    fn d_version() -> String {
        crate::modules::coding_agents::ORCA_VERSION.into()
    }
}

impl CodingAgentsSection {
    fn d_user() -> String {
        "agent".into()
    }
    fn d_claude_code() -> String {
        "stable".into()
    }
    fn d_opencode() -> String {
        "latest".into()
    }
    fn d_docker() -> String {
        "none".into()
    }
}

/// `npx skills add <source>`: every skill in it, or only `names`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillSource {
    /// `owner/repo` or an https git URL.
    pub source: String,
    #[serde(default)]
    pub names: Vec<String>,
    /// `claude-code` and/or `opencode`; unset = the installed agents.
    #[serde(default)]
    pub agents: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentSetup {
    /// https git URL.
    pub url: String,
    /// 40-hex commit.
    pub rev: String,
    /// Script path relative to the repo root.
    pub run: String,
}

// --- [execution_order] (R47) ------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionOrderSection {
    #[serde(default)]
    pub modules: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deserialize an empty TOML table into a section, exercising the serde
    /// defaults exactly as an empty `[section]` in a user config would.
    fn empty<T: serde::de::DeserializeOwned>() -> T {
        toml::from_str("").expect("empty section deserializes via defaults")
    }

    #[test]
    fn auth_key_expiration_parses_like_headscale() {
        let secs = |e: &str| {
            AuthKeySpec {
                name: "k".into(),
                reusable: false,
                expiration: e.into(),
                tags: Vec::new(),
                ephemeral: false,
            }
            .expiration_secs()
        };
        assert_eq!(secs("24h"), Some(86_400));
        assert_eq!(secs("1h30m"), Some(5_400));
        assert_eq!(secs("2w"), Some(1_209_600));
        assert_eq!(secs("1y"), Some(31_536_000));
        assert_eq!(secs("7d"), Some(604_800));
        assert_eq!(secs("90s"), Some(90));
        for bad in [
            "",
            "h",
            "24",
            "1h30",
            "1x",
            "-1h",
            "30m1h",
            "1h1h",
            "99999999999999999999y",
        ] {
            assert_eq!(secs(bad), None, "{bad}");
        }
    }

    #[test]
    fn sshd_defaults_are_hardened() {
        let s: SshdSection = empty();
        assert!(s.strong_ciphers, "strong_ciphers defaults on");
        assert!(
            s.disable_x11_forwarding,
            "X11 forwarding disabled by default"
        );
        // The serde defaults and the Default impl must agree.
        let d = SshdSection::default();
        assert_eq!(s.strong_ciphers, d.strong_ciphers);
        assert_eq!(s.disable_x11_forwarding, d.disable_x11_forwarding);
    }

    #[test]
    fn forgejo_defaults() {
        let f: ForgejoSection = toml::from_str(
            r#"
domain = "git.example.com"
secret_key = "s"
internal_token = "t"
jwt_secret = "j"
"#,
        )
        .expect("minimal [forgejo] deserializes via defaults");
        assert_eq!(f.http_port, 3000);
        assert_eq!(f.ssh_port, 2222);
        assert_eq!(f.database, "sqlite3");
        assert_eq!(f.db_host, "127.0.0.1:5432");
        assert_eq!(f.db_name, "forgejo");
        assert_eq!(f.db_user, "forgejo");
        assert_eq!(f.db_ssl_mode, "disable");
        assert_eq!((f.deploy.as_str(), f.listen.as_str()), ("native", "public"));
        assert!(f.image_digest.is_none());
    }

    #[test]
    fn pam_minlen_default_is_14() {
        let p: PamSection = empty();
        assert_eq!(p.minlen, 14);
    }

    #[test]
    fn docker_presence_hardens_by_default() {
        let d: DockerSection = empty();
        assert!(d.iptables_off() && d.iptables_off.is_none());
        assert!(d.userns_remap() && d.userns_remap.is_none());
        assert!(!d.rootless);
        let def = DockerSection::default();
        assert_eq!(d.iptables_off, def.iptables_off);
        assert_eq!(d.userns_remap, def.userns_remap);
        let set: DockerSection =
            toml::from_str("userns_remap = false\niptables_off = true").unwrap();
        assert_eq!(
            (set.userns_remap, set.iptables_off),
            (Some(false), Some(true))
        );
        assert!(!set.userns_remap() && set.iptables_off());
        assert!(d.live_restore && def.live_restore);
        assert_eq!(d.source, "vendor");
        assert_eq!(d.source, def.source);
        assert!(!d.distro());
    }

    #[test]
    fn crowdsec_default_collections_cover_linux_and_sshd() {
        let c: CrowdsecSection = empty();
        assert_eq!(
            c.collections,
            vec!["crowdsecurity/linux", "crowdsecurity/sshd"]
        );
    }

    #[test]
    fn dns_defaults_to_quad9_cloudflare_over_tls() {
        let d: DnsSection = empty();
        assert_eq!(
            d.dns_servers,
            vec!["9.9.9.9", "149.112.112.112", "1.1.1.1", "1.0.0.1"]
        );
        assert!(d.dns_over_tls);
        let def = DnsSection::default();
        assert_eq!(d.dns_servers, def.dns_servers);
        assert_eq!(d.dns_over_tls, def.dns_over_tls);
    }

    #[test]
    fn headscale_auth_key_expiration_defaults_to_24h() {
        let k: AuthKeySpec = toml::from_str("name = \"ci\"").expect("parse");
        assert_eq!(k.expiration, "24h");
        assert!(!k.reusable);
    }

    #[test]
    fn kernel_disable_ipv6_is_opt_in() {
        let k: KernelSection = empty();
        assert!(k.harden_network, "network hardening defaults on");
        assert!(
            !k.disable_ipv6,
            "disable_ipv6 must default off — it breaks dual-stack hosts"
        );
    }

    #[test]
    fn suid_scans_whole_filesystem_by_default() {
        let s: SuidSection = empty();
        assert_eq!(s.scan_paths, vec!["/"]);
    }

    #[test]
    fn vector_defaults_point_at_local_greptimedb_public_db() {
        let v: VectorSection = empty();
        assert_eq!(v.greptimedb_host, "127.0.0.1");
        assert_eq!(v.db_name, "public");
    }

    // The default *values* below are the hardening contract shipped to every
    // host that enables a section without overriding fields — pinned
    // per-field so a drive-by change to a `d_*` function cannot ship silently
    // (surfaced by mutation testing: these all survived mutants before).

    #[test]
    fn sshd_timeout_defaults_are_pinned() {
        let s: SshdSection = empty();
        assert_eq!(s.max_auth_tries, 3);
        assert_eq!(s.login_grace_time, 30);
        assert_eq!(s.client_alive_interval, 300);
        assert_eq!(s.client_alive_count_max, 2);
    }

    #[test]
    fn fail2ban_defaults_are_pinned() {
        let f: Fail2banSection = empty();
        assert_eq!(f.bantime, "10m");
        assert_eq!(f.findtime, "10m");
        assert_eq!(f.maxretry, 5);
    }

    #[test]
    fn process_password_aging_defaults_are_pinned() {
        let p: ProcessSection = empty();
        assert_eq!(p.pass_max_days, 365);
        assert_eq!(p.pass_min_days, 1);
        assert_eq!(p.pass_warn_age, 7);
    }

    #[test]
    fn auditd_crowdsec_tls_hetzner_defaults_are_pinned() {
        let a: AuditdSection = empty();
        assert_eq!(a.rule_set, "cis-level1");
        let c: CrowdsecSection = empty();
        assert_eq!(c.bouncer_mode, None, "the distro package picks the backend");
        let t: TlsSection = empty();
        assert_eq!(t.provider, "certbot");
        let h: HetznerSection = empty();
        assert_eq!(h.firewall_name, "anvil");
    }

    #[test]
    fn caddy_defaults_are_pinned() {
        let c: CaddySection = empty();
        assert_eq!(
            (c.ca.as_str(), c.http_port, c.https_port, c.hsts),
            ("public", 80, 443, true)
        );
        assert!(c.email.is_none() && c.sites.is_empty());
    }

    #[test]
    fn headscale_defaults_are_pinned() {
        let h: HeadscaleSection = empty();
        assert_eq!(h.version, "0.23.0");
        assert_eq!(h.listen_addr, "0.0.0.0:8080");
        assert_eq!(h.db_path, "/var/lib/headscale/db.sqlite");
        assert_eq!(h.headplane_listen, "127.0.0.1:3000");
        assert!(!h.headplane_docker_socket);
    }

    #[test]
    fn coding_agents_defaults_are_pinned() {
        let c: CodingAgentsSection = empty();
        assert_eq!(
            (c.user.as_str(), c.claude_code.as_str(), c.opencode.as_str()),
            ("agent", "stable", "latest")
        );
        assert!(c.skills.is_empty() && c.setup.is_none() && c.orca_server.is_none());
        let o: OrcaServer = empty();
        assert_eq!((o.port, o.version.as_str()), (6769, "1.4.253"));
    }

    #[test]
    fn greptimedb_and_vector_defaults_are_pinned() {
        let g: GreptimedbSection = empty();
        assert_eq!(g.http_port, 4000);
        assert_eq!(g.grpc_port, 4001);
        assert_eq!(g.mysql_port, 4002);
        assert_eq!(g.postgres_port, 4003);
        assert_eq!(g.data_dir, "/var/lib/greptimedb");
        assert_eq!(g.listen_address, "127.0.0.1");
        assert_eq!(g.version, "v1.3.0");
        let v: VectorSection = empty();
        assert_eq!(v.greptimedb_grpc_port, 4001);
        assert_eq!(v.greptimedb_http_port, 4000);
        assert_eq!(v.scrape_interval_secs, 15);
        assert_eq!(
            v.cgroups_include,
            [
                "system.slice/docker-*.scope",
                "ci.slice/**",
                "apps.slice/**",
                "user.slice/user-*.slice",
                "system.slice/*.service"
            ]
        );
        let d: DockerSection = empty();
        assert_eq!(d.log_driver, "json-file");
        assert_eq!(DockerSection::default().log_driver, "json-file");
    }
}
