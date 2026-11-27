//! The `beszel` module: Beszel monitoring (github.com/henrygd/beszel) — the
//! **agent** (default), the **hub** (web UI + database), or both on one
//! machine. Each runs as its own unprivileged user (`beszel`, `beszel-hub`)
//! under a sandboxed systemd unit, from a pinned release.
//!
//! Layouts (upstream behaviour verified against v0.21.1):
//! - **Agent → remote hub, outbound** (`hub_url` + `token`): the agent dials
//!   the hub over WebSocket with `DISABLE_SSH=true`; nothing listens.
//! - **Agent → remote hub, inbound** (`key` only): the hub dials the agent on
//!   `listen_port`, opened in ufw only from `hub_addresses`, or only on
//!   `tailscale0` when `[tailscale]` is enabled.
//! - **Hub + agent here** (`hub = true`): anvil creates the hub's SSH key
//!   (`/var/lib/beszel-hub/id_ed25519`, which the hub loads instead of
//!   generating one), and the agent listens on `127.0.0.1:<listen_port>`
//!   trusting that key. Add it in the hub UI as host `127.0.0.1`.
//! - **Hub**: `beszel serve` on `hub_listen` (loopback by default). A
//!   non-loopback address is opened in ufw only from `hub_allow_from` or on
//!   `tailscale0`.
//!
//! Every ufw-rule command refuses to run unless ufw is active, and commands
//! run before the services start, so no Beszel port is ever up behind an
//! inactive firewall. Load-time validation enforces the scoping.
//!
//! Download: the release tarball for the host arch is checked against a
//! SHA-256 compiled in for [`DEFAULT_VERSION`] (or given in `sha256` for an
//! overridden `version`) before install (no `curl | sh`), so a compromised
//! release cannot swap the binary under a pinned version.
//! Binaries are root-owned, so neither service can replace itself.
//!
//! Secrets: the agent's `TOKEN` lives only in `/etc/default/beszel-agent`
//! (root, 0600), read by systemd before it drops privileges; the file is
//! host-computed, so `anvil diff` never prints it. Like every secret anvil
//! delivers, it is still inside the rendered apply/probe script. The hub's
//! private key and database stay in its 0700 state directory.
//!
//! Opt-ins (T16), both agent-only and off by default: `docker = true` adds
//! the `docker` group (container stats; **root-equivalent**: the socket can
//! start a privileged container). `smart = true` installs smartmontools and
//! adds the `disk` group (raw access to every block device, so also
//! root-equivalent in practice) plus ambient `CAP_SYS_RAWIO` for SATA/SAS
//! `SG_IO` pass-through. `CAP_SYS_ADMIN`, which NVMe admin pass-through
//! needs, is deliberately not granted.
//!
//! Every config-derived value that reaches bash goes through
//! [`shell_escape`] (R55). `hub_listen` (validated as `IP:port`) is the only
//! config value in a unit file.

use crate::config::schema::{BeszelSection, WallRule};
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::firewall::{rule_converge, rule_needle};
use super::{apt_install, Module};

/// The pinned release, with the SHA-256 of each tarball from
/// <https://github.com/henrygd/beszel/releases/download/v0.21.1/beszel_0.21.1_checksums.txt>
/// (verified 2026-11-02).
pub const DEFAULT_VERSION: &str = "0.21.1";
const DEFAULT_SHA256: [(&str, &str); 4] = [
    (
        "beszel-agent_linux_amd64.tar.gz",
        "3b6ee592632ec03b9a43312e99a40203a7b3d83fe40dd0c25acda1eb915ea7c0",
    ),
    (
        "beszel-agent_linux_arm64.tar.gz",
        "a6ea544976b9a74398ac88d5da5bb96813d9a2e353a37bbfdb6a903fa8ba1838",
    ),
    (
        "beszel_linux_amd64.tar.gz",
        "70857d0489cf790224167815c82f8807cc28134d27f209b58b1cd36e4082931a",
    ),
    (
        "beszel_linux_arm64.tar.gz",
        "c2357b94d36febfd0c6df9f89f523fff6f6df69a4b8ac91a8b262d2b7fdb0584",
    ),
];
const ARCHES: [&str; 2] = ["amd64", "arm64"];

/// Release tarball name for a service and Debian arch.
fn tarball(asset: &str, arch: &str) -> String {
    format!("{asset}_linux_{arch}.tar.gz")
}

/// Load-time check of the pins (T15): `sha256` keys must be tarball names
/// with 64-hex values, and a non-default `version` needs every tarball the
/// enabled services download.
pub fn validate_pins(c: &BeszelSection) -> Result<()> {
    for (k, v) in &c.sha256 {
        if !DEFAULT_SHA256.iter().any(|(n, _)| n == k) {
            return Err(AnvilError::Validation(format!(
                "beszel.sha256: unknown tarball {k:?}; expected beszel-agent_linux_<amd64|arm64>.tar.gz \
                 or beszel_linux_<amd64|arm64>.tar.gz"
            )));
        }
        if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AnvilError::Validation(format!(
                "beszel.sha256.{k:?} must be 64 hex characters"
            )));
        }
    }
    if c.version == DEFAULT_VERSION {
        return Ok(());
    }
    let mut assets = Vec::new();
    if c.hub {
        assets.push(HUB.asset);
    }
    if c.agent {
        assets.push(AGENT.asset);
    }
    let missing: Vec<String> = assets
        .iter()
        .flat_map(|a| ARCHES.map(|arch| tarball(a, arch)))
        .filter(|t| !c.sha256.contains_key(t))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(AnvilError::Validation(format!(
        "beszel.version = {:?} needs beszel.sha256 entries for {} (from the release's \
         beszel_<version>_checksums.txt); only {DEFAULT_VERSION} is built in",
        c.version,
        missing.join(", ")
    )))
}

/// Agent env file (Fixed Contract for drift/rollback).
pub const ENV_PATH: &str = "/etc/default/beszel-agent";
/// Hub env file with the first admin's credentials (only with `admin_email`).
pub const HUB_ENV_PATH: &str = "/etc/default/beszel-hub";
/// The hub's SSH private key; the local agent trusts its public half.
pub const HUB_KEY: &str = "/var/lib/beszel-hub/id_ed25519";
const WANTS_DIR: &str = "/etc/systemd/system/multi-user.target.wants";

/// One managed Beszel service (agent or hub).
pub struct Svc {
    /// systemd unit name, without `.service`.
    pub name: &'static str,
    pub user: &'static str,
    pub bin: &'static str,
    pub unit: &'static str,
    /// Release asset prefix; also the binary's name inside the tarball.
    asset: &'static str,
    version_flag: &'static str,
    version_out: &'static str,
    /// Written only when this module ran `useradd`; rollback deletes the
    /// user only then, so a pre-existing account survives.
    marker: &'static str,
    state_dir: &'static str,
    /// Rollback deletes the state dir (agent fingerprint). The hub's holds
    /// the database and is always kept.
    remove_state: bool,
    /// Shell flag a command raises to force a (re)start.
    flag: &'static str,
}

pub const AGENT: Svc = Svc {
    name: "beszel-agent",
    user: "beszel",
    bin: "/usr/local/bin/beszel-agent",
    unit: "/etc/systemd/system/beszel-agent.service",
    asset: "beszel-agent",
    version_flag: "-v",
    version_out: "beszel-agent",
    marker: "/var/lib/anvil/beszel-user.created",
    state_dir: "/var/lib/beszel-agent",
    remove_state: true,
    flag: "__bsz_restart",
};

pub const HUB: Svc = Svc {
    name: "beszel-hub",
    user: "beszel-hub",
    bin: "/usr/local/bin/beszel",
    unit: "/etc/systemd/system/beszel-hub.service",
    asset: "beszel",
    version_flag: "--version",
    version_out: "beszel version",
    marker: "/var/lib/anvil/beszel-hub-user.created",
    state_dir: "/var/lib/beszel-hub",
    remove_state: false,
    flag: "__bszhub_restart",
};

/// Sandboxing shared by both units: upstream's agent set plus
/// `NoNewPrivileges` and no capabilities.
const SANDBOX: &str = "KeyringMode=private\n\
     LockPersonality=yes\n\
     NoNewPrivileges=yes\n\
     CapabilityBoundingSet=\n\
     AmbientCapabilities=\n\
     ProtectClock=yes\n\
     ProtectControlGroups=yes\n\
     ProtectHome=read-only\n\
     ProtectHostname=yes\n\
     ProtectKernelLogs=yes\n\
     ProtectKernelModules=yes\n\
     ProtectSystem=strict\n\
     PrivateTmp=yes\n\
     RemoveIPC=yes\n\
     RestrictRealtime=yes\n\
     RestrictSUIDSGID=yes\n";

pub struct BeszelModule {
    cfg: BeszelSection,
    /// `[tailscale]` is enabled: an unscoped port is allowed on `tailscale0`.
    tailscale: bool,
}

impl BeszelModule {
    pub fn new(cfg: BeszelSection, tailscale: bool) -> Self {
        Self { cfg, tailscale }
    }

    /// Hub and agent on this machine: the agent is wired to the local hub.
    fn colocated(&self) -> bool {
        self.cfg.hub && self.cfg.agent
    }

    fn services(&self) -> Vec<&'static Svc> {
        let mut v = Vec::new();
        if self.cfg.hub {
            v.push(&HUB);
        }
        if self.cfg.agent {
            v.push(&AGENT);
        }
        v
    }

    /// The agent's environment as shell words for `printf '%s\n'` (upstream
    /// names `KEY`, `LISTEN`, `HUB_URL`, `TOKEN`, `DISABLE_SSH`). Config
    /// values are escaped; they are validated at load to hold no quote,
    /// backslash, `$` or control character, so the `KEY="…"` quoting holds.
    pub fn env_words(&self) -> Vec<String> {
        let c = &self.cfg;
        let mut v = vec![shell_escape("# Managed by anvil — do not edit by hand")];
        if self.colocated() {
            // The local hub's public key, derived on the host (read-only).
            v.push(format!(
                "\"KEY=\\\"$(ssh-keygen -y -f {HUB_KEY} 2>/dev/null)\\\"\""
            ));
            v.push(shell_escape(&format!("LISTEN=127.0.0.1:{}", c.listen_port)));
        } else if c.outbound() {
            v.push(shell_escape(&format!("KEY=\"{}\"", c.key)));
            v.push(shell_escape(&format!("HUB_URL=\"{}\"", c.hub_url)));
            v.push(shell_escape(&format!("TOKEN=\"{}\"", c.token)));
            v.push(shell_escape("DISABLE_SSH=true"));
        } else {
            v.push(shell_escape(&format!("KEY=\"{}\"", c.key)));
            v.push(shell_escape(&format!("LISTEN={}", c.listen_port)));
        }
        v
    }

    /// Bash printing the agent env file (a `Computed` generator: the content
    /// depends on the host in the colocated case, and `diff` never shows the
    /// token).
    fn env_generator(&self) -> String {
        format!("printf '%s\\n' {}", self.env_words().join(" "))
    }

    /// Bash printing the hub env file. Upstream's first-start migration reads
    /// `[BESZEL_HUB_]USER_EMAIL`/`USER_PASSWORD` and creates the superuser and
    /// an admin user, which closes the first-visitor `/create-user` endpoint.
    /// Values are validated at load like the agent's.
    fn hub_env_generator(&self) -> String {
        let c = &self.cfg;
        format!(
            "printf '%s\\n' {} {} {}",
            shell_escape("# Managed by anvil — do not edit by hand"),
            shell_escape(&format!("BESZEL_HUB_USER_EMAIL=\"{}\"", c.admin_email)),
            shell_escape(&format!(
                "BESZEL_HUB_USER_PASSWORD=\"{}\"",
                c.admin_password
            )),
        )
    }

    fn unit_content(&self, s: &Svc) -> String {
        let mut caps = String::new();
        let (desc, exec, extra) = if s.name == HUB.name {
            (
                "Beszel Hub",
                format!(
                    "{} serve --http {} --dir {}",
                    s.bin, self.cfg.hub_listen, s.state_dir
                ),
                if self.cfg.admin_email.is_empty() {
                    format!("WorkingDirectory={}\n", s.state_dir)
                } else {
                    format!(
                        "WorkingDirectory={}\nEnvironmentFile={HUB_ENV_PATH}\n",
                        s.state_dir
                    )
                },
            )
        } else {
            let mut groups = String::from("systemd-journal");
            if self.cfg.docker {
                groups.push_str(" docker");
            }
            if self.cfg.smart {
                groups.push_str(" disk");
                // After SANDBOX: its empty assignments reset earlier ones.
                caps = "CapabilityBoundingSet=CAP_SYS_RAWIO\nAmbientCapabilities=CAP_SYS_RAWIO\n"
                    .into();
            }
            (
                "Beszel Agent",
                s.bin.to_string(),
                format!("SupplementaryGroups={groups}\nEnvironmentFile={ENV_PATH}\n"),
            )
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description={desc} (anvil-managed)\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             User={user}\n\
             Group={user}\n\
             {extra}\
             ExecStart={exec}\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             StateDirectory={state}\n\
             StateDirectoryMode=0700\n\
             UMask=0077\n\
             \n\
             {SANDBOX}\
             {caps}\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            user = s.user,
            state = s.state_dir.trim_start_matches("/var/lib/"),
        )
    }

    /// A system account with no home and no shell; the marker records that
    /// anvil created it.
    fn ensure_user(&self, s: &Svc) -> ManagedCommand {
        let (u, marker) = (s.user, s.marker);
        ManagedCommand::new(
            format!("{u} system user"),
            format!("id -u {u} >/dev/null 2>&1"),
            format!(
                "if getent group {u} >/dev/null 2>&1; then __bsz_g='--gid {u}'; else __bsz_g='--user-group'; fi\n\
                 useradd --system $__bsz_g --no-create-home --home-dir /nonexistent \
                 --shell /usr/sbin/nologin {u}\n\
                 mkdir -p /var/lib/anvil && : > {marker}"
            ),
        )
    }

    /// The pinned SHA-256 of `file`: from `sha256`, else built in for the
    /// default version. Empty (so the install fails closed) when neither has
    /// it, which `validate_pins` rules out.
    fn sha256(&self, file: &str) -> String {
        let builtin = || {
            DEFAULT_SHA256
                .iter()
                .find(|(n, _)| *n == file && self.cfg.version == DEFAULT_VERSION)
                .map(|(_, h)| h.to_string())
        };
        self.cfg
            .sha256
            .get(file)
            .cloned()
            .or_else(builtin)
            .unwrap_or_default()
    }

    /// Download the pinned release for the host arch, verify it against the
    /// pinned SHA-256, and install it root-owned. A pre-existing binary is
    /// kept as `.anvil.bak` for rollback.
    fn install_command(&self, s: &Svc) -> ManagedCommand {
        let ver = shell_escape(&self.cfg.version);
        let want = shell_escape(&format!("{} {}", s.version_out, self.cfg.version));
        let (bin, asset, flag) = (s.bin, s.asset, s.flag);
        let detect = format!(
            "[ -x {bin} ] && [ \"$({bin} {} 2>/dev/null)\" = {want} ]",
            s.version_flag
        );
        let converge = format!(
            "__bsz_ver={ver}\n\
             __bsz_arch=$(dpkg --print-architecture)\n\
             case \"$__bsz_arch\" in\n\
             \x20 amd64) __bsz_sum={sum_amd64} ;;\n\
             \x20 arm64) __bsz_sum={sum_arm64} ;;\n\
             \x20 *) printf 'FAILED: beszel: unsupported architecture %s (amd64 and arm64 only)\\n' \"$__bsz_arch\"; exit 1 ;;\n\
             esac\n\
             command -v curl >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
             __bsz_tmp=\"$__rundir/{asset}\"\n\
             mkdir -p \"$__bsz_tmp\"\n\
             __bsz_base=\"https://github.com/henrygd/beszel/releases/download/v${{__bsz_ver}}\"\n\
             __bsz_file=\"{asset}_linux_${{__bsz_arch}}.tar.gz\"\n\
             curl -fsSL --retry 3 -o \"$__bsz_tmp/$__bsz_file\" \"$__bsz_base/$__bsz_file\"\n\
             __bsz_got=$(sha256sum \"$__bsz_tmp/$__bsz_file\" | awk '{{ print $1 }}')\n\
             if [ \"${{#__bsz_sum}}\" != 64 ] || [ \"$__bsz_got\" != \"$__bsz_sum\" ]; then\n\
             \x20 printf 'FAILED: beszel: checksum mismatch for %s\\n' \"$__bsz_file\"\n\
             \x20 exit 1\n\
             fi\n\
             tar -xzf \"$__bsz_tmp/$__bsz_file\" -C \"$__bsz_tmp\" {asset}\n\
             if [ -e {bin} ] && ! __anvil_created {bin} && [ ! -e {bin}.anvil.bak ]; then\n\
             \x20 cp -a {bin} {bin}.anvil.bak\n\
             fi\n\
             [ -e {bin} ] || __anvil_remember {bin}\n\
             install -m 0755 -o root -g root \"$__bsz_tmp/{asset}\" {bin}.new\n\
             mv -f {bin}.new {bin}\n\
             {flag}=1",
            bootstrap = apt_install(&["curl", "ca-certificates"]),
            sum_amd64 = shell_escape(&self.sha256(&tarball(asset, "amd64"))),
            sum_arm64 = shell_escape(&self.sha256(&tarball(asset, "arm64"))),
        );
        ManagedCommand::new(
            format!("install {} {}", s.name, self.cfg.version),
            detect,
            converge,
        )
    }

    /// `docker = true`: refuse unless the engine and its group exist (anvil
    /// never installs Docker for monitoring; use `[docker]`).
    fn docker_check() -> ManagedCommand {
        ManagedCommand::new(
            "beszel-agent docker group present (root-equivalent access)",
            "getent group docker >/dev/null 2>&1 && command -v docker >/dev/null 2>&1",
            "printf 'FAILED: beszel: docker = true but Docker or its docker group is missing; enable [docker] or install it first\\n'\n\
             exit 1",
        )
    }

    /// `smart = true`: the agent shells out to `smartctl`.
    fn smartctl_command() -> ManagedCommand {
        ManagedCommand::new(
            "smartmontools installed",
            "command -v smartctl >/dev/null 2>&1",
            format!("{}\n__bsz_restart=1", apt_install(&["smartmontools"])),
        )
    }

    /// Create the hub's SSH key before its first start so the local agent
    /// can trust it in the same run (the hub loads an existing key).
    fn hub_key_command(&self) -> ManagedCommand {
        let (u, dir) = (HUB.user, HUB.state_dir);
        ManagedCommand::new(
            "beszel-hub SSH key",
            format!("[ -s {HUB_KEY} ]"),
            format!(
                "command -v ssh-keygen >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
                 install -d -m 0700 -o {u} -g {u} {dir}\n\
                 ssh-keygen -q -t ed25519 -N '' -C beszel-hub -f {HUB_KEY}\n\
                 chown {u}:{u} {HUB_KEY} {HUB_KEY}.pub",
                bootstrap = apt_install(&["openssh-client"]),
            ),
        )
    }

    /// ufw rules for `port`: one per address, else one on `tailscale0` when
    /// `[tailscale]` is enabled. Pairs of (`ufw show added` needle, spec).
    fn scoped_rules(&self, port: u16, from: &[String]) -> Vec<(String, String)> {
        if from.is_empty() {
            if !self.tailscale {
                return Vec::new();
            }
            let spec = format!("allow in on tailscale0 to any port {port} proto tcp");
            return vec![(spec.clone(), spec)];
        }
        from.iter()
            .map(|from| {
                let rule = WallRule {
                    port: port.to_string(),
                    proto: Some("tcp".into()),
                    from: Some(from.clone()),
                    comment: None,
                };
                let conv = rule_converge("allow", &rule);
                let spec = conv.strip_prefix("ufw ").unwrap_or(&conv).to_string();
                (rule_needle("allow", &rule), spec)
            })
            .collect()
    }

    /// Every ufw rule this module owns: the agent port (remote hub, inbound
    /// mode) and the hub port (non-loopback `hub_listen`).
    pub fn firewall_rules(&self) -> Vec<(String, String)> {
        let c = &self.cfg;
        let mut v = Vec::new();
        if c.agent && !c.hub && !c.outbound() {
            v.extend(self.scoped_rules(c.listen_port, &c.hub_addresses));
        }
        if c.hub {
            if let Ok(addr) = c.hub_listen.parse::<std::net::SocketAddr>() {
                if !addr.ip().is_loopback() {
                    v.extend(self.scoped_rules(addr.port(), &c.hub_allow_from));
                }
            }
        }
        v
    }

    fn firewall_commands(&self) -> Vec<ManagedCommand> {
        self.firewall_rules()
            .into_iter()
            .map(|(needle, spec)| {
                ManagedCommand::new(
                    format!("firewall {needle} (beszel)"),
                    format!(
                        "ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null \
                         && ufw show added 2>/dev/null | grep -wF {} >/dev/null",
                        shell_escape(&needle)
                    ),
                    format!(
                        "if ! ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null; then\n\
                         \x20 printf 'FAILED: beszel: ufw is not active; refusing to start a service on an unfirewalled port\\n'\n\
                         \x20 exit 1\n\
                         fi\n\
                         ufw {spec} >/dev/null"
                    ),
                )
            })
            .collect()
    }

    /// Drift when a service is down; the guard does the actual (re)start.
    fn service_active(&self, s: &Svc) -> ManagedCommand {
        ManagedCommand::new(
            format!("{} service active", s.name),
            format!("systemctl is-active --quiet {}", s.name),
            format!("{}=1", s.flag),
        )
    }

    /// (Re)start a service only when its binary, unit or env changed this
    /// run, or it is down. A no-op when its unit is gone (after rollback).
    fn reload_block(s: &Svc) -> String {
        let (unit, name, flag) = (s.unit, s.name, s.flag);
        let paths = if s.name == AGENT.name {
            format!("{unit}|{ENV_PATH}")
        } else {
            unit.to_string()
        };
        format!(
            "if [ -f {unit} ]; then\n\
             \x20 __bsz_changed=\"${{{flag}:-0}}\"\n\
             \x20 for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do\n\
             \x20\x20 case \"$__p\" in {paths}) __bsz_changed=1 ;; esac\n\
             \x20 done\n\
             \x20 systemctl daemon-reload\n\
             \x20 systemctl enable {name} >/dev/null 2>&1 || true\n\
             \x20 if [ \"$__bsz_changed\" = 1 ]; then\n\
             \x20\x20 systemctl restart {name}\n\
             \x20 elif ! systemctl is-active --quiet {name}; then\n\
             \x20\x20 systemctl start {name}\n\
             \x20 fi\n\
             fi\n"
        )
    }

    /// Undo what files cannot, per service: stop/disable it (unless a
    /// pre-anvil unit was restored), and remove the binary and user only
    /// when anvil created them. Then delete this module's ufw rules.
    fn rollback_script(&self) -> String {
        let mut r = String::from("\n# rollback (module-authored): beszel\n");
        for s in self.services() {
            let (unit, name, bin, marker, state, user, flag) =
                (s.unit, s.name, s.bin, s.marker, s.state_dir, s.user, s.flag);
            let (state_cmd, state_msg) = if s.remove_state {
                (
                    format!("rm -rf {state}"),
                    format!("user and {state} removed"),
                )
            } else {
                (
                    String::new(),
                    format!("user removed; {state} (hub data) kept"),
                )
            };
            r.push_str(&format!(
                "if [ -f {unit} ]; then\n\
                 \x20 {flag}=1\n\
                 \x20 printf 'OK: {name}: pre-anvil unit restored; restarting it\\n'\n\
                 elif systemctl is-active --quiet {name} || [ -L {WANTS_DIR}/{name}.service ]; then\n\
                 \x20 systemctl stop {name} >/dev/null 2>&1 || true\n\
                 \x20 rm -f {WANTS_DIR}/{name}.service\n\
                 \x20 systemctl daemon-reload || true\n\
                 \x20 systemctl reset-failed {name} >/dev/null 2>&1 || true\n\
                 \x20 printf 'CHANGED: {name} service stopped and disabled\\n'\n\
                 else\n\
                 \x20 printf 'OK: {name} service not installed\\n'\n\
                 fi\n\
                 if __anvil_created {bin}; then\n\
                 \x20 rm -f {bin}\n\
                 \x20 __anvil_forget {bin}\n\
                 \x20 printf 'CHANGED: %s removed (installed by anvil)\\n' {bin}\n\
                 else\n\
                 \x20 printf 'OK: %s not installed by anvil; left alone\\n' {bin}\n\
                 fi\n\
                 if [ -e {marker} ] && [ ! -f {unit} ]; then\n\
                 \x20 if id -u {user} >/dev/null 2>&1; then userdel {user}; fi\n\
                 \x20 if getent group {user} >/dev/null 2>&1; then groupdel {user}; fi\n\
                 \x20 {state_cmd}\n\
                 \x20 rm -f {marker}\n\
                 \x20 printf 'CHANGED: {name}: {user} {state_msg}\\n'\n\
                 else\n\
                 \x20 printf 'OK: {user} user not created by anvil; left alone\\n'\n\
                 fi\n"
            ));
        }
        for (needle, spec) in self.firewall_rules() {
            let n = shell_escape(&needle);
            r.push_str(&format!(
                "if command -v ufw >/dev/null 2>&1 && ufw show added 2>/dev/null | grep -wF {n} >/dev/null; then\n\
                 \x20 ufw delete {spec} >/dev/null\n\
                 \x20 printf 'CHANGED: beszel removed firewall rule %s\\n' {n}\n\
                 fi\n"
            ));
        }
        r
    }
}

impl Module for BeszelModule {
    fn id(&self) -> &'static str {
        "beszel"
    }

    fn declaration(&self) -> Declaration {
        let svcs = self.services();
        let mut decl = Declaration::new("beszel")
            .secret(&self.cfg.token)
            .secret(&self.cfg.admin_password);
        for s in &svcs {
            decl = decl
                .command(self.ensure_user(s))
                .command(self.install_command(s));
        }
        if self.cfg.hub {
            decl = decl.command(self.hub_key_command());
        }
        if self.cfg.agent && self.cfg.docker {
            decl = decl.command(Self::docker_check());
        }
        if self.cfg.agent && self.cfg.smart {
            decl = decl.command(Self::smartctl_command());
        }
        // Before the service checks and the guard: a refused firewall rule
        // aborts the run before any service can start.
        for c in self.firewall_commands() {
            decl = decl.command(c);
        }
        for s in &svcs {
            decl = decl.command(self.service_active(s));
        }
        if self.cfg.agent {
            decl = decl.file(ManagedFile::computed(
                ENV_PATH,
                self.env_generator(),
                "0600",
                "root:root",
            ));
        }
        if self.cfg.hub && !self.cfg.admin_email.is_empty() {
            decl = decl.file(ManagedFile::computed(
                HUB_ENV_PATH,
                self.hub_env_generator(),
                "0600",
                "root:root",
            ));
        }
        let mut validate = Vec::new();
        let mut reload = String::new();
        for s in &svcs {
            decl = decl
                .file(ManagedFile::new(
                    s.unit,
                    self.unit_content(s),
                    "0644",
                    "root:root",
                ))
                .command_file(s.bin);
            // The unit's ExecStart binary must exist (ours on apply, the
            // restored one on rollback); vacuous once the unit is gone.
            validate.push(format!(
                "{{ [ ! -f {u} ] || [ -x \"$(awk '/^ExecStart=/ {{ sub(/^ExecStart=/, \"\"); print $1; exit }}' {u})\" ]; }}",
                u = s.unit
            ));
            reload.push_str(&Self::reload_block(s));
        }
        decl.rollback_script(self.rollback_script())
            .guarded_reload(ReloadGuard {
                describe: "beszel services".into(),
                validate: validate.join(" && "),
                reload: reload.trim_end().to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHub hub";

    fn module(tailscale: bool, mutate: impl FnOnce(&mut BeszelSection)) -> BeszelModule {
        let mut cfg: BeszelSection = toml::from_str("").unwrap();
        cfg.key = KEY.into();
        mutate(&mut cfg);
        BeszelModule::new(cfg, tailscale)
    }

    fn outbound(c: &mut BeszelSection) {
        c.hub_url = "https://beszel.example.com".into();
        c.token = "tok-123".into();
    }

    fn colocated(c: &mut BeszelSection) {
        c.key = String::new();
        c.hub = true;
    }

    fn hub_only(c: &mut BeszelSection) {
        colocated(c);
        c.agent = false;
    }

    /// Run the env generator and return the file it prints.
    fn env_file(m: &BeszelModule) -> Option<String> {
        let out = std::process::Command::new("bash")
            .args(["-c", &m.env_generator()])
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn version_is_pinned_in_download_and_detect() {
        let apply = module(true, |c| {
            colocated(c);
            c.version = "1.2.3".into();
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("__bsz_ver='1.2.3'"));
        assert!(apply.contains("releases/download/v${__bsz_ver}"));
        // The trust anchor is the pin, not a file from the same release.
        assert!(!apply.contains("checksums.txt"));
        assert!(apply.contains("= 'beszel-agent 1.2.3' ]"));
        assert!(apply
            .contains("/usr/local/bin/beszel --version 2>/dev/null)\" = 'beszel version 1.2.3' ]"));
        assert!(!apply.contains("latest"));
        assert!(!apply.contains("| sh"));
    }

    #[test]
    fn default_version_uses_the_compiled_in_hashes() {
        let apply = module(true, colocated).declaration().render_apply();
        for line in [
            "amd64) __bsz_sum='3b6ee592632ec03b9a43312e99a40203a7b3d83fe40dd0c25acda1eb915ea7c0' ;;",
            "arm64) __bsz_sum='a6ea544976b9a74398ac88d5da5bb96813d9a2e353a37bbfdb6a903fa8ba1838' ;;",
            "amd64) __bsz_sum='70857d0489cf790224167815c82f8807cc28134d27f209b58b1cd36e4082931a' ;;",
            "arm64) __bsz_sum='c2357b94d36febfd0c6df9f89f523fff6f6df69a4b8ac91a8b262d2b7fdb0584' ;;",
        ] {
            assert!(apply.contains(line), "missing {line:?}");
        }
        // Probe agrees: it never downloads, so it carries no hash either way.
        assert!(!module(true, colocated)
            .declaration()
            .render_probe()
            .contains("curl "));
    }

    #[test]
    fn overridden_version_uses_the_configured_hashes_only() {
        let (a, b) = ("ab".repeat(32), "cd".repeat(32));
        let apply = module(true, |c| {
            c.version = "0.22.0".into();
            c.sha256
                .insert("beszel-agent_linux_amd64.tar.gz".into(), a.clone());
            c.sha256
                .insert("beszel-agent_linux_arm64.tar.gz".into(), b.clone());
        })
        .declaration()
        .render_apply();
        assert!(
            apply.contains(&format!("amd64) __bsz_sum='{a}' ;;")),
            "{apply}"
        );
        assert!(apply.contains(&format!("arm64) __bsz_sum='{b}' ;;")));
        assert!(!apply.contains("3b6ee592632ec03b9a43312e99a40203a7b3d83fe40dd0c25acda1eb915ea7c0"));
        // No pin at all: an empty hash, so the length check fails closed.
        let none = module(true, |c| c.version = "0.22.0".into())
            .declaration()
            .render_apply();
        assert!(none.contains("amd64) __bsz_sum='' ;;"), "{none}");
    }

    #[test]
    fn validate_pins_rejects_unpinned_overrides_and_bad_tables() {
        let cfg = |f: &dyn Fn(&mut BeszelSection)| {
            let mut c: BeszelSection = toml::from_str("").unwrap();
            f(&mut c);
            validate_pins(&c)
        };
        let h = "a".repeat(64);
        assert!(cfg(&|_| {}).is_ok());
        let err = cfg(&|c| c.version = "0.22.0".into())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("beszel-agent_linux_amd64.tar.gz, beszel-agent_linux_arm64.tar.gz"),
            "{err}"
        );
        assert!(!err.contains("beszel_linux"), "hub not enabled: {err}");
        let agent_pins = |c: &mut BeszelSection| {
            c.version = "0.22.0".into();
            for t in [
                "beszel-agent_linux_amd64.tar.gz",
                "beszel-agent_linux_arm64.tar.gz",
            ] {
                c.sha256.insert(t.into(), "a".repeat(64));
            }
        };
        assert!(cfg(&agent_pins).is_ok());
        // With the hub too, its two tarballs are required as well.
        let err = cfg(&|c| {
            agent_pins(c);
            c.hub = true;
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("beszel_linux_amd64.tar.gz, beszel_linux_arm64.tar.gz"),
            "{err}"
        );
        // One arch missing is still rejected.
        assert!(cfg(&|c| {
            agent_pins(c);
            c.sha256.remove("beszel-agent_linux_arm64.tar.gz");
        })
        .is_err());
        // Typo'd key or malformed hash: rejected even on the default version.
        assert!(cfg(&|c| {
            c.sha256
                .insert("beszel-agent_amd64.tar.gz".into(), h.clone());
        })
        .is_err());
        for bad in ["a".repeat(63), "g".repeat(64)] {
            assert!(cfg(&|c| {
                c.sha256
                    .insert("beszel_linux_arm64.tar.gz".into(), bad.clone());
            })
            .is_err());
        }
    }

    #[test]
    fn checksum_is_verified_before_install() {
        let apply = module(true, |_| {}).declaration().render_apply();
        let check = apply.find("checksum mismatch").unwrap();
        let extract = apply.find("tar -xzf").unwrap();
        let install = apply.find("install -m 0755 -o root -g root").unwrap();
        assert!(check < extract && extract < install, "{apply}");
        assert!(apply.contains("dpkg --print-architecture"));
        assert!(apply.contains("beszel-agent_linux_${__bsz_arch}.tar.gz"));
        let hub = module(true, hub_only).declaration().render_apply();
        assert!(hub.contains("\"beszel_linux_${__bsz_arch}.tar.gz\""));
        assert!(hub.contains("-C \"$__bsz_tmp\" beszel\n"));
    }

    #[test]
    fn agent_unit_is_sandboxed_unprivileged_and_static() {
        let m = module(true, |_| {});
        let unit = m.unit_content(&AGENT);
        for line in [
            "User=beszel\n",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "CapabilityBoundingSet=\n",
            "StateDirectory=beszel-agent\n",
            "EnvironmentFile=/etc/default/beszel-agent",
            "ExecStart=/usr/local/bin/beszel-agent\n",
        ] {
            assert!(unit.contains(line), "missing {line:?}:\n{unit}");
        }
        assert!(unit.contains("SupplementaryGroups=systemd-journal\nEnvironmentFile"));
        for w in ["docker", "disk", "CAP_", "smartctl"] {
            assert!(!unit.contains(w), "nothing privileged by default: {w}");
        }
        let apply = m.declaration().render_apply();
        assert!(!apply.contains("smartmontools") && !apply.contains("getent group docker"));
        // No config value (and so no secret) ever lands in the agent unit.
        assert!(!unit.contains("KEY") && !unit.contains("TOKEN"));
        assert_eq!(unit, module(false, outbound).unit_content(&AGENT));
    }

    #[test]
    fn docker_opt_in_adds_only_the_docker_group_after_a_host_check() {
        let m = module(true, |c| c.docker = true);
        let unit = m.unit_content(&AGENT);
        assert!(
            unit.contains("SupplementaryGroups=systemd-journal docker\n"),
            "{unit}"
        );
        assert!(!unit.contains("disk") && !unit.contains("CAP_SYS"));
        let d = m.declaration();
        let apply = d.render_apply();
        let check = apply
            .find("getent group docker >/dev/null 2>&1 && command -v docker >/dev/null 2>&1")
            .unwrap();
        let refuse = apply.find("FAILED: beszel: docker = true but").unwrap();
        let start = apply.find("systemctl restart beszel-agent").unwrap();
        assert!(check < refuse && refuse < start, "{apply}");
        // Probe runs the same read-only detect.
        assert!(d
            .render_probe()
            .contains("getent group docker >/dev/null 2>&1 && command -v docker"));
        // The hub unit never gets it.
        let both = module(true, |c| {
            colocated(c);
            c.docker = true;
        });
        assert!(!both.unit_content(&HUB).contains("docker"));
    }

    #[test]
    fn smart_opt_in_adds_disk_and_rawio_only() {
        let m = module(true, |c| c.smart = true);
        let unit = m.unit_content(&AGENT);
        assert!(
            unit.contains("SupplementaryGroups=systemd-journal disk\n"),
            "{unit}"
        );
        assert!(!unit.contains("docker") && !unit.contains("CAP_SYS_ADMIN"));
        // The grants come after SANDBOX's empty resets, or systemd drops them.
        let reset = unit.find("CapabilityBoundingSet=\n").unwrap();
        let bound = unit.find("CapabilityBoundingSet=CAP_SYS_RAWIO\n").unwrap();
        let ambient = unit.find("AmbientCapabilities=CAP_SYS_RAWIO\n").unwrap();
        assert!(reset < bound && unit.find("AmbientCapabilities=\n").unwrap() < ambient);
        assert!(unit.contains("NoNewPrivileges=yes"));
        let apply = m.declaration().render_apply();
        let install = apply.find("install -y -- 'smartmontools'").unwrap();
        assert!(install < apply.find("systemctl restart beszel-agent").unwrap());
        assert!(apply.contains("'smartmontools'\n__bsz_restart=1"));
        let both = module(true, |c| {
            c.smart = true;
            c.docker = true;
        });
        assert!(both
            .unit_content(&AGENT)
            .contains("SupplementaryGroups=systemd-journal docker disk\n"));
        // Hub-only never installs or grants anything for SMART.
        let hub = module(true, |c| {
            hub_only(c);
            c.smart = true;
            c.docker = true;
        });
        assert!(!hub.unit_content(&HUB).contains("CAP_SYS_RAWIO"));
        let hub_apply = hub.declaration().render_apply();
        assert!(!hub_apply.contains("smartmontools") && !hub_apply.contains("getent group docker"));
    }

    #[test]
    fn hub_unit_runs_as_its_own_user_on_hub_listen() {
        let m = module(true, |c| {
            hub_only(c);
            c.hub_listen = "100.64.0.1:8090".into();
        });
        let unit = m.unit_content(&HUB);
        for line in [
            "User=beszel-hub\n",
            "ExecStart=/usr/local/bin/beszel serve --http 100.64.0.1:8090 --dir /var/lib/beszel-hub\n",
            "WorkingDirectory=/var/lib/beszel-hub\n",
            "StateDirectory=beszel-hub\n",
            "StateDirectoryMode=0700\n",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
        ] {
            assert!(unit.contains(line), "missing {line:?}:\n{unit}");
        }
        assert!(!unit.contains("EnvironmentFile"));
        // Hub only: no agent user, unit or env file.
        let d = m.declaration();
        assert!(d
            .files
            .iter()
            .all(|f| f.path != ENV_PATH && f.path != AGENT.unit));
        assert!(!d.render_apply().contains("useradd --system $__bsz_g --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin beszel\n"));
    }

    #[test]
    fn env_file_is_root_only_and_computed() {
        let d = module(false, outbound).declaration();
        let f = d.files.iter().find(|f| f.path == ENV_PATH).unwrap();
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0600", "root:root"));
        // Host-computed, so offline `diff` has no content to print.
        assert!(f.static_content().is_none());
    }

    #[test]
    fn hub_admin_comes_from_a_root_only_env_file_never_the_unit() {
        let with_admin = |c: &mut BeszelSection| {
            hub_only(c);
            c.admin_email = "ops@example.com".into();
            c.admin_password = "s3cret-pass word".into();
        };
        let m = module(false, with_admin);
        let unit = m.unit_content(&HUB);
        assert!(
            unit.contains("EnvironmentFile=/etc/default/beszel-hub\n"),
            "{unit}"
        );
        assert!(!unit.contains("s3cret") && !unit.contains("ops@example.com"));
        let d = m.declaration();
        let f = d.files.iter().find(|f| f.path == HUB_ENV_PATH).unwrap();
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0600", "root:root"));
        assert!(
            f.static_content().is_none(),
            "diff never shows the password"
        );
        // The probe is read-only: it starts nothing and creates no account.
        let probe = d.render_probe();
        assert!(!probe.contains("systemctl restart") && !probe.contains("systemctl start"));
        // The generator prints exactly what upstream's first-start migration reads.
        let Ok(out) = std::process::Command::new("bash")
            .args(["-c", &m.hub_env_generator()])
            .output()
        else {
            return;
        };
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "# Managed by anvil — do not edit by hand\n\
             BESZEL_HUB_USER_EMAIL=\"ops@example.com\"\n\
             BESZEL_HUB_USER_PASSWORD=\"s3cret-pass word\"\n"
        );
        // Without admin credentials: no env file, no EnvironmentFile line.
        let plain = module(false, hub_only);
        assert!(!plain.unit_content(&HUB).contains("EnvironmentFile"));
        assert!(plain
            .declaration()
            .files
            .iter()
            .all(|f| f.path != HUB_ENV_PATH));
    }

    #[test]
    fn outbound_mode_listens_on_nothing_and_opens_no_port() {
        let m = module(false, outbound);
        let Some(env) = env_file(&m) else { return };
        assert_eq!(
            env,
            "# Managed by anvil — do not edit by hand\nKEY=\"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHub hub\"\n\
             HUB_URL=\"https://beszel.example.com\"\nTOKEN=\"tok-123\"\nDISABLE_SSH=true\n"
        );
        assert!(m.firewall_rules().is_empty());
        assert!(!m.declaration().render_apply().contains("ufw "));
    }

    #[test]
    fn inbound_mode_scopes_port_to_hub_addresses() {
        let m = module(true, |c| {
            c.hub_addresses = vec!["10.0.0.5/24".into(), "192.0.2.7".into()];
        });
        if let Some(env) = env_file(&m) {
            assert!(env.ends_with("\nLISTEN=45876\n"), "{env}");
        }
        let rules = m.firewall_rules();
        // ufw-normalized needles, so detect does not drift forever.
        assert_eq!(
            rules[0].0,
            "allow from 10.0.0.0/24 to any port 45876 proto tcp"
        );
        assert_eq!(
            rules[0].1,
            "allow from '10.0.0.5/24' to any port '45876' proto 'tcp'"
        );
        assert_eq!(rules.len(), 2);
        let apply = m.declaration().render_apply();
        assert!(!apply.contains("ufw allow 45876"), "never world-open");
        assert!(!apply.contains("tailscale0"), "explicit addresses win");
    }

    #[test]
    fn inbound_mode_falls_back_to_tailnet_interface() {
        assert_eq!(
            module(true, |_| {}).firewall_rules(),
            vec![(
                "allow in on tailscale0 to any port 45876 proto tcp".to_string(),
                "allow in on tailscale0 to any port 45876 proto tcp".to_string()
            )]
        );
        assert!(module(false, |_| {}).firewall_rules().is_empty());
    }

    #[test]
    fn colocated_agent_trusts_the_local_hub_on_loopback() {
        let m = module(true, colocated);
        // No firewall rule: hub and agent both stay on loopback.
        assert!(m.firewall_rules().is_empty());
        let words = m.env_words().join(" ");
        assert!(words.contains("$(ssh-keygen -y -f /var/lib/beszel-hub/id_ed25519 2>/dev/null)"));
        assert!(words.contains("'LISTEN=127.0.0.1:45876'"));
        let apply = m.declaration().render_apply();
        // The hub key exists before the env file derives the agent's KEY.
        let key = apply
            .find("ssh-keygen -q -t ed25519 -N '' -C beszel-hub -f /var/lib/beszel-hub/id_ed25519")
            .unwrap();
        let env = apply.find("# file: /etc/default/beszel-agent").unwrap();
        assert!(key < env, "{apply}");
        assert!(apply.contains("systemctl restart beszel-hub"));
        assert!(apply.contains("systemctl restart beszel-agent"));
    }

    #[test]
    fn colocated_env_file_carries_the_hub_public_key() {
        let Ok(dir) = std::env::current_dir() else {
            return;
        };
        let tmp = dir.join("target/beszel-env-test");
        let _ = std::fs::create_dir_all(&tmp);
        let key = tmp.join("id_ed25519");
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(tmp.join("id_ed25519.pub"));
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t", "-f"])
            .arg(&key)
            .status();
        if !made.is_ok_and(|s| s.success()) {
            return; // ssh-keygen unavailable
        }
        let gen = module(true, colocated)
            .env_generator()
            .replace(HUB_KEY, &key.to_string_lossy());
        let Ok(out) = std::process::Command::new("bash")
            .args(["-c", &gen])
            .output()
        else {
            return;
        };
        let env = String::from_utf8_lossy(&out.stdout);
        let pubkey = std::fs::read_to_string(tmp.join("id_ed25519.pub")).unwrap();
        let pub_body = pubkey.split(' ').take(2).collect::<Vec<_>>().join(" ");
        assert!(env.contains(&format!("KEY=\"{pub_body}")), "{env}");
        assert!(env.ends_with("\nLISTEN=127.0.0.1:45876\n"), "{env}");
    }

    #[test]
    fn hub_on_network_address_is_firewalled() {
        let tail = module(true, |c| {
            hub_only(c);
            c.hub_listen = "0.0.0.0:8090".into();
        });
        assert_eq!(
            tail.firewall_rules()[0].0,
            "allow in on tailscale0 to any port 8090 proto tcp"
        );
        let scoped = module(false, |c| {
            hub_only(c);
            c.hub_listen = "0.0.0.0:8090".into();
            c.hub_allow_from = vec!["198.51.100.0/24".into()];
        });
        assert_eq!(
            scoped.firewall_rules()[0].0,
            "allow from 198.51.100.0/24 to any port 8090 proto tcp"
        );
        // Loopback hub opens nothing.
        assert!(module(true, hub_only).firewall_rules().is_empty());
    }

    #[test]
    fn firewall_rule_refuses_inactive_ufw_before_service_start() {
        let apply = module(true, |_| {}).declaration().render_apply();
        let refuse = apply.find("refusing to start a service").unwrap();
        let guard = apply.find("systemctl restart beszel-agent").unwrap();
        assert!(refuse < guard, "{apply}");
    }

    #[test]
    fn restart_is_gated_on_change_or_inactive() {
        let apply = module(true, colocated).declaration().render_apply();
        assert!(apply.contains("__bsz_changed=\"${__bsz_restart:-0}\""));
        assert!(apply.contains("__bsz_changed=\"${__bszhub_restart:-0}\""));
        assert!(apply.contains(
            "/etc/systemd/system/beszel-agent.service|/etc/default/beszel-agent) __bsz_changed=1"
        ));
        assert_eq!(apply.matches("systemctl restart beszel-agent").count(), 1);
        assert_eq!(apply.matches("systemctl restart beszel-hub").count(), 1);
        let probe = module(true, colocated).declaration().render_probe();
        assert!(probe.contains("systemctl is-active --quiet beszel-agent"));
        assert!(probe.contains("systemctl is-active --quiet beszel-hub"));
        for w in ["systemctl restart", "useradd", "curl ", "ssh-keygen -q"] {
            assert!(!probe.contains(w), "probe must stay read-only: {w}");
        }
    }

    #[test]
    fn rollback_removes_only_what_anvil_created() {
        let rb = module(true, |c| c.hub_addresses = vec!["192.0.2.7".into()])
            .declaration()
            .render_rollback();
        assert!(rb.contains("if __anvil_created /usr/local/bin/beszel-agent; then"));
        assert!(rb.contains("if [ -e /var/lib/anvil/beszel-user.created ] && [ ! -f "));
        assert!(rb.contains("ufw delete allow from '192.0.2.7' to any port '45876' proto 'tcp'"));
        assert!(
            rb.contains("rm -f /etc/systemd/system/multi-user.target.wants/beszel-agent.service")
        );
        assert!(rb.contains("rm -rf /var/lib/beszel-agent"));
        // The guard is a no-op once the unit file is gone.
        assert!(rb.contains("[ ! -f /etc/systemd/system/beszel-agent.service ] ||"));
        // Pre-existing binary is kept as a backup and restored.
        assert!(rb.contains("rollback (command-edited): /usr/local/bin/beszel-agent"));
    }

    #[test]
    fn hub_rollback_keeps_the_database() {
        let rb = module(true, hub_only).declaration().render_rollback();
        assert!(rb.contains("if __anvil_created /usr/local/bin/beszel; then"));
        assert!(rb.contains("if [ -e /var/lib/anvil/beszel-hub-user.created ]"));
        assert!(rb.contains("userdel beszel-hub"));
        assert!(!rb.contains("rm -rf /var/lib/beszel-hub"), "{rb}");
        assert!(rb.contains("(hub data) kept"));
        assert!(
            !rb.contains("beszel-agent"),
            "hub only touches no agent: {rb}"
        );
    }

    #[test]
    fn hostile_values_are_escaped() {
        let m = module(false, |c| {
            c.hub_url = "https://h'; rm -rf /; '".into();
            c.token = "t".into();
            c.version = "1.0.0'; id; '".into();
        });
        let apply = m.declaration().render_apply();
        assert!(apply.contains("__bsz_ver='1.0.0'\\''; id; '\\'''"));
        if let Some(env) = env_file(&m) {
            assert!(
                env.contains("HUB_URL=\"https://h'; rm -rf /; '\"\n"),
                "{env}"
            );
        }
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        for m in [
            module(false, outbound),
            module(true, |_| {}),
            module(false, |c| c.hub_addresses = vec!["10.0.0.0/8".into()]),
            module(true, colocated),
            module(true, |c| {
                c.docker = true;
                c.smart = true;
            }),
            module(true, |c| {
                hub_only(c);
                c.hub_listen = "0.0.0.0:8090".into();
            }),
        ] {
            let d = m.declaration();
            for s in [d.render_probe(), d.render_apply(), d.render_rollback()] {
                let Ok(mut child) = Command::new("bash")
                    .arg("-n")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                else {
                    return;
                };
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(s.as_bytes());
                }
                assert!(child.wait().map(|st| st.success()).unwrap_or(true), "{s}");
            }
        }
    }
}
