//! Configuration: top-level document, host spec, the load pipeline
//! and validation.

pub mod load;
pub mod schema;

use serde::{Deserialize, Serialize};

use crate::error::{AnvilError, Result};
pub use schema::*;

/// SSH target definition (`[host]` / `[[hosts]]`, R21/R22).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostSpec {
    pub address: String,
    pub user: String,
    #[serde(default = "schema::d_ssh_port")]
    pub port: u16,
    #[serde(default)]
    pub identity_file: Option<String>,
    #[serde(default)]
    pub ssh_options: Vec<String>,
}

/// The full config document. `profile`/`include` are consumed and removed
/// during loading, so they are intentionally absent here and the struct
/// can reject every other unknown key.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub host: Option<HostSpec>,
    #[serde(default)]
    pub hosts: Option<Vec<HostSpec>>,

    #[serde(default)]
    pub sshd: Option<SshdSection>,
    #[serde(default)]
    pub firewall: Option<FirewallSection>,
    #[serde(default)]
    pub fail2ban: Option<Fail2banSection>,
    #[serde(default)]
    pub updates: Option<UpdatesSection>,
    #[serde(default)]
    pub users: Option<UsersSection>,
    #[serde(default)]
    pub kernel: Option<KernelSection>,
    #[serde(default)]
    pub kernel_modules: Option<KernelModulesSection>,
    #[serde(default)]
    pub ssh_crypto: Option<SshCryptoSection>,
    #[serde(default)]
    pub suid: Option<SuidSection>,
    #[serde(default)]
    pub dns: Option<DnsSection>,
    #[serde(default)]
    pub process: Option<ProcessSection>,
    #[serde(default)]
    pub pam: Option<PamSection>,
    #[serde(default)]
    pub packages: Option<PackagesSection>,
    #[serde(default)]
    pub crowdsec: Option<CrowdsecSection>,
    #[serde(default)]
    pub auditd: Option<AuditdSection>,
    #[serde(default)]
    pub lynis: Option<LynisSection>,
    #[serde(default)]
    pub filesystem: Option<FilesystemSection>,
    #[serde(default)]
    pub docker: Option<DockerSection>,
    #[serde(default)]
    pub podman: Option<PodmanSection>,
    #[serde(default)]
    pub containers: Option<ContainersSection>,
    #[serde(default)]
    pub forgejo: Option<ForgejoSection>,
    #[serde(default)]
    pub tls: Option<TlsSection>,
    #[serde(default)]
    pub hetzner: Option<HetznerSection>,
    #[serde(default)]
    pub netcup: Option<NetcupSection>,
    #[serde(default)]
    pub headscale: Option<HeadscaleSection>,
    #[serde(default)]
    pub tailscale: Option<TailscaleSection>,
    #[serde(default)]
    pub greptimedb: Option<GreptimedbSection>,
    #[serde(default)]
    pub vector: Option<VectorSection>,
    #[serde(default)]
    pub beszel: Option<BeszelSection>,
    pub caddy: Option<CaddySection>,
    #[serde(default)]
    pub ci_resources: Option<CiResourcesSection>,
    #[serde(default)]
    pub apps_resources: Option<AppsResourcesSection>,
    #[serde(default)]
    pub github_runner: Option<GithubRunnerSection>,
    #[serde(default)]
    pub forgejo_runner: Option<ForgejoRunnerSection>,
    pub restic: Option<ResticSection>,
    #[serde(default)]
    pub coding_agents: Option<CodingAgentsSection>,

    #[serde(default)]
    pub execution_order: Option<ExecutionOrderSection>,
}

/// The canonical module id for every section, in a stable declaration order.
/// This is the id used in `--only`, ordering, and results.
pub const MODULE_IDS: &[&str] = &[
    "sshd",
    "firewall",
    "fail2ban",
    "updates",
    "users",
    "kernel",
    "kernel_modules",
    "ssh_crypto",
    "suid",
    "dns",
    "process",
    "pam",
    "packages",
    "crowdsec",
    "auditd",
    "lynis",
    "filesystem",
    "docker",
    "podman",
    "containers",
    "forgejo",
    "tls",
    "hetzner",
    "netcup",
    "headscale",
    "tailscale",
    "greptimedb",
    "vector",
    "beszel",
    "caddy",
    "ci_resources",
    "apps_resources",
    "github_runner",
    "forgejo_runner",
    "restic",
    "coding_agents",
];

/// Top-level keys a plugin may never bind as its section: every
/// built-in module id plus the structural keys. Binding one would let a
/// plugin steal a built-in module's config table.
pub fn is_reserved_section(name: &str) -> bool {
    MODULE_IDS.contains(&name)
        || matches!(
            name,
            "host" | "hosts" | "execution_order" | "profile" | "include"
        )
}

/// A host's container engine (see [`Config::host_engine`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Engine {
    #[default]
    Docker,
    Podman,
}

/// A section that is enabled (present) in the config, with its ordering hints.
#[derive(Debug, Clone)]
pub struct EnabledSection {
    pub id: &'static str,
    pub order_override: OrderOverride,
}

impl Config {
    /// All configured hosts (from `[host]` and/or `[[hosts]]`).
    pub fn hosts(&self) -> Vec<&HostSpec> {
        let mut v = Vec::new();
        if let Some(h) = &self.host {
            v.push(h);
        }
        if let Some(hs) = &self.hosts {
            v.extend(hs.iter());
        }
        v
    }

    /// Enabled sections in declaration order, each with its ordering hints.
    pub fn enabled_sections(&self) -> Vec<EnabledSection> {
        let mut out = Vec::new();
        macro_rules! push {
            ($opt:expr, $id:literal) => {
                if let Some(s) = &$opt {
                    out.push(EnabledSection {
                        id: $id,
                        order_override: s.order_override.clone(),
                    });
                }
            };
        }
        push!(self.sshd, "sshd");
        push!(self.firewall, "firewall");
        push!(self.fail2ban, "fail2ban");
        push!(self.updates, "updates");
        push!(self.users, "users");
        push!(self.kernel, "kernel");
        push!(self.kernel_modules, "kernel_modules");
        push!(self.ssh_crypto, "ssh_crypto");
        push!(self.suid, "suid");
        push!(self.dns, "dns");
        push!(self.process, "process");
        push!(self.pam, "pam");
        push!(self.packages, "packages");
        push!(self.crowdsec, "crowdsec");
        push!(self.auditd, "auditd");
        push!(self.lynis, "lynis");
        push!(self.filesystem, "filesystem");
        push!(self.docker, "docker");
        if self.docker_logs_only() {
            out.push(EnabledSection {
                id: "docker",
                order_override: OrderOverride::default(),
            });
        }
        push!(self.podman, "podman");
        push!(self.containers, "containers");
        push!(self.forgejo, "forgejo");
        push!(self.tls, "tls");
        push!(self.hetzner, "hetzner");
        push!(self.netcup, "netcup");
        push!(self.headscale, "headscale");
        push!(self.tailscale, "tailscale");
        push!(self.greptimedb, "greptimedb");
        push!(self.vector, "vector");
        push!(self.beszel, "beszel");
        if let Some(c) = &self.caddy {
            // Tailnet ports and Tailscale certificates need tailscaled up first.
            let mut order_override = c.order_override.clone();
            if c.listen == "tailnet" || c.sites.iter().any(|s| s.tls == "tailscale") {
                order_override.after.push("tailscale".into());
            }
            out.push(EnabledSection {
                id: "caddy",
                order_override,
            });
        }
        push!(self.ci_resources, "ci_resources");
        push!(self.apps_resources, "apps_resources");
        push!(self.github_runner, "github_runner");
        push!(self.forgejo_runner, "forgejo_runner");
        push!(self.restic, "restic");
        if let Some(c) = &self.coding_agents {
            // The Orca server's ufw rule and pairing address need both up first.
            let mut order_override = c.order_override.clone();
            if c.orca_server.is_some() {
                order_override
                    .after
                    .extend(["tailscale".into(), "firewall".into()]);
            }
            out.push(EnabledSection {
                id: "coding_agents",
                order_override,
            });
        }
        out
    }

    /// The one container engine this host runs: Podman with `[podman]` or
    /// `[containers] runtime = "podman"`, otherwise Docker.
    pub fn host_engine(&self) -> Engine {
        if self.podman.is_some() || self.containers.as_ref().is_some_and(|c| c.is_podman()) {
            Engine::Podman
        } else {
            Engine::Docker
        }
    }

    /// No `[docker]`, yet a module installs Docker here (and no v2
    /// runner, which writes daemon.json itself): `docker` runs logs-only so
    /// container logs are capped. (Forgejo compose already needs one of them.)
    pub fn docker_logs_only(&self) -> bool {
        let group = |d: &str| d == "group";
        self.docker.is_none()
            && self.host_engine() == Engine::Docker
            && !self.github_runner.as_ref().is_some_and(|g| g.ephemeral())
            && !self.forgejo_runner.as_ref().is_some_and(|f| f.ephemeral())
            && (self
                .containers
                .as_ref()
                .is_some_and(|c| !c.compose.is_empty())
                || self.greptimedb.is_some()
                || self.headscale.as_ref().is_some_and(|h| h.headplane)
                || self
                    .github_runner
                    .as_ref()
                    .is_some_and(|g| group(&g.docker))
                || self
                    .forgejo_runner
                    .as_ref()
                    .is_some_and(|f| group(&f.docker)))
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        self.enabled_sections().iter().any(|s| s.id == id)
    }

    /// The effective SSH port the firewall/cloud-firewall must keep open
    /// (R56/R61). The sshd module's `port` wins when that module is enabled:
    /// it converges the port to that value, so the firewall must allow it.
    ///
    /// When `[sshd]` is absent the host is already serving SSH on its live
    /// `port`; the firewall must allow *that*, not a hardcoded 22 — otherwise
    /// it fences off the real port and locks the operator out. When the
    /// hosts disagree on a port there is no single safe value; `validate`
    /// rejects that case, and 22 is only a last resort here.
    pub fn effective_ssh_port(&self) -> u16 {
        if let Some(s) = &self.sshd {
            return s.port;
        }
        let mut ports: Vec<u16> = self.hosts().iter().map(|h| h.port).collect();
        ports.sort_unstable();
        ports.dedup();
        if ports.len() == 1 {
            ports[0]
        } else {
            // No hosts (validate rejects) or distinct ports with no [sshd]
            // (validate reports the ambiguity); 22 only because validate gates
            // every apply before we rely on this value.
            22
        }
    }

    /// Live host ports other than the effective SSH port: sshd may
    /// still be listening there when the firewall/cloud firewall converges
    /// (port-move cutover, or an sshd failure that reverted), so they stay open.
    pub fn live_ssh_ports(&self) -> Vec<u16> {
        let effective = self.effective_ssh_port();
        let mut ports: Vec<u16> = self.hosts().iter().map(|h| h.port).collect();
        ports.retain(|&p| p != effective);
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Valid but risky container setups, printed (not rejected) at load.
    pub fn warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let iptables_off = self.docker.as_ref().is_some_and(|d| d.iptables_off());
        let compose = self
            .containers
            .as_ref()
            .is_some_and(|c| !c.compose.is_empty());
        if iptables_off && compose {
            w.push(
                "[docker] iptables_off = true: compose containers get no outbound internet \
                 (set it to false and publish ports on 127.0.0.1 only)"
                    .into(),
            );
        }
        if let Some(h) = self.headscale.as_ref().filter(|h| h.headplane) {
            let public = h
                .headplane_listen
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|a| !a.ip().is_loopback());
            if public && !iptables_off {
                w.push(format!(
                    "headscale.headplane_listen = {:?} is published by Docker, which bypasses ufw: \
                     it is reachable from the internet",
                    h.headplane_listen
                ));
            }
        }
        if let Some(h) = &self.headscale {
            // T6: headscale has no TLS here; clients need https:// in front.
            if !h.server_url.starts_with("https://") {
                w.push(format!(
                    "headscale.server_url = {:?} is not https://: clients send their \
                     registration over plain HTTP; front headscale with [caddy] or [tls]",
                    h.server_url
                ));
            }
            let public = h
                .listen_addr
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|a| !a.ip().is_loopback());
            if public {
                w.push(format!(
                    "headscale.listen_addr = {:?} serves plain HTTP beyond loopback; behind \
                     [caddy] or [tls] use \"127.0.0.1:8080\"",
                    h.listen_addr
                ));
            }
        }
        if let Some(f) = &self.forgejo {
            w.extend(crate::modules::forgejo::warnings(f, self.firewall.as_ref()));
            w.extend(crate::modules::forgejo::proxy_warnings(
                f,
                self.tls.as_ref(),
                self.caddy.as_ref(),
            ));
        }
        if let Some(h) = &self.hetzner {
            w.extend(self.provider_firewall_warnings("hetzner", &h.rules));
        }
        if let Some(n) = &self.netcup {
            w.extend(self.provider_firewall_warnings("netcup", &n.rules));
        }
        let docker_group = self
            .github_runner
            .as_ref()
            .is_some_and(|g| g.docker == "group")
            || self
                .forgejo_runner
                .as_ref()
                .is_some_and(|f| f.docker == "group");
        if docker_group && self.ci_resources.is_some() {
            w.push(
                "[ci_resources] does not cap docker = \"group\" job containers: they run \
                 under dockerd's cgroup, outside ci.slice (the runner's own caps \
                 do not reach them either)"
                    .into(),
            );
        }
        w
    }

    /// CA3/T17: anvil never adds provider rules for caddy/beszel; it warns
    /// when the explicit `[hetzner]`/`[netcup]` rules (`provider`) leave
    /// their public ports shut.
    fn provider_firewall_warnings(&self, provider: &str, rules: &[CloudEdgeRule]) -> Vec<String> {
        let mut w = Vec::new();
        if let Some(c) = self.caddy.as_ref().filter(|c| c.listen == "public") {
            for (port, effect) in [
                (
                    c.http_port,
                    "ACME HTTP-01 and the HTTP→HTTPS redirect will fail",
                ),
                (c.https_port, "the site and ACME will be unreachable"),
            ] {
                if !rules.iter().any(|r| rule_allows(r, port, None)) {
                    w.push(format!(
                        "{provider}: [caddy] is enabled but no rule allows {port}/tcp — {effect}"
                    ));
                }
            }
        }
        // validate() allows hub_addresses only for an inbound remote agent,
        // where they open listen_port. hub_allow_from is skipped: T19 keeps
        // it on the tailnet unless hub_listen is itself a tailnet IP, which
        // public hosts can only reach over WireGuard anyway.
        if let Some(b) = &self.beszel {
            for a in b.hub_addresses.iter().filter(|a| is_public(a)) {
                if !rules.iter().any(|r| rule_allows(r, b.listen_port, Some(a))) {
                    w.push(format!(
                        "{provider}: beszel.hub_addresses has public {a} but no rule allows it on \
                         {}/tcp — the hub cannot reach this agent",
                        b.listen_port
                    ));
                }
            }
        }
        w
    }

    /// Validate the whole document (R22/R48). All checks run before any
    /// connection is attempted.
    pub fn validate(&self) -> Result<()> {
        let hosts = self.hosts();
        if hosts.is_empty() {
            return Err(AnvilError::Validation(
                "no host defined: add a [host] table or at least one [[hosts]] entry".into(),
            ));
        }
        for (i, h) in hosts.iter().enumerate() {
            validate_host(h, i)?;
            // Two entries for one box would race under --parallel.
            if let Some(j) = hosts[..i]
                .iter()
                .position(|o| o.address.eq_ignore_ascii_case(&h.address) && o.port == h.port)
            {
                return Err(AnvilError::Validation(format!(
                    "host[{i}] duplicates host[{j}] ({}:{}): two concurrent \
                     sessions to one box would race under --parallel",
                    h.address, h.port
                )));
            }
        }
        // When [sshd] is absent, a firewall/cloud-firewall module must
        // infer the live SSH port from the host(s). If the hosts disagree there
        // is no single port it can allow without fencing another off — surface
        // it here, before any connection, rather than locking the operator out
        // mid-apply.
        if self.sshd.is_none()
            && (self.firewall.is_some()
                || self.fail2ban.is_some()
                || self.hetzner.is_some()
                || self.netcup.is_some()
                || self.tailscale.is_some())
        {
            let mut ports: Vec<u16> = hosts.iter().map(|h| h.port).collect();
            ports.sort_unstable();
            ports.dedup();
            if ports.len() > 1 {
                return Err(AnvilError::Validation(format!(
                    "ssh port is ambiguous: [sshd] is absent so a \
                     firewall/cloud-firewall module must infer the live port \
                     from the hosts, but they disagree ({ports:?}). Add an \
                     [sshd] section with an explicit port, or give every host \
                     the same port."
                )));
            }
        }
        if let Some(s) = &self.sshd {
            validate_port("sshd.port", s.port)?;
            // MaxAuthTries 0 passes `sshd -t` (so the reload guard lets it
            // through) but makes OpenSSH reject every authentication — an SSH
            // lockout R3 forbids. Sibling of the pam.deny guard below.
            if s.max_auth_tries == 0 {
                return Err(AnvilError::Validation(
                    "sshd.max_auth_tries must be at least 1 (0 rejects every login)".into(),
                ));
            }
            for user in &s.allow_users {
                validate_allow_user(user)?;
            }
            // `sshd -t` accepts a config that refuses the login user, so
            // the reload succeeds and the next connection is locked out. Allow
            // it only when this run also creates a usable sudo account.
            let denied = |name: &str| {
                (name == "root" && s.disable_root_login)
                    || (!s.allow_users.is_empty() && !s.allow_users.iter().any(|u| u == name))
            };
            let escape_hatch = self.users.as_ref().is_some_and(|u| {
                u.create.iter().any(|a| {
                    a.sudo
                        && a.ssh_authorized_keys
                            .as_ref()
                            .is_some_and(|k| !k.is_empty())
                        && !denied(&a.name)
                })
            });
            for h in &hosts {
                if denied(&h.user) && !escape_hatch {
                    return Err(AnvilError::Validation(format!(
                        "host {} logs in as {:?}, which [sshd] would refuse \
                         (disable_root_login / allow_users): the next login \
                         would be locked out. Log in as a permitted user, or \
                         add a [users].create account with sudo = true and \
                         ssh_authorized_keys{}",
                        h.address,
                        h.user,
                        if s.allow_users.is_empty() {
                            String::new()
                        } else {
                            " and list it in sshd.allow_users".into()
                        }
                    )));
                }
            }
        }
        if let Some(f) = &self.firewall {
            validate_enum(
                "firewall.default_incoming",
                &f.default_incoming,
                &["deny", "allow", "reject"],
            )?;
            validate_enum(
                "firewall.default_outgoing",
                &f.default_outgoing,
                &["deny", "allow", "reject"],
            )?;
        }
        if let Some(u) = &self.updates {
            validate_hhmm("updates.reboot_time", &u.reboot_time)?;
        }
        if let Some(u) = &self.users {
            for acct in &u.create {
                validate_username(&acct.name)?;
            }
        }
        if let Some(p) = &self.packages {
            for name in &p.install {
                validate_package_name("packages.install", name)?;
            }
            for name in &p.remove {
                validate_package_name("packages.remove", name)?;
            }
            // Listed in both would purge/reinstall on every run.
            if let Some(name) = p.install.iter().find(|n| p.remove.contains(n)) {
                return Err(AnvilError::Validation(format!(
                    "packages: {name:?} is in both install and remove"
                )));
            }
        }
        if let Some(mode) = self.crowdsec.as_ref().and_then(|c| c.bouncer_mode.as_ref()) {
            validate_enum("crowdsec.bouncer_mode", mode, &["iptables", "nftables"])?;
        }
        if let Some(a) = &self.auditd {
            // Only the rule sets the auditd module ships (single source of
            // truth in schema::AUDITD_RULE_SETS); naming anything else must
            // fail loudly instead of silently applying no rules.
            validate_enum("auditd.rule_set", &a.rule_set, AUDITD_RULE_SETS)?;
        }
        if let Some(t) = &self.tls {
            validate_enum("tls.provider", &t.provider, &["certbot", "acme.sh"])?;
            // Domains reach nginx `server_name` and the cert directory path.
            for d in &t.domains {
                if !is_hostname(d) {
                    return Err(invalid("tls.domains", d, "a hostname ([A-Za-z0-9.-])"));
                }
            }
            if let Some(w) = &t.webroot {
                if !w.starts_with('/')
                    || w.contains(|c: char| c.is_whitespace() || c.is_control() || c == ';')
                {
                    return Err(invalid(
                        "tls.webroot",
                        w,
                        "an absolute path without whitespace or ';'",
                    ));
                }
            }
        }
        if let Some(h) = &self.hetzner {
            if h.server_name.trim().is_empty() {
                return Err(AnvilError::Validation(
                    "hetzner.server_name must not be empty".into(),
                ));
            }
            for (i, rule) in h.rules.iter().enumerate() {
                let at = format!("hetzner.rules[{i}]");
                validate_enum(&format!("{at}.direction"), &rule.direction, &["in", "out"])?;
                validate_enum(
                    &format!("{at}.protocol"),
                    &rule.protocol,
                    &["tcp", "udp", "icmp", "esp", "gre"],
                )?;
                if let Some(port) = &rule.port {
                    validate_hetzner_port(&format!("{at}.port"), &rule.protocol, port)?;
                }
                for ip in &rule.source_ips {
                    validate_cidr(&format!("{at}.source_ips"), ip)?;
                }
            }
            if !h.keep_public_ssh && !self.tailscale.as_ref().is_some_and(|t| t.tailnet_only_ssh) {
                return Err(AnvilError::Validation(
                    "hetzner.keep_public_ssh = false requires [tailscale] tailnet_only_ssh = true: \
                     without the tailnet as the SSH path, closing public SSH at the cloud \
                     firewall locks you out of the server (recovery only via the Hetzner console)"
                        .into(),
                ));
            }
        }
        if let Some(n) = &self.netcup {
            if n.server.trim().is_empty() {
                return Err(AnvilError::Validation(
                    "netcup.server must not be empty (SCP server id or name)".into(),
                ));
            }
            if n.policy.trim().is_empty() || n.policy.chars().count() > 255 {
                return Err(invalid(
                    "netcup.policy",
                    &n.policy,
                    "a non-empty policy name of at most 255 characters",
                ));
            }
            for (i, rule) in n.rules.iter().enumerate() {
                let at = format!("netcup.rules[{i}]");
                validate_enum(&format!("{at}.direction"), &rule.direction, &["in", "out"])?;
                validate_enum(
                    &format!("{at}.protocol"),
                    &rule.protocol,
                    &["tcp", "udp", "icmp", "icmpv6"],
                )?;
                if let Some(port) = &rule.port {
                    validate_hetzner_port(&format!("{at}.port"), &rule.protocol, port)?;
                }
                for ip in &rule.source_ips {
                    validate_cidr(&format!("{at}.source_ips"), ip)?;
                }
            }
            if !n.keep_public_ssh && !self.tailscale.as_ref().is_some_and(|t| t.tailnet_only_ssh) {
                return Err(AnvilError::Validation(
                    "netcup.keep_public_ssh = false requires [tailscale] tailnet_only_ssh = true: \
                     without the tailnet as the SSH path, closing public SSH at the SCP \
                     firewall locks you out of the server (recovery only via the SCP console)"
                        .into(),
                ));
            }
        }
        if let Some(h) = &self.headscale {
            validate_headscale_server_url(&h.server_url)?;
            // A hostname is inert in YAML; headscale refuses a server_url
            // host inside base_domain.
            if !is_hostname(&h.base_domain) || !h.base_domain.contains('.') {
                return Err(invalid(
                    "headscale.base_domain",
                    &h.base_domain,
                    "a DNS name, e.g. \"tailnet.example.com\"",
                ));
            }
            let (host, base) = (url_host(&h.server_url), h.base_domain.to_ascii_lowercase());
            if host == base || host.ends_with(&format!(".{base}")) {
                return Err(AnvilError::Validation(format!(
                    "headscale.base_domain = {:?} must not contain the server_url host {host:?} \
                     (use a separate name, e.g. \"tailnet.example.com\")",
                    h.base_domain
                )));
            }
            validate_semver("headscale.version", &h.version)?;
            crate::modules::headscale::validate_pins(h)?;
            if let Some(hv) = &h.headplane_version {
                validate_semver("headscale.headplane_version", hv)?;
            }
            // Lands raw in the headplane unit's ExecStart docker `-p` flag.
            if h.headplane_listen.parse::<std::net::SocketAddr>().is_err() {
                return Err(invalid(
                    "headscale.headplane_listen",
                    &h.headplane_listen,
                    "IPv4:port or [IPv6]:port (e.g. \"127.0.0.1:3000\")",
                ));
            }
            // Key names form a file path and a `--user` argument.
            for k in &h.auth_keys {
                if !crate::plugin::valid_name(&k.name) {
                    return Err(invalid(
                        "headscale.auth_keys.name",
                        &k.name,
                        "[A-Za-z0-9_-]+",
                    ));
                }
                if k.expiration_secs().is_none_or(|s| s < 60) {
                    return Err(invalid(
                        "headscale.auth_keys.expiration",
                        &k.expiration,
                        "a duration of at least 1m, e.g. \"24h\", \"7d\" or \"1h30m\"",
                    ));
                }
                // headscale's own rule (`tag:` + lowercase); also comma-free,
                // as they are joined into one `--tags` value.
                for t in &k.tags {
                    let ok = t.strip_prefix("tag:").is_some_and(|r| {
                        !r.is_empty()
                            && r.chars().all(|c| {
                                c.is_ascii_lowercase()
                                    || c.is_ascii_digit()
                                    || matches!(c, '-' | '_' | '.')
                            })
                    });
                    if !ok {
                        return Err(invalid(
                            "headscale.auth_keys.tags",
                            t,
                            "tag:<name> in lowercase letters, digits, '-', '_' or '.'",
                        ));
                    }
                }
            }
        }
        if let Some(d) = &self.docker {
            validate_enum("docker.source", &d.source, &["vendor", "distro"])?;
            validate_enum(
                "docker.log_driver",
                &d.log_driver,
                &["json-file", "journald"],
            )?;
        }
        if let Some(p) = &self.podman {
            validate_enum(
                "podman.log_driver",
                &p.log_driver,
                &["k8s-file", "journald"],
            )?;
            validate_enum("podman.source", &p.source, &["distro"])?;
            if self
                .containers
                .as_ref()
                .is_some_and(|c| c.runtime.as_deref() == Some("docker"))
            {
                return Err(AnvilError::Validation(
                    "[podman] makes this a Podman host; it cannot be combined with \
                     [containers] runtime = \"docker\". Drop runtime or set it to \"podman\""
                        .into(),
                ));
            }
        }
        let podman = self.host_engine() == Engine::Podman;
        if let Some(c) = &self.containers {
            validate_containers(c, podman)?;
        }
        // One engine per host: each row installs or configures Docker.
        // Later work lifts rows as their Podman variants land.
        let group = |d: Option<&String>| d.is_some_and(|d| d == "group");
        let docker_only = [
            (
                self.docker.is_some(),
                "[docker] hardens dockerd",
                "Drop [docker] or use a Docker host",
            ),
            (
                group(self.github_runner.as_ref().map(|g| &g.docker)),
                "github_runner docker = \"group\" installs Docker",
                "Use docker = \"none\", docker = \"rootless\", a Docker host, or the v2 runner (mode = \"ephemeral\", \
                 a Podman sandbox per job)",
            ),
            (
                group(self.forgejo_runner.as_ref().map(|f| &f.docker)),
                "forgejo_runner docker = \"group\" installs Docker",
                "Use docker = \"rootless\" or a Docker host",
            ),
            (
                self.forgejo_runner.as_ref().is_some_and(|f| f.ephemeral()),
                "forgejo_runner mode = \"ephemeral\" runs sysbox sandboxes on Docker",
                "Use mode = \"persistent\" with docker = \"podman\" (a Podman sandbox is not supported yet)",
            ),
            (
                self.headscale
                    .as_ref()
                    .is_some_and(|h| h.headplane && h.headplane_docker_socket),
                "headscale.headplane_docker_socket mounts the Docker socket",
                "Drop headplane_docker_socket (Headplane itself runs as a Quadlet)",
            ),
        ];
        for (on, what, hint) in docker_only {
            if podman && on {
                return Err(AnvilError::Validation(format!(
                    "{what}; it cannot run on a Podman host ([podman] or \
                     [containers] runtime = \"podman\"). {hint}"
                )));
            }
        }
        let rootless = [
            (
                "github_runner",
                self.github_runner.as_ref().map(|g| &g.docker),
            ),
            (
                "forgejo_runner",
                self.forgejo_runner.as_ref().map(|f| &f.docker),
            ),
        ];
        let rootless = rootless.into_iter().chain([(
            "coding_agents",
            self.coding_agents.as_ref().map(|c| &c.docker),
        )]);
        let distro = self.docker.as_ref().is_some_and(|d| d.source == "distro");
        for (module, docker) in rootless {
            if !podman && docker.is_some_and(|d| d == "podman") {
                return Err(AnvilError::Validation(format!(
                    "{module} docker = \"podman\" needs a Podman host: add [podman] (or \
                     [containers] runtime = \"podman\"), or use docker = \"rootless\" on this Docker host"
                )));
            }
            // shortcut: rootless dockerd comes from docker-ce-rootless-extras; Ubuntu's
            // docker.io would need its own rootlesskit path, add it when someone asks.
            if !podman && distro && docker.is_some_and(|d| d == "rootless") {
                return Err(AnvilError::Validation(format!(
                    "{module} docker = \"rootless\" needs Docker's own packages \
                     (docker-ce-rootless-extras): set [docker] source = \"vendor\""
                )));
            }
        }
        let rootless_sandboxes = [
            (
                "forgejo_runner",
                self.forgejo_runner
                    .as_ref()
                    .is_some_and(|f| f.docker_rootless()),
            ),
            (
                "github_runner",
                self.github_runner.as_ref().is_some_and(|g| {
                    g.ephemeral() && g.sandbox_runtime(Engine::Docker) == "docker-rootless"
                }),
            ),
        ];
        if let Some((m, _)) = rootless_sandboxes.iter().find(|(_, on)| distro && *on) {
            return Err(AnvilError::Validation(format!(
                "{m} sandbox_runtime = \"docker-rootless\" (the default) needs Docker's own \
                 packages (docker-ce-rootless-extras): set [docker] source = \"vendor\", or \
                 sandbox_runtime = \"sysbox-runc\""
            )));
        }
        // Rootful netavark publishes past ufw: the generated Quadlets get the
        // [containers.quadlet] loopback check (Docker's default iptables_off
        // leaves these to ufw instead).
        if podman {
            let generated = [
                self.greptimedb.as_ref().map(|g| {
                    (
                        "greptimedb.listen_address",
                        crate::modules::greptimedb::GreptimedbModule::new(g.clone())
                            .quadlet_content(),
                    )
                }),
                self.headscale.as_ref().filter(|h| h.headplane).map(|h| {
                    (
                        "headscale.headplane_listen",
                        crate::modules::headscale::HeadscaleModule::new(h.clone())
                            .headplane_quadlet_content(),
                    )
                }),
            ];
            for (field, content) in generated.into_iter().flatten() {
                quadlet_publishes_loopback_only(&content).map_err(|bad| {
                    AnvilError::Validation(format!(
                        "{field}: {bad:?} may publish beyond 127.0.0.1; rootful Podman \
                         (netavark) would expose it past ufw — use a loopback address \
                         and a reverse proxy or the tailnet"
                    ))
                })?;
            }
        }
        if let Some(f) = &self.forgejo {
            crate::modules::forgejo::validate(f, self.effective_ssh_port())?;
            // A v2 runner brings Docker only with sysbox.
            let v2_runner = !podman
                && (self.github_runner.as_ref().is_some_and(|g| g.ephemeral())
                    || self.forgejo_runner.as_ref().is_some_and(|f| f.ephemeral()));
            crate::modules::forgejo::validate_host(
                f,
                self.docker.is_some() || v2_runner,
                podman,
                self.tailscale.is_some(),
            )?;
        }
        if let Some(v) = &self.vector {
            // Vector matches globs against paths relative to the cgroup root.
            if let Some(p) = v
                .cgroups_include
                .iter()
                .find(|p| p.is_empty() || p.starts_with('/'))
            {
                return Err(invalid(
                    "vector.cgroups_include",
                    p,
                    "a glob relative to /sys/fs/cgroup, e.g. \"system.slice/docker-*.scope\"",
                ));
            }
            // The CI slice moved; an old config naming it would make
            // every ci.slice panel silently empty.
            if let Some(p) = v
                .cgroups_include
                .iter()
                .find(|p| p.starts_with("anvil.slice"))
            {
                return Err(invalid(
                    "vector.cgroups_include",
                    p,
                    "the CI cgroup's new name: CI moved from anvil.slice to ci.slice, \
                     so use \"ci.slice/**\" instead",
                ));
            }
        }
        if let Some(g) = &self.greptimedb {
            validate_greptimedb_data_dir(&g.data_dir)?;
            validate_greptimedb_version(&g.version)?;
            if let Some(r) = &g.retention {
                validate_greptimedb_retention(r, &g.version)?;
            }
            if let Some(m) = &g.memory_max {
                validate_greptimedb_memory_max(m)?;
            }
            // CR9: greptimedb owns the compose project (Podman: Quadlet) of its name.
            if let Some(c) = &self.containers {
                for (kind, taken) in [
                    ("compose", c.compose.contains_key("greptimedb")),
                    ("quadlet", c.quadlet.contains_key("greptimedb")),
                ] {
                    if taken {
                        return Err(AnvilError::Validation(format!(
                            "[containers.{kind}.greptimedb] is reserved for [greptimedb]; \
                             rename it"
                        )));
                    }
                }
            }
            // Lands raw in the unit's ExecStart docker `-p <addr>:port` flags.
            let a = &g.listen_address;
            let ok = a.parse::<std::net::Ipv4Addr>().is_ok()
                || a.strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok());
            if !ok {
                return Err(invalid(
                    "greptimedb.listen_address",
                    a,
                    "an IPv4 address or [IPv6] (e.g. \"127.0.0.1\")",
                ));
            }
        }
        if let Some(b) = &self.beszel {
            self.validate_beszel(b)?;
        }
        if let Some(r) = &self.restic {
            crate::modules::restic::validate(r)?;
        }
        if let Some(p) = &self.pam {
            validate_umask("pam.umask", &p.umask)?;
            // deny=0 would lock the account on zero failures — nonsensical and a
            // lockout hazard; require at least one failed attempt first.
            if p.deny == 0 {
                return Err(AnvilError::Validation(
                    "pam.deny must be at least 1 (failures before the account locks)".into(),
                ));
            }
        }
        if let Some(f) = &self.fail2ban {
            validate_duration("fail2ban.bantime", &f.bantime)?;
            validate_duration("fail2ban.findtime", &f.findtime)?;
            for (name, jail) in &f.jails {
                // The name becomes an INI `[section]` header in jail.d.
                let ok = !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
                    && !name.eq_ignore_ascii_case("DEFAULT")
                    && !name.eq_ignore_ascii_case("INCLUDES");
                if !ok {
                    return Err(invalid(
                        "fail2ban.jails",
                        name,
                        "[A-Za-z0-9_.-]+ and not DEFAULT/INCLUDES",
                    ));
                }
                if let Some(b) = &jail.bantime {
                    validate_duration(&format!("fail2ban.jails.{name}.bantime"), b)?;
                }
                if let Some(port) = &jail.port {
                    validate_port_spec(&format!("fail2ban.jails.{name}.port"), port)?;
                }
            }
        }
        if let Some(fw) = &self.firewall {
            for (side, rules) in [("allow", &fw.allow), ("deny", &fw.deny)] {
                for (i, rule) in rules.iter().enumerate() {
                    let at = format!("firewall.{side}[{i}]");
                    validate_port_spec(&format!("{at}.port"), &rule.port)?;
                    if let Some(proto) = &rule.proto {
                        validate_enum(
                            &format!("{at}.proto"),
                            proto,
                            &["tcp", "udp", "ah", "esp", "gre", "ipv6"],
                        )?;
                    }
                    if let Some(from) = &rule.from {
                        validate_cidr(&format!("{at}.from"), from)?;
                    }
                }
            }
        }
        if let Some(d) = &self.dns {
            for s in &d.dns_servers {
                validate_ip("dns.dns_servers", s)?;
            }
            for s in &d.fallback_servers {
                validate_ip("dns.fallback_servers", s)?;
            }
        }
        if let Some(k) = &self.kernel {
            for (key, value) in &k.extra_sysctl {
                validate_sysctl_key(key)?;
                // The value lands on a `key = value` line: no newline/control chars.
                if value.contains(char::is_control) {
                    return Err(invalid(
                        &format!("kernel.extra_sysctl.{key}"),
                        value,
                        "a single line without control characters",
                    ));
                }
            }
        }
        if let Some(c) = &self.caddy {
            validate_caddy(
                c,
                self.tls.is_some(),
                self.tailscale.is_some(),
                self.firewall.is_some(),
            )?;
        }
        // `plugin::<name>` ids are resolved against discovered plugins later;
        // an id that matches no enabled node is simply ignored by the ordering
        // resolver — so a typo must be caught here.
        let check = |field: String, m: &str| {
            if MODULE_IDS.contains(&m) || m.starts_with("plugin::") {
                return Ok(());
            }
            Err(AnvilError::Validation(format!(
                "{field} references unknown module {m:?}; \
                 expected one of: {} (or plugin::<name>)",
                MODULE_IDS.join(", ")
            )))
        };
        if let Some(eo) = &self.execution_order {
            for m in &eo.modules {
                check("execution_order.modules".into(), m)?;
            }
        }
        for e in self.enabled_sections() {
            let o = &e.order_override;
            for m in &o.before {
                check(format!("{}.order_override.before", e.id), m)?;
            }
            for m in &o.after {
                check(format!("{}.order_override.after", e.id), m)?;
            }
        }
        if let Some(g) = &self.github_runner {
            validate_github_runner(g, self.host_engine())?;
            // ufw cannot allow by hostname; GitHub's endpoints need outbound 443.
            if g.proxy.is_empty()
                && self
                    .firewall
                    .as_ref()
                    .is_some_and(|f| f.default_outgoing != "allow")
            {
                return Err(AnvilError::Validation(
                    "github_runner needs outbound HTTPS to github.com: set \
                     firewall.default_outgoing = \"allow\" or github_runner.proxy"
                        .into(),
                ));
            }
        }
        if let Some(r) = &self.forgejo_runner {
            crate::modules::forgejo_runner::validate(r, self.forgejo.as_ref())?;
        }
        if let Some(c) = &self.coding_agents {
            self.validate_coding_agents(c)?;
        }
        if let Some(c) = &self.ci_resources {
            validate_runner_limits(
                "ci_resources",
                (None, None),
                c.cpu_quota.as_deref(),
                c.memory_max.as_deref(),
                c.tasks_max,
            )?;
            validate_cpu_weight("ci_resources", c.cpu_weight)?;
        }
        if let Some(a) = &self.apps_resources {
            validate_runner_limits(
                "apps_resources",
                (None, None),
                a.cpu_quota.as_deref(),
                a.memory_max.as_deref(),
                a.tasks_max,
            )?;
            validate_cpu_weight("apps_resources", a.cpu_weight)?;
            if let Some(low) = &a.system_memory_low {
                validate_memory_value("apps_resources.system_memory_low", low)?;
            }
        }
        // T4: the cutover only edits ufw rules; without [firewall] it would be a
        // silent no-op and public SSH stays open.
        if self.tailscale.as_ref().is_some_and(|t| t.tailnet_only_ssh) && self.firewall.is_none() {
            return Err(AnvilError::Validation(
                "tailscale.tailnet_only_ssh = true requires [firewall]: the cutover \
                 works through ufw rules, so without it public SSH stays open"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl Config {
    /// `[coding_agents]` (docs/design/coding-agents.md §1): the agent is an
    /// untrusted local user, so it must be a no-sudo `[users]` account and
    /// never a service or runner account.
    fn validate_coding_agents(&self, c: &CodingAgentsSection) -> Result<()> {
        let err = |m: String| Err(AnvilError::Validation(format!("coding_agents.{m}")));
        let u = &c.user;
        if matches!(
            u.as_str(),
            "root" | "git" | "github-runner" | "forgejo-runner" | "beszel"
        ) {
            return err(format!(
                "user = {u:?} is a system, runner or docker-group account; use its own login user"
            ));
        }
        match self
            .users
            .as_ref()
            .and_then(|s| s.create.iter().find(|a| &a.name == u))
        {
            None => {
                return err(format!(
                    "user = {u:?} must be a [users].create account (with sudo = false)"
                ))
            }
            Some(a) if a.sudo => {
                return err(format!(
                    "user = {u:?} has sudo = true: a hijacked agent would be root"
                ))
            }
            Some(_) => {}
        }
        if let Some(s) = self.sshd.as_ref().filter(|s| !s.allow_users.is_empty()) {
            if !s.allow_users.contains(u) {
                return err(format!("user = {u:?} is missing from sshd.allow_users"));
            }
        }
        if self
            .firewall
            .as_ref()
            .is_some_and(|f| f.default_outgoing != "allow")
        {
            return err("needs outbound HTTPS (Anthropic, GitHub, npm): set \
                        firewall.default_outgoing = \"allow\""
                .into());
        }
        if let Some(o) = &c.orca_server {
            if self.tailscale.is_none() || self.firewall.is_none() {
                return err(
                    "orca_server requires [tailscale] and [firewall]: it listens on \
                            0.0.0.0 and ufw keeps it on tailscale0 only"
                        .into(),
                );
            }
            if self
                .firewall
                .as_ref()
                .is_some_and(|f| f.default_incoming == "allow")
            {
                return err(
                    "orca_server needs firewall.default_incoming = \"deny\" (or \
                            \"reject\"); with \"allow\" a shell-as-agent server is world-open"
                        .into(),
                );
            }
            if o.port == 0 {
                return err("orca_server.port must be 1-65535".into());
            }
            crate::modules::coding_agents::validate_pins(o)?;
        }
        validate_enum("coding_agents.docker", &c.docker, &["none", "rootless"])?;
        validate_enum(
            "coding_agents.claude_code",
            &c.claude_code,
            &["stable", "latest", "none"],
        )?;
        let claude = c.claude_code != "none";
        let opencode = c.opencode != "none";
        // The v2 installer's `--version` (e.g. 2.2.5, 0.0.0-beta-17236).
        let version = c.opencode.starts_with(|ch: char| ch.is_ascii_digit())
            && c.opencode
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'));
        if !matches!(c.opencode.as_str(), "latest" | "none") && !version {
            return Err(invalid(
                "coding_agents.opencode",
                &c.opencode,
                "\"latest\", \"none\" or a version such as \"2.2.5\"",
            ));
        }
        // Every entry is shell-escaped; this only keeps them one word each.
        let word = |field: &str, v: &str| {
            if v.is_empty() || v.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
                Err(invalid(
                    &format!("coding_agents.{field}"),
                    v,
                    "one non-empty word",
                ))
            } else {
                Ok(())
            }
        };
        if !(claude || opencode)
            && !(c.skills.is_empty()
                && c.claude_marketplaces.is_empty()
                && c.claude_plugins.is_empty()
                && c.opencode_plugins.is_empty()
                && c.opencode_mcp.is_empty()
                && c.setup.is_none())
        {
            return err(
                "lists and setup need an agent: claude_code and opencode are both \"none\"".into(),
            );
        }
        for s in &c.skills {
            let repo = s.source.split_once('/').is_some_and(|(o, r)| {
                [o, r].iter().all(|p| {
                    !p.is_empty()
                        && p.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
                })
            });
            if !(repo || s.source.starts_with("https://")) {
                return Err(invalid(
                    "coding_agents.skills.source",
                    &s.source,
                    "owner/repo or an https git URL",
                ));
            }
            word("skills.source", &s.source)?;
            for n in &s.names {
                word("skills.names", n)?;
            }
            for a in s.agents.iter().flatten() {
                validate_enum(
                    "coding_agents.skills.agents",
                    a,
                    &["claude-code", "opencode"],
                )?;
                if (a == "claude-code" && !claude) || (a == "opencode" && !opencode) {
                    return err(format!(
                        "skills: {:?} targets {a}, which is not installed",
                        s.source
                    ));
                }
            }
        }
        if !claude && (!c.claude_marketplaces.is_empty() || !c.claude_plugins.is_empty()) {
            return err("claude_marketplaces/claude_plugins need claude_code".into());
        }
        if !opencode && (!c.opencode_plugins.is_empty() || !c.opencode_mcp.is_empty()) {
            return err("opencode_plugins/opencode_mcp need opencode".into());
        }
        for m in &c.claude_marketplaces {
            word("claude_marketplaces", m)?;
        }
        for p in &c.claude_plugins {
            word("claude_plugins", p)?;
            if !p
                .split_once('@')
                .is_some_and(|(n, m)| !n.is_empty() && !m.is_empty())
            {
                return Err(invalid(
                    "coding_agents.claude_plugins",
                    p,
                    "<name>@<marketplace>",
                ));
            }
        }
        for p in &c.opencode_plugins {
            word("opencode_plugins", p)?;
        }
        for (name, cmd) in &c.opencode_mcp {
            word("opencode_mcp", name)?;
            if cmd.is_empty() || cmd.iter().any(|a| a.chars().any(char::is_control)) {
                return err(format!("opencode_mcp.{name}: a command and its arguments"));
            }
        }
        if let Some(s) = &c.setup {
            if !s.url.starts_with("https://") {
                return Err(invalid(
                    "coding_agents.setup.url",
                    &s.url,
                    "an https git URL",
                ));
            }
            word("setup.url", &s.url)?;
            if s.rev.len() != 40 || !s.rev.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(
                    "coding_agents.setup.rev",
                    &s.rev,
                    "a 40-hex commit (a branch would never converge)",
                ));
            }
            word("setup.run", &s.run)?;
            if s.run.starts_with('/') || s.run.split('/').any(|p| p == ".." || p.is_empty()) {
                return Err(invalid(
                    "coding_agents.setup.run",
                    &s.run,
                    "a relative path inside the repo",
                ));
            }
        }
        validate_runner_limits(
            "coding_agents",
            (None, None),
            c.cpu_quota.as_deref(),
            c.memory_max.as_deref(),
            c.tasks_max,
        )
    }
}

impl Config {
    /// `[beszel]`: no Beszel port may be world-open. A local agent (with the
    /// hub here) and a loopback hub listen on 127.0.0.1 only; an agent
    /// reporting to a remote hub either dials out (`hub_url` + `token`) or
    /// is firewalled to `hub_addresses`/the tailnet; a non-loopback hub is
    /// firewalled to `hub_allow_from`/the tailnet.
    fn validate_beszel(&self, b: &BeszelSection) -> Result<()> {
        validate_semver("beszel.version", &b.version)?;
        crate::modules::beszel::validate_pins(b)?;
        validate_port("beszel.listen_port", b.listen_port)?;
        if !b.agent && !b.hub {
            return Err(AnvilError::Validation(
                "beszel: agent = false and hub = false leaves nothing to manage".into(),
            ));
        }
        if !b.agent && (b.docker || b.smart) {
            return Err(AnvilError::Validation(
                "beszel.docker/smart need agent = true".into(),
            ));
        }
        if !b.hub && !b.hub_allow_from.is_empty() {
            return Err(AnvilError::Validation(
                "beszel.hub_allow_from needs hub = true".into(),
            ));
        }
        let remote_agent = b.agent && !b.hub;
        if !remote_agent
            && (!b.key.is_empty()
                || !b.hub_url.is_empty()
                || !b.token.is_empty()
                || !b.hub_addresses.is_empty())
        {
            return Err(AnvilError::Validation(
                "beszel.key/hub_url/token/hub_addresses are for an agent reporting to a \
                 hub on another machine; with hub = true the local agent is wired to \
                 the local hub automatically — remove them"
                    .into(),
            ));
        }
        if remote_agent {
            self.validate_beszel_remote_agent(b)?;
        }
        if b.admin_email.is_empty() != b.admin_password.is_empty() {
            return Err(AnvilError::Validation(
                "beszel.admin_email and beszel.admin_password go together".into(),
            ));
        }
        if !b.admin_email.is_empty() {
            if !b.hub {
                return Err(AnvilError::Validation(
                    "beszel.admin_email/admin_password need hub = true".into(),
                ));
            }
            let (local, domain) = b.admin_email.split_once('@').unwrap_or_default();
            if local.is_empty() || !domain.contains('.') {
                return Err(invalid(
                    "beszel.admin_email",
                    &b.admin_email,
                    "an email address, e.g. \"ops@example.com\"",
                ));
            }
            for (field, v) in [
                ("beszel.admin_email", &b.admin_email),
                ("beszel.admin_password", &b.admin_password),
            ] {
                // Lands in a systemd EnvironmentFile as KEY="value".
                if v.chars()
                    .any(|c| c.is_control() || matches!(c, '"' | '\\' | '$' | '`'))
                {
                    return Err(AnvilError::Validation(format!(
                        "{field} must not contain quotes, backslashes, `$`, backticks \
                         or control characters"
                    )));
                }
            }
            // PocketBase's minimum for superuser passwords.
            if b.admin_password.chars().count() < 8 {
                return Err(AnvilError::Validation(
                    "beszel.admin_password must be at least 8 characters".into(),
                ));
            }
        }
        if b.hub {
            let addr: std::net::SocketAddr = b.hub_listen.parse().map_err(|_| {
                invalid(
                    "beszel.hub_listen",
                    &b.hub_listen,
                    "IP:port, e.g. \"127.0.0.1:8090\"",
                )
            })?;
            validate_port("beszel.hub_listen", addr.port())?;
            if b.agent && addr.port() == b.listen_port {
                return Err(AnvilError::Validation(format!(
                    "beszel.hub_listen and beszel.listen_port both use port {}",
                    b.listen_port
                )));
            }
            if addr.ip().is_loopback() {
                if !b.hub_allow_from.is_empty() {
                    return Err(AnvilError::Validation(
                        "beszel.hub_allow_from has no effect while hub_listen is \
                         loopback; remove it or listen on another address"
                            .into(),
                    ));
                }
            } else {
                // T18: on a fresh hub the first visitor creates the admin.
                if b.admin_email.is_empty() {
                    return Err(AnvilError::Validation(format!(
                        "beszel.hub_listen = {:?} is reachable by others, and a fresh hub \
                         lets its first visitor create the admin: set beszel.admin_email \
                         and beszel.admin_password = \"${{BESZEL_ADMIN_PASSWORD}}\"",
                        b.hub_listen
                    )));
                }
                for a in &b.hub_allow_from {
                    validate_cidr("beszel.hub_allow_from", a)?;
                }
                // T19: the hub speaks plain HTTP; off loopback only WireGuard
                // (the tailnet) may carry logins and agent tokens.
                if !in_tailnet(&addr.ip().to_string())
                    && !b.hub_allow_from.iter().all(|a| in_tailnet(a))
                {
                    return Err(AnvilError::Validation(format!(
                        "beszel.hub_listen = {:?} serves plain HTTP to beszel.hub_allow_from \
                         outside the tailnet: logins and agent tokens would cross the network \
                         in clear text. Keep hub_listen on 127.0.0.1 and put [caddy] or [tls] \
                         in front, or allow only tailnet addresses (100.64.0.0/10, \
                         fd7a:115c:a1e0::/48)",
                        b.hub_listen
                    )));
                }
                self.require_scoped_firewall(
                    "beszel.hub_listen",
                    "hub_allow_from",
                    &b.hub_allow_from,
                )?;
            }
        }
        Ok(())
    }

    fn validate_beszel_remote_agent(&self, b: &BeszelSection) -> Result<()> {
        let key_type = b.key.split(' ').next().unwrap_or("");
        if !(key_type.starts_with("ssh-") || key_type.starts_with("ecdsa-sha2-"))
            || b.key.split(' ').nth(1).is_none_or(str::is_empty)
        {
            return Err(invalid(
                "beszel.key",
                &b.key,
                "the hub's SSH public key, e.g. \"ssh-ed25519 AAAA…\"",
            ));
        }
        for (field, v) in [
            ("beszel.key", &b.key),
            ("beszel.hub_url", &b.hub_url),
            ("beszel.token", &b.token),
        ] {
            // Lands in a systemd EnvironmentFile as KEY="value": no quote,
            // backslash, `$`, backtick or control characters.
            if v.chars()
                .any(|c| c.is_control() || matches!(c, '"' | '\\' | '$' | '`'))
            {
                return Err(AnvilError::Validation(format!(
                    "{field} must not contain quotes, backslashes, `$`, backticks \
                     or control characters"
                )));
            }
        }
        if b.token.contains(char::is_whitespace) {
            return Err(AnvilError::Validation(
                "beszel.token must not contain whitespace".into(),
            ));
        }
        if b.outbound() || !b.token.is_empty() {
            if !(b.hub_url.starts_with("http://") || b.hub_url.starts_with("https://"))
                || b.hub_url.contains(char::is_whitespace)
            {
                return Err(invalid(
                    "beszel.hub_url",
                    &b.hub_url,
                    "an http:// or https:// URL when token is set",
                ));
            }
            if b.token.is_empty() {
                return Err(AnvilError::Validation(
                    "beszel.hub_url needs beszel.token (use \"${BESZEL_TOKEN}\")".into(),
                ));
            }
            if !b.hub_addresses.is_empty() {
                return Err(AnvilError::Validation(
                    "beszel.hub_addresses has no effect with hub_url/token (the agent \
                     connects out and listens on nothing); remove it"
                        .into(),
                ));
            }
            return Ok(());
        }
        for a in &b.hub_addresses {
            validate_cidr("beszel.hub_addresses", a)?;
        }
        self.require_scoped_firewall("beszel.listen_port", "hub_addresses", &b.hub_addresses)
    }

    /// A Beszel port reachable beyond loopback needs an active, deny-by-default
    /// `[firewall]` and a scope: `addrs`, or the tailnet when `addrs` is empty.
    fn require_scoped_firewall(&self, what: &str, field: &str, addrs: &[String]) -> Result<()> {
        match &self.firewall {
            None => Err(AnvilError::Validation(format!(
                "{what} is reachable from the network, so beszel needs [firewall] to \
                 keep it closed to the world (or use hub_url + token / a loopback \
                 address: nothing then listens publicly)"
            ))),
            Some(f) if f.default_incoming == "allow" => Err(AnvilError::Validation(format!(
                "{what} needs firewall.default_incoming = \"deny\" (or \"reject\"); \
                 with \"allow\" it is world-open"
            ))),
            Some(_) if addrs.is_empty() && self.tailscale.is_none() => {
                Err(AnvilError::Validation(format!(
                    "beszel.{field} is empty and [tailscale] is not enabled: list the \
                     allowed IPs/CIDRs in beszel.{field}, or enable [tailscale] to allow \
                     {what} on tailscale0 only"
                )))
            }
            Some(_) => Ok(()),
        }
    }
}

/// A DNS hostname (`[A-Za-z0-9.-]`, no leading `.`/`-`, no `..`): safe in an
/// nginx `server_name`, a Caddyfile site address, and a file name.
fn is_hostname(d: &str) -> bool {
    !d.is_empty()
        && !d.starts_with(['.', '-'])
        && !d.contains("..")
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// `[caddy]`: every value lands in the Caddyfile (or an auth snippet), where
/// whitespace, quotes, braces or `#` would change its structure, so each is
/// held to a token-safe charset. `tls_enabled`: `[tls]` binds 80/443 too.
fn validate_caddy(
    c: &CaddySection,
    tls_enabled: bool,
    tailscale: bool,
    firewall: bool,
) -> Result<()> {
    validate_enum("caddy.ca", &c.ca, &["public", "staging", "internal"])?;
    validate_enum("caddy.listen", &c.listen, &["public", "tailnet"])?;
    let tailnet = c.listen == "tailnet";
    // Without ufw a "tailnet" Caddy would still answer on every interface.
    if tailnet && !(tailscale && firewall) {
        return Err(AnvilError::Validation(
            "caddy.listen = \"tailnet\" needs [tailscale] (the tailscale0 interface) and \
             [firewall] (ufw keeps the ports off the public interfaces)"
                .into(),
        ));
    }
    validate_port("caddy.http_port", c.http_port)?;
    validate_port("caddy.https_port", c.https_port)?;
    if c.http_port == c.https_port {
        return Err(AnvilError::Validation(
            "caddy.http_port and caddy.https_port must differ".into(),
        ));
    }
    if tls_enabled && (c.http_port == 80 || c.https_port == 443) {
        return Err(AnvilError::Validation(
            "[tls] (nginx/certbot) and [caddy] both bind ports 80/443: enable only one \
             front door per host, or move caddy.http_port/https_port elsewhere \
             (see docs/design/caddy.md)"
                .into(),
        ));
    }
    if let Some(e) = &c.email {
        let ok = e
            .split_once('@')
            .is_some_and(|(u, d)| !u.is_empty() && is_hostname(d))
            && e.chars()
                .all(|ch| ch.is_ascii_graphic() && !"{}\"'#\\;".contains(ch));
        if !ok {
            return Err(invalid("caddy.email", e, "an email address"));
        }
    }
    if c.sites.is_empty() {
        return Err(AnvilError::Validation(
            "[caddy] needs at least one [[caddy.site]]".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut dns_tokens = std::collections::BTreeMap::new();
    for s in &c.sites {
        if !is_hostname(&s.domain) {
            return Err(invalid(
                "caddy.site.domain",
                &s.domain,
                "a hostname ([A-Za-z0-9.-])",
            ));
        }
        if !seen.insert(s.domain.to_ascii_lowercase()) {
            return Err(AnvilError::Validation(format!(
                "caddy.site.domain {:?} is listed twice",
                s.domain
            )));
        }
        let up_ok = s.upstream.rsplit_once(':').is_some_and(|(h, p)| {
            let h = h
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(h);
            (is_hostname(h) || h.parse::<std::net::IpAddr>().is_ok())
                && p.parse::<u16>().is_ok_and(|p| p != 0)
        });
        if !up_ok {
            return Err(invalid(
                "caddy.site.upstream",
                &s.upstream,
                "host:port, e.g. \"127.0.0.1:3000\"",
            ));
        }
        validate_enum("caddy.site.tls", &s.tls, &["acme", "tailscale", "dns"])?;
        crate::modules::caddy::validate_dns(s, &mut dns_tokens)?;
        if s.tls == "acme" && tailnet {
            return Err(AnvilError::Validation(format!(
                "caddy.site {:?}: tls = \"acme\" cannot work with caddy.listen = \"tailnet\" \
                 (the CA's HTTP/TLS challenge cannot reach a tailnet-only port); use \
                 tls = \"tailscale\" for a *.ts.net name",
                s.domain
            )));
        }
        if s.tls == "tailscale" {
            if !s.domain.to_ascii_lowercase().ends_with(".ts.net") {
                return Err(invalid(
                    "caddy.site.domain",
                    &s.domain,
                    "a *.ts.net MagicDNS name with tls = \"tailscale\"",
                ));
            }
            if !tailscale {
                return Err(AnvilError::Validation(format!(
                    "caddy.site {:?}: tls = \"tailscale\" needs [tailscale] (tailscaled issues the certificate)",
                    s.domain
                )));
            }
        }
        for a in &s.allow {
            validate_cidr("caddy.site.allow", a)?;
        }
        if let Some(b) = &s.basic_auth {
            let user_ok = !b.user.is_empty()
                && b.user
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch));
            if !user_ok {
                return Err(invalid(
                    "caddy.site.basic_auth.user",
                    &b.user,
                    "[A-Za-z0-9._-]",
                ));
            }
            // bcrypt (`$2a$14$…`) and argon2id PHC strings use only these.
            let hash_ok = b.password_hash.starts_with('$')
                && b.password_hash
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || "$./+=,-".contains(ch));
            if !hash_ok {
                return Err(AnvilError::Validation(
                    "caddy.site.basic_auth.password_hash is not a `caddy hash-password` hash \
                     (value not shown)"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// Shared by the runner modules: `cpu_quota`/`memory_max`/`tasks_max` land
/// raw in the unit's `[Service]` section; `version`+`sha256` pin a download.
pub(crate) fn validate_runner_limits(
    module: &str,
    pin: (Option<&str>, Option<&str>),
    cpu_quota: Option<&str>,
    memory_max: Option<&str>,
    tasks_max: Option<u32>,
) -> Result<()> {
    // GR17: land raw in the runner unit's [Service] section.
    let positive =
        |s: &str| s.chars().all(|c| c.is_ascii_digit()) && !s.trim_start_matches('0').is_empty();
    if let Some(q) = cpu_quota {
        if !q.strip_suffix('%').is_some_and(positive) {
            return Err(invalid(
                &format!("{module}.cpu_quota"),
                q,
                "a percentage of one core, e.g. \"400%\" = 4 cores",
            ));
        }
    }
    if let Some(m) = memory_max {
        validate_memory_value(&format!("{module}.memory_max"), m)?;
    }
    if tasks_max == Some(0) {
        return Err(AnvilError::Validation(format!(
            "{module}.tasks_max must be at least 1"
        )));
    }
    match pin {
        (None, None) => {}
        (Some(v), Some(s)) => {
            let semver = v.split('.').count() == 3
                && v.split('.')
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
            if !semver {
                return Err(invalid(
                    &format!("{module}.version"),
                    v,
                    "MAJOR.MINOR.PATCH",
                ));
            }
            if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(&format!("{module}.sha256"), s, "64 hex characters"));
            }
        }
        _ => {
            return Err(AnvilError::Validation(format!(
                "{module}.version and {module}.sha256 must be set together"
            )))
        }
    }
    Ok(())
}

/// A systemd memory value: bytes with an optional K/M/G/T suffix, or a
/// percentage of RAM up to 100%.
fn validate_memory_value(field: &str, m: &str) -> Result<()> {
    let positive =
        |s: &str| s.chars().all(|c| c.is_ascii_digit()) && !s.trim_start_matches('0').is_empty();
    let ok = match m.strip_suffix('%') {
        Some(p) => positive(p) && p.parse::<u8>().is_ok_and(|n| n <= 100),
        None => positive(m.strip_suffix(['K', 'M', 'G', 'T']).unwrap_or(m)),
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(
            field,
            m,
            "bytes with an optional K/M/G/T suffix (\"8G\") or a percentage of RAM (\"50%\")",
        ))
    }
}

/// systemd's `CPUWeight=` range (1–10000).
fn validate_cpu_weight(module: &str, w: u32) -> Result<()> {
    if (1..=10000).contains(&w) {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{module}.cpu_weight: {w} is invalid (must be 1-10000)"
        )))
    }
}

/// `[github_runner]`: runner names become paths and unit names; url, labels
/// and group reach `config.sh` (escaped) and the registration marker.
fn validate_github_runner(g: &GithubRunnerSection, engine: Engine) -> Result<()> {
    validate_enum(
        "github_runner.docker",
        &g.docker,
        &["none", "group", "podman", "rootless"],
    )?;
    validate_github_runner_mode(g, engine)?;
    let no_space =
        |s: &str| !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control());
    if !g.proxy.is_empty()
        && !((g.proxy.starts_with("http://") || g.proxy.starts_with("https://"))
            && no_space(&g.proxy)
            && !g.proxy.contains(['"', '\'', '\\']))
    {
        return Err(invalid(
            "github_runner.proxy",
            &g.proxy,
            "an http(s):// URL",
        ));
    }
    validate_runner_limits(
        "github_runner",
        (g.version.as_deref(), g.sha256.as_deref()),
        g.cpu_quota.as_deref(),
        g.memory_max.as_deref(),
        g.tasks_max,
    )?;
    if let Some(d) = &g.disk_max {
        if g.disk_max_bytes().is_none() {
            return Err(invalid(
                "github_runner.disk_max",
                d,
                "a whole number of gigabytes or terabytes, e.g. \"150G\" or \"1T\"",
            ));
        }
    }
    if let Some(h) = &g.home_cache_max {
        if g.home_cache_max_bytes().is_none() {
            return Err(invalid(
                "github_runner.home_cache_max",
                h,
                "a whole number of gigabytes or terabytes, e.g. \"20G\"",
            ));
        }
    }
    if g.diag_retention_days == 0 {
        return Err(AnvilError::Validation(
            "github_runner.diag_retention_days must be at least 1".into(),
        ));
    }
    if g.runners.is_empty() {
        return Err(AnvilError::Validation(
            "github_runner: add at least one [github_runner.runners.<name>]".into(),
        ));
    }
    let seg = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    for (name, r) in &g.runners {
        let ok = name.len() <= 64
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'));
        if !ok {
            return Err(invalid(
                "github_runner.runners",
                name,
                "[a-z0-9][a-z0-9_-]*, at most 64 characters",
            ));
        }
        let field = format!("github_runner.runners.{name}");
        let parts: Vec<&str> = r
            .url
            .strip_prefix("https://github.com/")
            .map(|p| p.split('/').collect())
            .unwrap_or_default();
        if !(1..=2).contains(&parts.len()) || !parts.iter().all(|p| seg(p)) {
            return Err(invalid(
                &format!("{field}.url"),
                &r.url,
                "https://github.com/<org> or https://github.com/<org>/<repo>",
            ));
        }
        if !r.group.is_empty() && parts.len() != 1 {
            return Err(AnvilError::Validation(format!(
                "{field}.group: runner groups exist only for org runners \
                 (url = \"https://github.com/<org>\")"
            )));
        }
        if r.group.chars().any(|c| c.is_control()) || r.group.len() > 100 {
            return Err(invalid(
                &format!("{field}.group"),
                &r.group,
                "a runner group name",
            ));
        }
        for l in &r.labels {
            if !seg(l) {
                return Err(invalid(&format!("{field}.labels"), l, "[A-Za-z0-9._-]+"));
            }
        }
        if g.ephemeral() {
            let why = if parts.len() != 1 {
                "url must be an org URL (https://github.com/<org>): the GitHub App mints org runners"
            } else if r.labels.is_empty() {
                "labels are required (jobs pick the runner by label)"
            } else if !(r.token.is_empty() && r.remove_token.is_empty() && r.group.is_empty()) {
                "token, remove_token and group are persistent-only (ephemeral runners use the App and runner_group_id)"
            } else {
                continue;
            };
            return Err(AnvilError::Validation(format!(
                "{field} (mode = \"ephemeral\"): {why}"
            )));
        }
    }
    Ok(())
}

/// GR9: the App and sandbox fields are required with `mode =
/// "ephemeral"` and rejected otherwise; v1-only fields are rejected in
/// ephemeral mode, where nothing would apply them.
fn validate_github_runner_mode(g: &GithubRunnerSection, engine: Engine) -> Result<()> {
    validate_enum("github_runner.mode", &g.mode, &["persistent", "ephemeral"])?;
    let ephemeral_only = [
        ("app_id", g.app_id.is_some()),
        ("installation_id", g.installation_id.is_some()),
        ("app_key", g.app_key.is_some()),
        ("runner_group_id", g.runner_group_id.is_some()),
        ("capacity", g.capacity.is_some()),
        ("sandbox_cpus", g.sandbox_cpus.is_some()),
        ("sandbox_memory", g.sandbox_memory.is_some()),
        ("sandbox_pids", g.sandbox_pids.is_some()),
        ("sandbox_disk", g.sandbox_disk.is_some()),
        ("sandbox_runtime", g.sandbox_runtime.is_some()),
        ("sandbox_packages", !g.sandbox_packages.is_empty()),
    ];
    if !g.ephemeral() {
        if let Some((f, _)) = ephemeral_only.iter().find(|(_, set)| *set) {
            return Err(AnvilError::Validation(format!(
                "github_runner.{f} needs mode = \"ephemeral\""
            )));
        }
        return Ok(());
    }
    let persistent_only = [
        ("docker", g.docker != "none"),
        ("proxy", !g.proxy.is_empty()),
        ("version", g.version.is_some()),
        ("sha256", g.sha256.is_some()),
        ("cpu_quota", g.cpu_quota.is_some()),
        ("memory_max", g.memory_max.is_some()),
        ("tasks_max", g.tasks_max.is_some()),
        ("disk_max", g.disk_max.is_some()),
        ("home_cache_max", g.home_cache_max.is_some()),
    ];
    if let Some((f, _)) = persistent_only.iter().find(|(_, set)| *set) {
        return Err(AnvilError::Validation(format!(
            "github_runner.{f} is persistent-only; with mode = \"ephemeral\" use the sandbox_* limits \
             (each sandbox has its own Docker)"
        )));
    }
    for (f, set) in &ephemeral_only[..4] {
        if !set {
            return Err(AnvilError::Validation(format!(
                "github_runner.{f} is required with mode = \"ephemeral\""
            )));
        }
    }
    // Each value needs its own install in github_runner_ephemeral.rs.
    let runtime = g.sandbox_runtime(engine);
    validate_enum(
        "github_runner.sandbox_runtime",
        runtime,
        &["sysbox-runc", "podman", "docker-rootless"],
    )?;
    // One engine per host: sysbox installs Docker.
    match (runtime, engine) {
        ("podman", Engine::Docker) => {
            return Err(AnvilError::Validation(
                "github_runner.sandbox_runtime = \"podman\" needs a Podman host ([podman] or \
                 [containers] runtime = \"podman\"); on a Docker host drop it (default \"sysbox-runc\")"
                    .into(),
            ))
        }
        ("docker-rootless", Engine::Podman) => {
            return Err(AnvilError::Validation(
                "github_runner.sandbox_runtime = \"docker-rootless\" needs a Docker host; on a Podman \
                 host drop it (default \"podman\")"
                    .into(),
            ))
        }
        ("docker-rootless", _) => {
            // One system user per slot: anvil-ghr-<runner>-<n>, at most 32 characters.
            let n = g.capacity().to_string().len();
            if let Some(name) = g.runners.keys().find(|k| 10 + k.len() + 1 + n > 32) {
                return Err(AnvilError::Validation(format!(
                    "github_runner.runners.{name}: too long for sandbox_runtime = \"docker-rootless\" \
                     (slot user anvil-ghr-{name}-<n> must fit 32 characters)"
                )));
            }
        }
        ("sysbox-runc", Engine::Podman) => {
            return Err(AnvilError::Validation(
                "github_runner.sandbox_runtime = \"sysbox-runc\" installs Docker + sysbox; it cannot \
                 run on a Podman host. Drop it (default \"podman\")"
                    .into(),
            ))
        }
        _ => {}
    }
    for p in &g.sandbox_packages {
        validate_package_name("github_runner.sandbox_packages", p)?;
    }
    let key = g.app_key.as_deref().unwrap_or_default();
    if !(key.contains("-----BEGIN") && key.contains("PRIVATE KEY-----")) {
        return Err(AnvilError::Validation(
            "github_runner.app_key must be the App's PEM private key, e.g. \"${GITHUB_APP_KEY}\""
                .into(),
        ));
    }
    if !(1..=32).contains(&g.capacity()) {
        return Err(invalid(
            "github_runner.capacity",
            &g.capacity().to_string(),
            "1 to 32",
        ));
    }
    validate_sandbox_limits(
        "github_runner",
        g.sandbox_cpus(),
        g.sandbox_memory(),
        g.sandbox_pids(),
        g.sandbox_disk(),
    )?;
    Ok(())
}

/// `data_dir` lands in both a shell `install -d` (where it is escaped) and
/// the compose file's `<dir>:/greptimedb_data` volume entry, where docker
/// splits on `:`. Whitespace stays rejected (the pre-compose contract).
fn validate_greptimedb_data_dir(dir: &str) -> Result<()> {
    if !dir.starts_with('/') {
        return Err(AnvilError::Validation(format!(
            "greptimedb.data_dir must be an absolute path, got {dir:?}"
        )));
    }
    if dir.chars().any(|c| c.is_whitespace()) || dir.contains(':') {
        return Err(AnvilError::Validation(format!(
            "greptimedb.data_dir must not contain whitespace or ':' — it is \
             embedded in the compose volume entry `<dir>:/greptimedb_data`; \
             got {dir:?}"
        )));
    }
    Ok(())
}

fn validate_host(h: &HostSpec, index: usize) -> Result<()> {
    if h.address.trim().is_empty() {
        return Err(AnvilError::Validation(format!(
            "host[{index}].address must not be empty"
        )));
    }
    if h.user.trim().is_empty() {
        return Err(AnvilError::Validation(format!(
            "host[{index}].user must not be empty"
        )));
    }
    validate_port(&format!("host[{index}].port"), h.port)
}

fn validate_port(field: &str, port: u16) -> Result<()> {
    if port == 0 {
        return Err(AnvilError::Validation(format!(
            "{field} must be in 1..=65535 (got 0)"
        )));
    }
    Ok(())
}

/// Per-sandbox limits of an ephemeral runner (`github_runner` v2, and
/// `forgejo_runner` since the rootless default): docker `--cpus`, `--memory`, `--pids-limit`
/// and the slot volume size.
pub(crate) fn validate_sandbox_limits(
    module: &str,
    cpus: &str,
    mem: &str,
    pids: u32,
    disk: &str,
) -> Result<()> {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let cpus_ok = match cpus.split_once('.') {
        Some((i, f)) => digits(i) && digits(f),
        None => digits(cpus),
    } && cpus.parse::<f64>().is_ok_and(|c| c > 0.0);
    if !cpus_ok {
        return Err(invalid(
            &format!("{module}.sandbox_cpus"),
            cpus,
            "a CPU count, e.g. \"2\" or \"1.5\"",
        ));
    }
    let num = mem.trim_end_matches(['b', 'k', 'm', 'g']);
    if !(digits(num) && mem.len() - num.len() <= 1 && num.parse::<u64>().is_ok_and(|n| n > 0)) {
        return Err(invalid(
            &format!("{module}.sandbox_memory"),
            mem,
            "a docker size, e.g. \"4g\" or \"512m\"",
        ));
    }
    if pids == 0 {
        return Err(invalid(
            &format!("{module}.sandbox_pids"),
            "0",
            "at least 1",
        ));
    }
    if schema::size_bytes(disk).is_none() {
        return Err(invalid(
            &format!("{module}.sandbox_disk"),
            disk,
            "a whole number of gigabytes or terabytes, e.g. \"40G\"",
        ));
    }
    Ok(())
}

fn validate_enum(field: &str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} is invalid; expected one of: {}",
            allowed.join(", ")
        )))
    }
}

fn validate_hhmm(field: &str, value: &str) -> Result<()> {
    let ok = || -> Option<()> {
        let (h, m) = value.split_once(':')?;
        // u8::from_str accepts a leading '+'.
        if h.len() != 2 || m.len() != 2 || !h.bytes().chain(m.bytes()).all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hh: u8 = h.parse().ok()?;
        let mm: u8 = m.parse().ok()?;
        (hh < 24 && mm < 60).then_some(())
    };
    ok().ok_or_else(|| {
        AnvilError::Validation(format!(
            "{field} = {value:?} must match HH:MM (00:00–23:59)"
        ))
    })
}

/// Usernames are interpolated into sudoers drop-in paths, so restrict to a
/// safe charset (R27/R93 spirit) and useradd's 32-character limit.
fn validate_username(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "users.create: {name:?} is not a valid account name \
             (allowed: letters, digits, '_' , '-'; must start with a letter or '_'; \
             max 32 characters)"
        )))
    }
}

/// Debian package-name charset (`^[a-z0-9][a-z0-9+._-]*$`): package names end
/// up in `apt-get` command lines, so anything else is rejected up front.
fn validate_package_name(field: &str, name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok = matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '.' | '_' | '-')
        });
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field}: {name:?} is not a valid Debian package name \
             (must match ^[a-z0-9][a-z0-9+._-]*$)"
        )))
    }
}

/// `sshd.allow_users` entries land in the sshd_config `AllowUsers` directive:
/// restrict to `^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,31}$`.
fn validate_allow_user(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok = name.len() <= 32
        && matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "sshd.allow_users: {name:?} is not a valid user name \
             (must match ^[a-zA-Z0-9_][a-zA-Z0-9_-]{{0,31}}$)"
        )))
    }
}

/// The host of an `http(s)://host[:port][/…]` URL (lowercase, no port).
fn url_host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host.split(':').next().unwrap_or("").to_ascii_lowercase()
}

fn validate_headscale_server_url(url: &str) -> Result<()> {
    if url.trim().is_empty() {
        return Err(AnvilError::Validation(
            "headscale.server_url must not be empty (clients need the public URL)".into(),
        ));
    }
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "headscale.server_url = {url:?} must start with http:// or https://"
        )))
    }
}

/// A pinned release version: strict `MAJOR.MINOR.PATCH`. Used for
/// `headscale.version` and `headscale.headplane_version` (both pin downloads).
fn validate_semver(field: &str, version: &str) -> Result<()> {
    let mut parts = version.split('.');
    let ok = parts.clone().count() == 3
        && parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {version:?} must be a full semantic version \
             (must match ^\\d+\\.\\d+\\.\\d+$, e.g. \"0.23.0\")"
        )))
    }
}

/// `[containers.compose.<name>]`: the name becomes a directory, a unit name and
/// the compose project name; env keys/values become `.env` lines (values are
/// single-quoted there, which compose reads literally — so no `'`/newline).
fn validate_containers(c: &ContainersSection, podman: bool) -> Result<()> {
    if let Some(r) = &c.runtime {
        validate_enum("containers.runtime", r, &["docker", "podman"])?;
    }
    let name_ok = |field: &str, name: &str| {
        let ok = name.len() <= 64
            && name.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
            && name.chars().all(|ch| {
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_')
            });
        if ok {
            Ok(())
        } else {
            Err(invalid(
                field,
                name,
                "[a-z0-9][a-z0-9_-]*, at most 64 characters",
            ))
        }
    };
    if podman && !c.compose.is_empty() {
        return Err(AnvilError::Validation(
            "containers.compose needs a Docker host: Podman Quadlets do not read \
             compose files; use [containers.quadlet.<name>] .container units"
                .into(),
        ));
    }
    if !podman && !c.quadlet.is_empty() {
        return Err(AnvilError::Validation(
            "containers.quadlet needs a Podman host: [podman] or runtime = \"podman\"".into(),
        ));
    }
    for (name, q) in &c.quadlet {
        name_ok("containers.quadlet", name)?;
        if q.content.trim().is_empty() {
            return Err(AnvilError::Validation(format!(
                "containers.quadlet.{name}.content must not be empty"
            )));
        }
        quadlet_publishes_loopback_only(&q.content).map_err(|bad| {
            AnvilError::Validation(format!(
                "containers.quadlet.{name}: {bad:?} may publish beyond 127.0.0.1; rootful \
                 Podman (netavark) would expose it past ufw — use PublishPort=127.0.0.1:<host>:<ctr>"
            ))
        })?;
    }
    for (name, p) in &c.compose {
        name_ok("containers.compose", name)?;
        if p.content.trim().is_empty() {
            return Err(AnvilError::Validation(format!(
                "containers.compose.{name}.content must not be empty"
            )));
        }
        for (k, v) in &p.env {
            let field = format!("containers.compose.{name}.env");
            let mut chars = k.chars();
            let key_ok = matches!(chars.next(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_')
                && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
            if !key_ok {
                return Err(invalid(&field, k, "[A-Za-z_][A-Za-z0-9_]*"));
            }
            if v.chars().any(|ch| ch.is_control()) {
                return Err(AnvilError::Validation(format!(
                    "{field}.{k}: value must not contain control characters"
                )));
            }
        }
    }
    Ok(())
}

/// Every `PublishPort=` binds a loopback host IP (`127.x.x.x:h:c`,
/// `[::1]:h:c`) and no `PodmanArgs=` publishes. Errs with the offending line.
/// Unparseable values fail closed.
fn quadlet_publishes_loopback_only(content: &str) -> std::result::Result<(), String> {
    for line in content.lines().map(str::trim) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"');
        let bad = match key.trim() {
            "PublishPort" => {
                let ip = match value.strip_prefix('[') {
                    Some(rest) => rest.split_once(']').map(|(ip, _)| ip),
                    None => {
                        let parts: Vec<&str> = value.split(':').collect();
                        (parts.len() == 3).then(|| parts[0])
                    }
                };
                !ip.and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                    .is_some_and(|ip| ip.is_loopback())
            }
            "PodmanArgs" => value.split_whitespace().any(|t| {
                t.starts_with("--publish")
                    || (t.starts_with("-p") || t.starts_with("-P")) && !t.starts_with("--")
            }),
            _ => false,
        };
        if bad {
            return Err(line.to_string());
        }
    }
    Ok(())
}

fn invalid(field: &str, value: &str, want: &str) -> AnvilError {
    AnvilError::Validation(format!("{field}: {value:?} is invalid (must be {want})"))
}

/// `kernel.extra_sysctl` keys land in a `sysctl.d` drop-in filename and a
/// `key = value` line; restrict to the sysctl key charset (dotted or slashed)
/// so a key can never break out of either.
fn validate_sysctl_key(key: &str) -> Result<()> {
    let ok = !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'));
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "kernel.extra_sysctl: key {key:?} is not a valid sysctl name \
             (allowed: letters, digits, '.', '_', '-', '/')"
        )))
    }
}

/// `greptimedb.retention`: `<n>h`, `<n>d` or `<n>w` (embedded in SQL), on a
/// GreptimeDB with `ALTER DATABASE … SET 'ttl'` (v0.12+).
fn validate_greptimedb_retention(r: &str, version: &str) -> Result<()> {
    let n = r.strip_suffix(['h', 'd', 'w']).unwrap_or("");
    if n.is_empty() || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "greptimedb.retention",
            r,
            "a number of hours, days or weeks, e.g. \"30d\"",
        ));
    }
    let mut v = version
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0));
    if (v.next().unwrap_or(0), v.next().unwrap_or(0)) < (0, 12) {
        return Err(AnvilError::Validation(format!(
            "greptimedb.retention needs GreptimeDB v0.12 or newer (ALTER DATABASE); \
             version is {version:?}"
        )));
    }
    Ok(())
}

/// `greptimedb.memory_max`: digits + K/M/G/T, the grammar both compose's
/// `mem_limit` and systemd's `MemoryMax=` read the same way (no `%`).
fn validate_greptimedb_memory_max(m: &str) -> Result<()> {
    let n = m.strip_suffix(['K', 'M', 'G', 'T']).unwrap_or("");
    if n.is_empty() || n.starts_with('0') || !n.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(
            "greptimedb.memory_max",
            m,
            "bytes with a K/M/G/T suffix, e.g. \"2G\"",
        ));
    }
    Ok(())
}

/// `greptimedb.version` pins the container image tag (GreptimeDB tags are
/// `v`-prefixed). `latest` and anything other than `vMAJOR.MINOR.PATCH` is
/// rejected so a default or typo can never deploy a floating tag (the default
/// `d_version` is itself pinned).
fn validate_greptimedb_version(version: &str) -> Result<()> {
    let Some(rest) = version.strip_prefix('v') else {
        return Err(AnvilError::Validation(format!(
            "greptimedb.version = {version:?} must be a pinned 'vMAJOR.MINOR.PATCH' tag \
             (e.g. \"v1.3.0\"); 'latest' and unpinned tags are rejected"
        )));
    };
    let mut parts = rest.split('.');
    let ok = parts.clone().count() == 3
        && parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "greptimedb.version = {version:?} must be a pinned 'vMAJOR.MINOR.PATCH' tag \
             (e.g. \"v1.3.0\"); 'latest' and unpinned tags are rejected"
        )))
    }
}

/// `pam.umask` lands verbatim in `pam_umask`/login.defs; only an octal string
/// of 3 or 4 digits is meaningful (`027`, `0027`).
fn validate_umask(field: &str, value: &str) -> Result<()> {
    let ok = matches!(value.len(), 3 | 4) && value.chars().all(|c| ('0'..='7').contains(&c));
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} must be 3 or 4 octal digits (e.g. \"027\")"
        )))
    }
}

/// fail2ban durations (`bantime`, `findtime`): bare seconds (`3600`) or a
/// number with a unit suffix (`10m`). One optional trailing s/m/h/d/w/y.
fn validate_duration(field: &str, value: &str) -> Result<()> {
    let is_unit = |c: char| matches!(c, 's' | 'm' | 'h' | 'd' | 'w' | 'y');
    // Valid iff all-digits (no suffix) OR digits + exactly one trailing unit.
    let ok = match value.chars().last() {
        Some(c) if is_unit(c) => {
            let head = &value[..value.len() - c.len_utf8()];
            !head.is_empty() && head.chars().all(|c| c.is_ascii_digit())
        }
        _ => !value.is_empty() && value.chars().all(|c| c.is_ascii_digit()),
    };
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} must be a duration: digits with an optional \
             s/m/h/d/w/y suffix (e.g. \"10m\", \"3600\")"
        )))
    }
}

/// An IP or CIDR (`1.2.3.4`, `10.0.0.0/8`, `::1`, `fd00::/8`). These land in
/// firewall/`source_ips` directives that cannot quote shell metacharacters, so
/// anything that is not a literal address+prefix is rejected up front.
/// An IP or CIDR (already validated) inside Tailscale's address ranges,
/// `100.64.0.0/10` or `fd7a:115c:a1e0::/48`, so its traffic is WireGuard.
fn in_tailnet(value: &str) -> bool {
    let (ip, prefix) = value.split_once('/').unwrap_or((value, ""));
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            prefix.parse::<u8>().unwrap_or(32) >= 10 && u32::from(v4) >> 22 == 0x6440_0000 >> 22
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            prefix.parse::<u8>().unwrap_or(128) >= 48
                && v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0]
        }
        Err(_) => false,
    }
}

/// An inbound tcp rule opening `port` (a range counts; no port = all) to
/// `source` (an IP/CIDR inside one of its sources; no sources = any).
fn rule_allows(r: &CloudEdgeRule, port: u16, source: Option<&str>) -> bool {
    let port_ok = r.port.as_deref().is_none_or(|p| {
        let (lo, hi) = p.split_once('-').unwrap_or((p, p));
        matches!((lo.parse::<u16>(), hi.parse::<u16>()), (Ok(l), Ok(h)) if l <= port && port <= h)
    });
    r.direction == "in"
        && r.protocol == "tcp"
        && port_ok
        && (r.source_ips.is_empty()
            || source.is_none_or(|a| r.source_ips.iter().any(|s| cidr_within(a, s))))
}

/// Ranges whose traffic never crosses the provider firewall from the
/// internet: RFC1918, loopback, link-local, CGNAT/tailnet, ULA (which holds
/// Tailscale's fd7a:115c:a1e0::/48).
const NON_PUBLIC: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fe80::/10",
    "fd00::/8",
];

/// True unless the whole IP/CIDR lies inside a [`NON_PUBLIC`] range.
fn is_public(a: &str) -> bool {
    !NON_PUBLIC.iter().any(|r| cidr_within(a, r))
}

/// Whether IP/CIDR `inner` lies entirely inside `outer` (same family).
pub(crate) fn cidr_within(inner: &str, outer: &str) -> bool {
    let parse = |v: &str| -> Option<(u128, u32, u32)> {
        let (ip, pfx) = v.split_once('/').map_or((v, None), |(i, p)| (i, Some(p)));
        let (bits, width) = match ip.parse::<std::net::IpAddr>().ok()? {
            std::net::IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32),
            std::net::IpAddr::V6(v6) => (u128::from(v6), 128),
        };
        let len = pfx.map_or(Some(width), |p| p.parse().ok())?;
        (len <= width).then_some((bits, width, len))
    };
    match (parse(inner), parse(outer)) {
        (Some((ib, iw, il)), Some((ob, ow, ol))) => {
            iw == ow && il >= ol && (ib ^ ob).checked_shr(iw - ol).unwrap_or(0) == 0
        }
        _ => false,
    }
}

fn validate_cidr(field: &str, value: &str) -> Result<()> {
    let (ip, prefix) = match value.split_once('/') {
        Some((ip, pfx)) => (ip, Some(pfx)),
        None => (value, None),
    };
    let parsed = ip.parse::<std::net::IpAddr>();
    let ok = match (parsed, prefix) {
        (Ok(_), None) => true,
        (Ok(std::net::IpAddr::V4(_)), Some(p)) => {
            p.chars().all(|c| c.is_ascii_digit()) && matches!(p.parse::<u8>(), Ok(n) if n <= 32)
        }
        (Ok(std::net::IpAddr::V6(_)), Some(p)) => {
            p.chars().all(|c| c.is_ascii_digit()) && matches!(p.parse::<u8>(), Ok(n) if n <= 128)
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} is not a valid IP or CIDR (e.g. \"10.0.0.0/8\")"
        )))
    }
}

/// A bare IP address (DNS servers).
fn validate_ip(field: &str, value: &str) -> Result<()> {
    if value.parse::<std::net::IpAddr>().is_ok() {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} is not a valid IP address"
        )))
    }
}

/// A port or port spec (`22`, `ssh`, `80,443`, `8000:9000`) for ufw / fail2ban /
/// cloud-firewall rules. Restricted charset so a value can never inject shell
/// metacharacters into the rendered command.
fn validate_port_spec(field: &str, value: &str) -> Result<()> {
    let ok = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | ',' | '-'));
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} must be a port, service, list, or range \
             (e.g. \"22\", \"ssh\", \"80,443\", \"8000:9000\")"
        )))
    }
}

/// A Hetzner cloud-firewall port: `N` or `N-M` (1–65535, N ≤ M), and only on
/// tcp/udp rules — the API rejects ufw-style services, lists and `:` ranges.
fn validate_hetzner_port(field: &str, protocol: &str, value: &str) -> Result<()> {
    if !matches!(protocol, "tcp" | "udp") {
        return Err(AnvilError::Validation(format!(
            "{field} is set but protocol {protocol:?} has no ports (only tcp/udp do)"
        )));
    }
    let num = |s: &str| {
        s.parse::<u16>()
            .ok()
            .filter(|p| *p > 0 && !s.starts_with('+'))
    };
    let ok = match value.split_once('-') {
        Some((lo, hi)) => matches!((num(lo), num(hi)), (Some(l), Some(h)) if l <= h),
        None => num(value).is_some(),
    };
    if ok {
        Ok(())
    } else {
        Err(AnvilError::Validation(format!(
            "{field} = {value:?} must be a port or range like \"443\" or \"8000-9000\""
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hetzner_rule_ports_match_what_the_api_accepts() {
        let rule = |proto: &str, port: &str| {
            validate_body(&format!(
                "[hetzner]\nserver_name = \"x\"\nrules = [{{ direction = \"in\", protocol = \"{proto}\", port = \"{port}\" }}]"
            ))
        };
        rule("tcp", "443").unwrap();
        rule("udp", "8000-9000").unwrap();
        rule("tcp", "443-443").unwrap();
        for bad in [
            "ssh",
            "80,443",
            "8000:9000",
            "0",
            "70000",
            "9000-8000",
            "+22",
            "-22",
            "22-",
        ] {
            assert!(rule("tcp", bad).is_err(), "{bad} must be rejected");
        }
        assert!(rule("icmp", "22").is_err(), "icmp has no ports");
    }

    #[test]
    fn hetzner_keep_public_ssh_false_needs_tailnet_only_ssh() {
        let hz = "[hetzner]\nserver_name = \"x\"\nkeep_public_ssh = false\n";
        let ts = |on: bool| format!("[firewall]\n[tailscale]\ntailnet_only_ssh = {on}\n");
        for body in [hz.to_string(), format!("{hz}{}", ts(false))] {
            let err = validate_body(&body).unwrap_err().to_string();
            assert!(err.contains("tailnet_only_ssh = true"), "{err}");
            assert!(err.contains("locks you out"), "{err}");
        }
        validate_body(&format!("{hz}{}", ts(true))).unwrap();
        validate_body("[hetzner]\nserver_name = \"x\"\n").unwrap();
    }

    #[test]
    fn netcup_section_is_validated() {
        let nc = |extra: &str| validate_body(&format!("[netcup]\nserver = \"7\"\n{extra}"));
        nc("").unwrap();
        nc("rules = [{ direction = \"in\", protocol = \"icmpv6\" }]").unwrap();
        nc("rules = [{ direction = \"out\", protocol = \"udp\", port = \"53\", source_ips = [\"10.0.0.0/8\"] }]").unwrap();
        for bad in [
            "rules = [{ direction = \"in\", protocol = \"esp\" }]",
            "rules = [{ direction = \"in\", protocol = \"icmp\", port = \"22\" }]",
            "rules = [{ direction = \"in\", protocol = \"tcp\", port = \"80,443\" }]",
            "rules = [{ direction = \"in\", protocol = \"tcp\", source_ips = [\"nope\"] }]",
            "rules = [{ direction = \"up\", protocol = \"tcp\" }]",
            "policy = \" \"",
        ] {
            assert!(nc(bad).is_err(), "{bad}");
        }
        assert!(nc(&format!("policy = \"{}\"", "p".repeat(256))).is_err());
        nc(&format!("policy = \"{}\"", "p".repeat(255))).unwrap();
        let err = validate_body("[netcup]\n").unwrap_err().to_string();
        assert!(err.contains("netcup.server"), "{err}");
        let cfg: NetcupSection = toml::from_str("server = \"7\"").unwrap();
        assert_eq!(cfg.policy, "anvil");
        assert!(cfg.keep_public_ssh);
    }

    #[test]
    fn netcup_keep_public_ssh_false_needs_tailnet_only_ssh() {
        let nc = "[netcup]\nserver = \"7\"\nkeep_public_ssh = false\n";
        let err = validate_body(nc).unwrap_err().to_string();
        assert!(
            err.contains("netcup.keep_public_ssh") && err.contains("SCP console"),
            "{err}"
        );
        validate_body(&format!(
            "{nc}[firewall]\n[tailscale]\ntailnet_only_ssh = true\n"
        ))
        .unwrap();
    }

    #[test]
    fn caddy_without_netcup_443_is_warned_as_netcup() {
        let w = host_plus(&format!("{CADDY}[netcup]\nserver = \"7\"\n"))
            .warnings()
            .join("\n");
        assert!(
            w.contains("netcup: [caddy] is enabled but no rule allows 443/tcp"),
            "{w}"
        );
        assert!(!w.contains("hetzner:"), "{w}");
    }

    fn base(toml: &str) -> Config {
        toml::from_str(toml).expect("parse")
    }

    #[test]
    fn minimal_valid_config() {
        let c = base(
            r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
        "#,
        );
        c.validate().expect("valid");
        assert!(c.is_enabled("sshd"));
        assert_eq!(c.effective_ssh_port(), 22);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [host]
            address = "h"
            user = "u"
            nope = true
        "#,
        );
        assert!(err.is_err(), "deny_unknown_fields should reject typos");
    }

    #[test]
    fn unknown_field_inside_a_section_is_rejected() {
        // deny_unknown_fields must hold on every section struct, not just the
        // top level: a misspelled security field that parses silently is a
        // hardening step that never happens.
        for (section, typo) in [
            ("sshd", "prot = 2222"),
            ("firewall", "default_incomming = \"deny\""),
            ("users", "craete = []"),
            ("updates", "security_onyl = true"),
        ] {
            let toml = format!("[host]\naddress = \"h\"\nuser = \"u\"\n[{section}]\n{typo}\n");
            assert!(
                toml::from_str::<Config>(&toml).is_err(),
                "unknown field in [{section}] must be rejected"
            );
        }
    }

    #[test]
    fn every_module_section_rejects_unknown_fields() {
        // deny_unknown_fields must hold on EVERY registered module
        // section (the public TOML contract), not just the four sampled above.
        // This also pins that a newly added section carries the attribute.
        for id in MODULE_IDS {
            let toml =
                format!("[host]\naddress = \"h\"\nuser = \"u\"\n[{id}]\n__anvil_unknown = true\n");
            assert!(
                toml::from_str::<Config>(&toml).is_err(),
                "[{id}] must reject an unknown field (deny_unknown_fields)"
            );
        }
    }

    /// Parse + validate a config built from a section body (host is valid).
    fn validate_body(body: &str) -> Result<()> {
        base(&format!("[host]\naddress = \"h\"\nuser = \"u\"\n{body}")).validate()
    }

    #[test]
    fn container_warnings() {
        let host = "[host]\naddress = \"h\"\nuser = \"u\"\n";
        let w = |body: &str| base(&format!("{host}{body}")).warnings();
        let compose = "[containers.compose.a]\ncontent = \"s\"\n";
        assert_eq!(w(&format!("[docker]\n{compose}")).len(), 1);
        assert!(w(&format!("[docker]\niptables_off = false\n{compose}")).is_empty());
        assert!(w(compose).is_empty());
        let hp = "[headscale]\nserver_url = \"https://h\"\nlisten_addr = \"127.0.0.1:8080\"\nheadplane = true\n";
        assert!(w(hp).is_empty(), "loopback default is fine");
        assert_eq!(
            w(&format!("{hp}headplane_listen = \"0.0.0.0:3000\"\n")).len(),
            1
        );
        assert!(w(&format!(
            "[docker]\n{hp}headplane_listen = \"0.0.0.0:3000\"\n"
        ))
        .is_empty());
    }

    #[test]
    fn podman_section_makes_a_podman_host() {
        let engine = |body: &str| {
            base(&format!("[host]\naddress = \"h\"\nuser = \"u\"\n{body}")).host_engine()
        };
        assert_eq!(engine(""), Engine::Docker);
        assert_eq!(engine("[docker]"), Engine::Docker);
        assert_eq!(engine("[containers]"), Engine::Docker);
        assert_eq!(engine("[containers]\nruntime = \"docker\""), Engine::Docker);
        assert_eq!(engine("[containers]\nruntime = \"podman\""), Engine::Podman);
        assert_eq!(engine("[podman]"), Engine::Podman);
        assert_eq!(engine("[podman]\n[containers]"), Engine::Podman);

        let quadlet = "[containers.quadlet.web]\ncontent = \"[Container]\\nImage=nginx\\n\"\n";
        validate_body("[podman]").unwrap();
        validate_body("[podman]\nlog_driver = \"journald\"").unwrap();
        validate_body(&format!("[podman]\n{quadlet}")).unwrap();
        validate_body(&format!(
            "[podman]\n[containers]\nruntime = \"podman\"\n{quadlet}"
        ))
        .unwrap();
        let e = |body: &str| validate_body(body).unwrap_err().to_string();
        assert!(e("[podman]\nlog_driver = \"json-file\"").contains("podman.log_driver"));
        validate_body("[docker]\nlog_driver = \"journald\"").unwrap();
        assert!(e("[docker]\nlog_driver = \"k8s-file\"").contains("docker.log_driver"));
        assert!(e("[podman]\nsource = \"vendor\"").contains("podman.source"));
        let both = e("[docker]\n[podman]");
        assert!(
            both.contains("[docker] hardens dockerd; it cannot run on a Podman host"),
            "{both}"
        );
        let rt = e("[podman]\n[containers]\nruntime = \"docker\"");
        assert!(
            rt.contains("[podman] makes this a Podman host") && rt.contains("runtime = \"docker\""),
            "{rt}"
        );
        // [podman] alone refuses the Docker-only rows, like runtime = "podman".
        assert!(
            e("[podman]\n[containers.compose.a]\ncontent = \"s\"").contains("needs a Docker host")
        );
        validate_body("[podman]\n[greptimedb]").unwrap();
        // The forgejo sandbox is sysbox, i.e. Docker.
        let fjr = "[forgejo_runner]\nmode = \"ephemeral\"\napi_token = \"t\"\n\
                   url = \"https://git.example.org/\"\nlabels = [\"debian:host\"]\n";
        validate_body(fjr).unwrap();
        assert!(e(&format!("[podman]\n{fjr}"))
            .contains("forgejo_runner mode = \"ephemeral\" runs sysbox sandboxes on Docker"));
        let gt = e("[podman]\n[greptimedb]\n[containers.quadlet.greptimedb]\ncontent = \"s\"");
        assert!(
            gt.contains("[containers.quadlet.greptimedb] is reserved"),
            "{gt}"
        );
    }

    #[test]
    fn containers_podman_runtime_is_validated() {
        let q = |content: &str| {
            format!(
                "[containers]\nruntime = \"podman\"\n[containers.quadlet.web]\n\
                 content = '''\n[Container]\nImage=nginx\n{content}\n'''\n"
            )
        };
        for ok in [
            "PublishPort=127.0.0.1:8080:80",
            "PublishPort = 127.0.0.2::80/udp",
            "PublishPort=\"[::1]:8080:80\"",
            "Network=host\nPodmanArgs=--pids-limit 100",
            "",
        ] {
            validate_body(&q(ok)).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in [
            "PublishPort=8080:80",
            "PublishPort=80",
            "PublishPort=0.0.0.0:8080:80",
            "PublishPort=[::]:8080:80",
            "PublishPort=10.0.0.1:8080:80",
            "PublishPort=localhost:8080:80",
            "PublishPort=127.0.0.1:8080:80\nPublishPort=9090:90",
            "PodmanArgs=-p 8080:80",
            "PodmanArgs=--publish=8080:80",
            "PodmanArgs=--rm -P",
        ] {
            let e = validate_body(&q(bad)).unwrap_err().to_string();
            assert!(e.contains("may publish beyond 127.0.0.1"), "{bad}: {e}");
        }
        let e = |body: &str| validate_body(body).unwrap_err().to_string();
        assert!(e("[containers]\nruntime = \"lxc\"").contains("containers.runtime"));
        assert!(e("[docker]\nsource = \"snap\"").contains("docker.source"));
        validate_body("[docker]\nsource = \"distro\"").unwrap();
        assert!(
            e("[containers]\nruntime = \"podman\"\n[containers.compose.a]\ncontent = \"s\"")
                .contains("needs a Docker host")
        );
        assert!(
            e("[containers.quadlet.a]\ncontent = \"[Container]\"").contains("needs a Podman host")
        );
        assert!(e(&format!("[docker]\n{}", q(""))).contains("[docker] hardens dockerd"));
        assert!(e(&q("").replace("quadlet.web", "quadlet.Web")).contains("containers.quadlet"));
        assert!(
            e("[containers]\nruntime = \"podman\"\n[containers.quadlet.a]\ncontent = \" \"")
                .contains("must not be empty")
        );
        // Docker stays the default; podman with no units is valid.
        validate_body("[containers]\nruntime = \"podman\"").unwrap();
        validate_body("[containers]\nruntime = \"docker\"\n[docker]").unwrap();
    }

    #[test]
    fn containers_compose_names_and_env_are_validated() {
        let ok = "[containers.compose.web-1]\ncontent = \"services: {}\"\nenv = { DB_PASS = \"a b $c\" }";
        validate_body(ok).unwrap();
        validate_body("[containers.compose.web]\ncontent = \"s\"\nenv = { A = \"it's\" }").unwrap();
        for bad in [
            "[containers.compose.Web]\ncontent = \"s\"",
            "[containers.compose.-web]\ncontent = \"s\"",
            "[containers.compose.\"a/b\"]\ncontent = \"s\"",
            "[containers.compose.web]\ncontent = \" \"",
            "[containers.compose.web]\ncontent = \"s\"\nenv = { \"1A\" = \"v\" }",
            "[containers.compose.web]\ncontent = \"s\"\nenv = { A = \"x\\ny\" }",
        ] {
            assert!(validate_body(bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn forgejo_runner_requires_forgejo_actions_in_the_same_config() {
        let fj = "[forgejo]\ndomain = \"git.example.org\"\nsecret_key = \"x\"\n\
                  internal_token = \"x\"\njwt_secret = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n";
        let r = "[forgejo_runner]\nuuid = \"00000000-0000-4000-8000-000000000000\"\n\
                 labels = [\"debian:host\"]\n";
        let err = validate_body(&format!("{fj}{r}")).unwrap_err().to_string();
        assert!(err.contains("forgejo.actions = true"), "{err}");
        validate_body(&format!("{fj}actions = true\n{r}")).unwrap();
        let err = validate_body(r).unwrap_err().to_string();
        assert!(err.contains("forgejo_runner.url is required"), "{err}");
    }

    #[test]
    fn forgejo_compose_and_tailnet_need_their_sections() {
        let fj = "[forgejo]\ndomain = \"git.example.org\"\nsecret_key = \"x\"\n\
                  internal_token = \"x\"\njwt_secret = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n";
        let err = |body: &str| validate_body(body).unwrap_err().to_string();
        let compose = format!("{fj}deploy = \"compose\"\n");
        assert!(err(&compose).contains("needs Docker"));
        validate_body(&format!("[docker]\n{compose}")).unwrap();
        let podman = format!("[containers]\nruntime = \"podman\"\n{compose}");
        assert!(
            err(&podman).contains("Use deploy = \"quadlet\""),
            "{}",
            err(&podman)
        );
        validate_body(&format!("[containers]\nruntime = \"podman\"\n{fj}")).unwrap();
        // A v2 runner brings Docker only on a Docker host (sysbox), not Podman.
        let v2 = "[github_runner]\nmode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\n\
                  runner_group_id = 3\napp_key = \"-----BEGIN RSA PRIVATE KEY-----\\nx\\n-----END RSA PRIVATE KEY-----\"\n\
                  [github_runner.runners.ci]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\"]\n";
        validate_body(&format!("{compose}{v2}")).unwrap();
        assert!(err(&format!("{podman}{v2}")).contains("Use deploy = \"quadlet\""));
        // So does an ephemeral forgejo runner.
        let fjr = "[forgejo_runner]\nmode = \"ephemeral\"\napi_token = \"t\"\nlabels = [\"debian:host\"]\n";
        validate_body(&format!("{compose}actions = true\n{fjr}")).unwrap();
        assert!(err(&format!("{compose}actions = true\n[forgejo_runner]\nuuid = \"00000000-0000-4000-8000-000000000000\"\nlabels = [\"debian:host\"]\n")).contains("needs Docker"));
        let quadlet = format!("{fj}deploy = \"quadlet\"\n");
        assert!(err(&quadlet).contains("needs a Podman host"));
        assert!(err(&format!("[docker]\n{quadlet}")).contains("needs a Podman host"));
        validate_body(&format!("[podman]\n{quadlet}")).unwrap();
        validate_body(&format!("[containers]\nruntime = \"podman\"\n{quadlet}")).unwrap();
        let tailnet = format!("{fj}listen = \"tailnet\"\n");
        assert!(err(&tailnet).contains("needs [tailscale]"));
        validate_body(&format!("[tailscale]\n{tailnet}")).unwrap();
    }

    #[test]
    fn ci_resources_fields_are_validated() {
        let c = base("[ci_resources]\n").ci_resources.unwrap();
        assert_eq!(c.cpu_weight, 50);
        validate_body(
            "[ci_resources]\ncpu_quota = \"800%\"\nmemory_max = \"20G\"\ntasks_max = 8192\n\
             cpu_weight = 10000",
        )
        .unwrap();
        validate_body("[ci_resources]\ncpu_weight = 1").unwrap();
        for (field, bad) in [
            ("cpu_quota", "\"8\""),
            ("memory_max", "\"20G\\nCPUWeight=1\""),
            ("tasks_max", "0"),
            ("cpu_weight", "0"),
            ("cpu_weight", "10001"),
        ] {
            let err = validate_body(&format!("[ci_resources]\n{field} = {bad}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(&format!("ci_resources.{field}")), "{err}");
        }
    }

    #[test]
    fn apps_resources_fields_are_validated() {
        // systemd's default: sibling slices split CPU evenly unless set.
        let a = base("[apps_resources]\n").apps_resources.unwrap();
        assert_eq!(a.cpu_weight, 100);
        assert!(!base("").is_enabled("apps_resources"), "opt-in section");
        validate_body(
            "[apps_resources]\ncpu_quota = \"400%\"\nmemory_max = \"6G\"\ntasks_max = 4096\n\
             cpu_weight = 10000\nsystem_memory_low = \"2G\"",
        )
        .unwrap();
        validate_body("[apps_resources]\nsystem_memory_low = \"100%\"").unwrap();
        for (field, bad) in [
            ("cpu_quota", "\"4\""),
            ("memory_max", "\"6G\\nCPUWeight=1\""),
            ("tasks_max", "0"),
            ("cpu_weight", "0"),
            ("cpu_weight", "10001"),
            ("system_memory_low", "\"101%\""),
            ("system_memory_low", "\"2G\\nMemoryMax=1G\""),
        ] {
            let err = validate_body(&format!("[apps_resources]\n{field} = {bad}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(&format!("apps_resources.{field}")), "{err}");
        }
    }

    #[test]
    fn ci_resources_with_docker_group_warns_that_containers_escape_the_slice() {
        let r = "[github_runner]\ndocker = \"group\"\n\
                 [github_runner.runners.b]\nurl = \"https://github.com/acme\"\n";
        let f = "[forgejo_runner]\nurl = \"https://git.example.org/\"\n\
                 uuid = \"00000000-0000-4000-8000-000000000000\"\nlabels = [\"x:host\"]\n\
                 docker = \"group\"\n";
        let warned = |body: &str| {
            base(body)
                .warnings()
                .iter()
                .any(|w| w.contains("dockerd's cgroup"))
        };
        assert!(warned(&format!("[ci_resources]\n{r}")));
        assert!(warned(&format!("[ci_resources]\n{f}")));
        assert!(!warned(r), "no slice, no warning");
        assert!(!warned(&format!(
            "[ci_resources]\n{}",
            r.replace("group", "none")
        )));
        assert!(!warned(&format!(
            "[ci_resources]\n{}",
            f.replace("\"group\"", "\"none\"")
        )));
    }

    #[test]
    fn forgejo_runner_docker_group_is_refused_on_podman() {
        let fj = "[forgejo]\ndomain = \"git.example.org\"\nsecret_key = \"x\"\n\
                  internal_token = \"x\"\nactions = true\n\
                  jwt_secret = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n";
        let r = "[forgejo_runner]\nuuid = \"00000000-0000-4000-8000-000000000000\"\n\
                 labels = [\"debian:host\"]\ndocker = \"group\"\n";
        let podman = "[containers]\nruntime = \"podman\"\n";
        validate_body(&format!("{fj}{r}")).unwrap();
        validate_body(&format!("[containers]\nruntime = \"docker\"\n{fj}{r}")).unwrap();
        validate_body(&format!(
            "{podman}{fj}{}",
            r.replace("\"group\"", "\"none\"")
        ))
        .unwrap();
        let e = validate_body(&format!("{podman}{fj}{r}"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("forgejo_runner docker = \"group\""), "{e}");
        let rp = r.replace("\"group\"", "\"podman\"");
        validate_body(&format!("{podman}{fj}{rp}")).unwrap();
        let e = validate_body(&format!("{fj}{rp}")).unwrap_err().to_string();
        assert!(
            e.contains("forgejo_runner docker = \"podman\" needs a Podman host"),
            "{e}"
        );
    }

    #[test]
    fn greptimedb_and_headplane_run_on_podman() {
        let podman = "[containers]\nruntime = \"podman\"\n";
        let gt = "[greptimedb]\n";
        let hs = "[headscale]\nserver_url = \"https://h\"\nlisten_addr = \"127.0.0.1:8080\"\n";
        let hp = format!("{hs}headplane = true\n");
        validate_body(gt).unwrap();
        validate_body(&hp).unwrap();
        validate_body(&format!("[containers]\nruntime = \"docker\"\n{gt}")).unwrap();
        validate_body(&format!("{podman}{hs}")).unwrap();
        validate_body(&format!("{podman}{gt}")).unwrap();
        validate_body(&format!("{podman}{hp}")).unwrap();
        // The Docker socket integration has no Podman counterpart.
        let sock = format!("{hp}headplane_docker_socket = true\n");
        validate_body(&sock).unwrap();
        let e = validate_body(&format!("{podman}{sock}"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("headplane_docker_socket mounts the Docker socket"),
            "{e}"
        );
        // Their publishes stay on loopback, like [containers.quadlet].
        let e = validate_body(&format!(
            "{podman}[greptimedb]\nlisten_address = \"0.0.0.0\"\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("greptimedb.listen_address") && e.contains("past ufw"),
            "{e}"
        );
        validate_body("[greptimedb]\nlisten_address = \"0.0.0.0\"\n").unwrap();
        validate_body(&format!(
            "{podman}[greptimedb]\nlisten_address = \"[::1]\"\n"
        ))
        .unwrap();
        let e = validate_body(&format!(
            "{podman}{hp}headplane_listen = \"0.0.0.0:3000\"\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("headscale.headplane_listen") && e.contains("past ufw"),
            "{e}"
        );
        validate_body(&format!(
            "{podman}{hs}headplane_listen = \"0.0.0.0:3000\"\n"
        ))
        .unwrap();
        // Without headplane the socket flag is inert.
        validate_body(&format!("{podman}{hs}headplane_docker_socket = true\n")).unwrap();
    }

    #[test]
    fn github_runner_container_engine_matrix() {
        let app = "app_id = 1\ninstallation_id = 2\nrunner_group_id = 3\n\
                   app_key = \"-----BEGIN RSA PRIVATE KEY-----\\nx\\n-----END RSA PRIVATE KEY-----\"\n";
        let org =
            "[github_runner.runners.ci]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\"]\n";
        let v1 = format!("[github_runner]\nmode = \"persistent\"\n{org}");
        let v2 = format!("[github_runner]\nmode = \"ephemeral\"\n{app}{org}");
        let v1_group = v1.replace("persistent\"\n", "persistent\"\ndocker = \"group\"\n");
        for engine in [
            "",
            "[containers]\nruntime = \"docker\"\n",
            "[containers]\nruntime = \"podman\"\n",
        ] {
            validate_body(&format!("{engine}{v1}")).unwrap();
        }
        validate_body(&v1_group).unwrap();
        validate_body(&format!("[containers]\nruntime = \"docker\"\n{v1_group}")).unwrap();
        let e = validate_body(&format!("[containers]\nruntime = \"podman\"\n{v1_group}"))
            .unwrap_err()
            .to_string();
        for want in [
            "github_runner docker = \"group\"",
            "docker = \"rootless\"",
            "Docker host",
            "v2 runner (mode = \"ephemeral\"",
        ] {
            assert!(e.contains(want), "{want}: {e}");
        }
        // docker = "podman": Podman host only, from either marker.
        let v1_podman = v1.replace("persistent\"\n", "persistent\"\ndocker = \"podman\"\n");
        validate_body(&format!("[containers]\nruntime = \"podman\"\n{v1_podman}")).unwrap();
        validate_body(&format!("[podman]\n{v1_podman}")).unwrap();
        // The docker-rootless sandbox needs Docker's rootless extras.
        let fj = "[forgejo_runner]\nmode = \"ephemeral\"\nurl = \"https://git.example.org/\"\n\
                  api_token = \"t\"\nlabels = [\"x:host\"]\nsandbox_runtime = \"docker-rootless\"\n";
        validate_body(fj).unwrap();
        let e = validate_body(&format!("[docker]\nsource = \"distro\"\n{fj}"))
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("sandbox_runtime = \"docker-rootless\" (the default) needs Docker's own"),
            "{e}"
        );
        // docker = "rootless": the host's engine, on either host.
        let v1_rootless = v1.replace("persistent\"\n", "persistent\"\ndocker = \"rootless\"\n");
        validate_body(&v1_rootless).unwrap();
        validate_body(&format!("[podman]\n{v1_rootless}")).unwrap();
        validate_body(&format!("[docker]\n{v1_rootless}")).unwrap();
        let e = validate_body(&format!("[docker]\nsource = \"distro\"\n{v1_rootless}"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("docker-ce-rootless-extras"), "{e}");
        for engine in ["", "[containers]\nruntime = \"docker\"\n"] {
            let e = validate_body(&format!("{engine}{v1_podman}"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("github_runner docker = \"podman\" needs a Podman host")
                    && e.contains("docker = \"rootless\" on this Docker host"),
                "{e}"
            );
        }
        validate_body(&v2).unwrap();
        validate_body(&format!("[containers]\nruntime = \"docker\"\n{v2}")).unwrap();
        // The runtime follows the host engine; the other one is refused.
        let rt = |r: &str| {
            v2.replace(
                "ephemeral\"\n",
                &format!("ephemeral\"\nsandbox_runtime = \"{r}\"\n"),
            )
        };
        for podman in ["[containers]\nruntime = \"podman\"\n", "[podman]\n"] {
            validate_body(&format!("{podman}{v2}")).unwrap();
            validate_body(&format!("{podman}{}", rt("podman"))).unwrap();
            let e = validate_body(&format!("{podman}{}", rt("sysbox-runc")))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("installs Docker + sysbox; it cannot run on a Podman host"),
                "{e}"
            );
        }
        validate_body(&rt("sysbox-runc")).unwrap();
        let e = validate_body(&rt("podman")).unwrap_err().to_string();
        assert!(
            e.contains("sandbox_runtime = \"podman\" needs a Podman host"),
            "{e}"
        );
        // docker-rootless on a Docker host only, Docker's packages,
        // and slot users (anvil-ghr-<runner>-<n>) that fit 32 characters.
        validate_body(&rt("docker-rootless")).unwrap();
        for (body, want) in [
            (
                format!("[podman]\n{}", rt("docker-rootless")),
                "docker-rootless\" needs a Docker host",
            ),
            (
                format!("[docker]\nsource = \"distro\"\n{}", rt("docker-rootless")),
                "github_runner sandbox_runtime = \"docker-rootless\" (the default) needs Docker's own",
            ),
            (
                rt("docker-rootless")
                    .replace("runners.ci]", &format!("runners.{}]", "r".repeat(21))),
                "too long for sandbox_runtime",
            ),
        ] {
            let e = validate_body(&body).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
        }
        // A sysbox v2 runner on distro Docker is not a docker-rootless one.
        let e = validate_body(&format!(
            "[docker]\nsource = \"distro\"\n{}",
            rt("sysbox-runc")
        ));
        assert!(!format!("{e:?}").contains("docker-rootless"), "{e:?}");
        validate_body(
            &rt("docker-rootless").replace("runners.ci]", &format!("runners.{}]", "r".repeat(20))),
        )
        .unwrap();
        let g: GithubRunnerSection = toml::from_str("").unwrap();
        assert_eq!(g.sandbox_runtime(Engine::Docker), "docker-rootless");
        assert_eq!(g.sandbox_runtime(Engine::Podman), "podman");
    }

    #[test]
    fn github_runner_ephemeral_validation_matrix() {
        let app = "mode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\nrunner_group_id = 3\n\
                   app_key = \"-----BEGIN RSA PRIVATE KEY-----\\nx\\n-----END RSA PRIVATE KEY-----\"\n";
        let org =
            "[github_runner.runners.ci]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\"]\n";
        let ok = |extra: &str, runner: &str| {
            validate_body(&format!("[github_runner]\n{app}{extra}\n{runner}"))
        };
        ok("", org).unwrap();
        ok(
            "capacity = 32\nsandbox_cpus = \"1.5\"\nsandbox_memory = \"512m\"\nsandbox_pids = 1\n\
             sandbox_disk = \"1T\"\nsandbox_runtime = \"sysbox-runc\"\n\
             sandbox_packages = [\"build-essential\", \"g++\"]",
            org,
        )
        .unwrap();
        let err = |extra: &str, runner: &str| ok(extra, runner).unwrap_err().to_string();
        // Required App fields.
        for f in ["app_id", "installation_id", "runner_group_id", "app_key"] {
            let body: String = app
                .lines()
                .filter(|l| !l.starts_with(f))
                .map(|l| format!("{l}\n"))
                .collect();
            let e = validate_body(&format!("[github_runner]\n{body}{org}"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains(&format!("github_runner.{f} is required")),
                "{f}: {e}"
            );
        }
        assert!(validate_body(&format!(
            "[github_runner]\n{}\n{org}",
            app.replace("PRIVATE KEY", "X")
        ))
        .unwrap_err()
        .to_string()
        .contains("PEM private key"));
        for (extra, field) in [
            ("capacity = 0", "capacity"),
            ("capacity = 33", "capacity"),
            ("sandbox_cpus = \"0\"", "sandbox_cpus"),
            ("sandbox_cpus = \"2x\"", "sandbox_cpus"),
            ("sandbox_cpus = \"1.\"", "sandbox_cpus"),
            ("sandbox_cpus = \".5\"", "sandbox_cpus"),
            ("sandbox_memory = \"4G\"", "sandbox_memory"),
            ("sandbox_memory = \"4gg\"", "sandbox_memory"),
            ("sandbox_memory = \"0g\"", "sandbox_memory"),
            ("sandbox_memory = \"g\"", "sandbox_memory"),
            ("sandbox_pids = 0", "sandbox_pids"),
            ("sandbox_disk = \"40\"", "sandbox_disk"),
            ("sandbox_runtime = \"kata\"", "sandbox_runtime"),
            ("sandbox_packages = [\"Bad Name\"]", "sandbox_packages"),
        ] {
            let e = err(extra, org);
            assert!(
                e.contains(&format!("github_runner.{field}")),
                "{extra}: {e}"
            );
        }
        assert!(err("sandbox_runtime = \"runc\"", org).contains("expected one of: sysbox-runc"));
        // v1-only fields are rejected in ephemeral mode.
        for f in [
            "docker = \"group\"",
            "proxy = \"http://p:3128\"",
            "version = \"2.400.0\"",
            "sha256 = \"aa\"",
            "cpu_quota = \"200%\"",
            "memory_max = \"4G\"",
            "tasks_max = 9",
            "disk_max = \"150G\"",
        ] {
            let name = f.split(' ').next().unwrap();
            let e = err(f, org);
            assert!(
                e.contains(&format!("github_runner.{name} is persistent-only")),
                "{f}: {e}"
            );
        }
        // Runners: org URL, labels, no tokens or group.
        for (runner, why) in [
            (
                "url = \"https://github.com/acme/app\"\nlabels = [\"a\"]",
                "org URL",
            ),
            ("url = \"https://github.com/acme\"", "labels are required"),
            (
                "url = \"https://github.com/acme\"\nlabels = [\"a\"]\ntoken = \"t\"",
                "persistent-only",
            ),
            (
                "url = \"https://github.com/acme\"\nlabels = [\"a\"]\nremove_token = \"t\"",
                "persistent-only",
            ),
            (
                "url = \"https://github.com/acme\"\nlabels = [\"a\"]\ngroup = \"g\"",
                "persistent-only",
            ),
        ] {
            let e = err("", &format!("[github_runner.runners.ci]\n{runner}\n"));
            assert!(
                e.contains("github_runner.runners.ci (mode = \"ephemeral\")") && e.contains(why),
                "{e}"
            );
        }
        // Ephemeral fields need the mode.
        for f in [
            "app_id = 1",
            "installation_id = 1",
            "app_key = \"k\"",
            "runner_group_id = 1",
            "capacity = 1",
            "sandbox_cpus = \"2\"",
            "sandbox_memory = \"4g\"",
            "sandbox_pids = 1",
            "sandbox_disk = \"40G\"",
            "sandbox_runtime = \"sysbox-runc\"",
            "sandbox_packages = [\"gcc\"]",
        ] {
            let name = f.split(' ').next().unwrap();
            let e = validate_body(&format!("[github_runner]\n{f}\n{org}"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains(&format!("github_runner.{name} needs mode = \"ephemeral\"")),
                "{e}"
            );
        }
        assert!(
            validate_body(&format!("[github_runner]\nmode = \"oneshot\"\n{org}"))
                .unwrap_err()
                .to_string()
                .contains("github_runner.mode")
        );
        validate_body(&format!("[github_runner]\nmode = \"persistent\"\n{org}")).unwrap();
    }

    #[test]
    fn github_runner_fields_are_validated() {
        let r = "[github_runner.runners.build-1]\nurl = \"https://github.com/acme\"";
        validate_body(r).unwrap();
        validate_body(&format!(
            "[github_runner]\ncpu_quota = \"1200%\"\nmemory_max = \"16G\"\ntasks_max = 4096\n{r}"
        ))
        .unwrap();
        validate_body(&format!("[github_runner]\nmemory_max = \"50%\"\n{r}")).unwrap();
        validate_body(&format!(
            "[github_runner]\ndisk_max = \"150G\"\ndiag_retention_days = 1\n{r}"
        ))
        .unwrap();
        validate_body(&format!("[github_runner]\ndisk_max = \"2T\"\n{r}")).unwrap();
        validate_body(&format!(
            "[github_runner]\nmemory_max = \"1073741824\"\n{r}"
        ))
        .unwrap();
        for (field, bad) in [
            ("cpu_quota", "\"12\""),
            ("cpu_quota", "\"0%\""),
            ("cpu_quota", "\"%\""),
            ("cpu_quota", "\"1.5%\""),
            ("cpu_quota", "\"100%\\nUser=root\""),
            ("memory_max", "\"8GB\""),
            ("memory_max", "\"0\""),
            ("memory_max", "\"G\""),
            ("memory_max", "\"101%\""),
            ("memory_max", "\"-1\""),
            ("memory_max", "\"8G\\nUser=root\""),
            ("tasks_max", "0"),
            ("disk_max", "\"150\""),
            ("disk_max", "\"150GB\""),
            ("disk_max", "\"0G\""),
            ("disk_max", "\"G\""),
            ("disk_max", "\"-1G\""),
            ("disk_max", "\"+5G\""),
            ("disk_max", "\"99999999999T\""),
            ("disk_max", "\"5G\\nUser=root\""),
            ("diag_retention_days", "0"),
            ("home_cache_max", "\"20GB\""),
        ] {
            let err = validate_body(&format!("[github_runner]\n{field} = {bad}\n{r}"))
                .expect_err(bad)
                .to_string();
            assert!(
                err.contains(&format!("github_runner.{field}")),
                "{bad}: {err}"
            );
        }
        validate_body("[github_runner.runners.b]\nurl = \"https://github.com/acme/app\"\nlabels = [\"x.y\", \"a-b\"]").unwrap();
        validate_body(&format!(
            "[github_runner]\ndocker = \"group\"\nproxy = \"http://p:3128\"\n{r}"
        ))
        .unwrap();
        validate_body(&format!(
            "[github_runner]\nversion = \"2.400.0\"\nsha256 = \"{}\"\n{r}",
            "a".repeat(64)
        ))
        .unwrap();
        validate_body(&format!(
            "[firewall]\ndefault_outgoing = \"deny\"\n[github_runner]\nproxy = \"http://p\"\n{r}"
        ))
        .unwrap();
        validate_body(&format!("{r}\ngroup = \"{}\"", "g".repeat(100))).unwrap();
        let rr = "[github_runner.runners";
        for bad in [
            "[github_runner]".to_string(),
            format!("[github_runner]\ndocker = \"sysbox\"\n{r}"),
            format!("[github_runner]\nproxy = \"socks5://p\"\n{r}"),
            format!("[github_runner]\nproxy = \"http://p q\"\n{r}"),
            format!("[github_runner]\nversion = \"2.400.0\"\n{r}"),
            format!("[github_runner]\nsha256 = \"{}\"\n{r}", "a".repeat(64)),
            format!(
                "[github_runner]\nversion = \"latest\"\nsha256 = \"{}\"\n{r}",
                "a".repeat(64)
            ),
            format!("[github_runner]\nversion = \"2.400.0\"\nsha256 = \"abc\"\n{r}"),
            format!(
                "[github_runner]\nversion = \"2.400\"\nsha256 = \"{}\"\n{r}",
                "a".repeat(64)
            ),
            format!(
                "[github_runner]\nversion = \"2..0\"\nsha256 = \"{}\"\n{r}",
                "a".repeat(64)
            ),
            format!(
                "{rr}.b]\nurl = \"https://github.com/acme\"\ngroup = \"{}\"",
                "g".repeat(101)
            ),
            format!("{rr}.Build]\nurl = \"https://github.com/acme\""),
            format!("{rr}.\"a/b\"]\nurl = \"https://github.com/acme\""),
            format!("{rr}.b]\nurl = \"http://github.com/acme\""),
            format!("{rr}.b]\nurl = \"https://gitlab.com/acme\""),
            format!("{rr}.b]\nurl = \"https://github.com/a/b/c\""),
            format!("{rr}.b]\nurl = \"https://github.com/a b\""),
            format!("{rr}.b]\nurl = \"https://github.com/acme/app\"\ngroup = \"g\""),
            format!("{rr}.b]\nurl = \"https://github.com/acme\"\nlabels = [\"a,b\"]"),
            format!("{rr}.b]\nurl = \"https://github.com/acme\"\nlabels = [\"a b\"]"),
            format!("{rr}.b]\nurl = \"https://github.com/acme\"\ngroup = \"a\\nb\""),
            format!("[firewall]\ndefault_outgoing = \"deny\"\n{r}"),
        ] {
            assert!(validate_body(&bad).is_err(), "should reject: {bad}");
        }
    }

    #[test]
    fn tailnet_only_ssh_requires_firewall() {
        let on = "[tailscale]\ntailnet_only_ssh = true\n";
        let err = validate_body(on).unwrap_err().to_string();
        assert!(
            err.contains("tailscale.tailnet_only_ssh = true requires [firewall]"),
            "{err}"
        );
        validate_body(&format!("[firewall]\n{on}")).unwrap();
        validate_body("[tailscale]\n").unwrap();
    }

    #[test]
    fn field_validators_accept_good_and_reject_bad() {
        // pam.umask: octal, 3 or 4 digits.
        validate_body("[pam]\numask = \"027\"").unwrap();
        validate_body("[pam]\numask = \"0027\"").unwrap();
        assert!(
            validate_body("[pam]\numask = \"099\"").is_err(),
            "9 is not octal"
        );
        assert!(validate_body("[pam]\numask = \"27\"").is_err(), "too short");
        // pam.deny must be >= 1.
        assert!(validate_body("[pam]\ndeny = 0").is_err());

        // sshd.max_auth_tries = 0 passes sshd -t but rejects every login.
        validate_body("[sshd]\nmax_auth_tries = 1").unwrap();
        let err = validate_body("[sshd]\nmax_auth_tries = 0").unwrap_err();
        assert!(
            err.to_string().contains("sshd.max_auth_tries"),
            "field-named error: {err}"
        );

        // fail2ban durations: digits + optional s/m/h/d/w/y.
        validate_body("[fail2ban]\nbantime = \"10m\"\nfindtime = \"3600\"").unwrap();
        assert!(
            validate_body("[fail2ban]\nbantime = \"10x\"").is_err(),
            "bad unit"
        );
        assert!(
            validate_body("[fail2ban]\nbantime = \"m\"").is_err(),
            "no digits"
        );

        // firewall proto/from/port.
        validate_body(
            "[firewall]\nallow = [{ port = \"22\", proto = \"tcp\", from = \"10.0.0.0/8\" }]",
        )
        .unwrap();
        assert!(
            validate_body("[firewall]\nallow = [{ port = \"22\", proto = \"banana\" }]").is_err()
        );
        assert!(
            validate_body("[firewall]\nallow = [{ port = \"22\", from = \"10.0.0.0/40\" }]")
                .is_err()
        );
        assert!(validate_body("[firewall]\nallow = [{ port = \"22; rm -rf\" }]").is_err());

        // dns servers are IPs.
        validate_body(
            "[dns]\ndns_servers = [\"9.9.9.9\"]\nfallback_servers = [\"1.1.1.1\", \"::1\"]",
        )
        .unwrap();
        assert!(validate_body("[dns]\ndns_servers = [\"not-an-ip\"]").is_err());

        // hetzner rule direction/protocol/source_ips.
        validate_body(
            "[hetzner]\nserver_name = \"x\"\nrules = [{ direction = \"in\", protocol = \"tcp\", source_ips = [\"10.0.0.0/8\"] }]",
        )
        .unwrap();
        assert!(validate_body(
            "[hetzner]\nserver_name = \"x\"\nrules = [{ direction = \"sideways\", protocol = \"tcp\" }]"
        )
        .is_err());
        assert!(validate_body(
            "[hetzner]\nserver_name = \"x\"\nrules = [{ direction = \"in\", protocol = \"tcp\", source_ips = [\"nope\"] }]"
        )
        .is_err());

        // headplane_version reuses the semver validator (server_url is required).
        validate_body(
            "[headscale]\nserver_url = \"https://hs.example\"\nversion = \"0.23.0\"\nheadplane_version = \"0.2.0\"",
        )
        .unwrap();
        assert!(validate_body(
            "[headscale]\nserver_url = \"https://hs.example\"\nversion = \"0.23.0\"\nheadplane_version = \"latest\""
        )
        .is_err());

        // kernel.extra_sysctl key charset.
        validate_body("[kernel]\nextra_sysctl = { \"net.ipv4.tcp_syncookies\" = \"1\" }").unwrap();
        assert!(validate_body("[kernel]\nextra_sysctl = { \"bad key!\" = \"1\" }").is_err());
    }

    #[test]
    fn missing_host_fails_validation() {
        let c = base("[sshd]\n");
        assert!(c.validate().is_err());
    }

    #[test]
    fn hosts_merges_singular_and_plural_preserving_order() {
        let c: Config = toml::from_str(
            r#"
            [host]
            address = "one"
            user = "u"
            [[hosts]]
            address = "two"
            user = "u"
            [[hosts]]
            address = "three"
            user = "u"
            [sshd]
        "#,
        )
        .unwrap();
        c.validate().expect("merged host set valid");
        let addrs: Vec<&str> = c.hosts().iter().map(|h| h.address.as_str()).collect();
        assert_eq!(
            addrs,
            ["one", "two", "three"],
            "[host] first, then [[hosts]]"
        );
    }

    #[test]
    fn plural_hosts_alone_suffice_and_are_validated_by_index() {
        let ok: Config = toml::from_str(
            r#"
            [[hosts]]
            address = "a"
            user = "u"
            [sshd]
        "#,
        )
        .unwrap();
        ok.validate().expect("plural-only config valid");
        assert_eq!(ok.hosts().len(), 1);

        // The error must name the offending entry by its merged index.
        let bad: Config = toml::from_str(
            r#"
            [[hosts]]
            address = "a"
            user = "u"
            [[hosts]]
            address = ""
            user = "u"
            [sshd]
        "#,
        )
        .unwrap();
        let err = bad.validate().expect_err("empty address rejected");
        assert!(err.to_string().contains("host[1].address"), "{err}");
    }

    #[test]
    fn bad_reboot_time_rejected() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [updates]
            reboot_time = "25:00"
        "#,
        );
        assert!(c.validate().is_err());
    }

    #[test]
    fn bad_firewall_policy_rejected() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [firewall]
            default_incoming = "drop"
        "#,
        );
        assert!(c.validate().is_err());
    }

    #[test]
    fn bad_username_rejected() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [users]
            create = [{ name = "../root" }]
        "#,
        );
        assert!(c.validate().is_err());
    }

    fn host_plus(extra: &str) -> Config {
        base(&format!("[host]\naddress = \"h\"\nuser = \"u\"\n{extra}"))
    }

    #[test]
    fn values_reaching_files_are_validated() {
        // One rejection per field, plus the accepted form.
        let rejects = |body: &str, field: &str| {
            let err = validate_body(body).expect_err(body).to_string();
            assert!(err.contains(field), "{body}: {err}");
        };
        validate_body("[kernel]\nextra_sysctl = { \"vm.swappiness\" = \"10\" }").unwrap();
        rejects(
            "[kernel]\nextra_sysctl = { \"vm.swappiness\" = \"10\\nkernel.x = 1\" }",
            "kernel.extra_sysctl.vm.swappiness",
        );

        validate_body("[fail2ban.jails.nginx-http-auth]\n").unwrap();
        rejects("[fail2ban.jails.\"a]\\n[b\"]\n", "fail2ban.jails");
        rejects("[fail2ban.jails.DEFAULT]\n", "fail2ban.jails");
        rejects("[fail2ban.jails.INCLUDES]\n", "fail2ban.jails");

        validate_body("[tls]\ndomains = [\"a.example.com\"]\nwebroot = \"/var/www/html\"").unwrap();
        rejects("[tls]\ndomains = [\"../../etc\"]", "tls.domains");
        rejects("[tls]\ndomains = [\"a.com; include /x\"]", "tls.domains");
        rejects("[tls]\nwebroot = \"var/www\"", "tls.webroot");
        rejects("[tls]\nwebroot = \"/var/www; }\"", "tls.webroot");
        rejects("[tls]\nwebroot = \"/var/www;x\"", "tls.webroot");
        rejects("[tls]\nwebroot = \"/var/w w\"", "tls.webroot");

        let hs = "[headscale]\nserver_url = \"https://h\"\n[[headscale.auth_keys]]\nname = ";
        validate_body(&format!("{hs}\"ci-1\"")).unwrap();
        rejects(&format!("{hs}\"../x\""), "headscale.auth_keys.name");
    }

    #[test]
    fn caddy_values_are_validated() {
        let rejects = |body: &str, field: &str| {
            let err = validate_body(body).expect_err(body).to_string();
            assert!(err.contains(field), "{body}: {err}");
        };
        let site = "[[caddy.site]]\ndomain = \"git.example.com\"\nupstream = \"127.0.0.1:3000\"\n";
        let hash = "$2a$14$Zkx19XLiW6VYouLHR5NmfOFU0z2GTNmpkT/5qqR7hx4IjWJPDhjvG";
        validate_body(&format!(
            "[caddy]\nemail = \"ops@example.com\"\nca = \"staging\"\n{site}\
             allow = [\"100.64.0.0/10\", \"::1\"]\n\
             basic_auth = {{ user = \"ops\", password_hash = \"{hash}\" }}\n\
             [[caddy.site]]\ndomain = \"b.example.com\"\nupstream = \"[::1]:8080\"\n\
             [[caddy.site]]\ndomain = \"c.example.com\"\nupstream = \"localhost:9000\""
        ))
        .unwrap();
        rejects("[caddy]\n", "caddy.site");
        rejects(&format!("[caddy]\nca = \"prod\"\n{site}"), "caddy.ca");
        rejects(
            &format!("[caddy]\nemail = \"a b@x.com\"\n{site}"),
            "caddy.email",
        );
        for bad in ["ops", "@example.com", "o{x}@example.com", "o#x@example.com"] {
            rejects(&format!("[caddy]\nemail = {bad:?}\n{site}"), "caddy.email");
        }
        rejects(
            &format!("[caddy]\n{site}[[caddy.site]]\ndomain = \"Git.Example.com\"\nupstream = \"127.0.0.1:1\""),
            "listed twice",
        );
        rejects(&format!("[caddy]\nhttp_port = 443\n{site}"), "must differ");
        rejects(&format!("[caddy]\n{site}{site}"), "listed twice");
        for bad in ["a.com {", "*.example.com", "a.com\nimport /x"] {
            rejects(
                &format!("[caddy]\n[[caddy.site]]\ndomain = {bad:?}\nupstream = \"127.0.0.1:1\""),
                "caddy.site.domain",
            );
        }
        for bad in ["127.0.0.1", "127.0.0.1:0", "x:y", "a b:80", "h:80 {"] {
            rejects(
                &format!("[caddy]\n[[caddy.site]]\ndomain = \"a.com\"\nupstream = {bad:?}"),
                "caddy.site.upstream",
            );
        }
        rejects(
            &format!("[caddy]\n{site}allow = [\"10.0.0.0/33\"]"),
            "caddy.site.allow",
        );
        rejects(
            &format!(
                "[caddy]\n{site}basic_auth = {{ user = \"a b\", password_hash = \"{hash}\" }}"
            ),
            "caddy.site.basic_auth.user",
        );
        let err = validate_body(&format!(
            "[caddy]\n{site}basic_auth = {{ user = \"a\", password_hash = \"hunter2 }}\" }}"
        ))
        .expect_err("plaintext");
        let err = err.to_string();
        assert!(
            err.contains("password_hash") && !err.contains("hunter2"),
            "{err}"
        );
        // Each condition alone must reject: no `$` prefix, or a bad char.
        for bad in ["plaintext", "$2a$14$ab}cd"] {
            rejects(
                &format!("[caddy]\n{site}basic_auth = {{ user = \"a\", password_hash = {bad:?} }}"),
                "password_hash",
            );
        }

        // [tls] and [caddy] both want 80/443 by default.
        let tls = "[tls]\ndomains = [\"a.example.com\"]\n";
        rejects(&format!("{tls}[caddy]\n{site}"), "[tls]");
        rejects(&format!("{tls}[caddy]\nhttp_port = 8080\n{site}"), "[tls]");
        validate_body(&format!(
            "{tls}[caddy]\nhttp_port = 8080\nhttps_port = 8443\n{site}"
        ))
        .unwrap();
    }

    #[test]
    fn caddy_tailnet_and_tailscale_tls_are_validated() {
        let rejects = |body: &str, needle: &str| {
            let err = validate_body(body).expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        let ts = "[tailscale]\n[firewall]\n";
        let ts_site =
            "[[caddy.site]]\ndomain = \"n1.tail1.ts.net\"\nupstream = \"127.0.0.1:3000\"\n\
                       tls = \"tailscale\"\n";
        let acme_site =
            "[[caddy.site]]\ndomain = \"git.example.com\"\nupstream = \"127.0.0.1:3000\"\n";
        validate_body(&format!("{ts}[caddy]\nlisten = \"tailnet\"\n{ts_site}")).unwrap();
        validate_body(&format!("{ts}[caddy]\n{ts_site}{acme_site}")).unwrap();
        rejects(
            &format!("{ts}[caddy]\nlisten = \"lan\"\n{ts_site}"),
            "caddy.listen",
        );
        rejects(
            &format!("{ts}[caddy]\n{acme_site}tls = \"x\""),
            "caddy.site.tls",
        );
        // tailnet needs both tailscale0 and ufw.
        for missing in ["[tailscale]\n", "[firewall]\n"] {
            rejects(
                &format!("{missing}[caddy]\nlisten = \"tailnet\"\n{ts_site}"),
                "needs [tailscale]",
            );
        }
        rejects(
            &format!("{ts}[caddy]\nlisten = \"tailnet\"\n{ts_site}{acme_site}"),
            "cannot work with caddy.listen",
        );
        rejects(
            &format!(
                "{ts}[caddy]\n[[caddy.site]]\ndomain = \"git.example.com\"\n\
                      upstream = \"127.0.0.1:1\"\ntls = \"tailscale\"\n"
            ),
            "*.ts.net",
        );
        rejects(
            &format!("[caddy]\n{ts_site}"),
            "tailscaled issues the certificate",
        );
    }

    #[test]
    fn caddy_dns_sites_are_validated() {
        let rejects = |body: &str, needle: &str| {
            let err = validate_body(body).expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
            assert!(!err.contains("s3cr3t"), "token leaked: {err}");
        };
        let site = |domain: &str, extra: &str| {
            format!("[[caddy.site]]\ndomain = \"{domain}\"\nupstream = \"127.0.0.1:1\"\n{extra}")
        };
        let dns = |t: &str| {
            format!("tls = \"dns\"\ndns_provider = \"infomaniak\"\ndns_token = \"{t}\"\n")
        };
        validate_body(&format!(
            "[caddy]\n{}{}",
            site("a.example.com", &dns("s3cr3t")),
            site("b.example.com", &dns("s3cr3t"))
        ))
        .unwrap();
        // DNS-01 needs no inbound port, so it works on the tailnet.
        validate_body(&format!(
            "[tailscale]\n[firewall]\n[caddy]\nlisten = \"tailnet\"\n{}",
            site("a.example.com", &dns("s3cr3t"))
        ))
        .unwrap();
        rejects(
            &format!(
                "[caddy]\n{}",
                site("a.example.com", "tls = \"dns\"\ndns_token = \"s3cr3t\"\n")
            ),
            "needs dns_provider",
        );
        rejects(
            &format!(
                "[caddy]\n{}",
                site(
                    "a.example.com",
                    "tls = \"dns\"\ndns_provider = \"cloudflare\"\ndns_token = \"s3cr3t\"\n"
                )
            ),
            "needs dns_provider, one of [\"infomaniak\"]",
        );
        rejects(
            &format!(
                "[caddy]\n{}",
                site(
                    "a.example.com",
                    "tls = \"dns\"\ndns_provider = \"infomaniak\"\n"
                )
            ),
            "dns_token is missing",
        );
        for bad in ["", "s3cr3t x", "s3cr3t\\nX=1", "s3cr3t'", "$s3cr3t"] {
            rejects(
                &format!("[caddy]\n{}", site("a.example.com", &dns(bad))),
                "dns_token is missing or not",
            );
        }
        rejects(
            &format!(
                "[caddy]\n{}{}",
                site("a.example.com", &dns("s3cr3t")),
                site("b.example.com", &dns("other"))
            ),
            "must share one dns_token",
        );
        for stray in [
            "dns_provider = \"infomaniak\"\n",
            "dns_token = \"s3cr3t\"\n",
        ] {
            rejects(
                &format!("[caddy]\n{}", site("a.example.com", stray)),
                "need tls = \"dns\"",
            );
        }
    }

    #[test]
    fn orca_server_orders_coding_agents_after_tailscale_and_firewall() {
        let after = |extra: &str| {
            host_plus(&format!(
                "[tailscale]\n[firewall]\n[coding_agents]\n{extra}"
            ))
            .enabled_sections()
            .into_iter()
            .find(|e| e.id == "coding_agents")
            .expect("coding_agents")
            .order_override
            .after
        };
        assert!(after("").is_empty());
        assert_eq!(
            after("[coding_agents.orca_server]\n"),
            ["tailscale", "firewall"]
        );
    }

    #[test]
    fn caddy_orders_after_tailscale_only_when_it_needs_it() {
        let after = |caddy: &str| {
            host_plus(&format!("[tailscale]\n[firewall]\n[caddy]\n{caddy}"))
                .enabled_sections()
                .into_iter()
                .find(|e| e.id == "caddy")
                .expect("caddy")
                .order_override
                .after
        };
        let site = |tls: &str| {
            format!("[[caddy.site]]\ndomain = \"n.t.ts.net\"\nupstream = \"127.0.0.1:1\"\ntls = \"{tls}\"\n")
        };
        assert!(after(&site("acme")).is_empty());
        assert_eq!(after(&site("tailscale")), ["tailscale"]);
        assert_eq!(
            after(&format!("listen = \"tailnet\"\n{}", site("acme"))),
            ["tailscale"]
        );
    }

    #[test]
    fn caddy_on_the_tailnet_needs_no_provider_rules() {
        let w = host_plus(
            "[caddy]\nlisten = \"tailnet\"\n[[caddy.site]]\ndomain = \"n.t.ts.net\"\n\
             upstream = \"127.0.0.1:1\"\ntls = \"tailscale\"\n[netcup]\nserver = \"7\"\n",
        )
        .warnings()
        .join("\n");
        assert!(!w.contains("[caddy]"), "{w}");
    }

    #[test]
    fn package_names_follow_debian_charset() {
        // Valid: lowercase start, digits, and +._- allowed.
        host_plus("[packages]\ninstall = [\"curl\", \"g++\", \"libssl1.1\", \"0ad\"]\n")
            .validate()
            .expect("valid package names");
        // Invalid names carry the field in the error.
        for (key, bad) in [
            ("install", "Curl"),
            ("install", "-dash-start"),
            ("install", "pkg name"),
            ("remove", "pkg;rm"),
            ("install", ""),
        ] {
            let c = host_plus(&format!("[packages]\n{key} = [{bad:?}]\n"));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(
                err.to_string().contains(&format!("packages.{key}")),
                "error names the field: {err}"
            );
        }
    }

    #[test]
    fn sshd_allow_users_charset_and_length() {
        host_plus("[sshd]\nallow_users = [\"admin\", \"_svc\", \"a-b_c9\", \"u\"]\n")
            .validate()
            .expect("valid allow_users");
        let too_long = "a".repeat(33);
        for bad in ["-lead", "with space", "a'b", too_long.as_str(), ""] {
            let c = host_plus(&format!("[sshd]\nallow_users = [{bad:?}]\n"));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(err.to_string().contains("sshd.allow_users"), "{err}");
        }
        // Exactly 32 characters is still fine.
        let max = format!("[sshd]\nallow_users = [\"u\", \"{}\"]\n", "a".repeat(32));
        host_plus(&max).validate().expect("32 chars allowed");
    }

    #[test]
    fn username_max_length_is_32() {
        let ok = format!("[users]\ncreate = [{{ name = \"{}\" }}]\n", "a".repeat(32));
        host_plus(&ok).validate().expect("32-char name allowed");
        let bad = format!("[users]\ncreate = [{{ name = \"{}\" }}]\n", "a".repeat(33));
        let err = host_plus(&bad).validate().expect_err("33 chars rejected");
        assert!(err.to_string().contains("users.create"), "{err}");
    }

    #[test]
    fn headscale_server_url_must_be_http_or_https() {
        host_plus("[headscale]\nserver_url = \"https://hs.example.com\"\n")
            .validate()
            .expect("https URL valid");
        for bad in ["", "hs.example.com", "ftp://hs.example.com"] {
            let c = host_plus(&format!("[headscale]\nserver_url = {bad:?}\n"));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(err.to_string().contains("headscale.server_url"), "{err}");
        }
    }

    #[test]
    fn headscale_base_domain_is_validated() {
        let cfg = |extra: &str| {
            host_plus(&format!(
                "[headscale]\nserver_url = \"https://hs.example.com:443/x\"\n{extra}"
            ))
        };
        cfg("").validate().expect("default base_domain");
        cfg("base_domain = \"tailnet.example.com\"\n")
            .validate()
            .expect("sibling name");
        for (bad, needle) in [
            ("example.com", "must not contain"),
            ("Hs.Example.com", "must not contain"),
            ("hs.example.com", "must not contain"),
            ("internal", "headscale.base_domain"),
            ("a b.example", "headscale.base_domain"),
            ("x\\ny.example", "headscale.base_domain"),
        ] {
            let err = cfg(&format!("base_domain = \"{bad}\"\n"))
                .validate()
                .expect_err(bad);
            assert!(err.to_string().contains(needle), "{bad}: {err}");
        }
        assert_eq!(
            url_host("https://u@HS.example.com:8443/p?q"),
            "hs.example.com"
        );
        assert_eq!(url_host("http://h"), "h");
    }

    #[test]
    fn headscale_auth_key_expiration_and_tags_are_validated() {
        let key = |fields: &str| {
            host_plus(&format!(
                "[headscale]\nserver_url = \"https://hs.example.com\"\n\
                 [[headscale.auth_keys]]\nname = \"srv\"\n{fields}"
            ))
            .validate()
        };
        key("").expect("defaults");
        key("expiration = \"1m\"\n").expect("1m is the minimum");
        key("expiration = \"1h30m\"\ntags = [\"tag:server\", \"tag:db-1\"]\nephemeral = true\n")
            .expect("tags + ephemeral");
        for (bad, needle) in [
            ("expiration = \"\"\n", "expiration"),
            ("expiration = \"59s\"\n", "expiration"),
            ("expiration = \"24\"\n", "expiration"),
            ("expiration = \"1x\"\n", "expiration"),
            ("expiration = \"h\"\n", "expiration"),
            ("tags = [\"server\"]\n", "tags"),
            ("tags = [\"tag:Server\"]\n", "tags"),
            ("tags = [\"tag:\"]\n", "tags"),
            ("tags = [\"tag:a,tag:b\"]\n", "tags"),
        ] {
            let err = key(bad).expect_err(bad).to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
    }

    #[test]
    fn headscale_plain_http_is_warned() {
        let warns = |body: &str| host_plus(body).warnings().join("\n");
        let fronted = warns(
            "[headscale]\nserver_url = \"https://hs.example.com\"\nlisten_addr = \"127.0.0.1:8080\"\n",
        );
        assert!(!fronted.contains("headscale"), "{fronted}");
        let w = warns("[headscale]\nserver_url = \"http://hs.example.com\"\n");
        assert!(
            w.contains("headscale.server_url") && w.contains("headscale.listen_addr"),
            "{w}"
        );
    }

    #[test]
    fn headscale_version_must_be_full_semver() {
        host_plus(&format!("[headscale]\nserver_url = \"https://h\"\nversion = \"1.20.3\"\nsha256_amd64 = \"{h}\"\nsha256_arm64 = \"{h}\"\n", h = "a".repeat(64)))
            .validate()
            .expect("full semver valid");
        for bad in ["0.23", "v0.23.0", "0.23.0-rc1", "0..1", "latest"] {
            let c = host_plus(&format!(
                "[headscale]\nserver_url = \"https://h\"\nversion = {bad:?}\n"
            ));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(err.to_string().contains("headscale.version"), "{err}");
        }
    }

    #[test]
    fn auditd_rule_set_must_be_implemented() {
        host_plus("[auditd]\nrule_set = \"cis-level1\"\n")
            .validate()
            .expect("cis-level1 valid");
        let err = host_plus("[auditd]\nrule_set = \"cis-level2\"\n")
            .validate()
            .expect_err("unknown rule set rejected");
        let msg = err.to_string();
        assert!(msg.contains("auditd.rule_set"), "{msg}");
        assert!(msg.contains("expected one of"), "{msg}");
        assert!(msg.contains("cis-level1"), "{msg}");
    }

    #[test]
    fn host_port_defaults_to_22() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
        "#,
        );
        assert_eq!(c.hosts()[0].port, 22);
    }

    #[test]
    fn port_zero_is_rejected() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            port = 0
        "#,
        );
        let err = c.validate().expect_err("port 0 rejected");
        assert!(err.to_string().contains("sshd.port"), "{err}");
    }

    #[test]
    fn reboot_time_boundaries_are_exact() {
        let hhmm = |v: &str| {
            base(&format!(
                "[host]\naddress = \"h\"\nuser = \"u\"\n[updates]\nreboot_time = {v:?}\n"
            ))
            .validate()
        };
        hhmm("00:00").expect("floor valid");
        hhmm("23:59").expect("ceiling valid");
        for bad in [
            "24:00", "23:60", "2:30", "02:3", "ab:cd", "0a:10", "+2:30", "23:+5",
        ] {
            assert!(hhmm(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn docker_listen_addresses_are_validated() {
        // Both land raw in an ExecStart docker `-p` flag.
        let g = |v: &str| validate_body(&format!("[greptimedb]\nlisten_address = {v:?}"));
        g("127.0.0.1").expect("IPv4 valid");
        g("[::1]").expect("bracketed IPv6 valid");
        for bad in [
            "",
            "::1",
            "127.0.0.1:4000",
            "127.0.0.1 -v /:/x",
            "127.0.0.1\nExecStartPre=x",
        ] {
            assert!(g(bad).is_err(), "{bad:?} must be rejected");
        }
        let h = |v: &str| {
            validate_body(&format!(
                "[headscale]\nserver_url = \"https://hs.example\"\nversion = \"0.23.0\"\nheadplane_listen = {v:?}"
            ))
        };
        h("0.0.0.0:3000").expect("IPv4:port valid");
        h("[::1]:3000").expect("[IPv6]:port valid");
        for bad in [
            "0.0.0.0",
            ":3000",
            "0.0.0.0:3000:1",
            "0.0.0.0: 3000",
            "0.0.0.0:3000\nUser=x",
        ] {
            assert!(h(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn duplicate_host_address_and_port_is_rejected() {
        let hosts = |second: &str| {
            base(&format!(
                "[[hosts]]\naddress = \"10.0.0.1\"\nuser = \"u\"\n[[hosts]]\n{second}user = \"u\"\n"
            ))
            .validate()
        };
        let err = hosts("address = \"10.0.0.1\"\n").expect_err("duplicate rejected");
        assert!(err.to_string().contains("duplicates host[0]"), "{err}");
        hosts("address = \"10.0.0.1\"\nport = 2222\n").expect("same address, other port valid");
    }

    #[test]
    fn package_in_both_install_and_remove_is_rejected() {
        let err = validate_body("[packages]\ninstall = [\"curl\", \"ufw\"]\nremove = [\"ufw\"]")
            .expect_err("overlap rejected");
        assert!(err.to_string().contains("\"ufw\""), "{err}");
    }

    #[test]
    fn usernames_are_validated_by_charset_start_and_length() {
        let user = |name: &str| {
            base(&format!(
                "[host]\naddress = \"h\"\nuser = \"u\"\n[users]\ncreate = [{{ name = {name:?} }}]\n"
            ))
            .validate()
        };
        user("deploy-2").expect("letters, digits, dash valid");
        user("_svc").expect("leading underscore valid");
        user(&"a".repeat(32)).expect("32 chars valid");
        for bad in ["", "9abc", "-abc", "ab.c", "ab c", &"a".repeat(33)] {
            assert!(user(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn execution_order_rejects_unknown_module_ids() {
        let eo = |id: &str| {
            base(&format!(
                "[host]\naddress = \"h\"\nuser = \"u\"\n[sshd]\n\
                 [execution_order]\nmodules = [{id:?}]\n"
            ))
            .validate()
        };
        eo("sshd").expect("known id valid");
        eo("plugin::backup").expect("plugin ids pass validation");
        let err = eo("sshdd").expect_err("typo rejected");
        assert!(
            err.to_string().contains("unknown module \"sshdd\""),
            "{err}"
        );
    }

    #[test]
    fn order_override_hints_reject_unknown_module_ids() {
        // `after = ["dnss"]` used to validate and be silently dropped.
        let hint = |key: &str, id: &str| {
            base(&format!(
                "[host]\naddress = \"h\"\nuser = \"u\"\n[sshd]\n\
                 [sshd.order_override]\n{key} = [{id:?}]\n"
            ))
            .validate()
        };
        hint("after", "dns").expect("known id valid");
        hint("before", "plugin::backup").expect("plugin ids pass validation");
        let err = hint("after", "dnss").expect_err("typo rejected");
        assert!(
            err.to_string()
                .contains("sshd.order_override.after references unknown module \"dnss\""),
            "{err}"
        );
        assert!(hint("before", "firewal").is_err());
    }

    #[test]
    fn greptimedb_data_dir_must_survive_the_docker_mount_flag() {
        host_plus("[greptimedb]\ndata_dir = \"/var/lib/greptimedb\"\n")
            .validate()
            .expect("plain absolute path valid");
        for bad in [
            "/srv/data dir",
            "/srv/a:b",
            "relative/path",
            "/srv/tab\there",
        ] {
            let c = host_plus(&format!("[greptimedb]\ndata_dir = {bad:?}\n"));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(err.to_string().contains("greptimedb.data_dir"), "{err}");
        }
    }

    #[test]
    fn greptimedb_reserves_its_compose_project_name() {
        let other = "[greptimedb]\n[containers.compose.web]\ncontent = \"s\"\n";
        host_plus(other).validate().expect("other names are fine");
        let err = host_plus("[greptimedb]\n[containers.compose.greptimedb]\ncontent = \"s\"\n")
            .validate()
            .expect_err("clash");
        assert!(
            err.to_string().contains("reserved for [greptimedb]"),
            "{err}"
        );
    }

    #[test]
    fn beszel_agent_port_is_never_world_open() {
        const K: &str = "key = \"ssh-ed25519 AAAAC3Nza hub\"\n";
        let ok = |body: &str| host_plus(body).validate().expect(body);
        let rejects = |body: &str, needle: &str| {
            let err = host_plus(body).validate().expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        // Outbound WebSocket mode needs no firewall at all.
        ok(&format!(
            "[beszel]\n{K}hub_url = \"https://hub.example\"\ntoken = \"t-1\"\n"
        ));
        // Inbound: scoped to hub addresses, or to the tailnet.
        ok(&format!(
            "[firewall]\n[beszel]\n{K}hub_addresses = [\"10.0.0.0/8\"]\n"
        ));
        ok(&format!("[firewall]\n[tailscale]\n[beszel]\n{K}"));
        rejects(
            &format!("[beszel]\n{K}hub_addresses = [\"10.0.0.1\"]\n"),
            "[firewall]",
        );
        rejects(
            &format!("[firewall]\n[beszel]\n{K}"),
            "hub_addresses is empty",
        );
        rejects(
            &format!("[firewall]\ndefault_incoming = \"allow\"\n[tailscale]\n[beszel]\n{K}"),
            "default_incoming",
        );
        rejects(
            &format!(
                "[beszel]\n{K}hub_url = \"https://h\"\ntoken = \"t\"\nhub_addresses = [\"10.0.0.1\"]\n"
            ),
            "no effect",
        );
        rejects(
            &format!("[firewall]\n[beszel]\n{K}hub_addresses = [\"nope\"]\n"),
            "beszel.hub_addresses",
        );
        rejects(
            &format!("[firewall]\n[tailscale]\n[beszel]\n{K}listen_port = 0\n"),
            "beszel.listen_port",
        );
    }

    #[test]
    fn beszel_pins_and_agent_opt_ins_validate() {
        const B: &str = "[beszel]\nhub_url = \"https://hub.example\"\ntoken = \"t-1\"\nkey = \"ssh-ed25519 AAAAC3Nza hub\"\n";
        let ok = |body: &str| host_plus(body).validate().expect(body);
        let rejects = |body: &str, needle: &str| {
            let err = host_plus(body).validate().expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        // T15: an overridden version needs its tarball hashes.
        rejects(&format!("{B}version = \"0.22.0\"\n"), "beszel.sha256");
        let h = "a".repeat(64);
        ok(&format!(
            "{B}version = \"0.22.0\"\nsha256 = {{ \"beszel-agent_linux_amd64.tar.gz\" = \"{h}\", \"beszel-agent_linux_arm64.tar.gz\" = \"{h}\" }}\n"
        ));
        // T16: opt-ins are agent-only.
        ok(&format!("{B}docker = true\nsmart = true\n"));
        let hub = "[beszel]\nagent = false\nhub = true\n";
        rejects(&format!("{hub}docker = true\n"), "need agent = true");
        rejects(&format!("{hub}smart = true\n"), "need agent = true");
    }

    #[test]
    fn beszel_hub_layouts_validate() {
        const ADMIN: &str =
            "admin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\n";
        let ok = |body: &str| host_plus(body).validate().expect(body);
        let rejects = |body: &str, needle: &str| {
            let err = host_plus(body).validate().expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        // Hub + agent on one machine: everything on loopback, no firewall needed.
        ok("[beszel]\nhub = true\n");
        // Hub only, loopback.
        ok("[beszel]\nhub = true\nagent = false\n");
        // Hub on the network: scoped like the agent port.
        ok("[firewall]\n[tailscale]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\n");
        ok("[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\nhub_allow_from = [\"100.64.0.0/10\", \"100.101.102.103\", \"fd7a:115c:a1e0::/48\"]\n");
        // T19: plain HTTP must not leave the tailnet.
        rejects(
            &format!("[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\n{ADMIN}hub_allow_from = [\"10.0.0.0/8\"]\n"),
            "clear text",
        );
        rejects(
            &format!("[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\n{ADMIN}hub_allow_from = [\"100.64.0.0/9\"]\n"),
            "clear text",
        );
        rejects(
            &format!("[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\n{ADMIN}hub_allow_from = [\"100.64.0.1\", \"203.0.113.5\"]\n"),
            "clear text",
        );
        // A hub bound to its tailnet address only receives tailnet traffic.
        ok(&format!("[firewall]\n[beszel]\nhub = true\nhub_listen = \"100.64.0.1:8090\"\n{ADMIN}hub_allow_from = [\"203.0.113.5\"]\n"));
        rejects(
            "[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\n",
            "[firewall]",
        );
        rejects(
            "[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\n",
            "hub_allow_from is empty",
        );
        rejects(
            "[firewall]\ndefault_incoming = \"allow\"\n[tailscale]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\n",
            "default_incoming",
        );
        rejects(
            "[firewall]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\nadmin_email = \"ops@example.com\"\nadmin_password = \"correct-horse\"\nhub_allow_from = [\"x\"]\n",
            "beszel.hub_allow_from",
        );
        rejects(
            "[beszel]\nhub = true\nhub_listen = \"localhost:8090\"\n",
            "beszel.hub_listen",
        );
        rejects(
            "[beszel]\nhub = true\nhub_listen = \"127.0.0.1:0\"\n",
            "beszel.hub_listen",
        );
        rejects(
            "[beszel]\nhub = true\nhub_listen = \"127.0.0.1:45876\"\n",
            "both use port",
        );
        rejects(
            "[beszel]\nhub = true\nhub_allow_from = [\"10.0.0.1\"]\n",
            "no effect",
        );
        rejects(
            "[beszel]\nhub_allow_from = [\"10.0.0.1\"]\nkey = \"ssh-ed25519 A\"\n",
            "needs hub = true",
        );
        rejects("[beszel]\nagent = false\n", "nothing to manage");
        // T18: a reachable hub must not let its first visitor become admin.
        rejects(
            "[firewall]\n[tailscale]\n[beszel]\nhub = true\nhub_listen = \"0.0.0.0:8090\"\n",
            "beszel.admin_email",
        );
        ok(&format!("[beszel]\nhub = true\n{ADMIN}"));
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"ops@example.com\"\n",
            "go together",
        );
        rejects(
            "[beszel]\nhub = true\nadmin_password = \"correct-horse\"\n",
            "go together",
        );
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"ops\"\nadmin_password = \"correct-horse\"\n",
            "beszel.admin_email",
        );
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"ops@example.com\"\nadmin_password = \"1234567\"\n",
            "at least 8",
        );
        ok("[beszel]\nhub = true\nadmin_email = \"ops@example.com\"\nadmin_password = \"12345678\"\n");
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"@example.com\"\nadmin_password = \"correct-horse\"\n",
            "beszel.admin_email",
        );
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"ops@example.com\"\nadmin_password = \"a\\\"bcdefghi\"\n",
            "beszel.admin_password",
        );
        rejects(
            "[beszel]\nhub = true\nadmin_email = \"o$s@example.com\"\nadmin_password = \"correct-horse\"\n",
            "beszel.admin_email",
        );
        rejects(
            &format!("[firewall]\n[tailscale]\n[beszel]\nkey = \"ssh-ed25519 AAAA\"\n{ADMIN}"),
            "need hub = true",
        );
        // Remote-hub settings make no sense when the hub is local.
        rejects(
            "[beszel]\nhub = true\nkey = \"ssh-ed25519 AAAA\"\n",
            "wired to the local hub",
        );
        rejects(
            "[beszel]\nhub = true\nagent = false\ntoken = \"t\"\n",
            "wired to the local hub",
        );
    }

    #[test]
    fn tailnet_ranges_are_exact() {
        for yes in [
            "100.64.0.0/10",
            "100.127.255.255",
            "100.100.0.0/16",
            "fd7a:115c:a1e0::1",
            "fd7a:115c:a1e0::/48",
        ] {
            assert!(in_tailnet(yes), "{yes}");
        }
        for no in [
            "100.64.0.0/9",
            "100.128.0.1",
            "100.63.255.255",
            "10.0.0.1",
            "fd7a:115c:a1e0::/47",
            "fd7a:115c:a1e1::1",
            "2001:db8::1",
            "x",
        ] {
            assert!(!in_tailnet(no), "{no}");
        }
    }

    #[test]
    fn beszel_values_are_validated() {
        let rejects = |body: &str, needle: &str| {
            let full = format!("[firewall]\n[tailscale]\n[beszel]\n{body}");
            let err = host_plus(&full).validate().expect_err(body).to_string();
            assert!(err.contains(needle), "{body}: {err}");
        };
        rejects("", "beszel.key");
        rejects("key = \"ssh-ed25519\"\n", "beszel.key");
        rejects("key = \"rsa AAAA\"\n", "beszel.key");
        rejects("key = \"ssh-ed25519 AA\\\"AA\"\n", "beszel.key");
        rejects("key = \"ssh-ed25519 AA$AA\"\n", "beszel.key");
        const K: &str = "key = \"ssh-ed25519 AAAA\"\n";
        rejects(&format!("{K}version = \"latest\"\n"), "beszel.version");
        rejects(&format!("{K}hub_url = \"https://h\"\n"), "beszel.token");
        rejects(&format!("{K}token = \"t\"\n"), "beszel.hub_url");
        rejects(
            &format!("{K}hub_url = \"ftp://h\"\ntoken = \"t\"\n"),
            "beszel.hub_url",
        );
        rejects(
            &format!("{K}hub_url = \"https://h x\"\ntoken = \"t\"\n"),
            "beszel.hub_url",
        );
        rejects(
            &format!("{K}hub_url = \"https://h\"\ntoken = \"a b\"\n"),
            "beszel.token",
        );
        rejects(
            &format!("{K}hub_url = \"https://h\"\ntoken = \"a`b\"\n"),
            "beszel.token",
        );
        // ecdsa keys are accepted too.
        host_plus("[firewall]\n[tailscale]\n[beszel]\nkey = \"ecdsa-sha2-nistp256 AAAA\"\n")
            .validate()
            .unwrap();
    }

    #[test]
    fn greptimedb_retention_is_hours_days_or_weeks_on_v0_12_plus() {
        for ok in ["30d", "12h", "2w"] {
            validate_greptimedb_retention(ok, "v0.12.0").unwrap();
        }
        validate_greptimedb_retention("30d", "v1.0.0").unwrap();
        for bad in ["30", "d", "0d", "030d", "30m", "1y", "30d'", "-1d", "30 d"] {
            assert!(
                validate_greptimedb_retention(bad, "v0.12.0").is_err(),
                "{bad}"
            );
        }
        let old = validate_greptimedb_retention("30d", "v0.11.9").unwrap_err();
        assert!(old.to_string().contains("v0.12 or newer"), "{old}");
    }

    #[test]
    fn vector_cgroups_include_is_relative_to_the_cgroup_root() {
        host_plus("[vector]\ncgroups_include = [\"system.slice/*.service\"]\n")
            .validate()
            .unwrap();
        for bad in ["\"/system.slice\"", "\"\""] {
            let e = host_plus(&format!("[vector]\ncgroups_include = [{bad}]\n"))
                .validate()
                .unwrap_err();
            assert!(e.to_string().contains("vector.cgroups_include"), "{e}");
        }
    }

    #[test]
    fn vector_cgroups_include_rejects_the_pre_rename_ci_slice() {
        // An old `init --full` config names the old slice explicitly;
        // accepting it would leave every ci.slice panel silently empty.
        host_plus("[vector]\ncgroups_include = [\"ci.slice/**\"]\n")
            .validate()
            .unwrap();
        for bad in [
            "\"anvil.slice/**\"",
            "\"anvil.slice\"",
            "\"anvil.slice/anvil-ci.slice\"",
        ] {
            let e = host_plus(&format!("[vector]\ncgroups_include = [{bad}]\n"))
                .validate()
                .unwrap_err();
            assert!(e.to_string().contains("vector.cgroups_include"), "{e}");
            assert!(e.to_string().contains("use \"ci.slice/**\" instead"), "{e}");
        }
    }

    #[test]
    fn greptimedb_memory_max_is_a_size_with_a_unit() {
        for ok in ["2G", "512M", "1T", "900K"] {
            validate_greptimedb_memory_max(ok).unwrap();
        }
        for bad in ["2", "G", "0G", "02G", "50%", "2g", "2GB", "-1G", "2G\n"] {
            assert!(validate_greptimedb_memory_max(bad).is_err(), "{bad:?}");
        }
        let e = host_plus("[greptimedb]\nmemory_max = \"2 G\"\n")
            .validate()
            .unwrap_err();
        assert!(e.to_string().contains("greptimedb.memory_max"), "{e}");
    }

    #[test]
    fn greptimedb_version_must_be_a_pinned_v_tag() {
        // A pinned vMAJOR.MINOR.PATCH tag (and the default) is valid.
        host_plus("[greptimedb]\nversion = \"v0.9.5\"\n")
            .validate()
            .expect("pinned v-tag valid");
        host_plus("[greptimedb]\n")
            .validate()
            .expect("default version is pinned");
        // `latest`, missing `v`, and partial versions are rejected — a floating
        // or typo'd tag breaks the reproducible-state guarantee.
        for bad in ["latest", "0.9.5", "v0.9", "v1.2.3.4", "vX.Y.Z"] {
            let c = host_plus(&format!("[greptimedb]\nversion = {bad:?}\n"));
            let err = c.validate().expect_err(&format!("{bad:?} must fail"));
            assert!(err.to_string().contains("greptimedb.version"), "{err}");
        }
    }

    #[test]
    fn effective_port_follows_sshd() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            port = 2222
        "#,
        );
        assert_eq!(c.effective_ssh_port(), 2222);
    }

    #[test]
    fn effective_port_falls_back_to_host_port_without_sshd() {
        // With no [sshd] section the box is already serving on the host's
        // live port. The firewall must open that port, not 22, or it fences the
        // operator out.
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            port = 2222
            [firewall]
        "#,
        );
        assert_eq!(c.effective_ssh_port(), 2222);
        // Two hosts sharing one port resolve to it too.
        let c = base(
            r#"
            [[hosts]]
            address = "a"
            user = "u"
            port = 2222
            [[hosts]]
            address = "b"
            user = "u"
            port = 2222
            [firewall]
        "#,
        );
        assert_eq!(c.effective_ssh_port(), 2222);
    }

    #[test]
    fn login_user_refused_by_sshd_is_rejected() {
        // root under the default disable_root_login, no escape account.
        let err = base(
            r#"
            [host]
            address = "a"
            user = "root"
            [sshd]
        "#,
        )
        .validate()
        .expect_err("root login refused");
        assert!(err.to_string().contains("\"root\""), "{err}");
        // A login user missing from allow_users.
        let err = base(
            r#"
            [host]
            address = "a"
            user = "deploy"
            [sshd]
            allow_users = ["admin"]
        "#,
        )
        .validate()
        .expect_err("deploy not in allow_users");
        assert!(err.to_string().contains("allow_users"), "{err}");
        // An escape account that is itself refused does not count.
        let err = base(
            r#"
            [host]
            address = "a"
            user = "deploy"
            [sshd]
            allow_users = ["admin"]
            [users]
            create = [{ name = "ops", sudo = true, ssh_authorized_keys = ["ssh-ed25519 AAAA"] }]
        "#,
        )
        .validate();
        assert!(err.is_err(), "ops is not in allow_users");
    }

    #[test]
    fn login_user_refused_but_admin_created_in_same_run_is_accepted() {
        base(
            r#"
            [host]
            address = "a"
            user = "root"
            [sshd]
            allow_users = ["admin"]
            [users]
            create = [{ name = "admin", sudo = true, ssh_authorized_keys = ["ssh-ed25519 AAAA"] }]
        "#,
        )
        .validate()
        .expect("admin with sudo + keys is the way back in");
    }

    #[test]
    fn ambiguous_host_ports_with_firewall_and_no_sshd_is_rejected() {
        // When [sshd] is absent and the hosts disagree on a port, no
        // single value the firewall allows is safe — must fail at validate.
        let c = base(
            r#"
            [[hosts]]
            address = "a"
            user = "u"
            port = 22
            [[hosts]]
            address = "b"
            user = "u"
            port = 2222
            [firewall]
        "#,
        );
        let err = c.validate().expect_err("ambiguous ports rejected");
        assert!(err.to_string().contains("ambiguous"), "{err}");
        assert!(err.to_string().contains("sshd"), "{err}");
        // The netcup SCP firewall infers the port the same way (T12).
        let fleet = "[[hosts]]\naddress = \"a\"\nuser = \"u\"\n\
                     [[hosts]]\naddress = \"b\"\nuser = \"u\"\nport = 2222\n";
        let nc = base(&format!("{fleet}[netcup]\nserver = \"7\"\n"));
        assert!(nc.validate().unwrap_err().to_string().contains("ambiguous"));
        // Same fleet is fine once a port source is unambiguous.
        let ok = base(
            r#"
            [[hosts]]
            address = "a"
            user = "u"
            port = 2222
            [firewall]
        "#,
        );
        ok.validate().expect("single host port inferred");
        // And fine if [sshd] pins the port (host ports then don't matter).
        let ok = base(
            r#"
            [sshd]
            port = 22
            [[hosts]]
            address = "a"
            user = "u"
            port = 2222
            [[hosts]]
            address = "b"
            user = "u"
            port = 22
            [firewall]
        "#,
        );
        ok.validate().expect("sshd present disambiguates");
    }

    #[test]
    fn order_override_parses_nested() {
        let c = base(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            [sshd.order_override]
            before = ["firewall"]
            after = ["users"]
        "#,
        );
        let s = &c.sshd.unwrap().order_override;
        assert_eq!(s.before, vec!["firewall".to_string()]);
        assert_eq!(s.after, vec!["users".to_string()]);
    }

    const CADDY: &str =
        "[caddy]\n[[caddy.site]]\ndomain = \"a.example.com\"\nupstream = \"127.0.0.1:3000\"\n";

    /// A validated config's provider-firewall warnings, joined.
    fn fw_warns(body: &str) -> String {
        let c = host_plus(body);
        c.validate().expect(body);
        c.provider_firewall_warnings(
            "hetzner",
            &c.hetzner.as_ref().map_or(vec![], |h| h.rules.clone()),
        )
        .join("\n")
    }

    fn hetzner(rules: &str) -> String {
        format!("[hetzner]\nserver_name = \"x\"\nrules = [{rules}]\n")
    }

    #[test]
    fn caddy_without_hetzner_80_443_is_warned() {
        let w = host_plus(&format!("{CADDY}{}", hetzner("")))
            .warnings()
            .join("\n");
        assert!(
            w.contains("hetzner: [caddy] is enabled but no rule allows 443/tcp — the site and ACME will be unreachable")
                && w.contains("no rule allows 80/tcp — ACME HTTP-01"),
            "{w}"
        );
        // No [hetzner]: no provider warning at all.
        assert!(!host_plus(CADDY).warnings().join("\n").contains("hetzner"));
    }

    #[test]
    fn caddy_rules_count_ranges_sources_and_custom_ports() {
        let tcp =
            |port: &str| format!("{{ direction = \"in\", protocol = \"tcp\", port = \"{port}\" }}");
        let w = fw_warns(&format!("{CADDY}{}", hetzner(&tcp("443"))));
        assert!(w.contains("80/tcp") && !w.contains("443/tcp"), "{w}");
        assert_eq!(fw_warns(&format!("{CADDY}{}", hetzner(&tcp("80-443")))), "");
        // 443/udp is optional and does not stand in for tcp.
        let udp = "{ direction = \"in\", protocol = \"udp\", port = \"443\" }";
        assert!(fw_warns(&format!(
            "{CADDY}{}",
            hetzner(&format!("{}, {udp}", tcp("80")))
        ))
        .contains("443/tcp"));
        // Outbound and above-range rules open nothing.
        let out = "{ direction = \"out\", protocol = \"tcp\", port = \"80-443\" }";
        assert_eq!(
            fw_warns(&format!("{CADDY}{}", hetzner(out)))
                .lines()
                .count(),
            2
        );
        assert_eq!(
            fw_warns(&format!("{CADDY}{}", hetzner(&tcp("81-442"))))
                .lines()
                .count(),
            2
        );
        // A source-scoped rule is the operator's choice: no warning.
        let scoped = "{ direction = \"in\", protocol = \"tcp\", port = \"80-443\", source_ips = [\"203.0.113.0/24\"] }";
        assert_eq!(fw_warns(&format!("{CADDY}{}", hetzner(scoped))), "");
        // Custom caddy ports are what must be open.
        let w = fw_warns(&format!(
            "[caddy]\nhttp_port = 8080\nhttps_port = 8443\n{}{}",
            &CADDY[8..],
            hetzner(&tcp("80-443"))
        ));
        assert!(w.contains("8080/tcp") && w.contains("8443/tcp"), "{w}");
        // Hetzner alone warns about nothing.
        assert_eq!(fw_warns(&hetzner("")), "");
    }

    const AGENT: &str = "[firewall]\n[beszel]\nkey = \"ssh-ed25519 AAAAkey\"\n";

    #[test]
    fn beszel_public_hub_addresses_need_a_hetzner_rule() {
        let agent = |addrs: &str, rules: &str| {
            fw_warns(&format!(
                "{AGENT}hub_addresses = [{addrs}]\n{}",
                hetzner(rules)
            ))
        };
        let w = agent(
            "\"203.0.113.7\", \"10.0.0.5\", \"100.100.1.1\", \"fd7a:115c:a1e0::1\"",
            "",
        );
        assert_eq!(
            w,
            "hetzner: beszel.hub_addresses has public 203.0.113.7 but no rule allows it on 45876/tcp — the hub cannot reach this agent"
        );
        let rule = |port: &str, src: &str| {
            format!("{{ direction = \"in\", protocol = \"tcp\", port = \"{port}\", source_ips = [{src}] }}")
        };
        assert_eq!(
            agent("\"203.0.113.7\"", &rule("45876", "\"203.0.113.0/24\"")),
            ""
        );
        assert_eq!(
            agent("\"203.0.113.7\"", &rule("45000-46000", "\"0.0.0.0/0\"")),
            ""
        );
        assert_eq!(
            agent(
                "\"203.0.113.7\"",
                "{ direction = \"in\", protocol = \"tcp\", port = \"45876\" }"
            ),
            ""
        );
        // Wrong source, wrong port, or a v6-only source: still shut.
        assert!(!agent("\"203.0.113.7\"", &rule("45876", "\"198.51.100.0/24\"")).is_empty());
        assert!(!agent("\"203.0.113.7\"", &rule("45877", "\"203.0.113.7\"")).is_empty());
        assert!(!agent("\"203.0.113.7\"", &rule("45876", "\"::/0\"")).is_empty());
        // A wider address than the rule's source is not covered.
        assert!(!agent("\"203.0.113.0/23\"", &rule("45876", "\"203.0.113.0/24\"")).is_empty());
        // Without [hetzner] nothing is said.
        let c = host_plus(&format!("{AGENT}hub_addresses = [\"203.0.113.7\"]\n"));
        c.validate().expect("valid");
        assert!(c.warnings().is_empty(), "{:?}", c.warnings());
    }

    #[test]
    fn beszel_addresses_that_open_nothing_are_not_warned() {
        // Outbound agent: hub_addresses is rejected, nothing listens.
        let out = format!(
            "{AGENT}hub_url = \"https://hub\"\ntoken = \"t\"\n{}",
            hetzner("")
        );
        assert_eq!(fw_warns(&out), "");
        // Hub on loopback with a local agent.
        assert_eq!(
            fw_warns(&format!("[beszel]\nhub = true\n{}", hetzner(""))),
            ""
        );
    }

    #[test]
    fn public_means_outside_private_tailnet_and_local_ranges() {
        for a in [
            "10.1.2.3",
            "172.16.0.0/12",
            "172.31.255.255",
            "192.168.1.0/24",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.0/10",
            "100.127.255.255",
            "::1",
            "fe80::1",
            "fd00::/8",
            "fd7a:115c:a1e0::/48",
        ] {
            assert!(!is_public(a), "{a}");
        }
        for a in [
            "203.0.113.7",
            "172.32.0.1",
            "100.128.0.1",
            "100.63.255.255",
            "0.0.0.0/0",
            "10.0.0.0/7",
            "fc00::1",
            "2001:db8::1",
            "::/0",
            "not-an-ip",
        ] {
            assert!(is_public(a), "{a}");
        }
    }

    #[test]
    fn cidr_within_boundaries() {
        assert!(cidr_within("1.2.3.4", "0.0.0.0/0"));
        assert!(cidr_within("2001:db8::1", "::/0"));
        assert!(cidr_within("10.0.0.0/24", "10.0.0.0/24"));
        assert!(!cidr_within("10.0.1.0/24", "10.0.0.0/24"));
        assert!(!cidr_within("10.0.0.0/23", "10.0.0.0/24"));
        assert!(!cidr_within("1.2.3.4", "::/0"));
        assert!(!cidr_within("::1", "0.0.0.0/0"));
        assert!(!cidr_within("1.2.3.4/33", "0.0.0.0/0"));
        assert!(!cidr_within("1.2.3.4", "0.0.0.0/x"));
    }
}
