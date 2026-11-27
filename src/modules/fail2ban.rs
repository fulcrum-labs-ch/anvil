//! The `fail2ban` module (R65): installs `fail2ban`, ensures the service is
//! running, and writes a jail drop-in with the global ban policy, an automatic
//! `[sshd]` jail on the effective SSH port, and each configured jail. The
//! config is then validated (`fail2ban-client -t`, version-gated to
//! fail2ban 0.11+) and the service reloaded — reverting the drop-in if
//! validation fails (via the engine's [`ReloadGuard`]).

use crate::config::schema::{Fail2banSection, JailDef};
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};

use super::{apt_install, Module};

/// Jail drop-in this module owns (Fixed Contract for drift/rollback).
pub const JAIL_FILE: &str = "/etc/fail2ban/jail.d/99-anvil.conf";

/// Filter for the automatic `forgejo` jail. `anvil-` prefixed: filter.d is not
/// a drop-in directory, so a future distro `forgejo.conf` must not collide.
pub const FORGEJO_FILTER: &str = "/etc/fail2ban/filter.d/anvil-forgejo.conf";

/// Forgejo 15's web-login failure (`routers/web/auth/auth.go`, `SignInPost`):
/// `Failed authentication attempt for <user> from <ip>:<port>: <err>`. Behind
/// the proxy the port is 0 and IPv6 is bracketed (`[fd7a::1]:0`).
pub const FORGEJO_FAILREGEX: &str =
    r"^.*Failed authentication attempt for .+ from \[?<ADDR>\]?:\d+:";

pub struct Fail2banModule {
    cfg: Fail2banSection,
    /// The effective SSH port from the whole config (sshd's `port` when that
    /// module is enabled, else 22). The automatic `[sshd]` jail watches this
    /// port so a relocated SSH daemon is still protected.
    ssh_port: u16,
    /// Never ban tailnet addresses (set when `[tailscale]` is enabled): after a
    /// tailnet-only cutover every SSH client is a tailnet IP, and a few typos
    /// would ban the operator's only way in.
    exempt_tailnet: bool,
    /// Ports of the automatic `forgejo` jail (set when `[forgejo]` is enabled).
    forgejo_ports: Option<String>,
}

impl Fail2banModule {
    pub fn new(cfg: Fail2banSection, ssh_port: u16) -> Self {
        Self {
            cfg,
            ssh_port,
            exempt_tailnet: false,
            forgejo_ports: None,
        }
    }

    /// Add the automatic `forgejo` jail on Forgejo's HTTPS front and, unless
    /// 0, its built-in SSH port.
    pub fn forgejo(mut self, https_port: u16, ssh_port: u16) -> Self {
        self.forgejo_ports = Some(match ssh_port {
            0 => https_port.to_string(),
            p => format!("{https_port},{p}"),
        });
        self
    }

    pub fn exempt_tailnet(mut self, on: bool) -> Self {
        self.exempt_tailnet = on;
        self
    }

    /// The effective SSH port fail2ban's sshd jail should watch.
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /// Render the desired jail config. The `[DEFAULT]` keys and each jail's keys
    /// are the hardening contract (R65); the formatting is ours. This content is
    /// base64-embedded by the engine, so config values are safe here without
    /// shell-escaping.
    ///
    /// A bare `[fail2ban]` section must still ban something: an `[sshd]` jail is
    /// always emitted, watching the effective SSH port. An operator-declared
    /// `sshd` jail wins wholesale, except that an omitted `port` is filled in
    /// with the effective SSH port so the jail never silently watches 22 while
    /// sshd listens elsewhere.
    pub fn jail_config(&self) -> String {
        let c = &self.cfg;
        let mut jails = c.jails.clone();
        let sshd = jails.entry("sshd".to_string()).or_insert(JailDef {
            enabled: Some(true),
            port: None,
            maxretry: None,
            bantime: None,
        });
        if sshd.port.is_none() {
            sshd.port = Some(self.ssh_port.to_string());
        }
        if let Some(ports) = &self.forgejo_ports {
            let fj = jails.entry("forgejo".to_string()).or_insert(JailDef {
                enabled: Some(true),
                port: None,
                maxretry: None,
                bantime: None,
            });
            fj.port.get_or_insert_with(|| ports.clone());
        }
        let mut s = String::from("# Managed by anvil — do not edit by hand\n");
        s.push_str("[DEFAULT]\n");
        s.push_str(&format!("bantime = {}\n", c.bantime));
        s.push_str(&format!("findtime = {}\n", c.findtime));
        s.push_str(&format!("maxretry = {}\n", c.maxretry));
        if self.exempt_tailnet {
            // Setting ignoreip replaces fail2ban's default, so keep loopback.
            s.push_str(&format!(
                "ignoreip = 127.0.0.1/8 ::1 {}\n",
                super::tailscale::TAILNET_CIDRS.join(" ")
            ));
        }
        // BTreeMap iterates in sorted key order, so the file is deterministic
        // (stable drift/diff).
        for (name, jail) in &jails {
            s.push('\n');
            s.push_str(&format!("[{name}]\n"));
            // A jail listed in config is enabled unless it explicitly opts out.
            s.push_str(&format!("enabled = {}\n", jail.enabled.unwrap_or(true)));
            if let Some(port) = &jail.port {
                s.push_str(&format!("port = {port}\n"));
            }
            if let Some(maxretry) = jail.maxretry {
                s.push_str(&format!("maxretry = {maxretry}\n"));
            }
            if let Some(bantime) = &jail.bantime {
                s.push_str(&format!("bantime = {bantime}\n"));
            }
            if name == "forgejo" && self.forgejo_ports.is_some() {
                // Always ours, even under an operator override. ignoreip
                // drops [DEFAULT]'s tailnet exemption: behind a tailnet-only
                // Caddy every client is a tailnet IP. Loopback stays exempt.
                s.push_str(&format!(
                    "filter = anvil-forgejo\n\
                     logpath = {}\n\
                     ignoreip = 127.0.0.1/8 ::1\n",
                    super::forgejo::LOG_FILE
                ));
            }
        }
        s
    }

    /// The `forgejo` filter. The username is attacker-controlled and Forgejo
    /// does not escape newlines in logs, so a crafted name can forge a line;
    /// loopback `ignoreip` bounds what such a line can ban.
    pub fn forgejo_filter() -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Definition]\n\
             failregex = {FORGEJO_FAILREGEX}\n\
             ignoreregex =\n"
        )
    }
}

/// Ensure `fail2ban` is installed before its config file is written.
fn ensure_fail2ban() -> ManagedCommand {
    ManagedCommand::new(
        "ensure fail2ban installed",
        "command -v fail2ban-client >/dev/null 2>&1",
        // Refresh lists first: a fresh minimal image may have stale/absent
        // lists and the install would fail outright (mirrors packages.rs). The
        // dpkg lock-wait (R109) tolerates a transient lock on a fresh box.
        apt_install(&["fail2ban"]),
    )
}

/// Ensure the fail2ban service is actually running. An up-to-date jail file in
/// front of a dead daemon bans nobody, so the probe must treat a stopped
/// service as drift and the apply must enable + start it.
fn ensure_fail2ban_active() -> ManagedCommand {
    ManagedCommand::new(
        "ensure fail2ban service active",
        "systemctl is-active --quiet fail2ban",
        "systemctl enable --now fail2ban",
    )
}

/// Validation expression for the [`ReloadGuard`]. `fail2ban-client -t` only
/// exists in fail2ban >= 0.11 (Debian 10 / Ubuntu 18.04 ship 0.10.x), so the
/// dry-run test is version-gated: on older versions validation is treated as
/// passed and the guarded reload still runs. The expression reads as "unless
/// the installed version is >= 0.11, pass; otherwise the config test decides".
/// `${Version}` is dpkg-query's format placeholder, single-quoted so the shell
/// never expands it; no config-derived values appear here.
const VALIDATE_JAILS: &str = "! dpkg --compare-versions \
     \"$(dpkg-query -W -f='${Version}' fail2ban 2>/dev/null || echo 0)\" \
     ge 0.11 || fail2ban-client -t";

impl Module for Fail2banModule {
    fn id(&self) -> &'static str {
        "fail2ban"
    }

    fn declaration(&self) -> Declaration {
        // Validate the whole config after the drop-in is written; only then
        // enable + reload. On validation failure the engine restores the prior
        // drop-in and does not reload.
        let guard = ReloadGuard {
            describe: "fail2ban jails".into(),
            validate: VALIDATE_JAILS.into(),
            reload: "systemctl enable fail2ban >/dev/null 2>&1 || true; \
                     systemctl reload fail2ban 2>/dev/null \
                     || fail2ban-client reload 2>/dev/null \
                     || systemctl restart fail2ban"
                .into(),
        };
        let mut d = Declaration::new("fail2ban")
            .command(ensure_fail2ban())
            .command(ensure_fail2ban_active());
        // The filter is written before the jail that names it.
        if self.forgejo_ports.is_some() {
            d = d.file(ManagedFile::new(
                FORGEJO_FILTER,
                Self::forgejo_filter(),
                "0644",
                "root:root",
            ));
        }
        d.file(ManagedFile::new(
            JAIL_FILE,
            self.jail_config(),
            "0644",
            "root:root",
        ))
        .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_dropin_keeps_the_high_prefix_and_path() {
        // jail.d is last-match-wins: keep the HIGH 99-anvil prefix so we sort
        // after numeric distro drop-ins, and never rename the path — drift,
        // diff, and rollback key on it.
        let name = JAIL_FILE.rsplit('/').next().expect("basename");
        assert!(JAIL_FILE.starts_with("/etc/fail2ban/jail.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }
    use crate::config::schema::JailDef;
    use std::collections::BTreeMap;

    fn section() -> Fail2banSection {
        let mut jails = BTreeMap::new();
        jails.insert(
            "sshd".to_string(),
            JailDef {
                enabled: None,
                port: Some("ssh".into()),
                maxretry: Some(3),
                bantime: Some("1h".into()),
            },
        );
        Fail2banSection {
            bantime: "15m".into(),
            findtime: "10m".into(),
            maxretry: 5,
            jails,
            order_override: Default::default(),
        }
    }

    #[test]
    fn jail_config_has_global_policy() {
        let content = Fail2banModule::new(section(), 22).jail_config();
        assert!(content.contains("[DEFAULT]"));
        assert!(content.contains("bantime = 15m"));
        assert!(content.contains("findtime = 10m"));
        assert!(content.contains("maxretry = 5"));
    }

    #[test]
    fn configured_jail_is_rendered() {
        let content = Fail2banModule::new(section(), 22).jail_config();
        assert!(content.contains("[sshd]"));
        // enabled defaults to true when unset.
        assert!(content.contains("enabled = true"));
        assert!(content.contains("port = ssh"));
        assert!(content.contains("maxretry = 3"));
        assert!(content.contains("bantime = 1h"));
    }

    #[test]
    fn default_section_emits_automatic_sshd_jail_on_effective_port() {
        // A bare [fail2ban] with no declared jails must still protect SSH —
        // and on the *effective* port, not a hardcoded 22.
        let mut sec = section();
        sec.jails.clear();
        let content = Fail2banModule::new(sec, 2222).jail_config();
        assert!(content.contains("[sshd]\nenabled = true\nport = 2222\n"));
    }

    #[test]
    fn operator_sshd_jail_overrides_automatic_one() {
        // section() declares sshd with port = "ssh"; the operator's values win
        // over the automatic jail and the effective port is not injected.
        let content = Fail2banModule::new(section(), 2222).jail_config();
        assert_eq!(
            content.matches("[sshd]").count(),
            1,
            "exactly one sshd jail"
        );
        assert!(content.contains("port = ssh"));
        assert!(!content.contains("port = 2222"));
        assert!(content.contains("maxretry = 3"));
        assert!(content.contains("bantime = 1h"));
    }

    #[test]
    fn operator_sshd_jail_without_port_gets_effective_port() {
        let mut sec = section();
        sec.jails.insert(
            "sshd".to_string(),
            JailDef {
                enabled: None,
                port: None,
                maxretry: Some(4),
                bantime: None,
            },
        );
        let content = Fail2banModule::new(sec, 2222).jail_config();
        // Operator keys survive; only the missing port is filled in.
        assert!(content.contains("[sshd]\nenabled = true\nport = 2222\nmaxretry = 4\n"));
    }

    #[test]
    fn jail_can_be_explicitly_disabled() {
        let mut sec = section();
        sec.jails.insert(
            "nginx".to_string(),
            JailDef {
                enabled: Some(false),
                port: None,
                maxretry: None,
                bantime: None,
            },
        );
        let content = Fail2banModule::new(sec, 22).jail_config();
        assert!(content.contains("[nginx]\nenabled = false\n"));
    }

    #[test]
    fn installs_and_validates_before_reload() {
        let apply = Fail2banModule::new(section(), 22)
            .declaration()
            .render_apply();
        // Refresh package lists before installing — a fresh minimal image may
        // have stale/absent lists and the install would fail outright.
        let update = apply.find("update -qq").expect("apt-get update present");
        let install = apply
            .find("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'fail2ban'")
            .expect("install present");
        assert!(
            update < install,
            "must refresh lists before installing:\n{apply}"
        );
        assert!(apply.contains(JAIL_FILE));
        assert!(apply.contains("fail2ban-client -t"));
        // On validation failure the guard reverts and never reloads.
        assert!(apply.contains("exit 1"));
    }

    #[test]
    fn probe_and_apply_reference_same_file() {
        let decl = Fail2banModule::new(section(), 22).declaration();
        assert!(decl.render_probe().contains(JAIL_FILE));
        assert!(decl.render_apply().contains(JAIL_FILE));
    }

    #[test]
    fn effective_ssh_port_is_stored() {
        let m = Fail2banModule::new(section(), 2222);
        assert_eq!(m.ssh_port(), 2222);
    }

    #[test]
    fn validation_is_version_gated_for_old_fail2ban() {
        // `fail2ban-client -t` first shipped in 0.11; Debian 10 / Ubuntu 18.04
        // carry 0.10.x, where an unconditional -t would fail every apply and
        // revert a perfectly good config. The validate expression must gate -t
        // behind a version check and pass outright on older versions.
        let apply = Fail2banModule::new(section(), 22)
            .declaration()
            .render_apply();
        let gate = apply
            .find("dpkg --compare-versions")
            .expect("version gate present");
        assert!(apply.contains("ge 0.11"));
        let test_cmd = apply.find("fail2ban-client -t").expect("-t present");
        assert!(
            gate < test_cmd,
            "-t must be reached only through the version gate"
        );
        // Older-version fallthrough: the gate short-circuits to success, so the
        // guarded reload still runs.
        assert!(apply.contains("|| fail2ban-client -t"));
    }

    #[test]
    fn dead_service_is_drift_and_apply_starts_it() {
        // A current jail file in front of a stopped daemon bans nothing: the
        // probe must flag it and the apply must enable + start the service.
        let decl = Fail2banModule::new(section(), 22).declaration();
        assert!(decl
            .render_probe()
            .contains("systemctl is-active --quiet fail2ban"));
        let apply = decl.render_apply();
        assert!(apply.contains("systemctl is-active --quiet fail2ban"));
        assert!(apply.contains("systemctl enable --now fail2ban"));
    }

    #[test]
    fn forgejo_jail_reads_its_log_with_our_filter_and_bans_tailnet_too() {
        let c = Fail2banModule::new(section(), 22)
            .exempt_tailnet(true)
            .forgejo(443, 2222)
            .jail_config();
        assert!(
            c.contains(
                "[forgejo]\nenabled = true\nport = 443,2222\nfilter = anvil-forgejo\n\
                 logpath = /var/lib/forgejo/log/forgejo.log\nignoreip = 127.0.0.1/8 ::1\n"
            ),
            "{c}"
        );
        let no_ssh = Fail2banModule::new(section(), 22)
            .forgejo(8443, 0)
            .jail_config();
        assert!(
            no_ssh.contains("[forgejo]\nenabled = true\nport = 8443\n"),
            "{no_ssh}"
        );
        assert!(!Fail2banModule::new(section(), 22)
            .jail_config()
            .contains("[forgejo]"));
        // Only the forgejo jail gets our filter, and only with [forgejo].
        assert_eq!(c.matches("filter = ").count(), 1, "{c}");
        let mut sec = section();
        sec.jails.insert(
            "forgejo".into(),
            JailDef {
                enabled: None,
                port: None,
                maxretry: None,
                bantime: None,
            },
        );
        let bare = Fail2banModule::new(sec, 22).jail_config();
        assert!(!bare.contains("filter = "), "{bare}");
    }

    #[test]
    fn operator_forgejo_jail_overrides_but_keeps_filter_and_log() {
        let mut sec = section();
        sec.jails.insert(
            "forgejo".into(),
            JailDef {
                enabled: Some(false),
                port: None,
                maxretry: Some(3),
                bantime: None,
            },
        );
        let c = Fail2banModule::new(sec, 22)
            .forgejo(443, 2222)
            .jail_config();
        assert!(
            c.contains("[forgejo]\nenabled = false\nport = 443,2222\nmaxretry = 3\nfilter = anvil-forgejo\n"),
            "{c}"
        );
    }

    #[test]
    fn forgejo_filter_matches_real_failed_login_lines() {
        // Forgejo v15.0.11 SignInPost lines as written by the file logger
        // (stdflags), behind the proxy (port 0). No fail2ban-regex here: check
        // the regex's literal anchors and that the address sits where <ADDR> is.
        let f = Fail2banModule::forgejo_filter();
        assert!(f.contains(&format!("[Definition]\nfailregex = {FORGEJO_FAILREGEX}\n")));
        let (pre, post) = FORGEJO_FAILREGEX
            .split_once(r"\[?<ADDR>\]?")
            .expect("<ADDR> placeholder");
        assert_eq!(pre, r"^.*Failed authentication attempt for .+ from ");
        assert_eq!(post, r":\d+:");
        for (line, ip) in [
            ("2026/11/03 10:15:02 .../web/auth/auth.go:220:SignInPost() [W] Failed authentication attempt for bob from 100.101.102.103:0: user does not exist [uid: 0, name: bob]", "100.101.102.103"),
            ("2026/11/03 10:15:09 .../web/auth/auth.go:220:SignInPost() [W] Failed authentication attempt for alice from 100.64.0.7:0: user's password is invalid [uid: 1, name: alice]", "100.64.0.7"),
            ("2026/11/03 10:16:00 .../web/auth/auth.go:226:SignInPost() [W] Failed authentication attempt for carol from [fd7a:115c:a1e0::1]:0: user is not allowed login [uid: 3, name: carol]", "fd7a:115c:a1e0::1"),
        ] {
            let rest = line
                .split_once("Failed authentication attempt for ")
                .expect("anchor")
                .1;
            let addr = rest.split_once(" from ").expect("from").1;
            let addr = addr.split_once(": ").expect("port then message").0;
            let (host, port) = addr.rsplit_once(':').expect(":port");
            assert!(port.chars().all(|c| c.is_ascii_digit()), "{line}");
            assert_eq!(host.trim_start_matches('[').trim_end_matches(']'), ip);
        }
    }

    #[test]
    fn filter_is_written_before_the_jail_that_names_it() {
        let d = Fail2banModule::new(section(), 22)
            .forgejo(443, 2222)
            .declaration();
        let apply = d.render_apply();
        let f = apply.find(FORGEJO_FILTER).expect("filter written");
        assert!(f < apply.find(JAIL_FILE).expect("jail written"));
        assert!(FORGEJO_FILTER.starts_with("/etc/fail2ban/filter.d/anvil-"));
        assert!(!Fail2banModule::new(section(), 22)
            .declaration()
            .render_apply()
            .contains(FORGEJO_FILTER));
    }

    #[test]
    fn tailnet_ranges_are_never_banned_only_when_exempt() {
        let off = Fail2banModule::new(section(), 22).jail_config();
        assert!(!off.contains("ignoreip"), "{off}");
        let on = Fail2banModule::new(section(), 22)
            .exempt_tailnet(true)
            .jail_config();
        // In [DEFAULT] (applies to every jail), loopback kept since ignoreip
        // replaces fail2ban's default.
        let default_end = on.find("\n[sshd]").expect("sshd jail");
        let line = "ignoreip = 127.0.0.1/8 ::1 100.64.0.0/10 fd7a:115c:a1e0::/48\n";
        let at = on.find(line).expect("ignoreip line");
        assert!(at < default_end, "{on}");
    }
}
