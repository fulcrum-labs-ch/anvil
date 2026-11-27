//! The `crowdsec` module (R76): installs CrowdSec and its firewall bouncer from
//! the distro's own archive, installs the requested `collections`, and enables
//! the services.
//!
//! Distro packages, not the vendor repo: CrowdSec's own apt repository does
//! not cover every release (no Debian 13 "trixie" on 2026-10-30), and a vendor
//! source for a missing release breaks every later `apt-get update` on the
//! host. Debian and Ubuntu ship `crowdsec` and `crowdsec-firewall-bouncer`
//! themselves, security-maintained for the release. The bouncer package
//! registers itself with the local agent on install (so crowdsec goes first)
//! and picks the firewall backend matching the system (nftables on an
//! nf_tables iptables, iptables on iptables-legacy), writing it to
//! [`BOUNCER_LOCAL`]. `bouncer_mode` overrides that choice only when set.
//!
//! Note: R76 also calls for adapting behaviour when fail2ban is enabled (to
//! avoid conflicting bans). That cross-module coordination needs both sections
//! and therefore belongs to the registry/ordering layer, not to a module built
//! from `CrowdsecSection` alone; it is intentionally out of scope here.

use crate::config::schema::CrowdsecSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// Written by the Debian/Ubuntu bouncer package on install: its backend
/// (`mode:`) and API key. Edited in place only when `bouncer_mode` is set.
pub const BOUNCER_LOCAL: &str = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local";

/// Parser whitelist exempting tailnet addresses (written with `[tailscale]`).
pub const TAILNET_WHITELIST: &str = "/etc/crowdsec/parsers/s02-enrich/anvil-tailnet-whitelist.yaml";

pub struct CrowdsecModule {
    cfg: CrowdsecSection,
    /// Never ban tailnet addresses: after a tailnet-only cutover they may be
    /// the operator's only way in (same reasoning as fail2ban's).
    exempt_tailnet: bool,
}

impl CrowdsecModule {
    pub fn new(cfg: CrowdsecSection) -> Self {
        Self {
            cfg,
            exempt_tailnet: false,
        }
    }

    pub fn exempt_tailnet(mut self, on: bool) -> Self {
        self.exempt_tailnet = on;
        self
    }
}

/// A local s02-enrich whitelist: events from these ranges never become
/// decisions (format supported since CrowdSec 1.0; checked on 1.4.6).
fn tailnet_whitelist() -> String {
    let mut s = String::from(
        "# Managed by anvil — do not edit by hand\n\
         name: anvil/tailnet-whitelist\n\
         description: \"Never ban tailnet addresses (anvil, [tailscale] enabled)\"\n\
         whitelist:\n\
         \x20 reason: \"tailnet\"\n\
         \x20 cidr:\n",
    );
    for cidr in super::tailscale::TAILNET_CIDRS {
        s.push_str(&format!("    - \"{cidr}\"\n"));
    }
    s
}

/// `dpkg -s` reports installed packages only; `apt_install` refreshes the
/// lists first (a fresh image may have none).
fn ensure_package(describe: &str, pkg: &str) -> ManagedCommand {
    ManagedCommand::new(
        describe,
        format!("dpkg -s {} >/dev/null 2>&1", shell_escape(pkg)),
        apt_install(&[pkg]),
    )
}

/// Force the bouncer backend the package chose. `mode` is validated to
/// `iptables`/`nftables`; iptables mode needs `ipset`, which the package does
/// not pull in on an nftables system. The file is backed up before its first
/// edit so `rollback` restores the package's own choice.
fn bouncer_mode(mode: &str) -> ManagedCommand {
    let local = shell_escape(BOUNCER_LOCAL);
    let line = shell_escape(&format!("mode: {mode}"));
    let sed = shell_escape(&format!("s/^mode:.*/mode: {mode}/"));
    let ipset = if mode == "iptables" {
        format!("{} && ", apt_install(&["ipset"]))
    } else {
        String::new()
    };
    ManagedCommand::new(
        format!("crowdsec bouncer backend {mode}"),
        format!("grep -qx {line} {local}"),
        format!(
            "{ipset}{{ [ -f {local}{BACKUP_SUFFIX} ] || cp -a {local} {local}{BACKUP_SUFFIX}; }} \
             && sed -i {sed} {local} && systemctl restart crowdsec-firewall-bouncer"
        ),
    )
}

/// Install a single CrowdSec collection. `name` is config-derived and escaped.
///
/// A successful install immediately reloads (or, failing that, restarts) the
/// agent: a running CrowdSec does not pick up newly installed collections on
/// its own, and the service-enable step's converge is skipped whenever the
/// services are already active — so without the reload here, an incrementally
/// added collection would stay dormant until a manual restart.
fn install_collection(name: &str) -> ManagedCommand {
    let name_esc = shell_escape(name);
    ManagedCommand::new(
        format!("crowdsec collection {name}"),
        // `inspect` exits 0 for any collection the hub knows, installed or
        // not (seen on 1.4.6, 2026-10-30) — only its `installed:` line tells.
        // Not `grep -q`: it stops reading at the match, cscli dies of SIGPIPE
        // and `pipefail` turns a match into a failure.
        format!(
            "cscli collections inspect {name_esc} 2>/dev/null | grep '^installed: true' >/dev/null"
        ),
        format!(
            "cscli collections install {name_esc} \
             && {{ systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec; }}"
        ),
    )
}

/// Enable and start CrowdSec and its firewall bouncer, reloading CrowdSec so it
/// picks up any freshly installed collections.
fn enable_services() -> ManagedCommand {
    ManagedCommand::new(
        "enable crowdsec services",
        "systemctl is-active crowdsec >/dev/null 2>&1 \
         && systemctl is-active crowdsec-firewall-bouncer >/dev/null 2>&1",
        "systemctl enable --now crowdsec\n\
         systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec\n\
         systemctl enable --now crowdsec-firewall-bouncer",
    )
}

impl Module for CrowdsecModule {
    fn id(&self) -> &'static str {
        "crowdsec"
    }

    fn declaration(&self) -> Declaration {
        let c = &self.cfg;
        // The agent first: the bouncer package registers itself with it.
        let mut decl = Declaration::new("crowdsec")
            .command(ensure_package("ensure crowdsec installed", "crowdsec"))
            .command(ensure_package(
                "ensure crowdsec firewall bouncer installed",
                "crowdsec-firewall-bouncer",
            ));
        if let Some(mode) = &c.bouncer_mode {
            decl = decl.command(bouncer_mode(mode)).command_file(BOUNCER_LOCAL);
        }
        // Collections need cscli (from crowdsec), so they follow the installs.
        for name in &c.collections {
            decl = decl.command(install_collection(name));
        }
        // Services enabled last, after the bouncer package exists.
        decl = decl.command(enable_services());
        if self.exempt_tailnet {
            // Files are written after every command, so crowdsec exists; a
            // config that fails `crowdsec -t` is reverted, never reloaded.
            decl = decl
                .file(ManagedFile::new(
                    TAILNET_WHITELIST,
                    tailnet_whitelist(),
                    "0644",
                    "root:root",
                ))
                .guarded_reload(ReloadGuard {
                    describe: "crowdsec tailnet whitelist".into(),
                    validate: "crowdsec -t".into(),
                    reload: "systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec"
                        .into(),
                });
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(mode: Option<&str>, collections: &[&str]) -> CrowdsecSection {
        CrowdsecSection {
            collections: collections.iter().map(|s| (*s).to_string()).collect(),
            bouncer_mode: mode.map(Into::into),
            order_override: Default::default(),
        }
    }

    #[test]
    fn installs_distro_packages_agent_first() {
        // The bouncer's postinst registers with the local agent, so crowdsec
        // must be installed first; both come from the distro archive.
        let apply = CrowdsecModule::new(section(None, &["crowdsecurity/sshd"]))
            .declaration()
            .render_apply();
        let agent = apply
            .find("install -y -- 'crowdsec'\n")
            .or_else(|| apply.find("install -y -- 'crowdsec'"));
        let bouncer = apply.find("install -y -- 'crowdsec-firewall-bouncer'");
        assert!(agent.unwrap() < bouncer.unwrap(), "{apply}");
        assert!(apply.contains("cscli collections install 'crowdsecurity/sshd'"));
        assert!(apply.contains("systemctl enable --now crowdsec-firewall-bouncer"));
    }

    #[test]
    fn never_adds_a_vendor_apt_source() {
        // CrowdSec's repo had no Debian 13 packages on 2026-10-30; a source for
        // a missing release breaks every later `apt-get update`.
        let apply = CrowdsecModule::new(section(Some("iptables"), &[]))
            .declaration()
            .render_apply();
        for bad in ["packagecloud", "sources.list.d", "gpg --dearmor", "| bash"] {
            assert!(!apply.contains(bad), "{bad} in:\n{apply}");
        }
    }

    #[test]
    fn backend_is_left_to_the_package_unless_set() {
        let auto = CrowdsecModule::new(section(None, &[])).declaration();
        assert!(
            !auto.render_apply().contains(BOUNCER_LOCAL),
            "package picks the backend"
        );
        assert!(auto.command_files.is_empty());

        let forced = CrowdsecModule::new(section(Some("iptables"), &[])).declaration();
        let apply = forced.render_apply();
        assert!(apply.contains("grep -qx 'mode: iptables'"));
        assert!(
            apply.contains("install -y -- 'ipset'"),
            "iptables mode needs ipset"
        );
        assert!(apply.contains("sed -i 's/^mode:.*/mode: iptables/'"));
        assert!(
            forced.command_files.iter().any(|p| p == BOUNCER_LOCAL),
            "rollback restores the package's choice"
        );

        let nft = CrowdsecModule::new(section(Some("nftables"), &[]))
            .declaration()
            .render_apply();
        assert!(!nft.contains("'ipset'"));
    }

    #[test]
    fn collection_name_is_escaped() {
        let apply = CrowdsecModule::new(section(None, &["a'; rm -rf / #"]))
            .declaration()
            .render_apply();
        // The payload survives only inside single-quote escaping.
        assert!(apply.contains(r"cscli collections install 'a'\''; rm -rf / #'"));
    }

    #[test]
    fn bouncer_install_precedes_service_enable() {
        let apply = CrowdsecModule::new(section(None, &[]))
            .declaration()
            .render_apply();
        let bouncer = apply
            .find("install -y -- 'crowdsec-firewall-bouncer'")
            .unwrap();
        let enable = apply
            .find("systemctl enable --now crowdsec-firewall-bouncer")
            .unwrap();
        assert!(bouncer < enable);
    }

    #[test]
    fn every_collection_converge_carries_its_own_reload() {
        // On an already-running host the service-enable step is skipped, and
        // `cscli collections install` alone does not activate the collection:
        // each collection's converge reloads for itself, gated on success.
        let apply = CrowdsecModule::new(section(
            None,
            &["crowdsecurity/sshd", "crowdsecurity/nginx"],
        ))
        .declaration()
        .render_apply();
        let chain = "&& { systemctl reload crowdsec 2>/dev/null || systemctl restart crowdsec; }";
        assert_eq!(
            apply.matches(chain).count(),
            2,
            "one install-and-reload per collection"
        );
        assert!(!apply.contains("install 'crowdsecurity/nginx';"));
    }

    #[test]
    fn collection_detect_runs_true_only_when_installed() {
        // Execute the real detect against a stub cscli that, like 1.4.6,
        // exits 0 for a known-but-not-installed collection.
        let dir = std::env::temp_dir().join(format!("anvil-cscli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("cscli");
        std::fs::write(
            &stub,
            "#!/usr/bin/env bash\n[ \"$3\" = crowdsecurity/linux ] && echo 'installed: true' || echo 'installed: false'\nyes 'parsers: x' | head -n 20000\nexit 0\n",
        )
        .unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&stub)
            .status()
            .unwrap();
        let detect = |name: &str| {
            let cmd = install_collection(name).detect;
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("set -euo pipefail; {cmd}"))
                .env(
                    "PATH",
                    format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
                )
                .status()
                .map(|s| s.success())
        };
        let Ok(installed) = detect("crowdsecurity/linux") else {
            return;
        };
        assert!(installed);
        assert!(
            !detect("crowdsecurity/mysql").unwrap(),
            "not installed must drift"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn collection_detect_is_cheap_and_probe_never_mutates() {
        let probe = CrowdsecModule::new(section(None, &["crowdsecurity/sshd"]))
            .declaration()
            .render_probe();
        assert!(probe.contains("cscli collections inspect 'crowdsecurity/sshd'"));
        assert!(
            probe.contains("grep '^installed: true' >/dev/null"),
            "inspect exits 0 even when not installed"
        );
        for bad in [
            "cscli collections install",
            "systemctl reload",
            "systemctl restart",
            "apt-get",
        ] {
            assert!(!probe.contains(bad), "{bad}");
        }
    }

    #[test]
    fn tailnet_whitelist_only_when_exempt_and_validated_before_reload() {
        let off = CrowdsecModule::new(section(None, &[])).declaration();
        assert!(off.files.is_empty());
        assert!(off.reload.is_none());

        let on = CrowdsecModule::new(section(None, &["crowdsecurity/sshd"]))
            .exempt_tailnet(true)
            .declaration();
        let wl = on
            .files
            .iter()
            .find(|f| f.path == TAILNET_WHITELIST)
            .expect("whitelist file");
        let content = match &wl.content {
            crate::engine::FileContent::Static(c) => c.clone(),
            other => panic!("static content expected, got {other:?}"),
        };
        for needle in [
            "name: anvil/tailnet-whitelist\n",
            "whitelist:\n  reason: \"tailnet\"\n  cidr:\n",
            "    - \"100.64.0.0/10\"\n",
            "    - \"fd7a:115c:a1e0::/48\"\n",
        ] {
            assert!(content.contains(needle), "{needle}: {content}");
        }
        let guard = on.reload.as_ref().expect("guarded reload");
        assert_eq!(guard.validate, "crowdsec -t");
        // The whitelist lands after the packages are installed and enabled.
        let apply = on.render_apply();
        let enable = apply.find("systemctl enable --now crowdsec\n").unwrap();
        let validate = apply.find("crowdsec -t").unwrap();
        assert!(enable < validate, "{apply}");
    }
}
