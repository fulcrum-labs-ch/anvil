//! The `dns` module (R72): a systemd-resolved drop-in setting `DNS=`,
//! `Domains=~.` (so the global resolvers take priority over per-link ones),
//! `FallbackDNS=`, `DNSSEC=` and `DNSOverTLS=`, followed by a guarded restart
//! of `systemd-resolved` so the new configuration takes effect.
//!
//! The restart is a [`ReloadGuard`] (runs after the drop-in is written) and is
//! tolerant of hosts that do not run systemd-resolved, degrading gracefully
//! rather than failing the module (R107).

use crate::config::schema::DnsSection;
use crate::engine::{Declaration, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::Module;

/// systemd-resolved drop-in this module owns (Fixed Contract).
pub const DROP_IN: &str = "/etc/systemd/resolved.conf.d/99-anvil.conf";

pub struct DnsModule {
    cfg: DnsSection,
}

impl DnsModule {
    pub fn new(cfg: DnsSection) -> Self {
        Self { cfg }
    }

    /// Render the desired `resolved.conf.d` drop-in. Server addresses are
    /// operator data but land in *file content* (base64-embedded), so they need
    /// no shell escaping here; resolved's grammar is space-separated lists.
    pub fn desired_content(&self) -> String {
        let c = &self.cfg;
        let mut lines = vec![
            "# Managed by anvil — do not edit by hand".to_string(),
            "[Resolve]".to_string(),
        ];
        if !c.dns_servers.is_empty() {
            lines.push(format!("DNS={}", c.dns_servers.join(" ")));
            // Route *all* lookups through the global resolvers. Without the
            // `~.` routing domain, per-link DNS servers (e.g. DHCP-provided)
            // keep priority for unqualified/default lookups and silently
            // bypass the servers configured above — a split-DNS leak.
            lines.push("Domains=~.".to_string());
        }
        if !c.fallback_servers.is_empty() {
            lines.push(format!("FallbackDNS={}", c.fallback_servers.join(" ")));
        }
        // Assert both toggles explicitly so the effective policy is unambiguous.
        lines.push(format!(
            "DNSSEC={}",
            if c.dnssec_strict {
                "yes"
            } else {
                "allow-downgrade"
            }
        ));
        // Honest boolean mapping: the operator asked for DNS-over-TLS or not.
        // (`opportunistic` would silently accept a downgrade to plaintext, so
        // it is not what either `true` or `false` means.)
        lines.push(format!(
            "DNSOverTLS={}",
            if c.dns_over_tls { "yes" } else { "no" }
        ));
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

impl Module for DnsModule {
    fn id(&self) -> &'static str {
        "dns"
    }

    fn declaration(&self) -> Declaration {
        let guard = ReloadGuard {
            describe: "systemd-resolved".into(),
            validate: format!("! [ -e {p} ] || [ -s {p} ]", p = shell_escape(DROP_IN)),
            reload: "systemctl restart systemd-resolved 2>/dev/null \
                     || systemctl restart systemd-resolved.service 2>/dev/null || true"
                .into(),
        };
        Declaration::new("dns")
            .file(ManagedFile::new(
                DROP_IN,
                self.desired_content(),
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
    fn resolved_dropin_keeps_the_high_prefix_and_path() {
        // resolved.conf.d is last-match-wins: keep the HIGH 99-anvil prefix
        // so we sort after numeric distro drop-ins, and never rename the
        // path — drift, diff, and rollback key on it.
        let name = DROP_IN.rsplit('/').next().expect("basename");
        assert!(DROP_IN.starts_with("/etc/systemd/resolved.conf.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }

    fn module(mutate: impl FnOnce(&mut DnsSection)) -> DnsModule {
        let mut cfg = DnsSection::default();
        mutate(&mut cfg);
        DnsModule::new(cfg)
    }

    #[test]
    fn servers_and_defaults_render() {
        let content = module(|c| {
            c.dns_servers = vec!["1.1.1.1".into(), "1.0.0.1".into()];
            c.fallback_servers = vec!["9.9.9.9".into()];
        })
        .desired_content();
        assert!(content.contains("[Resolve]"));
        assert!(content.contains("DNS=1.1.1.1 1.0.0.1"));
        // Configured resolvers must win for all domains, or per-link (DHCP)
        // DNS servers keep answering — a split-DNS leak.
        assert!(content.contains("Domains=~."));
        assert!(content.contains("FallbackDNS=9.9.9.9"));
        // Defaults for the two toggles when unset: DNSSEC stays permissive,
        // DNS-over-TLS is on by default.
        assert!(content.contains("DNSSEC=allow-downgrade"));
        assert!(content.contains("DNSOverTLS=yes"));
    }

    #[test]
    fn default_section_ships_hardened_resolvers() {
        let content = module(|_| {}).desired_content();
        assert!(content.contains("DNS=9.9.9.9 149.112.112.112 1.1.1.1 1.0.0.1"));
        assert!(content.contains("Domains=~."));
        assert!(content.contains("DNSOverTLS=yes"));
    }

    #[test]
    fn strict_toggles_flip_the_values() {
        let content = module(|c| {
            c.dnssec_strict = true;
            c.dns_over_tls = false;
        })
        .desired_content();
        assert!(content.contains("DNSSEC=yes"));
        // false means *no*: `opportunistic` would misrepresent the operator's
        // choice in both directions.
        assert!(content.contains("DNSOverTLS=no"));
        assert!(!content.contains("opportunistic"));
    }

    #[test]
    fn empty_server_lists_are_omitted() {
        let content = module(|c| {
            c.dns_servers = Vec::new();
            c.fallback_servers = Vec::new();
        })
        .desired_content();
        assert!(!content.contains("DNS="), "no bare DNS= without servers");
        assert!(!content.contains("FallbackDNS="));
        // Without global resolvers there is nothing to prioritize; forcing
        // `~.` would break resolution entirely.
        assert!(!content.contains("Domains="));
    }

    #[test]
    fn restart_runs_after_file_and_degrades_gracefully() {
        let apply = module(|_| {}).declaration().render_apply();
        let file_at = apply.find(DROP_IN).expect("file referenced");
        let restart_at = apply
            .find("systemctl restart systemd-resolved")
            .expect("restart present");
        assert!(
            file_at < restart_at,
            "write drop-in before restarting resolved"
        );
        assert!(
            apply.contains("|| true"),
            "restart must not fail the module"
        );
    }

    #[test]
    fn probe_is_read_only() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(probe.contains(DROP_IN));
        assert!(!probe.contains("systemctl restart"));
    }
}
