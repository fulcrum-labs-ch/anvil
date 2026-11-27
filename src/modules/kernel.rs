//! The `kernel` module (R68): a sysctl drop-in applying network hardening, the
//! dmesg/kernel-pointer restrictions and any operator-supplied `extra_sysctl`,
//! loaded with `sysctl --system`.
//!
//! The load is expressed as a [`ReloadGuard`] rather than a [`ManagedCommand`]
//! on purpose: `sysctl --system` reads the drop-in we write, so it must run
//! *after* the file is on disk. The engine renders managed commands *before*
//! managed files, so a command-based loader would run against a not-yet-written
//! file and take two apply passes to converge; the guarded reload runs after the
//! file and converges in a single pass. Keys the running kernel rejects are
//! tolerated (`|| true`) so the module never fails on an unknown key.

use crate::config::schema::KernelSection;
use crate::engine::{Declaration, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::Module;

/// Sysctl drop-in this module owns (Fixed Contract for drift/rollback).
pub const DROP_IN: &str = "/etc/sysctl.d/99-anvil-kernel.conf";

/// Network-hardening sysctl keys (Fixed Contract — the *values* are the
/// hardening; only the file framing is ours). Applied when `harden_network`.
const NETWORK_HARDENING: &[(&str, &str)] = &[
    ("net.ipv4.conf.all.rp_filter", "1"),
    ("net.ipv4.conf.default.rp_filter", "1"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv4.conf.default.accept_source_route", "0"),
    ("net.ipv6.conf.all.accept_source_route", "0"),
    ("net.ipv6.conf.default.accept_source_route", "0"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv6.conf.all.accept_redirects", "0"),
    ("net.ipv6.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.secure_redirects", "0"),
    ("net.ipv4.conf.default.secure_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.conf.default.send_redirects", "0"),
    ("net.ipv4.conf.all.log_martians", "1"),
    ("net.ipv4.conf.default.log_martians", "1"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv6.conf.all.accept_ra", "0"),
    ("net.ipv6.conf.default.accept_ra", "0"),
];

/// `disable_ipv6` keys (Fixed Contract). Opt-in — disabling IPv6 breaks
/// dual-stack hosts, so these are only emitted when the operator asks.
const DISABLE_IPV6: &[(&str, &str)] = &[
    ("net.ipv6.conf.all.disable_ipv6", "1"),
    ("net.ipv6.conf.default.disable_ipv6", "1"),
];

/// `restrict_dmesg` key/value (Fixed Contract).
const DMESG_RESTRICT: (&str, &str) = ("kernel.dmesg_restrict", "1");
/// `restrict_kernel_pointers` key/value (Fixed Contract).
const KPTR_RESTRICT: (&str, &str) = ("kernel.kptr_restrict", "2");

pub struct KernelModule {
    cfg: KernelSection,
}

impl KernelModule {
    pub fn new(cfg: KernelSection) -> Self {
        Self { cfg }
    }

    /// Render the desired sysctl drop-in. Operator `extra_sysctl` values land in
    /// *file content* (base64-embedded by the engine), so they need no shell
    /// escaping here.
    pub fn desired_content(&self) -> String {
        let c = &self.cfg;
        let mut lines = vec!["# Managed by anvil — do not edit by hand".to_string()];
        if c.harden_network {
            lines.push("# network hardening (harden_network)".into());
            for &(k, v) in NETWORK_HARDENING {
                lines.push(format!("{k} = {v}"));
            }
        }
        if c.disable_ipv6 {
            lines.push("# IPv6 disabled (disable_ipv6)".into());
            for &(k, v) in DISABLE_IPV6 {
                lines.push(format!("{k} = {v}"));
            }
        }
        if c.restrict_dmesg {
            lines.push("# dmesg restriction (restrict_dmesg)".into());
            lines.push(format!("{} = {}", DMESG_RESTRICT.0, DMESG_RESTRICT.1));
        }
        if c.restrict_kernel_pointers {
            lines.push("# kernel pointer restriction (restrict_kernel_pointers)".into());
            lines.push(format!("{} = {}", KPTR_RESTRICT.0, KPTR_RESTRICT.1));
        }
        if !c.extra_sysctl.is_empty() {
            lines.push("# extra_sysctl".into());
            // BTreeMap iterates in sorted key order → deterministic output.
            for (k, v) in &c.extra_sysctl {
                lines.push(format!("{k} = {v}"));
            }
        }
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

impl Module for KernelModule {
    fn id(&self) -> &'static str {
        "kernel"
    }

    fn declaration(&self) -> Declaration {
        // Load the drop-in after it is written. `|| true` tolerates keys the
        // running kernel does not recognize (R68) without failing the module.
        let guard = ReloadGuard {
            describe: "sysctl settings".into(),
            validate: format!("! [ -e {p} ] || [ -s {p} ]", p = shell_escape(DROP_IN)),
            reload: "sysctl --system || true".into(),
        };
        let content = self.desired_content();
        let keys: Vec<&str> = content
            .lines()
            .filter_map(|l| l.split_once(" = ").map(|(k, _)| k))
            .collect();
        let (snapshot, restore) = super::sysctl_snapshot("kernel", DROP_IN, &keys);
        Declaration::new("kernel")
            .command(snapshot)
            .rollback_script(restore)
            .file(ManagedFile::new(DROP_IN, content, "0644", "root:root"))
            .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_dropin_keeps_the_high_prefix_and_path() {
        // sysctl.d is last-match-wins: keep the HIGH 99-anvil prefix so we
        // sort after numeric distro drop-ins, and never rename the path —
        // drift, diff, and rollback key on it.
        let name = DROP_IN.rsplit('/').next().expect("basename");
        assert!(DROP_IN.starts_with("/etc/sysctl.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }
    use std::collections::BTreeMap;

    fn section() -> KernelSection {
        KernelSection {
            harden_network: true,
            restrict_dmesg: true,
            restrict_kernel_pointers: true,
            disable_ipv6: false,
            extra_sysctl: BTreeMap::new(),
            order_override: Default::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut KernelSection)) -> KernelModule {
        let mut cfg = section();
        mutate(&mut cfg);
        KernelModule::new(cfg)
    }

    #[test]
    fn default_content_has_the_fixed_keys() {
        let content = module(|_| {}).desired_content();
        for needle in [
            "net.ipv4.conf.all.rp_filter = 1",
            "net.ipv4.conf.all.accept_source_route = 0",
            "net.ipv4.tcp_syncookies = 1",
            "net.ipv6.conf.all.accept_ra = 0",
            "kernel.dmesg_restrict = 1",
            "kernel.kptr_restrict = 2",
        ] {
            assert!(content.contains(needle), "missing {needle:?}");
        }
        assert!(content.ends_with('\n'));
    }

    #[test]
    fn groups_are_conditional() {
        let none = module(|c| {
            c.harden_network = false;
            c.restrict_dmesg = false;
            c.restrict_kernel_pointers = false;
        })
        .desired_content();
        assert!(!none.contains("rp_filter"));
        assert!(!none.contains("kernel.dmesg_restrict"));
        assert!(!none.contains("kernel.kptr_restrict"));
        // Always keeps its managed header so the file is never empty.
        assert!(none.contains("Managed by anvil"));
    }

    #[test]
    fn ipv6_disable_is_opt_in() {
        // Off by default: no disable_ipv6 keys in the drop-in.
        let default = module(|_| {}).desired_content();
        assert!(!default.contains("disable_ipv6"));

        // Opted in: both the all and default interface keys are set.
        let disabled = module(|c| c.disable_ipv6 = true).desired_content();
        assert!(disabled.contains("net.ipv6.conf.all.disable_ipv6 = 1"));
        assert!(disabled.contains("net.ipv6.conf.default.disable_ipv6 = 1"));
    }

    #[test]
    fn extra_sysctl_is_appended_sorted() {
        let content = module(|c| {
            c.extra_sysctl.insert("vm.swappiness".into(), "10".into());
            c.extra_sysctl
                .insert("fs.protected_hardlinks".into(), "1".into());
        })
        .desired_content();
        assert!(content.contains("vm.swappiness = 10"));
        assert!(content.contains("fs.protected_hardlinks = 1"));
        // BTreeMap order: fs.* precedes vm.*
        let fs = content.find("fs.protected_hardlinks").unwrap();
        let vm = content.find("vm.swappiness").unwrap();
        assert!(fs < vm, "extra_sysctl must be deterministically sorted");
    }

    #[test]
    fn load_runs_after_file_and_tolerates_rejected_keys() {
        let apply = module(|_| {}).declaration().render_apply();
        // The file write must precede the sysctl load in source order.
        let file_at = apply.find(DROP_IN).expect("file referenced");
        let load_at = apply.find("sysctl --system").expect("load present");
        assert!(file_at < load_at, "must write drop-in before loading it");
        assert!(apply.contains("|| true"), "must tolerate rejected keys");
    }

    #[test]
    fn probe_is_read_only_and_references_the_dropin() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(probe.contains(DROP_IN));
        // A probe never loads/mutates; the guard is apply-only.
        assert!(!probe.contains("sysctl --system"));
        assert!(!probe.contains("cp -a"));
    }
}
