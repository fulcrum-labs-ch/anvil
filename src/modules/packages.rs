//! The `packages` module (R75): install the `install` list and purge the
//! `remove` list with `apt-get`, idempotently.
//!
//! Every apt invocation carries a dpkg lock-wait so it tolerates cloud-init or
//! unattended-upgrades briefly holding the dpkg lock on a fresh boot (R109).
//! Every config-derived package name is shell-escaped (R55) and, after the apt
//! call, its dpkg state is re-checked so success is never reported for a
//! package that did not actually converge.

use crate::config::schema::PackagesSection;
use crate::engine::{Declaration, ManagedCommand, MARK_FAILED};
use crate::escape::shell_escape;

use super::{apt_install, Module, APT_LOCK_TIMEOUT};

pub struct PackagesModule {
    cfg: PackagesSection,
}

impl PackagesModule {
    pub fn new(cfg: PackagesSection) -> Self {
        Self { cfg }
    }
}

/// dpkg predicate that is true exactly when the (already shell-escaped) package
/// is fully installed.
fn is_installed(name_esc: &str) -> String {
    format!(
        "dpkg-query -W -f='${{Status}}' {name_esc} 2>/dev/null | grep 'install ok installed' >/dev/null"
    )
}

/// Ensure `pkg` is installed, then verify its dpkg state (R75).
///
/// The converge refreshes the package lists before installing: on a fresh host
/// the lists may be absent or stale and the install would fail outright. The
/// refresh lives *inside* the converge (the detect's `else` branch), so it
/// never runs when the package is already installed — probe and re-apply stay
/// read-only/no-op on an aligned host.
fn install_command(pkg: &str) -> ManagedCommand {
    let name = shell_escape(pkg);
    let installed = is_installed(&name);
    let converge = format!(
        "{}\n\
         if ! {installed}; then printf '{MARK_FAILED} package %s not installed after apt-get\\n' {name}; exit 1; fi",
        apt_install(&[pkg])
    );
    ManagedCommand::new(format!("install package {pkg}"), installed, converge)
}

/// Ensure `pkg` is purged, then verify it is gone (R75).
fn purge_command(pkg: &str) -> ManagedCommand {
    let name = shell_escape(pkg);
    let installed = is_installed(&name);
    // Converged when the package is *not* installed.
    let detect = format!("! {installed}");
    let converge = format!(
        "DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} purge -y -- {name}\n\
         if {installed}; then printf '{MARK_FAILED} package %s still installed after purge\\n' {name}; exit 1; fi"
    );
    ManagedCommand::new(format!("purge package {pkg}"), detect, converge)
}

impl Module for PackagesModule {
    fn id(&self) -> &'static str {
        "packages"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("packages");
        for pkg in &self.cfg.install {
            decl = decl.command(install_command(pkg));
        }
        for pkg in &self.cfg.remove {
            decl = decl.command(purge_command(pkg));
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(install: &[&str], remove: &[&str]) -> PackagesModule {
        PackagesModule::new(PackagesSection {
            install: install.iter().map(|s| s.to_string()).collect(),
            remove: remove.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
    }

    #[test]
    fn install_uses_lock_timeout_and_verifies_state() {
        let apply = module(&["htop"], &[]).declaration().render_apply();
        assert!(apply.contains("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'htop'"));
        // dpkg state is verified before and after (idempotent + R75).
        assert!(apply.contains("dpkg-query -W -f='${Status}' 'htop'"));
        assert!(apply.contains("FAILED: package %s not installed after apt-get"));
    }

    #[test]
    fn install_refreshes_lists_only_inside_the_converge() {
        let cmd = install_command("htop");
        // The refresh is &&-joined to the install so stale/absent lists are
        // fetched first and a failed refresh never proceeds to install.
        assert!(cmd
            .converge
            .contains("apt-get -o DPkg::Lock::Timeout=600 update -qq &&"));
        let refresh = cmd.converge.find("update -qq").expect("refresh present");
        let install = cmd.converge.find("install -y").expect("install present");
        assert!(refresh < install, "refresh must precede install");
        // It lives in the converge, not the detect: an aligned host never
        // triggers an apt refresh on probe or re-apply.
        assert!(!cmd.detect.contains("update"));
        // The purge path is unchanged — removing a package needs no fresh lists.
        assert!(!purge_command("telnet").converge.contains("update -qq"));
    }

    #[test]
    fn remove_purges_with_lock_timeout() {
        let apply = module(&[], &["telnet"]).declaration().render_apply();
        assert!(apply.contains("apt-get -o DPkg::Lock::Timeout=600 purge -y -- 'telnet'"));
    }

    #[test]
    fn package_names_are_shell_escaped() {
        let apply = module(&["evil; rm -rf /"], &[])
            .declaration()
            .render_apply();
        assert!(apply.contains("'evil; rm -rf /'"));
    }

    #[test]
    fn probe_checks_dpkg_state_and_never_mutates() {
        let probe = module(&["htop"], &["telnet"]).declaration().render_probe();
        assert!(probe.contains("dpkg-query"));
        // A probe must not shell out to apt.
        assert!(!probe.contains("apt-get"));
    }
}
