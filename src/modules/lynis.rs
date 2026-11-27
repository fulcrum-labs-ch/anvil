//! The `lynis` module (R78): install `lynis` and expose the audit invocation
//! the `score` command runs to read the hardening index.
//!
//! This module is audit-only: it makes no hardening changes itself, so
//! its declaration just ensures the `lynis` package is present. The `score`
//! command runs [`AUDIT_COMMAND`] over SSH and feeds the output to
//! [`parse_hardening_index`].

use crate::config::schema::LynisSection;
use crate::engine::{Declaration, ManagedCommand};

use super::{apt_install, Module, APT_LOCK_TIMEOUT};

/// Fixed Contract: the `lynis` package name.
pub const LYNIS_PACKAGE: &str = "lynis";

/// The audit invocation `score` runs. `--quick` skips interactive pauses and
/// `--no-colors` keeps the output parseable.
pub const AUDIT_COMMAND: &str = "lynis audit system --quick --no-colors";

pub struct LynisModule;

impl LynisModule {
    /// The `[lynis]` section carries no tunables today (audit only, R38); the
    /// config is accepted for registry symmetry and forward compatibility.
    pub fn new(_cfg: LynisSection) -> Self {
        Self
    }
}

/// The command `score` runs over SSH to produce a hardening index.
pub fn audit_command() -> &'static str {
    AUDIT_COMMAND
}

/// A self-contained script the `score` command runs over SSH: ensure `lynis` is
/// present (best-effort, tolerating a transient dpkg lock, R109) and then run
/// the audit, printing whatever hardening index Lynis can compute. It uses
/// `set -uo pipefail` (deliberately no `-e`) and `|| true` so a network/install
/// hiccup never aborts before the audit — `score` then reports "no index"
/// rather than an opaque SSH failure. Every interpolated token is a trusted
/// compile-time literal, so no shell escaping is required (R55).
pub fn audit_script() -> String {
    format!(
        "#!/usr/bin/env bash\n\
         set -uo pipefail\n\
         if ! dpkg-query -W -f='${{Status}}' {pkg} 2>/dev/null | grep 'install ok installed' >/dev/null; then\n\
         \x20 DEBIAN_FRONTEND=noninteractive apt-get {lock} install -y -- {pkg} >/dev/null 2>&1 || true\n\
         fi\n\
         {audit} || true\n",
        pkg = LYNIS_PACKAGE,
        lock = APT_LOCK_TIMEOUT,
        audit = AUDIT_COMMAND,
    )
}

/// Extract the Lynis hardening index (0–100) from audit output. Handles both
/// the human line (`Hardening index : 67 [...]`) and the report.dat form
/// (`hardening_index=67`).
pub fn parse_hardening_index(output: &str) -> Option<u32> {
    for line in output.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("hardening_index=") {
            if let Ok(n) = v.trim().parse::<u32>() {
                return Some(n);
            }
        }
        if let Some(rest) = l.strip_prefix("Hardening index") {
            let digits: String = rest
                .trim_start_matches(|c: char| !c.is_ascii_digit())
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if let Ok(n) = digits.parse::<u32>() {
                return Some(n);
            }
        }
    }
    None
}

fn install_command() -> ManagedCommand {
    ManagedCommand::new(
        "install lynis",
        "dpkg-query -W -f='${Status}' lynis 2>/dev/null | grep 'install ok installed' >/dev/null",
        apt_install(&[LYNIS_PACKAGE]),
    )
}

impl Module for LynisModule {
    fn id(&self) -> &'static str {
        "lynis"
    }

    fn declaration(&self) -> Declaration {
        Declaration::new("lynis").command(install_command())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module() -> LynisModule {
        LynisModule::new(LynisSection::default())
    }

    #[test]
    fn declares_lynis_install_with_lock_timeout() {
        let apply = module().declaration().render_apply();
        // Lists are refreshed before the install (fresh minimal image).
        let update = apply.find("update -qq &&").expect("apt-get update present");
        let install = apply
            .find("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'lynis'")
            .expect("lynis install present");
        assert!(update < install);
    }

    #[test]
    fn audit_command_runs_lynis() {
        assert!(audit_command().contains("lynis audit system"));
        assert!(audit_command().contains("--no-colors"));
    }

    #[test]
    fn audit_script_installs_then_audits_tolerantly() {
        let s = audit_script();
        // Ensures the package first, then runs the audit.
        let install = s.find("apt-get").expect("install step present");
        let audit = s.find("lynis audit system").expect("audit step present");
        assert!(install < audit, "install must precede audit");
        assert!(s.contains("-o DPkg::Lock::Timeout=600"));
        // Must not abort before the audit runs.
        assert!(!s.contains("set -euo"));
        assert!(s.contains("|| true"));
    }

    #[test]
    fn parses_hardening_index_forms() {
        assert_eq!(
            parse_hardening_index("Hardening index : 67 [####      ]"),
            Some(67)
        );
        assert_eq!(parse_hardening_index("hardening_index=82"), Some(82));
        assert_eq!(parse_hardening_index("no index here"), None);
    }
}
