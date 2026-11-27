//! The `auditd` module (R77): install `auditd` and install the CIS rule set
//! named by `rule_set` into the audit rules directory, then load the rules
//! behind a validation guard that reverts the file if the rules do not compile.

use base64::Engine;

use crate::config::schema::AuditdSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// Fixed Contract: audit rules file path (Debian/Ubuntu `rules.d`). A single
/// owned file keeps drift and rollback exact.
pub const RULES_FILE: &str = "/etc/audit/rules.d/99-anvil.rules";

/// CIS Level 1 baseline audit rules. The rule *values* are the hardening
/// contract; only the surrounding comments are ours.
///
/// NB: this set intentionally does **not** set `-e 2` (immutable). Locking the
/// audit config would require a reboot before rules could be reloaded, breaking
/// idempotent re-apply; operators wanting strict CIS immutability can layer an
/// additional rule file.
const CIS_LEVEL1: &str = "
# Reset any previously loaded rules
-D

# Larger buffer for busy systems; printk on failure
-b 8192
-f 1

# Date/time modification
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# System network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Mandatory access controls (AppArmor)
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Login / logout / session
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Discretionary access control permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unsuccessful unauthorized file access attempts — both denial modes
# (EACCES: permission denied; EPERM: operation not permitted) must be
# covered or half of the denied accesses go unrecorded.
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# Filesystem mounts by unprivileged users
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# File deletion events by users
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Use of privileged / scope-changing commands
-w /usr/bin/sudo -p x -k privileged
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Kernel module loading and unloading
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
";

/// Aarch64 has only the `*at` forms of these syscalls, and `auditctl`
/// rejects a rule naming an unknown one. The b32 (arm32 compat) rules load.
const ARM64_B64: [(&str, &str); 3] = [
    (
        "-F arch=b64 -S chmod -S fchmod -S fchmodat",
        "-F arch=b64 -S fchmod -S fchmodat",
    ),
    (
        "-F arch=b64 -S creat -S open -S openat",
        "-F arch=b64 -S openat",
    ),
    (
        "-F arch=b64 -S unlink,unlinkat,rename,renameat",
        "-F arch=b64 -S unlinkat,renameat",
    ),
];

pub struct AuditdModule {
    cfg: AuditdSection,
}

impl AuditdModule {
    pub fn new(cfg: AuditdSection) -> Self {
        Self { cfg }
    }

    /// The rule body implementing `rule_set`, or `None` if this module does
    /// not ship it. Kept in lockstep with `schema::AUDITD_RULE_SETS` — a unit
    /// test pins that every validated name resolves to a body, so a set can
    /// be added to validation but not here without a test failing.
    fn rule_body(rule_set: &str) -> Option<(&'static str, &'static str)> {
        match rule_set {
            "cis-level1" => Some(("cis-level1", CIS_LEVEL1)),
            _ => None,
        }
    }

    /// Render the rules file. The header names the set the body actually
    /// implements — never the raw requested value — so header and rules can
    /// never disagree. An unimplemented name (unreachable past config
    /// validation) ships the `cis-level1` baseline and says so.
    pub fn rule_content(&self) -> String {
        let (set, body) = Self::rule_body(&self.cfg.rule_set).unwrap_or(("cis-level1", CIS_LEVEL1));
        format!(
            "## anvil auditd rules — {set}\n\
             ## Managed by anvil; do not edit by hand.\n\
             {body}"
        )
    }
}

impl AuditdModule {
    /// [`Self::rule_content`] for an arm64 host.
    pub fn rule_content_arm64(&self) -> String {
        ARM64_B64
            .iter()
            .fold(self.rule_content(), |c, (from, to)| c.replace(from, to))
    }

    /// Prints the rules for the host's architecture (arm64, else amd64).
    fn content_generator(&self) -> String {
        let b = |c: String| shell_escape(&base64::engine::general_purpose::STANDARD.encode(c));
        format!(
            "if [ \"$(dpkg --print-architecture)\" = arm64 ]; then printf '%s' {} | base64 -d; \
             else printf '%s' {} | base64 -d; fi",
            b(self.rule_content_arm64()),
            b(self.rule_content()),
        )
    }
}

fn install_command() -> ManagedCommand {
    ManagedCommand::new(
        "install auditd",
        "dpkg-query -W -f='${Status}' auditd 2>/dev/null | grep 'install ok installed' >/dev/null",
        // Refresh lists first: a fresh minimal image may have stale/absent lists
        // and the install would fail outright (mirrors packages.rs).
        apt_install(&["auditd"]),
    )
}

/// Probe fidelity: a rules file that is on disk but has never been compiled
/// and loaded must read as drift, not alignment. Aligned means the daemon is
/// active *and* `augenrules --check` reports no pending rule change; the
/// augenrules probe is guarded on the binary existing, so hosts without it
/// fall back to the service check alone. The converge enables/starts auditd
/// and loads the compiled rules — the same facts the detect observes, so
/// probe and apply cannot disagree.
fn rules_loaded_command() -> ManagedCommand {
    ManagedCommand::new(
        "auditd active with rules loaded",
        "systemctl is-active --quiet auditd 2>/dev/null \
         && { ! command -v augenrules >/dev/null 2>&1 \
              || augenrules --check 2>/dev/null | grep 'No change' >/dev/null; }",
        "systemctl enable --now auditd 2>/dev/null \
         || service auditd start 2>/dev/null || true\n\
         if command -v augenrules >/dev/null 2>&1; then augenrules --load; fi",
    )
}

impl Module for AuditdModule {
    fn id(&self) -> &'static str {
        "auditd"
    }

    fn declaration(&self) -> Declaration {
        // `augenrules --load` compiles rules.d and loads them into the kernel;
        // a non-zero exit (bad rule) triggers auto-revert of the rules file.
        let guard = ReloadGuard {
            describe: "auditd rules".into(),
            validate: "augenrules --load".into(),
            reload: "{ systemctl restart auditd 2>/dev/null \
                     || service auditd restart 2>/dev/null || true; }"
                .into(),
        };
        Declaration::new("auditd")
            .command(install_command())
            .command(rules_loaded_command())
            .file(ManagedFile::computed(
                RULES_FILE,
                self.content_generator(),
                "0640",
                "root:root",
            ))
            .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_dropin_keeps_the_high_prefix_and_path() {
        // audit rules.d is last-match-wins: keep the HIGH 99-anvil prefix so
        // we sort after numeric distro drop-ins, and never rename the path —
        // drift, diff, and rollback key on it.
        let name = RULES_FILE.rsplit('/').next().expect("basename");
        assert!(RULES_FILE.starts_with("/etc/audit/rules.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }

    fn module(rule_set: &str) -> AuditdModule {
        AuditdModule::new(AuditdSection {
            rule_set: rule_set.into(),
            order_override: Default::default(),
        })
    }

    fn rules_file(m: &AuditdModule) -> String {
        m.rule_content()
    }

    /// Runs the generator with `dpkg` stubbed to report `arch`.
    fn generated(arch: &str) -> String {
        let dir = std::env::temp_dir().join(format!("anvil-auditd-{arch}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dpkg = dir.join("dpkg");
        std::fs::write(&dpkg, format!("#!/bin/sh\necho {arch}\n")).unwrap();
        std::fs::set_permissions(&dpkg, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let out = std::process::Command::new("bash")
            .args(["-c", &module("cis-level1").content_generator()])
            .env(
                "PATH",
                format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn arm64_hosts_get_rules_without_the_syscalls_aarch64_lacks() {
        let m = module("cis-level1");
        assert_eq!(generated("amd64"), m.rule_content());
        assert_eq!(generated("riscv64"), m.rule_content());
        let arm = generated("arm64");
        assert_eq!(arm, m.rule_content_arm64());
        for l in arm.lines().filter(|l| l.contains("arch=b64")) {
            for name in ["chmod", "creat", "open", "unlink", "rename"] {
                assert!(!l.split([' ', ',']).any(|w| w == name), "{name} in {l}");
            }
        }
        // Only those names go: same rules, same keys, b32 untouched.
        assert_eq!(arm.lines().count(), m.rule_content().lines().count());
        let b32 = |c: &str| {
            c.lines()
                .filter(|l| l.contains("arch=b32"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(b32(&arm), b32(&m.rule_content()));
        assert!(arm.contains("-F arch=b64 -S fchmod -S fchmodat"));
        assert!(arm.contains("-F arch=b64 -S openat -S truncate"));
        assert!(arm.contains("-F arch=b64 -S unlinkat,renameat -F"));
    }

    #[test]
    fn writes_rules_to_fixed_path() {
        let decl = module("cis-level1").declaration();
        assert!(decl.files.iter().any(|f| f.path == RULES_FILE));
    }

    #[test]
    fn cis_level1_has_core_rules() {
        let content = rules_file(&module("cis-level1"));
        for needle in [
            "-w /etc/passwd -p wa -k identity",
            "-w /etc/sudoers.d/ -p wa -k scope",
            "-k time-change",
            "-k modules",
        ] {
            assert!(content.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn cis_level1_covers_mounts_deletions_and_both_denial_modes() {
        let content = rules_file(&module("cis-level1"));
        for needle in [
            "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
            "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts",
            "-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete",
            "-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=4294967295 -k delete",
        ] {
            assert!(content.contains(needle), "missing {needle:?}");
        }
        // Denied file access must be recorded for BOTH errno outcomes, on
        // both ABIs, under the `access` key.
        for errno in ["-F exit=-EACCES", "-F exit=-EPERM"] {
            for arch in ["arch=b64", "arch=b32"] {
                assert!(
                    content
                        .lines()
                        .any(|l| l.contains(errno) && l.contains(arch) && l.contains("-k access")),
                    "missing {errno} rule for {arch}"
                );
            }
        }
    }

    #[test]
    fn probe_flags_rules_on_disk_but_never_loaded() {
        let probe = module("cis-level1").declaration().render_probe();
        // Alignment requires an active daemon and no pending augenrules
        // change — a rules file sitting on disk unloaded is drift.
        assert!(probe.contains("systemctl is-active --quiet auditd"));
        assert!(probe.contains("augenrules --check"));
        // The check is guarded on the binary existing.
        assert!(probe.contains("command -v augenrules"));
        // The probe stays read-only: no loading, no service mutation.
        assert!(!probe.contains("augenrules --load"));
        assert!(!probe.contains("enable --now"));
    }

    #[test]
    fn converge_enables_service_and_loads_rules() {
        let apply = module("cis-level1").declaration().render_apply();
        // Detect and converge observe/produce the same facts (agreement).
        assert!(apply.contains("augenrules --check"));
        assert!(apply.contains("systemctl enable --now auditd"));
        assert!(apply.contains("augenrules --load"));
    }

    #[test]
    fn installs_auditd_and_loads_rules() {
        let apply = module("cis-level1").declaration().render_apply();
        // Refresh package lists before installing — a fresh minimal image may
        // have stale/absent lists and the install would fail outright.
        let update = apply.find("update -qq").expect("apt-get update present");
        let install = apply
            .find("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'auditd'")
            .expect("install present");
        assert!(
            update < install,
            "must refresh lists before installing:\n{apply}"
        );
        assert!(apply.contains("augenrules --load"));
        // A bad ruleset must revert (R57-style guard).
        assert!(apply.contains("exit 1"));
    }

    #[test]
    fn every_validated_rule_set_has_a_body_and_honest_header() {
        // Lockstep contract with config validation: each admitted name must
        // resolve to a body, and the header must name that set.
        for set in crate::config::schema::AUDITD_RULE_SETS {
            let content = rules_file(&module(set));
            assert!(
                content.contains(&format!("— {set}")),
                "header must name {set}:\n{content}"
            );
        }
    }

    #[test]
    fn unimplemented_rule_set_never_stamps_a_lying_header() {
        // A name that slipped past validation ships the baseline and says
        // so — the header must not claim a rule set the body doesn't have.
        let content = rules_file(&module("cis-level2"));
        assert!(content.contains("cis-level1"), "{content}");
        assert!(!content.contains("cis-level2"), "{content}");
    }
}
