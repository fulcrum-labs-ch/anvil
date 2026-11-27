//! The `updates` module (R66): configure `unattended-upgrades` and the periodic
//! apt timers so security patches (and optionally regular updates) apply
//! automatically, with a controlled auto-reboot window.
//!
//! This module runs **last** in the plan (R58) — the resolver enforces that, so
//! nothing here has to; we only declare the desired host state.

use crate::config::schema::UpdatesSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile};

use super::{apt_install, Module, APT_LOCK_TIMEOUT};

/// Fixed Contract: periodic apt configuration (enables the timers). Written as a
/// `99-anvil*` drop-in, not the stock `20auto-upgrades`: apt.conf.d is parsed
/// in numeric order and is last-definition-wins, so a high prefix makes our
/// settings win over a later cloud-init regen (e.g. `60-*`) and leaves the
/// distro's own `20auto-upgrades` defaults untouched (the same HIGH-prefix
/// convention used for `sysctl.d`/`rules.d`). apt reads `APT::Periodic::*` from
/// any file in this dir, so the non-canonical name still drives the timers.
pub const PERIODIC_FILE: &str = "/etc/apt/apt.conf.d/99-anvil-auto-upgrades";
/// Fixed Contract: unattended-upgrades policy. Same `99-anvil*` drop-in
/// rationale as [`PERIODIC_FILE`] — never overwrite the stock
/// `50unattended-upgrades` (it carries distro defaults like
/// `Skip-On-Metered-Connection` that a wholesale rewrite would clobber).
pub const UNATTENDED_FILE: &str = "/etc/apt/apt.conf.d/99-anvil-unattended-upgrades";

/// Enables the update + unattended-upgrade timers. Values are fixed policy.
const PERIODIC_CONTENT: &str = "\
// Managed by anvil — do not edit by hand
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Download-Upgradeable-Packages \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
APT::Periodic::AutocleanInterval \"7\";
";

pub struct UpdatesModule {
    cfg: UpdatesSection,
}

impl UpdatesModule {
    pub fn new(cfg: UpdatesSection) -> Self {
        Self { cfg }
    }

    /// Render `50unattended-upgrades`. The origin list, reboot policy and
    /// reboot time are the hardening contract (R66); this content is
    /// base64-embedded by the engine, so config values need no shell-escaping.
    pub fn unattended_content(&self) -> String {
        let c = &self.cfg;
        let mut s = String::from("// Managed by anvil — do not edit by hand\n");
        // Replace the distro's origin lists instead of adding to them: apt.conf.d
        // lists are additive, and Debian's stock `50unattended-upgrades` also
        // admits every stable point release, so `security_only` would not hold
        // `#clear` (apt.conf(5)) empties both lists; this file sorts
        // after `50unattended-upgrades`, so only the patterns below remain.
        // NB: these lines contain `${...}` placeholders that unattended-upgrades
        // expands itself, so they must be plain string literals.
        s.push_str("#clear Unattended-Upgrade::Allowed-Origins;\n");
        s.push_str("#clear Unattended-Upgrade::Origins-Pattern;\n");
        s.push_str("Unattended-Upgrade::Origins-Pattern {\n");
        // Security pocket. Ubuntu names it by archive (`noble-security`, codename
        // `noble`); Debian by codename (`trixie-security`, archive
        // `stable-security`). One pattern each; the other never matches.
        s.push_str("    \"origin=${distro_id},archive=${distro_codename}-security\";\n");
        s.push_str("    \"origin=${distro_id},codename=${distro_codename}-security\";\n");
        // Ubuntu Pro (ESM) security pockets; no match elsewhere.
        s.push_str("    \"origin=UbuntuESMApps,archive=${distro_codename}-apps-security\";\n");
        s.push_str("    \"origin=UbuntuESM,archive=${distro_codename}-infra-security\";\n");
        if !c.security_only {
            // Regular updates: Ubuntu/Debian `-updates`, plus Debian's stable
            // point releases (codename `trixie`, label `Debian`).
            s.push_str("    \"origin=${distro_id},archive=${distro_codename}-updates\";\n");
            s.push_str("    \"origin=${distro_id},codename=${distro_codename}-updates\";\n");
            s.push_str(
                "    \"origin=${distro_id},codename=${distro_codename},label=${distro_id}\";\n",
            );
        }
        s.push_str("};\n");

        let reboot = if c.auto_reboot { "true" } else { "false" };
        s.push_str(&format!(
            "Unattended-Upgrade::Automatic-Reboot \"{reboot}\";\n"
        ));
        if c.auto_reboot {
            // Only meaningful when auto-reboot is on; with it off, a lingering
            // Reboot-Time line is dead configuration that reads as live policy.
            s.push_str(&format!(
                "Unattended-Upgrade::Automatic-Reboot-Time \"{}\";\n",
                c.reboot_time
            ));
        }
        if c.remove_unused_deps {
            s.push_str("Unattended-Upgrade::Remove-Unused-Dependencies \"true\";\n");
        }
        s
    }
}

/// Ensure `unattended-upgrades` is installed.
///
/// The converge refreshes the package lists first (fresh hosts may have none),
/// &&-joined so a failed refresh never proceeds to install. The refresh lives
/// *inside* the converge, so it never runs when the package is already
/// installed — probe and re-apply stay no-op on an aligned host.
fn install_command() -> ManagedCommand {
    ManagedCommand::new(
        "install unattended-upgrades",
        "dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null \
         | grep 'install ok installed' >/dev/null",
        apt_install(&["unattended-upgrades"]),
    )
}

/// One-shot cleanup of unused dependencies (R66, optional).
fn autoremove_command() -> ManagedCommand {
    ManagedCommand::new(
        "autoremove unused dependencies",
        "[ -z \"$(apt-get -s autoremove 2>/dev/null | awk '/^Remv/{print; exit}')\" ]",
        format!("DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} autoremove -y"),
    )
}

impl Module for UpdatesModule {
    fn id(&self) -> &'static str {
        "updates"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("updates").command(install_command());
        if self.cfg.remove_unused_deps {
            decl = decl.command(autoremove_command());
        }
        decl.file(ManagedFile::new(
            PERIODIC_FILE,
            PERIODIC_CONTENT,
            "0644",
            "root:root",
        ))
        .file(ManagedFile::new(
            UNATTENDED_FILE,
            self.unattended_content(),
            "0644",
            "root:root",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> UpdatesSection {
        UpdatesSection {
            security_only: true,
            auto_reboot: false,
            reboot_time: "02:00".into(),
            remove_unused_deps: false,
            order_override: Default::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut UpdatesSection)) -> UpdatesModule {
        let mut cfg = base();
        mutate(&mut cfg);
        UpdatesModule::new(cfg)
    }

    #[test]
    fn declares_both_apt_config_files() {
        let decl = module(|_| {}).declaration();
        let paths: Vec<&str> = decl.files.iter().map(|f| f.path.as_str()).collect();
        assert!(paths.contains(&PERIODIC_FILE));
        assert!(paths.contains(&UNATTENDED_FILE));
    }

    #[test]
    fn uses_99_anvil_drop_ins_not_stock_files() {
        // apt.conf.d is last-definition-wins: a HIGH `99-anvil*` prefix wins
        // over a later regen and never clobbers the distro's stock
        // 20auto-upgrades / 50unattended-upgrades. Regressing to the canonical
        // stock names would silently let cloud-init override us.
        for path in [PERIODIC_FILE, UNATTENDED_FILE] {
            assert!(
                path.starts_with("/etc/apt/apt.conf.d/99-anvil-"),
                "{path} must be a 99-anvil drop-in"
            );
            assert!(!path.contains("20auto-upgrades"), "{path}");
            assert!(!path.contains("50unattended-upgrades"), "{path}");
        }
    }

    #[test]
    fn origins_replace_the_distro_lists_instead_of_extending_them() {
        // Debian's stock 50unattended-upgrades admits every stable point
        // release; an additive drop-in can never be security-only. Both lists
        // must be cleared before ours is defined, and with security_only every
        // allowed pattern must be a security pocket.
        let c = module(|c| c.security_only = true).unattended_content();
        let clear_a = c
            .find("#clear Unattended-Upgrade::Allowed-Origins;")
            .unwrap();
        let clear_p = c
            .find("#clear Unattended-Upgrade::Origins-Pattern;")
            .unwrap();
        let define = c.find("Unattended-Upgrade::Origins-Pattern {").unwrap();
        assert!(clear_a < define && clear_p < define, "{c}");
        assert!(!c.contains("Allowed-Origins {"), "{c}");
        let patterns: Vec<&str> = c.lines().filter(|l| l.contains("origin=")).collect();
        assert!(!patterns.is_empty());
        for p in &patterns {
            assert!(p.contains("-security"), "non-security origin allowed: {p}");
        }
        // Debian's security suite is matched by codename, Ubuntu's by archive.
        assert!(c.contains("origin=${distro_id},codename=${distro_codename}-security"));
        assert!(c.contains("origin=${distro_id},archive=${distro_codename}-security"));
    }

    #[test]
    fn security_only_omits_updates_pocket() {
        let secure = module(|c| c.security_only = true).unattended_content();
        assert!(secure.contains("-security"));
        assert!(!secure.contains("-updates"));

        let all = module(|c| c.security_only = false).unattended_content();
        assert!(all.contains("-updates"));
    }

    #[test]
    fn auto_reboot_and_time_are_reflected() {
        let content = module(|c| {
            c.auto_reboot = true;
            c.reboot_time = "03:30".into();
        })
        .unattended_content();
        assert!(content.contains("Unattended-Upgrade::Automatic-Reboot \"true\""));
        assert!(content.contains("Unattended-Upgrade::Automatic-Reboot-Time \"03:30\""));
    }

    #[test]
    fn reboot_time_is_omitted_when_auto_reboot_is_off() {
        // base() has auto_reboot = false: the switch must render explicitly
        // false, and the (meaningless) reboot time must be absent entirely.
        let content = module(|_| {}).unattended_content();
        assert!(content.contains("Unattended-Upgrade::Automatic-Reboot \"false\""));
        assert!(!content.contains("Automatic-Reboot-Time"));
    }

    #[test]
    fn installs_unattended_upgrades_with_lock_timeout() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply
            .contains("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'unattended-upgrades'"));
    }

    #[test]
    fn install_refreshes_lists_only_inside_the_converge() {
        let decl = module(|_| {}).declaration();
        // The refresh is &&-joined to the install inside the converge…
        assert!(decl
            .render_apply()
            .contains("apt-get -o DPkg::Lock::Timeout=600 update -qq &&"));
        // …and never appears in the read-only probe (detect path), so an
        // aligned host is never made to hit the mirrors.
        assert!(!decl.render_probe().contains("update -qq"));
    }

    #[test]
    fn autoremove_is_conditional() {
        let without = module(|_| {}).declaration().render_apply();
        assert!(!without.contains("autoremove"));

        let with = module(|c| c.remove_unused_deps = true);
        assert!(with.declaration().render_apply().contains("autoremove"));
        assert!(with
            .unattended_content()
            .contains("Remove-Unused-Dependencies \"true\""));
    }

    #[test]
    fn periodic_enables_the_timers() {
        assert!(PERIODIC_CONTENT.contains("APT::Periodic::Unattended-Upgrade \"1\""));
        assert!(PERIODIC_CONTENT.contains("APT::Periodic::Update-Package-Lists \"1\""));
    }
}
