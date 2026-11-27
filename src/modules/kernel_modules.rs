//! The `kernel_modules` module (R69): a modprobe drop-in that neutralizes rarely
//! needed kernel modules with `install <mod> /bin/false` lines, then refreshes
//! the initramfs so the blacklist also applies at early boot.
//!
//! The drop-in content is *computed on the target* ([`ManagedFile::computed`],
//! i.e. [`crate::engine::FileContent::Computed`]) because two of the blacklists
//! can brick a host when applied blindly:
//! - `vfat` backs the EFI System Partition; blacklisting it on an EFI-booted
//!   host (`/sys/firmware/efi` present) can leave the ESP unmountable and break
//!   boot tooling. A BIOS-booted host can still mount a vfat `/boot/efi` from
//!   fstab (some provider images do): blacklisting it there fails `local-fs.target`
//!   on the next boot and drops the host into emergency mode, so vfat is also
//!   omitted while any vfat filesystem is mounted or listed in fstab.
//! - `squashfs` backs every snap; blacklisting it where snapd is present breaks
//!   all snaps.
//!
//! On such hosts the generator emits an explanatory comment (e.g. `# vfat
//! omitted: EFI system`) instead of the `install` line, so operators can see
//! why a requested blacklist was skipped. Probe and apply run the *same*
//! generator, so per-host drift stays correct on EFI/snapd hosts. Everything
//! else is static within the generated output.
//!
//! `update-initramfs -u` must run *after* the drop-in exists, so it is a
//! [`ReloadGuard`] (the engine's only post-file hook), not a pre-file
//! [`ManagedCommand`](crate::engine::ManagedCommand). The regeneration is gated
//! on the drop-in being newer than the current initramfs image, so a converged
//! host does not rebuild the initramfs on every apply.

use crate::config::schema::KernelModulesSection;
use crate::engine::{Declaration, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::Module;

/// Modprobe drop-in this module owns (Fixed Contract for drift/rollback).
pub const DROP_IN: &str = "/etc/modprobe.d/99-anvil-blacklist.conf";

/// Rarely used filesystems (Fixed Contract). `blacklist_filesystems`.
const FILESYSTEMS: &[&str] = &["cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"];
/// `blacklist_squashfs` — host-conditional: omitted when snapd is present.
const SQUASHFS: &str = "squashfs";
/// `blacklist_vfat` — host-conditional: omitted on EFI-booted hosts and while
/// vfat is mounted or in fstab.
const VFAT: &str = "vfat";
/// `blacklist_usb_storage`.
const USB_STORAGE: &[&str] = &["usb-storage"];
/// Uncommon network protocols (Fixed Contract). `blacklist_network_protocols`.
const NETWORK_PROTOCOLS: &[&str] = &["dccp", "sctp", "rds", "tipc"];

/// Comment emitted instead of the vfat blacklist on EFI-booted hosts or hosts
/// that mount vfat.
pub const VFAT_OMITTED: &str = "# vfat omitted: EFI system or vfat in use";
/// Comment emitted instead of the squashfs blacklist when snapd is present.
pub const SQUASHFS_OMITTED: &str = "# squashfs omitted: snapd present";

/// One `printf` emitting an `install <mod> /bin/false` line per module name.
/// Names are compile-time literals (never operator input) and land in file
/// content regardless, so nothing here needs shell escaping.
fn install_lines(mods: &[&str]) -> String {
    format!("printf 'install %s /bin/false\\n' {}", mods.join(" "))
}

pub struct KernelModulesModule {
    cfg: KernelModulesSection,
}

impl KernelModulesModule {
    pub fn new(cfg: KernelModulesSection) -> Self {
        Self { cfg }
    }

    /// The bash generator that prints the desired drop-in content to stdout on
    /// the target (evaluated by the engine in both probe and apply, so they
    /// always agree). Unconditional groups are plain `printf`s; the squashfs
    /// and vfat lines are guarded by host probes (snapd, EFI firmware) and
    /// replaced with an explanatory comment when omitted.
    pub fn content_generator(&self) -> String {
        let c = &self.cfg;
        let mut lines =
            vec!["printf '%s\\n' '# Managed by anvil — do not edit by hand'".to_string()];
        if c.blacklist_filesystems {
            lines.push(install_lines(FILESYSTEMS));
        }
        if c.blacklist_squashfs {
            // snapd ships every snap as a squashfs image; blacklisting the
            // module there would break every installed snap.
            lines.push(format!(
                "if command -v snap >/dev/null 2>&1 || dpkg -s snapd >/dev/null 2>&1; then \
                 printf '%s\\n' '{SQUASHFS_OMITTED}'; \
                 else printf 'install %s /bin/false\\n' {SQUASHFS}; fi"
            ));
        }
        if c.blacklist_vfat {
            // The EFI System Partition is vfat; blacklisting the module on an
            // EFI-booted host, or on any host that mounts vfat at boot (a BIOS
            // host with a vfat /boot/efi in fstab), fails the next boot.
            // shortcut: the other FILESYSTEMS have no in-use guard; add one if a
            // host ever mounts hfs/udf/… at boot.
            lines.push(format!(
                "if [ -d /sys/firmware/efi ] || findmnt -rn -t {VFAT} >/dev/null 2>&1 \
                 || awk '$1 !~ /^#/ && $3 ~ /(^|,){VFAT}(,|$)/ && $4 !~ /noauto/ {{f=1}} END {{exit !f}}' \
                 /etc/fstab 2>/dev/null; \
                 then printf '%s\\n' '{VFAT_OMITTED}'; \
                 else printf 'install %s /bin/false\\n' {VFAT}; fi"
            ));
        }
        if c.blacklist_usb_storage {
            lines.push(install_lines(USB_STORAGE));
        }
        if c.blacklist_network_protocols {
            lines.push(install_lines(NETWORK_PROTOCOLS));
        }
        lines.join("\n")
    }
}

impl Module for KernelModulesModule {
    fn id(&self) -> &'static str {
        "kernel_modules"
    }

    fn declaration(&self) -> Declaration {
        // Rebuild the initramfs only when our drop-in is newer than the current
        // image (idempotent: a converged host skips the expensive rebuild), or
        // when it is gone (rollback: the image still carries it). The
        // whole reload tolerates hosts without `update-initramfs` (containers).
        let dropin = shell_escape(DROP_IN);
        let reload = format!(
            "if command -v update-initramfs >/dev/null 2>&1; then \
             __img=$(ls -1t /boot/initrd.img-* 2>/dev/null | head -n1) || true; \
             if [ -z \"$__img\" ] || [ ! -e {dropin} ] || [ {dropin} -nt \"$__img\" ]; then \
             update-initramfs -u || true; fi; fi"
        );
        let guard = ReloadGuard {
            describe: "initramfs module blacklist".into(),
            validate: format!("! [ -e {dropin} ] || [ -s {dropin} ]"),
            reload,
        };
        Declaration::new("kernel_modules")
            .file(ManagedFile::computed(
                DROP_IN,
                self.content_generator(),
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
    fn modprobe_dropin_keeps_the_high_prefix_and_path() {
        // modprobe.d is last-match-wins: keep the HIGH 99-anvil prefix so we
        // sort after numeric distro drop-ins, and never rename the path —
        // drift, diff, and rollback key on it.
        let name = DROP_IN.rsplit('/').next().expect("basename");
        assert!(DROP_IN.starts_with("/etc/modprobe.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }

    fn section() -> KernelModulesSection {
        KernelModulesSection {
            blacklist_filesystems: true,
            blacklist_squashfs: true,
            blacklist_vfat: true,
            blacklist_usb_storage: true,
            blacklist_network_protocols: true,
            order_override: Default::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut KernelModulesSection)) -> KernelModulesModule {
        let mut cfg = section();
        mutate(&mut cfg);
        KernelModulesModule::new(cfg)
    }

    #[test]
    fn content_is_computed_on_the_target_not_static() {
        let m = module(|_| {});
        let decl = m.declaration();
        let file = decl.files.first().expect("drop-in declared");
        assert_eq!(file.path, DROP_IN);
        // No static content — the blacklist depends on the host (EFI, snapd).
        assert!(
            file.static_content().is_none(),
            "drop-in must be host-computed, not static"
        );
        // Probe and apply materialize desired content via the same generator,
        // so per-host drift stays correct.
        let expected = format!("__desired=$({})", m.content_generator());
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
        ] {
            assert!(
                script.contains(&expected),
                "{kind} must use the generator:\n{script}"
            );
        }
    }

    #[test]
    fn vfat_blacklist_is_conditional_on_efi() {
        let g = module(|_| {}).content_generator();
        // Every vfat mention lives on the single EFI-guarded line: the install
        // is the non-EFI branch, the omission comment the EFI branch.
        let vfat_lines: Vec<&str> = g.lines().filter(|l| l.contains("vfat")).collect();
        assert_eq!(
            vfat_lines.len(),
            1,
            "vfat handled on exactly one line:\n{g}"
        );
        let line = vfat_lines[0];
        assert!(
            line.starts_with("if [ -d /sys/firmware/efi ] || findmnt -rn -t vfat"),
            "vfat must be guarded by the EFI and in-use probes: {line}"
        );
        assert!(
            line.contains("/etc/fstab"),
            "fstab vfat entries guard too: {line}"
        );
        assert!(line.contains(VFAT_OMITTED), "omission reason visible");
        assert!(line.contains("install %s /bin/false"));
    }

    #[test]
    fn vfat_fstab_guard_matches_boot_mounts_only() {
        // Run the generator's own fstab probe against sample fstabs: a vfat
        // mount needed at boot keeps vfat loadable; noauto or commented-out
        // entries do not.
        let g = module(|_| {}).content_generator();
        let line = g.lines().find(|l| l.contains("vfat")).unwrap();
        let start = line.find("awk '").unwrap();
        let end = line.find(" /etc/fstab").unwrap();
        let probe = &line[start..end];
        let dir = std::env::temp_dir().join(format!("anvil-vfat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, fstab, in_use) in [
            ("esp", "UUID=64E4 /boot/efi vfat umask=0077 0 1\n", true),
            ("multi", "/dev/sdb1 /mnt/x vfat,msdos defaults 0 0\n", true),
            ("noauto", "/dev/sdb1 /mnt/usb vfat user,noauto 0 0\n", false),
            (
                "comment",
                "#UUID=64E4 /boot/efi vfat umask=0077 0 1\n",
                false,
            ),
            ("ext4", "UUID=82e3 / ext4 errors=remount-ro 0 1\n", false),
        ] {
            let f = dir.join(name);
            std::fs::write(&f, fstab).unwrap();
            let Ok(out) = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("{probe} {}", f.display()))
                .output()
            else {
                return;
            };
            assert_eq!(out.status.success(), in_use, "{name}: {fstab}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guard_tolerates_a_rolled_back_drop_in() {
        // Rollback re-runs validate && reload after deleting the drop-in.
        // Validation must pass for "absent" (only a present-but-empty file is
        // invalid), and the reload must rebuild the initramfs, which still
        // carries the old blacklist.
        let d = module(|_| {}).declaration();
        let g = d.reload.as_ref().unwrap();
        let dir = std::env::temp_dir().join(format!("anvil-km-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("dropin.conf");
        let check = |v: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(v.replace(&shell_escape(DROP_IN), &f.display().to_string()))
                .status()
                .map(|s| s.success())
        };
        let Ok(absent) = check(&g.validate) else {
            return;
        };
        assert!(absent, "absent drop-in must validate: {}", g.validate);
        std::fs::write(&f, "").unwrap();
        assert!(!check(&g.validate).unwrap(), "empty drop-in must fail");
        std::fs::write(&f, "install cramfs /bin/false\n").unwrap();
        assert!(check(&g.validate).unwrap(), "non-empty drop-in validates");
        assert!(
            g.reload
                .contains(&format!("[ ! -e {} ]", shell_escape(DROP_IN))),
            "{}",
            g.reload
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn squashfs_blacklist_is_conditional_on_snapd() {
        let g = module(|_| {}).content_generator();
        let sq_lines: Vec<&str> = g.lines().filter(|l| l.contains("squashfs")).collect();
        assert_eq!(
            sq_lines.len(),
            1,
            "squashfs handled on exactly one line:\n{g}"
        );
        let line = sq_lines[0];
        assert!(
            line.starts_with("if command -v snap >/dev/null 2>&1 || dpkg -s snapd"),
            "squashfs must be guarded by the snapd probe: {line}"
        );
        assert!(line.contains(SQUASHFS_OMITTED), "omission reason visible");
        assert!(line.contains("install %s /bin/false"));
    }

    #[test]
    fn unconditional_groups_emit_plain_install_lines() {
        let g = module(|_| {}).content_generator();
        assert!(
            g.contains("printf 'install %s /bin/false\\n' cramfs freevxfs jffs2 hfs hfsplus udf")
        );
        assert!(g.contains("printf 'install %s /bin/false\\n' usb-storage"));
        assert!(g.contains("printf 'install %s /bin/false\\n' dccp sctp rds tipc"));
        // None of them hides behind a host conditional.
        for line in g
            .lines()
            .filter(|l| l.contains("cramfs") || l.contains("usb-storage") || l.contains("dccp"))
        {
            assert!(
                line.starts_with("printf 'install %s /bin/false"),
                "unconditional group must be a plain printf: {line}"
            );
        }
    }

    #[test]
    fn groups_are_conditional_on_config() {
        let only_usb = module(|c| {
            c.blacklist_filesystems = false;
            c.blacklist_squashfs = false;
            c.blacklist_vfat = false;
            c.blacklist_usb_storage = true;
            c.blacklist_network_protocols = false;
        })
        .content_generator();
        assert!(only_usb.contains("usb-storage"));
        assert!(!only_usb.contains("squashfs"));
        assert!(!only_usb.contains("vfat"));
        assert!(!only_usb.contains("dccp"));
        assert!(!only_usb.contains("cramfs"));
        // With squashfs/vfat disabled, their host probes disappear too.
        assert!(!only_usb.contains("/sys/firmware/efi"));
        assert!(!only_usb.contains("snapd"));
        // The managed header always remains so the file is never empty.
        assert!(only_usb.contains("Managed by anvil"));
    }

    #[test]
    fn apply_refreshes_initramfs_after_writing_the_dropin() {
        let apply = module(|_| {}).declaration().render_apply();
        let file_at = apply.find(DROP_IN).expect("file referenced");
        let load_at = apply.find("update-initramfs").expect("initramfs refresh");
        assert!(
            file_at < load_at,
            "write blacklist before rebuilding initramfs"
        );
        // Idempotency guard: only rebuild when the drop-in is newer than the image.
        assert!(apply.contains("-nt"));
        assert!(apply.contains("|| true"));
    }

    #[test]
    fn probe_is_read_only() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(probe.contains(DROP_IN));
        assert!(!probe.contains("update-initramfs"));
        assert!(!probe.contains("cp -a"));
    }
}
