//! The `filesystem` module (R39, R79): harden `/tmp` and scan the root
//! filesystem for risky permissions.
//!
//! **Fixed Contract:** `/tmp` is mounted `nodev,nosuid,noexec` **without ever
//! changing its backing store** — a disk-backed `/tmp` stays on disk (bind
//! mount over itself), a tmpfs `/tmp` stays tmpfs (remount in place); the
//! module never enables the stock tmpfs `tmp.mount` on a host that didn't have
//! it. World-writable directories gain the sticky bit; the world-writable bit
//! is cleared from regular files; and (optionally) AIDE is installed and its
//! baseline database initialized. No config-derived values reach remote bash;
//! the one embedded literal (the drop-in content) is shell-escaped anyway.

use crate::config::schema::FilesystemSection;
use crate::engine::{Declaration, ManagedCommand, MARK_CHANGED, MARK_FAILED, MARK_OK};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// systemd drop-in that pins the hardened `/tmp` mount options (Fixed Contract
/// path). A drop-in `Options=` replaces the base unit's options wholesale.
/// Written by the converge command **only** when a real `tmp.mount` unit (not
/// an fstab-generated one) is the active source of the `/tmp` mount.
pub const TMP_MOUNT_DROP_IN: &str = "/etc/systemd/system/tmp.mount.d/60-anvil.conf";

/// Desired content of the `tmp.mount` drop-in.
const TMP_MOUNT_CONTENT: &str = "# Managed by anvil — do not edit by hand\n\
     [Mount]\n\
     Options=mode=1777,strictatime,nodev,nosuid,noexec\n";

/// The fstab line that hardens a disk-backed `/tmp` by bind-mounting it over
/// itself: same directory, same disk, only the mount options change.
const TMP_FSTAB_BIND: &str = "/tmp /tmp none rw,bind,nosuid,nodev,noexec 0 0";

/// Pseudo/volatile filesystems and snap/container image storage we never
/// rewrite during permission scans (a `chmod` inside image storage corrupts
/// the images, not the host).
const PRUNE: &str = r#"\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /snap -o -path /var/lib/docker -o -path /var/lib/containerd -o -path /var/lib/containers -o -path /var/lib/sysbox -o -path /var/lib/lxc -o -path '/home/*/.local/share/docker' -o -path '/home/*/.local/share/containers' \) -prune -o"#;

/// `/tmp` is converged when its live mount options already carry all three of
/// `noexec`, `nosuid`, `nodev`. Read-only.
const TMP_DETECT: &str = r#"__o="$(awk '$2=="/tmp"{o=$4} END{print o}' /proc/self/mounts 2>/dev/null)"; printf ',%s,' "$__o" | grep ',noexec,' >/dev/null && printf ',%s,' "$__o" | grep ',nosuid,' >/dev/null && printf ',%s,' "$__o" | grep ',nodev,' >/dev/null"#;

/// The live options alone are not convergence — after a rollback (or a
/// hand-deleted drop-in) they survive until the next boot, so the probe also
/// checks the persistence the converge writes: the `tmp.mount` drop-in when a
/// real `tmp.mount` unit backs `/tmp`, else the `/tmp` fstab line's options.
const TMP_PERSISTED: &str = r#"{ __src="$(systemctl show tmp.mount -p FragmentPath --value 2>/dev/null || true)"; if systemctl is-active tmp.mount >/dev/null 2>&1 && [ -n "$__src" ] && [ "${__src#/run/systemd/generator}" = "$__src" ]; then grep -q noexec /etc/systemd/system/tmp.mount.d/60-anvil.conf 2>/dev/null; else awk '$0 !~ /^[[:space:]]*#/ && $2=="/tmp" && $4 ~ /(^|,)noexec(,|$)/ && $4 ~ /(^|,)nosuid(,|$)/ && $4 ~ /(^|,)nodev(,|$)/ {ok=1} END{exit !ok}' /etc/fstab 2>/dev/null; fi; }"#;

/// Matches a non-comment fstab line whose mount point (field 2) is `/tmp`.
const FSTAB_TMP_RE: &str = r#"'^[[:space:]]*[^#[:space:]]+[[:space:]]+/tmp[[:space:]]'"#;

/// Converge `/tmp` to `noexec,nosuid,nodev` while preserving its backing
/// store.
///
/// * `/tmp` already its own mount → remount with the options in place, then
///   persist them: via the `tmp.mount` drop-in when a real `tmp.mount` unit
///   (not the fstab generator) is the active source, otherwise by adding the
///   missing options to the existing `/tmp` fstab line (fstab backed up
///   first).
/// * `/tmp` not its own mount → append a bind-mount fstab entry (fstab backed
///   up first; only when no `/tmp` line exists) and activate it — the same
///   disk-backed directory, never a tmpfs swap. `systemctl enable --now
///   tmp.mount` is deliberately absent: the stock unit is tmpfs and would
///   silently move `/tmp` into RAM.
fn tmp_converge() -> String {
    // One shell-escaped word per drop-in line: `printf '%s\n' a b c` re-applies
    // the format per argument, producing the exact multi-line content while
    // keeping the script line single-line (the engine indents converge bodies
    // line-by-line, which would mangle a quoted multi-line string).
    let dropin_lines = TMP_MOUNT_CONTENT
        .lines()
        .map(shell_escape)
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"if awk '$2=="/tmp"{{f=1}} END{{exit !f}}' /proc/self/mounts 2>/dev/null; then
  # /tmp is already its own mount: harden the live options in place.
  mount -o remount,noexec,nosuid,nodev /tmp 2>/dev/null || true
  __src="$(systemctl show tmp.mount -p FragmentPath --value 2>/dev/null || true)"
  if systemctl is-active tmp.mount >/dev/null 2>&1 && [ -n "$__src" ] && [ "${{__src#/run/systemd/generator}}" = "$__src" ]; then
    # A real tmp.mount unit backs /tmp: persist via drop-in.
    mkdir -p {dropin_dir}
    printf '%s\n' {dropin_lines} > {dropin}
    chown root:root {dropin}
    chmod 0644 {dropin}
    systemctl daemon-reload 2>/dev/null || true
  elif grep -Eq {fstab_tmp_re} /etc/fstab 2>/dev/null; then
    # fstab owns the /tmp mount: make sure its options carry the trio.
    if ! awk '$0 !~ /^[[:space:]]*#/ && $2=="/tmp" && $4 ~ /(^|,)noexec(,|$)/ && $4 ~ /(^|,)nosuid(,|$)/ && $4 ~ /(^|,)nodev(,|$)/ {{ok=1}} END{{exit !ok}}' /etc/fstab 2>/dev/null; then
      cp -a /etc/fstab /etc/fstab{bak}
      awk '{{ if ($0 !~ /^[[:space:]]*#/ && $2=="/tmp") {{ if ($4 !~ /(^|,)noexec(,|$)/) $4=$4",noexec"; if ($4 !~ /(^|,)nosuid(,|$)/) $4=$4",nosuid"; if ($4 !~ /(^|,)nodev(,|$)/) $4=$4",nodev" }} print }}' /etc/fstab{bak} > /etc/fstab || cp -a /etc/fstab{bak} /etc/fstab
    fi
  fi
else
  # /tmp is not its own mount: bind it over itself with hardened options —
  # the backing store stays exactly where it is.
  if ! grep -Eq {fstab_tmp_re} /etc/fstab 2>/dev/null; then
    cp -a /etc/fstab /etc/fstab{bak} 2>/dev/null || true
    printf '%s\n' {fstab_bind} >> /etc/fstab
  fi
  mount /tmp 2>/dev/null || mount --bind /tmp /tmp 2>/dev/null || true
  mount -o remount,bind,noexec,nosuid,nodev /tmp 2>/dev/null || true
fi"#,
        dropin_dir = shell_escape("/etc/systemd/system/tmp.mount.d"),
        dropin_lines = dropin_lines,
        dropin = shell_escape(TMP_MOUNT_DROP_IN),
        fstab_tmp_re = FSTAB_TMP_RE,
        fstab_bind = shell_escape(TMP_FSTAB_BIND),
        bak = crate::engine::BACKUP_SUFFIX,
    )
}

/// Install AIDE and stand up its baseline database (Debian/Ubuntu paths).
const AIDE_DETECT: &str = "command -v aide >/dev/null 2>&1 && [ -f /var/lib/aide/aide.db ]";
/// Install failures propagate under `set -e`, and a final re-check of
/// [`AIDE_DETECT`] fails the step honestly instead of reporting CHANGED with no
/// AIDE.
fn aide_converge() -> String {
    format!(
        r#"{install}
if command -v aideinit >/dev/null 2>&1; then
  aideinit -y -f 2>/dev/null || aideinit 2>/dev/null || true
elif command -v aide >/dev/null 2>&1; then
  aide --init 2>/dev/null || true
fi
if [ -f /var/lib/aide/aide.db.new ]; then
  cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi
{AIDE_DETECT} || {{ printf '{MARK_FAILED} AIDE not installed or baseline not created\n'; exit 1; }}"#,
        install = apt_install(&["aide", "aide-common"]),
    )
}

pub struct FilesystemModule {
    cfg: FilesystemSection,
}

impl FilesystemModule {
    pub fn new(cfg: FilesystemSection) -> Self {
        Self { cfg }
    }
}

fn tmp_command() -> ManagedCommand {
    ManagedCommand::new(
        "mount /tmp with nodev,nosuid,noexec (preserving its backing store)",
        format!("{TMP_DETECT} && {TMP_PERSISTED}"),
        tmp_converge(),
    )
}

/// World-writable directories without the sticky bit are a hijack risk; add the
/// sticky bit to any we find on the root filesystem.
fn sticky_command() -> ManagedCommand {
    let detect = format!(
        "[ -z \"$(find / -xdev {prune} -type d -perm -0002 ! -perm -1000 -print 2>/dev/null)\" ]",
        prune = PRUNE,
    );
    let converge = format!(
        "find / -xdev {prune} -type d -perm -0002 ! -perm -1000 -exec chmod a+t {{}} + 2>/dev/null || true",
        prune = PRUNE,
    );
    ManagedCommand::new(
        "add sticky bit to world-writable directories",
        detect,
        converge,
    )
}

/// World-writable regular files should not be writable by everyone; clear the
/// other-write bit (CIS remediation).
fn world_writable_command() -> ManagedCommand {
    let detect = format!(
        "[ -z \"$(find / -xdev {prune} -type f -perm -0002 -print 2>/dev/null)\" ]",
        prune = PRUNE,
    );
    let converge = format!(
        "find / -xdev {prune} -type f -perm -0002 -exec chmod o-w {{}} + 2>/dev/null || true",
        prune = PRUNE,
    );
    ManagedCommand::new("clear the world-writable bit on files", detect, converge)
}

/// Rollback for the `tmp.mount` drop-in the converge command writes outside
/// the engine: remove it (anvil created it; there is no original to restore)
/// and reload systemd. Absent drop-in → safe no-op.
fn tmp_rollback() -> String {
    format!(
        "\n# rollback (module-authored): filesystem\n\
         if [ -e {dropin} ]; then\n\
         \x20 rm -f {dropin}\n\
         \x20 systemctl daemon-reload 2>/dev/null || true\n\
         \x20 printf '{changed} filesystem removed %s\\n' {dropin}\n\
         else\n\
         \x20 printf '{ok} filesystem has no tmp.mount drop-in\\n'\n\
         fi\n\
         # The live /tmp keeps noexec until remounted; drop it once\n\
         # nothing persists it any more (fstab was restored before this runs).\n\
         if findmnt -rn /tmp >/dev/null 2>&1 && ! {persisted} \\\n\
         \x20 && findmnt -rno OPTIONS /tmp | tr , '\\n' | grep -x noexec >/dev/null; then\n\
         \x20 mount -o remount,exec /tmp\n\
         \x20 printf '{changed} filesystem remounted /tmp exec\\n'\n\
         fi\n",
        persisted = TMP_PERSISTED,
        dropin = shell_escape(TMP_MOUNT_DROP_IN),
        changed = MARK_CHANGED,
        ok = MARK_OK,
    )
}

fn aide_command() -> ManagedCommand {
    ManagedCommand::new(
        "install AIDE and initialize its baseline",
        AIDE_DETECT,
        aide_converge(),
    )
}

impl Module for FilesystemModule {
    fn id(&self) -> &'static str {
        "filesystem"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("filesystem");
        if self.cfg.tmp_noexec {
            // The drop-in write lives inside the converge command (not a
            // ManagedFile) because it must only happen when tmp.mount is the
            // active source of /tmp — an unconditional file write would pin
            // tmpfs options onto hosts whose /tmp is disk-backed.
            decl = decl.command(tmp_command());
            // fstab is command-edited in place (backed up to .anvil.bak when
            // the /tmp entry is added or hardened); declare it so rollback can
            // restore it. When the tmp.mount path is taken instead, fstab is
            // never touched and rollback harmlessly no-ops.
            decl = decl.command_file("/etc/fstab");
            decl = decl.rollback_script(tmp_rollback());
        }
        if self.cfg.check_sticky_bits {
            decl = decl.command(sticky_command());
        }
        if self.cfg.check_world_writable {
            decl = decl.command(world_writable_command());
        }
        if self.cfg.aide_baseline {
            decl = decl.command(aide_command());
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut FilesystemSection)) -> FilesystemModule {
        let mut cfg: FilesystemSection = toml::from_str("").expect("default filesystem section");
        mutate(&mut cfg);
        FilesystemModule::new(cfg)
    }

    #[test]
    fn tmp_probe_requires_persisted_options_not_just_live_ones() {
        // After a rollback the live /tmp keeps noexec until reboot; a
        // live-only probe called that aligned and apply never restored the
        // drop-in. Detect must also check the drop-in / fstab line converge
        // writes, using the same paths.
        let d = module(|c| c.tmp_noexec = true).declaration();
        let tmp = d
            .commands
            .iter()
            .find(|c| c.describe.starts_with("mount /tmp"))
            .unwrap();
        assert!(tmp.detect.starts_with(TMP_DETECT), "{}", tmp.detect);
        assert!(
            tmp.detect.contains(TMP_MOUNT_DROP_IN),
            "drop-in persistence checked"
        );
        assert!(
            tmp.detect.contains("/etc/fstab"),
            "fstab persistence checked"
        );
        assert!(
            tmp.converge.contains("tmp.mount.d"),
            "converge writes what detect reads"
        );
    }

    #[test]
    fn tmp_dropin_is_conditional_on_tmp_mount_being_the_source() {
        let decl = module(|_| {}).declaration();
        // No unconditional ManagedFile: the drop-in is written by the converge
        // command, only when a real tmp.mount unit backs /tmp.
        assert!(decl.files.iter().all(|f| f.path != TMP_MOUNT_DROP_IN));
        let apply = decl.render_apply();
        let gate = apply
            .find("systemctl is-active tmp.mount")
            .expect("tmp.mount source check present");
        let write = apply
            .find(TMP_MOUNT_DROP_IN)
            .expect("drop-in write present");
        assert!(
            gate < write,
            "drop-in write must be behind the source check"
        );
        // The generator check keeps fstab-generated units from counting as a
        // real tmp.mount source.
        assert!(apply.contains("/run/systemd/generator"));
        // The drop-in still pins all three options.
        for opt in ["noexec", "nosuid", "nodev"] {
            assert!(TMP_MOUNT_CONTENT.contains(opt), "missing {opt:?}");
        }
        // daemon-reload accompanies the drop-in write.
        assert!(apply.contains("systemctl daemon-reload"));
    }

    #[test]
    fn rollback_removes_tmp_dropin_and_reloads() {
        // The drop-in is written by converge, not the engine, so the
        // module's rollback must remove it and reload systemd.
        let rb = module(|_| {}).declaration().render_rollback();
        let rm = rb
            .find(&format!("rm -f {}", shell_escape(TMP_MOUNT_DROP_IN)))
            .expect("drop-in removal");
        let reload = rb.find("systemctl daemon-reload").expect("daemon-reload");
        assert!(rm < reload, "remove, then reload:\n{rb}");
        assert!(rb.contains("CHANGED:") && rb.contains("OK:"));
        assert!(!rb.contains("FAILED:"));
        let off = module(|c| c.tmp_noexec = false)
            .declaration()
            .render_rollback();
        assert!(!off.contains(TMP_MOUNT_DROP_IN));

        // Executed against a temp path: removes the drop-in, then a re-run is OK.
        let dir = std::env::temp_dir().join(format!("anvil-fs-rb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let dropin = dir.join("60-anvil.conf");
        std::fs::write(&dropin, TMP_MOUNT_CONTENT).expect("write drop-in");
        let script = tmp_rollback().replace(
            &shell_escape(TMP_MOUNT_DROP_IN),
            &shell_escape(&dropin.to_string_lossy()),
        );
        let run = || {
            let out = std::process::Command::new("bash")
                // Stub systemctl so the test never reloads the real host.
                .args(["-c", &format!("systemctl() {{ :; }}\n{script}")])
                .output()
                .expect("run bash");
            assert!(out.status.success());
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        assert!(run().contains("CHANGED:"));
        assert!(!dropin.exists(), "drop-in removed");
        assert!(run().contains("OK:"), "second rollback is a no-op");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tmp_hardening_never_changes_the_backing_store() {
        let decl = module(|_| {}).declaration();
        for script in [decl.render_probe(), decl.render_apply()] {
            // The stock tmp.mount is a tmpfs unit; enabling it converts a
            // disk-backed /tmp to RAM. It must never be enabled or started.
            assert!(!script.contains("enable --now"));
            assert!(!script.contains("systemctl enable"));
            assert!(!script.contains("systemctl start tmp.mount"));
            assert!(!script.contains("systemctl restart tmp.mount"));
        }
    }

    #[test]
    fn tmp_not_a_mount_gets_a_bind_entry_not_tmpfs() {
        let apply = module(|_| {}).declaration().render_apply();
        // The not-its-own-mount branch appends a bind fstab entry (backing
        // store unchanged) and activates it without tmpfs.
        assert!(apply.contains(TMP_FSTAB_BIND));
        assert!(apply.contains(">> /etc/fstab"));
        assert!(apply.contains("mount --bind /tmp /tmp"));
        assert!(apply.contains("mount -o remount,bind,noexec,nosuid,nodev /tmp"));
        // fstab is backed up before it is appended to (checked within the
        // not-its-own-mount branch specifically).
        let branch_at = apply
            .find("bind it over itself")
            .expect("bind branch present");
        let branch = &apply[branch_at..];
        let bak = branch
            .find(&format!(
                "cp -a /etc/fstab /etc/fstab{}",
                crate::engine::BACKUP_SUFFIX
            ))
            .expect("fstab backup present");
        let append = branch.find(">> /etc/fstab").expect("fstab append present");
        assert!(bak < append, "back up fstab before appending");
    }

    #[test]
    fn tmp_apply_remounts_immediately() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("mount -o remount,noexec,nosuid,nodev /tmp"));
    }

    #[test]
    fn fstab_owned_tmp_gains_options_in_place() {
        let apply = module(|_| {}).declaration().render_apply();
        // When fstab owns the /tmp mount, the existing line gains the missing
        // options rather than being replaced by a tmpfs unit.
        assert!(apply.contains(r#"$4=$4",noexec""#));
        assert!(apply.contains(r#"$4=$4",nosuid""#));
        assert!(apply.contains(r#"$4=$4",nodev""#));
    }

    #[test]
    fn disabling_tmp_removes_command_and_dropin() {
        let decl = module(|c| c.tmp_noexec = false).declaration();
        assert!(decl.files.iter().all(|f| f.path != TMP_MOUNT_DROP_IN));
        let apply = decl.render_apply();
        assert!(!apply.contains("tmp.mount"));
        assert!(!apply.contains(TMP_FSTAB_BIND));
    }

    #[test]
    fn scans_remediate_permissions() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("chmod a+t"));
        assert!(apply.contains("chmod o-w"));
    }

    #[test]
    fn scan_prune_covers_pseudo_and_container_storage() {
        for dir in [
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/tmp",
            "/var/tmp",
            "/snap",
            "/var/lib/docker",
            "/var/lib/containerd",
            "/var/lib/containers",
            "/var/lib/sysbox",
            "/var/lib/lxc",
        ] {
            assert!(
                PRUNE.contains(&format!("-path {dir} ")),
                "{dir} missing from scan prune"
            );
        }
        // Rootless image stores: quoted, so find (not bash) globs them.
        for dir in [
            "/home/*/.local/share/docker",
            "/home/*/.local/share/containers",
        ] {
            assert!(PRUNE.contains(&format!("-path '{dir}' ")), "{dir}");
        }
        // Both scans carry the prune.
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("-path /var/lib/docker"));
        assert!(apply.contains("-path /snap"));
        assert!(apply.contains("-path /var/lib/lxc"));
    }

    #[test]
    fn scan_probes_are_read_only() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(!probe.contains("chmod a+t"));
        assert!(!probe.contains("chmod o-w"));
    }

    #[test]
    fn aide_is_opt_in() {
        let off = module(|_| {}).declaration().render_apply();
        assert!(!off.contains("aideinit"));

        let on = module(|c| c.aide_baseline = true)
            .declaration()
            .render_apply();
        assert!(on.contains("aideinit"));
        assert!(on.contains("aide-common"));
    }

    #[test]
    fn aide_install_refreshes_and_fails_honestly() {
        // Refresh before install, never swallow the install failure, and
        // fail the step when AIDE or its baseline is still missing.
        let c = aide_converge();
        assert!(!c.contains("|| true\nif command -v aideinit"));
        assert!(!c.contains("aide-common' 2>/dev/null"));
        let update = c.find("update -qq &&").expect("refresh");
        let install = c
            .find("install -y -- 'aide' 'aide-common'")
            .expect("install");
        assert!(update < install);
        let last = c.lines().last().expect("non-empty");
        assert!(last.starts_with(AIDE_DETECT));
        assert!(last.contains("FAILED: AIDE not installed") && last.contains("exit 1"));
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let bash_available = Command::new("bash")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !bash_available {
            eprintln!("skipping: bash not available");
            return;
        }
        let decl = module(|c| c.aide_baseline = true).declaration();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
            ("rollback", decl.render_rollback()),
        ] {
            let mut child = Command::new("bash")
                .arg("-n")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn bash -n");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(script.as_bytes())
                .expect("write script");
            let out = child.wait_with_output().expect("wait for bash");
            assert!(
                out.status.success(),
                "{kind} script failed bash -n:\n{}\n---\n{script}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
