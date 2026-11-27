//! The `suid` module (R31, R71): scan `scan_paths` for setuid/setgid binaries,
//! compare them against a built-in stock allowlist plus the operator's
//! `extra_whitelist`, strip the set-id bits from anything unexpected
//! (`chmod u-s,g-s`), and persist a state file so drift can be detected.
//!
//! Safety net: before any bit is stripped, each victim's current octal mode and
//! path are recorded (`stat -c '%a %n'`) into the state file (mode 0600). After
//! the sweep, if `/usr/bin/sudo` exists but has lost its setuid bit, every
//! recorded mode is restored from the state file and the apply fails loudly —
//! a sweep must never leave the operator locked out.
//!
//! `rollback` replays that same state file: it `chmod`s each recorded mode back
//! onto its binary (undoing the strip), then drops the state file — so a repeat
//! rollback is a safe no-op.
//!
//! Every config-derived path (`scan_paths`, `exclude_paths`, `extra_whitelist`)
//! is passed through [`shell_escape`] before it reaches remote bash (R55).

use crate::config::schema::SuidSection;
use crate::engine::{Declaration, ManagedCommand, MARK_CHANGED, MARK_FAILED, MARK_OK};
use crate::escape::{shell_escape, shell_escape_join};

use super::Module;

/// Directory holding anvil state (also used by the engine's manifests).
const STATE_DIR: &str = "/var/lib/anvil";
/// Audit record of the last set-id sweep (Fixed Contract path for drift).
/// Holds one `<octal-mode> <path>` line per binary whose bits were stripped,
/// so a failed sweep can restore exactly what it changed.
pub const STATE_FILE: &str = "/var/lib/anvil/suid.state";

/// Built-in allowlist of set-id binaries that are expected on a stock
/// Debian/Ubuntu system and MUST keep their bits (Fixed Contract). Absolute
/// paths only (usrmerge and legacy locations both listed); the operator
/// extends this with `extra_whitelist`.
pub const STOCK_ALLOWLIST: &[&str] = &[
    // --- setuid ---
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/bin/mount",
    "/bin/umount",
    // rootless Docker/Podman user-namespace helpers
    "/usr/bin/newuidmap",
    "/usr/bin/newgidmap",
    "/bin/fusermount",
    "/usr/bin/fusermount",
    "/bin/fusermount3",
    "/usr/bin/fusermount3",
    "/usr/bin/pkexec",
    "/usr/bin/ntfs-3g",
    "/sbin/mount.nfs",
    "/usr/sbin/mount.nfs",
    "/sbin/mount.cifs",
    "/usr/sbin/mount.cifs",
    "/usr/lib/snapd/snap-confine",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/lib/policykit-1/polkit-agent-helper-1",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/polkit-agent-helper-1",
    "/usr/lib/eject/dmcrypt-get-device",
    // --- setgid ---
    "/usr/bin/wall",
    "/usr/bin/write",
    "/usr/bin/bsd-write",
    "/usr/bin/chage",
    "/usr/bin/expiry",
    "/usr/bin/crontab",
    "/usr/bin/at",
    "/usr/bin/ssh-agent",
    "/usr/bin/mlocate",
    "/usr/bin/dotlockfile",
    "/usr/sbin/unix_chkpwd",
    "/sbin/unix_chkpwd",
    "/usr/sbin/pam_extrausers_chkpwd",
    "/usr/lib/utempter/utempter",
];

/// Directories the scan never descends into: pseudo-filesystems whose entries
/// are not real files, plus snap/container image storage where a `chmod` would
/// corrupt images rather than harden the host. Scanning `/` (the default) is
/// only safe with these pruned.
pub const SCAN_PRUNE: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",
    // Docker 29 keeps image layers in the containerd snapshotter.
    "/var/lib/containerd",
    "/var/lib/containers",
    "/var/lib/sysbox",
    "/var/lib/lxc",
    // Rootless Docker/Podman image stores: setuid files in
    // pulled images belong to the user's container root, not host root.
    "/home/*/.local/share/docker",
    "/home/*/.local/share/containers",
];

pub struct SuidModule {
    cfg: SuidSection,
}

impl SuidModule {
    pub fn new(cfg: SuidSection) -> Self {
        Self { cfg }
    }

    fn detect(&self) -> String {
        // Aligned iff the state file exists *and* no unexpected set-id binaries
        // remain. Converge always (re)creates the state file, so detect never
        // depends on state converge doesn't produce. The `{ … }` group is
        // purely read-only, so it is safe to reuse verbatim inside the probe's
        // `if` test.
        format!(
            "[ -f {state} ] && {{\n{block}[ -z \"$__unexpected\" ]\n}}",
            state = shell_escape(STATE_FILE),
            block = compute_block(&self.cfg),
        )
    }

    fn converge(&self) -> String {
        format!(
            "{block}\
             mkdir -p {state_dir}\n\
             if ! [ -f {state} ]; then\n\
             \x20 : > {state}\n\
             \x20 printf '# anvil suid audit %s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo now)\" >> {state}\n\
             fi\n\
             chmod 0600 {state}\n\
             if [ -n \"$__unexpected\" ]; then\n\
             \x20 printf '%s\\n' \"$__unexpected\" | while IFS= read -r __b; do\n\
             \x20\x20 [ -n \"$__b\" ] || continue\n\
             \x20\x20 stat -c '%a %n' -- \"$__b\" >> {state} 2>/dev/null || true\n\
             \x20\x20 chmod u-s,g-s -- \"$__b\" 2>/dev/null || true\n\
             \x20 done\n\
             fi\n\
             if [ -e /usr/bin/sudo ] && ! [ -u /usr/bin/sudo ]; then\n\
             \x20 while IFS=' ' read -r __mode __victim; do\n\
             \x20\x20 case \"$__mode\" in ''|*[!0-7]*) continue ;; esac\n\
             \x20\x20 [ -n \"$__victim\" ] || continue\n\
             \x20\x20 chmod \"$__mode\" -- \"$__victim\" 2>/dev/null || true\n\
             \x20 done < {state}\n\
             \x20 printf '{failed} suid sweep left /usr/bin/sudo without its setuid bit; restored recorded modes from %s\\n' {state} >&2\n\
             \x20 exit 1\n\
             fi",
            block = compute_block(&self.cfg),
            state_dir = shell_escape(STATE_DIR),
            state = shell_escape(STATE_FILE),
            failed = MARK_FAILED,
        )
    }

    /// Restore the set-id bits the last sweep stripped, by replaying the state
    /// file converge wrote: for each `<octal-mode> <path>` line, `chmod` the
    /// recorded mode back onto the binary (the inverse of `chmod u-s,g-s`).
    /// The state file is removed once read, so re-running rollback is a safe
    /// no-op — a second run finds no state file, mirroring how a `ManagedFile`
    /// rollback consumes its `.anvil.bak`. An unreadable victim is skipped, not
    /// fatal: rollback never *fails* the host, so it emits only `CHANGED:`/`OK:`.
    fn rollback(&self) -> String {
        let state = shell_escape(STATE_FILE);
        format!(
            "\n# rollback (module-authored): suid\n\
             if [ -f {state} ]; then\n\
             \x20 __n=0\n\
             \x20 while IFS=' ' read -r __mode __victim; do\n\
             \x20\x20 case \"$__mode\" in ''|*[!0-7]*) continue ;; esac\n\
             \x20\x20 [ -n \"$__victim\" ] || continue\n\
             \x20\x20 chmod \"$__mode\" -- \"$__victim\" 2>/dev/null || true\n\
             \x20\x20 __n=$((__n + 1))\n\
             \x20 done < {state}\n\
             \x20 rm -f {state}\n\
             \x20 if [ \"$__n\" -gt 0 ]; then\n\
             \x20\x20 printf '{changed} suid restored %d recorded set-id mode(s)\\n' \"$__n\"\n\
             \x20 else\n\
             \x20\x20 printf '{ok} suid state file held no recorded modes\\n'\n\
             \x20 fi\n\
             else\n\
             \x20 printf '{ok} suid has no state file; nothing to roll back\\n'\n\
             fi\n",
            state = state,
            changed = MARK_CHANGED,
            ok = MARK_OK,
        )
    }
}

/// The combined (stock + extra) whitelist, shell-escaped and space-joined for
/// use as `printf` arguments.
fn whitelist_words(cfg: &SuidSection) -> String {
    let mut all: Vec<String> = STOCK_ALLOWLIST.iter().map(|s| s.to_string()).collect();
    all.extend(cfg.extra_whitelist.iter().cloned());
    shell_escape_join(&all)
}

/// The `find` prune expression for [`SCAN_PRUNE`], every path shell-escaped.
fn prune_expr() -> String {
    let alts = SCAN_PRUNE
        .iter()
        .map(|p| format!("-path {}", shell_escape(p)))
        .collect::<Vec<_>>()
        .join(" -o ");
    format!("\\( {alts} \\) -prune -o")
}

/// Emit read-only bash that leaves the newline-delimited set of *unexpected*
/// set-id binaries in `$__unexpected`. Shared by `detect` and `converge` so the
/// check can never disagree with the fix (R101).
fn compute_block(cfg: &SuidSection) -> String {
    let whitelist = whitelist_words(cfg);
    let mut b = String::new();

    // Sorted, de-duplicated whitelist. `find -type f` reports real files, so an
    // allowlisted symlink (Ubuntu 26.04: /usr/bin/sudo -> sudo-rs) also
    // allows its resolved target.
    b.push_str(&format!(
        "__white=\"$(for __w in {whitelist}; do printf '%s\\n' \"$__w\"; readlink -f -- \"$__w\" 2>/dev/null || true; done | LC_ALL=C sort -u)\"\n"
    ));

    // Set-id binaries actually present under the scan roots. One `find` per
    // root so `-xdev` confines each traversal to that root's own filesystem;
    // pseudo-filesystems and container/snap image storage are pruned.
    if cfg.scan_paths.is_empty() {
        b.push_str("__found=\"\"\n");
    } else {
        let scan = shell_escape_join(&cfg.scan_paths);
        let prune = prune_expr();
        b.push_str(&format!(
            "__found=\"$( {{ for __root in {scan}; do find \"$__root\" -xdev {prune} -type f \\( -perm -4000 -o -perm -2000 \\) -print 2>/dev/null || true; done; }} | LC_ALL=C sort -u )\"\n"
        ));
    }

    // Drop whitelisted entries (whole-line, fixed-string match).
    b.push_str(
        "if [ -n \"$__white\" ]; then\n\
         \x20 __rest=\"$(printf '%s\\n' \"$__found\" | grep -vxF -f <(printf '%s\\n' \"$__white\") || true)\"\n\
         else\n\
         \x20 __rest=\"$__found\"\n\
         fi\n",
    );

    // Drop excluded prefixes (and any blank lines).
    if cfg.exclude_paths.is_empty() {
        b.push_str("__unexpected=\"$(printf '%s\\n' \"$__rest\" | grep -v '^$' || true)\"\n");
    } else {
        let exclude = shell_escape_join(&cfg.exclude_paths);
        b.push_str(&format!(
            "__unexpected=\"$(printf '%s\\n' \"$__rest\" | while IFS= read -r __l; do\n\
             \x20 [ -n \"$__l\" ] || continue\n\
             \x20 __skip=\n\
             \x20 for __e in {exclude}; do\n\
             \x20\x20 case \"$__l\" in \"$__e\"|\"$__e\"/*) __skip=1; break;; esac\n\
             \x20 done\n\
             \x20 [ -n \"$__skip\" ] || printf '%s\\n' \"$__l\"\n\
             done)\"\n"
        ));
    }
    b
}

impl Module for SuidModule {
    fn id(&self) -> &'static str {
        "suid"
    }

    fn declaration(&self) -> Declaration {
        Declaration::new("suid")
            .command(ManagedCommand::new(
                "strip unexpected setuid/setgid bits",
                self.detect(),
                self.converge(),
            ))
            .rollback_script(self.rollback())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut SuidSection)) -> SuidModule {
        let mut cfg: SuidSection = toml::from_str("").expect("default suid section");
        mutate(&mut cfg);
        SuidModule::new(cfg)
    }

    #[test]
    fn apply_strips_bits_and_persists_state() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("chmod u-s,g-s"));
        assert!(apply.contains(STATE_FILE));
    }

    #[test]
    fn default_scan_paths_and_stock_allowlist_are_escaped() {
        let apply = module(|_| {}).declaration().render_apply();
        // Default scan root: the whole filesystem, one find per root, each
        // confined to its own device.
        assert!(apply.contains("for __root in '/'"));
        assert!(apply.contains("find \"$__root\" -xdev"));
        // A representative stock allowlist entry, single-quoted.
        assert!(apply.contains("'/usr/bin/sudo'"));
    }

    #[test]
    fn allowlist_keeps_snap_confine_and_mount_helpers() {
        // These are legitimately setuid-root on stock Debian/Ubuntu; stripping
        // them breaks every snap / NFS / CIFS / FUSE mount.
        for path in [
            "/usr/lib/snapd/snap-confine",
            "/sbin/mount.nfs",
            "/usr/sbin/mount.nfs",
            "/sbin/mount.cifs",
            "/usr/sbin/mount.cifs",
            "/bin/fusermount3",
            "/usr/bin/fusermount3",
            // rootless docker helpers, newer polkit, non-merged-/usr.
            "/usr/bin/newuidmap",
            "/usr/bin/newgidmap",
            "/usr/lib/polkit-1/polkit-agent-helper-1",
            "/bin/su",
            "/bin/mount",
            "/bin/umount",
            "/sbin/unix_chkpwd",
        ] {
            assert!(
                STOCK_ALLOWLIST.contains(&path),
                "{path} missing from stock allowlist"
            );
        }
        // And they reach the script shell-escaped.
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("'/usr/lib/snapd/snap-confine'"));
        assert!(apply.contains("'/sbin/mount.nfs'"));
    }

    #[test]
    fn scan_prunes_pseudo_and_container_paths() {
        let apply = module(|_| {}).declaration().render_apply();
        for p in SCAN_PRUNE {
            assert!(
                apply.contains(&format!("-path '{p}'")),
                "{p} not pruned in scan"
            );
        }
        assert!(apply.contains("-prune -o"));
        // Prune must precede the permission tests so pruned dirs are never
        // descended into.
        let prune = apply.find("-prune -o").expect("prune present");
        let perm = apply.find("-perm -4000").expect("perm test present");
        assert!(prune < perm, "prune must come before the -perm tests");
    }

    #[test]
    fn setuid_file_in_a_containerd_snapshot_is_never_flagged() {
        // Runs the real scan against a temp root holding a fake
        // containerd snapshot (its prune path redirected in): the image
        // layer's setuid sudo is skipped, a stray host setuid file is not.
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let root = format!("{base}/anvil-suid-ctrd-{}", std::process::id());
        let layer = format!(
            "{root}/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs/usr/bin"
        );
        std::fs::create_dir_all(&layer).expect("mkdir layer");
        for f in [format!("{layer}/sudo"), format!("{root}/evil")] {
            std::fs::write(&f, b"x").expect("write fixture");
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).expect("chmod");
        }
        let real = format!("-path {}", shell_escape("/var/lib/containerd"));
        let fake = format!(
            "-path {}",
            shell_escape(&format!("{root}/var/lib/containerd"))
        );
        let block = compute_block(&module(|c| c.scan_paths = vec![root.clone()]).cfg);
        assert!(block.contains(&real), "containerd pruned:\n{block}");
        let out = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "{}printf '%s\\n' \"$__unexpected\"",
                block.replace(&real, &fake)
            ))
            .output()
            .expect("run bash");
        let found = String::from_utf8_lossy(&out.stdout);
        let _ = std::fs::remove_dir_all(&root);
        assert!(found.contains(&format!("{root}/evil")), "{found}");
        assert!(!found.contains("snapshots"), "image layer flagged: {found}");
    }

    #[test]
    fn probe_is_read_only() {
        // The probe uses only the detect expression, which must never mutate.
        let probe = module(|_| {}).declaration().render_probe();
        assert!(!probe.contains("chmod"));
        assert!(probe.contains(STATE_FILE));
    }

    #[test]
    fn modes_are_recorded_before_stripping() {
        let apply = module(|_| {}).declaration().render_apply();
        // The victim's current mode+path lands in the state file before the
        // chmod that strips it, so a failed sweep can restore it.
        let record = apply
            .find("stat -c '%a %n' -- \"$__b\"")
            .expect("mode recording present");
        let strip = apply.find("chmod u-s,g-s").expect("strip present");
        assert!(record < strip, "record mode before stripping");
        // The state file is not world-readable.
        assert!(apply.contains(&format!("chmod 0600 {}", shell_escape(STATE_FILE))));
    }

    #[test]
    fn sudo_sanity_check_restores_recorded_modes_on_failure() {
        let apply = module(|_| {}).declaration().render_apply();
        // After the sweep: if sudo exists but lost its setuid bit, restore
        // every recorded mode from the state file and fail loudly.
        assert!(apply.contains("[ -e /usr/bin/sudo ] && ! [ -u /usr/bin/sudo ]"));
        let strip = apply.find("chmod u-s,g-s").expect("strip present");
        let check = apply
            .find("! [ -u /usr/bin/sudo ]")
            .expect("sanity check present");
        let restore = apply
            .find("chmod \"$__mode\" -- \"$__victim\"")
            .expect("restore present");
        let fail = apply
            .find("FAILED: suid sweep left /usr/bin/sudo")
            .expect("failure marker present");
        let exit = apply.rfind("exit 1").expect("exit present");
        assert!(
            strip < check && check < restore && restore < fail && fail < exit,
            "strip, then sanity-check, then restore + FAILED + exit 1"
        );
        // Restoration reads the very state file the sweep wrote.
        assert!(apply.contains(&format!("done < {}", shell_escape(STATE_FILE))));
    }

    #[test]
    fn rollback_replays_state_file_and_consumes_it() {
        // Rollback restores the set-id bits the sweep stripped by
        // chmod-ing each recorded <mode> <path> back, then removes the state
        // file so a second rollback is a safe no-op (ManagedFile consumes its
        // .anvil.bak the same way).
        let rb = module(|_| {}).declaration().render_rollback();
        // The mode-replay loop is gated on the state file existing.
        let guard = rb
            .find(&format!("[ -f {} ]", shell_escape(STATE_FILE)))
            .expect("state-file guard");
        let replay = rb.find("chmod \"$__mode\"").expect("mode replay");
        assert!(
            guard < replay,
            "replay only when the state file exists:\n{rb}"
        );
        // It reads the very state file the sweep wrote, then drops it.
        assert!(rb.contains(&format!("done < {}", shell_escape(STATE_FILE))));
        assert!(rb.contains(&format!("rm -f {}", shell_escape(STATE_FILE))));
        // Emits parseable CHANGED:/OK: markers; rollback never fails the host.
        assert!(rb.contains("CHANGED:"));
        assert!(rb.contains("OK:"));
        assert!(!rb.contains("FAILED:"));
        // Not the generic "owns no files" no-op — the rollback script is here.
        assert!(
            !rb.contains("owns no files"),
            "suid rollback is the state-file replay, not a no-op:\n{rb}"
        );
    }

    #[test]
    fn rollback_replays_recorded_modes_when_executed() {
        // Executes the real rendered rollback against a temp dir (its hardcoded
        // state path is redirected in): a recorded mode is replayed onto a
        // "stripped" binary, the state file is consumed, and a second run is a
        // safe no-op. Render-level + bash -n pin structure; this proves the
        // replay loop's runtime contract. (Setuid-bit honoring is OS-dependent
        // and pinned at render level via the generic `chmod "$__mode"`; a plain
        // mode replay exercises the identical code path portably.)
        use std::fs;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use std::process::{Command, Stdio};
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);

        let bash_up = Command::new("bash")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !bash_up {
            eprintln!("skipping: bash not available");
            return;
        }

        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = format!("{base}/anvil-suid-rb-{n}");
        fs::create_dir_all(&dir).expect("mkdir scratch");
        let victim = format!("{dir}/victim");
        let state = format!("{dir}/suid.state");

        let mode_of = |p: &str| fs::metadata(p).expect("stat victim").permissions().mode() & 0o777;
        let set_mode = |p: &str, m: u32| {
            fs::set_permissions(p, fs::Permissions::from_mode(m)).expect("chmod victim")
        };

        fs::write(&victim, b"#!/bin/sh\nexit 0\n").expect("write victim");
        set_mode(&victim, 0o700);
        // Mirror what `stat -c '%a %n'` records for a 0700 file.
        fs::write(&state, format!("# anvil suid audit now\n700 {victim}\n")).expect("write state");

        // Redirect the rendered script's hardcoded state path into the temp dir.
        let real = shell_escape(STATE_FILE);
        let tmp = shell_escape(&state);
        let script = module(|_| {})
            .declaration()
            .render_rollback()
            .replace(&real, &tmp);
        assert!(
            script.contains(&tmp) && !script.contains(&real),
            "state path redirected into temp dir:\n{script}"
        );

        let run = |script: &str| -> (bool, String) {
            let mut child = Command::new("bash")
                .arg("-s")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn bash");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .expect("write script");
            let out = child.wait_with_output().expect("wait bash");
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        };

        // Simulate the sweep moving the binary off its recorded mode.
        set_mode(&victim, 0o644);
        assert_eq!(mode_of(&victim), 0o644, "fixture: victim drifted to 0644");

        let (ok, out) = run(&script);
        assert!(ok, "first rollback exited non-zero:\n{out}");
        assert_eq!(mode_of(&victim), 0o700, "recorded mode replayed:\n{out}");
        assert!(
            !Path::new(&state).exists(),
            "state file consumed after replay"
        );
        assert!(out.contains("CHANGED:"), "reports the restore:\n{out}");

        // Second run: no state file → safe no-op, victim unchanged.
        let (ok2, out2) = run(&script);
        assert!(ok2, "second rollback exited non-zero:\n{out2}");
        assert_eq!(mode_of(&victim), 0o700, "victim untouched on re-run");
        assert!(out2.contains("OK:"), "no-op reports OK:\n{out2}");
    }

    #[test]
    fn two_sweeps_then_rollback_restores_every_stripped_binary() {
        // Sweep 1 strips A,B,C; an "upgrade" re-adds the bit on D; sweep
        // 2 strips D. The state file must accumulate (not truncate) so rollback
        // restores all four. Executes the real converge + rollback bash against
        // a temp scan root with the state path redirected in.
        use std::fs;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};

        let bash_up = Command::new("bash")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !bash_up {
            eprintln!("skipping: bash not available");
            return;
        }

        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let dir = format!("{base}/anvil-suid-2sweep-{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        let root = format!("{dir}/root");
        let state_dir = format!("{dir}/state");
        let bin = format!("{dir}/bin");
        fs::create_dir_all(&root).expect("mkdir root");
        fs::create_dir_all(&bin).expect("mkdir bin");

        // Converge records modes with GNU `stat -c '%a %n'`; on a BSD userland
        // shim it with the equivalent `stat -f '%Mp%Lp %N'`.
        let gnu_stat = Command::new("stat")
            .args(["-c", "%a", "/"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !gnu_stat {
            let shim = format!("{bin}/stat");
            fs::write(
                &shim,
                "#!/bin/sh\nshift 2; [ \"$1\" = -- ] && shift\nexec /usr/bin/stat -f '%Mp%Lp %N' \"$@\"\n",
            )
            .expect("write stat shim");
            fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).expect("chmod shim");
        }

        let mode_of = |p: &str| fs::metadata(p).expect("stat").permissions().mode() & 0o7777;
        let make = |name: &str| {
            let p = format!("{root}/{name}");
            fs::write(&p, b"x").expect("write victim");
            // RestrictSUIDSGID (some CI runner mounts) refuses this: the
            // mode check below then skips the test.
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o4755));
            p
        };

        let m = module(|c| c.scan_paths = vec![root.clone()]);
        let redirect = |s: String| {
            s.replace(
                &shell_escape(STATE_FILE),
                &shell_escape(&format!("{state_dir}/suid.state")),
            )
            .replace(&shell_escape(STATE_DIR), &shell_escape(&state_dir))
        };
        let converge = redirect(m.converge());
        let rollback = redirect(m.rollback());
        let run = |script: &str| {
            let mut child = Command::new("bash")
                .arg("-s")
                .env(
                    "PATH",
                    format!("{bin}:{}", std::env::var("PATH").unwrap_or_default()),
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn bash");
            child
                .stdin
                .take()
                .unwrap()
                .write_all(script.as_bytes())
                .expect("write script");
            let out = child.wait_with_output().expect("wait bash");
            assert!(
                out.status.success(),
                "script failed:\n{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        };

        let abc: Vec<String> = ["a", "b", "c"].iter().map(|n| make(n)).collect();
        // Converge aborts when /usr/bin/sudo exists without its setuid bit.
        let sudo_ok = fs::metadata("/usr/bin/sudo")
            .map(|m| m.permissions().mode() & 0o4000 != 0)
            .unwrap_or(true);
        if !sudo_ok || mode_of(&abc[0]) & 0o4000 == 0 {
            eprintln!("skipping: filesystem does not keep the setuid bit");
            return;
        }
        run(&converge);
        for p in &abc {
            assert_eq!(mode_of(p), 0o755, "sweep 1 stripped {p}");
        }
        let d = make("d");
        run(&converge);
        assert_eq!(mode_of(&d), 0o755, "sweep 2 stripped d");

        run(&rollback);
        for p in abc.iter().chain(std::iter::once(&d)) {
            assert_eq!(mode_of(p), 0o4755, "rollback restored {p}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlisted_symlink_also_allows_its_target() {
        // Ubuntu 26.04: /usr/bin/sudo is a symlink to sudo-rs, and `find -type f`
        // reports the target. Allowlisting the link must keep the target too.
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let dir = format!("{base}/anvil-suid-link-{}", std::process::id());
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir scratch");
        let dir = fs::canonicalize(&dir).expect("canonical scratch");
        let real = dir.join("real");
        let link = dir.join("link");
        fs::write(&real, "").expect("write target");
        if fs::set_permissions(&real, fs::Permissions::from_mode(0o4755)).is_err() {
            eprintln!("skipping: setuid bits are refused here (RestrictSUIDSGID)");
            return;
        }
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let root = dir.display().to_string();

        let unexpected = |white: Vec<String>| {
            let m = module(|c| {
                c.scan_paths = vec![root.clone()];
                c.extra_whitelist = white;
            });
            let script = format!("{}printf '%s' \"$__unexpected\"", compute_block(&m.cfg));
            let out = Command::new("bash")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("bash");
            String::from_utf8_lossy(&out.stdout).into_owned()
        };
        let real_s = real.display().to_string();
        assert_eq!(unexpected(Vec::new()), real_s, "control: not allowlisted");
        assert_eq!(
            unexpected(vec![link.display().to_string()]),
            "",
            "link allows target"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extra_whitelist_is_escaped_into_bash() {
        let evil = "/opt/weird'name";
        let apply = module(|c| c.extra_whitelist = vec![evil.into()])
            .declaration()
            .render_apply();
        assert!(apply.contains(&shell_escape(evil)));
    }

    #[test]
    fn exclude_paths_add_a_prefix_filter() {
        let apply = module(|c| c.exclude_paths = vec!["/opt/skip".into()])
            .declaration()
            .render_apply();
        assert!(apply.contains("'/opt/skip'"));
        assert!(apply.contains("for __e in"));
    }

    #[test]
    fn empty_scan_paths_produce_no_find() {
        let apply = module(|c| c.scan_paths = Vec::new())
            .declaration()
            .render_apply();
        assert!(!apply.contains("find "));
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
        let decl = module(|c| {
            c.extra_whitelist = vec!["/opt/tool'with quote".into()];
            c.exclude_paths = vec!["/srv/chroot".into()];
        })
        .declaration();
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
