//! Hermetic roundtrip harness for the engine's rendered scripts.
//!
//! Renders probe/apply for a `Declaration` and EXECUTES them under real bash
//! against temp files (no ssh, no network) to prove the engine's core contract
//! end-to-end: the probe agrees with apply, mode/owner drift is detected and
//! corrected, and static content round-trips byte-exactly (trailing newlines
//! survive). These are the tests that catch the systemic engine defects:
//! render-level assertions next to the code (src/engine.rs) run
//! everywhere; these execution assertions run where the generated scripts'
//! target environment is available.
//!
//! The generated scripts target Debian/Ubuntu (GNU coreutils: `stat -c`, …), so
//! the execution tier is guarded on GNU `stat` and runs authoritatively in CI
//! (ubuntu); it skips on BSD-`stat` hosts (macOS dev). The `chown` in apply is
//! stubbed to a no-op via a scoped PATH so the harness can run as a non-root
//! user (chmod stays real — the test user owns the temp files).

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use fulcrum_anvil::engine::{
    parse_apply, parse_probe, Declaration, ManagedCommand, ManagedFile, ReloadGuard, Verdict,
};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// The generated scripts use GNU `stat -c`; that is the gate for executing
/// them locally. BSD `stat` (macOS) lacks `-c`, so the tier skips there —
/// CI (ubuntu) is the authoritative gate (R102).
fn gnu_stat_available() -> bool {
    Command::new("stat")
        .args(["-c", "%a", "/"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ready() -> bool {
    bash_available() && gnu_stat_available()
}

fn scratch(name: &str) -> String {
    let base = std::env::var("CARGO_TARGET_TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    // The pid keeps parallel test processes (nextest) apart; clearing the dir
    // keeps a recycled pid from inheriting a previous run's converged files.
    let dir = format!("{base}/anvil-rt-{name}-{}-{n}", std::process::id());
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("mkdir scratch");
    dir
}

fn make_executable(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).expect("stat shim").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("chmod shim");
    }
}

/// A temp PATH whose `chown` is a no-op, so apply's chown succeeds when the
/// harness runs non-root. `chmod` (and everything else) stays real.
fn chown_stub_dir() -> String {
    let dir = scratch("chown-stub");
    let shim = format!("{dir}/chown");
    fs::write(&shim, "#!/usr/bin/env bash\nexit 0\n").expect("write chown shim");
    make_executable(&shim);
    dir
}

/// The test user's `user:group`, learned by stating a temp file, so the
/// "aligned" fixture can declare a matching owner.
fn current_owner_group() -> String {
    let dir = scratch("owner");
    let probe = format!("{dir}/probe");
    fs::write(&probe, b"x").expect("write probe file");
    let out = Command::new("stat")
        .args(["-c", "%U:%G"])
        .arg(&probe)
        .output()
        .expect("stat probe file");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn run_script(script: &str, chown_dir: &str) -> (bool, String) {
    let path = format!(
        "{}:{}",
        chown_dir,
        std::env::var("PATH").unwrap_or_default()
    );
    let mut child = Command::new("bash")
        .arg("-s")
        .env("PATH", &path)
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
}

fn set_mode(path: &str, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
}

fn mode_of(path: &str) -> String {
    let out = Command::new("stat")
        .args(["-c", "%a"])
        .arg(path)
        .output()
        .expect("stat");
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[test]
fn apply_converges_then_probe_agrees_and_bytes_round_trip() {
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("converge");
    let path = format!("{dir}/managed.conf");
    let owner = current_owner_group();
    let content = "key = value\n"; // trailing newline must survive
    let decl = Declaration::new("rt").file(ManagedFile::new(&path, content, "0644", &owner));
    let chown_dir = chown_stub_dir();

    // First apply creates the file and converges mode.
    let (ok, out) = run_script(&decl.render_apply(), &chown_dir);
    assert!(ok, "first apply exited non-zero:\n{out}");
    assert_eq!(
        parse_apply(&out).as_str(),
        "changed",
        "first apply reports changed:\n{out}"
    );

    // Exact bytes on disk — the trailing newline survived.
    let bytes = fs::read(&path).expect("read managed file");
    assert_eq!(
        bytes,
        content.as_bytes(),
        "declared bytes must round-trip exactly"
    );
    // Mode was enforced to 0644 even though the write used the umask default.
    assert_eq!(mode_of(&path), "644", "mode enforced");

    // Probe now reports aligned (content + mode + owner all match).
    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok, "probe exited non-zero:\n{out}");
    assert_eq!(
        parse_probe(&out),
        Verdict::Aligned,
        "probe agrees with apply:\n{out}"
    );

    // A second apply is a no-op (idempotent).
    let (ok, out) = run_script(&decl.render_apply(), &chown_dir);
    assert!(ok, "second apply exited non-zero:\n{out}");
    assert_eq!(
        parse_apply(&out).as_str(),
        "ok",
        "second apply is a no-op:\n{out}"
    );
}

#[test]
fn computed_content_is_written_with_a_final_newline_and_stays_aligned() {
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("computed");
    let path = format!("{dir}/computed.rules");
    let decl = Declaration::new("rt").file(ManagedFile::computed(
        &path,
        "printf 'a\\nb\\n'",
        "0644",
        current_owner_group(),
    ));
    let chown_dir = chown_stub_dir();
    let (ok, out) = run_script(&decl.render_apply(), &chown_dir);
    assert!(ok, "apply exited non-zero:\n{out}");
    // `$(...)` strips the newline; the write puts it back (augenrules
    // glues a file without one to the next).
    assert_eq!(fs::read(&path).unwrap(), b"a\nb\n");
    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok, "probe exited non-zero:\n{out}");
    assert_eq!(parse_probe(&out), Verdict::Aligned, "{out}");
}

#[test]
fn mode_drift_is_detected_and_corrected_even_when_content_matches() {
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("mode");
    let path = format!("{dir}/m.conf");
    let owner = current_owner_group();
    let decl =
        Declaration::new("rt").file(ManagedFile::new(&path, "key = value\n", "0644", &owner));
    let chown_dir = chown_stub_dir();

    // Converge first, then corrupt only the mode.
    run_script(&decl.render_apply(), &chown_dir);
    set_mode(&path, 0o666);
    assert_eq!(mode_of(&path), "666");

    // The probe must flag drift despite correct content.
    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok, "probe exited non-zero:\n{out}");
    assert_ne!(
        parse_probe(&out),
        Verdict::Aligned,
        "mode drift must be detected:\n{out}"
    );

    // Apply corrects the mode (chmod runs outside the content gate) and reports changed.
    let (ok, out) = run_script(&decl.render_apply(), &chown_dir);
    assert!(ok, "apply exited non-zero:\n{out}");
    assert_eq!(
        parse_apply(&out).as_str(),
        "changed",
        "mode correction reports changed:\n{out}"
    );
    assert_eq!(mode_of(&path), "644", "mode restored");

    // Probe aligned again.
    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok);
    assert_eq!(parse_probe(&out), Verdict::Aligned, "re-converged:\n{out}");
}

#[test]
fn owner_drift_is_detected() {
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("owner-drift");
    let path = format!("{dir}/o.conf");
    // Declare an owner no real file on this host will have (detection only —
    // we cannot chown back as non-root, so this proves the probe notices).
    let decl = Declaration::new("rt").file(ManagedFile::new(
        &path,
        "key = value\n",
        "0644",
        "zzz_nope:zzz_nope",
    ));
    let chown_dir = chown_stub_dir();

    // File with correct content + mode, but owned by the test user (not the
    // declared bogus owner).
    fs::write(&path, "key = value\n").expect("write file");
    set_mode(&path, 0o644);

    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok, "probe exited non-zero:\n{out}");
    assert_ne!(
        parse_probe(&out),
        Verdict::Aligned,
        "owner drift must be detected:\n{out}"
    );
}

#[test]
fn rollback_restores_a_command_edited_file() {
    // A command backs up a shared file then rewrites it; rollback must restore
    // it from the .anvil.bak, and a second rollback must be a safe no-op that
    // leaves the file intact (it is never deleted). No GNU stat needed
    // (rollback uses only cp/rm), so this runs on any bash, including macOS dev.
    if !bash_available() {
        eprintln!("skipping: needs bash");
        return;
    }
    let dir = scratch("rb");
    let path = format!("{dir}/shared.conf");
    let bak = format!("{path}.anvil.bak");
    fs::write(&path, "original\n").expect("write original"); // pre-existing distro content

    let decl = Declaration::new("demo")
        .command(ManagedCommand::new(
            "edit shared file",
            "false", // always drift so the converge runs
            format!("[ -f '{bak}' ] || cp -a '{path}' '{bak}'\nprintf 'new\\n' > '{path}'"),
        ))
        .command_file(&path);

    // Apply: no chown in this command, so a clean PATH is fine.
    let empty = scratch("empty-path");
    let (ok, out) = run_script(&decl.render_apply(), &empty);
    assert!(ok, "apply exited non-zero:\n{out}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "new\n");
    assert!(std::path::Path::new(&bak).exists(), "backup taken");

    // Rollback restores the original and consumes the backup.
    let (ok, out) = run_script(&decl.render_rollback(), &empty);
    assert!(ok, "rollback exited non-zero:\n{out}");
    assert!(
        out.contains("restored from backup"),
        "rollback marker:\n{out}"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    assert!(!std::path::Path::new(&bak).exists(), "backup removed");

    // A second rollback is a safe no-op: no backup, file left as restored.
    let (ok, out) = run_script(&decl.render_rollback(), &empty);
    assert!(ok, "second rollback exited non-zero:\n{out}");
    assert!(
        out.contains("nothing to roll back"),
        "idempotent no-op:\n{out}"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
}

#[test]
fn rollback_deletes_a_command_created_file_it_remembered() {
    // A command that creates a file from scratch (no backup possible) records
    // it with __anvil_remember; rollback must delete it, and a file nobody
    // remembered must survive. Uses only bash/grep/rm, so it runs everywhere.
    if !bash_available() {
        eprintln!("skipping: needs bash");
        return;
    }
    let dir = scratch("rb-created");
    let made = format!("{dir}/daemon.json");
    let other = format!("{dir}/other.json");
    fs::write(&other, "{}\n").unwrap();
    let state = format!("ANVIL_STATE_DIR='{dir}/state'\n");
    let decl = Declaration::new("demo")
        .command(ManagedCommand::new(
            "create file",
            "false",
            format!("printf '{{}}' > '{made}'\n__anvil_remember '{made}'"),
        ))
        .command_file(&made)
        .command_file(&other);
    let empty = scratch("empty-path");
    let (ok, out) = run_script(&(state.clone() + &decl.render_apply()), &empty);
    assert!(ok, "apply exited non-zero:\n{out}");
    assert!(std::path::Path::new(&made).exists());

    let (ok, out) = run_script(&(state.clone() + &decl.render_rollback()), &empty);
    assert!(ok, "rollback exited non-zero:\n{out}");
    assert!(out.contains("removed (anvil created it)"), "{out}");
    assert!(
        !std::path::Path::new(&made).exists(),
        "created file deleted"
    );
    assert!(
        std::path::Path::new(&other).exists(),
        "unremembered file kept"
    );
    // Forgotten after deletion: a second rollback is a no-op.
    let (ok, out) = run_script(&(state + &decl.render_rollback()), &empty);
    assert!(ok && !out.contains("removed"), "{out}");
}

#[test]
fn reload_failure_after_validation_reverts_every_write() {
    // Validate passes but the reload fails. Under `set -e` the old guard
    // exited inside the success arm, leaving the new files on disk while the
    // service kept its old config. The revert must run for a failed reload too.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("reload-fail");
    let created = format!("{dir}/new.conf");
    let modified = format!("{dir}/old.conf");
    fs::write(&modified, "original\n").expect("write original");
    let owner = current_owner_group();
    let decl = Declaration::new("rt")
        .file(ManagedFile::new(&created, "new\n", "0644", &owner))
        .file(ManagedFile::new(&modified, "changed\n", "0644", &owner))
        .guarded_reload(ReloadGuard {
            describe: "rt service".into(),
            validate: "true".into(),
            reload: "false".into(),
        });

    let (ok, out) = run_script(&decl.render_apply(), &chown_stub_dir());
    assert!(!ok, "a failed reload must exit non-zero:\n{out}");
    assert!(
        !std::path::Path::new(&created).exists(),
        "created file removed"
    );
    assert_eq!(fs::read_to_string(&modified).unwrap(), "original\n");
}

#[test]
fn unwritable_created_list_does_not_abort_the_revert() {
    // Found on a CI runner: with /var/lib/anvil/created present but
    // read-only, __anvil_forget's mv failed under `set -e` and the revert
    // stopped before restoring modified files.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("forget-ro");
    let state = format!("{dir}/state");
    fs::create_dir_all(&state).expect("mkdir state");
    fs::write(format!("{state}/created"), "").expect("write created list");
    set_mode(&state, 0o555);
    let created = format!("{dir}/new.conf");
    let modified = format!("{dir}/old.conf");
    fs::write(&modified, "original\n").expect("write original");
    let owner = current_owner_group();
    let decl = Declaration::new("rt")
        .file(ManagedFile::new(&created, "new\n", "0644", &owner))
        .file(ManagedFile::new(&modified, "changed\n", "0644", &owner))
        .guarded_reload(ReloadGuard {
            describe: "rt service".into(),
            validate: "true".into(),
            reload: "false".into(),
        });

    let script = format!("ANVIL_STATE_DIR='{state}'\n{}", decl.render_apply());
    let (ok, out) = run_script(&script, &chown_stub_dir());
    set_mode(&state, 0o755);
    assert!(!ok, "a failed reload must exit non-zero:\n{out}");
    assert!(
        !std::path::Path::new(&created).exists(),
        "created file removed"
    );
    assert_eq!(
        fs::read_to_string(&modified).unwrap(),
        "original\n",
        "{out}"
    );
}

#[test]
fn rollback_restores_the_pristine_original_after_two_changes() {
    // A second content change used to overwrite `.anvil.bak` with
    // anvil's own first version, so rollback restored that, not the original.
    // And a file anvil created must still be deleted after it was changed.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("pristine");
    let owner = current_owner_group();
    let chown_dir = chown_stub_dir();
    let state = format!("ANVIL_STATE_DIR='{dir}/state'\n");
    let run = |script: String| run_script(&(state.clone() + &script), &chown_dir);
    let pre = format!("{dir}/pre.conf");
    let new = format!("{dir}/new.conf");
    fs::write(&pre, "distro original\n").unwrap();
    let decl = |v: &str| {
        Declaration::new("rt")
            .file(ManagedFile::new(&pre, v, "0644", &owner))
            .file(ManagedFile::new(&new, v, "0644", &owner))
    };
    for v in ["anvil v1\n", "anvil v2\n"] {
        let (ok, out) = run(decl(v).render_apply());
        assert!(ok, "apply {v:?} failed:\n{out}");
    }
    assert_eq!(
        fs::read_to_string(format!("{pre}.anvil.bak")).unwrap(),
        "distro original\n"
    );
    assert!(
        !std::path::Path::new(&format!("{new}.anvil.bak")).exists(),
        "created file gets no backup"
    );

    let (ok, out) = run(decl("anvil v2\n").render_rollback());
    assert!(ok, "rollback failed:\n{out}");
    assert_eq!(
        fs::read_to_string(&pre).unwrap(),
        "distro original\n",
        "pristine restored"
    );
    assert!(
        !std::path::Path::new(&new).exists(),
        "anvil-created file deleted"
    );
}

#[test]
fn symlinked_managed_path_is_refused_before_anything_is_written() {
    // The write followed the link while `cp -a` backed up the link
    // itself, so rollback could never restore the target's bytes. A symlinked
    // path is refused up front: probe reports drift, apply fails untouched.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("symlink");
    let owner = current_owner_group();
    let first = format!("{dir}/first.conf");
    let target = format!("{dir}/target.conf");
    let link = format!("{dir}/link.conf");
    fs::write(&target, "target original\n").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let decl = Declaration::new("rt")
        .file(ManagedFile::new(&first, "new\n", "0644", &owner))
        .file(ManagedFile::new(&link, "managed\n", "0644", &owner));
    let chown_dir = chown_stub_dir();
    let is_link = |p: &str| fs::symlink_metadata(p).unwrap().file_type().is_symlink();

    let (ok, out) = run_script(&decl.render_probe(), &chown_dir);
    assert!(ok, "probe failed:\n{out}");
    assert!(matches!(parse_probe(&out), Verdict::Drifted(_)), "{out}");
    assert!(out.contains("is a symlink"), "{out}");

    let (ok, out) = run_script(&decl.render_apply(), &chown_dir);
    assert!(!ok, "apply must refuse a symlinked path:\n{out}");
    assert!(out.contains("FAILED:") && out.contains(&link), "{out}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "target original\n");
    assert!(is_link(&link));
    assert!(
        !std::path::Path::new(&first).exists(),
        "nothing written before the refusal"
    );
    assert!(!std::path::Path::new(&format!("{link}.anvil.bak")).exists());

    let state = format!("ANVIL_STATE_DIR='{dir}/state'\n");
    let (ok, out) = run_script(&(state + &decl.render_rollback()), &chown_dir);
    assert!(ok, "rollback failed:\n{out}");
    assert!(is_link(&link), "rollback leaves an unmanaged symlink alone");
}

#[test]
fn guard_failure_reverts_a_mode_only_correction() {
    // chmod/chown on a content-correct file was in neither __creates nor
    // __reverts, so a failed guard left this run's mode change applied.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("guard-mode");
    let path = format!("{dir}/f.conf");
    fs::write(&path, "same\n").unwrap();
    set_mode(&path, 0o600);
    let decl = Declaration::new("rt")
        .file(ManagedFile::new(
            &path,
            "same\n",
            "0644",
            current_owner_group(),
        ))
        .guarded_reload(ReloadGuard {
            describe: "rt service".into(),
            validate: "false".into(),
            reload: "true".into(),
        });

    let (ok, out) = run_script(&decl.render_apply(), &chown_stub_dir());
    assert!(!ok, "a failed guard must exit non-zero:\n{out}");
    assert_eq!(mode_of(&path), "600", "mode change reverted:\n{out}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "same\n");
}

#[test]
fn rollback_never_deletes_a_preexisting_file_anvil_only_chmodded() {
    // Content already right, only the mode differed. Apply used to take
    // no backup, so rollback treated the distro file as anvil-created and
    // deleted it. Now the first change keeps a backup and rollback restores
    // the original mode; without a backup or a creation record it never deletes.
    if !ready() {
        eprintln!("skipping: needs bash + GNU stat");
        return;
    }
    let dir = scratch("chmod-only");
    let owner = current_owner_group();
    let chown_dir = chown_stub_dir();
    let state = format!("ANVIL_STATE_DIR='{dir}/state'\n");
    let run = |script: String| run_script(&(state.clone() + &script), &chown_dir);
    let path = format!("{dir}/distro.conf");
    fs::write(&path, "same\n").unwrap();
    set_mode(&path, 0o600);
    let decl = Declaration::new("rt").file(ManagedFile::new(&path, "same\n", "0644", &owner));

    let (ok, out) = run(decl.render_apply());
    assert!(ok, "apply failed:\n{out}");
    assert_eq!(mode_of(&path), "644");
    let (ok, out) = run(decl.render_rollback());
    assert!(ok, "rollback failed:\n{out}");
    assert!(
        std::path::Path::new(&path).exists(),
        "distro file must survive rollback:\n{out}"
    );
    assert_eq!(mode_of(&path), "600", "original mode restored");

    // Legacy host: changed earlier without a backup and no creation record.
    set_mode(&path, 0o644);
    let (ok, out) = run(decl.render_rollback());
    assert!(ok && out.contains("left in place"), "{out}");
    assert!(std::path::Path::new(&path).exists());
}
