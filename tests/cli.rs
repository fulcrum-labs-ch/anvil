//! CLI parsing / exit-code integration tests (R104) — no host required.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_anvil")
}

fn tmpdir() -> PathBuf {
    // Fixtures live under target/tmp (provided by cargo for integration
    // tests): wiped by `cargo clean` and never accumulating in the system
    // TMPDIR across runs. The per-pid dir is additionally removed once per
    // run in case a pid is recycled.
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let dir = base.join(format!("anvil-cli-{}", std::process::id()));
    static CLEAN: std::sync::Once = std::sync::Once::new();
    CLEAN.call_once(|| {
        // nextest runs each test in its own process: drop earlier runs' dirs
        // too (some fixtures are world-writable on purpose). Only dirs whose
        // pid is gone, so parallel test processes keep theirs.
        if let Ok(entries) = std::fs::read_dir(&base) {
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if let Some(pid) = name.strip_prefix("anvil-cli-") {
                    let alive = std::process::Command::new("kill")
                        .args(["-0", pid])
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success());
                    if !alive || pid == std::process::id().to_string() {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
            }
        }
    });
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// --- fake ssh transport --------------------------------------------------
//
// The engine shells out to `ssh` found on PATH (src/ssh.rs), so a shim
// script first on PATH makes transport behavior fully hermetic: no DNS, no
// network, deterministic timing. Tests set PATH on the spawned anvil
// process only (no global env mutation).

/// Write an executable fake `ssh` into a fresh dir under `test`'s namespace
/// and return the PATH value that puts it first. The shim always drains
/// stdin first — anvil pipes the rendered script into it, and exiting with
/// the pipe unread races the writer.
fn fake_ssh(test: &str, body: &str) -> std::ffi::OsString {
    let dir = tmpdir().join(format!("shim-{test}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let shim = dir.join("ssh");
    std::fs::write(
        &shim,
        format!("#!/usr/bin/env bash\ncat >/dev/null\n{body}\n"),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&shim).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&shim, perms).unwrap();
    let orig = std::env::var_os("PATH").unwrap_or_default();
    let paths: Vec<PathBuf> = std::iter::once(dir)
        .chain(std::env::split_paths(&orig))
        .collect();
    std::env::join_paths(paths).unwrap()
}

/// A shim refusing every connection, like an unreachable or firewalled host.
fn refusing_ssh(test: &str) -> std::ffi::OsString {
    fake_ssh(
        test,
        "echo 'ssh: connect to host 10.0.0.9 port 22: Connection refused' >&2\nexit 255",
    )
}

// --- plugin / custom-profile fixtures -----------------------------------
//
// Plugins and custom profiles are discovered under the user's config home;
// tests isolate that per-test by pointing XDG_CONFIG_HOME at a temp dir on
// the spawned process only (no global env mutation).

/// A fresh, isolated config home for one test.
fn config_home(test: &str) -> PathBuf {
    let dir = tmpdir().join(format!("xdg-{test}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn set_mode(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Write a file with deterministic (secure) permissions.
fn write_secure(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    set_mode(path, 0o644);
}

/// Create `<xdg>/anvil/plugins/<name>/` with a manifest, apply.sh, and an
/// optional check.sh, all with secure modes.
fn make_plugin(
    xdg: &Path,
    name: &str,
    manifest: &str,
    apply: &str,
    check: Option<&str>,
) -> PathBuf {
    let dir = xdg.join("anvil").join("plugins").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    // Discovery checks the plugin dir itself, not the ancestors we just made.
    set_mode(&dir, 0o755);
    write_secure(&dir.join("plugin.toml"), manifest);
    write_secure(&dir.join("apply.sh"), apply);
    if let Some(c) = check {
        write_secure(&dir.join("check.sh"), c);
    }
    dir
}

/// Create `<xdg>/anvil/profiles/<name>.toml` with secure modes.
fn make_profile(xdg: &Path, name: &str, body: &str) -> PathBuf {
    let dir = xdg.join("anvil").join("profiles");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.toml"));
    write_secure(&path, body);
    path
}

fn anvil_with_home(xdg: &Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .env("XDG_CONFIG_HOME", xdg)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn validate_accepts_a_good_config() {
    let dir = tmpdir();
    let cfg = dir.join("good.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
            [firewall]
            [updates]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success(), "expected exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("config OK"));
    // updates must be scheduled last in the reported order.
    assert!(stdout.contains("-> updates"));
}

#[test]
fn validate_rejects_a_bad_config() {
    let dir = tmpdir();
    let cfg = dir.join("bad.toml");
    // Missing required host.
    std::fs::write(&cfg, "[sshd]\n").unwrap();

    let out = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "invalid config must exit non-zero"
    );
}

#[test]
fn validate_rejects_tailnet_only_ssh_without_firewall() {
    let dir = tmpdir();
    let cfg = dir.join("tailnet.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"h\"\nuser = \"u\"\n[tailscale]\ntailnet_only_ssh = true\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("tailscale.tailnet_only_ssh = true requires [firewall]"),
        "{stderr}"
    );
}

#[test]
fn init_full_output_validates() {
    let dir = tmpdir();
    let cfg = dir.join("generated.toml");

    let init = Command::new(bin())
        .args(["init", "--full", "-o"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(init.status.success());

    let validate = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .env("RESTIC_PASSWORD", "test-only") // [restic] references ${RESTIC_PASSWORD}
        .output()
        .unwrap();
    assert!(
        validate.status.success(),
        "generated config should validate: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
}

#[test]
fn apply_dry_run_renders_scripts_without_connecting() {
    let dir = tmpdir();
    let cfg = dir.join("dry.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "unreachable.invalid"
            user = "admin"
            [sshd]
            [users]
            create = [{ name = "deploy", sudo = true }]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["apply", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("module: sshd"));
    assert!(stdout.contains("sshd -t"));
    assert!(stdout.contains("/etc/sudoers.d/deploy"));
}

#[test]
fn apply_dry_run_honors_output_format() {
    // `apply --dry-run --output json` must honor the format (matching
    // `rollback --dry-run`), not ignore it and print the human banner.
    let dir = tmpdir();
    let cfg = dir.join("dry-json.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["apply", "--dry-run", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON, not human text");
    let sshd = v
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["module"] == "sshd")
        .expect("sshd dry-run doc");
    assert_eq!(sshd["status"], "dry-run");
    assert!(sshd["script"].as_str().unwrap().contains("sshd -t"));
    // The human dry-run banner must not leak into machine output.
    assert!(!String::from_utf8_lossy(&out.stdout).contains("# dry-run: resolved order"));
}

#[test]
fn markdown_output_is_rejected_for_non_report_commands() {
    // `--output markdown` used to silently fall through to JSON for
    // every command but `report`. Only `report` offers it now, so clap rejects
    // it at parse time (exit 2) and lists the valid values.
    let cfg = tmpdir().join("md.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[sshd]\n",
    )
    .unwrap();
    let path = refusing_ssh("md-status");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["status", "--output", "markdown", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "markdown on status is a usage error, not silently JSON"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("markdown"), "mentions the value:\n{stderr}");
    assert!(
        stderr.contains("ndjson"),
        "lists the valid values:\n{stderr}"
    );
    // `report` still takes it (its default).
    let help = Command::new(bin())
        .args(["report", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("markdown"));
    let help = Command::new(bin())
        .args(["status", "--help"])
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains("markdown"));
}

#[test]
fn report_ndjson_is_one_compact_line() {
    // `report --output ndjson` must emit one compact JSON object per
    // line, not the pretty multi-line blob it used to print.
    let cfg = tmpdir().join("rep-ndjson.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["report", "--output", "ndjson", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim_end_matches('\n');
    assert!(
        !trimmed.contains('\n'),
        "ndjson must be a single compact line, not pretty:\n{stdout}"
    );
    let _: serde_json::Value = serde_json::from_str(trimmed).expect("valid compact JSON object");
}

#[test]
fn timeout_kills_a_stalled_ssh_probe() {
    // --timeout must kill a probe that never returns, instead of hanging
    // anvil forever — critical under --parallel, where one stuck host would
    // hold a worker. The shim drains stdin then sleeps: `exec` so the pid we
    // signal *is* the sleep, and a finite sleep so an escaped shim reaps itself
    // rather than idling until reboot. Never busy-loop here — a shim that
    // outlives the test then burns a core indefinitely.
    let cfg = tmpdir().join("timeout.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[sshd]\n",
    )
    .unwrap();
    let path = fake_ssh("timeout", "exec sleep 300");
    let start = std::time::Instant::now();
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["status", "--timeout", "1", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let elapsed = start.elapsed();
    assert!(
        !out.status.success(),
        "a timed-out probe must fail, not hang forever"
    );
    // Killed at ~1s; nowhere near the indefinite hang it used to be.
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "took {elapsed:?}"
    );
}

#[test]
fn profiles_list_shows_builtins() {
    let out = Command::new(bin())
        .args(["profiles", "list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    for p in ["minimal", "cis-level1", "web-server", "ci-runner"] {
        assert!(stdout.contains(p), "missing profile {p}");
    }
}

#[test]
fn plugins_list_with_no_plugins_is_calm() {
    let xdg = config_home("plugins-empty");
    let out = anvil_with_home(&xdg, &["plugins", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("no plugins discovered"), "{stdout}");
}

#[test]
fn plugins_list_shows_valid_and_skipped_with_reason() {
    let xdg = config_home("plugins-list");
    make_plugin(
        &xdg,
        "backup-agent",
        "name = \"backup-agent\"\nsection = \"backup_agent\"\norder = 42\nbefore = [\"updates\"]\nafter = [\"sshd\"]\n",
        "echo apply {{target}}\n",
        Some("true\n"),
    );
    // Broken neighbor: manifest name does not match its directory.
    make_plugin(
        &xdg,
        "broken",
        "name = \"other\"\nsection = \"broken_cfg\"\n",
        "echo x\n",
        None,
    );

    let out = anvil_with_home(&xdg, &["plugins", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Valid plugin: name, section, order hints, status, path.
    assert!(stdout.contains("backup-agent"), "{stdout}");
    assert!(stdout.contains("section=backup_agent"), "{stdout}");
    assert!(stdout.contains("order=42"), "{stdout}");
    assert!(stdout.contains("before=updates"), "{stdout}");
    assert!(stdout.contains("after=sshd"), "{stdout}");
    assert!(stdout.contains("valid"), "{stdout}");
    // Skipped plugin: status + reason.
    assert!(stdout.contains("broken"), "{stdout}");
    assert!(stdout.contains("skipped"), "{stdout}");
    assert!(stdout.contains("does not match"), "{stdout}");
}

#[test]
fn plugins_list_json_is_machine_readable() {
    let xdg = config_home("plugins-json");
    make_plugin(
        &xdg,
        "pg-tune",
        "name = \"pg-tune\"\nsection = \"pg_tune\"\n",
        "echo tuned\n",
        None,
    );
    let world_writable = make_plugin(
        &xdg,
        "loose",
        "name = \"loose\"\nsection = \"loose_cfg\"\n",
        "echo x\n",
        None,
    );
    set_mode(&world_writable, 0o777);

    let out = anvil_with_home(&xdg, &["plugins", "list", "--output", "json"]);
    // Leave nothing world-writable behind ([filesystem] scans hosts running the suite).
    set_mode(&world_writable, 0o755);
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("plugins list --output json emits valid JSON");
    let arr = v.as_array().expect("array of plugins");
    assert_eq!(arr.len(), 2);
    let by_name = |n: &str| arr.iter().find(|p| p["name"] == n).unwrap().clone();
    let ok = by_name("pg-tune");
    assert_eq!(ok["status"], "valid");
    assert_eq!(ok["section"], "pg_tune");
    let bad = by_name("loose");
    assert_eq!(bad["status"], "skipped");
    assert!(
        bad["reason"].as_str().unwrap().contains("writable"),
        "{bad}"
    );
}

#[test]
fn plugin_section_enables_plugin_through_the_pipeline() {
    // End-to-end: a plugin bound to [backup_agent] no longer trips
    // deny_unknown_fields, appears as plugin::backup-agent in the resolved
    // order BEFORE updates, and its dry-run script carries the substituted,
    // shell-escaped config value.
    let xdg = config_home("plugin-e2e");
    make_plugin(
        &xdg,
        "backup-agent",
        "name = \"backup-agent\"\nsection = \"backup_agent\"\n",
        "install-backup --target {{target}}\n",
        Some("test -x /usr/local/bin/backup\n"),
    );
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
            [updates]
            [backup_agent]
            target = "/srv/it's data"
        "#,
    );

    let validate = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert!(
        validate.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let stdout = String::from_utf8_lossy(&validate.stdout);
    assert!(stdout.contains("config OK"), "{stdout}");
    assert!(
        stdout.contains("plugin::backup-agent -> updates"),
        "plugin ordered before updates: {stdout}"
    );

    let dry = anvil_with_home(&xdg, &["apply", "--dry-run", "-c", cfg.to_str().unwrap()]);
    assert!(dry.status.success());
    let script = String::from_utf8_lossy(&dry.stdout);
    assert!(script.contains("module: plugin::backup-agent"), "{script}");
    // The config value arrives single-quoted with the embedded quote escaped.
    assert!(
        script.contains("install-backup --target '/srv/it'\\''s data'"),
        "substituted + escaped: {script}"
    );
}

#[test]
fn undefined_plugin_placeholder_fails_loudly() {
    let xdg = config_home("plugin-undef");
    make_plugin(
        &xdg,
        "backup-agent",
        "name = \"backup-agent\"\nsection = \"backup_agent\"\n",
        "install-backup --target {{target}}\n",
        None,
    );
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [backup_agent]
            wrong_key = "x"
        "#,
    );
    let out = anvil_with_home(&xdg, &["apply", "--dry-run", "-c", cfg.to_str().unwrap()]);
    assert!(!out.status.success(), "undefined {{{{VAR}}}} must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("target"), "names the variable: {stderr}");
}

#[test]
fn unbound_section_still_fails_with_plugins_present() {
    let xdg = config_home("plugin-typo");
    make_plugin(
        &xdg,
        "backup-agent",
        "name = \"backup-agent\"\nsection = \"backup_agent\"\n",
        "echo x\n",
        None,
    );
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [backup_agnet]
            target = "x"
        "#,
    );
    let out = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1), "typo section must be rejected");
    // Errors are diagnostics: stderr only (R100 stream contract).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("backup_agnet"), "{stderr}");
}

#[test]
fn profiles_list_shows_customs_and_json() {
    let xdg = config_home("profiles-list");
    make_profile(&xdg, "site-baseline", "[sshd]\n[updates]\n");

    let human = anvil_with_home(&xdg, &["profiles", "list"]);
    assert!(human.status.success());
    let stdout = String::from_utf8_lossy(&human.stdout);
    for p in [
        "minimal",
        "cis-level1",
        "web-server",
        "ci-runner",
        "site-baseline",
    ] {
        assert!(stdout.contains(p), "missing profile {p}: {stdout}");
    }

    let json = anvil_with_home(&xdg, &["profiles", "list", "--output", "json"]);
    assert!(json.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("profiles list --output json emits valid JSON");
    let arr = v.as_array().unwrap();
    assert!(arr
        .iter()
        .any(|p| p["name"] == "minimal" && p["source"] == "builtin"));
    let custom = arr.iter().find(|p| p["name"] == "site-baseline").unwrap();
    assert_eq!(custom["source"], "custom");
    assert!(custom["path"]
        .as_str()
        .unwrap()
        .ends_with("site-baseline.toml"));
}

#[test]
fn custom_profile_resolves_via_cli_and_rejects_insecure_files() {
    let xdg = config_home("profile-use");
    let profile_path = make_profile(&xdg, "site", "[sshd]\n[firewall]\n[updates]\n");
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            profile = "site"
            [host]
            address = "10.0.0.1"
            user = "admin"
        "#,
    );

    let ok = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert!(
        ok.status.success(),
        "custom profile must load: {}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let stdout = String::from_utf8_lossy(&ok.stdout);
    assert!(stdout.contains("-> updates"), "{stdout}");

    // The same profile file, made world-writable, must be refused.
    set_mode(&profile_path, 0o666);
    let bad = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    set_mode(&profile_path, 0o644);
    assert_eq!(bad.status.code(), Some(1));
    // Errors are diagnostics: stderr only (R100 stream contract).
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("writable"), "{stderr}");
}

#[test]
fn unknown_profile_error_lists_available_including_customs() {
    let xdg = config_home("profile-unknown");
    make_profile(&xdg, "site", "[sshd]\n");
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            profile = "does-not-exist"
            [host]
            address = "10.0.0.1"
            user = "admin"
        "#,
    );
    let out = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    // Errors are diagnostics: stderr only (R100 stream contract).
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("minimal"), "lists builtins: {stderr}");
    assert!(stderr.contains("site"), "lists customs: {stderr}");
}

#[test]
fn init_rejects_an_unknown_profile_and_accepts_customs() {
    let xdg = config_home("init-profile");
    make_profile(&xdg, "site", "[sshd]\n");

    let bad = anvil_with_home(&xdg, &["init", "--profile", "x\"\n[evil]"]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(bad.stdout.is_empty(), "no TOML emitted on refusal");
    let stderr = String::from_utf8_lossy(&bad.stderr);
    assert!(stderr.contains("not a known profile"), "{stderr}");
    assert!(
        stderr.contains("minimal") && stderr.contains("site"),
        "{stderr}"
    );

    for name in ["cis-level1", "site"] {
        let ok = anvil_with_home(&xdg, &["init", "--profile", name]);
        assert!(ok.status.success(), "{name}");
        assert!(String::from_utf8_lossy(&ok.stdout).starts_with(&format!("profile = \"{name}\"\n")));
    }
}

#[test]
fn report_check_shows_the_failing_plugin_that_drives_the_exit_code() {
    let xdg = config_home("report-plugin");
    make_plugin(
        &xdg,
        "backup-agent",
        "name = \"backup-agent\"\nsection = \"backup_agent\"\n",
        "true\n",
        Some("true\n"),
    );
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        "[host]\naddress = \"10.0.0.9\"\nuser = \"admin\"\n[backup_agent]\n",
    );
    let run = |output: &str| {
        Command::new(bin())
            .env("XDG_CONFIG_HOME", &xdg)
            .env("PATH", refusing_ssh("report-plugin"))
            .args(["report", "--check", "--output", output, "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };

    let human = run("human");
    assert_eq!(human.status.code(), Some(1), "plugin probe failure fails");
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(
        stdout
            .lines()
            .any(|l| l.contains("plugin::backup-agent") && l.contains("failed")),
        "the failing plugin is visible: {stdout}"
    );

    let json = run("json");
    assert_eq!(json.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    let plugin = v["categories"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["modules"].as_array().unwrap().clone())
        .find(|m| m["module"] == "plugin::backup-agent")
        .expect("plugin row");
    assert_eq!(plugin["drift"], "failed");
    assert_eq!(v["enabled"], 0, "plugins stay out of CIS coverage counts");
}

#[test]
fn report_markdown_lists_cis_coverage() {
    let dir = tmpdir();
    let cfg = dir.join("report.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
            [firewall]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["report", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CIS Coverage Report"));
    assert!(stdout.contains("| Category | Module | Enabled |"));
    assert!(stdout.contains("sshd"));
}

#[test]
fn report_json_is_machine_readable() {
    let dir = tmpdir();
    let cfg = dir.join("report-json.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["report", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("report --output json emits valid JSON");
    assert_eq!(v["enabled"], serde_json::json!(1));
    assert!(v["categories"].is_array());
}

#[test]
fn apply_skips_dependents_after_a_failure() {
    // Two-phase apply with failure propagation: the sshd probe fails (fake
    // ssh refuses every connection), so firewall (depends on sshd/ssh_crypto)
    // and updates (depends on everything) must be skipped for safety — and
    // the run must exit non-zero.
    let dir = tmpdir();
    let cfg = dir.join("two-phase.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
            [firewall]
            [updates]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .env("PATH", refusing_ssh("apply-fail"))
        .args(["apply", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "failures must exit non-zero");

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("apply --output json emits valid JSON");
    let modules = v[0]["modules"].as_array().expect("per-module results");
    let status_of = |id: &str| -> String {
        modules
            .iter()
            .find(|m| m["module"] == id)
            .unwrap_or_else(|| panic!("no result for {id}"))["status"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(status_of("sshd"), "failed");
    assert_eq!(status_of("firewall"), "skipped");
    assert_eq!(status_of("updates"), "skipped");
    // A skipped module must state why.
    let firewall = modules.iter().find(|m| m["module"] == "firewall").unwrap();
    assert!(firewall["reason"]
        .as_str()
        .expect("skip reason present")
        .contains("sshd"));
}

#[test]
fn check_reports_failures_with_nonzero_exit() {
    let dir = tmpdir();
    let cfg = dir.join("check-json.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .env("PATH", refusing_ssh("check-fail"))
        .args(["check", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("check --output json emits valid JSON");
    assert_eq!(v[0]["modules"][0]["module"], "sshd");
    assert_eq!(v[0]["modules"][0]["status"], "failed");
}

#[test]
fn check_and_apply_succeed_against_a_converged_host() {
    // A host whose every probe reports alignment: check and apply must both
    // exit 0 with the module ok, and two-phase apply must not run a converge
    // (the shim counts invocations — one probe each, nothing more).
    let dir = tmpdir();
    let cfg = dir.join("converged.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    for cmd in ["check", "apply"] {
        let path = fake_ssh(
            &format!("converged-{cmd}"),
            "echo 'OK: aligned'\ncount=\"$(dirname \"$0\")/calls\"\n\
             printf x >> \"$count\"\nexit 0",
        );
        let out = Command::new(bin())
            .env("PATH", &path)
            .args([cmd, "--output", "json", "-c"])
            .arg(&cfg)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{cmd} must succeed");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let module = &v[0]["modules"][0];
        assert_eq!(module["module"], "sshd");
        match cmd {
            // Unified JSON schema: `status` is always present (check and apply).
            "check" => assert_eq!(module["status"], "aligned"),
            _ => assert_eq!(module["status"], "ok", "aligned apply is ok"),
        }
        // Exactly one ssh call: the probe. Apply must skip its second phase.
        let calls =
            std::fs::read_to_string(tmpdir().join(format!("shim-converged-{cmd}")).join("calls"))
                .unwrap();
        assert_eq!(calls.len(), 1, "{cmd}: exactly one probe, no converge");
    }
}

#[test]
fn status_and_check_disagree_on_drift_exit_codes_by_design() {
    // A drifted-but-reachable host: `check` treats drift as actionable
    // (exit 1), `status` as informational (exit 0 — only probe *failures*
    // go non-zero there). Both must name the drift and its reason in JSON.
    let dir = tmpdir();
    let cfg = dir.join("drift-status.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    for (cmd, want_exit) in [("check", 1), ("status", 0)] {
        let path = fake_ssh(&format!("drift-{cmd}"), "echo 'DRIFTED: forced'\nexit 0");
        let out = Command::new(bin())
            .env("PATH", &path)
            .args([cmd, "--output", "json", "-c"])
            .arg(&cfg)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(want_exit), "{cmd} exit code");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let module = &v[0]["modules"][0];
        assert_eq!(module["module"], "sshd");
        assert_eq!(module["status"], "drifted", "{cmd} reports the drift");
        assert_eq!(module["reasons"][0], "forced", "{cmd} carries the reason");
    }
}

#[test]
fn apply_converges_a_drifted_host_and_reports_changed() {
    // End-to-end two-phase apply against a drifted host: the first ssh call
    // (probe) reports drift, the second (converge) reports the change; the
    // run exits 0 and the module status is `changed`.
    let dir = tmpdir();
    let cfg = dir.join("drifted.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    let path = fake_ssh(
        "drifted-apply",
        "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\n\
         if [ \"$(wc -c < \"$count\")\" -le 1 ]; then\n\
         echo 'DRIFTED: forced by fake ssh'\nelse\n\
         echo 'CHANGED: forced by fake ssh'\nfi\nexit 0",
    );
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "changed apply exits 0");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["module"], "sshd");
    assert_eq!(v[0]["modules"][0]["status"], "changed");
    assert_eq!(
        v[0]["modules"][0]["drift"], "drifted",
        "two-phase apply records why it converged"
    );
    // Exactly two ssh calls: probe then converge.
    let calls = std::fs::read_to_string(tmpdir().join("shim-drifted-apply").join("calls")).unwrap();
    assert_eq!(calls.len(), 2, "probe then converge, nothing else");
}

/// Config used by the single-host shim tests below.
fn one_host_cfg(dir: &Path, name: &str) -> PathBuf {
    let cfg = dir.join(name);
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();
    cfg
}

#[test]
fn apply_no_check_skips_the_probe_and_records_no_drift() {
    let cfg = one_host_cfg(&tmpdir(), "no-check.toml");
    let path = fake_ssh(
        "no-check",
        "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\necho 'CHANGED: forced'\nexit 0",
    );
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--no-check", "--output", "json", "-c"])
        .arg(cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["status"], "changed");
    assert!(
        v[0]["modules"][0].get("drift").is_none(),
        "--no-check ran no probe, so it must not claim drift: {v}"
    );
    let calls = std::fs::read_to_string(tmpdir().join("shim-no-check").join("calls")).unwrap();
    assert_eq!(calls.len(), 1, "converge only — no probe under --no-check");
}

#[test]
fn apply_reports_a_failed_converge_with_detail() {
    // Probe says drifted, converge reports FAILED: the run must exit 1 and
    // carry a failure detail for the operator.
    let cfg = one_host_cfg(&tmpdir(), "converge-fail.toml");
    let path = fake_ssh(
        "converge-fail",
        "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\n\
         if [ \"$(wc -c < \"$count\")\" -le 1 ]; then\n\
         echo 'DRIFTED: forced'\nelse\n\
         echo 'FAILED: converge exploded'\nfi\nexit 0",
    );
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--output", "json", "-c"])
        .arg(cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "failed converge exits non-zero");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["status"], "failed");
    assert_eq!(
        v[0]["modules"][0]["reason"], "FAILED: converge exploded",
        "the reason is the script's FAILED: line, not `exit 0`: {v}"
    );
    assert_eq!(
        v[0]["modules"][0]["drift"], "drifted",
        "the probe verdict survives the failed converge: {v}"
    );
}

#[test]
fn apply_verbose_human_indents_module_output_six_spaces() {
    let cfg = one_host_cfg(&tmpdir(), "verbose.toml");
    let shim_body = "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\n\
         if [ \"$(wc -c < \"$count\")\" -le 1 ]; then\n\
         echo 'DRIFTED: forced'\nelse\n\
         echo 'CHANGED: forced'\nfi\nexit 0";

    let verbose = Command::new(bin())
        .env("PATH", fake_ssh("verbose-on", shim_body))
        .args(["apply", "--verbose", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(verbose.status.success());
    let stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(
        stdout.contains("\n      CHANGED: forced"),
        "verbose shows module output indented six spaces:\n{stdout}"
    );

    let quiet = Command::new(bin())
        .env("PATH", fake_ssh("verbose-off", shim_body))
        .args(["apply", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(quiet.status.success());
    let stdout = String::from_utf8_lossy(&quiet.stdout);
    assert!(
        !stdout.contains("      CHANGED"),
        "module output only under --verbose:\n{stdout}"
    );
}

#[test]
fn diff_classifies_absent_files_as_create() {
    // The shim answers the read-files script with nothing, so every managed
    // path reads as absent: JSON classifies `create` with a real diff body,
    // human mode prints the diff indented, and both exit 0.
    let cfg = one_host_cfg(&tmpdir(), "diff-create.toml");

    let out = Command::new(bin())
        .env("PATH", fake_ssh("diff-json", "exit 0"))
        .args(["diff", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let files = v[0]["files"].as_array().expect("files array");
    assert!(!files.is_empty());
    for f in files {
        assert_eq!(f["change"], "create", "{f}");
        assert!(
            f["diff"].as_str().unwrap().contains("+++ b/"),
            "diff body present: {f}"
        );
    }

    let human = Command::new(bin())
        .env("PATH", fake_ssh("diff-human", "exit 0"))
        .args(["diff", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(human.status.success());
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("(sshd):"), "{stdout}");
    assert!(
        stdout.contains("\n      +++ b/"),
        "diff body indented six spaces:\n{stdout}"
    );
}

#[test]
fn diff_counts_unreadable_hosts_as_failures() {
    let cfg = one_host_cfg(&tmpdir(), "diff-fail.toml");
    let out = Command::new(bin())
        .env("PATH", refusing_ssh("diff-fail"))
        .args(["diff", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "unreadable host is a failure");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v[0]["error"].is_string(), "error is reported: {v}");
}

#[test]
fn score_parses_the_index_and_applies_the_threshold() {
    let cfg = one_host_cfg(&tmpdir(), "score.toml");
    let body = "echo 'hardening_index=66'\nexit 0";

    for (threshold, want_exit, want_pass) in [("50", 0, true), ("80", 1, false)] {
        let out = Command::new(bin())
            .env("PATH", fake_ssh(&format!("score-{threshold}"), body))
            .args(["score", "--threshold", threshold, "--output", "json", "-c"])
            .arg(&cfg)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(want_exit), "threshold {threshold}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(v[0]["index"], 66);
        assert_eq!(v[0]["pass"], want_pass);
    }

    // Output with no recognizable index never passes.
    let out = Command::new(bin())
        .env(
            "PATH",
            fake_ssh("score-none", "echo 'no index here'\nexit 0"),
        )
        .args(["score", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v[0]["index"].is_null());
    assert_eq!(v[0]["pass"], false);
    assert!(v[0]["error"].is_string(), "{v}");
}

#[test]
fn rollback_runs_remotely_and_reports_per_module_status() {
    let cfg = one_host_cfg(&tmpdir(), "rollback-live.toml");

    let ok = Command::new(bin())
        .env(
            "PATH",
            fake_ssh("rollback-ok", "echo 'CHANGED: restored'\nexit 0"),
        )
        .args(["rollback", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["module"], "sshd");
    assert_eq!(v[0]["modules"][0]["status"], "changed");

    let bad = Command::new(bin())
        .env("PATH", refusing_ssh("rollback-bad"))
        .args(["rollback", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1), "unreachable rollback fails");
    let v: serde_json::Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["status"], "failed");
    assert_eq!(
        v[0]["modules"][0]["reason"],
        "ssh: connect to host 10.0.0.9 port 22: Connection refused"
    );
}

#[test]
fn rollback_failure_carries_the_scripts_reason() {
    // A rollback that reports FAILED: on stdout (exit 0) names it.
    let cfg = one_host_cfg(&tmpdir(), "rollback-reason.toml");
    let path = fake_ssh("rollback-reason", "echo 'FAILED: no backup found'\nexit 0");
    let run = |fmt: &str| {
        Command::new(bin())
            .env("PATH", &path)
            .args(["rollback", "--output", fmt, "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let json = run("json");
    assert_eq!(json.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v[0]["modules"][0]["reason"], "FAILED: no backup found");
    let human = String::from_utf8_lossy(&run("human").stdout).into_owned();
    assert!(
        human.contains("sshd           failed (FAILED: no backup found)"),
        "{human}"
    );
}

#[test]
fn report_check_probes_hosts_and_fails_on_probe_errors() {
    let cfg = one_host_cfg(&tmpdir(), "report-check.toml");

    let ok = Command::new(bin())
        .env("PATH", fake_ssh("report-ok", "echo 'OK: aligned'\nexit 0"))
        .args(["report", "--check", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(ok.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&ok.stdout).unwrap();
    let sshd = v["categories"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|c| c["modules"].as_array().unwrap().clone())
        .find(|m| m["module"] == "sshd")
        .expect("sshd row");
    assert_eq!(sshd["drift"], "aligned");

    let bad = Command::new(bin())
        .env("PATH", refusing_ssh("report-bad"))
        .args(["report", "--check", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1), "probe failures fail the report");
}

#[test]
fn apply_fans_out_over_every_host_in_config_order() {
    // Two [[hosts]] with --parallel 2: one report per host, in config order,
    // each probed independently through the shim.
    let dir = tmpdir();
    let cfg = dir.join("fleet.toml");
    std::fs::write(
        &cfg,
        r#"
            [[hosts]]
            address = "alpha"
            user = "admin"
            [[hosts]]
            address = "beta"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();
    let path = fake_ssh(
        "fleet",
        "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\necho 'OK: aligned'\nexit 0",
    );
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--parallel", "2", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let hosts: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["host"].as_str().unwrap())
        .collect();
    assert_eq!(hosts, ["alpha", "beta"], "per-host docs in config order");
    for h in v.as_array().unwrap() {
        assert_eq!(h["modules"][0]["status"], "ok", "{h}");
    }
    let calls = std::fs::read_to_string(tmpdir().join("shim-fleet").join("calls")).unwrap();
    assert_eq!(calls.len(), 2, "one probe per host");
}

fn fleet_cfg() -> PathBuf {
    let dir = tmpdir();
    let cfg = dir.join("fleet-filter.toml");
    std::fs::write(
        &cfg,
        r#"
            [[hosts]]
            address = "alpha"
            user = "admin"
            [[hosts]]
            address = "beta"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();
    cfg
}

fn fleet_shim(tag: &str) -> std::ffi::OsString {
    fake_ssh(
        tag,
        "count=\"$(dirname \"$0\")/calls\"\nprintf x >> \"$count\"\necho 'OK: aligned'\nexit 0",
    )
}

fn host_addresses(out: &std::process::Output) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    v.as_array()
        .unwrap()
        .iter()
        .map(|h| h["host"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn host_filter_selects_one_host() {
    // --host targets a subset without editing the config.
    let cfg = fleet_cfg();
    let path = fleet_shim("hf-host");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--host", "alpha", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        host_addresses(&out),
        ["alpha"],
        "only the selected host runs"
    );
    let calls = std::fs::read_to_string(tmpdir().join("shim-hf-host").join("calls")).unwrap();
    assert_eq!(calls.len(), 1, "one probe for the selected host");
}

#[test]
fn host_filter_excludes_a_host() {
    // --exclude drops the named host; the rest run.
    let cfg = fleet_cfg();
    let path = fleet_shim("hf-excl");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--exclude", "alpha", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(host_addresses(&out), ["beta"], "excluded host is skipped");
    let calls = std::fs::read_to_string(tmpdir().join("shim-hf-excl").join("calls")).unwrap();
    assert_eq!(calls.len(), 1, "one probe for the non-excluded host");
}

#[test]
fn host_filter_unknown_host_is_an_error() {
    // --host <unknown> is a hard error, like --only <unknown module>.
    let cfg = fleet_cfg();
    let path = fleet_shim("hf-unknown");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--host", "gamma", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!out.status.success(), "--host with no match must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("matches no host"), "{stderr}");
    // No probe ran on any host.
    let calls_path = tmpdir().join("shim-hf-unknown").join("calls");
    assert!(
        !calls_path.exists(),
        "selection error short-circuits before probing"
    );
}

#[test]
fn host_filter_unknown_exclude_is_an_error() {
    // A typo'd --exclude must not silently exclude nothing — that would
    // harden (and possibly reboot) the host the operator meant to protect.
    let cfg = fleet_cfg();
    let path = fleet_shim("hf-unknown-excl");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["apply", "--exclude", "alpah", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!out.status.success(), "--exclude with no match must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--exclude") && stderr.contains("matches no host"),
        "{stderr}"
    );
    assert!(
        !tmpdir().join("shim-hf-unknown-excl").join("calls").exists(),
        "selection error short-circuits before probing"
    );
}

#[test]
fn host_filter_empty_selection_is_an_error() {
    // `--host X --exclude X` (or excluding every host) must not let
    // check/score/report pass vacuously against zero probes.
    let cfg = fleet_cfg();
    for (tag, args) in [
        ("hf-empty-1", vec!["--host", "alpha", "--exclude", "alpha"]),
        ("hf-empty-2", vec!["--exclude", "alpha,beta"]),
    ] {
        let path = fleet_shim(tag);
        let out = Command::new(bin())
            .env("PATH", &path)
            .arg("check")
            .args(&args)
            .args(["-c"])
            .arg(&cfg)
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}: empty selection must fail");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("selected no hosts"), "{args:?}: {stderr}");
        assert!(
            !tmpdir().join(format!("shim-{tag}")).join("calls").exists(),
            "{args:?}: nothing probed"
        );
    }
}

#[test]
fn env_var_substitution_applies_to_config_values() {
    // ${VAR} in a config string is expanded from the spawned process's
    // environment, so secrets need not live in the config file. The expanded
    // value reaches the rendered script; the placeholder does not.
    let dir = tmpdir();
    let cfg = dir.join("env.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n\
         [users]\ncreate = [{ name = \"${DEPLOY_USER}\", sudo = true }]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env("DEPLOY_USER", "deployer")
        .args(["apply", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("deployer"),
        "expanded value reaches the script:\n{stdout}"
    );
    assert!(
        !stdout.contains("${DEPLOY_USER}"),
        "placeholder must not survive:\n{stdout}"
    );
}

#[test]
fn env_var_substitution_missing_var_is_a_hard_error() {
    // An undefined ${VAR} with no default fails at load, loudly, rather
    // than silently becoming an empty string (a missing secret must not
    // half-configure a host).
    let dir = tmpdir();
    let cfg = dir.join("env-missing.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n\
         [users]\ncreate = [{ name = \"${DEPLOY_USER_MISSING}\" }]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env_remove("DEPLOY_USER_MISSING")
        .args(["apply", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "a missing env placeholder must fail, not silently empty-substitute"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("DEPLOY_USER_MISSING"), "{stderr}");
    assert!(stderr.contains("environment"), "{stderr}");
}

#[test]
fn doctor_passes_a_reachable_host() {
    // Doctor reports an ok host reachable (+sudo) and exits 0.
    let cfg = tmpdir().join("doc-ok.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let path = fake_ssh("doc-ok", "printf 'anvil-doctor-ok\\n'\nexit 0");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["doctor", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("config + plan: ok"), "{stdout}");
    assert!(stdout.contains("reachable"), "{stdout}");
}

#[test]
fn doctor_fails_an_unreachable_host() {
    // An unreachable host is reported as FAIL and doctor exits non-zero,
    // surfacing the breakage before a real apply.
    let cfg = tmpdir().join("doc-fail.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let path = refusing_ssh("doc-fail");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["doctor", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "an unreachable host must fail doctor"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL"), "{stdout}");
}

#[test]
fn ndjson_emits_one_object_per_line_per_host() {
    // --output ndjson over a fleet yields one compact JSON object per line.
    let cfg = fleet_cfg();
    let path = fleet_shim("ndjson");
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["status", "--output", "ndjson", "--parallel", "2", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), 2, "one line per host:\n{stdout}");
    for line in &lines {
        let _: serde_json::Value =
            serde_json::from_str(line).expect("each line is one JSON object");
    }
}

#[test]
fn apply_only_selects_one_module_in_dry_run() {
    // --only narrows to the named module; others are not rendered.
    let cfg = tmpdir().join("only.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n\
         [sshd]\n[users]\ncreate = [{ name = \"deploy\" }]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["apply", "--only", "sshd", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("module: sshd"), "{stdout}");
    assert!(
        !stdout.contains("module: users"),
        "users must not be selected:\n{stdout}"
    );
}

#[test]
fn apply_only_unknown_module_is_an_error() {
    // --only <unknown> is a hard error, not a silent empty selection.
    let cfg = tmpdir().join("only-bad.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["apply", "--only", "nope", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(!out.status.success(), "--only <unknown> must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nope"), "{stderr}");
    assert!(stderr.contains("not an enabled module"), "{stderr}");
}

#[test]
fn apply_only_hetzner_closing_public_ssh_needs_tailscale() {
    // T10: keep_public_ssh = false relies on tailscale in the same run
    // (ordering edge + T21 skip), so --only hetzner alone is refused.
    let cfg = tmpdir().join("only-hz-tailnet.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"100.64.0.1\"\nuser = \"a\"\n[firewall]\n\
         [tailscale]\ntailnet_only_ssh = true\n\
         [hetzner]\nserver_name = \"s\"\nkeep_public_ssh = false\n",
    )
    .unwrap();
    let run = |only: &str| {
        Command::new(bin())
            .args(["apply", "--only", only, "--dry-run", "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let out = run("hetzner");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--only tailscale,hetzner"), "{stderr}");
    let out = run("tailscale,hetzner");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tailscale -> hetzner"), "{stdout}");
    assert!(!stdout.contains("(R61)"), "no SSH guard rule: {stdout}");
}

#[test]
fn apply_only_netcup_is_fenced_like_hetzner() {
    // T12: --only netcup needs sshd (R56) and, with keep_public_ssh = false,
    // tailscale in the same run (T10).
    let cfg = tmpdir().join("only-nc.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"100.64.0.1\"\nuser = \"a\"\n[sshd]\n[firewall]\n\
         [tailscale]\ntailnet_only_ssh = true\n\
         [netcup]\nserver = \"7\"\nkeep_public_ssh = false\n",
    )
    .unwrap();
    let run = |only: &str| {
        Command::new(bin())
            .args(["apply", "--only", only, "--dry-run", "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let out = run("netcup");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("firewall/hetzner/netcup without sshd"),
        "{stderr}"
    );
    let out = run("sshd,netcup");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--only tailscale,netcup"), "{stderr}");
    let out = run("sshd,tailscale,netcup");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("tailscale -> netcup"), "{stdout}");
    assert!(!stdout.contains("(R61)"), "no SSH guard rule: {stdout}");
}

#[test]
fn apply_only_firewall_without_sshd_is_a_usage_error() {
    // --only firewall drops the R56 firewall-after-sshd edge, so it must
    // be refused while sshd is in the plan; --only sshd,firewall is fine.
    let cfg = tmpdir().join("only-fw.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\nport = 22\n\
         [sshd]\nport = 2222\n[firewall]\n\
         [hetzner]\nserver_name = \"s\"\nfirewall_name = \"f\"\n",
    )
    .unwrap();
    let run = |only: &str| {
        Command::new(bin())
            .args(["apply", "--only", only, "--dry-run", "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let out = run("firewall");
    // AnvilError::Usage exits 1 like `--only <unknown>`; 2 is reserved for clap.
    assert_eq!(
        out.status.code(),
        Some(1),
        "--only firewall must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("sshd"), "{stderr}");
    assert_eq!(
        run("hetzner").status.code(),
        Some(1),
        "hetzner is a fence too"
    );

    let out = run("sshd,firewall");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Without [sshd] in the plan there is no edge to drop.
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[firewall]\n",
    )
    .unwrap();
    let out = run("firewall");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn parallel_failure_on_one_host_does_not_abort_the_other() {
    // R53: host alpha's probe fails, host beta's succeeds — both must be
    // reported. A failure on one host never aborts the others. The shim fails
    // (exit 255) when the target is admin@alpha and aligns otherwise.
    let cfg = tmpdir().join("par-isolate.toml");
    std::fs::write(
        &cfg,
        "[[hosts]]\naddress = \"alpha\"\nuser = \"admin\"\n\
         [[hosts]]\naddress = \"beta\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let path = fake_ssh(
        "par-isolate",
        "case \" $* \" in *\" admin@alpha \"*) \
         echo 'ssh: refused' >&2; exit 255;; esac\n\
         echo 'OK: aligned'\nexit 0",
    );
    let out = Command::new(bin())
        .env("PATH", &path)
        .args(["status", "--output", "json", "--parallel", "2", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    // alpha failed → aggregate exit non-zero, but beta still ran and is reported.
    assert!(
        !out.status.success(),
        "alpha's failure must make status non-zero"
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let by_host: std::collections::HashMap<String, serde_json::Value> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|h| (h["host"].as_str().unwrap().to_string(), h.clone()))
        .collect();
    assert_eq!(by_host.len(), 2, "both hosts reported despite one failure");
    assert_eq!(
        by_host["alpha"]["modules"][0]["status"], "failed",
        "alpha failed: {:?}",
        by_host["alpha"]
    );
    assert_eq!(
        by_host["beta"]["modules"][0]["status"], "aligned",
        "beta aligned despite alpha's failure: {:?}",
        by_host["beta"]
    );
}

#[test]
fn validate_warns_about_skipped_plugins_on_stderr() {
    // Skipped-plugin warnings are diagnostics: they must land on stderr so
    // `--output json` pipelines stay parseable.
    let xdg = config_home("skip-warn");
    make_plugin(
        &xdg,
        "broken",
        "name = \"other\"\nsection = \"broken_cfg\"\n",
        "echo x\n",
        None,
    );
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [sshd]
        "#,
    );
    let out = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("warning: skipped plugin") && stderr.contains("does not match"),
        "warning with reason on stderr:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("warning"),
        "warnings must not pollute stdout:\n{stdout}"
    );
}

#[test]
fn validate_warns_about_a_shut_provider_firewall_on_stderr() {
    // CA3: [caddy] with [hetzner] rules that open neither 80 nor 443/tcp.
    let xdg = config_home("provider-fw-warn");
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [hetzner]
            server_name = "web1"
            [caddy]
            [[caddy.site]]
            domain = "a.example.com"
            upstream = "127.0.0.1:3000"
        "#,
    );
    let out = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert!(out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "anvil: warning: hetzner: [caddy] is enabled but no rule allows 443/tcp \
             — the site and ACME will be unreachable"
        ) && stderr.contains("no rule allows 80/tcp"),
        "warning on stderr:\n{stderr}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("warning"));
}

#[test]
fn plugins_list_with_only_valid_plugins_is_not_calm() {
    // "(no plugins discovered)" is for the both-empty case only; a valid
    // plugin with no skipped neighbors must not trigger it.
    let xdg = config_home("plugins-valid-only");
    make_plugin(
        &xdg,
        "solo",
        "name = \"solo\"\nsection = \"solo_cfg\"\n",
        "echo x\n",
        None,
    );
    let out = anvil_with_home(&xdg, &["plugins", "list"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("solo"), "{stdout}");
    assert!(
        !stdout.contains("(no plugins discovered)"),
        "calm message only when nothing was found:\n{stdout}"
    );
}

#[test]
fn rollback_dry_run_renders_scripts_without_connecting() {
    let dir = tmpdir();
    let cfg = dir.join("rollback.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "unreachable.invalid"
            user = "admin"
            [sshd]
        "#,
    )
    .unwrap();

    let out = Command::new(bin())
        .args(["rollback", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("module: sshd (rollback)"));
    // Restores from the .anvil.bak backup or removes a tool-created file.
    assert!(stdout.contains(".anvil.bak"));
}

#[test]
fn rollback_runs_reverse_apply_order_but_sshd_before_firewall() {
    let dir = tmpdir();
    let cfg = dir.join("rollback-order.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"unreachable.invalid\"\nuser = \"admin\"\n\
         [sshd]\n[firewall]\n[docker]\niptables_off = false\n\
         [containers.compose.a]\ncontent = \"services: {}\"\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["rollback", "--dry-run", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    let at = |m: &str| s.find(&format!("module: {m} (rollback)")).unwrap();
    assert!(at("containers") < at("docker"), "containers before docker");
    // sshd is restored first, so the firewall rollback re-allows its port.
    assert!(at("docker") < at("sshd") && at("sshd") < at("firewall"));

    // `--only firewall,sshd` keeps the same exception.
    let out = Command::new(bin())
        .args(["rollback", "--dry-run", "--only", "firewall,sshd", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    let at = |m: &str| s.find(&format!("module: {m} (rollback)")).unwrap();
    assert!(at("sshd") < at("firewall"), "sshd before firewall");
    assert!(!s.contains("module: docker (rollback)"));
}

#[test]
fn no_absolute_config_home_skips_plugin_discovery() {
    // cron/systemd: no HOME. A cwd-relative `.config/anvil/plugins/` (e.g. a
    // cloned repo) must not be discovered.
    let cwd = config_home("no-home");
    make_plugin(
        &cwd.join(".config"),
        "planted",
        "name = \"planted\"\nsection = \"planted\"\n",
        "echo pwned\n",
        None,
    );
    for xdg in [None, Some(".config")] {
        let mut cmd = Command::new(bin());
        cmd.current_dir(&cwd)
            .env_remove("HOME")
            .env_remove("XDG_CONFIG_HOME");
        if let Some(x) = xdg {
            cmd.env("XDG_CONFIG_HOME", x);
        }
        let out = cmd.args(["plugins", "list"]).output().unwrap();
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("discovery skipped"), "{stdout}");
        assert!(!stdout.contains("planted"), "{stdout}");
    }
}

#[test]
fn local_steps_run_once_per_fleet() {
    // hetzner (runs_locally) drives shared cloud state, so across N
    // hosts — even under --parallel — it must run once, not once per host.
    let dir = tmpdir();
    let cfg = dir.join("local-once.toml");
    std::fs::write(
        &cfg,
        "[[hosts]]\naddress = \"alpha\"\nuser = \"admin\"\n\
         [[hosts]]\naddress = \"beta\"\nuser = \"admin\"\n\
         [[hosts]]\naddress = \"gamma\"\nuser = \"admin\"\n\
         [sshd]\n[hetzner]\nserver_name = \"s\"\nfirewall_name = \"f\"\n",
    )
    .unwrap();
    for (cmd, extra, marker) in [
        ("check", None, "OK: aligned"),
        ("status", None, "OK: aligned"),
        ("report", Some("--check"), "OK: aligned"),
        ("apply", Some("--no-check"), "CHANGED: done"),
        ("rollback", None, "CHANGED: restored"),
    ] {
        let tag = format!("local-once-{cmd}");
        let path = fake_ssh(&tag, &format!("echo '{marker}'\nexit 0"));
        // Local runs spawn `bash -s` from PATH: count those, and pass every
        // other bash use (the ssh shim's own shebang) to the real one.
        let shim_dir = tmpdir().join(format!("shim-{tag}"));
        let fake_bash = shim_dir.join("bash");
        std::fs::write(
            &fake_bash,
            format!(
                "#!/bin/sh\nif [ \"$1\" = -s ]; then cat >/dev/null; \
                 printf x >> \"{}\"; echo '{marker}'; exit 0; fi\nexec /bin/bash \"$@\"\n",
                shim_dir.join("local-calls").display()
            ),
        )
        .unwrap();
        set_mode(&fake_bash, 0o755);
        let mut args = vec![cmd, "--output", "json"];
        args.extend(extra);
        if cmd != "report" {
            args.extend(["--parallel", "3"]); // report has no --parallel
        }
        let out = Command::new(bin())
            .env("PATH", &path)
            .args(&args)
            .arg("-c")
            .arg(&cfg)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{cmd}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let calls = std::fs::read_to_string(shim_dir.join("local-calls")).unwrap();
        assert_eq!(calls.len(), 1, "{cmd}: hetzner ran {} times", calls.len());
    }
}

#[test]
fn rollback_of_the_login_users_account_is_refused() {
    // Rolling back `users` deletes the authorized_keys and sudoers file
    // of the account anvil logs in as — with root login off, nobody can get
    // back in. Refused; other modules (or a different login user) are fine.
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxvbm9vbm9vbm9vbm9vbm9vbm9vbm9vbm9vbm9vbm9v t";
    let body = |user: &str| {
        format!(
            "[host]\naddress = \"10.0.0.1\"\nuser = \"{user}\"\n\
             [users]\ncreate = [{{ name = \"admin\", sudo = true, ssh_authorized_keys = [\"{key}\"] }}]\n\
             [sshd]\nallow_users = [\"admin\", \"ops\"]\n"
        )
    };
    let run = |user: &str, only: Option<&str>| {
        let cfg = tmpdir().join(format!("rb-users-{user}-{}.toml", only.unwrap_or("all")));
        std::fs::write(&cfg, body(user)).unwrap();
        let mut c = Command::new(bin());
        c.args(["rollback", "--dry-run", "-c"]).arg(&cfg);
        if let Some(o) = only {
            c.args(["--only", o]);
        }
        c.output().unwrap()
    };
    let out = run("admin", None);
    assert_eq!(
        out.status.code(),
        Some(1),
        "full rollback as admin must be refused"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("admin") && stderr.contains("locks the host out"),
        "{stderr}"
    );
    assert_eq!(
        run("admin", Some("sshd")).status.code(),
        Some(0),
        "users not selected"
    );
    assert_eq!(
        run("ops", None).status.code(),
        Some(0),
        "login user not anvil-created"
    );
}

#[test]
fn every_example_config_validates() {
    // The tutorial and README point at examples/*.toml; a schema change that
    // breaks one must fail here, not in a reader's terminal.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/examples");
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let out = Command::new(bin())
            .args(["validate", "-c"])
            .arg(&path)
            .env("RESTIC_PASSWORD", "test-only") // examples/backup.toml
            .env(
                "GITHUB_APP_KEY", // examples/github-runner-ephemeral.toml
                "-----BEGIN RSA PRIVATE KEY-----\ntest-only\n-----END RSA PRIVATE KEY-----",
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{} does not validate:\n{}",
            path.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        n += 1;
    }
    assert!(n >= 5, "expected the example configs, found {n}");
}

#[test]
fn validate_error_says_invalid_config_once() {
    let cfg = tmpdir().join("dup-prefix.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"203.0.113.10\"\nuser = \"a\"\n[updates]\nreboot_time = \"+2:30\"\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(stderr.matches("invalid config").count(), 1, "{stderr}");
}

/// A PATH with no `ssh` on it, so spawning the transport itself fails.
fn no_ssh_path(test: &str) -> std::ffi::OsString {
    let dir = tmpdir().join(format!("no-ssh-{test}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir.into_os_string()
}

#[test]
fn score_fleet_fails_when_any_host_is_below_threshold() {
    // A fleet passes only if every host clears the threshold (all_pass &=).
    let cfg = fleet_cfg();
    let body = "case \"$*\" in *alpha*) echo 'hardening_index=90';; *) echo 'hardening_index=10';; esac\nexit 0";
    let out = Command::new(bin())
        .env("PATH", fake_ssh("score-fleet", body))
        .args(["score", "--threshold", "50", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stdout}");
    assert!(
        stdout.contains("PASS") && stdout.contains("FAIL"),
        "{stdout}"
    );
}

#[test]
fn diff_reports_a_transport_that_cannot_start() {
    // exec_script returning Err (no ssh binary) is a failed host, in both formats.
    let cfg = one_host_cfg(&tmpdir(), "diff-spawn.toml");
    let path = no_ssh_path("diff-spawn");
    let json = Command::new(bin())
        .env("PATH", &path)
        .args(["diff", "--output", "json", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(json.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert!(v[0]["error"].is_string(), "{v}");

    let human = Command::new(bin())
        .env("PATH", &path)
        .args(["diff", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("failed to read files"), "{stdout}");
}

#[test]
fn doctor_fails_when_the_probe_runs_but_does_not_answer() {
    // Exit 0 without the marker is a failed probe, not a pass (&& not ||).
    let cfg = tmpdir().join("doc-silent.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env("PATH", fake_ssh("doc-silent", "echo nothing\nexit 0"))
        .args(["doctor", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL  probe did not succeed"), "{stdout}");
}

#[test]
fn doctor_fails_when_the_probe_cannot_be_spawned() {
    let cfg = tmpdir().join("doc-spawn.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env("PATH", no_ssh_path("doc-spawn"))
        .args(["doctor", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("could not run probe"), "{stdout}");
}

#[test]
fn doctor_labels_sudo_logins_and_omits_the_plugin_line_when_none() {
    // A non-root login is labelled as needing passwordless sudo; with no
    // plugins configured, no plugin line is printed.
    let cfg = tmpdir().join("doc-admin.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"admin\"\n[sshd]\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env(
            "PATH",
            fake_ssh("doc-admin", "printf 'anvil-doctor-ok\\n'\nexit 0"),
        )
        .args(["doctor", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ok (reachable + sudo NOPASSWD)"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("plugins:"),
        "no plugins, no plugin line: {stdout}"
    );
}

#[test]
fn validate_warns_when_nothing_proxies_forgejo() {
    // FJ7: Forgejo binds 127.0.0.1; without [tls]/[caddy] for its domain it is unreachable.
    let xdg = config_home("forgejo-proxy-warn");
    let cfg = xdg.join("harden.toml");
    write_secure(
        &cfg,
        r#"
            [host]
            address = "10.0.0.1"
            user = "admin"
            [forgejo]
            domain = "git.example.com"
            secret_key = "s3cret-key"
            internal_token = "token"
            jwt_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "#,
    );
    let out = anvil_with_home(&xdg, &["validate", "-c", cfg.to_str().unwrap()]);
    assert!(out.status.success(), "a warning, not an error: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(
            "anvil: warning: forgejo: no [tls] or [caddy] site serves git.example.com -> \
             127.0.0.1:3000; Forgejo will be unreachable from outside"
        ),
        "warning on stderr:\n{stderr}"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("warning"));
}

#[test]
fn dry_run_redacts_config_secrets() {
    // `-n` output is pasted into issues; it must not carry secrets.
    let dir = tmpdir();
    let cfg = dir.join("dry-secret.toml");
    std::fs::write(
        &cfg,
        "[host]\naddress = \"10.0.0.1\"\nuser = \"a\"\n[tailscale]\nauth_key = \"tskey-SENTINEL\"\n",
    )
    .unwrap();
    for args in [
        &["apply", "--dry-run", "-c"][..],
        &["apply", "--dry-run", "--output", "json", "-c"],
        &["rollback", "--dry-run", "--output", "json", "-c"],
    ] {
        let out = Command::new(bin()).args(args).arg(&cfg).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.contains("SENTINEL"), "{args:?} leaks:\n{stdout}");
        if args[0] == "apply" {
            assert!(stdout.contains("<redacted>"), "{args:?}");
        }
    }
}

#[test]
fn check_names_what_the_v2_runner_installs_on_the_host() {
    // Docker + sysbox must never be a surprise; plain modules list nothing.
    let cfg = tmpdir().join("v2-installs.toml");
    std::fs::write(
        &cfg,
        r#"
            [host]
            address = "10.0.0.9"
            user = "admin"
            [sshd]
            [github_runner]
            mode = "ephemeral"
            app_id = 1
            installation_id = 2
            runner_group_id = 3
            app_key = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
            [github_runner.runners.ci]
            url = "https://github.com/acme"
            labels = ["anvil"]
        "#,
    )
    .unwrap();
    let run = |output: &str| {
        Command::new(bin())
            .env(
                "PATH",
                fake_ssh(
                    &format!("v2-installs-{output}"),
                    "echo 'OK: aligned'\nexit 0",
                ),
            )
            .args(["check", "--output", output, "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    let human = String::from_utf8(run("human").stdout).unwrap();
    assert!(
        human.contains("github_runner  aligned\n      installs: Docker (rootless)\n"),
        "{human}"
    );
    assert_eq!(human.matches("installs:").count(), 1, "{human}");
    let v: serde_json::Value = serde_json::from_slice(&run("json").stdout).unwrap();
    let m = |id: &str| {
        v[0]["modules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["module"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        m("github_runner")["installs"],
        serde_json::json!(["Docker (rootless)"])
    );
    assert!(m("sshd").get("installs").is_none());
}

#[test]
fn v2_runner_on_a_podman_host_installs_podman_and_sysbox_is_refused() {
    // The sandbox runtime follows the host engine.
    let body = r#"
        [host]
        address = "10.0.0.9"
        user = "admin"
        [podman]
        [github_runner]
        mode = "ephemeral"
        app_id = 1
        installation_id = 2
        runner_group_id = 3
        app_key = "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----"
        RUNTIME
        [github_runner.runners.ci]
        url = "https://github.com/acme"
        labels = ["anvil"]
    "#;
    let cfg = tmpdir().join("v2-podman.toml");
    std::fs::write(&cfg, body.replace("RUNTIME", "")).unwrap();
    let out = Command::new(bin())
        .env("PATH", fake_ssh("v2-podman", "echo 'OK: aligned'\nexit 0"))
        .args(["check", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    let human = String::from_utf8(out.stdout).unwrap();
    assert!(
        human.contains("github_runner  aligned\n      installs: Podman\n"),
        "{human}"
    );
    std::fs::write(
        &cfg,
        body.replace("RUNTIME", "sandbox_runtime = \"sysbox-runc\""),
    )
    .unwrap();
    let out = Command::new(bin())
        .args(["validate", "-c"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("sandbox_runtime = \"sysbox-runc\" installs Docker + sysbox; it cannot run on a Podman host"),
        "{err}"
    );
}

#[test]
fn validate_rejects_bad_coding_agents_configs() {
    let dir = tmpdir();
    let base = "[host]\naddress = \"h\"\nuser = \"u\"\n";
    let agent = "[users]\ncreate = [{ name = \"agent\" }]\n";
    let ok = format!("{base}{agent}[coding_agents]\n");
    let rev = "0123456789abcdef0123456789abcdef01234567";
    let orca = format!(
        "{base}{agent}[firewall]\n[tailscale]\nlogin_server = \"https://hs.example.com\"\n\
         [coding_agents]\n[coding_agents.orca_server]\n"
    );
    let cases: Vec<(String, &str)> = vec![
        (format!("{base}[coding_agents]\n"), "must be a [users].create account"),
        (
            format!("{base}[users]\ncreate = [{{ name = \"agent\", sudo = true }}]\n[coding_agents]\n"),
            "has sudo = true",
        ),
        (format!("{ok}user = \"github-runner\"\n"), "runner or docker-group account"),
        (format!("{ok}user = \"beszel\"\n"), "runner or docker-group account"),
        (
            format!("{base}{agent}[sshd]\nallow_users = [\"u\"]\n[coding_agents]\n"),
            "missing from sshd.allow_users",
        ),
        (
            format!("{base}{agent}[firewall]\ndefault_outgoing = \"deny\"\n[coding_agents]\n"),
            "firewall.default_outgoing = \"allow\"",
        ),
        (format!("{ok}claude_code = \"beta\"\n"), "coding_agents.claude_code"),
        (format!("{ok}docker = \"group\"\n"), "coding_agents.docker"),
        (
            format!("[docker]\nsource = \"distro\"\n{ok}docker = \"rootless\"\n"),
            "docker-ce-rootless-extras",
        ),
        (format!("{ok}opencode = \"v2\"\n"), "coding_agents.opencode"),
        (format!("{ok}opencode = \"2.2.5;x\"\n"), "coding_agents.opencode"),
        (format!("{ok}skills = [{{ source = \"not a repo\" }}]\n"), "skills.source"),
        (format!("{ok}skills = [{{ source = \"o/\" }}]\n"), "skills.source"),
        (format!("{ok}skills = [{{ source = \"o/r\", names = [\"a b\"] }}]\n"), "skills.names"),
        (format!("{ok}skills = [{{ source = \"o/r\", agents = [\"codex\"] }}]\n"), "skills.agents"),
        (
            format!("{ok}opencode = \"none\"\nskills = [{{ source = \"o/r\", agents = [\"opencode\"] }}]\n"),
            "targets opencode, which is not installed",
        ),
        (
            format!("{ok}claude_code = \"none\"\nopencode = \"none\"\nskills = [{{ source = \"o/r\" }}]\n"),
            "both \"none\"",
        ),
        (format!("{ok}claude_plugins = [\"nomarketplace\"]\n"), "<name>@<marketplace>"),
        (format!("{ok}claude_plugins = [\"a@\"]\n"), "<name>@<marketplace>"),
        (
            format!("{ok}claude_code = \"none\"\nskills = [{{ source = \"o/r\", agents = [\"claude-code\"] }}]\n"),
            "targets claude-code, which is not installed",
        ),
        (
            format!("{ok}setup = {{ url = \"https://x/r.git\", rev = \"{}\", run = \"i.sh\" }}\n", "g".repeat(40)),
            "40-hex commit",
        ),
        (format!("{ok}claude_code = \"none\"\nclaude_plugins = [\"a@b\"]\n"), "need claude_code"),
        (format!("{ok}opencode = \"none\"\nopencode_plugins = [\"p\"]\n"), "need opencode"),
        (format!("{ok}claude_code = \"none\"\nclaude_marketplaces = [\"o/m\"]\n"), "need claude_code"),
        (format!("{ok}opencode = \"none\"\nopencode_mcp = {{ m = [\"c\"] }}\n"), "need opencode"),
        (format!("{ok}opencode_mcp = {{ m = [] }}\n"), "opencode_mcp.m"),
        (format!("{ok}setup = {{ url = \"http://x/r.git\", rev = \"{rev}\", run = \"i.sh\" }}\n"), "setup.url"),
        (format!("{ok}setup = {{ url = \"https://x/r.git\", rev = \"main\", run = \"i.sh\" }}\n"), "40-hex commit"),
        (format!("{ok}setup = {{ url = \"https://x/r.git\", rev = \"{rev}\", run = \"../i.sh\" }}\n"), "setup.run"),
        (format!("{ok}setup = {{ url = \"https://x/r.git\", rev = \"{rev}\", run = \"/i.sh\" }}\n"), "setup.run"),
        (format!("{ok}cpu_quota = \"4\"\n"), "coding_agents.cpu_quota"),
        (format!("{ok}tasks_max = 0\n"), "coding_agents.tasks_max"),
        (format!("{ok}unknown = 1\n"), "unknown field"),
        (format!("{ok}[coding_agents.orca_server]\n"), "orca_server requires [tailscale] and [firewall]"),
        (format!("{base}{agent}[firewall]\n[coding_agents.orca_server]\n"), "requires [tailscale]"),
        (format!("{orca}version = \"1.4.300\"\n"), "needs sha256_amd64"),
        (format!("{orca}version = \"1.4.300\"\nsha256_amd64 = \"{}\"\n", "a".repeat(64)), "needs sha256_arm64"),
        (format!("{orca}sha256_arm64 = \"{}\"\n", "g".repeat(64)), "64 hex characters"),
        (format!("{orca}port = 0\n"), "orca_server.port"),
        (
            orca.replace("[firewall]\n", "[firewall]\ndefault_incoming = \"allow\"\n"),
            "orca_server needs firewall.default_incoming = \"deny\"",
        ),
        (format!("{orca}bind = \"0.0.0.0\"\n"), "unknown field"),
    ];
    let run = |name: &str, body: &str| {
        let cfg = dir.join(format!("ca-{name}.toml"));
        std::fs::write(&cfg, body).unwrap();
        Command::new(bin())
            .args(["validate", "-c"])
            .arg(&cfg)
            .output()
            .unwrap()
    };
    for (name, body) in [
        ("docker", format!("{ok}docker = \"rootless\"\n")),
        ("podman", format!("[podman]\n{ok}docker = \"rootless\"\n")),
    ] {
        let out = run(name, &body);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let good = run("ok", &format!("{ok}opencode = \"0.0.0-beta-17236\"\nskills = [{{ source = \"https://git.example.org/s.git\", agents = [\"claude-code\", \"opencode\"] }}]\nclaude_marketplaces = [\"o/m\"]\nclaude_plugins = [\"p@m\"]\nopencode_plugins = [\"p\"]\nopencode_mcp = {{ m = [\"npx\", \"m\"] }}\nsetup = {{ url = \"https://x/r.git\", rev = \"{rev}\", run = \"bin/i.sh\" }}\n"));
    assert_eq!(
        good.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    let good_orca = run(
        "orca",
        &format!("{orca}port = 7000\nversion = \"1.4.300\"\nsha256_amd64 = \"{h}\"\nsha256_arm64 = \"{h}\"\n", h = "a".repeat(64)),
    );
    let reject = run(
        "orca-reject",
        &orca.replace(
            "[firewall]\n",
            "[firewall]\ndefault_incoming = \"reject\"\n",
        ),
    );
    assert_eq!(
        reject.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&reject.stderr)
    );
    assert_eq!(
        good_orca.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&good_orca.stderr)
    );
    for (i, (body, want)) in cases.iter().enumerate() {
        let out = run(&i.to_string(), body);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "case {i}: {body}");
        assert!(stderr.contains(want), "case {i}: want {want:?}\n{stderr}");
    }
}
