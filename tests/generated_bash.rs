//! R102 (generated-bash syntax gate) and R105 (diff-contract regression),
//! exercised end-to-end through the config → plan → engine pipeline.

use std::io::Write;
use std::process::{Command, Stdio};

use fulcrum_anvil::config::{Account, Config, MODULE_IDS};
use fulcrum_anvil::diff::read_files_script;
use fulcrum_anvil::engine::MARK_CHANGED;
use fulcrum_anvil::modules::{lynis, Plan};

/// A config with EVERY implemented section enabled, built from the binary's
/// own `init --full` template (kept valid by cli.rs tests) and sharpened with
/// adversarial values so the generated scripts contain real interpolation to
/// parse. Building from the template means a newly registered section joins
/// this gate automatically; `wide_config_covers_every_implemented_module`
/// pins that.
fn wide_config() -> Config {
    let out = Command::new(env!("CARGO_BIN_EXE_anvil"))
        .args(["init", "--full"])
        .output()
        .expect("run anvil init --full");
    assert!(out.status.success(), "init --full failed");
    let text = String::from_utf8(out.stdout).expect("utf8");
    let mut cfg: Config = toml::from_str(&text).expect("parse full init output");
    let users = cfg.users.as_mut().expect("--full enables [users]");
    users.create.push(Account {
        name: "ops".into(),
        sudo: false,
        shell: Some("/usr/bin/zsh".into()),
        ssh_authorized_keys: Some(vec!["ssh-ed25519 AAAAC3Nz key'with quote".into()]),
    });
    cfg.validate().expect("valid");
    cfg
}

#[test]
fn wide_config_covers_every_implemented_module() {
    // The gate is only as wide as this fixture: every registered module id
    // must be enabled, planned, and therefore bash -n checked below. A new
    // module that fails to appear here escapes the whole gate.
    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");
    let planned: Vec<&str> = plan.modules.iter().map(|m| m.id()).collect();
    // `[podman]` and `[docker]` cannot share a host: the Podman gate below
    // covers it.
    for id in MODULE_IDS.iter().filter(|&&id| id != "podman") {
        assert!(
            planned.contains(id),
            "module {id} is not part of the bash -n gate's wide config"
        );
    }
    assert_eq!(
        plan.modules.len(),
        plan.order.len(),
        "enabled sections without a module escape the gate: {:?}",
        plan.order
    );
}

// NB: the gate parses under whatever `bash` is first on PATH. Dev machines
// may carry an older bash (macOS ships 3.2) than the Debian/Ubuntu targets
// (5.x); an older parser is *stricter*, so local runs can only fail early,
// never falsely pass syntax the target would reject. CI runs on ubuntu with
// a target-matching bash, which is the authoritative gate.
fn bash_available() -> bool {
    Command::new("bash")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn bash_parse_ok(script: &str) -> Result<(), String> {
    let mut child = Command::new("bash")
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

#[test]
fn every_generated_script_parses_under_bash_n() {
    if !bash_available() {
        eprintln!("skipping: bash not available");
        return;
    }
    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");
    assert!(!plan.modules.is_empty());
    for m in &plan.modules {
        let decl = m.declaration();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
        ] {
            if let Err(err) = bash_parse_ok(&script) {
                panic!(
                    "module {} {kind} script failed bash -n:\n{err}\n---\n{script}",
                    m.id()
                );
            }
        }
    }
}

#[test]
fn no_generated_script_pipes_into_grep_q() {
    // Scripts run under `set -o pipefail`. `cmd | grep -q x` stops
    // reading at the first match; if `cmd` is still writing it dies of SIGPIPE
    // and the pipe fails although x matched (exit 141, seen with cscli on the
    // netcup host). Read the whole input instead: `| grep x >/dev/null`.
    // A lone `|` (a pipe, not `||`) followed by `grep` with `q` in its flags.
    let re_pipe_q = |s: &str| {
        let b = s.as_bytes();
        s.match_indices('|').any(|(i, _)| {
            let lone = (i == 0 || b[i - 1] != b'|') && b.get(i + 1) != Some(&b'|');
            let mut words = s[i + 1..].split_whitespace();
            lone && words.next() == Some("grep")
                && words
                    .next()
                    .is_some_and(|f| f.starts_with('-') && !f.starts_with("--") && f.contains('q'))
        })
    };
    assert!(re_pipe_q("x | grep -qwF y") && re_pipe_q("x|grep -q y"));
    assert!(!re_pipe_q("a || grep -qs f") && !re_pipe_q("x | grep -wF y >/dev/null"));
    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");
    for m in &plan.modules {
        let decl = m.declaration();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
            ("rollback", decl.render_rollback()),
        ] {
            for line in script.lines() {
                assert!(
                    !re_pipe_q(line),
                    "module {} {kind}: piped grep -q: {line}",
                    m.id()
                );
            }
        }
    }
}

/// A temp file outside the engine's `$__rundir` (removed by its EXIT
/// trap) leaks in /tmp when a `set -e` abort skips the module's own `rm`.
#[test]
fn apply_temp_files_live_under_the_run_dir() {
    let cfg = wide_config();
    for m in &Plan::build(&cfg).expect("plan").modules {
        // Only apply defines `$__rundir`; under `set -u` rollback would abort.
        let rollback = m.declaration().render_rollback();
        assert!(
            !rollback.contains("\"$__rundir") || rollback.contains("${__rundir:-}"),
            "module {}: rollback uses $__rundir, which only apply defines",
            m.id()
        );
        let apply = m.declaration().render_apply();
        let lines: Vec<&str> = apply.lines().collect();
        for (i, line) in lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("mktemp"))
        {
            // Allowed: under the run dir, the run dir itself, or an own EXIT trap.
            let own_trap = lines
                .get(i + 1)
                .is_some_and(|n| n.trim_start().starts_with("trap ") && n.ends_with(" EXIT"));
            assert!(
                line.contains("-p \"$__rundir\"")
                    || line.starts_with("__rundir=$(mktemp -d ")
                    || own_trap,
                "module {}: temp file outside $__rundir: {line}",
                m.id()
            );
        }
    }
}

#[test]
fn rollback_diff_and_score_scripts_parse_under_bash_n() {
    if !bash_available() {
        eprintln!("skipping: bash not available");
        return;
    }
    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");

    // Rollback scripts for every module.
    for m in &plan.modules {
        let script = m.declaration().render_rollback();
        if let Err(err) = bash_parse_ok(&script) {
            panic!(
                "module {} rollback failed bash -n:\n{err}\n---\n{script}",
                m.id()
            );
        }
    }

    // The diff read-file script over every managed path (real interpolation).
    let paths: Vec<String> = plan
        .modules
        .iter()
        .flat_map(|m| m.declaration().files.into_iter().map(|f| f.path))
        .collect();
    let read = read_files_script(&paths);
    if let Err(err) = bash_parse_ok(&read) {
        panic!("diff read-file script failed bash -n:\n{err}\n---\n{read}");
    }

    // The self-contained Lynis audit script `score` runs.
    let audit = lynis::audit_script();
    if let Err(err) = bash_parse_ok(&audit) {
        panic!("lynis audit script failed bash -n:\n{err}\n---\n{audit}");
    }
}

#[test]
fn diff_contract_desired_content_survives_into_script() {
    // R105: for every module that manages a static-content file, the declared
    // desired content must be recoverable from the apply script (here:
    // base64-embedded), so a renamed internal detail can't silently break
    // diff/rollback. Computed files have no local content to embed.
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");
    let mut checked_files = 0;
    for m in &plan.modules {
        let decl = m.declaration();
        let apply = decl.render_apply();
        for f in &decl.files {
            let Some(content) = f.static_content() else {
                continue;
            };
            let encoded = B64.encode(content.as_bytes());
            assert!(
                apply.contains(&encoded),
                "module {} file {} desired content not embedded in apply script",
                m.id(),
                f.path
            );
            checked_files += 1;
        }
    }
    assert!(checked_files > 0, "expected at least one managed file");
}

#[test]
fn computed_file_scripts_parse_and_share_the_generator() {
    // The computed-content mode (FileContent::Computed): probe and apply must
    // materialize the desired content through the *same* generator command
    // substitution, and the rendered scripts must still parse under bash -n.
    use fulcrum_anvil::engine::{Declaration, ManagedFile};

    let generator = "ssh -Q kex 2>/dev/null | grep -i pq | paste -sd, -";
    let decl = Declaration::new("demo_computed").file(ManagedFile::computed(
        "/etc/demo/computed.conf",
        generator,
        "0644",
        "root:root",
    ));

    let probe = decl.render_probe();
    let apply = decl.render_apply();
    let expected = format!("__desired=$({generator})");
    assert!(
        probe.contains(&expected),
        "probe uses the generator:\n{probe}"
    );
    assert!(
        apply.contains(&expected),
        "apply uses the generator:\n{apply}"
    );

    if !bash_available() {
        eprintln!("skipping bash -n gate: bash not available");
        return;
    }
    for (kind, script) in [
        ("probe", probe),
        ("apply", apply),
        ("rollback", decl.render_rollback()),
    ] {
        if let Err(err) = bash_parse_ok(&script) {
            panic!("computed-file {kind} script failed bash -n:\n{err}\n---\n{script}");
        }
    }
}

#[test]
fn apply_reports_changes_via_marker_contract() {
    let cfg = wide_config();
    let plan = Plan::build(&cfg).expect("plan");
    let sshd = plan
        .modules
        .iter()
        .find(|m| m.id() == "sshd")
        .expect("sshd present");
    // The apply script must be able to emit the CHANGED marker (R87).
    assert!(sshd.declaration().render_apply().contains(MARK_CHANGED));
}

/// The wide config as a Podman host: no `[docker]`, compose or Docker-only
/// services.
fn podman_host(mut cfg: Config) -> Config {
    cfg.docker = None;
    cfg.podman = Some(Default::default());
    if let Some(h) = cfg.headscale.as_mut() {
        h.headplane_docker_socket = false; // Docker only
    }
    if let Some(c) = cfg.containers.as_mut() {
        c.runtime = Some("podman".into());
        c.compose.clear();
    }
    cfg
}

/// The wide config cannot hold both container engines (`[docker]` and
/// `[podman]` / `runtime = "podman"` are mutually exclusive), so the Podman
/// host gets its own bash -n + diff-contract gate.
#[test]
fn podman_runtime_scripts_parse_and_embed_content() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    if !bash_available() {
        eprintln!("skipping: bash not available");
        return;
    }
    let mut cfg = podman_host(wide_config());
    // greptimedb and Headplane pick their Quadlets; Forgejo runs as one.
    assert!(cfg.greptimedb.is_some(), "--full enables [greptimedb]");
    cfg.headscale
        .as_mut()
        .expect("--full enables [headscale]")
        .headplane = true;
    cfg.forgejo
        .as_mut()
        .expect("--full enables [forgejo]")
        .deploy = "quadlet".into();
    let c = cfg
        .containers
        .as_mut()
        .expect("--full enables [containers]");
    for name in ["web", "b-1"] {
        c.quadlet.insert(
            name.into(),
            fulcrum_anvil::config::QuadletContainer {
                content: "[Container]\nImage=nginx\nPublishPort=127.0.0.1:8080:80\n\n[Install]\nWantedBy=multi-user.target\n".into(),
            },
        );
    }
    // Runner container jobs on rootless Podman.
    cfg.github_runner.as_mut().expect("--full").docker = "podman".into();
    cfg.forgejo_runner.as_mut().expect("--full").docker = "podman".into();
    cfg.validate().expect("valid");
    let plan = Plan::build(&cfg).expect("plan");
    for id in ["github_runner", "forgejo_runner"] {
        let m = plan.modules.iter().find(|m| m.id() == id).expect(id);
        let decl = m.declaration();
        assert_eq!(decl.installs, ["Podman"], "{id}");
        let apply = decl.render_apply();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", apply.clone()),
            ("rollback", decl.render_rollback()),
        ] {
            if let Err(err) = bash_parse_ok(&script) {
                panic!("{id} {kind} script failed bash -n:\n{err}\n---\n{script}");
            }
        }
        for f in &decl.files {
            if let Some(content) = f.static_content() {
                assert!(
                    apply.contains(&B64.encode(content.as_bytes())),
                    "{}",
                    f.path
                );
            }
        }
    }
    let mut quadlets = Vec::new();
    for id in ["podman", "containers", "greptimedb", "headscale", "forgejo"] {
        let m = plan.modules.iter().find(|m| m.id() == id).expect(id);
        let decl = m.declaration();
        let apply = decl.render_apply();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", apply.clone()),
            ("rollback", decl.render_rollback()),
        ] {
            if let Err(err) = bash_parse_ok(&script) {
                panic!("{id} {kind} script failed bash -n:\n{err}\n---\n{script}");
            }
        }
        for f in &decl.files {
            if let Some(content) = f.static_content() {
                assert!(
                    apply.contains(&B64.encode(content.as_bytes())),
                    "{}",
                    f.path
                );
            }
            if f.path.starts_with("/etc/containers/systemd/") {
                quadlets.push(f.path.clone());
            }
            assert!(
                !f.path.starts_with("/etc/systemd/system/headplane"),
                "{}",
                f.path
            );
            assert!(
                f.path != "/etc/systemd/system/forgejo.service",
                "{}",
                f.path
            );
        }
        assert!(!apply.contains("docker compose"), "{id}");
    }
    quadlets.sort();
    assert_eq!(
        quadlets,
        [
            "/etc/containers/systemd/anvil-b-1.container",
            "/etc/containers/systemd/anvil-greptimedb.container",
            "/etc/containers/systemd/anvil-web.container",
            "/etc/containers/systemd/forgejo.container",
            "/etc/containers/systemd/headplane.container",
        ]
    );
}

/// `[github_runner] mode = "ephemeral"` replaces the wide config's
/// persistent runner, so it gets its own gate, on a Docker host (sysbox) and
/// a Podman host. Its minter, entrypoint and podman wrapper are static
/// files (base64 in the scripts), so they are parsed on their own too.
#[test]
fn ephemeral_github_runner_scripts_parse() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    if !bash_available() {
        eprintln!("skipping: bash not available");
        return;
    }
    for (podman, want) in [(false, 5), (true, 6)] {
        ephemeral_scripts_parse(podman, want, |c| B64.encode(c));
    }
}

fn ephemeral_scripts_parse(podman: bool, want: usize, b64: impl Fn(&str) -> String) {
    let mut cfg = wide_config();
    if podman {
        cfg = podman_host(cfg);
    }
    cfg.github_runner = Some(
        toml::from_str(
            "mode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\nrunner_group_id = 3\n\
             capacity = 2\nsandbox_packages = [\"build-essential\", \"g++\"]\napp_key = \"-----BEGIN RSA PRIVATE KEY-----\\nk'ey\\n-----END RSA PRIVATE KEY-----\\n\"\n\
             [runners.b-1]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\", \"x.y\"]\n",
        )
        .expect("ephemeral section"),
    );
    cfg.validate().expect("valid");
    let plan = Plan::build(&cfg).expect("plan");
    let m = plan
        .modules
        .iter()
        .find(|m| m.id() == "github_runner")
        .expect("github_runner");
    let decl = m.declaration();
    assert_eq!(decl.installs.contains(&"Podman".to_string()), podman);
    let apply = decl.render_apply();
    let mut scripts = vec![
        ("probe".to_string(), decl.render_probe()),
        ("apply".to_string(), apply.clone()),
        ("rollback".to_string(), decl.render_rollback()),
    ];
    for f in &decl.files {
        if let Some(c) = f.static_content() {
            assert!(apply.contains(&b64(c)), "{} missing from apply", f.path);
            if c.starts_with("#!/bin/") {
                scripts.push((f.path.clone(), c.to_string()));
            }
        }
    }
    assert_eq!(
        scripts.len(),
        want,
        "minter, entrypoint (and wrapper) parsed too"
    );
    for (kind, script) in scripts {
        if let Err(err) = bash_parse_ok(&script) {
            panic!("ephemeral {kind} failed bash -n:\n{err}\n---\n{script}");
        }
    }
}

fn ephemeral_forgejo_runner(token: &str) -> fulcrum_anvil::config::schema::ForgejoRunnerSection {
    ephemeral_forgejo_runner_on(token, "sysbox-runc")
}

fn ephemeral_forgejo_runner_on(
    token: &str,
    rt: &str,
) -> fulcrum_anvil::config::schema::ForgejoRunnerSection {
    toml::from_str(&format!(
        "mode = \"ephemeral\"\napi_token = \"{token}\"\nowner = \"acme/app\"\ncapacity = 2\n\
         labels = [\"debian:host\", \"node:docker://node:22-trixie\"]\nsandbox_runtime = \"{rt}\"\n"
    ))
    .expect("ephemeral forgejo_runner")
}

/// `[forgejo_runner] mode = "ephemeral"` replaces the wide config's
/// persistent runner, so it gets its own gate; alone it owns Docker + sysbox,
/// next to a v2 GitHub runner it does not. Minter and entrypoint are static
/// files, parsed on their own too.
#[test]
fn ephemeral_forgejo_runner_scripts_parse() {
    if !bash_available() {
        eprintln!("skipping: bash not available");
        return;
    }
    // Both runtimes; only a sysbox forgejo runner alone owns daemon.json.
    for (rt, v2) in [
        ("sysbox-runc", false),
        ("sysbox-runc", true),
        ("docker-rootless", false),
        ("docker-rootless", true),
    ] {
        let mut cfg = wide_config();
        if v2 {
            cfg.github_runner = Some(
                toml::from_str(&format!(
                    "mode = \"ephemeral\"\nsandbox_runtime = \"{rt}\"\napp_id = 1\ninstallation_id = 2\nrunner_group_id = 3\n\
                     app_key = \"-----BEGIN RSA PRIVATE KEY-----\\nk\\n-----END RSA PRIVATE KEY-----\\n\"\n\
                     [runners.b-1]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\"]\n",
                ))
                .expect("v2 section"),
            );
        }
        cfg.forgejo_runner = Some(ephemeral_forgejo_runner_on("t'ok", rt));
        cfg.validate().expect("valid");
        let plan = Plan::build(&cfg).expect("plan");
        let decl = plan
            .modules
            .iter()
            .find(|m| m.id() == "forgejo_runner")
            .expect("forgejo_runner")
            .declaration();
        let owns_daemon_json = decl
            .files
            .iter()
            .any(|f| f.path == "/etc/docker/daemon.json");
        assert_eq!(
            owns_daemon_json,
            rt == "sysbox-runc" && !v2,
            "one daemon.json owner per host"
        );
        let mut scripts = vec![
            ("probe".to_string(), decl.render_probe()),
            ("apply".to_string(), decl.render_apply()),
            ("rollback".to_string(), decl.render_rollback()),
        ];
        for f in &decl.files {
            if let Some(c) = f.static_content().filter(|c| c.starts_with("#!/bin/")) {
                scripts.push((f.path.clone(), c.to_string()));
            }
        }
        assert_eq!(scripts.len(), 5, "minter and entrypoint parsed too");
        for (kind, script) in scripts {
            if let Err(err) = bash_parse_ok(&script) {
                panic!("ephemeral forgejo {kind} failed bash -n:\n{err}\n---\n{script}");
            }
        }
    }
}

/// `--dry-run` prints `redact(script)`, so no config secret may survive
/// it, in apply or rollback, for any module. Each sentinel must be in some
/// raw script (else the test proves nothing about it).
#[test]
fn dry_run_scripts_never_show_a_config_secret() {
    let mut cfg = wide_config();
    let f = cfg.forgejo.as_mut().expect("--full enables [forgejo]");
    f.secret_key = "SENTINEL-fj-secret-key".into();
    f.internal_token = "SENTINEL-fj-internal-token".into();
    f.jwt_secret = "SENTINELjwtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
    f.database = "postgres".into();
    f.db_password = Some("SENTINEL-fj-db'pw".into());
    f.admin_username = Some("boss".into());
    f.admin_email = Some("boss@example.com".into());
    f.admin_password = Some("SENTINEL-fj-admin pa's\"s\\".into());
    cfg.tailscale.as_mut().unwrap().auth_key = "SENTINEL-ts-authkey".into();
    let r = cfg.restic.as_mut().unwrap();
    r.password = "SENTINEL-restic'pw".into();
    r.env
        .insert("B2_ACCOUNT_KEY".into(), "SENTINEL-restic-env".into());
    let site = &mut cfg.caddy.as_mut().unwrap().sites[0];
    site.tls = "dns".into();
    site.dns_provider = Some("infomaniak".into());
    site.dns_token = Some("SENTINEL-caddy-dns".into());
    cfg.forgejo_runner.as_mut().unwrap().token = "SENTINEL-fr-token".into();
    for (i, gr) in cfg
        .github_runner
        .as_mut()
        .unwrap()
        .runners
        .values_mut()
        .enumerate()
    {
        gr.token = format!("SENTINEL-gh-token-{i}");
        gr.remove_token = format!("SENTINEL-gh-remove-{i}");
    }
    cfg.containers
        .as_mut()
        .unwrap()
        .compose
        .get_mut("web")
        .unwrap()
        .env
        .insert("API_KEY".into(), "SENTINEL-compose\"$env".into());
    let b = cfg.beszel.as_mut().unwrap();
    b.hub = true;
    b.admin_email = "boss@example.com".into();
    b.admin_password = "SENTINEL-beszel-admin".into();
    // Outbound agent mode carries the token instead of a hub.
    let mut agent = cfg.clone();
    let b = agent.beszel.as_mut().unwrap();
    b.hub = false;
    b.admin_password = String::new();
    b.hub_url = "https://hub.example.com".into();
    b.key = "ssh-ed25519 AAAA".into();
    b.token = "SENTINEL-beszel-token".into();
    // Ephemeral runners use an App key instead of runner tokens.
    let mut eph = cfg.clone();
    eph.github_runner = Some(
        toml::from_str(
            "mode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\nrunner_group_id = 3\n\
             app_key = \"-----BEGIN KEY-----\\nSENTINEL-gh-app-key\\n-----END KEY-----\\n\"\n\
             [runners.b-1]\nurl = \"https://github.com/acme\"\n",
        )
        .expect("ephemeral section"),
    );
    eph.forgejo_runner = Some(ephemeral_forgejo_runner("SENTINEL-fr-api-token"));

    let (mut raw, mut shown) = (String::new(), String::new());
    for c in [&cfg, &agent, &eph] {
        for m in &Plan::build(c).expect("plan").modules {
            let d = m.declaration();
            for s in [d.render_apply(), d.render_rollback()] {
                shown.push_str(&format!("\n# {}\n{}", m.id(), d.redact(&s)));
                raw.push_str(&s);
            }
        }
    }
    for s in [
        "SENTINEL-fj-secret-key",
        "SENTINEL-fj-internal-token",
        "SENTINELjwt",
        "SENTINEL-fj-db",
        "SENTINEL-fj-admin",
        "SENTINEL-ts-authkey",
        "SENTINEL-restic",
        "SENTINEL-restic-env",
        "SENTINEL-caddy-dns",
        "SENTINEL-fr-token",
        "SENTINEL-gh-token-0",
        "SENTINEL-gh-remove-0",
        "SENTINEL-beszel-admin",
        "SENTINEL-beszel-token",
        "SENTINEL-gh-app-key",
        "SENTINEL-fr-api-token",
        "SENTINEL-compose",
    ] {
        assert!(
            raw.contains(s),
            "{s} not in any raw script: the test misses it"
        );
    }
    if let Some(i) = shown.find("SENTINEL") {
        let ctx = &shown[i.saturating_sub(300)..(i + 80).min(shown.len())];
        panic!("a secret survives redaction:\n{ctx}");
    }
}
