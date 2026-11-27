//! The `docker` module (R80): owns `/etc/docker/daemon.json` as one engine
//! `ManagedFile` (backup, diff, rollback) rendered by [`daemon_json`] from
//! every source: log limits, the `[docker]` keys and, on v2 runner hosts, the
//! sysbox runtime. With a v2 runner the runner module declares the file
//! instead, so it is written after the sysbox .deb whose postinst edits it.
//! Without `[docker]`, a module that installs Docker enables it logs-only
//! ([`DockerModule::logs_only`]). Optionally installs rootless prerequisites.

use crate::config::schema::DockerSection;
use crate::config::Engine;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// The daemon config file this module manages (Fixed Contract, R80/R90).
pub const DAEMON_JSON: &str = "/etc/docker/daemon.json";

/// The one `daemon.json`: bounded json-file logs by default, or with
/// `log_driver = "journald"` the journal (Vector ships it; journald's
/// own caps apply, and `docker logs` still reads it), the `[docker]` keys,
/// and with `sysbox` exactly what the sysbox-ce postinst adds, so its
/// add-if-missing edits are no-ops on anvil's file.
pub fn daemon_json(docker: Option<&DockerSection>, sysbox: bool) -> String {
    let mut v = if docker.is_some_and(|c| c.log_driver == "journald") {
        // max-size/max-file are json-file options.
        serde_json::json!({ "log-driver": "journald" })
    } else {
        serde_json::json!({
            "log-driver": "json-file",
            "log-opts": { "max-size": "10m", "max-file": "3" },
        })
    };
    if let Some(c) = docker {
        if c.iptables_off() {
            v["iptables"] = false.into();
        }
        if c.userns_remap() {
            v["userns-remap"] = "default".into();
        }
        if c.live_restore {
            v["live-restore"] = true.into();
        }
    }
    if sysbox {
        v["runtimes"] = serde_json::json!({ "sysbox-runc": { "path": "/usr/bin/sysbox-runc" } });
        v["bip"] = "172.20.0.1/16".into();
        v["default-address-pools"] = serde_json::json!([{ "base": "172.25.0.0/16", "size": 24 }]);
    }
    format!("{v:#}\n")
}

pub fn daemon_json_file(docker: Option<&DockerSection>, sysbox: bool) -> ManagedFile {
    ManagedFile::new(
        DAEMON_JSON,
        daemon_json(docker, sysbox),
        "0644",
        "root:root",
    )
}

/// A *defaulted* `[docker]` key must not silently change a Docker
/// host in use. Before daemon.json is written (probe and apply): a defaulted
/// `userns_remap` that the current file lacks, with images or containers
/// present, is `FAILED:` (Docker would switch to a remapped store and they
/// would vanish); a defaulted `iptables_off` over containers that publish
/// ports is a warning. `None` when both keys are set explicitly.
pub fn in_use_guard(docker: Option<&DockerSection>) -> Option<ManagedCommand> {
    let c = docker?;
    let p = shell_escape(DAEMON_JSON);
    let mut s = format!("{{ __cur=$(cat {p} 2>/dev/null || true)\n");
    if c.userns_remap.is_none() {
        s.push_str(
            "case \"$__cur\" in *'\"userns-remap\"'*) ;; *)\n\
             if [ -n \"$(docker images -aq 2>/dev/null || true)$(docker ps -aq 2>/dev/null || true)\" ]; then\n\
             printf 'FAILED: docker: [docker] turns on userns-remap by default, and this host already has Docker images or containers: Docker would switch to a remapped store (/var/lib/docker/100000.100000) and they would become invisible; set userns_remap = true to accept that, or userns_remap = false to keep the current store\\n'; exit 1\n\
             fi ;; esac\n",
        );
    }
    if c.iptables_off.is_none() {
        s.push_str(
            "case \"$__cur\" in *'\"iptables\": false'*) ;; *)\n\
             if docker ps --format '{{.Ports}}' 2>/dev/null | grep -q -- '->'; then\n\
             printf 'anvil: warning: docker: [docker] sets iptables = false by default while containers publish ports: Docker stops managing iptables, so containers lose outbound NAT and published ports fall behind ufw; set iptables_off = true to accept or false to keep Docker'\\''s rules\\n' >&2\n\
             fi ;; esac\n",
        );
    }
    if c.userns_remap.is_some() && c.iptables_off.is_some() {
        return None;
    }
    s.push_str("true; }");
    Some(ManagedCommand::new(
        "[docker] defaults leave a Docker host in use as it is",
        s,
        ":",
    ))
}

/// `dockerd --validate` where dockerd has it; no dockerd yet means the file
/// is simply read when docker first starts. No file (rollback removed the one
/// anvil created) means dockerd's defaults: nothing to validate.
pub fn daemon_json_validate() -> String {
    let p = shell_escape(DAEMON_JSON);
    format!(
        "[ ! -e {p} ] || ! command -v dockerd >/dev/null 2>&1 || case \"$(dockerd --help 2>&1)\" in \
         *--validate*) dockerd --validate --config-file {p} >/dev/null ;; *) true ;; esac"
    )
}

/// Restart dockerd when this run wrote daemon.json (or rollback set
/// `__docker_restart=1`), but never over a running v2 sandbox: then
/// report it and leave the restart to the operator.
pub fn restart_dockerd() -> String {
    let p = shell_escape(DAEMON_JSON);
    format!(
        "__dj=${{__docker_restart:-0}}; for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do \
         [ \"$__p\" != {p} ] || __dj=1; done; \
         if [ \"$__dj\" = 1 ] && command -v dockerd >/dev/null 2>&1; then \
         if [ -n \"$(docker ps -q --filter name=anvil-github-runner- --filter name=anvil-forgejo-runner- 2>/dev/null)\" ]; then \
         printf 'anvil: warning: docker: daemon.json changed; dockerd restart deferred while runner sandboxes run (restart docker when idle)\\n' >&2; \
         else {{ systemctl reset-failed docker 2>/dev/null; systemctl restart docker 2>/dev/null; }} || service docker restart; fi; fi; "
    )
}

pub struct DockerModule {
    /// `None`: no `[docker]`, but a module installs Docker.
    cfg: Option<DockerSection>,
    /// A v2 (ephemeral) github_runner declares daemon.json instead.
    runner_owns_daemon_json: bool,
}

impl DockerModule {
    pub fn new(cfg: DockerSection) -> Self {
        Self {
            cfg: Some(cfg),
            runner_owns_daemon_json: false,
        }
    }

    /// No `[docker]` but Docker gets installed: cap container logs
    /// in a daemon.json anvil creates. An existing one (the operator's) is
    /// kept as it is: its keys are not anvil's to drop.
    pub fn logs_only() -> Self {
        Self {
            cfg: None,
            runner_owns_daemon_json: false,
        }
    }

    fn file(&self) -> ManagedFile {
        if let Some(c) = &self.cfg {
            return daemon_json_file(Some(c), false);
        }
        let p = shell_escape(DAEMON_JSON);
        ManagedFile::computed(
            DAEMON_JSON,
            format!(
                "if [ -e {p} ]; then cat {p}; else printf '%s' {}; fi",
                shell_escape(&daemon_json(None, false))
            ),
            "0644",
            "root:root",
        )
    }

    pub fn runner_owns_daemon_json(mut self, on: bool) -> Self {
        self.runner_owns_daemon_json = on;
        self
    }

    /// Rootless docker needs the sub-uid/gid mapping tool-chain; we install the
    /// prerequisites idempotently. The per-user `dockerd-rootless-setuptool.sh`
    /// step is intentionally left to the unprivileged account, since `[docker]`
    /// names no target user.
    fn rootless_command() -> ManagedCommand {
        ManagedCommand::new(
            "install rootless docker prerequisites",
            "dpkg -s uidmap >/dev/null 2>&1 && dpkg -s dbus-user-session >/dev/null 2>&1",
            apt_install(&["uidmap", "dbus-user-session"]),
        )
    }
}

impl Module for DockerModule {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("docker");
        // `[docker]` alone installs the engine (same command, so a module
        // that also needs Docker adds no second install). Rollback keeps it.
        if let Some(c) = &self.cfg {
            decl = decl.command(super::ensure_engine(Engine::Docker, c.distro()));
        }
        if !self.runner_owns_daemon_json {
            if let Some(g) = in_use_guard(self.cfg.as_ref()) {
                decl = decl.command(g);
            }
            decl = decl
                .file(self.file())
                // Rollback re-runs the guarded reload; restart dockerd so the
                // restored (or removed) daemon.json actually takes effect.
                .rollback_script("__docker_restart=1\n")
                .guarded_reload(ReloadGuard {
                    describe: "docker daemon".into(),
                    validate: daemon_json_validate(),
                    reload: restart_dockerd(),
                });
        }
        if self.cfg.as_ref().is_some_and(|c| c.rootless) {
            decl = decl.command(Self::rootless_command());
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut DockerSection)) -> DockerModule {
        let mut cfg = DockerSection::default();
        mutate(&mut cfg);
        DockerModule::new(cfg)
    }

    const LOGS: &str = "  \"log-driver\": \"json-file\",\n  \"log-opts\": {\n    \"max-file\": \"3\",\n    \"max-size\": \"10m\"\n  }";
    const SYSBOX: &str = "  \"bip\": \"172.20.0.1/16\",\n  \"default-address-pools\": [\n    {\n      \"base\": \"172.25.0.0/16\",\n      \"size\": 24\n    }\n  ],\n";
    const RUNTIMES: &str = ",\n  \"runtimes\": {\n    \"sysbox-runc\": {\n      \"path\": \"/usr/bin/sysbox-runc\"\n    }\n  }";
    const KEYS: &str = "  \"iptables\": false,\n  \"live-restore\": true,\n";

    #[test]
    fn daemon_json_for_every_source_combination() {
        let d = DockerSection::default();
        let none = daemon_json(None, false);
        assert_eq!(none, format!("{{\n{LOGS}\n}}\n"));
        assert_eq!(
            daemon_json(Some(&d), false),
            format!("{{\n{KEYS}{LOGS},\n  \"userns-remap\": \"default\"\n}}\n")
        );
        assert_eq!(
            daemon_json(None, true),
            format!("{{\n{SYSBOX}{LOGS}{RUNTIMES}\n}}\n")
        );
        assert_eq!(
            daemon_json(Some(&d), true),
            format!("{{\n{SYSBOX}{KEYS}{LOGS}{RUNTIMES},\n  \"userns-remap\": \"default\"\n}}\n")
        );
    }

    #[test]
    fn journald_log_driver_drops_the_json_file_caps() {
        let c = DockerSection {
            log_driver: "journald".into(),
            ..DockerSection::default()
        };
        for sysbox in [false, true] {
            let j = daemon_json(Some(&c), sysbox);
            assert!(j.contains("\"log-driver\": \"journald\""), "{j}");
            assert!(!j.contains("log-opts") && !j.contains("json-file"), "{j}");
            assert!(j.contains("\"live-restore\": true"), "{j}");
            assert_eq!(j.contains("sysbox-runc"), sysbox, "{j}");
        }
    }

    #[test]
    fn each_docker_key_is_its_own_switch() {
        let only = |k: u8| {
            let c = DockerSection {
                iptables_off: Some(k == 0),
                userns_remap: Some(k == 1),
                live_restore: k == 2,
                ..DockerSection::default()
            };
            daemon_json(Some(&c), false)
        };
        for (k, key) in ["iptables", "userns-remap", "live-restore"]
            .iter()
            .enumerate()
        {
            let j = only(k as u8);
            assert_eq!(
                j.matches(": false").count()
                    + j.matches(": true").count()
                    + j.matches("\"default\"").count(),
                1,
                "{j}"
            );
            assert!(j.contains(key), "{j}");
        }
    }

    #[test]
    fn owns_daemon_json_as_a_managed_file_behind_a_guard() {
        let d = module(|_| {}).declaration();
        assert_eq!(
            d.files,
            vec![daemon_json_file(Some(&DockerSection::default()), false)]
        );
        assert_eq!(d.files[0].mode, "0644");
        let g = d.reload.as_ref().unwrap();
        assert!(g
            .validate
            .contains("dockerd --validate --config-file '/etc/docker/daemon.json'"));
        // Rollback that removed the file anvil created must not fail validation.
        assert!(g
            .validate
            .starts_with("[ ! -e '/etc/docker/daemon.json' ] || "));
        assert!(g.reload.contains("systemctl restart docker"));
        // An apply + rollback within a minute must not trip start-limit-hit.
        assert!(g.reload.contains("systemctl reset-failed docker"));
        let probe = d.render_probe();
        assert!(probe.contains(DAEMON_JSON));
        assert!(!probe.contains("systemctl restart docker"));
    }

    #[test]
    fn logs_only_creates_a_capped_daemon_json_and_keeps_an_existing_one() {
        let d = DockerModule::logs_only().declaration();
        assert_eq!(d.files.len(), 1);
        assert!(d.reload.is_some() && d.commands.is_empty());
        let crate::engine::FileContent::Computed { generator: gen } = &d.files[0].content else {
            panic!("computed");
        };
        let dir = std::env::temp_dir().join(format!("anvil-dj-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("daemon.json");
        let _ = std::fs::remove_file(&f);
        let run = || {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(gen.replace(DAEMON_JSON, f.to_str().unwrap()))
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run(), daemon_json(None, false));
        std::fs::write(&f, "{\"data-root\": \"/srv/docker\"}\n").unwrap();
        assert_eq!(run(), "{\"data-root\": \"/srv/docker\"}\n");
        // Rollback deletes it only if anvil created it.
        assert!(d
            .render_rollback()
            .contains("was not created by anvil and has no backup; left in place"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_v2_runner_owns_daemon_json_instead() {
        let d = module(|c| c.rootless = false)
            .runner_owns_daemon_json(true)
            .declaration();
        assert!(d.files.is_empty() && d.reload.is_none() && d.rollback.is_none());
        assert_eq!(d.commands.len(), 1, "only the engine install");
        assert!(!d.render_apply().contains(DAEMON_JSON));
    }

    #[test]
    fn rollback_restarts_docker_with_the_restored_config() {
        let rb = module(|_| {}).declaration().render_rollback();
        let flag = rb.find("__docker_restart=1").unwrap();
        let restart = rb.rfind("systemctl restart docker").unwrap();
        assert!(flag < restart);
    }

    #[test]
    fn docker_section_alone_installs_the_engine_from_its_source() {
        for (distro, want) in [(false, "docker-ce"), (true, "docker.io")] {
            let d = module(|c| c.source = if distro { "distro" } else { "vendor" }.into())
                .declaration();
            assert_eq!(
                d.commands[0],
                super::super::ensure_engine(Engine::Docker, distro)
            );
            let apply = d.render_apply();
            let install = apply.find(want).expect(want);
            assert!(
                install < apply.find(DAEMON_JSON).unwrap(),
                "install, then daemon.json"
            );
        }
        // A v2 runner owns daemon.json; [docker] still installs the engine.
        let d = module(|_| {}).runner_owns_daemon_json(true).declaration();
        assert_eq!(
            d.commands,
            vec![super::super::ensure_engine(Engine::Docker, false)]
        );
        // Logs-only (no [docker]) installs nothing: another module does.
        assert!(DockerModule::logs_only().declaration().commands.is_empty());
    }

    /// Runs [`in_use_guard`]'s detect with a stub `docker` (images, ps -a,
    /// ps --format output) and `daemon.json`; returns (exit ok, stdout, stderr).
    fn run_guard(c: &DockerSection, dj: Option<&str>, docker: [&str; 3]) -> (bool, String, String) {
        let dir = std::env::temp_dir().join(format!(
            "anvil-guard-{}-{:?}-{:?}-{}",
            std::process::id(),
            (c.userns_remap, c.iptables_off),
            dj.map(str::len),
            docker.concat().len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("daemon.json");
        if let Some(dj) = dj {
            std::fs::write(&f, dj).unwrap();
        }
        let [imgs, ctrs, ports] = docker.map(shell_escape);
        let stub = dir.join("docker");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\ncase \"$1 $2\" in images*) printf '%s' {imgs} ;; 'ps --format') printf '%s' {ports} ;; ps*) printf '%s' {ctrs} ;; esac\n"
            ),
        )
        .unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&stub)
            .status()
            .unwrap();
        let detect = in_use_guard(Some(c)).unwrap().detect;
        let script = format!(
            "set -euo pipefail\nPATH='{}':\"$PATH\"\nif {}; then echo PASS; fi",
            dir.display(),
            detect.replace(DAEMON_JSON, f.to_str().unwrap())
        );
        let out = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        (
            out.status.success() && stdout.contains("PASS"),
            stdout,
            String::from_utf8_lossy(&out.stderr).into(),
        )
    }

    #[test]
    fn defaulted_userns_remap_refuses_a_host_with_images_or_containers() {
        let d = DockerSection::default();
        for docker in [["sha256:a\n", "", ""], ["", "c1\n", ""]] {
            for dj in [None, Some("{\"log-driver\": \"json-file\"}\n")] {
                let (ok, out, _) = run_guard(&d, dj, docker);
                assert!(!ok, "{out}");
                assert!(out.starts_with("FAILED: docker: "), "{out}");
                assert!(out.contains("userns_remap = false"), "{out}");
            }
        }
        // Nothing to lose, or remap already on: no flip, nothing printed.
        let (ok, out, _) = run_guard(&d, None, ["", "", ""]);
        assert!(ok && out == "PASS\n", "{out}");
        let on = "{\n  \"userns-remap\": \"default\"\n}\n";
        let (ok, out, _) = run_guard(&d, Some(on), ["sha256:a\n", "c1\n", ""]);
        assert!(ok && out == "PASS\n", "{out}");
        // Explicit `userns_remap = true` is the opt-in.
        let accept = DockerSection {
            userns_remap: Some(true),
            ..DockerSection::default()
        };
        let (ok, out, _) = run_guard(&accept, None, ["sha256:a\n", "c1\n", ""]);
        assert!(ok, "{out}");
    }

    #[test]
    fn defaulted_iptables_off_warns_over_published_ports_only() {
        let d = DockerSection {
            userns_remap: Some(false),
            ..DockerSection::default()
        };
        let ports = "0.0.0.0:8080->80/tcp\n";
        let (ok, _, err) = run_guard(&d, None, ["", "c1\n", ports]);
        assert!(ok && err.contains("anvil: warning: docker: "), "{err}");
        assert!(err.contains("iptables_off = true"), "{err}");
        for (dj, p) in [(None, ""), (Some("{\"iptables\": false}"), ports)] {
            let (ok, _, err) = run_guard(&d, dj, ["", "c1\n", p]);
            assert!(ok && err.is_empty(), "{err}");
        }
    }

    #[test]
    fn in_use_guard_only_for_defaulted_keys_and_before_daemon_json() {
        let set = |u, i| DockerSection {
            userns_remap: u,
            iptables_off: i,
            ..DockerSection::default()
        };
        assert!(in_use_guard(None).is_none());
        assert!(in_use_guard(Some(&set(Some(true), Some(false)))).is_none());
        let g = |u, i| in_use_guard(Some(&set(u, i))).unwrap().detect;
        assert!(
            g(None, Some(true)).contains("userns-remap") && !g(None, Some(true)).contains(".Ports")
        );
        assert!(
            !g(Some(false), None).contains("userns-remap")
                && g(Some(false), None).contains(".Ports")
        );
        let apply = module(|_| {}).declaration().render_apply();
        assert!(
            apply.find("userns-remap by default").unwrap()
                < apply.find("__path='/etc/docker/daemon.json'").unwrap()
        );
        assert!(
            module(|c| *c = set(Some(true), Some(true)))
                .declaration()
                .commands
                .len()
                == 1
        );
        // A v2 runner owns daemon.json: the guard goes with it.
        assert!(!module(|_| {})
            .runner_owns_daemon_json(true)
            .declaration()
            .render_apply()
            .contains("userns-remap by default"));
    }

    #[test]
    fn rootless_adds_prerequisites() {
        let apply = module(|c| c.rootless = true).declaration().render_apply();
        assert!(apply.contains("uidmap"));
        assert!(!module(|_| {})
            .declaration()
            .render_apply()
            .contains("uidmap"));
    }

    /// Runs `restart_dockerd` with stub docker/systemctl; returns the calls.
    fn run_restart(pre: &str, ps: &str) -> (String, String) {
        let dir = std::env::temp_dir().join(format!(
            "anvil-dockerd-{}-{}",
            std::process::id(),
            pre.len() + ps.len()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log");
        for (bin, body) in [
            ("dockerd", String::new()),
            ("docker", format!("printf '%s' {}", shell_escape(ps))),
            (
                "systemctl",
                format!("echo \"systemctl $*\" >> '{}'", log.display()),
            ),
        ] {
            let f = dir.join(bin);
            std::fs::write(&f, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::process::Command::new("chmod")
                .arg("+x")
                .arg(&f)
                .status()
                .unwrap();
        }
        let script = format!(
            "set -euo pipefail\nPATH='{}':\"$PATH\"\n__creates=()\n__reverts=()\n{pre}\n{}\n",
            dir.display(),
            restart_dockerd()
        );
        let out = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let calls = std::fs::read_to_string(&log).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        (calls, String::from_utf8_lossy(&out.stderr).into())
    }

    #[test]
    fn restarts_only_on_change_and_never_over_a_sandbox() {
        let changed = format!("__reverts+=({})", shell_escape(DAEMON_JSON));
        assert_eq!(run_restart("", "").0, "");
        assert_eq!(run_restart("__reverts+=(/etc/other)", "").0, "");
        let (calls, _) = run_restart(&changed, "");
        assert!(calls.contains("systemctl restart docker"), "{calls}");
        let (calls, _) = run_restart(&format!("__creates+=({})", shell_escape(DAEMON_JSON)), "");
        assert!(calls.contains("systemctl restart docker"), "{calls}");
        let (calls, _) = run_restart("__docker_restart=1", "");
        assert!(calls.contains("systemctl restart docker"), "{calls}");
        let (calls, err) = run_restart(&changed, "abc123\n");
        assert_eq!(calls, "");
        assert!(err.contains("dockerd restart deferred"), "{err}");
    }
}
