//! The `containers` module: Docker Compose projects as managed files plus one
//! systemd unit each.
//!
//! Per project `<n>` it owns `/etc/anvil/compose/<n>/compose.yaml` (0640),
//! an optional `.env` (0600, the only place secrets live) and
//! `/etc/systemd/system/anvil-compose-<n>.service`. The unit runs
//! `docker compose up -d` on start/reload and `down` on stop.
//!
//! Restart discipline: a project is touched only when one of *its* files was
//! written this run (or its unit is inactive), and then via
//! `systemctl reload-or-restart` — `up -d` recreates only the services whose
//! config changed. A compose file that fails `docker compose config` reverts.
//!
//! The project name is validated (`[a-z0-9][a-z0-9_-]*`) and still
//! shell-escaped wherever it reaches bash. File contents are base64-embedded
//! (compose.yaml) or built from escaped `printf` args (`.env`).

#[cfg(test)]
use crate::config::schema::QuadletContainer;
use crate::config::schema::{ComposeProject, ContainersSection};
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX};
use crate::escape::shell_escape;

use super::podman::{containers_conf, PODMAN_CONF};
use super::{apt_install, ensure_engine, Module};
use crate::config::Engine;

/// Parent of every project directory (Fixed Contract for drift/rollback).
pub const COMPOSE_ROOT: &str = "/etc/anvil/compose";

pub fn project_dir(name: &str) -> String {
    format!("{COMPOSE_ROOT}/{name}")
}
pub fn compose_path(name: &str) -> String {
    format!("{COMPOSE_ROOT}/{name}/compose.yaml")
}
pub fn env_path(name: &str) -> String {
    format!("{COMPOSE_ROOT}/{name}/.env")
}
pub fn unit_name(name: &str) -> String {
    format!("anvil-compose-{name}.service")
}
pub fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{}", unit_name(name))
}

pub struct ContainersModule {
    cfg: ContainersSection,
    /// Docker writes its own iptables rules (`[docker] iptables_off = false`),
    /// so a published port skips ufw and must stay on loopback (CR13).
    guard_ports: bool,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
    /// The host engine: Podman runs Quadlets, Docker runs compose projects.
    engine: Engine,
    /// `[podman]` declares the containers.conf drop-in instead.
    podman_owns_conf: bool,
    /// `[apps_resources]`: compose units put `Slice=apps.slice` on the unit.
    in_apps_slice: bool,
}

impl ContainersModule {
    pub fn new(cfg: ContainersSection) -> Self {
        Self {
            cfg,
            guard_ports: true,
            docker_distro: false,
            engine: Engine::Docker,
            podman_owns_conf: false,
            in_apps_slice: false,
        }
    }

    /// `[apps_resources]`: every compose unit joins `apps.slice`.
    pub fn in_apps_slice(mut self, on: bool) -> Self {
        self.in_apps_slice = on;
        self
    }

    pub fn engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    pub fn podman_owns_conf(mut self, on: bool) -> Self {
        self.podman_owns_conf = on;
        self
    }

    pub fn iptables_off(mut self, off: bool) -> Self {
        self.guard_ports = !off;
        self
    }

    /// `[docker] source = "distro"`: install the engine from Ubuntu's packages.
    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }
}

/// Guard clause: every port the project publishes binds a loopback host IP.
/// Counted on `docker compose config` (compose's own normalizer, so short,
/// long and flow syntax and `${VAR}` from `.env` are all resolved): one
/// `"target"` per port entry must match one loopback `"host_ip"`.
pub fn loopback_ports_check(name: &str) -> String {
    let compose = shell_escape(&compose_path(name));
    let project = shell_escape(name);
    // Fails closed: a failing `config --format json` fails the guard; only
    // the grep (no ports at all) may come back empty.
    let ports = format!(
        r#"__json=$(docker compose -p {project} -f {compose} config --format json) && __ports=$(printf '%s' "$__json" | tr -d ' \t\n' | grep -o '"ports":\[[^]]*\]' || true)"#
    );
    let count = |re: &str| format!(r#""$(printf '%s' "$__ports" | grep -oE '{re}' | wc -l)""#);
    format!(
        "{{ [ ! -f {compose} ] || {{ {ports} && [ {} -eq {} ]; }} || {{ printf 'FAILED: compose \
         project %s may publish a port beyond 127.0.0.1; Docker would expose it past ufw\\n' \
         {project}; false; }}; }}",
        count(r#""target""#),
        count(r#""host_ip":"(127\.[0-9.]+|::1)""#),
    )
}

/// The systemd unit for project `name`. The name is validated at load to the
/// compose project-name charset, so it is inert in a unit file.
pub fn unit_content(name: &str, in_apps_slice: bool) -> String {
    let dir = project_dir(name);
    let compose = "/usr/bin/docker compose -p";
    let slice = if in_apps_slice {
        format!("Slice={}\n", super::apps_resources::SLICE)
    } else {
        String::new()
    };
    format!(
        "# Managed by anvil — do not edit by hand\n\
         [Unit]\n\
         Description=anvil compose project {name}\n\
         After=docker.service network-online.target\n\
         Wants=docker.service network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         RemainAfterExit=yes\n\
         TimeoutStartSec=0\n\
         {slice}\
         WorkingDirectory={dir}\n\
         ExecStart={compose} {name} -f compose.yaml up -d --remove-orphans\n\
         ExecReload={compose} {name} -f compose.yaml up -d --remove-orphans\n\
         ExecStop={compose} {name} -f compose.yaml down\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// The `.env` generator: one `KEY="value"` line per entry, escaped so compose
/// reads it literally: `\\`, `\"` and `\$` (no interpolation). Control
/// characters are rejected at load. A `Computed` file, so `diff` never prints
/// the secrets.
pub fn env_generator(p: &ComposeProject) -> String {
    let lines: Vec<String> = p
        .env
        .iter()
        .map(|(k, v)| format!("{k}=\"{}\"", env_escape(v)))
        .collect();
    format!(
        "printf '%s\\n' {}",
        crate::escape::shell_escape_join(&lines)
    )
}

fn env_escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('$', "\\$")
}

/// True (exit 0) when any file under `name`'s directory or its unit was
/// created or modified this run. No `grep -q` in a pipe (§ bash gate).
fn changed_test(name: &str) -> String {
    format!(
        "[[ \" ${{__creates[*]-}} ${{__reverts[*]-}} \" == *{dir}/* || \
         \" ${{__creates[*]-}} ${{__reverts[*]-}} \" == *{unit}* ]]",
        dir = shell_escape(&project_dir(name)),
        unit = shell_escape(&unit_path(name)),
    )
}

impl Module for ContainersModule {
    fn id(&self) -> &'static str {
        "containers"
    }

    fn declaration(&self) -> Declaration {
        if self.engine == Engine::Podman {
            return podman_declaration(&self.cfg, self.podman_owns_conf);
        }
        let mut decl = Declaration::new("containers");
        if self.cfg.compose.is_empty() {
            return decl;
        }
        decl = decl
            .command(ensure_engine(Engine::Docker, self.docker_distro))
            .command(ManagedCommand::new(
                "docker compose v2 available",
                "docker compose version >/dev/null 2>&1",
                // Vendor repo ships docker-compose-plugin; Ubuntu's distro docker.io
                // pairs with docker-compose-v2; Debian 13's docker-compose (2.26, Go)
                // ships the CLI plugin. The final check rejects a v1 docker-compose.
                format!(
                    "{} || {} || {} || true\ndocker compose version >/dev/null",
                    apt_install(&["docker-compose-plugin"]),
                    apt_install(&["docker-compose-v2"]),
                    apt_install(&["docker-compose"]),
                ),
            ));

        let mut validate = Vec::new();
        let mut reload = vec!["systemctl daemon-reload".to_string()];
        let mut rollback = String::new();
        let mut rollback_first = String::new();
        for (i, (name, p)) in self.cfg.compose.iter().enumerate() {
            let dir = shell_escape(&project_dir(name));
            let compose = shell_escape(&compose_path(name));
            let env = shell_escape(&env_path(name));
            let unit = shell_escape(&unit_name(name));
            let unit_file = shell_escape(&unit_path(name));
            let root = shell_escape(COMPOSE_ROOT);
            let project = shell_escape(name);
            // "start/reload this project"; by index, as `-` is not valid in a
            // variable name and `a-b`/`a_b` must not share a flag.
            let flag = format!("__compose_up_{i}");

            decl = decl
                .command(ManagedCommand::new(
                    format!("compose project dir {}", project_dir(name)),
                    format!("[ -d {dir} ] && [ \"$(stat -c '%a' {dir})\" = '750' ]"),
                    format!(
                        "install -d -m 0750 {root} {dir}",
                        root = shell_escape(COMPOSE_ROOT)
                    ),
                ))
                .command(ManagedCommand::new(
                    format!("compose project {name} running"),
                    format!("systemctl is-active --quiet {unit}"),
                    format!("{flag}=1"),
                ))
                .file(ManagedFile::new(
                    compose_path(name),
                    p.content.clone(),
                    "0640",
                    "root:root",
                ));
            if !p.env.is_empty() {
                decl = decl.file(ManagedFile::computed(
                    env_path(name),
                    env_generator(p),
                    "0600",
                    "root:root",
                ));
                // The generator embeds the escaped form: mask both in `-n`.
                for v in p.env.values() {
                    decl = decl.secret(v).secret(env_escape(v));
                }
            }
            decl = decl.file(ManagedFile::new(
                unit_path(name),
                unit_content(name, self.in_apps_slice),
                "0644",
                "root:root",
            ));

            // Skip projects whose file is gone (rollback re-runs this guard).
            validate.push(format!(
                "{{ [ ! -f {compose} ] || docker compose -p {project} -f {compose} config -q; }}"
            ));
            if self.guard_ports {
                validate.push(loopback_ports_check(name));
            }
            // Refuse a `.env` (anvil's or hand-placed) that others can read.
            validate.push(format!(
                "{{ [ ! -e {env} ] || [ $(( 0$(stat -c '%a' {env}) & 4 )) = 0 ]; }}"
            ));
            reload.push(format!(
                "if [ -f {unit_file} ]; then systemctl enable {unit} >/dev/null 2>&1 || true; \
                 if [ \"${{{flag}:-0}}\" = 1 ] || {changed}; then systemctl reload-or-restart {unit}; fi; fi",
                changed = changed_test(name),
            ));
            // CR17: a project rollback is about to delete is stopped while its
            // unit and compose file still exist, so ExecStop's `down` works.
            rollback_first.push_str(&format!(
                "\n# rollback (before files): stop compose project {name}\n\
                 if [ ! -f {bak} ] && __anvil_created {compose} && \
                 {{ systemctl is-active --quiet {unit} || systemctl is-enabled --quiet {unit}; }} 2>/dev/null; then\n\
                 \x20 systemctl disable --now {unit} >/dev/null 2>&1 || true\n\
                 \x20 printf 'CHANGED: compose project %s stopped and disabled\\n' {project}\n\
                 fi\n",
                bak = shell_escape(&format!("{}{BACKUP_SUFFIX}", compose_path(name))),
            ));
            // Runs after the engine restored/removed the files. A restored
            // project is re-upped by the guard; a removed one is taken down by
            // project name (its compose file is already gone).
            rollback.push_str(&format!(
                "\n# rollback (module-authored): compose project {name}\n\
                 if [ -f {compose} ]; then\n\
                 \x20 {flag}=1\n\
                 \x20 printf 'OK: compose project %s restored; re-applied by the reload\\n' {project}\n\
                 else\n\
                 \x20 systemctl stop {unit} >/dev/null 2>&1 || true\n\
                 \x20 rm -f /etc/systemd/system/multi-user.target.wants/{unit}\n\
                 \x20 if command -v docker >/dev/null 2>&1 && [ -n \"$(docker compose -p {project} ps -aq 2>/dev/null)\" ]; then\n\
                 \x20\x20 docker compose -p {project} down --remove-orphans >/dev/null 2>&1 || \
                 docker ps -aq --filter label=com.docker.compose.project={project} | xargs -r docker rm -f >/dev/null || true\n\
                 \x20\x20 printf 'CHANGED: compose project %s stopped and removed\\n' {project}\n\
                 \x20 else\n\
                 \x20\x20 printf 'OK: compose project %s has no containers\\n' {project}\n\
                 \x20 fi\n\
                 \x20 systemctl reset-failed {unit} >/dev/null 2>&1 || true\n\
                 \x20 rmdir {dir} {root} /etc/anvil 2>/dev/null || true\n\
                 fi\n"
            ));
        }
        // Each project's images as its compose file names them now.
        let refs: Vec<String> = self
            .cfg
            .compose
            .keys()
            .map(|name| {
                let compose = shell_escape(&compose_path(name));
                format!(
                    "{{ [ ! -f {compose} ] || docker compose -p {} -f {compose} config --images 2>/dev/null; }}",
                    shell_escape(name)
                )
            })
            .collect();
        super::prune_superseded(decl, "compose", "docker", &refs.join("; "))
            .rollback_first(rollback_first)
            .rollback_script(rollback)
            .guarded_reload(ReloadGuard {
                describe: "compose projects".into(),
                validate: validate.join(" && "),
                reload: reload.join("\n"),
            })
    }
}

// --- runtime = "podman": rootful Quadlets ----------------------------------

/// Quadlet's admin unit directory (rootful).
pub const QUADLET_DIR: &str = "/etc/containers/systemd";
const QUADLET_BIN: &str = "/usr/libexec/podman/quadlet";

pub fn quadlet_path(name: &str) -> String {
    format!("{QUADLET_DIR}/anvil-{name}.container")
}
/// The service Quadlet generates from `anvil-<name>.container`.
pub fn quadlet_unit(name: &str) -> String {
    format!("anvil-{name}.service")
}

/// Guard clause: `file` (if present) converts to `unit`. Quadlet skips a
/// file it cannot convert, so "no generated service" is the error signal. Its
/// exit code is ignored: from 4.6 it is non-zero for *any* broken file in the
/// directory, not just ours.
pub fn quadlet_converts(file: &str, unit: &str) -> String {
    format!(
        "{{ [ ! -f {f} ] || {{ {QUADLET_BIN} -dryrun 2>/dev/null || true; }} | grep -xF -e {marker} >/dev/null || \
         {{ printf 'FAILED: quadlet %s does not convert (see {QUADLET_BIN} -dryrun)\\n' {f}; false; }}; }}",
        f = shell_escape(file),
        marker = shell_escape(&format!("---{unit}---")),
    )
}

fn podman_declaration(cfg: &ContainersSection, podman_owns_conf: bool) -> Declaration {
    let mut decl = Declaration::new("containers");
    // Every Podman host gets the iptables driver, Quadlets or not: a
    // v2 runner's sandboxes and image builds need outbound too.
    if !podman_owns_conf {
        decl = decl.file(ManagedFile::new(
            PODMAN_CONF,
            containers_conf(None),
            "0644",
            "root:root",
        ));
    }
    if cfg.quadlet.is_empty() {
        return decl;
    }
    decl = decl.command(ensure_engine(Engine::Podman, false));
    let mut validate = Vec::new();
    let mut reload = vec!["systemctl daemon-reload".to_string()];
    let mut rollback = String::from("\n# rollback (module-authored): drop removed Quadlet units\n");
    let mut rollback_first = String::new();
    for (i, name) in cfg.quadlet.keys().enumerate() {
        let file = shell_escape(&quadlet_path(name));
        let unit = shell_escape(&quadlet_unit(name));
        let flag = format!("__quadlet_up_{i}");
        decl = decl
            .command(ManagedCommand::new(
                format!("quadlet {name} running"),
                format!("systemctl is-active --quiet {unit}"),
                format!("{flag}=1"),
            ))
            .file(ManagedFile::new(
                quadlet_path(name),
                cfg.quadlet[name].content.clone(),
                "0644",
                "root:root",
            ));
        validate.push(quadlet_converts(&quadlet_path(name), &quadlet_unit(name)));
        reload.push(format!(
            "if [ -f {file} ] && {{ [ \"${{{flag}:-0}}\" = 1 ] || [[ \" ${{__creates[*]-}} ${{__reverts[*]-}} \" == *{file}* ]]; }}; then \
             systemctl restart {unit}; fi"
        ));
        // Stop while the file exists (the generated unit's ExecStop removes
        // the container); images and volumes are never touched.
        rollback_first.push_str(&format!(
            "\n# rollback (before files): stop quadlet {name}\n\
             if [ ! -f {bak} ] && __anvil_created {file} && systemctl is-active --quiet {unit} 2>/dev/null; then\n\
             \x20 systemctl stop {unit} >/dev/null 2>&1 || true\n\
             \x20 printf 'CHANGED: quadlet %s stopped\\n' {n}\n\
             fi\n",
            bak = shell_escape(&format!("{}{BACKUP_SUFFIX}", quadlet_path(name))),
            n = shell_escape(name),
        ));
        rollback.push_str(&format!(
            "if [ -f {file} ]; then {flag}=1; else systemctl reset-failed {unit} >/dev/null 2>&1 || true; fi\n"
        ));
    }
    let files: Vec<String> = cfg
        .quadlet
        .keys()
        .map(|n| shell_escape(&quadlet_path(n)))
        .collect();
    let refs = format!("sed -n 's/^Image=//p' {} 2>/dev/null", files.join(" "));
    super::prune_superseded(decl, "quadlet", "podman", &refs)
        .rollback_first(rollback_first)
        .rollback_script(rollback)
        .guarded_reload(ReloadGuard {
            describe: "quadlet units".into(),
            validate: validate.join(" && "),
            reload: reload.join("\n"),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn project(content: &str, env: &[(&str, &str)]) -> ComposeProject {
        ComposeProject {
            content: content.into(),
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn module(projects: &[(&str, ComposeProject)]) -> ContainersModule {
        ContainersModule::new(ContainersSection {
            compose: projects
                .iter()
                .map(|(n, p)| (n.to_string(), p.clone()))
                .collect::<BTreeMap<_, _>>(),
            ..Default::default()
        })
    }

    const YAML: &str =
        "services:\n  web:\n    image: nginx:1.27\n    environment:\n      PASS: ${PASS}\n";

    #[test]
    fn empty_section_does_nothing() {
        let d = module(&[]).declaration();
        assert!(d.files.is_empty() && d.commands.is_empty() && d.reload.is_none());
    }

    #[test]
    fn owns_compose_file_env_and_unit_with_tight_modes() {
        let d = module(&[("web", project(YAML, &[("PASS", "s3cret")]))]).declaration();
        let by_path = |p: &str| d.files.iter().find(|f| f.path == p).unwrap();
        let compose = by_path("/etc/anvil/compose/web/compose.yaml");
        assert_eq!(compose.mode, "0640");
        assert_eq!(compose.static_content(), Some(YAML));
        let env = by_path("/etc/anvil/compose/web/.env");
        assert_eq!(env.mode, "0600");
        assert!(env.static_content().is_none(), ".env must never be diffed");
        let unit = by_path("/etc/systemd/system/anvil-compose-web.service");
        assert_eq!(
            unit.static_content(),
            Some(unit_content("web", false).as_str())
        );
    }

    #[test]
    fn no_env_means_no_env_file() {
        let d = module(&[("web", project(YAML, &[]))]).declaration();
        assert!(!d.files.iter().any(|f| f.path.ends_with("/.env")));
    }

    #[test]
    fn unit_runs_compose_up_and_down_for_its_project() {
        let u = unit_content("web", false);
        assert!(u.contains("WorkingDirectory=/etc/anvil/compose/web\n"));
        assert!(u.contains("ExecStart=/usr/bin/docker compose -p web -f compose.yaml up -d"));
        assert!(u.contains("ExecReload=/usr/bin/docker compose -p web -f compose.yaml up -d"));
        assert!(u.contains("ExecStop=/usr/bin/docker compose -p web -f compose.yaml down"));
        // Wants=, not Requires=: Requires= would restart the unit (down + up)
        // whenever dockerd restarts, defeating live-restore.
        assert!(u.contains("Wants=docker.service"));
        assert!(!u.contains("Requires="));
    }

    #[test]
    fn unit_joins_apps_slice_only_with_apps_resources() {
        let on = unit_content("web", true);
        assert!(
            on.contains("[Service]\n") && on.contains("\nSlice=apps.slice\n"),
            "Slice= belongs to [Service]:\n{on}"
        );
        assert!(!unit_content("web", false).contains("apps.slice"));
        // The module passes its own flag into the unit it declares.
        let d = module(&[("web", project(YAML, &[]))])
            .in_apps_slice(true)
            .declaration();
        let unit = d
            .files
            .iter()
            .find(|f| f.path == "/etc/systemd/system/anvil-compose-web.service")
            .and_then(|f| f.static_content())
            .expect("unit");
        assert!(unit.contains("\nSlice=apps.slice\n"), "{unit}");
    }

    #[test]
    fn env_generator_quotes_values_literally() {
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(env_generator(&project(
                YAML,
                &[("A", "x $y \"z\""), ("B", "2"), ("C", r"it's \ ${D}\")],
            )))
            .output()
            .unwrap();
        // CR18: compose-go's double-quoted dotenv unescapes \\ \" \$ back.
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "A=\"x \\$y \\\"z\\\"\"\nB=\"2\"\nC=\"it's \\\\ \\${D}\\\\\"\n"
        );
    }

    #[test]
    fn compose_v2_falls_back_to_debian_docker_compose() {
        let apply = module(&[("web", project(YAML, &[]))])
            .declaration()
            .render_apply();
        let at = |pkgs: &[&str]| apply.find(&apt_install(pkgs)).unwrap();
        let plugin = at(&["docker-compose-plugin"]);
        let v2 = at(&["docker-compose-v2"]);
        let debian = at(&["docker-compose"]);
        let check = apply.find("\ndocker compose version >/dev/null\n").unwrap();
        assert!(plugin < v2 && v2 < debian && debian < check);
    }

    #[test]
    fn reload_is_per_project_and_validated() {
        let d = module(&[("a", project(YAML, &[])), ("b-1", project(YAML, &[]))]).declaration();
        let g = d.reload.as_ref().unwrap();
        assert!(g
            .validate
            .contains("docker compose -p 'a' -f '/etc/anvil/compose/a/compose.yaml' config -q"));
        assert!(g
            .reload
            .contains("systemctl reload-or-restart 'anvil-compose-a.service'"));
        // Each project restarts on its own change flag / own paths only.
        assert!(g.reload.contains("__compose_up_1"));
        assert!(g.reload.contains("*'/etc/anvil/compose/b-1'/*"));
        assert!(!g.reload.contains("systemctl restart"));
    }

    #[test]
    fn changed_test_matches_only_its_own_paths() {
        let run = |creates: &str| {
            let script = format!(
                "__creates=({creates}); __reverts=(); if {}; then echo y; else echo n; fi",
                changed_test("web")
            );
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run("/etc/anvil/compose/web/compose.yaml"), "y\n");
        assert_eq!(run("/etc/systemd/system/anvil-compose-web.service"), "y\n");
        assert_eq!(run("/etc/anvil/compose/webapp/compose.yaml"), "n\n");
        assert_eq!(run(""), "n\n");
    }

    #[test]
    fn probe_is_read_only() {
        let probe = module(&[("web", project(YAML, &[("PASS", "x")]))])
            .declaration()
            .render_probe();
        assert!(probe.contains("systemctl is-active --quiet 'anvil-compose-web.service'"));
        for bad in ["reload-or-restart", "compose up", "install -d", "mv "] {
            assert!(!probe.contains(bad), "probe must not mutate: {bad}");
        }
    }

    #[test]
    fn rollback_downs_removed_projects_by_name() {
        let rb = module(&[("web", project(YAML, &[]))])
            .declaration()
            .render_rollback();
        // Engine removes/restores the files first; then the project is downed
        // by name (the compose file is already gone) and the guard re-runs.
        let stop = rb
            .find("systemctl disable --now 'anvil-compose-web.service'")
            .unwrap();
        let files = rb
            .find("# rollback: /etc/anvil/compose/web/compose.yaml")
            .unwrap();
        let down = rb.find("docker compose -p 'web' down").unwrap();
        let reload = rb.find("reload with the restored config").unwrap();
        // CR17: the unit is stopped while its files exist (ExecStop works).
        assert!(stop < files && files < down && down < reload);
        // Only a project rollback deletes: never one restored from backup.
        assert!(rb.contains(
            "if [ ! -f '/etc/anvil/compose/web/compose.yaml.anvil.bak' ] && __anvil_created '/etc/anvil/compose/web/compose.yaml' && "
        ));
    }

    /// Runs the real guard clause against a stub `docker` printing `json`.
    fn ports_check_passes(json: &str) -> Option<bool> {
        let dir =
            std::env::temp_dir().join(format!("anvil-ports-{}-{}", std::process::id(), json.len()));
        std::fs::create_dir_all(&dir).ok()?;
        let compose = dir.join("compose.yaml");
        std::fs::write(&compose, "").ok()?;
        std::fs::write(dir.join("out.json"), json).ok()?;
        let stub = dir.join("docker");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/sh\n[ \"$(cat '{o}')\" = FAIL ] && exit 1\ncat '{o}'\n",
                o = dir.join("out.json").display()
            ),
        )
        .ok()?;
        std::process::Command::new("chmod")
            .args(["+x", &stub.to_string_lossy()])
            .status()
            .ok()?;
        let check = loopback_ports_check("web").replace(
            &shell_escape(&compose_path("web")),
            &shell_escape(&compose.to_string_lossy()),
        );
        let script = format!("set -euo pipefail\nPATH='{}':$PATH\n{check}", dir.display());
        let out = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .ok()?;
        let _ = std::fs::remove_dir_all(&dir);
        if !out.status.success() {
            assert!(String::from_utf8_lossy(&out.stdout).contains("FAILED: compose project web"));
        }
        Some(out.status.success())
    }

    #[test]
    fn ports_guard_rejects_any_non_loopback_publish() {
        let svc = |ports: &str| {
            format!(
                "{{\n  \"name\": \"web\",\n  \"services\": {{\n    \"web\": {{\n      \"image\": \"nginx\",\n      \
                 \"volumes\": [{{ \"type\": \"volume\", \"source\": \"d\", \"target\": \"/data\" }}],\n      \
                 \"ports\": [{ports}]\n    }}\n  }}\n}}\n"
            )
        };
        let public =
            r#"{ "mode": "ingress", "target": 80, "published": "8080", "protocol": "tcp" }"#;
        let ephemeral = r#"{ "mode": "ingress", "target": 80, "protocol": "tcp" }"#;
        let local = r#"{ "mode": "ingress", "host_ip": "127.0.0.1", "target": 80, "published": "8080", "protocol": "tcp" }"#;
        let local6 = r#"{ "host_ip": "::1", "target": 81, "published": "8081" }"#;
        let wildcard = r#"{ "host_ip": "0.0.0.0", "target": 82, "published": "8082" }"#;
        let Some(ok) = ports_check_passes(&svc(local)) else {
            return;
        };
        assert!(ok, "loopback publish is fine");
        assert_eq!(
            ports_check_passes(&svc(&format!("{local}, {local6}"))),
            Some(true)
        );
        assert_eq!(ports_check_passes(&svc(public)), Some(false));
        assert_eq!(
            ports_check_passes(&svc(ephemeral)),
            Some(false),
            "random host port is public"
        );
        assert_eq!(ports_check_passes(&svc(wildcard)), Some(false));
        assert_eq!(
            ports_check_passes(&svc(&format!("{local}, {public}"))),
            Some(false)
        );
        // A compose that cannot render JSON (old plugin, daemon down) fails closed.
        assert_eq!(ports_check_passes("FAIL"), Some(false));
        // No ports at all; a volume `target` is not a port.
        assert_eq!(
            ports_check_passes("{\"services\":{\"w\":{\"volumes\":[{\"target\":\"/d\"}]}}}"),
            Some(true)
        );
    }

    #[test]
    fn ports_guard_runs_in_validate_only_while_docker_owns_iptables() {
        let m = || module(&[("web", project(YAML, &[]))]);
        let on = m().declaration();
        let apply = on.render_apply();
        assert!(apply.contains("config --format json"), "{apply}");
        assert!(
            !on.render_probe().contains("config --format json"),
            "probe stays read-only"
        );
        // The guard sits in validate, i.e. before any reload/up.
        let guard = apply.find("config --format json").unwrap();
        assert!(guard < apply.rfind("reload-or-restart").unwrap());
        let off = m().iptables_off(true).declaration().render_apply();
        assert!(!off.contains("config --format json"));
    }

    // --- runtime = "podman" ---

    const QUADLET: &str =
        "[Container]\nImage=docker.io/library/nginx:alpine\nPublishPort=127.0.0.1:18090:80\n\n[Install]\nWantedBy=multi-user.target\n";

    fn podman(names: &[&str]) -> Declaration {
        ContainersModule::new(ContainersSection {
            runtime: Some("podman".into()),
            quadlet: names
                .iter()
                .map(|n| {
                    (
                        n.to_string(),
                        QuadletContainer {
                            content: QUADLET.into(),
                        },
                    )
                })
                .collect(),
            ..Default::default()
        })
        .engine(Engine::Podman)
        .declaration()
    }

    #[test]
    fn podman_owns_quadlet_files_and_never_docker() {
        let d = podman(&["web"]);
        let f = d
            .files
            .iter()
            .find(|f| f.path == "/etc/containers/systemd/anvil-web.container")
            .unwrap();
        assert_eq!(f.static_content(), Some(QUADLET));
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0644", "root:root"));
        assert_eq!(d.files.len(), 2);
        // Next to ufw, containers need netavark's iptables driver.
        let conf = d.files.iter().find(|f| f.path == PODMAN_CONF).unwrap();
        assert!(PODMAN_CONF.ends_with("/99-anvil.conf"));
        assert!(conf
            .static_content()
            .unwrap()
            .contains("[network]\nfirewall_driver = \"iptables\"\n"));
        let apply = d.render_apply();
        assert!(apply.contains("command -v iptables"));
        assert!(apply.contains("'podman' 'iptables' 'aardvark-dns'"));
        for bad in ["docker compose", "download.docker.com", "docker-ce"] {
            assert!(
                !apply.contains(bad),
                "podman path must not touch docker: {bad}"
            );
        }
        // Gate precedes the install, which precedes any file write.
        let gate = apply.find("a Podman host needs Podman >= 4.4").unwrap();
        let install = apply.find(&apt_install(&["podman"])).unwrap();
        let write = apply.find("base64 -d > \"$__path\"").unwrap();
        assert!(gate < install && install < write);
        // No Quadlets: only the iptables drop-in, nothing installed.
        let bare = podman(&[]);
        let paths: Vec<&str> = bare.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [PODMAN_CONF]);
        assert!(bare.reload.is_none() && bare.commands.is_empty());
    }

    #[test]
    fn podman_probe_gates_and_stays_read_only() {
        let probe = podman(&["web"]).render_probe();
        assert!(probe.contains("a Podman host needs Podman >= 4.4"));
        assert!(probe.contains("systemctl is-active --quiet 'anvil-web.service'"));
        for bad in ["apt-get", "systemctl restart", "daemon-reload", "-dryrun"] {
            assert!(!probe.contains(bad), "probe must not mutate: {bad}");
        }
    }

    #[test]
    fn podman_reload_validates_with_quadlet_then_restarts_changed_units() {
        let d = podman(&["a", "b-1"]);
        let g = d.reload.as_ref().unwrap();
        assert!(g.validate.contains(
            "{ /usr/libexec/podman/quadlet -dryrun 2>/dev/null || true; } | grep -xF -e '---anvil-a.service---' >/dev/null"
        ));
        // The marker starts with `-`; without `-e` grep reads it as an
        // option and every unit "does not convert". Run it against a stub.
        let validate = |dryrun_out: &str| {
            let stub = std::env::temp_dir().join(format!("anvil-quadlet-{}", std::process::id()));
            std::fs::write(&stub, format!("#!/bin/sh\nprintf '%b' '{dryrun_out}'\n")).unwrap();
            std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755))
                .unwrap();
            let unit = stub.with_extension("container");
            std::fs::write(&unit, "").unwrap();
            let script = g
                .validate
                .replace(QUADLET_BIN, stub.to_str().unwrap())
                .replace(
                    "'/etc/containers/systemd/anvil-a.container'",
                    unit.to_str().unwrap(),
                )
                .replace(
                    "'/etc/containers/systemd/anvil-b-1.container'",
                    "/nonexistent",
                );
            let ok = std::process::Command::new("bash")
                .args(["-c", &script])
                .output()
                .unwrap()
                .status
                .success();
            let _ = std::fs::remove_file(&stub);
            let _ = std::fs::remove_file(&unit);
            ok
        };
        assert!(validate("---anvil-a.service---\\n[Service]\\n"));
        assert!(!validate("---anvil-other.service---\\n"));
        assert!(g.validate.contains("'---anvil-b-1.service---'"));
        assert!(g.reload.starts_with("systemctl daemon-reload\n"));
        assert!(g.reload.contains("__quadlet_up_1"));
        assert!(g
            .reload
            .contains("*'/etc/containers/systemd/anvil-b-1.container'*"));
        assert!(g.reload.contains("systemctl restart 'anvil-a.service'"));
    }

    #[test]
    fn podman_rollback_stops_created_units_and_keeps_data() {
        let rb = podman(&["web"]).render_rollback();
        let stop = rb.find("systemctl stop 'anvil-web.service'").unwrap();
        let files = rb
            .find("# rollback: /etc/containers/systemd/anvil-web.container")
            .unwrap();
        let reset = rb
            .find("systemctl reset-failed 'anvil-web.service'")
            .unwrap();
        let reload = rb.rfind("systemctl daemon-reload").unwrap();
        assert!(stop < files && files < reset && reset < reload);
        assert!(rb.contains(
            "if [ ! -f '/etc/containers/systemd/anvil-web.container.anvil.bak' ] && __anvil_created "
        ));
        for bad in [
            "volume rm",
            "rmi",
            "apt-get",
            "purge",
            "/var/lib/containers",
        ] {
            assert!(!rb.contains(bad), "rollback must keep {bad}");
        }
    }
}
