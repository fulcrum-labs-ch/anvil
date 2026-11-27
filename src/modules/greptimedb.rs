//! The `greptimedb` module (R85, CR9): run a pinned GreptimeDB image as the
//! internal compose project `greptimedb`, built by the `containers` module's
//! machinery (one restart/validate/rollback path), with every port bound to
//! `listen_address` and a data directory that is not world-writable.
//!
//! The compose unit is `Wants=docker.service` (not `Requires=`), so a dockerd
//! restart no longer restarts GreptimeDB; `restart: always` replaces the old
//! unit's `Restart=always`. The container keeps its old name (`greptimedb`).
//!
//! `data_dir` reaches the shell only via [`shell_escape`] (R55) and the
//! compose file as a single-quoted YAML scalar with `$` doubled. Ports, image
//! tag and bind address are validated at load and base64-embedded.
//!
//! Migration from the pre-CR9 `docker run` unit ([`UNIT_PATH`]): after the
//! guard has validated the new compose file, the old unit is backed up to
//! `.anvil.bak`, stopped, disabled and removed, its container removed, then
//! the compose project is started on the same bind-mounted `data_dir`. The
//! data never moves and the two never run at once. Rollback restores and
//! restarts the old unit once the compose project is down.
//!
//! On a Podman host the same container runs as the Quadlet
//! `anvil-greptimedb.container` (same image, ports, data dir and rollback,
//! via the `containers` module's Quadlet path); there is no legacy unit.

use crate::config::schema::{
    ComposeProject, ContainersSection, GreptimedbSection, QuadletContainer,
};
use crate::config::Engine;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, BACKUP_SUFFIX};
use crate::escape::shell_escape;

use super::containers::{self, ContainersModule};
use super::Module;

/// The pre-CR9 systemd unit, removed by the migration (rollback restores it).
pub const UNIT_PATH: &str = "/etc/systemd/system/greptimedb.service";
/// Compose project name, service name and container name.
const NAME: &str = "greptimedb";
/// The applied `retention`, so a changed value is drift.
pub const RETENTION_PATH: &str = "/etc/anvil/greptimedb-retention";
/// The shipped Perses dashboards, POSTed after every reload; a changed
/// file is drift. `<dir>/<name>.json` holds the API body for `<name>`.
pub const DASHBOARDS_DIR: &str = "/etc/anvil/greptimedb-dashboards";
/// (name, dashboard JSON) for the built-in Perses (`:4000/dashboard`).
pub const DASHBOARDS: [(&str, &str); 4] = [
    (
        "anvil-host",
        include_str!("../../assets/perses/anvil-host.json"),
    ),
    (
        "anvil-errors",
        include_str!("../../assets/perses/anvil-errors.json"),
    ),
    (
        "anvil-containers",
        include_str!("../../assets/perses/anvil-containers.json"),
    ),
    (
        "anvil-ci",
        include_str!("../../assets/perses/anvil-ci.json"),
    ),
];

pub struct GreptimedbModule {
    cfg: GreptimedbSection,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
    engine: Engine,
    /// `[apps_resources]`: the container and its compose unit join `apps.slice`.
    in_apps_slice: bool,
}

/// A single-quoted YAML scalar that docker compose will not interpolate.
fn yaml_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''").replace('$', "$$"))
}

impl GreptimedbModule {
    pub fn new(cfg: GreptimedbSection) -> Self {
        Self {
            cfg,
            docker_distro: false,
            engine: Engine::Docker,
            in_apps_slice: false,
        }
    }

    /// `[apps_resources]`: greptimedb joins `apps.slice`.
    pub fn in_apps_slice(mut self, on: bool) -> Self {
        self.in_apps_slice = on;
        self
    }

    /// The host engine: Podman runs the Quadlet instead of compose.
    pub fn engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    /// `[docker] source = "distro"`: install the engine from Ubuntu's packages.
    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }

    /// The compose file. Each port is published on `listen_address`
    /// (loopback by default), so the database is not exposed publicly.
    pub fn compose_content(&self) -> String {
        let c = &self.cfg;
        let bind = &c.listen_address;
        let cgroup = if self.in_apps_slice {
            // Docker (systemd cgroup driver) creates the container's scope
            // under this slice instead of system.slice/docker-*.scope.
            "\x20   cgroup_parent: apps.slice\n"
        } else {
            ""
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             services:\n\
             \x20 greptimedb:\n\
             \x20   image: \"greptime/greptimedb:{version}\"\n\
             \x20   container_name: {NAME}\n\
             {cgroup}\
             \x20   restart: always\n\
             \x20   userns_mode: host\n\
             \x20   ports:\n\
             \x20     - \"{bind}:{http}:4000\"\n\
             \x20     - \"{bind}:{grpc}:4001\"\n\
             \x20     - \"{bind}:{mysql}:4002\"\n\
             \x20     - \"{bind}:{postgres}:4003\"\n\
             \x20   volumes:\n\
             \x20     - {data}\n\
             \x20   command: [standalone, start, --http-addr, \"0.0.0.0:4000\", --rpc-addr, \"0.0.0.0:4001\", \
             --mysql-addr, \"0.0.0.0:4002\", --postgres-addr, \"0.0.0.0:4003\", --data-home, /greptimedb_data]\n\
             {mem}",
            mem = c
                .memory_max
                .as_ref()
                .map(|m| format!("\x20   mem_limit: {m}\n"))
                .unwrap_or_default(),
            version = c.version,
            http = c.http_port,
            grpc = c.grpc_port,
            mysql = c.mysql_port,
            postgres = c.postgres_port,
            data = yaml_literal(&format!("{}:/greptimedb_data", c.data_dir)),
        )
    }

    /// The Podman Quadlet: the compose file's flags, one key each. Rootful
    /// Podman maps no user namespace by default (`userns_mode: host`).
    /// `%` is doubled: systemd would read it as a specifier.
    pub fn quadlet_content(&self) -> String {
        let c = &self.cfg;
        let bind = &c.listen_address;
        let slice = if self.in_apps_slice {
            format!("Slice={}\n", super::apps_resources::SLICE)
        } else {
            String::new()
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=GreptimeDB (anvil-managed)\n\
             \n\
             [Container]\n\
             Image=docker.io/greptime/greptimedb:{version}\n\
             ContainerName={NAME}\n\
             PublishPort={bind}:{http}:4000\n\
             PublishPort={bind}:{grpc}:4001\n\
             PublishPort={bind}:{mysql}:4002\n\
             PublishPort={bind}:{postgres}:4003\n\
             Volume={data}:/greptimedb_data\n\
             Exec=standalone start --http-addr 0.0.0.0:4000 --rpc-addr 0.0.0.0:4001 \
             --mysql-addr 0.0.0.0:4002 --postgres-addr 0.0.0.0:4003 --data-home /greptimedb_data\n\
             \n\
             [Service]\n\
             Restart=always\n\
             {slice}\
             {mem}\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            // Quadlet runs the container in the unit's cgroup (split), so the
            // unit's cap is the container's on every Podman >= 4.4.
            mem = c
                .memory_max
                .as_ref()
                .map(|m| format!("MemoryMax={m}\n"))
                .unwrap_or_default(),
            version = c.version,
            http = c.http_port,
            grpc = c.grpc_port,
            mysql = c.mysql_port,
            postgres = c.postgres_port,
            data = c.data_dir.replace('%', "%%"),
        )
    }

    /// Once the service answers, set `retention` as the TTL of every
    /// database (system ones excepted). Skipped once rollback removed
    /// `unit_file`; a failure fails the reload.
    fn retention_script(&self, retention: &str, unit_file: &str) -> String {
        let url = shell_escape(&self.http_url());
        format!(
            r#"[ ! -f {unit} ] || {{ __gt_ok=0
for __i in $(seq 1 60); do curl -fsS -o /dev/null {url}/health && break; sleep 1; done
if __gt_out=$(curl -fsS -X POST {url}/v1/sql --data-urlencode 'sql=SHOW DATABASES'); then
  __gt_ok=1
  for __db in $(printf '%s' "$__gt_out" | grep -o '\["[A-Za-z0-9_]*"\]' | tr -d '[]"' | grep -vxE 'information_schema|greptime_private|pg_catalog' || true); do
    curl -fsS -o /dev/null -X POST {url}/v1/sql --data-urlencode "sql=ALTER DATABASE $__db SET 'ttl'='{retention}'" || __gt_ok=0
  done
fi
[ "$__gt_ok" = 1 ] || {{ printf 'FAILED: greptimedb: could not set retention {retention} via %s\n' {url}; false; }}; }}"#,
            unit = shell_escape(unit_file),
        )
    }

    /// Once the service answers, upsert every shipped dashboard
    /// (`POST /v1/dashboards/<name>`, keyed by name). Skipped once rollback
    /// removed `unit_file`; a failure fails the reload.
    fn dashboards_script(&self, unit_file: &str) -> String {
        let health = shell_escape(&format!("{}/health", self.http_url()));
        let url = shell_escape(&format!("{}/v1/dashboards", self.http_url()));
        let dir = shell_escape(DASHBOARDS_DIR);
        format!(
            r#"[ ! -f {unit} ] || {{ __gt_ok=1
for __i in $(seq 1 60); do curl -fsS -o /dev/null {health} && break; sleep 1; done
for __f in {dir}/*.json; do
  [ -f "$__f" ] || continue
  __n=$(basename "$__f" .json)
  curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' --data-binary "@$__f" {url}/"$__n" || __gt_ok=0
done
[ "$__gt_ok" = 1 ] || {{ printf 'FAILED: greptimedb: could not import the dashboards via %s\n' {url}; false; }}; }}"#,
            unit = shell_escape(unit_file),
        )
    }

    /// The HTTP API as seen from the host.
    fn http_url(&self) -> String {
        let host = match self.cfg.listen_address.as_str() {
            "0.0.0.0" => "127.0.0.1",
            "[::]" => "[::1]",
            a => a,
        };
        format!("http://{host}:{}", self.cfg.http_port)
    }

    /// curl, the dashboards (and with `retention` its stamp file), then the
    /// TTL and dashboard steps after the reload.
    fn with_post_reload(&self, mut decl: Declaration, unit_file: &str) -> Declaration {
        decl = decl.command(ManagedCommand::new(
            "curl installed",
            "command -v curl >/dev/null 2>&1",
            super::apt_install(&["curl"]),
        ));
        for (name, json) in DASHBOARDS {
            let body = serde_json::json!({ "content": json }).to_string();
            decl = decl.file(ManagedFile::new(
                format!("{DASHBOARDS_DIR}/{name}.json"),
                body + "\n",
                "0644",
                "root:root",
            ));
        }
        // After the files are gone: the directory apply created, if empty
        // (rmdir, never rm -r: an operator's own files stay).
        decl = decl.rollback_script(format!(
            "\nrmdir {} 2>/dev/null || true\n",
            shell_escape(DASHBOARDS_DIR)
        ));
        let mut steps = vec![self.dashboards_script(unit_file)];
        if let Some(r) = &self.cfg.retention {
            decl = decl.file(ManagedFile::new(
                RETENTION_PATH,
                format!("{r}\n"),
                "0644",
                "root:root",
            ));
            steps.insert(0, self.retention_script(r, unit_file));
        }
        if let Some(g) = decl.reload.as_mut() {
            for step in steps {
                g.reload = format!("{{ {}\n}} && {{ {step}\n}}", g.reload);
            }
        }
        decl
    }

    /// V1.x cannot open data written before v0.16 (GreptimeDB's
    /// upgrade guide), so a pinned v1+ never replaces a running older one.
    fn upgrade_guard(&self, engine: &str) -> Option<ManagedCommand> {
        let major = self.cfg.version.trim_start_matches('v').split('.').next()?;
        if major.parse::<u32>().ok()? == 0 {
            return None;
        }
        let img = format!(
            "$({engine} container inspect -f '{{{{.Config.Image}}}}' {NAME} 2>/dev/null || true)"
        );
        Some(ManagedCommand::new(
            "no pre-v0.16 greptimedb container on the data dir",
            format!("case \"{img}\" in *:v0.[0-9].*|*:v0.1[0-5].*) false ;; *) true ;; esac"),
            format!(
                "printf 'FAILED: greptimedb: the running %s cannot be upgraded to {v} in place (no path from before v0.16); \
                 pin its version, or remove the container ({engine} rm -f {NAME}) and set a new data_dir\\n' \"{img}\"; false",
                v = self.cfg.version,
            ),
        ))
    }

    /// Create the data directory at mode 0750 (owner-only + group read), so it
    /// is never world-writable/readable (R85).
    fn ensure_data_dir(&self) -> ManagedCommand {
        let dir = shell_escape(&self.cfg.data_dir);
        ManagedCommand::new(
            format!("data dir {}", self.cfg.data_dir),
            format!("[ -d {dir} ] && [ \"$(stat -c '%a' {dir} 2>/dev/null)\" = '750' ]"),
            format!("install -d -m 0750 {dir}"),
        )
    }
}

/// Probe-visible drift while the pre-CR9 unit exists; the guard migrates it.
fn legacy_unit_absent() -> ManagedCommand {
    ManagedCommand::new(
        "pre-compose greptimedb unit absent (the reload migrates it)",
        format!("[ ! -e {} ]", shell_escape(UNIT_PATH)),
        ":",
    )
}

/// Runs inside the guard's reload, i.e. only after the compose file
/// validated, and only while the compose unit exists — so rollback's re-run
/// of the reload never migrates a just-restored legacy unit. Nothing is
/// stopped or removed unless the backup exists; a failed reload leaves that
/// backup for `rollback` (not in `__reverts`, whose revert consumes it).
fn migrate_legacy() -> String {
    let unit = shell_escape(UNIT_PATH);
    let bak = shell_escape(&format!("{UNIT_PATH}{BACKUP_SUFFIX}"));
    format!(
        "if [ -f {compose_unit} ] && [ -e {unit} ]; then\n\
         \x20 if [ -e {bak} ] || cp -a {unit} {bak}; then\n\
         \x20\x20 systemctl disable --now {NAME}.service >/dev/null 2>&1 || true\n\
         \x20\x20 docker rm -f {NAME} >/dev/null 2>&1 || true\n\
         \x20\x20 rm -f {unit}\n\
         \x20\x20 systemctl reset-failed {NAME}.service >/dev/null 2>&1 || true\n\
         \x20\x20 printf 'CHANGED: greptimedb moved from %s to compose project %s (data dir kept)\\n' {unit} {NAME}\n\
         \x20 else\n\
         \x20\x20 printf 'FAILED: could not back up %s; leaving it in place\\n' {unit} >&2\n\
         \x20 fi\n\
         fi",
        compose_unit = shell_escape(&containers::unit_path(NAME)),
    )
}

/// After rollback took the compose project down and restored the old unit
/// (command file), start the old unit again.
fn restart_legacy() -> String {
    let unit = shell_escape(UNIT_PATH);
    format!(
        "\n# rollback (module-authored): restart the pre-compose greptimedb unit\n\
         if [ -f {unit} ] && ! systemctl is-active --quiet {NAME}.service; then\n\
         \x20 systemctl daemon-reload\n\
         \x20 systemctl enable --now {NAME}.service >/dev/null 2>&1 || true\n\
         \x20 printf 'CHANGED: greptimedb unit %s restored and started\\n' {unit}\n\
         fi\n"
    )
}

impl Module for GreptimedbModule {
    fn id(&self) -> &'static str {
        "greptimedb"
    }

    fn declaration(&self) -> Declaration {
        if self.engine == Engine::Podman {
            let section = ContainersSection {
                quadlet: [(
                    NAME.to_string(),
                    QuadletContainer {
                        content: self.quadlet_content(),
                    },
                )]
                .into(),
                ..Default::default()
            };
            // The host's [podman]/[containers] module owns the drop-in.
            let mut decl = ContainersModule::new(section)
                .engine(Engine::Podman)
                .podman_owns_conf(true)
                .in_apps_slice(self.in_apps_slice)
                .declaration()
                .command(self.ensure_data_dir());
            decl.module_id = NAME.into();
            if let Some(g) = decl.reload.as_mut() {
                g.describe = "greptimedb quadlet".into();
            }
            if let Some(g) = self.upgrade_guard("podman") {
                decl.commands.insert(0, g);
            }
            return self.with_post_reload(decl, &containers::quadlet_path(NAME));
        }
        let project = ComposeProject {
            content: self.compose_content(),
            env: Default::default(),
        };
        let section = ContainersSection {
            compose: [(NAME.to_string(), project)].into(),
            ..Default::default()
        };
        // No loopback-publish guard: `listen_address` is the operator's
        // explicit choice (the pre-CR9 contract), validated as an IP at load.
        let mut decl = ContainersModule::new(section)
            .iptables_off(true)
            .docker_distro(self.docker_distro)
            .in_apps_slice(self.in_apps_slice)
            .declaration()
            .command(self.ensure_data_dir())
            .command(legacy_unit_absent())
            .command_file(UNIT_PATH)
            .rollback_script(restart_legacy());
        decl.module_id = NAME.into();
        if let Some(g) = decl.reload.as_mut() {
            g.describe = "greptimedb compose project".into();
            g.reload = format!("{}\n{}", migrate_legacy(), g.reload);
        }
        if let Some(g) = self.upgrade_guard("docker") {
            decl.commands.insert(0, g);
        }
        self.with_post_reload(decl, &containers::unit_path(NAME))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut GreptimedbSection)) -> GreptimedbModule {
        let mut cfg = GreptimedbSection {
            http_port: 4000,
            grpc_port: 4001,
            mysql_port: 4002,
            postgres_port: 4003,
            data_dir: "/var/lib/greptimedb".into(),
            listen_address: "127.0.0.1".into(),
            version: "v0.9.5".into(),
            retention: None,
            memory_max: None,
            order_override: Default::default(),
        };
        mutate(&mut cfg);
        GreptimedbModule::new(cfg)
    }

    const COMPOSE: &str = "/etc/anvil/compose/greptimedb/compose.yaml";
    const COMPOSE_UNIT: &str = "/etc/systemd/system/anvil-compose-greptimedb.service";

    #[test]
    fn apps_slice_is_opt_in_for_compose_and_quadlet() {
        let on = module(|_| {}).in_apps_slice(true);
        assert_eq!(
            on.compose_content()
                .matches("cgroup_parent: apps.slice\n")
                .count(),
            1,
            "the container must not land in docker's own scope"
        );
        let q = on.quadlet_content();
        assert!(
            q.contains("[Service]\n") && q.contains("\nSlice=apps.slice\n"),
            "Slice= belongs to [Service]:\n{q}"
        );
        // The compose unit generated by the containers module carries it too.
        let d = on.declaration();
        let unit = d
            .files
            .iter()
            .find(|f| f.path == COMPOSE_UNIT)
            .and_then(|f| f.static_content())
            .expect("compose unit");
        assert!(unit.contains("\nSlice=apps.slice\n"), "{unit}");
        for off in [
            module(|_| {}).compose_content(),
            module(|_| {}).quadlet_content(),
        ] {
            assert!(!off.contains("apps.slice"), "{off}");
        }
    }

    #[test]
    fn ports_are_bound_to_listen_address() {
        let y = module(|_| {}).compose_content();
        for p in 4000..=4003 {
            assert!(y.contains(&format!("- \"127.0.0.1:{p}:{p}\"\n")), "{y}");
        }
        let y = module(|c| {
            c.http_port = 14000;
            c.listen_address = "[::1]".into();
        })
        .compose_content();
        assert!(y.contains("- \"[::1]:14000:4000\"\n"), "{y}");
    }

    #[test]
    fn compose_keeps_the_old_run_flags() {
        let y = module(|c| c.version = "v1.2.3".into()).compose_content();
        assert!(y.contains("image: \"greptime/greptimedb:v1.2.3\"\n"));
        assert!(y.contains("container_name: greptimedb\n"));
        assert!(
            y.contains("restart: always\n"),
            "the oneshot unit does not supervise"
        );
        assert!(y.contains("userns_mode: host\n"));
        assert!(y.contains("- '/var/lib/greptimedb:/greptimedb_data'\n"));
        assert!(y.contains("--data-home, /greptimedb_data]"));
    }

    #[test]
    fn compose_content_parses_as_yaml() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        // A real YAML parser when the dev box has one (no docker needed).
        let py = "import sys,yaml,json; s=yaml.safe_load(sys.stdin)['services']['greptimedb']; \
                  print(json.dumps([s['command'], s['ports'], s['volumes'], s['restart']]))";
        let Ok(mut child) = Command::new("python3")
            .args(["-c", py])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };
        let content = module(|c| c.data_dir = "/srv/it's$x".into()).compose_content();
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(content.as_bytes());
        }
        let out = child.wait_with_output().unwrap();
        if !out.status.success() {
            return; // python3 without PyYAML: skip
        }
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            r#"[["standalone", "start", "--http-addr", "0.0.0.0:4000", "--rpc-addr", "0.0.0.0:4001", "--mysql-addr", "0.0.0.0:4002", "--postgres-addr", "0.0.0.0:4003", "--data-home", "/greptimedb_data"], ["127.0.0.1:4000:4000", "127.0.0.1:4001:4001", "127.0.0.1:4002:4002", "127.0.0.1:4003:4003"], ["/srv/it's$$x:/greptimedb_data"], "always"]"#
        );
    }

    #[test]
    fn memory_max_caps_the_container_on_both_engines() {
        let m = module(|_| {});
        assert!(!m.compose_content().contains("mem_limit"));
        assert!(!m.quadlet_content().contains("MemoryMax"));
        let m = module(|c| c.memory_max = Some("2G".into()));
        assert!(m.compose_content().ends_with("\x20   mem_limit: 2G\n"));
        assert!(m
            .quadlet_content()
            .contains("[Service]\nRestart=always\nMemoryMax=2G\n\n[Install]"));
    }

    #[test]
    fn data_dir_is_a_literal_yaml_scalar() {
        assert_eq!(yaml_literal("/a'b$c"), "'/a''b$$c'");
    }

    #[test]
    fn is_a_compose_project_owned_by_greptimedb() {
        let m = module(|_| {});
        let d = m.declaration();
        assert_eq!(d.module_id, "greptimedb");
        let compose = d.files.iter().find(|f| f.path == COMPOSE).unwrap();
        assert_eq!(compose.static_content(), Some(m.compose_content().as_str()));
        assert!(d.files.iter().any(|f| f.path == COMPOSE_UNIT));
        assert!(
            !d.files.iter().any(|f| f.path == UNIT_PATH),
            "the docker-run unit is gone"
        );
        assert_eq!(d.command_files, vec![UNIT_PATH.to_string()]);
        let g = d.reload.unwrap();
        assert_eq!(g.describe, "greptimedb compose project");
        assert!(g.validate.contains("config -q"));
        assert!(
            !g.validate.contains("host_ip"),
            "listen_address stays the operator's choice"
        );
    }

    #[test]
    fn data_dir_created_non_world_writable_and_escaped() {
        let apply = module(|c| c.data_dir = "/srv/data dir".into())
            .declaration()
            .render_apply();
        assert!(apply.contains("install -d -m 0750 '/srv/data dir'"));
    }

    #[test]
    fn migration_runs_after_validate_and_before_the_project_starts() {
        let apply = module(|_| {}).declaration().render_apply();
        let validate = apply.find("config -q").unwrap();
        let gate = apply
            .find(&format!(
                "if [ -f '{COMPOSE_UNIT}' ] && [ -e '{UNIT_PATH}' ]; then"
            ))
            .expect("migration gated on both units");
        let backup = apply
            .find(&format!(
                "if [ -e '{UNIT_PATH}.anvil.bak' ] || cp -a '{UNIT_PATH}' '{UNIT_PATH}.anvil.bak'; then"
            ))
            .unwrap();
        // The guard's revert would consume the backup that rollback needs.
        assert!(!apply.contains(&format!("__reverts+=('{UNIT_PATH}')")));
        let stop = apply
            .find("systemctl disable --now greptimedb.service")
            .unwrap();
        let rm_ctr = apply.find("docker rm -f greptimedb").unwrap();
        let rm_unit = apply.find(&format!("rm -f '{UNIT_PATH}'\n")).unwrap();
        let start = apply
            .find("systemctl reload-or-restart 'anvil-compose-greptimedb.service'")
            .unwrap();
        assert!(validate < gate, "{apply}");
        assert!(gate < backup && backup < stop, "{apply}");
        assert!(
            stop < rm_ctr && rm_ctr < rm_unit && rm_unit < start,
            "{apply}"
        );
        assert!(!apply.contains("down -v"), "volumes are never removed");
    }

    #[test]
    fn migration_snippet_runs_under_bash() {
        let run = |script: String| {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .output()
                .unwrap();
            (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        };
        // The gate: nothing happens while either unit is missing.
        assert_eq!(run(format!("{}\necho done", migrate_legacy())).0, "done\n");
        // Both units present, backup impossible: nothing is stopped or removed.
        let dir = std::env::temp_dir().join(format!("anvil-gdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (u, c) = (dir.join("old.service"), dir.join("compose.service"));
        std::fs::write(&u, "x").unwrap();
        std::fs::write(&c, "x").unwrap();
        let script = migrate_legacy()
            .replace(
                &shell_escape(&containers::unit_path(NAME)),
                &c.display().to_string(),
            )
            .replace(
                &shell_escape(&format!("{UNIT_PATH}{BACKUP_SUFFIX}")),
                "/nonexistent-dir/bak",
            )
            .replace(&shell_escape(UNIT_PATH), &u.display().to_string());
        // The snippet silences these, so the stubs log to a file.
        let log = dir.join("calls.log");
        let stubs = format!(
            "systemctl() {{ echo STOP >> {l}; }}; docker() {{ echo RM >> {l}; }}\n",
            l = shell_escape(&log.display().to_string())
        );
        let calls = || std::fs::read_to_string(&log).unwrap_or_default();
        let (_, err) = run(format!("{stubs}{script}"));
        assert!(u.exists(), "unit kept when the backup fails");
        assert_eq!(calls(), "", "nothing stopped or removed");
        assert!(err.contains("FAILED: could not back up"), "{err}");
        // With a writable backup path the unit is backed up, then removed.
        let bak = dir.join("old.service.anvil.bak");
        let script = script.replace("/nonexistent-dir/bak", &bak.display().to_string());
        let (out, _) = run(format!("{stubs}{script}"));
        assert!(bak.exists() && !u.exists(), "{out}");
        assert!(out.contains("CHANGED:"), "{out}");
        assert_eq!(calls(), "STOP\nRM\nSTOP\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_reports_the_legacy_unit_and_never_migrates() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(probe.contains(&format!("[ ! -e '{UNIT_PATH}' ]")));
        assert!(probe.contains("systemctl is-active --quiet 'anvil-compose-greptimedb.service'"));
        assert!(!probe.contains("disable --now"));
        assert!(!probe.contains("docker rm"));
    }

    #[test]
    fn rollback_downs_the_project_before_restarting_the_old_unit() {
        let rb = module(|_| {}).declaration().render_rollback();
        let restore = rb.find(&format!("__path='{UNIT_PATH}'")).unwrap();
        let down = rb.find("docker compose -p 'greptimedb' down").unwrap();
        let restart = rb
            .find("systemctl enable --now greptimedb.service")
            .unwrap();
        assert!(restore < restart && down < restart, "{rb}");
        assert!(rb.contains(&format!(
            "if [ -f '{UNIT_PATH}' ] && ! systemctl is-active --quiet greptimedb.service; then"
        )));
    }

    #[test]
    fn docker_engine_is_keyring_pinned_not_pipe_to_shell() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(!apply.contains("get.docker.com"), "no pipe-to-shell");
        assert!(apply.contains("signed-by=/etc/apt/keyrings/docker.asc"));
    }

    const QUADLET: &str = "/etc/containers/systemd/anvil-greptimedb.container";

    #[test]
    fn podman_quadlet_keeps_image_ports_and_data_dir() {
        let q = module(|c| {
            c.http_port = 14000;
            c.data_dir = "/srv/g%h".into();
        })
        .quadlet_content();
        for needle in [
            "Image=docker.io/greptime/greptimedb:v0.9.5\n",
            "ContainerName=greptimedb\n",
            "PublishPort=127.0.0.1:14000:4000\n",
            "PublishPort=127.0.0.1:4003:4003\n",
            "Volume=/srv/g%%h:/greptimedb_data\n",
            "--postgres-addr 0.0.0.0:4003 --data-home /greptimedb_data\n",
            "Restart=always\n",
            "WantedBy=multi-user.target\n",
        ] {
            assert!(q.contains(needle), "missing {needle:?}:\n{q}");
        }
    }

    #[test]
    fn podman_runs_the_quadlet_and_never_docker() {
        let m = module(|_| {}).engine(Engine::Podman);
        let d = m.declaration();
        assert_eq!(d.module_id, "greptimedb");
        let f = d.files.iter().find(|f| f.path == QUADLET).unwrap();
        assert_eq!(f.static_content(), Some(m.quadlet_content().as_str()));
        assert_eq!(
            d.files.len(),
            1 + DASHBOARDS.len(),
            "no compose file, no drop-in (host owns it)"
        );
        assert!(d.command_files.is_empty(), "no legacy unit on Podman");
        let apply = d.render_apply();
        assert!(apply.contains("install -d -m 0750 '/var/lib/greptimedb'"));
        assert!(apply.contains("systemctl restart 'anvil-greptimedb.service'"));
        assert!(!apply.contains("docker"), "{apply}");
        let g = d.reload.as_ref().unwrap();
        assert_eq!(g.describe, "greptimedb quadlet");
        assert!(g.validate.contains("---anvil-greptimedb.service---"));
        let rb = d.render_rollback();
        assert!(rb.contains("systemctl stop 'anvil-greptimedb.service'"));
        assert!(!rb.contains("rm -rf") && !rb.contains("/var/lib/greptimedb/"));
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        for engine in [Engine::Docker, Engine::Podman] {
            let decl = module(|c| {
                c.data_dir = "/srv/data dir".into();
                c.retention = Some("30d".into());
            })
            .engine(engine)
            .declaration();
            for (kind, s) in [
                ("probe", decl.render_probe()),
                ("apply", decl.render_apply()),
                ("rollback", decl.render_rollback()),
            ] {
                let Ok(mut child) = Command::new("bash")
                    .arg("-n")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                else {
                    return; // bash unavailable: skip the gate
                };
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(s.as_bytes());
                }
                let ok = child.wait().map(|st| st.success()).unwrap_or(true);
                assert!(ok, "greptimedb {kind} script failed bash -n:\n{s}");
            }
        }
    }

    /// Run the retention step against a stub `curl` (`fail` = the SQL
    /// API errors). Returns (status ok, the SQL it sent, stdout).
    fn retention_run(unit_exists: bool, fail: bool) -> (bool, String, String) {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!(
            "anvil-gt-{}-{unit_exists}{fail}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        let unit = d.join("unit");
        if unit_exists {
            std::fs::write(&unit, "").unwrap();
        }
        let stub = d.join("bin/curl");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/bash\ncase \"$*\" in\n*/health*) exit 0 ;;\n*SHOW*) {} ;;\n\
                 *) printf '%s\\n' \"${{@: -1}}\" >> {}/sql ;;\nesac\n",
                if fail {
                    "exit 22"
                } else {
                    r#"echo '{"output":[{"records":{"schema":{"column_schemas":[{"name":"Database"}]},"rows":[["greptime_private"],["information_schema"],["public"],["logs_2"]]}}]}'"#
                },
                d.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = module(|c| c.retention = Some("30d".into()))
            .retention_script("30d", unit.to_str().unwrap());
        let out = std::process::Command::new("bash")
            .args([
                "-euo",
                "pipefail",
                "-c",
                &format!(
                    "PATH={}/bin:$PATH\nif {script}\nthen :; else exit 1; fi",
                    d.display()
                ),
            ])
            .output()
            .unwrap();
        let sql = std::fs::read_to_string(d.join("sql")).unwrap_or_default();
        std::fs::remove_dir_all(&d).unwrap();
        (
            out.status.success(),
            sql,
            String::from_utf8_lossy(&out.stdout).into(),
        )
    }

    #[test]
    fn retention_sets_the_ttl_of_every_user_database() {
        let (ok, sql, _) = retention_run(true, false);
        assert!(ok);
        assert_eq!(
            sql,
            "sql=ALTER DATABASE public SET 'ttl'='30d'\nsql=ALTER DATABASE logs_2 SET 'ttl'='30d'\n"
        );
        let (ok, sql, out) = retention_run(true, true);
        assert!(
            !ok && sql.is_empty()
                && out.starts_with("FAILED: greptimedb: could not set retention 30d")
        );
        // Rolled back (unit gone): nothing to do, no failure.
        let (ok, sql, _) = retention_run(false, true);
        assert!(ok && sql.is_empty());
    }

    #[test]
    fn retention_adds_its_stamp_and_step_on_both_engines() {
        assert!(module(|_| {})
            .declaration()
            .files
            .iter()
            .all(|f| f.path != RETENTION_PATH));
        for engine in [Engine::Docker, Engine::Podman] {
            let d = module(|c| c.retention = Some("2w".into()))
                .engine(engine)
                .declaration();
            let f = d.files.iter().find(|f| f.path == RETENTION_PATH).unwrap();
            assert_eq!(f.static_content(), Some("2w\n"));
            let reload = d.reload.unwrap().reload;
            let unit = match engine {
                Engine::Docker => containers::unit_path(NAME),
                Engine::Podman => containers::quadlet_path(NAME),
            };
            assert!(
                reload.contains(&format!("}} && {{ [ ! -f {} ] ||", shell_escape(&unit))),
                "{reload}"
            );
            assert!(reload.contains("SET 'ttl'='2w'"));
        }
    }

    #[test]
    fn dashboards_are_valid_perses_named_like_their_files() {
        let d = module(|_| {}).declaration();
        for (name, json) in DASHBOARDS {
            let v: serde_json::Value = serde_json::from_str(json).unwrap();
            assert_eq!(v["kind"], "Dashboard");
            assert_eq!(v["metadata"]["name"], name);
            assert_eq!(v["metadata"]["project"], "default");
            // Every layout item points at a panel that exists.
            for item in v["spec"]["layouts"][0]["spec"]["items"].as_array().unwrap() {
                let r = item["content"]["$ref"].as_str().unwrap();
                let key = r.strip_prefix("#/spec/panels/").unwrap();
                assert!(v["spec"]["panels"].get(key).is_some(), "{name}: {r}");
            }
            // The managed file is the API body: {"content": "<dashboard JSON>"}.
            let path = format!("{DASHBOARDS_DIR}/{name}.json");
            let f = d.files.iter().find(|f| f.path == path).unwrap();
            let body: serde_json::Value =
                serde_json::from_str(f.static_content().unwrap()).unwrap();
            assert_eq!(body["content"].as_str(), Some(json));
        }
    }

    #[test]
    fn rollback_removes_the_empty_dashboards_dir_after_its_files() {
        for engine in [Engine::Docker, Engine::Podman] {
            let rb = module(|_| {})
                .engine(engine)
                .declaration()
                .render_rollback();
            let rmdir = format!("rmdir '{DASHBOARDS_DIR}' 2>/dev/null || true\n");
            let at = rb.find(&rmdir).expect("rmdir of the dashboards dir");
            let last_file = rb.rfind(&format!("__path='{DASHBOARDS_DIR}/")).unwrap();
            assert!(last_file < at, "{rb}");
            assert!(!rb.contains(&format!("rm -r '{DASHBOARDS_DIR}'")));
            assert!(!rb.contains(&format!("rm -rf '{DASHBOARDS_DIR}'")));
        }
        // rmdir keeps a directory with an operator's file in it.
        let d = std::env::temp_dir().join(format!("anvil-gtdir-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("mine.json"), "{}").unwrap();
        let run = |dir: &std::path::Path| {
            std::process::Command::new("bash")
                .args(["-euo", "pipefail", "-c"])
                .arg(format!(
                    "rmdir {} 2>/dev/null || true",
                    shell_escape(&dir.display().to_string())
                ))
                .status()
                .unwrap()
                .success()
        };
        assert!(run(&d) && d.join("mine.json").exists());
        std::fs::remove_file(d.join("mine.json")).unwrap();
        assert!(run(&d) && !d.exists());
    }

    #[test]
    fn dashboards_are_imported_after_the_start_and_retention() {
        let reload = module(|c| c.retention = Some("30d".into()))
            .declaration()
            .reload
            .unwrap()
            .reload;
        let start = reload
            .find("reload-or-restart 'anvil-compose-greptimedb.service'")
            .unwrap();
        let ttl = reload.find("SET 'ttl'").unwrap();
        let dash = reload.find("--data-binary").unwrap();
        assert!(start < ttl && ttl < dash, "{reload}");
        assert!(reload.contains("'http://127.0.0.1:4000/v1/dashboards'/\"$__n\""));
    }

    /// Run the dashboards step against a stub `curl`; returns (ok, POSTs, stdout).
    fn dashboards_run(fail: bool) -> (bool, String, String) {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("anvil-gtd-{}-{fail}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::create_dir_all(d.join("dash")).unwrap();
        for n in ["a", "b"] {
            std::fs::write(d.join(format!("dash/{n}.json")), "{}").unwrap();
        }
        let unit = d.join("unit");
        std::fs::write(&unit, "").unwrap();
        let stub = d.join("bin/curl");
        std::fs::write(
            &stub,
            format!(
                "#!/bin/bash\ncase \"$*\" in\n*/health*) exit 0 ;;\n\
                 *) printf '%s\\n' \"${{@: -1}}\" >> {}/posts; {} ;;\nesac\n",
                d.display(),
                if fail { "exit 22" } else { "exit 0" },
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script = module(|_| {})
            .dashboards_script(unit.to_str().unwrap())
            .replace(
                &shell_escape(DASHBOARDS_DIR),
                &d.join("dash").display().to_string(),
            );
        let out = std::process::Command::new("bash")
            .args([
                "-euo",
                "pipefail",
                "-c",
                &format!(
                    "PATH={}/bin:$PATH\nif {script}\nthen :; else exit 1; fi",
                    d.display()
                ),
            ])
            .output()
            .unwrap();
        let posts = std::fs::read_to_string(d.join("posts")).unwrap_or_default();
        std::fs::remove_dir_all(&d).unwrap();
        (
            out.status.success(),
            posts,
            String::from_utf8_lossy(&out.stdout).into(),
        )
    }

    #[test]
    fn http_url_reaches_a_wildcard_bind_over_loopback() {
        for (bind, url) in [
            ("0.0.0.0", "http://127.0.0.1:4000"),
            ("[::]", "http://[::1]:4000"),
            ("10.0.0.5", "http://10.0.0.5:4000"),
        ] {
            assert_eq!(module(|c| c.listen_address = bind.into()).http_url(), url);
        }
    }

    #[test]
    fn dashboards_step_posts_every_file_and_fails_loudly() {
        let (ok, posts, _) = dashboards_run(false);
        assert!(ok);
        assert_eq!(
            posts,
            "http://127.0.0.1:4000/v1/dashboards/a\nhttp://127.0.0.1:4000/v1/dashboards/b\n"
        );
        let (ok, _, out) = dashboards_run(true);
        assert!(!ok && out.starts_with("FAILED: greptimedb: could not import the dashboards"));
    }

    #[test]
    fn upgrade_guard_refuses_v1_over_a_pre_v0_16_container() {
        assert!(
            module(|_| {}).upgrade_guard("docker").is_none(),
            "v0.x target"
        );
        let m = module(|c| c.version = "v1.3.0".into());
        let g = m.upgrade_guard("docker").unwrap();
        let run = |image: &str, script: &str| {
            std::process::Command::new("bash")
                .args([
                    "-euo",
                    "pipefail",
                    "-c",
                    &format!(
                        "docker() {{ printf '%s' {}; }}\n{script}",
                        shell_escape(image)
                    ),
                ])
                .output()
                .unwrap()
        };
        for (image, ok) in [
            ("greptime/greptimedb:v0.9.5", false),
            ("greptime/greptimedb:v0.15.2", false),
            ("greptime/greptimedb:v0.16.0", true),
            ("greptime/greptimedb:v1.2.1", true),
            ("", true),
        ] {
            assert_eq!(run(image, &g.detect).status.success(), ok, "{image}");
        }
        let out = run("greptime/greptimedb:v0.9.5", &g.converge);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!out.status.success());
        assert!(
            stdout.starts_with("FAILED: greptimedb: the running greptime/greptimedb:v0.9.5 cannot"),
            "{stdout}"
        );
        // First, so nothing is written or pulled before it.
        for (engine, e) in [(Engine::Docker, "docker"), (Engine::Podman, "podman")] {
            let d = module(|c| c.version = "v1.3.0".into())
                .engine(engine)
                .declaration();
            assert!(d.commands[0]
                .detect
                .contains(&format!("{e} container inspect")));
        }
    }
}
