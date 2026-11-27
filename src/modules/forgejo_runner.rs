//! The `forgejo_runner` module: one Forgejo Actions runner per host
//! (docs/design/github-actions-runner.md §5), built on [`runner_common`].
//!
//! The pinned, SHA-256-verified `forgejo-runner` static binary goes to
//! `/usr/local/bin/forgejo-runner` (recorded in the created list so rollback
//! removes it only if anvil installed it). Registration is declarative: the
//! UUID and token from Forgejo's "Create new runner" dialog (or from
//! `forgejo forgejo-cli actions register --secret`) go into
//! `server.connections` of the runner's config file — no deprecated
//! `forgejo-runner register`, no `.runner` file. That file holds the token,
//! so it is a `Computed` file (never in `diff`), readable by the runner user
//! but owned by root. `forgejo-runner daemon -c <config>` runs as the
//! unprivileged `forgejo-runner` user under a hardened unit.

use crate::config::schema::{ForgejoRunnerSection, ForgejoSection};
use crate::config::Engine;
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_CHANGED,
    MARK_FAILED, MARK_OK,
};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::forgejo_runner_ephemeral as eph;
use super::runner_common::{self, Account, Download};
use super::{apt_install, Module};

pub const USER: &str = "forgejo-runner";
pub const HOME: &str = "/var/lib/forgejo-runner";
pub const CONF_DIR: &str = "/etc/forgejo-runner";
pub const CONFIG: &str = "/etc/forgejo-runner/config.yml";
pub const BIN: &str = "/usr/local/bin/forgejo-runner";
pub const UNIT: &str = "anvil-forgejo-runner.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/anvil-forgejo-runner.service";
pub const PRUNE_SCRIPT: &str = "/usr/local/libexec/anvil/forgejo-runner-prune.sh";
pub const PRUNE_SERVICE: &str = "/etc/systemd/system/anvil-forgejo-runner-prune.service";
pub const PRUNE_TIMER_UNIT: &str = "anvil-forgejo-runner-prune.timer";
pub const PRUNE_TIMER: &str = "/etc/systemd/system/anvil-forgejo-runner-prune.timer";
/// `mode = "ephemeral"`'s slot units (never the prune service).
const SLOT_UNITS: &str = "/etc/systemd/system/anvil-forgejo-runner-[0-9]*.service";
/// Pinned default (forgejo-runner v13.2.1, released 2026-10-29). Hashes are
/// the release's `forgejo-runner-13.2.1-linux-<arch>.sha256` assets.
pub const DEFAULT_VERSION: &str = "13.2.1";
const DEFAULT_SHA256_AMD64: &str =
    "bb369fe1ecb50fdc983c0b1d993f19b0920df6e5864511892b3cdbf16d858b34";
const DEFAULT_SHA256_ARM64: &str =
    "eeddb7902f79abe488972f4189fbe3ea02762ee827d1b406b469420bf0d62dd9";

const ACCOUNT: Account<'static> = Account {
    module: "forgejo_runner",
    user: USER,
    home: HOME,
    root: CONF_DIR,
    leftover: "runner configs",
};

pub struct ForgejoRunnerModule {
    cfg: ForgejoRunnerSection,
    /// `url` after defaulting to this config's `[forgejo]` instance.
    url: String,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
    /// `[ci_resources]` is enabled: the unit runs in `ci.slice`.
    in_ci_slice: bool,
    /// `[ci_resources] cpu_weight` for docker-rootless slot users (else 100).
    ci_cpu_weight: u32,
    /// `[docker]`, for an ephemeral runner's daemon.json.
    docker: Option<crate::config::schema::DockerSection>,
    /// Ephemeral: this module sets up Docker + sysbox (no v2 GitHub runner does).
    owns_engine: bool,
    /// The host's engine: what `docker = "rootless"` runs.
    engine: Engine,
}

impl ForgejoRunnerModule {
    /// `forgejo_domain` is `[forgejo].domain` when that section is present;
    /// it supplies the URL when `url` is empty.
    pub fn new(cfg: ForgejoRunnerSection, forgejo_domain: Option<&str>) -> Self {
        let url = match (cfg.url.is_empty(), forgejo_domain) {
            (true, Some(d)) => format!("https://{d}/"),
            _ => cfg.url.clone(),
        };
        Self {
            cfg,
            url,
            docker_distro: false,
            in_ci_slice: false,
            ci_cpu_weight: 100,
            docker: None,
            owns_engine: true,
            engine: Engine::Docker,
        }
    }

    pub fn engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    /// The rootless engine in the unit: `podman`, or `rootless` (the host's).
    fn rootless(&self) -> Option<Engine> {
        match self.cfg.docker.as_str() {
            "podman" => Some(Engine::Podman),
            "rootless" => Some(self.engine),
            _ => None,
        }
    }

    /// `[docker] source = "distro"`: install the engine from Ubuntu's packages.
    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }

    pub fn ci_cpu_weight(mut self, w: u32) -> Self {
        self.ci_cpu_weight = w;
        self
    }

    pub fn in_ci_slice(mut self, on: bool) -> Self {
        self.in_ci_slice = on;
        self
    }

    pub fn docker(mut self, docker: Option<crate::config::schema::DockerSection>) -> Self {
        self.docker = docker;
        self
    }

    /// False when `[github_runner] mode = "ephemeral"` owns Docker + sysbox.
    pub fn owns_engine(mut self, on: bool) -> Self {
        self.owns_engine = on;
        self
    }

    fn version(&self) -> &str {
        self.cfg.version.as_deref().unwrap_or(DEFAULT_VERSION)
    }

    /// `(amd64, arm64)`; an override pins one hash for this host's arch.
    fn hashes(&self) -> (&str, &str) {
        match &self.cfg.sha256 {
            Some(s) => (s, s),
            None => (DEFAULT_SHA256_AMD64, DEFAULT_SHA256_ARM64),
        }
    }

    /// Host-label jobs need git (upstream's only system requirement).
    fn ensure_tools() -> ManagedCommand {
        ManagedCommand::new(
            "curl and git for forgejo-runner",
            "command -v curl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 \
             && command -v git >/dev/null 2>&1",
            apt_install(&["curl", "ca-certificates", "coreutils", "git"]),
        )
    }

    fn install(&self) -> ManagedCommand {
        let ver = shell_escape(self.version());
        let (amd64, arm64) = self.hashes();
        let detect = format!(
            "{{ case \"$(dpkg --print-architecture)\" in amd64) __sha={} ;; arm64) __sha={} ;; \
             *) __sha='' ;; esac; [ -n \"$__sha\" ] && [ -x {BIN} ] && \
             printf '%s  %s\\n' \"$__sha\" {BIN} | sha256sum -c --status -; }}",
            shell_escape(amd64),
            shell_escape(arm64)
        );
        let url = format!(
            "\"https://code.forgejo.org/forgejo/runner/releases/download/v\"{ver}\"/forgejo-runner-\"{ver}\"-linux-${{__ra}}\""
        );
        let download = Download {
            module: "forgejo_runner",
            arch_names: ("amd64", "arm64"),
            sha256: (amd64, arm64),
            url: &url,
            file: "forgejo-runner",
            what: "forgejo-runner binary",
        }
        .script();
        ManagedCommand::new(
            format!(
                "forgejo-runner {} binary (SHA-256 verified)",
                self.version()
            ),
            detect,
            format!(
                "{download}\
                 [ -e {BIN} ] || __anvil_remember {BIN}\n\
                 install -m 0755 -o root -g root \"$__tmp/forgejo-runner\" {BIN}\n\
                 rm -rf \"$__tmp\"\n\
                 __fjr_restart=1"
            ),
        )
    }

    fn docker_group() -> ManagedCommand {
        ManagedCommand::new(
            "forgejo-runner in the docker group (jobs are root-equivalent on this host)",
            format!(
                "case \" $(id -nG {USER} 2>/dev/null) \" in *' docker '*) true ;; *) false ;; esac"
            ),
            format!("usermod -aG docker {USER}\n__fjr_restart=1"),
        )
    }

    /// An empty token (unset `FORGEJO_RUNNER_TOKEN`) fails before the config
    /// is written, instead of starting a runner that cannot authenticate.
    fn token_missing() -> ManagedCommand {
        ManagedCommand::new(
            "forgejo-runner token set",
            "false",
            format!(
                "printf '{MARK_FAILED} forgejo_runner: token is empty; export the runner token \
                 shown with its UUID (see docs/04_modules.md)\\n'\nexit 1"
            ),
        )
    }

    /// The runner's config (`forgejo-runner generate-config` keys). Every
    /// value is validated at load to a charset that is safe in a YAML
    /// double-quoted string.
    pub fn config_yaml(&self) -> String {
        let labels: String = self
            .cfg
            .labels
            .iter()
            .map(|l| format!("    - \"{l}\"\n"))
            .collect();
        format!(
            "# Managed by anvil — do not edit by hand\n\
             log:\n\
             \x20 level: info\n\
             runner:\n\
             \x20 capacity: {capacity}\n\
             \x20 labels:\n\
             {labels}\
             container:\n\
             \x20 # Never hand the Docker socket to job containers.\n\
             \x20 docker_host: \"-\"\n\
             server:\n\
             \x20 connections:\n\
             \x20   anvil:\n\
             \x20     url: \"{url}\"\n\
             \x20     uuid: \"{uuid}\"\n\
             \x20     token: \"{token}\"\n",
            capacity = self.cfg.capacity,
            url = self.url,
            uuid = self.cfg.uuid,
            token = self.cfg.token,
        )
    }

    /// Upstream's `contrib/forgejo-runner.service` (on-failure restart,
    /// `TimeoutStopSec=infinity` so `shutdown_timeout` lets jobs finish, HUP
    /// reload) plus the shared hardening and caps.
    pub fn unit_content(&self) -> String {
        let c = &self.cfg;
        let slice = if self.in_ci_slice {
            format!("Slice={}\n", super::ci_resources::SLICE)
        } else {
            String::new()
        };
        let engine = self.rootless();
        let exec = format!("{BIN} daemon -c {CONFIG}");
        let (exec, rootless) = match engine {
            Some(e) => runner_common::rootless_exec(e, USER, &exec),
            None => (exec, String::new()),
        };
        let service = format!(
            "ExecReload=/bin/kill -s HUP $MAINPID\n\
             {rootless}\
             {slice}\
             {caps}\
             Restart=on-failure\n\
             RestartSec=10\n\
             TimeoutStopSec=infinity\n",
            caps = runner_common::cgroup_caps(
                c.cpu_quota.as_deref(),
                c.memory_max.as_deref(),
                c.tasks_max
            ),
        );
        runner_common::unit(
            "Forgejo Actions runner (anvil)",
            USER,
            HOME,
            &exec,
            &service,
            HOME,
            engine.is_some(),
        )
    }

    /// Daily, as the runner user: wipe HOME caches past
    /// `home_cache_max` while no job runs. Idle = nothing but the daemon
    /// (and its rootless Podman service) in the unit's cgroup, which holds
    /// host jobs and Podman job containers; Docker's job containers run in
    /// dockerd's, so `docker = "group"` also asks Docker.
    pub fn prune_content(&self) -> String {
        let docker = if self.cfg.docker == "group" {
            "\n  [ -z \"$(docker ps -q --filter name=ACTIONS-TASK 2>/dev/null)\" ] || return 1"
        } else {
            ""
        };
        let wipe = self
            .cfg
            .home_cache_max_bytes()
            .map_or(String::new(), |max| {
                runner_common::home_cache_prune(HOME, max, "idle")
            });
        format!(
            "#!/bin/bash\n\
             # Managed by anvil — prunes oversized forgejo-runner caches.\n\
             set -u\n\
             idle() {{\n\
             \x20 local cg p\n\
             \x20 cg=$(systemctl show -p ControlGroup --value {UNIT} 2>/dev/null)\n\
             \x20 if [ -n \"$cg\" ]; then\n\
             \x20\x20 for p in $(find \"/sys/fs/cgroup$cg\" -name cgroup.procs -exec cat {{}} + 2>/dev/null); do\n\
             \x20\x20\x20 case \"$(cat /proc/$p/comm 2>/dev/null)\" in (forgejo-runner|podman|'podman pause'|catatonit|dockerd-rootles|rootlesskit|exe|slirp4netns|dockerd|containerd|containerd-shim|'') ;; (*) return 1 ;; esac\n\
             \x20\x20 done\n\
             \x20 fi{docker}\n\
             }}\n\
             {wipe}"
        )
    }

    pub fn prune_service_content() -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Prune forgejo-runner caches (anvil)\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             User={USER}\n\
             ExecStart={PRUNE_SCRIPT}\n\
             NoNewPrivileges=yes\n\
             ProtectSystem=strict\n\
             ReadWritePaths={HOME}\n\
             PrivateTmp=yes\n"
        )
    }

    /// The engine removes the unit and config it created; this stops the
    /// service, removes the binary only if anvil installed it, then the user.
    /// The state dir (caches) is data and stays.
    /// Switching back from `mode = "ephemeral"` stops its slots
    /// (each stop deletes its registered runners) and moves their units,
    /// minter and API token to `.anvil.bak`; [`Self::rollback`] restores
    /// them. Image, slot volumes and the sandbox network stay for that.
    fn retire_ephemeral() -> ManagedCommand {
        let files = format!("{SLOT_UNITS} {} {}", eph::MINTER, eph::TOKEN_PATH);
        ManagedCommand::new(
            "ephemeral forgejo runner slots retired (mode = \"persistent\")",
            format!(
                "! compgen -G '{SLOT_UNITS}' >/dev/null && [ ! -e {} ] && [ ! -e {} ]",
                eph::MINTER,
                eph::TOKEN_PATH
            ),
            format!(
                "for __u in {SLOT_UNITS}; do\n\
                 \x20 [ ! -e \"$__u\" ] || systemctl disable --now \"${{__u##*/}}\" 2>/dev/null || true\n\
                 done\n\
                 for __p in {files}; do\n\
                 \x20 [ -e \"$__p\" ] || continue\n\
                 \x20 [ -e \"$__p{BACKUP_SUFFIX}\" ] || cp -a \"$__p\" \"$__p{BACKUP_SUFFIX}\"\n\
                 \x20 rm -f \"$__p\"\n\
                 \x20 printf '{MARK_CHANGED} %s retired (mode = \"persistent\")\\n' \"$__p\"\n\
                 done\n\
                 systemctl daemon-reload"
            ),
        )
    }

    fn rollback() -> String {
        format!(
            "\n# rollback forgejo runner\n\
             systemctl stop {UNIT} 2>/dev/null || true\n\
             rm -f /etc/systemd/system/multi-user.target.wants/{UNIT}\n\
             # Ephemeral slots this run retired come back.\n\
             for __b in {SLOT_UNITS}{BACKUP_SUFFIX} {minter}{BACKUP_SUFFIX} {token}{BACKUP_SUFFIX}; do\n\
             \x20 [ -e \"$__b\" ] || continue\n\
             \x20 mv -f \"$__b\" \"${{__b%{BACKUP_SUFFIX}}}\"\n\
             \x20 printf '{MARK_CHANGED} %s restored\\n' \"${{__b%{BACKUP_SUFFIX}}}\"\n\
             done\n\
             systemctl daemon-reload 2>/dev/null || true\n\
             for __u in {SLOT_UNITS}; do\n\
             \x20 [ ! -e \"$__u\" ] || systemctl enable --now \"${{__u##*/}}\" >/dev/null 2>&1 || true\n\
             done\n\
             if __anvil_created {BIN} && [ ! -e {minter} ]; then\n\
             \x20 rm -f {BIN}\n\
             \x20 __anvil_forget {BIN}\n\
             \x20 printf '{MARK_CHANGED} forgejo_runner: {BIN} removed (installed by anvil)\\n'\n\
             fi\n\
             printf '{MARK_OK} forgejo_runner: removed from this host; the runner stays listed in \
             Forgejo as offline until you delete it under Settings → Actions → Runners\\n'\n\
             {subids}{user}",
            subids = runner_common::rootless_rollback(USER),
            user = ACCOUNT.rollback(),
            minter = eph::MINTER,
            token = eph::TOKEN_PATH,
        )
    }
}

impl Module for ForgejoRunnerModule {
    fn id(&self) -> &'static str {
        "forgejo_runner"
    }

    fn declaration(&self) -> Declaration {
        if self.cfg.ephemeral() {
            return super::forgejo_runner_ephemeral::ForgejoEphemeral {
                cfg: &self.cfg,
                url: &self.url,
                docker_distro: self.docker_distro,
                docker: self.docker.as_ref(),
                in_ci_slice: self.in_ci_slice,
                ci_cpu_weight: self.ci_cpu_weight,
                owns_engine: self.owns_engine,
            }
            .declaration(self.install());
        }
        let mut decl = Declaration::new("forgejo_runner").secret(&self.cfg.token);
        if self.cfg.token.is_empty() {
            decl = decl.command(Self::token_missing());
        }
        decl = decl
            .command(Self::retire_ephemeral())
            .command(Self::ensure_tools())
            .command(ACCOUNT.ensure());
        if self.cfg.docker == "group" {
            decl = decl
                .installs(&["Docker"])
                .command(super::ensure_engine(
                    crate::config::Engine::Docker,
                    self.docker_distro,
                ))
                .command(Self::docker_group());
        }
        if let Some(engine) = self.rootless() {
            decl = decl
                .installs(&[match engine {
                    Engine::Podman => "Podman",
                    Engine::Docker => "Docker (rootless)",
                }])
                .command(super::ensure_engine(engine, self.docker_distro));
            for c in runner_common::rootless(engine, USER, "__fjr_restart=1") {
                decl = decl.command(c);
            }
        }
        decl.command(self.install())
            .command(ManagedCommand::new(
                "forgejo-runner service active",
                format!("systemctl is-active --quiet {UNIT}"),
                "__fjr_restart=1",
            ))
            .file(ManagedFile::computed(
                CONFIG,
                format!("printf '%s' {}", shell_escape(&self.config_yaml())),
                "0640",
                format!("root:{USER}"),
            ))
            .file(runner_common::unit_file(UNIT_PATH, self.unit_content(), USER))
            .file(ManagedFile::new(PRUNE_SCRIPT, self.prune_content(), "0755", "root:root"))
            .file(ManagedFile::new(
                PRUNE_SERVICE,
                Self::prune_service_content(),
                "0644",
                "root:root",
            ))
            .file(ManagedFile::new(
                PRUNE_TIMER,
                runner_common::prune_timer_content("forgejo-runner caches"),
                "0644",
                "root:root",
            ))
            .rollback_first(format!(
                "\n# rollback forgejo runner prune timer\n\
                 systemctl disable --now {PRUNE_TIMER_UNIT} 2>/dev/null || true\n\
                 rm -f /etc/systemd/system/timers.target.wants/{PRUNE_TIMER_UNIT}\n"
            ))
            .rollback_script(Self::rollback())
            .guarded_reload(ReloadGuard {
                describe: "forgejo runner service".into(),
                // A unit rollback already deleted needs no binary or config.
                validate: format!(
                    "{{ [ ! -e {UNIT_PATH} ] || {{ [ -x {BIN} ] && runuser -u {USER} -- test -r {CONFIG}; }}; }}"
                ),
                reload: format!(
                    "systemctl daemon-reload; \
                     for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do \
                     case \"$__p\" in ({CONFIG}|{UNIT_PATH}) __fjr_restart=1 ;; esac; done; \
                     if [ -e {UNIT_PATH} ]; then systemctl enable {UNIT} >/dev/null 2>&1 || true; \
                     if [ \"${{__fjr_restart:-0}}\" = 1 ]; then systemctl restart {UNIT}; fi; fi; \
                     [ ! -e {PRUNE_TIMER} ] || systemctl enable --now {PRUNE_TIMER_UNIT} >/dev/null 2>&1"
                ),
            })
    }
}

// --- validation (called from config::Config::validate) ---------------------

fn invalid(field: &str, value: &str, want: &str) -> AnvilError {
    AnvilError::Validation(format!(
        "forgejo_runner.{field}: {value:?} is invalid (must be {want})"
    ))
}

/// Safe inside a YAML double-quoted string and a unit/ shell word.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '\''))
}

/// Each mode's fields are rejected in the other, where nothing would
/// apply them; `api_token` lands in a curl config's double-quoted string.
fn validate_mode_fields(c: &ForgejoRunnerSection) -> Result<()> {
    if !c.ephemeral() {
        for (f, set) in [
            ("api_token", c.api_token.is_some()),
            ("owner", c.owner.is_some()),
            ("sandbox_runtime", c.sandbox_runtime.is_some()),
            ("sandbox_cpus", c.sandbox_cpus.is_some()),
            ("sandbox_memory", c.sandbox_memory.is_some()),
            ("sandbox_pids", c.sandbox_pids.is_some()),
            ("sandbox_disk", c.sandbox_disk.is_some()),
        ] {
            if set {
                return Err(AnvilError::Validation(format!(
                    "forgejo_runner.{f} needs mode = \"ephemeral\""
                )));
            }
        }
        return Ok(());
    }
    let persistent_only = [
        ("uuid", !c.uuid.is_empty()),
        ("token", !c.token.is_empty()),
        ("docker", c.docker != "none"),
        ("cpu_quota", c.cpu_quota.is_some()),
        ("memory_max", c.memory_max.is_some()),
        ("tasks_max", c.tasks_max.is_some()),
        ("home_cache_max", c.home_cache_max.is_some()),
    ];
    if let Some((f, _)) = persistent_only.iter().find(|(_, set)| *set) {
        return Err(AnvilError::Validation(format!(
            "forgejo_runner.{f} is persistent-only; with mode = \"ephemeral\" each job gets its own \
             sandbox, runner and Docker"
        )));
    }
    if let Some(r) = &c.sandbox_runtime {
        if !["sysbox-runc", "docker-rootless"].contains(&r.as_str()) {
            return Err(invalid(
                "sandbox_runtime",
                r,
                "\"sysbox-runc\" or \"docker-rootless\"",
            ));
        }
    }
    crate::config::validate_sandbox_limits(
        "forgejo_runner",
        c.sandbox_cpus(),
        c.sandbox_memory(),
        c.sandbox_pids(),
        c.sandbox_disk(),
    )?;
    let Some(token) = &c.api_token else {
        return Err(AnvilError::Validation(
            "forgejo_runner.api_token is required with mode = \"ephemeral\", e.g. \
             \"${FORGEJO_API_TOKEN:-}\""
                .into(),
        ));
    };
    // Don't echo a secret into the error.
    if token
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\'))
    {
        return Err(AnvilError::Validation(
            "forgejo_runner.api_token is invalid (no quotes, backslashes or control characters)"
                .into(),
        ));
    }
    if let Some(o) = &c.owner {
        let seg = |s: &str| {
            !matches!(s, "" | "." | "..")
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        };
        let ok = match o.split_once('/') {
            Some((a, b)) => seg(a) && seg(b),
            None => seg(o),
        };
        if !ok {
            return Err(invalid("owner", o, "\"<org>\" or \"<owner>/<repo>\""));
        }
    }
    Ok(())
}

/// `[forgejo]` in the same config must have Actions on; every value
/// that reaches the YAML config is restricted to a quote-free charset.
pub fn validate(c: &ForgejoRunnerSection, forgejo: Option<&ForgejoSection>) -> Result<()> {
    if forgejo.is_some_and(|f| !f.actions) {
        return Err(AnvilError::Validation(
            "forgejo_runner needs Forgejo Actions: set forgejo.actions = true".into(),
        ));
    }
    if !["persistent", "ephemeral"].contains(&c.mode.as_str()) {
        return Err(invalid("mode", &c.mode, "\"persistent\" or \"ephemeral\""));
    }
    validate_mode_fields(c)?;
    if !["none", "group", "podman", "rootless"].contains(&c.docker.as_str()) {
        return Err(invalid(
            "docker",
            &c.docker,
            "\"none\", \"group\", \"podman\" or \"rootless\"",
        ));
    }
    if c.url.is_empty() {
        if forgejo.is_none() {
            return Err(AnvilError::Validation(
                "forgejo_runner.url is required unless [forgejo] is in the same config".into(),
            ));
        }
    } else if !(c.url.starts_with("https://") && c.url.len() > 8 && plain(&c.url)) {
        return Err(invalid("url", &c.url, "an https:// URL"));
    }
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    let parts: Vec<&str> = c.uuid.split('-').collect();
    let lens: Vec<usize> = parts.iter().map(|p| p.len()).collect();
    if !c.ephemeral() && (lens != [8, 4, 4, 4, 12] || !parts.iter().all(|p| hex(p))) {
        return Err(invalid(
            "uuid",
            &c.uuid,
            "the runner UUID Forgejo shows (8-4-4-4-12 hex)",
        ));
    }
    // Lands in a YAML double-quoted string. Don't echo a secret into the error.
    if c.token
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\'))
    {
        return Err(AnvilError::Validation(
            "forgejo_runner.token is invalid (no quotes, backslashes or control characters)".into(),
        ));
    }
    if let Some(h) = &c.home_cache_max {
        if c.home_cache_max_bytes().is_none() {
            return Err(invalid(
                "home_cache_max",
                h,
                "a whole number of gigabytes or terabytes, e.g. \"20G\"",
            ));
        }
    }
    if c.capacity == 0 {
        return Err(AnvilError::Validation(
            "forgejo_runner.capacity must be at least 1".into(),
        ));
    }
    if c.labels.is_empty() {
        return Err(AnvilError::Validation(
            "forgejo_runner.labels: add at least one, e.g. \"debian:host\" or \
             \"debian:docker://node:22-trixie\""
                .into(),
        ));
    }
    for l in &c.labels {
        let (name, how) = l.split_once(':').unwrap_or((l, ""));
        let name_ok = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        let how_ok = how == "host"
            || how
                .strip_prefix("docker://")
                .is_some_and(|img| plain(img) && !img.contains('#'));
        if !(name_ok && how_ok) {
            return Err(invalid(
                "labels",
                l,
                "<name>:host or <name>:docker://<image>",
            ));
        }
        // Ephemeral: the sandbox's own dockerd runs container jobs.
        if how != "host" && c.docker == "none" && !c.ephemeral() {
            return Err(AnvilError::Validation(format!(
                "forgejo_runner.labels: {l:?} runs jobs in containers, which needs \
                 forgejo_runner.docker = \"rootless\" (either engine) or \"group\" \
                 (root-equivalent, Docker host); use \"{name}:host\" otherwise"
            )));
        }
    }
    crate::config::validate_runner_limits(
        "forgejo_runner",
        (c.version.as_deref(), c.sha256.as_deref()),
        c.cpu_quota.as_deref(),
        c.memory_max.as_deref(),
        c.tasks_max,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const BASE: &str = r#"
        url = "https://git.example.org/"
        uuid = "00000000-0000-4000-8000-000000000000"
        token = "f00dfeedf00dfeedf00dfeedf00dfeedf00dfeed"
        labels = ["debian:host"]
    "#;

    /// BASE with the keys `extra` sets replaced.
    fn section(extra: &str) -> ForgejoRunnerSection {
        let key = |l: &str| l.split('=').next().unwrap_or("").trim().to_string();
        let set: Vec<String> = extra.lines().map(key).collect();
        let base: String = BASE
            .lines()
            .filter(|l| !set.contains(&key(l)))
            .map(|l| format!("{l}\n"))
            .collect();
        toml::from_str(&format!("{base}{extra}")).unwrap()
    }

    fn module(extra: &str) -> ForgejoRunnerModule {
        ForgejoRunnerModule::new(section(extra), None)
    }

    fn forgejo(actions: bool) -> ForgejoSection {
        toml::from_str(&format!(
            "domain = \"git.local.test\"\nsecret_key = \"x\"\ninternal_token = \"x\"\n\
             jwt_secret = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\nactions = {actions}"
        ))
        .unwrap()
    }

    fn config_generator(d: &Declaration) -> String {
        let f = d.files.iter().find(|f| f.path == CONFIG).unwrap();
        assert_eq!(
            (f.mode.as_str(), f.owner.as_str()),
            ("0640", "root:forgejo-runner")
        );
        match &f.content {
            crate::engine::FileContent::Computed { generator } => generator.clone(),
            _ => panic!("the config holds the token; it must be computed"),
        }
    }

    #[test]
    fn binary_is_pinned_verified_then_installed_and_recorded() {
        let apply = module("").declaration().render_apply();
        assert!(apply.contains(
            "\"https://code.forgejo.org/forgejo/runner/releases/download/v\"'13.2.1'\"/forgejo-runner-\"'13.2.1'\"-linux-${__ra}\""
        ));
        assert!(apply.contains(DEFAULT_SHA256_AMD64) && apply.contains(DEFAULT_SHA256_ARM64));
        let check = apply.find("sha256sum -c --status -; then").unwrap();
        let remember = apply
            .find("[ -e /usr/local/bin/forgejo-runner ] || __anvil_remember /usr/local/bin/forgejo-runner\n")
            .unwrap();
        let install = apply
            .find("install -m 0755 -o root -g root \"$__tmp/forgejo-runner\" /usr/local/bin/forgejo-runner")
            .unwrap();
        assert!(check < remember && remember < install);
        assert!(!apply.contains("| sh\n") && !apply.contains("| bash"));
    }

    #[test]
    fn detect_checks_the_installed_binary_against_the_pin() {
        let d = module("").install().detect;
        assert!(d.contains(&format!("amd64) __sha='{DEFAULT_SHA256_AMD64}' ;;")));
        assert!(d.contains(&format!("arm64) __sha='{DEFAULT_SHA256_ARM64}' ;;")));
        assert!(d.contains("[ -n \"$__sha\" ] && [ -x /usr/local/bin/forgejo-runner ]"));
        assert!(d.contains(
            "printf '%s  %s\\n' \"$__sha\" /usr/local/bin/forgejo-runner | sha256sum -c --status -"
        ));
        let sha = "a".repeat(64);
        let pinned = module(&format!("version = \"13.3.0\"\nsha256 = \"{sha}\""));
        let d = pinned.install();
        assert!(d
            .detect
            .contains(&format!("amd64) __sha='{sha}' ;; arm64) __sha='{sha}' ;;")));
        assert!(d.converge.contains("'13.3.0'"));
        assert_eq!(
            d.describe,
            "forgejo-runner 13.3.0 binary (SHA-256 verified)"
        );
    }

    #[test]
    fn config_carries_the_connection_and_labels_and_never_mounts_docker() {
        let y = module("labels = [\"debian:host\", \"node:docker://node:22-trixie\"]\ncapacity = 3\ndocker = \"group\"")
            .config_yaml();
        for want in [
            "runner:\n  capacity: 3\n  labels:\n    - \"debian:host\"\n    - \"node:docker://node:22-trixie\"\n",
            "container:\n  # Never hand the Docker socket to job containers.\n  docker_host: \"-\"\n",
            "server:\n  connections:\n    anvil:\n      url: \"https://git.example.org/\"\n      \
             uuid: \"00000000-0000-4000-8000-000000000000\"\n      \
             token: \"f00dfeedf00dfeedf00dfeedf00dfeedf00dfeed\"\n",
        ] {
            assert!(y.contains(want), "missing {want:?} in\n{y}");
        }
    }

    #[test]
    fn token_only_in_the_computed_config_never_in_static_content() {
        let d = module("").declaration();
        assert!(config_generator(&d).starts_with("printf '%s' '# Managed by anvil"));
        for f in &d.files {
            let c = f.static_content().unwrap_or_default();
            assert!(!c.contains("f00dfeed"), "{} leaks the token", f.path);
        }
        for c in &d.commands {
            assert!(!c.converge.contains("f00dfeed") && !c.detect.contains("f00dfeed"));
        }
    }

    #[test]
    fn url_defaults_to_the_forgejo_instance() {
        let m = ForgejoRunnerModule::new(section("url = \"\""), Some("git.local.test"));
        assert!(m
            .config_yaml()
            .contains("      url: \"https://git.local.test/\"\n"));
        let m = ForgejoRunnerModule::new(section(""), Some("git.local.test"));
        assert!(m
            .config_yaml()
            .contains("      url: \"https://git.example.org/\"\n"));
    }

    #[test]
    fn empty_token_fails_apply_before_anything_is_written() {
        let d = module("token = \"\"").declaration();
        let c = &d.commands[0];
        assert_eq!(c.detect, "false");
        assert!(c
            .converge
            .contains("printf 'FAILED: forgejo_runner: token is empty;"));
        assert!(c.converge.ends_with("\nexit 1"));
        assert!(!module("")
            .declaration()
            .commands
            .iter()
            .any(|c| c.detect == "false"));
    }

    #[test]
    fn unit_runs_the_daemon_hardened_as_the_runner_user() {
        let u = module("").unit_content();
        let svc = u.split("[Install]").next().unwrap();
        for line in [
            "\nUser=forgejo-runner\n",
            "\nWorkingDirectory=/var/lib/forgejo-runner\n",
            "\nExecStart=/usr/local/bin/forgejo-runner daemon -c /etc/forgejo-runner/config.yml\n",
            "\nExecReload=/bin/kill -s HUP $MAINPID\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=infinity\n",
            "\nNoNewPrivileges=yes\n",
            "\nProtectSystem=strict\n",
            "\nReadWritePaths=/var/lib/forgejo-runner\n",
            "\nPrivateTmp=yes\n",
            "\nPrivateDevices=yes\n",
            "\nCapabilityBoundingSet=\n",
            "\nRestrictSUIDSGID=yes\n",
        ] {
            assert!(svc.contains(line), "unit missing {line:?}:\n{u}");
        }
        assert!(!u.contains("CPUQuota") && !u.contains("MemoryMax") && !u.contains("TasksMax"));
        let capped =
            module("cpu_quota = \"200%\"\nmemory_max = \"4G\"\ntasks_max = 512").unit_content();
        assert!(capped.contains(
            "\nExecReload=/bin/kill -s HUP $MAINPID\nCPUQuota=200%\nMemoryMax=4G\nTasksMax=512\nRestart=on-failure\n"
        ));
    }

    #[test]
    fn docker_group_is_opt_in() {
        let none = module("").declaration().render_apply();
        assert!(!none.contains("usermod -aG docker"));
        let group = module("docker = \"group\"").declaration().render_apply();
        assert!(group.contains("usermod -aG docker forgejo-runner\n__fjr_restart=1"));
        assert!(group.contains("root-equivalent"));
        assert!(module("").declaration().installs.is_empty());
        assert_eq!(
            module("docker = \"group\"").declaration().installs,
            ["Docker"]
        );
    }

    #[test]
    fn docker_rootless_runs_rootless_dockerd_inside_the_unit() {
        let d = module("docker = \"rootless\"").declaration();
        assert_eq!(d.installs, ["Docker (rootless)"]);
        let apply = d.render_apply();
        assert!(apply.contains("'docker-ce-rootless-extras' 'uidmap' 'slirp4netns'"));
        assert!(apply.contains("usermod --add-subuids") && !apply.contains("usermod -aG docker"));
        let u = module("docker = \"rootless\"").unit_content();
        assert!(u.contains("/usr/bin/dockerd-rootless.sh"), "{u}");
        assert!(
            u.contains("\nEnvironment=DOCKER_HOST=unix:///run/user/ANVIL_RUNNER_UID/forgejo-runner/docker.sock\n"),
            "{u}"
        );
        assert!(!u.contains("NoNewPrivileges") && !u.contains("podman"));
    }

    #[test]
    fn docker_podman_runs_rootless_podman_inside_the_unit() {
        let d = module("docker = \"podman\"").declaration();
        assert_eq!(d.installs, ["Podman"]);
        let apply = d.render_apply();
        assert!(
            apply.contains("'podman' 'iptables' 'aardvark-dns'")
                && !apply.contains("usermod -aG docker")
        );
        assert!(apply.contains("usermod --add-subuids") && apply.contains("\n__fjr_restart=1"));
        let u = module("docker = \"podman\"")
            .in_ci_slice(true)
            .unit_content();
        for want in [
            "\nExecStart=/bin/bash -c 'env -u CONTAINER_HOST podman --cgroup-manager=cgroupfs \
             --runroot /run/user/ANVIL_RUNNER_UID/forgejo-runner/containers ",
            " system service --time=0 unix:///run/user/ANVIL_RUNNER_UID/forgejo-runner/podman.sock & ",
            "\nEnvironment=XDG_RUNTIME_DIR=/run/user/ANVIL_RUNNER_UID\n",
            "exec /usr/local/bin/forgejo-runner daemon -c /etc/forgejo-runner/config.yml'\n",
            "\nExecStartPre=/bin/sh -c 'f=/run/user/ANVIL_RUNNER_UID/libpod/tmp/pause.pid; ",
            "\nExecReload=/bin/kill -s HUP $MAINPID\nExecStartPre=/bin/mkdir -p -m 0700 /run/user/ANVIL_RUNNER_UID/forgejo-runner\n",
            "\nEnvironment=DOCKER_HOST=unix:///run/user/ANVIL_RUNNER_UID/forgejo-runner/podman.sock\n",
            "\nKillMode=mixed\nDelegate=yes\nSlice=ci.slice\n",
        ] {
            assert!(u.contains(want), "missing {want:?}:\n{u}");
        }
        assert!(!u.contains("NoNewPrivileges"));
        for other in ["", "docker = \"group\""] {
            let u = module(other).unit_content();
            assert!(
                u.contains("NoNewPrivileges=yes")
                    && !u.contains("podman")
                    && !u.contains("Delegate="),
                "{u}"
            );
        }
        // Job containers never get the socket: the daemon is found via DOCKER_HOST.
        assert!(module("docker = \"podman\"")
            .config_yaml()
            .contains("  docker_host: \"-\"\n"));
        let rb = d.render_rollback();
        let stop = rb
            .find("systemctl stop anvil-forgejo-runner.service")
            .unwrap();
        let subids = rb.find("sed -n 's/^subids:forgejo-runner://p'").unwrap();
        let user = rb
            .find("if __anvil_created user:forgejo-runner; then")
            .unwrap();
        let linger = rb.find("loginctl disable-linger 'forgejo-runner'").unwrap();
        assert!(stop < linger && linger < subids && subids < user);
        // The unit's uid is filled in on the host; other modes stay static.
        let unit = d.files.iter().find(|f| f.path == UNIT_PATH).unwrap();
        assert!(unit.static_content().is_none());
        let d = module("").declaration();
        let unit = d.files.iter().find(|f| f.path == UNIT_PATH).unwrap();
        assert!(unit.static_content().is_some());
    }

    #[test]
    fn restart_only_when_something_changed() {
        let g = module("").declaration().reload.unwrap();
        assert_eq!(
            g.validate,
            "{ [ ! -e /etc/systemd/system/anvil-forgejo-runner.service ] || \
             { [ -x /usr/local/bin/forgejo-runner ] && \
             runuser -u forgejo-runner -- test -r /etc/forgejo-runner/config.yml; }; }"
        );
        assert!(g.reload.contains(
            "if [ -e /etc/systemd/system/anvil-forgejo-runner.service ]; then systemctl enable anvil-forgejo-runner.service"
        ));
        // Only the runner's own files restart it, not the prune timer's.
        let restarts = |set: &str| {
            let script = format!(
                "systemctl() {{ echo \"systemctl $*\"; }}\n{set}\n{}",
                g.reload.replace(UNIT_PATH, "/")
            );
            let out = std::process::Command::new("bash")
                .args(["-euo", "pipefail", "-c", &script])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).contains("systemctl restart")
        };
        assert!(!restarts(&format!(
            "__creates=({PRUNE_SCRIPT} {PRUNE_TIMER}); __reverts=()"
        )));
        assert!(restarts(&format!("__creates=(); __reverts=({CONFIG})")));
        assert!(restarts("__creates=(); __reverts=(); __fjr_restart=1"));
        assert!(!restarts("__creates=(); __reverts=()"));
    }

    #[test]
    fn prune_wipes_home_caches_only_when_idle_and_past_the_cap() {
        let m = module("");
        let p = m.prune_content();
        let idle = p.find("idle() {").unwrap();
        let wipe = p
            .find("rm -rf -- '/var/lib/forgejo-runner/.cache'")
            .unwrap();
        assert!(idle < wipe && p.contains("-gt 21474836480 ] && idle; then"));
        assert!(!p.contains("docker ps"));
        assert!(module("docker = \"group\"")
            .prune_content()
            .contains("docker ps -q --filter name=ACTIONS-TASK"));
        assert!(!module("home_cache_max = \"1T\"")
            .prune_content()
            .contains("-gt 21474836480"));
        assert!(p.contains("systemctl show -p ControlGroup --value anvil-forgejo-runner.service"));
        let svc = ForgejoRunnerModule::prune_service_content();
        assert!(
            svc.contains("User=forgejo-runner\n")
                && svc.contains("ReadWritePaths=/var/lib/forgejo-runner\n")
        );
        let d = m.declaration();
        for path in [PRUNE_SCRIPT, PRUNE_SERVICE, PRUNE_TIMER] {
            assert!(d.files.iter().any(|f| f.path == path), "{path}");
        }
        assert!(d.reload.as_ref().unwrap().reload.ends_with(&format!(
            "[ ! -e {PRUNE_TIMER} ] || systemctl enable --now {PRUNE_TIMER_UNIT} >/dev/null 2>&1"
        )));
        assert!(d
            .render_rollback()
            .contains(&format!("systemctl disable --now {PRUNE_TIMER_UNIT}")));
        // The idle test parses and, with no such unit, finds the runner idle.
        let out = std::process::Command::new("bash")
            .args([
                "-c",
                &format!("{}\nidle", p.split("\nif [").next().unwrap()),
            ])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[test]
    fn rollback_removes_only_what_anvil_created_and_never_the_state_dir() {
        let rb = module("").declaration().render_rollback();
        let stop = rb
            .find("systemctl stop anvil-forgejo-runner.service")
            .unwrap();
        let gate = rb
            .find("if __anvil_created /usr/local/bin/forgejo-runner && [ ! -e /usr/local/libexec/anvil/forgejo-runner-mint.sh ]; then\n  rm -f /usr/local/bin/forgejo-runner\n  __anvil_forget /usr/local/bin/forgejo-runner\n")
            .unwrap();
        let warn = rb
            .find("printf 'OK: forgejo_runner: removed from this host; the runner stays listed in Forgejo")
            .unwrap();
        let user = rb
            .find("if __anvil_created user:forgejo-runner; then")
            .unwrap();
        let reload = rb.find("# reload with the restored config").unwrap();
        assert!(stop < gate && gate < warn && warn < user && user < reload);
        assert!(rb
            .contains("forgejo-runner user kept; runner configs remain under /etc/forgejo-runner"));
        assert!(!rb.contains("rm -rf"));
        assert!(!rb.contains("userdel -r"));
    }

    #[test]
    fn every_script_parses_under_bash_n() {
        for extra in [
            "",
            "docker = \"group\"\ntoken = \"\"\ncpu_quota = \"100%\"",
            "docker = \"podman\"",
        ] {
            let d = module(extra).declaration();
            for s in [d.render_probe(), d.render_apply(), d.render_rollback()] {
                let out = Command::new("bash")
                    .args(["-n", "-c", &s])
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }

    #[test]
    fn validation_accepts_the_defaults() {
        validate(&section(""), None).unwrap();
        validate(&section("url = \"\""), Some(&forgejo(true))).unwrap();
        validate(&section("token = \"\""), None).unwrap();
        validate(
            &section(
                "docker = \"group\"\nlabels = [\"a.b-c_d:docker://node:22-trixie\", \"x:host\"]",
            ),
            None,
        )
        .unwrap();
        let s = section("");
        assert_eq!((s.capacity, s.docker.as_str()), (1, "none"));
    }

    #[test]
    fn validation_rejects_each_bad_value() {
        let err = |extra: &str, f: Option<ForgejoSection>| {
            validate(&section(extra), f.as_ref())
                .unwrap_err()
                .to_string()
        };
        assert!(err("", Some(forgejo(false))).contains("forgejo.actions = true"));
        assert!(err("url = \"\"", None).contains("forgejo_runner.url is required"));
        for (extra, want) in [
            ("url = \"http://git.example.org/\"", "forgejo_runner.url"),
            ("url = \"https://\"", "forgejo_runner.url"),
            ("url = \"https://a b/\"", "forgejo_runner.url"),
            ("url = \"https://a\\\"b/\"", "forgejo_runner.url"),
            (
                "uuid = \"00000000-0000-4000-8000-00000000000\"",
                "forgejo_runner.uuid",
            ),
            (
                "uuid = \"00000000-0000-4000-8000-00000000000g\"",
                "forgejo_runner.uuid",
            ),
            (
                "uuid = \"000000000000-4000-8000-0000000000000000\"",
                "forgejo_runner.uuid",
            ),
            ("token = \"ab\\\"c\"", "forgejo_runner.token"),
            ("token = \"ab\\\\c\"", "forgejo_runner.token"),
            ("token = \"ab\\nc\"", "forgejo_runner.token"),
            ("capacity = 0", "forgejo_runner.capacity"),
            ("home_cache_max = \"20\"", "forgejo_runner.home_cache_max"),
            ("docker = \"sysbox\"", "forgejo_runner.docker"),
            ("labels = []", "forgejo_runner.labels"),
            ("labels = [\"debian\"]", "forgejo_runner.labels"),
            ("labels = [\":host\"]", "forgejo_runner.labels"),
            ("labels = [\"de bian:host\"]", "forgejo_runner.labels"),
            (
                "labels = [\"debian:lxc://debian:bookworm\"]",
                "forgejo_runner.labels",
            ),
            (
                "docker = \"group\"\nlabels = [\"a:docker://\"]",
                "forgejo_runner.labels",
            ),
            (
                "docker = \"group\"\nlabels = [\"a:docker://x#y\"]",
                "forgejo_runner.labels",
            ),
            (
                "docker = \"group\"\nlabels = [\"a:docker://x\\\"y\"]",
                "forgejo_runner.labels",
            ),
            ("cpu_quota = \"4\"", "forgejo_runner.cpu_quota"),
            ("tasks_max = 0", "forgejo_runner.tasks_max"),
            (
                "version = \"13.3.0\"",
                "forgejo_runner.version and forgejo_runner.sha256",
            ),
        ] {
            let e = err(extra, None);
            assert!(e.contains(want), "{extra}: {e}");
        }
        let e = err("labels = [\"node:docker://node:22\"]", None);
        assert!(
            e.contains("needs forgejo_runner.docker = \"rootless\"")
                && e.contains("or \"group\"")
                && e.contains("\"node:host\""),
            "{e}"
        );
        validate(
            &section("docker = \"podman\"\nlabels = [\"node:docker://node:22\"]"),
            None,
        )
        .unwrap();
        assert!(!err("token = \"s3cr\\\"et\"", None).contains("s3cr"));
    }

    #[test]
    fn ephemeral_mode_validates_its_own_fields() {
        let eph = |extra: &str| -> ForgejoRunnerSection {
            toml::from_str(&format!(
                "mode = \"ephemeral\"\nurl = \"https://git.example.org/\"\n\
                 labels = [\"node:docker://node:22\"]\n{extra}"
            ))
            .unwrap()
        };
        validate(&eph("api_token = \"t\""), None).unwrap();
        validate(&eph("api_token = \"\"\nowner = \"acme/app\""), None).unwrap();
        validate(&eph("api_token = \"t\"\nowner = \"a-b.c_d\""), None).unwrap();
        for r in ["sysbox-runc", "docker-rootless"] {
            validate(
                &eph(&format!("api_token = \"t\"\nsandbox_runtime = \"{r}\"")),
                None,
            )
            .unwrap();
        }
        for (extra, want) in [
            (
                "api_token = \"t\"\nsandbox_runtime = \"podman\"",
                "forgejo_runner.sandbox_runtime: \"podman\" is invalid",
            ),
            (
                "api_token = \"t\"\nsandbox_cpus = \"0\"",
                "forgejo_runner.sandbox_cpus",
            ),
            (
                "api_token = \"t\"\nsandbox_memory = \"4x\"",
                "forgejo_runner.sandbox_memory",
            ),
            (
                "api_token = \"t\"\nsandbox_pids = 0",
                "forgejo_runner.sandbox_pids",
            ),
            (
                "api_token = \"t\"\nsandbox_disk = \"40\"",
                "forgejo_runner.sandbox_disk",
            ),
            ("", "forgejo_runner.api_token is required"),
            (
                "api_token = \"a\\\"b\"",
                "forgejo_runner.api_token is invalid",
            ),
            (
                "api_token = \"t\"\nuuid = \"00000000-0000-4000-8000-000000000000\"",
                "forgejo_runner.uuid is persistent-only",
            ),
            (
                "api_token = \"t\"\ntoken = \"x\"",
                "forgejo_runner.token is persistent-only",
            ),
            (
                "api_token = \"t\"\ndocker = \"group\"",
                "forgejo_runner.docker is persistent-only",
            ),
            (
                "api_token = \"t\"\ncpu_quota = \"100%\"",
                "forgejo_runner.cpu_quota is persistent-only",
            ),
            (
                "api_token = \"t\"\nmemory_max = \"1G\"",
                "forgejo_runner.memory_max is persistent-only",
            ),
            (
                "api_token = \"t\"\ntasks_max = 9",
                "forgejo_runner.tasks_max is persistent-only",
            ),
            (
                "api_token = \"t\"\nhome_cache_max = \"1G\"",
                "forgejo_runner.home_cache_max is persistent-only",
            ),
            (
                "api_token = \"t\"\nowner = \"a/b/c\"",
                "forgejo_runner.owner",
            ),
            (
                "api_token = \"t\"\nowner = \"../x\"",
                "forgejo_runner.owner",
            ),
            ("api_token = \"t\"\nowner = \"a b\"", "forgejo_runner.owner"),
            ("api_token = \"t\"\nowner = \"\"", "forgejo_runner.owner"),
        ] {
            let e = validate(&eph(extra), None).unwrap_err().to_string();
            assert!(e.contains(want), "{extra}: {e}");
        }
        assert!(!validate(&eph("api_token = \"s3cr\\\"et\""), None)
            .unwrap_err()
            .to_string()
            .contains("s3cr"));
        for (extra, want) in [
            (
                "api_token = \"t\"",
                "forgejo_runner.api_token needs mode = \"ephemeral\"",
            ),
            (
                "owner = \"acme\"",
                "forgejo_runner.owner needs mode = \"ephemeral\"",
            ),
            (
                "sandbox_runtime = \"docker-rootless\"",
                "forgejo_runner.sandbox_runtime needs mode = \"ephemeral\"",
            ),
            (
                "sandbox_cpus = \"2\"",
                "forgejo_runner.sandbox_cpus needs mode = \"ephemeral\"",
            ),
            ("mode = \"oneshot\"", "forgejo_runner.mode"),
        ] {
            let e = validate(&section(extra), None).unwrap_err().to_string();
            assert!(e.contains(want), "{extra}: {e}");
        }
        assert_eq!(section("").mode, "persistent");
        assert!(!section("").ephemeral() && eph("").ephemeral());
    }

    #[test]
    fn mode_picks_the_declaration() {
        let s: ForgejoRunnerSection =
            toml::from_str("mode = \"ephemeral\"\napi_token = \"t\"\nlabels = [\"debian:host\"]")
                .unwrap();
        let d = ForgejoRunnerModule::new(s, Some("git.local.test")).declaration();
        let minter = d
            .files
            .iter()
            .find(|f| f.path == super::super::forgejo_runner_ephemeral::MINTER)
            .and_then(|f| f.static_content())
            .unwrap();
        assert!(minter.contains("'https://git.local.test/api/v1'"));
        assert!(!d.files.iter().any(|f| f.path == CONFIG));
        // The sandbox mounts the pinned, verified binary.
        assert!(d.render_apply().contains(DEFAULT_SHA256_AMD64));
        let p = module("").declaration();
        assert!(p.files.iter().any(|f| f.path == CONFIG));
    }

    /// Review: persistent mode stops leftover ephemeral slots and moves
    /// their files aside; its rollback restores and restarts them.
    #[test]
    fn persistent_retires_ephemeral_slots_and_rollback_brings_them_back() {
        use super::super::forgejo_runner_ephemeral::tests::run_in_root;
        let slot = "/etc/systemd/system/anvil-forgejo-runner-1.service";
        let c = ForgejoRunnerModule::retire_ephemeral();
        let setup = [slot, eph::MINTER, eph::TOKEN_PATH, PRUNE_SERVICE];
        let (root, calls) = run_in_root(&c.converge, &setup);
        assert!(calls.starts_with("systemctl disable --now anvil-forgejo-runner-1.service\n"));
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        for p in [slot, eph::MINTER, eph::TOKEN_PATH] {
            assert!(
                !at(p).exists() && at(&format!("{p}{BACKUP_SUFFIX}")).exists(),
                "{p}"
            );
        }
        assert!(
            at(PRUNE_SERVICE).exists(),
            "the prune service is persistent's own"
        );
        let rb = ForgejoRunnerModule::rollback();
        let start = rb.find("for __b in").unwrap();
        let end = start + rb[start..].find("if __anvil_created").unwrap();
        let r = root.display().to_string();
        let restore = rb[start..end]
            .replace("/etc/", &format!("{r}/etc/"))
            .replace("/usr/", &format!("{r}/usr/"));
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c"])
            .arg(format!(
                "systemctl() {{ echo \"systemctl $*\" >>{r}/calls2; }}\n{restore}"
            ))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        for p in [slot, eph::MINTER, eph::TOKEN_PATH] {
            assert!(
                at(p).exists() && !at(&format!("{p}{BACKUP_SUFFIX}")).exists(),
                "{p}"
            );
        }
        let calls = std::fs::read_to_string(root.join("calls2")).unwrap();
        assert!(calls.contains("systemctl enable --now anvil-forgejo-runner-1.service"));
        std::fs::remove_dir_all(root).ok();
        // First in the declaration, before the persistent unit starts.
        assert!(module("").declaration().commands[0]
            .describe
            .starts_with("ephemeral forgejo runner slots retired"));
    }

    #[test]
    fn unit_joins_the_ci_slice_only_with_ci_resources() {
        assert!(!module("").unit_content().contains("Slice="));
        let u = module("").in_ci_slice(true).unit_content();
        let service = u.split("[Service]").nth(1).unwrap();
        assert!(
            service.contains("\nExecReload=/bin/kill -s HUP $MAINPID\nSlice=ci.slice\n"),
            "{u}"
        );
    }
}
