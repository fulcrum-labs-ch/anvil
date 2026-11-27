//! The `github_runner` module: self-hosted GitHub Actions runners
//! (docs/design/github-actions-runner.md).
//!
//! Each `[github_runner.runners.<name>]` gets the pinned, SHA-256-verified
//! actions/runner tarball under `/opt/github-runner/<name>`, a one-time
//! registration (`config.sh`, token passed by environment — never argv), and
//! an anvil-owned hardened systemd unit. All runners share the unprivileged
//! `github-runner` system user.
//!
//! Every config value reaching bash goes through [`shell_escape`]; unit and
//! hook content is static and base64-embedded by the engine. Tokens only ever
//! appear inside command converge/rollback bodies, which `diff` never prints.

use crate::config::schema::{GithubRunner, GithubRunnerSection};
use crate::config::Engine;
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, MARK_CHANGED, MARK_FAILED, MARK_OK,
};
use crate::escape::shell_escape;

use super::runner_common::{self, Account, Download};
use super::{apt_install, Module};

pub const USER: &str = "github-runner";
pub const HOME: &str = "/var/lib/github-runner";
pub const ROOT: &str = "/opt/github-runner";
pub const NEEDRESTART_CONF: &str = "/etc/needrestart/conf.d/99-anvil-github-runner.conf";
/// Pinned default (actions/runner v2.338.2, released 2026-10-26). Hashes are
/// copied from the release notes' "SHA-256 Checksums" section.
pub const DEFAULT_VERSION: &str = "2.338.2";
const DEFAULT_SHA256_X64: &str = "baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40";
const DEFAULT_SHA256_ARM64: &str =
    "670adb2f268fe21dcbb58b3db0e0aa9d5b3bddfe2c651481336e561ff86de945";

/// True when every library `bin/installdependencies.sh` installs is present
/// (GR13). ICU, OpenSSL and LTTng package names change per release
/// (`libssl3t64`, `liblttng-ust1t64`, `libicu76`…), so those are globbed.
const DEPS_PRESENT: &str = "dpkg -s libkrb5-3 zlib1g >/dev/null 2>&1 \
     && compgen -G '/usr/lib/*/libicuuc.so.*' >/dev/null \
     && compgen -G '/usr/lib/*/libssl.so.*' >/dev/null \
     && compgen -G '/usr/lib/*/liblttng-ust.so.*' >/dev/null";

pub fn runner_dir(name: &str) -> String {
    format!("{ROOT}/{name}")
}

pub fn unit_name(name: &str) -> String {
    format!("anvil-github-runner-{name}.service")
}

/// GR31: each runner's own HOME (`~/.rustup`, `~/.cargo`, caches).
pub fn runner_home(name: &str) -> String {
    format!("{HOME}/{name}")
}

pub fn unit_path(name: &str) -> String {
    format!("/etc/systemd/system/{}", unit_name(name))
}

/// GR29: one job-started hook for all runners; the runner execs it
/// fresh per job, so a content change restarts nothing.
pub const JOB_STARTED_HOOK: &str = "/usr/local/libexec/anvil/github-runner-job-started.sh";
pub const JOB_STARTED_CONTENT: &str = "#!/bin/bash\n\
     # Managed by anvil — CIS mounts /tmp noexec; give each job an exec-able TMPDIR.\n\
     set -eu\n\
     printf 'TMPDIR=%s\\n' \"$RUNNER_TEMP\" >> \"$GITHUB_ENV\"\n\
     # Container jobs bind these into the job; Podman refuses a missing source\n\
     # (Docker made it as root). Inside _work, so on the disk_max volume.\n\
     w=$(dirname \"$RUNNER_TEMP\")\n\
     mkdir -p \"$w/_actions\" \"$w/_tool\" \"$RUNNER_TEMP/_github_home\" \"$RUNNER_TEMP/_github_workflow\"\n";

/// Defines `__ghr_mine <unit> <path>...`: true when any path was created or
/// reverted this run, or the unit was flagged (version-proof under `set -u`:
/// rollback scripts define no `__creates`).
pub(super) const MINE_FN: &str = "__ghr_mine() { local __p __q; \
     for __p in \"${__creates[@]:-}\" \"${__reverts[@]:-}\" \"${__ghr_restart[@]:-}\"; do \
     for __q in \"$@\"; do [ \"$__p\" != \"$__q\" ] || return 0; done; done; return 1; }; ";

pub fn hook_path(name: &str) -> String {
    format!("/usr/local/libexec/anvil/github-runner-clean-{name}.sh")
}

/// `docker = "podman"`: actions/runner pulls `node:22` through the podman
/// CLI, which (unlike Docker) resolves short names only via search registries.
/// registries.conf.d merges in order: HIGH prefix.
pub const REGISTRIES_CONF: &str = "/etc/containers/registries.conf.d/99-anvil-github-runner.conf";
pub const REGISTRIES_CONTENT: &str =
    "# Managed by anvil — short image names resolve on Docker Hub, as with Docker\n\
     unqualified-search-registries = [\"docker.io\"]\n";

/// GR23: loop images for the capped `_work` volumes live here (root-only).
pub const IMAGE_DIR: &str = "/var/lib/anvil-ci";
pub const PRUNE_SCRIPT: &str = "/usr/local/libexec/anvil/github-runner-prune.sh";
pub const PRUNE_SERVICE: &str = "/etc/systemd/system/anvil-github-runner-prune.service";
pub const PRUNE_TIMER_UNIT: &str = "anvil-github-runner-prune.timer";
pub const PRUNE_TIMER: &str = "/etc/systemd/system/anvil-github-runner-prune.timer";
/// `check` drifts once a capped `_work` volume is this full (percent).
const USAGE_ALERT_PCT: u8 = 90;

pub fn work_dir(name: &str) -> String {
    format!("{}/_work", runner_dir(name))
}

pub fn image_path(name: &str) -> String {
    format!("{IMAGE_DIR}/github-runner-{name}.img")
}

/// `systemd-escape --path`: `RequiresMountsFor=` finds the mount unit only
/// under exactly this name.
pub fn escape_path(path: &str) -> String {
    let mut out = String::new();
    for (i, b) in path.trim_matches('/').bytes().enumerate() {
        match b {
            b'/' => out.push('-'),
            b'.' if i == 0 => out.push_str("\\x2e"),
            b if b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'.') => {
                out.push(b as char)
            }
            b => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

pub fn mount_unit(name: &str) -> String {
    format!("{}.mount", escape_path(&work_dir(name)))
}

pub fn mount_path(name: &str) -> String {
    format!("/etc/systemd/system/{}", mount_unit(name))
}

pub struct GithubRunnerModule {
    cfg: GithubRunnerSection,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
    /// `[docker]`, whose keys v2 folds into the daemon.json it owns.
    docker: Option<crate::config::schema::DockerSection>,
    /// `[ci_resources]` is enabled: the unit runs in `ci.slice`.
    in_ci_slice: bool,
    /// `[ci_resources] cpu_weight` for docker-rootless slot users (else 100).
    ci_cpu_weight: u32,
    /// The host's engine: picks v2's default `sandbox_runtime` and
    /// what `docker = "rootless"` runs.
    engine: crate::config::Engine,
}

impl GithubRunnerModule {
    pub fn new(cfg: GithubRunnerSection) -> Self {
        Self {
            cfg,
            docker_distro: false,
            docker: None,
            in_ci_slice: false,
            ci_cpu_weight: 100,
            engine: crate::config::Engine::Docker,
        }
    }

    pub fn engine(mut self, engine: crate::config::Engine) -> Self {
        self.engine = engine;
        self
    }

    /// The rootless engine in each runner's unit: `podman`, or `rootless`
    /// (the host's engine).
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

    pub fn docker(mut self, docker: Option<crate::config::schema::DockerSection>) -> Self {
        self.docker = docker;
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

    fn version(&self) -> &str {
        self.cfg.version.as_deref().unwrap_or(DEFAULT_VERSION)
    }

    /// `(x64, arm64)` hashes. An operator override pins one hash for the
    /// host's architecture, so both arms carry it.
    fn hashes(&self) -> (&str, &str) {
        match &self.cfg.sha256 {
            Some(s) => (s, s),
            None => (DEFAULT_SHA256_X64, DEFAULT_SHA256_ARM64),
        }
    }

    fn ensure_tools() -> ManagedCommand {
        ManagedCommand::new(
            "curl for the runner download",
            "command -v curl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1",
            apt_install(&["curl", "ca-certificates", "coreutils"]),
        )
    }

    const ACCOUNT: Account<'static> = Account {
        module: "github_runner",
        user: USER,
        home: HOME,
        root: ROOT,
        leftover: "runner trees",
    };

    fn docker_group() -> ManagedCommand {
        ManagedCommand::new(
            "github-runner in the docker group (jobs are root-equivalent on this host)",
            format!(
                "case \" $(id -nG {USER} 2>/dev/null) \" in *' docker '*) true ;; *) false ;; esac"
            ),
            format!("usermod -aG docker {USER}\n__ghr_restart_all=1"),
        )
    }

    /// Download, verify and unpack the tarball. Root never writes into the
    /// runner dir (jobs can plant symlinks there): extraction and markers run
    /// as the runner user, and the dependency script runs from the verified,
    /// root-only temp copy. Detect ignores the version when `auto_update` is
    /// on, because the runner rewrites its own binaries.
    fn install(&self, name: &str) -> ManagedCommand {
        let dir = shell_escape(&runner_dir(name));
        let ver = shell_escape(self.version());
        let unit = shell_escape(&unit_name(name));
        let mut detect = format!("[ -x {dir}/bin/Runner.Listener ] && [ -f {dir}/.anvil-managed ]");
        if !self.cfg.auto_update {
            detect.push_str(&format!(" && [ \"$(cat {dir}/.anvil-managed)\" = {ver} ]"));
        }
        let url = format!(
            "\"https://github.com/actions/runner/releases/download/v\"{ver}\"/actions-runner-linux-${{__ra}}-\"{ver}\".tar.gz\""
        );
        let download = Download {
            module: "github_runner",
            arch_names: ("x64", "arm64"),
            sha256: self.hashes(),
            url: &url,
            file: "runner.tgz",
            what: "runner tarball",
        }
        .script();
        let converge = format!(
            "{download}\
             if ! {{ {deps}; }}; then\n\
             \x20 mkdir \"$__tmp/deps\"\n\
             \x20 tar -xzf \"$__tmp/runner.tgz\" -C \"$__tmp/deps\" --wildcards '*bin/installdependencies.sh'\n\
             \x20 DEBIAN_FRONTEND=noninteractive apt-get {lock} update -qq\n\
             \x20 DEBIAN_FRONTEND=noninteractive bash \"$__tmp/deps/bin/installdependencies.sh\"\n\
             fi\n\
             systemctl stop {unit} 2>/dev/null || true\n\
             install -d -m 0750 -o {USER} -g {USER} {dir}\n\
             runuser -u {USER} -- tar -xzf - -C {dir} < \"$__tmp/runner.tgz\"\n\
             rm -rf \"$__tmp\"\n\
             printf '%s\\n' {ver} | runuser -u {USER} -- tee {dir}/.anvil-managed >/dev/null\n\
             __ghr_restart+=({unit})",
            deps = DEPS_PRESENT,
            lock = super::APT_LOCK_TIMEOUT,
        );
        ManagedCommand::new(
            format!("runner {name} installed (v{})", self.version()),
            detect,
            converge,
        )
    }

    /// What the runner was registered with; a change forces re-registration.
    pub fn registration_marker(&self, name: &str, r: &GithubRunner) -> String {
        format!(
            "url={}\nname={name}\nlabels={}\ngroup={}\ndisableupdate={}",
            r.url,
            r.labels.join(","),
            r.group,
            !self.cfg.auto_update
        )
    }

    fn register(&self, name: &str, r: &GithubRunner) -> ManagedCommand {
        let dir = shell_escape(&runner_dir(name));
        let marker = shell_escape(&self.registration_marker(name, r));
        let unit = shell_escape(&unit_name(name));
        let mut args = format!(
            "--unattended --replace --url {} --name {} --work _work",
            shell_escape(&r.url),
            shell_escape(name)
        );
        if !r.labels.is_empty() {
            args.push_str(&format!(" --labels {}", shell_escape(&r.labels.join(","))));
        }
        if !r.group.is_empty() {
            args.push_str(&format!(" --runnergroup {}", shell_escape(&r.group)));
        }
        if !self.cfg.auto_update {
            args.push_str(" --disableupdate");
        }
        ManagedCommand::new(
            format!("runner {name} registered with GitHub"),
            format!("[ -s {dir}/.runner ] && [ \"$(cat {dir}/.anvil-registration 2>/dev/null)\" = {marker} ]"),
            format!(
                "__tok={tok}\n\
                 if [ -z \"$__tok\" ]; then\n\
                 \x20 printf '{failed} github_runner: runner %s must (re-)register but its token is empty; export a registration token (see docs/04_modules.md)\\n' {name_q}\n\
                 \x20 exit 1\n\
                 fi\n\
                 systemctl stop {unit} 2>/dev/null || true\n\
                 rm -f {dir}/.runner {dir}/.credentials {dir}/.credentials_rsaparams {dir}/.anvil-registration\n\
                 (cd {dir} && ACTIONS_RUNNER_INPUT_TOKEN=\"$__tok\" runuser -u {USER} -- ./config.sh {args})\n\
                 printf '%s' {marker} | runuser -u {USER} -- tee {dir}/.anvil-registration >/dev/null\n\
                 __ghr_restart+=({unit})",
                tok = shell_escape(&r.token),
                name_q = shell_escape(name),
                failed = MARK_FAILED,
            ),
        )
    }

    fn service_active(name: &str) -> ManagedCommand {
        let unit = shell_escape(&unit_name(name));
        ManagedCommand::new(
            format!("runner {name} service active"),
            format!("systemctl is-active --quiet {unit}"),
            format!("__ghr_restart+=({unit})"),
        )
    }

    /// Created as the runner user: the shared parent is runner-writable, so
    /// root never writes there (a job could plant a symlink).
    fn home_dir(name: &str) -> ManagedCommand {
        let home = shell_escape(&runner_home(name));
        ManagedCommand::new(
            format!("runner {name} home"),
            format!("[ -d {home} ]"),
            format!(
                "runuser -u {USER} -- mkdir -m 0750 {home}\n\
                 __anvil_remember {home}"
            ),
        )
    }

    /// Mirrors upstream's `svc.sh` unit (runsvc.sh, KillMode=process, SIGTERM,
    /// 5 min stop timeout) plus hardening. Hooks and proxy live here, not in
    /// the runner's `.env`, because jobs can write the runner directory.
    pub fn unit_content(&self, name: &str) -> String {
        let dir = runner_dir(name);
        let home = runner_home(name);
        let mut env = format!(
            "Environment=HOME={home}\nEnvironment=ACTIONS_RUNNER_HOOK_JOB_STARTED={JOB_STARTED_HOOK}\n"
        );
        if self.cfg.clean_workspace {
            env.push_str(&format!(
                "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED={}\n",
                hook_path(name)
            ));
        }
        if !self.cfg.proxy.is_empty() {
            env.push_str(&format!(
                "Environment=https_proxy={p}\nEnvironment=http_proxy={p}\n",
                p = self.cfg.proxy
            ));
        }
        if self.in_ci_slice {
            env.push_str(&format!("Slice={}\n", super::ci_resources::SLICE));
        }
        let c = &self.cfg;
        env.push_str(&runner_common::cgroup_caps(
            c.cpu_quota.as_deref(),
            c.memory_max.as_deref(),
            c.tasks_max,
        ));
        env.push_str(
            "KillMode=process\n\
             KillSignal=SIGTERM\n\
             TimeoutStopSec=5min\n\
             Restart=always\n\
             RestartSec=10\n",
        );
        let rootless = self.rootless();
        let mut exec = format!("{dir}/bin/runsvc.sh");
        if let Some(engine) = rootless {
            let rt = unit_name(name).trim_end_matches(".service").to_string();
            let (run, service) = runner_common::rootless_exec(engine, &rt, &exec);
            exec = run;
            // Replaces upstream's KillMode=process with mixed (see podman_service).
            env = env.replace("KillMode=process\n", &service);
        }
        let unit = runner_common::unit(
            &format!("GitHub Actions runner {name} (anvil)"),
            USER,
            &dir,
            &exec,
            &env,
            &format!("{dir} {home}"),
            rootless.is_some(),
        );
        if self.cfg.disk_max.is_none() {
            return unit;
        }
        // GR23: never start (or run jobs) on the uncapped root filesystem.
        unit.replacen(
            "\n[Service]\n",
            &format!("RequiresMountsFor={}\n\n[Service]\n", work_dir(name)),
            1,
        )
    }

    /// GR23: the sparse ext4 image behind `_work` ([`loop_image`]).
    fn volume_image(name: &str, disk_max: &str, bytes: u64) -> ManagedCommand {
        loop_image(
            format!("runner {name} _work volume image ({disk_max})"),
            &image_path(name),
            "disk_max",
            disk_max,
            bytes,
            &format!("$(id -u {USER}):$(id -g {USER})"),
        )
    }

    fn volume_mounted(name: &str) -> ManagedCommand {
        ManagedCommand::new(
            format!("runner {name} _work volume mounted"),
            format!("mountpoint -q {}", shell_escape(&work_dir(name))),
            // The runner's RequiresMountsFor= starts the mount on restart.
            format!("__ghr_restart+=({})", shell_escape(&unit_name(name))),
        )
    }

    /// `check` has no info channel, so usage surfaces as drift past the
    /// alert threshold; apply reports it as FAILED (nothing to converge).
    fn volume_usage(name: &str, disk_max: &str) -> ManagedCommand {
        let work = shell_escape(&work_dir(name));
        ManagedCommand::new(
            format!("runner {name} _work volume under {USAGE_ALERT_PCT}% of {disk_max}"),
            format!(
                "! mountpoint -q {work} || \
                 [ \"$(df --output=pcent {work} | tail -n 1 | tr -dc 0-9)\" -lt {USAGE_ALERT_PCT} ]"
            ),
            format!(
                "printf '{failed} github_runner: %s is %s full (%s of %s used); jobs fail when it is full \
                 (the daily prune wipes the tool caches past half of disk_max)\\n' {work} \
                 \"$(df --output=pcent {work} | tail -n 1 | tr -d ' ')\" \
                 \"$(df -h --output=used {work} | tail -n 1 | tr -d ' ')\" {dm}",
                dm = shell_escape(disk_max),
                failed = MARK_FAILED,
            ),
        )
    }

    /// Loop mount of the image on `_work`, owned by the runner (mkfs set the
    /// root owner). systemd refuses a symlinked `Where=`.
    pub fn mount_content(name: &str) -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=GitHub Actions runner {name} work volume (anvil)\n\
             \n\
             [Mount]\n\
             What={img}\n\
             Where={work}\n\
             Type=ext4\n\
             Options=loop,nodev,nosuid\n",
            img = image_path(name),
            work = work_dir(name),
        )
    }

    /// Daily, as the runner user (it can only delete what jobs could):
    /// expire `_diag` logs; on capped runners, drop the tool/action caches
    /// once they pass half of `disk_max`; drop HOME caches past
    /// `home_cache_max`. Never while a job is running.
    pub fn prune_content(&self) -> String {
        let mut s = String::from(
            "#!/bin/bash\n\
             # Managed by anvil — prunes runner logs and oversized caches (GR23).\n\
             set -u\n",
        );
        let half = self.cfg.disk_max_bytes().map(|b| b / 2);
        for name in self.cfg.runners.keys() {
            let dir = runner_dir(name);
            let idle = format!("! pgrep -u {USER} -f '^{dir}/bin/Runner.Worker' >/dev/null");
            // No trailing slash: find -P never follows a symlinked _diag.
            s.push_str(&format!(
                "find '{dir}/_diag' -maxdepth 1 -type f -name '*.log' -mtime +{days} -delete 2>/dev/null || true\n",
                days = self.cfg.diag_retention_days,
            ));
            if let Some(half) = half {
                s.push_str(&format!(
                    "if [ \"$(du -sbc '{dir}/_work/_tool' '{dir}/_work/_actions' 2>/dev/null | tail -n 1 | cut -f 1)\" -gt {half} ] \
                     && {idle}; then\n\
                     \x20 rm -rf -- '{dir}/_work/_tool' '{dir}/_work/_actions'\n\
                     fi\n"
                ));
            }
            if let Some(max) = self.cfg.home_cache_max_bytes() {
                s.push_str(&runner_common::home_cache_prune(
                    &runner_home(name),
                    max,
                    &idle,
                ));
            }
        }
        s
    }

    pub fn prune_service_content() -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Prune GitHub Actions runner logs and caches (anvil)\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             User={USER}\n\
             ExecStart={PRUNE_SCRIPT}\n\
             NoNewPrivileges=yes\n\
             ProtectSystem=strict\n\
             ReadWritePaths={ROOT} {HOME}\n\
             ProtectHome=yes\n\
             PrivateTmp=yes\n"
        )
    }

    pub fn prune_timer_content() -> String {
        runner_common::prune_timer_content("GitHub Actions runner logs and caches")
    }

    /// Runs before the engine deletes the unit files: stop the timer and
    /// every work mount (stopping a mount stops its runner), so the runner
    /// tree is never removed over a live mount.
    fn rollback_first(&self) -> String {
        let mut s = format!(
            "\n# rollback github runner prune timer and work volumes\n\
             systemctl disable --now {PRUNE_TIMER_UNIT} 2>/dev/null || true\n\
             rm -f /etc/systemd/system/timers.target.wants/{PRUNE_TIMER_UNIT}\n"
        );
        for name in self.cfg.runners.keys() {
            let work = shell_escape(&work_dir(name));
            s.push_str(&format!(
                "systemctl stop {} 2>/dev/null || true\n\
                 ! mountpoint -q {work} || umount {work}\n",
                shell_escape(&mount_unit(name)),
            ));
        }
        s
    }

    /// Job-completed hook: wipe checkouts, keep the action/tool caches.
    pub fn hook_content(name: &str) -> String {
        format!(
            "#!/bin/bash\n\
             # Managed by anvil — wipes the previous job's files after each job.\n\
             set -eu\n\
             cd '{dir}/_work' || exit 0\n\
             find . -mindepth 1 -maxdepth 1 ! -name _actions ! -name _tool ! -name lost+found -exec rm -rf -- {{}} +\n\
             # GR26: the unit's private /tmp and /var/tmp outlive a job; never fail the job over it.\n\
             find /tmp /var/tmp -mindepth 1 -maxdepth 1 -user {USER} -exec rm -rf -- {{}} + 2>/dev/null || true\n",
            dir = runner_dir(name)
        )
    }

    fn rollback(name: &str, r: &GithubRunner) -> String {
        let dir = shell_escape(&runner_dir(name));
        let unit = shell_escape(&unit_name(name));
        let n = shell_escape(name);
        format!(
            "\n# rollback github runner {name}\n\
             systemctl stop {unit} 2>/dev/null || true\n\
             rm -f /etc/systemd/system/multi-user.target.wants/{unit}\n\
             systemctl daemon-reload 2>/dev/null || true\n\
             __rt={rt}\n\
             __keep=0\n\
             __unreg=0\n\
             if [ -f {dir}/.runner ]; then\n\
             \x20 if [ -z \"$__rt\" ]; then\n\
             \x20\x20 __unreg=1\n\
             \x20 elif (cd {dir} && ACTIONS_RUNNER_INPUT_TOKEN=\"$__rt\" runuser -u {USER} -- ./config.sh remove); then\n\
             \x20\x20 printf '{changed} runner %s deregistered from GitHub\\n' {n}\n\
             \x20 else\n\
             \x20\x20 __keep=1\n\
             \x20\x20 printf '{failed} runner %s could not be deregistered; kept %s for a retry with a fresh remove_token\\n' {n} {dir}\n\
             \x20 fi\n\
             fi\n\
             if [ \"$__keep\" = 0 ] && [ -f {dir}/.anvil-managed ]; then\n\
             \x20 rm -rf {dir}\n\
             \x20 printf '{changed} %s removed\\n' {dir}\n\
             fi\n\
             if [ \"$__keep\" = 0 ] && __anvil_created {home}; then\n\
             \x20 rm -rf {home}\n\
             \x20 __anvil_forget {home}\n\
             \x20 printf '{changed} %s removed\\n' {home}\n\
             fi\n\
             if __anvil_created {img}; then\n\
             \x20 rm -f {img}\n\
             \x20 __anvil_forget {img}\n\
             \x20 rmdir {img_dir} 2>/dev/null || true\n\
             \x20 printf '{changed} %s removed\\n' {img}\n\
             fi\n\
             # GR16: GitHub deletes a runner offline for 14 days, so this is not a failure.\n\
             if [ \"$__unreg\" = 1 ]; then\n\
             \x20 printf '{ok} github_runner %s: removed from this host, but still registered on GitHub (no remove_token). \
             It shows as Offline and GitHub deletes it after 14 days; remove it sooner under Settings → Actions → Runners.\\n' {n}\n\
             fi\n",
            rt = shell_escape(&r.remove_token),
            home = shell_escape(&runner_home(name)),
            img = shell_escape(&image_path(name)),
            img_dir = shell_escape(IMAGE_DIR),
            ok = MARK_OK,
            changed = MARK_CHANGED,
            failed = MARK_FAILED,
        )
    }
}

/// GR23: a sparse ext4 image, created once. Built under a temp name so a
/// failed `mkfs` never leaves a "converged" image; a size change is
/// reported, never applied (resizing could lose data). `root_owner` is a
/// bash word for mkfs's `root_owner=` (`uid:gid`).
pub(super) fn loop_image(
    describe: String,
    img: &str,
    field: &str,
    size: &str,
    bytes: u64,
    root_owner: &str,
) -> ManagedCommand {
    let img = shell_escape(img);
    ManagedCommand::new(
        describe,
        format!("[ -f {img} ] && [ \"$(stat -c %s {img})\" = {bytes} ]"),
        format!(
            "if [ -e {img} ]; then\n\
             \x20 printf '{failed} github_runner: %s is %s bytes but {field} = %s wants {bytes}; \
             anvil never resizes a volume (stop the runner, delete the image, re-apply)\\n' \
             {img} \"$(stat -c %s {img})\" {dm}\n\
             else\n\
             \x20 install -d -m 0700 {dir}\n\
             \x20 rm -f {img}.tmp\n\
             \x20 truncate -s {bytes} {img}.tmp\n\
             \x20 mkfs.ext4 -q -F -m 0 -E root_owner=\"{root_owner}\" {img}.tmp\n\
             \x20 chmod 0600 {img}.tmp\n\
             \x20 mv {img}.tmp {img}\n\
             \x20 __anvil_remember {img}\n\
             fi",
            dir = shell_escape(IMAGE_DIR),
            dm = shell_escape(size),
            failed = MARK_FAILED,
        ),
    )
}

impl Module for GithubRunnerModule {
    fn id(&self) -> &'static str {
        "github_runner"
    }

    fn declaration(&self) -> Declaration {
        if self.cfg.ephemeral() {
            return super::github_runner_ephemeral::Ephemeral {
                cfg: &self.cfg,
                docker_distro: self.docker_distro,
                docker: self.docker.as_ref(),
                in_ci_slice: self.in_ci_slice,
                ci_cpu_weight: self.ci_cpu_weight,
                engine: self.engine,
            }
            .declaration();
        }
        let mut decl = Declaration::new("github_runner")
            .command(Self::ensure_tools())
            .command(Self::ACCOUNT.ensure());
        for r in self.cfg.runners.values() {
            decl = decl.secret(&r.token).secret(&r.remove_token);
        }
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
            if engine == Engine::Podman {
                decl = decl.file(ManagedFile::new(
                    REGISTRIES_CONF,
                    REGISTRIES_CONTENT,
                    "0644",
                    "root:root",
                ));
            }
            for c in runner_common::rootless(engine, USER, "__ghr_restart_all=1") {
                decl = decl.command(c);
            }
        }
        for name in self.cfg.runners.keys() {
            decl = decl.command(self.install(name));
        }
        if let (Some(dm), Some(bytes)) = (&self.cfg.disk_max, self.cfg.disk_max_bytes()) {
            for name in self.cfg.runners.keys() {
                decl = decl
                    .command(Self::volume_image(name, dm, bytes))
                    .command(Self::volume_mounted(name))
                    .command(Self::volume_usage(name, dm))
                    .file(ManagedFile::new(
                        mount_path(name),
                        Self::mount_content(name),
                        "0644",
                        "root:root",
                    ));
            }
        }
        for (name, r) in &self.cfg.runners {
            decl = decl
                .command(Self::home_dir(name))
                .command(self.register(name, r))
                .command(Self::service_active(name))
                .file(runner_common::unit_file(
                    &unit_path(name),
                    self.unit_content(name),
                    USER,
                ));
            if self.cfg.clean_workspace {
                decl = decl.file(ManagedFile::new(
                    hook_path(name),
                    Self::hook_content(name),
                    "0755",
                    "root:root",
                ));
            }
            decl = decl.rollback_script(Self::rollback(name, r));
        }
        decl = decl
            .rollback_first(self.rollback_first())
            .rollback_script(runner_common::rootless_rollback(USER))
            .rollback_script(Self::ACCOUNT.rollback())
            .file(ManagedFile::new(
                PRUNE_SCRIPT,
                self.prune_content(),
                "0755",
                "root:root",
            ))
            .file(ManagedFile::new(
                PRUNE_SERVICE,
                Self::prune_service_content(),
                "0644",
                "root:root",
            ))
            .file(ManagedFile::new(
                JOB_STARTED_HOOK,
                JOB_STARTED_CONTENT,
                "0755",
                "root:root",
            ))
            .file(ManagedFile::new(
                PRUNE_TIMER,
                Self::prune_timer_content(),
                "0644",
                "root:root",
            ));
        decl = decl.file(ManagedFile::new(
            NEEDRESTART_CONF,
            "# Managed by anvil — never restart runners mid-job\n\
             $nrconf{override_rc}{qr(^anvil-github-runner-.+\\.service$)} = 0;\n",
            "0644",
            "root:root",
        ));

        let units: Vec<String> = self
            .cfg
            .runners
            .keys()
            .map(|n| shell_escape(&unit_name(n)))
            .collect();
        let entries: Vec<String> = self
            .cfg
            .runners
            .keys()
            // A unit rollback already deleted needs no runsvc.sh (and no restart).
            .map(|n| {
                format!(
                    "{{ [ ! -e {} ] || [ -x {}/bin/runsvc.sh ]; }}",
                    shell_escape(&unit_path(n)),
                    shell_escape(&runner_dir(n))
                )
            })
            .collect();
        // GR30: restart a runner only when its own unit, hook, mount or
        // registration changed; shared files (prune, needrestart) restart none.
        let restarts: String = self
            .cfg
            .runners
            .keys()
            .map(|n| {
                let u = shell_escape(&unit_name(n));
                format!(
                    "if [ \"${{__ghr_restart_all:-0}}\" = 1 ] || __ghr_mine {u} {} {} {}; \
                     then systemctl restart {u}; fi; ",
                    shell_escape(&unit_path(n)),
                    shell_escape(&hook_path(n)),
                    shell_escape(&mount_path(n)),
                )
            })
            .collect();
        decl.guarded_reload(ReloadGuard {
            describe: "github runner services".into(),
            validate: entries.join(" && "),
            reload: format!(
                "systemctl daemon-reload; systemctl enable {u} >/dev/null 2>&1 || true; \
                 {MINE_FN}{restarts}\
                 [ ! -e {timer_path} ] || systemctl enable --now {PRUNE_TIMER_UNIT} >/dev/null 2>&1",
                u = units.join(" "),
                timer_path = shell_escape(PRUNE_TIMER),
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn runner(url: &str) -> GithubRunner {
        GithubRunner {
            url: url.into(),
            token: "REGTOKEN-s3cret".into(),
            remove_token: "RMTOKEN-s3cret".into(),
            labels: vec!["anvil".into(), "debian".into()],
            group: "private-ci".into(),
        }
    }

    fn module(mutate: impl FnOnce(&mut GithubRunnerSection)) -> GithubRunnerModule {
        let mut cfg = GithubRunnerSection {
            auto_update: true,
            docker: "none".into(),
            clean_workspace: true,
            proxy: String::new(),
            version: None,
            sha256: None,
            cpu_quota: None,
            memory_max: None,
            tasks_max: None,
            disk_max: None,
            home_cache_max: None,
            diag_retention_days: 14,
            runners: BTreeMap::from([("build-1".to_string(), runner("https://github.com/acme"))]),
            mode: "persistent".into(),
            app_id: None,
            installation_id: None,
            app_key: None,
            runner_group_id: None,
            capacity: None,
            sandbox_cpus: None,
            sandbox_memory: None,
            sandbox_pids: None,
            sandbox_disk: None,
            sandbox_runtime: None,
            sandbox_packages: Vec::new(),
            order_override: Default::default(),
        };
        mutate(&mut cfg);
        GithubRunnerModule::new(cfg)
    }

    #[test]
    fn download_is_pinned_and_checksum_verified_before_extract() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains(
            "releases/download/v\"'2.338.2'\"/actions-runner-linux-${__ra}-\"'2.338.2'\".tar.gz"
        ));
        assert!(apply.contains(DEFAULT_SHA256_X64) && apply.contains(DEFAULT_SHA256_ARM64));
        let check = apply.find("sha256sum -c --status").unwrap();
        let extract = apply.find("tar -xzf").unwrap();
        assert!(
            check < extract,
            "checksum must be verified before extraction"
        );
        assert!(
            !apply.contains("| sh\n") && !apply.contains("| bash"),
            "no curl | sh"
        );
    }

    #[test]
    fn root_never_writes_into_the_job_writable_runner_dir() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(
            !apply.contains("> '/opt/github-runner"),
            "no root redirect into the runner dir"
        );
        assert!(!apply.contains("chown -R"));
        assert!(apply.contains("runuser -u github-runner -- tar -xzf - -C '/opt/github-runner/build-1' < \"$__tmp/runner.tgz\""));
        assert!(apply.contains(
            "runuser -u github-runner -- tee '/opt/github-runner/build-1'/.anvil-managed"
        ));
        assert!(apply.contains(
            "runuser -u github-runner -- tee '/opt/github-runner/build-1'/.anvil-registration"
        ));
        // Dependencies come from the verified temp copy, never the runner dir.
        assert!(apply.contains("bash \"$__tmp/deps/bin/installdependencies.sh\""));
        assert!(!apply.contains("'/opt/github-runner/build-1'/bin/installdependencies.sh"));
        let verify = apply.find("sha256sum -c --status").unwrap();
        let deps = apply.find("installdependencies.sh").unwrap();
        assert!(verify < deps);
    }

    #[test]
    fn dependency_script_runs_unless_all_five_libraries_are_present() {
        let apply = module(|_| {}).declaration().render_apply();
        let guard = apply
            .find(&format!("if ! {{ {DEPS_PRESENT}; }}; then"))
            .unwrap();
        assert!(
            guard
                < apply
                    .find("bash \"$__tmp/deps/bin/installdependencies.sh\"")
                    .unwrap()
        );
        for lib in [
            "libkrb5-3",
            "zlib1g",
            "libicuuc.so.*",
            "libssl.so.*",
            "liblttng-ust.so.*",
        ] {
            assert!(DEPS_PRESENT.contains(lib), "detect misses {lib}");
        }
    }

    #[test]
    fn version_override_uses_the_given_hash() {
        let sha = "a".repeat(64);
        let apply = module(|c| {
            c.version = Some("2.400.0".into());
            c.sha256 = Some(sha.clone());
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("'2.400.0'"));
        assert!(apply.contains(&format!("__sha='{sha}'")));
        assert!(!apply.contains(DEFAULT_SHA256_X64));
    }

    #[test]
    fn token_goes_through_env_never_argv_or_static_content() {
        let m = module(|_| {});
        let d = m.declaration();
        let apply = d.render_apply();
        assert!(apply.contains("__tok='REGTOKEN-s3cret'"));
        assert!(apply.contains(
            "ACTIONS_RUNNER_INPUT_TOKEN=\"$__tok\" runuser -u github-runner -- ./config.sh"
        ));
        assert!(!apply.contains("--token"));
        for f in &d.files {
            let c = f.static_content().unwrap_or_default();
            assert!(!c.contains("s3cret"), "{} leaks a token", f.path);
        }
        assert!(
            !d.render_probe().contains("s3cret"),
            "probe must not carry tokens"
        );
    }

    #[test]
    fn registration_args_are_escaped_and_complete() {
        let apply = module(|c| c.auto_update = false)
            .declaration()
            .render_apply();
        assert!(apply.contains(
            "./config.sh --unattended --replace --url 'https://github.com/acme' --name 'build-1' \
             --work _work --labels 'anvil,debian' --runnergroup 'private-ci' --disableupdate"
        ));
    }

    #[test]
    fn empty_token_fails_loudly_instead_of_skipping() {
        let apply = module(|c| c.runners.get_mut("build-1").unwrap().token.clear())
            .declaration()
            .render_apply();
        assert!(apply.contains("__tok=''"));
        assert!(apply.contains("if [ -z \"$__tok\" ]; then"));
        assert!(apply.contains("FAILED: github_runner: runner %s must (re-)register"));
    }

    #[test]
    fn registration_marker_tracks_every_registration_input() {
        let m = module(|_| {});
        let r = runner("https://github.com/acme");
        let base = m.registration_marker("build-1", &r);
        let mut r2 = r.clone();
        r2.labels.push("x".into());
        assert_ne!(base, m.registration_marker("build-1", &r2));
        let mut r3 = r.clone();
        r3.group = "other".into();
        assert_ne!(base, m.registration_marker("build-1", &r3));
        assert_ne!(
            base,
            module(|c| c.auto_update = false).registration_marker("build-1", &r)
        );
        // Tokens rotate hourly; they must not trigger re-registration.
        let mut r4 = r.clone();
        r4.token = "new".into();
        assert_eq!(base, m.registration_marker("build-1", &r4));
    }

    #[test]
    fn detect_ignores_version_only_with_auto_update() {
        let auto = module(|_| {}).install("build-1").detect;
        assert!(!auto.contains("$(cat"));
        let pinned = module(|c| c.auto_update = false).install("build-1").detect;
        assert!(
            pinned.contains("\"$(cat '/opt/github-runner/build-1'/.anvil-managed)\" = '2.338.2'")
        );
    }

    #[test]
    fn unit_is_hardened_and_runs_as_the_runner_user() {
        let unit = module(|_| {}).unit_content("build-1");
        for line in [
            "User=github-runner",
            "ExecStart=/opt/github-runner/build-1/bin/runsvc.sh",
            "KillMode=process",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "\nEnvironment=HOME=/var/lib/github-runner/build-1\n",
            "\nReadWritePaths=/opt/github-runner/build-1 /var/lib/github-runner/build-1\n",
            "PrivateTmp=yes",
            "\nPrivateDevices=yes\n",
            "\nCapabilityBoundingSet=\n",
            "RestrictSUIDSGID=yes",
            "Environment=ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/libexec/anvil/github-runner-clean-build-1.sh",
        ] {
            assert!(unit.contains(line), "unit missing {line}");
        }
        assert!(!unit.contains("proxy"));
        for key in ["CPUQuota=", "MemoryMax=", "TasksMax="] {
            assert!(!unit.contains(key), "no cap unless configured: {key}");
        }
        let capped = module(|c| {
            c.cpu_quota = Some("1200%".into());
            c.memory_max = Some("16G".into());
            c.tasks_max = Some(4096);
        })
        .unit_content("build-1");
        let svc = capped.split("[Install]").next().unwrap();
        for line in [
            "\nCPUQuota=1200%\n",
            "\nMemoryMax=16G\n",
            "\nTasksMax=4096\n",
        ] {
            assert!(svc.contains(line), "[Service] missing {line:?}:\n{capped}");
        }
        let unit = module(|c| {
            c.clean_workspace = false;
            c.proxy = "http://proxy:3128".into();
        })
        .unit_content("build-1");
        assert!(!unit.contains("HOOK_JOB_COMPLETED"));
        assert!(unit.contains("Environment=https_proxy=http://proxy:3128"));
    }

    #[test]
    fn job_started_hook_gives_jobs_an_exec_able_tmpdir() {
        // GR29: set whatever clean_workspace says.
        for clean in [true, false] {
            let m = module(|c| c.clean_workspace = clean);
            assert!(m.unit_content("build-1").contains(
                "\nEnvironment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/anvil/github-runner-job-started.sh\n"
            ));
            let d = m.declaration();
            let f = d.files.iter().find(|f| f.path == JOB_STARTED_HOOK).unwrap();
            assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0755", "root:root"));
            assert_eq!(f.static_content(), Some(JOB_STARTED_CONTENT));
        }
        let d = std::env::temp_dir().join(format!("anvil-gr29-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let env = d.join("env");
        std::fs::write(&env, "A=1\n").unwrap();
        let temp = d.join("_work/_temp");
        let out = std::process::Command::new("bash")
            .args(["-c", JOB_STARTED_CONTENT])
            .env("RUNNER_TEMP", &temp)
            .env("GITHUB_ENV", &env)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(
            std::fs::read_to_string(&env).unwrap(),
            format!("A=1\nTMPDIR={}\n", temp.display())
        );
        // Every bind source actions/runner gives a container job exists
        // before "Initialize containers" (Podman refuses missing ones).
        for dir in [
            "_work/_actions",
            "_work/_tool",
            "_work/_temp/_github_home",
            "_work/_temp/_github_workflow",
        ] {
            assert!(d.join(dir).is_dir(), "{dir}");
        }
        std::fs::remove_dir_all(&d).unwrap();
        // The runner execs it per job: a content change restarts nobody.
        let m = module(|_| {});
        assert!(restarted(&m, &format!("__reverts=({JOB_STARTED_HOOK})")).is_empty());
    }

    #[test]
    fn each_runner_has_its_own_home() {
        // GR31: a job on one runner can't write the other's toolchains.
        let m = module(|c| {
            c.runners
                .insert("build-2".into(), runner("https://github.com/acme"));
        });
        let a = m.unit_content("build-1");
        assert!(a.contains(
            "\nReadWritePaths=/opt/github-runner/build-1 /var/lib/github-runner/build-1\n"
        ));
        assert!(!a.contains("build-2"));
        let b = m.unit_content("build-2");
        assert!(b.contains("\nEnvironment=HOME=/var/lib/github-runner/build-2\n"));
        assert!(b.contains(
            "\nReadWritePaths=/opt/github-runner/build-2 /var/lib/github-runner/build-2\n"
        ));
        assert!(!b.contains("build-1"));
        let home = GithubRunnerModule::home_dir("build-2");
        assert_eq!(home.detect, "[ -d '/var/lib/github-runner/build-2' ]");
        assert_eq!(
            home.converge,
            "runuser -u github-runner -- mkdir -m 0750 '/var/lib/github-runner/build-2'\n\
             __anvil_remember '/var/lib/github-runner/build-2'"
        );
        let apply = m.declaration().render_apply();
        let mkdir = apply
            .find("mkdir -m 0750 '/var/lib/github-runner/build-2'")
            .unwrap();
        assert!(apply.find("useradd --system").unwrap() < mkdir);
        assert!(mkdir < apply.find("# guarded reload").unwrap());
        // Rollback removes a home only if anvil created it and kept no runner.
        let rb = m.declaration().render_rollback();
        let gate = rb
            .find("if [ \"$__keep\" = 0 ] && __anvil_created '/var/lib/github-runner/build-2'; then\n  rm -rf '/var/lib/github-runner/build-2'\n  __anvil_forget '/var/lib/github-runner/build-2'\n")
            .unwrap();
        assert!(rb.find("__keep=1").unwrap() < gate);
    }

    #[test]
    fn docker_group_is_opt_in() {
        let none = module(|_| {}).declaration().render_apply();
        assert!(!none.contains("usermod -aG docker"));
        let group = module(|c| c.docker = "group".into())
            .declaration()
            .render_apply();
        assert!(group.contains("usermod -aG docker github-runner"));
        assert!(group.contains("root-equivalent"));
        assert!(module(|_| {}).declaration().installs.is_empty());
        let installs = module(|c| c.docker = "group".into()).declaration().installs;
        assert_eq!(installs, ["Docker"]);
    }

    #[test]
    fn docker_podman_gives_each_runner_its_own_rootless_podman() {
        let m = module(|c| c.docker = "podman".into());
        let d = m.declaration();
        assert_eq!(d.installs, ["Podman"]);
        let apply = d.render_apply();
        assert!(
            apply.contains("'podman' 'iptables' 'aardvark-dns'")
                && !apply.contains("usermod -aG docker")
        );
        assert!(apply.contains("usermod --add-subuids") && apply.contains("\n__ghr_restart_all=1"));
        let reg = d.files.iter().find(|f| f.path == REGISTRIES_CONF).unwrap();
        assert_eq!(reg.static_content(), Some(REGISTRIES_CONTENT));
        assert!(REGISTRIES_CONTENT.contains("unqualified-search-registries = [\"docker.io\"]\n"));
        let u = m.unit_content("b");
        for want in [
            "\nExecStart=/bin/bash -c 'env -u CONTAINER_HOST podman --cgroup-manager=cgroupfs \
             --runroot /run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/containers \
             --tmpdir /run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/libpod system service \
             --time=0 unix:///run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/podman.sock & ",
            "\nEnvironment=XDG_RUNTIME_DIR=/run/user/ANVIL_RUNNER_UID\n",
            // Round 5: the runner's `-v /var/run/docker.sock:…` gets this socket.
            "\nBindPaths=-/run/user/ANVIL_RUNNER_UID/anvil-github-runner-b:/run/podman\n",
            "exec /opt/github-runner/b/bin/runsvc.sh'\n",
            "\nExecStartPre=/bin/mkdir -p -m 0700 /run/user/ANVIL_RUNNER_UID/anvil-github-runner-b\n",
            "\nEnvironment=CONTAINER_HOST=unix:///run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/podman.sock\n",
            "\nKillMode=mixed\nDelegate=yes\nKillSignal=SIGTERM\n",
        ] {
            assert!(u.contains(want), "missing {want:?}:\n{u}");
        }
        assert!(!u.contains("KillMode=process") && !u.contains("NoNewPrivileges"));
        let none = module(|_| {});
        assert!(none
            .unit_content("b")
            .contains("KillMode=process\nKillSignal"));
        // Only a podman unit takes its cgroup over.
        assert!(!none.unit_content("b").contains("Delegate="));
        assert!(!none
            .declaration()
            .files
            .iter()
            .any(|f| f.path == REGISTRIES_CONF));
        let rb = d.render_rollback();
        let stop = rb.find("systemctl stop 'anvil-github-runner-").unwrap();
        let subids = rb.find("sed -n 's/^subids:github-runner://p'").unwrap();
        let user = rb
            .find("if __anvil_created user:github-runner; then")
            .unwrap();
        let linger = rb.find("loginctl disable-linger 'github-runner'").unwrap();
        assert!(stop < linger && linger < subids && subids < user);
        for s in [d.render_probe(), apply, rb] {
            let out = std::process::Command::new("bash")
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

    #[test]
    fn docker_rootless_runs_the_hosts_engine_rootless_in_each_unit() {
        let m = module(|c| c.docker = "rootless".into());
        let d = m.declaration();
        assert_eq!(d.installs, ["Docker (rootless)"]);
        let apply = d.render_apply();
        assert!(apply.contains("'docker-ce-rootless-extras' 'uidmap' 'slirp4netns'"));
        assert!(
            apply.contains("'docker-ce' 'docker-ce-cli'") && !apply.contains("usermod -aG docker")
        );
        assert!(apply.contains("usermod --add-subuids") && apply.contains("\n__ghr_restart_all=1"));
        assert!(!d.files.iter().any(|f| f.path == REGISTRIES_CONF));
        let u = m.unit_content("b");
        for want in [
            "\nExecStart=/bin/bash -c '/usr/bin/dockerd-rootless.sh --exec-opt native.cgroupdriver=cgroupfs \
             -H unix:///run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/docker.sock & ",
            "exec /opt/github-runner/b/bin/runsvc.sh'\n",
            // Its own runtime dir: runners sharing the user never share rootlesskit state.
            "\nEnvironment=XDG_RUNTIME_DIR=/run/user/ANVIL_RUNNER_UID/anvil-github-runner-b\n",
            "\nEnvironment=DOCKER_HOST=unix:///run/user/ANVIL_RUNNER_UID/anvil-github-runner-b/docker.sock\n",
            "\nEnvironment=HOME=/var/lib/github-runner/b\n",
            "\nKillMode=mixed\nDelegate=yes\nKillSignal=SIGTERM\n",
        ] {
            assert!(u.contains(want), "missing {want:?}:\n{u}");
        }
        assert!(!u.contains("NoNewPrivileges") && !u.contains("podman"));
        // On a Podman host it is rootless Podman, exactly as docker = "podman".
        let p = module(|c| c.docker = "rootless".into()).engine(Engine::Podman);
        let podman = module(|c| c.docker = "podman".into());
        assert_eq!(p.unit_content("b"), podman.unit_content("b"));
        assert_eq!(
            p.declaration().render_apply(),
            podman.declaration().render_apply()
        );
        for s in [d.render_probe(), apply, d.render_rollback()] {
            let out = std::process::Command::new("bash")
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

    #[test]
    fn hook_keeps_caches_and_files_are_root_owned() {
        let hook = GithubRunnerModule::hook_content("build-1");
        assert!(hook.contains("cd '/opt/github-runner/build-1/_work'"));
        assert!(hook.contains("! -name _actions ! -name _tool"));
        let tmp_line = hook
            .lines()
            .find(|l| l.starts_with("find /tmp /var/tmp "))
            .unwrap();
        assert_eq!(
            tmp_line,
            "find /tmp /var/tmp -mindepth 1 -maxdepth 1 -user github-runner -exec rm -rf -- {} + 2>/dev/null || true"
        );
        assert!(hook.find("_work").unwrap() < hook.find(tmp_line).unwrap());
        // Run it against a scratch dir as this user: the dir's own entries go,
        // a symlinked dir's target survives, and a missing path does not fail.
        let d = std::env::temp_dir().join(format!("anvil-gr26-{}", std::process::id()));
        let (work, outside) = (d.join("t"), d.join("outside"));
        std::fs::create_dir_all(work.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(work.join("sub/f"), "x").unwrap();
        std::fs::write(work.join("leftover-1"), "x").unwrap();
        std::fs::write(outside.join("keep"), "x").unwrap();
        std::os::unix::fs::symlink(&outside, work.join("link")).unwrap();
        let script = tmp_line
            .replace(
                "/tmp /var/tmp",
                &format!("{} {}/missing", work.display(), d.display()),
            )
            .replace("-user github-runner", "-user \"$(id -un)\"");
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
        assert!(outside.join("keep").exists());
        std::fs::remove_dir_all(&d).unwrap();
        let d = module(|_| {}).declaration();
        for f in &d.files {
            assert_eq!(f.owner, "root:root", "{} must not be job-writable", f.path);
        }
    }

    #[test]
    fn validate_passes_once_rollback_deleted_the_unit() {
        let d = module(|_| {}).declaration();
        let g = d.reload.unwrap();
        // Rollback deletes the unit and the tree first; the guard must pass then.
        assert!(g.validate.contains(
            "{ [ ! -e '/etc/systemd/system/anvil-github-runner-build-1.service' ] || \
             [ -x '/opt/github-runner/build-1'/bin/runsvc.sh ]; }"
        ));
    }

    /// Runs the reload against a stub `systemctl` after `setup` and returns
    /// the units it restarted, in order.
    fn restarted(m: &GithubRunnerModule, setup: &str) -> Vec<String> {
        let reload = m.declaration().reload.unwrap().reload;
        let script = format!(
            "systemctl() {{ [ \"$1\" != restart ] || printf '%s\\n' \"$2\"; }}\n{setup}\n{reload}"
        );
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn a_runner_restarts_only_for_its_own_changes() {
        // GR30: adding runner B must not kill a job on runner A.
        let m = module(|c| {
            c.disk_max = Some("20G".into());
            c.runners
                .insert("build-2".into(), runner("https://github.com/acme"));
        });
        let (a, b) = (unit_name("build-1"), unit_name("build-2"));
        // Rollback (and a no-op apply) define none of the arrays.
        assert!(restarted(&m, "").is_empty());
        let added_b = format!(
            "__creates=({} {} {} {PRUNE_SCRIPT})\n__ghr_restart=({b})",
            unit_path("build-2"),
            hook_path("build-2"),
            shell_escape(&mount_path("build-2")),
        );
        assert_eq!(restarted(&m, &added_b), [b.as_str()]);
        let shared = format!("__reverts=({PRUNE_SCRIPT} {PRUNE_SERVICE} {NEEDRESTART_CONF})\n__creates=({PRUNE_TIMER})");
        assert!(restarted(&m, &shared).is_empty());
        for own in [
            unit_path("build-1"),
            hook_path("build-1"),
            mount_path("build-1"),
        ] {
            let own = shell_escape(&own);
            assert_eq!(restarted(&m, &format!("__reverts=({own})")), [a.as_str()]);
        }
        assert_eq!(restarted(&m, &format!("__ghr_restart=({a})")), [a.as_str()]);
        assert_eq!(restarted(&m, "__ghr_restart_all=1"), [a, b]);
    }

    #[test]
    fn per_runner_commands_flag_only_their_own_runner() {
        let m = module(|c| {
            c.disk_max = Some("20G".into());
            c.docker = "group".into();
        });
        let flag = format!("__ghr_restart+=('{}')", unit_name("build-1"));
        let r = runner("https://github.com/acme");
        for c in [
            m.install("build-1"),
            m.register("build-1", &r),
            GithubRunnerModule::service_active("build-1"),
            GithubRunnerModule::volume_mounted("build-1"),
        ] {
            assert!(c.converge.ends_with(&flag), "{}", c.describe);
        }
        assert!(GithubRunnerModule::docker_group()
            .converge
            .ends_with("__ghr_restart_all=1"));
    }

    #[test]
    fn rollback_deregisters_only_with_a_token_and_removes_only_marked_trees() {
        let rb = module(|_| {}).declaration().render_rollback();
        assert!(rb.contains("systemctl stop 'anvil-github-runner-build-1.service'"));
        assert!(rb.contains("__rt='RMTOKEN-s3cret'"));
        assert!(rb.contains(
            "ACTIONS_RUNNER_INPUT_TOKEN=\"$__rt\" runuser -u github-runner -- ./config.sh remove"
        ));
        // GR16: no remove_token is a warning, not a failure, and comes after
        // the local removal.
        let rb = module(|c| c.runners.get_mut("build-1").unwrap().remove_token.clear())
            .declaration()
            .render_rollback();
        let rm = rb.find("rm -rf '/opt/github-runner/build-1'").unwrap();
        let unreg = rb
            .find("if [ -z \"$__rt\" ]; then\n   __unreg=1\n")
            .unwrap();
        let warn = rb
            .find(
                "if [ \"$__unreg\" = 1 ]; then\n  printf 'OK: github_runner %s: removed from this \
                 host, but still registered on GitHub (no remove_token). It shows as Offline and \
                 GitHub deletes it after 14 days; remove it sooner under Settings → Actions → \
                 Runners.\\n' 'build-1'",
            )
            .unwrap();
        assert!(unreg < rm && rm < warn);
        assert!(!rb.contains("FAILED: runner %s left"));
        let guard = rb
            .find("[ -f '/opt/github-runner/build-1'/.anvil-managed ]")
            .unwrap();
        let rm = rb.find("rm -rf '/opt/github-runner/build-1'").unwrap();
        assert!(guard < rm);
        // Engine-owned files (unit, hook, needrestart) are undone by the engine.
        assert!(rb.contains("/etc/systemd/system/anvil-github-runner-build-1.service"));
    }

    #[test]
    fn user_is_recorded_only_when_anvil_creates_it() {
        let d = module(|_| {}).declaration();
        let apply = d.render_apply();
        assert!(apply.contains(
            "|| { useradd --system --gid github-runner --home-dir /var/lib/github-runner \
             --shell /usr/sbin/nologin github-runner; __anvil_remember user:github-runner; }"
        ));
        assert!(apply.contains(
            "|| { groupadd --system github-runner; __anvil_remember group:github-runner; }"
        ));
        assert!(!d.render_probe().contains("__anvil_remember"));
    }

    #[test]
    fn rollback_removes_the_user_only_if_created_and_after_the_runners() {
        let rb = module(|c| {
            c.runners
                .insert("build-2".into(), runner("https://github.com/acme/app"));
        })
        .declaration()
        .render_rollback();
        let gate = rb
            .find("if __anvil_created user:github-runner; then")
            .unwrap();
        let empty = rb
            .find("if [ -n \"$(ls -A /opt/github-runner 2>/dev/null)\" ]")
            .unwrap();
        let userdel = rb.find("|| userdel github-runner; then").unwrap();
        let forget = rb.find("__anvil_forget user:github-runner").unwrap();
        for dir in ["build-1", "build-2"] {
            let rm = rb
                .find(&format!("rm -rf '/opt/github-runner/{dir}'"))
                .unwrap();
            assert!(rm < gate, "runner {dir} must be removed before the user");
        }
        assert!(gate < empty && empty < userdel && userdel < forget);
        assert!(userdel < rb.find("# reload with the restored config").unwrap());
        assert!(!rb.contains("userdel -r"), "never remove the home");
        assert!(!rb.contains("rm -rf /var/lib/github-runner"));
        // Group: only if anvil created it and the user is gone.
        let ggate = rb
            .find("if __anvil_created group:github-runner && ! __anvil_created user:github-runner; then")
            .unwrap();
        let keep = rb
            .find("if id -u github-runner >/dev/null 2>&1; then")
            .unwrap();
        let groupdel = rb.find("|| groupdel github-runner; then").unwrap();
        assert!(forget < ggate && ggate < keep && keep < groupdel);
        assert!(rb.contains("__anvil_forget group:github-runner"));
    }

    #[test]
    fn every_runner_gets_its_own_unit_and_hook() {
        let d = module(|c| {
            c.runners
                .insert("build-2".into(), runner("https://github.com/acme/app"));
        })
        .declaration();
        for p in [
            unit_path("build-1"),
            unit_path("build-2"),
            hook_path("build-1"),
            hook_path("build-2"),
            NEEDRESTART_CONF.to_string(),
        ] {
            assert!(d.files.iter().any(|f| f.path == p), "missing {p}");
        }
    }

    #[test]
    fn unit_joins_the_ci_slice_only_with_ci_resources() {
        let svc = |m: GithubRunnerModule| m.unit_content("build-1");
        assert!(!svc(module(|_| {})).contains("Slice="));
        let u = svc(module(|_| {}).in_ci_slice(true));
        let service = u.split("[Service]").nth(1).unwrap();
        assert!(service.contains("\nSlice=ci.slice\n"), "{u}");
    }

    fn capped() -> GithubRunnerModule {
        module(|c| c.disk_max = Some("150G".into()))
    }

    #[test]
    fn diag_logs_are_kept_14_days_by_default() {
        let c: GithubRunnerSection =
            toml::from_str("[runners.b]\nurl = \"https://github.com/acme\"").unwrap();
        assert_eq!(c.diag_retention_days, 14);
        assert_eq!(c.disk_max, None);
    }

    #[test]
    fn mount_unit_name_matches_systemd_escape_path() {
        // `systemd-escape --path /opt/github-runner/build-1/_work`
        assert_eq!(
            mount_unit("build-1"),
            "opt-github\\x2drunner-build\\x2d1-_work.mount"
        );
        assert_eq!(escape_path("/.a/b.c:d/"), "\\x2ea-b.c:d");
        assert_eq!(escape_path("/a b"), "a\\x20b");
    }

    #[test]
    fn without_disk_max_there_is_no_volume() {
        let m = module(|_| {});
        let d = m.declaration();
        assert!(!d.files.iter().any(|f| f.path.ends_with(".mount")));
        assert!(!m.unit_content("build-1").contains("RequiresMountsFor"));
        assert!(!m.prune_content().contains("_work/_tool"));
        assert!(!d.render_apply().contains("mkfs.ext4"));
    }

    #[test]
    fn disk_max_creates_the_image_once_and_never_resizes() {
        let d = capped().declaration();
        let apply = d.render_apply();
        let img = "'/var/lib/anvil-ci/github-runner-build-1.img'";
        assert!(apply.contains(&format!(
            "[ -f {img} ] && [ \"$(stat -c %s {img})\" = 161061273600 ]"
        )));
        let failed = apply.find("anvil never resizes a volume").unwrap();
        let create = apply.find("truncate -s 161061273600").unwrap();
        assert!(
            failed < create,
            "an existing image is reported, not rebuilt"
        );
        assert!(apply.contains("install -d -m 0700 '/var/lib/anvil-ci'"));
        let mkfs = apply
            .find("mkfs.ext4 -q -F -m 0 -E root_owner=\"$(id -u github-runner):$(id -g github-runner)\"")
            .unwrap();
        let mv = apply.find(&format!("mv {img}.tmp {img}")).unwrap();
        let remember = apply.find(&format!("__anvil_remember {img}")).unwrap();
        assert!(create < mkfs && mkfs < mv && mv < remember);
        assert!(apply.contains(&format!("rm -f {img}.tmp")));
        assert!(apply.contains(&format!("chmod 0600 {img}.tmp")));
    }

    #[test]
    fn capped_runner_waits_for_its_mounted_volume() {
        let m = capped();
        let unit = m.unit_content("build-1");
        let req = unit
            .find("RequiresMountsFor=/opt/github-runner/build-1/_work\n")
            .unwrap();
        assert!(req < unit.find("[Service]").unwrap());
        assert!(req > unit.find("[Unit]").unwrap());
        let mount = GithubRunnerModule::mount_content("build-1");
        for line in [
            "What=/var/lib/anvil-ci/github-runner-build-1.img\n",
            "Where=/opt/github-runner/build-1/_work\n",
            "Type=ext4\n",
            "Options=loop,nodev,nosuid\n",
        ] {
            assert!(mount.contains(line), "{line}");
        }
        let d = m.declaration();
        assert!(d.files.iter().any(|f| f.path
            == "/etc/systemd/system/opt-github\\x2drunner-build\\x2d1-_work.mount"
            && f.static_content() == Some(mount.as_str())));
        let probe = d.render_probe();
        assert!(probe.contains("if mountpoint -q '/opt/github-runner/build-1/_work'; then"));
        // Usage drifts at 90% and is read-only.
        assert!(probe.contains(
            "[ \"$(df --output=pcent '/opt/github-runner/build-1/_work' | tail -n 1 | tr -dc 0-9)\" -lt 90 ]"
        ));
        assert!(probe.contains("! mountpoint -q '/opt/github-runner/build-1/_work' ||"));
        assert!(d
            .render_apply()
            .contains("FAILED: github_runner: %s is %s full"));
    }

    #[test]
    fn job_hook_keeps_the_volume_lost_and_found() {
        assert!(GithubRunnerModule::hook_content("build-1")
            .contains("! -name _tool ! -name lost+found -exec rm -rf"));
    }

    #[test]
    fn prune_runs_as_the_runner_user_and_only_touches_diag_and_caches() {
        let p = module(|c| {
            c.diag_retention_days = 7;
            c.disk_max = Some("1T".into());
        })
        .prune_content();
        assert!(p.contains(
            "find '/opt/github-runner/build-1/_diag' -maxdepth 1 -type f -name '*.log' -mtime +7 -delete"
        ));
        // Half of 1T, and never while a job runs.
        assert!(p.contains("| cut -f 1)\" -gt 549755813888 ]"));
        let guard = p
            .find("! pgrep -u github-runner -f '^/opt/github-runner/build-1/bin/Runner.Worker'")
            .unwrap();
        let wipe = p
            .find("rm -rf -- '/opt/github-runner/build-1/_work/_tool' '/opt/github-runner/build-1/_work/_actions'")
            .unwrap();
        assert!(guard < wipe);
        // The HOME caches (default 20G), behind the same idle guard.
        let home = p
            .find("rm -rf -- '/var/lib/github-runner/build-1/.cache' '/var/lib/github-runner/build-1/.cargo'")
            .unwrap();
        assert!(p.contains("| cut -f 1)\" -gt 21474836480 ] && ! pgrep -u github-runner"));
        assert!(wipe < home);
        assert_eq!(p.matches("rm ").count(), 2);
        let svc = GithubRunnerModule::prune_service_content();
        assert!(svc.contains("User=github-runner\n"));
        assert!(svc.contains("ReadWritePaths=/opt/github-runner /var/lib/github-runner\n"));
        assert!(svc.contains("ProtectSystem=strict\n"));
        assert!(svc.contains(&format!("ExecStart={PRUNE_SCRIPT}\n")));
        assert!(GithubRunnerModule::prune_timer_content().contains("OnCalendar=daily\n"));
        let d = module(|_| {}).declaration();
        for path in [PRUNE_SCRIPT, PRUNE_SERVICE, PRUNE_TIMER] {
            assert!(d.files.iter().any(|f| f.path == path), "{path}");
        }
        let reload = d.reload.unwrap().reload;
        assert!(reload.ends_with(&format!(
            "[ ! -e '{PRUNE_TIMER}' ] || systemctl enable --now {PRUNE_TIMER_UNIT} >/dev/null 2>&1"
        )));
    }

    #[test]
    fn rollback_unmounts_before_removing_and_deletes_only_created_images() {
        let rb = capped().declaration().render_rollback();
        let timer = rb
            .find(&format!("systemctl disable --now {PRUNE_TIMER_UNIT}"))
            .unwrap();
        assert!(rb.contains(&format!(
            "rm -f /etc/systemd/system/timers.target.wants/{PRUNE_TIMER_UNIT}"
        )));
        let stop = rb
            .find("systemctl stop 'opt-github\\x2drunner-build\\x2d1-_work.mount'")
            .unwrap();
        let umount = rb
            .find("! mountpoint -q '/opt/github-runner/build-1/_work' || umount '/opt/github-runner/build-1/_work'")
            .unwrap();
        let unit_removed = rb.find("# rollback: /etc/systemd/system/").unwrap();
        let tree = rb.find("rm -rf '/opt/github-runner/build-1'").unwrap();
        assert!(timer < unit_removed && stop < umount && umount < unit_removed);
        assert!(umount < tree);
        let img = "'/var/lib/anvil-ci/github-runner-build-1.img'";
        let created = rb.find(&format!("if __anvil_created {img}; then")).unwrap();
        let rm = rb.find(&format!("rm -f {img}\n")).unwrap();
        assert!(created < rm);
        assert!(rb.contains(&format!("__anvil_forget {img}")));
        assert!(rb.contains("rmdir '/var/lib/anvil-ci' 2>/dev/null || true"));
    }
}
