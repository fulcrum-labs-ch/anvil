//! `[forgejo_runner] mode = "ephemeral"`: one job per sysbox sandbox.
//!
//! Per slot, a root minter unit registers an ephemeral runner through the
//! Forgejo API (Forgejo ≥ 15 serves it one job, then deletes it), and runs
//! `forgejo-runner one-job --wait` for it in a fresh sysbox sandbox (own
//! dockerd, no host Docker socket, root inside = unprivileged on the host).
//! The sandbox's Docker data and job workspace live on the slot's capped
//! loop volume, re-made before every job; the sandbox goes with its volumes
//! (`rm -fv`) and its runner is deleted (a 404 means Forgejo already did).
//!
//! Secrets: the API token is a `Computed` 0600 root file (never in `diff`)
//! and reaches curl on stdin (`-K -`); the one-job runner config reaches the
//! sandbox through a 0600 env file deleted right after `docker create`.
//! Sandbox engine, image base and volumes are v2's
//! ([`super::github_runner_ephemeral`]).

use crate::config::schema::{size_bytes, DockerSection, ForgejoRunnerSection};
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_CHANGED, MARK_FAILED,
};
use crate::escape::shell_escape;

use super::forgejo_runner::{
    BIN, CONFIG, PRUNE_SCRIPT, PRUNE_SERVICE, PRUNE_TIMER, PRUNE_TIMER_UNIT, UNIT, UNIT_PATH,
};
use super::github_runner::{loop_image, IMAGE_DIR, MINE_FN};
use super::github_runner_ephemeral::{
    build_image, docker_sandbox_engine, dockerfile, fnv1a, superseded_images, Ephemeral, AA_PROFILE,
};
use super::{ci_resources, docker, rootless_sandbox};

pub const TOKEN_PATH: &str = "/etc/anvil/forgejo-runner/api-token";
pub const IMAGE_CTX: &str = "/etc/anvil/forgejo-runner/image";
pub const IMAGE_REPO: &str = "anvil-forgejo-runner";
pub const MINTER: &str = "/usr/local/libexec/anvil/forgejo-runner-mint.sh";
/// Sandboxes join this network, so the firewall can tell them apart from
/// every other container (docker0) by its bridge.
pub const NETWORK: &str = "anvil-forgejo-sandbox";
pub const BRIDGE: &str = "anvil-fjsb0";
/// The persistent mode's files, retired (backed up) in ephemeral mode.
const PERSISTENT_FILES: [&str; 5] = [UNIT_PATH, PRUNE_TIMER, PRUNE_SERVICE, PRUNE_SCRIPT, CONFIG];

/// `sandbox_runtime = "docker-rootless"`: the user unit each slot
/// user's manager runs (started by the minter, never enabled).
pub const USER_UNIT: &str = "anvil-sandbox-docker.service";
pub const USER_UNIT_PATH: &str = "/etc/systemd/user/anvil-sandbox-docker.service";
/// The sandbox image as `docker save`d by root; the minter loads it into a
/// slot's fresh engine before every job.
pub const IMAGE_TAR: &str = "/var/lib/anvil-ci/forgejo-runner-sandbox.tar";
pub const IMAGE_TAR_TAG: &str = "/var/lib/anvil-ci/forgejo-runner-sandbox.tag";

/// The system user owning slot `i`'s rootless dockerd; its home is the
/// slot volume, so the engine's data-root is wiped with every job.
pub fn slot_user(i: u32) -> String {
    format!("anvil-fjr-{i}")
}

/// Slot `i`'s volume mount point (inside its root-owned home).
pub fn slot_vol(i: u32) -> String {
    rootless_sandbox::vol(&slot_user(i))
}

pub fn unit_name(i: u32) -> String {
    format!("anvil-forgejo-runner-{i}.service")
}

pub fn unit_path(i: u32) -> String {
    format!("/etc/systemd/system/{}", unit_name(i))
}

/// The sandbox container of a slot (one at a time).
pub fn container(i: u32) -> String {
    format!("anvil-forgejo-runner-{i}")
}

pub fn image_path(i: u32) -> String {
    format!("{IMAGE_DIR}/forgejo-runner-{i}.img")
}

pub fn mount_dir(i: u32) -> String {
    format!("{IMAGE_DIR}/forgejo-runner-{i}.mnt")
}

/// Ids of runners this slot registered and not yet deleted; on disk, so a
/// reboot mid-job still deletes them.
pub fn ids_path(i: u32) -> String {
    format!("{IMAGE_DIR}/forgejo-runner-{i}.ids")
}

/// Set by apply when a slot's unit changed while its sandbox existed; the
/// minter restarts the slot between jobs.
pub fn restart_flag(i: u32) -> String {
    format!("/run/{}.restart", container(i))
}

/// Runs as root inside the sandbox. The runner (and so the job) can read
/// its one-job config: that token serves this one job only.
pub const ENTRYPOINT: &str = r#"#!/bin/bash
# Managed by anvil — sandbox entrypoint: own dockerd, then exactly one Forgejo job.
set -euo pipefail
# Out of the environment before dockerd starts, so it never inherits it.
cfg=$ANVIL_RUNNER_CONFIG
unset ANVIL_RUNNER_CONFIG
chown runner:runner /home/runner/.cache
dockerd >/var/log/dockerd.log 2>&1 &
for _ in $(seq 60); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
if ! docker info >/dev/null 2>&1; then
  echo 'anvil: dockerd did not start in the sandbox' >&2
  tail -n 20 /var/log/dockerd.log >&2
  exit 1
fi
umask 077
printf '%s' "$cfg" | base64 -d >/home/runner/.runner.yml
chown runner:runner /home/runner/.runner.yml
unset cfg
cd /home/runner
exec runuser -u runner -- forgejo-runner one-job --wait -c /home/runner/.runner.yml
"#;

/// `<slot> [once|cleanup]`; the loop, backoff and restart flag are v2's.
const MINTER_SCRIPT: &str = r#"#!/bin/bash
# Managed by anvil — runs one Forgejo job per sandbox.
# The API token reaches curl on stdin, the runner config the sandbox via a
# 0600 env file; never argv. One brace group, parsed whole before it runs:
# apply rewrites this file in place while a job runs.
{
set -euo pipefail
umask 077
slot=$1
ctr=anvil-forgejo-runner-$slot
img=@IMAGE_DIR@/forgejo-runner-$slot.img
mnt=@MNT@
ids=@IMAGE_DIR@/forgejo-runner-$slot.ids

# <method> <path> [curl args]: the Forgejo API with the token from a curl config on stdin.
api() {
  printf 'header = "Authorization: token %s"\n' "$(cat @TOKEN@)" |
    curl -fsS --proto '=https' --connect-timeout 10 --max-time 60 -K - -X "$1" \
      -H 'Accept: application/json' -H 'Content-Type: application/json' "${@:3}" @API@"$2"
}

@SB_FNS@
cleanup() {
  @SB_RM@
  ! mountpoint -q "$mnt" || umount "$mnt"
  # A runner that never got a job stays registered; one that did is gone (404).
  if [ -s "$ids" ]; then
    keep=
    while read -r id; do
      case "$(api DELETE @RUNNERS@/"$id" -o /dev/null -w '%{http_code}' 2>/dev/null || true)" in
        204 | 404) ;;
        *) keep+="$id"$'\n' ;;
      esac
    done <"$ids"
    printf '%s' "$keep" >"$ids"
  fi
}

case "${2:-loop}" in
  cleanup) cleanup; exit 0 ;;
  once) ;;
  *)
    delay=10
    while :; do
      if [ -e "/run/$ctr.restart" ]; then rm -f "/run/$ctr.restart"; exit 0; fi
      # one-job exits 0 after any job, red or green (runner v13.2.1
      # poll/single.go: Run reports the result to Forgejo, Poll returns nil),
      # so only register/sandbox failures back off.
      if "$0" "$slot" once; then
        delay=10
      else
        echo "anvil: forgejo runner slot $slot: register or sandbox failed; retrying in ${delay}s" >&2
        sleep "$delay"
        delay=$(( delay * 2 > 600 ? 600 : delay * 2 ))
      fi
    done ;;
esac

cleanup
mkfs.ext4 -q -F -m 0 "$img"
install -d -m 0700 "$mnt"
mount -o loop,nodev,nosuid "$img" "$mnt"
install -d -m 0755 "$mnt/docker" "$mnt/work"
@SB_UP@
env=$(mktemp -p /run)
trap 'rm -f "$env"' EXIT
name=$(hostname -s)-$slot-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
reg=$(api POST @RUNNERS@ --data-binary "$(jq -nc --arg n "$name" '{name: $n, ephemeral: true}')")
printf '%s' "$reg" | jq -er .id >>"$ids"
# YAML is a superset of JSON: the runner reads this config as is.
printf '%s' "$reg" | jq -er --arg url @URL@ --argjson l @LABELS@ \
  '"ANVIL_RUNNER_CONFIG=" + ({log: {level: "info"}, runner: {capacity: 1, labels: $l},
    container: {docker_host: "-"},
    server: {connections: {anvil: {url: $url, uuid: .uuid, token: .token}}}} | tojson | @base64)' >"$env"
unset reg
@SB_ENV@# --init: a reaping PID 1; orphaned zombies would count against --pids-limit.
@DOCKER@ create --name "$ctr" --init --hostname "$ctr" @SANDBOX@ @CGROUP@--cpus @CPUS@ \
  --memory @MEMORY@ --pids-limit @PIDS@ --env-file "$env" \
  -v "$mnt/docker:/var/lib/docker" -v "$mnt/work:/home/runner/.cache" \
  -v @BIN@:/usr/local/bin/forgejo-runner:ro @IMAGE@ >/dev/null
rm -f "$env"
rc=0
@DOCKER@ start -a "$ctr" || rc=$?
cleanup
exit "$rc"
}
"#;

pub struct ForgejoEphemeral<'a> {
    pub cfg: &'a ForgejoRunnerSection,
    /// `url` after defaulting to this config's `[forgejo]` instance.
    pub url: &'a str,
    pub docker_distro: bool,
    pub docker: Option<&'a DockerSection>,
    pub in_ci_slice: bool,
    /// CPUWeight of each docker-rootless slot user's slice.
    pub ci_cpu_weight: u32,
    /// False when `[github_runner] mode = "ephemeral"` already sets up
    /// Docker, sysbox and daemon.json on this host.
    pub owns_engine: bool,
}

/// `(host, port)` of an `https://` URL (validated at load).
pub fn url_host_port(url: &str) -> (&str, u16) {
    let authority = url
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("");
    match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().unwrap_or(443)),
        None => (authority, 443),
    }
}

/// Build context of the sandbox image: v2's Dockerfile, our entrypoint.
pub fn context() -> Vec<(&'static str, String, &'static str)> {
    vec![
        ("Dockerfile", dockerfile(&[]), "0644"),
        ("entrypoint.sh", ENTRYPOINT.into(), "0755"),
    ]
}

/// `anvil-forgejo-runner:<hash of the build context>`.
pub fn image_tag() -> String {
    let ctx: Vec<String> = context().into_iter().map(|f| f.1).collect();
    format!("{IMAGE_REPO}:{:016x}", fnv1a(ctx.join("\0").as_bytes()))
}

impl ForgejoEphemeral<'_> {
    fn slots(&self) -> std::ops::RangeInclusive<u32> {
        1..=self.cfg.capacity
    }

    /// The register/delete endpoint for `owner` (validated segments).
    pub fn runners_path(&self) -> String {
        match self.cfg.owner.as_deref() {
            None => "/admin/actions/runners".into(),
            Some(o) if o.contains('/') => format!("/repos/{o}/actions/runners"),
            Some(o) => format!("/orgs/{o}/actions/runners"),
        }
    }

    pub fn minter_content(&self) -> String {
        // Labels are validated quote-free, so plain quoting is valid JSON.
        let labels = format!(
            "[{}]",
            self.cfg
                .labels
                .iter()
                .map(|l| format!("\"{l}\""))
                .collect::<Vec<_>>()
                .join(",")
        );
        let cgroup = if self.in_ci_slice {
            format!("--cgroup-parent={} ", ci_resources::SLICE)
        } else {
            String::new()
        };
        let api = format!("{}/api/v1", self.url.trim_end_matches('/'));
        let (fns, rm, up, env, docker, sandbox, cgroup) = if self.cfg.docker_rootless() {
            (
                rootless_sandbox::fns("anvil-fjr-$slot", IMAGE_TAR),
                rootless_sandbox::cleanup(USER_UNIT, "@IMAGE_DIR@/forgejo-runner-\"$slot\".mnt"),
                rootless_sandbox::up(USER_UNIT),
                rootless_sandbox::ENV_OWNER,
                "ud",
                "--privileged".to_string(),
                String::new(),
            )
        } else {
            (
                String::new(),
                "docker rm -fv \"$ctr\" >/dev/null 2>&1 || true".to_string(),
                String::new(),
                "",
                "docker",
                format!("--network {NETWORK} --runtime=sysbox-runc"),
                cgroup,
            )
        };
        let mnt = if self.cfg.docker_rootless() {
            "/var/lib/anvil-fjr-$slot/vol"
        } else {
            "@IMAGE_DIR@/forgejo-runner-$slot.mnt"
        };
        MINTER_SCRIPT
            .replace("@MNT@", mnt)
            .replace("@SB_FNS@\n", &fns)
            .replace("@SB_RM@", &rm)
            .replace("@SB_UP@", &up)
            .replace("@SB_ENV@", env)
            .replace("@DOCKER@", docker)
            .replace("@SANDBOX@", &sandbox)
            .replace("@IMAGE_DIR@", &shell_escape(IMAGE_DIR))
            .replace("@TOKEN@", &shell_escape(TOKEN_PATH))
            .replace("@API@", &shell_escape(&api))
            .replace("@RUNNERS@", &shell_escape(&self.runners_path()))
            .replace("@URL@", &shell_escape(self.url))
            .replace("@LABELS@", &shell_escape(&labels))
            .replace("@CGROUP@", &cgroup)
            .replace("@CPUS@", &shell_escape(self.cfg.sandbox_cpus()))
            .replace("@MEMORY@", &shell_escape(self.cfg.sandbox_memory()))
            .replace(
                "@PIDS@",
                &shell_escape(&self.cfg.sandbox_pids().to_string()),
            )
            .replace("@BIN@", &shell_escape(BIN))
            .replace("@IMAGE@", &shell_escape(&image_tag()))
    }

    /// Root, no filesystem namespacing: the minter mounts the slot volume,
    /// which dockerd (in the host namespace) must see.
    pub fn unit_content(&self, i: u32) -> String {
        let slice = if self.in_ci_slice {
            format!("Slice={}\n", ci_resources::SLICE)
        } else {
            String::new()
        };
        let deps = if self.cfg.docker_rootless() {
            "After=network-online.target\n\
             Wants=network-online.target\n"
                .to_string()
        } else {
            "After=network-online.target docker.service sysbox.service\n\
             Wants=network-online.target\n\
             Requires=docker.service\n"
                .to_string()
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Forgejo Actions ephemeral runner slot {i} (anvil)\n\
             {deps}\
             \n\
             [Service]\n\
             ExecStart={MINTER} {i}\n\
             ExecStopPost={MINTER} {i} cleanup\n\
             {slice}\
             Restart=always\n\
             RestartSec=10\n\
             TimeoutStopSec=2min\n\
             NoNewPrivileges=yes\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        )
    }

    fn slot_users(&self) -> Vec<String> {
        self.slots().map(slot_user).collect()
    }

    pub fn user_unit_content(&self) -> String {
        rootless_sandbox::user_unit("forgejo runner", &self.slot_users())
    }

    /// An empty token (unset `FORGEJO_API_TOKEN`) fails before anything is
    /// written, instead of slots that cannot register.
    fn token_missing() -> ManagedCommand {
        ManagedCommand::new(
            "forgejo-runner api_token set",
            "false",
            format!(
                "printf '{MARK_FAILED} forgejo_runner: api_token is empty; export a Forgejo API \
                 token for the runner owner (see docs/modules/forgejo.md)\\n'\nexit 1"
            ),
        )
    }

    fn service_active(i: u32) -> ManagedCommand {
        let unit = shell_escape(&unit_name(i));
        ManagedCommand::new(
            format!("forgejo runner slot {i} minter active"),
            format!("systemctl is-active --quiet {unit}"),
            format!("__ghr_restart+=({unit})"),
        )
    }

    fn network() -> ManagedCommand {
        ManagedCommand::new(
            format!("sandbox network {NETWORK} (bridge {BRIDGE})"),
            format!("docker network inspect {NETWORK} >/dev/null 2>&1"),
            format!(
                "docker network create -o com.docker.network.bridge.name={BRIDGE} {NETWORK} >/dev/null"
            ),
        )
    }

    /// The ufw rule letting sandboxes reach this host's Forgejo; only on
    /// the sandbox bridge, never docker0.
    pub fn ufw_rule(&self) -> String {
        format!(
            "allow in on {BRIDGE} to any port {} proto tcp",
            url_host_port(self.url).1
        )
    }

    /// Live test: when `url`'s host resolves to an address of this host
    /// (e.g. Caddy on the tailnet IP, ufw open only on `tailscale0`),
    /// sandbox traffic arrives on [`BRIDGE`] and ufw drops it. Decided on
    /// the host, so it holds however the config reaches Forgejo.
    fn ufw_allow(&self) -> ManagedCommand {
        let rule = self.ufw_rule();
        let local = format!(
            "__fjr_local() {{ local a; for a in $(getent ahosts {} 2>/dev/null | awk '{{print $1}}' | sort -u); do \
             ip -o addr show 2>/dev/null | awk '{{sub(\"/.*\", \"\", $4); print $4}}' | grep -qxF \"$a\" && return 0; \
             done; return 1; }}; ",
            shell_escape(url_host_port(self.url).0)
        );
        ManagedCommand::new(
            format!("firewall {rule} if Forgejo is on this host (forgejo_runner sandboxes)"),
            format!(
                "{local}! command -v ufw >/dev/null 2>&1 || ! __fjr_local || \
                 ufw show added 2>/dev/null | grep -wF {} >/dev/null",
                shell_escape(&rule)
            ),
            format!("ufw {rule} comment 'anvil forgejo_runner' >/dev/null"),
        )
    }

    /// Review: a persistent runner left on the host would keep taking
    /// jobs outside any sandbox. Stop it and move its files to `.anvil.bak`
    /// (declared command files: rollback restores them, `rollback()`
    /// restarts it).
    fn retire_persistent() -> ManagedCommand {
        let paths = PERSISTENT_FILES.join(" ");
        ManagedCommand::new(
            "persistent forgejo runner retired (unit, prune timer, config)",
            PERSISTENT_FILES
                .iter()
                .map(|p| format!("[ ! -e {p} ]"))
                .collect::<Vec<_>>()
                .join(" && "),
            format!(
                "systemctl disable --now {PRUNE_TIMER_UNIT} {UNIT} 2>/dev/null || true\n\
                 for __p in {paths}; do\n\
                 \x20 [ -e \"$__p\" ] || continue\n\
                 \x20 [ -e \"$__p{BACKUP_SUFFIX}\" ] || cp -a \"$__p\" \"$__p{BACKUP_SUFFIX}\"\n\
                 \x20 rm -f \"$__p\"\n\
                 \x20 printf '{MARK_CHANGED} %s retired (mode = \"ephemeral\")\\n' \"$__p\"\n\
                 done\n\
                 systemctl daemon-reload"
            ),
        )
    }

    fn rollback_first(&self) -> String {
        let mut s = String::from("\n# rollback ephemeral forgejo runner slots\n");
        for i in self.slots() {
            // Stopping runs the minter's cleanup: sandbox, mount, stale runners.
            let unit = shell_escape(&unit_name(i));
            s.push_str(&format!(
                "systemctl disable --now {unit} 2>/dev/null || true\n\
                 rm -f /etc/systemd/system/multi-user.target.wants/{unit}\n\
                 docker rm -fv {ctr} >/dev/null 2>&1 || true\n\
                 ! mountpoint -q {mnt} || umount {mnt}\n",
                ctr = shell_escape(&container(i)),
                mnt = shell_escape(&mount_dir(i)),
            ));
            if self.cfg.docker_rootless() {
                s.push_str(&rootless_sandbox::umount(&slot_user(i)));
            }
        }
        s
    }

    fn rollback(&self) -> String {
        let mut s = format!(
            "\n# rollback ephemeral forgejo runner image and slot volumes\n\
             docker image ls {IMAGE_REPO} --format '{{{{.Repository}}}}:{{{{.Tag}}}}' 2>/dev/null | \
             xargs -r docker image rm >/dev/null 2>&1 || true\n\
             docker builder prune -af >/dev/null 2>&1 || true\n"
        );
        for i in self.slots() {
            let img = shell_escape(&image_path(i));
            s.push_str(&format!(
                "rmdir {mnt} 2>/dev/null || true\n\
                 if [ -s {ids} ]; then\n\
                 \x20 printf '{MARK_FAILED} forgejo_runner: Forgejo runner ids %s still registered (listed in %s); \
                 delete them under Settings → Actions → Runners, then the file\\n' \"$(tr '\\n' ' ' <{ids})\" {ids}\n\
                 else\n\
                 \x20 rm -f {ids}\n\
                 fi\n\
                 if __anvil_created {img}; then\n\
                 \x20 rm -f {img}\n\
                 \x20 __anvil_forget {img}\n\
                 \x20 printf 'CHANGED: %s removed\\n' {img}\n\
                 fi\n",
                mnt = shell_escape(&mount_dir(i)),
                ids = shell_escape(&ids_path(i)),
            ));
        }
        // The bridge is ours alone: a rule on it is anvil's.
        let ufw = format!(
            "! command -v ufw >/dev/null 2>&1 || ufw delete {} >/dev/null 2>&1 || true\n",
            self.ufw_rule()
        );
        s.push_str(&format!(
            "docker network rm {NETWORK} >/dev/null 2>&1 || true\n\
             {ufw}\
             rmdir {ctx} {conf} 2>/dev/null || true\n\
             # The persistent runner's files are restored by now: restart it.\n\
             if [ -e {UNIT_PATH} ]; then\n\
             \x20 systemctl daemon-reload\n\
             \x20 systemctl enable --now {UNIT} >/dev/null 2>&1 || true\n\
             \x20 [ ! -e {PRUNE_TIMER} ] || systemctl enable --now {PRUNE_TIMER_UNIT} >/dev/null 2>&1 || true\n\
             \x20 printf '{MARK_CHANGED} forgejo_runner: persistent runner restored\\n'\n\
             fi\n\
             rmdir {} 2>/dev/null || true\n\
             if __anvil_created {BIN} && [ ! -e {UNIT_PATH} ]; then\n\
             \x20 rm -f {BIN}\n\
             \x20 __anvil_forget {BIN}\n\
             \x20 printf 'CHANGED: forgejo_runner: {BIN} removed (installed by anvil)\\n'\n\
             fi\n",
            shell_escape(IMAGE_DIR),
            ctx = shell_escape(IMAGE_CTX),
            conf = shell_escape(TOKEN_PATH.trim_end_matches("/api-token")),
        ));
        if self.cfg.docker_rootless() {
            s.push_str(&rootless_sandbox::rollback(
                "forgejo_runner",
                IMAGE_TAR,
                IMAGE_TAR_TAG,
                &self.slot_users(),
            ));
        } else if self.owns_engine {
            s.push_str(&format!(
                // The local include is restored by now; load the profile without it.
                "if [ -f {p} ] && aa-enabled -q 2>/dev/null; then apparmor_parser -r {p} || true; fi\n\
                 __docker_restart=1\n",
                p = shell_escape(AA_PROFILE),
            ));
        }
        s
    }

    /// `install` is the persistent mode's pinned, verified binary, which
    /// every sandbox mounts read-only.
    pub fn declaration(&self, install: ManagedCommand) -> Declaration {
        let token = self.cfg.api_token.as_deref().unwrap_or_default();
        let mut decl = Declaration::new("forgejo_runner").secret(token);
        if token.is_empty() {
            decl = decl.command(Self::token_missing());
        }
        decl = decl
            .command(Ephemeral::tools())
            .command(Self::retire_persistent());
        for p in PERSISTENT_FILES {
            decl = decl.command_file(p);
        }
        let rootless = self.cfg.docker_rootless();
        if rootless {
            // Root's Docker only builds the image; jobs never touch it.
            let (cmds, unit) = rootless_sandbox::host(
                "forgejo_runner",
                self.docker_distro,
                &self.slot_users(),
                USER_UNIT_PATH,
                self.user_unit_content(),
                self.ci_cpu_weight,
            );
            decl = decl.installs(&["Docker (rootless)"]);
            for c in cmds {
                decl = decl.command(c);
            }
            decl = decl.file(unit);
        } else if self.owns_engine {
            decl = docker_sandbox_engine(decl, self.docker_distro, self.docker, "sysbox-runc");
        } else {
            decl = decl.installs(&["Docker", "sysbox-ce 0.7.1"]);
        }
        let tag = image_tag();
        let mut decl = decl
            .command(install)
            .command(build_image(
                "docker",
                &tag,
                &context(),
                "docker builder prune -af",
            ))
            .command(superseded_images("docker", IMAGE_REPO, &tag));
        decl = if rootless {
            // Sandbox traffic leaves as the slot user from the host: no bridge, no ufw rule.
            decl.command(rootless_sandbox::image_tar(IMAGE_TAR, IMAGE_TAR_TAG, &tag))
        } else {
            decl.command(Self::network()).command(self.ufw_allow())
        };
        let mut decl = decl
            .file(ManagedFile::computed(
                TOKEN_PATH,
                format!("printf '%s\\n' {}", shell_escape(token)),
                "0600",
                "root:root",
            ))
            .file(ManagedFile::new(
                MINTER,
                self.minter_content(),
                "0700",
                "root:root",
            ));
        for (f, content, mode) in context() {
            decl = decl.file(ManagedFile::new(
                format!("{IMAGE_CTX}/{f}"),
                content,
                mode,
                "root:root",
            ));
        }
        let disk = self.cfg.sandbox_disk();
        let bytes = size_bytes(disk).unwrap_or(0);
        for i in self.slots() {
            decl = decl
                .command(loop_image(
                    format!("forgejo runner slot {i} sandbox volume ({disk})"),
                    &image_path(i),
                    "the sandbox disk",
                    disk,
                    bytes,
                    "0:0",
                ))
                .command(Self::service_active(i))
                .file(ManagedFile::new(
                    unit_path(i),
                    self.unit_content(i),
                    "0644",
                    "root:root",
                ));
        }
        // A new minter, image or token takes effect from each slot's
        // next job. Only its own unit change or a stopped slot restarts it,
        // and never over a sandbox: then a flag restarts it between jobs.
        let restarts: String = self
            .slots()
            .map(|i| {
                let u = shell_escape(&unit_name(i));
                format!(
                    "if __ghr_mine {u} {path}; then \
                     if systemctl is-active --quiet {u} && {busy}; \
                     then touch {flag}; else rm -f {flag}; systemctl restart {u}; fi; fi; ",
                    path = shell_escape(&unit_path(i)),
                    busy = if rootless {
                        format!("mountpoint -q {}", shell_escape(&slot_vol(i)))
                    } else {
                        format!(
                            "docker container inspect {} >/dev/null 2>&1",
                            shell_escape(&container(i))
                        )
                    },
                    flag = shell_escape(&restart_flag(i)),
                )
            })
            .collect();
        let units: Vec<String> = self.slots().map(|i| shell_escape(&unit_name(i))).collect();
        let entries: Vec<String> = self
            .slots()
            // A unit rollback already deleted needs no minter.
            .map(|i| {
                format!(
                    "{{ [ ! -e {} ] || [ -x {MINTER} ]; }}",
                    shell_escape(&unit_path(i))
                )
            })
            .collect();
        let (validate, pre) = if self.owns_engine && !rootless {
            (docker::daemon_json_validate(), docker::restart_dockerd())
        } else {
            ("true".into(), String::new())
        };
        decl.rollback_first(self.rollback_first())
            .rollback_script(self.rollback())
            .guarded_reload(ReloadGuard {
                describe: "forgejo runner minters".into(),
                validate: format!("{{ {validate}; }} && {}", entries.join(" && ")),
                reload: format!(
                    "{pre}systemctl daemon-reload; systemctl enable {u} >/dev/null 2>&1 || true; \
                     {MINE_FN}{restarts}",
                    u = units.join(" "),
                ),
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::process::Command;

    /// sysbox unless `extra` picks a runtime (docker-rootless is the default).
    fn cfg(extra: &str) -> ForgejoRunnerSection {
        let rt = if extra.contains("sandbox_runtime") {
            ""
        } else {
            "sandbox_runtime = \"sysbox-runc\"\n"
        };
        toml::from_str(&format!(
            "mode = \"ephemeral\"\napi_token = \"S3CRET\"\nlabels = [\"debian:host\", \
             \"node:docker://node:22-trixie\"]\ncapacity = 2\n{rt}{extra}"
        ))
        .unwrap()
    }

    fn eph(c: &ForgejoRunnerSection, slice: bool, owns: bool) -> ForgejoEphemeral<'_> {
        ForgejoEphemeral {
            cfg: c,
            url: "https://git.example.org/",
            docker_distro: false,
            docker: None,
            in_ci_slice: slice,
            ci_cpu_weight: 100,
            owns_engine: owns,
        }
    }

    fn decl(c: &ForgejoRunnerSection, owns: bool) -> Declaration {
        eph(c, false, owns).declaration(ManagedCommand::new("binary", "true", "true"))
    }

    #[test]
    fn owner_picks_the_register_endpoint() {
        for (owner, want) in [
            ("", "/admin/actions/runners"),
            ("owner = \"acme\"", "/orgs/acme/actions/runners"),
            ("owner = \"acme/app\"", "/repos/acme/app/actions/runners"),
        ] {
            let c = cfg(owner);
            assert_eq!(eph(&c, false, true).runners_path(), want);
            assert!(eph(&c, false, true)
                .minter_content()
                .contains(&format!("api POST '{want}' --data-binary")));
        }
    }

    #[test]
    fn minter_registers_then_runs_one_sandbox_then_cleans_up() {
        let c = cfg("owner = \"acme\"");
        let m = eph(&c, true, true).minter_content();
        for want in [
            "\"$(cat '/etc/anvil/forgejo-runner/api-token')\" |\n    curl -fsS --proto '=https'",
            "-K - -X \"$1\"",
            "\"${@:3}\" 'https://git.example.org/api/v1'\"$2\"",
            "api DELETE '/orgs/acme/actions/runners'/\"$id\" -o /dev/null -w '%{http_code}'",
            "204 | 404) ;;",
            "jq -nc --arg n \"$name\" '{name: $n, ephemeral: true}'",
            "jq -er --arg url 'https://git.example.org/' --argjson l '[\"debian:host\",\"node:docker://node:22-trixie\"]'",
            "docker create --name \"$ctr\" --init --hostname \"$ctr\" --network anvil-forgejo-sandbox \
             --runtime=sysbox-runc --cgroup-parent=ci.slice --cpus '2' \\\n  --memory '4g' --pids-limit '2048' --env-file \"$env\"",
            "-v \"$mnt/docker:/var/lib/docker\" -v \"$mnt/work:/home/runner/.cache\"",
            "-v '/usr/local/bin/forgejo-runner':/usr/local/bin/forgejo-runner:ro",
            &format!("{} >/dev/null\nrm -f \"$env\"\n", shell_escape(&image_tag())),
            "mkfs.ext4 -q -F -m 0 \"$img\"\n",
            "ids='/var/lib/anvil-ci'/forgejo-runner-$slot.ids\n",
        ] {
            assert!(m.contains(want), "minter misses {want:?}\n{m}");
        }
        // Wipe, register, create, drop the env file, run, clean up.
        let pos = |s: &str| m.find(s).unwrap();
        assert!(pos("mkfs.ext4 -q") < pos("reg=$(api POST"));
        assert!(pos("reg=$(api POST") < pos("jq -er .id >>\"$ids\""));
        assert!(pos("jq -er .id >>\"$ids\"") < pos("docker create"));
        assert!(pos("docker create") < pos("rm -f \"$env\"\nrc=0"));
        assert!(pos("rm -f \"$env\"\nrc=0") < pos("docker start -a"));
        assert!(pos("docker start -a") < m.rfind("cleanup\nexit").unwrap());
        // No token ever on a command line, nor the host's Docker socket.
        assert!(!m.contains("-H \"Authorization") && !m.contains("S3CRET"));
        assert!(!m.contains("docker.sock"));
        assert!(!eph(&c, false, true)
            .minter_content()
            .contains("--cgroup-parent"));
    }

    /// Runs the minter's config line on a fake register response: one
    /// connection with the per-job credentials, the labels, no Docker socket.
    #[test]
    fn runner_config_carries_only_the_one_job_runner() {
        if Command::new("jq").arg("--version").output().is_err() {
            return;
        }
        let c = cfg("");
        let m = eph(&c, false, true).minter_content();
        let start = m.find("printf '%s' \"$reg\" | jq -er --arg url").unwrap();
        let end = start + m[start..].find(">\"$env\"").unwrap();
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c"])
            .arg(format!(
                "reg='{{\"id\":7,\"uuid\":\"u-1\",\"token\":\"t-1\"}}'\n{}",
                &m[start..end]
            ))
            .output()
            .unwrap();
        let line = String::from_utf8(out.stdout).unwrap();
        let b64 = line
            .trim()
            .strip_prefix("ANVIL_RUNNER_CONFIG=")
            .expect(&line);
        use base64::Engine;
        let yml = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&yml).unwrap();
        assert_eq!(
            v["server"]["connections"]["anvil"],
            serde_json::json!({"url": "https://git.example.org/", "uuid": "u-1", "token": "t-1"})
        );
        assert_eq!(v["runner"]["capacity"], 1);
        assert_eq!(v["runner"]["labels"][1], "node:docker://node:22-trixie");
        assert_eq!(v["container"]["docker_host"], "-");
    }

    /// Runs `cleanup` with a stub API: deleted (204) and already-gone (404)
    /// runners leave the ids file, any other answer keeps the id for later.
    #[test]
    fn cleanup_deletes_registered_runners_and_keeps_failures() {
        let c = cfg("");
        let m = eph(&c, false, true).minter_content();
        let start = m.find("cleanup() {").unwrap();
        let end = start + m[start..].find("\n}\n").unwrap() + 3;
        let dir = std::env::temp_dir().join(format!("anvil-fjr-cleanup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ids = dir.join("ids");
        std::fs::write(&ids, "1\n2\n3\n").unwrap();
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c"])
            .arg(format!(
                "docker() {{ :; }}; mountpoint() {{ return 1; }}\n\
                 api() {{ case \"$2\" in */1) echo 204 ;; */2) echo 404 ;; *) echo 502; return 22 ;; esac; }}\n\
                 ctr=x; mnt=/nonexistent; ids={}\n{}cleanup",
                ids.display(),
                &m[start..end]
            ))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert_eq!(std::fs::read_to_string(&ids).unwrap(), "3\n");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn minter_is_one_parsed_group_and_restarts_between_jobs_on_the_flag() {
        let m = eph(&cfg(""), false, true).minter_content();
        assert!(m.contains("\n{\nset -euo pipefail\n") && m.ends_with("exit \"$rc\"\n}\n"));
        assert!(m.contains(
            "if [ -e \"/run/$ctr.restart\" ]; then rm -f \"/run/$ctr.restart\"; exit 0; fi"
        ));
    }

    #[test]
    fn entrypoint_hands_the_config_to_the_runner_user_and_runs_one_job() {
        let e = ENTRYPOINT;
        let pos = |s: &str| e.find(s).unwrap();
        assert!(pos("dockerd >") < pos("base64 -d >/home/runner/.runner.yml"));
        assert!(pos("umask 077") < pos("base64 -d"));
        assert!(pos("unset ANVIL_RUNNER_CONFIG") < pos("exec runuser -u runner -- forgejo-runner one-job --wait -c /home/runner/.runner.yml"));
        let ctx = context();
        assert_eq!(ctx[0].1, dockerfile(&[]));
        assert!(image_tag().starts_with("anvil-forgejo-runner:"));
    }

    /// Runs a script with `/etc` and `/usr` under a temp root and a logging
    /// `systemctl`; returns (root, systemctl calls).
    pub(crate) fn run_in_root(script: &str, setup: &[&str]) -> (std::path::PathBuf, String) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let root = std::env::temp_dir().join(format!(
            "anvil-fjr-root-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);
        for f in setup {
            let p = root.join(f.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, "x").unwrap();
        }
        let r = root.display().to_string();
        let script = script
            .replace("/etc/", &format!("{r}/etc/"))
            .replace("/usr/", &format!("{r}/usr/"));
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c"])
            .arg(format!(
                "systemctl() {{ echo \"systemctl $*\" >>{r}/calls; }}\n\
                 __anvil_created() {{ return 1; }}; __anvil_forget() {{ :; }}\n{script}"
            ))
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let calls = std::fs::read_to_string(root.join("calls")).unwrap_or_default();
        (root, calls)
    }

    /// Review: ephemeral mode stops the persistent runner and moves its
    /// files to `.anvil.bak`; the engine restores those (command files) and
    /// rollback restarts it.
    #[test]
    fn ephemeral_retires_the_persistent_runner_and_rollback_brings_it_back() {
        let c = ForgejoEphemeral::retire_persistent();
        let (root, calls) = run_in_root(&c.converge, &[UNIT_PATH, CONFIG, PRUNE_TIMER]);
        assert!(calls.starts_with(
            "systemctl disable --now anvil-forgejo-runner-prune.timer anvil-forgejo-runner.service\n"
        ));
        let at = |p: &str| root.join(p.trim_start_matches('/'));
        for p in [UNIT_PATH, CONFIG, PRUNE_TIMER] {
            assert!(
                !at(p).exists() && at(&format!("{p}{BACKUP_SUFFIX}")).exists(),
                "{p}"
            );
        }
        // Converged once nothing is left; the files are the declaration's command files.
        run_in_root(&c.detect, &[]);
        let d = decl(&cfg(""), true);
        assert_eq!(d.command_files[..5], PERSISTENT_FILES);
        let rb = d.render_rollback();
        let restore = rb
            .find(&format!("if [ -f \"$__path{BACKUP_SUFFIX}\" ]; then"))
            .unwrap();
        let restart = rb
            .find("systemctl enable --now anvil-forgejo-runner.service")
            .unwrap();
        assert!(restore < restart);
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn entrypoint_takes_the_config_out_of_the_environment_before_dockerd() {
        let e = ENTRYPOINT;
        let pos = |s: &str| e.find(s).unwrap();
        assert!(pos("unset ANVIL_RUNNER_CONFIG") < pos("dockerd >"));
        assert!(!e[pos("dockerd >")..].contains("ANVIL_RUNNER_CONFIG"));
    }

    #[test]
    fn sandboxes_get_their_own_bridge_and_ufw_opens_it_when_forgejo_is_local() {
        let c = cfg("");
        let d = decl(&c, true);
        let net = d
            .commands
            .iter()
            .find(|c| c.describe.starts_with("sandbox network"))
            .unwrap();
        assert_eq!(
            net.converge,
            "docker network create -o com.docker.network.bridge.name=anvil-fjsb0 anvil-forgejo-sandbox >/dev/null"
        );
        let ufw = d
            .commands
            .iter()
            .find(|c| c.describe.starts_with("firewall"))
            .unwrap();
        assert_eq!(
            ufw.converge,
            "ufw allow in on anvil-fjsb0 to any port 443 proto tcp comment 'anvil forgejo_runner' >/dev/null"
        );
        // Detect against stubs: (url resolves locally, rule present) -> converged?
        let run = |local: bool, present: bool| {
            let ip = if local { "100.64.0.1" } else { "192.0.2.1" };
            let rule = if present {
                "ufw allow in on anvil-fjsb0 to any port 443 proto tcp"
            } else {
                "ufw allow 22/tcp"
            };
            let script = format!(
                "getent() {{ [ \"$2\" = git.example.org ] && echo '{ip} STREAM git.example.org'; }}\n\
                 ip() {{ echo '2: tailscale0    inet 100.64.0.1/32 scope global tailscale0'; }}\n\
                 ufw() {{ echo '{rule}'; }}\n{}",
                ufw.detect
            );
            Command::new("bash")
                .args(["-c", &script])
                .status()
                .unwrap()
                .success()
        };
        assert!(run(false, false), "a remote Forgejo needs no rule");
        assert!(!run(true, false), "a local Forgejo needs the rule");
        assert!(run(true, true));
        let mut other = eph(&c, false, true);
        other.url = "https://git.example.org:8443/x/";
        assert_eq!(
            other.ufw_rule(),
            "allow in on anvil-fjsb0 to any port 8443 proto tcp"
        );
        assert_eq!(url_host_port("https://h/"), ("h", 443));
        assert_eq!(url_host_port("https://h:3000"), ("h", 3000));
    }

    #[test]
    fn unit_per_slot_runs_the_minter_in_the_ci_slice() {
        let c = cfg("");
        let u = eph(&c, true, true).unit_content(2);
        for want in [
            "\nExecStart=/usr/local/libexec/anvil/forgejo-runner-mint.sh 2\n",
            "\nExecStopPost=/usr/local/libexec/anvil/forgejo-runner-mint.sh 2 cleanup\n",
            "\nSlice=ci.slice\nRestart=always\n",
            "\nRequires=docker.service\n",
            "\nNoNewPrivileges=yes\n",
        ] {
            assert!(u.contains(want), "unit misses {want:?}\n{u}");
        }
        assert!(!eph(&c, false, true).unit_content(1).contains("Slice="));
        let d = decl(&c, true);
        for i in [1, 2] {
            assert!(d.files.iter().any(|f| f.path == unit_path(i)));
        }
        assert!(!d.files.iter().any(|f| f.path == unit_path(3)));
    }

    #[test]
    fn api_token_is_a_computed_root_file_and_never_static() {
        let d = decl(&cfg(""), true);
        let f = d.files.iter().find(|f| f.path == TOKEN_PATH).unwrap();
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0600", "root:root"));
        assert!(f.static_content().is_none());
        for f in &d.files {
            assert!(
                !f.static_content().unwrap_or_default().contains("S3CRET"),
                "{}",
                f.path
            );
        }
        for c in &d.commands {
            assert!(!c.converge.contains("S3CRET") && !c.detect.contains("S3CRET"));
        }
        assert!(!d.redact(&d.render_apply()).contains("S3CRET"));
    }

    #[test]
    fn empty_api_token_fails_apply_first() {
        let d = decl(
            &ForgejoRunnerSection {
                api_token: Some(String::new()),
                ..cfg("")
            },
            true,
        );
        assert_eq!(d.commands[0].detect, "false");
        assert!(d.commands[0]
            .converge
            .contains("FAILED: forgejo_runner: api_token is empty"));
        assert!(!decl(&cfg(""), true)
            .commands
            .iter()
            .any(|c| c.detect == "false"));
    }

    #[test]
    fn engine_and_daemon_json_only_without_a_v2_runner() {
        let c = cfg("");
        let (own, shared) = (decl(&c, true), decl(&c, false));
        let has = |d: &Declaration, p: &str| d.files.iter().any(|f| f.path == p);
        assert!(has(&own, "/etc/docker/daemon.json") && !has(&shared, "/etc/docker/daemon.json"));
        let own_apply = own.render_apply();
        assert!(own_apply.contains("sysbox-ce") && !shared.render_apply().contains("sysbox.deb"));
        assert_eq!(own.installs, shared.installs);
        let reload = |d: &Declaration| d.reload.clone().unwrap();
        assert!(
            reload(&own).reload.starts_with("__dj=")
                && reload(&shared)
                    .reload
                    .starts_with("systemctl daemon-reload")
        );
        assert!(own.render_rollback().contains("__docker_restart=1"));
        assert!(!shared.render_rollback().contains("__docker_restart=1"));
    }

    #[test]
    fn reload_restarts_only_changed_or_stopped_slots_never_over_a_sandbox() {
        let r = decl(&cfg(""), true).reload.unwrap().reload;
        assert!(r.contains(
            "if __ghr_mine 'anvil-forgejo-runner-1.service' '/etc/systemd/system/anvil-forgejo-runner-1.service'; then \
             if systemctl is-active --quiet 'anvil-forgejo-runner-1.service' && docker container inspect 'anvil-forgejo-runner-1' >/dev/null 2>&1; \
             then touch '/run/anvil-forgejo-runner-1.restart'; else rm -f '/run/anvil-forgejo-runner-1.restart'; systemctl restart 'anvil-forgejo-runner-1.service'; fi; fi; "
        ));
        assert!(r.contains(
            "systemctl enable 'anvil-forgejo-runner-1.service' 'anvil-forgejo-runner-2.service'"
        ));
    }

    #[test]
    fn rollback_stops_slots_first_then_removes_image_and_volumes() {
        let d = decl(&cfg(""), true);
        let rb = d.render_rollback();
        let stop = rb
            .find("systemctl disable --now 'anvil-forgejo-runner-1.service'")
            .unwrap();
        let rm = rb.find("docker rm -fv 'anvil-forgejo-runner-2'").unwrap();
        let img = rb.find("docker image ls anvil-forgejo-runner").unwrap();
        let vol = rb
            .find("if __anvil_created '/var/lib/anvil-ci/forgejo-runner-2.img'; then")
            .unwrap();
        assert!(stop < rm && rm < img && img < vol);
        assert!(rb.contains("rm -f '/var/lib/anvil-ci/forgejo-runner-1.ids'\n"));
        assert!(rb.contains(
            "! mountpoint -q '/var/lib/anvil-ci/forgejo-runner-2.mnt' || umount '/var/lib/anvil-ci/forgejo-runner-2.mnt'\n"
        ));
        assert!(rb.contains("rmdir '/var/lib/anvil-ci/forgejo-runner-1.mnt' 2>/dev/null || true\n"));
        let bin = rb
            .find("if __anvil_created /usr/local/bin/forgejo-runner && [ ! -e /etc/systemd/system/anvil-forgejo-runner.service ]; then\n  rm -f /usr/local/bin/forgejo-runner\n")
            .unwrap();
        assert!(stop < bin);
        // Review: the persistent runner restarts before the binary check,
        // the network, the ufw rule and anvil's dirs go.
        let restart = rb
            .find("if [ -e /etc/systemd/system/anvil-forgejo-runner.service ]; then\n  systemctl daemon-reload\n  systemctl enable --now anvil-forgejo-runner.service")
            .unwrap();
        assert!(img < restart && restart < bin);
        assert!(rb.contains("docker network rm anvil-forgejo-sandbox >/dev/null 2>&1 || true\n"));
        assert!(rb.contains(
            "ufw delete allow in on anvil-fjsb0 to any port 443 proto tcp >/dev/null 2>&1 || true\n"
        ));
        assert!(rb.contains(
            "rmdir '/etc/anvil/forgejo-runner/image' '/etc/anvil/forgejo-runner' 2>/dev/null || true\n"
        ));
        // A non-empty ids file is kept and reported, never silently dropped.
        assert!(rb.contains(
            "if [ -s '/var/lib/anvil-ci/forgejo-runner-1.ids' ]; then\n  printf 'FAILED: forgejo_runner: Forgejo runner ids"
        ));
        assert!(rb.contains("else\n  rm -f '/var/lib/anvil-ci/forgejo-runner-1.ids'\nfi\n"));
    }

    #[test]
    fn every_script_parses_under_bash_n() {
        let c = cfg("owner = \"a/b\"");
        for owns in [true, false] {
            let d = decl(&c, owns);
            let m = eph(&c, true, owns).minter_content();
            for s in [
                d.render_probe(),
                d.render_apply(),
                d.render_rollback(),
                m,
                ENTRYPOINT.into(),
            ] {
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

    // --- sandbox_runtime = "docker-rootless" ---

    const RL: &str = "sandbox_runtime = \"docker-rootless\"";

    #[test]
    fn rootless_minter_runs_a_privileged_sandbox_in_the_slot_users_fresh_engine() {
        let c = cfg(RL);
        let m = eph(&c, true, true).minter_content();
        assert!(
            !m.contains("sysbox") && !m.contains("--network") && !m.contains("--cgroup-parent")
        );
        assert!(
            m.contains("mnt=/var/lib/anvil-fjr-$slot/vol\n") && m.contains("u=anvil-fjr-$slot\n")
        );
        assert!(m.contains(
            "ud create --name \"$ctr\" --init --hostname \"$ctr\" --privileged --cpus '2'"
        ));
        assert!(m.contains("ud start -a \"$ctr\""));
        let pos = |n: &str| m.find(n).unwrap_or_else(|| panic!("{n} missing:\n{m}"));
        // Fresh volume (= the engine's data-root) → owned by the slot user →
        // its engine → the saved image → the env file it may read → sandbox.
        assert!(pos("mkfs.ext4") < pos("chown -R \"$u:$(id -g \"$u\")\" \"$mnt\""));
        assert!(
            pos("chown -R \"$u:$(id -g \"$u\")\" \"$mnt\"")
                < pos("us systemctl --user start anvil-sandbox-docker.service")
        );
        assert!(pos("us systemctl --user start") < pos("ud load -q <\"$tar\""));
        // A lingering manager caches units: a changed one needs a reload first.
        assert!(pos("us systemctl --user daemon-reload") < pos("us systemctl --user start"));
        assert!(
            pos("ud load") < pos("chown \"$u\" \"$env\"")
                && pos("chown \"$u\" \"$env\"") < pos("ud create")
        );
        // A slot that ran in root's Docker before leaves no sandbox or mount behind.
        assert!(m.contains("|| docker rm -fv \"$ctr\""));
        assert!(m.contains("umount '/var/lib/anvil-ci'/forgejo-runner-\"$slot\".mnt"));
        // Cleanup stops the engine before it unmounts its data-root.
        assert!(
            pos("us systemctl --user stop anvil-sandbox-docker.service") < pos("umount \"$mnt\"")
        );
    }

    #[test]
    fn rootless_user_unit_admits_only_the_slot_users() {
        let c = cfg(RL);
        let u = eph(&c, false, true).user_unit_content();
        assert!(u.contains("ConditionUser=|anvil-fjr-1\nConditionUser=|anvil-fjr-2\n"));
        assert!(
            u.contains("ExecStart=/usr/bin/dockerd-rootless.sh --data-root=%h/vol/engine --log-driver=journald\n")
                && u.contains("Delegate=yes\n")
        );
        assert!(
            !u.contains("[Install]"),
            "the minter starts it, nothing enables it"
        );
    }

    #[test]
    fn rootless_declaration_has_slot_users_and_no_sysbox_bridge_or_daemon_json() {
        let c = cfg(RL);
        let d = decl(&c, true);
        let has = |p: &str| d.files.iter().any(|f| f.path == p);
        assert!(has(USER_UNIT_PATH) && !has("/etc/docker/daemon.json"));
        let apply = d.render_apply();
        for gone in ["sysbox", NETWORK, "ufw "] {
            assert!(!apply.contains(gone), "{gone}");
        }
        for want in [
            "useradd --system --gid anvil-fjr-2",
            "usermod -c umask=022 'anvil-fjr-1'",
            "loginctl enable-linger 'anvil-fjr-2'",
            "docker save -o '/var/lib/anvil-ci/forgejo-runner-sandbox.tar'.tmp",
            "docker-ce-rootless-extras",
        ] {
            assert!(apply.contains(want), "{want}");
        }
        let n = |x: &str| apply.matches(x).count();
        assert_eq!(
            n("rootless docker helpers"),
            n("anvil-fjr-1 user manager lingers"),
            "helpers once"
        );
        assert_eq!(
            n("anvil-fjr-1 user manager lingers"),
            n("anvil-fjr-2 user manager lingers")
        );
        assert!(!d.reload.clone().unwrap().reload.starts_with("__dj="));
        let units = d.files.iter().find(|f| f.path == unit_path(1)).unwrap();
        let unit = eph(&c, false, true).unit_content(1);
        assert!(!unit.contains("docker.service") && units.path == unit_path(1));
        // Busy = volume mounted (the sandbox is not in root's Docker).
        assert!(d
            .reload
            .unwrap()
            .reload
            .contains("mountpoint -q '/var/lib/anvil-fjr-1/vol'"));
    }

    #[test]
    fn rootless_rollback_unmounts_then_drops_the_slot_users() {
        let c = cfg(RL);
        let rb = decl(&c, true).render_rollback();
        let pos = |n: &str| rb.find(n).unwrap_or_else(|| panic!("{n} missing"));
        assert!(
            pos("umount '/var/lib/anvil-fjr-2/vol'") < pos("loginctl disable-linger 'anvil-fjr-2'")
        );
        assert!(
            pos("loginctl disable-linger 'anvil-fjr-2'") < pos("rm -rf '/var/lib/anvil-fjr-2'")
        );
        assert!(pos("rm -rf '/var/lib/anvil-fjr-2'") < pos("userdel anvil-fjr-2"));
        assert!(rb.contains("rm -f '/var/lib/anvil-ci/forgejo-runner-sandbox.tar'"));
        assert!(
            !rb.contains("__docker_restart=1"),
            "root dockerd was never reconfigured"
        );
    }

    #[test]
    fn rootless_scripts_parse_under_bash_n() {
        let c = cfg(RL);
        let d = decl(&c, true);
        for s in [
            d.render_probe(),
            d.render_apply(),
            d.render_rollback(),
            eph(&c, false, true).minter_content(),
        ] {
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

    #[test]
    fn rootless_slot_users_yield_cpu_with_the_ci_weight_and_rollback_reverts_it() {
        let c = cfg(RL);
        let mut e = eph(&c, true, true);
        e.ci_cpu_weight = 50;
        let d = e.declaration(ManagedCommand::new("binary", "true", "true"));
        let apply = d.render_apply();
        for i in [1, 2] {
            let slice = format!("\"user-$(id -u 'anvil-fjr-{i}').slice\"");
            assert!(apply.contains(&format!("systemctl set-property {slice} CPUWeight=50")));
            assert!(d.render_probe().contains(&format!(
                "[ \"$(systemctl show -p CPUWeight --value {slice})\" = 50 ]"
            )));
        }
        let rb = d.render_rollback();
        let pos = |n: &str| rb.find(n).unwrap_or_else(|| panic!("{n} missing"));
        assert!(pos("systemctl revert \"user-$__u.slice\"") < pos("userdel anvil-fjr-1"));
        // Without [ci_resources]: systemd's default.
        assert!(decl(&c, true).render_apply().contains("CPUWeight=100"));
    }

    #[test]
    fn sandbox_limits_come_from_config() {
        let d = eph(&cfg(""), false, true).minter_content();
        assert!(
            d.contains("--cpus '2' \\\n  --memory '4g' --pids-limit '2048'"),
            "{d}"
        );
        let c = cfg("sandbox_cpus = \"1.5\"\nsandbox_memory = \"2g\"\nsandbox_pids = 512\nsandbox_disk = \"20G\"");
        let m = eph(&c, false, true).minter_content();
        assert!(
            m.contains("--cpus '1.5' \\\n  --memory '2g' --pids-limit '512'"),
            "{m}"
        );
        assert!(decl(&c, true)
            .render_apply()
            .contains("forgejo runner slot 1 sandbox volume (20G)"));
    }
}
