//! `[github_runner] mode = "ephemeral"` (GR9; docs/design/github-actions-runner.md §4, §10).
//!
//! Per runner and slot, a root minter unit signs a GitHub App JWT, trades it
//! for an installation token, mints a one-job JIT runner config and runs it
//! in a fresh sysbox sandbox (own dockerd inside, no host Docker socket, root
//! inside = unprivileged on the host). The sandbox's Docker data and `_work`
//! live on the slot's capped loop volume, re-made before every job; the
//! sandbox is removed with its volumes (`rm -fv`, spike) after the job.
//!
//! Secrets: the App key is a `Computed` 0600 file (never in `diff`); the JWT
//! and installation token reach curl on stdin (`-K -`), the JIT config
//! reaches the sandbox through a 0600 env file deleted right after `docker
//! create`. Config values reaching bash go through [`shell_escape`].

use base64::Engine;

use crate::config::schema::{size_bytes, GithubRunnerSection};
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_FAILED,
};
use crate::escape::shell_escape;

use super::github_runner::{loop_image, IMAGE_DIR};
use super::runner_common::Download;
use super::{apt_install, ci_resources, rootless_sandbox, APT_LOCK_TIMEOUT};

pub const KEY_PATH: &str = "/etc/anvil/github-runner/app.pem";
pub const IMAGE_CTX: &str = "/etc/anvil/github-runner/image";
pub const IMAGE_REPO: &str = "anvil-github-runner";
/// actions/runner's official image, v2.338.2 (the v1 pin), multi-arch index
/// digest read from ghcr.io on 2026-11-02. Ubuntu 24.04 + the static Docker
/// engine (dockerd, containerd, runc) in `/usr/bin`.
pub const BASE_IMAGE: &str = "ghcr.io/actions/actions-runner:2.338.2@sha256:759a1d94a15b05941aba5196974ff43fe15b4cbba29b694b35cbc32a1166b232";
/// `${__ra}` is `amd64` or `arm64` ([`Download`]).
pub const SYSBOX_URL: &str =
    "https://downloads.nestybox.com/sysbox/releases/v0.7.1/sysbox-ce_0.7.1-0.linux_${__ra}.deb";
/// amd64, arm64; as in the v0.7.1 release notes and GitHub asset digests.
pub const SYSBOX_SHA256: (&str, &str) = (
    "9d6d5484f980d0a17f86c492c1262015c2afb66280bdb97215b79fde6a0261c5",
    "04ca894ae0b53f0fa54eaacc173ce40363c9a95ea5450f773716a84ef650a69b",
);

/// Ubuntu 24.04+ confines fusermount3, which denies sysbox-fs its mount
/// and, without the `umount` rule, the unmount when a sandbox ends (leaked mounts).
pub const AA_PROFILE: &str = "/etc/apparmor.d/fusermount3";
pub const AA_LOCAL: &str = "/etc/apparmor.d/local/fusermount3";
pub const AA_RULE: &str =
    "mount fstype=fuse options=(rw,nosuid,nodev) sysboxfs -> /var/lib/sysboxfs/*/, \
                           umount /var/lib/sysboxfs/*/,";

// --- sandbox_runtime = "podman": rootful Podman per job, rootless inside.

/// Rootful Podman names local builds `localhost/<repo>`; `image ls`/`ps`
/// print that form, so build, inspect, create and prune all use it.
pub const PODMAN_IMAGE_REPO: &str = "localhost/anvil-github-runner";
/// The runner's container hooks for rootless Podman (`services:`/`container:`).
pub const HOOKS_URL: &str = "https://registry.npmjs.org/@universityofwarwick/github-runner-podman-hooks/-/github-runner-podman-hooks-0.9.0.tgz";
pub const HOOKS_SHA256: &str = "4a60032392ea2832dc7782d0cc37341d73bb3687fb54ef53c96fa30971cea161";
/// `--userns=auto` takes host ids from the `containers` entries; root inside
/// a sandbox maps to 2147483647+ (never a real host uid).
pub const SUBID_FILES: [&str; 2] = ["/etc/subuid", "/etc/subgid"];
pub const SUBID_LINE: &str = "containers:2147483647:2147483648";
/// Ubuntu: Podman's `containers-default` denies the inner Podman's mounts and
/// user namespaces (spike); the sandbox runs under this profile instead
/// wherever AppArmor is on.
pub const AA_SANDBOX: &str = "anvil-github-runner-sandbox";
pub const AA_SANDBOX_PATH: &str = "/etc/apparmor.d/anvil-github-runner-sandbox";
/// Podman's `containers-default` template with `deny mount` lifted and
/// `userns` allowed: the inner rootless Podman mounts overlay/proc/sysfs/
/// tmpfs/binds in its own user namespace (the kernel still bounds those to
/// what that namespace owns). Ubuntu live test: crun needs `mqueue`
/// and signals from Ubuntu's `crun` profile; netavark writes
/// `/proc/sys/net/**` in the job's own netns (denies hold even in complain).
pub const AA_SANDBOX_PROFILE: &str =
    "# Managed by anvil — AppArmor profile for Podman runner sandboxes\n\
abi <abi/4.0>,\n\
include <tunables/global>\n\
\n\
profile anvil-github-runner-sandbox flags=(attach_disconnected,mediate_deleted) {\n\
\x20 include <abstractions/base>\n\
\x20 network,\n\
\x20 capability,\n\
\x20 file,\n\
\x20 mount,\n\
\x20 umount,\n\
\x20 remount,\n\
\x20 pivot_root,\n\
\x20 userns,\n\
\x20 mqueue,\n\
\x20 signal (receive) peer=unconfined,\n\
\x20 signal (receive) peer=crun,\n\
\x20 signal (send,receive) peer=anvil-github-runner-sandbox,\n\
\x20 ptrace (trace,read,tracedby,readby) peer=anvil-github-runner-sandbox,\n\
\x20 deny @{PROC}/* w,\n\
\x20 deny @{PROC}/{[^1-9],[^1-9][^0-9],[^1-9s][^0-9y][^0-9s],[^1-9][^0-9][^0-9][^0-9/]*}/** w,\n\
\x20 deny @{PROC}/sys/[^kn]** w,\n\
\x20 deny @{PROC}/sys/n[^e]** w,\n\
\x20 deny @{PROC}/sys/ne[^t]** w,\n\
\x20 deny @{PROC}/sys/net[^/]** w,\n\
\x20 deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,\n\
\x20 deny @{PROC}/sysrq-trigger rwklx,\n\
\x20 deny @{PROC}/kcore rwklx,\n\
\x20 deny /sys/[^f]*/** wklx,\n\
\x20 deny /sys/f[^s]*/** wklx,\n\
\x20 deny /sys/fs/[^c]*/** wklx,\n\
\x20 deny /sys/fs/c[^g]*/** wklx,\n\
\x20 deny /sys/fs/cg[^r]*/** wklx,\n\
\x20 deny /sys/firmware/** rwklx,\n\
\x20 deny /sys/kernel/security/** rwklx,\n\
}\n";

pub const CONTAINERFILE: &str = "# Managed by anvil — Podman sandbox image for ephemeral GitHub runners\n\
FROM @BASE@\n\
USER root\n\
ENV ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=0\n\
# The base ships static docker/dockerd; `docker` here is podman-docker.\n\
# newuidmap/newgidmap get file caps: setuid fails inside the user namespace.\n\
RUN rm -f /usr/bin/docker /usr/bin/dockerd && apt-get update \\\n\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\\n\
      podman podman-docker netavark aardvark-dns iptables fuse-overlayfs uidmap passt \\\n\
      slirp4netns catatonit libcap2-bin@PACKAGES@ \\\n\
 && rm -rf /var/lib/apt/lists/* \\\n\
 && chmod 0755 /usr/bin/newuidmap /usr/bin/newgidmap \\\n\
 && setcap cap_setuid=ep /usr/bin/newuidmap && setcap cap_setgid=ep /usr/bin/newgidmap\n\
# Inner rootless Podman for `runner`: a sub-range of the sandbox's 65536 ids.\n\
RUN sed -i '/^runner:/d' /etc/subuid /etc/subgid \\\n\
 && echo 'runner:2000:63000' >>/etc/subuid && echo 'runner:2000:63000' >>/etc/subgid \\\n\
 && touch /etc/containers/nodocker \\\n\
 && printf 'unqualified-search-registries = [\"docker.io\"]\\n' >/etc/containers/registries.conf.d/99-anvil.conf\n\
RUN curl -fsSL --proto '=https' -o /tmp/hooks.tgz @HOOKS_URL@ \\\n\
 && echo '@HOOKS_SHA256@  /tmp/hooks.tgz' | sha256sum -c - \\\n\
 && mkdir -p /opt/podman-hooks && tar -xzf /tmp/hooks.tgz -C /opt/podman-hooks --strip-components=1 \\\n\
 && rm /tmp/hooks.tgz \\\n\
 && printf 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n' >>/home/runner/.env\n\
COPY containers.conf /home/runner/.config/containers/containers.conf\n\
RUN chown -R runner:runner /home/runner/.config /home/runner/.env\n\
ENV ACTIONS_RUNNER_CONTAINER_HOOKS=/opt/podman-hooks/packages/podman/dist/index.js\n\
COPY --chmod=0755 podman-wrapper /usr/local/bin/podman\n\
COPY --chmod=0755 entrypoint.sh /usr/local/bin/anvil-entrypoint\n\
ENTRYPOINT [\"/usr/local/bin/anvil-entrypoint\"]\n";

/// The inner rootless Podman, as in `quay.io/podman/stable`; netavark
/// (the Ubuntu 24.04 base defaults to CNI).
pub const INNER_CONTAINERS_CONF: &str =
    "# Managed by anvil — nested rootless Podman in the runner sandbox\n\
[containers]\n\
netns = \"host\"\n\
userns = \"host\"\n\
ipcns = \"host\"\n\
utsns = \"host\"\n\
cgroupns = \"host\"\n\
cgroups = \"disabled\"\n\
log_driver = \"k8s-file\"\n\
volumes = [\"/proc:/proc\"]\n\
default_sysctls = []\n\
\n\
[network]\n\
network_backend = \"netavark\"\n\
\n\
[engine]\n\
cgroup_manager = \"cgroupfs\"\n\
events_logger = \"file\"\n\
helper_binaries_dir = [\"/usr/lib/podman\", \"/usr/libexec/podman\", \"/usr/bin\"]\n";

/// The hooks run podman with an empty environment, where `newuidmap` and the
/// rootless runtime dir are not found.
pub const PODMAN_WRAPPER: &str = "#!/bin/sh\n\
# Managed by anvil — podman with the environment the runner hooks drop\n\
export PATH=\"${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}\"\n\
export HOME=\"${HOME:-/home/runner}\"\n\
export XDG_RUNTIME_DIR=\"${XDG_RUNTIME_DIR:-/run/user/1001}\"\n\
exec /usr/bin/podman \"$@\"\n";

/// Root inside the sandbox; the job runs as `runner` with rootless Podman.
pub const PODMAN_ENTRYPOINT: &str = r#"#!/bin/bash
# Managed by anvil — sandbox entrypoint: rootless Podman, then exactly one job.
set -euo pipefail
chown runner:runner /home/runner/_work /home/runner/.local/share/containers
install -d -m 0700 -o runner -g runner /run/user/1001
cd /home/runner
exec runuser -u runner -- env XDG_RUNTIME_DIR=/run/user/1001 bash -c '
  # The hooks mount this socket into container: jobs (in place of docker.sock).
  podman system service --time=0 "unix://$XDG_RUNTIME_DIR/podman/podman.sock" &
  # No systemd in the sandbox: run health checks here (services: wait on them).
  while sleep 2; do
    for c in $(podman ps -q --filter health=starting --filter health=unhealthy 2>/dev/null); do
      podman healthcheck run "$c" >/dev/null 2>&1 || true
    done
  done &
  exec ./run.sh'
"#;

/// `sandbox_runtime = "docker-rootless"`: the user unit each slot
/// user's manager runs (started by the minter, never enabled).
pub const USER_UNIT: &str = "anvil-ghr-sandbox-docker.service";
pub const USER_UNIT_PATH: &str = "/etc/systemd/user/anvil-ghr-sandbox-docker.service";
pub const IMAGE_TAR: &str = "/var/lib/anvil-ci/github-runner-sandbox.tar";
pub const IMAGE_TAR_TAG: &str = "/var/lib/anvil-ci/github-runner-sandbox.tag";

/// The system user owning a docker-rootless slot's engine (validated ≤ 32 chars).
pub fn slot_user(name: &str, i: u32) -> String {
    format!("anvil-ghr-{}", slot(name, i))
}

pub fn slot(name: &str, i: u32) -> String {
    format!("{name}-{i}")
}

pub fn unit_name(name: &str, i: u32) -> String {
    format!("anvil-github-runner-{}.service", slot(name, i))
}

pub fn unit_path(name: &str, i: u32) -> String {
    format!("/etc/systemd/system/{}", unit_name(name, i))
}

/// The sandbox container of a slot (one at a time).
pub fn container(name: &str, i: u32) -> String {
    format!("anvil-github-runner-{}", slot(name, i))
}

pub fn image_path(name: &str, i: u32) -> String {
    format!("{IMAGE_DIR}/github-runner-{}.img", slot(name, i))
}

pub fn mount_dir(name: &str, i: u32) -> String {
    format!("{IMAGE_DIR}/github-runner-{}.mnt", slot(name, i))
}

/// Set by apply when a slot's unit changed while its sandbox existed; the
/// minter restarts the slot between jobs.
pub fn restart_flag(name: &str, i: u32) -> String {
    format!("/run/{}.restart", container(name, i))
}

pub fn minter_path(name: &str) -> String {
    format!("/usr/local/libexec/anvil/github-runner-mint-{name}.sh")
}

pub const DOCKERFILE: &str = "# Managed by anvil — sandbox image for ephemeral GitHub runners\n\
FROM @BASE@\n\
USER root\n\
# The runner's stdout goes to the journal: its terminal lines, not the diag trace.\n\
ENV ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=0\n\
# The base image ships dockerd; it needs iptables for its bridge network.\n\
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables@PACKAGES@ \\\n\
 && rm -rf /var/lib/apt/lists/*\n\
COPY entrypoint.sh /usr/local/bin/anvil-entrypoint\n\
ENTRYPOINT [\"/usr/local/bin/anvil-entrypoint\"]\n";

/// Runs as root inside the sandbox (an unprivileged uid on the host). The
/// runner reads its JIT config from `ACTIONS_RUNNER_INPUT_JITCONFIG`
/// (actions/runner `CommandSettings.GetJitConfig`), so it is never in argv.
pub const ENTRYPOINT: &str = r#"#!/bin/bash
# Managed by anvil — sandbox entrypoint: own dockerd, then exactly one job.
set -euo pipefail
chown runner:runner /home/runner/_work
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
cd /home/runner
exec runuser -u runner -- ./run.sh
"#;

/// Minter for one runner; `<slot> [once|cleanup]`. Without a mode it loops:
/// one job per `once` child (a fresh bash, so `set -e` holds inside, and a
/// rewritten script, i.e. new image or limits, takes effect from the next
/// job), with exponential backoff (10 s → 10 min) after a failed mint or
/// sandbox. Between jobs it exits for a restart [`restart_flag`] asked for.
const MINTER: &str = r#"#!/bin/bash
# Managed by anvil — mints one-job GitHub runners into sandboxes.
# Tokens reach curl on stdin and the sandbox via a 0600 env file; never argv.
# One brace group, parsed whole before it runs: apply rewrites this file in
# place while a job runs, and bash would read on into the new bytes.
{
set -euo pipefail
umask 077
slot=$1
name=@NAME@-$slot
ctr=anvil-github-runner-$name
img=@IMAGE_DIR@/github-runner-$name.img
mnt=@MNT@
ids=@IMAGE_DIR@/github-runner-$name.ids

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# POST to the GitHub API: <bearer> <path> <json>. The bearer goes in a curl
# config on stdin, so it is never in argv (ps) or in a file.
gh_post() {
  printf 'header = "Authorization: Bearer %s"\n' "$1" |
    curl -fsS --proto '=https' --connect-timeout 10 --max-time 60 -K - -X POST \
      -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
      -H 'Content-Type: application/json' --data-binary "$3" "https://api.github.com$2"
}

# DELETE <bearer> <path>; prints the HTTP status.
gh_delete() {
  printf 'header = "Authorization: Bearer %s"\n' "$1" |
    curl -sS --proto '=https' --connect-timeout 10 --max-time 60 -K - -X DELETE -o /dev/null \
      -w '%{http_code}' -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' "https://api.github.com$2"
}

# An installation token, from a JWT signed with the App key.
mint_token() {
  local now jwt
  now=$(date +%s)
  jwt=$(printf '{"alg":"RS256","typ":"JWT"}' | b64url).$(printf '{"iat":%d,"exp":%d,"iss":%d}' \
    $((now - 60)) $((now + 540)) @APP_ID@ | b64url)
  jwt=$jwt.$(printf '%s' "$jwt" | openssl dgst -sha256 -sign @KEY@ -binary | b64url)
  gh_post "$jwt" /app/installations/@INSTALLATION_ID@/access_tokens '{}' | jq -er .token
}

@SB_FNS@cleanup() {
  @SB_RM@
  ! mountpoint -q "$mnt" || umount "$mnt"
  # A runner that never got a job stays listed (offline) in the org; one that
  # ran its job removed itself (404). On disk, so a reboot mid-job still deletes it.
  # Without a token (offline) the ids stay for the next cleanup.
  if [ -s "$ids" ] && dtok=$(mint_token 2>/dev/null); then
    keep=
    while read -r id; do
      case "$(gh_delete "$dtok" /orgs/@ORG@/actions/runners/"$id" 2>/dev/null || true)" in
        204 | 404) ;;
        *) keep+="$id"$'\n' ;;
      esac
    done <"$ids"
    unset dtok
    printf '%s' "$keep" >"$ids"
  fi
}

case "${2:-loop}" in
  cleanup) cleanup; exit 0 ;;
  once) ;;
  *)
    delay=10
    while :; do
      # Apply changed the unit while the sandbox ran: restart now, between jobs.
      if [ -e "/run/$ctr.restart" ]; then rm -f "/run/$ctr.restart"; exit 0; fi
      if "$0" "$slot" once; then
        delay=10
      else
        echo "anvil: runner $name: mint or sandbox failed; retrying in ${delay}s" >&2
        sleep "$delay"
        delay=$(( delay * 2 > 600 ? 600 : delay * 2 ))
      fi
    done ;;
esac

cleanup
mkfs.ext4 -q -F -m 0 "$img"
install -d -m 0700 "$mnt"
mount -o loop,nodev,nosuid "$img" "$mnt"
install -d -m 0755 "$mnt/@DATA@" "$mnt/work"
@SB_UP@
tok=$(mint_token)
# JIT runners get no default labels: add what config.sh would.
case "$(uname -m)" in aarch64 | arm64) arch=ARM64 ;; *) arch=X64 ;; esac
body=$(jq -nc --arg n "$name-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')" \
  --argjson g @GROUP_ID@ --argjson l @LABELS@ --arg a "$arch" \
  '{name: $n, runner_group_id: $g, work_folder: "_work",
    labels: (["self-hosted", "Linux", $a] + $l | unique_by(ascii_downcase))}')
env=$(mktemp -p /run)
trap 'rm -f "$env"' EXIT
jit=$(gh_post "$tok" /orgs/@ORG@/actions/runners/generate-jitconfig "$body")
printf '%s' "$jit" | jq -er .runner.id >>"$ids"
printf '%s' "$jit" | jq -er '"ACTIONS_RUNNER_INPUT_JITCONFIG=" + .encoded_jit_config' >"$env"
unset tok jit
@SB_ENV@# --init: a reaping PID 1; orphaned zombies would count against --pids-limit.
@AA@@ENGINE@ create --name "$ctr" --init @SANDBOX_OPTS@ @CGROUP@--cpus @CPUS@ --memory @MEMORY@ \
  --pids-limit @PIDS@ --env-file "$env" \
  -v "$mnt/@DATA@:@DATA_DIR@" -v "$mnt/work:/home/runner/_work@U@" @IMAGE@ >/dev/null
rm -f "$env"
rc=0
@ENGINE@ start -a "$ctr" || rc=$?
cleanup
exit "$rc"
}
"#;

pub(super) fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(*b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// `packages`: `sandbox_packages`, validated Debian names.
pub fn dockerfile(packages: &[String]) -> String {
    DOCKERFILE
        .replace("@BASE@", BASE_IMAGE)
        .replace("@PACKAGES@", &extra_packages(packages))
}

fn extra_packages(packages: &[String]) -> String {
    packages
        .iter()
        .map(|p| format!(" {}", shell_escape(p)))
        .collect()
}

/// `anvil-github-runner:<hash>`: a content hash of the build context, so a
/// changed Dockerfile or entrypoint is a new tag, i.e. drift and a rebuild.
pub fn image_tag(packages: &[String]) -> String {
    let ctx = format!("{}\0{ENTRYPOINT}", dockerfile(packages));
    format!("{IMAGE_REPO}:{:016x}", fnv1a(ctx.as_bytes()))
}

pub fn containerfile(packages: &[String]) -> String {
    CONTAINERFILE
        .replace("@BASE@", BASE_IMAGE)
        .replace("@PACKAGES@", &extra_packages(packages))
        .replace("@HOOKS_URL@", &shell_escape(HOOKS_URL))
        .replace("@HOOKS_SHA256@", HOOKS_SHA256)
}

/// Build context of a sandbox image: (file name, content, mode).
pub fn context(podman: bool, packages: &[String]) -> Vec<(&'static str, String, &'static str)> {
    if !podman {
        return vec![
            ("Dockerfile", dockerfile(packages), "0644"),
            ("entrypoint.sh", ENTRYPOINT.into(), "0755"),
        ];
    }
    vec![
        ("Containerfile", containerfile(packages), "0644"),
        ("entrypoint.sh", PODMAN_ENTRYPOINT.into(), "0755"),
        ("containers.conf", INNER_CONTAINERS_CONF.into(), "0644"),
        ("podman-wrapper", PODMAN_WRAPPER.into(), "0755"),
    ]
}

/// As [`image_tag`], under [`PODMAN_IMAGE_REPO`], hashing all four files.
pub fn podman_image_tag(packages: &[String]) -> String {
    let ctx: Vec<String> = context(true, packages).into_iter().map(|f| f.1).collect();
    format!(
        "{PODMAN_IMAGE_REPO}:{:016x}",
        fnv1a(ctx.join("\0").as_bytes())
    )
}

pub struct Ephemeral<'a> {
    pub cfg: &'a GithubRunnerSection,
    pub docker_distro: bool,
    pub docker: Option<&'a crate::config::schema::DockerSection>,
    pub in_ci_slice: bool,
    /// CPUWeight of each docker-rootless slot user's slice.
    pub ci_cpu_weight: u32,
    pub engine: crate::config::Engine,
}

impl Ephemeral<'_> {
    /// `sandbox_runtime`, defaulting by host engine.
    fn runtime(&self) -> &str {
        self.cfg.sandbox_runtime(self.engine)
    }

    pub fn podman(&self) -> bool {
        self.runtime() == "podman"
    }

    /// Each slot's sandbox in its own user's rootless dockerd.
    pub fn rootless(&self) -> bool {
        self.runtime() == "docker-rootless"
    }

    fn slot_users(&self) -> Vec<String> {
        self.slots().map(|(n, i)| slot_user(n, i)).collect()
    }

    pub fn user_unit_content(&self) -> String {
        rootless_sandbox::user_unit("github runner", &self.slot_users())
    }

    /// The host engine that runs the sandboxes.
    fn eng(&self) -> &'static str {
        if self.podman() {
            "podman"
        } else {
            "docker"
        }
    }

    fn repo(&self) -> &'static str {
        if self.podman() {
            PODMAN_IMAGE_REPO
        } else {
            IMAGE_REPO
        }
    }

    pub fn tag(&self) -> String {
        let p = &self.cfg.sandbox_packages;
        if self.podman() {
            podman_image_tag(p)
        } else {
            image_tag(p)
        }
    }

    /// Podman keeps no build cache, only dangling intermediate images.
    fn prune(&self) -> &'static str {
        if self.podman() {
            "podman image prune -f"
        } else {
            "docker builder prune -af"
        }
    }

    fn slots(&self) -> impl Iterator<Item = (&str, u32)> + '_ {
        let n = self.cfg.capacity();
        self.cfg
            .runners
            .keys()
            .flat_map(move |name| (1..=n).map(move |i| (name.as_str(), i)))
    }

    pub fn minter_content(&self, name: &str) -> String {
        let c = self.cfg;
        let r = &c.runners[name];
        let org = r.url.trim_start_matches("https://github.com/");
        // Labels are validated to [A-Za-z0-9._-]+, so plain quoting is valid JSON.
        let labels = format!(
            "[{}]",
            r.labels
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
        let num = |v: Option<u64>| shell_escape(&v.unwrap_or_default().to_string());
        // Podman: root inside = an unprivileged host uid (`--userns=auto`),
        // rootless Podman inside on the slot volume (`:U` chowns it).
        let (aa, opts, data, data_dir, u) = if self.rootless() {
            (
                String::new(),
                "--privileged".to_string(),
                "docker",
                "/var/lib/docker",
                "",
            )
        } else if self.podman() {
            (
                format!(
                    "aa=\nif aa-enabled -q 2>/dev/null; then aa=--security-opt=apparmor={}; fi\n",
                    shell_escape(AA_SANDBOX)
                ),
                "--userns=auto:size=65536 --device /dev/fuse --device /dev/net/tun \\\n  \
                 --security-opt unmask=ALL --security-opt label=disable ${aa:+\"$aa\"}"
                    .to_string(),
                "containers",
                "/home/runner/.local/share/containers:U",
                ":U",
            )
        } else {
            (
                String::new(),
                format!("--runtime={}", shell_escape(self.runtime())),
                "docker",
                "/var/lib/docker",
                "",
            )
        };
        let (mnt, fns, rm, up, env, eng, cgroup) = if self.rootless() {
            (
                "/var/lib/anvil-ghr-$name/vol",
                rootless_sandbox::fns("anvil-ghr-$name", IMAGE_TAR),
                rootless_sandbox::cleanup(USER_UNIT, "@IMAGE_DIR@/github-runner-\"$name\".mnt"),
                rootless_sandbox::up(USER_UNIT),
                rootless_sandbox::ENV_OWNER,
                "ud",
                String::new(),
            )
        } else {
            (
                "@IMAGE_DIR@/github-runner-$name.mnt",
                String::new(),
                "@ENGINE@ rm -fv \"$ctr\" >/dev/null 2>&1 || true".to_string(),
                String::new(),
                "",
                self.eng(),
                cgroup,
            )
        };
        MINTER
            .replace("@MNT@", mnt)
            .replace("@SB_FNS@", &fns)
            .replace("@SB_RM@", &rm)
            .replace("@SB_UP@", &up)
            .replace("@SB_ENV@", env)
            .replace("@AA@", &aa)
            .replace("@SANDBOX_OPTS@", &opts)
            .replace("@DATA_DIR@", data_dir)
            .replace("@DATA@", data)
            .replace("@U@", u)
            .replace("@ENGINE@", eng)
            .replace("@NAME@", &shell_escape(name))
            .replace("@IMAGE_DIR@", &shell_escape(IMAGE_DIR))
            .replace("@KEY@", &shell_escape(KEY_PATH))
            .replace("@APP_ID@", &num(c.app_id))
            .replace("@INSTALLATION_ID@", &num(c.installation_id))
            .replace("@GROUP_ID@", &num(c.runner_group_id))
            .replace("@LABELS@", &shell_escape(&labels))
            .replace("@ORG@", &shell_escape(org))
            .replace("@CGROUP@", &cgroup)
            .replace("@CPUS@", &shell_escape(c.sandbox_cpus()))
            .replace("@MEMORY@", &shell_escape(c.sandbox_memory()))
            .replace("@PIDS@", &shell_escape(&c.sandbox_pids().to_string()))
            .replace("@IMAGE@", &shell_escape(&self.tag()))
    }

    /// Root, no filesystem namespacing: the minter mounts the slot volume,
    /// which dockerd (in the host namespace) must see.
    pub fn unit_content(&self, name: &str, i: u32) -> String {
        let script = minter_path(name);
        let slice = if self.in_ci_slice {
            format!("Slice={}\n", ci_resources::SLICE)
        } else {
            String::new()
        };
        // Podman has no daemon to wait for, and the sandbox is this unit's
        // child (conmon): NoNewPrivileges would reach the job and the kernel
        // would ignore newuidmap's file caps, so rootless Podman inside fails
        // (live test). `--userns=auto` is the isolation.
        let (after, requires, nnp) = if self.podman() {
            ("", "", "")
        } else if self.rootless() {
            // Root's Docker only built the image; the slot user's engine runs the sandbox.
            ("", "", "NoNewPrivileges=yes\n")
        } else {
            (
                " docker.service sysbox.service",
                "Requires=docker.service\n",
                "NoNewPrivileges=yes\n",
            )
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=GitHub Actions ephemeral runner {name} slot {i} (anvil)\n\
             After=network-online.target{after}\n\
             Wants=network-online.target\n\
             {requires}\
             \n\
             [Service]\n\
             ExecStart={script} {i}\n\
             ExecStopPost={script} {i} cleanup\n\
             {slice}\
             Restart=always\n\
             RestartSec=10\n\
             TimeoutStopSec=2min\n\
             {nnp}\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        )
    }

    pub(super) fn tools() -> ManagedCommand {
        ManagedCommand::new(
            "curl, jq, openssl and mkfs.ext4 for the minter",
            "command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1 \
             && command -v openssl >/dev/null 2>&1 && command -v mkfs.ext4 >/dev/null 2>&1",
            apt_install(&["curl", "ca-certificates", "jq", "openssl", "e2fsprogs"]),
        )
    }

    /// Detect: docker knows `runtime` (exact name, as JSON key).
    fn runtime_present(runtime: &str) -> String {
        format!(
            "case \"$(docker info --format '{{{{json .Runtimes}}}}' 2>/dev/null)\" in \
             *{}*) true ;; *) false ;; esac",
            shell_escape(&format!("\"{runtime}\""))
        )
    }

    /// The install behind a `sandbox_runtime` value; a new runtime adds an arm.
    fn runtime_install(runtime: &str) -> Option<ManagedCommand> {
        match runtime {
            "sysbox-runc" => Some(Self::sysbox(runtime)),
            _ => None,
        }
    }

    /// Pinned sysbox-ce .deb, verified before install. Never removed on rollback.
    fn sysbox(runtime: &str) -> ManagedCommand {
        ManagedCommand::new(
            format!("sysbox-ce 0.7.1 installed (docker runtime {runtime})"),
            Self::runtime_present(runtime),
            format!(
                "{download}\
                 DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} install -y -qq \"$__tmp/sysbox.deb\"\n\
                 rm -rf \"$__tmp\"\n\
                 __ghr_restart_all=1",
                download = Download {
                    module: "github_runner",
                    arch_names: ("amd64", "arm64"),
                    sha256: SYSBOX_SHA256,
                    url: &format!("\"{SYSBOX_URL}\""),
                    file: "sysbox.deb",
                    what: "sysbox-ce package",
                }
                .script(),
            ),
        )
    }

    /// Host `containers:` id range for `--userns=auto`, appended to
    /// [`SUBID_FILES`] (original backed up once); an existing range is kept.
    fn subids() -> ManagedCommand {
        let files = SUBID_FILES.map(shell_escape).join(" ");
        ManagedCommand::new(
            format!("{SUBID_LINE} in /etc/subuid and /etc/subgid (podman --userns=auto)"),
            SUBID_FILES
                .map(|f| format!("grep -qs '^containers:' {}", shell_escape(f)))
                .join(" && "),
            format!(
                "for __f in {files}; do\n\
                 \x20 ! grep -qs '^containers:' \"$__f\" || continue\n\
                 \x20 if [ -e \"$__f\" ]; then\n\
                 \x20\x20 [ -e \"$__f{BACKUP_SUFFIX}\" ] || __anvil_created \"$__f\" || cp -a \"$__f\" \"$__f{BACKUP_SUFFIX}\"\n\
                 \x20 else\n\
                 \x20\x20 __anvil_remember \"$__f\"; : >\"$__f\"; chmod 0644 \"$__f\"\n\
                 \x20 fi\n\
                 \x20 {{ [ ! -s \"$__f\" ] || [ -z \"$(tail -c1 \"$__f\")\" ] || echo; printf '%s\\n' {line}; }} >>\"$__f\"\n\
                 done",
                line = shell_escape(SUBID_LINE),
            ),
        )
    }

    /// Appends [`AA_RULE`] to the profile's local include (existing
    /// lines kept, original backed up once) and reloads the profile when
    /// AppArmor is on; a rejected reload undoes the append. A host without
    /// the profile (Debian 13) is converged as is.
    fn apparmor_rule() -> ManagedCommand {
        let (profile, local, rule) = (
            shell_escape(AA_PROFILE),
            shell_escape(AA_LOCAL),
            shell_escape(AA_RULE),
        );
        ManagedCommand::new(
            "fusermount3 AppArmor profile allows the sysbox-fs mount",
            format!("! grep -qs 'local/fusermount3' {profile} || grep -qsxF {rule} {local}"),
            format!(
                "__aa={local}\n\
                 __aa_prev=$(mktemp -p \"$__rundir\")\n\
                 if [ -e \"$__aa\" ]; then\n\
                 \x20 cp -a \"$__aa\" \"$__aa_prev\"\n\
                 \x20 [ -e \"$__aa{BACKUP_SUFFIX}\" ] || __anvil_created \"$__aa\" || cp -a \"$__aa\" \"$__aa{BACKUP_SUFFIX}\"\n\
                 else\n\
                 \x20 rm -f \"$__aa_prev\"\n\
                 \x20 __anvil_remember \"$__aa\"\n\
                 \x20 mkdir -p \"$(dirname \"$__aa\")\"\n\
                 \x20 : >\"$__aa\"\n\
                 \x20 chmod 0644 \"$__aa\"\n\
                 fi\n\
                 {{ [ ! -s \"$__aa\" ] || [ -z \"$(tail -c1 \"$__aa\")\" ] || echo; printf '%s\\n' {rule}; }} >>\"$__aa\"\n\
                 if aa-enabled -q 2>/dev/null && ! apparmor_parser -r {profile}; then\n\
                 \x20 if [ -e \"$__aa_prev\" ]; then mv -f \"$__aa_prev\" \"$__aa\"; else rm -f \"$__aa\"; __anvil_forget \"$__aa\"; fi\n\
                 \x20 printf '{failed} github_runner: apparmor_parser rejected %s; reverted\\n' {local}\n\
                 \x20 exit 1\n\
                 fi\n\
                 rm -f \"$__aa_prev\"",
                failed = MARK_FAILED,
            ),
        )
    }

    /// Builds from a private temp copy of the managed context (commands run
    /// before the engine writes files), then prunes the build cache: every
    /// rebuild trigger (base pin, `sandbox_packages`) invalidates the one
    /// `RUN` layer, so kept cache would never be reused.
    fn image(&self) -> ManagedCommand {
        let ctx = context(self.podman(), &self.cfg.sandbox_packages);
        build_image(self.eng(), &self.tag(), &ctx, self.prune())
    }

    /// Older `anvil-github-runner` tags no container (running or
    /// stopped) uses, once the current tag exists. Its own command, so a tag
    /// a slot still held at build time goes on a later apply.
    fn superseded_images(&self) -> ManagedCommand {
        superseded_images(self.eng(), self.repo(), &self.tag())
    }

    fn service_active(name: &str, i: u32) -> ManagedCommand {
        let unit = shell_escape(&unit_name(name, i));
        ManagedCommand::new(
            format!("runner {} minter active", slot(name, i)),
            format!("systemctl is-active --quiet {unit}"),
            format!("__ghr_restart+=({unit})"),
        )
    }

    fn rollback_first(&self) -> String {
        let mut s = String::from("\n# rollback ephemeral github runner slots\n");
        for (name, i) in self.slots() {
            let unit = shell_escape(&unit_name(name, i));
            let mnt = shell_escape(&mount_dir(name, i));
            s.push_str(&format!(
                "systemctl disable --now {unit} 2>/dev/null || true\n\
                 rm -f /etc/systemd/system/multi-user.target.wants/{unit}\n\
                 {eng} rm -fv {ctr} >/dev/null 2>&1 || true\n\
                 ! mountpoint -q {mnt} || umount {mnt}\n",
                eng = self.eng(),
                ctr = shell_escape(&container(name, i)),
            ));
            if self.rootless() {
                s.push_str(&rootless_sandbox::umount(&slot_user(name, i)));
            }
        }
        if self.podman() {
            // Unloaded while its file exists; no sandbox uses it any more.
            s.push_str(&format!(
                "if [ -f {p} ] && aa-enabled -q 2>/dev/null; then apparmor_parser -R {p} >/dev/null 2>&1 || true; fi\n",
                p = shell_escape(AA_SANDBOX_PATH),
            ));
        }
        s
    }

    fn rollback(&self) -> String {
        let (eng, repo) = (self.eng(), self.repo());
        let mut s = format!(
            "\n# rollback ephemeral github runner image and slot volumes\n\
             {eng} image ls {repo} --format '{{{{.Repository}}}}:{{{{.Tag}}}}' 2>/dev/null | \
             xargs -r {eng} image rm >/dev/null 2>&1 || true\n\
             {prune} >/dev/null 2>&1 || true\n",
            prune = self.prune(),
        );
        for (name, i) in self.slots() {
            let img = shell_escape(&image_path(name, i));
            // Stopping ran the cleanup that deleted its runners; leftovers expire at GitHub.
            s.push_str(&format!(
                "rmdir {mnt} 2>/dev/null || true\n\
                 rm -f {ids}\n\
                 if __anvil_created {img}; then\n\
                 \x20 rm -f {img}\n\
                 \x20 __anvil_forget {img}\n\
                 \x20 printf 'CHANGED: %s removed\\n' {img}\n\
                 fi\n",
                mnt = shell_escape(&mount_dir(name, i)),
                ids = shell_escape(&format!("{IMAGE_DIR}/github-runner-{}.ids", slot(name, i))),
            ));
        }
        if self.rootless() {
            s.push_str(&rootless_sandbox::rollback(
                "github_runner",
                IMAGE_TAR,
                IMAGE_TAR_TAG,
                &self.slot_users(),
            ));
        }
        if self.podman() || self.rootless() {
            s.push_str(&format!(
                "rmdir {} 2>/dev/null || true\n",
                shell_escape(IMAGE_DIR)
            ));
            return s;
        }
        s.push_str(&format!(
            // The local include is restored by now; load the profile without it.
            "if [ -f {p} ] && aa-enabled -q 2>/dev/null; then apparmor_parser -r {p} || true; fi\n\
             rmdir {} 2>/dev/null || true\n__docker_restart=1\n",
            shell_escape(IMAGE_DIR),
            p = shell_escape(AA_PROFILE),
        ));
        s
    }

    /// Docker + sysbox, or Podman with its id range and AppArmor profile.
    /// The netavark iptables drop-in (outbound next to ufw) is `[podman]`'s
    /// or `[containers]`', which run first.
    fn engine(&self, decl: Declaration) -> Declaration {
        if self.podman() {
            return decl
                .installs(&["Podman"])
                .command(super::ensure_engine(crate::config::Engine::Podman, false))
                // `podman create --init` runs catatonit; only a Recommends of podman.
                .command(ManagedCommand::new(
                    "catatonit for podman --init",
                    super::dpkg_installed("catatonit"),
                    apt_install(&["catatonit"]),
                ))
                .command(Self::subids())
                .command_file(SUBID_FILES[0])
                .command_file(SUBID_FILES[1])
                .file(ManagedFile::new(
                    AA_SANDBOX_PATH,
                    AA_SANDBOX_PROFILE,
                    "0644",
                    "root:root",
                ));
        }
        if self.rootless() {
            let (cmds, unit) = rootless_sandbox::host(
                "github_runner",
                self.docker_distro,
                &self.slot_users(),
                USER_UNIT_PATH,
                self.user_unit_content(),
                self.ci_cpu_weight,
            );
            let mut decl = decl.installs(&["Docker (rootless)"]);
            for c in cmds {
                decl = decl.command(c);
            }
            return decl.file(unit);
        }
        docker_sandbox_engine(decl, self.docker_distro, self.docker, self.runtime())
    }

    pub fn declaration(&self) -> Declaration {
        let c = self.cfg;
        let key = c.app_key.as_deref().unwrap_or_default().trim_end();
        let decl = self
            .engine(
                Declaration::new("github_runner")
                    .secret(key)
                    .command(Self::tools()),
            )
            .command(self.image())
            .command(self.superseded_images());
        let decl = if self.rootless() {
            decl.command(rootless_sandbox::image_tar(
                IMAGE_TAR,
                IMAGE_TAR_TAG,
                &self.tag(),
            ))
        } else {
            decl
        };
        // A BASE_IMAGE pin bump leaves the old base (where the engine keeps it).
        let mut decl = super::prune_superseded(
            decl,
            "sandbox base",
            self.eng(),
            &format!("printf '%s\\n' {}", shell_escape(BASE_IMAGE)),
        )
        .file(ManagedFile::computed(
            KEY_PATH,
            format!("printf '%s\\n' {}", shell_escape(key)),
            "0600",
            "root:root",
        ));
        for (f, content, mode) in context(self.podman(), &c.sandbox_packages) {
            decl = decl.file(ManagedFile::new(
                format!("{IMAGE_CTX}/{f}"),
                content,
                mode,
                "root:root",
            ));
        }
        let (disk, bytes) = (c.sandbox_disk(), size_bytes(c.sandbox_disk()).unwrap_or(0));
        for (name, i) in self.slots() {
            decl = decl
                .command(loop_image(
                    format!("runner {} sandbox volume ({disk})", slot(name, i)),
                    &image_path(name, i),
                    "sandbox_disk",
                    disk,
                    bytes,
                    "0:0",
                ))
                .command(Self::service_active(name, i))
                .file(ManagedFile::new(
                    unit_path(name, i),
                    self.unit_content(name, i),
                    "0644",
                    "root:root",
                ));
        }
        for name in c.runners.keys() {
            decl = decl.file(ManagedFile::new(
                minter_path(name),
                self.minter_content(name),
                "0700",
                "root:root",
            ));
        }
        // A new minter, image or key takes effect from each slot's next
        // job (the minter re-reads them). Only a slot's own unit change, a
        // stopped slot or a new runtime restarts it, and never over a sandbox:
        // a slot whose sandbox exists gets a flag and restarts between jobs.
        let restarts: String = self
            .slots()
            .map(|(name, i)| {
                let u = shell_escape(&unit_name(name, i));
                let flag = shell_escape(&restart_flag(name, i));
                format!(
                    "if [ \"${{__ghr_restart_all:-0}}\" = 1 ] || __ghr_mine {u} {path}; then \
                     if systemctl is-active --quiet {u} && {busy}; \
                     then touch {flag}; else rm -f {flag}; systemctl restart {u}; fi; fi; ",
                    path = shell_escape(&unit_path(name, i)),
                    // A rootless sandbox is not in root's engine: busy = volume mounted.
                    busy = if self.rootless() {
                        format!(
                            "mountpoint -q {}",
                            shell_escape(&rootless_sandbox::vol(&slot_user(name, i)))
                        )
                    } else {
                        format!(
                            "{} container inspect {} >/dev/null 2>&1",
                            self.eng(),
                            shell_escape(&container(name, i))
                        )
                    },
                )
            })
            .collect();
        let (units, entries): (Vec<String>, Vec<String>) = self
            .slots()
            .map(|(name, i)| {
                (
                    shell_escape(&unit_name(name, i)),
                    // A unit rollback already deleted needs no minter.
                    format!(
                        "{{ [ ! -e {} ] || [ -x {} ]; }}",
                        shell_escape(&unit_path(name, i)),
                        shell_escape(&minter_path(name))
                    ),
                )
            })
            .unzip();
        // Podman: the sandbox profile must parse before it is loaded.
        // A profile the kernel rejects fails the reload (and reverts).
        let (validate, pre, post) = if self.rootless() {
            ("true".to_string(), String::new(), "")
        } else if self.podman() {
            let p = shell_escape(AA_SANDBOX_PATH);
            (
                // Rollback re-runs this guard after removing the profile.
                format!("[ ! -f {p} ] || ! aa-enabled -q 2>/dev/null || apparmor_parser -Q -K {p}"),
                format!(
                    "if [ -f {p} ] && aa-enabled -q 2>/dev/null && ! apparmor_parser -r {p}; then false; else "
                ),
                "fi",
            )
        } else {
            (
                super::docker::daemon_json_validate(),
                super::docker::restart_dockerd(),
                "",
            )
        };
        decl.rollback_first(self.rollback_first())
            .rollback_script(self.rollback())
            .guarded_reload(ReloadGuard {
                describe: "github runner minters".into(),
                validate: format!("{{ {validate}; }} && {}", entries.join(" && ")),
                reload: format!(
                    "{pre}systemctl daemon-reload; systemctl enable {u} >/dev/null 2>&1 || true; \
                     {mine}{restarts}{post}",
                    u = units.join(" "),
                    mine = super::github_runner::MINE_FN,
                ),
            })
    }
}

/// Docker + sysbox (+ the AppArmor rule and daemon.json) for a sandbox host;
/// one owner per host, shared with `forgejo_runner`.
pub(super) fn docker_sandbox_engine(
    decl: Declaration,
    docker_distro: bool,
    docker: Option<&crate::config::schema::DockerSection>,
    runtime: &str,
) -> Declaration {
    let mut decl = decl
        .installs(&["Docker", "sysbox-ce 0.7.1"])
        .command(super::ensure_engine(
            crate::config::Engine::Docker,
            docker_distro,
        ));
    // Before the sysbox .deb, whose postinst restarts dockerd.
    if let Some(g) = super::docker::in_use_guard(docker) {
        decl = decl.command(g);
    }
    if let Some(install) = Ephemeral::runtime_install(runtime) {
        decl = decl.command(install);
    }
    decl.command(Ephemeral::apparmor_rule())
        .command_file(AA_LOCAL)
        // Written after the sysbox .deb, so anvil's content wins.
        .file(super::docker::daemon_json_file(
            docker,
            runtime == "sysbox-runc",
        ))
}

/// Builds `tag` from a private temp copy of the build context `ctx` (file,
/// content, mode; commands run before the engine writes files), then
/// prunes the build cache: every rebuild trigger invalidates the one `RUN`
/// layer, so kept cache would never be reused.
pub(super) fn build_image(
    eng: &str,
    raw: &str,
    ctx: &[(&str, String, &str)],
    prune: &str,
) -> ManagedCommand {
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let tag = shell_escape(raw);
    let mut put: String = ctx
        .iter()
        .map(|(f, c, _)| format!("printf '%s' '{}' | base64 -d >\"$__tmp/{f}\"\n", b64(c)))
        .collect();
    for (f, _, mode) in ctx {
        if *mode == "0755" {
            put.push_str(&format!("chmod 0755 \"$__tmp/{f}\"\n"));
        }
    }
    ManagedCommand::new(
        format!("sandbox image {raw} built"),
        format!("{eng} image inspect {tag} >/dev/null 2>&1"),
        format!(
            "__tmp=$(mktemp -d -p \"$__rundir\")\n\
             {put}\
             {eng} build -q -t {tag} \"$__tmp\" >/dev/null\n\
             rm -rf \"$__tmp\"\n\
             {prune} >/dev/null",
        ),
    )
}

/// Older `repo` tags no container (running or stopped) uses, once
/// `tag` exists. Its own command, so a tag a slot still held at build time
/// goes on a later apply.
pub(super) fn superseded_images(eng: &str, repo: &str, tag: &str) -> ManagedCommand {
    let tag = shell_escape(tag);
    let list = format!(
        "{{ {eng} image inspect {tag} >/dev/null 2>&1 && \
         {eng} image ls {repo} --filter dangling=false --format '{{{{.Repository}}}}:{{{{.Tag}}}}' | \
         grep -vxF {tag} | grep -vxF -f <({eng} ps -a --format '{{{{.Image}}}}'); }} 2>/dev/null"
    );
    ManagedCommand::new(
        "superseded sandbox images removed",
        format!("[ -z \"$({list} || true)\" ]"),
        // A slot that took a tag meanwhile keeps it; the next apply retries.
        format!("{{ {list} || true; }} | xargs -r {eng} image rm >/dev/null || true"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::github_runner::GithubRunnerModule;
    use crate::modules::Module;
    use std::process::Command;

    const KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\nS3CRETKEY\n-----END RSA PRIVATE KEY-----\n";

    /// sysbox unless `extra` picks a runtime (docker-rootless is the default).
    fn cfg(extra: &str) -> GithubRunnerSection {
        let rt = if extra.contains("sandbox_runtime") {
            ""
        } else {
            "sandbox_runtime = \"sysbox-runc\"\n"
        };
        toml::from_str(&format!(
            "mode = \"ephemeral\"\napp_id = 1234567\ninstallation_id = 987654321\n\
             runner_group_id = 3\napp_key = {KEY:?}\n{rt}{extra}\n\
             [runners.ci]\nurl = \"https://github.com/acme\"\nlabels = [\"anvil\", \"x.y\"]\n"
        ))
        .unwrap()
    }

    fn eph(c: &GithubRunnerSection, slice: bool) -> Ephemeral<'_> {
        Ephemeral {
            cfg: c,
            docker_distro: false,
            docker: None,
            in_ci_slice: slice,
            ci_cpu_weight: 100,
            engine: crate::config::Engine::Docker,
        }
    }

    fn decl(extra: &str) -> Declaration {
        GithubRunnerModule::new(cfg(extra)).declaration()
    }

    #[test]
    fn minter_mints_with_the_app_and_runs_one_sandbox() {
        let c = cfg("");
        let m = eph(&c, true).minter_content("ci");
        for want in [
            "name='ci'-$slot\n",
            "printf '{\"iat\":%d,\"exp\":%d,\"iss\":%d}' \\\n    $((now - 60)) $((now + 540)) '1234567'",
            "openssl dgst -sha256 -sign '/etc/anvil/github-runner/app.pem' -binary",
            "/app/installations/'987654321'/access_tokens '{}' | jq -er .token\n",
            "tok=$(mint_token)\n",
            "--argjson g '3' --argjson l '[\"anvil\",\"x.y\"]'",
            "/orgs/'acme'/actions/runners/generate-jitconfig \"$body\"",
            "\"ACTIONS_RUNNER_INPUT_JITCONFIG=\" + .encoded_jit_config' >\"$env\"",
            "docker create --name \"$ctr\" --init --runtime='sysbox-runc' --cgroup-parent=ci.slice \
             --cpus '2' --memory '4g' \\\n  --pids-limit '2048' --env-file \"$env\"",
            "-v \"$mnt/docker:/var/lib/docker\" -v \"$mnt/work:/home/runner/_work\"",
            &format!("{} >/dev/null\nrm -f \"$env\"\n", shell_escape(&image_tag(&[]))),
            "docker rm -fv \"$ctr\"",
            "mkfs.ext4 -q -F -m 0 \"$img\"\n",
            "mount -o loop,nodev,nosuid \"$img\" \"$mnt\"\n",
            "-K - -X POST",
        ] {
            assert!(m.contains(want), "minter misses {want:?}\n{m}");
        }
        // Wipe before mint, mint before start, cleanup after the job.
        let pos = |s: &str| m.find(s).unwrap();
        assert!(
            pos("mkfs.ext4") < pos("tok=$(mint_token)")
                && pos("docker create") < pos("docker start -a")
        );
        assert!(pos("docker start -a") < m.rfind("cleanup\n").unwrap());
        // No bearer or JIT ever on a command line.
        assert!(!m.contains("-H \"Authorization") && !m.contains("--jitconfig"));
        assert!(!m.contains("S3CRET"));
        let no_slice = eph(&c, false).minter_content("ci");
        assert!(!no_slice.contains("--cgroup-parent"));
        assert!(no_slice.contains("--runtime='sysbox-runc' --cpus"));
    }

    #[test]
    fn sandbox_limits_come_from_config() {
        let c = cfg("sandbox_cpus = \"1.5\"\nsandbox_memory = \"512m\"\nsandbox_pids = 99");
        let m = eph(&c, false).minter_content("ci");
        assert!(m.contains("--cpus '1.5' --memory '512m' \\\n  --pids-limit '99'"));
    }

    /// Runs the minter's label lines; the JIT runner gets the defaults
    /// `config.sh` adds, deduplicated case-insensitively with the configured.
    #[test]
    fn jit_runner_gets_the_default_labels() {
        if Command::new("jq").arg("--version").output().is_err() {
            return;
        }
        let c = cfg("");
        let m = eph(&c, false)
            .minter_content("ci")
            .replace("[\"anvil\",\"x.y\"]", "[\"anvil\",\"linux\",\"x.y\"]");
        let start = m.find("case \"$(uname -m)\"").unwrap();
        let end = start + m[start..].find("_work\",").unwrap();
        let end = end + m[end..].find("}')\n").unwrap() + 4;
        let out = Command::new("bash")
            .arg("-c")
            .arg(format!(
                "name=ci-1\n{}printf '%s' \"$body\"",
                &m[start..end]
            ))
            .output()
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json body");
        let mut labels: Vec<&str> = body["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l.as_str().unwrap())
            .collect();
        labels.sort_unstable();
        let arch = if cfg!(target_arch = "aarch64") {
            "ARM64"
        } else {
            "X64"
        };
        let mut want = vec!["Linux", "anvil", "self-hosted", "x.y", arch];
        want.sort_unstable();
        assert_eq!(labels, want, "{body}");
        assert_eq!(body["runner_group_id"], 3);
    }

    /// Runs the minter's JWT and API lines in bash with a throwaway key and a
    /// stub curl: the claims are right, the signature verifies, and the
    /// bearer reaches curl on stdin only.
    #[test]
    fn jwt_verifies_and_the_bearer_never_reaches_argv() {
        if Command::new("openssl").arg("version").output().is_err() {
            return;
        }
        let d = std::env::temp_dir().join(format!("anvil-gr9-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let key = d.join("k.pem");
        let pubk = d.join("k.pub");
        let ok = |c: &mut Command| assert!(c.status().unwrap().success());
        ok(Command::new("openssl")
            .args(["genrsa", "-out"])
            .arg(&key)
            .arg("2048"));
        ok(Command::new("openssl")
            .args(["rsa", "-pubout", "-in"])
            .arg(&key)
            .arg("-out")
            .arg(&pubk));
        let c = cfg("");
        let m = eph(&c, false)
            .minter_content("ci")
            .replace(KEY_PATH, key.to_str().unwrap());
        let a = m.find("b64url()").unwrap();
        let fns = &m[a..m.find("cleanup() {").unwrap()];
        // mint_token's JWT reaches curl only on stdin; the stub answers a token.
        let script = format!(
            "set -euo pipefail\n{fns}\n\
             curl() {{ printf '%s\\n' \"$@\" >{d}/argv; cat >{d}/stdin; echo '{{\"token\":\"t\"}}'; }}\n\
             [ \"$(mint_token)\" = t ]\nsed -n 's/.*Bearer \\(.*\\)\"$/\\1/p' {d}/stdin | tr -d '\\n'",
            d = d.display()
        );
        let out = Command::new("bash").args(["-c", &script]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let jwt = String::from_utf8(out.stdout).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let dec = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .unwrap()
        };
        let claims: serde_json::Value = serde_json::from_slice(&dec(parts[1])).unwrap();
        assert_eq!(claims["iss"], 1234567);
        let (iat, exp) = (
            claims["iat"].as_i64().unwrap(),
            claims["exp"].as_i64().unwrap(),
        );
        assert_eq!(exp - iat, 600);
        let header: serde_json::Value = serde_json::from_slice(&dec(parts[0])).unwrap();
        assert_eq!(header["alg"], "RS256");
        std::fs::write(d.join("msg"), format!("{}.{}", parts[0], parts[1])).unwrap();
        std::fs::write(d.join("sig"), dec(parts[2])).unwrap();
        ok(Command::new("openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(&pubk)
            .arg("-signature")
            .arg(d.join("sig"))
            .arg(d.join("msg")));
        let argv = std::fs::read_to_string(d.join("argv")).unwrap();
        let stdin = std::fs::read_to_string(d.join("stdin")).unwrap();
        assert!(!argv.contains(&jwt), "bearer in argv: {argv}");
        assert!(
            argv.contains("https://api.github.com/app/installations/'987654321'/access_tokens")
                || argv
                    .contains("https://api.github.com/app/installations/987654321/access_tokens"),
            "{argv}"
        );
        assert_eq!(stdin, format!("header = \"Authorization: Bearer {jwt}\"\n"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn key_is_a_computed_root_only_file() {
        let d = decl("");
        let f = d.files.iter().find(|f| f.path == KEY_PATH).unwrap();
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0600", "root:root"));
        assert!(
            f.static_content().is_none(),
            "diff must never print the key"
        );
        for f in &d.files {
            assert!(!f.static_content().unwrap_or_default().contains("S3CRET"));
        }
        assert!(d
            .render_apply()
            .contains(&format!("printf '%s\\n' {}", shell_escape(KEY.trim_end()))));
    }

    #[test]
    fn sysbox_is_pinned_verified_and_detected_by_runtime() {
        assert_eq!(decl("").installs, ["Docker", "sysbox-ce 0.7.1"]);
        let apply = decl("").render_apply();
        assert!(apply.contains(&format!("\"{SYSBOX_URL}\"")));
        // Both arches pinned, picked by dpkg; anything else fails.
        for (arch, sha) in [("amd64", SYSBOX_SHA256.0), ("arm64", SYSBOX_SHA256.1)] {
            assert!(
                apply.contains(&format!("{arch}) __ra={arch}; __sha={}", shell_escape(sha))),
                "{arch}"
            );
        }
        assert!(apply.contains("github_runner: unsupported architecture"));
        let check = apply
            .find("printf '%s  %s\\n' \"$__sha\" \"$__tmp/sysbox.deb\" | sha256sum -c")
            .unwrap();
        let install = apply.find("install -y -qq \"$__tmp/sysbox.deb\"").unwrap();
        assert!(check < install);
        let probe = decl("").render_probe();
        assert!(probe.contains(
            "case \"$(docker info --format '{{json .Runtimes}}' 2>/dev/null)\" in *'\"sysbox-runc\"'*) true"
        ));
        assert!(Ephemeral::runtime_install("kata").is_none());
    }

    #[test]
    fn image_is_built_from_the_managed_context_under_a_content_tag() {
        let d = decl("");
        let tag = image_tag(&[]);
        assert!(tag.starts_with("anvil-github-runner:") && tag.len() == 20 + 16);
        assert!(dockerfile(&[]).contains(&format!("FROM {BASE_IMAGE}\n")));
        assert!(BASE_IMAGE.contains("@sha256:"));
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let apply = d.render_apply();
        assert!(apply.contains(&format!(
            "printf '%s' '{}' | base64 -d >\"$__tmp/Dockerfile\"",
            b64(&dockerfile(&[]))
        )));
        assert!(apply.contains(&format!(
            "printf '%s' '{}' | base64 -d >\"$__tmp/entrypoint.sh\"",
            b64(ENTRYPOINT)
        )));
        assert!(apply.contains(&format!(
            "docker build -q -t {} \"$__tmp\"",
            shell_escape(&tag)
        )));
        assert!(d
            .render_probe()
            .contains(&format!("docker image inspect {} ", shell_escape(&tag))));
        for p in ["Dockerfile", "entrypoint.sh"] {
            assert!(d.files.iter().any(|f| f.path == format!("{IMAGE_CTX}/{p}")));
        }
        // The journal gets the runner's terminal lines, not its trace.
        assert!(dockerfile(&[]).contains("\nENV ACTIONS_RUNNER_PRINT_LOG_TO_STDOUT=0\n"));
        // `sandbox_packages` are baked in; a change is a new tag.
        assert!(dockerfile(&[]).contains(" iptables \\\n"));
        let pk = decl("sandbox_packages = [\"build-essential\", \"pkg-config\"]");
        let pkgs = ["build-essential".to_string(), "pkg-config".to_string()];
        assert!(dockerfile(&pkgs).contains(" iptables 'build-essential' 'pkg-config' \\\n"));
        assert_ne!(image_tag(&pkgs), tag);
        let df = pk
            .files
            .iter()
            .find(|f| f.path.ends_with("/Dockerfile"))
            .unwrap();
        assert!(format!("{:?}", df.content).contains("pkg-config"));
        assert!(pk.render_probe().contains(&format!(
            "docker image inspect {} ",
            shell_escape(&image_tag(&pkgs))
        )));
        let m = eph(&cfg("sandbox_packages = [\"gcc\"]"), false).minter_content("ci");
        assert!(m.contains(&shell_escape(&image_tag(&["gcc".to_string()]))));
        assert_ne!(fnv1a(b"a"), fnv1a(b"b"));
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert!(ENTRYPOINT.contains("exec runuser -u runner -- ./run.sh\n"));
        assert!(ENTRYPOINT.find("dockerd").unwrap() < ENTRYPOINT.find("run.sh").unwrap());
    }

    #[test]
    fn build_cache_is_pruned_only_after_a_successful_build() {
        let apply = decl("").render_apply();
        let pos = |s: &str| apply.find(s).unwrap_or_else(|| panic!("{s}\n{apply}"));
        let tag = shell_escape(&image_tag(&[]));
        let build = pos(&format!("docker build -q -t {tag} \"$__tmp\" >/dev/null\n"));
        let prune = pos("docker builder prune -af >/dev/null\n");
        let old = pos("# converge: superseded sandbox images removed");
        assert!(build < prune && prune < old);
        // Same converge body, no `||` fence: a failed build aborts before the prune.
        assert!(!apply[build..prune].contains("fi\n") && !apply[build..prune].contains("||"));
        assert!(decl("")
            .render_rollback()
            .contains("docker builder prune -af"));
    }

    /// Runs `superseded_images` against a stub `docker` holding `images`
    /// (one `repo:tag` per line) and `ps` (container image names); prints
    /// the removals and the images left.
    fn superseded_run(images: &str, ps: &str) -> String {
        superseded_run_on("", images, ps)
    }

    /// `rt`: `sandbox_runtime` line ("" = sysbox); the stub takes the engine's name.
    fn superseded_run_on(rt: &str, images: &str, ps: &str) -> String {
        let c = cfg(rt);
        let e = eph(&c, false);
        let d = std::env::temp_dir().join(format!(
            "anvil-img-{}-{}",
            std::process::id(),
            fnv1a(format!("{rt}|{images}|{ps}").as_bytes())
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::write(d.join("images"), images).unwrap();
        std::fs::write(d.join("ps"), ps).unwrap();
        let stub = d.join("bin").join(e.eng());
        std::fs::write(
            &stub,
            "#!/bin/bash
case \"$1 $2\" in
\
             'image inspect') grep -qxF \"$3\" images ;;
\
             'image ls') grep \"^$3:\" images || true ;;
\
             'ps -a') cat ps ;;
\
             'image rm') shift 2; for i; do echo \"rm $i\" >>log; grep -vxF \"$i\" images >t || true; mv t images; done ;;
\
             *) exit 1 ;;
esac
",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let c = e.superseded_images();
        let script = format!(
            "cd {dir}\nPATH={dir}/bin:$PATH\n\
             if {detect}; then echo converged; else {converge}\n fi\n\
             {detect} && echo now-converged\ncat log 2>/dev/null || true\necho == left; cat images",
            dir = d.display(),
            detect = c.detect,
            converge = c.converge,
        );
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(out.status.success(), "{out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn superseded_images_go_only_once_the_current_tag_exists_and_none_in_use() {
        let cur = image_tag(&[]);
        let forgejo = "codeberg.org/forgejo/forgejo:13\n";
        let olds = "anvil-github-runner:aaaa\nanvil-github-runner:bbbb\nanvil-github-runner:cccc\n";
        // Build failed or not run yet: the current tag is missing, nothing goes.
        assert_eq!(
            superseded_run(&format!("{olds}{forgejo}"), ""),
            format!("converged\nnow-converged\n== left\n{olds}{forgejo}")
        );
        // aaaa runs a sandbox, bbbb is a stopped one: only cccc goes.
        let out = superseded_run(
            &format!("{olds}{cur}\n{forgejo}"),
            &format!("anvil-github-runner:aaaa\n{cur}\nanvil-github-runner:bbbb\n"),
        );
        assert_eq!(
            out,
            format!(
                "now-converged\nrm anvil-github-runner:cccc\n== left\n\
                 anvil-github-runner:aaaa\nanvil-github-runner:bbbb\n{cur}\n{forgejo}"
            )
        );
        // Nothing in use: every older tag goes, the current one and Forgejo stay.
        let out = superseded_run(&format!("{olds}{cur}\n{forgejo}"), "");
        assert!(
            out.ends_with(&format!("\n== left\n{cur}\n{forgejo}")),
            "{out}"
        );
        assert!(out.starts_with("now-converged\n"), "{out}");
        assert_eq!(out.matches("rm anvil-github-runner:").count(), 3, "{out}");
    }

    #[test]
    fn slot_paths_are_pinned() {
        // Minter, rollback and drift key on these; never rename once shipped.
        assert_eq!(
            image_path("ci", 2),
            "/var/lib/anvil-ci/github-runner-ci-2.img"
        );
        assert_eq!(
            mount_dir("ci", 2),
            "/var/lib/anvil-ci/github-runner-ci-2.mnt"
        );
        let c = cfg("");
        let m = eph(&c, false).minter_content("ci");
        assert!(m.contains("img='/var/lib/anvil-ci'/github-runner-$name.img\n"));
        assert!(m.contains("mnt='/var/lib/anvil-ci'/github-runner-$name.mnt\n"));
    }

    #[test]
    fn one_unit_and_volume_per_slot() {
        let d = decl("capacity = 2\nsandbox_disk = \"10G\"");
        for i in [1, 2] {
            assert!(d.files.iter().any(|f| f.path == unit_path("ci", i)));
            let img = shell_escape(&image_path("ci", i));
            assert!(d
                .render_probe()
                .contains(&format!("[ \"$(stat -c %s {img})\" = 10737418240 ]")));
        }
        assert!(!d.files.iter().any(|f| f.path == unit_path("ci", 3)));
        let apply = d.render_apply();
        assert!(apply.contains("root_owner=\"0:0\""));
        assert!(apply.contains("sandbox_disk = %s"));
        assert!(d
            .files
            .iter()
            .any(|f| f.path == minter_path("ci") && f.mode == "0700"));
        let r = d.reload.unwrap();
        assert!(r.validate.contains(&format!(
            "{{ [ ! -e '{}' ] || [ -x '{}' ]; }}",
            unit_path("ci", 2),
            minter_path("ci")
        )));
    }

    /// Runs the reload with stub `systemctl`/`docker`/`touch` after `setup`;
    /// `busy` slots have a sandbox, `stopped` slots an inactive unit.
    fn reload_actions(setup: &str, busy: &[u32], stopped: &[u32]) -> Vec<String> {
        let reload = decl("capacity = 2").reload.unwrap().reload;
        let set = |v: &[u32], f: fn(&str, u32) -> String| {
            v.iter()
                .map(|&i| format!(" {} ", f("ci", i)))
                .collect::<String>()
        };
        let script = format!(
            "busy='{}'; stopped='{}'\n\
             systemctl() {{ case $1 in restart) echo \"restart $2\" ;; \
             is-active) [[ $stopped != *\" $3 \"* ]] ;; esac; }}\n\
             docker() {{ [[ $busy == *\" $3 \"* ]]; }}\n\
             touch() {{ echo \"flag $1\"; }}\nrm() {{ :; }}\n{setup}\n{reload}",
            set(busy, container),
            set(stopped, unit_name),
        );
        let out = Command::new("bash")
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
    fn apply_never_restarts_a_slot_over_its_sandbox() {
        // Rollback and a no-op apply restart nothing.
        assert!(reload_actions("", &[], &[]).is_empty());
        // A new minter, image context or key: the next job picks it up.
        let next_job = format!(
            "__reverts=({} {KEY_PATH} {IMAGE_CTX}/Dockerfile {IMAGE_CTX}/entrypoint.sh)",
            minter_path("ci")
        );
        assert!(reload_actions(&next_job, &[1, 2], &[]).is_empty());
        assert!(reload_actions(&next_job, &[], &[]).is_empty());
        let (u1, u2) = (unit_name("ci", 1), unit_name("ci", 2));
        let unit1 = format!("__reverts=({})", unit_path("ci", 1));
        assert_eq!(reload_actions(&unit1, &[], &[]), [format!("restart {u1}")]);
        assert_eq!(
            reload_actions(&unit1, &[1], &[]),
            [format!("flag {}", restart_flag("ci", 1))]
        );
        assert_eq!(
            reload_actions("__ghr_restart_all=1", &[1], &[]),
            [
                format!("flag {}", restart_flag("ci", 1)),
                format!("restart {u2}")
            ]
        );
        // A stopped slot runs no job: start it even over a leftover sandbox.
        let down = format!("__ghr_restart=({u2})");
        assert_eq!(reload_actions(&down, &[2], &[2]), [format!("restart {u2}")]);
        assert_eq!(
            restart_flag("ci", 2),
            "/run/anvil-github-runner-ci-2.restart"
        );
    }

    #[test]
    fn only_a_stopped_slot_or_new_runtime_flags_a_restart() {
        assert!(!eph(&cfg(""), false)
            .image()
            .converge
            .contains("__ghr_restart"));
        assert!(Ephemeral::sysbox("sysbox-runc")
            .converge
            .ends_with("\n__ghr_restart_all=1"));
        assert_eq!(
            Ephemeral::service_active("ci", 2).converge,
            "__ghr_restart+=('anvil-github-runner-ci-2.service')"
        );
    }

    #[test]
    fn minter_is_one_parsed_group_and_restarts_between_jobs_on_the_flag() {
        let c = cfg("");
        let m = eph(&c, false).minter_content("ci");
        assert!(m.contains("\n{\nset -euo pipefail\n"));
        assert!(m.ends_with("\nexit \"$rc\"\n}\n"));
        let lp = m.find("    while :; do\n").unwrap();
        let flag = m
            .find("if [ -e \"/run/$ctr.restart\" ]; then rm -f \"/run/$ctr.restart\"; exit 0; fi")
            .unwrap();
        assert!(lp < flag && flag < m.find("if \"$0\" \"$slot\" once").unwrap());
        let out = Command::new("bash")
            .args(["-n", "-c", &m])
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    }

    #[test]
    fn unit_restarts_cleans_up_and_joins_the_slice() {
        let c = cfg("");
        let u = eph(&c, true).unit_content("ci", 2);
        for line in [
            "ExecStart=/usr/local/libexec/anvil/github-runner-mint-ci.sh 2\n",
            "ExecStopPost=/usr/local/libexec/anvil/github-runner-mint-ci.sh 2 cleanup\n",
            "Restart=always\n",
            "Requires=docker.service\n",
            "Slice=ci.slice\n",
        ] {
            assert!(u.contains(line), "{line}");
        }
        assert!(!eph(&c, false).unit_content("ci", 2).contains("Slice="));
        assert!(!u.contains("PrivateTmp"), "dockerd must see the slot mount");
    }

    #[test]
    fn rollback_stops_slots_removes_sandboxes_image_and_created_volumes() {
        let rb = decl("").render_rollback();
        let pos = |s: &str| rb.find(s).unwrap_or_else(|| panic!("{s}\n{rb}"));
        let stop = pos("systemctl disable --now 'anvil-github-runner-ci-1.service'");
        let rm = pos("docker rm -fv 'anvil-github-runner-ci-1'");
        let umount = pos(&format!("umount {}", shell_escape(&mount_dir("ci", 1))));
        let unit = pos(&format!("# rollback: {}", unit_path("ci", 1)));
        assert!(stop < rm && rm < umount && umount < unit);
        pos("docker image ls anvil-github-runner --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | xargs -r docker image rm");
        let img = shell_escape(&image_path("ci", 1));
        assert!(pos(&format!("if __anvil_created {img}; then")) < pos(&format!("rm -f {img}\n")));
        pos(&format!("__anvil_forget {img}"));
        pos(&format!("# rollback: {KEY_PATH}"));
        assert!(
            !rb.contains("apt-get") && !rb.contains("purge"),
            "packages stay"
        );
    }

    #[test]
    fn owns_one_daemon_json_with_sysbox_and_docker_keys() {
        use crate::modules::docker::{daemon_json, DAEMON_JSON};
        let c = cfg("");
        let docker = crate::config::schema::DockerSection::default();
        for d in [None, Some(&docker)] {
            let e = Ephemeral {
                docker: d,
                ..eph(&c, false)
            };
            let decl = e.declaration();
            let f = decl.files.iter().find(|f| f.path == DAEMON_JSON).unwrap();
            assert_eq!(f.static_content(), Some(daemon_json(d, true).as_str()));
            assert!(decl.render_probe().contains(DAEMON_JSON));
            // A defaulted [docker] is guarded before the sysbox.deb.
            let apply = decl.render_apply();
            let guard = apply.find("userns-remap by default");
            assert_eq!(guard.is_some(), d.is_some());
            if let Some(g) = guard {
                assert!(g < apply.find("sysbox.deb").unwrap());
            }
        }
        let d = decl("");
        let apply = d.render_apply();
        let pos = |s: &str| apply.find(s).unwrap_or_else(|| panic!("{s}"));
        // Written after the sysbox .deb (its postinst edits the file).
        assert!(
            pos("install -y -qq \"$__tmp/sysbox.deb\"") < pos(&format!("# file: {DAEMON_JSON}"))
        );
        let g = d.reload.unwrap();
        assert!(g
            .validate
            .starts_with("{ [ ! -e '/etc/docker/daemon.json' ] || ! command -v dockerd"));
        assert!(g.validate.contains("dockerd --validate"));
        // dockerd restarts (when idle) before the slots, and on rollback.
        assert!(
            g.reload.find("systemctl restart docker").unwrap()
                < g.reload.find("systemctl daemon-reload").unwrap()
        );
        assert!(d.rollback.unwrap().ends_with("__docker_restart=1\n"));
    }

    /// Runs detect/converge in a temp dir with AppArmor stubbed via
    /// `$AA` (`on`, `bad` = parser rejects, else absent); prints detect's
    /// verdict, the local file and the created list.
    fn apparmor_run(setup: &str, aa: &str) -> (bool, String) {
        let d = std::env::temp_dir().join(format!(
            "anvil-aa-{}-{}",
            std::process::id(),
            fnv1a(format!("{setup}{aa}").as_bytes())
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("local")).unwrap();
        let dir = d.to_str().unwrap();
        let c = Ephemeral::apparmor_rule();
        let fix = |s: &str| {
            s.replace(AA_LOCAL, &format!("{dir}/local/fusermount3"))
                .replace(AA_PROFILE, &format!("{dir}/profile"))
        };
        let script = format!(
            "cd {dir}\nAA={aa}\n__rundir={dir}\n\
             aa-enabled() {{ [ \"$AA\" = on ] || [ \"$AA\" = bad ]; }}\n\
             apparmor_parser() {{ echo \"parse $2\" >>log; [ \"$AA\" != bad ]; }}\n\
             __anvil_created() {{ grep -qsxF -- \"$1\" created; }}\n\
             __anvil_remember() {{ echo \"$1\" >>created; }}\n\
             __anvil_forget() {{ echo \"forget $1\" >>created; }}\n\
             {setup}\n\
             if {detect}; then echo converged; exit 0; fi\n\
             ( {converge}\n ) || echo failed\n\
             {detect} && echo now-converged\n\
             for f in local/fusermount3 local/fusermount3.anvil.bak created log; do \
             [ ! -e $f ] || {{ echo \"== $f\"; cat $f; }}; done",
            detect = fix(&c.detect),
            converge = fix(&c.converge),
        );
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        let o = String::from_utf8(out.stdout).unwrap().replace(dir, "D");
        (out.status.success(), o)
    }

    #[test]
    fn apparmor_rule_allows_mount_and_unmount() {
        // Without umount, every ended sandbox leaks its sysbox-fs mount.
        assert!(AA_RULE.contains(
            "mount fstype=fuse options=(rw,nosuid,nodev) sysboxfs -> /var/lib/sysboxfs/*/,"
        ));
        assert!(AA_RULE.ends_with(", umount /var/lib/sysboxfs/*/,"));
    }

    #[test]
    fn apparmor_rule_is_appended_only_where_the_profile_includes_it() {
        let inc = "echo 'include if exists <local/fusermount3>' >profile";
        // Debian 13: no profile, nothing to do.
        assert_eq!(apparmor_run("", "on"), (true, "converged\n".into()));
        assert_eq!(apparmor_run("echo x >profile", "on").1, "converged\n");
        let rule = format!("{AA_RULE}\n");
        // Fresh local file: created (and remembered), profile reloaded.
        let (ok, o) = apparmor_run(inc, "on");
        assert!(ok, "{o}");
        assert_eq!(
            o,
            format!(
                "now-converged\n== local/fusermount3\n{rule}== created\nD/local/fusermount3\n\
                 == log\nparse D/profile\n"
            )
        );
        // Existing lines kept (even without a final newline), original backed up.
        let (_, o) = apparmor_run(
            &format!("{inc}; printf 'deny /x r,' >local/fusermount3"),
            "",
        );
        assert_eq!(
            o,
            format!(
                "now-converged\n== local/fusermount3\ndeny /x r,\n{rule}\
                 == local/fusermount3.anvil.bak\ndeny /x r,"
            )
        );
        // Already present: converged.
        let set = format!(
            "{inc}; printf '%s\\n' {} >local/fusermount3",
            shell_escape(AA_RULE)
        );
        assert_eq!(apparmor_run(&set, "on").1, "converged\n");
        // A rejected reload undoes the append.
        let (_, o) = apparmor_run(&format!("{inc}; echo keep >local/fusermount3"), "bad");
        assert!(
            o.starts_with("FAILED: github_runner: apparmor_parser rejected"),
            "{o}"
        );
        assert!(o.contains("failed\n== local/fusermount3\nkeep\n== local/fusermount3.anvil.bak"));
        assert!(!o.contains("now-converged"));
        let (_, o) = apparmor_run(inc, "bad");
        assert!(o.ends_with("failed\n== created\nD/local/fusermount3\nforget D/local/fusermount3\n== log\nparse D/profile\n"), "{o}");
        // Rollback restores the file (engine) and reloads the profile.
        let d = decl("");
        assert!(d.command_files.contains(&AA_LOCAL.to_string()));
        assert!(d
            .render_probe()
            .contains(&Ephemeral::apparmor_rule().detect));
        let rb = d.render_rollback();
        assert!(
            rb.find(&format!("# rollback (command-edited): {AA_LOCAL}"))
                .unwrap()
                < rb.find("then apparmor_parser -r '/etc/apparmor.d/fusermount3' || true")
                    .unwrap()
        );
    }

    const PODMAN: &str = "sandbox_runtime = \"podman\"";

    fn bash(script: &str) -> (bool, String) {
        let out = Command::new("bash")
            .args(["-euo", "pipefail", "-c", script])
            .output()
            .unwrap();
        let o = String::from_utf8_lossy(&out.stdout).into_owned();
        (
            out.status.success(),
            o + &String::from_utf8_lossy(&out.stderr),
        )
    }

    #[test]
    fn podman_minter_runs_one_userns_sandbox_on_the_slot_volume() {
        let c = cfg(PODMAN);
        let m = eph(&c, true).minter_content("ci");
        for want in [
            "podman create --name \"$ctr\" --init --userns=auto:size=65536 --device /dev/fuse \
             --device /dev/net/tun \\\n  --security-opt unmask=ALL --security-opt label=disable \
             ${aa:+\"$aa\"} --cgroup-parent=ci.slice --cpus '2' --memory '4g' \\\n  \
             --pids-limit '2048' --env-file \"$env\"",
            "-v \"$mnt/containers:/home/runner/.local/share/containers:U\" \
             -v \"$mnt/work:/home/runner/_work:U\"",
            &format!("{} >/dev/null\n", shell_escape(&podman_image_tag(&[]))),
            "install -d -m 0755 \"$mnt/containers\" \"$mnt/work\"\n",
            "  podman rm -fv \"$ctr\" >/dev/null 2>&1 || true\n",
            "podman start -a \"$ctr\" || rc=$?\n",
        ] {
            assert!(m.contains(want), "minter misses {want:?}\n{m}");
        }
        assert!(!m.contains("docker") && !m.contains("--runtime"), "{m}");
        assert!(podman_image_tag(&[]).starts_with("localhost/anvil-github-runner:"));
        let (ok, o) = bash(&format!("bash -n <<'EOF'\n{m}\nEOF"));
        assert!(ok, "{o}");
    }

    /// Ubuntu: without the profile the sandbox gets `containers-default`,
    /// which denies the inner Podman's mounts. Runs the minter's line.
    #[test]
    fn podman_sandbox_runs_under_the_anvil_profile_where_apparmor_is_on() {
        let c = cfg(PODMAN);
        let m = eph(&c, false).minter_content("ci");
        let line = &m[m.find("aa=\n").unwrap()..m.find("podman create").unwrap()];
        let run = |on: bool| {
            bash(&format!(
                "aa-enabled() {{ {on}; }}\n{line}printf '<%s>' x ${{aa:+\"$aa\"}} y"
            ))
        };
        assert_eq!(
            run(true),
            (
                true,
                format!("<x><--security-opt=apparmor={AA_SANDBOX}><y>")
            )
        );
        assert_eq!(run(false), (true, "<x><y>".into()));
        let d = decl(PODMAN);
        let f = d.files.iter().find(|f| f.path == AA_SANDBOX_PATH).unwrap();
        let p = f.static_content().unwrap();
        assert!(p.contains(&format!("\nprofile {AA_SANDBOX} flags=")));
        // mqueue: AppArmor 4 mediates POSIX mqueues; crun (inner Podman)
        // stats one, denied on Ubuntu 26.04 without it (the live test).
        for rule in [
            "  signal (receive) peer=crun,\n",
            "  deny @{PROC}/sys/[^kn]** w,\n",
            "  deny @{PROC}/sys/n[^e]** w,\n",
            "  deny @{PROC}/sys/ne[^t]** w,\n",
            "  deny @{PROC}/sys/net[^/]** w,\n",
            "  deny @{PROC}/sys/kernel/{?,??,[^s][^h][^m]**} w,\n",
            "  mqueue,\n",
            "  mount,\n",
            "  umount,\n",
            "  pivot_root,\n",
            "  userns,\n",
        ] {
            assert!(p.contains(rule), "{rule}");
        }
        assert!(!p.contains("deny mount"));
        // netavark's sysctls under /proc/sys/net must not be denied.
        assert!(!p.contains("deny @{PROC}/sys/[^k]** w"), "{p}");
        assert!(p.contains(&format!("peer={AA_SANDBOX},\n")));
    }

    /// Runs the reload with stub AppArmor/systemctl: a profile the parser
    /// rejects fails the reload before any slot starts.
    #[test]
    fn podman_reload_loads_the_profile_first_and_fails_when_rejected() {
        let g = decl(PODMAN).reload.unwrap();
        assert!(!g.reload.contains("docker") && !g.validate.contains("dockerd"));
        let prof = std::env::temp_dir().join(format!("anvil-aa-sandbox-{}", std::process::id()));
        let prof = prof.to_str().unwrap();
        // Runs the guard as apply and rollback do: `{ validate } && { reload }`.
        let run = |aa: &str, present: bool| {
            let _ = std::fs::remove_file(prof);
            if present {
                std::fs::write(prof, AA_SANDBOX_PROFILE).unwrap();
            }
            let fix = |s: &str| s.replace(AA_SANDBOX_PATH, prof);
            let out = bash(&format!(
                "AA={aa}\naa-enabled() {{ [ \"$AA\" != off ]; }}\n\
                 apparmor_parser() {{ echo \"parse $1\"; [ \"$AA\" != bad ]; }}\n\
                 systemctl() {{ echo \"systemctl $1\"; [ \"$1\" != is-active ]; }}\n\
                 podman() {{ false; }}\n__ghr_restart_all=1\n\
                 {{ {}\n}} && {{ {}\n}}",
                fix(&g.validate),
                fix(&g.reload)
            ));
            let _ = std::fs::remove_file(prof);
            out
        };
        // Parsed before loading; a rejected profile fails before any slot starts.
        let (ok, o) = run("bad", true);
        assert!(!ok && o == "parse -Q\n", "{o}");
        let (ok, o) = run("on", true);
        assert!(ok, "{o}");
        assert!(
            o.starts_with("parse -Q\nparse -r\nsystemctl daemon-reload\n"),
            "{o}"
        );
        assert!(o.contains("systemctl restart"), "{o}");
        let (ok, o) = run("off", true);
        assert!(
            ok && !o.contains("parse") && o.starts_with("systemctl daemon-reload"),
            "{o}"
        );
        // Rollback removed the profile (Ubuntu live test): not FAILED.
        let (ok, o) = run("bad", false);
        assert!(ok && !o.contains("parse"), "{o}");
    }

    #[test]
    fn podman_declaration_installs_podman_and_no_docker_pieces() {
        let d = decl(PODMAN);
        assert_eq!(d.installs, ["Podman"]);
        let apply = d.render_apply();
        assert!(apply.contains("install -y -- 'podman' 'iptables' 'aardvark-dns'"));
        // `podman create --init` needs catatonit; Docker's --init ships with Docker.
        assert!(apply.contains("install -y -- 'catatonit'"));
        assert!(!decl("").render_apply().contains("catatonit"));
        for gone in ["docker", "sysbox", "fusermount3", "daemon.json"] {
            assert!(!apply.contains(gone), "{gone}");
        }
        let f = |p: &str| d.files.iter().find(|f| f.path == p).unwrap();
        assert!(!d
            .files
            .iter()
            .any(|f| f.path.starts_with("/etc/containers/")));
        for (name, content, mode) in context(true, &[]) {
            let file = f(&format!("{IMAGE_CTX}/{name}"));
            assert_eq!(
                (file.static_content(), file.mode.as_str()),
                (Some(content.as_str()), mode)
            );
        }
        assert!(!d.files.iter().any(|f| f.path.ends_with("/Dockerfile")));
        assert_eq!(d.command_files, SUBID_FILES);
        let u = eph(&cfg(PODMAN), true).unit_content("ci", 1);
        // live test: NNP on the minter reached the job; newuidmap failed.
        assert!(!u.contains("NoNewPrivileges"), "{u}");
        let m = eph(&cfg(PODMAN), false).minter_content("ci");
        assert!(
            !m.contains("no-new-privileges") && !m.contains("setpriv"),
            "{m}"
        );
        assert!(
            !PODMAN_ENTRYPOINT.contains("no-new-privs") && !PODMAN_ENTRYPOINT.contains("setpriv")
        );
        assert!(eph(&cfg(""), true)
            .unit_content("ci", 1)
            .contains("\nNoNewPrivileges=yes\n"));
        assert!(u.contains("After=network-online.target\nWants=network-online.target\n\n[Service]"));
        assert!(u.contains("Slice=ci.slice\n") && !u.contains("docker"));
        for script in [d.render_probe(), apply, d.render_rollback()] {
            let (ok, o) = bash(&format!("bash -n <<'EOF'\n{script}\nEOF"));
            assert!(ok, "{o}");
        }
    }

    #[test]
    fn podman_image_bakes_hooks_wrapper_and_inner_podman() {
        let c = cfg(PODMAN);
        let e = eph(&c, false);
        let cf = containerfile(&[]);
        assert!(cf.contains(&format!("FROM {BASE_IMAGE}\n")));
        assert!(cf.contains(&format!("-o /tmp/hooks.tgz {}", shell_escape(HOOKS_URL))));
        let sum = cf
            .find(&format!(
                "echo '{HOOKS_SHA256}  /tmp/hooks.tgz' | sha256sum -c -"
            ))
            .unwrap();
        assert!(sum < cf.find("tar -xzf /tmp/hooks.tgz").unwrap());
        assert!(cf.contains(
            "setcap cap_setuid=ep /usr/bin/newuidmap && setcap cap_setgid=ep /usr/bin/newgidmap"
        ));
        assert!(cf.contains("COPY --chmod=0755 podman-wrapper /usr/local/bin/podman\n"));
        assert!(containerfile(&["gcc".into()]).contains(" libcap2-bin 'gcc' \\\n"));
        assert_ne!(podman_image_tag(&["gcc".into()]), podman_image_tag(&[]));
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let img = e.image();
        let tag = shell_escape(&podman_image_tag(&[]));
        for (f, c, _) in context(true, &[]) {
            assert!(img.converge.contains(&format!(
                "printf '%s' '{}' | base64 -d >\"$__tmp/{f}\"",
                b64(&c)
            )));
        }
        assert!(img.converge.contains(
            "chmod 0755 \"$__tmp/entrypoint.sh\"\nchmod 0755 \"$__tmp/podman-wrapper\"\n"
        ));
        assert!(img.converge.ends_with(&format!("podman build -q -t {tag} \"$__tmp\" >/dev/null\nrm -rf \"$__tmp\"\npodman image prune -f >/dev/null")));
        assert_eq!(
            img.detect,
            format!("podman image inspect {tag} >/dev/null 2>&1")
        );
        // The entrypoint serves the hooks' socket and runs health checks.
        assert!(PODMAN_ENTRYPOINT.contains(
            "podman system service --time=0 \"unix://$XDG_RUNTIME_DIR/podman/podman.sock\" &"
        ));
        assert!(PODMAN_ENTRYPOINT.contains("podman healthcheck run \"$c\""));
        assert!(PODMAN_WRAPPER.ends_with("exec /usr/bin/podman \"$@\"\n"));
        assert!(INNER_CONTAINERS_CONF.contains("network_backend = \"netavark\"\n"));
    }

    #[test]
    fn podman_superseded_images_match_the_localhost_names() {
        let cur = podman_image_tag(&[]);
        let olds = "localhost/anvil-github-runner:aaaa\nlocalhost/anvil-github-runner:bbbb\n";
        let out = superseded_run_on(
            PODMAN,
            &format!("{olds}{cur}\n"),
            "localhost/anvil-github-runner:aaaa\n",
        );
        assert_eq!(
            out,
            format!(
                "now-converged\nrm localhost/anvil-github-runner:bbbb\n== left\n\
                 localhost/anvil-github-runner:aaaa\n{cur}\n"
            )
        );
    }

    /// Runs the id-range command in a temp dir; prints the files after.
    fn subids_run(setup: &str) -> String {
        let d = std::env::temp_dir().join(format!(
            "anvil-subid-{}-{}",
            std::process::id(),
            fnv1a(setup.as_bytes())
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let dir = d.to_str().unwrap();
        let c = Ephemeral::subids();
        let fix = |s: &str| s.replace("/etc/", &format!("{dir}/"));
        let (ok, o) = bash(&format!(
            "cd {dir}\n__anvil_created() {{ grep -qsxF -- \"$1\" created; }}\n\
             __anvil_remember() {{ echo \"$1\" >>created; }}\n{setup}\n\
             if {detect}; then echo converged; exit 0; fi\n{converge}\n\
             {detect} && echo now-converged\n\
             for f in subuid subuid.anvil.bak subgid subgid.anvil.bak created; do \
             [ ! -e $f ] || {{ echo \"== $f\"; cat $f; }}; done",
            detect = fix(&c.detect),
            converge = fix(&c.converge),
        ));
        std::fs::remove_dir_all(&d).unwrap();
        assert!(ok, "{o}");
        o.replace(dir, "D")
    }

    #[test]
    fn subid_range_is_appended_once_and_backed_up() {
        let l = SUBID_LINE;
        assert_eq!(
            subids_run("printf 'u:100000:65536' >subuid; : >subgid"),
            format!(
                "now-converged\n== subuid\nu:100000:65536\n{l}\n== subuid.anvil.bak\nu:100000:65536\
                 == subgid\n{l}\n== subgid.anvil.bak\n"
            )
        );
        // An operator's own range is kept; only the missing file gets ours.
        assert_eq!(
            subids_run("echo containers:1:2 >subuid"),
            format!(
                "now-converged\n== subuid\ncontainers:1:2\n== subgid\n{l}\n== created\nD/subgid\n"
            )
        );
        assert_eq!(
            subids_run("echo containers:1:2 >subuid; cp subuid subgid"),
            "converged\n"
        );
    }

    #[test]
    fn podman_rollback_stops_sandboxes_unloads_the_profile_and_removes_images() {
        let rb = decl(PODMAN).render_rollback();
        let pos = |s: &str| rb.find(s).unwrap_or_else(|| panic!("{s}\n{rb}"));
        let stop = pos("systemctl disable --now 'anvil-github-runner-ci-1.service'");
        let rm = pos("podman rm -fv 'anvil-github-runner-ci-1'");
        let unload = pos(&format!(
            "aa-enabled -q 2>/dev/null; then apparmor_parser -R {} ",
            shell_escape(AA_SANDBOX_PATH)
        ));
        let file = pos(&format!("# rollback: {AA_SANDBOX_PATH}"));
        assert!(stop < rm && rm < unload && unload < file);
        pos("podman image ls localhost/anvil-github-runner --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | xargs -r podman image rm");
        pos("podman image prune -f >/dev/null 2>&1 || true\n");
        pos("# rollback (command-edited): /etc/subuid");
        assert!(
            !rb.contains("docker") && !rb.contains("fusermount3"),
            "{rb}"
        );
    }

    #[test]
    fn persistent_mode_never_renders_ephemeral_pieces() {
        let mut c = cfg("");
        c.mode = "persistent".into();
        let d = GithubRunnerModule::new(c).declaration();
        assert!(!d.files.iter().any(|f| f.path == KEY_PATH));
        assert!(!d.render_apply().contains("sysbox"));
        assert!(!d.render_apply().contains("apparmor"));
    }

    // --- sandbox_runtime = "docker-rootless" ---

    const RL: &str = "sandbox_runtime = \"docker-rootless\"\ncapacity = 2";

    #[test]
    fn rootless_minter_runs_a_privileged_sandbox_in_the_slot_users_fresh_engine() {
        let c = cfg(RL);
        let m = eph(&c, true).minter_content("ci");
        assert!(
            !m.contains("sysbox") && !m.contains("--runtime") && !m.contains("--cgroup-parent")
        );
        assert!(
            m.contains("mnt=/var/lib/anvil-ghr-$name/vol\n") && m.contains("u=anvil-ghr-$name\n")
        );
        assert!(m.contains("ud create --name \"$ctr\" --init --privileged --cpus"));
        assert!(m.contains("ud start -a \"$ctr\""));
        let pos = |n: &str| m.find(n).unwrap_or_else(|| panic!("{n} missing:\n{m}"));
        assert!(pos("mkfs.ext4") < pos("chown -R \"$u:$(id -g \"$u\")\" \"$mnt\""));
        assert!(
            pos("chown -R") < pos("us systemctl --user start anvil-ghr-sandbox-docker.service")
        );
        assert!(pos("us systemctl --user start") < pos("ud load -q <\"$tar\""));
        assert!(
            pos("ud load") < pos("chown \"$u\" \"$env\"")
                && pos("chown \"$u\" \"$env\"") < pos("ud create")
        );
        assert!(
            pos("us systemctl --user stop anvil-ghr-sandbox-docker.service")
                < pos("umount \"$mnt\"")
        );
        // A slot that ran in root's Docker before leaves no sandbox or mount behind.
        assert!(m.contains("|| docker rm -fv \"$ctr\""));
        assert!(m.contains("umount '/var/lib/anvil-ci'/github-runner-\"$name\".mnt"));
    }

    #[test]
    fn rootless_declaration_has_slot_users_and_no_sysbox_or_daemon_json() {
        let d = decl(RL);
        let has = |p: &str| d.files.iter().any(|f| f.path == p);
        assert!(has(USER_UNIT_PATH) && !has("/etc/docker/daemon.json"));
        let apply = d.render_apply();
        for gone in ["sysbox", "fusermount3"] {
            assert!(!apply.contains(gone), "{gone}");
        }
        for want in [
            "useradd --system --gid anvil-ghr-ci-2",
            "usermod -c umask=022 'anvil-ghr-ci-1'",
            "loginctl enable-linger 'anvil-ghr-ci-2'",
            "docker save -o '/var/lib/anvil-ci/github-runner-sandbox.tar'.tmp",
        ] {
            assert!(apply.contains(want), "{want}");
        }
        let n = |x: &str| apply.matches(x).count();
        assert_eq!(
            n("rootless docker helpers"),
            n("anvil-ghr-ci-1 user manager lingers")
        );
        let r = d.reload.unwrap();
        assert!(r.validate.starts_with("{ true; }") && !r.reload.contains("__dj="));
        assert!(r
            .reload
            .contains("mountpoint -q '/var/lib/anvil-ghr-ci-2/vol'"));
        let unit = eph(&cfg(RL), false).unit_content("ci", 1);
        assert!(!unit.contains("docker.service") && unit.contains("NoNewPrivileges=yes\n"));
        let uu = eph(&cfg(RL), false).user_unit_content();
        assert!(uu.contains("ConditionUser=|anvil-ghr-ci-1\nConditionUser=|anvil-ghr-ci-2\n"));
    }

    #[test]
    fn rootless_rollback_unmounts_then_drops_the_slot_users() {
        let rb = decl(RL).render_rollback();
        let pos = |n: &str| rb.find(n).unwrap_or_else(|| panic!("{n} missing"));
        assert!(
            pos("umount '/var/lib/anvil-ghr-ci-2/vol'")
                < pos("loginctl disable-linger 'anvil-ghr-ci-2'")
        );
        assert!(
            pos("loginctl disable-linger 'anvil-ghr-ci-2'")
                < pos("rm -rf '/var/lib/anvil-ghr-ci-2'")
        );
        assert!(pos("rm -rf '/var/lib/anvil-ghr-ci-2'") < pos("userdel anvil-ghr-ci-2"));
        assert!(rb.contains("rm -f '/var/lib/anvil-ci/github-runner-sandbox.tar'"));
        assert!(
            !rb.contains("__docker_restart=1"),
            "root dockerd was never reconfigured"
        );
    }

    #[test]
    fn rootless_scripts_parse_under_bash_n() {
        let d = decl(RL);
        for s in [
            d.render_probe(),
            d.render_apply(),
            d.render_rollback(),
            eph(&cfg(RL), true).minter_content("ci"),
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
    fn cleanup_deletes_unused_runners_and_keeps_failures() {
        let m = eph(&cfg(""), false).minter_content("ci");
        let a = m.find("b64url()").unwrap();
        let fns = &m[a..m.find("\ncase \"${2:-loop}\"").unwrap()];
        let d = std::env::temp_dir().join(format!("anvil-ghids-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let run = |mint: &str| {
            let ids = d.join("ids");
            std::fs::write(&ids, "11\n22\n33\n").unwrap();
            let script = format!(
                "set -euo pipefail\nctr=c mnt=/nonexistent ids={ids}\n{fns}\n\
                 docker() {{ :; }}\nmountpoint() {{ return 1; }}\nmint_token() {{ {mint}; }}\n\
                 gh_delete() {{ case $2 in */11) echo 204 ;; */22) echo 404 ;; *) echo 502 ;; esac; }}\n\
                 cleanup",
                ids = ids.display()
            );
            let out = Command::new("bash").args(["-c", &script]).output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            std::fs::read_to_string(&ids).unwrap()
        };
        // 204 deleted, 404 already gone (ran its job), 502 kept for the next cleanup.
        assert_eq!(run("echo t"), "33\n");
        // No token (offline): every id stays, and cleanup still succeeds.
        assert_eq!(run("false"), "11\n22\n33\n");
        std::fs::remove_dir_all(&d).unwrap();
        assert!(m.contains("printf '%s' \"$jit\" | jq -er .runner.id >>\"$ids\""));
    }
}
