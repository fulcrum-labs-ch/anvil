//! Pieces shared by the CI runner modules (`github_runner`, `forgejo_runner`;
//! docs/design/github-actions-runner.md §1, §5): the unprivileged system
//! account (recorded in the engine's created list, GR15), a pinned download
//! verified with `sha256sum -c` before anything uses it, and the hardened
//! systemd unit with the optional cgroup caps (GR17).
//!
//! Every config-derived value reaching bash goes through [`shell_escape`] here
//! or at the caller; unit content is static and base64-embedded by the engine.

use crate::config::Engine;
use crate::engine::{ManagedCommand, ManagedFile, MARK_CHANGED, MARK_FAILED, MARK_OK};
use crate::escape::shell_escape;

/// The runner's system account. `root` holds what anvil installs for the
/// runners; while it is non-empty, rollback keeps the account.
pub struct Account<'a> {
    /// Module id, used as the prefix of every marker message.
    pub module: &'a str,
    pub user: &'a str,
    pub home: &'a str,
    pub root: &'a str,
    /// What is left under `root` when rollback keeps the user, e.g. "runner trees".
    pub leftover: &'a str,
}

impl Account<'_> {
    /// Created-list entry for the user (`/var/lib/anvil/created`).
    pub fn created_user(&self) -> String {
        format!("user:{}", self.user)
    }

    pub fn created_group(&self) -> String {
        format!("group:{}", self.user)
    }

    /// Group and user are recorded only when anvil ran `groupadd`/`useradd`,
    /// so rollback never deletes an account the operator already had.
    pub fn ensure(&self) -> ManagedCommand {
        let Account {
            user, home, root, ..
        } = self;
        let (cu, cg) = (self.created_user(), self.created_group());
        ManagedCommand::new(
            format!("{user} system user and directories"),
            format!("id -u {user} >/dev/null 2>&1 && [ -d {home} ] && [ -d {root} ]"),
            format!(
                "getent group {user} >/dev/null 2>&1 || \
                 {{ groupadd --system {user}; __anvil_remember {cg}; }}\n\
                 id -u {user} >/dev/null 2>&1 || {{ useradd --system --gid {user} \
                 --home-dir {home} --shell /usr/sbin/nologin {user}; __anvil_remember {cu}; }}\n\
                 install -d -m 0750 -o {user} -g {user} {home}\n\
                 install -d -m 0755 {root}"
            ),
        )
    }

    /// Runs after every runner's rollback: drop the account only if anvil
    /// created it and `root` is empty (a kept or unknown runner still needs
    /// it). The home (caches) is kept: no `userdel -r`.
    pub fn rollback(&self) -> String {
        let Account {
            module,
            user,
            home,
            root,
            leftover,
        } = self;
        let (cu, cg) = (self.created_user(), self.created_group());
        format!(
            "\n# rollback {user} user (only if anvil created it)\n\
             if __anvil_created {cu}; then\n\
             \x20 if [ -n \"$(ls -A {root} 2>/dev/null)\" ]; then\n\
             \x20\x20 printf '{ok} {module}: {user} user kept; {leftover} remain under {root}\\n'\n\
             \x20 elif ! id -u {user} >/dev/null 2>&1 || userdel {user}; then\n\
             \x20\x20 __anvil_forget {cu}\n\
             \x20\x20 printf '{changed} {module}: {user} user removed (created by anvil; {home} kept)\\n'\n\
             \x20 else\n\
             \x20\x20 printf '{failed} {module}: userdel {user} failed (job processes still running?); re-run rollback\\n'\n\
             \x20 fi\n\
             fi\n\
             if __anvil_created {cg} && ! __anvil_created {cu}; then\n\
             \x20 if id -u {user} >/dev/null 2>&1; then\n\
             \x20\x20 printf '{ok} {module}: {user} group kept; the user still exists\\n'\n\
             \x20 elif ! getent group {user} >/dev/null 2>&1 || groupdel {user}; then\n\
             \x20\x20 __anvil_forget {cg}\n\
             \x20\x20 printf '{changed} {module}: {user} group removed (created by anvil)\\n'\n\
             \x20 else\n\
             \x20\x20 printf '{failed} {module}: groupdel {user} failed\\n'\n\
             \x20 fi\n\
             fi\n",
            ok = MARK_OK,
            changed = MARK_CHANGED,
            failed = MARK_FAILED,
        )
    }
}

/// A pinned release asset for amd64 and arm64.
pub struct Download<'a> {
    pub module: &'a str,
    /// Upstream's names for amd64 and arm64; the chosen one is `${__ra}`.
    pub arch_names: (&'a str, &'a str),
    /// Expected SHA-256 for amd64 and arm64 (escaped here).
    pub sha256: (&'a str, &'a str),
    /// Bash word for the URL; may use `${__ra}`. Values in it must be escaped.
    pub url: &'a str,
    /// File name under `$__tmp`.
    pub file: &'a str,
    /// Named in the mismatch message, e.g. "runner tarball".
    pub what: &'a str,
}

impl Download<'_> {
    /// Bash that leaves the verified asset at `"$__tmp/<file>"` (a
    /// fresh dir under the engine's `$__rundir`, so an abort leaves nothing) or exits 1 with `FAILED:`. No
    /// `curl | sh`: nothing touches the file before `sha256sum -c` passed.
    pub fn script(&self) -> String {
        let Download {
            module,
            arch_names: (amd64, arm64),
            url,
            file,
            what,
            ..
        } = self;
        format!(
            "case \"$(dpkg --print-architecture)\" in\n\
             \x20 amd64) __ra={amd64}; __sha={sha_amd64} ;;\n\
             \x20 arm64) __ra={arm64}; __sha={sha_arm64} ;;\n\
             \x20 *) printf '{failed} {module}: unsupported architecture %s\\n' \"$(dpkg --print-architecture)\"; exit 1 ;;\n\
             esac\n\
             __tmp=$(mktemp -d -p \"$__rundir\")\n\
             curl -fsSL --proto '=https' -o \"$__tmp/{file}\" {url}\n\
             if ! printf '%s  %s\\n' \"$__sha\" \"$__tmp/{file}\" | sha256sum -c --status -; then\n\
             \x20 rm -rf \"$__tmp\"\n\
             \x20 printf '{failed} {module}: {what} checksum mismatch\\n'\n\
             \x20 exit 1\n\
             fi\n",
            sha_amd64 = shell_escape(self.sha256.0),
            sha_arm64 = shell_escape(self.sha256.1),
            failed = MARK_FAILED,
        )
    }
}

/// `CPUQuota=`/`MemoryMax=`/`TasksMax=` lines for the configured caps (GR17:
/// the runner and every job share the unit's cgroup). Values are validated at
/// load to a systemd-safe charset.
pub fn cgroup_caps(
    cpu_quota: Option<&str>,
    memory_max: Option<&str>,
    tasks_max: Option<u32>,
) -> String {
    let mut s = String::new();
    if let Some(q) = cpu_quota {
        s.push_str(&format!("CPUQuota={q}\n"));
    }
    if let Some(m) = memory_max {
        s.push_str(&format!("MemoryMax={m}\n"));
    }
    if let Some(t) = tasks_max {
        s.push_str(&format!("TasksMax={t}\n"));
    }
    s
}

/// A hardened runner unit. `service` holds the module's own `[Service]` lines
/// (environment, caps, stop/restart policy); `rw_paths` is the only writable
/// part of the filesystem besides the private /tmp.
///
/// `rootless` (`docker = "podman"` or `"rootless"`): a rootless engine runs
/// inside this unit, so it drops what Podman and rootlesskit cannot live under — setuid `newuidmap` (NoNewPrivileges,
/// the empty bounding set), setuid files in images (RestrictSUIDSGID),
/// /dev/net/tun and /dev/fuse (PrivateDevices), and fresh proc/sysfs mounts in
/// a user namespace (ProtectKernelTunables/ProtectControlGroups overmounts).
/// It needs the user's lingering manager (`/run/user/<uid>` and its bus:
/// Ubuntu's pasta profile, aardvark-dns' scope), so `/home` and `/root` stay
/// hidden by a tmpfs and only `/run/user/<uid>` is bound in.
pub fn unit(
    description: &str,
    user: &str,
    workdir: &str,
    exec_start: &str,
    service: &str,
    rw_paths: &str,
    rootless: bool,
) -> String {
    let strict = if rootless {
        ""
    } else {
        "NoNewPrivileges=yes\n"
    };
    let devices = if rootless {
        ""
    } else {
        "PrivateDevices=yes\n\
         CapabilityBoundingSet=\n\
         ProtectKernelTunables=yes\n"
    };
    let cgroups = if rootless {
        ""
    } else {
        "ProtectControlGroups=yes\n\
         RestrictSUIDSGID=yes\n"
    };
    let (manager, home) = if rootless {
        (
            format!("After=user@{RUNNER_UID}.service\nWants=user@{RUNNER_UID}.service\n"),
            format!("ProtectHome=tmpfs\nBindPaths=/run/user/{RUNNER_UID}\n"),
        )
    } else {
        (String::new(), "ProtectHome=yes\n".to_string())
    };
    format!(
        "# Managed by anvil — do not edit by hand\n\
         [Unit]\n\
         Description={description}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         {manager}\
         \n\
         [Service]\n\
         User={user}\n\
         WorkingDirectory={workdir}\n\
         ExecStart={exec_start}\n\
         {service}\
         {strict}\
         ProtectSystem=strict\n\
         ReadWritePaths={rw_paths}\n\
         {home}\
         PrivateTmp=yes\n\
         {devices}\
         ProtectKernelModules=yes\n\
         {cgroups}\
         LockPersonality=yes\n\
         OOMPolicy=continue\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Placeholder for the runner user's uid in a podman-mode unit; [`unit_file`]
/// fills it in on the host (the account exists only after its command ran).
pub const RUNNER_UID: &str = "ANVIL_RUNNER_UID";

/// The unit as a managed file: static, or with [`RUNNER_UID`] replaced by the
/// user's uid on the host (0 before the account exists: the probe drifts).
pub fn unit_file(path: &str, content: String, user: &str) -> ManagedFile {
    if !content.contains(RUNNER_UID) {
        return ManagedFile::new(path, content, "0644", "root:root");
    }
    ManagedFile::computed(
        path,
        format!(
            "__u=$(id -u {} 2>/dev/null) || __u=0; __t={}; printf '%s' \"${{__t//{RUNNER_UID}/$__u}}\"",
            shell_escape(user),
            shell_escape(&content)
        ),
        "0644",
        "root:root",
    )
}

/// `docker = "podman"`: the unit's own dir under the user's `/run/user/<uid>`
/// (socket, podman's runroot and tmpdir), one per unit: one runroot pairs
/// with one HOME graphroot even when runners share the user.
/// `XDG_RUNTIME_DIR` itself stays `/run/user/<uid>`: sd-bus finds the user
/// bus and manager only there (netavark's `systemd-run --user` for
/// aardvark-dns), and Ubuntu's pasta profile allows netns files under it.
pub fn podman_runtime(runtime_dir: &str) -> String {
    format!("/run/user/{RUNNER_UID}/{runtime_dir}")
}

/// `docker = "podman"`: the unit's own rootless Podman API socket.
pub fn podman_socket(runtime_dir: &str) -> String {
    format!("{}/podman.sock", podman_runtime(runtime_dir))
}

/// `ExecStart=` for `docker = "podman"`: start `podman system service` in the
/// unit, wait (bounded) for its socket, then exec the runner. Containers are
/// spawned by that service, so they stay in this unit's cgroup — in
/// `ci.slice` and under the unit's caps. cgroupfs, not systemd, so
/// podman never hands containers to the user manager. `CONTAINER_HOST` is
/// unset for the service itself, or podman would start as a remote client of
/// itself.
pub fn podman_exec(runtime_dir: &str, exec: &str) -> String {
    let (rt, sock) = (podman_runtime(runtime_dir), podman_socket(runtime_dir));
    format!(
        "/bin/bash -c 'env -u CONTAINER_HOST podman --cgroup-manager=cgroupfs \
         --runroot {rt}/containers --tmpdir {rt}/libpod system service \
         --time=0 unix://{sock} & for _ in $$(seq 100); do [ -S {sock} ] && break; sleep 0.1; done; \
         exec {exec}'"
    )
}

/// Rootless podman's pause process (it holds the user namespace) records its
/// pid in `$XDG_RUNTIME_DIR/libpod/tmp/pause.pid` (`--tmpdir` does not move
/// it). Stopping the unit kills the process, but the file outlives it in the
/// lingering `/run/user/<uid>`, and the next podman fails to join the dead
/// namespace. Removed unless that pid is still a `podman pause` (not a
/// reused pid). Bash for `ExecStartPre=` (systemd turns `$$` into `$`).
pub fn pause_pid_cleanup() -> String {
    format!(
        "f=/run/user/{RUNNER_UID}/libpod/tmp/pause.pid; [ ! -f \"$$f\" ] || \
         [ \"$$(cat \"/proc/$$(cat \"$$f\")/comm\" 2>/dev/null)\" = \"podman pause\" ] || rm -f \"$$f\""
    )
}

/// `[Service]` lines for `docker = "podman"`: the runtime dir is made before
/// and removed after each run (stale podman state must not survive a
/// restart), a stale pause pid is cleared ([`pause_pid_cleanup`]); the bus is the user manager's (netavark starts aardvark-dns in a
/// user scope). `DOCKER_HOST` reaches Docker-API clients (forgejo-runner,
/// actions/runner's socket mount); `CONTAINER_HOST` makes the `podman-docker`
/// shim a client of the same service. actions/runner mounts
/// `/var/run/docker.sock` into every job and service container; podman-docker's
/// `/run/docker.sock` links to `/run/podman/podman.sock`, so the unit's own
/// dir is bound over `/run/podman` in its private namespace: jobs get this
/// rootless socket, never a root one (`-`: absent until `ExecStartPre` made it).
/// `KillMode=mixed`: the runner drains its
/// jobs first; the service and leftover containers are killed after it exits.
/// `Delegate=yes` chowns the unit's cgroup to `User=`: rootless podman that
/// does not own its cgroup moves itself (and every container) into a user
/// scope, out of `ci.slice`, the caps and `KillMode`. With
/// `--cgroup-manager=cgroupfs` the containers' cgroups are children of it.
pub fn podman_service(runtime_dir: &str) -> String {
    let (rt, sock) = (podman_runtime(runtime_dir), podman_socket(runtime_dir));
    let pause = pause_pid_cleanup();
    format!(
        "ExecStartPre=/bin/mkdir -p -m 0700 {rt}\n\
         ExecStartPre=/bin/sh -c '{pause}'\n\
         ExecStopPost=-/bin/rm -rf {rt}\n\
         BindPaths=-{rt}:/run/podman\n\
         Environment=XDG_RUNTIME_DIR=/run/user/{RUNNER_UID}\n\
         Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{RUNNER_UID}/bus\n\
         Environment=DOCKER_HOST=unix://{sock}\n\
         Environment=CONTAINER_HOST=unix://{sock}\n\
         KillMode=mixed\n\
         Delegate=yes\n"
    )
}

/// `docker = "rootless"` on a Docker host: a rootless dockerd started inside
/// the unit, like [`podman_exec`]. `XDG_RUNTIME_DIR` is the unit's own dir
/// (rootlesskit state, exec-root, socket), so runners sharing the user never
/// share one; the data-root is `$HOME/.local/share/docker`, per runner HOME.
/// cgroupfs: the unit has no user bus, and containers stay in its cgroup —
/// in `ci.slice` and under the unit's caps. Jobs' `/var/run/docker.sock`
/// mount (actions/runner) still names the root socket, which the
/// runner's uid cannot open: docker-in-job needs `group` or the v2 runner.
pub fn dockerd_exec(runtime_dir: &str, exec: &str) -> String {
    let sock = dockerd_socket(runtime_dir);
    format!(
        "/bin/bash -c '/usr/bin/dockerd-rootless.sh --exec-opt native.cgroupdriver=cgroupfs \
         -H unix://{sock} & for _ in $$(seq 300); do [ -S {sock} ] && break; sleep 0.1; done; \
         exec {exec}'"
    )
}

/// `docker = "rootless"` on a Docker host: the unit's rootless dockerd socket.
pub fn dockerd_socket(runtime_dir: &str) -> String {
    format!("{}/docker.sock", podman_runtime(runtime_dir))
}

/// `[Service]` lines for [`dockerd_exec`]: the runtime dir is made before and
/// removed after each run (rootlesskit refuses a stale state dir);
/// `KillMode=mixed` and `Delegate=yes` as in [`podman_service`].
pub fn dockerd_service(runtime_dir: &str) -> String {
    let rt = podman_runtime(runtime_dir);
    format!(
        "ExecStartPre=/bin/mkdir -p -m 0700 {rt}\n\
         ExecStopPost=-/bin/rm -rf {rt}\n\
         Environment=XDG_RUNTIME_DIR={rt}\n\
         Environment=DOCKER_HOST=unix://{sock}\n\
         KillMode=mixed\n\
         Delegate=yes\n",
        sock = dockerd_socket(runtime_dir),
    )
}

/// `ExecStart=` and `[Service]` lines for a runner unit running `exec` next
/// to its own rootless `engine` in `runtime_dir`.
pub fn rootless_exec(engine: Engine, runtime_dir: &str, exec: &str) -> (String, String) {
    match engine {
        Engine::Podman => (podman_exec(runtime_dir, exec), podman_service(runtime_dir)),
        Engine::Docker => (
            dockerd_exec(runtime_dir, exec),
            dockerd_service(runtime_dir),
        ),
    }
}

/// Subordinate IDs per user (`useradd --system` allocates none).
const SUBID_COUNT: u32 = 65536;

/// What a rootless engine needs on the host for `user` besides the engine
/// (`ensure_engine` runs first): its helpers, setuid id mappers, a subordinate
/// id range and a lingering manager with its bus. `restart` is the module's
/// restart flag, set when the user gains subordinate IDs (the engine needs them).
pub fn rootless(engine: Engine, user: &str, restart: &str) -> Vec<ManagedCommand> {
    let n = SUBID_COUNT;
    let u = shell_escape(user);
    let linger = shell_escape(&format!("/var/lib/systemd/linger/{user}"));
    let starts = shell_escape(&format!("^{user}:"));
    let (what, helpers) = match engine {
        Engine::Podman => (
            "podman",
            ManagedCommand::new(
                "rootless podman helpers (uidmap, passt, podman-docker, dbus-user-session)",
                format!(
                    "command -v newuidmap >/dev/null 2>&1 && command -v pasta >/dev/null 2>&1 \
                     && [ -x /usr/bin/docker ] && {}",
                    super::dpkg_installed("dbus-user-session")
                ),
                super::apt_install(&["uidmap", "passt", "podman-docker", "dbus-user-session"]),
            ),
        ),
        // docker-ce-rootless-extras: dockerd-rootless.sh and rootlesskit, from
        // Docker's repo (validation refuses `[docker] source = "distro"`).
        Engine::Docker => (
            "docker",
            ManagedCommand::new(
                "rootless docker helpers (docker-ce-rootless-extras, uidmap, slirp4netns, dbus-user-session)",
                format!(
                    "command -v newuidmap >/dev/null 2>&1 && command -v slirp4netns >/dev/null 2>&1 \
                     && [ -x /usr/bin/dockerd-rootless.sh ] && {}",
                    super::dpkg_installed("dbus-user-session")
                ),
                super::apt_install(&[
                    "docker-ce-rootless-extras",
                    "uidmap",
                    "slirp4netns",
                    "dbus-user-session",
                ]),
            ),
        ),
    };
    vec![
        helpers,
        // The suid module allowlists both helpers; this only catches a host
        // that stripped them by hand.
        ManagedCommand::new(
            "newuidmap/newgidmap setuid or file caps",
            "{ [ -u /usr/bin/newuidmap ] || getcap /usr/bin/newuidmap 2>/dev/null | grep cap_setuid >/dev/null; } \
             && { [ -u /usr/bin/newgidmap ] || getcap /usr/bin/newgidmap 2>/dev/null | grep cap_setgid >/dev/null; }",
            format!(
                "printf '{MARK_FAILED} rootless {what}: /usr/bin/newuidmap and newgidmap need setuid \
                 or file caps (apt-get install --reinstall uidmap)\\n'\nexit 1"
            ),
        ),
        // First free range above every existing one, in both files; the start
        // is recorded so rollback deletes exactly this range.
        ManagedCommand::new(
            format!("{user} subordinate uid/gid range"),
            format!("grep -q {starts} /etc/subuid 2>/dev/null && grep -q {starts} /etc/subgid 2>/dev/null"),
            format!(
                "__s=$(cat /etc/subuid /etc/subgid 2>/dev/null | awk -F: \
                 'BEGIN {{ m = 100000 }} $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {{ if ($2 + $3 > m) m = $2 + $3 }} END {{ print m }}')\n\
                 usermod --add-subuids \"$__s-$((__s + {last}))\" --add-subgids \"$__s-$((__s + {last}))\" {u}\n\
                 __anvil_remember {token}\"$__s\"\n\
                 {restart}",
                last = n - 1,
                token = shell_escape(&format!("subids:{user}:")),
            ),
        ),
        // The unit binds /run/user/<uid> and uses its bus; lingering keeps
        // both up without a login. Recorded only when anvil enabled it.
        ManagedCommand::new(
            format!("{user} user manager lingers (/run/user/<uid>, its bus)"),
            format!(
                "[ -e {linger} ] && __u=$(id -u {u}) && systemctl is-active --quiet \"user@$__u.service\" \
                 && [ -S \"/run/user/$__u/bus\" ]"
            ),
            format!(
                "if [ ! -e {linger} ]; then loginctl enable-linger {u}; __anvil_remember {token}; fi\n\
                 __u=$(id -u {u})\n\
                 systemctl start \"user@$__u.service\"\n\
                 # a manager started before dbus-user-session has no bus socket yet\n\
                 [ -S \"/run/user/$__u/bus\" ] || systemctl restart \"user@$__u.service\"\n\
                 for _ in $(seq 50); do [ -S \"/run/user/$__u/bus\" ] && break; sleep 0.1; done\n\
                 [ -S \"/run/user/$__u/bus\" ] || {{ printf '{MARK_FAILED} rootless {what}: no user bus at /run/user/%s/bus\\n' \"$__u\"; exit 1; }}\n\
                 {restart}",
                token = shell_escape(&format!("linger:{user}")),
            ),
        ),
    ]
}

/// Rollback for [`rootless`]: delete only the ranges anvil added and
/// stop lingering only if anvil enabled it. Runs
/// after the units stopped and before the account's rollback.
pub fn rootless_rollback(user: &str) -> String {
    let u = shell_escape(user);
    let lt = shell_escape(&format!("linger:{user}"));
    format!(
        "\n# rollback {user}: stop its user manager and processes, then its subordinate ids\n\
         if grep -qE {any} \"$__created_list\" 2>/dev/null; then\n\
         \x20 if grep -qxF {lt} \"$__created_list\"; then\n\
         \x20\x20 loginctl disable-linger {u} || true\n\
         \x20\x20 __anvil_forget {lt}\n\
         \x20\x20 printf '{MARK_CHANGED} %s: linger disabled\\n' {u}\n\
         \x20 fi\n\
         \x20 if __u=$(id -u {u} 2>/dev/null); then\n\
         \x20\x20 systemctl stop \"user@$__u.service\" 2>/dev/null || true\n\
         \x20\x20 pkill -KILL -u {u} 2>/dev/null || true\n\
         \x20\x20 for _ in $(seq 50); do pgrep -u {u} >/dev/null 2>&1 || break; sleep 0.1; done\n\
         \x20 fi\n\
         fi\n\
         for __s in $(sed -n {sed} \"$__created_list\" 2>/dev/null); do\n\
         \x20 __r=\"$__s-$((__s + {last}))\"\n\
         \x20 if ! id -u {u} >/dev/null 2>&1 \\\n\
         \x20\x20 || [ -z \"$(cat /etc/subuid /etc/subgid 2>/dev/null | grep {starts}\"$__s:\")\" ]; then\n\
         \x20\x20 __anvil_forget {st}\"$__s\"\n\
         \x20\x20 printf '{MARK_OK} %s: subordinate ids %s already gone\\n' {u} \"$__r\"\n\
         \x20 elif __e=$(usermod --del-subuids \"$__r\" --del-subgids \"$__r\" {u} 2>&1); then\n\
         \x20\x20 __anvil_forget {st}\"$__s\"\n\
         \x20\x20 printf '{MARK_CHANGED} %s: subordinate ids %s removed\\n' {u} \"$__r\"\n\
         \x20 else\n\
         \x20\x20 printf '{MARK_FAILED} %s: usermod --del-subuids %s failed: %s\\n' {u} \"$__r\" \"$__e\"\n\
         \x20 fi\n\
         done\n",
        any = shell_escape(&format!("^(linger|subids):{user}(:|$)")),
        sed = shell_escape(&format!("s/^subids:{user}://p")),
        starts = shell_escape(&format!("^{user}:")),
        st = shell_escape(&format!("subids:{user}:")),
        last = SUBID_COUNT - 1,
    )
}

/// Tool caches jobs leave in the runner's HOME. Not `~/.local`
/// (rootless Podman's and Docker's storage) nor `~/go` (read-only module trees).
pub const HOME_CACHES: [&str; 4] = [".cache", ".cargo", ".rustup", ".npm"];

/// Prune-script lines: wipe `home`'s [`HOME_CACHES`] once together past
/// `max` bytes, only while `idle` (a shell test) holds. `home` is a fixed,
/// validated path (single-quoted as is).
pub fn home_cache_prune(home: &str, max: u64, idle: &str) -> String {
    let dirs: Vec<String> = HOME_CACHES
        .iter()
        .map(|d| format!("'{home}/{d}'"))
        .collect();
    let dirs = dirs.join(" ");
    format!(
        "if [ \"$(du -sbc {dirs} 2>/dev/null | tail -n 1 | cut -f 1)\" -gt {max} ] && {idle}; then\n\
         \x20 rm -rf -- {dirs}\n\
         fi\n"
    )
}

/// The daily prune timer of a runner module.
pub fn prune_timer_content(what: &str) -> String {
    format!(
        "# Managed by anvil — do not edit by hand\n\
         [Unit]\n\
         Description=Daily prune of {what} (anvil)\n\
         \n\
         [Timer]\n\
         OnCalendar=daily\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const ACCOUNT: Account = Account {
        module: "demo_runner",
        user: "demo-runner",
        home: "/var/lib/demo-runner",
        root: "/opt/demo-runner",
        leftover: "runner trees",
    };

    fn download() -> Download<'static> {
        Download {
            module: "demo_runner",
            arch_names: ("amd64", "arm64"),
            sha256: ("aa", "bb"),
            url: "\"https://example.org/demo-${__ra}\"",
            file: "demo.bin",
            what: "demo binary",
        }
    }

    fn bash_n(script: &str) {
        let out = Command::new("bash")
            .args(["-n", "-c", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{script}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn checksum_check_precedes_any_use_and_a_mismatch_fails() {
        let s = download().script();
        bash_n(&s);
        assert!(s.contains("amd64) __ra=amd64; __sha='aa' ;;"));
        assert!(s.contains("arm64) __ra=arm64; __sha='bb' ;;"));
        assert!(s.contains(
            "curl -fsSL --proto '=https' -o \"$__tmp/demo.bin\" \"https://example.org/demo-${__ra}\""
        ));
        let fetch = s.find("curl ").unwrap();
        let check = s
            .find("if ! printf '%s  %s\\n' \"$__sha\" \"$__tmp/demo.bin\" | sha256sum -c --status -; then")
            .unwrap();
        let fail = s
            .find("printf 'FAILED: demo_runner: demo binary checksum mismatch\\n'\n  exit 1\nfi\n")
            .unwrap();
        assert!(fetch < check && check < fail);
        assert!(s.ends_with("fi\n"));
        assert!(s.contains("*) printf 'FAILED: demo_runner: unsupported architecture %s\\n'"));
    }

    #[test]
    fn bad_hash_fails_and_good_hash_passes_under_bash() {
        // Run just the verification against a real file: the wrong hash must
        // exit 1 with FAILED:, the right one must fall through.
        let s = download().script();
        let verify = &s[s.find("if ! printf").unwrap()..];
        let run = |sha: &str| {
            Command::new("bash")
                .args([
                    "-euo",
                    "pipefail",
                    "-c",
                    &format!(
                        "__tmp=$(mktemp -d); printf x > \"$__tmp/demo.bin\"; __sha={sha}\n{verify}echo PASSED"
                    ),
                ])
                .output()
                .unwrap()
        };
        let good = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881";
        let ok = run(good);
        assert!(String::from_utf8_lossy(&ok.stdout).contains("PASSED"));
        let bad = run(&"0".repeat(64));
        assert_eq!(bad.status.code(), Some(1));
        let out = String::from_utf8_lossy(&bad.stdout);
        assert!(out.contains("FAILED: demo_runner: demo binary checksum mismatch"));
        assert!(!out.contains("PASSED"));
    }

    #[test]
    fn unit_contains_the_hardening_lines_and_the_module_lines() {
        let u = unit(
            "Demo runner (anvil)",
            "demo-runner",
            "/var/lib/demo-runner",
            "/usr/local/bin/demo daemon",
            "Restart=always\n",
            "/var/lib/demo-runner",
            false,
        );
        let svc = u.split("[Install]").next().unwrap();
        for line in [
            "\nDescription=Demo runner (anvil)\n",
            "\nUser=demo-runner\n",
            "\nWorkingDirectory=/var/lib/demo-runner\n",
            "\nExecStart=/usr/local/bin/demo daemon\nRestart=always\nNoNewPrivileges=yes\n",
            "\nProtectSystem=strict\n",
            "\nReadWritePaths=/var/lib/demo-runner\n",
            "\nProtectHome=yes\n",
            "\nPrivateTmp=yes\n",
            "\nPrivateDevices=yes\n",
            "\nCapabilityBoundingSet=\n",
            "\nProtectKernelTunables=yes\n",
            "\nProtectKernelModules=yes\n",
            "\nProtectControlGroups=yes\n",
            "\nRestrictSUIDSGID=yes\n",
            "\nLockPersonality=yes\n",
            "\nOOMPolicy=continue\n",
        ] {
            assert!(svc.contains(line), "[Service] missing {line:?}:\n{u}");
        }
        assert!(u.ends_with("[Install]\nWantedBy=multi-user.target\n"));
    }

    #[test]
    fn podman_unit_drops_only_what_rootless_podman_cannot_run_under() {
        let u = unit("D", "u", "/w", "/x", "", "/w", true);
        for gone in [
            "NoNewPrivileges",
            "PrivateDevices",
            "CapabilityBoundingSet",
            "ProtectKernelTunables",
            "ProtectControlGroups",
            "RestrictSUIDSGID",
        ] {
            assert!(!u.contains(gone), "{gone} kept:\n{u}");
        }
        assert!(
            u.contains(
                "\nExecStart=/x\nProtectSystem=strict\nReadWritePaths=/w\nProtectHome=tmpfs\n\
                 BindPaths=/run/user/ANVIL_RUNNER_UID\nPrivateTmp=yes\nProtectKernelModules=yes\n\
                 LockPersonality=yes\nOOMPolicy=continue\n"
            ),
            "{u}"
        );
        // The user's manager (its /run/user/<uid> and bus) is up first.
        assert!(u.contains(
            "Wants=network-online.target\nAfter=user@ANVIL_RUNNER_UID.service\n\
             Wants=user@ANVIL_RUNNER_UID.service\n\n[Service]\n"
        ));
    }

    #[test]
    fn unit_file_fills_the_runner_uid_on_the_host_only_in_podman_mode() {
        let plain = unit("D", "u", "/w", "/x", "", "/w", false);
        let f = unit_file("/etc/u.service", plain.clone(), "u");
        assert_eq!(f.static_content(), Some(plain.as_str()));
        let u = unit("D", "u", "/w", "/x", &podman_service("rt"), "/w", true);
        let f = unit_file("/etc/u.service", u.clone(), "demo'user");
        let crate::engine::FileContent::Computed { generator } = &f.content else {
            panic!("podman units are computed");
        };
        assert!(generator.starts_with("__u=$(id -u 'demo'\\''user' 2>/dev/null) || __u=0; "));
        let run = |id: &str| {
            let out = Command::new("bash")
                .args(["-c", &format!("id() {{ {id}; }}\n{generator}")])
                .output()
                .unwrap();
            String::from_utf8(out.stdout).unwrap()
        };
        assert_eq!(run("echo 988"), u.replace(RUNNER_UID, "988"));
        assert!(run("echo 988").contains("BindPaths=/run/user/988\n"));
        assert_eq!(run("return 1"), u.replace(RUNNER_UID, "0"));
    }

    #[test]
    fn podman_runs_in_the_unit_and_every_client_finds_its_socket() {
        let e = podman_exec("demo", "/bin/demo daemon");
        assert_eq!(
            e,
            "/bin/bash -c 'env -u CONTAINER_HOST podman --cgroup-manager=cgroupfs \
             --runroot /run/user/ANVIL_RUNNER_UID/demo/containers \
             --tmpdir /run/user/ANVIL_RUNNER_UID/demo/libpod system service \
             --time=0 unix:///run/user/ANVIL_RUNNER_UID/demo/podman.sock & for _ in $$(seq 100); do \
             [ -S /run/user/ANVIL_RUNNER_UID/demo/podman.sock ] && break; sleep 0.1; done; \
             exec /bin/demo daemon'"
        );
        // systemd turns $$ into $; the rest must parse as bash.
        let inner = e
            .strip_prefix("/bin/bash -c '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap()
            .replace("$$", "$");
        bash_n(&inner);
        assert_eq!(
            podman_service("demo"),
            "ExecStartPre=/bin/mkdir -p -m 0700 /run/user/ANVIL_RUNNER_UID/demo\n\
             ExecStartPre=/bin/sh -c 'f=/run/user/ANVIL_RUNNER_UID/libpod/tmp/pause.pid; \
             [ ! -f \"$$f\" ] || [ \"$$(cat \"/proc/$$(cat \"$$f\")/comm\" 2>/dev/null)\" = \"podman pause\" ] \
             || rm -f \"$$f\"'\n\
             ExecStopPost=-/bin/rm -rf /run/user/ANVIL_RUNNER_UID/demo\n\
             BindPaths=-/run/user/ANVIL_RUNNER_UID/demo:/run/podman\n\
             Environment=XDG_RUNTIME_DIR=/run/user/ANVIL_RUNNER_UID\n\
             Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/ANVIL_RUNNER_UID/bus\n\
             Environment=DOCKER_HOST=unix:///run/user/ANVIL_RUNNER_UID/demo/podman.sock\n\
             Environment=CONTAINER_HOST=unix:///run/user/ANVIL_RUNNER_UID/demo/podman.sock\n\
             KillMode=mixed\nDelegate=yes\n"
        );
    }

    #[test]
    fn rootless_dockerd_runs_in_the_unit_on_its_own_runtime_dir() {
        let (e, svc) = rootless_exec(Engine::Docker, "demo", "/bin/demo daemon");
        let inner = e
            .strip_prefix("/bin/bash -c '")
            .and_then(|s| s.strip_suffix('\''))
            .unwrap()
            .replace("$$", "$");
        bash_n(&inner);
        assert!(inner.starts_with("/usr/bin/dockerd-rootless.sh "));
        assert!(inner.ends_with("; exec /bin/demo daemon"));
        assert!(svc.contains("Environment=XDG_RUNTIME_DIR=/run/user/ANVIL_RUNNER_UID/demo\n"));
        assert!(svc.contains(&format!(
            "Environment=DOCKER_HOST=unix://{}\n",
            dockerd_socket("demo")
        )));
        assert!(!svc.contains("BindPaths") && svc.ends_with("KillMode=mixed\nDelegate=yes\n"));
        assert_eq!(
            rootless_exec(Engine::Podman, "demo", "/x"),
            (podman_exec("demo", "/x"), podman_service("demo"))
        );
        let docker = rootless(Engine::Docker, "demo-runner", "__restart=1");
        assert!(docker[0].converge.contains("'docker-ce-rootless-extras'"));
        assert!(docker[0]
            .detect
            .contains("[ -x /usr/bin/dockerd-rootless.sh ]"));
        assert!(docker[1].converge.contains("FAILED: rootless docker"));
        // Only the helpers differ between the engines.
        let podman = rootless(Engine::Podman, "demo-runner", "__restart=1");
        assert_eq!(docker[2].converge, podman[2].converge);
    }

    #[test]
    fn a_stale_pause_pid_is_removed_and_a_live_one_kept() {
        // Round 4: a restart left pause.pid of the killed pause process,
        // and podman could not re-exec into the dead user namespace.
        let d = std::env::temp_dir().join(format!("anvil-pause-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let dir = d.to_str().unwrap();
        let script = pause_pid_cleanup()
            .replace("$$", "$")
            .replace("/run/user/ANVIL_RUNNER_UID/libpod/tmp", dir)
            .replace("/proc/", &format!("{dir}/proc/"));
        let run = |pid: &str, comm: Option<&str>| {
            std::fs::create_dir_all(d.join("proc/7")).unwrap();
            std::fs::write(d.join("pause.pid"), pid).unwrap();
            let _ = std::fs::remove_file(d.join("proc/7/comm"));
            if let Some(c) = comm {
                std::fs::write(d.join("proc/7/comm"), format!("{c}\n")).unwrap();
            }
            let ok = Command::new("bash")
                .args(["-euo", "pipefail", "-c", &script])
                .status()
                .unwrap()
                .success();
            (ok, d.join("pause.pid").exists())
        };
        assert_eq!(run("7", Some("podman pause")), (true, true), "live: kept");
        assert_eq!(run("7", Some("bash")), (true, false), "pid reused: removed");
        assert_eq!(run("7", None), (true, false), "dead: removed");
        assert_eq!(run("999999", None), (true, false));
        std::fs::remove_file(d.join("pause.pid")).ok();
        let ok = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .status()
            .unwrap();
        assert!(ok.success(), "no file: nothing to do");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Runs `script` with `cat`, `usermod`, `id` and the created-list helpers
    /// stubbed; `list` is the created list's content.
    fn run_stubbed(tag: &str, subids: &str, list: &str, script: &str) -> String {
        let created =
            std::env::temp_dir().join(format!("anvil-subids-{}-{tag}", std::process::id()));
        std::fs::write(&created, list).unwrap();
        let out = Command::new("bash")
            .args([
                "-euo",
                "pipefail",
                "-c",
                &format!(
                    "cat() {{ printf '%s' {subids}; }}\n\
                     usermod() {{ echo \"usermod $*\"; [ -z \"${{FAIL:-}}\" ] || {{ echo busy >&2; return 1; }}; }}\n\
                     pkill() {{ echo \"pkill $*\"; }}\n\
                     pgrep() {{ return 1; }}\n\
                     id() {{ [ \"${{1:-}}\" != -u ] || echo 4242; }}\n\
                     loginctl() {{ echo \"loginctl $*\"; }}\n\
                     systemctl() {{ echo \"systemctl $*\"; }}\n\
                     __anvil_remember() {{ echo \"remember $1\"; }}\n\
                     __anvil_forget() {{ echo \"forget $1\"; }}\n\
                     __created_list={created}\n{script}",
                    subids = shell_escape(subids),
                    created = shell_escape(&created.to_string_lossy()),
                ),
            ])
            .output()
            .unwrap();
        std::fs::remove_file(&created).unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    #[test]
    fn subids_take_the_first_free_range_and_rollback_removes_only_it() {
        let cmds = rootless(Engine::Podman, "demo-runner", "__restart=1");
        assert_eq!(cmds.len(), 4);
        assert!(cmds[0]
            .converge
            .contains("'uidmap' 'passt' 'podman-docker' 'dbus-user-session'"));
        assert!(cmds[0]
            .detect
            .contains("dpkg-query -W -f='${Status}' 'dbus-user-session'"));
        assert!(cmds[0].detect.contains("command -v newuidmap"));
        assert!(cmds[1].detect.contains("[ -u /usr/bin/newuidmap ]"));
        assert!(cmds[1].detect.contains("getcap /usr/bin/newgidmap"));
        assert!(cmds[1].converge.contains("FAILED: rootless podman"));
        assert!(cmds[1].converge.ends_with("\nexit 1"));
        let sub = &cmds[2];
        assert_eq!(
            sub.detect,
            "grep -q '^demo-runner:' /etc/subuid 2>/dev/null && \
             grep -q '^demo-runner:' /etc/subgid 2>/dev/null"
        );
        assert!(sub.converge.ends_with("\n__restart=1"));
        bash_n(&sub.converge);
        let add = |tag: &str, files: &str| run_stubbed(tag, files, "", &sub.converge);
        assert_eq!(
            add("empty", ""),
            "usermod --add-subuids 100000-165535 --add-subgids 100000-165535 demo-runner\n\
             remember subids:demo-runner:100000\n"
        );
        // Above the highest end in either file; malformed lines are ignored.
        let out = add("used", "alice:100000:65536\nbob:300000:1000\njunk\nx:a:b\n");
        assert!(
            out.starts_with(
                "usermod --add-subuids 301000-366535 --add-subgids 301000-366535 demo-runner\n"
            ),
            "{out}"
        );
        let rb = rootless_rollback("demo-runner");
        bash_n(&rb);
        let list = "user:demo-runner\nsubids:demo-runner:301000\nsubids:other:5\n";
        let held = "demo-runner:301000:65536\n";
        // The user's processes go first: usermod refuses a busy user.
        let stop = "systemctl stop user@4242.service\npkill -KILL -u demo-runner\n";
        assert_eq!(
            run_stubbed("rb", held, list, &rb),
            format!(
                "{stop}forget subids:demo-runner:301000\n\
                 CHANGED: demo-runner: subordinate ids 301000-366535 removed\n"
            )
        );
        // Idempotent: a range already gone is forgotten, not a failure.
        assert_eq!(
            run_stubbed("gone", "", list, &rb),
            format!(
                "{stop}forget subids:demo-runner:301000\n\
                 OK: demo-runner: subordinate ids 301000-366535 already gone\n"
            )
        );
        // A real failure keeps the record and says why.
        let out = run_stubbed("fail", held, list, &format!("FAIL=1\n{rb}"));
        assert_eq!(
            out,
            format!(
                "{stop}FAILED: demo-runner: usermod --del-subuids 301000-366535 failed: \
                 usermod --del-subuids 301000-366535 --del-subgids 301000-366535 demo-runner\n\
                 busy\n"
            )
        );
        assert_eq!(run_stubbed("none", "", "user:demo-runner\n", &rb), "");
    }

    #[test]
    fn linger_is_enabled_and_rolled_back_only_when_anvil_did_it() {
        let c = &rootless(Engine::Podman, "demo-runner", "__restart=1")[3];
        assert!(c
            .detect
            .starts_with("[ -e '/var/lib/systemd/linger/demo-runner' ] && "));
        assert!(c.detect.ends_with("&& [ -S \"/run/user/$__u/bus\" ]"));
        bash_n(&c.converge);
        assert!(c.converge.starts_with(
            "if [ ! -e '/var/lib/systemd/linger/demo-runner' ]; then loginctl enable-linger 'demo-runner'; \
             __anvil_remember 'linger:demo-runner'; fi\n"
        ));
        assert!(c
            .converge
            .contains("|| systemctl restart \"user@$__u.service\"\n"));
        assert!(c.converge.contains("FAILED: rootless podman: no user bus"));
        assert!(c.converge.ends_with("\n__restart=1"));
        let rb = rootless_rollback("demo-runner");
        let out = run_stubbed("linger", "", "user:demo-runner\nlinger:demo-runner\n", &rb);
        assert_eq!(
            out,
            "loginctl disable-linger demo-runner\nforget linger:demo-runner\n\
             CHANGED: demo-runner: linger disabled\n\
             systemctl stop user@4242.service\npkill -KILL -u demo-runner\n"
        );
    }

    #[test]
    fn caps_only_when_configured() {
        assert_eq!(cgroup_caps(None, None, None), "");
        assert_eq!(
            cgroup_caps(Some("400%"), Some("8G"), Some(512)),
            "CPUQuota=400%\nMemoryMax=8G\nTasksMax=512\n"
        );
        assert_eq!(cgroup_caps(None, Some("8G"), None), "MemoryMax=8G\n");
    }

    #[test]
    fn account_is_recorded_only_when_created_and_removed_only_then() {
        let c = ACCOUNT.ensure();
        bash_n(&c.converge);
        assert_eq!(c.describe, "demo-runner system user and directories");
        assert!(c
            .converge
            .contains("|| { groupadd --system demo-runner; __anvil_remember group:demo-runner; }"));
        assert!(c.converge.contains(
            "--shell /usr/sbin/nologin demo-runner; __anvil_remember user:demo-runner; }"
        ));
        assert!(c.detect.contains("[ -d /opt/demo-runner ]"));
        let rb = ACCOUNT.rollback();
        bash_n(&rb);
        let gate = rb
            .find("if __anvil_created user:demo-runner; then")
            .unwrap();
        let busy = rb
            .find("printf 'OK: demo_runner: demo-runner user kept; runner trees remain under /opt/demo-runner\\n'")
            .unwrap();
        let del = rb.find("|| userdel demo-runner; then").unwrap();
        assert!(gate < busy && busy < del);
        assert!(!rb.contains("userdel -r"));
        assert!(rb.contains("__anvil_forget group:demo-runner"));
    }
}
