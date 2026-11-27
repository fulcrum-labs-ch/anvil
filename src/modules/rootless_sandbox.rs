//! `sandbox_runtime = "docker-rootless"`, shared by the ephemeral
//! `forgejo_runner` and `github_runner` (v2): one system user per slot with a
//! lingering manager and its own rootless dockerd; the sandbox runs
//! `--privileged` there, so root in it is that user on the host, never root.
//!
//! The slot volume mounts at `<home>/vol` (the home stays root-owned, so
//! nothing a job leaves persists) and holds the engine's data-root: re-made
//! per job. Root's Docker builds the sandbox image once and saves it; the
//! minter loads it into each fresh engine. GECOS `umask=022` (pam_umask)
//! keeps the user's sandbox cgroups readable by Vector under CIS `UMASK 027`.

use crate::config::Engine;
use crate::engine::{ManagedCommand, ManagedFile};
use crate::escape::shell_escape;

use super::runner_common::{self, Account};

/// The slot user's home; root-owned, outside the root-only `/var/lib/anvil-ci`.
pub fn home(user: &str) -> String {
    format!("/var/lib/{user}")
}

/// Where the slot volume mounts. Not the home itself: the user's bus daemon
/// runs there and would keep the volume busy.
pub fn vol(user: &str) -> String {
    format!("{}/vol", home(user))
}

/// Minter preamble: `user` is a bash word naming the slot user (e.g.
/// `anvil-fjr-$slot`); `us`/`ud` run systemctl/docker as it, from root.
pub fn fns(user: &str, tar: &str) -> String {
    format!(
        "u={user}\n\
         uid=$(id -u \"$u\")\n\
         tar={}\n\
         us() {{ runuser -u \"$u\" -- env XDG_RUNTIME_DIR=\"/run/user/$uid\" DBUS_SESSION_BUS_ADDRESS=\"unix:path=/run/user/$uid/bus\" \"$@\"; }}\n\
         ud() {{ us env DOCKER_HOST=\"unix:///run/user/$uid/docker.sock\" docker \"$@\"; }}\n",
        shell_escape(tar)
    )
}

/// Cleanup lines: the sandbox, then the engine before its data-root is
/// unmounted. A slot switched from root's Docker (`old_mnt`, a bash word)
/// must not leave its old sandbox taking jobs.
pub fn cleanup(unit: &str, old_mnt: &str) -> String {
    format!(
        "ud rm -fv \"$ctr\" >/dev/null 2>&1 || true\n  \
         us systemctl --user stop {unit} >/dev/null 2>&1 || true\n  \
         # A slot switched from root's Docker: its old sandbox must not keep taking jobs.\n  \
         ! command -v docker >/dev/null || docker rm -fv \"$ctr\" >/dev/null 2>&1 || true\n  \
         ! mountpoint -q {old_mnt} || umount {old_mnt}"
    )
}

/// After the fresh volume is mounted at `$mnt`: hand it to the slot user
/// (uutils chown ignores `user:`, hence the gid), start its engine (reloaded
/// first: a lingering manager keeps a changed unit cached), load the saved
/// image. The journald log driver gives Vector the sandbox's CONTAINER_NAME,
/// which the `anvil-ci` dashboard joins on.
pub fn up(unit: &str) -> String {
    format!(
        "chown -R \"$u:$(id -g \"$u\")\" \"$mnt\"\n\
         us systemctl --user daemon-reload\n\
         us systemctl --user start {unit}\n\
         for _ in $(seq 60); do ud info >/dev/null 2>&1 && break; sleep 1; done\n\
         ud load -q <\"$tar\" >/dev/null"
    )
}

/// The env file the slot user's docker CLI reads.
pub const ENV_OWNER: &str = "chown \"$u\" \"$env\"\n";

/// The user unit every slot user's manager may run; one `ConditionUser=|`
/// per slot keeps every other user's manager out. The minter starts it.
pub fn user_unit(what: &str, users: &[String]) -> String {
    let conds: String = users
        .iter()
        .map(|u| format!("ConditionUser=|{u}\n"))
        .collect();
    format!(
        "# Managed by anvil — rootless dockerd for {what} sandboxes\n\
         [Unit]\n\
         Description=Docker (rootless) for a {what} slot (anvil)\n\
         {conds}\
         \n\
         [Service]\n\
         Environment=PATH=/usr/bin:/sbin:/usr/sbin:/bin\n\
         ExecStart=/usr/bin/dockerd-rootless.sh --data-root=%h/vol/engine --log-driver=journald\n\
         TimeoutSec=0\n\
         LimitNOFILE=infinity\n\
         LimitNPROC=infinity\n\
         Delegate=yes\n\
         Type=notify\n\
         NotifyAccess=all\n\
         KillMode=mixed\n"
    )
}

fn account<'a>(module: &'a str, user: &'a str, home: &'a str) -> Account<'a> {
    Account {
        module,
        user,
        home,
        root: home,
        leftover: "a slot volume",
    }
}

/// Engine, helper packages and id-mapper check (once), every slot user and
/// the user unit.
pub fn host(
    module: &str,
    docker_distro: bool,
    users: &[String],
    unit_path: &str,
    unit: String,
    cpu_weight: u32,
) -> (Vec<ManagedCommand>, ManagedFile) {
    let mut v = vec![super::ensure_engine(Engine::Docker, docker_distro)];
    if let Some(first) = users.first() {
        v.extend(
            runner_common::rootless(Engine::Docker, first, "")
                .into_iter()
                .take(2),
        );
    }
    for user in users {
        v.extend(slot_account(module, user));
        v.push(cpu_weight_cmd(user, cpu_weight));
    }
    (v, ManagedFile::new(unit_path, unit, "0644", "root:root"))
}

/// A slot user: account, root-owned home with the mount point, GECOS
/// `umask=022`, subordinate ids and linger.
fn slot_account(module: &str, user: &str) -> Vec<ManagedCommand> {
    let h = home(user);
    let (u, he, ve) = (
        shell_escape(user),
        shell_escape(&h),
        shell_escape(&vol(user)),
    );
    let mut v = vec![
        account(module, user, &h).ensure(),
        ManagedCommand::new(
            format!("{user} home root-owned, slot volume mount point inside"),
            format!("[ \"$(stat -c %U:%a {he})\" = root:755 ] && [ \"$(stat -c %U {ve})\" = {u} ]"),
            format!(
                "chown root:root {he}\nchmod 0755 {he}\n\
                 mountpoint -q {ve} || install -d -m 0700 -o {u} -g \"$(id -g {u})\" {ve}"
            ),
        ),
        ManagedCommand::new(
            format!("{user} umask=022 (cgroups readable by Vector)"),
            format!("[ \"$(getent passwd {u} | cut -d: -f5)\" = umask=022 ]"),
            format!("usermod -c umask=022 {u}"),
        ),
    ];
    v.extend(
        runner_common::rootless(Engine::Docker, user, "")
            .into_iter()
            .skip(2),
    );
    v
}

/// Option (c): CI yields under contention instead of a hard total cap
/// (the slot users' slices cannot sit under `ci.slice`). Persisted in
/// `/etc/systemd/system.control/`, undone by `systemctl revert` on rollback.
fn cpu_weight_cmd(user: &str, weight: u32) -> ManagedCommand {
    let slice = format!("\"user-$(id -u {}).slice\"", shell_escape(user));
    ManagedCommand::new(
        format!("{user} slice CPUWeight={weight} ([ci_resources] cpu_weight)"),
        format!("[ \"$(systemctl show -p CPUWeight --value {slice})\" = {weight} ]"),
        format!("systemctl set-property {slice} CPUWeight={weight}"),
    )
}

/// The sandbox image saved by root's Docker that built it; the tag file
/// makes a new image drift.
pub fn image_tar(tar: &str, tag_file: &str, tag: &str) -> ManagedCommand {
    let (t, tf, g) = (shell_escape(tar), shell_escape(tag_file), shell_escape(tag));
    let dir = shell_escape(tar.rsplit_once('/').map_or("/", |(d, _)| d));
    ManagedCommand::new(
        format!("sandbox image saved for the slot users ({tar})"),
        format!("[ -s {t} ] && [ \"$(cat {tf} 2>/dev/null)\" = {g} ]"),
        format!(
            "install -d -m 0700 {dir}\n\
             docker save -o {t}.tmp {g}\n\
             mv -f {t}.tmp {t}\n\
             printf '%s\\n' {g} >{tf}"
        ),
    )
}

/// `rollback_first` line: the volume, once the slot unit stopped.
pub fn umount(user: &str) -> String {
    let v = shell_escape(&vol(user));
    format!("! mountpoint -q {v} || umount {v}\n")
}

/// Rollback after the slots stopped: the image tar, then per user its
/// manager, ids, home and account.
pub fn rollback(module: &str, tar: &str, tag_file: &str, users: &[String]) -> String {
    let mut s = format!("rm -f {} {}\n", shell_escape(tar), shell_escape(tag_file));
    for user in users {
        let h = home(user);
        s.push_str(&format!(
            "! __u=$(id -u {u} 2>/dev/null) || systemctl revert \"user-$__u.slice\" >/dev/null 2>&1 || true\n",
            u = shell_escape(user)
        ));
        s.push_str(&runner_common::rootless_rollback(user));
        // What the manager wrote under the unmounted home is anvil's too.
        s.push_str(&format!(
            "if __anvil_created {cu} && ! mountpoint -q {v}; then rm -rf {he}; fi\n",
            cu = shell_escape(&format!("user:{user}")),
            v = shell_escape(&vol(user)),
            he = shell_escape(&h),
        ));
        s.push_str(&account(module, user, &h).rollback());
    }
    s
}
