# Acceptance test: `scripts/acceptance.sh`

The default checklist and the SSH port move. This page is for the operator who runs the test. It lists
every step, the commands it runs, what each one changes on the host, and the
lockout risk and its guard. Read it before the first run.
`scripts/acceptance.sh --dry-run <user@host>` prints every command without
connecting to anything.

The script replaces `scripts/smoke.sh`, which only worked on Hetzner. It runs
against a box you already have. It automates a full manual hardening run:
tutorial step 1, CIS, a reboot, PAM, drift, then a port move and a
rollback cycle.

**The box ends hardened.** It is not restored to its original state. Use a
disposable box and reinstall it after the run.

## Preconditions

- **A fresh, disposable Debian 13 or Ubuntu 26.04 box** that nothing else
  depends on. Use the provider's plain image, not a box with your own config.
  You need the provider's web console in case SSH breaks.
- **Key login on port 22** as `root` or as a user with passwordless sudo,
  for example `ubuntu` on Ubuntu cloud images. This is the `<user@host>`
  argument. Do not pass `ops`: the script creates `ops`.
- **On your machine:** `jq`, `ssh`, a Rust toolchain (the script runs
  `cargo build --release` unless `ANVIL_PREBUILT=1`), and a key pair.
  The default key is `~/.ssh/id_ed25519.pub` or the first `~/.ssh/*.pub`;
  set `ANVIL_ACCEPT_KEY=~/.ssh/<key>.pub` to pick another. The same key logs
  in as the given user and is installed for `ops`.
- **Nothing else on the box listens on 2222**, and the network allows
  inbound 2222 (a provider firewall, if there is one, must allow 22 and 2222).
- Running time is about 15–30 minutes. Most of it is the first apt runs, the
  Lynis audit and the reboot.

Running it:

```bash
scripts/acceptance.sh --dry-run root@203.0.113.10   # read this first
scripts/acceptance.sh root@203.0.113.10             # asks you to type the host
scripts/acceptance.sh --yes --containers --beszel --podman root@203.0.113.10
```

The exit code is 0 only when every step passed. At the end the script prints a
PASS/FAIL table, and the JSON from every step is in the work directory it
names. A failed **gate** (marked below) stops the run on the spot: every later
step depends on that state.

## Configs used

The fixtures are in `scripts/acceptance/`. The script copies them into a
private `mktemp -d` work directory (mode 0600, to pass the include trust
check) next to a generated `host.toml`. Each fixture includes `host.toml`,
which holds the current login (`address`, `user`, `port`, `identity_file`,
`ssh_options = ["UserKnownHostsFile=<work>/known_hosts", "IdentitiesOnly=yes"]`).
Your key comes in through `${ANVIL_ACCEPT_PUBKEY}`, which anvil expands from
the environment.

| Fixture | Content |
|---|---|
| `step1.toml` | Tutorial step 1 (`examples/fresh-vps.toml`): `[users]` `ops` (sudo, your key), `[sshd] port = 22`, `[firewall] restrict_ssh = false`, `[updates] auto_reboot = false` |
| `cis.toml` | Tutorial step 2 (`examples/fresh-vps-cis.toml`): `profile = "cis-level1"`, the same `ops`, `restrict_ssh = false`, `auto_reboot = false`, `[lynis]` |
| `port.toml` | `cis.toml` plus `[sshd] port = 2222`. A full copy, because `profile` only works in the top-level file |
| `containers.toml` | `--containers` only: `[docker]` (default `iptables_off = true`) and one compose project, `accept`: `nginx:alpine` on `127.0.0.1:18080` and `0.0.0.0:18081` |
| `beszel.toml` | `--beszel` only: `[beszel] hub = true` (hub and agent on one host) |
| `podman.toml` | `--podman` only: `[podman]`, `[containers] runtime = "podman"` and one Quadlet, `accept`: `docker.io/library/nginx:alpine` on `127.0.0.1:18090` |
| `podman-docker.toml` | `--podman` only: `[docker]` + `[podman]`; `validate` must refuse it, it is never applied |
| `podman-runner.toml` | `--podman` only: `[podman]`, `[ci_resources]` and `[forgejo_runner] docker = "podman"` with a `docker://` label; its url/uuid/token come from `ANVIL_ACCEPT_FORGEJO_URL`/`_UUID`/`_TOKEN` (a real runner; without one, a fake token and only the token-free steps) |
| `podman-runner-docker.toml` | `--podman` only: `docker = "podman"` without `[podman]`; `validate` must refuse it, it is never applied |
| `podman-services.toml` | `--podman` only: `[podman]`, `[forgejo] deploy = "quadlet"` (admin `accept-admin`, throwaway secrets), `[greptimedb]`, `[headscale] headplane = true` on `127.0.0.1:3001` |
| `podman-public.toml` | `--podman` only: the same Quadlet published on `18091` (all addresses); `validate` must refuse it, it is never applied |
| `podman-v2.toml` | `--podman` only: `[containers] runtime = "podman"` and a v2 `[github_runner]` (Podman sandbox, `sandbox_disk = "10G"`) with a throwaway App key the script generates |
| `coding-agents.toml` | `--coding-agents` only: `[users]` account `agent` (your key, no sudo) and `[coding_agents]` with two skills (one OpenCode-only), one official Claude plugin, ponytail, context-mode MCP, caps 200% / 4G / 512 tasks |
| `coding-agents-edit.toml` | the same without `opencode_plugins`: the list hash changes |
| `coding-agents-docker.toml` | `coding-agents.toml` plus `docker = "rootless"`: the host's engine as `agent` |

`restrict_ssh = false` everywhere keeps one plain `ufw allow 22/tcp`. The CIS
profile alone would switch it to `limit`, and anvil never deletes ufw rules,
so the box would end up with both. `auto_reboot = false` makes sure that
unattended-upgrades never reboots the box mid-run. The script reboots it
once, on purpose.

## Guards against lockout

- **Lifeline session.** Before the first apply, the script opens an SSH
  master connection (`ssh -M -S <work>/lifeline.sock -fN`) as the given user.
  sshd reloads keep existing sessions, so this connection survives root login
  being turned off and the port moving. The reboot closes it, and the script
  opens a new one as `ops@22` afterwards. If a gate fails, the script leaves
  the lifeline open and prints `ssh -S <work>/lifeline.sock <host>` (then
  `sudo -i`). When every gate passes, the script closes it at exit.
- **Fresh logins for checks.** Reachability checks open a new connection
  (`ControlMaster=no`), so a live session cannot hide a broken sshd or a
  blocked port.
- **`IdentitiesOnly=yes`** on every connection. With the CIS
  `MaxAuthTries 3`, an agent offering several keys could fail authentication
  and make fail2ban ban your IP.
- **Gates** stop the run when a login that later steps need does not work.
- **Ports are opened before they are needed and closed only after a fresh
  login proves the other port works** (steps 7 and 9).
- **`users` is never rolled back.** That would delete `ops`'s key and sudo
  rule, and anvil refuses it anyway (22c).

## Steps

"Reverted?" says whether the change is still there when a full run ends.

### 0. Preflight (local only)

Checks for `jq`/`ssh`, runs `cargo build --release`, finds the key pair, asks
you to type the host (skipped with `--yes`), copies the fixtures and writes
`host.toml`. **Host:** nothing.

### 1. Connect (gate)

```bash
ssh $SSH -p 22 -M -S $WORK/lifeline.sock -o ControlPersist=yes -fN <user>@<host>
ssh $SSH -p 22 <user>@<host> 'cloud-init status --wait; . /etc/os-release; echo $PRETTY_NAME; systemctl is-enabled ssh.socket'
```

**Host:** read-only. Waits for cloud-init so apt is free. Prints the OS and
whether `ssh.socket` is enabled. `enabled` means the run exercises the
socket path of the port move (Ubuntu). Debian has it disabled. **Lockout risk:** none.

### 2. Validate fixtures (local), doctor (gate)

```bash
anvil validate -c $WORK/{step1,cis,port,containers,beszel,podman,podman-v2}.toml
anvil doctor -c $WORK/step1.toml --timeout 60
```

**Host:** `doctor` logs in and runs `sudo -n true`. Nothing changes.

### 3. Tutorial step 1 as the given user (gate), then `ops` (gate)

```bash
anvil apply -c $WORK/step1.toml --output json        # as <user>@22
# host.toml -> ops@22
anvil doctor -c $WORK/step1.toml --timeout 60
anvil apply / check / diff -c $WORK/step1.toml       # all ok, exit 0, nothing to change
```

**Host:**
- **users:** creates `ops` with `/bin/bash`, your key in
  `~ops/.ssh/authorized_keys`, and a NOPASSWD rule in `/etc/sudoers.d/`.
- **sshd:** writes `/etc/ssh/sshd_config.d/05-anvil.conf` (no root login, no
  passwords, port 22) and reloads sshd behind `sshd -t`.
- **firewall:** installs `ufw`, sets deny-in/allow-out, runs
  `ufw allow 22/tcp` and enables ufw.
- **updates:** installs `unattended-upgrades` and writes
  `/etc/apt/apt.conf.d/99-anvil-{auto-upgrades,unattended-upgrades}`.
- **anvil state:** `<file>.anvil.bak` backups and
  `/var/lib/anvil/runs/<run>` manifests.

**Reverted?** `ops`, `ufw` and `unattended-upgrades` stay. The files are
replaced by step 9's rollback, then written again by step 10.

**Lockout risk:** root (or the given user, if it is root) loses SSH login the
moment sshd reloads. **Guard:** `users` runs before `sshd` in the same apply,
the lifeline is open, and the `ops@22` doctor gate stops the run if the new
account cannot log in and `sudo -n`. From here on, every step logs in as
`ops`.

### 4. CIS Level 1, score, status, report

```bash
anvil apply -c $WORK/cis.toml --output json
anvil apply / check / diff -c $WORK/cis.toml     # all ok, exit 0, nothing to change
anvil score -c $WORK/cis.toml --output json      # prints the Lynis index
anvil status -c $WORK/cis.toml
anvil report -c $WORK/cis.toml --check
```

**Host:** the 14 modules of `cis-level1`:
- **ssh_crypto:** `05-anvil-crypto.conf`, then an sshd reload.
- **kernel, process:** `/etc/sysctl.d/99-anvil-{kernel,process}.conf`. Both
  run `sysctl --system` and save the old runtime values to
  `/var/lib/anvil/sysctl-*.orig`.
- **kernel_modules:** `/etc/modprobe.d/99-anvil-blacklist.conf`. vfat is
  left out when it is in use (22b), squashfs when snapd is installed.
- **pam:** installs `libpam-pwquality`; writes `pwquality.conf`,
  `faillock.conf`, `/etc/profile.d/99-anvil-hardening.sh`, two profiles in
  `/usr/share/pam-configs/`, and the login.defs UMASK; then runs
  `pam-auth-update`.
- **process:** core dumps off, the hidepid unit, `login.defs` PASS_*.
- **suid:** writes `/var/lib/anvil/suid.state`.
- **filesystem:** `/tmp` is remounted `noexec` and kept that way by a
  `tmp.mount` drop-in or an fstab line; sticky-bit and world-writable checks.
- **auditd:** installs `auditd` and writes `rules.d/99-anvil.rules`.
- **fail2ban:** installs `fail2ban` and writes `jail.d/99-anvil.conf`.
- **lynis:** installs `lynis`. `score` runs a full Lynis audit, which takes
  a few minutes.

**Reverted?** No. The box ends in this state (see step 10). **Lockout risk:**
an sshd reload with a stricter config, guarded by `sshd -t` and the
auto-revert. fail2ban is active from here on. **Guard:** the lifeline, and
`IdentitiesOnly=yes`.

### 5. Reboot (gate), then check

```bash
ssh $SSH -p 22 ops@<host> cat /proc/sys/kernel/random/boot_id
ssh -S $WORK/lifeline.sock -O exit <host>
ssh $SSH -p 22 ops@<host> sudo -n systemctl reboot
# poll (10 s timeout + 10 s sleep, 30 tries, about 10 min) until boot_id changes
ssh $SSH -p 22 -M -S $WORK/lifeline.sock -o ControlPersist=yes -fN ops@<host>
anvil check -c $WORK/cis.toml --output json       # exit 0
ssh $SSH -p 22 ops@<host> systemctl list-units --state=failed --no-legend --plain   # empty
```

**Host:** one reboot. **Reverted?** Not applicable. **Lockout risk: the
highest in the run.** The lifeline cannot survive a reboot. A boot that fails
on the hardened config (the 22b class: a blacklisted filesystem in fstab, or
`/tmp` options) leaves the box in emergency mode, which only the console can
reach. **Guard:** this step comes after the CIS apply converged and passed
`check` twice. If the box is not back within 10 minutes, the gate fails and
says to use the console. That failure is the bug the step exists to find.

### 6. PAM functional test (pamtester)

The script below runs as root (`ssh ops@<host> 'sudo -n bash -euo pipefail -s'`):

```bash
apt-get install -y pamtester                 # purged again at the end if it was not installed before
useradd -m -s /usr/sbin/nologin anvil-accept-pam
printf 'anvil-accept-pam:<random 36-char password>\n' | chpasswd
pamtester login anvil-accept-pam authenticate   # right password  -> must succeed
#   5x a wrong password                          -> each must fail
#   the right password again                     -> must fail (faillock deny = 5)
faillock --user anvil-accept-pam --reset
pamtester login anvil-accept-pam authenticate   # right password  -> must succeed
# on exit, always: faillock --reset, userdel -r anvil-accept-pam, apt-get purge pamtester
```

**Host:** a throwaway user that never gets a login shell or SSH access, and
`pamtester` for the length of the step. **Reverted?** Yes: the user, its home
and the faillock tally are removed. pamtester is purged unless it was already
installed. Its dependencies, if any, and the apt log lines stay. **Lockout
risk:** none. The 5 failures lock only the throwaway user. Root is never
locked (`even_deny_root` is unset), and `ops` uses keys, not PAM passwords.

### 7. Drift

```bash
ssh ops@<host> sudo -n bash -s <<< "printf '# anvil acceptance: hand edit\n' >> /etc/sysctl.d/99-anvil-kernel.conf"
anvil check -c $WORK/cis.toml   # exit 1, kernel drifted
anvil diff  -c $WORK/cis.toml   # the file listed as "modify"
anvil apply -c $WORK/cis.toml   # kernel changed
anvil check -c $WORK/cis.toml   # exit 0
```

**Host:** a comment line added to the kernel sysctl drop-in. A comment has no
runtime effect. `apply` writes the file back. **Reverted?** Yes. The
first-write `.anvil.bak` is not touched, because a backup is only taken
before anvil's first change. **Lockout risk:** none.

### 8. Opt-in stages (only with their flag; they run here, before the port move)

Each stage runs: apply → re-apply all `ok` → check exit 0 → diff empty → its
own checks → `rollback --only <its modules>`.

**`--containers`**:

```bash
anvil apply/check/diff -c $WORK/containers.toml
ssh ops@<host> curl -fsS http://127.0.0.1:18080             # must answer
curl --max-time 5 http://<host>:18081                       # from YOUR machine: must fail (ufw filters it)
ssh ops@<host> 'sudo -n docker run --rm alpine wget -T 5 http://deb.debian.org'   # informational only
anvil rollback -c $WORK/containers.toml --only containers,docker
```

**Host:** installs Docker (packages, the Docker apt source and key,
`docker-compose-plugin`, `docker-compose-v2` or Debian's `docker-compose`,
plus `jq`) and writes
`/etc/docker/daemon.json` (`iptables: false`, `live-restore`, capped logs). Writes
`/etc/anvil/compose/accept/` and `anvil-compose-accept.service`, and pulls
`nginx:alpine` and `alpine`. Port 18081 binds on all addresses, but ufw has
no rule for it. **Reverted?** Partly. Rollback removes daemon.json, the compose
files and the unit, and restarts dockerd. The Docker packages, the apt source
written by a command, and the images stay. **Whether the `accept` container
keeps running after its unit is gone is to be confirmed on the first run.**
**Lockout risk:** none for SSH. The real risk is that 18081 is reachable
from the internet; that is what the check tests. Note: on a host that already
has `curl` the remote check works. On a minimal image without curl it fails
(the step does not install it).

**`--beszel`** (steps 1, 2, 4 and 5):

```bash
anvil apply/check/diff -c $WORK/beszel.toml
ssh ops@<host> systemctl is-active beszel-hub beszel-agent
ssh ops@<host> 'sudo -n systemd-analyze security beszel-agent beszel-hub; sudo -n journalctl -u beszel-agent -u beszel-hub -p err -b'   # informational
anvil rollback -c $WORK/beszel.toml --only beszel
ssh ops@<host> '! systemctl cat beszel-agent && ! systemctl cat beszel-hub && sudo -n test -d /var/lib/beszel-hub'
```

**Host:** downloads and checksums the pinned beszel binaries into
`/usr/local/bin`, creates the `beszel` and `beszel-hub` users, installs the
sandboxed units, the agent env file and the hub key in `/var/lib/beszel-hub`.
**Reverted?** Units, binaries and users are removed. `/var/lib/beszel-hub`
(the database) stays by design. **Lockout risk:** none (hub on loopback).

**`--podman`**:

```bash
anvil validate -c $WORK/podman-public.toml                  # local: must fail (public PublishPort)
anvil validate -c $WORK/podman-docker.toml                  # local: must fail (two engines)
anvil apply/check/diff -c $WORK/podman.toml
ssh ops@<host> curl -fsS http://127.0.0.1:18090             # must answer
ssh ops@<host> grep log_size_max /etc/containers/containers.conf.d/99-anvil.conf
ssh ops@<host> sudo podman inspect --format '{{.HostConfig.LogConfig.Type}}' systemd-anvil-accept   # k8s-file
anvil rollback -c $WORK/podman.toml --only containers,podman
ssh ops@<host> '! test -e /etc/containers/systemd/anvil-accept.container && ! test -e /etc/containers/containers.conf.d/99-anvil.conf && ! systemctl is-active --quiet anvil-accept.service && command -v podman && sudo -n podman image exists docker.io/library/nginx:alpine'
anvil apply/check/diff -c $WORK/podman-services.toml         # during apply a root sampler greps every
                                                             # /proc/*/cmdline for the admin password each 50 ms
ssh ops@<host> sudo podman container inspect forgejo        # running, and :3000/api/healthz answers (≤ 90s);
                                                             # same for greptimedb :4000, headplane :3001; headscale active; no docker-ce/docker.io
ssh ops@<host> sudo podman exec forgejo … admin user list    # accept-admin; the API answers 403 "must change password" to its password, 401 to a wrong one; forgejo.log non-empty
ssh ops@<host> sudo systemctl restart forgejo               # twice; healthz answers again, admin still there
anvil rollback -c $WORK/podman-services.toml --only forgejo,greptimedb,podman
ssh ops@<host> '…'                                           # quadlets gone, units inactive, forgejo.db and /var/lib/greptimedb kept
```

**Host:** the probe reads the Podman version (or apt's candidate) and stops
with `FAILED:` below 4.4, so on Debian 12 / Ubuntu 22.04 the apply step fails
by design. Installs the distro `podman`, `iptables` and `aardvark-dns` packages, writes
`/etc/containers/containers.conf.d/99-anvil.conf` (`[podman]`: k8s-file logs
capped at 10 MiB, netavark's iptables driver) and
`/etc/containers/systemd/anvil-accept.container`, runs `daemon-reload` and
starts `anvil-accept.service` (pulls `nginx:alpine`). **Reverted?** Partly.
Rollback stops the unit (Quadlet removes the container), deletes the
`.container` file and the drop-in and reloads systemd. The `podman` package, its
dependencies and the image stay, by design. **Lockout risk:** none (loopback
publish only).

`podman-services.toml` installs headscale (`.deb`), creates the `git` user,
`/var/lib/forgejo`, `/var/lib/greptimedb`, `/etc/forgejo`, `/etc/headplane`,
the Quadlets `forgejo`, `anvil-greptimedb` and `headplane` in
`/etc/containers/systemd`, and pulls three images. **Reverted?** Partly:
Forgejo's and GreptimeDB's Quadlets, configs and secrets go; data dirs, the
`git` user, the images and headscale + Headplane (not rolled back here) stay. **Lockout risk:** none (loopback
HTTP; Forgejo's SSH 2222 is not allowed in ufw).

Then the v2 runner on the same host:

```bash
anvil apply/check -c $WORK/podman-v2.toml
ssh ops@<host> 'systemctl is-active anvil-github-runner-accept-1.service; sudo -n podman image ls localhost/anvil-github-runner'
# a sandbox started with the slot unit's NoNewPrivileges; runner runs rootless alpine inside,
# then again on a `podman network create` bridge (netavark sysctls, as job services: use)
ssh ops@<host> 'sudo -n systemd-run --wait --pipe -p NoNewPrivileges=… podman run … <image> … podman run --rm [--network anvil-selftest] docker.io/library/alpine:3 true'
anvil rollback -c $WORK/podman-v2.toml --only github_runner
```

**Host:** adds the `containers:` range to `/etc/subuid`/`/etc/subgid`,
`[containers]` writes `/etc/containers/containers.conf.d/99-anvil.conf` (netavark iptables driver; the image build needs it), the AppArmor
profile `/etc/apparmor.d/anvil-github-runner-sandbox` (loaded where AppArmor
is on), builds `localhost/anvil-github-runner:<hash>` (pulls the runner base
image and apt packages) and starts one slot on a 10G loop volume. The App key
is fake, so the minter's GitHub calls fail with 401 and back off.
**Reverted?** Slot, image, profile, key and volume go; the id files
are restored from backup. Podman stays. **Lockout risk:** none.

Then `[forgejo_runner] docker = "podman"`:

```bash
anvil validate -c $WORK/podman-runner-docker.toml           # local: must fail (needs a Podman host)
anvil apply -c $WORK/podman-runner.toml
ssh ops@<host> 'grep ^forgejo-runner: /etc/subuid && test -e /var/lib/systemd/linger/forgejo-runner'
# after 30s of the unit's (fake-token) restarts: at most one podman service of forgejo-runner, nothing of
# it under user@<uid>.service but the manager, pause and aardvark-dns, its podman/conmon/containers in the unit
# only with ANVIL_ACCEPT_FORGEJO_TOKEN: check/diff converged; podman run -d alpine through the
# runner's socket, its PID's cgroup …/ci.slice/anvil-forgejo-runner.service, owner forgejo-runner;
# prints (not asserted) the cgroups of aardvark-dns and the pause process (user@<uid>.service)
# then systemctl restart twice: still active, a rootless alpine runs through the socket
# then restart x3: exactly one podman service, the same cgroup check, and the socket container again
# unit stopped; its [Service] lines as systemd-run -p: rootless alpine, then on a bridge with outbound
# and, through the unit's service, docker run -v /var/run/docker.sock:… (what actions/runner adds)
ssh ops@<host> 'sudo -n systemd-run --wait --pipe -p User=forgejo-runner -p … podman run --rm …'
anvil rollback -c $WORK/podman-runner.toml --only forgejo_runner,ci_resources,podman
ssh ops@<host> '! grep ^forgejo-runner: /etc/subuid && ! id forgejo-runner && ! test -e /var/lib/systemd/linger/forgejo-runner && sudo test -d /var/lib/forgejo-runner'
```

**Host (runner):** installs `uidmap`, `passt`, `podman-docker`,
`dbus-user-session` and the pinned `forgejo-runner`, creates `forgejo-runner`
with a subuid/subgid range, enables its linger (`user@<uid>.service`), and
starts `anvil-forgejo-runner.service` (podman service inside, in
`ci.slice`); test `alpine` containers run for seconds. Without a token
the runner gets a fake one and restarts every 10 s; the self-test does not need it. **Reverted?**
Unit, config, binary, linger, user and the id range go; `/var/lib/forgejo-runner`
(images), packages and the runner's Forgejo entry stay. **Lockout risk:** none.

### 9. Port move 22 → 2222 and the rollback cycle

```bash
ssh ops@<host> sudo -n ufw allow 2222/tcp                    # a) pre-open
anvil apply -c $WORK/port.toml                                # b) gate: sshd changed, nothing failed
ssh $SSH -p 2222 ops@<host> true; ... ss -Htln 'sport = :2222'  # c) gate: fresh login, listening
# host.toml -> ops@2222
anvil apply / check / diff -c $WORK/port.toml                 # d) converged on 2222
ssh -p 2222 ops@<host> 'sudo -n ufw delete allow 22/tcp'      # e) gate: close the old port
anvil rollback -c $WORK/port.toml --only <every module but users>   # f)
ssh $SSH -p 22 ops@<host> true; ... ss -Htln 'sport = :22'    # g) gate: back on 22
# host.toml -> ops@22
anvil check -c $WORK/cis.toml                                 # h) exit 1: drift after rollback
```

**Host:**
- a) adds a ufw rule for 2222/tcp.
- b) rewrites `05-anvil.conf` with `Port 2222` and reloads sshd. On Ubuntu
  with `ssh.socket` that means `systemctl daemon-reload && systemctl restart
  ssh.socket`. The firewall finds 2222 already allowed, and keeps 22 because
  `host.port` is still 22.
- e) deletes the `22/tcp` rule (v4 and v6). anvil never deletes rules, so this
  is a manual edit outside anvil. It lets step f prove that rollback re-opens
  the restored port by itself.
- f) restores every managed file from its `.anvil.bak` or deletes the files
  anvil created. That covers the sshd drop-ins (sshd goes back to 22: socket
  restart on Ubuntu, reload on Debian), sysctl (runtime values restored from
  the snapshots), modprobe, PAM profiles (`pam-auth-update` runs again),
  login.defs keys, `/tmp` (remounted `exec`), auditd rules, the fail2ban jail
  and the apt drop-ins. The firewall rollback reads the restored port from
  `sshd -T` and runs `ufw allow 22/tcp`. ufw stays enabled and keeps its
  rules. Packages stay.
- After f, root login and password authentication are back at the image
  defaults. Your key still works for root if the image allowed it.

**Reverted?** sshd ends on 22 again. The 2222 rule is removed in step 10.

**Lockout risk:** this is the step that checks it.
- **b:** sshd moves to 2222 before the firewall module runs. If the restart of
  `ssh.socket` dropped anvil's connection there, the firewall would never
  allow 2222. Step a covers that window, so a dropped session costs a failed
  apply, not the box.
- **b:** if systemd refuses to restart `ssh.socket` (an open question), sshd's guard reverts the drop-in. The gate then fails with sshd still
  on 22, so you can still log in.
- **e:** the 22 rule is deleted only after (c) proved a fresh login on 2222.
  It also relies on (b): the whole apply kept running after the socket
  restart, which shows that sessions survive it, so the rollback's own
  restart in (f) cannot drop the run halfway.
- **f:** rollback runs in reverse apply order with one exception: sshd and
  ssh_crypto roll back before the firewall, so the firewall re-allows
  22 after sshd moved back. Between the
  two, sshd listens on 22 and ufw allows only 2222. Only the running
  connection carries the run through that window. The lifeline is the
  fallback.
- **g:** the gate. If it fails, the lifeline (on 22, opened before the move)
  and the console are your way in. To recover by hand:
  `sudo ufw allow 22/tcp`.

### 10. Re-apply and clean up

```bash
anvil apply -c $WORK/cis.toml                    # CIS on 22 again
anvil apply / check / diff -c $WORK/cis.toml     # all ok, exit 0, nothing to change
ssh ops@<host> sudo -n ufw delete allow 2222/tcp
ssh -S $WORK/lifeline.sock -O exit <host>        # at exit, when all gates passed
```

**Host:** the same state as after step 4. The rule added in step 9a is removed.

## `--coding-agents` (alone, on a box in use)

`scripts/acceptance.sh --coding-agents <sudo-user>@<host>` runs only the
coding agents checks (docs/design/coding-agents.md §9: 1, 2, 3, 7 without
`setup`, 8, 9, 10, plus 11, run before 10) as the given user, port `ANVIL_ACCEPT_PORT` (default 22).
It applies nothing but the three fixtures above, so a box that already runs
other modules keeps its config.

| Step | Pass when |
|---|---|
| 1 | apply ok; re-apply all ok, `check` 0, `diff` empty |
| 2, 3 | `claude` and `opencode --version` run for `agent` from `~/.local/bin` (opencode linked from `~/.opencode/bin`, also on a login shell's PATH); `claude` = the `stable` channel at install time; no `claude-code` apt package |
| 2 | `node` for `agent` is `/usr/bin/node` ≥ 24.15 from NodeSource; context-mode's `ctx_doctor` over MCP stdio (the fixture's `opencode_mcp` argv) has no `FAIL` on `D2 node`; its `D3` row is printed |
| 7 | `~/.agents/skills/{find-skills,frontend-design}`, `~/.claude/skills/find-skills` but not `frontend-design` (OpenCode-only), plugin `commit-commands`, ponytail in `~/.config/opencode`, `mcp.context-mode` and no `mcp.servers` in its `opencode.json`, marker; the edit fixture reports `changed`, and so does going back |
| 8 | as `agent`: `sudo -n true` fails; can't read the App key, runner credentials, Docker/Podman sockets; can't list `/root`, other homes, runner trees (`/etc/anvil` is 0755 by design; the App key in it is checked); `journalctl --system` empty |
| 9 | `user-<uid>.slice` shows 2 s CPU/s, 4 GiB, 512 tasks; 700 `sleep`s in a unit in that slice stop at 512 (`pids.events` max rises); a fresh login works |
| 11 | apply `coding-agents-docker.toml`; in a login shell as `agent`: `DOCKER_HOST` is under `/run/user/<uid>/`, `docker info` reports rootless, `docker run --rm busybox` works, a container with `/etc` mounted can't read `shadow` |
| 10 | `rollback --only coding_agents` (with the docker fixture): linger, caps drop-in, marker, `anvil-docker-rootless.service` gone, the agent's `/etc/subuid` range gone if anvil added it (kept if `useradd` gave one); `~/.local/bin/claude`, `~/.local/share/claude`, `~/.opencode/bin`, `~/.local/bin/opencode` gone unless they were there before; NodeSource key, source and pin gone; `~/.agents/skills`, `~/.claude` and `/usr/bin/node` kept |

**Host:** adds the user `agent`, the NodeSource apt source and its Node 24
(replacing a distro `nodejs`/`npm`), build tools; `agent` installs Claude Code
and OpenCode in its home. Step 11 installs the host's engine if absent
(docker-ce + `docker-ce-rootless-extras`, or Podman) and pulls `busybox` as
`agent`. **Reverted?** Step 10 removes both installs, linger,
the caps, the rootless unit and id range, and the NodeSource source (the engine
packages and the agent's images stay); the account, its config/data, `nodejs` and
the distro packages stay.
**Lockout risk:** none (no sshd or firewall change).

## `--hygiene` (alone, on a box in use)

`scripts/acceptance.sh --hygiene [--greptimedb] <sudo-user>@<host>` checks
a box that already runs Forgejo and runners, after this build was
applied with the box's own config. It applies only its fixtures, each with
`--only`, and rolls them back. Engine: Docker if `docker` is active, else
Podman.

| Step | Pass when |
|---|---|
| 5 | Plugins from `$WORK/xdg`: a converged `apply --no-check` leaves no `runs/plugin::hygiene-ok.*`; a changing one keeps its manifest with its `cmd` line. Prints the empty manifests older applies left |
| 6 | A plugin that writes noise, then `FAILED: hygiene: planted failure` to stderr: exit 1, JSON `reason` is the `FAILED:` line |
| 3 | A busybox compose project (Podman: Quadlet) moves 1.36 → 1.37: 1.36 gone, 1.37 and 1.35 (held by a stopped container) kept, `check --only containers` aligned |
| 4 | `anvil-forgejo-runner-prune.timer` enabled, the service runs; its script on a scratch HOME with a sparse cache past the cap: idle, cache wiped. Fails "a job is running" when busy: re-run |
| 1 (`--greptimedb`) | GreptimeDB `ANVIL_ACCEPT_GREPTIMEDB_VERSION` (`v0.12.0`) on 14000–14003 with `retention = "7d"`: apply ok, `check` aligned, `SHOW CREATE DATABASE public` shows the TTL. Refused if a `greptimedb` container already runs |

**Host:** pulls busybox 1.35–1.37 (and the GreptimeDB image), runs the
forgejo-runner prune service once (it may wipe the runner's real caches if
they are past the cap, as the daily timer would). **Reverted?** The project,
its images, the plugin manifests, the GreptimeDB data dir and image go; the
real runners, Forgejo and their files are not touched.
**Lockout risk:** none.

## `--in-use` (alone, read-only, on a Docker box in use)

`scripts/acceptance.sh --in-use <sudo-user>@<host>` checks the monitoring
follow-ups on a host that already runs its real config (Forgejo compose,
Vector, a v2 runner with sysbox). It only runs `check` and read-only
commands; no confirmation.

| Step | Pass when |
|---|---|
| 1 | `check --only docker` with `userns_remap = false` (and the other two keys) set explicitly: not `failed`. With a bare `[docker]`: `failed`, naming `userns_remap` (the host has images) |
| 2 | No `logging:` in `/etc/forgejo/compose.yaml`; the `forgejo` container's log driver equals dockerd's (skipped without the container) |
| 3 | `vector.toml` has the sysbox-fs filter and Vector is active; rows arrive in `vector_logs` since Vector's start, none of them sysbox-fs's `reaper: nothing to reap` (skipped without `sysbox-fs`) |

**Host:** nothing changes. **Lockout risk:** none.

## `--monitoring` (alone, on a Docker box in use)

`scripts/acceptance.sh --monitoring <sudo-user>@<host>` checks monitoring on a
Docker host that runs Forgejo, runners and coding agents. It applies only
`greptimedb` + `vector` with `--only` (GreptimeDB at the default version on
14000–14003, `retention = "7d"`, `memory_max = "2G"`, data in
`/var/lib/anvil-monitoring-greptimedb`) and rolls them back. `daemon.json`
and dockerd are not touched: the container uses `--log-driver=journald`.

| Step | Pass when |
|---|---|
| 0 | Docker is active, no `greptimedb` container, no `/etc/vector/vector.toml` (else refused) |
| 1 | apply ok, `check --only greptimedb,vector` aligned |
| 2 | `SHOW CREATE DATABASE public` shows the 7d TTL; `HostConfig.Memory` = 2 GiB; `/v1/dashboards` lists `anvil-host`, `anvil-errors`, `anvil-containers`, `anvil-ci` |
| 3 | A `systemd-run` unit's line is in `vector_logs` with its `_SYSTEMD_UNIT` (polls up to 10 min: Vector ships the retained journal first) |
| 4 | A busybox container's line is in `vector_logs` with `CONTAINER_NAME` |
| 5 | `host_cgroup_cpu_usage_seconds_total` has rows for the container's `system.slice/docker-<id>.scope` and for `ci.slice` (needs `[ci_resources]`); a `logger -p user.err` line matches the errors dashboard's `PRIORITY` filter |
| 6 | rollback: no `greptimedb` container, compose project, Vector config/unit or dashboard files; `vector` inactive and disabled |

**Host:** pulls busybox 1.37 and GreptimeDB; Vector's package and apt
source stay. **Reverted?** Step 6 removes the probe container, the test data
dir, Vector's state dir and both images. **Lockout risk:** none.

## `--forgejo-sandbox` (alone, on a Docker box in use)

`scripts/acceptance.sh --forgejo-sandbox <sudo-user>@<host>` checks the
Forgejo sandbox on a Docker host with Forgejo ≥ 15. Without `ANVIL_ACCEPT_FORGEJO_URL`,
`<host>` must be a public IPv4 and the box runs its own Forgejo: `[docker]`,
`[caddy]` with a Let's Encrypt site `<ip-with-dashes>.sslip.io` and `[forgejo]`
compose (admin `accept-admin`, random secrets), so ports 80/443 must be
reachable from anywhere for the run. The Forgejo CLI lifts the admin's forced password change (it blocks API
tokens too) and mints the token; after step 9, `forgejo` and `caddy` are rolled back.
Settings:

| Variable | What |
|---|---|
| `ANVIL_ACCEPT_FORGEJO_URL` | Optional: an external Forgejo instead of the box's own |
| `ANVIL_ACCEPT_FORGEJO_API_TOKEN` | With the URL: a token with `write:repository` and `write:user` (`GET /user`, `POST /user/repos`) |
| `ANVIL_ACCEPT_SANDBOX_EXTRA` | Optional: **path** to a TOML file with this host's `[docker]`/`[github_runner]` sections, so `daemon.json` stays |
| `ANVIL_ACCEPT_SANDBOX_RUNTIME` | Optional: `docker-rootless` checks the sandbox in slot user `anvil-fjr-1`'s rootless engine (privileged) instead of root's sysbox one; rollback must also remove the slot user, its home, user unit, image tar, linger and subuid range |

It creates a private throwaway repo, `<token user>/anvil-sandbox-<epoch>`. It
applies only `forgejo_runner` with `--only`: `mode = "ephemeral"`, one slot,
label `anvil-sandbox-<epoch>:host`, `owner` = that repo. A persistent
`forgejo_runner` on the host is stopped while the test runs, and rollback
brings it back.

| Step | Pass when |
|---|---|
| 0 | Docker is active, no `anvil-forgejo-runner-1.service`; `diff` leaves `/etc/docker/daemon.json` alone (else refused); records whether the persistent runner is active |
| 1 | The repo is created |
| 2 | apply ok; re-apply all ok, `check` exit 0; persistent runner stopped, its unit and `config.yml` gone (kept as `.anvil.bak`); network `anvil-forgejo-sandbox` on bridge `anvil-fjsb0`; ufw rule on that bridge if Forgejo is on this host |
| 3 | `anvil-forgejo-runner-1` runs under `sysbox-runc`; the repo has one runner, ephemeral |
| 4–5 | A pushed workflow's job passes. Its hostname is `anvil-forgejo-runner-1`, it runs `sudo touch /<label>` and `docker run busybox` in the sandbox |
| 6 | No `/<label>` on the host or in the next job's sandbox; no busybox container on host Docker; at most one runner (the waiting one), ephemeral |
| 7 | Still converged |
| 8 | rollback: no sandbox, unit, minter, API token file, slot volume, `anvil-forgejo-runner` image, network, ufw rule or `/etc/anvil/forgejo-runner{/image,}`; the repo has no runner left; the persistent runner is active again if it was at step 0 |
| 9 | The repo is deleted |
| 10 | Own Forgejo only: rollback `forgejo,caddy`; no `forgejo` container; the packaged Caddyfile is back (Caddy stays installed) |

**Host:** builds the `anvil-forgejo-runner` image and installs sysbox if
missing; busybox is pulled inside the sandbox only. **Reverted?** Step 8, and
step 9 deletes the repo. sysbox stays, and so does the forgejo-runner binary if it was there before.
**Lockout risk:** none.

## Host state after a full run

| Area | State | From |
|---|---|---|
| Users | `ops`: sudo NOPASSWD, your key, `/bin/bash`. No other account added; `anvil-accept-pam` is gone | step 3 (never rolled back) |
| SSH | Port 22, CIS sshd drop-ins (`05-anvil.conf`, `05-anvil-crypto.conf`): no root login, no passwords, `MaxAuthTries 3` | step 10 |
| Your access | `ssh -i <key> ops@<host>` on 22. The given user, if root, cannot log in over SSH | step 3 / 10 |
| Firewall | ufw active, deny-in/allow-out, `22/tcp` ALLOW (re-added by the rollback, v4 and v6). No 2222 rule | steps 3, 9f, 10 |
| Packages added | `ufw`, `unattended-upgrades`, `libpam-pwquality`, `auditd`, `fail2ban`, `lynis` and their dependencies. With `--containers`: Docker, compose plugin, `jq`, images. With `--beszel`: `curl`, `ca-certificates`, `openssh-client` if they were missing. `pamtester` purged | steps 3, 4, 8 |
| Config | Every CIS managed file in place (see 04_modules.md), `.anvil.bak` next to every distro file that existed before | step 10 |
| PAM | pwquality and faillock active through `pam-auth-update`. `/etc/pam.d` only changed by `pam-auth-update` | step 10 |
| Kernel | Hardened sysctls live and persisted; module blacklist in modprobe.d (vfat/squashfs left out if in use) | step 10 |
| `/tmp` | `noexec,nosuid,nodev` live and persisted | step 10 |
| Services | auditd, fail2ban, unattended-upgrades timers active; `auto_reboot = false` | step 10 |
| anvil state | `/var/lib/anvil/`: run manifests, sysctl snapshots, suid state, login.defs records | all steps |
| `--containers` | Docker installed, no `daemon.json`, no compose project files. The `accept` container may still run (to confirm) | step 8 |
| `--beszel` | `/var/lib/beszel-hub` (database) kept; units, binaries and users removed | step 8 |
| Boots | Rebooted once | step 5 |

The box is hardened and reachable, but it no longer matches its image.
Reinstall it before the next run, so step 3 starts from the distro config
again.

## Opt-in or manual checks

| Check | Decision | Why |
|---|---|---|
| Default checklist | Default run | The whole checklist: steps 3–7, 9 and 10 |
| SSH port move | Default run (step 9) | Needs nothing but the box. Run it on Ubuntu 26.04 to exercise `ssh.socket`; step 1 prints which path ran |
| containers | `--containers` | Self-contained, but it installs Docker and pulls images, which the core run should not need |
| Docker publish vs ufw | `--containers` | Your own machine is the "other host" for the inbound check. Outbound is printed, not asserted (Docker documents it as lost with `iptables=false`) |
| beszel | `--beszel` (steps 1, 2, 4, 5) | Self-contained. Step 3 (admin account in the web UI) needs a browser. Step 6 (outbound mode, tailnet mode) needs a token or a tailnet: stays manual |
| tailscale rollback after a real cutover | Manual | Closes public SSH. It needs an auth key, a second tailnet device and a check from outside the tailnet. The only guard is a person with a console |
| tailnet-only cutover | Manual | Same as the tailscale rollback: tailnet, a second device, and the address switch to the tailnet name |
| github_runner | Manual, done 2026-11-02 on a Debian 13 box | Needs a 1-hour registration token and workflow runs on GitHub's side. Procedure and results are in the module docs. |
| fresh host | Manual, done 2026-11-03 on an Ubuntu 26.04 box | Reinstall, then `users` as root, then one apply as the admin user: 16 hardening modules in 102 s, Tailscale, v2 runner in 83 s; full `check` aligned; v2 isolation checks green; Lynis 74. Found the AppArmor fusermount3 vs sysbox-fs bug. |
| podman | `--podman`, done 2026-11-03 on a Hetzner CAX41 (arm64), Debian 13 + Ubuntu 26.04 | 32/32 on both. Found three fixes: auditd load, a Quadlet check and no outbound next to ufw. |
| forgejo | Manual | Needs a DNS name for `[tls]`/`[caddy]`, a browser for the first admin, and a git push over SSH |
| caddy | Manual | Needs a DNS name pointing at the box for ACME (staging CA), plus ports 80/443 open |
| greptimedb / Headplane | Manual | A matrix: userns-remap on and off means reconfiguring dockerd between runs, and Headplane needs a headscale server. Run it after `--containers` passes |

## Not covered

- **`[hetzner]`.** smoke.sh was its only real-host test. It needs a Hetzner
  server and token, and this script is provider-neutral.
- **Debian 12 / Ubuntu 24.04.** The script does not refuse them, but the
  release gate is Debian 13 + Ubuntu 26.04.
- **The fail2ban/crowdsec ban path.** `[crowdsec]` is not in the CIS profile,
  and no step tries to get banned on purpose.
