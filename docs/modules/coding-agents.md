# Coding agents (`[coding_agents]`)

Claude Code and OpenCode on the VPS for one unprivileged login user, reached
from your Mac with Orca over SSH. Design and security model:
[docs/design/coding-agents.md](../design/coding-agents.md).

> The agent runs arbitrary code as its user, including code from any prompt
> injection it reads. Treat that user as untrusted: no sudo, its own tokens.

## Config

```toml
[users]
create = [
  { name = "admin", sudo = true, ssh_authorized_keys = ["ssh-ed25519 AAAA… admin@laptop"] },
  { name = "agent", shell = "/bin/bash", ssh_authorized_keys = ["ssh-ed25519 AAAA… orca@mac"] },
]

[sshd]
allow_users = ["admin", "agent"]

[coding_agents]
user = "agent"                             # a [users] account with sudo = false
claude_code = "stable"                     # "latest" | "none"
opencode = "latest"                        # or a version for the v2 installer, or "none"
skills = [
  { source = "vercel-labs/skills", names = ["find-skills"] },
  { source = "example-org/claude-skills", agents = ["opencode"] },
]
claude_marketplaces = ["anthropics/claude-plugins-official"]
claude_plugins = ["playwright@claude-plugins-official"]
opencode_plugins = ["@example-org/example-plugin"]
opencode_mcp = { example-mcp = ["npx", "-y", "example-mcp@latest", "server", "--agent", "opencode"] }
# setup = { url = "https://github.com/owner/setup-repo.git", rev = "<40 hex>", run = "install.sh" }
cpu_quota = "400%"
memory_max = "12G"
tasks_max = 4096
docker = "rootless"                        # optional: Docker/Podman as agent (below)
```

After `anvil apply`:

| What | Where |
|---|---|
| `claude` (Anthropic's native installer, run as `agent`) | `~agent/.local/bin/claude`, self-updating |
| `opencode` (OpenCode's v2 installer, run as `agent`) | `~agent/.opencode/bin/opencode` (linked as `~/.local/bin/opencode`), self-updating |
| Node.js 24 (with npm/npx) | NodeSource apt repo, key pinned in anvil: the distro's 20/22 is too old for context-mode v2 (≥ 24.15). Replaces a distro `nodejs`/`npm`; rollback keeps it |
| git, build tools, python3 | distro packages |
| Skills, plugins, MCP servers, `setup` | the agent's home, installed **as `agent`** |
| Linger | `agent`'s user manager runs without a login |
| Caps | everything `agent` runs shares 4 cores, 12 GB, 4096 tasks |
| `TMPDIR=~/.cache/tmp` | only with `[filesystem] tmp_noexec` |
| Rootless Docker or Podman, `DOCKER_HOST` | only with `docker = "rootless"` (below) |

Both agents update themselves (`claude update` works); anvil only checks
that they run, so an update is never drift. Lists only add; `anvil apply --no-check` refreshes them. A private `setup` repo waits
until `agent` has a GitHub login (below), then the next apply runs it.

## Containers (`docker = "rootless"`)

The agent gets the host's engine, run **as `agent`**: `docker run`,
`docker build` and `docker compose` work from its shells and Orca terminals
(`DOCKER_HOST` points at its own socket). The root socket stays out of reach:
`agent` is never in the `docker` group.

| Host | What runs | Socket |
|---|---|---|
| Docker host | rootless dockerd (`docker-ce-rootless-extras`) as a user unit, `/etc/systemd/user/anvil-docker-rootless.service` | `/run/user/<uid>/docker.sock` |
| Podman host | rootless Podman (`podman-docker` gives `docker`), `podman.socket` for Docker-API clients | `/run/user/<uid>/podman/podman.sock` |

What it means in practice (tested on a Debian 13 VPS, 2026-11-08):

| | |
|---|---|
| Two engines | The agent's engine is separate from the system one. `docker ps` as `agent` shows only its own containers; Forgejo, runners and GreptimeDB on the system engine are invisible to it and it can't stop them. |
| Can | run, stop and remove containers, build images, `docker compose`, publish ports ≥ 1024 |
| Can't | `--privileged` that needs real root, ports below 1024, touch the system engine |
| Published ports | rootlesskit binds them as a normal process, so the firewall applies (unlike rootful Docker): `-p 8080:80` is reachable on localhost and the tailnet, not from the internet. Bind `127.0.0.1:8080:80` to keep it on the host. |
| Outbound | containers have full internet access (no egress filter yet) |
| Monitoring | Docker: container logs go to the journal (`--log-driver=journald`), so `[vector]` ships them with `CONTAINER_NAME`; `docker logs` still works. Podman follows `[podman] log_driver`. Metrics: only the agent's total (`user.slice/user-<uid>.slice`), not per container: the CIS umask makes its cgroups unreadable to Vector. |
| Resources | containers run inside `agent`'s slice: CPU, memory and tasks share the caps above. Disk isn't capped and anvil doesn't prune the agent's images: `docker system prune` as `agent`. |
| Security | root in a container is `agent` (or one of its 65536 subordinate ids), so `docker run -v /:/host` reaches only what `agent` can, and an escape lands as `agent`, the user a hijacked agent already is. User namespaces give `agent` more kernel surface: keep the kernel patched (`[updates]`). |
| Reboot | the engine starts with `agent`'s lingering user manager; containers come back only with `--restart` |
| Rollback | stops the engine and removes its unit and the subuid range anvil added; images in `~/.local/share/docker` (Podman: `~/.local/share/containers`) stay |

`[docker] source = "distro"` is refused: Ubuntu's `docker.io` has no rootless
package. On a Docker host, the first apply may upgrade `docker-ce` with
`docker-ce-rootless-extras` (their versions must match). That restarts the
system dockerd, and every container on it unless `[docker] live_restore` is on.

## Log in, once per host

| Agent | Command | Then |
|---|---|---|
| Claude Code | `ssh -t agent@host claude` | `/login`, open the URL, paste the code |
| OpenCode | `ssh -t agent@host opencode` | `/connect` |
| GitHub (private repos, pushes) | `ssh -t agent@host gh auth login` (`gh` from `[packages]`) | or a fine-grained PAT for the agent's repos only |

Give the agent its own tokens, scoped to what it needs.

## Orca

1. In Orca, add an SSH target `agent@<host>.<tailnet>` (with
   `[tailscale] tailnet_only_ssh = true`, the tailnet is the only way in).
2. On first connect Orca installs its server in `~agent/.orca-remote`.
3. Clone a project from the desktop UI or
   `orca project setup-clone --host ssh:<id>`, then open worktrees with
   `claude` or `opencode`. Terminals survive the Mac closing.

## Orca server (phone and laptop without the Mac on)

With `[coding_agents.orca_server]`, the host runs its own Remote Orca Server
as `agent`, so the phone and the laptop pair with it directly over the
tailnet. Needs `[tailscale]` and `[firewall]`.

```toml
[coding_agents.orca_server]
port = 6769            # default; 6768 is the SSH-target runtime's (~/.orca-remote)
# version = "1.4.253"  # pinned; another version needs sha256_amd64 + sha256_arm64
```

```
phone / laptop ──tailnet──▶ tailscale0:6769 ──▶ orca-ide serve (user agent, its slice caps)
internet ───────────────X── ufw: no public rule
```

- `orca-ide` from the release `.deb`, sha256-pinned, through apt: the
  Electron binary needs its GTK/X dependencies even headless, about
  **1.25 GB** on disk (`/opt/Orca`, `/usr/bin/orca-ide`).
- `/etc/systemd/user/orca-server.service` (renamed from
  `anvil-orca-server.service`: the next apply backs the old unit up
  to `.anvil.bak`, stops, disables and removes it, then starts the new one;
  `rollback` restores and restarts the old one), root-owned, enabled in
  `agent`'s user manager (linger): `orca-ide serve --supervise
  --mobile-pairing --port 6769 --pairing-address <tailscale ip -4>`.
  `--mobile-pairing` listens on `0.0.0.0`; ufw allows the port on
  `tailscale0` only. After 6 crashes in 15 min `--supervise` gives up;
  the next `anvil apply` sees it down and starts it.
- State in `agent`'s home: `~/.orca/` (secret store and its key; a restic
  backup of the home contains both), `~/.config/orca/`,
  `~/.claude/keybindings.json`, `~/.claude/orca-agent-view.json`.

### Pairing

Orca 1.4.253 has no `orca-ide pair` yet, and a `--supervise`d server hides
its pairing link ("not writing to a terminal"). So pair by stopping the
service, running the server once in your terminal for 40 s, and starting
the service again. Pairings are stored on the server and survive the restart.

```bash
# laptop: prints "Pairing URL: orca://pair?code=…"
ssh -t <admin>@<host> 'sudo systemctl --user -M agent@ stop orca-server
  sudo -iu agent env TMPDIR=/home/agent/.cache/tmp timeout 40 \
    /usr/bin/orca-ide serve --port 6769 --bind 0.0.0.0 --pairing-address "$(tailscale ip -4)"
  sudo systemctl --user -M agent@ start orca-server'
```

For the **phone**, add `--mobile-pairing` to the `serve` line: it prints a
QR code. Make the terminal tall enough (or zoom out) to fit it, then scan it
in the Orca app. The phone must be on the tailnet.

| Device | Link from | Then |
|---|---|---|
| Laptop | the run without `--mobile-pairing` | Settings → Remote Orca Servers → Add server, paste the link (or `orca environment add --name <host> --pairing-code '<link>'`) |
| Phone | the run with `--mobile-pairing` | Tailscale on, scan the QR in the Orca app |

- Use the laptop link for the laptop: a link from a `--mobile-pairing` run
  is mobile-scoped, and the laptop then can't add projects ("not available
  to mobile clients").
- The server starts empty. Add projects from the laptop (they then show on
  the phone too); the phone can create workspaces but not add projects.
- The code in the link is base64 JSON: the endpoint, the server's public key
  and a device token. **The token is a shell as `agent`**: don't paste links
  in chats or tickets. Revoke a client under Remote Orca Servers.
- Call `/usr/bin/orca-ide`, not plain `orca-ide`: the SSH-target runtime puts
  an older `orca-ide` in `~agent/.local/bin`, first in PATH.

## Rollback

`anvil rollback --only coding_agents` removes, if anvil installed them,
`~/.local/bin/claude`, `~/.local/share/claude` `~/.opencode/bin` and `~/.local/bin/opencode`, plus
linger, the caps drop-in, the `TMPDIR` script, the marker and the `setup`
checkout. With `orca_server`, it stops the server, removes its unit and ufw
rule, and keeps `orca-ide` installed (`apt purge orca-ide`); roll back
before removing the table.

It keeps the account and everything in its home: `~/.agents`, `~/.claude`,
`~/.config/opencode`, `~/.local/share/opencode`, `~/.orca-remote`, `~/.orca`, logins
and repos. Remove those by hand or with the setup repo's `prune.py`.
