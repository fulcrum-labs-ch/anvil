# Host hygiene

What each module leaves on a host over time. Rollback and apply know only the
current config: roll a module back **before** removing it or switching its
mode, or the old mode's units and files stay.

| Module | Grows (bound) | Rollback removes | Left on purpose | Mode switch by apply leaves |
|---|---|---|---|---|
| engine | `runs/` manifest only for an apply that changed something; `.anvil.bak` once per file; `$__rundir` removed on exit | backups restored, created files | packages, users, ufw rules | — |
| github_runner v1 | `_diag` (daily prune); `_tool`/`_actions` only with `disk_max`; HOME caches past `home_cache_max` (daily, idle) | units, registration, trees, homes and images it created, empty user | account home | v1 units, trees, timer (v1→v2) |
| github_runner v2 | slot volumes re-made per job; build cache pruned per build; older `anvil-github-runner` tags and sandbox bases removed once unused | slots, sandboxes, image tags, build cache, key, volumes | sysbox, Docker | minters, sysbox, daemon.json runtime (v2→v1) |
| forgejo_runner | HOME caches past `home_cache_max` (daily, idle); `docker://` images unbounded | unit, binary it installed, user | state dir | — |
| docker | container logs 10m×3 wherever Docker is installed (logs-only without `[docker]`) | daemon.json | engine, images, volumes | distro↔upstream keeps the engine (warns) |
| containers | old images removed after a tag change once unused; Podman logs 10m | units, files; `down` without `-v` | volumes, images | compose units (docker→podman) |
| forgejo | old image removed after a version bump once unused; logs capped | service, config, binary it installed | `/var/lib/forgejo`, image | compose files and image (→native); binary (→compose) |
| caddy | dns build lives in `$__rundir` | Caddyfile, snippets, dns files if `tls = "dns"` now | certs, package, ufw rules, `caddy-anvil` | world 80/443 rules (→tailnet) |
| greptimedb | `data_dir`, bounded by `retention` (TTL); old images removed once unused | compose project | `data_dir` | — |
| beszel | hub database (beszel's own retention) | binaries, units, agent state | hub database | the dropped hub/agent keeps running |
| updates / apt | apt autoclean every 7 days with `[updates]` | files | packages | — |

Other: journald and auditd use distro limits.
