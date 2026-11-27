# Monitoring: GreptimeDB + Vector

Every journal line and the host's and containers' CPU/memory, in one
GreptimeDB on the host, with dashboards. `[vector]` ships, `[greptimedb]`
stores; with `[docker] log_driver = "journald"`, container output joins the
journal.

```toml
[greptimedb]
retention = "30d"            # TTL on every database
memory_max = "2G"            # container memory limit

[vector]                     # defaults: GreptimeDB on 127.0.0.1, journald + host metrics

[docker]
log_driver = "journald"      # containers → journal → Vector
```

## What is collected

| Source | What | Lands in (database `public`) |
|---|---|---|
| journald (all retained boots) | systemd units, kernel, sshd, runners; containers with the journald log driver (known noise is dropped: sysbox-fs's idle `reaper: nothing to reap`, networkctl's `Interface "veth…" not found` and LLDP varlink errors) | table `vector_logs`: one column per journal field (`message`, `PRIORITY`, `_SYSTEMD_UNIT`, `SYSLOG_IDENTIFIER`, `CONTAINER_NAME`, …), time `greptime_timestamp` (when the line was logged, not when it arrived) |
| `extra_log_files` | the files you list | `vector_logs` |
| host metrics, every `scrape_interval_secs` | CPU, load, memory, disks, filesystems, network, TCP (no per-process series: half the disk, no dashboard reads them) | one table per metric: `host_cpu_seconds_total`, `host_memory_available_bytes`, `host_filesystem_used_ratio`, … (value `greptime_value`) |
| cgroups (`cgroups_include`) | CPU and memory per container (`system.slice/docker-<id>.scope`), CI (`ci.slice` and each runner in it), user (`user.slice/user-<uid>.slice`, i.e. coding agents, including their rootless containers as one total), system services (`system.slice/<name>.service`), and each docker-rootless CI sandbox (`user.slice/user-<uid>.slice/user@<uid>.service/user.slice/docker-<id>.scope`, added on the host for every `anvil-fjr-*`/`anvil-ghr-*` slot user) | `host_cgroup_cpu_usage_seconds_total`, `host_cgroup_memory_current_bytes`, …, tag `cgroup` |

Journal fields are strings, so `PRIORITY` is `'3'`, not `3`. Column names
are case-sensitive: quote them (`"_SYSTEMD_UNIT"`).

## Container logs

`[docker] log_driver = "journald"` reaches containers created after dockerd
restarted with it; running ones keep json-file until recreated. anvil
recreates its own on their next change (compose projects, `[greptimedb]`,
Forgejo compose, Headplane, each v2 runner sandbox per job); recreate
others with `docker compose up -d --force-recreate`. `docker logs` keeps
working. The journal's size is then the cap: journald's `SystemMaxUse`
(default 10 % of the filesystem, at most 4G).

## Open the dashboards

GreptimeDB listens on 127.0.0.1 only. Tunnel to it, or put it behind a
tailnet-only `[[caddy.site]]` with `upstream = "127.0.0.1:4000"` (it has no
login of its own: keep it off the public internet):

```bash
ssh -L 4000:127.0.0.1:4000 <user>@<host>
```

then open <http://localhost:4000/dashboard> → **Visualization**. Every apply
of `[greptimedb]` that changes something imports these (same name =
replaced):

| Dashboard | Shows |
|---|---|
| `anvil-host` | Overview gauges and stats (CPU, memory, root disk, uptime, load per core, OOM kills), then CPU by mode, load, memory, real filesystems, disk throughput and IOPS, network, TCP, memory per system service, CPU/memory per user (memory panels here and in `anvil-containers`/`anvil-ci` exclude reclaimable file cache) |
| `anvil-errors` | journal lines with priority ≤ 3 (err, crit, alert, emerg): per unit over time, and the lines |
| `anvil-containers` | Overview stats (running, CPU, memory, log and error lines), CPU and memory per container **by name** (from the journald log driver's `CONTAINER_NAME`; a recreated container continues its line), the same per container **id** (collapsed; `name · id`, or the bare id if it never logged), log lines per container, the lines |
| `anvil-ci` | Overview stats (busy minutes, sandboxes, CPU, memory, runner errors); CPU and memory **per runner including its jobs** (service cgroup + its sysbox sandboxes, matched by container name; stacked = CI total; memory without reclaimable file cache); busy minutes per hour; per sandbox `runner · id` (collapsed); runner log lines |

Sources: [`assets/perses/`](../../assets/perses/). They query database
`public` (`[vector] db_name`'s default). `rollback` leaves them, the data
and the TTL in GreptimeDB.

## Queries

SQL in the dashboard's query page, or `mysql -h 127.0.0.1 -P 4002`, or
`curl -s localhost:4000/v1/sql --data-urlencode "sql=…"`:

```sql
-- errors in the last hour, per unit
SELECT "_SYSTEMD_UNIT", count(*) AS n FROM vector_logs
WHERE "PRIORITY" IN ('0','1','2','3') AND greptime_timestamp > now() - INTERVAL '1 hour'
GROUP BY "_SYSTEMD_UNIT" ORDER BY n DESC;

-- one container's last lines
SELECT greptime_timestamp, message FROM vector_logs
WHERE "CONTAINER_NAME" = 'forgejo' ORDER BY greptime_timestamp DESC LIMIT 50;

-- full-text search across everything
SELECT greptime_timestamp, "_SYSTEMD_UNIT", message FROM vector_logs
WHERE message LIKE '%rustup%' ORDER BY greptime_timestamp DESC LIMIT 50;
```

PromQL (`/v1/prometheus`, or a dashboard panel):

```promql
# CPU cores used by all CI work
rate(host_cgroup_cpu_usage_seconds_total{cgroup="ci.slice"}[5m])
```

Metric names need an exact name: `{__name__=~"…"}` finds nothing on
Vector's tables.

## Upgrading GreptimeDB

The default `version` is `v1.3.0`. v1.x cannot open data written before
v0.16, so apply stops with `FAILED:` while an older `greptimedb` container
runs. Keep the old one with `version = "<its tag>"`, or start empty:
`docker rm -f greptimedb` and a new `data_dir`.
