# Module guides

Detail for operating one module, beyond the summary in
[04_modules.md](../04_modules.md) and the fields in
[05_configuration.md](../05_configuration.md).

| Module | Guide |
|---|---|
| `github_runner`, `ci_resources` | [GitHub Actions runner](github-runner.md): setup, limits, security, troubleshooting |
| `forgejo` (+ `caddy`, `fail2ban`) | [Forgejo](forgejo.md): tailnet-only setup, own domain, security, operations, troubleshooting |
| `forgejo_runner` | [Forgejo Actions runner](forgejo-runner.md): why jobs run on the host, setup, security, troubleshooting |
| `coding_agents` | [Coding agents](coding-agents.md): Claude Code and OpenCode for a no-sudo user, logins, Orca, rollback |
| `greptimedb`, `vector` (+ `docker` `log_driver`) | [Monitoring](monitoring.md): what is collected, the SSH tunnel, dashboards, queries |
| `containers`, `docker` and every module that needs an engine | [Docker or Podman](container-engines.md): one engine per host, which modules run on each |
