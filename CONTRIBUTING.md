# Contributing

Thanks for helping. Bugs and ideas: open an issue. Security problems: see
[`SECURITY.md`](SECURITY.md), never a public issue.

## Pull requests

- One change per PR, with tests. Write the test first and see it fail.
- Run the gate before pushing; CI runs the same:

  ```bash
  cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo nextest run && cargo test --doc
  ```

  CI also mutation-tests the lines your PR changes (`cargo mutants --in-diff`).
- TOML section and field names, drop-in paths and unit names are a public
  contract. Renaming one needs an issue first.
- Changed install or detect logic? Run `scripts/acceptance.sh` against a
  **disposable** Debian 13 or Ubuntu 26.04 box and say so in the PR.
- PRs from forks wait for a maintainer to approve their CI run.

## Where things are

- Build, tests, adding a module: [`docs/09_development.md`](docs/09_development.md)
- Architecture: [`docs/08_architecture.md`](docs/08_architecture.md)
- Rules the code must keep (escaping, backups, safety edges, PAM):
  [`AGENTS.md`](AGENTS.md). Read them even if you are not an agent.
