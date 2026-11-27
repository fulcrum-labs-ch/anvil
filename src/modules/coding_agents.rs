//! The `coding_agents` module (docs/design/coding-agents.md): Claude
//! Code and OpenCode v2 from their official installers, run as one
//! unprivileged login user and self-updating in its home.
//! Skills, plugins, MCP servers and an optional setup repo are installed **as
//! that user** (`runuser`): root never writes into the agent's home.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::config::schema::{CodingAgentsSection, OrcaServer};
use crate::config::Engine;
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_CHANGED,
    MARK_DRIFTED, MARK_FAILED, MARK_OK,
};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::runner_common::{self, cgroup_caps, Download};
use super::{apt_install, dpkg_installed, Module, APT_LOCK_TIMEOUT};

pub const PROFILE_PATH: &str = "/etc/profile.d/anvil-coding-agents.sh";

/// Node 24 from NodeSource (D6): context-mode v2 needs >= 24.15; the distro
/// ships 20/22. Hardcoded: one major line, no config field.
const NODE_MIN: &str = "24.15.0";
const NODE_KEY_PATH: &str = "/etc/apt/keyrings/nodesource.asc";
const NODE_LIST_PATH: &str = "/etc/apt/sources.list.d/nodesource.list";
const NODE_PIN_PATH: &str = "/etc/apt/preferences.d/99-anvil-nodesource";
/// Verified 2026-11-06 against `https://deb.nodesource.com/node_24.x/dists/nodistro/Release`.
const NODE_SOURCE: &str = "deb [signed-by=/etc/apt/keyrings/nodesource.asc] \
https://deb.nodesource.com/node_24.x nodistro main\n";
/// Beats the distro `nodejs` (500), so an installed distro Node is upgraded.
const NODE_PIN: &str = "Package: nodejs\nPin: origin deb.nodesource.com\nPin-Priority: 600\n";
/// `https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key`, primary
/// fingerprint `6F71F525282841EEDAF851B42F59B5F99B1BE0B4` (tested below).
const NODE_KEY: &str = include_str!("nodesource.asc");

/// Orca release `.deb`s, sha256 from the GitHub release asset digests
/// (`gh api repos/stablyai/orca/releases/tags/v1.4.253`, 2026-11-07).
pub const ORCA_VERSION: &str = "1.4.253";
const ORCA_SHA256: (&str, &str) = (
    "982fc25b1805dc8be66096b9a1ebcaf0b55eec3966b5c6ee606919797263d572",
    "f237b7242537442283a300380295a7b3807ee2226f88773e52f541706f7fa103",
);
/// A user unit root owns: the agent can neither edit it nor see it in its home.
pub const ORCA_UNIT_PATH: &str = "/etc/systemd/user/orca-server.service";
const ORCA_UNIT: &str = "orca-server.service";
/// Pre- name, migrated on apply and restored on rollback.
const ORCA_LEGACY_PATH: &str = "/etc/systemd/user/anvil-orca-server.service";
const ORCA_LEGACY_UNIT: &str = "anvil-orca-server.service";
/// `docker = "rootless"` on a Docker host: the agent's dockerd, root-owned
/// like the Orca unit. Mirrors `dockerd-rootless-setuptool.sh install`'s unit.
pub const DOCKER_UNIT_PATH: &str = "/etc/systemd/user/anvil-docker-rootless.service";
const DOCKER_UNIT: &str = "anvil-docker-rootless.service";
/// `docker = "rootless"` on a Podman host: Podman's own Docker-API socket.
const PODMAN_SOCKET: &str = "podman.socket";

/// Load-time check: pins are 64 hex, and a non-default `version` needs both.
pub fn validate_pins(o: &OrcaServer) -> Result<()> {
    for (f, v) in [
        ("sha256_amd64", &o.sha256_amd64),
        ("sha256_arm64", &o.sha256_arm64),
    ] {
        match v {
            Some(v) if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                return Err(AnvilError::Validation(format!(
                    "coding_agents.orca_server.{f} = {v:?} must be 64 hex characters"
                )))
            }
            None if o.version != ORCA_VERSION => {
                return Err(AnvilError::Validation(format!(
                    "coding_agents.orca_server.version = {:?} needs {f} (the release \
                     asset's sha256 digest); only {ORCA_VERSION} is built in",
                    o.version
                )))
            }
            _ => {}
        }
    }
    Ok(())
}

/// One agent's official installer, run as the agent. Paths are relative to
/// its home; `owned` is what rollback removes (config and data stay).
struct Installer {
    name: &'static str,
    token: &'static str,
    bin: &'static str,
    /// `$@` = the installer's arguments.
    pipe: &'static str,
    owned: &'static [&'static str],
}

const CLAUDE: Installer = Installer {
    name: "Claude Code",
    token: "claude",
    bin: ".local/bin/claude",
    pipe: "curl -fsSL https://claude.ai/install.sh | bash -s \"$@\"",
    owned: &[".local/bin/claude", ".local/share/claude"],
};

const OPENCODE: Installer = Installer {
    name: "OpenCode",
    token: "opencode",
    // The installer's bin dir is not on a login shell's PATH; ~/.local/bin is
    // (Debian/Ubuntu ~/.profile), so link it there, next to claude.
    bin: ".local/bin/opencode",
    pipe: "curl -fsSL https://opencode.ai/v2/install | bash -s -- \"$@\" \
           && mkdir -p \"$HOME/.local/bin\" \
           && ln -sfn ../../.opencode/bin/opencode \"$HOME/.local/bin/opencode\"",
    owned: &[".opencode/bin", ".local/bin/opencode"],
};

/// Sets `mcp.<argv[2]>` in the OpenCode config `argv[1]` to a local server
/// running the JSON array `argv[3]`; other keys stay. OpenCode v2 reads
/// `mcp.<name>`, not the `mcp.servers.<name>` its `mcp add` writes, so a stale
/// entry there is dropped. Invalid JSON (e.g. comments) fails, untouched.
const OPENCODE_MCP_PY: &str = r#"import json, os, sys
p, name, cmd = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
try:
    with open(p) as f:
        c = json.load(f)
except FileNotFoundError:
    c = {}
mcp = c.setdefault("mcp", {})
old = mcp.get("servers")
if isinstance(old, dict):
    old.pop(name, None)
    if not old:
        del mcp["servers"]
e = mcp.get(name) if isinstance(mcp.get(name), dict) else {}
e.update(type="local", command=cmd, enabled=True)
mcp[name] = e
os.makedirs(os.path.dirname(p), exist_ok=True)
with open(p + ".tmp", "w") as f:
    json.dump(c, f, indent=2)
    f.write("\n")
os.replace(p + ".tmp", p)
"#;

/// Relative to the agent's home.
const MARKER: &str = ".agents/.anvil-coding-agents";
const SETUP_DIR: &str = ".local/share/anvil/setup";
/// What the agent's home keeps after rollback (its data, docs/design/coding-agents.md §2).
const KEPT: &str =
    "~/.agents ~/.claude ~/.config/opencode ~/.local/share/opencode ~/.orca-remote ~/.orca ~/.config/orca";
/// Exit code of the agent script when a private `setup` repo needs a login.
const WAITS_FOR_GITHUB: u8 = 3;

pub struct CodingAgentsModule {
    cfg: CodingAgentsSection,
    tmp_noexec: bool,
    /// The host's engine: what `docker = "rootless"` runs.
    engine: Engine,
    /// `[docker] source = "distro"` (see `ensure_engine`).
    docker_distro: bool,
}

impl CodingAgentsModule {
    pub fn new(cfg: CodingAgentsSection) -> Self {
        Self {
            cfg,
            tmp_noexec: false,
            engine: Engine::Docker,
            docker_distro: false,
        }
    }

    pub fn engine(mut self, engine: Engine) -> Self {
        self.engine = engine;
        self
    }

    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }

    /// `docker = "rootless"`: the host's engine, run as the agent.
    fn rootless(&self) -> Option<Engine> {
        (self.cfg.docker == "rootless").then_some(self.engine)
    }

    /// The agent's Docker-API socket under its `XDG_RUNTIME_DIR`.
    fn docker_socket(&self) -> Option<&'static str> {
        self.rootless().map(|e| match e {
            Engine::Docker => "docker.sock",
            Engine::Podman => "podman/podman.sock",
        })
    }

    /// `[filesystem] tmp_noexec`: give the agent its own `TMPDIR`.
    pub fn tmp_noexec(mut self, on: bool) -> Self {
        self.tmp_noexec = on;
        self
    }

    fn claude(&self) -> bool {
        self.cfg.claude_code != "none"
    }

    fn opencode(&self) -> bool {
        self.cfg.opencode != "none"
    }

    /// `-a` values for `npx skills` and `AGENTS` for `setup`.
    fn agents(&self) -> Vec<&'static str> {
        let mut a = Vec::new();
        if self.claude() {
            a.push("claude-code");
        }
        if self.opencode() {
            a.push("opencode");
        }
        a
    }

    fn user(&self) -> String {
        shell_escape(&self.cfg.user)
    }

    /// `id -u` resolves the caps drop-in path; refuse before anything is
    /// written for a user `[users]` did not create.
    fn user_exists(&self) -> ManagedCommand {
        let u = self.user();
        ManagedCommand::new(
            format!("coding agent user {} exists", self.cfg.user),
            format!("id -u {u} >/dev/null 2>&1"),
            format!(
                "printf '{MARK_FAILED} coding_agents: user %s does not exist; create it in [users]\\n' {u}\nexit 1"
            ),
        )
    }

    fn deps() -> ManagedCommand {
        let pkgs = [
            "git",
            "curl",
            "ca-certificates",
            "build-essential",
            "python3",
        ];
        let detect: Vec<String> = pkgs.iter().map(|p| dpkg_installed(p)).collect();
        ManagedCommand::new(
            "git, build tools, python3 for the coding agents",
            detect.join(" && "),
            apt_install(&pkgs),
        )
    }

    /// NodeSource key, source and pin from content embedded here, then
    /// `nodejs` (it includes npm/npx and conflicts with the distro `npm`).
    fn node() -> ManagedCommand {
        let files = [
            (NODE_KEY_PATH, NODE_KEY),
            (NODE_LIST_PATH, NODE_SOURCE),
            (NODE_PIN_PATH, NODE_PIN),
        ];
        let at_least = format!(
            "dpkg --compare-versions \"$(/usr/bin/node --version 2>/dev/null | sed 's/^v//')\" ge {NODE_MIN}"
        );
        let mut detect = vec![at_least.clone()];
        let mut write = String::from("install -d -m 0755 /etc/apt/keyrings\n");
        for (path, content) in files {
            let b = shell_escape(&B64.encode(content));
            detect.push(format!("cmp -s {path} <(printf '%s' {b} | base64 -d)"));
            write.push_str(&format!("printf '%s' {b} | base64 -d > {path}\n"));
        }
        ManagedCommand::new(
            "Node.js 24 from NodeSource (key pinned)",
            detect.join(" && "),
            format!(
                "{write}chmod 0644 {NODE_KEY_PATH} {NODE_LIST_PATH} {NODE_PIN_PATH}\n\
                 {install}\n\
                 {at_least} || {{ printf '{MARK_FAILED} coding_agents: /usr/bin/node is %s, not >= {NODE_MIN}\\n' \
                 \"$(/usr/bin/node --version 2>&1)\"; exit 1; }}",
                install = apt_install(&["nodejs", "npm-"]),
            ),
        )
    }

    /// The installer as the agent: the binary updates itself, so detect only
    /// checks that it runs, never a version. Recorded only when anvil
    /// installed it, so rollback leaves a pre-existing install alone.
    fn agent_install(&self, i: &Installer, args: &[&str]) -> ManagedCommand {
        let u = self.user();
        let token = shell_escape(&format!("{}:{}", i.token, self.cfg.user));
        let runs = self.as_agent(&format!("\"$__home/{}\" --version", i.bin));
        let argv: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
        let install = self.as_agent(&format!(
            "bash -c {} bash {}",
            shell_escape(&format!(
                "set -o pipefail; cd \"$HOME\"\n\
                 mkdir -p \"$HOME/.cache/tmp\" && export TMPDIR=\"$HOME/.cache/tmp\"\n\
                 {}",
                i.pipe
            )),
            argv.join(" ")
        ));
        ManagedCommand::new(
            format!("{} runs for {} (official installer)", i.name, self.cfg.user),
            format!(
                "{{ __home=$(getent passwd {u} | cut -d: -f6); [ -n \"$__home\" ] && {runs} >/dev/null 2>&1 </dev/null; }}"
            ),
            format!(
                "[ -n \"$__home\" ]\n\
                 __ci_rc=0\n\
                 __ci_out=$({install} 2>&1 </dev/null) || __ci_rc=$?\n\
                 printf '%s\\n' \"$__ci_out\" | sed 's/^/  | /'\n\
                 if [ \"$__ci_rc\" != 0 ] || ! {runs} >/dev/null 2>&1 </dev/null; then\n\
                 \x20 printf '{MARK_FAILED} coding_agents: {name} installer failed for %s (exit %s)\\n' {u} \"$__ci_rc\"; exit 1\n\
                 fi\n\
                 __anvil_remember {token}",
                name = i.name,
            ),
        )
    }

    /// `claude_code` is the installer's channel; `opencode` is `latest` or a
    /// version for its `--version` (used when it installs, not enforced after).
    fn installers(&self) -> Vec<(&'static Installer, Vec<&str>)> {
        let mut v = Vec::new();
        if self.claude() {
            v.push((&CLAUDE, vec![self.cfg.claude_code.as_str()]));
        }
        if self.opencode() {
            let args = match self.cfg.opencode.as_str() {
                "latest" => vec![],
                ver => vec!["--version", ver],
            };
            v.push((&OPENCODE, args));
        }
        v
    }

    fn linger(&self) -> ManagedCommand {
        let u = self.user();
        let linger = shell_escape(&format!("/var/lib/systemd/linger/{}", self.cfg.user));
        let token = shell_escape(&format!("linger:{}", self.cfg.user));
        ManagedCommand::new(
            format!("{} lingers (user manager without a login)", self.cfg.user),
            format!("[ -e {linger} ]"),
            format!("loginctl enable-linger {u}\n__anvil_remember {token}"),
        )
    }

    /// The script the agent user runs (`bash -c`, `$1` = the marker hash).
    /// Every item runs; the marker is written only when none failed and
    /// `setup` did not wait for GitHub access.
    pub fn agent_script(&self) -> String {
        let c = &self.cfg;
        let e = |v: &str| shell_escape(v);
        let mut s = String::from(
            "set -uo pipefail\ncd \"$HOME\"\n\
             mkdir -p \"$HOME/.cache/tmp\" && export TMPDIR=\"$HOME/.cache/tmp\"\n\
             failed=() waits=0\n\
             run() { printf -- '--> %s\\n' \"$*\"; \"$@\" </dev/null || failed+=(\"$*\"); }\n",
        );
        for sk in &c.skills {
            let agents = sk
                .agents
                .clone()
                .unwrap_or_else(|| self.agents().iter().map(|a| a.to_string()).collect());
            let mut line = format!("run npx -y skills@latest add {} -g -y", e(&sk.source));
            for a in &agents {
                line.push_str(&format!(" -a {}", e(a)));
            }
            for n in &sk.names {
                line.push_str(&format!(" -s {}", e(n)));
            }
            s.push_str(&line);
            s.push('\n');
        }
        for m in &c.claude_marketplaces {
            s.push_str(&format!("run claude plugin marketplace add {}\n", e(m)));
        }
        if !c.claude_marketplaces.is_empty() {
            s.push_str("run claude plugin marketplace update\n");
        }
        for p in &c.claude_plugins {
            s.push_str(&format!("run claude plugin install {} -s user\n", e(p)));
        }
        for p in &c.opencode_plugins {
            s.push_str(&format!("run opencode plugin add {}\n", e(p)));
        }
        for (name, cmd) in &c.opencode_mcp {
            s.push_str(&format!(
                "run python3 -c {} \"$HOME/.config/opencode/opencode.json\" {} {}\n",
                e(OPENCODE_MCP_PY),
                e(name),
                e(&serde_json::Value::from(cmd.clone()).to_string())
            ));
        }
        if let Some(st) = &c.setup {
            let (url, rev, run) = (e(&st.url), e(&st.rev), e(&format!("./{}", st.run)));
            let agents = e(&self.agents().join(" "));
            s.push_str(&format!(
                "d=\"$HOME/{SETUP_DIR}\"\n\
                 setup() {{\n\
                 \x20 if [ -d \"$d/.git\" ]; then git -C \"$d\" remote set-url origin {url} && git -C \"$d\" fetch -q origin || return 1\n\
                 \x20 else rm -rf \"$d\" && mkdir -p \"${{d%/*}}\" && git clone -q {url} \"$d\" || return 1; fi\n\
                 \x20 git -C \"$d\" cat-file -e {rev}^{{commit}} 2>/dev/null || git -C \"$d\" fetch -q origin {rev} || return 1\n\
                 \x20 git -C \"$d\" checkout -q --detach {rev} && (cd \"$d\" && AGENTS={agents} {run} </dev/null)\n\
                 }}\n\
                 if ! out=$(git ls-remote {url} 2>&1 </dev/null); then\n\
                 \x20 printf '%s\\n' \"$out\"\n\
                 \x20 case $out in\n\
                 \x20\x20 *Authentication*|*'could not read Username'*|*'not found'*|*'terminal prompts disabled'*) waits=1 ;;\n\
                 \x20\x20 *) failed+=(\"setup: git ls-remote\") ;;\n\
                 \x20 esac\n\
                 else\n\
                 \x20 printf -- '--> setup %s\\n' {rev}\n\
                 \x20 setup || failed+=(\"setup\")\n\
                 fi\n"
            ));
        }
        s.push_str(&format!(
            "if [ ${{#failed[@]}} -gt 0 ]; then printf 'failed: %s\\n' \"${{failed[@]}}\"; exit 1; fi\n\
             [ \"$waits\" = 0 ] || exit {WAITS_FOR_GITHUB}\n\
             mkdir -p \"$HOME/.agents\" && printf '%s\\n' \"$1\" > \"$HOME/{MARKER}\"\n"
        ));
        s
    }

    /// The hash the marker must hold: lists and `setup`. No agent version:
    /// both update themselves, and every update would re-run the installers.
    fn marker_hash(&self) -> String {
        let c = &self.cfg;
        let spec = serde_json::json!({
            "skills": c.skills,
            "claude_marketplaces": c.claude_marketplaces,
            "claude_plugins": c.claude_plugins,
            "opencode_plugins": c.opencode_plugins,
            "opencode_mcp": c.opencode_mcp,
            // Bumped when an item's install changes, so hosts re-run it.
            "format": 2,
            "setup": c.setup,
        })
        .to_string();
        format!(
            "__want=$(printf '%s\\n' {} | sha256sum | cut -d' ' -f1)",
            shell_escape(&spec)
        )
    }

    /// As the agent, nothing as root in its home (`HOME` from passwd).
    fn as_agent(&self, cmd: &str) -> String {
        let u = self.user();
        format!(
            "runuser -u {u} -- env -i HOME=\"$__home\" USER={u} LOGNAME={u} SHELL=/bin/bash \
             PATH=\"$__home/.local/bin:$__home/.opencode/bin:/usr/local/bin:/usr/bin:/bin\" LANG=C.UTF-8 GIT_TERMINAL_PROMPT=0 {cmd}"
        )
    }

    fn lists(&self) -> ManagedCommand {
        let u = self.user();
        let home = format!("__home=$(getent passwd {u} | cut -d: -f6)");
        let read = self.as_agent(&format!("cat \"$__home/{MARKER}\""));
        let script = self.as_agent(&format!(
            "bash -c {} bash \"$__want\"",
            shell_escape(&self.agent_script())
        ));
        ManagedCommand::new(
            format!(
                "skills, plugins, MCP servers and setup installed as {}",
                self.cfg.user
            ),
            format!(
                "{{ {home}; {want}; [ -n \"$__home\" ] && [ \"$({read} 2>/dev/null)\" = \"$__want\" ]; }}",
                want = self.marker_hash()
            ),
            format!(
                "[ -n \"$__home\" ]\n\
                 __ca_rc=0\n\
                 __ca_out=$({script} 2>&1 </dev/null) || __ca_rc=$?\n\
                 # indented, so the installers' output can never pass for a marker\n\
                 printf '%s\\n' \"$__ca_out\" | sed 's/^/  | /'\n\
                 case $__ca_rc in\n\
                 \x20 0) ;;\n\
                 \x20 {WAITS_FOR_GITHUB}) printf '{MARK_DRIFTED} coding_agents: setup waits for GitHub access; \
                 log in as %s (gh auth login), then apply again\\n' {u} ;;\n\
                 \x20 *) printf '{MARK_FAILED} coding_agents: as %s, failed: %s; the next apply retries\\n' {u} \
                 \"$(printf '%s\\n' \"$__ca_out\" | sed -n 's/^failed: //p' | paste -sd ',' -)\"; exit 1 ;;\n\
                 esac"
            ),
        )
    }

    fn caps(&self) -> Option<ManagedFile> {
        let c = &self.cfg;
        let caps = cgroup_caps(c.cpu_quota.as_deref(), c.memory_max.as_deref(), c.tasks_max);
        if caps.is_empty() {
            return None;
        }
        Some(
            ManagedFile::new(
                format!(
                    "/etc/systemd/system/user-<uid>.slice.d/99-anvil-coding-agents.conf ({})",
                    c.user
                ),
                format!("# Managed by anvil — caps for everything {} runs\n[Slice]\n{caps}", c.user),
                "0644",
                "root:root",
            )
            .with_path_resolver(format!(
                "printf '/etc/systemd/system/user-%s.slice.d/99-anvil-coding-agents.conf' \"$(id -u {} 2>/dev/null)\"",
                self.user()
            )),
        )
    }

    /// `profile.d` runs for login shells (ssh, Orca terminals): a home
    /// `TMPDIR` when /tmp is noexec, `DOCKER_HOST` for the rootless engine.
    fn profile(&self) -> String {
        let mut lines = String::new();
        if self.tmp_noexec {
            lines.push_str(
                "  mkdir -p \"$HOME/.cache/tmp\" && export TMPDIR=\"$HOME/.cache/tmp\"\n",
            );
        }
        if let Some(sock) = self.docker_socket() {
            lines.push_str(&format!(
                "  export DOCKER_HOST=\"unix:///run/user/$(id -u)/{sock}\"\n"
            ));
        }
        format!(
            "# Managed by anvil — {u}'s TMPDIR and DOCKER_HOST\n\
             if [ \"$(id -un)\" = {e} ]; then\n\
             {lines}\
             fi\n",
            u = self.cfg.user,
            e = self.user(),
        )
    }

    /// Static, so `diff` shows it; `ConditionUser` keeps other users' managers out.
    fn docker_unit(&self) -> String {
        format!(
            "# Managed by anvil — rootless dockerd for {u}\n\
             [Unit]\n\
             Description=Docker (rootless, anvil)\n\
             ConditionUser={u}\n\
             StartLimitIntervalSec=60s\n\
             StartLimitBurst=3\n\
             \n\
             [Service]\n\
             Environment=PATH=/usr/bin:/sbin:/usr/sbin:/bin\n\
             ExecStart=/usr/bin/dockerd-rootless.sh --log-driver=journald\n\
             ExecReload=/bin/kill -s HUP $MAINPID\n\
             TimeoutSec=0\n\
             RestartSec=2\n\
             Restart=always\n\
             LimitNOFILE=infinity\n\
             LimitNPROC=infinity\n\
             LimitCORE=infinity\n\
             Delegate=yes\n\
             Type=notify\n\
             NotifyAccess=all\n\
             KillMode=mixed\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            u = self.cfg.user,
        )
    }

    /// Drift when the agent's dockerd is down; the guard (re)starts it.
    fn docker_active(&self) -> ManagedCommand {
        ManagedCommand::new(
            format!("rootless dockerd running as {}", self.cfg.user),
            format!(
                "{} is-active --quiet {DOCKER_UNIT} 2>/dev/null",
                self.user_ctl()
            ),
            "true",
        )
    }

    /// Podman needs no daemon; the socket serves Docker-API clients (compose,
    /// testcontainers). Enabled by the agent's own manager, in its home.
    fn podman_socket(&self) -> ManagedCommand {
        let ctl = self.user_ctl();
        ManagedCommand::new(
            format!("rootless podman socket for {}", self.cfg.user),
            format!(
                "{{ {ctl} is-enabled --quiet {PODMAN_SOCKET} && {ctl} is-active --quiet {PODMAN_SOCKET}; }} 2>/dev/null"
            ),
            format!(
                "systemctl start \"user@$(id -u {u}).service\"\n\
                 {ctl} enable --now {PODMAN_SOCKET} >/dev/null 2>&1",
                u = self.user(),
            ),
        )
    }

    /// The pinned `.deb` through apt (its GTK/X `Depends`, even for `serve`).
    fn orca_install(o: &OrcaServer) -> ManagedCommand {
        let ver = shell_escape(&o.version);
        let sums = (
            o.sha256_amd64.as_deref().unwrap_or(ORCA_SHA256.0),
            o.sha256_arm64.as_deref().unwrap_or(ORCA_SHA256.1),
        );
        let download = Download {
            module: "coding_agents",
            arch_names: ("amd64", "arm64"),
            sha256: sums,
            url: "\"https://github.com/stablyai/orca/releases/download/v${__ov}/orca-ide_${__ov}_${__ra}.deb\"",
            file: "orca-ide.deb",
            what: "orca-ide package",
        }
        .script();
        ManagedCommand::new(
            format!("Orca server orca-ide {} installed", o.version),
            format!(
                "[ \"$(dpkg-query -W -f='${{Status}} ${{Version}}' orca-ide 2>/dev/null)\" = {} ]",
                shell_escape(&format!("install ok installed {}", o.version))
            ),
            format!(
                "__ov={ver}\n{download}\
                 DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} update -qq && \
                 DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} install -y -qq \"$__tmp/orca-ide.deb\"\n\
                 rm -rf \"$__tmp\"\n\
                 __orca_new=1"
            ),
        )
    }

    /// The .deb ships world-writable files in /opt/Orca (libraries, the crash
    /// handler): any local user could swap code the agent then runs.
    fn orca_not_world_writable() -> ManagedCommand {
        ManagedCommand::new(
            "no world-writable files in /opt/Orca",
            "[ -z \"$(find /opt/Orca -perm -0002 ! -type l -print -quit 2>/dev/null)\" ]",
            "chmod -R o-w /opt/Orca",
        )
    }

    /// Fails before the unit is written, so it never pairs to an empty address.
    fn orca_tailnet_ip() -> ManagedCommand {
        ManagedCommand::new(
            "tailnet IPv4 for the Orca pairing address",
            "[ -n \"$(tailscale ip -4 2>/dev/null | head -n1 || true)\" ]",
            format!(
                "printf '{MARK_FAILED} coding_agents: no tailnet IPv4 (tailscale ip -4); orca_server needs [tailscale] up\\n'\nexit 1"
            ),
        )
    }

    /// `--mobile-pairing` binds 0.0.0.0, so ufw is what keeps it tailnet-only.
    fn orca_rule(o: &OrcaServer) -> String {
        format!(
            "allow in on tailscale0 to any port {} proto tcp",
            shell_escape(&o.port.to_string())
        )
    }

    /// `ufw show added` prints the rule unquoted.
    fn orca_needle(o: &OrcaServer) -> String {
        shell_escape(&format!(
            "allow in on tailscale0 to any port {} proto tcp",
            o.port
        ))
    }

    fn orca_firewall(o: &OrcaServer) -> ManagedCommand {
        ManagedCommand::new(
            format!("firewall allow {}/tcp on tailscale0 only (Orca server)", o.port),
            format!(
                "ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null \
                 && ufw show added 2>/dev/null | grep -wF {} >/dev/null",
                Self::orca_needle(o)
            ),
            format!(
                "if ! ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null; then\n\
                 \x20 printf '{MARK_FAILED} coding_agents: ufw is not active; refusing to start the Orca server on 0.0.0.0\\n'\n\
                 \x20 exit 1\n\
                 fi\n\
                 if ufw status verbose 2>/dev/null | grep -F 'allow (incoming)' >/dev/null; then\n\
                 \x20 printf '{MARK_FAILED} coding_agents: ufw default incoming is allow; refusing to start the Orca server on 0.0.0.0\\n'\n\
                 \x20 exit 1\n\
                 fi\n\
                 ufw {} >/dev/null",
                Self::orca_rule(o)
            ),
        )
    }

    /// `systemctl` on the agent's user manager, from root.
    fn user_ctl(&self) -> String {
        format!(
            "systemctl --user -M {}",
            shell_escape(&format!("{}@", self.cfg.user))
        )
    }

    /// Probe-visible drift while the older unit exists; the reload migrates
    /// it once the new unit is in place.
    fn orca_legacy_absent() -> ManagedCommand {
        ManagedCommand::new(
            "older Orca unit absent (the reload migrates it)",
            format!("[ ! -e {} ]", shell_escape(ORCA_LEGACY_PATH)),
            ":",
        )
    }

    /// Drift when the server is down; the guard (re)starts it.
    fn orca_active(&self) -> ManagedCommand {
        ManagedCommand::new(
            format!("Orca server running as {}", self.cfg.user),
            format!(
                "{} is-active --quiet {ORCA_UNIT} 2>/dev/null",
                self.user_ctl()
            ),
            "true",
        )
    }

    /// Run inside the guard's reload, i.e. only after the new unit was
    /// written, and only while the old one exists. Nothing is stopped or
    /// removed unless the backup exists; a failed backup leaves the old unit
    /// in place and the next apply retries.
    fn orca_migrate_legacy(&self) -> String {
        let ctl = self.user_ctl();
        let new = shell_escape(ORCA_UNIT_PATH);
        let old = shell_escape(ORCA_LEGACY_PATH);
        let bak = shell_escape(&format!("{ORCA_LEGACY_PATH}{BACKUP_SUFFIX}"));
        format!(
            "if [ -f {new} ] && [ -e {old} ]; then\n\
             \x20 if [ -e {bak} ] || cp -a {old} {bak}; then\n\
             \x20\x20 {ctl} disable --now {ORCA_LEGACY_UNIT} >/dev/null 2>&1 || true\n\
             \x20\x20 rm -f {old}\n\
             \x20\x20 printf '{MARK_CHANGED} Orca unit migrated from %s to {ORCA_UNIT}\\n' {old}\n\
             \x20 else\n\
             \x20\x20 printf '{MARK_FAILED} could not back up %s; leaving it in place\\n' {old} >&2\n\
             \x20 fi\n\
             fi"
        )
    }

    /// After rollback removed the new unit, put the older unit back from
    /// the migration's backup and start it (its enable symlink went with the
    /// `disable --now`). Runs before linger is disabled, while the user
    /// manager still answers; the backup is the only copy until the restore
    /// ran, and it survives a failed `cp` so the next rollback can retry.
    /// `! -e new` also keeps the reload that the engine re-runs after this
    /// from migrating it straight back.
    fn orca_restore_legacy(&self) -> String {
        let ctl = self.user_ctl();
        let new = shell_escape(ORCA_UNIT_PATH);
        let old = shell_escape(ORCA_LEGACY_PATH);
        let bak = shell_escape(&format!("{ORCA_LEGACY_PATH}{BACKUP_SUFFIX}"));
        format!(
            "\n# rollback (module-authored): restore the older Orca unit\n\
             if [ -f {bak} ] && [ ! -e {old} ] && [ ! -e {new} ]; then\n\
             \x20 if cp -a {bak} {old}; then\n\
             \x20\x20 {ctl} daemon-reload || true\n\
             \x20\x20 {ctl} enable --now {ORCA_LEGACY_UNIT} >/dev/null 2>&1 || true\n\
             \x20\x20 rm -f {bak}\n\
             \x20\x20 printf '{MARK_CHANGED} Orca unit %s restored and started\\n' {old}\n\
             \x20 fi\n\
             fi\n"
        )
    }

    /// Prints the unit; the pairing address is the host's tailnet IPv4
    /// (empty only in a probe before `[tailscale]` ran, never written).
    fn orca_unit(&self, o: &OrcaServer) -> String {
        let mut lines = vec![
            "# Managed by anvil — Remote Orca Server".to_string(),
            "[Unit]".into(),
            "Description=Orca server (anvil)".into(),
            format!("ConditionUser={}", self.cfg.user),
            String::new(),
            "[Service]".into(),
            "Environment=PATH=%h/.local/bin:%h/.opencode/bin:/usr/local/bin:/usr/bin:/bin".into(),
        ];
        if self.tmp_noexec {
            lines.push("Environment=TMPDIR=%h/.cache/tmp".into());
            lines.push("ExecStartPre=/bin/mkdir -p %h/.cache/tmp".into());
        }
        if let Some(sock) = self.docker_socket() {
            lines.push(format!("Environment=DOCKER_HOST=unix://%t/{sock}"));
        }
        let words: Vec<String> = lines.iter().map(|l| shell_escape(l)).collect();
        let tail = [
            "Restart=on-failure",
            "RestartSec=10",
            "",
            "[Install]",
            "WantedBy=default.target",
        ]
        .map(shell_escape);
        format!(
            "__oip=$(tailscale ip -4 2>/dev/null | head -n1 || true)\n\
             printf '%s\\n' {} {}\"$__oip\" {}",
            words.join(" "),
            shell_escape(&format!(
                "ExecStart=/usr/bin/orca-ide serve --supervise --mobile-pairing --port {} --pairing-address ",
                o.port
            )),
            tail.join(" ")
        )
    }

    /// Restart a root-owned user unit when it or `flag` changed, else start
    /// it when down.
    fn user_unit_reload(&self, path: &str, unit: &str, flag: &str) -> String {
        let ctl = self.user_ctl();
        format!(
            "if [ -f {path} ]; then\n\
             \x20 __unit_changed=\"${{{flag}:-0}}\"\n\
             \x20 for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do\n\
             \x20\x20 [ \"$__p\" != {path} ] || __unit_changed=1\n\
             \x20 done\n\
             \x20 systemctl start \"user@$(id -u {u}).service\"\n\
             \x20 {ctl} daemon-reload\n\
             \x20 {ctl} enable {unit} >/dev/null 2>&1\n\
             \x20 if [ \"$__unit_changed\" = 1 ]; then {ctl} restart {unit}\n\
             \x20 elif ! {ctl} is-active --quiet {unit}; then {ctl} start {unit}; fi\n\
             fi",
            u = self.user(),
        )
    }

    fn orca_rollback_first(&self) -> String {
        let ctl = self.user_ctl();
        format!(
            "if [ -f {ORCA_UNIT_PATH} ] && {{ {ctl} is-active --quiet {ORCA_UNIT} || {ctl} is-enabled --quiet {ORCA_UNIT}; }} 2>/dev/null; then\n\
             \x20 {ctl} disable --now {ORCA_UNIT} >/dev/null 2>&1 || true\n\
             \x20 printf '{MARK_CHANGED} %s: Orca server stopped\\n' {u}\n\
             fi\n",
            u = self.user(),
        )
    }

    /// The agent's engine stops before its unit goes; its images stay.
    fn docker_rollback_first(&self, engine: Engine) -> String {
        let ctl = self.user_ctl();
        let unit = match engine {
            Engine::Docker => DOCKER_UNIT,
            Engine::Podman => PODMAN_SOCKET,
        };
        format!(
            "if {{ {ctl} is-active --quiet {unit} || {ctl} is-enabled --quiet {unit}; }} 2>/dev/null; then\n\
             \x20 {ctl} disable --now {unit} >/dev/null 2>&1 || true\n\
             \x20 printf '{MARK_CHANGED} %s: rootless {name} stopped\\n' {u}\n\
             fi\n",
            name = if engine == Engine::Docker { "dockerd" } else { "podman socket" },
            u = self.user(),
        )
    }

    fn rollback(&self) -> String {
        let u = self.user();
        let token = shell_escape(&format!("linger:{}", self.cfg.user));
        let rm_home = self.as_agent(&format!(
            "rm -rf \"$__home/{MARKER}\" \"$__home/{SETUP_DIR}\""
        ));
        let test_home = self.as_agent(&format!(
            "test -e \"$__home/{MARKER}\" -o -e \"$__home/{SETUP_DIR}\""
        ));
        let orca = self.cfg.orca_server.as_ref().map_or(String::new(), |o| {
            format!(
                "if command -v ufw >/dev/null 2>&1 && ufw show added 2>/dev/null | grep -wF {n} >/dev/null; then\n\
                 \x20 ufw delete {r} >/dev/null\n\
                 \x20 printf '{MARK_CHANGED} ufw: Orca server port %s closed\\n' {p}\n\
                 fi\n\
                 printf '{MARK_OK} orca-ide stays installed (apt purge orca-ide frees ~1.25 GB)\\n'\n",
                n = Self::orca_needle(o),
                r = Self::orca_rule(o),
                p = shell_escape(&o.port.to_string()),
            )
        });
        let mut agents = String::new();
        let legacy = self.orca_restore_legacy();
        // Both, so switching an agent to "none" still lets rollback remove it.
        for i in [&CLAUDE, &OPENCODE] {
            let t = shell_escape(&format!("{}:{}", i.token, self.cfg.user));
            let paths: Vec<String> = i.owned.iter().map(|p| format!("\"$__home/{p}\"")).collect();
            let shown: Vec<String> = i.owned.iter().map(|p| format!("~/{p}")).collect();
            agents.push_str(&format!(
                "if [ -n \"$__home\" ] && __anvil_created {t}; then\n\
                 \x20 {rm}\n\
                 \x20 __anvil_forget {t}; printf '{MARK_CHANGED} %s: {name} removed ({shown})\\n' {u}\n\
                 fi\n",
                rm = self.as_agent(&format!("rm -rf {}", paths.join(" "))),
                name = i.name,
                shown = shown.join(", "),
            ));
        }
        let images = match self.rootless() {
            Some(Engine::Docker) => " ~/.local/share/docker",
            Some(Engine::Podman) => " ~/.local/share/containers",
            None => "",
        };
        format!(
            "\n# rollback coding_agents: what anvil installed; the home stays\n\
             __home=$(getent passwd {u} | cut -d: -f6 || true)\n\
             {agents}{legacy}\
             if __anvil_created {token}; then\n\
             \x20 loginctl disable-linger {u} || true; __anvil_forget {token}; printf '{MARK_CHANGED} %s: linger disabled\\n' {u}\n\
             fi\n\
             if [ -n \"$__home\" ] && {test_home}; then\n\
             \x20 {rm_home}\n\
             \x20 printf '{MARK_CHANGED} %s: marker and setup checkout removed\\n' {u}\n\
             fi\n\
             printf '{MARK_OK} %s keeps its data: {KEPT}{images} (remove by hand or with prune.py from the setup repo)\\n' {u}\n\
             if [ -e {NODE_KEY_PATH} ] || [ -e {NODE_LIST_PATH} ] || [ -e {NODE_PIN_PATH} ]; then\n\
             \x20 rm -f {NODE_KEY_PATH} {NODE_LIST_PATH} {NODE_PIN_PATH}\n\
             \x20 printf '{MARK_CHANGED} NodeSource apt key, source and pin removed\\n'\n\
             fi\n\
             printf '{MARK_OK} nodejs stays installed (other software may use it)\\n'\n{orca}"
        )
    }
}

impl Module for CodingAgentsModule {
    fn id(&self) -> &'static str {
        "coding_agents"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("coding_agents")
            .command(self.user_exists())
            .command(Self::deps())
            .command(Self::node());
        decl = decl.installs(&["Node.js 24 (NodeSource)"]);
        // Before the lists: `claude plugin` and `opencode plugin` need them.
        for (i, args) in self.installers() {
            decl.installs.push(format!("{} (self-updating)", i.name));
            decl = decl.command(self.agent_install(i, &args));
        }
        decl = decl.command(self.linger());
        decl = decl.command(self.lists());
        let mut reload = Vec::new();
        let mut rollback_first = Vec::new();
        if let Some(engine) = self.rootless() {
            decl = decl.command(super::ensure_engine(engine, self.docker_distro));
            for c in runner_common::rootless(engine, &self.cfg.user, "__ca_docker_restart=1") {
                decl = decl.command(c);
            }
            if engine == Engine::Docker {
                decl.installs.push("Docker (rootless, as the agent)".into());
                decl = decl.command(self.docker_active()).file(ManagedFile::new(
                    DOCKER_UNIT_PATH,
                    self.docker_unit(),
                    "0644",
                    "root:root",
                ));
                reload.push(self.user_unit_reload(
                    DOCKER_UNIT_PATH,
                    DOCKER_UNIT,
                    "__ca_docker_restart",
                ));
            } else {
                decl.installs.push("Podman (rootless, as the agent)".into());
                decl = decl.command(self.podman_socket());
            }
            rollback_first.push(self.docker_rollback_first(engine));
            decl = decl.rollback_script(runner_common::rootless_rollback(&self.cfg.user));
        }
        if let Some(o) = &self.cfg.orca_server {
            decl.installs
                .push("Orca server (orca-ide .deb with GTK/X deps, ~1.25 GB)".into());
            decl = decl
                // Cheap checks first: no 1.25 GB install on a host that would abort.
                .command(Self::orca_tailnet_ip())
                .command(Self::orca_firewall(o))
                .command(Self::orca_install(o))
                .command(Self::orca_not_world_writable())
                .command(Self::orca_legacy_absent())
                .command(self.orca_active())
                .file(ManagedFile::computed(
                    ORCA_UNIT_PATH,
                    self.orca_unit(o),
                    "0644",
                    "root:root",
                ));
            rollback_first.push(self.orca_rollback_first());
            // Once the new unit is on disk, migrate the older unit before
            // the reload starts the new one (one server, one port).
            reload.push(self.orca_migrate_legacy());
            reload.push(self.user_unit_reload(ORCA_UNIT_PATH, ORCA_UNIT, "__orca_new"));
        }
        if !rollback_first.is_empty() {
            decl = decl.rollback_first(rollback_first.concat());
        }
        if self.tmp_noexec || self.rootless().is_some() {
            decl = decl.file(ManagedFile::new(
                PROFILE_PATH,
                self.profile(),
                "0644",
                "root:root",
            ));
        }
        if let Some(f) = self.caps() {
            // daemon-reload applies changed limits to the live slice.
            decl = decl.file(f);
            reload.insert(0, "systemctl daemon-reload".into());
        }
        if !reload.is_empty() {
            decl = decl.guarded_reload(ReloadGuard {
                describe: "coding agent slice caps, rootless dockerd and Orca server".into(),
                validate: "true".into(),
                reload: reload.join(" &&\n"),
            });
        }
        decl.rollback_script(self.rollback())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(extra: &str) -> CodingAgentsModule {
        CodingAgentsModule::new(toml::from_str(extra).expect("section"))
    }

    const WIDE: &str = r#"
user = "agent"
skills = [
  { source = "vercel-labs/skills", names = ["find-skills"] },
  { source = "o/r", agents = ["opencode"] },
]
claude_marketplaces = ["anthropics/claude-plugins-official"]
claude_plugins = ["commit-commands@claude-plugins-official"]
opencode_plugins = ["@example-org/example-plugin"]
opencode_mcp = { example-mcp = ["npx", "-y", "example-mcp@latest"] }
setup = { url = "https://github.com/o/setup.git", rev = "0123456789abcdef0123456789abcdef01234567", run = "install.sh" }
cpu_quota = "400%"
memory_max = "12G"
tasks_max = 4096
"#;

    #[test]
    fn root_never_writes_into_the_home() {
        let m = module(WIDE).tmp_noexec(true);
        let d = m.declaration();
        let apply = d.render_apply();
        let rb = d.render_rollback();
        // Every $__home use is inside a runuser-run command; root only reads passwd.
        for script in [&apply, &rb] {
            for line in script.lines().filter(|l| l.contains("$__home")) {
                assert!(
                    line.contains("runuser -u 'agent' --")
                        || line.contains("__home=$(getent")
                        || line.trim_start().starts_with("[ -n \"$__home\" ]")
                        || line.starts_with("if [ -n \"$__home\" ] && __anvil_created"),
                    "{line}"
                );
            }
        }
        assert!(!apply.contains("/home/agent"));
        assert!(m
            .agent_script()
            .contains("printf '%s\\n' \"$1\" > \"$HOME/.agents/.anvil-coding-agents\""));
    }

    #[test]
    fn marker_is_written_only_after_a_clean_run() {
        let s = module(WIDE).agent_script();
        let marker = s.find("> \"$HOME/.agents/.anvil-coding-agents\"").unwrap();
        let fail_exit = s.find("exit 1; fi").unwrap();
        let waits_exit = s.find("|| exit 3").unwrap();
        assert!(fail_exit < marker && waits_exit < marker);
        // Every installer and the setup run come before the checks.
        for item in [
            "skills@latest add",
            "plugin install",
            "opencode.json",
            "setup ||",
        ] {
            assert!(s.find(item).unwrap() < fail_exit, "{item}");
        }
        // Each item records its failure instead of stopping the rest.
        assert!(s.contains("\"$@\" </dev/null || failed+=(\"$*\")"));
        assert!(!s.contains("set -e"));
    }

    #[test]
    fn agent_script_runs_and_writes_the_marker_only_when_clean() {
        // Runs the generated script with stub installers on PATH.
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("anvil-ca-{}", std::process::id()));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let script = module(
            "skills = [{ source = \"o/r\" }]\nclaude_plugins = [\"p@m\"]\nclaude_marketplaces = [\"m/m\"]\n\
             opencode_mcp = { cm = [\"npx\", \"it's\"] }",
        )
        .agent_script();
        let run = |fail: &str| {
            for tool in ["npx", "claude", "opencode"] {
                let body = if tool == fail { "exit 1" } else { "exit 0" };
                let p = bin.join(tool);
                std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            let home = dir.join(format!("home-{fail}"));
            std::fs::create_dir_all(&home).unwrap();
            let st = Command::new("bash")
                .args(["-c", &script, "bash", "HASH"])
                .env("HOME", &home)
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .output()
                .unwrap();
            (
                st.status.code(),
                std::fs::read_to_string(home.join(MARKER)).ok(),
            )
        };
        assert_eq!(run("none"), (Some(0), Some("HASH\n".into())));
        // The escaped python edit runs as written.
        let oc =
            std::fs::read_to_string(dir.join("home-none/.config/opencode/opencode.json")).unwrap();
        assert!(
            oc.contains("\"command\": [\n        \"npx\",\n        \"it's\"\n      ]"),
            "{oc}"
        );
        assert_eq!(run("claude"), (Some(1), None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_values_are_shell_escaped() {
        let m = module(
            r#"
skills = [{ source = "https://x/$(id)", names = ["a'b"] }]
claude_marketplaces = ["m;rm"]
claude_plugins = ["p`x`@m"]
opencode_plugins = ["$HOME"]
opencode_mcp = { "n" = ["c", "$(x)"] }
setup = { url = "https://x/'y", rev = "0123456789abcdef0123456789abcdef01234567", run = "a b.sh" }
"#,
        );
        let s = m.agent_script();
        for want in [
            "add 'https://x/$(id)' -g -y -a 'claude-code' -a 'opencode' -s 'a'\\''b'",
            "marketplace add 'm;rm'",
            "install 'p`x`@m' -s user",
            "plugin add '$HOME'",
            "opencode.json\" 'n' '[\"c\",\"$(x)\"]'",
            "git ls-remote 'https://x/'\\''y'",
            "AGENTS='claude-code opencode' './a b.sh'",
        ] {
            assert!(s.contains(want), "{want}\n{s}");
        }
        // The script itself reaches bash -c as one escaped word.
        assert!(m
            .lists()
            .converge
            .contains(&format!("bash -c {}", shell_escape(&s))));
    }

    #[test]
    fn private_setup_waits_instead_of_failing() {
        let c = module(WIDE).lists().converge;
        assert!(c.contains("3) printf 'DRIFTED: coding_agents: setup waits for GitHub access"));
        assert!(c.contains("*) printf 'FAILED: coding_agents: as %s, failed: %s"));
        assert!(c.contains("sed -n 's/^failed: //p'"));
        assert!(module(WIDE)
            .agent_script()
            .contains("*'could not read Username'*"));
    }

    #[test]
    fn none_installs_nothing_of_that_agent() {
        let apply = module("claude_code = \"none\"\nopencode = \"none\"")
            .declaration()
            .render_apply();
        assert!(!apply.contains("install.sh") && !apply.contains("opencode.ai"));
        let s = module("claude_code = \"none\"\nskills = [{ source = \"o/r\" }]").agent_script();
        assert!(s.contains("-a 'opencode'") && !s.contains("claude-code"));
        assert!(!s.contains("marketplace update"));
        assert!(module(WIDE)
            .agent_script()
            .contains("run claude plugin marketplace update\n"));
    }

    #[test]
    fn caps_drop_in_path_is_computed_on_the_host() {
        let d = module(WIDE).declaration();
        let f = d.files.iter().find(|f| f.path.contains("slice.d")).unwrap();
        assert_eq!(
            f.static_content(),
            Some("# Managed by anvil — caps for everything agent runs\n[Slice]\nCPUQuota=400%\nMemoryMax=12G\nTasksMax=4096\n")
        );
        assert!(f
            .path_resolver
            .as_deref()
            .unwrap()
            .contains("$(id -u 'agent' 2>/dev/null)"));
        assert!(d.reload.is_some());
        assert!(module("").declaration().reload.is_none());
    }

    #[test]
    fn tmpdir_profile_only_with_tmp_noexec() {
        let has =
            |m: CodingAgentsModule| m.declaration().files.iter().any(|f| f.path == PROFILE_PATH);
        assert!(!has(module("")));
        assert!(has(module("").tmp_noexec(true)));
        assert!(module("")
            .profile()
            .contains("if [ \"$(id -un)\" = 'agent' ]"));
    }

    #[test]
    fn rollback_removes_installs_and_keeps_the_home() {
        let rb = module(WIDE).declaration().render_rollback();
        for want in [
            "__anvil_created 'claude:agent'",
            "rm -rf \"$__home/.local/bin/claude\" \"$__home/.local/share/claude\"",
            "__anvil_created 'opencode:agent'",
            "rm -rf \"$__home/.opencode/bin\" \"$__home/.local/bin/opencode\"",
            "loginctl disable-linger 'agent'",
            "rm -rf \"$__home/.agents/.anvil-coding-agents\" \"$__home/.local/share/anvil/setup\"",
            "OK: %s keeps its data: ~/.agents ~/.claude",
            "systemctl daemon-reload",
        ] {
            assert!(rb.contains(want), "{want}");
        }
        assert!(!rb.contains("rm -rf \"$__home\"") && !rb.contains("userdel"));
    }

    #[test]
    fn agents_come_from_their_installers_as_the_agent() {
        let d = module("claude_code = \"latest\"\nopencode = \"2.2.5\"").declaration();
        let pos = |p: &str| {
            d.commands
                .iter()
                .position(|c| c.describe.starts_with(p))
                .unwrap()
        };
        for (name, pipe, args, bin, token) in [
            (
                "Claude Code",
                "curl -fsSL https://claude.ai/install.sh | bash -s",
                " bash 'latest' 2>&1",
                ".local/bin/claude",
                "'claude:agent'",
            ),
            (
                "OpenCode",
                "curl -fsSL https://opencode.ai/v2/install | bash -s --",
                " bash '--version' '2.2.5' 2>&1",
                ".local/bin/opencode",
                "'opencode:agent'",
            ),
        ] {
            let c = &d.commands[pos(name)];
            assert!(c.detect.contains("runuser -u 'agent' --"), "{name}");
            assert!(c.detect.contains(&format!("\"$__home/{bin}\" --version")));
            let install = c.converge.find(pipe).expect(name);
            assert!(c.converge.contains(args), "{name}\n{}", c.converge);
            let fail = c
                .converge
                .find(&format!("FAILED: coding_agents: {name} installer failed"))
                .unwrap();
            let record = c
                .converge
                .find(&format!("__anvil_remember {token}"))
                .unwrap();
            assert!(install < fail && fail < record, "{name}");
            // Before the lists: `claude plugin` and `opencode plugin` need them.
            assert!(pos(name) < pos("skills, plugins"), "{name}");
        }
        // "latest" passes no --version.
        assert!(!module("")
            .declaration()
            .render_apply()
            .contains("'--version'"));
        // The lists find both binaries.
        assert!(module("")
            .lists()
            .converge
            .contains("PATH=\"$__home/.local/bin:$__home/.opencode/bin:/usr/local/bin"));
    }

    #[test]
    fn node_24_comes_from_nodesource_before_the_agents() {
        let d = module("").declaration();
        let pos = |p: &str| {
            d.commands
                .iter()
                .position(|c| c.describe.starts_with(p))
                .unwrap()
        };
        assert!(
            pos("git, build tools") < pos("Node.js 24") && pos("Node.js 24") < pos("Claude Code")
        );
        let deps = &d.commands[pos("git, build tools")];
        assert!(!deps.detect.contains("nodejs") && !deps.converge.contains("npm"));
        let n = &d.commands[pos("Node.js 24")];
        let at_least = "dpkg --compare-versions \"$(/usr/bin/node --version 2>/dev/null | sed 's/^v//')\" ge 24.15.0";
        assert!(n.detect.starts_with(at_least));
        let install = n
            .converge
            .find("install -y -- 'nodejs' 'npm-'")
            .expect("nodejs, distro npm removed");
        for (path, content) in [
            (NODE_KEY_PATH, NODE_KEY),
            (NODE_LIST_PATH, NODE_SOURCE),
            (NODE_PIN_PATH, NODE_PIN),
        ] {
            let b = shell_escape(&B64.encode(content));
            assert!(n
                .detect
                .contains(&format!("cmp -s {path} <(printf '%s' {b} | base64 -d)")));
            let w = n
                .converge
                .find(&format!("printf '%s' {b} | base64 -d > {path}\n"))
                .expect(path);
            assert!(w < install, "{path}");
        }
        assert!(n.converge.contains(
            "chmod 0644 /etc/apt/keyrings/nodesource.asc /etc/apt/sources.list.d/nodesource.list \
             /etc/apt/preferences.d/99-anvil-nodesource"
        ));
        // Installed but still too old fails instead of drifting forever.
        let check = n
            .converge
            .find(&format!("{at_least} || {{ printf 'FAILED:"))
            .unwrap();
        assert!(install < check && n.converge.ends_with("exit 1; }"));
    }

    #[test]
    fn nodesource_source_and_pin_are_the_verified_lines() {
        assert_eq!(
            NODE_SOURCE,
            "deb [signed-by=/etc/apt/keyrings/nodesource.asc] https://deb.nodesource.com/node_24.x nodistro main\n"
        );
        assert_eq!(
            NODE_PIN,
            "Package: nodejs\nPin: origin deb.nodesource.com\nPin-Priority: 600\n"
        );
    }

    #[test]
    fn nodesource_key_has_the_pinned_fingerprint() {
        // Skips when gpg is missing; CI images and dev machines usually have it.
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        assert!(NODE_KEY.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        let Ok(mut child) = Command::new("gpg")
            .args(["--show-keys", "--with-colons"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            return;
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(NODE_KEY.as_bytes()).expect("write key");
        }
        let out = child.wait_with_output().expect("gpg");
        let text = String::from_utf8_lossy(&out.stdout);
        let first_fpr = text
            .lines()
            .find_map(|l| l.strip_prefix("fpr:::::::::"))
            .and_then(|r| r.split(':').next());
        assert_eq!(first_fpr, Some("6F71F525282841EEDAF851B42F59B5F99B1BE0B4"));
    }

    #[test]
    fn rollback_removes_nodesource_and_keeps_nodejs() {
        let rb = module("").declaration().render_rollback();
        let rm = "rm -f /etc/apt/keyrings/nodesource.asc /etc/apt/sources.list.d/nodesource.list \
                  /etc/apt/preferences.d/99-anvil-nodesource";
        assert!(rb.contains(&format!(
            "if [ -e /etc/apt/keyrings/nodesource.asc ] || [ -e /etc/apt/sources.list.d/nodesource.list ] \
             || [ -e /etc/apt/preferences.d/99-anvil-nodesource ]; then\n  {rm}\n  \
             printf 'CHANGED: NodeSource apt key, source and pin removed\\n'\nfi\n"
        )));
        assert!(rb.contains("printf 'OK: nodejs stays installed (other software may use it)\\n'"));
        assert!(!rb.contains("apt-get"));
    }

    #[test]
    fn opencode_mcp_is_written_as_mcp_name_keeping_other_keys() {
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("anvil-ocmcp-{}", std::process::id()));
        let p = dir.join("opencode/opencode.json");
        let run = |name: &str, cmd: &str| {
            Command::new("python3")
                .args(["-c", OPENCODE_MCP_PY, p.to_str().unwrap(), name, cmd])
                .status()
                .unwrap()
                .success()
        };
        // No file yet: created with its directory.
        assert!(run("a", r#"["x"]"#));
        std::fs::write(
            &p,
            r#"{"theme":"t","mcp":{"servers":{"cm":{"command":"old"},"other":{}},"cm":{"timeout":5}}}"#,
        )
        .unwrap();
        assert!(run("cm", r#"["npx","-y","context-mode@next"]"#));
        let c: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(
            c,
            serde_json::json!({"theme": "t", "mcp": {
                "servers": {"other": {}},
                "cm": {"timeout": 5, "type": "local", "command": ["npx", "-y", "context-mode@next"], "enabled": true},
            }})
        );
        // Our last stale entry gone: `servers` goes too.
        std::fs::write(&p, r#"{"mcp":{"servers":{"cm":{}}}}"#).unwrap();
        assert!(run("cm", r#"["c"]"#));
        let c: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(
            c,
            serde_json::json!({"mcp": {"cm": {"type": "local", "command": ["c"], "enabled": true}}})
        );
        // JSONC with comments: fails and leaves the file alone.
        std::fs::write(&p, "// c\n{}").unwrap();
        assert!(!run("cm", r#"["c"]"#));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "// c\n{}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    const ORCA: &str = "[orca_server]\nport = 7000\n";

    #[test]
    fn orca_server_is_tailnet_only_and_verified_before_install() {
        let d = module(ORCA).declaration();
        let apply = d.render_apply();
        let pos = |p: &str| apply.find(p).unwrap_or_else(|| panic!("{p}"));
        // Checksum before apt sees the file; ufw before the unit and the start.
        assert!(pos("sha256sum -c") < pos("install -y -qq \"$__tmp/orca-ide.deb\""));
        // No local user may swap Orca's code: world-writable bits go after install.
        assert!(pos("install -y -qq \"$__tmp/orca-ide.deb\"") < pos("chmod -R o-w /opt/Orca"));
        assert!(d.render_probe().contains("find /opt/Orca -perm -0002"));
        assert!(pos("ufw allow in on tailscale0") < pos("sha256sum -c"));
        assert!(apply.contains("releases/download/v${__ov}/orca-ide_${__ov}_${__ra}.deb"));
        assert!(apply.contains(&format!("__ov='{ORCA_VERSION}'")));
        assert!(apply.contains(ORCA_SHA256.0) && apply.contains(ORCA_SHA256.1));
        let rule = pos("ufw allow in on tailscale0 to any port '7000' proto tcp");
        assert!(pos("refusing to start the Orca server") < rule);
        assert!(pos("ufw status verbose 2>/dev/null | grep -F 'allow (incoming)'") < rule);
        assert!(pos("ufw default incoming is allow") < rule);
        assert!(rule < pos(&format!("__path='{ORCA_UNIT_PATH}'")));
        assert!(rule < pos("systemctl --user -M 'agent@' restart orca-server.service"));
        assert!(pos("no tailnet IPv4") < pos(&format!("__path='{ORCA_UNIT_PATH}'")));
        assert!(!apply.contains("ufw allow 7000") && !apply.contains("ufw allow '7000'"));
        // anvil never starts a pairing itself: the link stays out of its output.
        for script in [&apply, &d.render_probe(), &d.render_rollback()] {
            assert!(!script.contains("orca-ide pair"));
            for l in script.lines().filter(|l| l.contains("orca-ide serve")) {
                assert!(l.contains("ExecStart=/usr/bin/orca-ide serve"), "{l}");
            }
        }
        assert!(d.installs.iter().any(|i| i.starts_with("Orca server")));
        assert!(!module("").declaration().render_apply().contains("orca"));
    }

    #[test]
    fn orca_unit_pairs_on_the_tailnet_ip_computed_on_the_host() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;
        let dir = std::env::temp_dir().join(format!("anvil-orca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ts = dir.join("tailscale");
        std::fs::write(&ts, "#!/bin/sh\nprintf '100.64.0.7\\nfd7a::7\\n'\n").unwrap();
        std::fs::set_permissions(&ts, std::fs::Permissions::from_mode(0o755)).unwrap();
        let m = module(ORCA).tmp_noexec(true);
        let o = m.cfg.orca_server.clone().unwrap();
        let out = |path: &str| {
            let o = Command::new("/bin/bash")
                .args(["-euo", "pipefail", "-c", &m.orca_unit(&o)])
                .env("PATH", path)
                .output()
                .unwrap();
            assert!(o.status.success());
            String::from_utf8(o.stdout).unwrap()
        };
        let unit = out(&format!("{}:/usr/bin:/bin", dir.display()));
        assert!(unit.contains("ConditionUser=agent\n"), "{unit}");
        assert!(unit.contains(
            "ExecStart=/usr/bin/orca-ide serve --supervise --mobile-pairing --port 7000 --pairing-address 100.64.0.7\n"
        ));
        assert!(unit.contains("Environment=TMPDIR=%h/.cache/tmp\n"));
        assert!(!module(ORCA).orca_unit(&o).contains("TMPDIR"));
        assert!(unit.ends_with("[Install]\nWantedBy=default.target\n"));
        // No tailscale yet (a probe before [tailscale] ran): no abort. The PATH
        // holds only `head`, so a tailscale on the test host can't leak in.
        let bare = dir.join("bare");
        std::fs::create_dir_all(&bare).unwrap();
        std::os::unix::fs::symlink("/usr/bin/head", bare.join("head")).unwrap();
        assert!(out(&bare.display().to_string()).contains("--pairing-address \n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orca_rollback_stops_closes_and_keeps_the_package() {
        let d = module(ORCA).declaration();
        let rb = d.render_rollback();
        let stop = rb
            .find("systemctl --user -M 'agent@' disable --now orca-server.service")
            .unwrap();
        assert!(
            stop < rb.find("rm -f \"$__path\"").unwrap(),
            "stopped before the unit goes"
        );
        assert!(rb.contains("ufw delete allow in on tailscale0 to any port '7000' proto tcp"));
        assert!(rb.contains("grep -wF 'allow in on tailscale0 to any port 7000 proto tcp'"));
        assert!(rb.contains("OK: orca-ide stays installed"));
        assert!(!rb.contains("apt-get"));
        assert!(module("").declaration().rollback_first.is_none());
    }

    #[test]
    fn orca_reload_restarts_on_change_and_shares_the_caps_guard() {
        let d = module(&format!("memory_max = \"12G\"\n{ORCA}")).declaration();
        let r = d.reload.unwrap().reload;
        // The migration runs first, and only once the new unit is written.
        assert!(r.starts_with(
            "systemctl daemon-reload &&\nif [ -f '/etc/systemd/user/orca-server.service' ] \
             && [ -e '/etc/systemd/user/anvil-orca-server.service' ]; then"
        ));
        for want in [
            "systemctl start \"user@$(id -u 'agent').service\"",
            "__unit_changed=\"${__orca_new:-0}\"",
            "systemctl --user -M 'agent@' enable orca-server.service",
            "elif ! systemctl --user -M 'agent@' is-active --quiet orca-server.service",
        ] {
            assert!(r.contains(want), "{want}");
        }
        assert!(module(ORCA)
            .declaration()
            .commands
            .iter()
            .any(|c| c.converge.ends_with("__orca_new=1")));
    }

    #[test]
    fn orca_unit_is_orca_server_and_the_old_name_only_migrates() {
        let m = module(ORCA);
        let d = m.declaration();
        let apply = d.render_apply();
        assert_eq!(ORCA_UNIT_PATH, "/etc/systemd/user/orca-server.service");
        assert_eq!(ORCA_UNIT, "orca-server.service");
        assert!(apply.contains(&format!("__path='{ORCA_UNIT_PATH}'")));
        assert!(d.files.iter().any(|f| f.path == ORCA_UNIT_PATH));
        assert!(apply.contains("systemctl --user -M 'agent@' enable orca-server.service"));
        // The shipped name survives only in the migration and the drift probe.
        let rest = apply
            .replace(&m.orca_migrate_legacy(), "")
            .replace(&format!("[ ! -e '{ORCA_LEGACY_PATH}' ]"), "");
        let leftover: Vec<&str> = rest
            .lines()
            .filter(|l| l.contains("anvil-orca-server"))
            .collect();
        assert!(leftover.is_empty(), "{leftover:?}");
    }

    #[test]
    fn orca_migration_gates_on_the_new_unit_and_backs_up_first() {
        let apply = module(ORCA).declaration().render_apply();
        let gate = apply
            .find(
                "if [ -f '/etc/systemd/user/orca-server.service' ] \
                 && [ -e '/etc/systemd/user/anvil-orca-server.service' ]; then",
            )
            .expect("migration gated on the new unit");
        let backup = apply
            .find(
                "if [ -e '/etc/systemd/user/anvil-orca-server.service.anvil.bak' ] \
                 || cp -a '/etc/systemd/user/anvil-orca-server.service' '/etc/systemd/user/anvil-orca-server.service.anvil.bak'; then",
            )
            .expect("backup gate");
        let stop = apply
            .find("disable --now anvil-orca-server.service")
            .unwrap();
        let rm = apply
            .find("rm -f '/etc/systemd/user/anvil-orca-server.service'")
            .unwrap();
        let start = apply.find("enable orca-server.service").unwrap();
        assert!(
            gate < backup && backup < stop && stop < rm && rm < start,
            "{apply}"
        );
    }

    #[test]
    fn orca_migration_backs_up_then_stops_and_removes() {
        let run = |script: String| {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .output()
                .unwrap();
            (
                String::from_utf8_lossy(&out.stdout).into_owned(),
                String::from_utf8_lossy(&out.stderr).into_owned(),
            )
        };
        let dir = std::env::temp_dir().join(format!("anvil-orca-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (new, old) = (
            dir.join("orca-server.service"),
            dir.join("anvil-orca-server.service"),
        );
        let script = module(ORCA)
            .orca_migrate_legacy()
            .replace(
                &shell_escape(&format!("{ORCA_LEGACY_PATH}{BACKUP_SUFFIX}")),
                "/nonexistent-dir/bak",
            )
            .replace(&shell_escape(ORCA_LEGACY_PATH), &old.display().to_string())
            .replace(&shell_escape(ORCA_UNIT_PATH), &new.display().to_string());
        // The gate: nothing happens while the new unit is missing.
        std::fs::write(&old, "x").unwrap();
        assert_eq!(run(format!("{script}\necho done")).0, "done\n");
        assert!(old.exists());
        // Backup impossible: nothing is stopped or removed.
        std::fs::write(&new, "x").unwrap();
        let log = dir.join("calls.log");
        let stubs = format!(
            "systemctl() {{ echo \"$*\" >> {}; }}\n",
            shell_escape(&log.display().to_string())
        );
        let calls = || std::fs::read_to_string(&log).unwrap_or_default();
        let (_, err) = run(format!("{stubs}{script}"));
        assert!(old.exists(), "old unit kept when the backup fails");
        assert_eq!(calls(), "", "nothing stopped or removed");
        assert!(err.contains("FAILED: could not back up"), "{err}");
        // With a writable backup path: back up, stop, then remove.
        let bak = dir.join("anvil-orca-server.service.anvil.bak");
        let script = script.replace("/nonexistent-dir/bak", &bak.display().to_string());
        let (out, _) = run(format!("{stubs}{script}"));
        assert!(bak.exists() && !old.exists(), "{out}");
        assert!(out.contains("CHANGED:"), "{out}");
        assert!(
            calls().contains("disable --now anvil-orca-server.service"),
            "{}",
            calls()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_reports_the_old_orca_unit_and_never_migrates() {
        let probe = module(ORCA).declaration().render_probe();
        assert!(probe.contains("[ ! -e '/etc/systemd/user/anvil-orca-server.service' ]"));
        assert!(
            probe.contains("systemctl --user -M 'agent@' is-active --quiet orca-server.service")
        );
        assert!(!probe.contains("disable --now") && !probe.contains("rm -f"));
    }

    #[test]
    fn orca_rollback_restores_the_old_unit_and_starts_it() {
        let rb = module(ORCA).declaration().render_rollback();
        let restore = rb
            .find(
                "cp -a '/etc/systemd/user/anvil-orca-server.service.anvil.bak' \
                 '/etc/systemd/user/anvil-orca-server.service'",
            )
            .expect("old unit restored from the migration's backup");
        let start = rb
            .find("systemctl --user -M 'agent@' enable --now anvil-orca-server.service")
            .expect("old unit started");
        let linger = rb.find("loginctl disable-linger 'agent'").unwrap();
        let rm_bak = rb
            .find("rm -f '/etc/systemd/user/anvil-orca-server.service.anvil.bak'")
            .expect("backup removed only after the restore");
        // The user manager must still exist while the old unit is restored,
        // and the backup is the only copy until the restore ran.
        assert!(
            restore < linger,
            "old unit restored while the user manager still runs"
        );
        assert!(
            restore < start && start < rm_bak,
            "backup removed only after the old unit started"
        );
        assert!(rb.contains("systemctl --user -M 'agent@' daemon-reload || true"));
        assert!(rb.contains("CHANGED: Orca unit %s restored and started"));
        bash_n(&rb);
    }

    fn bash_n(script: &str) {
        let out = std::process::Command::new("bash")
            .args(["-n", "-c", script])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn rootless_docker_runs_as_the_agent_never_through_the_root_socket() {
        let m = module(&format!("docker = \"rootless\"\n{ORCA}"));
        let d = m.declaration();
        let apply = d.render_apply();
        let pos = |p: &str| apply.find(p).unwrap_or_else(|| panic!("{p}"));
        // Engine, then the agent's ids, then its dockerd (re)started by the guard.
        assert!(pos("'docker-ce' 'docker-ce-cli'") < pos("'docker-ce-rootless-extras'"));
        assert!(pos("usermod --add-subuids") < pos("restart anvil-docker-rootless.service"));
        assert!(apply
            .contains("'agent'\n__anvil_remember 'subids:agent:'\"$__s\"\n__ca_docker_restart=1"));
        assert!(!apply.contains("usermod -aG docker") && !apply.contains("docker.sock\" agent"));
        let unit = d.files.iter().find(|f| f.path == DOCKER_UNIT_PATH).unwrap();
        let unit = unit.static_content().unwrap();
        assert!(
            unit.contains("ConditionUser=agent\n")
                && unit.contains("ExecStart=/usr/bin/dockerd-rootless.sh --log-driver=journald\n")
        );
        assert!(unit.contains("Delegate=yes\n") && unit.ends_with("WantedBy=default.target\n"));
        // Login shells and Orca's terminals reach the agent's own socket.
        let profile = d.files.iter().find(|f| f.path == PROFILE_PATH).unwrap();
        assert!(profile
            .static_content()
            .unwrap()
            .contains("export DOCKER_HOST=\"unix:///run/user/$(id -u)/docker.sock\"\n"));
        let o = m.cfg.orca_server.clone().unwrap();
        assert!(m
            .orca_unit(&o)
            .contains("Environment=DOCKER_HOST=unix://%t/docker.sock"));
        assert!(d
            .installs
            .contains(&"Docker (rootless, as the agent)".to_string()));
        // Rollback: dockerd stops before its unit goes; the ids go; images stay.
        let rb = d.render_rollback();
        let stop = rb
            .find("systemctl --user -M 'agent@' disable --now anvil-docker-rootless.service")
            .unwrap();
        assert!(stop < rb.find("rm -f \"$__path\"").unwrap());
        assert!(rb.contains("usermod --del-subuids \"$__r\" --del-subgids \"$__r\" 'agent'"));
        assert!(rb.contains("~/.local/share/docker (remove by hand"));
        for s in [&apply, &d.render_probe(), &rb] {
            bash_n(s);
        }
        // Off by default: nothing of it.
        let none = module("").declaration();
        assert!(
            !none.render_apply().contains("rootless")
                && none.files.iter().all(|f| f.path != PROFILE_PATH)
        );
    }

    #[test]
    fn rootless_podman_serves_the_docker_api_on_the_agents_socket() {
        let d = module("docker = \"rootless\"")
            .engine(Engine::Podman)
            .declaration();
        let apply = d.render_apply();
        assert!(
            apply.contains("'podman' 'iptables' 'aardvark-dns'")
                && apply.contains("'podman-docker'")
        );
        assert!(apply.contains("systemctl --user -M 'agent@' enable --now podman.socket"));
        assert!(!apply.contains("docker-ce") && d.files.iter().all(|f| f.path != DOCKER_UNIT_PATH));
        let profile = d.files.iter().find(|f| f.path == PROFILE_PATH).unwrap();
        assert!(profile
            .static_content()
            .unwrap()
            .contains("/run/user/$(id -u)/podman/podman.sock"));
        let rb = d.render_rollback();
        assert!(
            rb.contains("disable --now podman.socket") && rb.contains("~/.local/share/containers")
        );
        for s in [&apply, &d.render_probe(), &rb] {
            bash_n(s);
        }
    }

    #[test]
    fn orca_pins_need_both_hashes_off_the_default_version() {
        let o = |t: &str| -> OrcaServer { toml::from_str(t).unwrap() };
        assert!(validate_pins(&o("")).is_ok());
        let h = "a".repeat(64);
        assert!(validate_pins(&o("version = \"1.4.300\"")).is_err());
        assert!(validate_pins(&o(&format!(
            "version = \"1.4.300\"\nsha256_amd64 = \"{h}\""
        )))
        .is_err());
        let both = format!("version = \"1.4.300\"\nsha256_amd64 = \"{h}\"\nsha256_arm64 = \"{h}\"");
        assert!(validate_pins(&o(&both)).is_ok());
        assert!(validate_pins(&o("sha256_arm64 = \"abc\"")).is_err());
        // An override replaces the built-in hash.
        let apply = module(&format!("[orca_server]\n{both}"))
            .declaration()
            .render_apply();
        assert!(apply.contains(&format!("__sha='{h}'")) && !apply.contains(ORCA_SHA256.0));
    }

    #[test]
    fn marker_hash_covers_lists_and_setup_not_versions() {
        let h = |t: &str| module(t).marker_hash();
        assert_ne!(h(""), h("skills = [{ source = \"o/r\" }]"));
        // Both agents update themselves: no version reaches the marker.
        assert_eq!(h(""), h("opencode = \"2.3.0\"\nclaude_code = \"latest\""));
    }
}
