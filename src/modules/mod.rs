//! Module trait and the registry that maps enabled config sections to
//! implemented modules (R14), reporting which enabled sections are not yet
//! implemented in this scaffold.

pub mod apps_resources;
pub mod auditd;
pub mod beszel;
pub mod caddy;
pub mod ci_resources;
pub mod coding_agents;
pub mod containers;
pub mod crowdsec;
pub mod dns;
pub mod docker;
pub mod fail2ban;
pub mod filesystem;
pub mod firewall;
pub mod forgejo;
pub mod forgejo_runner;
pub mod forgejo_runner_ephemeral;
pub mod github_runner;
pub mod github_runner_ephemeral;
pub mod greptimedb;
pub mod headscale;
pub mod hetzner;
pub mod kernel;
pub mod kernel_modules;
pub mod lynis;
pub mod netcup;
pub mod packages;
pub mod pam;
pub mod podman;
pub mod process;
pub mod restic;
pub mod rootless_sandbox;
pub mod runner_common;
pub mod ssh_crypto;
pub mod sshd;
pub mod suid;
pub mod tailscale;
pub mod tls;
pub mod updates;
pub mod users;
pub mod vector;

use crate::config::{Config, EnabledSection, Engine};
use crate::engine::{Declaration, ManagedCommand};
use crate::error::Result;
use crate::order::resolve_order;
use crate::plugin::EnabledPlugin;

/// Fixed Contract: dpkg lock-wait so apt waits out a transient lock instead of
/// failing outright (R109).
pub(crate) const APT_LOCK_TIMEOUT: &str = "-o DPkg::Lock::Timeout=600";

/// The one apt install fragment: refresh the lists (a fresh minimal image
/// has stale/absent ones), then install `pkgs` non-interactively with the dpkg
/// lock-wait. `&&`-joined so a failed refresh aborts even inside a `|| { … }`
/// group where `set -e` is off. Every name is shell-escaped here.
pub(crate) fn apt_install(pkgs: &[&str]) -> String {
    format!(
        "DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} update -qq && \
         DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} install -y -- {}",
        crate::escape::shell_escape_join(pkgs)
    )
}

/// `pam` and `process` both edit `/etc/login.defs` in place. A shared
/// whole-file `.anvil.bak` let one module's rollback undo the other's lines,
/// so each module records only *its own* directives (the original lines, or
/// nothing if absent) once, before its first edit, and its rollback swaps
/// exactly those back. Returns (capture snippet for the converge, rollback
/// script). Keys are compile-time literals; matching is case-insensitive like
/// login.defs itself.
pub(crate) fn login_defs_keys(module: &str, keys: &[&str]) -> (String, String) {
    let defs = crate::escape::shell_escape("/etc/login.defs");
    let state = crate::escape::shell_escape(&format!("/var/lib/anvil/login.defs-{module}.orig"));
    let re = crate::escape::shell_escape(&format!("^[[:space:]]*({})[[:space:]]", keys.join("|")));
    // A host hardened before these records existed still has the pristine
    // file in the old shared `.anvil.bak`: record from that, not the live,
    // already-hardened file.
    let capture = format!(
        "[ -e {state} ] || {{ __ld_src={defs}; [ -f {defs}.anvil.bak ] && __ld_src={defs}.anvil.bak; \
         mkdir -p /var/lib/anvil && {{ grep -iE {re} \"$__ld_src\" || true; }} > {state}; }}\n"
    );
    // Restore from our record, or (host hardened before records existed) from
    // the old shared backup — but only our own lines, and the backup stays for
    // the other module.
    let rollback = format!(
        "\n# rollback (module-authored): {module}'s /etc/login.defs directives\n\
         if [ -e {state} ] || [ -f {defs}.anvil.bak ]; then\n\
         \x20 if [ -e {state} ]; then __ld_orig=$(cat {state}); \
         else __ld_orig=$(grep -iE {re} {defs}.anvil.bak || true); fi\n\
         \x20 __ld_tmp=\"$(mktemp)\"\n\
         \x20 {{ grep -viE {re} {defs} || true; }} > \"$__ld_tmp\"\n\
         \x20 [ -z \"$__ld_orig\" ] || printf '%s\\n' \"$__ld_orig\" >> \"$__ld_tmp\"\n\
         \x20 cat \"$__ld_tmp\" > {defs}\n\
         \x20 rm -f \"$__ld_tmp\" {state}\n\
         \x20 printf 'CHANGED: {module} restored its /etc/login.defs directives\\n'\n\
         else\n\
         \x20 printf 'OK: {module} has no /etc/login.defs record\\n'\n\
         fi\n"
    );
    (capture, rollback)
}

/// `sysctl --system` never resets a key whose file was removed, so a
/// rolled-back sysctl drop-in left the hardened values live until reboot.
/// The command snapshots the runtime values of `keys` once, before the
/// module's first write (skipped when `dropin` already exists: a host
/// hardened before this snapshot existed has no pre-anvil values to save).
/// The rollback script re-applies the snapshot and removes it. Keys are
/// compile-time literals or validated `extra_sysctl` keys; all escaped.
pub(crate) fn sysctl_snapshot(
    module: &str,
    dropin: &str,
    keys: &[&str],
) -> (ManagedCommand, String) {
    let state = crate::escape::shell_escape(&format!("/var/lib/anvil/sysctl-{module}.orig"));
    let dropin = crate::escape::shell_escape(dropin);
    let keys = crate::escape::shell_escape_join(keys);
    let cmd = ManagedCommand::new(
        format!("snapshot pre-anvil sysctl values ({module})"),
        format!("[ -e {state} ] || [ -e {dropin} ]"),
        format!(
            "mkdir -p /var/lib/anvil\n\
             for __k in {keys}; do __v=$(sysctl -n \"$__k\" 2>/dev/null) && printf '%s = %s\\n' \"$__k\" \"$__v\"; done > {state}"
        ),
    );
    let rollback = format!(
        "\n# rollback (module-authored): {module} runtime sysctl values\n\
         if [ -s {state} ]; then\n\
         \x20 sysctl -q -p {state} >/dev/null 2>&1 || true\n\
         \x20 rm -f {state}\n\
         \x20 printf 'CHANGED: {module} restored pre-anvil sysctl values\\n'\n\
         else\n\
         \x20 rm -f {state}\n\
         \x20 printf 'OK: {module} has no sysctl snapshot; removed keys reset at reboot\\n'\n\
         fi\n"
    );
    (cmd, rollback)
}

/// The `printf` that renders Docker's apt source line (no redirect). The
/// format string is single-quoted so bash never expands inside it; the three
/// `%s` args carry the architecture and the `/etc/os-release` `ID` /
/// `VERSION_CODENAME` the caller has sourced. Kept as its own value so a test
/// can execute it and check the expanded line (a single-quoted format
/// with the variables *inside* it shipped `$ID` literally).
const DOCKER_APT_SOURCE_PRINTF: &str = "printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\\n' \"$(dpkg --print-architecture)\" \"$ID\" \"$VERSION_CODENAME\"";

/// `0` when dpkg has `pkg` installed (read-only; used by the no-switch check).
fn dpkg_installed(pkg: &str) -> String {
    format!(
        "[ \"$(dpkg-query -W -f='${{Status}}' {} 2>/dev/null)\" = 'install ok installed' ]",
        crate::escape::shell_escape(pkg)
    )
}

/// Install the host's container engine — shared by every module that runs
/// containers (containers, greptimedb, headscale, forgejo, the CI runners).
///
/// Podman: the distro's `podman` + `iptables` (netavark's firewall driver)
/// plus `aardvark-dns` (container DNS on user networks; a separate package
/// on Debian, without it job services cannot resolve each other or the
/// internet), behind [`podman_version_gate`] so hosts below Podman 4.4 stop with
/// `FAILED:` in the probe, before anything is installed.
///
/// Docker: `distro = false` (`[docker] source = "vendor"`, the default): Docker's
/// official, keyring-pinned apt repository — no vendor script is ever piped to
/// a shell (the vector pattern). `distro = true`: Ubuntu's `docker.io` +
/// `docker-compose-v2`; any other distro reports `FAILED:` (the Docker source decision).
///
/// An installed engine is never switched: `docker-ce` and `docker.io`
/// conflict, so apt would remove one. `detect` passes whenever `docker` exists
/// and only warns when it came from the other source.
pub(crate) fn ensure_engine(engine: Engine, distro: bool) -> ManagedCommand {
    if engine == Engine::Podman {
        let gate = podman_version_gate();
        return ManagedCommand::new(
            format!(
                "install podman >= {}.{} + iptables + aardvark-dns (distro packages)",
                PODMAN_MIN.0, PODMAN_MIN.1
            ),
            format!(
                "{gate} && command -v podman >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1 \
                 && {}",
                dpkg_installed("aardvark-dns")
            ),
            apt_install(&["podman", "iptables", "aardvark-dns"]),
        );
    }
    let (want, other) = if distro {
        ("distro", "docker-ce")
    } else {
        ("vendor", "docker.io")
    };
    let warn = format!(
        "anvil: warning: docker: {other} is installed but [docker] source = \"{want}\"; \
         keeping the installed engine (the packages conflict; switch by hand)"
    );
    let warn = crate::escape::shell_escape(&warn);
    // Only an absent engine on a non-Ubuntu host fails; the probe reports it too.
    let refuse = if distro {
        "elif ! ( . /etc/os-release && [ \"${ID:-}\" = ubuntu ] ); then \
         printf 'FAILED: docker: source = \"distro\" needs Ubuntu (docker.io + docker-compose-v2); \
         use source = \"vendor\" on %s\\n' \"$( . /etc/os-release 2>/dev/null && printf '%s' \"${PRETTY_NAME:-this host}\" || printf 'this host')\"; exit 1; "
    } else {
        ""
    };
    let detect = format!(
        "{{ if command -v docker >/dev/null 2>&1; then \
         if {installed}; then printf '%s\\n' {warn}; printf '%s\\n' {warn} >&2; fi; true; \
         {refuse}else false; fi; }}",
        installed = dpkg_installed(other),
    );
    if distro {
        return ManagedCommand::new(
            "install docker engine (Ubuntu docker.io + docker-compose-v2)",
            detect,
            apt_install(&["docker.io", "docker-compose-v2"]),
        );
    }
    ManagedCommand::new(
        "install docker engine (keyring-pinned apt repo)",
        detect,
        // Bootstrap curl/gnupg/ca-certificates (a minimal image carries none),
        // then pin Docker's signing key and add a signed-by= source: apt verifies
        // the key on every install, unlike `get.docker.com | sh`.
        format!(
            "command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
             . /etc/os-release\n\
             install -d -m 0755 /etc/apt/keyrings\n\
             curl -fsSL \"https://download.docker.com/linux/$ID/gpg\" -o /etc/apt/keyrings/docker.asc\n\
             chmod a+r /etc/apt/keyrings/docker.asc\n\
             {DOCKER_APT_SOURCE_PRINTF} > /etc/apt/sources.list.d/docker.list\n\
             {install}",
            bootstrap = apt_install(&["curl", "gnupg", "ca-certificates"]),
            install = apt_install(&[
                "docker-ce",
                "docker-ce-cli",
                "containerd.io",
                "docker-buildx-plugin",
                "docker-compose-plugin"
            ]),
        ),
    )
}

/// First Podman with Quadlet (`.container` in `/etc/containers/systemd`,
/// `PublishPort=`, `[Install]`, `quadlet -dryrun`): 4.4.0.
pub const PODMAN_MIN: (u32, u32) = (4, 4);

/// The per-host gate (the Podman decision): reads the installed Podman version, or
/// apt's candidate when Podman is absent, and refuses below [`PODMAN_MIN`]
/// with `FAILED:` + exit 1 — in the probe too, so `check`/`apply` report the
/// reason before anything is installed. Exit 0 when the host qualifies.
pub fn podman_version_gate() -> String {
    let (maj, min) = PODMAN_MIN;
    format!(
        "{{ __pv=$(podman --version 2>/dev/null | awk '{{print $NF}}' || true)\n\
         [ -n \"$__pv\" ] || __pv=$(apt-cache policy podman 2>/dev/null | awk '/Candidate:/{{print $2}}' || true)\n\
         __pv=${{__pv#*:}}; __pv=${{__pv%%[+~-]*}}\n\
         __rel=$( . /etc/os-release 2>/dev/null && printf '%s' \"${{PRETTY_NAME:-this host}}\" || printf 'this host')\n\
         if [[ ! $__pv =~ ^([0-9]+)\\.([0-9]+) ]]; then\n\
         \x20 printf 'FAILED: podman: cannot determine the Podman version on %s (got \"%s\"); a Podman host needs Podman >= {maj}.{min} for Quadlets — install podman or use a Docker host\\n' \"$__rel\" \"$__pv\"; exit 1\n\
         elif (( BASH_REMATCH[1] < {maj} || (BASH_REMATCH[1] == {maj} && BASH_REMATCH[2] < {min}) )); then\n\
         \x20 printf 'FAILED: podman: a Podman host needs Podman >= {maj}.{min} for Quadlets; this host (%s) ships %s — use a Docker host\\n' \"$__rel\" \"$__pv\"; exit 1\n\
         fi; }}"
    )
}

/// IDs of local images in the repositories of the refs `refs` prints
/// (one per line) that are none of those refs and that no container, running
/// or stopped, uses. Prints nothing unless every ref is present locally.
fn superseded_list(eng: &str, refs: &str) -> String {
    // Docker lists `busybox` for `docker.io/library/busybox`; Podman keeps
    // qualified names, so only Docker's need the prefixes dropped.
    let norm = if eng == "docker" {
        r"sed -E 's#^docker\.io/##; s#^library/##'"
    } else {
        "cat"
    };
    format!(
        r#"( set +e +o pipefail; __refs=$({refs}); [ -n "$__refs" ] || exit 0
__keep=$(printf '%s\n' "$__refs" | while IFS= read -r __r; do {eng} image inspect -f '{{{{.Id}}}}' "$__r" 2>/dev/null || echo -; done)
case "
$__keep
" in (*"
-
"*) exit 0 ;; esac
__used=$({eng} ps -aq 2>/dev/null | xargs -r {eng} inspect -f '{{{{.Image}}}}' 2>/dev/null)
__repos=$(printf '%s\n' "$__refs" | sed -E 's/@.*$//; s/:[^:/]*$//' | {norm} | sort -u)
{eng} image ls --no-trunc --format '{{{{.Repository}}}} {{{{.ID}}}}' 2>/dev/null | {norm} | \
__repos="$__repos" awk 'BEGIN {{ n = split(ENVIRON["__repos"], w, "\n"); for (i = 1; i <= n; i++) k[w[i]] = 1 }}
$1 in k {{ id = $2; sub(/^sha256:/, "", id); print id }}' | \
sort -u | grep -vxF -f <(printf '%s\n' $__keep $__used | sed 's/^sha256://') )"#
    )
}

/// An image a pull or rebuild superseded goes once no container uses
/// it: probe-visible as drift, removed by apply before and again after the
/// (re)start that releases it. Never forced; rollback keeps images.
pub(crate) fn prune_superseded(
    decl: Declaration,
    what: &str,
    eng: &str,
    refs: &str,
) -> Declaration {
    let rm = format!(
        "{{ {}; }} | xargs -r {eng} image rm >/dev/null 2>&1 || true",
        superseded_list(eng, refs)
    );
    decl.command(ManagedCommand::new(
        format!("superseded {what} images removed"),
        format!("[ -z \"$( {} )\" ]", superseded_list(eng, refs)),
        rm.clone(),
    ))
    .after_apply(format!("\n# superseded {what} images\n{rm}\n"))
}

/// A hardening module: given its config it renders a [`Declaration`] the engine
/// turns into probe/apply scripts.
pub trait Module {
    /// Canonical module id (matches the config section name).
    fn id(&self) -> &'static str;
    /// The desired-state declaration for this host.
    fn declaration(&self) -> Declaration;
}

/// Construct a module instance for `id` from `config`, if that module is
/// implemented in this scaffold.
fn build_module(id: &str, config: &Config) -> Option<Box<dyn Module>> {
    macro_rules! m {
        ($field:ident, $ctor:expr) => {
            config
                .$field
                .clone()
                .map(|c| Box::new($ctor(c)) as Box<dyn Module>)
        };
    }
    // One engine per host: every module that installs docker reads [docker] source.
    let docker_distro = config.docker.as_ref().is_some_and(|d| d.distro());
    let in_ci_slice = config.ci_resources.is_some();
    let ci_cpu_weight = config.ci_resources.as_ref().map_or(100, |c| c.cpu_weight);
    // The apps' units/drop-ins put Slice=apps.slice on the slice this writes.
    let in_apps_slice = config.apps_resources.is_some();
    // One owner for daemon.json; a v2 runner writes it after sysbox.
    // A docker-rootless v2 runner installs neither sysbox nor daemon.json.
    let v2_runner = config.github_runner.as_ref().is_some_and(|g| {
        g.ephemeral() && g.sandbox_runtime(config.host_engine()) != "docker-rootless"
    });
    // An ephemeral forgejo runner too, unless a v2 runner already does.
    let sandbox_host = v2_runner
        || config
            .forgejo_runner
            .as_ref()
            .is_some_and(|f| f.ephemeral() && !f.docker_rootless());
    match id {
        "users" => m!(users, users::UsersModule::new),
        "packages" => m!(packages, packages::PackagesModule::new),
        "sshd" => m!(sshd, sshd::SshdModule::new),
        "ssh_crypto" => m!(ssh_crypto, ssh_crypto::SshCryptoModule::new),
        "kernel" => m!(kernel, kernel::KernelModule::new),
        "kernel_modules" => m!(kernel_modules, kernel_modules::KernelModulesModule::new),
        "pam" => m!(pam, pam::PamModule::new),
        "process" => m!(process, process::ProcessModule::new),
        "dns" => m!(dns, dns::DnsModule::new),
        "suid" => m!(suid, suid::SuidModule::new),
        "filesystem" => m!(filesystem, filesystem::FilesystemModule::new),
        "auditd" => m!(auditd, auditd::AuditdModule::new),
        "lynis" => m!(lynis, lynis::LynisModule::new),
        // fail2ban's sshd jail must watch the effective SSH port, not blindly
        // assume 22. With a tailnet, its addresses are never banned (nor by
        // crowdsec): they may be the operator's only way in.
        // With [forgejo], a jail on its HTTPS front (Caddy's port, else 443)
        // and its built-in SSH port.
        "fail2ban" => config.fail2ban.clone().map(|c| {
            let mut m = fail2ban::Fail2banModule::new(c, config.effective_ssh_port())
                .exempt_tailnet(config.tailscale.is_some());
            if let Some(fj) = &config.forgejo {
                let https = config.caddy.as_ref().map_or(443, |c| c.https_port);
                m = m.forgejo(https, fj.ssh_port);
            }
            Box::new(m) as Box<dyn Module>
        }),
        "crowdsec" => config.crowdsec.clone().map(|c| {
            Box::new(crowdsec::CrowdsecModule::new(c).exempt_tailnet(config.tailscale.is_some()))
                as Box<dyn Module>
        }),
        // Firewall needs the effective SSH port so its pre-enable allow rule
        // matches the real port (R56) — a non-default port must not be fenced off.
        // It also needs to know whether tailscale's tailnet-only SSH tightening is
        // enabled, so re-applies don't re-open SSH to the world once the tailnet
        // has taken over (the allow stays runtime-conditional, lockout-safe).
        "firewall" => config.firewall.clone().map(|c| {
            let tailnet_only_ssh = config
                .tailscale
                .as_ref()
                .is_some_and(|t| t.tailnet_only_ssh);
            Box::new(firewall::FirewallModule::new(
                c,
                config.effective_ssh_port(),
                tailnet_only_ssh,
                config.live_ssh_ports(),
            )) as Box<dyn Module>
        }),
        "docker" => m!(docker, |c| docker::DockerModule::new(c)
            .runner_owns_daemon_json(sandbox_host))
        .or_else(|| {
            config
                .docker_logs_only()
                .then(|| Box::new(docker::DockerModule::logs_only()) as Box<dyn Module>)
        }),
        "podman" => m!(podman, podman::PodmanModule::new),
        "containers" => config.containers.clone().map(|c| {
            let iptables_off = config.docker.as_ref().is_some_and(|d| d.iptables_off());
            Box::new(
                containers::ContainersModule::new(c)
                    .iptables_off(iptables_off)
                    .docker_distro(docker_distro)
                    .engine(config.host_engine())
                    .podman_owns_conf(config.podman.is_some())
                    .in_apps_slice(in_apps_slice),
            ) as Box<dyn Module>
        }),
        "tls" => m!(tls, tls::TlsModule::new),
        // A `listen` switch removes caddy's old ufw rules, never [firewall]'s.
        "caddy" => config.caddy.clone().map(|c| {
            let allows = config.firewall.as_ref().map_or(&[][..], |f| &f.allow[..]);
            Box::new(
                caddy::CaddyModule::new(c)
                    .firewall_allows(allows)
                    .in_apps_slice(in_apps_slice),
            ) as Box<dyn Module>
        }),
        // The nginx proxy snippet is written only when [tls] serves the domain.
        "forgejo" => config.forgejo.clone().map(|c| {
            let via_tls = config
                .tls
                .as_ref()
                .is_some_and(|t| t.domains.contains(&c.domain));
            Box::new(
                forgejo::ForgejoModule::new(c, via_tls)
                    .docker_distro(docker_distro)
                    .in_apps_slice(in_apps_slice),
            ) as Box<dyn Module>
        }),
        // The cloud lockout guard (R61) must permit the *effective* SSH port.
        "hetzner" => config.hetzner.clone().map(|c| {
            Box::new(hetzner::HetznerModule::new(
                c,
                config.effective_ssh_port(),
                config.live_ssh_ports(),
            )) as Box<dyn Module>
        }),
        "netcup" => config.netcup.clone().map(|c| {
            Box::new(netcup::NetcupModule::new(
                c,
                config.effective_ssh_port(),
                config.live_ssh_ports(),
            )) as Box<dyn Module>
        }),
        "headscale" => m!(headscale, |c| headscale::HeadscaleModule::new(c)
            .docker_distro(docker_distro)
            .engine(config.host_engine())),
        // Tailscale's tailnet-only SSH tightening must scope the *effective*
        // SSH port, never a hardcoded 22.
        "tailscale" => config.tailscale.clone().map(|c| {
            Box::new(tailscale::TailscaleModule::new(
                c,
                config.effective_ssh_port(),
            )) as Box<dyn Module>
        }),
        "greptimedb" => m!(greptimedb, |c| greptimedb::GreptimedbModule::new(c)
            .docker_distro(docker_distro)
            .engine(config.host_engine())
            .in_apps_slice(in_apps_slice)),
        "ci_resources" => m!(ci_resources, ci_resources::CiResourcesModule::new),
        "apps_resources" => m!(apps_resources, apps_resources::AppsResourcesModule::new),
        "github_runner" => m!(github_runner, |c| github_runner::GithubRunnerModule::new(c)
            .docker_distro(docker_distro)
            .docker(config.docker.clone())
            .in_ci_slice(in_ci_slice)
            .ci_cpu_weight(ci_cpu_weight)
            .engine(config.host_engine())),
        // An empty url means this config's [forgejo] instance.
        "forgejo_runner" => config.forgejo_runner.clone().map(|c| {
            let domain = config.forgejo.as_ref().map(|f| f.domain.as_str());
            Box::new(
                forgejo_runner::ForgejoRunnerModule::new(c, domain)
                    .docker_distro(docker_distro)
                    .docker(config.docker.clone())
                    .owns_engine(!v2_runner)
                    .in_ci_slice(in_ci_slice)
                    .ci_cpu_weight(ci_cpu_weight)
                    .engine(config.host_engine()),
            ) as Box<dyn Module>
        }),
        "vector" => m!(vector, |c| vector::VectorModule::new(c)
            .in_apps_slice(in_apps_slice)),
        // With no hub_addresses, the agent port is allowed on tailscale0 only.
        "beszel" => config.beszel.clone().map(|c| {
            Box::new(beszel::BeszelModule::new(c, config.tailscale.is_some())) as Box<dyn Module>
        }),
        "restic" => m!(restic, restic::ResticModule::new),
        "coding_agents" => m!(coding_agents, |c| coding_agents::CodingAgentsModule::new(c)
            .tmp_noexec(config.filesystem.as_ref().is_some_and(|f| f.tmp_noexec))
            .engine(config.host_engine())
            .docker_distro(docker_distro)),
        "updates" => m!(updates, updates::UpdatesModule::new),
        _ => None,
    }
}

/// An enabled out-of-tree plugin adapted to the [`Module`] trait (R92): its
/// declaration was already rendered at load time from the substituted
/// `apply.sh`/`check.sh`, so from here on it behaves exactly like a built-in
/// module (probe/apply rendering, markers, results as `plugin::<name>`).
struct PluginModule {
    id: &'static str,
    decl: Declaration,
}

impl Module for PluginModule {
    fn id(&self) -> &'static str {
        self.id
    }
    fn declaration(&self) -> Declaration {
        self.decl.clone()
    }
}

/// The resolved execution plan for one config: its modules in run order.
pub struct Plan {
    /// Full resolved order of enabled module ids.
    pub order: Vec<String>,
    /// The modules, in run order (one per `order` entry).
    pub modules: Vec<Box<dyn Module>>,
}

impl Plan {
    /// Build the plan: resolve ordering (enforcing the hard edges), then instantiate each
    /// enabled section's module.
    pub fn build(config: &Config) -> Result<Plan> {
        Self::build_with_plugins(config, &[])
    }

    /// [`Plan::build`] including enabled plugins: each participates in
    /// ordering as `plugin::<name>` (the hard edges — updates last — apply
    /// to plugins too) and joins the module list as a regular module.
    pub fn build_with_plugins(config: &Config, plugins: &[EnabledPlugin]) -> Result<Plan> {
        let mut enabled = config.enabled_sections();
        for p in plugins {
            enabled.push(EnabledSection {
                id: p.id,
                order_override: p.order_override.clone(),
            });
        }
        let execution_order = config
            .execution_order
            .as_ref()
            .map(|e| e.modules.as_slice());
        let order = resolve_order(&enabled, execution_order)?;

        let mut modules: Vec<Box<dyn Module>> = Vec::new();
        for id in &order {
            if let Some(p) = plugins.iter().find(|p| p.id == id.as_str()) {
                modules.push(Box::new(PluginModule {
                    id: p.id,
                    decl: p.declaration.clone(),
                }));
            } else if let Some(m) = build_module(id, config) {
                modules.push(m);
            }
        }
        Ok(Plan { order, modules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(toml: &str) -> Config {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn login_defs_rollback_of_one_module_keeps_the_others_lines() {
        // Acceptance: pam (UMASK) and process (PASS_*) share login.defs.
        // Rolling back process alone must restore only its lines.
        let dir = std::env::temp_dir().join(format!("anvil-ld-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let defs = dir.join("login.defs");
        std::fs::write(
            &defs,
            "UMASK\t022\nPASS_MAX_DAYS\t99999\nMAIL_DIR /var/mail\n",
        )
        .unwrap();
        let fix = |s: String| {
            s.replace("/etc/login.defs", &defs.display().to_string())
                .replace("/var/lib/anvil", &dir.display().to_string())
        };
        let (pam_cap, pam_rb) = login_defs_keys("pam", &["UMASK"]);
        let (proc_cap, proc_rb) = login_defs_keys("process", &["PASS_MAX_DAYS"]);
        let capture = format!("{}{}", fix(pam_cap), fix(proc_cap));
        let run = |script: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .output()
        };
        let Ok(out) = run(&capture) else { return };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // Both modules have now hardened their lines.
        std::fs::write(
            &defs,
            "UMASK\t027\nPASS_MAX_DAYS\t365\nMAIL_DIR /var/mail\n",
        )
        .unwrap();
        let out = run(&fix(proc_rb)).unwrap();
        assert!(out.status.success());
        let after = std::fs::read_to_string(&defs).unwrap();
        assert!(
            after.contains("PASS_MAX_DAYS\t99999"),
            "process restored:\n{after}"
        );
        assert!(
            after.contains("UMASK\t027"),
            "pam's line untouched:\n{after}"
        );
        assert!(
            after.contains("MAIL_DIR /var/mail"),
            "unrelated lines kept:\n{after}"
        );
        run(&fix(pam_rb)).unwrap();
        let after = std::fs::read_to_string(&defs).unwrap();
        assert!(
            after.contains("UMASK\t022") && after.contains("PASS_MAX_DAYS\t99999"),
            "{after}"
        );

        // Legacy host: no records, only the old shared whole-file backup.
        // Rolling back process takes only its lines from it and keeps it.
        let bak = dir.join("login.defs.anvil.bak");
        std::fs::write(&bak, "UMASK\t022\nPASS_MAX_DAYS\t99999\n").unwrap();
        std::fs::write(&defs, "UMASK\t027\nPASS_MAX_DAYS\t365\n").unwrap();
        run(&fix(login_defs_keys("process", &["PASS_MAX_DAYS"]).1)).unwrap();
        let after = std::fs::read_to_string(&defs).unwrap();
        assert!(
            after.contains("PASS_MAX_DAYS\t99999") && after.contains("UMASK\t027"),
            "{after}"
        );
        assert!(bak.exists(), "shared backup kept for pam");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sysctl_snapshot_is_taken_once_and_restored_on_rollback() {
        // Snapshot before the first write only (a present drop-in means
        // the runtime is already ours), re-apply it on rollback, then drop it.
        let (cmd, rb) = sysctl_snapshot("kernel", "/etc/sysctl.d/99-x.conf", &["kernel.sysrq"]);
        assert_eq!(
            cmd.detect,
            "[ -e '/var/lib/anvil/sysctl-kernel.orig' ] || [ -e '/etc/sysctl.d/99-x.conf' ]"
        );
        assert!(
            cmd.converge.contains("for __k in 'kernel.sysrq'; do"),
            "{}",
            cmd.converge
        );
        assert!(cmd
            .converge
            .contains("> '/var/lib/anvil/sysctl-kernel.orig'"));
        let restore = rb
            .find("sysctl -q -p '/var/lib/anvil/sysctl-kernel.orig'")
            .unwrap();
        let remove = rb
            .find("rm -f '/var/lib/anvil/sysctl-kernel.orig'")
            .unwrap();
        assert!(restore < remove, "{rb}");
    }

    #[test]
    fn apt_install_refreshes_then_installs_escaped() {
        let s = apt_install(&["a", "b'c"]);
        let update = s.find("update -qq &&").expect("refresh present");
        let install = s
            .find("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'a' 'b'\\''c'")
            .expect("escaped install present");
        assert!(update < install);
        assert_eq!(s.matches("DEBIAN_FRONTEND=noninteractive").count(), 2);
    }

    #[test]
    fn docker_apt_source_line_expands_when_executed() {
        // Regression: the source line must be produced by *running* the
        // printf, not by string-matching the Rust literal — the original bug
        // shipped `$ID`/`$VERSION_CODENAME`/`$(dpkg …)` verbatim into
        // docker.list, and a `.contains("$ID")` assertion passed on it.
        let script = format!(
            "dpkg() {{ echo amd64; }}\nID=debian\nVERSION_CODENAME=bookworm\n{DOCKER_APT_SOURCE_PRINTF}"
        );
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .expect("bash available");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable\n"
        );

        // And the rendered converge carries no unexpanded token into the file:
        // every `$` on the docker.list line must sit outside the format string.
        let apply = ensure_engine(Engine::Docker, false).converge;
        let line = apply
            .lines()
            .find(|l| l.contains("sources.list.d/docker.list"))
            .expect("source line present");
        let fmt_end = line.find("' ").expect("closing quote of the format string");
        let fmt = &line[..fmt_end];
        assert!(
            !fmt.contains('$'),
            "no expansion inside the format string: {fmt}"
        );
        assert!(line.contains("\"$ID\" \"$VERSION_CODENAME\""), "{line}");
    }

    /// Runs the gate with stub `podman`/`apt-cache` printing the given lines
    /// (None = command absent). Returns (exit ok, stdout).
    fn gate(podman: Option<&str>, apt: Option<&str>) -> Option<(bool, String)> {
        let dir = std::env::temp_dir().join(format!(
            "anvil-gate-{}-{:?}-{:?}",
            std::process::id(),
            podman.map(str::len),
            apt.map(str::len)
        ));
        std::fs::create_dir_all(&dir).ok()?;
        for (bin, out) in [("podman", podman), ("apt-cache", apt)] {
            if let Some(out) = out {
                let stub = dir.join(bin);
                std::fs::write(&stub, format!("#!/bin/sh\nprintf '%s\\n' '{out}'\n")).ok()?;
                std::process::Command::new("chmod")
                    .args(["+x", &stub.to_string_lossy()])
                    .status()
                    .ok()?;
            }
        }
        // Hermetic: PATH is the stub dir alone (plus awk), so a real podman or
        // apt-cache on the runner can never stand in for an absent stub.
        let script = format!(
            "set -euo pipefail\nln -s \"$(command -v awk)\" '{0}/awk'\nPATH='{0}'\nif {1}; then echo PASS; fi",
            dir.display(),
            podman_version_gate()
        );
        let out = std::process::Command::new("bash")
            .args(["-c", &script])
            .output()
            .ok()?;
        let _ = std::fs::remove_dir_all(&dir);
        Some((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        ))
    }

    #[test]
    fn podman_engine_installs_and_requires_aardvark_dns() {
        // Without aardvark-dns (its own package on Debian) containers on
        // a user network get no DNS: job services, `wget` from a job.
        let c = ensure_engine(Engine::Podman, false);
        assert!(c
            .converge
            .contains("install -y -- 'podman' 'iptables' 'aardvark-dns'"));
        assert!(c.detect.contains(&dpkg_installed("aardvark-dns")));
        assert!(c.detect.contains("command -v iptables"));
    }

    #[test]
    fn version_gate_refuses_below_quadlet_minimum_per_host() {
        let v = |s: &str| gate(Some(&format!("podman version {s}")), None);
        let Some((ok, out)) = v("4.3.1") else { return };
        assert!(!ok && !out.contains("PASS"), "{out}");
        assert!(
            out.contains(
                "FAILED: podman: a Podman host needs Podman >= 4.4 for Quadlets; this host"
            ) && out.contains("ships 4.3.1 — use a Docker host"),
            "{out}"
        );
        for below in ["3.4.4", "4.3.9", "2.10.0"] {
            assert!(!v(below).unwrap().0, "{below} must be refused");
        }
        for ok in ["4.4.0", "4.4", "4.9.3", "5.4.2", "5.0.0", "10.1.0"] {
            let (pass, out) = v(ok).unwrap();
            assert!(pass && out.ends_with("PASS\n"), "{ok}: {out}");
        }
        // Unparseable → FAILED with the reason, never a silent pass.
        let (ok, out) = v("dev").unwrap();
        assert!(!ok && out.contains("FAILED: podman: cannot determine the Podman version"));
        assert!(out.contains("(got \"dev\")"), "{out}");
    }

    #[test]
    fn version_gate_reads_apt_candidate_before_install() {
        let apt = |c: &str| {
            gate(
                None,
                Some(&format!("podman:\n  Installed: (none)\n  Candidate: {c}")),
            )
        };
        let Some((ok, out)) = apt("4.3.1+ds1-8+deb12u1+b3") else {
            return;
        };
        assert!(!ok && out.contains("ships 4.3.1 "), "{out}");
        assert!(apt("4.9.3+ds1-1ubuntu0.2").unwrap().0);
        assert!(apt("1:5.7.0+ds2-3build1").unwrap().0, "epoch stripped");
        let (ok, out) = apt("(none)").unwrap();
        assert!(!ok && out.contains("cannot determine"), "{out}");
        let (ok, out) = gate(None, None).unwrap();
        assert!(!ok && out.contains("(got \"\")"), "{out}");
    }

    #[test]
    fn docker_source_picks_the_package_set() {
        let vendor = ensure_engine(Engine::Docker, false).converge;
        assert!(vendor.contains("download.docker.com"), "{vendor}");
        assert!(vendor.contains("'docker-ce'"), "{vendor}");
        assert!(!vendor.contains("docker.io"), "{vendor}");
        let distro = ensure_engine(Engine::Docker, true).converge;
        assert!(
            distro.contains("install -y -- 'docker.io' 'docker-compose-v2'"),
            "{distro}"
        );
        assert!(!distro.contains("download.docker.com"), "{distro}");
        assert!(!distro.contains("docker-ce"), "{distro}");
    }

    /// Run `detect` with stub `docker`/`dpkg-query` binaries and a fake
    /// os-release. `installed` is the package dpkg reports (None = no docker).
    /// Returns (exit ok, stdout, stderr).
    fn run_docker_detect(
        distro: bool,
        installed: Option<&str>,
        id: &str,
    ) -> (bool, String, String) {
        use std::os::unix::fs::PermissionsExt;
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("anvil-dk-{}-{n}", std::process::id()));
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = |name: &str, body: &str| {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        if let Some(pkg) = installed {
            stub("docker", "exit 0");
            // dpkg-query -W -f=... <pkg>: report only `pkg` as installed.
            stub(
                "dpkg-query",
                &format!("for a; do last=$a; done; [ \"$last\" = {pkg} ] || exit 1; printf 'install ok installed'"),
            );
        }
        let osr = dir.join("os-release");
        std::fs::write(&osr, format!("ID={id}\nPRETTY_NAME=\"{id} test\"\n")).unwrap();
        let detect = ensure_engine(Engine::Docker, distro)
            .detect
            .replace("/etc/os-release", osr.to_str().unwrap());
        let out = std::process::Command::new("/bin/bash")
            .args([
                "-euo",
                "pipefail",
                "-c",
                &format!("if {detect}; then exit 0; else exit 3; fi"),
            ])
            // Stub dir only: detect needs nothing but builtins and the stubs,
            // and a host docker (CI runners have one) must not leak in.
            .env("PATH", &bin)
            .output()
            .expect("bash available");
        std::fs::remove_dir_all(&dir).ok();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    #[test]
    fn docker_detect_never_switches_an_installed_engine() {
        // Matching source: converged, silent.
        for (distro, pkg) in [(false, "docker-ce"), (true, "docker.io")] {
            let (ok, out, err) = run_docker_detect(distro, Some(pkg), "debian");
            assert!(ok && out.is_empty() && err.is_empty(), "{pkg}: {out}{err}");
        }
        // The other source's engine: kept (converged, no install) and warned
        // about on stdout and stderr — even on a non-Ubuntu host with "distro".
        for (distro, pkg, want) in [
            (true, "docker-ce", "source = \"distro\""),
            (false, "docker.io", "source = \"vendor\""),
        ] {
            let (ok, out, err) = run_docker_detect(distro, Some(pkg), "debian");
            assert!(ok, "{pkg}: {out}{err}");
            for s in [&out, &err] {
                assert!(s.contains("anvil: warning: docker:"), "{s}");
                assert!(
                    s.contains(&format!("{pkg} is installed but [docker] {want}")),
                    "{s}"
                );
            }
        }
    }

    #[test]
    fn docker_distro_source_fails_off_ubuntu_only_when_docker_is_absent() {
        let (ok, out, _) = run_docker_detect(true, None, "debian");
        assert!(!ok);
        assert!(
            out.starts_with("FAILED: docker: source = \"distro\" needs Ubuntu")
                && out.contains("on debian test"),
            "{out}"
        );
        // Ubuntu without docker: plain drift, the converge installs docker.io.
        let (ok, out, _) = run_docker_detect(true, None, "ubuntu");
        assert!(!ok && out.is_empty(), "{out}");
        // vendor never refuses a distro.
        let (ok, out, _) = run_docker_detect(false, None, "debian");
        assert!(!ok && out.is_empty(), "{out}");
    }

    #[test]
    fn docker_source_reaches_every_engine_installer() {
        let body = r#"
            [host]
            address = "h"
            user = "u"
            [containers.compose.web]
            content = "services: {}"
            [greptimedb]
            [headscale]
            server_url = "https://hs.example.com"
            headplane = true
            base_domain = "tailnet.example.com"
            [github_runner]
            docker = "group"
            [github_runner.runners.r1]
            url = "https://github.com/acme"
            token = "t"
            labels = ["anvil"]
            [forgejo_runner]
            url = "https://git.example.org/"
            uuid = "00000000-0000-4000-8000-000000000000"
            token = "t"
            labels = ["debian:host"]
            docker = "group"
        "#;
        let ids = [
            "containers",
            "greptimedb",
            "headscale",
            "github_runner",
            "forgejo_runner",
        ];
        for (docker, distro) in [
            ("", false),
            ("[docker]\n", false),
            ("[docker]\nsource = \"distro\"\n", true),
        ] {
            let c = cfg(&format!("{docker}{body}"));
            for id in ids {
                let apply = build_module(id, &c).unwrap().declaration().render_apply();
                assert_eq!(
                    apply.contains("'docker.io' 'docker-compose-v2'"),
                    distro,
                    "{id} {docker}"
                );
                assert_eq!(
                    apply.contains("download.docker.com"),
                    !distro,
                    "{id} {docker}"
                );
            }
        }
    }

    #[test]
    fn exactly_one_module_owns_daemon_json() {
        let v2 = r#"
            [github_runner]
            mode = "ephemeral"
            app_id = 1
            installation_id = 2
            app_key = "k"
            [github_runner.runners.r1]
            url = "https://github.com/acme"
            labels = ["anvil"]
        "#;
        let host = "[host]\naddress = \"h\"\nuser = \"u\"\n";
        let owners = |body: &str| {
            let c = cfg(&format!("{host}{body}"));
            ["docker", "github_runner", "forgejo_runner"]
                .into_iter()
                .filter(|id| {
                    build_module(id, &c).is_some_and(|m| {
                        m.declaration()
                            .files
                            .iter()
                            .any(|f| f.path == docker::DAEMON_JSON)
                    })
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(owners("[docker]\n"), ["docker"]);
        // The default docker-rootless v2 runner leaves daemon.json to [docker].
        assert_eq!(owners(&format!("[docker]\n{v2}")), ["docker"]);
        let v2 = &v2.replace(
            "mode = \"ephemeral\"\n",
            "mode = \"ephemeral\"\n            sandbox_runtime = \"sysbox-runc\"\n",
        );
        assert_eq!(owners(v2), ["github_runner"]);
        assert_eq!(owners(&format!("[docker]\n{v2}")), ["github_runner"]);
        // Every module that installs Docker gets capped logs, through
        // a logs-only docker module when [docker] is absent.
        let compose = "[containers.compose.web]\ncontent = \"services: {}\\n\"\n";
        for installer in [
            compose,
            "[greptimedb]\n",
            "[headscale]\nserver_url = \"https://hs.example.com\"\nheadplane = true\n",
            "[github_runner]\ndocker = \"group\"\n[github_runner.runners.r]\nurl = \"https://github.com/o\"\n",
        ] {
            assert_eq!(owners(installer), ["docker"], "{installer}");
            let c = cfg(&format!("{host}{installer}"));
            assert!(c.enabled_sections().iter().any(|s| s.id == "docker"));
        }
        assert_eq!(owners(&format!("{compose}{v2}")), ["github_runner"]);
        // An ephemeral forgejo runner owns it, unless a v2 runner does.
        let fjr = "[forgejo_runner]\nmode = \"ephemeral\"\napi_token = \"t\"\n\
                   url = \"https://git.example.org/\"\nlabels = [\"debian:host\"]\n\
                   sandbox_runtime = \"sysbox-runc\"\n";
        assert_eq!(owners(fjr), ["forgejo_runner"]);
        assert_eq!(owners(&format!("[docker]\n{fjr}")), ["forgejo_runner"]);
        assert_eq!(owners(&format!("{fjr}{v2}")), ["github_runner"]);
        assert!(owners("[containers]\n").is_empty());
        assert!(owners("[headscale]\nserver_url = \"https://hs.example.com\"\n").is_empty());
        assert!(owners("[podman]\n[greptimedb]\n").is_empty());
        // v2 folds the [docker] keys into its file.
        let c = cfg(&format!("{host}[docker]\n{v2}"));
        let d = build_module("github_runner", &c).unwrap().declaration();
        let f = d
            .files
            .iter()
            .find(|f| f.path == docker::DAEMON_JSON)
            .unwrap();
        assert!(f.static_content().unwrap().contains("userns-remap"));
    }

    /// Run `prune_superseded` against a stub engine. `images`: "ID REF"
    /// lines; `ps`: "CONTAINER IMAGE-ID" lines. Returns (drifted, left).
    fn superseded_run_on(eng: &str, images: &str, ps: &str, refs: &str) -> (bool, String) {
        use std::os::unix::fs::PermissionsExt;
        let d =
            std::env::temp_dir().join(format!("anvil-ss-{}-{}", std::process::id(), refs.len()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("bin")).unwrap();
        std::fs::write(d.join("images"), images).unwrap();
        std::fs::write(d.join("ps"), ps).unwrap();
        let stub = d.join("bin").join(eng);
        std::fs::write(
            &stub,
            "#!/bin/bash\ncd \"$(dirname \"$0\")/..\"\ncase \"$1 $2\" in\n\
             'image inspect') awk -v r=\"$5\" '$2==r {print \"sha256:\" $1; f=1} END {exit !f}' images ;;\n\
             'image ls') awk '{r = $2; sub(/@.*/, \"\", r); sub(/:[^:\\/]*$/, \"\", r); print r, \"sha256:\" $1}' images ;;\n\
             'ps -aq') cut -d' ' -f1 ps ;;\n\
             'image rm') shift 2; for i; do grep -v \"^$i \" images >t; mv t images; done ;;\n\
             *) [ \"$1\" = inspect ] || exit 1; shift 3; for c; do awk -v c=\"$c\" '$1==c {print $2}' ps; done ;;\n\
             esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        let decl = prune_superseded(Declaration::new("t"), "demo", eng, refs);
        let c = &decl.commands[0];
        let script = format!(
            "PATH={dir}/bin:$PATH\nif {detect}; then echo aligned; else echo drifted; fi\n{after}",
            dir = d.display(),
            detect = c.detect,
            after = decl.after_apply.unwrap(),
        );
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        assert!(out.status.success() && out.stderr.is_empty(), "{out:?}");
        let left = std::fs::read_to_string(d.join("images")).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        (
            String::from_utf8_lossy(&out.stdout).trim() == "drifted",
            left,
        )
    }

    fn superseded_run(images: &str, ps: &str, refs: &str) -> (bool, String) {
        superseded_run_on("docker", images, ps, refs)
    }

    #[test]
    fn superseded_images_go_only_when_unused_and_the_current_ref_exists() {
        let imgs =
            "a1 forgejo/forgejo:14\nb2 forgejo/forgejo:15\nc3 forgejo/forgejo:13\nd4 nginx:1\n";
        let refs = "printf '%s\\n' forgejo/forgejo:15";
        // 14 is a stopped container's: only 13 goes; other repos stay.
        let (drift, left) = superseded_run(imgs, "x b2\ny a1\n", refs);
        assert!(drift);
        assert_eq!(
            left,
            "a1 forgejo/forgejo:14\nb2 forgejo/forgejo:15\nd4 nginx:1\n"
        );
        // Converged: nothing superseded, nothing removed.
        let (drift, left) = superseded_run("b2 forgejo/forgejo:15\n", "", refs);
        assert!(!drift && left == "b2 forgejo/forgejo:15\n");
        // The current ref is not pulled (yet): nothing goes.
        let (drift, left) = superseded_run("a1 forgejo/forgejo:14\n", "", refs);
        assert!(!drift && left == "a1 forgejo/forgejo:14\n");
        // A digest-pinned ref keeps its repo; a registry port is not a tag.
        let pinned = "printf '%s\\n' reg:5000/fj:15@sha256:ff";
        let (drift, left) = superseded_run(
            "a1 reg:5000/fj:14\nb2 reg:5000/fj:15@sha256:ff\n",
            "",
            pinned,
        );
        assert!(drift && left == "b2 reg:5000/fj:15@sha256:ff\n");
        // Docker's short names and Podman's qualified ones are one repository.
        let (drift, left) = superseded_run(
            "a1 busybox:1.36\nb2 docker.io/library/busybox:1.37\nc3 other/busybox:1\n",
            "",
            "printf '%s\\n' docker.io/library/busybox:1.37",
        );
        assert!(
            drift && left == "b2 docker.io/library/busybox:1.37\nc3 other/busybox:1\n",
            "{left}"
        );
        // Podman compares names as listed (already qualified).
        let imgs =
            "a1 docker.io/library/busybox:1.36\nb2 docker.io/library/busybox:1.37\nc3 busybox:1\n";
        let (drift, left) = superseded_run_on(
            "podman",
            imgs,
            "",
            "printf '%s\\n' docker.io/library/busybox:1.37",
        );
        assert!(
            drift && left == "b2 docker.io/library/busybox:1.37\nc3 busybox:1\n",
            "{left}"
        );
        // No refs (a removed project): nothing goes.
        let (drift, _) = superseded_run(imgs, "", "true");
        assert!(!drift);
    }

    /// An unset `sandbox_runtime` follows the host engine.
    #[test]
    fn v2_runner_sandbox_follows_the_host_engine() {
        let host = "[host]\naddress = \"h\"\nuser = \"u\"\n";
        let v2 = "[github_runner]\nmode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\n\
                  runner_group_id = 3\napp_key = \"k\"\n\
                  [github_runner.runners.r1]\nurl = \"https://github.com/o\"\n";
        let installs = |engine: &str| {
            let c = cfg(&format!("{host}{engine}{v2}"));
            build_module("github_runner", &c)
                .unwrap()
                .declaration()
                .installs
        };
        // docker-rootless by default on a Docker host; sysbox on request.
        assert_eq!(installs(""), ["Docker (rootless)"]);
        let sysbox = v2.replace(
            "ephemeral\"\n",
            "ephemeral\"\nsandbox_runtime = \"sysbox-runc\"\n",
        );
        assert_eq!(
            installs_of(&format!("{host}{sysbox}"), "github_runner"),
            ["Docker", "sysbox-ce 0.7.1"]
        );
        assert_eq!(installs("[podman]\n"), ["Podman"]);
        assert_eq!(installs("[containers]\nruntime = \"podman\"\n"), ["Podman"]);
        // A docker-rootless v2 runner leaves sysbox to an ephemeral
        // forgejo runner that still uses it, and daemon.json to [docker].
        let rl = v2.replace(
            "ephemeral\"\n",
            "ephemeral\"\nsandbox_runtime = \"docker-rootless\"\n",
        );
        assert_eq!(
            installs_of(&format!("{host}{rl}"), "github_runner"),
            ["Docker (rootless)"]
        );
        let fj = "[forgejo_runner]\nmode = \"ephemeral\"\nurl = \"https://git.example.org/\"\n\
                  api_token = \"t\"\nlabels = [\"x:host\"]\nsandbox_runtime = \"sysbox-runc\"\n";
        assert_eq!(
            installs_of(&format!("{host}{rl}{fj}"), "forgejo_runner"),
            ["Docker", "sysbox-ce 0.7.1"]
        );
        let c = cfg(&format!("{host}[docker]\n{rl}"));
        let dj = |c: &Config| {
            build_module("docker", c)
                .unwrap()
                .declaration()
                .files
                .iter()
                .any(|f| f.path == "/etc/docker/daemon.json")
        };
        assert!(dj(&c), "no sysbox runner: [docker] keeps daemon.json");
        assert!(!dj(&cfg(&format!("{host}[docker]\n{sysbox}"))));
        // A persistent forgejo runner runs no sandboxes: [docker] keeps daemon.json.
        let fj_persistent = "[forgejo_runner]\nurl = \"https://git.example.org/\"\n\
                             uuid = \"00000000-0000-4000-8000-000000000000\"\ntoken = \"x\"\n\
                             labels = [\"x:host\"]\n";
        assert!(dj(&cfg(&format!("{host}[docker]\n{fj_persistent}"))));
    }

    fn installs_of(body: &str, id: &str) -> Vec<String> {
        build_module(id, &cfg(body)).unwrap().declaration().installs
    }

    #[test]
    fn one_owner_for_the_containers_conf_drop_in() {
        let host = "[host]\naddress = \"h\"\nuser = \"u\"\n";
        let quadlet = "[containers.quadlet.web]\ncontent = \"[Container]\\nImage=nginx\\n\"\n";
        let owners = |body: &str| {
            let c = cfg(&format!("{host}{body}"));
            ["podman", "containers"]
                .into_iter()
                .filter(|id| {
                    build_module(id, &c).is_some_and(|m| {
                        m.declaration()
                            .files
                            .iter()
                            .any(|f| f.path == podman::PODMAN_CONF)
                    })
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(owners("[podman]\n"), ["podman"]);
        assert_eq!(owners(&format!("[podman]\n{quadlet}")), ["podman"]);
        assert_eq!(
            owners(&format!("[containers]\nruntime = \"podman\"\n{quadlet}")),
            ["containers"]
        );
        // A Podman host without Quadlets still gets it (a v2 runner's
        // sandboxes and image build need outbound next to ufw).
        let v2 = "[github_runner]\nmode = \"ephemeral\"\napp_id = 1\ninstallation_id = 2\n\
                  runner_group_id = 3\napp_key = \"k\"\n\
                  [github_runner.runners.r1]\nurl = \"https://github.com/o\"\n";
        for body in [
            "[containers]\nruntime = \"podman\"\n".to_string(),
            format!("[containers]\nruntime = \"podman\"\n{v2}"),
        ] {
            assert_eq!(owners(&body), ["containers"], "{body}");
        }
        assert_eq!(owners(&format!("[podman]\n{v2}")), ["podman"]);
        assert!(owners("[containers]\n").is_empty());
        // [podman] alone (runtime unset) runs Quadlets, never compose.
        let c = cfg(&format!("{host}[podman]\n{quadlet}"));
        let apply = build_module("containers", &c)
            .unwrap()
            .declaration()
            .render_apply();
        assert!(
            apply.contains("anvil-web.container") && !apply.contains("docker"),
            "{apply}"
        );
    }
    #[test]
    fn plan_builds_every_enabled_section_in_safe_order() {
        let c = cfg(r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            [users]
            [firewall]
            [updates]
        "#);
        let plan = Plan::build(&c).unwrap();
        // Every enabled section now has a module — nothing pending.
        let implemented: Vec<&str> = plan.modules.iter().map(|m| m.id()).collect();
        assert!(implemented.contains(&"sshd"));
        assert!(implemented.contains(&"firewall"));
        assert_eq!(plan.modules.len(), plan.order.len(), "every id builds");
        // Ordering safety holds: sshd before firewall, updates last.
        let pos = |id: &str| plan.order.iter().position(|m| m == id).unwrap();
        assert!(pos("sshd") < pos("firewall"));
        assert_eq!(plan.order.last().unwrap(), "updates");
    }

    #[test]
    fn plan_with_plugins_orders_and_implements_them() {
        use crate::config::schema::OrderOverride;
        use crate::engine::{Declaration, ManagedCommand};

        let c = cfg(r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            [updates]
        "#);
        let plugin = EnabledPlugin {
            id: "plugin::demo",
            order_override: OrderOverride::default(),
            declaration: Declaration::new("plugin::demo").command(ManagedCommand::new(
                "demo plugin",
                "false",
                "(\necho converge\n)",
            )),
        };
        let plan = Plan::build_with_plugins(&c, &[plugin]).unwrap();
        // In the resolved order, after built-ins but before updates.
        let pos = |id: &str| plan.order.iter().position(|m| m == id).unwrap();
        assert!(pos("sshd") < pos("plugin::demo"));
        assert!(pos("plugin::demo") < pos("updates"));
        assert_eq!(plan.order.last().unwrap(), "updates");
        // And implemented as a regular module with the engine's rendering.
        let m = plan
            .modules
            .iter()
            .find(|m| m.id() == "plugin::demo")
            .expect("plugin module present");
        assert!(m.declaration().render_apply().contains("echo converge"));
        assert_eq!(plan.modules.len(), plan.order.len());
    }

    #[test]
    fn effective_ssh_port_threads_to_every_port_sensitive_module() {
        // The registry must hand config.effective_ssh_port() — not a
        // hardcoded 22 — to every module that opens or watches the SSH port;
        // a regression here is the R56 lockout these edges exist to prevent.
        let c = cfg(r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            port = 2222
            [firewall]
            [fail2ban]
            [hetzner]
            [netcup]
            server = "7"
            [tailscale]
            tailnet_only_ssh = true
        "#);
        let plan = Plan::build(&c).unwrap();
        let decl = |id: &str| {
            plan.modules
                .iter()
                .find(|m| m.id() == id)
                .unwrap_or_else(|| panic!("{id} module present"))
                .declaration()
        };

        // firewall: the pre-enable allow targets the effective port; the
        // live host port (22 here) stays allowed for the cutover.
        let fw = decl("firewall").render_apply();
        assert!(
            fw.contains("limit 2222/tcp") && fw.contains("limit 22/tcp"),
            "effective and live ports allowed:\n{fw}"
        );

        // fail2ban: the sshd jail watches the effective port.
        let jailed = decl("fail2ban")
            .files
            .iter()
            .filter_map(|f| f.static_content())
            .any(|c| c.contains("port = 2222"));
        assert!(jailed, "sshd jail must watch the effective port");

        // tailscale: both the tailnet-scoped rule and the world-open rule
        // cleanup are pinned to the effective port.
        let ts = decl("tailscale").render_apply();
        assert!(ts.contains("port 2222 proto tcp"), "{ts}");
        assert!(ts.contains("limit 2222/tcp"), "{ts}");

        // hetzner: the cloud firewall's SSH guard covers the effective port
        // (22 may also stay open during cutover, so no absence assert).
        let hz = decl("hetzner").render_apply();
        assert!(hz.contains("2222"), "{hz}");
        let nc = decl("netcup").render_apply();
        assert!(nc.contains(r#""destinationPorts":"2222""#), "{nc}");
    }

    #[test]
    fn live_host_port_stays_open_during_a_port_move() {
        // sshd may still listen on the live host port (cutover, or
        // a failed reload that reverted), so firewall and hetzner keep it open.
        let c = cfg(r#"
            [host]
            address = "h"
            user = "u"
            port = 2200
            [sshd]
            port = 2222
            [firewall]
            [hetzner]
            [netcup]
            server = "7"
        "#);
        let plan = Plan::build(&c).unwrap();
        let apply = |id: &str| {
            plan.modules
                .iter()
                .find(|m| m.id() == id)
                .unwrap_or_else(|| panic!("{id} module present"))
                .declaration()
                .render_apply()
        };
        let fw = apply("firewall");
        let enable = fw.find("ufw --force enable").expect("enable present");
        for port in ["2222", "2200"] {
            let at = fw
                .find(&format!("ufw limit {port}/tcp"))
                .unwrap_or_else(|| panic!("{port} allowed:\n{fw}"));
            assert!(at < enable, "{port} must be allowed before enable");
        }
        let hz = apply("hetzner");
        for port in ["2222", "2200", "22"] {
            assert!(
                hz.contains(&format!("always allow SSH on tcp/{port} ")),
                "{port}:\n{hz}"
            );
        }
        let nc = apply("netcup");
        for port in ["2222", "2200", "22"] {
            assert!(
                nc.contains(&format!("always allow SSH on tcp/{port} ")),
                "{port}:\n{nc}"
            );
        }
    }

    #[test]
    fn tailnet_only_ssh_flag_reaches_the_firewall_module() {
        let firewall_apply = |toml: &str| {
            let plan = Plan::build(&cfg(toml)).unwrap();
            plan.modules
                .iter()
                .find(|m| m.id() == "firewall")
                .expect("firewall module present")
                .declaration()
                .render_apply()
        };
        // With tailscale's tightening enabled, the firewall SSH allow is gated
        // on the tailnet being confirmed up.
        let gated = firewall_apply(
            r#"
            [host]
            address = "h"
            user = "u"
            [firewall]
            [tailscale]
            tailnet_only_ssh = true
        "#,
        );
        assert!(gated.contains("tailscale ip -4"));
        // Without it (section absent, or flag unset) the allow is unconditional.
        for toml in [
            r#"
            [host]
            address = "h"
            user = "u"
            [firewall]
        "#,
            r#"
            [host]
            address = "h"
            user = "u"
            [firewall]
            [tailscale]
        "#,
        ] {
            assert!(!firewall_apply(toml).contains("tailscale ip -4"));
        }
    }

    #[test]
    fn forgejo_adds_a_fail2ban_jail_on_its_front_and_ssh_ports() {
        let jail = |extra: &str| {
            let toml = format!("[host]\naddress = \"h\"\nuser = \"u\"\n[fail2ban]\n{extra}");
            let plan = Plan::build(&cfg(&toml)).unwrap();
            let decl = plan
                .modules
                .iter()
                .find(|m| m.id() == "fail2ban")
                .expect("fail2ban present")
                .declaration();
            let has_filter = decl
                .files
                .iter()
                .any(|f| f.path == fail2ban::FORGEJO_FILTER);
            let jail = decl
                .files
                .iter()
                .find(|f| f.path == fail2ban::JAIL_FILE)
                .and_then(|f| f.static_content().map(str::to_string))
                .expect("jail file");
            (jail, has_filter)
        };
        let fj = "[forgejo]\ndomain = \"g\"\nsecret_key = \"a\"\ninternal_token = \"b\"\njwt_secret = \"c\"\n";
        let (j, filter) = jail(fj);
        assert!(
            filter && j.contains("[forgejo]\nenabled = true\nport = 443,2222\n"),
            "{j}"
        );
        let (j, _) = jail(&format!("{fj}[caddy]\nhttps_port = 8443\n"));
        assert!(j.contains("port = 8443,2222\n"), "caddy's https_port: {j}");
        let (j, filter) = jail("");
        assert!(!filter && !j.contains("[forgejo]"), "{j}");
    }

    #[test]
    fn tailscale_section_exempts_tailnet_from_fail2ban_and_crowdsec() {
        // (fail2ban jail content, crowdsec declares the whitelist file?)
        let exempt = |toml: &str| {
            let plan = Plan::build(&cfg(toml)).unwrap();
            let decl = |id: &str| {
                plan.modules
                    .iter()
                    .find(|m| m.id() == id)
                    .unwrap_or_else(|| panic!("{id} present"))
                    .declaration()
            };
            let jail = decl("fail2ban")
                .files
                .iter()
                .find(|f| f.path == fail2ban::JAIL_FILE)
                .map(|f| match &f.content {
                    crate::engine::FileContent::Static(c) => c.clone(),
                    other => panic!("static jail content expected, got {other:?}"),
                })
                .expect("jail file");
            let whitelist = decl("crowdsec")
                .files
                .iter()
                .any(|f| f.path == crowdsec::TAILNET_WHITELIST);
            (jail.contains("100.64.0.0/10"), whitelist)
        };
        let base = "[host]\naddress = \"h\"\nuser = \"u\"\n[fail2ban]\n[crowdsec]\n";
        assert_eq!(exempt(&format!("{base}[tailscale]\n")), (true, true));
        assert_eq!(exempt(base), (false, false));
    }

    #[test]
    fn ci_resources_puts_both_runners_in_the_slice() {
        let runners = r#"
            [host]
            address = "h"
            user = "u"
            [github_runner.runners.r1]
            url = "https://github.com/acme"
            [forgejo_runner]
            url = "https://git.example.org/"
            uuid = "00000000-0000-4000-8000-000000000000"
            labels = ["debian:host"]
        "#;
        for (extra, want) in [("", false), ("[ci_resources]\n", true)] {
            let c = cfg(&format!("{extra}{runners}"));
            assert_eq!(build_module("ci_resources", &c).is_some(), want);
            for id in ["github_runner", "forgejo_runner"] {
                let decl = build_module(id, &c).unwrap().declaration();
                let sliced = decl
                    .files
                    .iter()
                    .filter_map(|f| f.static_content())
                    .any(|u| u.contains("\nSlice=ci.slice\n"));
                assert_eq!(sliced, want, "{id} {extra:?}");
            }
        }
    }

    #[test]
    fn apps_resources_joins_every_app_and_is_opt_in() {
        let apps = r#"
            [host]
            address = "h"
            user = "u"
            [caddy]
            [[caddy.site]]
            domain = "git.example.com"
            upstream = "127.0.0.1:3000"
            [vector]
            [forgejo]
            domain = "git.example.com"
            secret_key = "s"
            internal_token = "t"
            jwt_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            deploy = "compose"
            [greptimedb]
        "#;
        for (extra, want) in [("", false), ("[apps_resources]\n", true)] {
            let c = cfg(&format!("{extra}{apps}"));
            assert_eq!(build_module("apps_resources", &c).is_some(), want);
            for id in ["caddy", "vector", "forgejo", "greptimedb"] {
                let decl = build_module(id, &c).unwrap().declaration();
                let file_text = |p: &str| {
                    decl.files
                        .iter()
                        .find(|f| f.path == p)
                        .and_then(|f| f.static_content())
                };
                let found = match id {
                    "caddy" => decl.files.iter().any(|f| f.path == caddy::SLICE_DROPIN),
                    "vector" => file_text(vector::UNIT_PATH)
                        .is_some_and(|u| u.contains("\nSlice=apps.slice\n")),
                    // Both deploy through a generated compose file.
                    _ => decl
                        .files
                        .iter()
                        .filter(|f| f.path.ends_with("compose.yaml"))
                        .any(|f| {
                            f.static_content()
                                .is_some_and(|y| y.contains("cgroup_parent: apps.slice\n"))
                        }),
                };
                assert_eq!(found, want, "{id} with apps_resources = {want}: {extra:?}");
                // The absent section leaves no trace, not even a path.
                if !want {
                    assert!(
                        decl.files.iter().all(|f| !f.path.contains("anvil-slice")),
                        "{id}: no drop-in without the section"
                    );
                }
            }
        }
    }
}
