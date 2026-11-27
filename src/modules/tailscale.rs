//! The `tailscale` module (R84, R62): install Tailscale, bring the node up
//! against a (self-hosted) coordination server, and optionally restrict SSH
//! ingress to the tailnet interface behind a fallback guard.
//!
//! `tailnet_only_ssh` is a real restriction: once the tailnet is **proven
//! reachable** — an established SSH connection arrives on one of this node's
//! own tailnet addresses, which is anvil's own session when it connects over
//! the tailnet — the converge ensures a tailnet-scoped ufw allow for the
//! effective SSH port and deletes the world-open rule for that port. A node
//! that merely has a tailnet IP is not enough: the operator may not be on the
//! tailnet, or an ACL may deny them. Until then no firewall change is made —
//! public SSH stays reachable (the R62 fallback guard), so a half-joined node
//! can never lock the operator out.
//!
//! Every config-derived value that reaches the shell — `login_server`,
//! `auth_key`, `hostname` — is passed through [`shell_escape`] (R55). The
//! `auth_key` is a secret: written by the `printf` builtin to a 0600 file in
//! the engine's root-only run dir and passed as `--auth-key file:<path>`, so
//! it never reaches argv (`ps`); never echoed. The SSH port is a `u16` threaded in by the
//! registry (never a hardcoded 22), safe to interpolate directly.

use crate::config::schema::TailscaleSection;
use crate::engine::{Declaration, ManagedCommand, MARK_FAILED};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// The address ranges Tailscale (and headscale's default `prefixes`) assigns
/// tailnet nodes from: the CGNAT block and Tailscale's ULA prefix. fail2ban
/// and crowdsec exempt them so the operator's own tailnet IP is never banned.
pub const TAILNET_CIDRS: [&str; 2] = ["100.64.0.0/10", "fd7a:115c:a1e0::/48"];

/// Rollback re-opens SSH that `tailnet_only_ssh` closed. Driven by the
/// live ufw rules, not the config (which may have changed since): for every
/// tailnet-scoped SSH rule, ensure a world-open allow for that port **first**,
/// then remove the scoped rule. Rollback runs in plan order, so with
/// `[firewall]` its own rollback (which re-allows the `sshd -T` ports) has
/// already run; this one is what makes `rollback --only tailscale` safe. The
/// node stays joined: commands are not undone (docs/03_operations.md).
const ROLLBACK_REOPEN_SSH: &str = r#"
# rollback (module-authored): tailscale — re-open SSH that tailnet_only_ssh closed
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep '^Status: active' >/dev/null; then
  __ts_ports=$(ufw show added 2>/dev/null | sed -n 's/^ufw allow in on tailscale0 to any port \([0-9][0-9]*\) proto tcp$/\1/p')
  [ -n "$__ts_ports" ] || printf 'OK: tailscale: no tailnet-only SSH rule; nothing to re-open\n'
  for __p in $__ts_ports; do
    if ! ufw show added 2>/dev/null | grep -E "^ufw (allow|limit) ${__p}/tcp$" >/dev/null; then
      ufw allow "${__p}/tcp" >/dev/null
    fi
    ufw delete allow in on tailscale0 to any port "$__p" proto tcp >/dev/null
    printf 'CHANGED: tailscale: SSH port %s/tcp open to the world again (tailnet-only rule removed)\n' "$__p"
  done
else
  printf 'OK: tailscale: ufw inactive; nothing to re-open\n'
fi
printf 'OK: tailscale: node stays joined (remove it in the admin console, or run tailscale logout)\n'
"#;

pub struct TailscaleModule {
    cfg: TailscaleSection,
    /// Effective SSH port (`[sshd].port`, else the host port), threaded in by
    /// the registry so the tailnet-only SSH tightening scopes the *real* port.
    ssh_port: u16,
}

impl TailscaleModule {
    pub fn new(cfg: TailscaleSection, ssh_port: u16) -> Self {
        Self { cfg, ssh_port }
    }

    /// Install Tailscale from its official apt repo, pinned to the vendor key
    /// via `signed-by=` — no vendor script piped to a shell. curl is
    /// bootstrapped first (a minimal image lacks it); the `.noarmor.gpg` key is
    /// already binary, so no gnupg is needed. Key and source are chmod'ed 0644:
    /// under a hardened `umask 027` they land 0640, and apt (Debian 13's `sqv`
    /// runs as `_apt`) then cannot read the key.
    fn install_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "install tailscale (keyring-pinned apt repo)",
            "command -v tailscale >/dev/null 2>&1",
            format!(
                "command -v curl >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
                 . /etc/os-release\n\
                 install -d -m 0755 /usr/share/keyrings\n\
                 curl -fsSL \"https://pkgs.tailscale.com/stable/$ID/$VERSION_CODENAME.noarmor.gpg\" -o /usr/share/keyrings/tailscale-archive-keyring.gpg\n\
                 printf 'deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/%s %s main\\n' \"$ID\" \"$VERSION_CODENAME\" > /etc/apt/sources.list.d/tailscale.list\n\
                 chmod 0644 /usr/share/keyrings/tailscale-archive-keyring.gpg /etc/apt/sources.list.d/tailscale.list\n\
                 {install}",
                bootstrap = apt_install(&["curl", "ca-certificates"]),
                install = apt_install(&["tailscale"]),
            ),
        )
    }

    /// The `tailscale up …` invocation (Fixed Contract R84: the flag set).
    /// Flags are only emitted for values the user actually set.
    ///
    /// Detect verifies not just that the daemon is up but that it is joined to
    /// the **configured** coordination server: a node pointed at the wrong
    /// `login_server` still passes `tailscale status`, and without the
    /// ControlURL check the converge would never re-run to move it.
    fn up_command(&self) -> ManagedCommand {
        let c = &self.cfg;
        let mut pre = String::new();
        let mut up = String::from("tailscale up");
        if !c.login_server.is_empty() {
            up.push_str(&format!(
                " --login-server {}",
                shell_escape(&c.login_server)
            ));
        }
        // The key stays off argv. `--auth-key file:` exists since
        // Tailscale v1.16.0 (commit b822b5c). `printf` is a builtin, so no
        // child process carries the key; `$__rundir` is the engine's 0700
        // mktemp dir, removed by its EXIT trap on success and failure alike.
        if !c.auth_key.is_empty() {
            pre = format!(
                "(umask 077; printf '%s\\n' {} > \"$__rundir/tailscale-authkey\")\n",
                shell_escape(&c.auth_key)
            );
            up.push_str(" --auth-key \"file:$__rundir/tailscale-authkey\"");
        }
        if c.accept_routes {
            up.push_str(" --accept-routes");
        }
        if let Some(h) = &c.hostname {
            if !h.is_empty() {
                up.push_str(&format!(" --hostname {}", shell_escape(h)));
            }
        }
        // `tailscale status` exits non-zero when logged out / stopped; the
        // prefs check additionally pins the ControlURL to the configured
        // login server (only when one is configured).
        let mut detect = String::from("tailscale status >/dev/null 2>&1");
        if !c.login_server.is_empty() {
            detect.push_str(&format!(
                " && tailscale debug prefs 2>/dev/null | grep -F ControlURL | grep -F {} >/dev/null",
                shell_escape(&c.login_server)
            ));
        }
        // Converge re-runs the full `tailscale up`, which also re-points a
        // node joined to the wrong login server.
        if !pre.is_empty() {
            up = format!("{pre}{up}\nrm -f \"$__rundir/tailscale-authkey\"");
        } else {
            // No key: a node that must log in would wait for a browser login
            // forever. Fail fast and say what to do instead.
            up = format!(
                "{up} --timeout 30s || {{ printf '%s\\n' '{MARK_FAILED} tailscale: not logged in and [tailscale] auth_key is empty: \
                 set auth_key = \"${{TAILSCALE_AUTH_KEY}}\", or run `sudo tailscale up` on the host once'; false; }}"
            );
        }
        ManagedCommand::new("bring tailscale up", detect, up)
    }

    /// The tailnet-only SSH tightening (declared **after** [`Self::up_command`]).
    ///
    /// Aligned when ufw is active and either the tightened state holds (tailnet
    /// up, scoped rule present, world-open rule gone) or the R62 fallback does
    /// (no SSH session over the tailnet yet, world-open rule present).
    ///
    /// The converge drops the world-open rule only when the tailnet is
    /// **proven reachable**: an established connection to the SSH port whose
    /// local address is one of this node's tailnet IPs — anvil's own session
    /// when `[host] address` is the tailnet name/IP. A tailnet IP alone is not
    /// proof (the operator may not be on the tailnet, or an ACL may deny
    /// them). Otherwise it changes nothing and says so. Deletion tolerates
    /// absence and covers both the plain `allow` and rate-limited `limit`
    /// forms the firewall module may have added.
    fn tailnet_only_ssh_command(&self) -> ManagedCommand {
        let port = self.ssh_port;
        // The scoped rule exactly as `ufw show added` prints it.
        let scoped = format!("allow in on tailscale0 to any port {port} proto tcp");
        let scoped_needle = shell_escape(&scoped);
        let world_allow = shell_escape(&format!("allow {port}/tcp"));
        let world_limit = shell_escape(&format!("limit {port}/tcp"));
        let tailnet_up = "__ts_ip=$(tailscale ip -4 2>/dev/null) && [ -n \"$__ts_ip\" ]";
        // An established SSH connection whose *local* address (`ss` column 3
        // under a state filter) is one of our tailnet IPs, in the forms ss
        // prints: `100.x.y.z:P`, `[::ffff:100.x.y.z]:P`, `[fd7a:…]:P`.
        let via_tailnet = format!(
            "ss -Htn state established '( sport = :{port} )' 2>/dev/null | awk '{{print $3}}' \
             | grep -xF -f <(tailscale ip 2>/dev/null | awk -v p={port} 'NF {{ if (index($0, \":\")) \
             print \"[\" $0 \"]:\" p; else {{ print $0 \":\" p; print \"[::ffff:\" $0 \"]:\" p }} }}') \
             >/dev/null"
        );
        let world_open = format!(
            "{{ ufw show added 2>/dev/null | grep -wF {world_allow} >/dev/null \
             || ufw show added 2>/dev/null | grep -wF {world_limit} >/dev/null; }}"
        );
        // `ufw show added` lists rules even while ufw is disabled, so detect
        // first requires ufw active.
        let detect = format!(
            "ufw status 2>/dev/null | grep -i 'Status: active' >/dev/null && {{ \
             {{ {tailnet_up} \
             && ufw show added 2>/dev/null | grep -wF {scoped_needle} >/dev/null \
             && ! {world_open}; }} \
             || {{ ! {{ {via_tailnet}; }} && {world_open}; }}; }}"
        );
        let converge = format!(
            "if ! command -v ufw >/dev/null 2>&1; then\n\
             \x20 printf 'ufw not installed; SSH ingress left unchanged\\n'\n\
             elif {via_tailnet}; then\n\
             \x20 ufw {scoped}\n\
             \x20 ufw delete allow {port}/tcp >/dev/null 2>&1 || true\n\
             \x20 ufw delete limit {port}/tcp >/dev/null 2>&1 || true\n\
             elif {tailnet_up}; then\n\
             \x20 printf 'tailnet up, but no SSH session arrives over it; keeping public SSH on port {port} open (set [host] address to the tailnet name/IP to tighten)\\n'\n\
             else\n\
             \x20 printf 'tailnet not confirmed up; keeping public SSH on port {port} open (no firewall change)\\n'\n\
             fi"
        );
        ManagedCommand::new(
            format!(
                "restrict ssh on port {port} to the tailnet interface \
                 (drop the world-open rule once SSH is proven to work over the tailnet)"
            ),
            detect,
            converge,
        )
    }
}

impl Module for TailscaleModule {
    fn id(&self) -> &'static str {
        "tailscale"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("tailscale")
            .secret(&self.cfg.auth_key)
            .command(self.install_command())
            .command(self.up_command());
        if self.cfg.tailnet_only_ssh {
            // Declared after `tailscale up` so the tailnet has had its chance
            // to come up before we ever consider dropping the public rule.
            decl = decl.command(self.tailnet_only_ssh_command());
        }
        // Unconditional: a scoped rule from an earlier tailnet_only_ssh run
        // must be undoable even after the flag was turned off.
        decl.rollback_script(ROLLBACK_REOPEN_SSH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module_on_port(port: u16, mutate: impl FnOnce(&mut TailscaleSection)) -> TailscaleModule {
        let mut cfg = TailscaleSection {
            login_server: String::new(),
            auth_key: String::new(),
            hostname: None,
            accept_routes: false,
            tailnet_only_ssh: false,
            order_override: Default::default(),
        };
        mutate(&mut cfg);
        TailscaleModule::new(cfg, port)
    }

    fn module(mutate: impl FnOnce(&mut TailscaleSection)) -> TailscaleModule {
        module_on_port(22, mutate)
    }

    #[test]
    fn installs_and_brings_up() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("tailscale up"));
    }

    #[test]
    fn install_uses_pinned_repo_not_pipe_to_shell() {
        // Keyring-pinned apt source, curl bootstrapped first, and no
        // vendor script piped to a root shell.
        let c = module(|_| {}).install_command().converge;
        assert!(!c.contains("| sh") && !c.contains("| bash"));
        assert!(!c.contains("install.sh"));
        let bootstrap = c
            .find("command -v curl >/dev/null 2>&1 || {")
            .expect("curl bootstrap");
        let key = c.find("tailscale-archive-keyring.gpg").expect("keyring");
        let source = c
            .find("deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg]")
            .expect("signed-by source");
        let install = c.find("install -y -- 'tailscale'").expect("install");
        assert!(bootstrap < key && key < source && source < install);
    }

    #[test]
    fn keyring_and_source_are_world_readable_before_install() {
        // Under the CIS `umask 027` both files land 0640 and apt's `_apt`
        // verifier cannot read the key (seen on Debian 13): chmod after the
        // writes, before apt runs.
        let c = module(|_| {}).install_command().converge;
        let source = c
            .find("> /etc/apt/sources.list.d/tailscale.list")
            .expect("source write");
        let chmod = c
            .find(
                "chmod 0644 /usr/share/keyrings/tailscale-archive-keyring.gpg \
                 /etc/apt/sources.list.d/tailscale.list",
            )
            .expect("chmod 0644 of key and source");
        let install = c.find("install -y -- 'tailscale'").expect("install");
        assert!(source < chmod && chmod < install);
    }

    #[test]
    fn up_flags_are_conditional_and_escaped() {
        let apply = module(|c| {
            c.login_server = "https://hs.example.com".into();
            c.auth_key = "tskey-auth-abc".into();
            c.accept_routes = true;
            c.hostname = Some("edge-1".into());
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("--login-server 'https://hs.example.com'"));
        assert!(apply.contains("--auth-key \"file:$__rundir/tailscale-authkey\""));
        assert!(apply.contains("--accept-routes"));
        assert!(apply.contains("--hostname 'edge-1'"));
    }

    #[test]
    fn secret_and_hostname_injection_is_neutralized() {
        let apply = module(|c| {
            c.auth_key = "k'; rm -rf / #".into();
            c.hostname = Some("h$(reboot)".into());
        })
        .declaration()
        .render_apply();
        // The payloads survive only inside single quotes.
        assert!(apply.contains("'k'\\''; rm -rf / #'"));
        assert!(apply.contains("'h$(reboot)'"));
        assert!(!apply.contains("--auth-key k'; rm"));
    }

    #[test]
    fn without_auth_key_up_fails_fast_with_a_hint() {
        let up = module(|_| {}).up_command().converge;
        assert!(up.starts_with("tailscale up --timeout 30s || {"), "{up}");
        assert!(
            up.contains(&format!(
                "'{MARK_FAILED} tailscale: not logged in and [tailscale] auth_key is empty"
            )),
            "{up}"
        );
        assert!(up.ends_with("false; }"), "{up}");
        // With a key, no timeout: a first join may take longer.
        let up = module(|c| c.auth_key = "k".into()).up_command().converge;
        assert!(!up.contains("--timeout"), "{up}");
    }

    /// R56-style safety: with no key on a logged-out node, the failed `up`
    /// stops the module, so the tailnet-only SSH step after it never runs.
    #[test]
    fn keyless_up_failure_stops_before_the_ssh_tightening() {
        let decl = module(|c| c.tailnet_only_ssh = true).declaration();
        let names: Vec<_> = decl.commands.iter().map(|c| c.describe.as_str()).collect();
        let up = names
            .iter()
            .position(|n| *n == "bring tailscale up")
            .unwrap();
        assert_eq!(
            up + 1,
            names.len() - 1,
            "tightening is the step after up: {names:?}"
        );
        let dir = std::env::temp_dir().join(format!("anvil-ts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tailscale"), "#!/bin/sh\nexit 1\n").unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(dir.join("tailscale"))
            .status()
            .unwrap();
        // The engine's context: converge inside an `else` branch, under -eu.
        let script = format!(
            "if false; then :; else\n{}\nfi\necho TIGHTENING-RAN",
            decl.commands[up].converge
        );
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .env(
                "PATH",
                format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!out.status.success(), "{stdout}");
        assert!(!stdout.contains("TIGHTENING-RAN"), "{stdout}");
        assert!(stdout.contains("auth_key is empty"), "{stdout}");
    }

    #[test]
    fn auth_key_never_on_tailscale_argv() {
        let apply = module(|c| c.auth_key = "tskey-auth-secret".into())
            .declaration()
            .render_apply();
        let up = apply
            .lines()
            .find(|l| l.trim_start().starts_with("tailscale up"))
            .expect("tailscale up line");
        assert!(!up.contains("tskey-auth-secret"), "{up}");
        assert!(up.contains("--auth-key \"file:$__rundir/tailscale-authkey\""));
        // Only the builtin printf sees the key, into a 0600 file.
        let lines: Vec<_> = apply.lines().filter(|l| l.contains("tskey")).collect();
        assert_eq!(
            lines,
            ["(umask 077; printf '%s\\n' 'tskey-auth-secret' > \"$__rundir/tailscale-authkey\")"]
        );
        // Written before `up`, removed right after, and the engine's EXIT trap
        // removes the run dir if `up` fails.
        let write = apply.find("umask 077").expect("write");
        let up_at = apply.find("\ntailscale up").expect("up");
        let rm = apply
            .find("rm -f \"$__rundir/tailscale-authkey\"")
            .expect("rm");
        let trap = apply.find("trap 'rm -rf \"$__rundir\";").expect("trap");
        assert!(trap < write && write < up_at && up_at < rm);
        // The wide gate config sets no auth_key, so parse this script here, and
        // run the write line for real: the file lands 0600 with the key.
        let bash = |script: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .output()
        };
        let Ok(out) = bash(&format!("bash -n <<'__EOF__'\n{apply}\n__EOF__")) else {
            return;
        };
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let out = bash(&format!(
            "set -euo pipefail; umask 022; __rundir=$(mktemp -d); trap 'rm -rf \"$__rundir\"' EXIT\n\
             {}\n\
             [ -n \"$(find \"$__rundir/tailscale-authkey\" -perm 600)\" ]\n\
             cat \"$__rundir/tailscale-authkey\"",
            lines[0]
        ))
        .expect("bash");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "tskey-auth-secret\n");
        // The probe never touches the key.
        let probe = module(|c| c.auth_key = "tskey-auth-secret".into())
            .declaration()
            .render_probe();
        assert!(!probe.contains("tskey-auth-secret"));
    }

    #[test]
    fn no_flags_when_unset() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(!apply.contains("--login-server"));
        assert!(!apply.contains("--auth-key"));
        assert!(!apply.contains("--accept-routes"));
        assert!(!apply.contains("--hostname"));
    }

    #[test]
    fn up_detect_verifies_configured_login_server() {
        let decl = module(|c| c.login_server = "https://hs.example.com".into()).declaration();
        let probe = decl.render_probe();
        // A node joined to the WRONG control server still passes plain
        // `tailscale status`; detect must pin the configured ControlURL.
        assert!(probe.contains("tailscale status >/dev/null 2>&1"));
        assert!(probe.contains("tailscale debug prefs"));
        assert!(probe.contains("grep -F ControlURL"));
        assert!(probe.contains("grep -F 'https://hs.example.com' >/dev/null"));
        // Converge re-runs the full up invocation.
        let apply = decl.render_apply();
        assert!(apply.contains("tailscale up --login-server 'https://hs.example.com'"));
    }

    #[test]
    fn up_detect_skips_login_server_check_when_unset() {
        let probe = module(|_| {}).declaration().render_probe();
        assert!(probe.contains("tailscale status >/dev/null 2>&1"));
        assert!(!probe.contains("ControlURL"));
    }

    #[test]
    fn tailnet_only_ssh_is_opt_in() {
        let off = module(|_| {}).declaration();
        assert_eq!(off.commands.len(), 2);
        let on = module(|c| c.tailnet_only_ssh = true).declaration();
        assert_eq!(on.commands.len(), 3);
    }

    #[test]
    fn restrict_step_uses_effective_port_not_22() {
        let decl = module_on_port(2222, |c| c.tailnet_only_ssh = true).declaration();
        for s in [decl.render_probe(), decl.render_apply()] {
            assert!(s.contains("allow in on tailscale0 to any port 2222 proto tcp"));
            // No hardcoded default port anywhere in the restrict wiring.
            assert!(!s.contains(" 22/tcp") && !s.contains("port 22 "), "{s}");
        }
    }

    #[test]
    fn restrict_detect_requires_up_scoped_present_and_world_open_gone() {
        let probe = module_on_port(2222, |c| c.tailnet_only_ssh = true)
            .declaration()
            .render_probe();
        // Tailnet confirmed up…
        assert!(probe.contains("__ts_ip=$(tailscale ip -4 2>/dev/null) && [ -n \"$__ts_ip\" ]"));
        // …AND scoped rule present…
        assert!(probe
            .contains("grep -wF 'allow in on tailscale0 to any port 2222 proto tcp' >/dev/null"));
        // …AND both world-open forms gone; the fallback asks for a tailnet session.
        assert!(probe.contains("grep -wF 'allow 2222/tcp' >/dev/null"));
        assert!(probe.contains("grep -wF 'limit 2222/tcp' >/dev/null"));
        assert!(probe.contains("ss -Htn state established '( sport = :2222 )'"));
    }

    /// Stub `ufw`/`tailscale`/`ss` on PATH; `ufw` mutations are logged to
    /// `$UFW_LOG`. [`Stubs::run`] returns `None` when bash cannot run here.
    struct Stubs {
        dir: std::path::PathBuf,
    }

    impl Stubs {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("anvil-ts-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let stub = |name: &str, body: &str| {
                let p = dir.join(name);
                std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
                std::process::Command::new("chmod")
                    .arg("+x")
                    .arg(&p)
                    .status()
                    .unwrap();
            };
            stub(
                "ufw",
                "case \"$1\" in status) printf 'Status: %s\\n' \"$UFW_STATE\" ;; \
                 show) printf 'Added user rules:\\n%b' \"$UFW_RULES\" ;; \
                 *) echo \"$*\" >> \"$UFW_LOG\" ;; esac",
            );
            stub(
                "tailscale",
                "[ -n \"$TS_IP\" ] || exit 1; echo \"$TS_IP\"; \
                 [ \"${2:-}\" = -4 ] || [ -z \"${TS_IP6:-}\" ] || echo \"$TS_IP6\"",
            );
            // Prints `Recv-Q Send-Q Local Peer` rows like `ss -Htn state …`.
            stub("ss", "printf '%b' \"$SS_OUT\"");
            Self { dir }
        }

        /// Run `script` with the given state; returns (success, stdout, ufw log).
        fn run(
            &self,
            script: &str,
            ufw_state: &str,
            ts_ip: &str,
            rules: &str,
            ss_local: &str,
        ) -> Option<(bool, String, String)> {
            let log = self.dir.join("ufw.log");
            let _ = std::fs::remove_file(&log);
            let ss_out = if ss_local.is_empty() {
                String::new()
            } else {
                format!("0 0 {ss_local} 198.51.100.7:50000\\n")
            };
            let out = std::process::Command::new("bash")
                .args(["-euo", "pipefail", "-c", script])
                .env(
                    "PATH",
                    format!("{}:{}", self.dir.display(), std::env::var("PATH").unwrap()),
                )
                .env("UFW_STATE", ufw_state)
                .env("TS_IP", ts_ip)
                .env(
                    "TS_IP6",
                    if ts_ip.is_empty() {
                        ""
                    } else {
                        "fd7a:115c:a1e0::1"
                    },
                )
                .env("UFW_RULES", rules)
                .env("SS_OUT", ss_out)
                .env("UFW_LOG", &log)
                .output()
                .ok()?;
            let ufw_log = std::fs::read_to_string(&log).unwrap_or_default();
            Some((
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
                ufw_log,
            ))
        }
    }

    impl Drop for Stubs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    const SCOPED: &str = "ufw allow in on tailscale0 to any port 2222 proto tcp\\n";
    const WORLD: &str = "ufw limit 2222/tcp\\n";

    #[test]
    fn restrict_detect_agrees_with_reachability() {
        // Reachability gate: run the real detect against stubs.
        let stubs = Stubs::new("det");
        let detect = module_on_port(2222, |c| c.tailnet_only_ssh = true)
            .tailnet_only_ssh_command()
            .detect;
        let script = format!("if {detect}; then exit 0; else exit 1; fi");
        let aligned = |ufw: &str, ip: &str, rules: &str, ss: &str| {
            stubs.run(&script, ufw, ip, rules, ss).map(|r| r.0)
        };
        let Some(tightened) = aligned("active", "100.64.0.1", SCOPED, "") else {
            return;
        };
        assert!(tightened, "tailnet up + scoped only + ufw active");
        assert_eq!(
            aligned("inactive", "100.64.0.1", SCOPED, ""),
            Some(false),
            "ufw disabled: SSH is world-reachable, never aligned"
        );
        assert_eq!(
            aligned("active", "", WORLD, ""),
            Some(true),
            "tailnet down + world-open kept is the converged fallback"
        );
        assert_eq!(aligned("inactive", "", WORLD, ""), Some(false));
        assert_eq!(
            aligned("active", "100.64.0.1", WORLD, "203.0.113.5:2222"),
            Some(true),
            "tailnet up but anvil came in over the public IP: fallback is converged"
        );
        assert_eq!(
            aligned(
                "active",
                "100.64.0.1",
                &format!("{SCOPED}{WORLD}"),
                "100.64.0.1:2222"
            ),
            Some(false),
            "SSH proven over the tailnet: the world-open rule must still be dropped"
        );
        assert_eq!(aligned("active", "", "", ""), Some(false));
    }

    #[test]
    fn restrict_converge_tightens_only_when_ssh_arrives_over_the_tailnet() {
        let stubs = Stubs::new("conv");
        let converge = module_on_port(2222, |c| c.tailnet_only_ssh = true)
            .tailnet_only_ssh_command()
            .converge;
        let run = |ss: &str| stubs.run(&converge, "active", "100.64.0.1", WORLD, ss);
        let Some((ok, _, log)) = run("100.64.0.1:2222") else {
            return;
        };
        assert!(ok);
        assert!(
            log.contains("allow in on tailscale0 to any port 2222 proto tcp"),
            "{log}"
        );
        assert!(log.contains("delete allow 2222/tcp") && log.contains("delete limit 2222/tcp"));

        // The lockout this gate exists for: the node is on the tailnet, but
        // anvil (and so the operator) reached it over the public IP.
        let (ok, out, log) = run("203.0.113.5:2222").unwrap();
        assert!(ok);
        assert!(
            log.is_empty(),
            "no ufw change without a tailnet session: {log}"
        );
        assert!(out.contains("no SSH session arrives over it"), "{out}");

        // A tailnet session on another port proves nothing for this one.
        let (_, _, log) = run("100.64.0.1:22").unwrap();
        assert!(log.is_empty(), "{log}");

        // IPv6 and v4-mapped forms of our own tailnet address count.
        for local in ["[fd7a:115c:a1e0::1]:2222", "[::ffff:100.64.0.1]:2222"] {
            let (_, _, log) = run(local).unwrap();
            assert!(log.contains("delete allow 2222/tcp"), "{local}: {log}");
        }

        // Tailnet down: report, change nothing.
        let (ok, out, log) = stubs.run(&converge, "active", "", WORLD, "").unwrap();
        assert!(ok);
        assert!(log.is_empty(), "{log}");
        assert!(out.contains("tailnet not confirmed up"), "{out}");
    }

    #[test]
    fn world_open_deletion_only_in_confirmed_branch() {
        let apply = module_on_port(2222, |c| c.tailnet_only_ssh = true)
            .declaration()
            .render_apply();
        // The converge gates on a tailnet SSH session before any deletion…
        let gate = apply
            .find("elif ss -Htn state established '( sport = :2222 )'")
            .expect("tailnet-session gate present in converge");
        let ensure = apply
            .find("ufw allow in on tailscale0 to any port 2222 proto tcp\n")
            .expect("scoped ensure present");
        let del_allow = apply
            .find("ufw delete allow 2222/tcp >/dev/null 2>&1 || true")
            .expect("world-open allow deletion present (tolerating absence)");
        let del_limit = apply
            .find("ufw delete limit 2222/tcp >/dev/null 2>&1 || true")
            .expect("world-open limit deletion present (tolerating absence)");
        assert!(gate < ensure && ensure < del_allow && del_allow < del_limit);
        // …and both fallback branches report clearly and change nothing.
        let not_via = apply
            .find("tailnet up, but no SSH session arrives over it; keeping public SSH on port 2222 open")
            .expect("not-reachable report present");
        let fallback = apply
            .find("tailnet not confirmed up; keeping public SSH on port 2222 open (no firewall change)")
            .expect("fallback report present");
        assert!(
            del_limit < not_via && not_via < fallback,
            "deletions live in the confirmed branch only"
        );
        assert!(!apply[not_via..].contains("ufw delete"));
    }

    #[test]
    fn rollback_reopens_world_ssh_before_removing_the_scoped_rule() {
        // Run the real rollback snippet against stub ufw.
        let stubs = Stubs::new("rb");
        let rb = module(|_| {})
            .declaration()
            .rollback
            .expect("rollback script");
        let run = |ufw: &str, rules: &str| stubs.run(&rb, ufw, "", rules, "");
        let Some((ok, out, log)) = run("active", SCOPED) else {
            return;
        };
        assert!(ok, "{out}");
        let allow = log.find("allow 2222/tcp\n").expect("world allow re-added");
        let delete = log
            .find("delete allow in on tailscale0 to any port 2222 proto tcp")
            .expect("scoped rule removed");
        assert!(
            allow < delete,
            "re-open before removing the scoped rule: {log}"
        );
        assert!(
            out.contains("CHANGED: tailscale: SSH port 2222/tcp open to the world again"),
            "{out}"
        );

        // World rule already back (e.g. firewall's rollback ran first): only
        // the scoped rule goes.
        let (_, _, log) = run("active", &format!("{SCOPED}{WORLD}")).unwrap();
        assert_eq!(
            log.trim(),
            "delete allow in on tailscale0 to any port 2222 proto tcp"
        );

        // Every scoped port is handled, independent of the configured one.
        let two = format!("{SCOPED}ufw allow in on tailscale0 to any port 22 proto tcp\\n");
        let (_, _, log) = run("active", &two).unwrap();
        assert!(
            log.contains("allow 22/tcp\n") && log.contains("allow 2222/tcp\n"),
            "{log}"
        );

        // Nothing scoped, or ufw inactive: no mutation, OK markers only.
        for (ufw, rules) in [("active", WORLD), ("inactive", SCOPED)] {
            let (ok, out, log) = run(ufw, rules).unwrap();
            assert!(ok);
            assert!(log.is_empty(), "{ufw}: {log}");
            assert!(!out.contains("CHANGED:"), "{out}");
            assert!(out.contains("OK: tailscale: node stays joined"), "{out}");
        }
    }

    #[test]
    fn rollback_is_declared_even_without_tailnet_only_ssh() {
        // A scoped rule from an earlier run must stay undoable after the flag
        // is turned off.
        for flag in [false, true] {
            let decl = module(|c| c.tailnet_only_ssh = flag).declaration();
            assert!(decl
                .render_rollback()
                .contains("re-open SSH that tailnet_only_ssh closed"));
        }
    }
}
