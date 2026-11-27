//! The `firewall` module (R64, R56): renders `ufw` commands in a lockout-safe
//! order.
//!
//! Because the engine runs a declaration's commands in declaration order, the
//! *order* in which we declare them is the safety mechanism. We declare, in
//! this exact sequence:
//!
//! 1. ensure `ufw` is installed,
//! 2. `ufw default <in> incoming` / `ufw default <out> outgoing`,
//! 3. an allow (or rate-limited `limit`) rule for the SSH port — **before** the
//!    firewall is ever enabled (R56),
//! 4. user allow/deny rules,
//! 5. `ufw --force enable` **last**.
//!
//! Enabling the firewall before permitting SSH is a spec violation; the
//! declaration order above is what makes that impossible.

use crate::config::schema::{FirewallSection, WallRule};
use crate::engine::{Declaration, ManagedCommand};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// Rollback leaves ufw active with its rules (undoing a firewall is
/// itself a risk), but a rolled-back sshd may now listen on a port ufw never
/// allowed — e.g. back on 22 after a port move. Rollback runs sshd and
/// ssh_crypto before the firewall (`order::rollback_order`), so this
/// runs after sshd's rollback and reload: allow every port the
/// restored sshd config listens on that has no rule yet.
const ROLLBACK_KEEP_SSH: &str = r#"
# rollback (module-authored): firewall — rules stay; keep restored sshd reachable
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep '^Status: active' >/dev/null; then
  for __p in $(sshd -T 2>/dev/null | awk '$1=="port"{print $2}'); do
    if ufw status | grep -E "^${__p}(/tcp)?[[:space:]]+(ALLOW|LIMIT)" >/dev/null; then
      printf 'OK: firewall already allows sshd port %s
' "$__p"
    else
      ufw allow "${__p}/tcp" >/dev/null
      printf 'CHANGED: firewall allowed sshd port %s/tcp after rollback
' "$__p"
    fi
  done
else
  printf 'OK: firewall inactive; nothing to keep open
'
fi
"#;

pub struct FirewallModule {
    cfg: FirewallSection,
    /// Effective SSH port (`[sshd].port`, else the host port), threaded in by the
    /// registry so the pre-enable allow rule matches the real port (R56). Without
    /// this, a non-default SSH port would be firewalled off — a lockout.
    ssh_port: u16,
    /// True when the tailscale section is enabled with `tailnet_only_ssh = true`
    /// (threaded in by the registry). It makes the SSH-allow step
    /// runtime-conditional so a later `anvil apply` does not re-open SSH to the
    /// world after the tailscale module has scoped it to the tailnet — while
    /// still falling back to the world-open allow whenever the tailnet is not
    /// confirmed up (never risk lockout, R56/R62).
    tailnet_only_ssh: bool,
    /// Live host ports other than `ssh_port` ([`crate::config::Config::live_ssh_ports`]):
    /// sshd may still listen there mid port-move, so they are allowed too.
    live_ports: Vec<u16>,
}

impl FirewallModule {
    pub fn new(
        cfg: FirewallSection,
        ssh_port: u16,
        tailnet_only_ssh: bool,
        live_ports: Vec<u16>,
    ) -> Self {
        Self {
            cfg,
            ssh_port,
            tailnet_only_ssh,
            live_ports,
        }
    }
}

/// Ensure `ufw` is installed before any rule is declared. The converge refreshes
/// package lists first — a fresh box has stale/empty lists and the install would
/// otherwise fail — while detect stays a cheap `command -v` so no refresh runs
/// when ufw is already installed.
fn ensure_ufw() -> ManagedCommand {
    ManagedCommand::new(
        "ensure ufw installed",
        "command -v ufw >/dev/null 2>&1",
        // dpkg lock-wait (R109) so apt tolerates a transient lock on a fresh box.
        apt_install(&["ufw"]),
    )
}

/// A default-policy command (`ufw default <policy> <direction>`). `direction`
/// is a trusted literal (`incoming`/`outgoing`); `policy` is config-derived and
/// is shell-escaped.
fn default_policy(direction: &str, policy: &str) -> ManagedCommand {
    let policy_esc = shell_escape(policy);
    // `direction` is a trusted literal ("incoming"/"outgoing"), so it is not
    // escaped; `policy` is config-derived and is.
    // `ufw status verbose` prints e.g.
    // "Default: deny (incoming), allow (outgoing), disabled (routed)".
    let needle = shell_escape(&format!("{policy} ({direction})"));
    ManagedCommand::new(
        format!("default {direction} policy {policy}"),
        format!("LANG=C ufw status verbose 2>/dev/null | grep -iF {needle} >/dev/null"),
        format!("ufw default {policy_esc} {direction}"),
    )
}

/// Permit the SSH port. `restrict` selects `ufw limit` (connection
/// rate-limiting, still permits SSH) over a plain `ufw allow`; either way SSH is
/// never dropped, so R56 holds. Declared **before** [`enable_cmd`].
///
/// With `tailnet_only_ssh` the step becomes **runtime-conditional**: when the
/// tailnet is confirmed up (`tailscale ip -4` returns an address) *and* the
/// tailnet-scoped SSH rule already exists, the step keeps the scoped rule and
/// does **not** re-add the world-open allow (which would undo the tailscale
/// module's tightening on every re-apply). In every other case it falls back to
/// the world-open allow exactly as without the flag — SSH is never left
/// unpermitted before enable, so R56 holds. Detect and converge evaluate the
/// same condition.
fn allow_ssh(restrict: bool, ssh_port: u16, tailnet_only_ssh: bool) -> ManagedCommand {
    let action = if restrict { "limit" } else { "allow" };
    // `ssh_port` is a u16 (not attacker-controlled text), so the spec is safe to
    // interpolate directly.
    let spec = format!("{action} {ssh_port}/tcp");
    let needle = shell_escape(&spec);
    if !tailnet_only_ssh {
        return ManagedCommand::new(
            format!("{action} ssh on port {ssh_port}/tcp"),
            format!("ufw show added 2>/dev/null | grep -wF {needle} >/dev/null"),
            format!("ufw {spec}"),
        );
    }
    // The tailnet-scoped rule as `ufw show added` prints it (and as the
    // tailscale module adds it).
    let scoped = format!("allow in on tailscale0 to any port {ssh_port} proto tcp");
    let scoped_needle = shell_escape(&scoped);
    // Shared condition: tailnet confirmed up AND the scoped rule is in place.
    let tailnet_confirmed = format!(
        "__fw_ts_ip=$(tailscale ip -4 2>/dev/null) && [ -n \"$__fw_ts_ip\" ] \
         && ufw show added 2>/dev/null | grep -wF {scoped_needle} >/dev/null"
    );
    // Aligned when the tightened state holds, or when the world-open allow is in
    // place (the safe fallback state).
    let detect = format!(
        "{{ {tailnet_confirmed}; }} || ufw show added 2>/dev/null | grep -wF {needle} >/dev/null"
    );
    // Converge re-evaluates the same condition at run time: keep/ensure the
    // scoped rule when the tailnet is confirmed, otherwise world-open as usual.
    let converge = format!(
        "if {tailnet_confirmed}; then\n\
         \x20 ufw {scoped}\n\
         else\n\
         \x20 ufw {spec}\n\
         fi"
    );
    ManagedCommand::new(
        format!(
            "{action} ssh on port {ssh_port}/tcp (tailnet-scoped once the tailnet is confirmed up)"
        ),
        detect,
        converge,
    )
}

/// The *unescaped* idempotency token for a rule — matched whole-word, as a
/// fixed string (`grep -qwF`) against `ufw show added`, whose lines mirror the
/// command that added them (proto resolved to `<port>/<proto>`, comments
/// re-quoted, which we deliberately exclude from the needle). Extracted so the
/// detect/converge agreement can be pinned against real `ufw` output.
pub(crate) fn rule_needle(action: &str, rule: &WallRule) -> String {
    let mut needle = action.to_string();
    if let Some(from) = rule.from.as_deref() {
        let from = canonical_from(from);
        needle.push_str(&format!(" from {from} to any port {}", rule.port));
        if let Some(proto) = rule.proto.as_deref() {
            needle.push_str(&format!(" proto {proto}"));
        }
    } else if let Some(proto) = rule.proto.as_deref() {
        needle.push_str(&format!(" {}/{proto}", rule.port));
    } else {
        needle.push_str(&format!(" {}", rule.port));
    }
    needle
}

/// A `from` address as ufw stores it: ufw normalizes before saving, so
/// `10.0.0.5/24` becomes `10.0.0.0/24` and `2001:DB8:0:0::1` becomes
/// `2001:db8::1`. Matching the operator's literal spelling would never find the
/// rule — perpetual drift. Unparseable input (rejected by `validate_cidr`
/// anyway) is returned unchanged.
fn canonical_from(from: &str) -> String {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let (ip, prefix) = match from.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (from, None),
    };
    let Ok(ip) = ip.parse::<IpAddr>() else {
        return from.to_string();
    };
    let Some(prefix) = prefix else {
        return ip.to_string();
    };
    let Ok(n) = prefix.parse::<u32>() else {
        return from.to_string();
    };
    // ufw stores a full-length prefix as the bare address (observed on ufw
    // 0.36.2: `10.0.0.7/32` -> `10.0.0.7`, `2001:db8::7/128` -> `2001:db8::7`).
    if matches!((ip, n), (IpAddr::V4(_), 32) | (IpAddr::V6(_), 128)) {
        return ip.to_string();
    }
    // Mask the host bits; a shift by the full width (prefix 0) masks everything.
    let net = match ip {
        IpAddr::V4(a) if n <= 32 => IpAddr::V4(Ipv4Addr::from(
            u32::from(a) & u32::MAX.checked_shl(32 - n).unwrap_or(0),
        )),
        IpAddr::V6(a) if n <= 128 => IpAddr::V6(Ipv6Addr::from(
            u128::from(a) & u128::MAX.checked_shl(128 - n).unwrap_or(0),
        )),
        _ => return from.to_string(),
    };
    format!("{net}/{n}")
}

/// The escaped `ufw` command that converges a rule (run on apply).
pub(crate) fn rule_converge(action: &str, rule: &WallRule) -> String {
    let mut converge = format!("ufw {action}");
    if let Some(from) = rule.from.as_deref() {
        converge.push_str(&format!(
            " from {} to any port {}",
            shell_escape(from),
            shell_escape(&rule.port)
        ));
        if let Some(proto) = rule.proto.as_deref() {
            converge.push_str(&format!(" proto {}", shell_escape(proto)));
        }
    } else if let Some(proto) = rule.proto.as_deref() {
        converge.push_str(&format!(
            " {}/{}",
            shell_escape(&rule.port),
            shell_escape(proto)
        ));
    } else {
        converge.push_str(&format!(" {}", shell_escape(&rule.port)));
    }
    if let Some(comment) = rule.comment.as_deref() {
        converge.push_str(&format!(" comment {}", shell_escape(comment)));
    }
    converge
}

/// A user allow/deny rule. `action` is a trusted literal (`allow`/`deny`); every
/// value drawn from [`WallRule`] is shell-escaped.
fn rule_command(action: &str, rule: &WallRule) -> ManagedCommand {
    let needle = rule_needle(action, rule);
    let converge = rule_converge(action, rule);
    let mut describe = format!("firewall {needle}");
    if let Some(c) = rule.comment.as_deref() {
        describe.push_str(&format!(" ({c})"));
    }
    ManagedCommand::new(
        describe,
        format!(
            "ufw show added 2>/dev/null | grep -wF {} >/dev/null",
            shell_escape(&needle)
        ),
        converge,
    )
}

/// Enable the firewall. Declared **last** so every allow rule (including SSH) is
/// already in place (R56).
fn enable_cmd() -> ManagedCommand {
    ManagedCommand::new(
        "enable ufw",
        "ufw status 2>/dev/null | grep -i 'Status: active' >/dev/null",
        "ufw --force enable",
    )
}

impl Module for FirewallModule {
    fn id(&self) -> &'static str {
        "firewall"
    }

    fn declaration(&self) -> Declaration {
        let c = &self.cfg;
        let mut decl = Declaration::new("firewall")
            .command(ensure_ufw())
            .command(default_policy("incoming", &c.default_incoming))
            .command(default_policy("outgoing", &c.default_outgoing))
            // SSH allow ALWAYS precedes enable (R56).
            .command(allow_ssh(
                c.restrict_ssh,
                self.ssh_port,
                self.tailnet_only_ssh,
            ));
        for &port in &self.live_ports {
            decl = decl.command(allow_ssh(c.restrict_ssh, port, false));
        }
        for rule in &c.allow {
            decl = decl.command(rule_command("allow", rule));
        }
        for rule in &c.deny {
            decl = decl.command(rule_command("deny", rule));
        }
        // Enable is the final command so the box is never firewalled before SSH
        // is permitted.
        decl.command(enable_cmd())
            .rollback_script(ROLLBACK_KEEP_SSH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FirewallSection {
        FirewallSection {
            default_incoming: "deny".into(),
            default_outgoing: "allow".into(),
            restrict_ssh: true,
            allow: Vec::new(),
            deny: Vec::new(),
            order_override: Default::default(),
        }
    }

    fn rule(
        port: &str,
        proto: Option<&str>,
        from: Option<&str>,
        comment: Option<&str>,
    ) -> WallRule {
        WallRule {
            port: port.into(),
            proto: proto.map(Into::into),
            from: from.map(Into::into),
            comment: comment.map(Into::into),
        }
    }

    #[test]
    fn rollback_allows_the_restored_sshd_port_once() {
        // After a port move is rolled back, sshd is back on 22 while ufw
        // only allows 2222. Run the real rollback snippet against stub ufw and
        // sshd binaries: 22 gets allowed; an already-allowed port is left alone.
        let dir = std::env::temp_dir().join(format!("anvil-fw-rb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("ufw.log");
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
            &format!(
                "if [ \"$1\" = status ]; then printf 'Status: active\\n\\nTo Action From\\n2222/tcp ALLOW Anywhere\\n'; \
                 else echo \"$*\" >> {}; fi",
                log.display()
            ),
        );
        let run = |port: &str| {
            stub("sshd", &format!("echo 'port {port}'"));
            let _ = std::fs::remove_file(&log);
            std::process::Command::new("bash")
                .arg("-c")
                .arg(ROLLBACK_KEEP_SSH)
                .env(
                    "PATH",
                    format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
                )
                .output()
        };
        let Ok(out) = run("22") else { return };
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("CHANGED: firewall allowed sshd port 22/tcp"),
            "{stdout}"
        );
        assert_eq!(
            std::fs::read_to_string(&log).unwrap().trim(),
            "allow 22/tcp"
        );
        let out = run("2222").unwrap();
        assert!(String::from_utf8_lossy(&out.stdout).contains("OK: firewall already allows"));
        assert!(!log.exists(), "no rule added for an allowed port");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allows_ssh_strictly_before_enabling() {
        let apply = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_apply();
        let ssh = apply.find("ufw limit 22/tcp").expect("ssh allow present");
        let enable = apply.find("ufw --force enable").expect("enable present");
        assert!(
            ssh < enable,
            "SSH must be permitted before the firewall is enabled (R56)"
        );
    }

    #[test]
    fn user_rules_land_between_ssh_and_enable() {
        let mut cfg = base();
        cfg.allow = vec![rule("443", Some("tcp"), None, None)];
        let apply = FirewallModule::new(cfg, 22, false, vec![])
            .declaration()
            .render_apply();
        let ssh = apply.find("ufw limit 22/tcp").unwrap();
        let user = apply.find("ufw allow '443'/'tcp'").unwrap();
        let enable = apply.find("ufw --force enable").unwrap();
        assert!(ssh < user && user < enable);
    }

    #[test]
    fn restrict_ssh_false_uses_plain_allow() {
        let mut cfg = base();
        cfg.restrict_ssh = false;
        let apply = FirewallModule::new(cfg, 22, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("ufw allow 22/tcp"));
        assert!(!apply.contains("ufw limit 22/tcp"));
    }

    #[test]
    fn default_policies_reflect_config() {
        let apply = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("ufw default 'deny' incoming"));
        assert!(apply.contains("ufw default 'allow' outgoing"));
    }

    #[test]
    fn from_rule_renders_full_grammar_and_stable_needle() {
        let mut cfg = base();
        cfg.allow = vec![rule("5432", Some("tcp"), Some("10.0.0.0/8"), Some("db"))];
        let apply = FirewallModule::new(cfg, 22, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply
            .contains("ufw allow from '10.0.0.0/8' to any port '5432' proto 'tcp' comment 'db'"));
        // The idempotency needle excludes the (re-quoted) comment.
        assert!(apply
            .contains("grep -wF 'allow from 10.0.0.0/8 to any port 5432 proto tcp' >/dev/null"));
    }

    #[test]
    fn idempotency_needles_agree_with_real_ufw_show_added() {
        // Feed each rule's detect needle through captured `ufw show
        // added` output and confirm detect agrees with what converge produced —
        // no spurious CHANGED on a converged host, and no false match on a
        // near-port (4430 vs 443). This is the agreement the render-level tests
        // can only assume.
        use std::path::Path;
        use std::process::Command;
        let grep = |needle: &str, fixture: &str| -> bool {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(fixture);
            Command::new("grep")
                .args(["-qwF", needle])
                .arg(&path)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };
        // A no-proto allow: ufw expanded 443 to /tcp + /udp; the bare
        // `allow 443` needle still matches because `-w` treats `/` as a word
        // boundary — so a converged host reports aligned, not perpetual drift.
        assert!(
            grep(
                &rule_needle("allow", &rule("443", None, None, None)),
                "ufw_show_added.txt",
            ),
            "no-proto 443 must match ufw's 443/tcp entry"
        );
        // A from + proto rule matches its full line verbatim.
        assert!(
            grep(
                &rule_needle(
                    "allow",
                    &rule("5432", Some("tcp"), Some("10.0.0.0/8"), None)
                ),
                "ufw_show_added.txt",
            ),
            "from+proto rule must match"
        );
        // A deny rule.
        assert!(
            grep(
                &rule_needle("deny", &rule("23", Some("tcp"), None, None)),
                "ufw_show_added.txt",
            ),
            "deny 23/tcp must match"
        );
        // No false positive: 4430/4434 must NOT satisfy the `allow 443` needle
        // (the word boundary stops a prefix from matching).
        assert!(
            !grep(
                &rule_needle("allow", &rule("443", None, None, None)),
                "ufw_show_added_confusable.txt",
            ),
            "4430 must not be mistaken for 443"
        );
    }

    #[test]
    fn from_needle_matches_ufw_normalized_address() {
        // ufw stores `from` addresses normalized (fixture captured on
        // ufw 0.36.2); the needle built from the operator's spelling must match.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ufw_show_added_normalized.txt");
        for from in [
            "10.0.0.5/24",
            "2001:DB8:0:0::1",
            "2001:db8:0000::/48",
            "192.168.1.10",
        ] {
            let needle = rule_needle("allow", &rule("9", Some("tcp"), Some(from), None));
            let hit = std::process::Command::new("grep")
                .args(["-qwF", &needle])
                .arg(&path)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            assert!(hit, "{from}: needle {needle:?} not in ufw output");
        }
        // Prefix 0 masks every bit instead of overflowing the shift.
        assert_eq!(canonical_from("10.1.2.3/0"), "0.0.0.0/0");
        // ufw drops a full-length prefix (observed on ufw 0.36.2).
        assert_eq!(canonical_from("::1/128"), "::1");
        assert_eq!(canonical_from("10.0.0.7/32"), "10.0.0.7");
        assert_eq!(canonical_from("2001:DB8::7/128"), "2001:db8::7");
        // Out-of-range prefixes pass through; in-range ones mask host bits.
        assert_eq!(canonical_from("10.0.0.7/33"), "10.0.0.7/33");
        assert_eq!(canonical_from("2001:db8::/129"), "2001:db8::/129");
        assert_eq!(canonical_from("10.1.2.3/24"), "10.1.2.0/24");
        assert_eq!(
            canonical_from("2001:db8:1:2:3:4:5:6/64"),
            "2001:db8:1:2::/64"
        );
    }

    #[test]
    fn deny_rules_are_emitted() {
        let mut cfg = base();
        cfg.deny = vec![rule("23", Some("tcp"), None, None)];
        let apply = FirewallModule::new(cfg, 22, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("ufw deny '23'/'tcp'"));
    }

    #[test]
    fn malicious_comment_is_neutralized() {
        let mut cfg = base();
        cfg.allow = vec![rule("80", None, None, Some("x'; rm -rf / #"))];
        let apply = FirewallModule::new(cfg, 22, false, vec![])
            .declaration()
            .render_apply();
        // Payload stays inside single-quote escaping, never as bare shell.
        assert!(apply.contains(r"comment 'x'\''; rm -rf / #'"));
        assert!(!apply.contains("; rm -rf / #\n"));
    }

    #[test]
    fn probe_never_enables_or_mutates() {
        let probe = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_probe();
        assert!(!probe.contains("ufw --force enable"));
        assert!(!probe.contains("ufw default 'deny' incoming"));
    }

    #[test]
    fn install_converge_refreshes_package_lists_first() {
        let apply = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_apply();
        let update = apply
            .find("apt-get -o DPkg::Lock::Timeout=600 update -qq")
            .expect("apt update present in install converge");
        let install = apply
            .find("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'ufw'")
            .expect("ufw install present");
        assert!(update < install, "list refresh must precede the install");
    }

    #[test]
    fn detect_stays_cheap_no_apt_refresh_in_probe() {
        let probe = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_probe();
        // The probe only runs detect expressions; no apt activity may leak in.
        assert!(!probe.contains("apt-get"));
    }

    #[test]
    fn ssh_port_is_interpolated_not_hardcoded() {
        // Non-flag path: the effective port lands in describe/detect/converge.
        let apply = FirewallModule::new(base(), 2222, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("ufw limit 2222/tcp"));
        assert!(!apply.contains(" 22/tcp") && !apply.contains("port 22 "));

        // Flag path: the scoped rule and fallback both use the effective port.
        let apply = FirewallModule::new(base(), 2222, true, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("allow in on tailscale0 to any port 2222 proto tcp"));
        assert!(apply.contains("ufw limit 2222/tcp"));
        assert!(!apply.contains("port 22 "));
    }

    #[test]
    fn tailnet_flag_gates_ssh_allow_at_runtime() {
        let decl = FirewallModule::new(base(), 2222, true, vec![]).declaration();
        let probe = decl.render_probe();
        let apply = decl.render_apply();
        // Detect and converge share the tailnet-up + scoped-rule condition.
        for s in [&probe, &apply] {
            assert!(
                s.contains("tailscale ip -4"),
                "tailnet-up gate missing:\n{s}"
            );
            assert!(s.contains("allow in on tailscale0 to any port 2222 proto tcp"));
        }
        // Fallback branch keeps the world-open allow (never risk lockout): the
        // converge is an if/else whose else re-adds the plain rule.
        let cond = apply
            .find("if __fw_ts_ip=$(tailscale ip -4")
            .expect("condition");
        let scoped = apply
            .find("  ufw allow in on tailscale0 to any port 2222 proto tcp")
            .expect("scoped keep/ensure");
        let fallback = apply
            .find("  ufw limit 2222/tcp")
            .expect("world-open fallback");
        assert!(cond < scoped && scoped < fallback);
        // Detect treats world-open as the aligned fallback state too.
        assert!(
            probe.contains("|| ufw show added 2>/dev/null | grep -wF 'limit 2222/tcp' >/dev/null")
        );
    }

    #[test]
    fn tailnet_gated_ssh_allow_still_precedes_enable() {
        let apply = FirewallModule::new(base(), 22, true, vec![])
            .declaration()
            .render_apply();
        let ssh = apply
            .find("tailscale ip -4")
            .expect("conditional ssh step present");
        let enable = apply.find("ufw --force enable").expect("enable present");
        assert!(
            ssh < enable,
            "SSH must be permitted before the firewall is enabled (R56)"
        );
    }

    #[test]
    fn without_flag_ssh_allow_is_unconditional() {
        let apply = FirewallModule::new(base(), 22, false, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("ufw limit 22/tcp"));
        // No runtime tailnet condition anywhere in the module.
        assert!(!apply.contains("tailscale"));
    }
}
