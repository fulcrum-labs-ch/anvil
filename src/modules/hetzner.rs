//! The `hetzner` module (R82): runs **locally** against the `hcloud` CLI to
//! create/update a cloud firewall from `rules` and apply it to a server.
//!
//! Lockout guard (R61): the effective rule set is *guaranteed* to permit inbound
//! SSH on the **effective** SSH port (sshd's configured port when that module is
//! enabled, else 22). If the operator's own rules don't already open it, a
//! permit-SSH-from-anywhere rule is prepended, so it is impossible to push a
//! cloud firewall that drops management SSH. When the effective port is not 22,
//! TCP 22 is kept open as well: `hcloud firewall set-rules` replaces the whole
//! rule set, and the cloud firewall can converge before sshd has actually moved
//! off the default port (cutover safety).
//!
//! Preflight: the scripts run on the operator's machine, so missing `hcloud`,
//! missing `jq`, or an unset `HCLOUD_TOKEN` fail fast with an actionable
//! message instead of erroring confusingly mid-run.
//!
//! Every config-derived value (firewall/server names, and the whole rules JSON
//! built from the operator's ports/IPs/descriptions) passes through
//! [`shell_escape`] before it reaches bash (R55).

use crate::config::schema::{CloudEdgeRule, HetznerSection};
use crate::engine::{Declaration, ManagedCommand};
use crate::escape::shell_escape;

use super::Module;

/// Default SSH port; kept open alongside a custom effective port during
/// cutover, since sshd may not have moved yet when the cloud firewall
/// (a full rule-set replacement) applies (R61).
const DEFAULT_SSH_PORT: &str = "22";

/// jq projection that canonicalizes a rule array (fill defaults, drop field-order
/// / presence differences) so current-vs-desired can be compared for drift.
const RULE_NORM: &str = "[ .[] | { direction, protocol, port: (.port // null), \
source_ips: (.source_ips // []), destination_ips: (.destination_ips // []), \
description: (.description // null) } ] | sort";

pub struct HetznerModule {
    cfg: HetznerSection,
    /// The effective SSH port from the whole config (sshd's `port` when that
    /// module is enabled, else 22). The lockout-guard rules (R61) are built
    /// from it.
    ssh_port: u16,
    /// Live host ports other than `ssh_port`, kept open like 22: sshd
    /// may still listen there when a port move failed or has not landed yet.
    live_ports: Vec<u16>,
}

impl HetznerModule {
    pub fn new(cfg: HetznerSection, ssh_port: u16, live_ports: Vec<u16>) -> Self {
        Self {
            cfg,
            ssh_port,
            live_ports,
        }
    }

    /// The effective SSH port the cloud firewall must keep open (R61).
    pub fn ssh_port(&self) -> u16 {
        self.ssh_port
    }

    /// Operator rules plus the R61 guard rules (see [`guarded_rules`]).
    fn effective_rules(&self) -> Vec<CloudEdgeRule> {
        guarded_rules(
            &self.cfg.rules,
            self.cfg.keep_public_ssh,
            self.ssh_port,
            &self.live_ports,
            false,
        )
    }

    /// Fail fast, with actionable messages, when the operator's machine lacks
    /// what the module needs: the `hcloud` CLI, `jq` (used by the drift
    /// detects), or an `HCLOUD_TOKEN` for authentication.
    fn preflight_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "preflight: hcloud CLI, jq and HCLOUD_TOKEN available locally",
            "command -v hcloud >/dev/null 2>&1 \
             && command -v jq >/dev/null 2>&1 \
             && [ -n \"${HCLOUD_TOKEN:-}\" ]",
            "command -v hcloud >/dev/null 2>&1 || { printf 'FAILED: hcloud CLI not found on this machine; install it from https://github.com/hetznercloud/cli and re-run\\n'; exit 1; }\n\
             command -v jq >/dev/null 2>&1 || { printf 'FAILED: jq not found on this machine; install it (apt-get install -y jq / brew install jq) and re-run\\n'; exit 1; }\n\
             [ -n \"${HCLOUD_TOKEN:-}\" ] || { printf 'FAILED: HCLOUD_TOKEN is unset or empty; export a Hetzner Cloud API token and re-run\\n'; exit 1; }",
        )
    }

    /// Serialize the effective rules into hcloud's `--rules-file` JSON shape.
    pub fn rules_json(&self) -> String {
        let arr: Vec<serde_json::Value> = self.effective_rules().iter().map(rule_to_json).collect();
        serde_json::Value::Array(arr).to_string()
    }

    fn ensure_firewall_command(&self) -> ManagedCommand {
        let fw = &self.cfg.firewall_name;
        let name = shell_escape(fw);
        ManagedCommand::new(
            format!("ensure hcloud firewall {fw} exists"),
            format!("hcloud firewall describe {name} >/dev/null 2>&1"),
            format!("hcloud firewall create --name {name}"),
        )
    }

    fn set_rules_command(&self) -> ManagedCommand {
        let fw = &self.cfg.firewall_name;
        let name = shell_escape(fw);
        let json = shell_escape(&self.rules_json());
        let norm = RULE_NORM;

        // Converged when the firewall's current rules canonicalize identically to
        // the desired set. Requires jq locally; if absent, treat as drift.
        let detect = format!(
            "command -v jq >/dev/null 2>&1 \
             && __cur=$(hcloud firewall describe {name} -o json 2>/dev/null) \
             && [ -n \"$__cur\" ] \
             && [ \"$(printf '%s' \"$__cur\" | jq -S -c '.rules | {norm}')\" \
                = \"$(printf '%s' {json} | jq -S -c '{norm}')\" ]"
        );

        let converge = format!(
            "__rf=\"$__rundir/hcloud-rules.json\"\n\
             printf '%s' {json} > \"$__rf\"\n\
             hcloud firewall set-rules {name} --rules-file \"$__rf\"\n\
             rm -f \"$__rf\""
        );

        ManagedCommand::new(format!("set hcloud firewall {fw} rules"), detect, converge)
    }

    fn apply_command(&self) -> ManagedCommand {
        let fw = &self.cfg.firewall_name;
        let srv = &self.cfg.server_name;
        let name = shell_escape(fw);
        let server = shell_escape(srv);

        // Converged when the firewall's applied-to set already contains this
        // server (matched by resolved server id).
        let detect = format!(
            "__sid=$(hcloud server describe {server} -o json 2>/dev/null | jq -r '.id // empty') \
             && [ -n \"$__sid\" ] \
             && hcloud firewall describe {name} -o json 2>/dev/null \
             | jq -e --argjson sid \"$__sid\" \
               'any((.applied_to // [])[]; (.server.id // -1) == $sid)' >/dev/null 2>&1"
        );
        let converge =
            format!("hcloud firewall apply-to-resource {name} --type server --server {server}");

        ManagedCommand::new(
            format!("apply hcloud firewall {fw} to server {srv}"),
            detect,
            converge,
        )
    }
}

/// A mandatory inbound-SSH allow rule for `port` (R61).
fn ssh_guard_rule(port: &str) -> CloudEdgeRule {
    CloudEdgeRule {
        direction: "in".into(),
        protocol: "tcp".into(),
        port: Some(port.into()),
        source_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
        description: Some(format!("anvil: always allow SSH on tcp/{port} (R61)")),
    }
}

/// True when an operator rule already opens inbound TCP `port` to the
/// world for hetzner: a source-restricted rule is no cover; empty
/// sources mean "any", see [`rule_to_json`]). With `sources_cover`, any
/// operator rule on the port counts, whatever its sources (netcup, T12).
fn covers_inbound_tcp(rules: &[CloudEdgeRule], port: &str, sources_cover: bool) -> bool {
    rules.iter().any(|r| {
        r.direction == "in"
            && r.protocol == "tcp"
            && r.port.as_deref() == Some(port)
            && (sources_cover
                || r.source_ips.is_empty()
                || ["0.0.0.0/0", "::/0"]
                    .iter()
                    .all(|any| r.source_ips.iter().any(|s| s == any)))
    })
}

/// Operator `rules` plus the guaranteed inbound-SSH rule(s) (R61), shared by
/// every provider firewall (hetzner, netcup): the effective SSH port is
/// always kept open, and when it differs from 22, TCP 22 stays open too — a
/// provider rule set is replaced wholesale, and sshd may still be listening
/// on 22 when it converges (cutover safety). Live host ports likewise.
/// `keep_public_ssh = false` (T10) adds no guard at all; validation and the
/// apply-time tailnet gate make that safe. `sources_cover`: see
/// [`covers_inbound_tcp`].
pub(crate) fn guarded_rules(
    rules: &[CloudEdgeRule],
    keep_public_ssh: bool,
    ssh_port: u16,
    live_ports: &[u16],
    sources_cover: bool,
) -> Vec<CloudEdgeRule> {
    if !keep_public_ssh {
        return rules.to_vec();
    }
    let effective_port = ssh_port.to_string();
    let mut out = Vec::with_capacity(rules.len() + 2);
    if !covers_inbound_tcp(rules, &effective_port, sources_cover) {
        out.push(ssh_guard_rule(&effective_port));
    }
    if effective_port != DEFAULT_SSH_PORT
        && !covers_inbound_tcp(rules, DEFAULT_SSH_PORT, sources_cover)
    {
        out.push(ssh_guard_rule(DEFAULT_SSH_PORT));
    }
    for port in live_ports.iter().map(u16::to_string) {
        if port != DEFAULT_SSH_PORT && !covers_inbound_tcp(rules, &port, sources_cover) {
            out.push(ssh_guard_rule(&port));
        }
    }
    out.extend(rules.iter().cloned());
    out
}

/// One `CloudEdgeRule` as an hcloud rules-file object. The schema carries a
/// single `source_ips` list; it maps to `source_ips` for inbound rules and
/// `destination_ips` for outbound ones, defaulting to "any" when unset.
fn rule_to_json(r: &CloudEdgeRule) -> serde_json::Value {
    use serde_json::{Map, Value};

    let mut m = Map::new();
    m.insert("direction".into(), Value::String(r.direction.clone()));
    m.insert("protocol".into(), Value::String(r.protocol.clone()));
    if let Some(port) = &r.port {
        m.insert("port".into(), Value::String(port.clone()));
    }

    let ips: Vec<Value> = if r.source_ips.is_empty() {
        vec![
            Value::String("0.0.0.0/0".into()),
            Value::String("::/0".into()),
        ]
    } else {
        r.source_ips.iter().cloned().map(Value::String).collect()
    };
    if r.direction == "out" {
        m.insert("destination_ips".into(), Value::Array(ips));
    } else {
        m.insert("source_ips".into(), Value::Array(ips));
    }

    if let Some(desc) = &r.description {
        m.insert("description".into(), Value::String(desc.clone()));
    }
    Value::Object(m)
}

impl Module for HetznerModule {
    fn id(&self) -> &'static str {
        "hetzner"
    }

    fn declaration(&self) -> Declaration {
        // Runs on the operator's machine (R82): `hcloud` authenticates with a
        // local HCLOUD_TOKEN, which does not exist on the target host.
        Declaration::new("hetzner")
            .command(self.preflight_command())
            .command(self.ensure_firewall_command())
            .command(self.set_rules_command())
            .command(self.apply_command())
            .local()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::OrderOverride;

    fn section(rules: Vec<CloudEdgeRule>) -> HetznerSection {
        HetznerSection {
            server_name: "web1".into(),
            firewall_name: "anvil".into(),
            rules,
            keep_public_ssh: true,
            order_override: OrderOverride::default(),
        }
    }

    fn rule(direction: &str, protocol: &str, port: Option<&str>) -> CloudEdgeRule {
        CloudEdgeRule {
            direction: direction.into(),
            protocol: protocol.into(),
            port: port.map(|p| p.to_string()),
            source_ips: Vec::new(),
            description: None,
        }
    }

    #[test]
    fn ssh_rule_is_always_present() {
        let json = HetznerModule::new(section(vec![]), 22, vec![]).rules_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = v.as_array().unwrap();
        assert!(arr
            .iter()
            .any(|r| { r["direction"] == "in" && r["protocol"] == "tcp" && r["port"] == "22" }));
        // Defaulted to allow-from-anywhere.
        assert!(json.contains("0.0.0.0/0"));
    }

    #[test]
    fn existing_ssh_rule_is_not_duplicated() {
        let json = HetznerModule::new(section(vec![rule("in", "tcp", Some("22"))]), 22, vec![])
            .rules_json();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let count = v
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["direction"] == "in" && r["port"] == "22")
            .count();
        assert_eq!(count, 1, "must not add a second SSH rule");
    }

    #[test]
    fn source_restricted_rule_does_not_cover_ssh() {
        // An office-CIDR rule on 22 must not drop the world-open guard.
        let mut office = rule("in", "tcp", Some("22"));
        office.source_ips = vec!["203.0.113.0/24".into()];
        let json = HetznerModule::new(section(vec![office]), 22, vec![]).rules_json();
        assert!(json.contains("always allow SSH on tcp/22"), "{json}");

        let mut world = rule("in", "tcp", Some("22"));
        world.source_ips = vec!["0.0.0.0/0".into(), "::/0".into()];
        let json = HetznerModule::new(section(vec![world]), 22, vec![]).rules_json();
        assert!(
            !json.contains("always allow SSH"),
            "world-open rule covers: {json}"
        );
    }

    #[test]
    fn live_host_port_is_kept_open() {
        // host.port 2200 survives a failed move to 2222.
        let json = HetznerModule::new(section(vec![]), 2222, vec![2200]).rules_json();
        for port in ["2222", "22", "2200"] {
            assert!(
                json.contains(&format!("always allow SSH on tcp/{port} ")),
                "{port}: {json}"
            );
        }
    }

    #[test]
    fn outbound_rule_uses_destination_ips() {
        let mut out = rule("out", "tcp", Some("443"));
        out.source_ips = vec!["10.0.0.0/8".into()];
        let json = HetznerModule::new(section(vec![out]), 22, vec![]).rules_json();
        assert!(json.contains(r#""destination_ips":["10.0.0.0/8"]"#));
    }

    #[test]
    fn declaration_uses_fixed_hcloud_subcommands() {
        let apply = HetznerModule::new(section(vec![]), 22, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains("hcloud firewall create --name 'anvil'"));
        assert!(apply.contains("hcloud firewall set-rules 'anvil' --rules-file"));
        assert!(apply
            .contains("hcloud firewall apply-to-resource 'anvil' --type server --server 'web1'"));
    }

    #[test]
    fn config_values_are_shell_escaped() {
        let mut s = section(vec![]);
        s.firewall_name = "fw'; rm -rf /".into();
        let apply = HetznerModule::new(s, 22, vec![])
            .declaration()
            .render_apply();
        // The injection attempt is neutralized inside single-quote wrapping.
        assert!(apply.contains(r#"'fw'\''; rm -rf /'"#));
        assert!(!apply.contains("--name fw; rm"));
    }

    #[test]
    fn declaration_runs_locally() {
        // hcloud authenticates with the operator's local HCLOUD_TOKEN, so the
        // scripts must never be shipped over SSH to the target.
        let decl = HetznerModule::new(section(vec![]), 22, vec![]).declaration();
        assert!(decl.runs_locally);
    }

    #[test]
    fn effective_ssh_port_is_stored() {
        let m = HetznerModule::new(section(vec![]), 2222, vec![]);
        assert_eq!(m.ssh_port(), 2222);
    }

    /// Count the guaranteed inbound-TCP allow rules for `port`.
    fn inbound_tcp_rules(json: &str, port: &str) -> usize {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .filter(|r| r["direction"] == "in" && r["protocol"] == "tcp" && r["port"] == port)
            .count()
    }

    #[test]
    fn custom_ssh_port_is_in_guaranteed_rules() {
        // A host with sshd on 2222 must keep 2222 open at the cloud edge —
        // a guard pinned to 22 would lock the operator out after cutover.
        let json = HetznerModule::new(section(vec![]), 2222, vec![]).rules_json();
        assert_eq!(inbound_tcp_rules(&json, "2222"), 1);
        assert!(json.contains("always allow SSH on tcp/2222"));
    }

    #[test]
    fn keep_public_ssh_false_drops_every_guard() {
        // T10: no guard for the effective port, 22, or live ports; the
        // operator's own rules still go out unchanged.
        let mut cfg = section(vec![rule("in", "udp", Some("41641"))]);
        cfg.keep_public_ssh = false;
        let json = HetznerModule::new(cfg, 2222, vec![2200]).rules_json();
        for port in ["22", "2222", "2200"] {
            assert_eq!(inbound_tcp_rules(&json, port), 0, "{port}: {json}");
        }
        assert!(!json.contains("R61"), "{json}");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1, "{json}");
        assert!(json.contains("41641"));
    }

    #[test]
    fn keep_public_ssh_default_keeps_every_guard() {
        let json = HetznerModule::new(section(vec![]), 2222, vec![2200]).rules_json();
        for port in ["22", "2222", "2200"] {
            assert_eq!(inbound_tcp_rules(&json, port), 1, "{port}: {json}");
        }
        let cfg: HetznerSection = toml::from_str("server_name = \"web1\"").unwrap();
        assert!(cfg.keep_public_ssh, "default is true");
    }

    #[test]
    fn custom_port_keeps_default_22_open_for_cutover() {
        // set-rules replaces the entire rule set; sshd may still listen on 22
        // when the cloud firewall applies, so both ports stay open.
        let json = HetznerModule::new(section(vec![]), 2222, vec![]).rules_json();
        assert_eq!(inbound_tcp_rules(&json, "2222"), 1);
        assert_eq!(inbound_tcp_rules(&json, "22"), 1);
    }

    #[test]
    fn live_port_22_is_not_guarded_twice() {
        let json = HetznerModule::new(section(vec![]), 2222, vec![22]).rules_json();
        assert_eq!(inbound_tcp_rules(&json, "22"), 1);
    }

    #[test]
    fn default_port_yields_only_the_22_guard() {
        let json = HetznerModule::new(section(vec![]), 22, vec![]).rules_json();
        assert_eq!(inbound_tcp_rules(&json, "22"), 1);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1, "no extra guard rules");
    }

    #[test]
    fn operator_rule_for_custom_port_still_keeps_22() {
        // The operator already opens 2222 (no duplicate guard), but the
        // cutover-safety 22 rule is still added.
        let json = HetznerModule::new(section(vec![rule("in", "tcp", Some("2222"))]), 2222, vec![])
            .rules_json();
        assert_eq!(inbound_tcp_rules(&json, "2222"), 1);
        assert_eq!(inbound_tcp_rules(&json, "22"), 1);
    }

    #[test]
    fn preflight_checks_hcloud_jq_and_token() {
        let apply = HetznerModule::new(section(vec![]), 22, vec![])
            .declaration()
            .render_apply();
        // All three checks are present…
        assert!(apply.contains("command -v hcloud >/dev/null 2>&1"));
        assert!(apply.contains("command -v jq >/dev/null 2>&1"));
        assert!(apply.contains("[ -n \"${HCLOUD_TOKEN:-}\" ]"));
        // …and each failure is fast and actionable.
        assert!(apply.contains("FAILED: hcloud CLI not found"));
        assert!(apply.contains("FAILED: jq not found"));
        assert!(apply.contains("FAILED: HCLOUD_TOKEN is unset or empty"));
        assert!(apply.contains("exit 1"));
    }

    #[test]
    fn probe_is_read_only() {
        let probe = HetznerModule::new(section(vec![]), 22, vec![])
            .declaration()
            .render_probe();
        assert!(probe.contains("hcloud firewall describe"));
        // No mutating subcommands in the probe.
        assert!(!probe.contains("firewall create"));
        assert!(!probe.contains("set-rules"));
        assert!(!probe.contains("apply-to-resource"));
    }
}
