//! The `netcup` module (T12): runs **locally** (like `hetzner`) and manages
//! the netcup SCP firewall through the SCP REST API with `curl` + `jq`.
//!
//! anvil owns exactly ONE user firewall policy (by name, `policy`): it creates
//! it if absent, converges its rules, and attaches it to the server's single
//! public interface next to whatever is already attached. Other user policies
//! (and copied policies) are never edited, deleted or detached.
//!
//! Security: the SCP refresh token carries the account's full rights (disk
//! format, reinstall, snapshots…), so every request goes through ONE bash
//! function, `__scp`, which refuses any method + path outside [`ALLOWLIST`]
//! (OIDC token refresh, userinfo, server list/detail, the interface firewall
//! and the user's firewall policies). A test scans this source for any other
//! `/api/` path. The refresh token comes from `NETCUP_SCP_REFRESH_TOKEN`, is
//! written with the `printf` builtin to a 0600 file and handed to curl as
//! `--data-urlencode refresh_token@file`; the access token reaches curl via a
//! 0600 `-K` config file — neither ever appears in an argv or in output. The
//! files live in a private temp dir removed on exit.
//!
//! Lockout guard (R61): the policy always allows SSH on the effective port
//! (and 22 / live ports during a cutover, as for hetzner, [`guarded_rules`])
//! unless `keep_public_ssh = false` (T10, validated). Unlike hetzner, an
//! operator rule on that port restricted to `source_ips` counts as the guard
//! ("world or the configured sources"), so a box that only admits the
//! operator's IP is not opened to the world.
//!
//! Rollback: before the first attach, the interface's attached user-policy
//! ids are snapshotted on the operator's machine
//! (`$XDG_STATE_HOME/anvil/netcup/<server>-<mac>.json`); rollback PUTs that set
//! back and removes the snapshot. The anvil policy itself is left in place,
//! detached (rollback never deletes a policy).

use crate::config::schema::{CloudEdgeRule, NetcupSection};
use crate::engine::{Declaration, ManagedCommand};
use crate::escape::shell_escape;

use super::hetzner::guarded_rules;
use super::Module;

/// Every request anvil may send to netcup: `METHOD path` as an anchored ERE.
/// Ids are digits, the MAC is the SCP pattern, list filters are `@uri`-encoded.
/// Nothing else on the account is reachable — `__scp` refuses it before curl
/// runs.
pub const ALLOWLIST: &[&str] = &[
    "POST /realms/scp/protocol/openid-connect/token",
    "GET /realms/scp/protocol/openid-connect/userinfo",
    r"GET /scp-core/api/v1/servers(\?q=[A-Za-z0-9%._~-]*)?",
    "GET /scp-core/api/v1/servers/[0-9]+",
    "(GET|PUT) /scp-core/api/v1/servers/[0-9]+/interfaces/[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}/firewall",
    r"(GET|POST) /scp-core/api/v1/users/[0-9]+/firewall-policies(\?q=[A-Za-z0-9%._~-]*)?",
    "(GET|PUT) /scp-core/api/v1/users/[0-9]+/firewall-policies/[0-9]+",
];

/// jq projection canonicalizing an SCP rule array (defaults filled, server-only
/// fields like `numberOfEffectiveRules` dropped, order ignored) for drift.
/// Only the address side anvil sets is compared: SCP fills the other side
/// with e.g. `["0.0.0.0/0"]` (seen live on an INGRESS rule's destinations).
const RULE_NORM: &str = "[ (. // [])[] | { direction, protocol, action, \
addrs: ((if .direction == \"EGRESS\" then .destinations else .sources end) // [] | sort), \
sourcePorts: (.sourcePorts // null), destinationPorts: (.destinationPorts // null), \
description: (.description // null) } ] | sort";

/// The helpers every netcup command needs, re-declared at the head of each
/// `detect` (the engine has no preamble slot; detect always runs first in the
/// same shell, so converge sees them). Resolution is memoized: one token,
/// one userinfo/server lookup per script. Functions report through
/// `$__scp_err` and a non-zero return — never via errexit, which is off
/// inside `if`/`||`.
const PRELUDE: &str = r#"{
__scp_base='https://www.servercontrolpanel.de'
__scp_re='^(@ALLOWLIST@)$'
__scp_norm=@NORM@
__scp_srv=@SERVER@
__scp_pol=@POLICY@
__scp_rules=@RULES@
__scp_init() {
  [ -z "${__scp_dir:-}" ] || return 0
  umask 077
  if [ -n "${__rundir:-}" ] && [ -d "$__rundir" ]; then
    __scp_dir="$__rundir/scp"; mkdir -m 700 "$__scp_dir" || return 1
  else
    __scp_dir=$(mktemp -d) || return 1
    trap 'rm -rf "$__scp_dir"' EXIT
    trap 'exit 1' HUP INT TERM
  fi
}
# The ONLY place anvil talks to netcup: METHOD PATH [BODY_FILE] > out.
__scp() {
  if ! [[ "$1 $2" =~ $__scp_re ]]; then
    __scp_err="refusing SCP request outside the allowlist: $1 ${2%%\?*}"; return 1
  fi
  if [ "$2" = /realms/scp/protocol/openid-connect/token ]; then
    curl -sS -f --proto '=https' --max-time 60 -X POST \
      --data-urlencode grant_type=refresh_token --data-urlencode client_id=scp \
      --data-urlencode "refresh_token@$__scp_dir/rt" \
      "$__scp_base$2" 2>"$__scp_dir/err"
  elif [ -n "${3:-}" ]; then
    curl -sS -f --proto '=https' --max-time 60 -X "$1" -K "$__scp_dir/auth" \
      -H 'Content-Type: application/json' --data-binary "@$3" \
      "$__scp_base$2" 2>"$__scp_dir/err"
  else
    curl -sS -f --proto '=https' --max-time 60 -X "$1" -K "$__scp_dir/auth" \
      "$__scp_base$2" 2>"$__scp_dir/err"
  fi || { __scp_err="$1 ${2%%\?*} failed: $(head -n1 "$__scp_dir/err")"; return 1; }
}
__scp_uri() { jq -rn --arg v "$1" '$v|@uri'; }
# The session id (`sid`) of a JWT in file $1; empty when it is not one.
__scp_jwt_sid() { jq -Rr 'split(".")[1] // "" | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - length % 4) % 4)) | @base64d | fromjson | .sid // empty' "$1" 2>/dev/null || true; }
# Token, userinfo → user id, server id, the single public interface MAC.
__scp_resolve() {
  [ -z "${__scp_mac:-}" ] || return 0
  command -v curl >/dev/null 2>&1 || { __scp_err='curl not found on this machine; install it and re-run'; return 1; }
  command -v jq >/dev/null 2>&1 || { __scp_err='jq not found on this machine; install it (apt-get install -y jq / brew install jq) and re-run'; return 1; }
  [ -n "${NETCUP_SCP_REFRESH_TOKEN:-}" ] || { __scp_err='NETCUP_SCP_REFRESH_TOKEN is unset or empty; export an SCP refresh token (device flow, client_id scp, scope offline_access openid) and re-run'; return 1; }
  __scp_init || { __scp_err='cannot create a private temp dir'; return 1; }
  local d="$__scp_dir" m
  printf '%s' "$NETCUP_SCP_REFRESH_TOKEN" > "$d/rt" || return 1
  __scp POST /realms/scp/protocol/openid-connect/token > "$d/tok" || return 1
  jq -r '.access_token // empty | select(test("^[A-Za-z0-9._~+/=-]+$")) | "header = \"Authorization: Bearer \(.)\""' "$d/tok" > "$d/auth" || return 1
  [ -s "$d/auth" ] || { rm -f "$d/tok"; __scp_err='the SCP token endpoint returned no usable access_token'; return 1; }
  # netcup refresh tokens stay valid while used (30 days); anvil never stores
  # a new one. SCP reissues the offline token on every refresh (same session
  # `sid`, new `exp`; seen live) — only a different session is a rotation.
  jq -j '.refresh_token // empty' "$d/tok" > "$d/rt.new" || return 1
  rm -f "$d/tok"
  if [ -s "$d/rt.new" ] && ! cmp -s "$d/rt" "$d/rt.new" \
     && { [ -z "$(__scp_jwt_sid "$d/rt")" ] || [ "$(__scp_jwt_sid "$d/rt")" != "$(__scp_jwt_sid "$d/rt.new")" ]; }; then
    __scp_warn='anvil: warning: netcup: the SCP token endpoint returned a refresh token for a different session; anvil does not store it and keeps using NETCUP_SCP_REFRESH_TOKEN — if that one stops working, run the device flow again'
    printf '%s\n' "$__scp_warn"; printf '%s\n' "$__scp_warn" >&2
  fi
  rm -f "$d/rt.new"
  __scp GET /realms/scp/protocol/openid-connect/userinfo > "$d/ui" || return 1
  __scp_uid=$(jq -r 'first((.userId, .user_id, .id) | select(type == "number" or (type == "string" and test("^[0-9]+$")))) // empty' "$d/ui")
  [ -n "$__scp_uid" ] || { __scp_err="userinfo carries no numeric SCP user id (claims: $(jq -r 'keys | join(",")' "$d/ui"))"; return 1; }
  if [[ "$__scp_srv" =~ ^[0-9]+$ ]]; then
    __scp_sid=$__scp_srv
  else
    __scp GET "/scp-core/api/v1/servers?q=$(__scp_uri "$__scp_srv")" > "$d/srvs" || return 1
    __scp_sid=$(jq -r --arg n "$__scp_srv" '[.[] | select(.name == $n or .nickname == $n) | .id] | if length == 1 then .[0] else empty end' "$d/srvs")
    [ -n "$__scp_sid" ] || { __scp_err="no single SCP server with name or nickname $__scp_srv; set netcup.server to its numeric id"; return 1; }
  fi
  __scp GET "/scp-core/api/v1/servers/$__scp_sid" > "$d/srv" || return 1
  m=$(jq -r '[((.serverLiveInfo // {}).interfaces // [])[] | select(.vlanInterface != true) | .mac] | if length == 1 then .[0] else "\(length) public interfaces: \(join(" "))" end' "$d/srv")
  [[ "$m" =~ ^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$ ]] || { __scp_err="server $__scp_sid has no single public interface ($m); is it running?"; return 1; }
  __scp_mac=$m
}
# Look up anvil's policy by exact name: __scp_pid ('' when absent).
__scp_policy() {
  local n
  __scp GET "/scp-core/api/v1/users/$__scp_uid/firewall-policies?q=$(__scp_uri "$__scp_pol")" > "$__scp_dir/pols" || return 1
  n=$(jq --arg n "$__scp_pol" '[.[] | select(.name == $n)] | length' "$__scp_dir/pols") || return 1
  [ "$n" -le 1 ] || { __scp_err="$n SCP firewall policies are named $__scp_pol; anvil owns exactly one, rename the others"; return 1; }
  __scp_pid=$(jq -r --arg n "$__scp_pol" 'first(.[] | select(.name == $n) | .id) // empty' "$__scp_dir/pols")
  # Just created this run: the list may lag behind the POST.
  [ -n "$__scp_pid" ] || __scp_pid=${__scp_created:-}
  # The list omits rules (`rules: null`, seen live); read them by id.
  [ -z "$__scp_pid" ] || __scp GET "/scp-core/api/v1/users/$__scp_uid/firewall-policies/$__scp_pid" > "$__scp_dir/pol"
}
__scp_fw() { __scp GET "/scp-core/api/v1/servers/$__scp_sid/interfaces/$__scp_mac/firewall" > "$__scp_dir/fw"; }
__scp_fail() { printf 'FAILED: netcup: %s\n' "${__scp_err:-SCP request failed}"; exit 1; }
__scp_state_dir="${XDG_STATE_HOME:-$HOME/.local/state}/anvil/netcup"
true
}"#;

pub struct NetcupModule {
    cfg: NetcupSection,
    /// Effective SSH port (R61), as for hetzner.
    ssh_port: u16,
    /// Live host ports other than `ssh_port`, kept open.
    live_ports: Vec<u16>,
}

impl NetcupModule {
    pub fn new(cfg: NetcupSection, ssh_port: u16, live_ports: Vec<u16>) -> Self {
        Self {
            cfg,
            ssh_port,
            live_ports,
        }
    }

    /// The desired policy rules as an SCP `FirewallRule` JSON array.
    pub fn rules_json(&self) -> String {
        let rules = guarded_rules(
            &self.cfg.rules,
            self.cfg.keep_public_ssh,
            self.ssh_port,
            &self.live_ports,
            true,
        );
        serde_json::Value::Array(rules.iter().map(rule_to_scp).collect()).to_string()
    }

    /// The shared helpers with this config's values (all shell-escaped, R55).
    fn prelude(&self) -> String {
        PRELUDE
            .replace("@ALLOWLIST@", &ALLOWLIST.join("|"))
            .replace("@NORM@", &shell_escape(RULE_NORM))
            .replace("@SERVER@", &shell_escape(&self.cfg.server))
            .replace("@POLICY@", &shell_escape(&self.cfg.policy))
            .replace("@RULES@", &shell_escape(&self.rules_json()))
    }

    /// `detect` = prelude, then `check`; a failed lookup reports its reason
    /// on stderr and counts as drift.
    fn detect(&self, check: &str) -> String {
        format!(
            "{prelude} && {{ __scp_resolve && {check} || {{ [ -z \"${{__scp_err:-}}\" ] \
             || printf 'anvil: netcup: %s\\n' \"$__scp_err\" >&2; false; }}; }}",
            prelude = self.prelude()
        )
    }

    fn preflight_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "preflight: curl, jq, NETCUP_SCP_REFRESH_TOKEN and the SCP server/interface",
            self.detect("true"),
            "__scp_fail",
        )
    }

    fn policy_command(&self) -> ManagedCommand {
        let pol = &self.cfg.policy;
        let check = "__scp_policy && [ -n \"$__scp_pid\" ] \
             && [ \"$(jq -S -c \".rules | $__scp_norm\" \"$__scp_dir/pol\")\" \
             = \"$(printf '%s' \"$__scp_rules\" | jq -S -c \"$__scp_norm\")\" ]";
        let converge = "__scp_resolve || __scp_fail\n\
             __scp_policy || __scp_fail\n\
             jq -cn --arg n \"$__scp_pol\" --argjson r \"$__scp_rules\" \
             '{name: $n, description: \"managed by anvil; edits are overwritten\", rules: $r}' > \"$__scp_dir/body\"\n\
             if [ -z \"$__scp_pid\" ]; then\n\
             \x20 __scp POST \"/scp-core/api/v1/users/$__scp_uid/firewall-policies\" \"$__scp_dir/body\" > \"$__scp_dir/resp\" || __scp_fail\n\
             \x20 __scp_created=$(jq -r '.id // empty | select(type == \"number\")' \"$__scp_dir/resp\")\n\
             \x20 [ -n \"$__scp_created\" ] || { __scp_err='the SCP did not return the new policy id'; __scp_fail; }\n\
             else\n\
             \x20 __scp PUT \"/scp-core/api/v1/users/$__scp_uid/firewall-policies/$__scp_pid\" \"$__scp_dir/body\" > \"$__scp_dir/resp\" || __scp_fail\n\
             fi";
        ManagedCommand::new(
            format!("netcup SCP firewall policy {pol} has the desired rules"),
            self.detect(check),
            converge,
        )
    }

    fn attach_command(&self) -> ManagedCommand {
        let pol = &self.cfg.policy;
        let check = "__scp_policy && [ -n \"$__scp_pid\" ] && __scp_fw \
             && jq -e --argjson p \"$__scp_pid\" 'any((.userPolicies // [])[]; .id == $p)' \"$__scp_dir/fw\" >/dev/null";
        // Snapshot the attached set once (first change), then append anvil's
        // policy to it: other policies, copied policies and `active` pass
        // through untouched.
        let converge = "__scp_resolve || __scp_fail\n\
             __scp_policy || __scp_fail\n\
             [ -n \"$__scp_pid\" ] || { __scp_err=\"policy $__scp_pol does not exist\"; __scp_fail; }\n\
             __scp_fw || __scp_fail\n\
             __scp_state=\"$__scp_state_dir/$__scp_sid-${__scp_mac//:/}.json\"\n\
             if [ ! -e \"$__scp_state\" ]; then\n\
             \x20 mkdir -p \"$__scp_state_dir\" && jq -c '{userPolicies: [(.userPolicies // [])[] | {id}]}' \"$__scp_dir/fw\" > \"$__scp_state.tmp\" \
             && mv \"$__scp_state.tmp\" \"$__scp_state\" || { __scp_err=\"cannot write the rollback snapshot $__scp_state\"; __scp_fail; }\n\
             fi\n\
             jq -c --argjson p \"$__scp_pid\" '{copiedPolicies: [(.copiedPolicies // [])[] | {id}], \
             userPolicies: ([(.userPolicies // [])[] | {id}] + [{id: $p}]), \
             active: (if .active == null then true else .active end)}' \"$__scp_dir/fw\" > \"$__scp_dir/body\"\n\
             __scp PUT \"/scp-core/api/v1/servers/$__scp_sid/interfaces/$__scp_mac/firewall\" \"$__scp_dir/body\" > \"$__scp_dir/resp\" || __scp_fail";
        ManagedCommand::new(
            format!("netcup SCP firewall policy {pol} attached to the server's public interface"),
            self.detect(check),
            converge,
        )
    }

    /// Restore the snapshotted user-policy set (copied policies and `active`
    /// pass through). No snapshot → nothing to roll back, without any API call.
    fn rollback_script(&self) -> String {
        format!(
            "\n# rollback: netcup SCP firewall attachment\n\
             {prelude}\n\
             if ! ls \"$__scp_state_dir\"/*.json >/dev/null 2>&1; then\n\
             \x20 printf 'OK: netcup: no attachment snapshot; nothing to roll back\\n'\n\
             else\n\
             \x20 __scp_resolve || __scp_fail\n\
             \x20 __scp_state=\"$__scp_state_dir/$__scp_sid-${{__scp_mac//:/}}.json\"\n\
             \x20 if [ ! -e \"$__scp_state\" ]; then\n\
             \x20\x20 printf 'OK: netcup: no attachment snapshot for this server; nothing to roll back\\n'\n\
             \x20 else\n\
             \x20\x20 __scp_fw || __scp_fail\n\
             \x20\x20 if [ \"$(jq -c '[(.userPolicies // [])[].id]' \"$__scp_dir/fw\")\" = \"$(jq -c '[.userPolicies[].id]' \"$__scp_state\")\" ]; then\n\
             \x20\x20\x20 printf 'OK: netcup: attached policies already match the snapshot\\n'\n\
             \x20\x20 else\n\
             \x20\x20\x20 jq -c --slurpfile s \"$__scp_state\" '{{copiedPolicies: [(.copiedPolicies // [])[] | {{id}}], \
             userPolicies: $s[0].userPolicies, active: (if .active == null then true else .active end)}}' \"$__scp_dir/fw\" > \"$__scp_dir/body\"\n\
             \x20\x20\x20 __scp PUT \"/scp-core/api/v1/servers/$__scp_sid/interfaces/$__scp_mac/firewall\" \"$__scp_dir/body\" > \"$__scp_dir/resp\" || __scp_fail\n\
             \x20\x20\x20 printf 'CHANGED: netcup: restored the attached policy set from the snapshot\\n'\n\
             \x20\x20 fi\n\
             \x20\x20 rm -f \"$__scp_state\"\n\
             \x20 fi\n\
             fi\n",
            prelude = self.prelude()
        )
    }
}

/// One `CloudEdgeRule` as an SCP `FirewallRule` (always ACCEPT). The single
/// `source_ips` list is `sources` for ingress and `destinations` for egress;
/// unset means "any" (omitted). `port` is the destination port.
fn rule_to_scp(r: &CloudEdgeRule) -> serde_json::Value {
    use serde_json::{Map, Value};

    let mut m = Map::new();
    let egress = r.direction == "out";
    m.insert(
        "direction".into(),
        Value::from(if egress { "EGRESS" } else { "INGRESS" }),
    );
    let proto = match r.protocol.as_str() {
        "icmpv6" => "ICMPv6".to_string(),
        p => p.to_ascii_uppercase(),
    };
    m.insert("protocol".into(), Value::from(proto));
    m.insert("action".into(), Value::from("ACCEPT"));
    if !r.source_ips.is_empty() {
        let key = if egress { "destinations" } else { "sources" };
        m.insert(key.into(), Value::from(r.source_ips.clone()));
    }
    if let Some(port) = &r.port {
        m.insert("destinationPorts".into(), Value::from(port.clone()));
    }
    if let Some(desc) = &r.description {
        m.insert("description".into(), Value::from(desc.clone()));
    }
    Value::Object(m)
}

impl Module for NetcupModule {
    fn id(&self) -> &'static str {
        "netcup"
    }

    fn declaration(&self) -> Declaration {
        // Runs on the operator's machine: the SCP token lives there, never
        // on the target host.
        Declaration::new("netcup")
            .command(self.preflight_command())
            .command(self.policy_command())
            .command(self.attach_command())
            .rollback_script(self.rollback_script())
            .local()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::OrderOverride;

    fn section(rules: Vec<CloudEdgeRule>) -> NetcupSection {
        NetcupSection {
            server: "v2202501234".into(),
            policy: "anvil".into(),
            rules,
            keep_public_ssh: true,
            order_override: OrderOverride::default(),
        }
    }

    fn module(rules: Vec<CloudEdgeRule>) -> NetcupModule {
        NetcupModule::new(section(rules), 22, vec![])
    }

    fn rule(direction: &str, protocol: &str, port: Option<&str>) -> CloudEdgeRule {
        CloudEdgeRule {
            direction: direction.into(),
            protocol: protocol.into(),
            port: port.map(String::from),
            source_ips: Vec::new(),
            description: None,
        }
    }

    fn rules(m: &NetcupModule) -> Vec<serde_json::Value> {
        serde_json::from_str::<serde_json::Value>(&m.rules_json())
            .unwrap()
            .as_array()
            .unwrap()
            .clone()
    }

    fn ssh_guards(m: &NetcupModule, port: &str) -> usize {
        rules(m)
            .iter()
            .filter(|r| {
                r["direction"] == "INGRESS"
                    && r["protocol"] == "TCP"
                    && r["destinationPorts"] == port
            })
            .count()
    }

    #[test]
    fn source_scan_finds_no_api_path_outside_the_allowlist() {
        // Every `/api/` or `/realms/` path in this file is built only from
        // allowlisted segments; no other SCP resource is ever named.
        let full = include_str!("netcup.rs");
        let src = &full[..full.find("#[cfg(test)]").unwrap()];
        let allowed = [
            "api",
            "v1",
            "servers",
            "interfaces",
            "firewall",
            "users",
            "firewall-policies",
            "realms",
            "scp",
            "protocol",
            "openid-connect",
            "token",
            "userinfo",
        ];
        let mut seen = 0;
        for marker in ["/api/", "/realms/"] {
            for (at, _) in src.match_indices(marker) {
                seen += 1;
                let tail = &src[at + 1..];
                let end = tail
                    .find(|c: char| {
                        matches!(c, '"' | '\'' | ' ' | '\\' | '`' | '(' | ')' | '?' | '|')
                    })
                    .unwrap_or(tail.len());
                for seg in tail[..end].split('/') {
                    let dynamic = seg.is_empty()
                        || seg.starts_with('$')
                        || seg.starts_with('[')
                        || seg.starts_with('(')
                        || seg.starts_with('{');
                    assert!(
                        dynamic || allowed.contains(&seg),
                        "off-allowlist SCP path segment {seg:?} in {:?}",
                        &tail[..end]
                    );
                }
            }
        }
        assert!(seen > 10, "scan found the module's paths ({seen})");
        for verb in [
            concat!(":re", "apply"),
            concat!(":restore-", "copied"),
            "DELETE",
        ] {
            assert!(!src.contains(verb), "{verb} must not appear");
        }
    }

    /// Run `script` under bash against a stub `curl` that serves canned SCP
    /// JSON and logs every request line to `$LOG`; returns (stdout, log).
    fn run_stubbed(script: &str, fw: &str, pols: &str, home: &std::path::Path) -> (String, String) {
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = r#"#!/usr/bin/env bash
url=${@: -1}; method=GET; body=
while [ $# -gt 0 ]; do case "$1" in -X) method=$2; shift;; --data-binary) body=$(cat "${2#@}"); shift;; esac; shift; done
printf '%s %s %s\n' "$method" "${url#https://www.servercontrolpanel.de}" "$body" >> "$LOG"
case "$url" in
  */token) cat "$HOME/tok.json" 2>/dev/null || printf '{"access_token":"acc.ess-tok","refresh_token":"ROTATED"}';;
  */userinfo) printf '{"sub":"u-u-i-d","id":4242}';;
  *'/servers?q='*) printf '[{"id":7,"name":"v2202501234","nickname":null}]';;
  */servers/7) printf '{"id":7,"serverLiveInfo":{"interfaces":[{"mac":"aa:bb:cc:dd:ee:ff","vlanInterface":false},{"mac":"11:22:33:44:55:66","vlanInterface":true}]}}';;
  */firewall) [ "$method" = GET ] && cat "$HOME/fw.json" || printf '{}';;
  *'/firewall-policies?q='*) cat "$HOME/pols.json";;
  */firewall-policies/99) [ "$method" = GET ] && { cat "$HOME/pol.json" 2>/dev/null || printf '{"id":99,"rules":null}'; } || printf '{"id":99}';;
  *) printf '{"id":99}';;
esac
"#;
        let curl = bin.join("curl");
        std::fs::write(&curl, stub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(home.join("fw.json"), fw).unwrap();
        std::fs::write(home.join("pols.json"), pols).unwrap();
        let log = home.join("log");
        let _ = std::fs::remove_file(&log);
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .env(
                "PATH",
                format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
            )
            .env("HOME", home)
            .env_remove("XDG_STATE_HOME")
            .env("LOG", &log)
            .env(
                "NETCUP_SCP_REFRESH_TOKEN",
                std::fs::read_to_string(home.join("rt")).unwrap_or("s3cret-refresh".into()),
            )
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            !stdout.contains("s3cret") && !stderr.contains("s3cret"),
            "token leaked"
        );
        assert!(!stdout.contains("acc.ess-tok") && !stderr.contains("acc.ess-tok"));
        (
            stdout + &stderr,
            std::fs::read_to_string(&log).unwrap_or_default(),
        )
    }

    fn have_jq() -> bool {
        std::process::Command::new("jq")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn tmp_home(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("anvil-netcup-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn stubbed_apply_creates_attaches_snapshots_and_rolls_back() {
        if !have_jq() {
            eprintln!("skipped: jq not installed");
            return;
        }
        let home = tmp_home("apply");
        let m = module(vec![]);
        let d = m.declaration();
        // Other user's policy 424242 attached, anvil's policy absent.
        let fw = r#"{"userPolicies":[{"id":424242,"name":"other-user"}],"copiedPolicies":[{"id":5}],"active":true}"#;
        let (out, log) = run_stubbed(&d.render_apply(), fw, "[]", &home);
        assert!(
            out.contains("CHANGED: netcup SCP firewall policy anvil has the desired rules"),
            "{out}"
        );
        assert!(
            out.contains("CHANGED: netcup SCP firewall policy anvil attached"),
            "{out}"
        );
        assert!(
            out.contains("for a different session"),
            "rotation warned: {out}"
        );
        // Created with the guard rule, attached next to the other policy.
        assert!(
            log.contains("POST /scp-core/api/v1/users/4242/firewall-policies {\"name\":\"anvil\""),
            "{log}"
        );
        assert!(log.contains("\"destinationPorts\":\"22\""), "{log}");
        assert!(log.contains(
            "PUT /scp-core/api/v1/servers/7/interfaces/aa:bb:cc:dd:ee:ff/firewall \
             {\"copiedPolicies\":[{\"id\":5}],\"userPolicies\":[{\"id\":424242},{\"id\":99}],\"active\":true}"
        ), "{log}");
        assert!(
            !log.contains("PUT /scp-core/api/v1/users"),
            "never edits other policies: {log}"
        );
        let snap = home.join(".local/state/anvil/netcup/7-aabbccddeeff.json");
        assert_eq!(
            std::fs::read_to_string(&snap).unwrap().trim(),
            r#"{"userPolicies":[{"id":424242}]}"#
        );

        // Rollback PUTs the snapshot set back and removes the snapshot.
        let fw_now =
            r#"{"userPolicies":[{"id":424242},{"id":99}],"copiedPolicies":[],"active":true}"#;
        let (out, log) = run_stubbed(&d.render_rollback(), fw_now, "[]", &home);
        assert!(out.contains("CHANGED: netcup: restored"), "{out}");
        assert!(log.contains("\"userPolicies\":[{\"id\":424242}]"), "{log}");
        assert!(!snap.exists());
        // Second rollback: no snapshot, no API call at all.
        let (out, log) = run_stubbed(&d.render_rollback(), fw_now, "[]", &home);
        assert!(out.contains("OK: netcup: no attachment snapshot"), "{out}");
        assert!(log.is_empty(), "{log}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn stubbed_probe_agrees_with_converged_state_and_is_read_only() {
        if !have_jq() {
            eprintln!("skipped: jq not installed");
            return;
        }
        let home = tmp_home("probe");
        let m = module(vec![]);
        // The live policy as SCP returns it: extra fields, null defaults.
        let mut live = rules(&m);
        for r in &mut live {
            r["numberOfEffectiveRules"] = 1.into();
            r["sourcePorts"] = serde_json::Value::Null;
            // As seen on the real SCP: the side anvil leaves unset comes back filled.
            r["destinations"] = serde_json::json!(["0.0.0.0/0"]);
        }
        // As seen live: the list carries no rules; GET by id does.
        let pols = serde_json::json!([{"id": 99, "name": "anvil", "rules": null},
                                     {"id": 424242, "name": "anvil-old", "rules": null}])
        .to_string();
        std::fs::write(
            home.join("pol.json"),
            serde_json::json!({"id": 99, "name": "anvil", "rules": live}).to_string(),
        )
        .unwrap();
        let fw = r#"{"userPolicies":[{"id":424242},{"id":99}],"copiedPolicies":[],"active":true}"#;
        // SCP reissues the offline token each refresh (same sid, new exp):
        // that is no rotation and must not warn.
        let jwt = |claims: &str| {
            use base64::Engine;
            let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
            format!("h.{b}.s3cret-sig")
        };
        std::fs::write(home.join("rt"), jwt(r#"{"sid":"s1","exp":1}"#)).unwrap();
        let reissued = jwt(r#"{"sid":"s1","exp":2}"#);
        std::fs::write(
            home.join("tok.json"),
            format!(r#"{{"access_token":"acc.ess-tok","refresh_token":"{reissued}"}}"#),
        )
        .unwrap();
        let (out, log) = run_stubbed(&m.declaration().render_probe(), fw, &pols, &home);
        assert!(!out.contains("DRIFTED"), "{out}");
        assert!(
            !out.contains("different"),
            "same session is no rotation: {out}"
        );
        assert_eq!(out.matches("OK: ").count(), 3, "{out}");
        for line in log.lines() {
            assert!(
                line.starts_with("GET ")
                    || line.starts_with("POST /realms/scp/protocol/openid-connect/token"),
                "probe is read-only: {line}"
            );
        }
        let other_session = jwt(r#"{"sid":"s2","exp":2}"#);
        std::fs::write(
            home.join("tok.json"),
            format!(r#"{{"access_token":"acc.ess-tok","refresh_token":"{other_session}"}}"#),
        )
        .unwrap();
        let (out, _) = run_stubbed(&m.declaration().render_probe(), fw, &pols, &home);
        assert!(
            out.contains("for a different session"),
            "new session warns: {out}"
        );
        // A changed rule set is drift, and apply converges it with a PUT.
        let other = module(vec![rule("in", "tcp", Some("443"))]);
        let (out, _) = run_stubbed(&other.declaration().render_probe(), fw, &pols, &home);
        assert!(
            out.contains("DRIFTED: netcup SCP firewall policy anvil has the desired rules"),
            "{out}"
        );
        assert!(
            out.contains("OK: netcup SCP firewall policy anvil attached"),
            "{out}"
        );
        let (_, log) = run_stubbed(&other.declaration().render_apply(), fw, &pols, &home);
        assert!(
            log.contains("PUT /scp-core/api/v1/users/4242/firewall-policies/99 "),
            "{log}"
        );
        assert!(!log.contains("/firewall {"), "already attached: {log}");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn stubbed_preflight_fails_fast_without_token() {
        let m = module(vec![]);
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(m.declaration().render_apply())
            .env_remove("NETCUP_SCP_REFRESH_TOKEN")
            .output()
            .unwrap();
        assert!(!out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("FAILED: netcup:"), "{stdout}");
        if have_jq() {
            assert!(
                stdout.contains("NETCUP_SCP_REFRESH_TOKEN is unset"),
                "{stdout}"
            );
        }
    }

    #[test]
    fn allowlist_refuses_everything_else() {
        let re = format!("^({})$", ALLOWLIST.join("|"));
        let check = |req: &str| {
            std::process::Command::new("bash")
                .args(["-c", "[[ \"$1\" =~ $2 ]]", "_", req, &re])
                .status()
                .unwrap()
                .success()
        };
        for ok in [
            "POST /realms/scp/protocol/openid-connect/token",
            "GET /realms/scp/protocol/openid-connect/userinfo",
            "GET /scp-core/api/v1/servers?q=v22%20x",
            "GET /scp-core/api/v1/servers/7",
            "PUT /scp-core/api/v1/servers/7/interfaces/aa:bb:cc:dd:ee:ff/firewall",
            "POST /scp-core/api/v1/users/1/firewall-policies",
            "GET /scp-core/api/v1/users/1/firewall-policies?q=anvil",
            "PUT /scp-core/api/v1/users/1/firewall-policies/9",
            "GET /scp-core/api/v1/users/1/firewall-policies/9",
        ] {
            assert!(check(ok), "{ok}");
        }
        for bad in [
            "DELETE /scp-core/api/v1/users/1/firewall-policies/9",
            "POST /scp-core/api/v1/users/1/firewall-policies/9",
            "PUT /scp-core/api/v1/servers/7",
            "POST /scp-core/api/v1/servers/7/interfaces/aa:bb:cc:dd:ee:ff/firewall:reapply",
            "GET /scp-core/api/v1/servers/7/disks",
            "GET /scp-core/api/v1/servers/../7",
            "GET /scp-core/api/v1/servers?q=a/b",
            "POST /scp-core/api/v1/servers/7/snapshots",
            "GET /realms/scp/protocol/openid-connect/token",
            "GET /scp-core/api/v1/servers/7 x",
        ] {
            assert!(!check(bad), "{bad}");
        }
        // The prelude carries exactly this allowlist.
        assert!(module(vec![]).prelude().contains(&re));
    }

    #[test]
    fn curl_is_only_called_inside_scp() {
        let apply = module(vec![]).declaration().render_apply();
        let curls = apply.matches("curl -sS -f --proto '=https'").count();
        let blocks = apply.matches("\n__scp() {").count();
        assert_eq!(curls, 3 * blocks, "three curl forms per __scp definition");
        assert_eq!(
            apply.matches("curl -").count(),
            curls,
            "no curl outside __scp:\n{apply}"
        );
        // The refresh token is touched only by the -n check and the builtin write.
        assert_eq!(
            apply.matches("$NETCUP_SCP_REFRESH_TOKEN\"").count(),
            blocks,
            "{apply}"
        );
        assert!(apply.contains("umask 077"));
        assert!(apply.contains("trap 'rm -rf \"$__scp_dir\"' EXIT"));
        assert!(apply.contains("-K \"$__scp_dir/auth\""));
        assert!(apply.contains("refresh_token@$__scp_dir/rt"));
    }

    #[test]
    fn probe_never_mutates() {
        let probe = module(vec![]).declaration().render_probe();
        for verb in [
            "__scp PUT",
            "__scp POST \"/scp",
            "mv ",
            "rm -f \"$__scp_state",
        ] {
            assert!(!probe.contains(verb), "{verb} in probe");
        }
        assert!(probe.contains("__scp_fw"));
    }

    #[test]
    fn config_values_are_shell_escaped() {
        let mut s = section(vec![]);
        s.server = "x'; rm -rf /".into();
        s.policy = "p$(id)".into();
        let apply = NetcupModule::new(s, 22, vec![])
            .declaration()
            .render_apply();
        assert!(apply.contains(r#"__scp_srv='x'\''; rm -rf /'"#), "{apply}");
        assert!(apply.contains("__scp_pol='p$(id)'"), "{apply}");
    }

    #[test]
    fn rules_map_to_the_scp_schema() {
        let mut out = rule("out", "udp", Some("53"));
        out.source_ips = vec!["10.0.0.0/8".into()];
        let mut icmp6 = rule("in", "icmpv6", None);
        icmp6.description = Some("ping6".into());
        let r = rules(&module(vec![out, icmp6]));
        assert_eq!(
            r[1],
            serde_json::json!({"direction": "EGRESS", "protocol": "UDP", "action": "ACCEPT",
                               "destinations": ["10.0.0.0/8"], "destinationPorts": "53"})
        );
        assert_eq!(
            r[2],
            serde_json::json!({"direction": "INGRESS", "protocol": "ICMPv6", "action": "ACCEPT",
                               "description": "ping6"})
        );
        assert_eq!(r[0]["sources"], serde_json::json!(["0.0.0.0/0", "::/0"]));
    }

    #[test]
    fn ssh_guard_follows_hetzner_semantics() {
        assert_eq!(ssh_guards(&module(vec![]), "22"), 1);
        let m = NetcupModule::new(section(vec![]), 2222, vec![2200]);
        for port in ["2222", "22", "2200"] {
            assert_eq!(ssh_guards(&m, port), 1, "{port}");
        }
        let mut off = section(vec![rule("in", "udp", Some("41641"))]);
        off.keep_public_ssh = false;
        let m = NetcupModule::new(off, 2222, vec![2200]);
        assert_eq!(rules(&m).len(), 1, "no guard with keep_public_ssh = false");
        assert!(!m.rules_json().contains("R61"));
        // Unlike hetzner, a source-restricted rule IS the guard: SSH stays
        // limited to the configured sources, never opened to the world.
        let mut office = rule("in", "tcp", Some("22"));
        office.source_ips = vec!["203.0.113.7/32".into()];
        let m = module(vec![office]);
        assert_eq!(ssh_guards(&m, "22"), 1);
        assert!(!m.rules_json().contains("0.0.0.0/0"), "{}", m.rules_json());
        // …per port: covering 2222 still guards 22 during the cutover.
        let mut office = rule("in", "tcp", Some("2222"));
        office.source_ips = vec!["203.0.113.7/32".into()];
        let m = NetcupModule::new(section(vec![office]), 2222, vec![]);
        assert!(m.rules_json().contains("always allow SSH on tcp/22 "));
        assert!(!m.rules_json().contains("always allow SSH on tcp/2222"));
    }

    #[test]
    fn declaration_runs_locally_with_a_rollback() {
        let d = module(vec![]).declaration();
        assert!(d.runs_locally);
        assert_eq!(d.commands.len(), 3);
        assert!(d
            .render_rollback()
            .contains("restored the attached policy set"));
    }
}
