//! Deterministic ordering resolver (R51).
//!
//! Produces a total run order from (a) each module's default wave, (b) user
//! `before`/`after` hints and `[execution_order]`, and (c) the non-negotiable
//! safety constraints encoded as **hard edges**. It is a topological sort
//! with stable tie-breaking; cycles and safety violations are hard errors.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::EnabledSection;
use crate::error::{AnvilError, Result};

/// Default wave for each module id. Lower runs earlier. This is the tie-break
/// baseline; explicit `order`/hints refine it.
pub fn default_order(id: &str) -> i64 {
    match id {
        "users" => 10,
        "packages" => 15,
        "sshd" => 20,
        "ssh_crypto" => 25,
        "kernel" => 30,
        "kernel_modules" => 31,
        "pam" => 32,
        "process" => 33,
        "dns" => 34,
        "suid" => 35,
        "filesystem" => 36,
        "auditd" => 37,
        "fail2ban" => 40,
        "crowdsec" => 41,
        "firewall" => 50,
        "docker" => 55,
        "podman" => 55,
        "containers" => 57,
        "forgejo" => 58,
        "tls" => 56,
        // After firewall, so 80/443 are open before Caddy requests certificates.
        "caddy" => 57,
        // Before the runners: their units put Slice= on it.
        "ci_resources" => 57,
        // Before the apps (57-63): their units/drop-ins put Slice= on it.
        "apps_resources" => 56,
        "github_runner" => 58,
        // After forgejo (58): a runner on the same host connects to it.
        "forgejo_runner" => 59,
        "headscale" => 60,
        "tailscale" => 61,
        "greptimedb" => 62,
        "vector" => 63,
        // After firewall (its ufw rule needs an active ufw) and tailscale.
        "beszel" => 64,
        "restic" => 64,
        "hetzner" => 65,
        "netcup" => 65,
        "lynis" => 90,
        "updates" => 100,
        // Plugins (`plugin::<name>`) default to running after every built-in
        // module but before updates; manifest hints refine this, and
        // the R58 hard edge keeps updates last regardless.
        p if p.starts_with("plugin::") => 95,
        _ => 70,
    }
}

/// Compute the run order for the enabled sections.
pub fn resolve_order(
    enabled: &[EnabledSection],
    execution_order: Option<&[String]>,
) -> Result<Vec<String>> {
    if enabled.is_empty() {
        return Err(AnvilError::EmptyOrder);
    }

    let nodes: BTreeSet<String> = enabled.iter().map(|e| e.id.to_string()).collect();
    let present = |id: &str| nodes.contains(id);

    // Effective tie-break order: default, overridden by an explicit `order`.
    let mut effective: BTreeMap<String, i64> = BTreeMap::new();
    for e in enabled {
        let ord = e
            .order_override
            .order
            .unwrap_or_else(|| default_order(e.id));
        effective.insert(e.id.to_string(), ord);
    }

    // Guard against explicit execution_order that contradicts the hard edges.
    if let Some(list) = execution_order {
        check_execution_order_safety(list, &nodes)?;
    }

    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    let add_edge = |from: &str, to: &str, edges: &mut BTreeSet<(String, String)>| {
        if present(from) && present(to) && from != to {
            edges.insert((from.to_string(), to.to_string()));
        }
    };

    // (c) Safety hard edges.
    add_edge("sshd", "firewall", &mut edges); // R56
    add_edge("sshd", "ssh_crypto", &mut edges); // R57 separate waves
    add_edge("ssh_crypto", "firewall", &mut edges); // R56: fence after every SSH change
                                                    // T10: the cloud edge may close public SSH only after tailscale had its
                                                    // chance to prove (or fail) the tailnet path in this run.
    add_edge("tailscale", "hetzner", &mut edges);
    add_edge("tailscale", "netcup", &mut edges);
    // GR22: the runner units run in the slice this writes.
    add_edge("ci_resources", "github_runner", &mut edges);
    add_edge("ci_resources", "forgejo_runner", &mut edges);
    // The apps' units/drop-ins put Slice= on the slice this writes.
    for app in ["caddy", "forgejo", "greptimedb", "vector", "containers"] {
        add_edge("apps_resources", app, &mut edges);
    }
    // The engine's containers.conf drop-in (netavark iptables driver)
    // is in place before a runner starts Podman (v2 sandboxes, docker = "podman").
    add_edge("podman", "github_runner", &mut edges);
    add_edge("containers", "github_runner", &mut edges);
    add_edge("podman", "forgejo_runner", &mut edges);
    add_edge("containers", "forgejo_runner", &mut edges);
    // The forgejo jail's logpath exists only once Forgejo has started;
    // fail2ban rejects a jail without its log and would revert every jail.
    add_edge("forgejo", "fail2ban", &mut edges);
    if present("updates") {
        for id in &nodes {
            if id != "updates" {
                edges.insert((id.clone(), "updates".to_string())); // R58 last
            }
        }
    }

    // (b) User/manifest hints. R58 applies to hints too — nothing (module or
    // plugin) may demand to run after updates, and updates may not demand to
    // run before anything; report a safety violation instead of an opaque
    // cycle.
    if present("updates") {
        for e in enabled {
            if e.id != "updates" && e.order_override.after.iter().any(|a| a == "updates") {
                return Err(AnvilError::Safety(format!(
                    "{} declares after = [\"updates\"], but updates (and any reboot) \
                     must run after every other module (R58)",
                    e.id
                )));
            }
            if e.id == "updates"
                && e.order_override
                    .before
                    .iter()
                    .any(|b| b != "updates" && present(b))
            {
                return Err(AnvilError::Safety(
                    "updates declares before-hints, but updates (and any reboot) \
                     must run after every other module (R58)"
                        .into(),
                ));
            }
        }
    }
    for e in enabled {
        for b in &e.order_override.before {
            add_edge(e.id, b, &mut edges);
        }
        for a in &e.order_override.after {
            add_edge(a, e.id, &mut edges);
        }
    }
    if let Some(list) = execution_order {
        let filtered: Vec<&String> = list.iter().filter(|m| present(m)).collect();
        for pair in filtered.windows(2) {
            add_edge(pair[0], pair[1], &mut edges);
        }
    }

    let ordered = topo_sort(&nodes, &edges, &effective)?;

    // Belt-and-suspenders: re-assert the safety invariants on the result.
    assert_safety(&ordered)?;
    Ok(ordered)
}

/// Rollback order for an apply-ordered selection: reverse apply order
/// (CR1: undo the last change first, so `containers` goes before `docker`),
/// except that `sshd` and `ssh_crypto` roll back before `firewall`, whose
/// rollback then allows the port the restored sshd listens on. Safe because
/// anvil never deletes ufw rules: the current connection's port stays allowed.
pub fn rollback_order<T>(apply_order: &[T], id: impl Fn(&T) -> &str) -> Vec<&T> {
    let (ssh, mut out): (Vec<&T>, Vec<&T>) = apply_order
        .iter()
        .rev()
        .partition(|m| matches!(id(m), "sshd" | "ssh_crypto"));
    match out.iter().position(|m| id(m) == "firewall") {
        Some(at) => {
            out.splice(at..at, ssh);
            out
        }
        None => apply_order.iter().rev().collect(),
    }
}

/// Kahn's algorithm with a stable tie-break: among nodes whose predecessors are
/// all placed, pick the one with the lowest `(effective_order, id)`.
fn topo_sort(
    nodes: &BTreeSet<String>,
    edges: &BTreeSet<(String, String)>,
    effective: &BTreeMap<String, i64>,
) -> Result<Vec<String>> {
    let mut indeg: BTreeMap<String, usize> = nodes.iter().map(|n| (n.clone(), 0)).collect();
    let mut adj: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (from, to) in edges {
        adj.entry(from.clone()).or_default().push(to.clone());
        // Every edge endpoint is in `nodes` (edges are derived from it), so
        // `to` is always present in `indeg` — but use a real error rather than
        // `.expect` so a future invariant break surfaces cleanly.
        *indeg.get_mut(to).ok_or_else(|| {
            AnvilError::Validation(format!("ordering edge targets unknown node {to}"))
        })? += 1;
    }

    let key = |id: &str| (*effective.get(id).unwrap_or(&70), id.to_string());

    let mut ready: BTreeSet<(i64, String)> = indeg
        .iter()
        .filter(|(_, &d)| d == 0)
        .map(|(n, _)| key(n))
        .collect();

    let mut out = Vec::with_capacity(nodes.len());
    while let Some((_, n)) = ready.iter().next().cloned() {
        ready.remove(&(key(&n).0, n.clone()));
        out.push(n.clone());
        if let Some(succs) = adj.get(&n) {
            for s in succs {
                let d = indeg.get_mut(s).ok_or_else(|| {
                    AnvilError::Validation(format!("ordering successor {s} is unknown"))
                })?;
                *d -= 1;
                if *d == 0 {
                    ready.insert(key(s));
                }
            }
        }
    }

    if out.len() != nodes.len() {
        let stuck: Vec<String> = indeg
            .iter()
            .filter(|(_, &d)| d > 0)
            .map(|(n, _)| n.clone())
            .collect();
        return Err(AnvilError::OrderingCycle(format!(
            "cycle among modules: {}",
            stuck.join(", ")
        )));
    }
    Ok(out)
}

fn check_execution_order_safety(list: &[String], nodes: &BTreeSet<String>) -> Result<()> {
    let pos = |id: &str| list.iter().position(|m| m == id);
    let both = |a: &str, b: &str| nodes.contains(a) && nodes.contains(b);

    if both("sshd", "firewall") {
        if let (Some(s), Some(f)) = (pos("sshd"), pos("firewall")) {
            if s > f {
                return Err(AnvilError::Safety(
                    "execution_order places `firewall` before `sshd`; the firewall must \
                     run after sshd so the effective SSH port is known (R56)"
                        .into(),
                ));
            }
        }
    }
    if both("sshd", "ssh_crypto") {
        if let (Some(s), Some(c)) = (pos("sshd"), pos("ssh_crypto")) {
            if s > c {
                return Err(AnvilError::Safety(
                    "execution_order places `ssh_crypto` before `sshd`; crypto changes must \
                     run after the sshd config wave (R57)"
                        .into(),
                ));
            }
        }
    }
    for edge in PROVIDER_FIREWALLS {
        if both("tailscale", edge) && edge_before_tailscale(list, edge) {
            return Err(AnvilError::Safety(format!(
                "execution_order places `{edge}` before `tailscale`; the provider firewall \
                 must run after the tailnet join it may rely on for SSH (T10)"
            )));
        }
    }
    if nodes.contains("updates") {
        if let Some(u) = pos("updates") {
            let last_present = list.iter().rposition(|m| nodes.contains(m)).unwrap_or(u);
            if u != last_present {
                return Err(AnvilError::Safety(
                    "execution_order does not place `updates` last; updates (and any reboot) \
                     must run after every other module (R58)"
                        .into(),
                ));
            }
        }
    }
    Ok(())
}

/// Provider (cloud-edge) firewalls: each runs after `tailscale` (T10).
pub const PROVIDER_FIREWALLS: &[&str] = &["hetzner", "netcup"];

/// True when `list` has both `tailscale` and `edge`, `edge` first (T10).
fn edge_before_tailscale(list: &[String], edge: &str) -> bool {
    let first = list.iter().find(|m| *m == "tailscale" || *m == edge);
    first.is_some_and(|m| m == edge) && list.iter().any(|m| m == "tailscale")
}

/// Final invariant check on the produced order.
fn assert_safety(order: &[String]) -> Result<()> {
    let pos = |id: &str| order.iter().position(|m| m == id);
    if let (Some(s), Some(f)) = (pos("sshd"), pos("firewall")) {
        if s > f {
            return Err(AnvilError::Safety(
                "resolved order runs firewall before sshd (R56)".into(),
            ));
        }
    }
    if let (Some(s), Some(c)) = (pos("sshd"), pos("ssh_crypto")) {
        if s > c {
            return Err(AnvilError::Safety(
                "resolved order runs ssh_crypto before sshd (R57)".into(),
            ));
        }
    }
    if let (Some(c), Some(f)) = (pos("ssh_crypto"), pos("firewall")) {
        if c > f {
            return Err(AnvilError::Safety(
                "resolved order runs firewall before ssh_crypto (R56)".into(),
            ));
        }
    }
    for edge in PROVIDER_FIREWALLS {
        if edge_before_tailscale(order, edge) {
            return Err(AnvilError::Safety(format!(
                "resolved order runs {edge} before tailscale (T10)"
            )));
        }
    }
    if let Some(u) = pos("updates") {
        if u != order.len() - 1 {
            return Err(AnvilError::Safety(
                "resolved order does not run updates last (R58)".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::OrderOverride;

    fn sections(ids: &[&str]) -> Vec<EnabledSection> {
        ids.iter()
            .map(|id| EnabledSection {
                id: crate::config::MODULE_IDS
                    .iter()
                    .find(|m| **m == *id)
                    .expect("known id"),
                order_override: OrderOverride::default(),
            })
            .collect()
    }

    #[test]
    fn canonical_order_of_all_modules_is_pinned() {
        // Pins the default wave table itself: dropping or renumbering any
        // module's wave reorders this sequence (surfaced by mutation testing —
        // every `default_order` match arm could be deleted without a test
        // failing). The exceptions are `lynis` and `updates`, whose positions
        // are additionally held by the R58 hard edge / their high waves.
        let order = resolve_order(&sections(crate::config::MODULE_IDS), None).unwrap();
        let expected = [
            "users",
            "packages",
            "sshd",
            "ssh_crypto",
            "kernel",
            "kernel_modules",
            "pam",
            "process",
            "dns",
            "suid",
            "filesystem",
            "auditd",
            "crowdsec",
            "firewall",
            "docker",
            "podman",
            "apps_resources",
            "tls",
            "caddy",
            "ci_resources",
            "containers",
            "forgejo",
            "fail2ban",
            "github_runner",
            "forgejo_runner",
            "headscale",
            "tailscale",
            "greptimedb",
            "vector",
            "beszel",
            "restic",
            "hetzner",
            "netcup",
            "coding_agents",
            "lynis",
            "updates",
        ];
        assert_eq!(order, expected, "canonical wave order changed");
    }

    fn rollback(apply: &[String]) -> Vec<&str> {
        rollback_order(apply, |s| s.as_str())
            .into_iter()
            .map(String::as_str)
            .collect()
    }

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn canonical_rollback_order_is_pinned() {
        // Reverse apply order, with sshd/ssh_crypto pulled ahead of firewall
        // ; everything else, containers before docker included, keeps
        // its reversed position.
        let apply = resolve_order(&sections(crate::config::MODULE_IDS), None).unwrap();
        let expected = [
            "updates",
            "lynis",
            "coding_agents",
            "netcup",
            "hetzner",
            "restic",
            "beszel",
            "vector",
            "greptimedb",
            "tailscale",
            "headscale",
            "forgejo_runner",
            "github_runner",
            "fail2ban",
            "forgejo",
            "containers",
            "ci_resources",
            "caddy",
            "tls",
            "apps_resources",
            "podman",
            "docker",
            "ssh_crypto",
            "sshd",
            "firewall",
            "crowdsec",
            "auditd",
            "filesystem",
            "suid",
            "dns",
            "process",
            "pam",
            "kernel_modules",
            "kernel",
            "packages",
            "users",
        ];
        assert_eq!(
            rollback(&apply),
            expected,
            "canonical rollback order changed"
        );
    }

    #[test]
    fn rollback_restores_sshd_before_firewall_under_hostile_overrides() {
        // Whatever apply order the resolver accepts, sshd and
        // ssh_crypto roll back before firewall (so ufw re-allows the restored
        // port) and containers still rolls back before docker (CR1).
        let all = [
            "sshd",
            "ssh_crypto",
            "firewall",
            "docker",
            "containers",
            "kernel",
        ];
        let with = |id: &str, f: &dyn Fn(&mut OrderOverride)| {
            let mut secs = sections(&all);
            f(&mut secs.iter_mut().find(|s| s.id == id).unwrap().order_override);
            secs
        };
        let mut cases: Vec<(Vec<EnabledSection>, Option<Vec<String>>)> = vec![
            (sections(&all), None),
            (with("firewall", &|o| o.order = Some(1)), None),
            (with("firewall", &|o| o.order = Some(21)), None),
            (with("sshd", &|o| o.order = Some(1_000)), None),
            (with("ssh_crypto", &|o| o.order = Some(1_000)), None),
            (with("docker", &|o| o.order = Some(1)), None),
            (with("kernel", &|o| o.before = vec!["sshd".into()]), None),
            (with("firewall", &|o| o.after = vec!["docker".into()]), None),
            (with("sshd", &|o| o.after = vec!["containers".into()]), None),
            (
                sections(&all),
                Some(ids(&[
                    "kernel",
                    "docker",
                    "containers",
                    "sshd",
                    "ssh_crypto",
                    "firewall",
                ])),
            ),
        ];
        let mut p = plugin("plugin::edge");
        p.order_override.before = vec!["firewall".into()];
        let mut secs = sections(&all);
        secs.push(p);
        cases.push((secs, None));

        for (secs, eo) in cases {
            let apply = resolve_order(&secs, eo.as_deref()).unwrap();
            let rb = rollback(&apply);
            let pos = |id: &str| rb.iter().position(|m| *m == id).unwrap();
            assert!(pos("sshd") < pos("firewall"), "apply {apply:?} → {rb:?}");
            assert!(
                pos("ssh_crypto") < pos("firewall"),
                "apply {apply:?} → {rb:?}"
            );
            assert!(
                pos("containers") < pos("docker"),
                "apply {apply:?} → {rb:?}"
            );
            assert_eq!(rb.len(), apply.len(), "rollback drops nothing");
        }
    }

    #[test]
    fn rollback_subset_keeps_the_ssh_exception() {
        // `rollback --only firewall,sshd`: the selection keeps apply order.
        assert_eq!(rollback(&ids(&["sshd", "firewall"])), ["sshd", "firewall"]);
        // Each of sshd / ssh_crypto moves on its own.
        assert_eq!(
            rollback(&ids(&["ssh_crypto", "firewall"])),
            ["ssh_crypto", "firewall"]
        );
        assert_eq!(
            rollback(&ids(&["sshd", "kernel", "firewall", "dns"])),
            ["dns", "sshd", "firewall", "kernel"]
        );
    }

    #[test]
    fn rollback_without_firewall_is_plain_reverse() {
        let apply = ids(&["kernel", "sshd", "ssh_crypto", "dns"]);
        assert_eq!(rollback(&apply), ["dns", "ssh_crypto", "sshd", "kernel"]);
        assert!(rollback(&[]).is_empty());
    }

    #[test]
    fn apps_resources_runs_before_every_app_under_hostile_overrides() {
        // Their units/drop-ins put Slice= on the slice it writes; an app that
        // ran first would start outside apps.slice.
        let ids = [
            "apps_resources",
            "caddy",
            "forgejo",
            "greptimedb",
            "vector",
            "containers",
        ];
        let mut s = sections(&ids);
        for e in s.iter_mut() {
            // The apps demand the earliest order, the slice the latest.
            e.order_override.order = Some(if e.id == "apps_resources" { 1_000 } else { 1 });
        }
        let order = resolve_order(&s, None).unwrap();
        assert_eq!(
            order[0], "apps_resources",
            "hard edge beats order: {order:?}"
        );

        // A before-hint the other way is a cycle, not a silent reorder.
        let mut s = sections(&["apps_resources", "caddy"]);
        s[1].order_override.before = vec!["apps_resources".into()];
        let err = resolve_order(&s, None).unwrap_err();
        assert!(
            matches!(err, AnvilError::OrderingCycle(_)),
            "expected a cycle: {err}"
        );
    }

    #[test]
    fn fail2ban_runs_after_forgejo_under_hostile_overrides() {
        // The forgejo jail's log exists only once Forgejo runs; a fail2ban
        // apply before it would fail validation and revert every jail.
        let mut s = sections(&["fail2ban", "forgejo"]);
        s[0].order_override.order = Some(1);
        s[1].order_override.order = Some(99);
        assert_eq!(resolve_order(&s, None).unwrap(), ["forgejo", "fail2ban"]);
    }

    #[test]
    fn firewall_runs_after_sshd() {
        let order = resolve_order(&sections(&["firewall", "sshd"]), None).unwrap();
        let s = order.iter().position(|m| m == "sshd").unwrap();
        let f = order.iter().position(|m| m == "firewall").unwrap();
        assert!(s < f, "sshd before firewall, got {order:?}");
    }

    #[test]
    fn updates_runs_last() {
        let order =
            resolve_order(&sections(&["updates", "sshd", "firewall", "kernel"]), None).unwrap();
        assert_eq!(order.last().unwrap(), "updates");
    }

    #[test]
    fn ssh_crypto_after_sshd() {
        let order = resolve_order(&sections(&["ssh_crypto", "sshd"]), None).unwrap();
        let s = order.iter().position(|m| m == "sshd").unwrap();
        let c = order.iter().position(|m| m == "ssh_crypto").unwrap();
        assert!(s < c);
    }

    #[test]
    fn firewall_order_override_cannot_precede_sshd() {
        // R56 is a hard edge, not a wave default: an explicit order far below
        // sshd's wave still cannot move the firewall before sshd (running the
        // firewall first would fence off a not-yet-moved SSH port).
        let mut secs = sections(&["sshd", "firewall"]);
        secs.iter_mut()
            .find(|s| s.id == "firewall")
            .unwrap()
            .order_override
            .order = Some(1);
        let order = resolve_order(&secs, None).unwrap();
        let s = order.iter().position(|m| m == "sshd").unwrap();
        let f = order.iter().position(|m| m == "firewall").unwrap();
        assert!(s < f, "hard edge must beat explicit order, got {order:?}");
    }

    #[test]
    fn ssh_crypto_order_override_cannot_precede_sshd() {
        // Same for R57: crypto changes stay after the sshd config wave even
        // under an explicit early order.
        let mut secs = sections(&["sshd", "ssh_crypto"]);
        secs.iter_mut()
            .find(|s| s.id == "ssh_crypto")
            .unwrap()
            .order_override
            .order = Some(1);
        let order = resolve_order(&secs, None).unwrap();
        let s = order.iter().position(|m| m == "sshd").unwrap();
        let c = order.iter().position(|m| m == "ssh_crypto").unwrap();
        assert!(s < c, "hard edge must beat explicit order, got {order:?}");
    }

    #[test]
    fn firewall_order_override_cannot_precede_ssh_crypto() {
        // Order 21 sits between sshd (20) and ssh_crypto (25); without
        // the hard edge the firewall would enable before the crypto reload,
        // and the "skip after ssh_crypto failed" fence would never fire.
        let mut secs = sections(&["sshd", "ssh_crypto", "firewall"]);
        secs.iter_mut()
            .find(|s| s.id == "firewall")
            .unwrap()
            .order_override
            .order = Some(21);
        let order = resolve_order(&secs, None).unwrap();
        let c = order.iter().position(|m| m == "ssh_crypto").unwrap();
        let f = order.iter().position(|m| m == "firewall").unwrap();
        assert!(c < f, "hard edge must beat explicit order, got {order:?}");
        // assert_safety rejects the inverted order on its own.
        let bad: Vec<String> = ["sshd", "firewall", "ssh_crypto"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(matches!(assert_safety(&bad), Err(AnvilError::Safety(_))));
    }

    #[test]
    fn hetzner_cannot_precede_tailscale_under_hostile_overrides() {
        // T10: with keep_public_ssh = false the cloud edge relies on the
        // tailnet; hostile order / before-hints / execution_order never move
        // hetzner ahead of tailscale.
        let mut secs = sections(&["tailscale", "hetzner"]);
        secs[1].order_override.order = Some(1);
        let order = resolve_order(&secs, None).unwrap();
        assert_eq!(order, ["tailscale", "hetzner"], "hard edge beats order");

        let mut secs = sections(&["tailscale", "hetzner"]);
        secs[1].order_override.before = vec!["tailscale".into()];
        let err = resolve_order(&secs, None).unwrap_err();
        assert!(
            matches!(err, AnvilError::OrderingCycle(_) | AnvilError::Safety(_)),
            "{err}"
        );

        let list: Vec<String> = ["hetzner", "tailscale"].map(String::from).to_vec();
        let err = resolve_order(&sections(&["tailscale", "hetzner"]), Some(&list)).unwrap_err();
        assert!(
            matches!(err, AnvilError::Safety(ref m) if m.contains("T10")),
            "{err}"
        );

        let bad: Vec<String> = ["hetzner", "tailscale"].map(String::from).to_vec();
        assert!(matches!(assert_safety(&bad), Err(AnvilError::Safety(_))));
        // Either one alone is no violation, even if execution_order names both.
        for alone in [["hetzner"], ["tailscale"]] {
            let one: Vec<String> = alone.map(String::from).to_vec();
            assert!(assert_safety(&one).is_ok());
            resolve_order(&sections(&alone), Some(&list)).unwrap();
        }
    }

    #[test]
    fn netcup_cannot_precede_tailscale_under_hostile_overrides() {
        // T12: the SCP firewall gets the same T10 edge as hetzner.
        assert_eq!(
            default_order("netcup"),
            default_order("hetzner"),
            "same wave"
        );
        let mut secs = sections(&["tailscale", "netcup", "hetzner"]);
        secs[1].order_override.order = Some(1);
        secs[2].order_override.order = Some(0);
        let order = resolve_order(&secs, None).unwrap();
        assert_eq!(order[0], "tailscale", "hard edge beats order: {order:?}");

        let mut secs = sections(&["tailscale", "netcup"]);
        secs[1].order_override.before = vec!["tailscale".into()];
        let err = resolve_order(&secs, None).unwrap_err();
        assert!(
            matches!(err, AnvilError::OrderingCycle(_) | AnvilError::Safety(_)),
            "{err}"
        );

        let list: Vec<String> = ["netcup", "tailscale"].map(String::from).to_vec();
        let err = resolve_order(&sections(&["tailscale", "netcup"]), Some(&list)).unwrap_err();
        assert!(
            matches!(err, AnvilError::Safety(ref m) if m.contains("`netcup` before `tailscale`")),
            "{err}"
        );
        assert!(
            matches!(assert_safety(&list), Err(AnvilError::Safety(ref m)) if m.contains("netcup"))
        );
        // hetzner first in the list does not hide netcup's violation.
        let list: Vec<String> = ["hetzner", "netcup", "tailscale"]
            .map(String::from)
            .to_vec();
        assert!(assert_safety(&list).is_err());
        let ok: Vec<String> = ["tailscale", "hetzner", "netcup"]
            .map(String::from)
            .to_vec();
        assert!(assert_safety(&ok).is_ok());
        assert!(assert_safety(&["netcup".to_string()]).is_ok());
    }

    #[test]
    fn firewall_before_sshd_hint_is_a_hard_error() {
        // A hint that inverts R56 must fail loudly (it contradicts the safety
        // edge), never resolve to an order with the firewall first.
        let mut secs = sections(&["sshd", "firewall"]);
        secs.iter_mut()
            .find(|s| s.id == "firewall")
            .unwrap()
            .order_override
            .before = vec!["sshd".into()];
        let err = resolve_order(&secs, None).unwrap_err();
        assert!(
            matches!(err, AnvilError::OrderingCycle(_) | AnvilError::Safety(_)),
            "{err}"
        );
    }

    #[test]
    fn valid_execution_order_actually_reorders() {
        // The positive path: an explicit execution_order overrides the wave
        // default (kernel 30 < dns 34) when no safety edge is involved.
        let secs = sections(&["kernel", "dns"]);
        let eo = vec!["dns".to_string(), "kernel".to_string()];
        let order = resolve_order(&secs, Some(&eo)).unwrap();
        assert_eq!(order, vec!["dns".to_string(), "kernel".to_string()]);
    }

    #[test]
    fn execution_order_entries_for_absent_modules_are_ignored() {
        let secs = sections(&["kernel", "dns"]);
        let eo = vec![
            "dns".to_string(),
            "auditd".to_string(),
            "kernel".to_string(),
        ];
        let order = resolve_order(&secs, Some(&eo)).unwrap();
        assert_eq!(order, vec!["dns".to_string(), "kernel".to_string()]);
    }

    #[test]
    fn empty_is_rejected() {
        assert!(matches!(
            resolve_order(&[], None).unwrap_err(),
            AnvilError::EmptyOrder
        ));
    }

    #[test]
    fn user_cycle_is_detected() {
        let mut secs = sections(&["kernel", "dns"]);
        secs[0].order_override.before = vec!["dns".into()];
        secs[1].order_override.before = vec!["kernel".into()];
        assert!(matches!(
            resolve_order(&secs, None).unwrap_err(),
            AnvilError::OrderingCycle(_)
        ));
    }

    #[test]
    fn execution_order_violating_safety_is_rejected() {
        let secs = sections(&["sshd", "firewall"]);
        let eo = vec!["firewall".to_string(), "sshd".to_string()];
        assert!(matches!(
            resolve_order(&secs, Some(&eo)).unwrap_err(),
            AnvilError::Safety(_)
        ));
    }

    #[test]
    fn stable_tiebreak_is_deterministic() {
        let a = resolve_order(&sections(&["dns", "kernel", "pam", "suid"]), None).unwrap();
        let b = resolve_order(&sections(&["suid", "pam", "kernel", "dns"]), None).unwrap();
        assert_eq!(a, b, "order must not depend on input ordering");
    }

    fn plugin(id: &'static str) -> EnabledSection {
        EnabledSection {
            id,
            order_override: OrderOverride::default(),
        }
    }

    #[test]
    fn plugin_defaults_after_builtins_but_before_updates() {
        let mut secs = sections(&["sshd", "firewall", "lynis", "updates"]);
        secs.push(plugin("plugin::backup"));
        let order = resolve_order(&secs, None).unwrap();
        let pos = |id: &str| order.iter().position(|m| m == id).unwrap();
        // After every built-in except updates…
        assert!(pos("plugin::backup") > pos("sshd"));
        assert!(pos("plugin::backup") > pos("firewall"));
        assert!(pos("plugin::backup") > pos("lynis"));
        // …and updates still runs last (R58 applies to plugins too).
        assert_eq!(order.last().unwrap(), "updates");
    }

    #[test]
    fn plugin_manifest_hints_are_respected() {
        let mut secs = sections(&["sshd", "firewall", "updates"]);
        let mut p = plugin("plugin::edge");
        p.order_override.before = vec!["firewall".into()];
        p.order_override.after = vec!["sshd".into()];
        secs.push(p);
        let order = resolve_order(&secs, None).unwrap();
        let pos = |id: &str| order.iter().position(|m| m == id).unwrap();
        assert!(pos("sshd") < pos("plugin::edge"));
        assert!(pos("plugin::edge") < pos("firewall"));
        assert_eq!(order.last().unwrap(), "updates");
    }

    #[test]
    fn plugin_explicit_order_cannot_displace_updates() {
        // Even an absolute order far beyond updates' wave loses to the R58
        // hard edge: updates stays last.
        let mut secs = sections(&["sshd", "updates"]);
        let mut p = plugin("plugin::late");
        p.order_override.order = Some(1_000);
        secs.push(p);
        let order = resolve_order(&secs, None).unwrap();
        assert_eq!(order.last().unwrap(), "updates");
        assert!(order.contains(&"plugin::late".to_string()));
    }

    #[test]
    fn plugin_after_updates_hint_is_a_safety_error() {
        let mut secs = sections(&["sshd", "updates"]);
        let mut p = plugin("plugin::tail");
        p.order_override.after = vec!["updates".into()];
        secs.push(p);
        let err = resolve_order(&secs, None).unwrap_err();
        assert!(matches!(err, AnvilError::Safety(_)), "{err}");
        assert!(err.to_string().contains("plugin::tail"), "{err}");
    }

    #[test]
    fn updates_before_hint_is_a_safety_error() {
        let mut secs = sections(&["sshd", "updates"]);
        secs.iter_mut()
            .find(|s| s.id == "updates")
            .unwrap()
            .order_override
            .before = vec!["sshd".into()];
        let err = resolve_order(&secs, None).unwrap_err();
        assert!(matches!(err, AnvilError::Safety(_)), "{err}");
    }

    #[test]
    fn ci_slice_precedes_the_runners_under_hostile_overrides() {
        let pairs = [
            ("ci_resources", "github_runner"),
            ("ci_resources", "forgejo_runner"),
            ("podman", "github_runner"),
            ("containers", "github_runner"),
            ("podman", "forgejo_runner"),
            ("containers", "forgejo_runner"),
        ];
        for (first, runner) in pairs {
            let mut secs = sections(&[first, runner]);
            secs[0].order_override.order = Some(99);
            let order = resolve_order(&secs, None).unwrap();
            assert_eq!(order, [first, runner], "hard edge beats order");

            let mut secs = sections(&[first, runner]);
            secs[1].order_override.before = vec![first.into()];
            let err = resolve_order(&secs, None).unwrap_err();
            assert!(matches!(err, AnvilError::OrderingCycle(_)), "{err}");

            let list: Vec<String> = [runner, first].map(String::from).to_vec();
            let err = resolve_order(&sections(&[first, runner]), Some(&list)).unwrap_err();
            assert!(matches!(err, AnvilError::OrderingCycle(_)), "{err}");
        }
    }
}
