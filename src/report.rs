//! Compliance reporting for the `report` command.
//!
//! Maps every module id to a CIS-benchmark category and renders a coverage
//! table of *available* modules versus the ones *enabled* in the config. With
//! `--check`, a live drift verdict (gathered by the CLI via the probe engine) is
//! overlaid per module. Rendering is pure and unit-tested; the SSH probing lives
//! in the CLI.

use std::collections::BTreeMap;

use serde_json::json;

use crate::config::MODULE_IDS;

/// Static module → CIS-category assignment (Fixed-ish: keep stable so reports
/// are comparable over time). Every id in [`MODULE_IDS`] has exactly one entry;
/// [`cis_category`] falls back to a catch-all only defensively.
const CIS_CATEGORIES: &[(&str, &str)] = &[
    ("filesystem", "1 Initial Setup"),
    ("kernel_modules", "1 Initial Setup"),
    ("process", "1 Initial Setup"),
    ("updates", "1 Initial Setup"),
    ("packages", "2 Services"),
    ("docker", "2 Services"),
    ("podman", "2 Services"),
    ("containers", "2 Services"),
    ("forgejo", "2 Services"),
    ("dns", "2 Services"),
    ("tls", "2 Services"),
    ("caddy", "2 Services"),
    ("headscale", "2 Services"),
    ("tailscale", "2 Services"),
    ("greptimedb", "2 Services"),
    ("ci_resources", "2 Services"),
    ("apps_resources", "2 Services"),
    ("github_runner", "2 Services"),
    ("forgejo_runner", "2 Services"),
    ("coding_agents", "2 Services"),
    ("kernel", "3 Network Configuration"),
    ("firewall", "3 Network Configuration"),
    ("fail2ban", "3 Network Configuration"),
    ("crowdsec", "3 Network Configuration"),
    ("hetzner", "3 Network Configuration"),
    ("netcup", "3 Network Configuration"),
    ("auditd", "4 Logging and Auditing"),
    ("lynis", "4 Logging and Auditing"),
    ("vector", "4 Logging and Auditing"),
    ("beszel", "2 Services"),
    ("sshd", "5 Access, Authentication and Authorization"),
    ("ssh_crypto", "5 Access, Authentication and Authorization"),
    ("pam", "5 Access, Authentication and Authorization"),
    ("users", "5 Access, Authentication and Authorization"),
    ("suid", "6 System Maintenance"),
    ("restic", "6 System Maintenance"),
];

/// The CIS category a module contributes to.
pub fn cis_category(module_id: &str) -> &'static str {
    CIS_CATEGORIES
        .iter()
        .find(|(id, _)| *id == module_id)
        .map(|(_, cat)| *cat)
        .unwrap_or("Uncategorized")
}

/// Live drift verdict overlaid on an enabled module when `--check` is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    Aligned,
    Drifted,
    Failed,
}

impl DriftState {
    pub fn as_str(self) -> &'static str {
        match self {
            DriftState::Aligned => "aligned",
            DriftState::Drifted => "drifted",
            DriftState::Failed => "failed",
        }
    }
}

/// One row of the coverage table: an available module, whether it is enabled,
/// and (when checked) its drift verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportRow {
    pub module: &'static str,
    pub category: &'static str,
    pub enabled: bool,
    pub drift: Option<DriftState>,
}

/// Build the coverage rows for every available module, grouped by category then
/// module id. `enabled` is the set of enabled module ids; `drift` maps an
/// enabled module id to its live verdict (only populated with `--check`).
pub fn build_rows(enabled: &[String], drift: &BTreeMap<String, DriftState>) -> Vec<ReportRow> {
    let mut rows: Vec<ReportRow> = MODULE_IDS
        .iter()
        .map(|&module| {
            let is_enabled = enabled.iter().any(|e| e == module);
            ReportRow {
                module,
                category: cis_category(module),
                enabled: is_enabled,
                drift: drift.get(module).copied(),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.category.cmp(b.category).then(a.module.cmp(b.module)));
    rows
}

/// Category of `plugin::<name>` rows. Sorts after every CIS category.
pub const PLUGIN_CATEGORY: &str = "Plugins";

/// Rows for enabled plugins (always enabled; `drift` keyed by `plugin::<name>`),
/// appended after [`build_rows`] so a plugin verdict that drives the `--check`
/// exit code is visible. Plugins stay out of the CIS coverage counts.
pub fn plugin_rows(
    plugins: &[&'static str],
    drift: &BTreeMap<String, DriftState>,
) -> Vec<ReportRow> {
    plugins
        .iter()
        .map(|&module| ReportRow {
            module,
            category: PLUGIN_CATEGORY,
            enabled: true,
            drift: drift.get(module).copied(),
        })
        .collect()
}

fn available_count(rows: &[ReportRow]) -> usize {
    rows.iter()
        .filter(|r| r.category != PLUGIN_CATEGORY)
        .count()
}

fn enabled_count(rows: &[ReportRow]) -> usize {
    rows.iter()
        .filter(|r| r.enabled && r.category != PLUGIN_CATEGORY)
        .count()
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn drift_cell(row: &ReportRow) -> &'static str {
    match (row.enabled, row.drift) {
        (false, _) => "-",
        (true, Some(d)) => d.as_str(),
        (true, None) => "-",
    }
}

/// Render the coverage table as a CIS-category Markdown table (R97).
pub fn render_markdown(rows: &[ReportRow], checked: bool) -> String {
    let mut out = String::new();
    out.push_str("# Fulcrum Anvil — CIS Coverage Report\n\n");
    out.push_str(&format!(
        "Coverage: {} / {} modules enabled.\n\n",
        enabled_count(rows),
        available_count(rows)
    ));
    if checked {
        out.push_str("| Category | Module | Enabled | Drift |\n");
        out.push_str("|---|---|---|---|\n");
        for r in rows {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                r.category,
                r.module,
                yes_no(r.enabled),
                drift_cell(r)
            ));
        }
    } else {
        out.push_str("| Category | Module | Enabled |\n");
        out.push_str("|---|---|---|\n");
        for r in rows {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                r.category,
                r.module,
                yes_no(r.enabled)
            ));
        }
    }
    out
}

/// Render the coverage table as plain text for the terminal.
pub fn render_human(rows: &[ReportRow], checked: bool) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "CIS coverage: {} / {} modules enabled\n",
        enabled_count(rows),
        available_count(rows)
    ));
    let mut current = "";
    for r in rows {
        if r.category != current {
            out.push_str(&format!("\n{}\n", r.category));
            current = r.category;
        }
        if checked {
            out.push_str(&format!(
                "  {:<16} {:<9} {}\n",
                r.module,
                if r.enabled { "enabled" } else { "disabled" },
                drift_cell(r)
            ));
        } else {
            out.push_str(&format!(
                "  {:<16} {}\n",
                r.module,
                if r.enabled { "enabled" } else { "disabled" }
            ));
        }
    }
    out
}

/// Render the coverage report as a stable JSON document (R97).
pub fn render_json(rows: &[ReportRow], checked: bool) -> serde_json::Value {
    // Group modules under their category, preserving the sorted row order.
    let mut categories: Vec<serde_json::Value> = Vec::new();
    let mut idx = 0;
    while idx < rows.len() {
        let cat = rows[idx].category;
        let mut modules = Vec::new();
        while idx < rows.len() && rows[idx].category == cat {
            let r = &rows[idx];
            let mut obj = json!({ "module": r.module, "enabled": r.enabled });
            if checked && r.enabled {
                obj["drift"] = json!(r.drift.map(DriftState::as_str).unwrap_or("-"));
            }
            modules.push(obj);
            idx += 1;
        }
        categories.push(json!({ "category": cat, "modules": modules }));
    }
    json!({
        "available": available_count(rows),
        "enabled": enabled_count(rows),
        "checked": checked,
        "categories": categories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_module_has_a_category() {
        for &id in MODULE_IDS {
            let cat = cis_category(id);
            assert_ne!(cat, "Uncategorized", "module {id} missing CIS category");
            assert!(!cat.is_empty());
        }
    }

    #[test]
    fn cis_category_maps_known_and_unknown_names() {
        assert_eq!(
            cis_category("sshd"),
            "5 Access, Authentication and Authorization"
        );
        assert_eq!(cis_category("suid"), "6 System Maintenance");
        assert_eq!(cis_category("plugin::backup"), "Uncategorized");
    }

    #[test]
    fn human_report_names_categories_enablement_and_drift() {
        let enabled = vec!["sshd".to_string()];
        let mut drift = BTreeMap::new();
        drift.insert("sshd".to_string(), DriftState::Drifted);
        let rows = build_rows(&enabled, &drift);

        let plain = render_human(&rows, false);
        assert!(
            plain.starts_with(&format!(
                "CIS coverage: 1 / {} modules enabled\n",
                MODULE_IDS.len()
            )),
            "{plain}"
        );
        assert!(plain.contains("6 System Maintenance"), "category headers");
        assert!(
            plain
                .lines()
                .any(|l| l.contains("sshd") && l.contains("enabled")),
            "{plain}"
        );
        assert!(
            plain
                .lines()
                .any(|l| l.contains("suid") && l.contains("disabled")),
            "{plain}"
        );
        assert!(
            !plain.contains("drifted"),
            "no drift column without --check"
        );

        let checked = render_human(&rows, true);
        assert!(
            checked
                .lines()
                .any(|l| l.contains("sshd") && l.contains("enabled") && l.contains("drifted")),
            "{checked}"
        );
    }

    #[test]
    fn markdown_enabled_column_uses_yes_no() {
        let enabled = vec!["sshd".to_string()];
        let md = render_markdown(&build_rows(&enabled, &BTreeMap::new()), false);
        assert!(
            md.lines()
                .any(|l| l.contains("sshd") && l.contains("| yes |")),
            "{md}"
        );
        assert!(
            md.lines()
                .any(|l| l.contains("suid") && l.contains("| no |")),
            "{md}"
        );
    }

    #[test]
    fn json_report_includes_drift_only_when_checked_and_enabled() {
        let enabled = vec!["sshd".to_string()];
        let mut drift = BTreeMap::new();
        drift.insert("sshd".to_string(), DriftState::Aligned);
        let rows = build_rows(&enabled, &drift);
        let module = |v: &serde_json::Value, id: &str| -> serde_json::Value {
            v["categories"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|c| c["modules"].as_array().unwrap().clone())
                .find(|m| m["module"] == id)
                .unwrap()
        };
        let unchecked = render_json(&rows, false);
        assert!(module(&unchecked, "sshd").get("drift").is_none());
        let checked = render_json(&rows, true);
        assert_eq!(module(&checked, "sshd")["drift"], "aligned");
        // Disabled modules never carry a drift verdict, checked or not.
        assert!(module(&checked, "suid").get("drift").is_none());
    }

    #[test]
    fn plugin_rows_render_their_verdict_outside_cis_counts() {
        let enabled = vec!["sshd".to_string()];
        let mut drift = BTreeMap::new();
        drift.insert("sshd".to_string(), DriftState::Aligned);
        drift.insert("plugin::backup".to_string(), DriftState::Failed);
        let mut rows = build_rows(&enabled, &drift);
        rows.extend(plugin_rows(&["plugin::backup"], &drift));

        let human = render_human(&rows, true);
        assert!(
            human.starts_with(&format!(
                "CIS coverage: 1 / {} modules enabled\n",
                MODULE_IDS.len()
            )),
            "{human}"
        );
        assert!(human.contains("\nPlugins\n"), "{human}");
        assert!(
            human
                .lines()
                .any(|l| l.contains("plugin::backup") && l.contains("failed")),
            "{human}"
        );
        let md = render_markdown(&rows, true);
        assert!(
            md.contains("| Plugins | plugin::backup | yes | failed |"),
            "{md}"
        );
        let v = render_json(&rows, true);
        assert_eq!(v["available"], json!(MODULE_IDS.len()));
        assert_eq!(v["enabled"], json!(1));
        let cats = v["categories"].as_array().unwrap();
        let last = cats.last().unwrap();
        assert_eq!(last["category"], "Plugins");
        assert_eq!(
            last["modules"],
            json!([{ "module": "plugin::backup", "enabled": true, "drift": "failed" }])
        );
    }

    #[test]
    fn rows_cover_all_modules_sorted_by_category() {
        let enabled = vec!["sshd".to_string(), "firewall".to_string()];
        let rows = build_rows(&enabled, &BTreeMap::new());
        assert_eq!(rows.len(), MODULE_IDS.len());
        // Sorted by category then module.
        for w in rows.windows(2) {
            let a = (w[0].category, w[0].module);
            let b = (w[1].category, w[1].module);
            assert!(a <= b, "rows not sorted: {a:?} then {b:?}");
        }
        assert_eq!(enabled_count(&rows), 2);
        assert!(rows.iter().find(|r| r.module == "sshd").unwrap().enabled);
        assert!(!rows.iter().find(|r| r.module == "suid").unwrap().enabled);
    }

    #[test]
    fn markdown_table_reflects_coverage_and_drift() {
        let enabled = vec!["sshd".to_string()];
        let mut drift = BTreeMap::new();
        drift.insert("sshd".to_string(), DriftState::Drifted);
        let rows = build_rows(&enabled, &drift);

        let plain = render_markdown(&rows, false);
        assert!(plain.contains("Coverage: 1 / "));
        assert!(plain.contains("| Category | Module | Enabled |"));
        assert!(!plain.contains("Drift |"));

        let checked = render_markdown(&rows, true);
        assert!(checked.contains("| Category | Module | Enabled | Drift |"));
        // sshd enabled + drifted appears with its verdict.
        assert!(checked
            .lines()
            .any(|l| l.contains("sshd") && l.contains("drifted")));
        // A disabled module shows a placeholder in the drift column.
        assert!(checked
            .lines()
            .any(|l| l.contains("suid") && l.trim_end().ends_with("- |")));
    }

    #[test]
    fn json_groups_modules_by_category() {
        let enabled = vec!["lynis".to_string()];
        let mut drift = BTreeMap::new();
        drift.insert("lynis".to_string(), DriftState::Aligned);
        let rows = build_rows(&enabled, &drift);
        let v = render_json(&rows, true);
        assert_eq!(v["available"], json!(MODULE_IDS.len()));
        assert_eq!(v["enabled"], json!(1));
        assert_eq!(v["checked"], json!(true));
        let cats = v["categories"].as_array().unwrap();
        // Every module appears exactly once across the grouped categories.
        let total: usize = cats
            .iter()
            .map(|c| c["modules"].as_array().unwrap().len())
            .sum();
        assert_eq!(total, MODULE_IDS.len());
        // The enabled+checked module carries its drift verdict.
        let has_lynis_drift = cats.iter().any(|c| {
            c["modules"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m["module"] == json!("lynis") && m["drift"] == json!("aligned"))
        });
        assert!(has_lynis_drift);
    }
}
