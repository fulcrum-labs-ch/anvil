//! The `apps_resources` module: one systemd slice, `apps.slice`, that holds the
//! host's own applications (Caddy, Vector, Forgejo, GreptimeDB), plus an
//! optional `MemoryLow=` for `system.slice`.
//!
//! `apps.slice` has no dash, so systemd makes it a direct child of `-.slice`,
//! next to `system.slice` and `user.slice`: its `CPUWeight=` counts among
//! siblings, and its caps bound every app at once. `MemoryLow=` on
//! `system.slice` tells the kernel to reclaim from user/CI/apps work first,
//! protecting sshd and the rest of the system under memory pressure. Its
//! drop-in uses a HIGH prefix: `.d` directories are last-wins.
//!
//! Values are validated at load to a systemd-safe charset; the files are
//! static and base64-embedded by the engine. Rollback removes them.

use crate::config::schema::AppsResourcesSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX};
use crate::escape::{shell_escape, shell_escape_join};

use super::{runner_common, Module};

/// `Slice=` for every app module; systemd adds `Requires=`/`After=` on it.
pub const SLICE: &str = "apps.slice";
pub const SLICE_PATH: &str = "/etc/systemd/system/apps.slice";
/// `system.slice`'s `MemoryLow=`. HIGH prefix: `.d` is last-wins.
pub const SYSTEM_MEMORY_LOW_DROPIN: &str =
    "/etc/systemd/system/system.slice.d/99-anvil-memory-low.conf";

pub struct AppsResourcesModule {
    cfg: AppsResourcesSection,
}

impl AppsResourcesModule {
    pub fn new(cfg: AppsResourcesSection) -> Self {
        Self { cfg }
    }

    pub fn slice_content(&self) -> String {
        let c = &self.cfg;
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Applications and their services (anvil)\n\
             \n\
             [Slice]\n\
             {caps}\
             CPUWeight={weight}\n",
            caps = runner_common::cgroup_caps(
                c.cpu_quota.as_deref(),
                c.memory_max.as_deref(),
                c.tasks_max
            ),
            weight = c.cpu_weight,
        )
    }

    pub fn memory_low_content(&self) -> Option<String> {
        self.cfg.system_memory_low.as_ref().map(|low| {
            format!("# Managed by anvil — do not edit by hand\n[Slice]\nMemoryLow={low}\n")
        })
    }
}

/// Probe-visible drift while the `MemoryLow=` drop-in is still on disk after
/// `system_memory_low` was unset; apply removes it (and its backup), then the
/// guarded reload's `daemon-reload` drops the setting.
fn memory_low_absent() -> ManagedCommand {
    let all = [
        SYSTEM_MEMORY_LOW_DROPIN.to_string(),
        format!("{SYSTEM_MEMORY_LOW_DROPIN}{BACKUP_SUFFIX}"),
    ];
    let detect = all
        .iter()
        .map(|p| format!("[ ! -e {} ]", shell_escape(p)))
        .collect::<Vec<_>>()
        .join(" && ");
    ManagedCommand::new(
        "no leftover system.slice MemoryLow drop-in",
        detect,
        format!(
            "for __f in {}; do rm -f \"$__f\"; __anvil_forget \"$__f\"; done",
            shell_escape_join(&all)
        ),
    )
}

impl Module for AppsResourcesModule {
    fn id(&self) -> &'static str {
        "apps_resources"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("apps_resources").file(ManagedFile::new(
            SLICE_PATH,
            self.slice_content(),
            "0644",
            "root:root",
        ));
        if let Some(content) = self.memory_low_content() {
            decl = decl.file(ManagedFile::new(
                SYSTEM_MEMORY_LOW_DROPIN,
                content,
                "0644",
                "root:root",
            ));
        } else {
            decl = decl.command(memory_low_absent());
        }
        // daemon-reload applies changed limits to the running slice; never
        // restart it (that would stop every app in it).
        decl.guarded_reload(ReloadGuard {
            describe: "application slice".into(),
            validate: "true".into(),
            reload: "systemctl daemon-reload".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(toml: &str) -> AppsResourcesModule {
        AppsResourcesModule::new(toml::from_str(toml).unwrap())
    }

    #[test]
    fn slice_carries_the_caps_and_the_weight() {
        let m =
            module("cpu_quota = \"400%\"\nmemory_max = \"6G\"\ntasks_max = 4096\ncpu_weight = 200");
        assert_eq!(
            m.slice_content(),
            "# Managed by anvil — do not edit by hand\n[Unit]\n\
             Description=Applications and their services (anvil)\n\n[Slice]\n\
             CPUQuota=400%\nMemoryMax=6G\nTasksMax=4096\nCPUWeight=200\n"
        );
        let bare = module("").slice_content();
        assert!(bare.ends_with("[Slice]\nCPUWeight=100\n"), "{bare}");
    }

    #[test]
    fn memory_low_dropin_is_written_only_when_set() {
        let low = module("system_memory_low = \"2G\"")
            .memory_low_content()
            .expect("drop-in content");
        assert_eq!(
            low,
            "# Managed by anvil — do not edit by hand\n[Slice]\nMemoryLow=2G\n"
        );
        assert_eq!(module("").memory_low_content(), None);
    }

    #[test]
    fn declares_the_slice_and_the_optional_dropin() {
        let d = module("system_memory_low = \"2G\"").declaration();
        let by_path = |p: &str| d.files.iter().find(|f| f.path == p).unwrap();
        assert_eq!(by_path(SLICE_PATH).mode, "0644");
        assert_eq!(
            by_path(SYSTEM_MEMORY_LOW_DROPIN).static_content(),
            module("system_memory_low = \"2G\"")
                .memory_low_content()
                .as_deref()
        );
        let off = module("").declaration();
        assert!(off.files.iter().any(|f| f.path == SLICE_PATH));
        assert!(
            !off.files.iter().any(|f| f.path == SYSTEM_MEMORY_LOW_DROPIN),
            "no system_memory_low, no drop-in"
        );
    }

    #[test]
    fn unsetting_system_memory_low_removes_the_dropin() {
        // The section stays on; only the field went away. The old drop-in
        // must not keep protecting system.slice behind the operator's back.
        let off = module("").declaration();
        let removal = off
            .commands
            .iter()
            .find(|c| c.describe.contains("MemoryLow"))
            .expect("removal command");
        assert_eq!(
            removal.detect,
            format!(
                "[ ! -e '{SYSTEM_MEMORY_LOW_DROPIN}' ] && \
                 [ ! -e '{SYSTEM_MEMORY_LOW_DROPIN}.anvil.bak' ]"
            )
        );
        assert!(
            removal.converge.contains("rm -f \"$__f\""),
            "{}",
            removal.converge
        );
        // The probe drifts while the file is still there.
        assert!(off
            .render_probe()
            .contains(&format!("[ ! -e '{SYSTEM_MEMORY_LOW_DROPIN}' ]")));
        // Apply removes it before the daemon-reload that drops the setting.
        let apply = off.render_apply();
        let rm = apply.find("rm -f \"$__f\"").expect("removal runs");
        let reload = apply.rfind("systemctl daemon-reload").expect("reload");
        assert!(rm < reload, "{apply}");

        for m in [
            module(""),
            module("system_memory_low = \"2G\""),
            module("cpu_quota = \"200%\""),
        ] {
            let d = m.declaration();
            let removes = d.commands.iter().any(|c| c.describe.contains("MemoryLow"));
            assert_eq!(
                removes,
                m.cfg.system_memory_low.is_none(),
                "removal only while the field is unset"
            );
        }
    }

    #[test]
    fn reloads_without_ever_restarting_the_slice() {
        // Restarting a slice stops every unit in it.
        let d = module("system_memory_low = \"2G\"").declaration();
        let apply = d.render_apply();
        assert!(apply.contains("systemctl daemon-reload"), "{apply}");
        assert!(!apply.contains("restart"), "{apply}");
        let rb = d.render_rollback();
        assert!(rb.contains(SLICE_PATH) && rb.contains(SYSTEM_MEMORY_LOW_DROPIN));
    }
}
