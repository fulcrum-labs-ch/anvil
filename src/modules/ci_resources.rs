//! The `ci_resources` module: one systemd slice, `ci.slice`, that holds every
//! CI runner unit (GR22; docs/design/github-actions-runner.md).
//!
//! Its caps are the total share of the host for all CI work; each runner's own
//! `cpu_quota`/`memory_max`/`tasks_max` still apply inside it. `CPUWeight=`
//! below the default 100 lets system and user work win under contention. The
//! kernel compares weights only among siblings; `ci.slice` has no dash, so
//! systemd makes it a direct child of `-.slice`, next to `system.slice` and
//! `user.slice`, and its own weight counts (older `anvil-ci.slice` hung
//! under `anvil.slice`, whose lone child left the weight inert there).
//! Values are validated at load to a systemd-safe charset; the slice file is
//! static and base64-embedded by the engine. Rollback removes it.

use crate::config::schema::CiResourcesSection;
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, BACKUP_SUFFIX, MARK_CHANGED, MARK_FAILED,
};
use crate::escape::shell_escape;

use super::{runner_common, Module};

/// Runner units put `Slice=` on this; systemd adds `Requires=`/`After=` on
/// the slice implicitly.
pub const SLICE: &str = "ci.slice";
pub const SLICE_PATH: &str = "/etc/systemd/system/ci.slice";
/// Pre-rename slice and the parent drop-in its weight needed; removed on
/// apply (backed up for rollback).
pub const LEGACY_SLICE_PATH: &str = "/etc/systemd/system/anvil-ci.slice";
pub const LEGACY_PARENT_DROPIN: &str = "/etc/systemd/system/anvil.slice.d/99-anvil-ci-weight.conf";

pub struct CiResourcesModule {
    cfg: CiResourcesSection,
}

impl CiResourcesModule {
    pub fn new(cfg: CiResourcesSection) -> Self {
        Self { cfg }
    }

    pub fn slice_content(&self) -> String {
        let c = &self.cfg;
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=CI runners and their jobs (anvil)\n\
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
}

/// Probe-visible drift while a pre-rename file exists; the guard migrates it.
fn legacy_absent() -> ManagedCommand {
    ManagedCommand::new(
        "pre-rename CI slice and its anvil.slice drop-in absent (the reload migrates them)",
        format!(
            "[ ! -e {} ] && [ ! -e {} ]",
            shell_escape(LEGACY_SLICE_PATH),
            shell_escape(LEGACY_PARENT_DROPIN)
        ),
        ":",
    )
}

/// Runs inside the guard's reload, only while `ci.slice` is on disk, so
/// rollback's re-run of the reload never deletes a just-restored legacy file.
/// Both files move only once both backups exist.
fn migrate_legacy() -> String {
    format!(
        "if [ -f {slice} ] && {{ [ -e {legacy} ] || [ -e {dropin} ]; }}; then\n\
         \x20 __anvil_ci_bak=1\n\
         \x20 for __p in {legacy} {dropin}; do\n\
         \x20\x20 if [ -e \"$__p\" ] && [ ! -e \"$__p{bak}\" ] && ! cp -a \"$__p\" \"$__p{bak}\"; \
         then __anvil_ci_bak=0; fi\n\
         \x20 done\n\
         \x20 if [ \"$__anvil_ci_bak\" = 1 ]; then\n\
         \x20\x20 rm -f {legacy} {dropin}\n\
         \x20\x20 printf '{changed} CI slice renamed to ci.slice: removed the old anvil-ci.slice and \
         anvil.slice drop-in (backed up as {bak})\\n'\n\
         \x20 else\n\
         \x20\x20 printf '{failed} could not back up the pre-rename CI slice files; leaving them in place\\n' >&2\n\
         \x20 fi\n\
         fi",
        slice = shell_escape(SLICE_PATH),
        legacy = shell_escape(LEGACY_SLICE_PATH),
        dropin = shell_escape(LEGACY_PARENT_DROPIN),
        bak = BACKUP_SUFFIX,
        changed = MARK_CHANGED,
        failed = MARK_FAILED,
    )
}

/// Rollback restores both files the migration backed up.
fn restore_legacy() -> String {
    format!(
        "\n# rollback (module-authored): restore the pre-rename CI slice and its drop-in\n\
         for __p in {legacy} {dropin}; do\n\
         \x20 if [ -e \"$__p{bak}\" ]; then cp -a \"$__p{bak}\" \"$__p\"; fi\n\
         done\n",
        legacy = shell_escape(LEGACY_SLICE_PATH),
        dropin = shell_escape(LEGACY_PARENT_DROPIN),
        bak = BACKUP_SUFFIX,
    )
}

impl Module for CiResourcesModule {
    fn id(&self) -> &'static str {
        "ci_resources"
    }

    fn declaration(&self) -> Declaration {
        Declaration::new("ci_resources")
            .file(ManagedFile::new(
                SLICE_PATH,
                self.slice_content(),
                "0644",
                "root:root",
            ))
            .command(legacy_absent())
            .rollback_script(restore_legacy())
            // daemon-reload applies changed limits to the running slice; never
            // restart it (that would stop every runner and job in it).
            .guarded_reload(ReloadGuard {
                describe: "CI slice".into(),
                validate: "true".into(),
                reload: format!("{}\nsystemctl daemon-reload", migrate_legacy()),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(toml: &str) -> CiResourcesModule {
        CiResourcesModule::new(toml::from_str(toml).unwrap())
    }

    #[test]
    fn slice_carries_the_caps_and_the_weight() {
        let m = module("cpu_quota = \"800%\"\nmemory_max = \"20G\"\ntasks_max = 8192");
        assert_eq!(
            m.slice_content(),
            "# Managed by anvil — do not edit by hand\n[Unit]\n\
             Description=CI runners and their jobs (anvil)\n\n[Slice]\n\
             CPUQuota=800%\nMemoryMax=20G\nTasksMax=8192\nCPUWeight=50\n"
        );
        let bare = module("cpu_weight = 20").slice_content();
        assert!(bare.ends_with("[Slice]\nCPUWeight=20\n"), "{bare}");
    }

    const LEGACY_SLICE: &str = "/etc/systemd/system/anvil-ci.slice";
    const LEGACY_DROPIN: &str = "/etc/systemd/system/anvil.slice.d/99-anvil-ci-weight.conf";

    #[test]
    fn declares_ci_slice_and_no_parent_dropin() {
        // A dash-free name is a direct child of -.slice, next to system/user,
        // so its own CPUWeight= counts and no anvil.slice drop-in is needed.
        let d = module("cpu_weight = 30").declaration();
        assert!(d
            .files
            .iter()
            .any(|f| f.path == "/etc/systemd/system/ci.slice"));
        assert!(
            d.files.iter().all(|f| !f.path.contains("anvil.slice")),
            "the parent drop-in is gone with the rename: {:?}",
            d.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        let apply = d.render_apply();
        let write = apply.find(SLICE_PATH).unwrap();
        let reload = apply.rfind("systemctl daemon-reload").unwrap();
        assert!(write < reload);
        assert!(!apply.contains("restart"), "never restart the slice");
    }

    #[test]
    fn the_probe_drifts_while_a_legacy_file_exists() {
        let d = module("").declaration();
        let legacy = d
            .commands
            .iter()
            .find(|c| c.describe.contains("pre-rename"))
            .expect("legacy probe");
        assert_eq!(
            legacy.detect,
            format!("[ ! -e '{LEGACY_SLICE}' ] && [ ! -e '{LEGACY_DROPIN}' ]")
        );
        assert_eq!(legacy.converge, ":", "probe only; the reload migrates");
        let probe = d.render_probe();
        assert!(probe.contains(&format!("[ ! -e '{LEGACY_SLICE}' ]")));
        assert!(probe.contains(&format!("[ ! -e '{LEGACY_DROPIN}' ]")));
    }

    #[test]
    fn apply_backs_up_the_legacy_files_before_removing_them() {
        let apply = module("").declaration().render_apply();
        assert!(
            apply.contains(&format!("for __p in '{LEGACY_SLICE}' '{LEGACY_DROPIN}'")),
            "{apply}"
        );
        let cp = apply.find("cp -a \"$__p\" \"$__p.anvil.bak\"").unwrap();
        let guard = apply.find("[ \"$__anvil_ci_bak\" = 1 ]").unwrap();
        let rm = apply
            .find(&format!("rm -f '{LEGACY_SLICE}' '{LEGACY_DROPIN}'"))
            .unwrap();
        assert!(cp < guard && guard < rm, "{apply}");
        // The rm lives in the branch only a full set of backups opens.
        assert!(
            apply.contains(&format!(
                "if [ \"$__anvil_ci_bak\" = 1 ]; then\n   rm -f '{LEGACY_SLICE}' '{LEGACY_DROPIN}'\n   printf 'CHANGED:"
            )),
            "{apply}"
        );
        // A failed copy leaves both files for the next run.
        assert!(apply.contains("leaving them in place"), "{apply}");
    }

    #[test]
    fn rollback_restores_both_legacy_files() {
        let d = module("").declaration();
        let rb = d.render_rollback();
        assert!(rb.contains("cp -a \"$__p.anvil.bak\" \"$__p\""), "{rb}");
        for p in [LEGACY_SLICE, LEGACY_DROPIN] {
            assert!(rb.contains(&format!("'{p}'")), "{rb}");
        }
        // The new slice is removed before the old ones come back, and the
        // reload's migration never deletes what rollback just restored.
        assert!(rb.find(SLICE_PATH).unwrap() < rb.find(&format!("'{LEGACY_SLICE}'")).unwrap());
        assert!(rb.contains(&format!("if [ -f '{SLICE_PATH}' ] &&")), "{rb}");
        assert!(rb.contains("systemctl daemon-reload"));
    }
}
