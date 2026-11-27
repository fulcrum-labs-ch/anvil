//! The `process` module (R73): core-dump disablement (limits + systemd
//! `coredump.conf`), an optional magic-SysRq lockdown, `login.defs` password
//! policy (aging plus `ENCRYPT_METHOD SHA512`), and an optional `/proc`
//! `hidepid=2` restriction backed by a persistent systemd unit.
//!
//! Design notes on ordering (the engine renders commands *before* files, files
//! *before* the guarded reload):
//! - `login.defs` is a shared distro file we must *edit in place* (never own), so
//!   it is a [`ManagedCommand`] doing an idempotent sed — it depends on no
//!   managed file, so running before the files is fine.
//! - Runtime sysctl toggles are applied live with `sysctl -w` (a command that
//!   depends on no managed file), while the sysctl drop-in persists them across
//!   reboot. This converges in a single pass without a reload.
//! - `hidepid` is enforced against *live* state, not just the unit file: a
//!   [`ManagedCommand`] whose detect requires `hidepid=2` among `/proc`'s mount
//!   options in `/proc/self/mounts`, and whose converge enables the unit and
//!   applies the remount immediately. Because commands render before files, the
//!   unit may not exist yet on the first pass — the post-file [`ReloadGuard`]
//!   backstops the enable, so the module still converges in a single pass.

use crate::config::schema::ProcessSection;
use crate::engine::{
    Declaration, ManagedCommand, ManagedFile, ReloadGuard, MARK_CHANGED, MARK_FAILED,
};
use crate::escape::shell_escape;

use super::Module;

/// limits.d drop-in disabling core dumps (Fixed Contract).
pub const LIMITS_COREDUMP: &str = "/etc/security/limits.d/99-anvil-coredump.conf";
/// systemd coredump drop-in (Fixed Contract).
pub const COREDUMP_CONF: &str = "/etc/systemd/coredump.conf.d/99-anvil.conf";
/// sysctl drop-in persisting runtime process toggles (Fixed Contract).
pub const SYSCTL_DROP_IN: &str = "/etc/sysctl.d/99-anvil-process.conf";
/// Shared distro login policy file — edited in place, never owned (R73).
pub const LOGIN_DEFS: &str = "/etc/login.defs";
/// Persistent unit that reapplies `hidepid=2` to `/proc` at boot.
pub const HIDEPID_UNIT: &str = "/etc/systemd/system/anvil-hidepid.service";
/// Bare unit name used with `systemctl`.
const HIDEPID_SERVICE: &str = "anvil-hidepid.service";

pub struct ProcessModule {
    cfg: ProcessSection,
}

impl ProcessModule {
    pub fn new(cfg: ProcessSection) -> Self {
        Self { cfg }
    }

    /// Runtime sysctl keys (as `key=value`) implied by the config toggles.
    fn sysctl_pairs(&self) -> Vec<&'static str> {
        let c = &self.cfg;
        let mut pairs = Vec::new();
        if c.disable_sysrq {
            pairs.push("kernel.sysrq=0");
        }
        if c.disable_core_dumps {
            // SUID programs must not be dumpable when core dumps are disabled.
            pairs.push("fs.suid_dumpable=0");
        }
        pairs
    }
}

/// `* hard core 0` style limits that forbid core dumps for every user (R73).
fn limits_content() -> String {
    "# Managed by anvil — do not edit by hand\n\
     * hard core 0\n\
     * soft core 0\n\
     root hard core 0\n\
     root soft core 0\n"
        .to_string()
}

/// systemd-coredump storage disablement (R73).
fn coredump_content() -> String {
    "# Managed by anvil — do not edit by hand\n\
     [Coredump]\n\
     Storage=none\n\
     ProcessSizeMax=0\n"
        .to_string()
}

/// Persisted runtime sysctl toggles (loaded at boot by systemd-sysctl).
fn sysctl_file_content(pairs: &[&str]) -> String {
    let mut lines = vec!["# Managed by anvil — do not edit by hand".to_string()];
    for kv in pairs {
        if let Some((k, v)) = kv.split_once('=') {
            lines.push(format!("{k} = {v}"));
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Persistent unit that re-restricts `/proc` on boot; skipped inside containers
/// where a `/proc` remount is not permitted (graceful degradation, R107).
fn hidepid_unit() -> String {
    "# Managed by anvil — do not edit by hand\n\
     [Unit]\n\
     Description=anvil: restrict /proc with hidepid=2\n\
     ConditionVirtualization=!container\n\
     \n\
     [Service]\n\
     Type=oneshot\n\
     RemainAfterExit=yes\n\
     ExecStart=/bin/mount -o remount,hidepid=2 /proc\n\
     \n\
     [Install]\n\
     WantedBy=multi-user.target\n"
        .to_string()
}

/// Live-apply the runtime sysctl toggles (`sysctl -w`) and detect drift against
/// the running kernel. Independent of the persisted drop-in, so it converges in
/// one pass. Keys the kernel does not expose are tolerated.
fn sysctl_apply_command(pairs: &[&str]) -> ManagedCommand {
    let list = pairs
        .iter()
        .map(|p| shell_escape(p))
        .collect::<Vec<_>>()
        .join(" ");
    let detect = format!(
        "__ok=1; for __kv in {list}; do __k=${{__kv%%=*}}; __w=${{__kv#*=}}; \
         __g=$(sysctl -n \"$__k\" 2>/dev/null) || continue; \
         [ \"$__g\" = \"$__w\" ] || __ok=0; done; [ \"$__ok\" = 1 ]"
    );
    let converge =
        format!("for __kv in {list}; do sysctl -w \"$__kv\" >/dev/null 2>&1 || true; done");
    ManagedCommand::new("runtime sysctl process toggles", detect, converge)
}

/// Created-list key prefix recording an apport unit anvil disabled, so
/// rollback re-enables exactly those and never one disabled before anvil.
const APPORT_KEY: &str = "apport-unit:";
/// apport units whose unit-file state is `enabled*` (never static/masked,
/// which `disable` cannot change). Column 2 only: newer systemd adds PRESET.
const APPORT_ENABLED: &str = "systemctl list-unit-files --no-legend --plain 'apport*' 2>/dev/null \
     | awk '$2 ~ /^enabled/ { print $1 }'";
/// Currently active apport units (oneshot `active (exited)`, listening sockets).
const APPORT_ACTIVE: &str =
    "systemctl list-units --no-legend --plain --state=active 'apport*' 2>/dev/null \
     | awk '{ print $1 }'";

/// Neutralise apport: converged when no apport unit is enabled or
/// active — trivially so on Debian, where apport does not exist. Converge
/// disables what is enabled (recording each unit for rollback) and stops what
/// is still running; stopping `apport.service` runs `apport --stop`, which
/// restores `suid_dumpable=0` and the core_pattern.
fn apport_command() -> ManagedCommand {
    // awk consumes all input (unlike `grep -q`), so no SIGPIPE under pipefail.
    let detect = format!("[ -z \"$({APPORT_ENABLED})\" ] && [ -z \"$({APPORT_ACTIVE})\" ]");
    let converge = format!(
        "for __u in $({APPORT_ENABLED}); do \
         __anvil_remember \"{APPORT_KEY}$__u\"; systemctl disable --now \"$__u\"; done\n\
         for __u in $({APPORT_ACTIVE}); do systemctl stop \"$__u\"; done"
    );
    ManagedCommand::new("apport disabled (core dumps)", detect, converge)
}

/// Re-enable only the apport units anvil disabled. Runs after the sysctl
/// restore so `apport --start` has the last word, as it did before anvil.
fn apport_rollback() -> String {
    format!(
        "\n# rollback (module-authored): apport units disabled by anvil\n\
         for __u in $(sed -n 's/^{APPORT_KEY}//p' \"$__created_list\" 2>/dev/null); do\n\
         \x20 if systemctl enable --now \"$__u\"; then\n\
         \x20\x20 __anvil_forget \"{APPORT_KEY}$__u\"\n\
         \x20\x20 printf '{changed} process re-enabled %s (anvil disabled it)\\n' \"$__u\"\n\
         \x20 else\n\
         \x20\x20 printf '{failed} process could not re-enable %s\\n' \"$__u\"\n\
         \x20 fi\n\
         done\n",
        changed = MARK_CHANGED,
        failed = MARK_FAILED,
    )
}

/// Idempotently set the `PASS_MAX_DAYS` / `PASS_MIN_DAYS` / `PASS_WARN_AGE`
/// aging directives plus `ENCRYPT_METHOD SHA512` in the shared `login.defs`,
/// replacing existing lines or appending them. Aging values are numeric but
/// still shell-escaped per the injection contract; the encrypt method is a
/// compile-time literal. Detect and converge iterate the same key=value list,
/// so they can never disagree about which directives are enforced.
/// The `login.defs` directives this module owns (recorded for rollback).
const LOGIN_DEFS_KEYS: &[&str] = &[
    "PASS_MAX_DAYS",
    "PASS_MIN_DAYS",
    "PASS_WARN_AGE",
    "ENCRYPT_METHOD",
];

/// SHA512 and yescrypt both meet CIS; yescrypt (the Debian 12+/Ubuntu
/// 22.04+ default) is stronger. Accept either and never downgrade.
const ENCRYPT_OK: &str =
    "grep -Eq '^[[:space:]]*ENCRYPT_METHOD[[:space:]]+(SHA512|YESCRYPT)([[:space:]]|$)'";

fn login_defs_command(cfg: &ProcessSection) -> ManagedCommand {
    let max = shell_escape(&cfg.pass_max_days.to_string());
    let min = shell_escape(&cfg.pass_min_days.to_string());
    let warn = shell_escape(&cfg.pass_warn_age.to_string());
    // Each item concatenates a quoted key prefix with the escaped value, e.g.
    // `'PASS_MAX_DAYS='` + `'365'` -> the single word `PASS_MAX_DAYS=365`.
    let list = format!("'PASS_MAX_DAYS='{max} 'PASS_MIN_DAYS='{min} 'PASS_WARN_AGE='{warn}");
    let login = shell_escape(LOGIN_DEFS);
    let detect = format!(
        "__ok=1; for __kv in {list}; do __k=${{__kv%%=*}}; __v=${{__kv#*=}}; \
         grep -Eq \"^[[:space:]]*${{__k}}[[:space:]]+${{__v}}([[:space:]]|\\$)\" {login} \
         || __ok=0; done; [ \"$__ok\" = 1 ] && {ENCRYPT_OK} {login}"
    );
    // `login.defs` is distro-owned and shared with pam: record our own
    // directives once so rollback restores exactly them.
    let (capture, _) = super::login_defs_keys("process", LOGIN_DEFS_KEYS);
    let converge = format!(
        "{capture}\
         {ENCRYPT_OK} {login} || {{ __m=SHA512; grep -qs yescrypt /etc/pam.d/common-password && __m=YESCRYPT; \
         if grep -Eq '^[[:space:]]*ENCRYPT_METHOD[[:space:]]' {login}; then \
         sed -ri \"s|^[[:space:]]*ENCRYPT_METHOD[[:space:]].*|ENCRYPT_METHOD\\t$__m|\" {login}; \
         else printf 'ENCRYPT_METHOD\\t%s\\n' \"$__m\" >> {login}; fi; }}\n\
         for __kv in {list}; do __k=${{__kv%%=*}}; __v=${{__kv#*=}}; \
         if grep -Eq \"^[[:space:]]*${{__k}}[[:space:]]\" {login}; then \
         sed -ri \"s|^[[:space:]]*${{__k}}[[:space:]].*|${{__k}}\\t${{__v}}|\" {login}; \
         else printf '%s\\t%s\\n' \"${{__k}}\" \"${{__v}}\" >> {login}; fi; done"
    );
    ManagedCommand::new("login.defs password policy", detect, converge)
}

/// Live `/proc` hidepid enforcement. The persistent unit alone is not proof the
/// restriction is active, so detect requires `hidepid=2` among `/proc`'s mount
/// options in `/proc/self/mounts` (kernels >= 5.8 report the value by its
/// symbolic name, `invisible`, so both spellings are accepted). Converge
/// installs/enables the unit and applies the remount immediately. Commands run
/// before managed files, so on the very first pass the unit file does not exist
/// yet — the `enable` is tolerated and the post-file [`ReloadGuard`] backstops
/// it; the remount itself needs no unit, so live state still converges in one
/// pass. Remount failures (e.g. containers) are tolerated (R107).
fn hidepid_command() -> ManagedCommand {
    let detect = "awk '$2 == \"/proc\" { __o = \",\" $4 \",\" } \
                  END { exit !(__o ~ /,hidepid=(2|invisible),/) }' /proc/self/mounts"
        .to_string();
    let converge = format!(
        "systemctl daemon-reload 2>/dev/null || true; \
         systemctl enable --now {svc} 2>/dev/null || true; \
         mount -o remount,hidepid=2 /proc 2>/dev/null || true",
        svc = shell_escape(HIDEPID_SERVICE)
    );
    ManagedCommand::new("hidepid=2 active on /proc", detect, converge)
}

impl Module for ProcessModule {
    fn id(&self) -> &'static str {
        "process"
    }

    fn declaration(&self) -> Declaration {
        let c = &self.cfg;
        let mut decl = Declaration::new("process");

        // --- prerequisite commands (run before files; depend on no managed file)
        // Password aging always applies when [process] is enabled.
        decl = decl.command(login_defs_command(c));
        // login.defs is shared with pam: roll back only our own directives.
        decl = decl.rollback_script(super::login_defs_keys("process", LOGIN_DEFS_KEYS).1);

        let pairs = self.sysctl_pairs();
        if !pairs.is_empty() {
            let keys: Vec<&str> = pairs
                .iter()
                .filter_map(|p| p.split_once('=').map(|(k, _)| k))
                .collect();
            let (snapshot, restore) = super::sysctl_snapshot("process", SYSCTL_DROP_IN, &keys);
            decl = decl.command(snapshot).rollback_script(restore);
            if c.disable_core_dumps {
                decl = decl
                    .command(apport_command())
                    .rollback_script(apport_rollback());
            }
            decl = decl.command(sysctl_apply_command(&pairs));
        }

        // --- managed files
        if c.disable_core_dumps {
            decl = decl.file(ManagedFile::new(
                LIMITS_COREDUMP,
                limits_content(),
                "0644",
                "root:root",
            ));
            decl = decl.file(ManagedFile::new(
                COREDUMP_CONF,
                coredump_content(),
                "0644",
                "root:root",
            ));
        }
        if !pairs.is_empty() {
            decl = decl.file(ManagedFile::new(
                SYSCTL_DROP_IN,
                sysctl_file_content(&pairs),
                "0644",
                "root:root",
            ));
        }

        // --- hidepid: live remount + enablement (command, drift-detected via
        // /proc/self/mounts), the persistent unit (file), then a guarded
        // (re)enable once the unit exists on disk.
        if c.hidepid {
            decl = decl.command(hidepid_command());
            decl = decl.file(ManagedFile::new(
                HIDEPID_UNIT,
                hidepid_unit(),
                "0644",
                "root:root",
            ));
            decl = decl.guarded_reload(ReloadGuard {
                describe: "hidepid /proc restriction".into(),
                validate: format!("! [ -e {p} ] || [ -s {p} ]", p = shell_escape(HIDEPID_UNIT)),
                reload: format!(
                    "systemctl daemon-reload 2>/dev/null || true; \
                     systemctl enable --now {svc} 2>/dev/null || true",
                    svc = shell_escape(HIDEPID_SERVICE)
                ),
            });
        }

        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_dropin_keeps_the_high_prefix_and_path() {
        // sysctl.d is last-match-wins: keep the HIGH 99-anvil prefix so we
        // sort after numeric distro drop-ins, and never rename the path —
        // drift, diff, and rollback key on it.
        let name = SYSCTL_DROP_IN.rsplit('/').next().expect("basename");
        assert!(SYSCTL_DROP_IN.starts_with("/etc/sysctl.d/"));
        assert!(name.starts_with("99-anvil"), "{name:?}");
        assert!(
            name > "70-",
            "{name:?} must sort after numeric distro files"
        );
    }

    fn section() -> ProcessSection {
        ProcessSection {
            disable_core_dumps: true,
            disable_sysrq: true,
            pass_max_days: 365,
            pass_min_days: 1,
            pass_warn_age: 7,
            hidepid: false,
            order_override: Default::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut ProcessSection)) -> ProcessModule {
        let mut cfg = section();
        mutate(&mut cfg);
        ProcessModule::new(cfg)
    }

    fn file_content<'a>(decl: &'a Declaration, path: &str) -> &'a str {
        decl.files
            .iter()
            .find(|f| f.path == path)
            .and_then(|f| f.static_content())
            .unwrap_or_else(|| panic!("no managed file {path}"))
    }

    #[test]
    fn core_dumps_disabled_via_limits_and_coredump_conf() {
        let decl = module(|_| {}).declaration();
        assert!(file_content(&decl, LIMITS_COREDUMP).contains("* hard core 0"));
        let cd = file_content(&decl, COREDUMP_CONF);
        assert!(cd.contains("[Coredump]"));
        assert!(cd.contains("Storage=none"));
        // suid_dumpable rides along with core-dump disablement.
        assert!(file_content(&decl, SYSCTL_DROP_IN).contains("fs.suid_dumpable = 0"));
    }

    #[test]
    fn sysrq_is_optional() {
        let with = module(|_| {}).declaration();
        assert!(file_content(&with, SYSCTL_DROP_IN).contains("kernel.sysrq = 0"));

        // Disable both sysctl toggles -> no sysctl drop-in at all.
        let without = module(|c| {
            c.disable_sysrq = false;
            c.disable_core_dumps = false;
        })
        .declaration();
        assert!(
            without.files.iter().all(|f| f.path != SYSCTL_DROP_IN),
            "no sysctl drop-in when nothing to persist"
        );
        // Core-dump files also gone when disabled.
        assert!(without.files.iter().all(|f| f.path != LIMITS_COREDUMP));
    }

    #[test]
    fn sysctl_toggles_are_live_applied_and_idempotent() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("sysctl -w"));
        assert!(apply.contains("kernel.sysrq=0"));
        assert!(apply.contains("fs.suid_dumpable=0"));
        assert!(apply.contains("|| true"));
    }

    #[test]
    fn login_defs_is_edited_in_place_not_owned() {
        let decl = module(|c| c.pass_max_days = 90).declaration();
        // login.defs is never a managed file — it must be edited via a command.
        assert!(decl.files.iter().all(|f| f.path != LOGIN_DEFS));
        let apply = decl.render_apply();
        assert!(apply.contains("/etc/login.defs"));
        assert!(apply.contains("sed -ri"));
        // The configured value is present as a shell-escaped word.
        assert!(apply.contains("'90'"));
        // The probe checks the same file read-only.
        let probe = decl.render_probe();
        assert!(probe.contains("grep -Eq"));
        assert!(!probe.contains("sed -ri"));
    }

    #[test]
    fn login_defs_record_precedes_the_edit() {
        // process records its own directives before any sed touches
        // the file it shares with pam.
        let apply = module(|c| c.pass_max_days = 90)
            .declaration()
            .render_apply();
        let bak = apply
            .find("/var/lib/anvil/login.defs-process.orig")
            .expect("login.defs record present");
        let edit = apply.find("sed -ri").expect("edit present");
        assert!(bak < edit, "backup must precede the sed edit:\n{apply}");
    }

    #[test]
    fn hidepid_writes_unit_and_enables_after_it() {
        let plain = module(|_| {}).declaration();
        assert!(plain.reload.is_none(), "no guard without hidepid");
        assert!(plain.files.iter().all(|f| f.path != HIDEPID_UNIT));

        let decl = module(|c| c.hidepid = true).declaration();
        let unit = file_content(&decl, HIDEPID_UNIT);
        assert!(unit.contains("hidepid=2"));
        assert!(unit.contains("ConditionVirtualization=!container"));
        let apply = decl.render_apply();
        let unit_at = apply.find(HIDEPID_UNIT).expect("unit written");
        // The first `enable --now` is the best-effort command converge (which
        // renders before files); the guard's enable after the unit file is on
        // disk is the authoritative one, so first-pass convergence holds.
        let enable_at = apply
            .rfind("systemctl enable --now")
            .expect("enable present");
        assert!(
            unit_at < enable_at,
            "guard (re)enables after unit is written"
        );
        assert!(apply.contains("|| true"));
    }

    #[test]
    fn hidepid_detect_checks_live_proc_mount() {
        let decl = module(|c| c.hidepid = true).declaration();
        // Probe fidelity: the unit file alone is not proof — /proc must
        // actually be mounted with hidepid right now, per /proc/self/mounts.
        let probe = decl.render_probe();
        assert!(probe.contains("/proc/self/mounts"));
        assert!(probe.contains("hidepid=(2|invisible)"));
        // Converge applies the restriction immediately, not just at next boot.
        let apply = decl.render_apply();
        assert!(apply.contains("mount -o remount,hidepid=2 /proc"));
        // Without hidepid there is no live check at all.
        let plain = module(|_| {}).declaration().render_probe();
        assert!(!plain.contains("/proc/self/mounts"));
    }

    #[test]
    fn encrypt_method_accepts_yescrypt_and_never_downgrades() {
        // Debian 12+/Ubuntu 22.04+ ship YESCRYPT; forcing SHA512 was a
        // downgrade. Both are accepted; only weaker methods get rewritten.
        let decl = module(|_| {}).declaration();
        assert!(!decl.render_apply().contains("ENCRYPT_METHOD=SHA512"));
        assert!(decl.render_probe().contains(ENCRYPT_OK));
        let accepts = |line: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "printf '%s\\n' {} | {ENCRYPT_OK} -",
                    shell_escape(line)
                ))
                .status()
                .map(|s| s.success())
        };
        let Ok(yes) = accepts("ENCRYPT_METHOD YESCRYPT") else {
            return;
        };
        assert!(yes, "yescrypt is compliant");
        assert!(accepts("ENCRYPT_METHOD\tSHA512").unwrap());
        assert!(
            !accepts("ENCRYPT_METHOD MD5").unwrap(),
            "weaker methods drift"
        );
        assert!(
            !accepts("#ENCRYPT_METHOD SHA512").unwrap(),
            "comments don't count"
        );
    }

    #[test]
    fn login_defs_command_runs_before_managed_files() {
        // Commands precede files in the engine's apply order; login.defs must be
        // set before (unrelated) files are written, and it always runs.
        let apply = module(|_| {}).declaration().render_apply();
        let login_at = apply.find("login.defs password policy").expect("login cmd");
        let file_at = apply.find(LIMITS_COREDUMP).expect("a managed file");
        assert!(login_at < file_at);
    }

    /// Run `script` under `bash -euo pipefail` with a stub `systemctl` that
    /// prints `$UF` for `list-unit-files`, `$ACT` for `list-units`, and logs
    /// every other call to `$dir/log`. Returns (exit ok, log, created list).
    fn with_stub_systemctl(
        tag: &str,
        uf: &str,
        act: &str,
        created: &str,
        script: &str,
    ) -> Option<(bool, String, String)> {
        let dir = std::env::temp_dir().join(format!("anvil-apport-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let stub = dir.join("systemctl");
        std::fs::write(
            &stub,
            "#!/bin/bash\ncase \"$1\" in\n list-unit-files) printf '%b' \"$UF\" ;;\n list-units) printf '%b' \"$ACT\" ;;\n *) echo \"$*\" >> \"$D/log\" ;;\nesac\n",
        )
        .ok()?;
        std::fs::write(dir.join("created"), created).ok()?;
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&stub)
            .status()
            .ok()?;
        let wrapped = format!(
            "__created_list=\"$D/created\"\n\
             __anvil_created() {{ grep -qsxF -- \"$1\" \"$__created_list\"; }}\n\
             __anvil_remember() {{ printf '%s\\n' \"$1\" >> \"$__created_list\"; }}\n\
             __anvil_forget() {{ grep -vxF -- \"$1\" \"$__created_list\" > \"$__created_list.t\" || true; mv \"$__created_list.t\" \"$__created_list\"; }}\n\
             {script}\n"
        );
        let path = format!(
            "{}:{}",
            dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let ok = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &wrapped])
            .env("PATH", path)
            .env("D", &dir)
            .env("UF", uf)
            .env("ACT", act)
            .status()
            .ok()?
            .success();
        let log = std::fs::read_to_string(dir.join("log")).unwrap_or_default();
        let created = std::fs::read_to_string(dir.join("created")).unwrap_or_default();
        let _ = std::fs::remove_dir_all(&dir);
        Some((ok, log, created))
    }

    #[test]
    fn apport_detect_passes_when_absent_or_static_and_drifts_when_enabled_or_active() {
        let detect = apport_command().detect;
        let run = |tag: &str, uf: &str, act: &str| {
            with_stub_systemctl(tag, uf, act, "", &detect).map(|r| r.0)
        };
        // Debian: no apport units at all -> converged, nothing to do.
        let Some(absent) = run("absent", "", "") else {
            return;
        };
        assert!(absent, "no apport units must be a no-op");
        assert!(!run("en", "apport.service enabled enabled\\n", "").unwrap());
        assert!(!run("enrt", "apport.service enabled-runtime -\\n", "").unwrap());
        // static/disabled units are not "enabled" (is-enabled's exit code would lie).
        assert!(run(
            "static",
            "apport-autoreport.service static -\\napport.service disabled enabled\\n",
            ""
        )
        .unwrap());
        assert!(!run(
            "act",
            "apport.service disabled enabled\\n",
            "apport.service loaded active exited x\\n"
        )
        .unwrap());
    }

    #[test]
    fn apport_converge_disables_only_enabled_units_and_records_them() {
        let c = apport_command().converge;
        let Some((ok, log, created)) = with_stub_systemctl(
            "conv",
            "apport.service enabled enabled\\napport-autoreport.path enabled enabled\\napport-forward.socket disabled enabled\\napport-autoreport.service static -\\n",
            "apport-forward.socket loaded active listening x\\n",
            "",
            &c,
        ) else {
            return;
        };
        assert!(ok);
        assert!(log.contains("disable --now apport.service"), "{log}");
        assert!(
            log.contains("disable --now apport-autoreport.path"),
            "{log}"
        );
        assert!(
            !log.contains("disable --now apport-forward.socket"),
            "{log}"
        );
        assert!(
            !log.contains("apport-autoreport.service"),
            "static units untouched: {log}"
        );
        assert!(log.contains("stop apport-forward.socket"), "{log}");
        assert_eq!(
            created,
            "apport-unit:apport.service\napport-unit:apport-autoreport.path\n"
        );
    }

    #[test]
    fn apport_rollback_reenables_only_units_anvil_disabled() {
        let Some((ok, log, created)) = with_stub_systemctl(
            "rb",
            "",
            "",
            "user:x\napport-unit:apport.service\n",
            &apport_rollback(),
        ) else {
            return;
        };
        assert!(ok);
        assert_eq!(log, "enable --now apport.service\n");
        assert_eq!(created, "user:x\n", "marker forgotten after re-enable");
        // Nothing recorded (apport was off before anvil) -> nothing enabled.
        let (ok, log, _) =
            with_stub_systemctl("rb0", "", "", "user:x\n", &apport_rollback()).unwrap();
        assert!(ok);
        assert!(log.is_empty(), "{log}");
    }

    #[test]
    fn apport_runs_between_snapshot_and_live_sysctl_and_rolls_back_last() {
        let decl = module(|c| c.disable_sysrq = false).declaration();
        let apply = decl.render_apply();
        let snap = apply
            .find("snapshot pre-anvil sysctl values")
            .expect("snapshot");
        let apport = apply.find("apport disabled (core dumps)").expect("apport");
        let live = apply
            .find("runtime sysctl process toggles")
            .expect("sysctl");
        assert!(snap < apport && apport < live, "{apply}");
        // Probe stays read-only.
        let probe = decl.render_probe();
        assert!(probe.contains("list-unit-files"));
        for w in [
            "disable --now",
            "systemctl stop",
            "enable --now",
            "__anvil_remember \"apport",
        ] {
            assert!(!probe.contains(w), "probe must not contain {w:?}");
        }
        // Rollback: sysctl restore first, then apport re-enable (its --start wins).
        let rb = decl.render_rollback();
        let restore = rb
            .find("restored pre-anvil sysctl values")
            .expect("restore");
        let reenable = rb.find("enable --now \"$__u\"").expect("apport rollback");
        assert!(restore < reenable);
        // Without disable_core_dumps, apport is left alone everywhere.
        let off = module(|c| c.disable_core_dumps = false).declaration();
        for s in [
            off.render_apply(),
            off.render_probe(),
            off.render_rollback(),
        ] {
            assert!(!s.contains("apport"), "{s}");
        }
    }
}
