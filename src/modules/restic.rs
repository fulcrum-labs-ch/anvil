//! The `restic` module: scheduled, pruned restic backups driven by a systemd
//! timer, plus a probe that reports drift when the newest snapshot is older
//! than `max_age_hours` or the last run failed (reported, never retried;
//! `apply` starts a backup only while the host has no snapshot at all,
//! the backup decision). Design and verified/assumed upstream facts:
//! `docs/design/restic.md`.
//!
//! Secrets (`password`, `env` values) only ever land in the computed 0600 env
//! file and in subshells of the generated scripts, always through
//! [`shell_escape`] inside bash builtins — never in an argv, never in `diff`.
//!
//! The engine runs commands before files, so repository init and the
//! "backup now" kick only raise flags; the guarded reload (which runs after
//! every file is written) acts on them. Rollback removes the units, wrapper
//! and config files but never runs restic: the repository and its snapshots
//! are never touched. Packages and data are never removed: the restic apt
//! package (or pinned binary) stays installed (the rollback rule).

use crate::config::schema::ResticSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::{apt_install, Module, APT_LOCK_TIMEOUT};

/// Repository, password and backend credentials (`export K='v'` lines).
pub const ENV_PATH: &str = "/etc/restic/env";
/// Backup paths, one per line (`--files-from-verbatim`).
pub const PATHS_PATH: &str = "/etc/restic/paths";
/// Exclude patterns (`--exclude-file`).
pub const EXCLUDES_PATH: &str = "/etc/restic/excludes";
/// Wrapper that sources [`ENV_PATH`] and execs restic (also for restores).
pub const WRAPPER_PATH: &str = "/usr/local/sbin/anvil-restic";
pub const SERVICE_PATH: &str = "/etc/systemd/system/anvil-restic.service";
pub const TIMER_PATH: &str = "/etc/systemd/system/anvil-restic.timer";
const TIMER_WANTS: &str = "/etc/systemd/system/timers.target.wants/anvil-restic.timer";

/// Exit code 10 ("repository does not exist") arrived in 0.17.0 and 12
/// ("wrong password") in 0.17.1; safe init depends on them.
const MIN_VERSION: &str = "0.17.1";
/// Pinned release used when the distro package is older than [`MIN_VERSION`].
const RELEASE_VERSION: &str = "0.19.1";
/// From the release's SHA256SUMS, re-hashed from the downloaded assets.
const SHA256_AMD64: &str = "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c";
const SHA256_ARM64: &str = "a5f64aaab53d51e311fa3829124c5b703f2d14cf187d8640b6be3b2b49376465";
/// Every snapshot anvil makes carries this tag; probe and `forget` filter on
/// it (plus the host) so other backup sets in a shared repository are ignored.
const TAG: &str = "anvil";

/// Rebuildable, volatile or unsafe-to-copy paths, excluded by default.
const DEFAULT_EXCLUDES: &[&str] = &[
    "/var/lib/containerd",
    "/var/lib/apt/lists",
    "/var/lib/snapd/snaps",
    "/var/lib/lxcfs",
    "/root/.cache",
    "/home/*/.cache",
];

pub struct ResticModule {
    cfg: ResticSection,
}

/// Load-time checks (called from `Config::validate`). Messages never echo a
/// secret value.
pub fn validate(c: &ResticSection) -> Result<()> {
    let bad = |field: &str, want: &str| {
        Err(AnvilError::Validation(format!(
            "restic.{field} is invalid (must be {want})"
        )))
    };
    let one_line = |s: &str| !s.is_empty() && !s.contains(char::is_control);
    if !one_line(&c.repository) {
        return bad("repository", "a non-empty single line");
    }
    if c.password.is_empty() || c.password.contains('\0') {
        return bad("password", "non-empty; supply it as \"${RESTIC_PASSWORD}\"");
    }
    for (k, v) in &c.env {
        let name_ok = k
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
            && k.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_');
        if !name_ok || k == "RESTIC_REPOSITORY" || k == "RESTIC_PASSWORD" {
            return bad(
                &format!("env.{k}"),
                "an environment variable name other than RESTIC_REPOSITORY/RESTIC_PASSWORD",
            );
        }
        if v.contains('\0') {
            return bad(&format!("env.{k}"), "free of NUL bytes");
        }
    }
    if c.paths.is_empty() || !c.paths.iter().all(|p| one_line(p) && p.starts_with('/')) {
        return bad("paths", "a non-empty list of absolute single-line paths");
    }
    if !c.exclude.iter().all(|e| one_line(e)) {
        return bad("exclude", "non-empty single-line patterns");
    }
    if !one_line(&c.schedule) || c.schedule.contains('%') {
        return bad(
            "schedule",
            "a systemd OnCalendar expression, e.g. \"daily\"",
        );
    }
    if [c.keep_daily, c.keep_weekly, c.keep_monthly, c.keep_yearly] == [0; 4] {
        return bad(
            "keep_*",
            "at least one keep_daily/weekly/monthly/yearly > 0",
        );
    }
    if c.max_age_hours == 0 {
        return bad("max_age_hours", "at least 1");
    }
    let hook_ok = |h: &String| {
        h.starts_with('/')
            && h.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '+'))
    };
    if !c.pre_backup.iter().all(hook_ok) {
        return bad(
            "pre_backup",
            "absolute executable paths without spaces or special characters",
        );
    }
    Ok(())
}

impl ResticModule {
    pub fn new(cfg: ResticSection) -> Self {
        Self { cfg }
    }

    /// The env file: bash `export` lines with every value shell-escaped, so
    /// any byte round-trips exactly (systemd's `EnvironmentFile=` parser
    /// would apply its own quoting rules). Also valid as an inline preamble.
    pub fn env_content(&self) -> String {
        let mut s = String::from("# Managed by anvil — do not edit by hand. Holds secrets.\n");
        let mut push = |k: &str, v: &str| s.push_str(&format!("export {k}={}\n", shell_escape(v)));
        push("RESTIC_REPOSITORY", &self.cfg.repository);
        push("RESTIC_PASSWORD", &self.cfg.password);
        for (k, v) in &self.cfg.env {
            push(k, v);
        }
        s
    }

    /// One path per line. `--files-from-verbatim` takes every line as-is
    /// (no comments), so this file carries no header.
    pub fn paths_content(&self) -> String {
        self.cfg.paths.iter().map(|p| format!("{p}\n")).collect()
    }

    pub fn excludes_content(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        if self.cfg.default_excludes {
            if self.cfg.docker_volumes {
                // restic's documented negation: cancel the match for volumes.
                lines.push("/var/lib/docker/*".into());
                lines.push("!/var/lib/docker/volumes".into());
            } else {
                lines.push("/var/lib/docker".into());
            }
            lines.extend(DEFAULT_EXCLUDES.iter().map(|e| e.to_string()));
        }
        // restic expands $VAR in exclude files; `$$` is a literal dollar.
        lines.extend(self.cfg.exclude.iter().map(|e| e.replace('$', "$$")));
        let mut s = String::from("# Managed by anvil — do not edit by hand\n");
        for l in lines {
            s.push_str(&l);
            s.push('\n');
        }
        s
    }

    pub fn wrapper_content(&self) -> String {
        format!(
            "#!/bin/bash\n\
             # Managed by anvil — do not edit by hand.\n\
             # Runs restic against the configured repository, e.g.\n\
             #   anvil-restic snapshots\n\
             #   anvil-restic restore latest --target /root/restore\n\
             set -euo pipefail\n\
             . {ENV_PATH}\n\
             # A system service has no $HOME, so restic would run without a cache.\n\
             export RESTIC_CACHE_DIR=\"${{RESTIC_CACHE_DIR:-/var/cache/restic}}\"\n\
             exec restic \"$@\"\n"
        )
    }

    pub fn forget_args(&self) -> String {
        let c = &self.cfg;
        let mut s = format!("forget --prune --tag {TAG} --host %H");
        for (flag, n) in [
            ("daily", c.keep_daily),
            ("weekly", c.keep_weekly),
            ("monthly", c.keep_monthly),
            ("yearly", c.keep_yearly),
        ] {
            if n > 0 {
                s.push_str(&format!(" --keep-{flag} {n}"));
            }
        }
        s
    }

    pub fn service_content(&self) -> String {
        let hooks: String = self
            .cfg
            .pre_backup
            .iter()
            .map(|h| format!("ExecStartPre={h}\n"))
            .collect();
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=restic backup (anvil-managed)\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             {hooks}\
             ExecStart={WRAPPER_PATH} backup --tag {TAG} --host %H --files-from-verbatim {PATHS_PATH} --exclude-file {EXCLUDES_PATH} --exclude-caches\n\
             ExecStart={WRAPPER_PATH} {forget}\n\
             # 3 = some files were unreadable; the snapshot was still written.\n\
             SuccessExitStatus=3\n\
             Nice=10\n\
             IOSchedulingClass=idle\n",
            forget = self.forget_args(),
        )
    }

    pub fn timer_content(&self) -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Scheduled restic backup (anvil-managed)\n\
             \n\
             [Timer]\n\
             OnCalendar={}\n\
             RandomizedDelaySec=1h\n\
             Persistent=true\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            self.cfg.schedule
        )
    }

    /// `( <env exports> \n <body> )`: the desired credentials inline in a
    /// subshell, because commands run before the env file is written.
    fn with_env(&self, body: &str) -> String {
        format!("( {}{body}\n)", self.env_content())
    }

    fn install_command(&self) -> ManagedCommand {
        let release = format!(
            "command -v curl >/dev/null 2>&1 && command -v bunzip2 >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
             __arch=$(dpkg --print-architecture)\n\
             case \"$__arch\" in\n\
             \x20 amd64) __sha={SHA256_AMD64} ;;\n\
             \x20 arm64) __sha={SHA256_ARM64} ;;\n\
             \x20 *) printf 'FAILED: no pinned restic release for %s; install restic >= {MIN_VERSION} yourself\\n' \"$__arch\"; exit 1 ;;\n\
             esac\n\
             __tmp=$(mktemp -d -p \"$__rundir\")\n\
             curl -fsSL -o \"$__tmp/restic.bz2\" \"https://github.com/restic/restic/releases/download/v{RELEASE_VERSION}/restic_{RELEASE_VERSION}_linux_${{__arch}}.bz2\"\n\
             printf '%s  %s\\n' \"$__sha\" \"$__tmp/restic.bz2\" | sha256sum -c --quiet - \
             || {{ printf 'FAILED: restic {RELEASE_VERSION} download failed its SHA-256 check\\n'; rm -rf \"$__tmp\"; exit 1; }}\n\
             bunzip2 \"$__tmp/restic.bz2\"\n\
             install -m 0755 -o root -g root \"$__tmp/restic\" /usr/local/bin/restic\n\
             rm -rf \"$__tmp\"",
            bootstrap = apt_install(&["curl", "ca-certificates", "bzip2"]),
        );
        ManagedCommand::new(
            format!("restic >= {MIN_VERSION} installed"),
            format!(
                "{{ __v=$(restic version 2>/dev/null | sed -n 's/^restic \\([0-9][0-9.]*\\).*/\\1/p'); \
                 [ -n \"$__v\" ] && dpkg --compare-versions \"$__v\" ge {MIN_VERSION}; }}"
            ),
            // Prefer the distro package when its candidate is new enough;
            // otherwise the pinned, checksum-verified upstream release.
            format!(
                "DEBIAN_FRONTEND=noninteractive apt-get {APT_LOCK_TIMEOUT} update -qq\n\
                 __cand=$(apt-cache policy restic 2>/dev/null | sed -n 's/^ *Candidate: *//p')\n\
                 if [ -n \"$__cand\" ] && [ \"$__cand\" != '(none)' ] && dpkg --compare-versions \"$__cand\" ge {MIN_VERSION}; then\n\
                 {distro}\n\
                 else\n\
                 {release}\n\
                 fi",
                distro = apt_install(&["restic"]),
            ),
        )
    }

    /// Read-only: `cat config` needs no lock and `--no-cache` writes no cache.
    fn repository_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "restic repository initialized",
            self.with_env("restic --no-lock --no-cache cat config >/dev/null 2>&1"),
            "__restic_init=1",
        )
    }

    /// Some `anvil`-tagged snapshot of this host exists. Sets
    /// `__restic_newest` (epoch, 0 = none) for [`Self::freshness_command`].
    /// The only path to a backup kick: first install or a new repo.
    /// `--no-lock`/`--no-cache` keep the probe write-free.
    fn snapshot_command(&self) -> ManagedCommand {
        let body = format!(
            "__newest=0\n\
             for __t in $(restic --no-lock --no-cache snapshots --json --tag {TAG} --host \"$(uname -n)\" --latest 1 2>/dev/null \
             | tr ',' '\\n' | sed -n 's/^.*\"time\":\"\\([^\"]*\\)\".*$/\\1/p' | sed 's/\\.[0-9]*//'); do\n\
             \x20 __e=$(date -d \"$__t\" +%s 2>/dev/null) || continue\n\
             \x20 if [ \"$__e\" -gt \"$__newest\" ]; then __newest=$__e; fi\n\
             done\n\
             echo \"$__newest\""
        );
        ManagedCommand::new(
            "restic snapshot of this host exists",
            format!(
                "{{ __restic_newest=$( {} 2>/dev/null || echo 0); [ \"$__restic_newest\" -gt 0 ]; }}",
                self.with_env(&body)
            ),
            "__restic_backup=1",
        )
    }

    /// Report-only: the newest snapshot is younger than
    /// `max_age_hours` and the last run of the service did not fail. A stale
    /// snapshot is reported with its age and the last run's result, never
    /// retried; a failed last run drifts whatever the age. Only `DRIFTED:`,
    /// never `FAILED:` or an exit: either would fail `apply`, which skips
    /// `updates` and (exit) blocks writing a config fix. No snapshot at all is left to
    /// [`Self::snapshot_command`].
    fn freshness_command(&self) -> ManagedCommand {
        let h = self.cfg.max_age_hours;
        let secs = u64::from(h) * 3600;
        let detect = format!(
            "{{ __restic_show=$(systemctl show -p Result,ExecMainStatus anvil-restic.service 2>/dev/null || true); \
             __restic_res=$(printf '%s\\n' \"$__restic_show\" | sed -n 's/^Result=//p'); \
             __restic_st=$(printf '%s\\n' \"$__restic_show\" | sed -n 's/^ExecMainStatus=//p'); \
             __restic_age=-1; __restic_agetxt=none; \
             if [ \"${{__restic_newest:-0}}\" -gt 0 ]; then __restic_age=$(( $(date +%s) - __restic_newest )); __restic_agetxt=\"$(( __restic_age / 3600 ))h\"; fi; \
             if [ -n \"$__restic_res\" ] && [ \"$__restic_res\" != success ]; then \
             printf 'DRIFTED: restic: last backup run failed (%s, status %s), see journalctl -u anvil-restic; newest snapshot age %s\\n' \"$__restic_res\" \"${{__restic_st:-?}}\" \"$__restic_agetxt\"; \
             false; \
             elif [ \"$__restic_age\" -gt {secs} ]; then \
             printf 'DRIFTED: restic: newest snapshot is %s old (max {h}h); last run: %s; not retried, see journalctl -u anvil-restic\\n' \"$__restic_agetxt\" \"${{__restic_res:-none}}\"; \
             false; \
             fi; }}"
        );
        ManagedCommand::new(
            format!("restic snapshot newer than {h}h and last backup run succeeded"),
            detect,
            "# reported only: a stale snapshot is never retried",
        )
    }

    fn timer_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "anvil-restic.timer enabled and active",
            "{ systemctl is-enabled --quiet anvil-restic.timer 2>/dev/null \
             && systemctl is-active --quiet anvil-restic.timer 2>/dev/null; }",
            ": # enabled by the guarded reload below",
        )
    }

    /// Runs after every file is written, and again after rollback (so each
    /// step tolerates absent files). Init runs only on exit code 10 — a wrong
    /// password or an unreachable backend fails the apply and never inits.
    fn guard(&self) -> ReloadGuard {
        let init = format!(
            "{{ [ \"${{__restic_init:-0}}\" != 1 ] || {{ __rc=0; {WRAPPER_PATH} --no-lock --no-cache cat config >/dev/null 2>&1 || __rc=$?; \
             if [ \"$__rc\" = 0 ]; then :; elif [ \"$__rc\" = 10 ]; then {WRAPPER_PATH} init; \
             else printf 'FAILED: restic repository check exited %s (wrong password or unreachable?); not running init\\n' \"$__rc\"; false; fi; }}; }}"
        );
        ReloadGuard {
            describe: "restic backup units".into(),
            validate: format!(
                "{{ ! [ -e {SERVICE_PATH} ] || systemd-analyze verify {SERVICE_PATH} {TIMER_PATH}; }} \
                 && {{ ! [ -e {WRAPPER_PATH} ] || bash -n {WRAPPER_PATH}; }}"
            ),
            reload: format!(
                "systemctl daemon-reload && {{ ! [ -e {TIMER_PATH} ] || {{ {init} \
                 && systemctl enable --now anvil-restic.timer \
                 && {{ [ \"${{__restic_backup:-0}}\" != 1 ] || systemctl start --no-block anvil-restic.service; }}; }}; }}"
            ),
        }
    }

    /// Stops the timer and drops its `enable` symlink (the engine has already
    /// removed the unit files). Never runs restic; a running backup finishes.
    /// It runs before the guard's reload, so clearing the flags here pins the
    /// init/backup branches of that reload off during rollback.
    fn rollback_script() -> String {
        format!(
            "\n# rollback (module-authored): restic timer (repository and snapshots are never touched)\n\
             __restic_init=0\n\
             __restic_backup=0\n\
             if [ -L {TIMER_WANTS} ] || systemctl is-active --quiet anvil-restic.timer 2>/dev/null; then\n\
             \x20 systemctl stop anvil-restic.timer 2>/dev/null || true\n\
             \x20 rm -f {TIMER_WANTS}\n\
             \x20 printf 'CHANGED: anvil-restic.timer stopped and disabled; repository left intact\\n'\n\
             else\n\
             \x20 printf 'OK: anvil-restic.timer not active; repository left intact\\n'\n\
             fi\n"
        )
    }
}

impl Module for ResticModule {
    fn id(&self) -> &'static str {
        "restic"
    }

    fn declaration(&self) -> Declaration {
        // The generator is a bash builtin printf: the secrets never reach an argv.
        let env_gen = format!("printf '%s' {}", shell_escape(&self.env_content()));
        let secrets = std::iter::once(&self.cfg.password).chain(self.cfg.env.values());
        secrets
            .fold(Declaration::new("restic"), |d, v| d.secret(v))
            .command(self.install_command())
            .command(self.repository_command())
            .command(self.snapshot_command())
            .command(self.freshness_command())
            .command(self.timer_command())
            .file(ManagedFile::computed(
                ENV_PATH,
                env_gen,
                "0600",
                "root:root",
            ))
            .file(ManagedFile::new(
                PATHS_PATH,
                self.paths_content(),
                "0640",
                "root:root",
            ))
            .file(ManagedFile::new(
                EXCLUDES_PATH,
                self.excludes_content(),
                "0640",
                "root:root",
            ))
            .file(ManagedFile::new(
                WRAPPER_PATH,
                self.wrapper_content(),
                "0750",
                "root:root",
            ))
            .file(ManagedFile::new(
                SERVICE_PATH,
                self.service_content(),
                "0644",
                "root:root",
            ))
            .file(ManagedFile::new(
                TIMER_PATH,
                self.timer_content(),
                "0644",
                "root:root",
            ))
            .rollback_script(Self::rollback_script())
            .guarded_reload(self.guard())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr'et$pw";

    fn section(mutate: impl FnOnce(&mut ResticSection)) -> ResticSection {
        let mut c: ResticSection = toml::from_str(&format!(
            "repository = \"sftp:backup@nas:/srv/restic\"\npassword = {SECRET:?}\n"
        ))
        .expect("minimal section");
        c.env.insert("AWS_SECRET_ACCESS_KEY".into(), "k3y".into());
        mutate(&mut c);
        c
    }

    fn module(mutate: impl FnOnce(&mut ResticSection)) -> ResticModule {
        ResticModule::new(section(mutate))
    }

    #[test]
    fn defaults_validate_and_cover_system_paths() {
        let c = section(|_| {});
        validate(&c).expect("defaults valid");
        let hooked = section(|c| c.pre_backup = vec!["/usr/local/bin/dump-db_v2.sh".into()]);
        validate(&hooked).expect("a plain absolute hook path is valid");
        assert!(c.paths.iter().any(|p| p == "/etc"));
        assert_eq!(
            (c.keep_daily, c.keep_weekly, c.keep_monthly, c.keep_yearly),
            (7, 4, 6, 0)
        );
        assert_eq!(c.max_age_hours, 36);
        assert!(!format!("{c:?}").contains(SECRET), "Debug must redact");
        assert!(!format!("{c:?}").contains("k3y"), "Debug must redact env");
        assert!(format!("{c:?}").contains("sftp:backup@nas:/srv/restic"));
        assert!(format!("{c:?}").contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn validation_rejects_hostile_or_empty_values() {
        let cases: Vec<fn(&mut ResticSection)> = vec![
            |c| c.repository = String::new(),
            |c| c.repository = "/srv\nx".into(),
            |c| c.password = String::new(),
            |c| {
                c.env.insert("BAD-NAME".into(), "v".into());
            },
            |c| {
                c.env.insert("RESTIC_PASSWORD".into(), "v".into());
            },
            |c| c.paths = vec![],
            |c| c.paths = vec!["relative".into()],
            |c| c.paths = vec!["/a\n/b".into()],
            |c| c.exclude = vec!["x\ny".into()],
            |c| c.schedule = "daily\nExecStart=/bin/sh".into(),
            |c| c.schedule = "%H".into(),
            |c| {
                c.keep_daily = 0;
                c.keep_weekly = 0;
                c.keep_monthly = 0;
            },
            |c| c.max_age_hours = 0,
            |c| c.password = "a\0b".into(),
            |c| {
                c.env.insert("RESTIC_REPOSITORY".into(), "v".into());
            },
            |c| {
                c.env.insert("GOOD".into(), "a\0b".into());
            },
            |c| {
                c.env.insert("1BAD".into(), "v".into());
            },
            |c| c.pre_backup = vec!["/bin/sh -c rm".into()],
            |c| c.pre_backup = vec!["dump".into()],
        ];
        for (i, f) in cases.into_iter().enumerate() {
            let c = section(f);
            let err = validate(&c).expect_err(&format!("case {i} must be rejected"));
            assert!(
                !err.to_string().contains(SECRET),
                "case {i} leaks the secret"
            );
        }
    }

    #[test]
    fn env_file_is_computed_root_only_and_escaped() {
        let d = module(|_| {}).declaration();
        let env = d.files.iter().find(|f| f.path == ENV_PATH).unwrap();
        assert_eq!(
            env.static_content(),
            None,
            "computed so diff never shows it"
        );
        assert_eq!(
            (env.mode.as_str(), env.owner.as_str()),
            ("0600", "root:root")
        );
        let content = module(|_| {}).env_content();
        assert!(content.contains(&format!("export RESTIC_PASSWORD={}", shell_escape(SECRET))));
        assert!(content.contains("export AWS_SECRET_ACCESS_KEY='k3y'"));
        // Sourcing the file reproduces the exact secret bytes.
        let out = std::process::Command::new("bash")
            .args(["-c", &format!("{content}printf '%s' \"$RESTIC_PASSWORD\"")])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), SECRET);
    }

    #[test]
    fn secrets_stay_out_of_static_content() {
        let d = module(|_| {}).declaration();
        for f in &d.files {
            if let Some(c) = f.static_content() {
                assert!(
                    !c.contains(SECRET) && !c.contains("k3y"),
                    "{} leaks",
                    f.path
                );
            }
        }
    }

    #[test]
    fn service_backs_up_then_prunes_with_policy_scoped_to_host_and_tag() {
        let m = module(|c| {
            c.keep_yearly = 2;
            c.pre_backup = vec!["/usr/local/bin/dump-db".into()];
        });
        let s = m.service_content();
        let pre = s.find("ExecStartPre=/usr/local/bin/dump-db").unwrap();
        let backup = s
            .find(" backup --tag anvil --host %H --files-from-verbatim")
            .unwrap();
        let forget = s
            .find(" forget --prune --tag anvil --host %H --keep-daily 7 --keep-weekly 4 --keep-monthly 6 --keep-yearly 2\n")
            .unwrap();
        assert!(pre < backup && backup < forget, "{s}");
        assert!(s.contains("Type=oneshot") && s.contains("SuccessExitStatus=3"));
        assert!(
            module(|_| {}).forget_args().ends_with("--keep-monthly 6"),
            "0 omitted"
        );
        let t = m.timer_content();
        assert!(t.contains("OnCalendar=daily\n") && t.contains("Persistent=true"));
    }

    #[test]
    fn wrapper_sources_env_and_execs_restic() {
        let w = module(|_| {}).wrapper_content();
        assert!(w.starts_with("#!/bin/bash\n"));
        let src = w.find(&format!("\n. {ENV_PATH}\n")).expect("sources env");
        let cache = w
            .find("export RESTIC_CACHE_DIR=\"${RESTIC_CACHE_DIR:-/var/cache/restic}\"")
            .expect("cache dir set: a system service has no $HOME");
        assert!(src < cache && cache < w.find("\nexec restic \"$@\"\n").expect("execs restic"));
        let out = std::process::Command::new("bash")
            .args(["-n", "-c", &w])
            .output()
            .unwrap();
        assert!(out.status.success(), "wrapper must parse");
    }

    #[test]
    fn excludes_default_docker_and_escape_dollar() {
        let x = module(|c| c.exclude = vec!["/srv/$tmp".into()]).excludes_content();
        assert!(x.lines().any(|l| l == "/var/lib/docker"));
        assert!(x.lines().any(|l| l == "/srv/$$tmp"), "{x}");
        let v = module(|c| c.docker_volumes = true).excludes_content();
        assert!(
            v.contains("/var/lib/docker/*\n!/var/lib/docker/volumes\n"),
            "{v}"
        );
        assert!(!v.lines().any(|l| l == "/var/lib/docker"));
        let none = module(|c| c.default_excludes = false).excludes_content();
        assert!(!none.contains("/var/lib/docker"));
        // --files-from-verbatim has no comments: the paths file is paths only.
        let p = module(|c| c.paths = vec!["/etc".into(), "/srv/my data".into()]).paths_content();
        assert_eq!(p, "/etc\n/srv/my data\n");
    }

    #[test]
    fn probe_is_read_only_and_checks_freshness() {
        let probe = module(|c| c.max_age_hours = 2).declaration().render_probe();
        assert!(probe.contains("snapshots --json --tag anvil --host \"$(uname -n)\" --latest 1"));
        assert!(probe.contains("-gt 7200 ]"), "max age in seconds");
        assert!(probe.contains("systemctl show -p Result,ExecMainStatus anvil-restic.service"));
        for cmd in ["snapshots", "cat config"] {
            let at = probe
                .find(&format!("--no-lock --no-cache {cmd}"))
                .unwrap_or(usize::MAX);
            assert!(at != usize::MAX, "{cmd} must not lock or cache:\n{probe}");
        }
        for forbidden in [
            "restic init",
            "forget --prune",
            "systemctl start",
            "systemctl enable",
        ] {
            assert!(!probe.contains(forbidden), "probe runs {forbidden:?}");
        }
    }

    #[test]
    fn snapshot_check_parses_restic_json() {
        // Run the real detect body against a fake restic printing the JSON
        // shape restic's encoder produces (RFC3339Nano time). Needs GNU date.
        let gnu_date = std::process::Command::new("date")
            .args(["-d", "@0"])
            .output();
        if !gnu_date.is_ok_and(|o| o.status.success()) {
            return;
        }
        let det = module(|_| {}).snapshot_command().detect;
        let run = |json: &str| {
            let fake = format!("restic() {{ printf '%s\\n' {}; }}\n", shell_escape(json));
            let out = std::process::Command::new("bash")
                .args([
                    "-euo",
                    "pipefail",
                    "-c",
                    &format!("{fake}if {det}; then echo some $__restic_newest; else echo none $__restic_newest; fi"),
                ])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        };
        let snap = r#"[{"time":"2020-01-02T03:04:05.123456789+01:00","tree":"ab","paths":["/etc"],"hostname":"h","tags":["anvil"]}]"#;
        assert_eq!(run(snap), "some 1577930645");
        assert_eq!(run("[]"), "none 0");
    }

    /// Runs the freshness detect with a given newest-snapshot age (hours,
    /// None = no snapshot) and a fake `systemctl show` result.
    fn freshness(max_age: u32, age_h: Option<u64>, result: &str) -> (bool, String) {
        let det = module(|c| c.max_age_hours = max_age)
            .freshness_command()
            .detect;
        let newest = age_h.map_or("0".to_string(), |h| {
            format!("$(( $(date +%s) - {} ))", h * 3600 + 60)
        });
        let script = format!(
            "systemctl() {{ printf 'Result=%s\\nExecMainStatus=%s\\n' {result} 1; }}\n\
             __restic_newest={newest}\n\
             if {det}; then echo PASS; else echo DRIFT; fi"
        );
        let out = std::process::Command::new("bash")
            .args(["-euo", "pipefail", "-c", &script])
            .output()
            .unwrap();
        assert!(out.status.success(), "detect must not exit the script");
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        (s.ends_with("PASS\n"), s)
    }

    #[test]
    fn stale_snapshot_is_reported_with_age_and_last_result() {
        let (ok, out) = freshness(36, Some(1), "success");
        assert!(
            ok && !out.contains("DRIFTED") && !out.contains("FAILED"),
            "{out}"
        );
        let (ok, out) = freshness(36, Some(50), "success");
        assert!(!ok, "{out}");
        assert!(
            out.contains(
                "DRIFTED: restic: newest snapshot is 50h old (max 36h); last run: success"
            ),
            "{out}"
        );
        assert!(!out.contains("FAILED"), "{out}");
        // Exactly at the limit is still fresh.
        assert!(freshness(2, Some(1), "success").0);
        // No snapshot is the snapshot command's job (first backup), not drift here.
        assert!(freshness(36, None, "success").0);
    }

    #[test]
    fn failed_last_run_drifts_even_with_a_fresh_snapshot() {
        for age in [Some(1), Some(50), None] {
            let (ok, out) = freshness(36, age, "exit-code");
            assert!(!ok, "{out}");
            assert!(
                out.contains("DRIFTED: restic: last backup run failed (exit-code, status 1), see journalctl -u anvil-restic;"),
                "{out}"
            );
            // FAILED: would fail apply and skip `updates` behind it.
            assert!(!out.contains("FAILED"), "{out}");
        }
        let (_, out) = freshness(36, None, "exit-code");
        assert!(out.contains("newest snapshot age none"), "{out}");
    }

    #[test]
    fn backup_starts_only_when_no_snapshot_exists() {
        let m = module(|_| {});
        assert_eq!(m.snapshot_command().converge, "__restic_backup=1");
        let fresh = m.freshness_command();
        assert!(
            !fresh.converge.contains("__restic_backup"),
            "stale must never retry"
        );
        assert!(!fresh.detect.contains("systemctl start"));
        let d = m.declaration();
        let at = |needle: &str| {
            d.commands
                .iter()
                .position(|c| c.describe.starts_with(needle))
        };
        // The snapshot command sets __restic_newest before freshness reads it.
        assert!(at("restic snapshot of this host").unwrap() < at("restic snapshot newer").unwrap());
        let g = d.reload.unwrap().reload;
        assert!(g.contains("{ [ \"${__restic_backup:-0}\" != 1 ] || systemctl start --no-block anvil-restic.service; }"));
    }

    #[test]
    fn init_only_on_missing_repository_and_after_files() {
        let d = module(|_| {}).declaration();
        let apply = d.render_apply();
        let g = d.reload.as_ref().unwrap();
        assert!(g
            .reload
            .contains("elif [ \"$__rc\" = 10 ]; then /usr/local/sbin/anvil-restic init"));
        assert!(g.reload.contains("FAILED: restic repository check exited"));
        // init happens in the guard, after the files, and before the timer starts.
        let last_file = apply.rfind("# file:").unwrap();
        let init = apply.rfind("anvil-restic init").unwrap();
        assert!(last_file < init);
        assert!(g.reload.find(" init").unwrap() < g.reload.find("enable --now").unwrap());
        // Validation tolerates absent files (rollback re-runs the guard).
        assert!(g
            .validate
            .starts_with(&format!("{{ ! [ -e {SERVICE_PATH} ] ||")));
    }

    #[test]
    fn install_prefers_distro_then_verified_release() {
        let c = module(|_| {}).install_command();
        assert!(c
            .detect
            .contains("dpkg --compare-versions \"$__v\" ge 0.17.1"));
        let distro = c.converge.find("install -y -- 'restic'").unwrap();
        let sha = c.converge.find("sha256sum -c").unwrap();
        let install = c.converge.find("install -m 0755").unwrap();
        assert!(distro < sha && sha < install, "checksum before install");
        assert!(c.converge.contains(SHA256_AMD64) && c.converge.contains(SHA256_ARM64));
        for pipe_to_shell in ["| sh ", "| sh\n", "| bash"] {
            assert!(!c.converge.contains(pipe_to_shell));
        }
    }

    #[test]
    fn rollback_never_touches_the_repository() {
        let rb = module(|c| c.repository = "/srv/restic-repo".into())
            .declaration()
            .render_rollback();
        assert!(
            !rb.contains("/srv/restic-repo"),
            "repository path in rollback"
        );
        for forbidden in ["restic forget", "forget --prune", "prune", "rm -rf"] {
            assert!(!rb.contains(forbidden), "rollback contains {forbidden:?}");
        }
        // The guard's reload re-runs in rollback; its init/backup branches are
        // pinned off by the flag reset that precedes it.
        let reset = rb
            .find("__restic_init=0\n__restic_backup=0")
            .expect("flags reset");
        assert!(reset < rb.find("anvil-restic init").unwrap(), "{rb}");
        for p in [
            ENV_PATH,
            PATHS_PATH,
            EXCLUDES_PATH,
            WRAPPER_PATH,
            SERVICE_PATH,
            TIMER_PATH,
        ] {
            assert!(
                rb.contains(&format!("# rollback: {p}")),
                "{p} not rolled back"
            );
        }
        assert!(rb.contains(&format!("rm -f {TIMER_WANTS}")));
    }
}
