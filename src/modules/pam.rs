//! The `pam` module (R34, R74): password quality and failed-login lockout.
//!
//! **Fixed Contract — R59:** this module MUST NEVER hand-edit anything under
//! `/etc/pam.d/`. It writes the policy files the PAM modules read
//! (`pwquality.conf`, `faillock.conf`) and, because those are inert until the
//! modules are in the stack, wires them in the distro's supported way:
//! `libpam-pwquality` registers itself with `pam-auth-update`, and faillock
//! gets two anvil-owned profiles in `/usr/share/pam-configs/` that
//! `pam-auth-update` merges into `common-auth`/`common-account`. A structural
//! check after the merge backs it out if the stack does not look right.

use crate::config::schema::PamSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};
use crate::escape::shell_escape;

use super::Module;

/// libpwquality policy file (Fixed Contract path; read by `pam_pwquality`).
pub const PWQUALITY_CONF: &str = "/etc/security/pwquality.conf";
/// `pam_faillock` policy file (Fixed Contract path).
pub const FAILLOCK_CONF: &str = "/etc/security/faillock.conf";
/// Shell drop-in carrying the session `umask` and auto-logout `TMOUT`. Owned
/// end-to-end (base64-embedded), so it is safe to rewrite and to roll back.
pub const PROFILE_DROP_IN: &str = "/etc/profile.d/99-anvil-hardening.sh";
/// System login definitions. Edited *in place* (never clobbered) so the distro
/// defaults survive; only the `UMASK` directive is rewritten.
pub const LOGIN_DEFS: &str = "/etc/login.defs";

const HEADER: &str = "# Managed by anvil — do not edit by hand";

/// pam-auth-update profile: `pam_faillock preauth`, ordered before pam_unix
/// (priority 1024) so a locked account is refused before the password check.
pub const FAILLOCK_PREAUTH_PROFILE: &str = "/usr/share/pam-configs/anvil-faillock-preauth";
/// pam-auth-update profile: `authfail` after pam_unix (priority 0) counts a
/// failure; the account line clears the counter on success.
pub const FAILLOCK_PROFILE: &str = "/usr/share/pam-configs/anvil-faillock";

const FAILLOCK_PREAUTH_CONTENT: &str = "\
Name: anvil: refuse locked accounts before the password check (pam_faillock)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
\trequisite\t\t\tpam_faillock.so preauth
";

const FAILLOCK_CONTENT: &str = "\
Name: anvil: lock accounts after repeated failures (pam_faillock)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
\t[default=die]\t\t\tpam_faillock.so authfail
Account-Type: Additional
Account:
\trequired\t\t\tpam_faillock.so
";

/// `preauth` before the first `pam_unix`, `authfail` after it, and the account
/// line present: the only shape anvil accepts after `pam-auth-update`.
const FAILLOCK_STACK_OK: &str =
    "awk '/pam_faillock\\.so preauth/ && !p {p=NR} /pam_unix\\.so/ && !u {u=NR} \
/pam_faillock\\.so authfail/ && !f {f=NR} END {exit !(p && u && f && p < u && u < f)}' \
/etc/pam.d/common-auth && grep -q 'pam_faillock\\.so' /etc/pam.d/common-account";

/// libpam-pwquality installed and `pam_pwquality` in the password stack.
const PWQUALITY_WIRED: &str = "dpkg-query -W -f='${Status}' libpam-pwquality 2>/dev/null \
| grep 'install ok installed' >/dev/null && grep -qs pam_pwquality /etc/pam.d/common-password";

/// `awk` program that prints the effective (last-wins) `UMASK` value from
/// `login.defs`, ignoring comments. A trusted compile-time literal.
const AWK_LOGIN_UMASK: &str = r#"awk 'toupper($1)=="UMASK"{v=$2} END{print v}'"#;

pub struct PamModule {
    cfg: PamSection,
}

impl PamModule {
    pub fn new(cfg: PamSection) -> Self {
        Self { cfg }
    }

    /// `pwquality.conf`: minimum length plus per-class *credit* requirements. In
    /// libpwquality a credit of `-1` **requires** at least one character of that
    /// class; `0` neither requires nor rewards it. `minclass` mirrors the number
    /// of required classes.
    pub fn pwquality_content(&self) -> String {
        let c = &self.cfg;
        let credit = |required: bool| if required { -1 } else { 0 };
        let required = [
            c.require_uppercase,
            c.require_lowercase,
            c.require_digit,
            c.require_special,
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        format!(
            "{HEADER}\n\
             minlen = {minlen}\n\
             minclass = {minclass}\n\
             ucredit = {u}\n\
             lcredit = {l}\n\
             dcredit = {d}\n\
             ocredit = {o}\n",
            minlen = c.minlen,
            minclass = required,
            u = credit(c.require_uppercase),
            l = credit(c.require_lowercase),
            d = credit(c.require_digit),
            o = credit(c.require_special),
        )
    }

    /// `faillock.conf`: lock an account after `deny` consecutive failures for
    /// `unlock_time` seconds. Deliberately does *not* set `even_deny_root`, so a
    /// misconfiguration can never lock the operator out of root.
    pub fn faillock_content(&self) -> String {
        let c = &self.cfg;
        format!(
            "{HEADER}\ndeny = {deny}\nunlock_time = {unlock}\n",
            deny = c.deny,
            unlock = c.unlock_time,
        )
    }

    /// A `/etc/profile.d` drop-in applying the session `umask` and, for
    /// interactive shells only, an auto-logout `TMOUT`. This file is *sourced*
    /// by login shells; its content is operator-controlled config, embedded
    /// verbatim (base64) exactly like the sshd drop-in — it is never
    /// interpolated into anvil's own remote bash.
    pub fn profile_content(&self) -> String {
        let c = &self.cfg;
        format!(
            "{HEADER}\n\
             umask {umask}\n\
             if [ -n \"${{PS1-}}\" ] && [ -z \"${{TMOUT-}}\" ]; then\n\
             \x20 TMOUT={tmout}\n\
             \x20 export TMOUT\n\
             fi\n",
            umask = c.umask,
            tmout = c.tmout,
        )
    }

    /// Idempotently set the login `UMASK` in `/etc/login.defs`. Because that
    /// file is distro-owned (not fully ours), we cannot model it as a
    /// `ManagedFile`; instead a command rewrites just the `UMASK` line, taking a
    /// `.anvil.bak` backup (R60/R88) on first change so `rollback` can restore
    /// it.
    fn login_defs_command(&self) -> ManagedCommand {
        let umask = shell_escape(&self.cfg.umask);
        let defs = shell_escape(LOGIN_DEFS);
        let awk = AWK_LOGIN_UMASK;
        let detect = format!("[ \"$({awk} {defs} 2>/dev/null)\" = {umask} ]");
        let (capture, _) = super::login_defs_keys("pam", &["UMASK"]);
        let converge = format!(
            "{capture}\
             __ld_umask={umask}\n\
             __ld_tmp=\"$(mktemp -p \"$__rundir\")\"\n\
             grep -viE '^[[:space:]]*UMASK[[:space:]]' {defs} > \"$__ld_tmp\" 2>/dev/null || true\n\
             printf 'UMASK\\t%s\\n' \"$__ld_umask\" >> \"$__ld_tmp\"\n\
             cat \"$__ld_tmp\" > {defs}\n\
             rm -f \"$__ld_tmp\""
        );
        ManagedCommand::new("set login UMASK in /etc/login.defs", detect, converge)
    }
}

/// pwquality.conf is read only by `pam_pwquality`, which stock Debian
/// does not install. The package's own pam-auth-update profile wires it in.
fn pwquality_command() -> ManagedCommand {
    ManagedCommand::new(
        "pam_pwquality active in the password stack",
        PWQUALITY_WIRED,
        format!(
            "{} && DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable pwquality",
            super::apt_install(&["libpam-pwquality"])
        ),
    )
}

/// Drift check for the faillock wiring. The wiring itself happens in
/// the reload guard, after the profiles exist on disk.
fn faillock_wired_command() -> ManagedCommand {
    ManagedCommand::new(
        "pam_faillock active in the auth stack",
        FAILLOCK_STACK_OK,
        "true",
    )
}

/// Enable the faillock profiles and verify the merged stack; back out if it
/// is not the expected shape. With the profiles gone (rollback), remove them
/// from the stack instead.
fn faillock_guard() -> ReloadGuard {
    let pre = shell_escape(FAILLOCK_PREAUTH_PROFILE);
    let main = shell_escape(FAILLOCK_PROFILE);
    let names = "anvil-faillock-preauth anvil-faillock";
    ReloadGuard {
        describe: "pam_faillock via pam-auth-update".into(),
        validate: format!(
            "{{ ! [ -e {pre} ] || [ -s {pre} ]; }} && {{ ! [ -e {main} ] || [ -s {main} ]; }}"
        ),
        reload: format!(
            "if [ -e {pre} ] && [ -e {main} ]; then \
             {{ DEBIAN_FRONTEND=noninteractive pam-auth-update --package --enable {names} && {FAILLOCK_STACK_OK}; }} \
             || {{ DEBIAN_FRONTEND=noninteractive pam-auth-update --package --remove {names}; false; }}; \
             else DEBIAN_FRONTEND=noninteractive pam-auth-update --package --remove {names}; fi"
        ),
    }
}

impl Module for PamModule {
    fn id(&self) -> &'static str {
        "pam"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("pam")
            .command(pwquality_command())
            .command(self.login_defs_command())
            .rollback_script(super::login_defs_keys("pam", &["UMASK"]).1)
            .file(ManagedFile::new(
                PWQUALITY_CONF,
                self.pwquality_content(),
                "0644",
                "root:root",
            ))
            .file(ManagedFile::new(
                PROFILE_DROP_IN,
                self.profile_content(),
                "0644",
                "root:root",
            ));
        if self.cfg.enable_faillock {
            decl = decl
                .command(faillock_wired_command())
                .file(ManagedFile::new(
                    FAILLOCK_CONF,
                    self.faillock_content(),
                    "0644",
                    "root:root",
                ))
                .file(ManagedFile::new(
                    FAILLOCK_PREAUTH_PROFILE,
                    FAILLOCK_PREAUTH_CONTENT,
                    "0644",
                    "root:root",
                ))
                .file(ManagedFile::new(
                    FAILLOCK_PROFILE,
                    FAILLOCK_CONTENT,
                    "0644",
                    "root:root",
                ))
                .guarded_reload(faillock_guard());
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut PamSection)) -> PamModule {
        // PamSection has no `Default` impl (its serde defaults are the real
        // ones), so derive a defaulted section from an empty document.
        let mut cfg: PamSection = toml::from_str("").expect("default pam section");
        mutate(&mut cfg);
        PamModule::new(cfg)
    }

    #[test]
    fn pwquality_defaults_require_all_classes() {
        let content = module(|_| {}).pwquality_content();
        for needle in [
            "minlen = 14",
            "minclass = 4",
            "ucredit = -1",
            "lcredit = -1",
            "dcredit = -1",
            "ocredit = -1",
        ] {
            assert!(content.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn disabling_a_class_zeroes_its_credit() {
        let content = module(|c| {
            c.require_uppercase = false;
            c.require_special = false;
        })
        .pwquality_content();
        assert!(content.contains("ucredit = 0"));
        assert!(content.contains("ocredit = 0"));
        assert!(content.contains("lcredit = -1"));
        // Two classes required now (lower + digit).
        assert!(content.contains("minclass = 2"));
    }

    #[test]
    fn custom_minlen_is_reflected() {
        let content = module(|c| c.minlen = 20).pwquality_content();
        assert!(content.contains("minlen = 20"));
    }

    #[test]
    fn faillock_is_conditional_and_carries_deny_and_unlock() {
        let enabled = module(|_| {}).declaration();
        let faillock = enabled.files.iter().find(|f| f.path == FAILLOCK_CONF);
        let f = faillock.expect("faillock file declared when enabled");
        let content = f.static_content().expect("static faillock content");
        assert!(content.contains("deny = 5"));
        assert!(content.contains("unlock_time = 900"));
        // Must never lock root out.
        assert!(!content.contains("even_deny_root"));

        let disabled = module(|c| c.enable_faillock = false).declaration();
        assert!(disabled.files.iter().all(|f| f.path != FAILLOCK_CONF));
    }

    #[test]
    fn profile_sets_umask_and_tmout() {
        let content = module(|_| {}).profile_content();
        assert!(content.contains("umask 027"));
        assert!(content.contains("TMOUT=900"));
    }

    #[test]
    fn login_defs_command_escapes_umask() {
        let apply = module(|c| c.umask = "0700".into())
            .declaration()
            .render_apply();
        assert!(apply.contains(LOGIN_DEFS));
        // The value is interpolated into bash, so it must be single-quoted.
        assert!(apply.contains("'0700'"));
    }

    #[test]
    fn login_defs_record_precedes_the_rewrite() {
        // pam records its own UMASK line before rewriting the shared
        // distro file, or rollback has nothing to restore.
        let apply = module(|_| {}).declaration().render_apply();
        let bak = apply
            .find("/var/lib/anvil/login.defs-pam.orig")
            .expect("login.defs record present");
        let rewrite = apply
            .find("cat \"$__ld_tmp\"")
            .expect("login.defs rewrite present");
        assert!(bak < rewrite, "backup must precede the rewrite:\n{apply}");
    }

    #[test]
    fn faillock_stack_check_accepts_only_preauth_unix_authfail() {
        // After pam-auth-update the guard verifies the merged stack.
        // Run the real check against Debian-shaped common-auth files.
        let dir = std::env::temp_dir().join(format!("anvil-pamd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let check = FAILLOCK_STACK_OK.replace("/etc/pam.d", &dir.display().to_string());
        let ok = |auth: &str, account: &str| {
            std::fs::write(dir.join("common-auth"), auth).unwrap();
            std::fs::write(dir.join("common-account"), account).unwrap();
            std::process::Command::new("bash")
                .arg("-c")
                .arg(&check)
                .status()
                .map(|s| s.success())
        };
        let account = "account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so\naccount required pam_faillock.so\n";
        let good = "auth requisite pam_faillock.so preauth\nauth [success=2 default=ignore] pam_unix.so nullok\nauth [default=die] pam_faillock.so authfail\nauth requisite pam_deny.so\n";
        let Ok(accepted) = ok(good, account) else {
            return;
        };
        assert!(accepted, "Debian stack with both profiles");
        let swapped = "auth [success=2 default=ignore] pam_unix.so nullok\nauth requisite pam_faillock.so preauth\nauth [default=die] pam_faillock.so authfail\n";
        assert!(!ok(swapped, account).unwrap(), "preauth after pam_unix");
        let stock =
            "auth [success=1 default=ignore] pam_unix.so nullok\nauth requisite pam_deny.so\n";
        assert!(!ok(stock, account).unwrap(), "not wired");
        assert!(
            !ok(good, "account [success=1 default=ignore] pam_unix.so\n").unwrap(),
            "account line missing"
        );
        let _ = std::fs::remove_dir_all(&dir);
        // The profiles pam-auth-update reads: right priorities and module args.
        assert!(
            FAILLOCK_PREAUTH_CONTENT.contains("Priority: 1024")
                && FAILLOCK_PREAUTH_CONTENT.contains("pam_faillock.so preauth")
        );
        assert!(
            FAILLOCK_CONTENT.contains("Priority: 0")
                && FAILLOCK_CONTENT.contains("pam_faillock.so authfail")
        );
        assert!(
            !FAILLOCK_CONTENT.contains("even_deny_root"),
            "root is never locked"
        );
    }

    #[test]
    fn never_touches_pam_d() {
        // R59: /etc/pam.d is only ever read; changes go through
        // pam-auth-update. No redirect, sed, cp or rm may target it.
        let decl = module(|_| {}).declaration();
        for script in [
            decl.render_probe(),
            decl.render_apply(),
            decl.render_rollback(),
        ] {
            for line in script.lines().filter(|l| l.contains("/etc/pam.d")) {
                for bad in [
                    "> /etc/pam.d",
                    ">> /etc/pam.d",
                    "sed -i",
                    "cp ",
                    "rm ",
                    "mv ",
                ] {
                    assert!(!line.contains(bad), "writes /etc/pam.d: {line}");
                }
            }
        }
    }

    #[test]
    fn probe_and_apply_reference_pwquality() {
        let decl = module(|_| {}).declaration();
        assert!(decl.render_probe().contains(PWQUALITY_CONF));
        assert!(decl.render_apply().contains(PWQUALITY_CONF));
    }

    #[test]
    fn login_defs_is_rollback_restorable() {
        // login.defs is shared with process, so pam restores only its own
        // UMASK record instead of a whole-file backup.
        let decl = module(|_| {}).declaration();
        assert!(!decl.command_files.iter().any(|p| p == LOGIN_DEFS));
        let rb = decl.render_rollback();
        assert!(rb.contains("/var/lib/anvil/login.defs-pam.orig"), "{rb}");
    }
}
