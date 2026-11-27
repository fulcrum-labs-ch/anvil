//! The `users` module (R67): create accounts, sudoers drop-ins and
//! `authorized_keys`, all idempotently.
//!
//! Key placement never assumes `/home/<name>`: the account's real home
//! directory is resolved at runtime from the passwd database (`getent passwd
//! <name> | cut -d: -f6`), so pre-existing accounts with non-standard homes —
//! and root — are handled correctly. Ownership uses the `chown <name>:`
//! colon-form, which assigns the account's actual login group instead of
//! guessing a `<name>:<name>` group that is not guaranteed to exist.

use crate::config::schema::{Account, UsersSection};
use crate::engine::{Declaration, ManagedCommand, ManagedFile};
use crate::escape::shell_escape;

use super::Module;

const DEFAULT_SHELL: &str = "/bin/bash";

pub struct UsersModule {
    cfg: UsersSection,
}

impl UsersModule {
    pub fn new(cfg: UsersSection) -> Self {
        Self { cfg }
    }
}

/// Sudoers drop-in path for an account (Fixed Contract for rollback).
pub fn sudoers_path(name: &str) -> String {
    format!("/etc/sudoers.d/{name}")
}

/// Bash snippet that resolves the account's real home directory (field 6 of
/// its passwd entry) into `__home`. `escaped_name` must already have passed
/// through [`shell_escape`]. Detect and converge both use this *same* snippet,
/// so they can never disagree about where the ssh material lives.
fn resolve_home(escaped_name: &str) -> String {
    format!("__home=$(getent passwd {escaped_name} | cut -d: -f6)")
}

fn create_command(acct: &Account) -> ManagedCommand {
    let name = shell_escape(&acct.name);
    let shell = shell_escape(acct.shell.as_deref().unwrap_or(DEFAULT_SHELL));
    ManagedCommand::new(
        format!("create account {}", acct.name),
        format!("id -u {name} >/dev/null 2>&1"),
        format!("useradd -m -s {shell} {name}"),
    )
}

/// `~/.ssh` at 0700, owned by the account (login group via `chown <name>:`),
/// in the account's real home.
fn ssh_dir_command(acct: &Account) -> ManagedCommand {
    let name = shell_escape(&acct.name);
    let home = resolve_home(&name);
    let expect = shell_escape(&format!("700 {}", acct.name));
    ManagedCommand::new(
        format!("ssh dir for {}", acct.name),
        format!(
            "{home} && [ -n \"$__home\" ] && \
             [ \"$(stat -c '%a %U' \"$__home/.ssh\" 2>/dev/null)\" = {expect} ]"
        ),
        format!(
            "{home}\n\
             [ -n \"$__home\" ]\n\
             install -d -m 0700 \"$__home/.ssh\"\n\
             chown {name}: \"$__home/.ssh\""
        ),
    )
}

/// `authorized_keys` at 0600 in the account's real home. The path is resolved
/// on the target from the account's passwd entry (`getent`), so non-standard
/// homes — and root — are handled; the account is created by an earlier command
/// in this declaration, so `getent` resolves by the time this file step runs.
/// Ownership is the account via the `chown <name>:` login-group form (the
/// engine checks the user only, never a guessed group). Byte-exact content,
/// backup-before-overwrite, mode/owner drift detection, and rollback all come
/// from the engine now — no hand-rolled `stat`/`cat` detects that could drift
/// from apply.
fn authorized_keys_file(acct: &Account, keys: &[String]) -> ManagedFile {
    let name = shell_escape(&acct.name);
    let mut content = keys.join("\n");
    content.push('\n');
    let resolver =
        format!("printf '%s/.ssh/authorized_keys' \"$(getent passwd {name} | cut -d: -f6)\"");
    ManagedFile::new(
        format!("<home>/.ssh/authorized_keys ({})", acct.name),
        content,
        "0600",
        format!("{}:", acct.name),
    )
    .with_path_resolver(resolver)
}

impl Module for UsersModule {
    fn id(&self) -> &'static str {
        "users"
    }

    fn declaration(&self) -> Declaration {
        let mut decl = Declaration::new("users");
        for acct in &self.cfg.create {
            decl = decl.command(create_command(acct));
            if let Some(keys) = acct.ssh_authorized_keys.as_ref().filter(|k| !k.is_empty()) {
                // create → ~/.ssh (command) → authorized_keys (managed file),
                // per account, in order. Commands run before files, so ~/.ssh
                // exists (0700, account-owned) before the key file is written.
                decl = decl.command(ssh_dir_command(acct));
                decl = decl.file(authorized_keys_file(acct, keys));
            }
        }
        for acct in &self.cfg.create {
            if acct.sudo {
                // NOPASSWD sudoers drop-in at 0440 (R67).
                let content = format!("{} ALL=(ALL) NOPASSWD:ALL\n", acct.name);
                decl = decl.file(ManagedFile::new(
                    sudoers_path(&acct.name),
                    content,
                    "0440",
                    "root:root",
                ));
            }
        }
        decl
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::BACKUP_SUFFIX;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;

    fn account(name: &str) -> Account {
        Account {
            name: name.into(),
            sudo: false,
            shell: None,
            ssh_authorized_keys: None,
        }
    }

    fn with_keys(name: &str, keys: &[&str]) -> Account {
        let mut a = account(name);
        a.ssh_authorized_keys = Some(keys.iter().map(|k| k.to_string()).collect());
        a
    }

    fn module(accts: Vec<Account>) -> UsersModule {
        UsersModule::new(UsersSection {
            create: accts,
            ..Default::default()
        })
    }

    #[test]
    fn creates_user_idempotently() {
        let s = module(vec![account("alice")]).declaration().render_apply();
        assert!(s.contains("id -u 'alice'"));
        assert!(s.contains("useradd -m -s '/bin/bash' 'alice'"));
    }

    #[test]
    fn sudo_writes_nopasswd_dropin_at_0440() {
        let mut a = account("bob");
        a.sudo = true;
        let decl = module(vec![a]).declaration();
        // The desired content is declared (the engine base64-embeds it), so we
        // assert on the declaration, not the rendered bash.
        let sudoers = decl
            .files
            .iter()
            .find(|f| f.path == "/etc/sudoers.d/bob")
            .expect("sudoers file declared");
        assert_eq!(
            sudoers.static_content(),
            Some("bob ALL=(ALL) NOPASSWD:ALL\n")
        );
        assert_eq!(sudoers.mode, "0440");
        // The rendered apply still references the path and mode.
        let apply = decl.render_apply();
        assert!(apply.contains("/etc/sudoers.d/bob"));
        assert!(apply.contains("chmod '0440'"));
    }

    #[test]
    fn authorized_keys_is_a_resolved_managed_file() {
        // authorized_keys is a ManagedFile (no hand-rolled stat detect)
        // whose path resolves at runtime via getent, owned by the login group
        // (colon form → user-only check), mode 0600, byte-exact static content.
        let decl = module(vec![with_keys("carol", &["ssh-ed25519 AAAA"])]).declaration();
        let ak = decl
            .files
            .iter()
            .find(|f| f.path.contains("authorized_keys"))
            .expect("authorized_keys declared as a managed file");
        assert!(ak.path_resolver.is_some(), "path is host-computed");
        let resolver = ak.path_resolver.as_ref().unwrap();
        assert!(
            resolver.contains("getent passwd"),
            "resolves home: {resolver}"
        );
        assert_eq!(ak.mode, "0600");
        assert_eq!(ak.owner, "carol:", "login-group colon form");
        assert_eq!(ak.static_content(), Some("ssh-ed25519 AAAA\n"));
    }

    #[test]
    fn home_is_resolved_via_getent_in_probe_and_apply() {
        let decl = module(vec![with_keys("carol", &["ssh-ed25519 AAAA"])]).declaration();
        let getent = "getent passwd 'carol' | cut -d: -f6";
        // The ssh-dir command resolves home in detect+converge, and the
        // authorized_keys file resolves it in its path line — in both scripts.
        for s in [decl.render_probe(), decl.render_apply()] {
            assert!(s.contains(getent), "home resolved via getent:\n{s}");
        }
    }

    #[test]
    fn authorized_keys_uses_login_group_colon_form() {
        let apply = module(vec![with_keys("carol", &["ssh-ed25519 AAAA"])])
            .declaration()
            .render_apply();
        // `chown 'carol':` (login group) for both the dir and the key file.
        assert!(apply.contains("chown 'carol':"));
        assert!(!apply.contains("carol:carol"));
    }

    #[test]
    fn no_hardcoded_home_for_key_placement() {
        let decl = module(vec![with_keys("erin", &["ssh-ed25519 KEY"])]).declaration();
        for s in [decl.render_probe(), decl.render_apply()] {
            assert!(
                !s.contains("/home/"),
                "home must come from getent, not a literal:\n{s}"
            );
        }
    }

    #[test]
    fn dir_0700_and_file_0600_with_engine_backup() {
        let apply = module(vec![with_keys("carol", &["ssh-ed25519 AAAA"])])
            .declaration()
            .render_apply();
        // The .ssh dir is still a command (install -d -m 0700, account-owned).
        assert!(apply.contains("install -d -m 0700 \"$__home/.ssh\""));
        // The key file's 0600 mode and backup-before-overwrite now come from the
        // engine (the old hand-rolled converge is gone).
        assert!(apply.contains("chmod '0600'"));
        assert!(apply.contains(&format!("cp -a \"$__path\" \"$__path{BACKUP_SUFFIX}\"")));
    }

    #[test]
    fn key_material_is_base64_embedded_in_probe_and_apply() {
        // Keys are file *content*: embedded inert (base64), never interpolated
        // into bash — even a key containing a quote cannot inject.
        let decl = module(vec![with_keys(
            "carol",
            &["ssh-ed25519 AAAA", "ssh-rsa B'B"],
        )])
        .declaration();
        let encoded = B64.encode("ssh-ed25519 AAAA\nssh-rsa B'B\n".as_bytes());
        assert!(decl.render_probe().contains(&encoded));
        assert!(decl.render_apply().contains(&encoded));
    }

    #[test]
    fn authorized_keys_is_rollback_restorable() {
        // As a ManagedFile, rollback restores authorized_keys
        // from its .anvil.bak — the hand-rolled command had no rollback path.
        let decl = module(vec![with_keys("carol", &["ssh-ed25519 AAAA"])]).declaration();
        let rb = decl.render_rollback();
        assert!(
            rb.contains("getent passwd 'carol'"),
            "rollback resolves the path too:\n{rb}"
        );
        assert!(rb.contains(&format!("cp -a \"$__path{BACKUP_SUFFIX}\" \"$__path\"")));
    }

    #[test]
    fn probe_checks_same_artifacts() {
        let mut a = account("dave");
        a.sudo = true;
        let probe = module(vec![a]).declaration().render_probe();
        assert!(probe.contains("id -u 'dave'"));
        assert!(probe.contains("/etc/sudoers.d/dave"));
    }
}
