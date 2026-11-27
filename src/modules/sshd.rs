//! The `sshd` module (R63, R57): writes a hardened sshd drop-in and reloads it
//! behind an `sshd -t` validation guard with auto-revert.

use crate::config::schema::SshdSection;
use crate::engine::{Declaration, ManagedFile, ReloadGuard};

use super::Module;

/// Drop-in this module owns (Fixed Contract for drift/rollback consistency).
///
/// sshd_config is FIRST-match-wins per directive, and stock Debian/Ubuntu
/// includes `/etc/ssh/sshd_config.d/*.conf` in lexical order at the *top* of
/// the main file. The `05-` prefix makes this file sort before distro and
/// cloud-init drop-ins (notably Ubuntu's `50-cloud-init.conf`, which often
/// sets `PasswordAuthentication yes`), so our directives win instead of being
/// silently overridden by an earlier match.
pub const DROP_IN: &str = "/etc/ssh/sshd_config.d/05-anvil.conf";

/// Reload sshd, shared with `ssh_crypto`. Under socket activation
/// (Ubuntu 22.10+) `ssh.socket` owns the listening port and only picks up a
/// `Port` change on `daemon-reload` + socket restart; a running
/// `ssh.service` is then reloaded for every other directive. Otherwise reload
/// across the service names Debian/Ubuntu have used.
pub const RELOAD: &str = "if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then \
systemctl daemon-reload && systemctl restart ssh.socket \
&& { ! systemctl is-active --quiet ssh || systemctl reload ssh; }; \
else systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
|| service ssh reload; fi";

/// Strong cipher/MAC policy applied when `strong_ciphers = true`.
const STRONG_CIPHERS: &str =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr";
const STRONG_MACS: &str =
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com";

pub struct SshdModule {
    cfg: SshdSection,
}

impl SshdModule {
    pub fn new(cfg: SshdSection) -> Self {
        Self { cfg }
    }

    /// Render the desired drop-in content. Directive *values* are the hardening
    /// contract (R63); only the surrounding formatting is ours.
    pub fn desired_content(&self) -> String {
        let c = &self.cfg;
        let mut lines = vec!["# Managed by anvil — do not edit by hand".to_string()];
        if c.disable_root_login {
            lines.push("PermitRootLogin no".into());
        }
        if c.disable_password_auth {
            lines.push("PasswordAuthentication no".into());
        }
        if c.disable_empty_passwords {
            lines.push("PermitEmptyPasswords no".into());
        }
        if c.disable_x11_forwarding {
            lines.push("X11Forwarding no".into());
        }
        lines.push(format!("Port {}", c.port));
        lines.push(format!("MaxAuthTries {}", c.max_auth_tries));
        lines.push(format!("LoginGraceTime {}", c.login_grace_time));
        lines.push(format!("ClientAliveInterval {}", c.client_alive_interval));
        lines.push(format!("ClientAliveCountMax {}", c.client_alive_count_max));
        if !c.allow_users.is_empty() {
            // Usernames are data in file content, but join with spaces per the
            // AllowUsers grammar.
            lines.push(format!("AllowUsers {}", c.allow_users.join(" ")));
        }
        if c.strong_ciphers {
            lines.push(format!("Ciphers {STRONG_CIPHERS}"));
            lines.push(format!("MACs {STRONG_MACS}"));
        }
        let mut out = lines.join("\n");
        out.push('\n');
        out
    }
}

impl Module for SshdModule {
    fn id(&self) -> &'static str {
        "sshd"
    }

    fn declaration(&self) -> Declaration {
        // Validate the *whole* effective config, then reload; revert on failure.
        let guard = ReloadGuard {
            describe: "sshd configuration".into(),
            validate: "sshd -t".into(),
            reload: RELOAD.into(),
        };
        Declaration::new("sshd")
            .file(ManagedFile::new(
                DROP_IN,
                self.desired_content(),
                "0644",
                "root:root",
            ))
            .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut SshdSection)) -> SshdModule {
        let mut cfg = SshdSection::default();
        mutate(&mut cfg);
        SshdModule::new(cfg)
    }

    #[test]
    fn reload_restarts_ssh_socket_when_socket_activated() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains(
            "if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then \
             systemctl daemon-reload && systemctl restart ssh.socket"
        ));
        assert!(
            apply.contains("service ssh reload"),
            "non-socket fallback kept"
        );
    }

    #[test]
    fn default_directives_present() {
        let content = module(|_| {}).desired_content();
        for needle in [
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "PermitEmptyPasswords no",
            "X11Forwarding no",
            "Port 22",
            "MaxAuthTries 3",
            "LoginGraceTime 30",
            "ClientAliveInterval 300",
            "ClientAliveCountMax 2",
        ] {
            assert!(content.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn allow_users_and_ciphers_are_conditional() {
        // strong_ciphers now defaults on; opting out removes the directives.
        let plain = module(|c| c.strong_ciphers = false).desired_content();
        assert!(!plain.contains("AllowUsers"));
        assert!(!plain.contains("Ciphers"));

        let default = module(|_| {}).desired_content();
        assert!(default.contains("Ciphers "), "hardened by default");

        let hardened = module(|c| {
            c.allow_users = vec!["alice".into(), "bob".into()];
        })
        .desired_content();
        assert!(hardened.contains("AllowUsers alice bob"));
        assert!(hardened.contains("Ciphers "));
        assert!(hardened.contains("MACs "));
    }

    #[test]
    fn apply_guards_reload_and_reverts() {
        let s = module(|_| {}).declaration().render_apply();
        assert!(s.contains("sshd -t"));
        assert!(s.contains(DROP_IN));
        assert!(s.contains("exit 1")); // auto-revert path
    }

    #[test]
    fn probe_and_apply_reference_same_file() {
        let decl = module(|_| {}).declaration();
        assert!(decl.render_probe().contains(DROP_IN));
        assert!(decl.render_apply().contains(DROP_IN));
    }

    #[test]
    fn custom_port_is_reflected() {
        let content = module(|c| c.port = 2222).desired_content();
        assert!(content.contains("Port 2222"));
    }

    #[test]
    fn x11_forwarding_is_wired_and_conditional() {
        // Default (true): the directive is emitted.
        let default = module(|_| {}).desired_content();
        assert!(default.contains("X11Forwarding no"));
        // Opted out (false): the directive is omitted entirely.
        let permissive = module(|c| c.disable_x11_forwarding = false).desired_content();
        assert!(!permissive.contains("X11Forwarding"));
    }

    #[test]
    fn dropin_sorts_before_cloud_init() {
        // sshd_config.d is included first-match-wins in lexical order; our
        // drop-in must sort before Ubuntu's 50-cloud-init.conf or directives
        // like `PasswordAuthentication yes` there would win over ours.
        let name = DROP_IN.rsplit('/').next().expect("basename");
        assert!(
            name < "50-cloud-init.conf",
            "{name:?} must sort lexically before 50-cloud-init.conf"
        );
        assert!(DROP_IN.starts_with("/etc/ssh/sshd_config.d/"));
    }
}
