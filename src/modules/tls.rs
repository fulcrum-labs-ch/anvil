//! The `tls` module (R81): issue/renew certificates with `certbot` or `acme.sh`
//! (webroot or standalone) and install a hardened nginx TLS server block,
//! reloading nginx behind an `nginx -t` validation guard with auto-revert (R57).
//!
//! Hosts without nginx are *skipped*, not failed: the server-block step's
//! detect treats "nginx not installed" as aligned, its converge only writes
//! when nginx exists, and the guard's validate/reload short-circuit to success
//! — so certificate issuance still works on a bare box while the nginx
//! hardening waits until nginx is installed.
//!
//! Ordering note: the certificate command runs *before* the server-block
//! command (commands run in declaration order), so `nginx -t` sees real cert
//! files. On a brand-new host, `--webroot` issuance still requires an existing
//! port-80 server to answer the ACME challenge; use `--standalone` (omit
//! `webroot`) for first issuance on a bare box.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::config::schema::TlsSection;
use crate::engine::{Declaration, ManagedCommand, ReloadGuard, BACKUP_SUFFIX, MARK_FAILED};
use crate::escape::shell_escape;

use super::{apt_install, Module};

/// nginx drop-in this module owns (Fixed Contract for drift/rollback, R90).
/// `conf.d/*.conf` is auto-included by the stock nginx config.
pub const NGINX_CONF: &str = "/etc/nginx/conf.d/anvil-tls.conf";

/// Other modules drop server-level snippets (e.g. forgejo's `location /`)
/// here; the 443 block includes `*.conf` from it. An empty glob is fine.
pub const SNIPPET_DIR: &str = "/etc/nginx/anvil-tls.d";

/// Mozilla "intermediate" cipher suite (Fixed Contract, R81).
const SSL_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";

pub struct TlsModule {
    cfg: TlsSection,
}

impl TlsModule {
    pub fn new(cfg: TlsSection) -> Self {
        Self { cfg }
    }

    fn primary(&self) -> Option<&str> {
        self.cfg.domains.first().map(|s| s.as_str())
    }

    /// `(fullchain, privkey)` on-disk paths for the chosen provider + primary
    /// domain. certbot uses its `live/` layout; for acme.sh we install to a
    /// stable path so the nginx block can reference it deterministically.
    fn cert_paths(&self, primary: &str) -> (String, String) {
        if self.cfg.provider == "acme.sh" {
            (
                format!("/etc/nginx/ssl/{primary}/fullchain.pem"),
                format!("/etc/nginx/ssl/{primary}/privkey.pem"),
            )
        } else {
            (
                format!("/etc/letsencrypt/live/{primary}/fullchain.pem"),
                format!("/etc/letsencrypt/live/{primary}/privkey.pem"),
            )
        }
    }

    /// `-d a -d b …` with every domain shell-escaped for the provider CLI.
    fn domain_flags(&self) -> String {
        self.cfg
            .domains
            .iter()
            .map(|d| format!("-d {}", shell_escape(d)))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The hardened nginx server block. Domain values live in *file content*
    /// (base64-embedded into the scripts), so they are not a bash-injection
    /// vector.
    ///
    /// `http2 on;` is deliberately absent: it requires nginx >= 1.25.1, newer
    /// than what Debian 11/12 and Ubuntu 22.04 ship, so on those targets it
    /// makes `nginx -t` fail and the guard revert the whole apply — exactly
    /// where the module is most used. (The deprecated `listen … http2` form is
    /// not a substitute either.)
    pub fn nginx_block(&self, primary: &str) -> String {
        let (fullchain, privkey) = self.cert_paths(primary);
        let server_names = self.cfg.domains.join(" ");

        let mut lines: Vec<String> = vec![
            "# Managed by anvil — do not edit by hand".into(),
            "server {".into(),
            "    listen 80;".into(),
            "    listen [::]:80;".into(),
            format!("    server_name {server_names};"),
        ];
        if let Some(webroot) = self.cfg.webroot.as_deref() {
            lines.push(format!(
                "    location /.well-known/acme-challenge/ {{ root {webroot}; }}"
            ));
        }
        lines.push("    location / { return 301 https://$host$request_uri; }".into());
        lines.push("}".into());
        lines.push(String::new());
        lines.push("server {".into());
        lines.push("    listen 443 ssl;".into());
        lines.push("    listen [::]:443 ssl;".into());
        lines.push(format!("    server_name {server_names};"));
        lines.push(String::new());
        lines.push(format!("    ssl_certificate {fullchain};"));
        lines.push(format!("    ssl_certificate_key {privkey};"));
        lines.push(String::new());
        lines.push("    ssl_protocols TLSv1.2 TLSv1.3;".into());
        lines.push("    ssl_prefer_server_ciphers off;".into());
        lines.push(format!("    ssl_ciphers {SSL_CIPHERS};"));
        lines.push("    ssl_session_timeout 1d;".into());
        lines.push("    ssl_session_cache shared:anvilTLS:10m;".into());
        lines.push("    ssl_session_tickets off;".into());
        lines.push("    add_header Strict-Transport-Security \"max-age=63072000\" always;".into());
        lines.push(String::new());
        lines.push(format!("    include {SNIPPET_DIR}/*.conf;"));
        lines.push("}".into());

        let mut out = lines.join("\n");
        out.push('\n');
        out
    }

    /// Idempotent issue+renew: converged when a cert already exists and is valid
    /// for at least 30 more days; otherwise (re)issue via the provider.
    fn issue_command(&self, primary: &str) -> ManagedCommand {
        let (fullchain, privkey) = self.cert_paths(primary);
        let fc = shell_escape(&fullchain);
        let domains = self.domain_flags();

        let detect = format!(
            "[ -f {fc} ] && openssl x509 -checkend 2592000 -noout -in {fc} >/dev/null 2>&1"
        );

        let converge = if self.cfg.provider == "acme.sh" {
            let pk = shell_escape(&privkey);
            let dir = shell_escape(&format!("/etc/nginx/ssl/{primary}"));
            let issue_mode = match self.cfg.webroot.as_deref() {
                Some(w) => format!("-w {}", shell_escape(w)),
                None => "--standalone".to_string(),
            };
            let register = match self.cfg.email.as_deref() {
                Some(e) => format!(
                    "acme.sh --register-account --server letsencrypt -m {}\n",
                    shell_escape(e)
                ),
                None => String::new(),
            };
            // acme.sh has no Debian package and its installer is a pipe-to-shell
            // so require it and say how to fix it.
            format!(
                "command -v acme.sh >/dev/null 2>&1 || {{ printf '{MARK_FAILED} acme.sh not found; install it or set provider = \"certbot\"\\n'; exit 1; }}\n\
                 {register}acme.sh --issue --server letsencrypt {issue_mode} {domains}\n\
                 mkdir -p {dir}\n\
                 acme.sh --install-cert {domains} --key-file {pk} --fullchain-file {fc} \
                 --reloadcmd 'systemctl reload nginx'"
            )
        } else {
            let auth = match self.cfg.webroot.as_deref() {
                Some(w) => format!("--webroot -w {}", shell_escape(w)),
                None => "--standalone".to_string(),
            };
            let email = match self.cfg.email.as_deref() {
                Some(e) => format!("-m {}", shell_escape(e)),
                None => "--register-unsafely-without-email".to_string(),
            };
            format!(
                "command -v certbot >/dev/null 2>&1 || {{ {install}; }}\n\
                 certbot certonly --non-interactive --agree-tos --keep-until-expiring \
                 {auth} {email} {domains}",
                install = apt_install(&["certbot"]),
            )
        };

        ManagedCommand::new(
            format!("issue/renew TLS certificate for {primary}"),
            detect,
            converge,
        )
    }

    /// Command-driven install of the hardened server block. A host without
    /// nginx has nothing to harden: detect short-circuits to "aligned", so
    /// probe and apply both *skip* instead of failing `nginx -t` on a box that
    /// never had nginx. When nginx is present, converge performs the same
    /// backed-up write the engine would do for a [`crate::engine::ManagedFile`]
    /// — backup to `.anvil.bak` plus `__reverts` registration, so the guard's
    /// auto-revert covers it. Content is base64-embedded (injection-inert).
    fn server_block_command(&self, primary: &str) -> ManagedCommand {
        let path = shell_escape(NGINX_CONF);
        let bak = shell_escape(&format!("{NGINX_CONF}{BACKUP_SUFFIX}"));
        let content_b64 = shell_escape(&B64.encode(self.nginx_block(primary).as_bytes()));
        let snippets = shell_escape(SNIPPET_DIR);

        let detect = format!(
            "! command -v nginx >/dev/null 2>&1 || {{ [ -f {path} ] && \
             [ \"$(cat {path})\" = \"$(printf '%s' {content_b64} | base64 -d)\" ]; }}"
        );
        let converge = format!(
            "if command -v nginx >/dev/null 2>&1; then\n\
             \x20 mkdir -p \"$(dirname {path})\" {snippets}\n\
             \x20 if [ -f {path} ]; then cp -a {path} {bak}; fi\n\
             \x20 __reverts+=({path})\n\
             \x20 printf '%s' {content_b64} | base64 -d > {path}\n\
             \x20 chown root:root {path}\n\
             \x20 chmod 0644 {path}\n\
             fi"
        );

        ManagedCommand::new(
            format!("nginx TLS server block for {primary} (skipped when nginx is absent)"),
            detect,
            converge,
        )
    }
}

impl Module for TlsModule {
    fn id(&self) -> &'static str {
        "tls"
    }

    fn declaration(&self) -> Declaration {
        let decl = Declaration::new("tls");
        let primary = match self.primary() {
            Some(p) => p.to_string(),
            None => return decl, // no domains → nothing to do
        };

        decl.command(self.issue_command(&primary))
            .command(self.server_block_command(&primary))
            .command_file(NGINX_CONF)
            .guarded_reload(ReloadGuard {
                describe: "nginx TLS configuration".into(),
                // A host without nginx validates trivially (nothing was
                // written there) and is never reloaded.
                validate: "! command -v nginx >/dev/null || nginx -t".into(),
                reload: "! command -v nginx >/dev/null || \
                         systemctl reload nginx 2>/dev/null || service nginx reload"
                    .into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::OrderOverride;

    fn section() -> TlsSection {
        TlsSection {
            provider: "certbot".into(),
            domains: vec!["example.com".into()],
            email: None,
            webroot: None,
            order_override: OrderOverride::default(),
        }
    }

    fn module(mutate: impl FnOnce(&mut TlsSection)) -> TlsModule {
        let mut cfg = section();
        mutate(&mut cfg);
        TlsModule::new(cfg)
    }

    #[test]
    fn provider_is_ensured_before_issuance() {
        // certbot is installed (refresh first) before `certbot certonly`;
        // acme.sh, which has no apt package, fails with a clear error.
        let c = module(|_| {}).issue_command("example.com").converge;
        let guard = c
            .find("command -v certbot >/dev/null 2>&1 ||")
            .expect("guard");
        let install = c.find("install -y -- 'certbot'").expect("install");
        let issue = c.find("certbot certonly").expect("issue");
        assert!(guard < install && install < issue);

        let c = module(|t| t.provider = "acme.sh".into())
            .issue_command("example.com")
            .converge;
        let guard = c
            .find("command -v acme.sh >/dev/null 2>&1 || { printf 'FAILED: acme.sh not found")
            .expect("acme.sh guard");
        assert!(guard < c.find("acme.sh --issue").expect("issue"));
        assert!(!c.contains("get.acme.sh"));
    }

    /// `bash -n` gate for a rendered script; skips (returns true) when bash is
    /// not available on the test machine.
    fn bash_n_ok(script: &str) -> bool {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let Ok(mut child) = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return true;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(script.as_bytes());
        }
        child.wait().map(|s| s.success()).unwrap_or(true)
    }

    #[test]
    fn nginx_block_has_strong_directives_and_certbot_paths() {
        let block = module(|c| c.domains = vec!["example.com".into(), "www.example.com".into()])
            .nginx_block("example.com");
        for needle in [
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_prefer_server_ciphers off;",
            "ssl_session_tickets off;",
            "Strict-Transport-Security",
            "server_name example.com www.example.com;",
            "ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
            "ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;",
            "return 301 https://$host$request_uri;",
            "    include /etc/nginx/anvil-tls.d/*.conf;\n}\n",
        ] {
            assert!(block.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn no_http2_directive_in_block_or_scripts() {
        // `http2 on;` needs nginx >= 1.25.1 — newer than Debian 11/12 and
        // Ubuntu 22.04 — so it must not appear in any form, including the
        // deprecated `listen … http2` variant.
        let m = module(|_| {});
        let block = m.nginx_block("example.com");
        assert!(!block.contains("http2"), "no http2 directive:\n{block}");
        assert!(block.contains("listen 443 ssl;"), "plain ssl listen kept");
        let decl = m.declaration();
        for s in [decl.render_probe(), decl.render_apply()] {
            assert!(!s.contains("http2"), "no http2 in rendered script:\n{s}");
        }
    }

    #[test]
    fn acme_sh_uses_stable_install_paths() {
        let block = module(|c| c.provider = "acme.sh".into()).nginx_block("example.com");
        assert!(block.contains("ssl_certificate /etc/nginx/ssl/example.com/fullchain.pem;"));
    }

    #[test]
    fn webroot_adds_challenge_location() {
        let with = module(|c| c.webroot = Some("/var/www/html".into())).nginx_block("example.com");
        assert!(with.contains("location /.well-known/acme-challenge/ { root /var/www/html; }"));
        let without = module(|_| {}).nginx_block("example.com");
        assert!(!without.contains(".well-known/acme-challenge"));
    }

    #[test]
    fn certbot_webroot_and_escaped_domains() {
        let apply = module(|c| {
            c.webroot = Some("/var/www/html".into());
            c.email = Some("ops@example.com".into());
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("certbot certonly --non-interactive --agree-tos"));
        assert!(apply.contains("--webroot -w '/var/www/html'"));
        assert!(apply.contains("-m 'ops@example.com'"));
        assert!(apply.contains("-d 'example.com'"));
    }

    #[test]
    fn certbot_standalone_without_email() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("--standalone"));
        assert!(apply.contains("--register-unsafely-without-email"));
    }

    #[test]
    fn acme_sh_issue_and_install() {
        let apply = module(|c| {
            c.provider = "acme.sh".into();
            c.webroot = Some("/srv/web".into());
        })
        .declaration()
        .render_apply();
        assert!(apply.contains("acme.sh --issue --server letsencrypt -w '/srv/web'"));
        assert!(apply.contains("acme.sh --install-cert"));
        assert!(apply.contains("--fullchain-file '/etc/nginx/ssl/example.com/fullchain.pem'"));
    }

    #[test]
    fn reload_is_guarded_by_nginx_t() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("nginx -t"));
        assert!(apply.contains(NGINX_CONF));
        assert!(apply.contains("exit 1")); // auto-revert path
    }

    #[test]
    fn absent_nginx_short_circuits_detect_and_validate() {
        let decl = module(|_| {}).declaration();
        let probe = decl.render_probe();
        let apply = decl.render_apply();
        // detect: "nginx not installed" reads as aligned — in the probe and,
        // identically, in the apply (probe/apply agreement).
        let short_circuit = "! command -v nginx >/dev/null 2>&1 ||";
        assert!(
            probe.contains(short_circuit),
            "probe detect skips:\n{probe}"
        );
        assert!(
            apply.contains(short_circuit),
            "apply detect skips:\n{apply}"
        );
        // guard: validate passes trivially without nginx, reload is gated too.
        assert!(apply.contains("! command -v nginx >/dev/null || nginx -t"));
        assert!(apply.contains("! command -v nginx >/dev/null || systemctl reload nginx"));
        // The probe never validates or reloads.
        assert!(!probe.contains("nginx -t"));
        assert!(!probe.contains("systemctl reload nginx"));
    }

    #[test]
    fn server_block_written_only_when_nginx_present_with_backup() {
        let apply = module(|_| {}).declaration().render_apply();
        let gate = apply
            .find("if command -v nginx >/dev/null 2>&1; then")
            .expect("converge gated on nginx presence");
        let write = apply
            .find(&format!("base64 -d > '{NGINX_CONF}'"))
            .expect("gated write present");
        assert!(gate < write, "write only inside the nginx-present branch");
        // Backed-up write, registered for the guard's auto-revert.
        assert!(apply.contains(&format!(
            "cp -a '{NGINX_CONF}' '{NGINX_CONF}{BACKUP_SUFFIX}'"
        )));
        assert!(apply.contains(&format!("__reverts+=('{NGINX_CONF}')")));
        assert!(apply.contains("chmod 0644"));
    }

    #[test]
    fn server_block_content_is_embedded_identically_in_probe_and_apply() {
        let m = module(|_| {});
        let encoded = B64.encode(m.nginx_block("example.com").as_bytes());
        let decl = m.declaration();
        assert!(decl.render_probe().contains(&encoded));
        assert!(decl.render_apply().contains(&encoded));
    }

    #[test]
    fn no_domains_is_a_noop() {
        let decl = module(|c| c.domains.clear()).declaration();
        assert!(decl.commands.is_empty());
        assert!(decl.files.is_empty());
        assert!(decl.reload.is_none());
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        for m in [
            module(|c| {
                c.webroot = Some("/var/www/html".into());
                c.email = Some("ops@example.com".into());
            }),
            module(|c| c.provider = "acme.sh".into()),
        ] {
            let decl = m.declaration();
            for (kind, s) in [
                ("probe", decl.render_probe()),
                ("apply", decl.render_apply()),
                ("rollback", decl.render_rollback()),
            ] {
                assert!(bash_n_ok(&s), "tls {kind} script failed bash -n:\n{s}");
            }
        }
    }
}
