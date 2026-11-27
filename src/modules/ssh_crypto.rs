//! The `ssh_crypto` module (R70, R57): a *separate* sshd drop-in that pins a
//! strong, post-quantum-aware crypto policy (`KexAlgorithms` / `Ciphers` /
//! `MACs` / `HostKeyAlgorithms`).
//!
//! The drop-in content is *computed on the target*
//! ([`crate::engine::FileContent::Computed`] via [`ManagedFile::computed`]): a
//! generator snippet asks the host's ssh which KEX algorithms it supports
//! (`ssh -Q kex`) and intersects that with our preference order, so the
//! `KexAlgorithms` line only ever names algorithms the host understands.
//! Hosts on OpenSSH older than 8.5 (Debian 11, Ubuntu 20.04) get a
//! classical-only line that `sshd -t` accepts — instead of a guard revert that
//! would leave them with zero crypto hardening — while OpenSSH 9.9+ hosts pick
//! up `mlkem768x25519-sha256`, the NIST-standardized hybrid. Probe and apply
//! run the *same* generator, so they can never disagree about desired content.
//!
//! Safety (R57): after the drop-in is written a [`ReloadGuard`] runs `sshd -t`;
//! only if validation passes is sshd reloaded. On failure the engine restores
//! the prior state **without** reloading, so the host is never locked out.
//! This runs in its own ordering wave *after* `sshd` so a crypto change can
//! never mask a plain config change (the resolver enforces this edge).

use crate::config::schema::SshCryptoSection;
use crate::engine::{Declaration, ManagedFile, ReloadGuard};

use super::Module;

/// Drop-in this module owns. Distinct from the `sshd` module's drop-in so the
/// two waves are independent for drift/rollback. sshd_config is
/// first-match-wins and `sshd_config.d/*.conf` is included in lexical order,
/// so the name is chosen to sort *before* both:
/// - the `sshd` module's `05-anvil.conf` (`-` 0x2D < `.` 0x2E), so this
///   module's `Ciphers`/`MACs` win when both modules are enabled, and
/// - distro/cloud-init drop-ins such as Ubuntu's `50-cloud-init.conf`.
pub const DROP_IN: &str = "/etc/ssh/sshd_config.d/05-anvil-crypto.conf";

// --- Fixed Contract (R70): the crypto directive *values* ------------------

/// KEX preference order, best first: the NIST-standardized ML-KEM hybrid
/// (OpenSSH ≥ 9.9), the sntrup761 hybrid (OpenSSH ≥ 8.5), then strong
/// classical curves and large finite-field groups. The generator intersects
/// this with what the host's ssh actually supports, preserving this order.
const KEX_PREFERENCE: [&str; 7] = [
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
];

/// Classical-only safe list used when `ssh` is absent, `-Q` is unsupported, or
/// the intersection with [`KEX_PREFERENCE`] comes up empty. Every OpenSSH a
/// Debian/Ubuntu host could plausibly run understands all of these.
const KEX_FALLBACK: [&str; 5] = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha256",
];

/// AEAD-first cipher suite.
const CIPHERS: &str = "chacha20-poly1305@openssh.com,\
aes256-gcm@openssh.com,aes128-gcm@openssh.com,\
aes256-ctr,aes192-ctr,aes128-ctr";

/// Encrypt-then-MAC only, SHA-2 family.
const MACS: &str = "hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,\
umac-128-etm@openssh.com";

/// Ed25519 first, then RSA with SHA-2 signatures (never SHA-1 `ssh-rsa`).
const HOST_KEY_ALGORITHMS: &str = "ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,\
rsa-sha2-512,rsa-sha2-256,\
rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com";

/// The bash generator that prints the desired drop-in content to stdout. It is
/// evaluated on the target by the engine (in both probe and apply, so they
/// always agree): query the host's supported KEX set with `ssh -Q kex`
/// (falling back to [`KEX_FALLBACK`] when `ssh` is missing or predates `-Q`),
/// intersect with [`KEX_PREFERENCE`] preserving preference order, and emit the
/// four directive lines. Contains no config-derived values, so nothing here
/// needs shell escaping.
pub fn content_generator() -> String {
    let pref = KEX_PREFERENCE.join(" ");
    let fallback = KEX_FALLBACK.join(" ");
    let fallback_csv = KEX_FALLBACK.join(",");
    format!(
        "__kex_pref='{pref}'\n\
         __kex_fb='{fallback}'\n\
         __kex_sup=''\n\
         if command -v ssh >/dev/null 2>&1; then __kex_sup=$(ssh -Q kex 2>/dev/null || true); fi\n\
         if [ -z \"$__kex_sup\" ]; then __kex_sup=$(printf '%s\\n' $__kex_fb); fi\n\
         __kex=''\n\
         for __kex_a in $__kex_pref; do\n\
         \x20 if printf '%s\\n' \"$__kex_sup\" | grep -Fx -- \"$__kex_a\" >/dev/null; then __kex=\"${{__kex:+$__kex,}}$__kex_a\"; fi\n\
         done\n\
         if [ -z \"$__kex\" ]; then __kex='{fallback_csv}'; fi\n\
         printf '%s\\n' \\\n\
         \x20 '# Managed by anvil — strong, PQ-aware SSH crypto. do not edit by hand' \\\n\
         \x20 \"KexAlgorithms $__kex\" \\\n\
         \x20 'Ciphers {CIPHERS}' \\\n\
         \x20 'MACs {MACS}' \\\n\
         \x20 'HostKeyAlgorithms {HOST_KEY_ALGORITHMS}'"
    )
}

pub struct SshCryptoModule;

impl SshCryptoModule {
    /// The section carries no user-tunable fields (R30); the policy is fixed.
    pub fn new(_cfg: SshCryptoSection) -> Self {
        SshCryptoModule
    }
}

impl Module for SshCryptoModule {
    fn id(&self) -> &'static str {
        "ssh_crypto"
    }

    fn declaration(&self) -> Declaration {
        // R57: validate the *whole* effective sshd config (including this
        // drop-in) before reloading; auto-revert on failure.
        let guard = ReloadGuard {
            describe: "ssh crypto policy".into(),
            validate: "sshd -t".into(),
            reload: super::sshd::RELOAD.into(),
        };
        Declaration::new("ssh_crypto")
            .file(ManagedFile::computed(
                DROP_IN,
                content_generator(),
                "0644",
                "root:root",
            ))
            .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::sshd;

    fn module() -> SshCryptoModule {
        SshCryptoModule::new(SshCryptoSection::default())
    }

    fn basename(path: &str) -> &str {
        path.rsplit('/').next().expect("basename")
    }

    #[test]
    fn all_four_crypto_directives_present() {
        let g = content_generator();
        for needle in ["KexAlgorithms ", "Ciphers ", "MACs ", "HostKeyAlgorithms "] {
            assert!(g.contains(needle), "missing {needle:?}");
        }
    }

    #[test]
    fn kex_preference_is_pq_first_and_excludes_weak_groups() {
        // Both hybrids, best (ML-KEM) first, then sntrup.
        assert_eq!(KEX_PREFERENCE[0], "mlkem768x25519-sha256");
        assert_eq!(KEX_PREFERENCE[1], "sntrup761x25519-sha512@openssh.com");
        let g = content_generator();
        let mlkem = g.find("mlkem768x25519-sha256").expect("mlkem in generator");
        let sntrup = g
            .find("sntrup761x25519-sha512@openssh.com")
            .expect("sntrup in generator");
        assert!(mlkem < sntrup, "mlkem must precede sntrup in preference");
        // No SHA-1 group1 / weak KEX anywhere.
        assert!(!g.contains("diffie-hellman-group1-sha1"));
        assert!(!g.contains("diffie-hellman-group14-sha1"));
    }

    #[test]
    fn generator_queries_host_kex_and_has_classical_fallback() {
        let g = content_generator();
        assert!(g.contains("ssh -Q kex"), "must query host support");
        assert!(!KEX_FALLBACK.is_empty(), "fallback must be non-empty");
        for algo in KEX_FALLBACK {
            assert!(g.contains(algo), "fallback algo {algo} missing");
            assert!(
                !algo.contains("mlkem") && !algo.contains("sntrup"),
                "fallback must be classical-only, got {algo}"
            );
            assert!(
                KEX_PREFERENCE.contains(&algo),
                "fallback {algo} must be a subset of the preference list"
            );
        }
        // The empty-intersection guard falls back to a comma-joined list too.
        assert!(g.contains(&KEX_FALLBACK.join(",")));
    }

    #[test]
    fn ciphers_and_macs_are_strong_only() {
        let g = content_generator();
        // AEAD ciphers, ETM MACs; no CBC, no MD5, no plain (non-ETM) SHA1 MAC.
        assert!(g.contains("chacha20-poly1305@openssh.com"));
        assert!(!g.contains("-cbc"));
        assert!(!g.contains("hmac-md5"));
        assert!(!g.contains("hmac-sha1"));
    }

    #[test]
    fn host_key_algorithms_exclude_sha1_rsa() {
        let g = content_generator();
        assert!(g.contains("ssh-ed25519"));
        assert!(g.contains("rsa-sha2-512"));
        // The legacy SHA-1 "ssh-rsa" signature algorithm must not appear.
        assert!(!g.contains("ssh-rsa,"));
        assert!(!g.contains("ssh-rsa\n"));
        assert!(!g.contains("ssh-rsa'"));
    }

    #[test]
    fn dropin_sorts_before_sshd_dropin_and_cloud_init() {
        // sshd_config.d inclusion is lexical + first-match-wins, so ordering
        // *is* precedence. The crypto file must beat the sshd module's file
        // (its Ciphers/MACs win when both are enabled) and both must beat
        // Ubuntu's 50-cloud-init.conf.
        let crypto = basename(DROP_IN);
        let sshd_name = basename(sshd::DROP_IN);
        assert_ne!(DROP_IN, sshd::DROP_IN);
        assert!(
            crypto < sshd_name,
            "{crypto:?} must sort lexically before {sshd_name:?}"
        );
        assert!(crypto < "50-cloud-init.conf");
        assert!(sshd_name < "50-cloud-init.conf");
    }

    #[test]
    fn probe_and_apply_share_the_generator() {
        let decl = module().declaration();
        let expected = format!("__desired=$({})", content_generator());
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
        ] {
            assert!(
                script.contains(&expected),
                "{kind} must materialize desired content via the generator:\n{script}"
            );
            assert!(script.contains(DROP_IN));
        }
    }

    #[test]
    fn rendered_scripts_parse_under_bash_n() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let bash_available = Command::new("bash")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !bash_available {
            eprintln!("skipping: bash not available");
            return;
        }
        let decl = module().declaration();
        for (kind, script) in [
            ("probe", decl.render_probe()),
            ("apply", decl.render_apply()),
            ("rollback", decl.render_rollback()),
        ] {
            let mut child = Command::new("bash")
                .arg("-n")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn bash -n");
            child
                .stdin
                .take()
                .expect("stdin")
                .write_all(script.as_bytes())
                .expect("write script");
            let out = child.wait_with_output().expect("wait for bash");
            assert!(
                out.status.success(),
                "{kind} script failed bash -n:\n{}\n---\n{script}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn apply_validates_with_sshd_t_and_reverts() {
        let decl = module().declaration();
        let apply = decl.render_apply();
        assert!(apply.contains("sshd -t"));
        assert!(apply.contains(DROP_IN));
        // The guarded-reload revert path exists (R57).
        assert!(apply.contains("exit 1"));
    }

    #[test]
    fn probe_never_reloads_or_validates() {
        let probe = module().declaration().render_probe();
        assert!(probe.contains(DROP_IN));
        // A probe is read-only: no sshd -t, no reload. (It *does* run the
        // generator's `ssh -Q kex`, which is a pure query.)
        assert!(!probe.contains("sshd -t"));
        assert!(!probe.contains("systemctl reload"));
    }
}
