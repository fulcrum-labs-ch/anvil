//! The `podman` module: the counterpart of `[docker]` on a Podman host. Owns
//! the containers.conf drop-in (backup, diff, rollback), rendered by
//! [`containers_conf`] from every source: netavark's iptables driver and
//! capped container logs always, the log driver with `[podman]`. Without `[podman]`,
//! `[containers]` (on every Podman host) declares the same file. Installs nothing itself:
//! the first module that runs containers does (`ensure_engine`).

use crate::config::schema::PodmanSection;
use crate::engine::{Declaration, ManagedFile};

use super::Module;

/// containers.conf.d is last-match-wins: HIGH prefix.
pub const PODMAN_CONF: &str = "/etc/containers/containers.conf.d/99-anvil.conf";

/// Docker's daemon.json cap (`max-size` 10m), in bytes as containers.conf wants.
const LOG_SIZE_MAX: u64 = 10 * 1024 * 1024;

/// ufw's FORWARD policy is DROP and netavark's nftables driver adds no
/// accept there, so containers had no outbound network. The iptables driver
/// hooks FORWARD the way Docker does (publishes stay loopback-only, validated).
/// Logs are always size-capped (k8s-file only; journald has its own limits);
/// `[podman]` also picks the log driver. Settings reach containers
/// started after the change.
pub fn containers_conf(podman: Option<&PodmanSection>) -> String {
    let network = "[network]\nfirewall_driver = \"iptables\"\n";
    match podman {
        None => format!(
            "# Managed by anvil — Podman log cap, networking next to ufw\n\
             [containers]\n\
             log_size_max = {LOG_SIZE_MAX}\n\n\
             {network}"
        ),
        Some(p) => format!(
            "# Managed by anvil — [podman] logs, networking next to ufw\n\
             [containers]\n\
             log_driver = \"{}\"\n\
             log_size_max = {LOG_SIZE_MAX}\n\n\
             {network}",
            p.log_driver
        ),
    }
}

pub struct PodmanModule {
    cfg: PodmanSection,
}

impl PodmanModule {
    pub fn new(cfg: PodmanSection) -> Self {
        Self { cfg }
    }
}

impl Module for PodmanModule {
    fn id(&self) -> &'static str {
        "podman"
    }

    fn declaration(&self) -> Declaration {
        Declaration::new("podman").file(ManagedFile::new(
            PODMAN_CONF,
            containers_conf(Some(&self.cfg)),
            "0644",
            "root:root",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conf_always_carries_the_iptables_driver() {
        let net = "[network]\nfirewall_driver = \"iptables\"\n";
        assert_eq!(
            containers_conf(None),
            format!(
                "# Managed by anvil — Podman log cap, networking next to ufw\n[containers]\n\
                 log_size_max = 10485760\n\n{net}"
            )
        );
        let k8s = containers_conf(Some(&PodmanSection::default()));
        assert_eq!(
            k8s,
            format!(
                "# Managed by anvil — [podman] logs, networking next to ufw\n[containers]\n\
                 log_driver = \"k8s-file\"\nlog_size_max = 10485760\n\n{net}"
            )
        );
        let j = containers_conf(Some(&PodmanSection {
            log_driver: "journald".into(),
            ..Default::default()
        }));
        assert!(
            j.contains("log_driver = \"journald\"\n") && j.ends_with(net),
            "{j}"
        );
    }

    #[test]
    fn owns_the_drop_in_and_installs_nothing() {
        let d = PodmanModule::new(PodmanSection::default()).declaration();
        assert_eq!(d.files.len(), 1);
        let f = &d.files[0];
        assert_eq!(f.path, PODMAN_CONF);
        assert!(PODMAN_CONF.ends_with("/99-anvil.conf"));
        assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0644", "root:root"));
        assert_eq!(
            f.static_content(),
            Some(containers_conf(Some(&PodmanSection::default())).as_str())
        );
        assert!(d.commands.is_empty() && d.reload.is_none());
        assert!(!d.render_apply().contains("apt-get"));
    }
}
