//! The `vector` module (R86): install Vector from its keyring-pinned apt
//! repository (no pipe-to-shell) and configure it to scrape journald +
//! `extra_log_files` (and host metrics) and ship them to GreptimeDB, managed
//! by a systemd unit. The `vector` service user is added to the
//! `systemd-journal` and `adm` groups so the journald source can actually
//! read the logs it declares.
//!
//! All config-derived values (`greptimedb_host`, ports, `db_name`, log paths)
//! land in the Vector *config file content*, which the engine delivers
//! base64-encoded (never interpolated into bash). They are TOML-escaped so a
//! stray quote cannot corrupt the config or break `vector validate`.
//!
//! Restart discipline: the guarded reload restarts the service only when this
//! run changed a file or the service was down (`systemctl is-active` is part of
//! the probe, so a crashed shipper reads as drift, not `aligned`). A converged,
//! healthy host is left running.

use crate::config::schema::VectorSection;
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};

use super::{apt_install, Module};
use base64::Engine as _;

/// Vector config this module owns (Fixed Contract for drift/rollback).
pub const CONFIG_PATH: &str = "/etc/vector/vector.toml";
/// systemd unit; overrides the packaged one so only our config is loaded.
pub const UNIT_PATH: &str = "/etc/systemd/system/vector.service";

/// Vendor signing key (dearmored) pinning the apt repository below.
const KEYRING_PATH: &str = "/usr/share/keyrings/vector-archive-keyring.gpg";
/// The pinned apt source referencing [`KEYRING_PATH`] via `signed-by=`.
const APT_LIST_PATH: &str = "/etc/apt/sources.list.d/vector.list";
/// Official Vector (Datadog) apt signing key.
const SIGNING_KEY_URL: &str = "https://keys.datadoghq.com/DATADOG_APT_KEY_CURRENT.public";
/// Official Vector apt repository layout: `<url> <suite> <component>`.
const APT_REPO: &str = "https://apt.vector.dev/ stable vector-0";

pub struct VectorModule {
    cfg: VectorSection,
    /// `[apps_resources]`: the unit's `[Service]` gets `Slice=apps.slice`.
    in_apps_slice: bool,
}

/// Escape a string as a TOML basic (double-quoted) string.
fn toml_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML inline array of basic strings, e.g. `["a", "b"]`.
fn toml_str_array<I: IntoIterator<Item = S>, S: AsRef<str>>(items: I) -> String {
    let inner = items
        .into_iter()
        .map(|s| toml_str(s.as_ref()))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// Vector's cgroups collector only descends into groups that pass the
/// filter, so each pattern's ancestors (`a`, `a/b` for `a/b/c*`) are added.
fn cgroup_includes(patterns: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in patterns {
        let parts: Vec<&str> = p.split('/').collect();
        for i in 1..=parts.len() {
            let prefix = parts[..i].join("/");
            if !out.contains(&prefix) {
                out.push(prefix);
            }
        }
    }
    out
}

/// Replaced on the host by [`slot_cgroups_generator`]'s list (or nothing).
const SLOT_CGROUPS: &str = "@SLOT_CGROUPS@";

/// Docker-rootless CI sandboxes live under their slot user's manager
/// (`anvil-fjr-*`, `anvil-ghr-*`, whose cgroups are 0755). Their uids exist
/// only on the host, and a `user@*` glob would walk the agent's 0750 tree
/// and log an ERROR every scrape: so one exact path per slot user.
fn slot_cgroups_generator(template: &str) -> String {
    format!(
        "__x=\n\
         for __u in $(getent passwd | awk -F: '$1 ~ /^anvil-(fjr|ghr)-[a-z0-9-]+$/ {{print $3}}' | sort -n); do\n\
         \x20 __b=\"user.slice/user-$__u.slice/user@$__u.service\"\n\
         \x20 __x=\"$__x, \\\"user.slice\\\", \\\"user.slice/user-$__u.slice\\\", \\\"$__b\\\", \\\"$__b/user.slice\\\", \\\"$__b/user.slice/docker-*.scope\\\"\"\n\
         done\n\
         printf '%s' '{}' | base64 -d | sed \"s|{SLOT_CGROUPS}|$__x|\"",
        base64::engine::general_purpose::STANDARD.encode(template)
    )
}

impl VectorModule {
    pub fn new(cfg: VectorSection) -> Self {
        Self {
            cfg,
            in_apps_slice: false,
        }
    }

    /// `[apps_resources]`: anvil owns the unit, so the slice goes in it.
    pub fn in_apps_slice(mut self, on: bool) -> Self {
        self.in_apps_slice = on;
        self
    }

    /// The GreptimeDB host, with an empty/blank value falling back to the
    /// schema default (localhost) — an empty string would otherwise produce a
    /// broken `http://:4000`-style endpoint that `vector validate` may only
    /// reject at apply time on the target.
    fn effective_host(&self) -> &str {
        let host = self.cfg.greptimedb_host.trim();
        if host.is_empty() {
            "127.0.0.1"
        } else {
            host
        }
    }

    /// Render `vector.toml`: a journald source (all retained boots — hardening
    /// wants history, not just the current boot), a host-metrics source (using
    /// `scrape_interval_secs`), an optional file source for `extra_log_files`,
    /// and the two GreptimeDB sinks (logs over HTTP, metrics over gRPC).
    pub fn config_content(&self) -> String {
        self.config_template().replace(SLOT_CGROUPS, "")
    }

    /// [`config_content`] with [`SLOT_CGROUPS`] in the cgroup
    /// includes, where the generator puts each CI slot user's sandbox scopes.
    fn config_template(&self) -> String {
        let c = &self.cfg;
        let has_extra = !c.extra_log_files.is_empty();

        let mut log_inputs = vec!["journald_quiet"];
        if has_extra {
            log_inputs.push("extra_files");
        }

        let host = self.effective_host();
        let logs_endpoint = format!("http://{}:{}", host, c.greptimedb_http_port);
        let metrics_endpoint = format!("{}:{}", host, c.greptimedb_grpc_port);

        let mut s = String::new();
        s.push_str("# Managed by anvil — do not edit by hand\n");
        s.push_str("data_dir = \"/var/lib/vector\"\n\n");

        s.push_str("[sources.journald]\n");
        s.push_str("type = \"journald\"\n");
        s.push_str("current_boot_only = false\n\n");

        // Known noise, dropped exactly; everything else is kept.
        // sysbox-fs logs the reaper line every few seconds (>95 % of its
        // lines); networkd-dispatcher runs networkctl for container veths
        // Docker already removed (prio 3) and hits an LLDP varlink bug.
        // `??`: a line may lack `message`.
        s.push_str("[transforms.journald_quiet]\n");
        s.push_str("type = \"filter\"\n");
        s.push_str("inputs = [\"journald\"]\n");
        s.push_str(
            "condition = '''\n\
             msg = string(.message) ?? \"\"\n\
             !(.\"_SYSTEMD_UNIT\" == \"sysbox-fs.service\" && contains(msg, \"reaper: nothing to reap\")) &&\n\
             !(.SYSLOG_IDENTIFIER == \"networkctl\" &&\n  \
             (match(msg, r'^Interface \".+\" not found\\.$') || contains(msg, \"GetLLDPNeighbors()\")))\n\
             '''\n\n",
        );

        // The line's own time (journald: when it was logged; files:
        // when read) as GreptimeDB's time index, not the arrival time, so a
        // backfill or a Vector outage doesn't pile old lines onto "now".
        s.push_str("[transforms.logs_time]\n");
        s.push_str("type = \"remap\"\n");
        s.push_str(&format!("inputs = {}\n", toml_str_array(log_inputs)));
        s.push_str(
            "source = '''\n\
             ts = timestamp(.timestamp) ?? now()\n\
             ns, err = to_unix_timestamp(ts, unit: \"nanoseconds\")\n\
             if err == null { .greptime_timestamp = ns }\n\
             '''\n\n",
        );

        s.push_str("[sources.host_metrics]\n");
        s.push_str("type = \"host_metrics\"\n");
        // Vector's Linux default minus `process`: per-process series were half
        // of a busy host's stored data and no dashboard reads them (the review);
        // cgroups cover per container, CI slice and user.
        s.push_str(
            "collectors = [\"cgroups\", \"cpu\", \"disk\", \"filesystem\", \"host\", \"load\", \
             \"memory\", \"network\", \"tcp\"]\n",
        );
        s.push_str(&format!(
            "scrape_interval_secs = {}\n\n",
            c.scrape_interval_secs
        ));
        // Docker's netns and other pseudo mounts have no partition info, and
        // the CI runners' sysbox mounts deny statvfs: Vector would log an
        // ERROR for each on every scrape.
        s.push_str("[sources.host_metrics.filesystem.mountpoints]\n");
        s.push_str(
            "excludes = [\"/run/docker/netns/*\", \"/run/netns/*\", \"/var/lib/docker/*\", \
             \"/run/user/*\", \"/proc/*\", \"/sys/*\", \"/var/lib/anvil-ci/*\"]\n\n",
        );
        if !c.cgroups_include.is_empty() {
            s.push_str("[sources.host_metrics.cgroups.groups]\n");
            let list = toml_str_array(cgroup_includes(&c.cgroups_include));
            s.push_str(&format!(
                "includes = {}{SLOT_CGROUPS}]\n\n",
                &list[..list.len() - 1]
            ));
        }

        if has_extra {
            s.push_str("[sources.extra_files]\n");
            s.push_str("type = \"file\"\n");
            s.push_str(&format!(
                "include = {}\n",
                toml_str_array(&c.extra_log_files)
            ));
            s.push_str("read_from = \"beginning\"\n\n");
        }

        s.push_str("[sinks.greptimedb_logs]\n");
        s.push_str("type = \"greptimedb_logs\"\n");
        s.push_str("inputs = [\"logs_time\"]\n");
        s.push_str(&format!("endpoint = {}\n", toml_str(&logs_endpoint)));
        s.push_str(&format!("dbname = {}\n", toml_str(&c.db_name)));
        s.push_str("table = \"vector_logs\"\n");
        s.push_str("pipeline_name = \"greptime_identity\"\n");
        s.push_str("compression = \"gzip\"\n");
        s.push_str("[sinks.greptimedb_logs.extra_params]\n");
        s.push_str("custom_time_index = \"greptime_timestamp;epoch;ns\"\n\n");

        // `greptimedb_metrics` is the current sink type (bare `greptimedb` is
        // a legacy alias); `new_naming` opts into its current metric naming.
        s.push_str("[sinks.greptimedb_metrics]\n");
        s.push_str("type = \"greptimedb_metrics\"\n");
        s.push_str("new_naming = true\n");
        s.push_str("inputs = [\"host_metrics\"]\n");
        s.push_str(&format!("endpoint = {}\n", toml_str(&metrics_endpoint)));
        s.push_str(&format!("dbname = {}\n", toml_str(&c.db_name)));

        s
    }

    /// systemd unit pinned to our config file.
    pub fn unit_content(&self) -> String {
        let slice = if self.in_apps_slice {
            format!("Slice={}\n", super::apps_resources::SLICE)
        } else {
            String::new()
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Vector (anvil-managed)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=exec\n\
             User=vector\n\
             Group=vector\n\
             {slice}\
             ExecStartPre=/usr/bin/vector validate --no-environment {CONFIG_PATH}\n\
             ExecStart=/usr/bin/vector --config {CONFIG_PATH}\n\
             ExecReload=/bin/kill -HUP $MAINPID\n\
             Restart=always\n\
             RestartSec=5\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        )
    }

    /// Install Vector from its official apt repository, pinned to the vendor
    /// signing key via `signed-by=` — no vendor script is ever piped to a
    /// shell. Bootstraps `curl`/`gnupg` first (a minimal image carries
    /// neither), with dpkg lock-wait (R109) on every apt call.
    fn install_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "install vector (keyring-pinned apt repo)",
            "command -v vector >/dev/null 2>&1",
            format!(
                "command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1 || {{ {bootstrap}; }}\n\
                 install -d -m 0755 /usr/share/keyrings\n\
                 curl -fsSL {SIGNING_KEY_URL} | gpg --dearmor --yes -o {KEYRING_PATH}\n\
                 printf 'deb [signed-by={KEYRING_PATH}] {APT_REPO}\\n' > {APT_LIST_PATH}\n\
                 chmod 0644 {KEYRING_PATH} {APT_LIST_PATH}\n\
                 {install}",
                bootstrap = apt_install(&["curl", "gnupg"]),
                install = apt_install(&["vector"]),
            ),
        )
    }

    /// The unit runs `User=vector`, which by default cannot read the journal
    /// its own config scrapes; membership in `systemd-journal` (journal
    /// access) and `adm` (classic /var/log readability) fixes that. Runs
    /// after the package install (which creates the user) and before the
    /// guarded reload starts the service.
    fn journal_access_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "vector user can read the journal (systemd-journal + adm)",
            // Plain `grep -Fx` (not `-q`) reads all input, so it never closes
            // the pipe early and trips `pipefail` via SIGPIPE on the producer.
            "id -nG vector 2>/dev/null | tr ' ' '\\n' | grep -Fx systemd-journal >/dev/null 2>&1 \
             && id -nG vector 2>/dev/null | tr ' ' '\\n' | grep -Fx adm >/dev/null 2>&1",
            "usermod -aG systemd-journal,adm vector",
        )
    }

    /// Probe the live service state so (a) a *crashed* vector reports drift
    /// instead of `aligned`, and (b) the guarded reload knows to (re)start it.
    /// The "converge" only raises a flag (`__vector_restart=1`); the actual
    /// start happens in the guarded reload, gated on this flag or a file change
    /// this run — so a converged, healthy host is never bounced (unlike a bare
    /// unconditional `systemctl restart`).
    fn service_state_command(&self) -> ManagedCommand {
        ManagedCommand::new(
            "vector service is active",
            "systemctl is-active --quiet vector",
            "__vector_restart=1",
        )
    }
}

impl Module for VectorModule {
    fn id(&self) -> &'static str {
        "vector"
    }

    fn declaration(&self) -> Declaration {
        let guard = ReloadGuard {
            describe: "vector configuration".into(),
            // Config-only validation (no health/env checks) before (re)starting.
            validate: format!(
                "! [ -e {CONFIG_PATH} ] || vector validate --no-environment {CONFIG_PATH}"
            ),
            // Restart only when warranted: the service was down
            // (`__vector_restart=1`, raised by the service-state command) or a
            // file changed this run (`__creates`/`__reverts`). A converged,
            // healthy host is left running — no churn every apply.
            // Once rollback removed our unit, stop Vector instead of
            // starting the packaged unit with the package's demo config.
            reload: format!(
                "systemctl daemon-reload; if [ -f {UNIT_PATH} ]; then \
                 systemctl enable vector >/dev/null 2>&1 || true; \
                 if [ \"${{__vector_restart:-0}}\" = 1 ] || [ \"${{#__creates[@]}}\" -gt 0 ] \
                 || [ \"${{#__reverts[@]}}\" -gt 0 ]; then systemctl restart vector; fi; \
                 else systemctl disable --now vector >/dev/null 2>&1 || true; fi"
            ),
        };
        Declaration::new("vector")
            .command(self.install_command())
            .command(self.journal_access_command())
            .command(self.service_state_command())
            .file(ManagedFile::computed(
                CONFIG_PATH,
                slot_cgroups_generator(&self.config_template()),
                "0644",
                "root:root",
            ))
            .file(ManagedFile::new(
                UNIT_PATH,
                self.unit_content(),
                "0644",
                "root:root",
            ))
            .guarded_reload(guard)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(mutate: impl FnOnce(&mut VectorSection)) -> VectorModule {
        let mut cfg = VectorSection {
            greptimedb_host: "127.0.0.1".into(),
            greptimedb_grpc_port: 4001,
            greptimedb_http_port: 4000,
            db_name: "logs".into(),
            extra_log_files: Vec::new(),
            scrape_interval_secs: 15,
            cgroups_include: vec!["system.slice/docker-*.scope".into(), "ci.slice/**".into()],
            order_override: Default::default(),
        };
        mutate(&mut cfg);
        VectorModule::new(cfg)
    }

    #[test]
    fn scrapes_journald_and_ships_to_greptimedb() {
        let conf = module(|_| {}).config_content();
        assert!(conf.contains("[sources.journald]"));
        assert!(conf.contains("type = \"journald\""));
        // Hardening wants retained history, not just the current boot.
        assert!(conf.contains("current_boot_only = false"));
        assert!(conf.contains("type = \"greptimedb_logs\""));
        assert!(conf.contains("endpoint = \"http://127.0.0.1:4000\""));
        assert!(conf.contains("endpoint = \"127.0.0.1:4001\""));
        assert!(conf.contains("dbname = \"logs\""));
    }

    #[test]
    fn logs_sink_sets_pipeline_and_compression() {
        let conf = module(|_| {}).config_content();
        let logs = conf
            .split("[sinks.greptimedb_logs]")
            .nth(1)
            .expect("logs sink present")
            .split("[sinks.")
            .next()
            .unwrap()
            .to_string();
        assert!(logs.contains("pipeline_name = \"greptime_identity\""));
        assert!(logs.contains("compression = \"gzip\""));
    }

    #[test]
    fn metrics_sink_uses_current_type_and_naming() {
        let conf = module(|_| {}).config_content();
        // Bare `greptimedb` is a legacy alias for the metrics sink.
        assert!(conf.contains("type = \"greptimedb_metrics\""));
        assert!(!conf.contains("type = \"greptimedb\"\n"));
        assert!(conf.contains("new_naming = true"));
    }

    #[test]
    fn empty_host_falls_back_to_localhost() {
        for host in ["", "   "] {
            let conf = module(|c| c.greptimedb_host = host.into()).config_content();
            assert!(conf.contains("endpoint = \"http://127.0.0.1:4000\""));
            assert!(conf.contains("endpoint = \"127.0.0.1:4001\""));
            // No malformed host-less endpoints may survive.
            assert!(!conf.contains("http://:"), "empty-host artifact:\n{conf}");
            assert!(!conf.contains("\":4001\""));
        }
    }

    #[test]
    fn host_metrics_collect_cgroups_not_process_for_the_included_groups() {
        let conf = module(|_| {}).config_content();
        assert!(
            conf.contains("collectors = [\"cgroups\", \"cpu\""),
            "{conf}"
        );
        assert!(!conf.contains("\"process\""), "{conf}");
        assert!(conf.contains(
            "[sources.host_metrics.cgroups.groups]\nincludes = [\"system.slice\", \
             \"system.slice/docker-*.scope\", \"ci.slice\", \"ci.slice/**\"]\n"
        ));
        assert!(!conf.contains("anvil.slice"), "rename residue:\n{conf}");
        let all = module(|c| c.cgroups_include.clear()).config_content();
        assert!(!all.contains("cgroups.groups"), "[] = every cgroup");
    }

    #[test]
    fn unit_joins_apps_slice_only_with_apps_resources() {
        let on = module(|_| {}).in_apps_slice(true).unit_content();
        assert!(
            on.contains("[Service]\n") && on.contains("\nSlice=apps.slice\n"),
            "Slice= belongs to [Service]:\n{on}"
        );
        let off = module(|_| {}).unit_content();
        assert!(!off.contains("apps.slice"), "{off}");
    }

    #[test]
    fn validate_takes_the_config_as_a_positional_path() {
        // Vector 0.61's `validate` rejects `--config` (only `vector` itself takes it).
        let d = module(|_| {}).declaration();
        let want = format!("vector validate --no-environment {CONFIG_PATH}");
        assert!(d.reload.unwrap().validate.ends_with(&want));
        let unit = module(|_| {}).unit_content();
        assert!(unit.contains(&format!("ExecStartPre=/usr/bin/{want}\n")));
        assert!(unit.contains(&format!(
            "ExecStart=/usr/bin/vector --config {CONFIG_PATH}\n"
        )));
        assert!(!unit.contains("validate --no-environment --config"));
    }

    #[test]
    fn filesystem_metrics_skip_docker_netns_and_pseudo_mounts() {
        let conf = module(|_| {}).config_content();
        assert!(conf.contains(
            "[sources.host_metrics.filesystem.mountpoints]\nexcludes = [\"/run/docker/netns/*\", \
             \"/run/netns/*\", \"/var/lib/docker/*\", \"/run/user/*\", \"/proc/*\", \"/sys/*\", \
             \"/var/lib/anvil-ci/*\"]\n"
        ));
    }

    #[test]
    fn cgroup_includes_add_each_ancestor_once() {
        let p = ["a/b/c*", "a/d", "e"].map(String::from);
        assert_eq!(cgroup_includes(&p), ["a", "a/b", "a/b/c*", "a/d", "e"]);
    }

    #[test]
    fn journald_reaches_the_logs_sink_filtered_then_timed() {
        // CONTAINER_NAME/_SYSTEMD_UNIT survive: identity pipeline; the filter
        // only drops known noise, the remap only adds the time index.
        let conf = module(|_| {}).config_content();
        assert_eq!(conf.matches("[transforms.").count(), 2, "{conf}");
        let quiet = &conf[conf.find("[transforms.journald_quiet]").unwrap()..];
        let quiet = &quiet[..quiet.find("[transforms.logs_time]").unwrap()];
        assert!(quiet.contains("type = \"filter\"\ninputs = [\"journald\"]\n"));
        for noise in [
            "\"sysbox-fs.service\" && contains(msg, \"reaper: nothing to reap\")",
            ".SYSLOG_IDENTIFIER == \"networkctl\"",
            "r'^Interface \".+\" not found\\.$'",
            "contains(msg, \"GetLLDPNeighbors()\")",
        ] {
            assert!(quiet.contains(noise), "{noise} in {quiet}");
        }
        let time = &conf[conf.find("[transforms.logs_time]").unwrap()..];
        assert!(time.contains("type = \"remap\"\ninputs = [\"journald_quiet\"]\n"));
        assert!(time.contains(
            "ns, err = to_unix_timestamp(ts, unit: \"nanoseconds\")\nif err == null { .greptime_timestamp = ns }"
        ));
        let sink = &conf[conf.find("[sinks.greptimedb_logs]").unwrap()..];
        assert!(sink.contains("inputs = [\"logs_time\"]"), "{sink}");
        // Same column and unit as the remap writes; without it GreptimeDB
        // stamps the arrival time.
        assert!(sink.contains(
            "[sinks.greptimedb_logs.extra_params]\n\
             custom_time_index = \"greptime_timestamp;epoch;ns\"\n"
        ));
    }

    #[test]
    fn scrape_interval_is_applied() {
        let conf = module(|c| c.scrape_interval_secs = 30).config_content();
        assert!(conf.contains("scrape_interval_secs = 30"));
    }

    #[test]
    fn extra_log_files_add_a_file_source_only_when_present() {
        let none = module(|_| {}).config_content();
        assert!(!none.contains("[sources.extra_files]"));
        assert!(none.contains("inputs = [\"journald_quiet\"]"));

        let some = module(|c| {
            c.extra_log_files = vec![
                "/var/log/nginx/access.log".into(),
                "/var/log/app.log".into(),
            ];
        })
        .config_content();
        assert!(some.contains("[sources.extra_files]"));
        assert!(some.contains("include = [\"/var/log/nginx/access.log\", \"/var/log/app.log\"]"));
        assert!(some.contains("inputs = [\"journald_quiet\", \"extra_files\"]"));
    }

    #[test]
    fn toml_values_are_escaped() {
        // A hostile db name / host / path must not break out of the TOML string.
        let conf = module(|c| {
            c.db_name = "a\"b\\c".into();
            c.greptimedb_host = "evil\"host".into();
            c.extra_log_files = vec!["/v/\"weird\".log".into()];
        })
        .config_content();
        assert!(conf.contains("dbname = \"a\\\"b\\\\c\""));
        assert!(conf.contains("endpoint = \"http://evil\\\"host:4000\""));
        assert!(conf.contains("endpoint = \"evil\\\"host:4001\""));
        assert!(conf.contains("\"/v/\\\"weird\\\".log\""));
    }

    #[test]
    fn install_uses_pinned_apt_repo_not_pipe_to_shell() {
        let decl = module(|_| {}).declaration();
        for script in [decl.render_probe(), decl.render_apply()] {
            // No vendor script piped into a shell, anywhere.
            assert!(!script.contains("| bash"), "pipe-to-bash:\n{script}");
            assert!(!script.contains("|bash"), "pipe-to-bash:\n{script}");
            assert!(!script.contains("| sh"), "pipe-to-sh:\n{script}");
            assert!(!script.contains("setup.vector.dev"));
        }
        let apply = decl.render_apply();
        // Keyring-pinned official repo layout.
        assert!(apply.contains("gpg --dearmor"));
        assert!(apply.contains("/usr/share/keyrings/vector-archive-keyring.gpg"));
        assert!(apply.contains(
            "deb [signed-by=/usr/share/keyrings/vector-archive-keyring.gpg] \
             https://apt.vector.dev/ stable vector-0"
        ));
        assert!(apply.contains("/etc/apt/sources.list.d/vector.list"));
        // Readable by apt's `_apt` verifier even under a hardened umask 027,
        // and fixed before apt runs.
        let chmod = apply
            .find(
                "chmod 0644 /usr/share/keyrings/vector-archive-keyring.gpg \
                 /etc/apt/sources.list.d/vector.list",
            )
            .expect("chmod 0644 of key and source");
        let list = apply
            .find("> /etc/apt/sources.list.d/vector.list")
            .expect("source write");
        let install = apply.find("install -y -- 'vector'").expect("install");
        assert!(list < chmod && chmod < install);
        // curl/gnupg bootstrap and dpkg lock-wait on every apt call.
        assert!(
            apply.contains("command -v curl >/dev/null 2>&1 && command -v gpg >/dev/null 2>&1 ||")
        );
        assert!(apply.contains("apt-get -o DPkg::Lock::Timeout=600 update -qq"));
        assert!(apply.contains("apt-get -o DPkg::Lock::Timeout=600 install -y -- 'vector'"));
    }

    #[test]
    fn vector_user_gains_journal_access_before_service_start() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("usermod -aG systemd-journal,adm vector"));
        // Idempotent detect on group membership.
        assert!(apply.contains("id -nG vector"));
        assert!(apply.contains("grep -Fx systemd-journal"));
        assert!(apply.contains("grep -Fx adm"));
        // Group membership converges before the guarded reload (re)starts the
        // service.
        let groups_at = apply.find("usermod -aG").expect("groups converge");
        let restart_at = apply
            .find("systemctl restart vector")
            .expect("service restart");
        assert!(groups_at < restart_at, "groups must precede service start");
    }

    #[test]
    fn install_and_reload_are_declared() {
        let apply = module(|_| {}).declaration().render_apply();
        assert!(apply.contains("apt.vector.dev"));
        assert!(apply.contains("install -y -- 'vector'"));
        assert!(apply.contains("vector validate --no-environment"));
        assert!(apply.contains("systemctl restart vector"));
        assert!(apply.contains(CONFIG_PATH));
        assert!(apply.contains(UNIT_PATH));
    }

    #[test]
    fn rollback_stops_vector_once_our_unit_is_gone() {
        let rb = module(|_| {}).declaration().render_rollback();
        let gate = rb
            .rfind(&format!("if [ -f {UNIT_PATH} ]; then"))
            .expect("unit gate");
        let stop = rb.rfind("else systemctl disable --now vector").unwrap();
        let restart = rb.rfind("systemctl restart vector").unwrap();
        assert!(gate < restart && restart < stop, "{rb}");
    }

    #[test]
    fn restart_only_when_changed_or_inactive() {
        // A converged, healthy host must not be bounced every apply, and a
        // crashed vector must read as drift. A service-state command probes
        // `is-active`; the restart is gated on that flag or a file change.
        let decl = module(|_| {}).declaration();
        let probe = decl.render_probe();
        let apply = decl.render_apply();
        // The probe now catches a dead service (no longer "aligned" forever).
        assert!(
            probe.contains("systemctl is-active --quiet vector"),
            "probe checks service state:\n{probe}"
        );
        assert!(
            apply.contains("__vector_restart=1"),
            "inactive service raises a restart flag:\n{apply}"
        );
        let gate = apply
            .find(r#"if [ "${__vector_restart:-0}" = 1 ] || [ "${#__creates[@]}" -gt 0 ]"#)
            .expect("restart gated on flag or file change");
        let restart = apply
            .find("systemctl restart vector")
            .expect("restart present");
        assert!(gate < restart, "restart is inside the gate:\n{apply}");
    }

    /// Runs the vector.toml generator with `getent passwd` stubbed.
    fn generated(passwd: &str) -> String {
        let dir = std::env::temp_dir().join(format!("anvil-vec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("getent");
        std::fs::write(&stub, format!("#!/bin/sh\nprintf '%s' '{passwd}'\n")).unwrap();
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&stub)
            .status()
            .unwrap();
        let m = module(|_| {});
        let out = std::process::Command::new("bash")
            .args(["-c", &slot_cgroups_generator(&m.config_template())])
            .env(
                "PATH",
                format!("{}:{}", dir.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    fn slot_users_sandbox_cgroups_are_collected_by_exact_uid_only() {
        let m = module(|_| {});
        // No slot users: exactly the static config.
        assert_eq!(
            generated("agent:x:1002:1002::/home/agent:/bin/bash\n"),
            m.config_content()
        );
        let conf = generated(
            "agent:x:1002:1002::/home/agent:/bin/bash\n\
             anvil-fjr-1:x:992:978:umask=022:/var/lib/anvil-fjr-1:/usr/sbin/nologin\n\
             anvil-ghr-runner-2:x:990:976:umask=022:/var/lib/anvil-ghr-runner-2:/usr/sbin/nologin\n",
        );
        let inc = conf.lines().find(|l| l.starts_with("includes = ")).unwrap();
        for want in [
            "\"user.slice/user-992.slice/user@992.service/user.slice/docker-*.scope\"",
            "\"user.slice/user-990.slice/user@990.service/user.slice\"",
        ] {
            assert!(inc.contains(want), "{want}: {inc}");
        }
        assert!(!inc.contains("1002") && !inc.contains("user@*"), "{inc}");
        assert!(inc.ends_with("docker-*.scope\"]"), "{inc}");
        assert!(toml::from_str::<toml::Value>(&conf).is_ok(), "{conf}");
    }
}
