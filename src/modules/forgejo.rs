//! The `forgejo` module: a Forgejo git forge from the signature-verified
//! upstream binary under a sandboxed systemd unit (`deploy = "native"`), or
//! the digest-pinned rootless image under Docker Compose (`deploy =
//! "compose"`) or as a Podman Quadlet (`deploy = "quadlet"`). Design:
//! docs/design/forgejo.md.
//!
//! - All modes share `app.ini`, the secret files, `/var/lib/forgejo` and the
//!   `forgejo.service` name; containers run on the host network, so they
//!   bind exactly what `app.ini` says and ufw still applies.
//! - HTTP listens on 127.0.0.1 only. With `[tls]` serving `domain`, an nginx
//!   snippet in [`tls::SNIPPET_DIR`] proxies to it; otherwise front it with
//!   `[caddy]` or your own proxy.
//! - Git over SSH uses Forgejo's built-in server on `ssh_port`, so the host's
//!   sshd hardening (`AllowUsers`, `tailnet_only_ssh`, fail2ban) is untouched.
//! - Secrets reach Forgejo only through `*_URI` files (computed, 0640
//!   root:git); `app.ini` is static, secret-free and therefore diffable.
//! - Rollback stops the service, removes config and the binary if anvil
//!   installed it; `/var/lib/forgejo` (repositories, database) and apt
//!   packages are never removed.

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine as _;

use crate::config::schema::{CaddySection, FirewallSection, ForgejoSection, TlsSection};
use crate::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard, MARK_FAILED};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

use super::{apt_install, tls, Module};

/// Current LTS (supported until 2027-07-15), with its release checksums
/// (checked on top of the signature).
pub const DEFAULT_VERSION: &str = "15.0.11";
const DEFAULT_SHA256_AMD64: &str =
    "17b59b5f8a8f968126b7a6fcc1d45d9531228dbf293f172cf5565d2e72e999a3";
const DEFAULT_SHA256_ARM64: &str =
    "897629ce7723b46620004ae2e7b2ff21917efd24e9a2d2f02b77888e867e4af5";

/// Primary fingerprint of Forgejo's release signing key, from
/// <https://forgejo.org/download/>. Only the fingerprint is pinned: the key
/// is fetched at install time because its signing subkeys rotate yearly.
pub const SIGNING_KEY_FPR: &str = "EB114F5E6C0DC2BCDD183550A4B61A2DC5923710";

pub const BIN: &str = "/usr/local/bin/forgejo";
pub const DATA_DIR: &str = "/var/lib/forgejo";
pub const CONF_DIR: &str = "/etc/forgejo";
pub const APP_INI: &str = "/etc/forgejo/app.ini";
/// Forgejo's log file in both deploy modes (`[log] ROOT_PATH` + `FILE_NAME`):
/// the fail2ban `forgejo` jail reads it, so journald vs json-file never matters.
pub const LOG_FILE: &str = "/var/lib/forgejo/log/forgejo.log";
pub const UNIT_PATH: &str = "/etc/systemd/system/forgejo.service";
const SECRET_KEY: &str = "/etc/forgejo/secret_key";
const INTERNAL_TOKEN: &str = "/etc/forgejo/internal_token";
const JWT_SECRET: &str = "/etc/forgejo/jwt_secret";
const DB_PASSWORD: &str = "/etc/forgejo/db_password";

/// Index digest of `codeberg.org/forgejo/forgejo:15.0.11-rootless` (amd64 +
/// arm64), from the registry's `Docker-Content-Digest`.
const DEFAULT_IMAGE_DIGEST: &str =
    "sha256:3cd6bc2b74c87cbde0a0fd527c9665cb416f5a0540dee54fe5afb3fa2df9f40c";
pub const COMPOSE_PATH: &str = "/etc/forgejo/compose.yaml";
/// `FORGEJO_UID`/`FORGEJO_GID` of the host's `git` user (host-dependent).
const COMPOSE_ENV: &str = "/etc/forgejo/compose.env";
const CONTAINER: &str = "forgejo";
/// `deploy = "quadlet"`: generates `forgejo.service`, so no file may sit at
/// [`UNIT_PATH`] (it would shadow the generated unit).
pub const QUADLET_PATH: &str = "/etc/containers/systemd/forgejo.container";
/// The binary in the image (`/usr/local/bin/gitea` is the entrypoint's wrapper).
const IMAGE_BIN: &str = "/app/gitea/gitea";

pub fn nginx_snippet_path() -> String {
    format!("{}/forgejo.conf", tls::SNIPPET_DIR)
}

pub struct ForgejoModule {
    cfg: ForgejoSection,
    /// `[tls]` serves `domain`, so the nginx snippet is ours to write.
    via_tls: bool,
    docker_distro: bool,
    /// `[apps_resources]`: the unit, compose service and Quadlet join `apps.slice`.
    in_apps_slice: bool,
}

impl ForgejoModule {
    pub fn new(cfg: ForgejoSection, via_tls: bool) -> Self {
        Self {
            cfg,
            via_tls,
            docker_distro: false,
            in_apps_slice: false,
        }
    }

    /// `[apps_resources]`: forgejo joins `apps.slice` in every deploy mode.
    pub fn in_apps_slice(mut self, on: bool) -> Self {
        self.in_apps_slice = on;
        self
    }

    /// `[docker] source = "distro"`: compose mode installs that engine.
    pub fn docker_distro(mut self, on: bool) -> Self {
        self.docker_distro = on;
        self
    }

    fn compose(&self) -> bool {
        self.cfg.deploy == "compose"
    }

    fn quadlet(&self) -> bool {
        self.cfg.deploy == "quadlet"
    }

    /// The container engine's CLI in compose/quadlet mode.
    fn ctl(&self) -> &'static str {
        if self.quadlet() {
            "podman"
        } else {
            "docker"
        }
    }

    /// The file that defines `forgejo.service`.
    fn unit_file(&self) -> &'static str {
        if self.quadlet() {
            QUADLET_PATH
        } else {
            UNIT_PATH
        }
    }

    /// `<version>-rootless@<digest>`; validation requires a digest for a
    /// non-default version.
    pub fn image(&self) -> String {
        let digest = match &self.cfg.image_digest {
            Some(d) => d.as_str(),
            None if self.cfg.version == DEFAULT_VERSION => DEFAULT_IMAGE_DIGEST,
            None => "",
        };
        format!(
            "codeberg.org/forgejo/forgejo:{}-rootless@{digest}",
            self.cfg.version
        )
    }

    /// The ufw rule for `listen = "tailnet"` (spec, also its `ufw show added` line).
    fn tailnet_rule(&self) -> Option<String> {
        (self.cfg.listen == "tailnet" && self.cfg.ssh_port != 0).then(|| {
            format!(
                "allow in on tailscale0 to any port {} proto tcp",
                self.cfg.ssh_port
            )
        })
    }

    fn postgres(&self) -> bool {
        self.cfg.database == "postgres"
    }

    /// Empty for an architecture without a checksum: only the default
    /// version has built-in ones, other versions rely on the signature.
    fn checksums(&self) -> (String, String) {
        let builtin = self.cfg.version == DEFAULT_VERSION;
        let pick = |o: &Option<String>, d: &str| {
            o.clone()
                .unwrap_or_else(|| if builtin { d.into() } else { String::new() })
        };
        (
            pick(&self.cfg.sha256_amd64, DEFAULT_SHA256_AMD64),
            pick(&self.cfg.sha256_arm64, DEFAULT_SHA256_ARM64),
        )
    }

    /// Every value here was validated at load to an ini-safe charset.
    pub fn app_ini(&self) -> String {
        let c = &self.cfg;
        let ssh = if c.ssh_port == 0 {
            "DISABLE_SSH = true\n".to_string()
        } else {
            format!(
                "DISABLE_SSH = false\n\
                 START_SSH_SERVER = true\n\
                 SSH_DOMAIN = {d}\n\
                 SSH_PORT = {p}\n\
                 SSH_LISTEN_PORT = {p}\n",
                d = c.domain,
                p = c.ssh_port
            )
        };
        let db = if self.postgres() {
            format!(
                "DB_TYPE = postgres\n\
                 HOST = {}\n\
                 NAME = {}\n\
                 USER = {}\n\
                 PASSWD_URI = file:{DB_PASSWORD}\n\
                 SSL_MODE = {}\n",
                c.db_host, c.db_name, c.db_user, c.db_ssl_mode
            )
        } else {
            format!("DB_TYPE = sqlite3\nPATH = {DATA_DIR}/data/forgejo.db\n")
        };
        format!(
            "; Managed by anvil — do not edit by hand\n\
             APP_NAME = Forgejo\n\
             RUN_USER = git\n\
             RUN_MODE = prod\n\
             WORK_PATH = {DATA_DIR}\n\
             \n\
             [server]\n\
             PROTOCOL = http\n\
             DOMAIN = {domain}\n\
             ROOT_URL = https://{domain}/\n\
             HTTP_ADDR = 127.0.0.1\n\
             HTTP_PORT = {http}\n\
             OFFLINE_MODE = true\n\
             LFS_START_SERVER = false\n\
             {ssh}\
             \n\
             [database]\n\
             {db}\
             \n\
             [security]\n\
             INSTALL_LOCK = true\n\
             SECRET_KEY_URI = file:{SECRET_KEY}\n\
             INTERNAL_TOKEN_URI = file:{INTERNAL_TOKEN}\n\
             DISABLE_GIT_HOOKS = true\n\
             REVERSE_PROXY_LIMIT = 1\n\
             REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128\n\
             \n\
             [log]\n\
             MODE = console, file\n\
             ROOT_PATH = {DATA_DIR}/log\n\
             \n\
             [log.file]\n\
             FILE_NAME = forgejo.log\n\
             \n\
             [oauth2]\n\
             JWT_SECRET_URI = file:{JWT_SECRET}\n\
             \n\
             [service]\n\
             DISABLE_REGISTRATION = true\n\
             REQUIRE_SIGNIN_VIEW = {signin}\n\
             \n\
             [session]\n\
             COOKIE_SECURE = true\n\
             \n\
             [actions]\n\
             ENABLED = {actions}\n",
            domain = c.domain,
            http = c.http_port,
            signin = c.require_signin_view,
            actions = c.actions,
        )
    }

    /// Upstream `contrib/systemd/forgejo.service`, plus sandboxing; in
    /// compose mode a oneshot that brings the project up and down.
    pub fn unit(&self) -> String {
        let pg = if self.postgres() {
            "After=postgresql.service\n"
        } else {
            ""
        };
        let slice = if self.in_apps_slice {
            format!("Slice={}\n", super::apps_resources::SLICE)
        } else {
            String::new()
        };
        if self.compose() {
            return format!(
                "# Managed by anvil — do not edit by hand\n\
                 [Unit]\n\
                 Description=Forgejo (Docker Compose)\n\
                 Requires=docker.service\n\
                 After=docker.service network-online.target\n\
                 {pg}\
                 \n\
                 [Service]\n\
                 Type=oneshot\n\
                 RemainAfterExit=yes\n\
                 TimeoutStartSec=600\n\
                 {slice}\
                 ExecStart=/usr/bin/docker compose -p {CONTAINER} -f {COMPOSE_PATH} --env-file {COMPOSE_ENV} up -d --wait --remove-orphans\n\
                 ExecStop=/usr/bin/docker compose -p {CONTAINER} down\n\
                 \n\
                 [Install]\n\
                 WantedBy=multi-user.target\n"
            );
        }
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Forgejo\n\
             After=network.target\n\
             {pg}\
             \n\
             [Service]\n\
             Type=simple\n\
             User=git\n\
             Group=git\n\
             {slice}\
             WorkingDirectory={DATA_DIR}\n\
             ExecStart={BIN} web --config {APP_INI}\n\
             Restart=always\n\
             RestartSec=2s\n\
             Environment=USER=git HOME={DATA_DIR} FORGEJO_WORK_DIR={DATA_DIR}\n\
             NoNewPrivileges=true\n\
             ProtectSystem=strict\n\
             ReadWritePaths={DATA_DIR}\n\
             ProtectHome=true\n\
             PrivateTmp=true\n\
             PrivateDevices=true\n\
             ProtectKernelTunables=true\n\
             ProtectKernelModules=true\n\
             ProtectControlGroups=true\n\
             RestrictSUIDSGID=true\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        )
    }

    /// Static, so `diff` shows it; the uid comes from [`COMPOSE_ENV`].
    /// Host network: no published port (Docker's would bypass ufw), and
    /// `app.ini`'s 127.0.0.1 HTTP bind means the host's loopback. Docker owns
    /// crash restarts (`restart`), the unit owns up/down. No `logging:`:
    /// the daemon.json default applies (`[docker] log_driver`).
    pub fn compose_yaml(&self) -> String {
        let cgroup = if self.in_apps_slice {
            // Docker (systemd cgroup driver) creates the container's scope
            // under this slice instead of system.slice/docker-*.scope.
            "\x20   cgroup_parent: apps.slice\n"
        } else {
            ""
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             name: {CONTAINER}\n\
             services:\n\
             \x20 forgejo:\n\
             \x20   image: {image}\n\
             \x20   container_name: {CONTAINER}\n\
             \x20   entrypoint: [\"{IMAGE_BIN}\", \"web\", \"--config\", \"{APP_INI}\", \"--work-path\", \"{DATA_DIR}\"]\n\
             \x20   user: \"${{FORGEJO_UID:?}}:${{FORGEJO_GID:?}}\"\n\
             \x20   userns_mode: host\n\
             {cgroup}\
             \x20   network_mode: host\n\
             \x20   init: true\n\
             \x20   restart: unless-stopped\n\
             \x20   read_only: true\n\
             \x20   tmpfs:\n\
             \x20     - /tmp\n\
             \x20     - /var/lib/gitea\n\
             \x20   cap_drop: [ALL]\n\
             \x20   security_opt: [\"no-new-privileges:true\"]\n\
             \x20   mem_limit: 2g\n\
             \x20   cpu_shares: 512\n\
             \x20   pids_limit: 1024\n\
             \x20   environment:\n\
             \x20     USER: git\n\
             \x20     HOME: {DATA_DIR}\n\
             \x20     FORGEJO_WORK_DIR: {DATA_DIR}\n\
             \x20     GITEA_CUSTOM: {DATA_DIR}/custom\n\
             \x20     GITEA_TEMP: /tmp\n\
             \x20     TMPDIR: /tmp\n\
             \x20   volumes:\n\
             \x20     - {DATA_DIR}:{DATA_DIR}\n\
             \x20     - {CONF_DIR}:{CONF_DIR}:ro\n",
            image = self.image(),
        )
    }

    /// The Quadlet: [`Self::compose_yaml`] as Quadlet keys, with the host
    /// `git` uid/gid as placeholders that [`Self::quadlet_generator`] fills.
    /// Podman owns crash restarts via systemd (`Restart=always`).
    pub fn quadlet_template(&self) -> String {
        let pg = if self.postgres() {
            "After=postgresql.service\n"
        } else {
            ""
        };
        let slice = if self.in_apps_slice {
            format!("Slice={}\n", super::apps_resources::SLICE)
        } else {
            String::new()
        };
        format!(
            "# Managed by anvil — do not edit by hand\n\
             [Unit]\n\
             Description=Forgejo (Podman Quadlet)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             {pg}\
             \n\
             [Container]\n\
             Image={image}\n\
             ContainerName={CONTAINER}\n\
             User=@FORGEJO_UID@\n\
             Group=@FORGEJO_GID@\n\
             Network=host\n\
             ReadOnly=true\n\
             Tmpfs=/tmp\n\
             Tmpfs=/var/lib/gitea\n\
             DropCapability=all\n\
             NoNewPrivileges=true\n\
             Environment=USER=git HOME={DATA_DIR} FORGEJO_WORK_DIR={DATA_DIR} GITEA_CUSTOM={DATA_DIR}/custom GITEA_TEMP=/tmp TMPDIR=/tmp\n\
             Volume={DATA_DIR}:{DATA_DIR}\n\
             Volume={CONF_DIR}:{CONF_DIR}:ro\n\
             PodmanArgs=--init --entrypoint={IMAGE_BIN} --memory=2g --cpu-shares=512 --pids-limit=1024\n\
             Exec=web --config {APP_INI} --work-path {DATA_DIR}\n\
             \n\
             [Service]\n\
             Restart=always\n\
             {slice}\
             TimeoutStartSec=600\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            image = self.image(),
        )
    }

    /// Prints [`Self::quadlet_template`] with the host's `git` uid/gid (the
    /// template is base64-embedded, so nothing in it reaches the shell).
    fn quadlet_generator(&self) -> String {
        format!(
            "printf '%s' {} | base64 -d | sed \"s/@FORGEJO_UID@/$(id -u git 2>/dev/null)/; s/@FORGEJO_GID@/$(id -g git 2>/dev/null)/\"",
            shell_escape(&B64.encode(self.quadlet_template()))
        )
    }

    /// Forgejo's reverse-proxy recipe, as a server-level snippet for [tls].
    pub fn nginx_snippet(&self) -> String {
        format!(
            "# Managed by anvil — do not edit by hand\n\
             # Forgejo on 127.0.0.1:{p}, included by the [tls] server block.\n\
             merge_slashes off;\n\
             location / {{\n\
             \x20   proxy_pass http://127.0.0.1:{p};\n\
             \x20   proxy_set_header Connection $http_connection;\n\
             \x20   proxy_set_header Upgrade $http_upgrade;\n\
             \x20   proxy_set_header Host $host;\n\
             \x20   proxy_set_header X-Real-IP $remote_addr;\n\
             \x20   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n\
             \x20   proxy_set_header X-Forwarded-Proto $scheme;\n\
             \x20   client_max_body_size 512M;\n\
             }}\n",
            p = self.cfg.http_port
        )
    }

    /// `forgejo …` as the git user (Forgejo refuses to run as root); in
    /// compose mode inside the container, which already runs as git.
    fn cli(&self, args: &str) -> String {
        let bin = if self.compose() || self.quadlet() {
            format!("{} exec {CONTAINER} {IMAGE_BIN}", self.ctl())
        } else {
            format!("runuser -u git -- {BIN}")
        };
        format!("{bin} --work-path {DATA_DIR} --config {APP_INI} {args}")
    }

    /// True when a user of that name exists (any role, so a clash never makes
    /// `create` fail). Only queries a running instance, so the probe never
    /// creates or migrates a database.
    fn admin_exists(&self, name: &str) -> String {
        format!(
            "{{ systemctl is-active --quiet forgejo && {} 2>/dev/null | \
             awk -v n={} 'NR>1 && $2==n {{f=1}} END {{exit !f}}'; }}",
            self.cli("admin user list"),
            shell_escape(name)
        )
    }

    fn admin(&self) -> Option<(&str, &str, &str)> {
        match (
            &self.cfg.admin_username,
            &self.cfg.admin_email,
            &self.cfg.admin_password,
        ) {
            (Some(u), Some(e), Some(p)) => Some((u, e, p)),
            _ => None,
        }
    }

    /// Create the admin once; never reset.
    fn admin_bootstrap(&self, user: &str, email: &str, pass: &str) -> String {
        // Create once; never reset. Forgejo 15 reads --password only from
        // argv (visible in /proc), so create with a random password, then
        // set the real one through the local API: the body on curl's stdin
        // (printf is a builtin), basic auth from the random one via `-K`
        // on a pipe. must_change_password is explicit because Forgejo
        // exempts the first admin by default. A failed PATCH deletes the
        // user so the next apply retries instead of skipping it.
        let u = shell_escape(user);
        format!(
            "{{ {exists} || {{ __fj_rp=$({create} | \
             sed -n \"s/^generated random password is '\\(.*\\)'\\$/\\1/p\") && [ -n \"$__fj_rp\" ] && \
             printf '%s' {body} | curl -fsS -o /dev/null -X PATCH -H 'Content-Type: application/json' \
             -K <(printf 'header = \"Authorization: Basic %s\"\\n' \"$(printf '%s:%s' {u} \"$__fj_rp\" | base64 -w0)\") \
             --data-binary @- {url} || {{ __fj_d='user removed, re-apply retries'; \
             {delete} >/dev/null 2>&1 || __fj_d='delete the user and re-apply'; \
             printf '{MARK_FAILED} forgejo admin %s: password not set via the API; %s\\n' {u} \"$__fj_d\"; false; }}; }}; }}",
            exists = self.admin_exists(user),
            create = self.cli(&format!(
                "admin user create --admin --random-password --username {u} --email {}",
                shell_escape(email)
            )),
            body = shell_escape(&admin_body(pass)),
            url = shell_escape(&format!(
                "http://127.0.0.1:{}/api/v1/admin/users/{user}",
                self.cfg.http_port
            )),
            delete = self.cli(&format!("admin user delete --username {u}")),
        )
    }

    /// Download, check the SHA-256 (when pinned) and the release signature,
    /// install. Sets `__fj_changed` so the reload restarts on the new binary.
    fn install_command(&self) -> ManagedCommand {
        let (amd64, arm64) = self.checksums();
        let pick = format!(
            "case \"$(dpkg --print-architecture)\" in amd64) __fj_sha={}; __fj_arch=amd64 ;; \
             arm64) __fj_sha={}; __fj_arch=arm64 ;; *) __fj_sha=''; __fj_arch='' ;; esac",
            shell_escape(&amd64),
            shell_escape(&arm64)
        );
        // Without a pinned checksum the installed binary is only identified
        // by its version (`15.0.11+gitea-1.22.0`); the `+` stops 15.0.1 matching 15.0.11.
        let detect = format!(
            "{{ {pick}; [ -n \"$__fj_arch\" ] && [ -x {BIN} ] && \
             if [ -n \"$__fj_sha\" ]; then printf '%s  %s\\n' \"$__fj_sha\" {BIN} | sha256sum -c --status -; \
             else grep -qiF -- {want} <<<\"$({BIN} --version 2>/dev/null)\"; fi; }}",
            want = shell_escape(&format!("version {}+", self.cfg.version)),
        );
        let converge = format!(
            "{pick}\n\
             [ -n \"$__fj_arch\" ] || {{ printf '{MARK_FAILED} forgejo: unsupported architecture %s (amd64 and arm64 only)\\n' \"$(dpkg --print-architecture)\"; exit 1; }}\n\
             command -v curl >/dev/null 2>&1 || {{ {curl}; }}\n\
             __fj_ver={ver}\n\
             __fj_tmp=$(mktemp -p \"$__rundir\")\n\
             command -v gpg >/dev/null 2>&1 || {{ {gpg}; }}\n\
             __fj_asc=$(mktemp -p \"$__rundir\")\n\
             __fj_key=$(mktemp -p \"$__rundir\")\n\
             __fj_url=\"https://codeberg.org/forgejo/forgejo/releases/download/v${{__fj_ver}}/forgejo-${{__fj_ver}}-linux-${{__fj_arch}}\"\n\
             curl -fsSL -o \"$__fj_tmp\" \"$__fj_url\"\n\
             if ! curl -fsSL -o \"$__fj_asc\" \"$__fj_url.asc\" || ! curl -fsSL -o \"$__fj_key\" {key_url}; then\n\
             \x20 rm -f \"$__fj_tmp\" \"$__fj_asc\" \"$__fj_key\"\n\
             \x20 printf '{MARK_FAILED} forgejo %s: could not download the release signature or signing key, not installed\\n' \"$__fj_ver\"\n\
             \x20 exit 1\n\
             fi\n\
             if [ -n \"$__fj_sha\" ] && ! printf '%s  %s\\n' \"$__fj_sha\" \"$__fj_tmp\" | sha256sum -c --status -; then\n\
             \x20 rm -f \"$__fj_tmp\" \"$__fj_asc\" \"$__fj_key\"\n\
             \x20 printf '{MARK_FAILED} forgejo %s: SHA-256 mismatch, not installed\\n' \"$__fj_ver\"\n\
             \x20 exit 1\n\
             fi\n\
             {verify}\n\
             [ -e {BIN} ] || __anvil_remember {BIN}\n\
             install -m 0755 -o root -g root \"$__fj_tmp\" {BIN}\n\
             rm -f \"$__fj_tmp\" \"$__fj_asc\" \"$__fj_key\"\n\
             __fj_changed=1",
            curl = apt_install(&["curl"]),
            gpg = apt_install(&["gpg"]),
            key_url = shell_escape(&format!(
                "https://keys.openpgp.org/vks/v1/by-fingerprint/{SIGNING_KEY_FPR}"
            )),
            ver = shell_escape(&self.cfg.version),
            verify = verify_script(SIGNING_KEY_FPR),
        );
        ManagedCommand::new(
            format!("forgejo {} binary (signature verified)", self.cfg.version),
            detect,
            converge,
        )
    }

    fn reload_script(&self) -> String {
        // Native after compose: the container is outside the unit's cgroup,
        // so take it down before the native unit starts on the same ports.
        let pre = if self.compose() || self.quadlet() {
            String::new()
        } else {
            format!(
                "{{ [ ! -f {COMPOSE_PATH} ] || ! command -v docker >/dev/null 2>&1 || \
                 docker compose -p {CONTAINER} down >/dev/null 2>&1 || true; }}; "
            )
        };
        let logs = if self.compose() {
            "docker logs forgejo"
        } else {
            "journalctl -u forgejo"
        };
        let mut r = format!(
            "__fj_restart=${{__fj_changed:-0}}\n\
             __fj_ng=${{__fj_ng:-0}}\n\
             for __p in \"${{__creates[@]:-}}\" \"${{__reverts[@]:-}}\"; do\n\
             \x20 case \"$__p\" in\n\
             \x20\x20 {APP_INI}|{SECRET_KEY}|{INTERNAL_TOKEN}|{JWT_SECRET}|{DB_PASSWORD}|{UNIT_PATH}|{COMPOSE_PATH}|{COMPOSE_ENV}|{QUADLET_PATH}) __fj_restart=1 ;;\n\
             \x20\x20 {snippet}) __fj_ng=1 ;;\n\
             \x20 esac\n\
             done\n\
             systemctl daemon-reload\n\
             if [ -f {unit} ]; then\n\
             \x20 systemctl enable forgejo >/dev/null 2>&1 || true\n\
             \x20 if [ \"$__fj_restart\" = 1 ]; then {pre}systemctl restart forgejo; \
             elif ! systemctl is-active --quiet forgejo; then systemctl start forgejo; fi && \
             {{ for __i in $(seq 1 60); do curl -fsS -o /dev/null {health} && break; sleep 1; done; \
             curl -fsS -o /dev/null {health} || \
             {{ printf '{MARK_FAILED} forgejo did not answer %s within 60s ({logs})\\n' {health}; false; }}; }}",
            snippet = nginx_snippet_path(),
            unit = self.unit_file(),
            health = shell_escape(&format!(
                "http://127.0.0.1:{}/api/healthz",
                self.cfg.http_port
            )),
        );
        if let Some((user, email, pass)) = self.admin() {
            r.push_str(" && \\\n\x20 ");
            r.push_str(&self.admin_bootstrap(user, email, pass));
        }
        r.push_str(
            "\nfi && { [ \"$__fj_ng\" = 0 ] || ! command -v nginx >/dev/null 2>&1 || \
             systemctl reload nginx; }",
        );
        r
    }

    fn rollback(&self) -> String {
        // The engine has already removed compose.yaml: down by project label.
        let compose = if self.compose() {
            format!(
                "if command -v docker >/dev/null 2>&1 && \
                 [ -n \"$(docker ps -aq --filter label=com.docker.compose.project={CONTAINER} 2>/dev/null)\" ]; then\n\
                 \x20 docker compose -p {CONTAINER} down >/dev/null 2>&1 || true\n\
                 \x20 printf 'CHANGED: forgejo container removed; image and %s kept\\n' {DATA_DIR}\n\
                 fi\n"
            )
        } else {
            String::new()
        };
        let ufw = self
            .tailnet_rule()
            .map(|spec| {
                format!(
                    "if command -v ufw >/dev/null 2>&1 && ufw show added 2>/dev/null | grep -wF {n} >/dev/null; then\n\
                     \x20 ufw delete {spec} >/dev/null\n\
                     \x20 printf 'CHANGED: forgejo removed firewall rule %s\\n' {n}\n\
                     fi\n",
                    n = shell_escape(&spec)
                )
            })
            .unwrap_or_default();
        format!(
            "\n# rollback (module-authored): forgejo — data in {DATA_DIR} is never removed\n\
             {compose}\
             __fj_ng=1\n\
             if [ -f {unit} ]; then\n\
             \x20 __fj_changed=1\n\
             \x20 printf 'OK: forgejo unit restored; restarted by the reload\\n'\n\
             elif systemctl is-active --quiet forgejo || [ -e /etc/systemd/system/multi-user.target.wants/forgejo.service ]; then\n\
             \x20 systemctl stop forgejo >/dev/null 2>&1 || true\n\
             \x20 rm -f /etc/systemd/system/multi-user.target.wants/forgejo.service\n\
             \x20 printf 'CHANGED: forgejo stopped and disabled; %s kept\\n' {DATA_DIR}\n\
             else\n\
             \x20 printf 'OK: forgejo not running; %s kept\\n' {DATA_DIR}\n\
             fi\n\
             if [ ! -f {unit} ] && __anvil_created {BIN}; then\n\
             \x20 rm -f {BIN}\n\
             \x20 __anvil_forget {BIN}\n\
             \x20 printf 'CHANGED: %s removed (installed by anvil)\\n' {BIN}\n\
             else\n\
             \x20 printf 'OK: %s not installed by anvil (or its unit was restored); left alone\\n' {BIN}\n\
             fi\n\
             {ufw}",
            unit = self.unit_file(),
        )
    }
}

impl Module for ForgejoModule {
    fn id(&self) -> &'static str {
        "forgejo"
    }

    fn declaration(&self) -> Declaration {
        let secret = |path: &str, value: &str| {
            ManagedFile::computed(
                path,
                format!("printf '%s' {}", shell_escape(value)),
                "0640",
                "root:git",
            )
        };
        let mut decl = Declaration::new("forgejo");
        decl = if self.compose() {
            // curl: the reload's health check (native gets it with the binary).
            decl.command(ManagedCommand::new(
                "curl installed",
                "command -v curl >/dev/null 2>&1",
                apt_install(&["curl"]),
            ))
            .command(super::ensure_engine(
                crate::config::Engine::Docker,
                self.docker_distro,
            ))
            .command(ManagedCommand::new(
                "docker compose v2 available",
                "{ docker compose version >/dev/null 2>&1 && \
                     ! docker --version 2>/dev/null | grep -qi podman; }",
                format!(
                    "printf '{MARK_FAILED} forgejo: deploy = \"compose\" needs Docker with \
                         the compose v2 plugin (Podman is not supported yet)\\n'\nexit 1"
                ),
            ))
        } else if self.quadlet() {
            // catatonit: `--init` (compose's `init: true`) reaps git's children.
            decl.command(ManagedCommand::new(
                "curl installed",
                "command -v curl >/dev/null 2>&1",
                apt_install(&["curl"]),
            ))
            .command(super::ensure_engine(crate::config::Engine::Podman, false))
            .command(ManagedCommand::new(
                "catatonit installed (podman --init)",
                "[ -x /usr/libexec/podman/catatonit ] || command -v catatonit >/dev/null 2>&1",
                apt_install(&["catatonit"]),
            ))
            .command(ManagedCommand::new(
                format!("no {UNIT_PATH} shadowing the Quadlet"),
                format!("[ ! -e {UNIT_PATH} ]"),
                format!(
                    "printf '{MARK_FAILED} forgejo: %s (another deploy mode) would shadow the Quadlet; \
                     roll that deploy back first (anvil rollback --only forgejo)\\n' {UNIT_PATH}\nexit 1"
                ),
            ))
        } else {
            decl.command(ManagedCommand::new(
                "git installed",
                "command -v git >/dev/null 2>&1",
                apt_install(&["git"]),
            ))
        };
        decl = decl.command(ManagedCommand::new(
            "forgejo system user and directories",
            format!(
                "{{ id -u git >/dev/null 2>&1 && \
                     [ \"$(stat -c '%a %U:%G' {DATA_DIR} 2>/dev/null)\" = '750 git:git' ] && \
                     [ \"$(stat -c '%a %U:%G' {CONF_DIR} 2>/dev/null)\" = '750 root:git' ]; }}"
            ),
            format!(
                "getent group git >/dev/null 2>&1 || groupadd --system git\n\
                     id -u git >/dev/null 2>&1 || useradd --system --gid git \
                     --home-dir {DATA_DIR} --shell /usr/sbin/nologin git\n\
                     install -d -m 0750 -o git -g git {DATA_DIR}\n\
                     install -d -m 0750 -o root -g git {CONF_DIR}"
            ),
        ));
        if self.compose() || self.quadlet() {
            let (image, ctl) = (shell_escape(&self.image()), self.ctl());
            decl = decl.command(ManagedCommand::new(
                format!("forgejo image {}", self.image()),
                format!("{ctl} image inspect {image} >/dev/null 2>&1"),
                format!("{ctl} pull -q {image} >/dev/null"),
            ));
            decl =
                super::prune_superseded(decl, "forgejo", ctl, &format!("printf '%s\\n' {image}"));
        } else {
            decl = decl.command(self.install_command());
        }
        if let Some(spec) = self.tailnet_rule() {
            decl = decl.command(ManagedCommand::new(
                format!("firewall {spec} (forgejo ssh_port, tailnet only)"),
                format!(
                    "ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null \
                     && ufw show added 2>/dev/null | grep -wF {} >/dev/null",
                    shell_escape(&spec)
                ),
                format!(
                    "if ! ufw status 2>/dev/null | grep -F 'Status: active' >/dev/null; then\n\
                     \x20 printf '{MARK_FAILED} forgejo: listen = \"tailnet\" needs an active ufw ([firewall])\\n'\n\
                     \x20 exit 1\n\
                     fi\n\
                     ufw {spec} >/dev/null"
                ),
            ));
        }
        // A oneshot unit stays active when its container dies: check both.
        decl = decl.command(if self.compose() {
            ManagedCommand::new(
                "forgejo service active",
                format!(
                    "{{ systemctl is-active --quiet forgejo && \
                     [ \"$(docker inspect -f '{{{{.State.Running}}}}' {CONTAINER} 2>/dev/null)\" = true ]; }}"
                ),
                "__fj_changed=1",
            )
        } else {
            ManagedCommand::new(
                "forgejo service active",
                "systemctl is-active --quiet forgejo",
                ": # started by the guarded reload once config is in place",
            )
        });
        if let Some((user, _, _)) = self.admin() {
            decl = decl.command(ManagedCommand::new(
                format!("forgejo admin user {user}"),
                self.admin_exists(user),
                ": # created by the guarded reload once forgejo answers",
            ));
        }
        decl = decl
            .file(ManagedFile::new(
                APP_INI,
                self.app_ini(),
                "0640",
                "root:git",
            ))
            .file(secret(SECRET_KEY, &self.cfg.secret_key))
            .file(secret(INTERNAL_TOKEN, &self.cfg.internal_token))
            .file(secret(JWT_SECRET, &self.cfg.jwt_secret));
        if let (true, Some(p)) = (self.postgres(), &self.cfg.db_password) {
            decl = decl.file(secret(DB_PASSWORD, p));
        }
        if self.compose() {
            decl = decl
                .file(ManagedFile::new(
                    COMPOSE_PATH,
                    self.compose_yaml(),
                    "0644",
                    "root:root",
                ))
                .file(ManagedFile::computed(
                    COMPOSE_ENV,
                    "printf 'FORGEJO_UID=%s\\nFORGEJO_GID=%s\\n' \"$(id -u git 2>/dev/null)\" \"$(id -g git 2>/dev/null)\"",
                    "0644",
                    "root:root",
                ));
        }
        decl = decl.file(if self.quadlet() {
            ManagedFile::computed(QUADLET_PATH, self.quadlet_generator(), "0644", "root:root")
        } else {
            ManagedFile::new(UNIT_PATH, self.unit(), "0644", "root:root")
        });
        if self.via_tls {
            decl = decl.file(ManagedFile::new(
                nginx_snippet_path(),
                self.nginx_snippet(),
                "0644",
                "root:root",
            ));
        }
        // git must be able to read its config; nginx must accept the snippet.
        let readable: Vec<String> = [APP_INI, SECRET_KEY, INTERNAL_TOKEN, JWT_SECRET]
            .iter()
            .map(|p| format!("{{ [ ! -f {p} ] || runuser -u git -- test -r {p}; }}"))
            .collect();
        let mut validate = readable.join(" && ");
        if self.compose() {
            validate.push_str(&format!(
                " && {{ [ ! -f {COMPOSE_PATH} ] || \
                 docker compose -p {CONTAINER} -f {COMPOSE_PATH} --env-file {COMPOSE_ENV} config -q; }}"
            ));
        }
        if self.quadlet() {
            validate.push_str(" && ");
            validate.push_str(&super::containers::quadlet_converts(
                QUADLET_PATH,
                "forgejo.service",
            ));
        }
        if self.via_tls {
            validate.push_str(" && { ! command -v nginx >/dev/null 2>&1 || nginx -t; }");
        }
        for v in [&self.cfg.db_password, &self.cfg.admin_password]
            .into_iter()
            .flatten()
        {
            decl = decl.secret(v);
        }
        if let Some(p) = &self.cfg.admin_password {
            // The PATCH body carries it JSON-escaped; redact that form too.
            decl = decl.secret(admin_body(p));
        }
        decl.secret(&self.cfg.secret_key)
            .secret(&self.cfg.internal_token)
            .secret(&self.cfg.jwt_secret)
            .rollback_script(self.rollback())
            .guarded_reload(ReloadGuard {
                describe: "forgejo service".into(),
                validate,
                reload: self.reload_script(),
            })
    }
}

// --- validation (called from config::Config::validate / warnings) ----------

/// Verifies `$__fj_asc` over `$__fj_tmp` with the key in `$__fj_key`, in a
/// throwaway keyring; anything but a valid signature whose primary key is
/// `fpr` (last `VALIDSIG` field) prints `FAILED:` and exits. An expired
/// subkey passes (old releases stay installable), a revoked one does not.
fn verify_script(fpr: &str) -> String {
    format!(
        "__fj_gh=$(mktemp -d -p \"$__rundir\")\n\
         __fj_sig=$(gpg --homedir \"$__fj_gh\" --batch -q --import \"$__fj_key\" 2>/dev/null && \
         gpg --homedir \"$__fj_gh\" --batch -q --status-fd 1 --verify \"$__fj_asc\" \"$__fj_tmp\" 2>/dev/null) || __fj_sig=''\n\
         gpgconf --homedir \"$__fj_gh\" --kill all >/dev/null 2>&1 || true\n\
         rm -rf \"$__fj_gh\"\n\
         if grep -q '^\\[GNUPG:\\] REVKEYSIG' <<<\"$__fj_sig\" || \
         ! grep -qE '^\\[GNUPG:\\] VALIDSIG .* {fpr}$' <<<\"$__fj_sig\"; then\n\
         \x20 rm -f \"$__fj_tmp\" \"$__fj_asc\" \"$__fj_key\"\n\
         \x20 printf '{MARK_FAILED} forgejo %s: release signature is not valid for key {fpr}, not installed\\n' \"$__fj_ver\"\n\
         \x20 exit 1\n\
         fi"
    )
}

/// PATCH body that sets the admin's real password.
fn admin_body(pass: &str) -> String {
    serde_json::json!({ "password": pass, "must_change_password": true }).to_string()
}

fn invalid(field: &str, value: &str, want: &str) -> AnvilError {
    AnvilError::Validation(format!(
        "forgejo.{field}: {value:?} is invalid (must be {want})"
    ))
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Values that land in `app.ini` (static content) are restricted so they can
/// never add a line or a key; secrets only need to be non-empty one-liners.
pub fn validate(c: &ForgejoSection, host_ssh_port: u16) -> Result<()> {
    let hostname = |s: &str| {
        !s.is_empty()
            && !s.starts_with(['.', '-'])
            && !s.contains("..")
            && s.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-')
    };
    if !hostname(&c.domain) {
        return Err(invalid("domain", &c.domain, "a hostname ([A-Za-z0-9.-])"));
    }
    let semver = c.version.split('.').count() == 3
        && c.version
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|ch| ch.is_ascii_digit()));
    if !semver {
        return Err(invalid("version", &c.version, "X.Y.Z, e.g. \"15.0.11\""));
    }
    for (f, v) in [
        ("sha256_amd64", &c.sha256_amd64),
        ("sha256_arm64", &c.sha256_arm64),
    ] {
        if let Some(v) = v {
            if !is_sha256(v) {
                return Err(invalid(f, v, "64 hex characters"));
            }
        }
    }
    match c.deploy.as_str() {
        "native" | "compose" | "quadlet" => {}
        "podman" => {
            return Err(AnvilError::Validation(
                "forgejo.deploy = \"podman\": use \"quadlet\" (Podman) or \"compose\" (Docker)"
                    .into(),
            ))
        }
        other => {
            return Err(invalid(
                "deploy",
                other,
                "\"native\", \"compose\" or \"quadlet\"",
            ))
        }
    }
    if !matches!(c.listen.as_str(), "public" | "tailnet") {
        return Err(invalid("listen", &c.listen, "\"public\" or \"tailnet\""));
    }
    if let Some(d) = &c.image_digest {
        if !d.strip_prefix("sha256:").is_some_and(is_sha256) {
            return Err(invalid(
                "image_digest",
                d,
                "\"sha256:\" + 64 hex characters",
            ));
        }
    }
    if c.deploy != "native" && c.version != DEFAULT_VERSION && c.image_digest.is_none() {
        return Err(AnvilError::Validation(format!(
            "forgejo.version = {:?} with deploy = {:?} needs forgejo.image_digest \
             (the sha256 of codeberg.org/forgejo/forgejo:{}-rootless); only {DEFAULT_VERSION} is built in",
            c.version, c.deploy, c.version
        )));
    }
    if c.http_port == 0 {
        return Err(invalid("http_port", "0", "1-65535"));
    }
    if c.ssh_port != 0
        && (c.ssh_port < 1024 || c.ssh_port == host_ssh_port || c.ssh_port == c.http_port)
    {
        return Err(invalid(
            "ssh_port",
            &c.ssh_port.to_string(),
            "0 (off) or 1024-65535, not the host's SSH port or http_port",
        ));
    }
    match c.database.as_str() {
        "sqlite3" => {}
        "postgres" => {
            let plain = |s: &str| {
                !s.is_empty()
                    && s.chars().all(|ch| {
                        ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '/')
                    })
            };
            for (f, v) in [
                ("db_host", &c.db_host),
                ("db_name", &c.db_name),
                ("db_user", &c.db_user),
                ("db_ssl_mode", &c.db_ssl_mode),
            ] {
                if !plain(v) {
                    return Err(invalid(f, v, "non-empty [A-Za-z0-9._:/-]"));
                }
            }
            if c.db_password.as_deref().is_none_or(|p| p.trim().is_empty()) {
                return Err(AnvilError::Validation(
                    "forgejo.db_password is required with database = \"postgres\" \
                     (e.g. \"${FORGEJO_DB_PASSWORD}\")"
                        .into(),
                ));
            }
        }
        other => return Err(invalid("database", other, "\"sqlite3\" or \"postgres\"")),
    }
    for (f, v) in [
        ("secret_key", &c.secret_key),
        ("internal_token", &c.internal_token),
    ] {
        if v.trim().is_empty() {
            return Err(AnvilError::Validation(format!(
                "forgejo.{f} must not be empty (generate one with `forgejo generate secret {}`)",
                f.to_uppercase()
            )));
        }
    }
    // Forgejo only accepts exactly 32 bytes; anything else it regenerates and
    // tries to save into the read-only app.ini (fatal).
    if URL_SAFE_NO_PAD.decode(c.jwt_secret.trim()).map(|b| b.len()) != Ok(32) {
        return Err(AnvilError::Validation(
            "forgejo.jwt_secret must be base64url without padding for 32 bytes \
             (generate one with `forgejo generate secret JWT_SECRET`)"
                .into(),
        ));
    }
    let admin = [&c.admin_username, &c.admin_email, &c.admin_password];
    let set = admin.iter().filter(|v| v.is_some()).count();
    if set != 0 && set != 3 {
        return Err(AnvilError::Validation(
            "forgejo: set all of admin_username, admin_email and admin_password, or none".into(),
        ));
    }
    if let Some(u) = &c.admin_username {
        let ok = !u.is_empty()
            && u.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
        if !ok {
            return Err(invalid("admin_username", u, "[A-Za-z0-9._-]+"));
        }
    }
    if let Some(e) = &c.admin_email {
        if !e.contains('@') || e.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
            return Err(invalid("admin_email", e, "an email address"));
        }
    }
    // anvil's floor, matching Forgejo's web default MIN_PASSWORD_LENGTH = 8.
    if c.admin_password
        .as_deref()
        .is_some_and(|p| p.chars().count() < 8)
    {
        return Err(AnvilError::Validation(
            "forgejo.admin_password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}

/// What the other sections must provide: Docker for compose (from `[docker]`
/// or a v2 `[github_runner]`, which configure the daemon), `[tailscale]` for
/// a tailnet-only `ssh_port`.
pub fn validate_host(
    c: &ForgejoSection,
    docker: bool,
    podman: bool,
    tailscale: bool,
) -> Result<()> {
    if c.deploy == "compose" && podman {
        return Err(AnvilError::Validation(
            "forgejo.deploy = \"compose\" runs on Docker; this is a Podman host \
             ([podman] or [containers] runtime = \"podman\"). Use deploy = \"quadlet\""
                .into(),
        ));
    }
    if c.deploy == "quadlet" && !podman {
        return Err(AnvilError::Validation(
            "forgejo.deploy = \"quadlet\" needs a Podman host: add [podman] \
             (or [containers] runtime = \"podman\")"
                .into(),
        ));
    }
    if c.deploy == "compose" && !docker {
        return Err(AnvilError::Validation(
            "forgejo.deploy = \"compose\" needs Docker: add [docker] \
             (or a [github_runner] with mode = \"ephemeral\")"
                .into(),
        ));
    }
    if c.listen == "tailnet" && !tailscale {
        return Err(AnvilError::Validation(
            "forgejo.listen = \"tailnet\" needs [tailscale] (ssh_port is opened on tailscale0 only)"
                .into(),
        ));
    }
    Ok(())
}

/// The built-in SSH port is a new public port: ufw must allow it. With
/// `listen = "tailnet"` the module adds its own tailscale0 rule, so a public
/// allow would defeat it.
pub fn warnings(c: &ForgejoSection, firewall: Option<&FirewallSection>) -> Vec<String> {
    let port = c.ssh_port.to_string();
    if c.listen == "tailnet" {
        return match firewall {
            Some(fw) if fw.allow.iter().any(|r| r.port == port && r.from.is_none()) => {
                vec![format!(
                    "forgejo.listen = \"tailnet\", but [firewall].allow opens port {port} to \
                     everyone: git over SSH stays public"
                )]
            }
            _ => Vec::new(),
        };
    }
    match firewall {
        Some(fw) if c.ssh_port != 0 && !fw.allow.iter().any(|r| r.port == port) => vec![format!(
            "forgejo.ssh_port = {port} is not in [firewall].allow: git over SSH will be blocked \
             (add [[firewall.allow]] port = \"{port}\")"
        )],
        _ => Vec::new(),
    }
}

/// FJ7: Forgejo binds 127.0.0.1, so something must proxy `domain` to it.
/// A warning, not an error: the operator may run their own proxy.
pub fn proxy_warnings(
    c: &ForgejoSection,
    tls: Option<&TlsSection>,
    caddy: Option<&CaddySection>,
) -> Vec<String> {
    // Same exact match the registry uses to decide whether to write the nginx snippet.
    if tls.is_some_and(|t| t.domains.contains(&c.domain)) {
        return Vec::new();
    }
    let (d, port) = (&c.domain, c.http_port);
    let site = caddy.and_then(|k| k.sites.iter().find(|s| s.domain.eq_ignore_ascii_case(d)));
    match site {
        None => vec![format!(
            "forgejo: no [tls] or [caddy] site serves {d} -> 127.0.0.1:{port}; \
             Forgejo will be unreachable from outside"
        )],
        Some(s) if s.upstream.rsplit_once(':').map(|(_, p)| p) != Some(&port.to_string()) => {
            vec![format!(
                "forgejo: [[caddy.site]] {d} proxies to {:?}, but Forgejo listens on \
                 127.0.0.1:{port} (forgejo.http_port)",
                s.upstream
            )]
        }
        Some(_) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::OrderOverride;

    const JWT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn section() -> ForgejoSection {
        ForgejoSection {
            domain: "git.example.com".into(),
            version: DEFAULT_VERSION.into(),
            sha256_amd64: None,
            sha256_arm64: None,
            deploy: "native".into(),
            image_digest: None,
            listen: "public".into(),
            http_port: 3000,
            ssh_port: 2222,
            require_signin_view: false,
            actions: false,
            database: "sqlite3".into(),
            db_host: "127.0.0.1:5432".into(),
            db_name: "forgejo".into(),
            db_user: "forgejo".into(),
            db_password: None,
            db_ssl_mode: "disable".into(),
            secret_key: "s3cret-key".into(),
            internal_token: "tok'en".into(),
            jwt_secret: JWT.into(),
            admin_username: Some("boss".into()),
            admin_email: Some("boss@example.com".into()),
            admin_password: Some("pa ss'word".into()),
            order_override: OrderOverride::default(),
        }
    }

    fn with(f: impl FnOnce(&mut ForgejoSection)) -> ForgejoSection {
        let mut c = section();
        f(&mut c);
        c
    }

    fn decl(via_tls: bool) -> Declaration {
        ForgejoModule::new(section(), via_tls).declaration()
    }

    #[test]
    fn app_ini_has_security_defaults_and_no_secrets() {
        let ini = ForgejoModule::new(section(), true).app_ini();
        for needle in [
            "HTTP_ADDR = 127.0.0.1\n",
            "HTTP_PORT = 3000\n",
            "ROOT_URL = https://git.example.com/\n",
            "INSTALL_LOCK = true\n",
            "DISABLE_REGISTRATION = true\n",
            "REQUIRE_SIGNIN_VIEW = false\n",
            "SECRET_KEY_URI = file:/etc/forgejo/secret_key\n",
            "INTERNAL_TOKEN_URI = file:/etc/forgejo/internal_token\n",
            "JWT_SECRET_URI = file:/etc/forgejo/jwt_secret\n",
            "START_SSH_SERVER = true\n",
            "SSH_LISTEN_PORT = 2222\n",
            "WORK_PATH = /var/lib/forgejo\n",
            "DB_TYPE = sqlite3\n",
            "[actions]\nENABLED = false\n",
        ] {
            assert!(ini.contains(needle), "missing {needle:?}");
        }
        for secret in ["s3cret-key", "tok'en", JWT, "pa ss'word"] {
            assert!(!ini.contains(secret), "app.ini leaks {secret}");
        }
    }

    #[test]
    fn app_ini_logs_real_client_ip_to_the_jail_file() {
        // fail2ban's forgejo jail bans the logged IP: it must be the client
        // from Caddy/nginx's X-Forwarded-For, not 127.0.0.1, and land in
        // LOG_FILE in both deploy modes.
        for deploy in ["native", "compose", "quadlet"] {
            let ini = ForgejoModule::new(with(|c| c.deploy = deploy.into()), false).app_ini();
            for needle in [
                "REVERSE_PROXY_LIMIT = 1\n",
                "REVERSE_PROXY_TRUSTED_PROXIES = 127.0.0.0/8,::1/128\n",
                "[log]\nMODE = console, file\nROOT_PATH = /var/lib/forgejo/log\n",
                "[log.file]\nFILE_NAME = forgejo.log\n",
            ] {
                assert!(ini.contains(needle), "{deploy}: missing {needle:?}");
            }
        }
        assert_eq!(LOG_FILE, "/var/lib/forgejo/log/forgejo.log");
    }

    #[test]
    fn actions_flag_is_always_written_explicitly() {
        let on = ForgejoModule::new(with(|c| c.actions = true), false).app_ini();
        assert!(on.contains("[actions]\nENABLED = true\n"));
        assert!(!on.contains("ENABLED = false"));
    }

    #[test]
    fn ssh_off_and_postgres_variants() {
        let m = ForgejoModule::new(
            with(|c| {
                c.ssh_port = 0;
                c.database = "postgres".into();
                c.db_password = Some("dbpw".into());
                c.require_signin_view = true;
            }),
            false,
        );
        let ini = m.app_ini();
        assert!(ini.contains("DISABLE_SSH = true\n") && !ini.contains("START_SSH_SERVER"));
        assert!(ini.contains("DB_TYPE = postgres\n"));
        assert!(ini.contains("PASSWD_URI = file:/etc/forgejo/db_password\n"));
        assert!(ini.contains("REQUIRE_SIGNIN_VIEW = true\n"));
        assert!(!ini.contains("dbpw"));
        assert!(m.unit().contains("After=postgresql.service"));
        let d = m.declaration();
        let pw = d.files.iter().find(|f| f.path == DB_PASSWORD).unwrap();
        assert!(pw.static_content().is_none());
    }

    #[test]
    fn secrets_are_computed_0640_root_git() {
        let d = decl(true);
        for p in [SECRET_KEY, INTERNAL_TOKEN, JWT_SECRET] {
            let f = d.files.iter().find(|f| f.path == p).unwrap();
            assert!(f.static_content().is_none(), "{p} must never be diffed");
            assert_eq!((f.mode.as_str(), f.owner.as_str()), ("0640", "root:git"));
        }
        assert!(!d.files.iter().any(|f| f.path == DB_PASSWORD));
        let ini = d.files.iter().find(|f| f.path == APP_INI).unwrap();
        assert!(ini.static_content().is_some(), "app.ini stays diffable");
    }

    #[test]
    fn secret_generator_prints_the_value_verbatim() {
        let d = decl(true);
        let g = match &d
            .files
            .iter()
            .find(|f| f.path == INTERNAL_TOKEN)
            .unwrap()
            .content
        {
            crate::engine::FileContent::Computed { generator } => generator.clone(),
            _ => panic!("secret file is static"),
        };
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(g)
            .output()
            .unwrap();
        assert_eq!(String::from_utf8(out.stdout).unwrap(), "tok'en");
    }

    #[test]
    fn nginx_snippet_only_with_tls() {
        let snippet = "/etc/nginx/anvil-tls.d/forgejo.conf";
        let d = decl(true);
        let f = d.files.iter().find(|f| f.path == snippet).unwrap();
        let s = f.static_content().unwrap();
        assert!(s.contains("proxy_pass http://127.0.0.1:3000;"));
        assert!(s.contains("proxy_set_header X-Forwarded-Proto $scheme;"));
        assert!(d.reload.as_ref().unwrap().validate.contains("nginx -t"));
        let d = decl(false);
        assert!(!d.files.iter().any(|f| f.path == snippet));
        assert!(!d.reload.as_ref().unwrap().validate.contains("nginx"));
    }

    #[test]
    fn install_verifies_pinned_checksum_before_installing() {
        let c = ForgejoModule::new(section(), true)
            .install_command()
            .converge;
        assert!(c.contains(DEFAULT_SHA256_AMD64) && c.contains(DEFAULT_SHA256_ARM64));
        let dl = c.find("curl -fsSL -o \"$__fj_tmp\"").unwrap();
        let check = c.find("sha256sum -c --status -").unwrap();
        let install = c.find("install -m 0755").unwrap();
        assert!(dl < check && check < install);
        assert!(c.contains("releases/download/v${__fj_ver}/forgejo-${__fj_ver}-linux-${__fj_arch}"));
        for pipe in ["| sh\n", "| sh ", "| bash"] {
            assert!(!c.contains(pipe), "no pipe-to-shell: {pipe:?}");
        }
        let custom = ForgejoModule::new(with(|c| c.sha256_amd64 = Some("ab".repeat(32))), true)
            .install_command();
        assert!(custom.detect.contains(&"ab".repeat(32)));
    }

    #[test]
    fn install_verifies_signature_with_pinned_key_in_a_temp_keyring() {
        let c = ForgejoModule::new(section(), true)
            .install_command()
            .converge;
        let asc = c.find("-o \"$__fj_asc\" \"$__fj_url.asc\"").unwrap();
        let key = c
            .find(&format!(
                "keys.openpgp.org/vks/v1/by-fingerprint/{SIGNING_KEY_FPR}"
            ))
            .unwrap();
        let sha = c.find("sha256sum -c --status -").unwrap();
        let verify = c.find("--status-fd 1 --verify").unwrap();
        let install = c.find("install -m 0755").unwrap();
        assert!(asc < key && key < sha && sha < verify && verify < install);
        assert!(c.contains(&format!("VALIDSIG .* {SIGNING_KEY_FPR}$")));
        assert!(c.contains("grep -q '^\\[GNUPG:\\] REVKEYSIG' <<<\"$__fj_sig\" ||"));
        assert!(c.contains("command -v gpg >/dev/null 2>&1 || { DEBIAN_FRONTEND"));
        // Every gpg call is confined to the throwaway homedir, which is removed.
        assert_eq!(
            c.matches("gpg --").count(),
            c.matches("gpg --homedir \"$__fj_gh\"").count()
        );
        assert!(c.contains("rm -rf \"$__fj_gh\""));
        assert!(!c.contains("GNUPGHOME") && !c.contains("--recv"));
        assert!(c.contains("could not download the release signature or signing key"));
    }

    #[test]
    fn custom_version_without_checksums_is_detected_by_version_and_signed() {
        let m = ForgejoModule::new(with(|c| c.version = "17.0.1".into()), true);
        assert_eq!(m.checksums(), (String::new(), String::new()));
        let cmd = m.install_command();
        assert!(cmd.detect.contains("grep -qiF -- 'version 17.0.1+'"));
        assert!(cmd.detect.contains(&format!("{BIN} --version")));
        assert!(!cmd.detect.contains(DEFAULT_SHA256_AMD64));
        assert!(cmd.converge.contains("--status-fd 1 --verify"));
        // A user checksum for one arch never falls back to the 15.0.11 one.
        let one = ForgejoModule::new(
            with(|c| {
                c.version = "17.0.1".into();
                c.sha256_amd64 = Some("a".repeat(64));
            }),
            true,
        );
        assert_eq!(one.checksums(), ("a".repeat(64), String::new()));
        assert_eq!(
            ForgejoModule::new(section(), true).checksums(),
            (DEFAULT_SHA256_AMD64.into(), DEFAULT_SHA256_ARM64.into())
        );
    }

    #[test]
    fn detect_matches_the_exact_installed_version() {
        let dir = std::env::temp_dir().join(format!("anvil-fjv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("forgejo");
        // Shaped like the real `--version` line (15.0.11+gitea-1.22.0).
        std::fs::write(
            &bin,
            "#!/bin/sh\necho 'Forgejo version 17.0.11+gitea-1.22.0 built with GNU Make'\n",
        )
        .unwrap();
        let run = |v: &str| {
            let d = ForgejoModule::new(with(|c| c.version = v.into()), true)
                .install_command()
                .detect
                .replace("$(dpkg --print-architecture)", "amd64")
                .replace(BIN, &bin.display().to_string());
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("chmod +x {}; {d}", bin.display()))
                .status()
                .unwrap()
                .success()
        };
        assert!(run("17.0.11"));
        assert!(!run("17.0.1") && !run("7.0.11") && !run("17.0.12"));
        // 15.0.11 is sha-pinned, so the version string alone never satisfies it.
        assert!(!run(DEFAULT_VERSION));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Runs [`verify_script`] against a throwaway key: a good signature passes
    /// only when that key's fingerprint is the pinned one.
    #[test]
    fn signature_failure_prints_failed_and_installs_nothing() {
        let has_gpg = std::process::Command::new("gpg")
            .arg("--version")
            .output()
            .is_ok();
        if !has_gpg {
            return; // no gpg on this machine
        }
        // Short path: gpg-agent's socket must fit in sun_path.
        let dir = std::path::PathBuf::from(format!("/tmp/anvil-fjg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("h")).unwrap();
        let sh = |s: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(s)
                .current_dir(&dir)
                .output()
                .unwrap()
        };
        let setup = sh("set -e; chmod 700 h; export GNUPGHOME=$PWD/h
            gpg --batch -q --passphrase '' --quick-gen-key 'anvil test <t@example.invalid>' ed25519 sign never
            echo payload > bin
            gpg --batch -q --armor --detach-sign -o bin.asc bin
            gpg --batch -q --armor --export > key.asc
            gpg --batch --with-colons --list-keys | awk -F: '/^fpr/{print $10; exit}'
            gpgconf --kill all");
        assert!(
            setup.status.success(),
            "{}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let fpr = String::from_utf8(setup.stdout).unwrap().trim().to_string();
        assert_eq!(fpr.len(), 40);
        let verify = |fpr: &str, asc: &str| {
            sh(&format!(
                "set -euo pipefail; cp bin t; cp {asc} a; cp key.asc k
                 __rundir=$PWD; __fj_tmp=t; __fj_asc=a; __fj_key=k; __fj_ver=9.9.9
                 {}
                 echo VERIFIED",
                verify_script(fpr)
            ))
        };
        let ok = verify(&fpr, "bin.asc");
        assert!(ok.status.success());
        assert_eq!(String::from_utf8_lossy(&ok.stdout), "VERIFIED\n");
        std::fs::write(dir.join("bad.asc"), "not a signature").unwrap();
        for (fpr, asc) in [(SIGNING_KEY_FPR, "bin.asc"), (fpr.as_str(), "bad.asc")] {
            let out = verify(fpr, asc);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(!out.status.success(), "{fpr} {asc}");
            assert!(
                stdout.starts_with("FAILED: forgejo 9.9.9: release signature"),
                "{stdout}"
            );
            assert!(!stdout.contains("VERIFIED") && !dir.join("t").exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn checksum_detect_and_mismatch_behave() {
        // Run the real converge/detect against a fake binary path.
        let dir = std::env::temp_dir().join(format!("anvil-fj-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("forgejo");
        std::fs::write(&bin, "hello").unwrap();
        let script = |sha: &str| {
            format!(
                "__fj_sha={sha}; printf '%s  %s\\n' \"$__fj_sha\" {} | sha256sum -c --status - && echo ok || echo bad",
                bin.display()
            )
        };
        let run = |s: String| {
            let out = std::process::Command::new("bash").arg("-c").arg(s).output();
            out.map(|o| String::from_utf8(o.stdout).unwrap())
                .unwrap_or_default()
        };
        // sha256("hello")
        let good = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        if run("command -v sha256sum".into()).is_empty() {
            return; // no coreutils sha256sum on this machine
        }
        assert_eq!(run(script(good)), "ok\n");
        assert_eq!(run(script(&"0".repeat(64))), "bad\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_is_read_only_and_admin_check_needs_a_running_service() {
        let probe = decl(true).render_probe();
        assert!(probe.contains("systemctl is-active --quiet forgejo && runuser -u git -- "));
        for bad in [
            "admin user create",
            "systemctl restart",
            "systemctl start",
            "useradd",
            "install -m",
            "curl -fsSL",
        ] {
            assert!(!probe.contains(bad), "probe must not mutate: {bad}");
        }
        assert!(
            !probe.contains("pa ss"),
            "probe must not carry the admin password"
        );
    }

    #[test]
    fn reload_restarts_on_change_waits_for_health_then_creates_admin() {
        let r = decl(true).reload.unwrap().reload;
        let restart = r.find("systemctl restart forgejo").unwrap();
        let health = r.find("http://127.0.0.1:3000/api/healthz").unwrap();
        let create = r
            .find("runuser -u git -- /usr/local/bin/forgejo --work-path /var/lib/forgejo --config /etc/forgejo/app.ini admin user create --admin --random-password --username 'boss' --email 'boss@example.com'")
            .unwrap();
        assert!(restart < health && health < create);
        // The password is only ever printf's (builtin) argument.
        assert!(!r.contains("--password"));
        assert_eq!(r.matches("pa ss").count(), 1);
        assert!(r.contains(&format!(
            "printf '%s' {} | curl ",
            shell_escape(&admin_body("pa ss'word"))
        )));
        assert!(r.contains("/etc/forgejo/app.ini|"));
        assert!(r.contains("/etc/nginx/anvil-tls.d/forgejo.conf) __fj_ng=1"));
        assert!(r.contains("systemctl reload nginx"));
        // No admin configured → no CLI create.
        let r = ForgejoModule::new(
            with(|c| {
                c.admin_username = None;
                c.admin_email = None;
                c.admin_password = None;
            }),
            true,
        )
        .declaration()
        .reload
        .unwrap()
        .reload;
        assert!(!r.contains("admin user create"));
    }

    /// Runs the bootstrap with `runuser`/`curl`/`base64` stubbed.
    fn bootstrap(curl_rc: u8, created: &str) -> (bool, String, String) {
        let m = ForgejoModule::new(
            with(|c| c.admin_password = Some("p\"a\\ ss'w".into())),
            true,
        );
        let script = format!(
            "T=$(mktemp -d); trap 'rm -rf \"$T\"' EXIT\n\
             systemctl() {{ return 1; }}\n\
             runuser() {{ echo \"$*\" >> \"$T/argv\"; case \"$*\" in *' create '*) printf '%b' \"$C\";; esac; }}\n\
             curl() {{ echo \"$*\" >> \"$T/argv\"; while [ \"$1\" != -K ]; do shift; done; cat \"$2\" > \"$T/cfg\"; cat > \"$T/body\"; return $CR; }}\n\
             base64() {{ cat; }}\n\
             CR={curl_rc} C={created} rc=0\n\
             {} || rc=$?\n\
             echo \"rc=$rc\"; cat \"$T/cfg\" \"$T/body\" 2>/dev/null; echo; echo ARGV; cat \"$T/argv\"",
            m.admin_bootstrap("boss", "boss@example.com", "p\"a\\ ss'w"),
            created = shell_escape(created),
        );
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&out.stdout).into_owned();
        let (res, argv) = out.split_once("\nARGV\n").unwrap();
        (res.starts_with("rc=0\n"), res.to_string(), argv.to_string())
    }

    #[test]
    fn admin_bootstrap_sets_the_password_through_the_api_never_argv() {
        let rand = "generated random password is 'r\"a n'd'\\nNew user 'boss' has been successfully created!\\n";
        let (ok, res, argv) = bootstrap(0, rand);
        assert!(ok, "{res}");
        assert!(
            res.contains("header = \"Authorization: Basic boss:r\"a n'd\"\n"),
            "{res}"
        );
        assert!(res.contains(&admin_body("p\"a\\ ss'w")), "{res}");
        assert!(argv.contains("admin user create --admin --random-password --username boss"));
        assert!(argv.contains("-X PATCH") && argv.contains("/api/v1/admin/users/boss"));
        assert!(!argv.contains("ss'w") && !argv.contains("r\"a n"), "{argv}");
        assert!(!argv.contains("delete"));
        // PATCH refused, or create printed no password: FAILED and the user goes.
        for (rc, created) in [
            (22, rand),
            (0, "New user 'boss' has been successfully created!\\n"),
        ] {
            let (ok, res, argv) = bootstrap(rc, created);
            assert!(!ok);
            assert!(
                res.contains("FAILED: forgejo admin boss: password not set"),
                "{res}"
            );
            assert!(argv.contains("admin user delete --username boss"), "{argv}");
        }
    }

    #[test]
    fn admin_check_matches_the_username_column_exactly() {
        let awk = "awk -v n='boss' 'NR>1 && $2==n {f=1} END {exit !f}'";
        let run = |input: &str| {
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("printf '%b' '{input}' | {awk} && echo y || echo n"))
                .output()
                .map(|o| String::from_utf8(o.stdout).unwrap())
                .unwrap()
        };
        let header = "ID   Username Email IsActive IsAdmin 2FA\\n";
        assert_eq!(
            run(&format!("{header}1    boss     b@x  true true false\\n")),
            "y\n"
        );
        assert_eq!(
            run(&format!("{header}1    bossy    b@x  true true false\\n")),
            "n\n"
        );
        assert_eq!(run(header), "n\n");
        assert!(ForgejoModule::new(section(), true)
            .admin_exists("boss")
            .contains(awk));
    }

    #[test]
    fn rollback_stops_service_and_never_touches_data() {
        let rb = decl(true).render_rollback();
        let files = rb.find("/etc/forgejo/app.ini").unwrap();
        let stop = rb.find("systemctl stop forgejo").unwrap();
        let reload = rb.find("reload with the restored config").unwrap();
        assert!(files < stop && stop < reload);
        for bad in ["rm -rf", "userdel", "/var/lib/forgejo/", "rm -f /var/lib"] {
            assert!(!rb.contains(bad), "rollback must keep data: {bad}");
        }
    }

    #[test]
    fn binary_is_recorded_when_created_and_removed_only_then() {
        let conv = ForgejoModule::new(section(), false)
            .install_command()
            .converge;
        let remember = conv
            .find("[ -e /usr/local/bin/forgejo ] || __anvil_remember /usr/local/bin/forgejo\n")
            .unwrap();
        let install = conv.find("install -m 0755").unwrap();
        assert!(remember < install, "record before the binary exists");

        let rb = decl(false).render_rollback();
        let stop = rb.find("systemctl stop forgejo").unwrap();
        let gate = rb
            .find("if [ ! -f /etc/systemd/system/forgejo.service ] && __anvil_created /usr/local/bin/forgejo; then")
            .unwrap();
        let rm = rb.find("rm -f /usr/local/bin/forgejo\n").unwrap();
        assert!(stop < gate && gate < rm);
        assert!(rb.contains("__anvil_forget /usr/local/bin/forgejo"));
        for bad in ["apt-get remove", "apt-get purge", "rm -rf"] {
            assert!(!rb.contains(bad), "rollback must keep packages/data: {bad}");
        }
    }

    #[test]
    fn apps_slice_is_opt_in_in_every_deploy_mode() {
        let on = |m: ForgejoModule| m.in_apps_slice(true);
        assert_eq!(
            on(compose(|_| {}))
                .compose_yaml()
                .matches("cgroup_parent: apps.slice\n")
                .count(),
            1,
            "every compose service needs it (docker creates the scope under it)"
        );
        for unit in [
            on(compose(|_| {})).unit(),
            on(quadlet(|_| {})).quadlet_template(),
            on(ForgejoModule::new(section(), false)).unit(),
        ] {
            assert!(
                unit.contains("[Service]\n") && unit.contains("\nSlice=apps.slice\n"),
                "Slice= belongs to [Service]:\n{unit}"
            );
        }
        for off in [
            compose(|_| {}).compose_yaml(),
            compose(|_| {}).unit(),
            quadlet(|_| {}).quadlet_template(),
            ForgejoModule::new(section(), false).unit(),
        ] {
            assert!(!off.contains("apps.slice"), "{off}");
        }
    }

    #[test]
    fn every_script_parses_under_bash_n_including_admin_and_postgres() {
        // The init --full gate has no admin or postgres; cover them here.
        let m = ForgejoModule::new(
            with(|c| {
                c.database = "postgres".into();
                c.db_password = Some("p'w".into());
            }),
            true,
        );
        let d = m.declaration();
        for script in [d.render_probe(), d.render_apply(), d.render_rollback()] {
            let out = std::process::Command::new("bash")
                .arg("-n")
                .stdin(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut ch| {
                    use std::io::Write as _;
                    ch.stdin.take().unwrap().write_all(script.as_bytes())?;
                    ch.wait_with_output()
                });
            if let Ok(o) = out {
                assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
            }
        }
    }

    fn compose(f: impl FnOnce(&mut ForgejoSection)) -> ForgejoModule {
        ForgejoModule::new(
            with(|c| {
                c.deploy = "compose".into();
                f(c);
            }),
            false,
        )
    }

    fn bash_n(script: &str) {
        let out = std::process::Command::new("bash")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write as _;
                ch.stdin.take().unwrap().write_all(script.as_bytes())?;
                ch.wait_with_output()
            });
        if let Ok(o) = out {
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        }
    }

    #[test]
    fn compose_file_is_pinned_hardened_and_publishes_nothing() {
        let m = compose(|_| {});
        let y = m.compose_yaml();
        for needle in [
            &format!(
                "image: codeberg.org/forgejo/forgejo:15.0.11-rootless@{DEFAULT_IMAGE_DIGEST}\n"
            ),
            "user: \"${FORGEJO_UID:?}:${FORGEJO_GID:?}\"\n",
            "userns_mode: host\n",
            "network_mode: host\n",
            "read_only: true\n",
            "cap_drop: [ALL]\n",
            "security_opt: [\"no-new-privileges:true\"]\n",
            "mem_limit: 2g\n",
            "pids_limit: 1024\n",
            "restart: unless-stopped\n",
            "- /var/lib/forgejo:/var/lib/forgejo\n",
            "- /etc/forgejo:/etc/forgejo:ro\n",
            "- /var/lib/gitea\n",
            "USER: git\n",
            "\"--config\", \"/etc/forgejo/app.ini\"",
        ] {
            assert!(y.contains(needle), "missing {needle:?}");
        }
        for bad in [
            "ports:",
            "0.0.0.0",
            "privileged",
            "s3cret-key",
            "pa ss",
            "logging:",
        ] {
            assert!(!y.contains(bad), "compose.yaml must not contain {bad:?}");
        }
        // Never the 15.0.11 digest for another version (validation demands one).
        let bare = compose(|c| c.version = "17.0.1".into()).image();
        assert!(!bare.contains(DEFAULT_IMAGE_DIGEST), "{bare}");
        // Same app.ini in both modes.
        assert_eq!(m.app_ini(), ForgejoModule::new(section(), false).app_ini());
        let custom = compose(|c| {
            c.version = "17.0.1".into();
            c.image_digest = Some(format!("sha256:{}", "c".repeat(64)));
        });
        assert!(custom.compose_yaml().contains(&format!(
            "forgejo:17.0.1-rootless@sha256:{}\n",
            "c".repeat(64)
        )));
    }

    #[test]
    fn compose_mode_declares_files_docker_and_no_binary() {
        let d = compose(|_| {}).declaration();
        let f = d.files.iter().find(|f| f.path == COMPOSE_PATH).unwrap();
        assert!(f.static_content().is_some(), "compose.yaml stays diffable");
        let env = d.files.iter().find(|f| f.path == COMPOSE_ENV).unwrap();
        assert!(env.static_content().is_none());
        let unit = d.files.iter().find(|f| f.path == UNIT_PATH).unwrap();
        let unit = unit.static_content().unwrap();
        assert!(unit.contains("Type=oneshot\nRemainAfterExit=yes\n"));
        assert!(unit.contains("--env-file /etc/forgejo/compose.env up -d --wait"));
        assert!(unit.contains("ExecStop=/usr/bin/docker compose -p forgejo down\n"));
        let apply = d.render_apply();
        assert!(
            apply.contains("docker pull -q 'codeberg.org/forgejo/forgejo:15.0.11-rootless@sha256:")
        );
        assert!(apply.contains("needs Docker with the compose v2 plugin"));
        assert!(!apply.contains("releases/download"), "no binary download");
        let r = d.reload.unwrap();
        // Rollback removes compose.yaml before this validate runs.
        assert!(r.validate.contains(
            "{ [ ! -f /etc/forgejo/compose.yaml ] || docker compose -p forgejo -f /etc/forgejo/compose.yaml \
             --env-file /etc/forgejo/compose.env config -q; }"
        ));
        assert!(r
            .reload
            .contains("docker exec forgejo /app/gitea/gitea --work-path /var/lib/forgejo --config /etc/forgejo/app.ini admin user create --admin --random-password"));
        assert!(r
            .reload
            .contains("/etc/forgejo/compose.yaml|/etc/forgejo/compose.env|/etc/containers/systemd/forgejo.container) __fj_restart=1"));
        assert!(r
            .reload
            .contains("docker exec forgejo /app/gitea/gitea --work-path"));
        assert!(r.reload.contains("(docker logs forgejo)"));
        // Native has none of it, but takes a leftover compose project down first.
        let n = decl(false);
        assert!(!n
            .files
            .iter()
            .any(|f| f.path == COMPOSE_PATH || f.path == COMPOSE_ENV));
        let ng = n.reload.unwrap();
        assert!(!ng.validate.contains("docker compose"));
        let nr = ng.reload;
        let down = nr.find("docker compose -p forgejo down").unwrap();
        assert!(down < nr.find("systemctl restart forgejo").unwrap());
        assert!(!r.reload.contains("[ ! -f /etc/forgejo/compose.yaml ]"));
    }

    #[test]
    fn compose_env_generator_prints_the_git_uid() {
        let d = compose(|_| {}).declaration();
        let g = match &d
            .files
            .iter()
            .find(|f| f.path == COMPOSE_ENV)
            .unwrap()
            .content
        {
            crate::engine::FileContent::Computed { generator } => {
                generator.replace(" git 2>", " root 2>")
            }
            _ => panic!("compose.env is static"),
        };
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(g)
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "FORGEJO_UID=0\nFORGEJO_GID=0\n"
        );
    }

    #[test]
    fn compose_probe_is_read_only_and_checks_the_container() {
        let probe = compose(|_| {}).declaration().render_probe();
        assert!(probe.contains("docker inspect -f '{{.State.Running}}' forgejo"));
        for bad in [
            "docker pull",
            " up -d",
            "compose -p forgejo down",
            "admin user create",
            "ufw allow",
        ] {
            assert!(!probe.contains(bad), "probe must not mutate: {bad}");
        }
    }

    #[test]
    fn compose_rollback_downs_the_project_and_keeps_data_and_image() {
        let rb = compose(|_| {}).declaration().render_rollback();
        let files = rb.find("/etc/forgejo/compose.yaml").unwrap();
        let down = rb.find("docker compose -p forgejo down").unwrap();
        assert!(files < down);
        assert!(rb.contains("label=com.docker.compose.project=forgejo"));
        for bad in [
            "rm -rf",
            "/var/lib/forgejo/",
            "docker rmi",
            "image rm",
            "volume rm",
            "down -v",
        ] {
            assert!(!rb.contains(bad), "rollback must keep data/image: {bad}");
        }
        assert!(!decl(false)
            .render_rollback()
            .contains("label=com.docker.compose.project"));
    }

    /// After rollback removed /etc/forgejo/*, the validate in the
    /// rendered rollback must pass (here docker always fails), in both modes.
    #[test]
    fn rollback_validate_passes_once_forgejo_files_are_gone() {
        let bin = std::env::temp_dir().join(format!("anvil-fj-210-{}", std::process::id()));
        std::fs::create_dir_all(&bin).unwrap();
        let docker = bin.join("docker");
        std::fs::write(&docker, "#!/bin/sh\nexit 1\n").unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o755)).unwrap();
        for m in [compose(|_| {}), ForgejoModule::new(section(), false)] {
            let d = m.declaration();
            let v = d.reload.as_ref().unwrap().validate.clone();
            assert!(d.render_rollback().contains(&format!("if {{ {v}\n}}")));
            let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
            let ok = std::process::Command::new("bash")
                .args(["-euo", "pipefail", "-c", &v])
                .env("PATH", path)
                .status()
                .unwrap()
                .success();
            assert!(ok || std::path::Path::new(CONF_DIR).exists(), "{v}");
        }
        std::fs::remove_dir_all(&bin).unwrap();
    }

    #[test]
    fn tailnet_listen_adds_a_tailscale0_rule_in_both_modes() {
        let rule = "ufw allow in on tailscale0 to any port 2222 proto tcp";
        for deploy in ["native", "compose", "quadlet"] {
            let d = ForgejoModule::new(
                with(|c| {
                    c.deploy = deploy.into();
                    c.listen = "tailnet".into();
                }),
                false,
            )
            .declaration();
            let apply = d.render_apply();
            let active = apply.find("needs an active ufw").unwrap();
            assert!(active < apply.find(rule).unwrap(), "{deploy}");
            assert!(d
                .render_rollback()
                .contains("ufw delete allow in on tailscale0 to any port 2222 proto tcp"));
        }
        assert!(!decl(false).render_apply().contains("tailscale0"));
        let off = ForgejoModule::new(
            with(|c| {
                c.listen = "tailnet".into();
                c.ssh_port = 0;
            }),
            false,
        );
        assert!(!off.declaration().render_apply().contains("tailscale0"));
    }

    #[test]
    fn compose_and_tailnet_scripts_parse_under_bash_n() {
        let m = compose(|c| {
            c.listen = "tailnet".into();
            c.database = "postgres".into();
            c.db_password = Some("p'w".into());
        });
        let d = ForgejoModule::new(m.cfg.clone(), true).declaration();
        for script in [d.render_probe(), d.render_apply(), d.render_rollback()] {
            bash_n(&script);
        }
    }

    fn quadlet(f: impl FnOnce(&mut ForgejoSection)) -> ForgejoModule {
        ForgejoModule::new(
            with(|c| {
                c.deploy = "quadlet".into();
                f(c);
            }),
            false,
        )
    }

    #[test]
    fn quadlet_mirrors_the_compose_container_and_publishes_nothing() {
        let q = quadlet(|_| {}).quadlet_template();
        for needle in [
            &format!("Image=codeberg.org/forgejo/forgejo:15.0.11-rootless@{DEFAULT_IMAGE_DIGEST}\n"),
            "ContainerName=forgejo\n",
            "User=@FORGEJO_UID@\nGroup=@FORGEJO_GID@\n",
            "Network=host\n",
            "ReadOnly=true\n",
            "Tmpfs=/var/lib/gitea\n",
            "DropCapability=all\n",
            "NoNewPrivileges=true\n",
            "Volume=/var/lib/forgejo:/var/lib/forgejo\n",
            "Volume=/etc/forgejo:/etc/forgejo:ro\n",
            "PodmanArgs=--init --entrypoint=/app/gitea/gitea --memory=2g --cpu-shares=512 --pids-limit=1024\n",
            "Exec=web --config /etc/forgejo/app.ini --work-path /var/lib/forgejo\n",
            "Restart=always\n",
            "WantedBy=multi-user.target\n",
        ] {
            assert!(q.contains(needle), "missing {needle:?}");
        }
        for bad in [
            "PublishPort",
            "0.0.0.0",
            "s3cret-key",
            "tok'en",
            "pa ss",
            "docker",
        ] {
            assert!(!q.contains(bad), "the Quadlet must not contain {bad:?}");
        }
        assert!(quadlet(|c| c.database = "postgres".into())
            .quadlet_template()
            .contains("After=postgresql.service\n"));
    }

    #[test]
    fn quadlet_generator_fills_the_git_uid_and_gid() {
        let m = quadlet(|_| {});
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "id() {{ case $1 in -u) echo 997;; -g) echo 996;; esac; }}\n{}",
                m.quadlet_generator()
            ))
            .output()
            .unwrap();
        let got = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            got,
            m.quadlet_template()
                .replace("@FORGEJO_UID@", "997")
                .replace("@FORGEJO_GID@", "996")
        );
    }

    #[test]
    fn quadlet_mode_runs_on_podman_with_the_same_files_and_bootstrap() {
        let d = quadlet(|_| {}).declaration();
        let f = d.files.iter().find(|f| f.path == QUADLET_PATH).unwrap();
        assert!(f.static_content().is_none(), "host uid: computed");
        assert!(
            !d.files.iter().any(|f| f.path == UNIT_PATH),
            "a file there would shadow the generated forgejo.service"
        );
        for p in [APP_INI, SECRET_KEY, INTERNAL_TOKEN, JWT_SECRET] {
            assert!(d.files.iter().any(|f| f.path == p), "{p}");
        }
        let apply = d.render_apply();
        assert!(apply.contains("a Podman host needs Podman >= 4.4"));
        assert!(
            apply.contains("podman pull -q 'codeberg.org/forgejo/forgejo:15.0.11-rootless@sha256:")
        );
        assert!(apply.contains(&format!("[ ! -e {UNIT_PATH} ]")));
        assert!(apply.contains("would shadow the Quadlet"));
        for bad in ["docker", "releases/download"] {
            assert!(!apply.contains(bad), "{bad}");
        }
        let r = d.reload.as_ref().unwrap();
        assert!(r.validate.contains("---forgejo.service---"));
        assert!(r
            .reload
            .contains(&format!("if [ -f {QUADLET_PATH} ]; then")));
        assert!(r.reload.contains(
            "podman exec forgejo /app/gitea/gitea --work-path /var/lib/forgejo --config /etc/forgejo/app.ini admin user create --admin --random-password"
        ));
        assert!(r
            .reload
            .contains("podman exec forgejo /app/gitea/gitea --work-path"));
        assert!(!r.reload.contains("compose -p forgejo down"));
        let rb = d.render_rollback();
        assert!(rb.contains(&format!("if [ -f {QUADLET_PATH} ]; then")));
        assert!(rb.contains("systemctl stop forgejo"));
        for bad in ["rm -rf", "/var/lib/forgejo/", "podman rmi"] {
            assert!(!rb.contains(bad), "{bad}");
        }
        for s in [d.render_probe(), apply, rb] {
            bash_n(&s);
        }
    }

    #[test]
    fn quadlet_probe_is_read_only() {
        let probe = quadlet(|_| {}).declaration().render_probe();
        for bad in [
            "podman pull",
            "systemctl restart",
            "systemctl stop",
            "would shadow",
        ] {
            assert!(!probe.contains(bad), "{bad}");
        }
        assert!(probe.contains("podman image inspect"));
    }

    #[test]
    fn compose_validation() {
        let ok = |f: fn(&mut ForgejoSection)| validate(&with(f), 22).is_ok();
        assert!(ok(|c| c.deploy = "compose".into()));
        assert!(ok(|c| c.listen = "tailnet".into()));
        assert!(!ok(|c| c.deploy = "docker".into()));
        assert!(!ok(|c| c.deploy = "podman".into()));
        assert!(!ok(|c| c.listen = "private".into()));
        // A non-default version needs its digest in compose mode only.
        assert!(!ok(|c| {
            c.deploy = "compose".into();
            c.version = "17.0.1".into();
        }));
        assert!(ok(|c| c.version = "17.0.1".into()));
        assert!(ok(|c| {
            c.deploy = "compose".into();
            c.version = "17.0.1".into();
            c.image_digest = Some(format!("sha256:{}", "a".repeat(64)));
        }));
        assert!(!ok(|c| c.image_digest = Some("a".repeat(64))));
        assert!(!ok(
            |c| c.image_digest = Some(format!("sha256:{}", "g".repeat(64)))
        ));
        let podman = validate(&with(|c| c.deploy = "podman".into()), 22).unwrap_err();
        assert!(podman.to_string().contains("use \"quadlet\""));
        assert!(ok(|c| c.deploy = "quadlet".into()));
        assert!(!ok(|c| {
            c.deploy = "quadlet".into();
            c.version = "17.0.1".into();
        }));

        let host = |f: fn(&mut ForgejoSection), docker, podman, ts| {
            validate_host(&with(f), docker, podman, ts).is_ok()
        };
        let comp: fn(&mut ForgejoSection) = |c| c.deploy = "compose".into();
        let tail: fn(&mut ForgejoSection) = |c| c.listen = "tailnet".into();
        assert!(host(|_| {}, false, true, false), "native needs nothing");
        assert!(host(comp, true, false, false));
        assert!(!host(comp, false, false, false));
        assert!(!host(comp, true, true, false));
        let quad: fn(&mut ForgejoSection) = |c| c.deploy = "quadlet".into();
        assert!(host(quad, false, true, false));
        assert!(!host(quad, true, false, false));
        assert!(host(tail, false, false, true));
        assert!(!host(tail, false, false, false));
    }

    #[test]
    fn validation_accepts_defaults_and_rejects_bad_values() {
        assert!(validate(&section(), 22).is_ok());
        let bad: Vec<(&str, ForgejoSection)> = vec![
            (
                "domain",
                with(|c| c.domain = "git.example.com\nX = 1".into()),
            ),
            ("version", with(|c| c.version = "15.0".into())),
            ("sha", with(|c| c.sha256_arm64 = Some("xyz".into()))),
            (
                "sha non-hex",
                with(|c| c.sha256_arm64 = Some("g".repeat(64))),
            ),
            ("sha short", with(|c| c.sha256_arm64 = Some("a".repeat(63)))),
            ("ssh_port=22", with(|c| c.ssh_port = 22)),
            ("ssh_port=http", with(|c| c.ssh_port = 3000)),
            ("db", with(|c| c.database = "mysql".into())),
            ("pg pw", with(|c| c.database = "postgres".into())),
            (
                "pg host",
                with(|c| {
                    c.database = "postgres".into();
                    c.db_password = Some("x".into());
                    c.db_host = "h\nINSTALL_LOCK = false".into();
                }),
            ),
            ("secret", with(|c| c.secret_key = " ".into())),
            ("jwt", with(|c| c.jwt_secret = "short".into())),
            ("partial admin", with(|c| c.admin_password = None)),
            (
                "admin name",
                with(|c| c.admin_username = Some("a b".into())),
            ),
            (
                "admin pw",
                with(|c| c.admin_password = Some("short".into())),
            ),
        ];
        for (what, c) in bad {
            assert!(validate(&c, 22).is_err(), "{what} must be rejected");
        }
        let custom = with(|c| {
            c.version = "17.0.1".into();
            c.sha256_amd64 = Some("a".repeat(64));
            c.sha256_arm64 = Some("b".repeat(64));
        });
        assert!(validate(&custom, 22).is_ok());
        assert!(validate(&with(|c| c.ssh_port = 0), 22).is_ok());
    }

    #[test]
    fn validation_checks_each_rule_on_its_own() {
        // Each case changes one field of an otherwise valid config, so a
        // rejection can only come from the rule under test.
        let pinned = |v: &str| {
            let v = v.to_string();
            with(move |c| {
                c.version = v;
                c.sha256_amd64 = Some("a".repeat(64));
                c.sha256_arm64 = Some("b".repeat(64));
            })
        };
        assert!(validate(&pinned("17.0.1"), 22).is_ok());
        for v in ["15.0", "15.0.x", "15..1", "15.0.1.2"] {
            assert!(validate(&pinned(v), 22).is_err(), "version {v:?}");
        }
        // The signature covers a custom version; checksums are optional extras.
        assert!(validate(&with(|c| c.version = "17.0.1".into()), 22).is_ok());
        let one = with(|c| {
            c.version = "17.0.1".into();
            c.sha256_amd64 = Some("a".repeat(64));
        });
        assert!(validate(&one, 22).is_ok());

        let ssh = |p: u16, host: u16| validate(&with(|c| c.ssh_port = p), host).is_ok();
        assert!(ssh(1024, 22) && ssh(2222, 22));
        assert!(!ssh(1023, 22) && !ssh(2222, 2222) && !ssh(3000, 22));

        let pg = |f: fn(&mut ForgejoSection)| {
            validate(
                &with(|c| {
                    c.database = "postgres".into();
                    c.db_password = Some("pw".into());
                    f(c);
                }),
                22,
            )
            .is_ok()
        };
        assert!(pg(|_| {}), "a valid postgres config is accepted");
        assert!(pg(|c| c.db_host = "db.internal:5432".into()));
        assert!(pg(|c| c.db_host = "/run/postgresql".into()));
        assert!(!pg(|c| c.db_name = String::new()));
        assert!(!pg(|c| c.db_user = "a b".into()));
        assert!(!pg(|c| c.db_ssl_mode = "x;y".into()));
        assert!(!pg(|c| c.db_password = Some(" ".into())));

        let email = |e: &str| {
            let e = e.to_string();
            validate(&with(move |c| c.admin_email = Some(e)), 22).is_ok()
        };
        assert!(email("a@example.com"));
        assert!(!email("example.com") && !email("a b@example.com") && !email("a@x\n"));
        assert!(validate(&with(|c| c.admin_password = Some("12345678".into())), 22).is_ok());
    }

    #[test]
    fn warns_when_firewall_does_not_allow_the_ssh_port() {
        let fw = |ports: &[&str]| FirewallSection {
            default_incoming: "deny".into(),
            default_outgoing: "allow".into(),
            restrict_ssh: true,
            allow: ports
                .iter()
                .map(|p| crate::config::schema::WallRule {
                    port: p.to_string(),
                    proto: None,
                    from: None,
                    comment: None,
                })
                .collect(),
            deny: vec![],
            order_override: OrderOverride::default(),
        };
        assert_eq!(warnings(&section(), Some(&fw(&["443"]))).len(), 1);
        assert!(warnings(&section(), Some(&fw(&["2222"]))).is_empty());
        assert!(warnings(&section(), None).is_empty());
        assert!(warnings(&with(|c| c.ssh_port = 0), Some(&fw(&[]))).is_empty());
        // Tailnet: the module owns the rule; only a public allow warns.
        let tn = with(|c| c.listen = "tailnet".into());
        assert!(warnings(&tn, Some(&fw(&["443"]))).is_empty());
        assert!(warnings(&tn, None).is_empty());
        assert!(warnings(&tn, Some(&fw(&["2222"])))[0].contains("stays public"));
    }

    #[test]
    fn proxy_warnings_need_tls_or_a_matching_caddy_site() {
        let tls = |d: &str| TlsSection {
            provider: "certbot".into(),
            domains: vec![d.into()],
            email: None,
            webroot: None,
            order_override: OrderOverride::default(),
        };
        let caddy = |d: &str, up: &str| CaddySection {
            email: None,
            ca: "letsencrypt".into(),
            http_port: 80,
            https_port: 443,
            hsts: true,
            listen: "public".into(),
            sites: vec![crate::config::schema::CaddySite {
                domain: d.into(),
                upstream: up.into(),
                allow: vec![],
                basic_auth: None,
                tls: "acme".into(),
                dns_provider: None,
                dns_token: None,
            }],
            order_override: OrderOverride::default(),
        };
        let c = section();
        let none = proxy_warnings(&c, None, None);
        assert_eq!(
            none,
            vec![
                "forgejo: no [tls] or [caddy] site serves git.example.com -> 127.0.0.1:3000; \
                  Forgejo will be unreachable from outside"
            ]
        );
        // [tls] covering the domain: the nginx snippet proxies it.
        assert!(proxy_warnings(&c, Some(&tls("git.example.com")), None).is_empty());
        assert_eq!(
            proxy_warnings(&c, Some(&tls("other.example.com")), None),
            none
        );
        // A caddy site for the domain on the right port (host spelling and case don't matter).
        let ok = caddy("Git.Example.com", "localhost:3000");
        assert!(proxy_warnings(&c, None, Some(&ok)).is_empty());
        assert_eq!(
            proxy_warnings(&c, None, Some(&caddy("x.example.com", "127.0.0.1:3000"))),
            none
        );
        // Right domain, wrong port.
        let wrong = proxy_warnings(&c, None, Some(&caddy("git.example.com", "127.0.0.1:30000")));
        assert_eq!(wrong.len(), 1);
        assert!(
            wrong[0].contains("\"127.0.0.1:30000\"") && wrong[0].contains("127.0.0.1:3000 "),
            "{wrong:?}"
        );
    }
}
