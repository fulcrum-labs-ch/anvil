//! The config load pipeline (R49): parse TOML → resolve `include`s →
//! apply `profile` defaults (built-in or custom) → extract plugin-bound
//! sections → deserialize. `profile`/`include` keys are consumed and removed
//! before module deserialization, and so are the sections bound by discovered
//! plugins — they are unknown keys to the module schema.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use toml::value::{Table, Value};

use crate::config::Config;
use crate::error::{AnvilError, Result};

/// Built-in profile names (R94, Fixed Contract).
pub const BUILTIN_PROFILES: &[&str] = &["minimal", "cis-level1", "web-server", "ci-runner"];

/// Default custom-profile directory: `~/.config/anvil/profiles`
/// ($XDG_CONFIG_HOME honored, R94); `None` when there is no absolute config
/// home.
pub fn default_profiles_dir() -> Option<PathBuf> {
    crate::plugin::config_home().map(|h| h.join("anvil").join("profiles"))
}

/// Knobs for [`load_with`]. Both are injectable for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions<'a> {
    /// Section names bound by discovered plugins; extracted (with their
    /// key/value tables) before module deserialization.
    pub plugin_sections: &'a [String],
    /// Custom-profile directory (`None` = [`default_profiles_dir`]).
    pub profiles_dir: Option<&'a Path>,
}

/// A loaded config plus the plugin-bound section tables that were extracted
/// from it (for `{{VAR}}` substitution).
#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    /// Section name → its key/value table, for every enabled plugin section.
    pub plugin_values: BTreeMap<String, Table>,
}

/// Load and structurally deserialize a config file, with plugin-section
/// extraction and an injectable profile directory. The returned
/// [`Config`] is **not** yet validated (call [`Config::validate`]).
pub fn load_with(path: impl AsRef<Path>, opts: &LoadOptions) -> Result<Loaded> {
    let path = path.as_ref();
    let mut visiting: Vec<PathBuf> = Vec::new();
    let mut done: BTreeSet<PathBuf> = BTreeSet::new();
    let mut merged = resolve_file(path, &mut visiting, &mut done)?;

    // Consume the top-level profile (includes' own `profile` keys are ignored).
    let profile = match merged.remove("profile") {
        Some(Value::String(name)) => Some(name),
        Some(other) => {
            return Err(AnvilError::ConfigParse(format!(
                "top-level `profile` must be a string, got {}",
                other.type_str()
            )))
        }
        None => None,
    };

    if let Some(name) = profile {
        let mut base = resolve_profile(&name, opts.profiles_dir)?;
        // Profile supplies defaults; the user's keys override. A user-set
        // array REPLACES the profile's — appending to a defaults layer would
        // make the user's value unremovable (R94).
        merge(&mut base, merged, ArrayMerge::Replace);
        merged = base;
    }

    // Expand ${VAR}/${VAR:-default} in every string value from the
    // environment, so secrets need not be committed to the config file. Applied
    // after include/profile resolution and before plugin-section extraction, so
    // plugin-bound sections get it too.
    substitute_env(&mut merged, &done)?;

    // Extract plugin-bound sections: to the module schema they are
    // unknown keys, so they must leave the table before deserialization —
    // exactly how `profile`/`include` were consumed above. Reserved built-in
    // keys are never extracted, so a plugin can't shadow a real module. A
    // section bound by no plugin still trips `deny_unknown_fields` below
    // (typo safety).
    let mut plugin_values: BTreeMap<String, Table> = BTreeMap::new();
    for section in opts.plugin_sections {
        if crate::config::is_reserved_section(section) {
            continue;
        }
        match merged.remove(section.as_str()) {
            None => {}
            Some(Value::Table(t)) => {
                plugin_values.insert(section.clone(), t);
            }
            Some(other) => {
                return Err(AnvilError::ConfigParse(format!(
                    "plugin section `{section}` must be a table, got {}",
                    other.type_str()
                )))
            }
        }
    }

    let config: Config = Value::Table(merged)
        .try_into()
        .map_err(|e: toml::de::Error| AnvilError::ConfigParse(e.to_string()))?;
    Ok(Loaded {
        config,
        plugin_values,
    })
}

/// Recursively expand `${VAR}` and `${VAR:-default}` in every string value
/// of a TOML table (including arrays and nested tables), in place. Secrets need
/// not be committed to the config file this way — they come from the operator's
/// environment (or a profile/include that already resolved). An undefined VAR
/// with no default is a hard error, so a missing secret fails at load rather
/// than silently becoming an empty string (the plugin undefined-variable rule,
/// applied to config).
///
/// Every unset variable is reported at once, each with the key that uses it
/// and its `file:line` in the config files read (`files`), so the operator
/// sees what to export before anything runs.
fn substitute_env(table: &mut Table, files: &BTreeSet<PathBuf>) -> Result<()> {
    // (variable, key path) per unset variable.
    type Missing = Vec<(String, Vec<String>)>;
    fn walk(value: &mut Value, path: &mut Vec<String>, missing: &mut Missing) -> Result<()> {
        match value {
            Value::String(s) => {
                let mut names = Vec::new();
                *s = expand_env(s, &mut names)?;
                missing.extend(names.into_iter().map(|n| (n, path.clone())));
            }
            Value::Table(t) => {
                for (k, v) in t.iter_mut() {
                    path.push(k.clone());
                    walk(v, path, missing)?;
                    path.pop();
                }
            }
            Value::Array(a) => {
                for (i, v) in a.iter_mut().enumerate() {
                    path.push(format!("[{i}]"));
                    walk(v, path, missing)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    // A compose file's `${VAR}` is docker compose's own syntax, resolved on the
    // host from the project's `.env`; expanding it here would bake secrets into
    // a file `diff` prints. Every other string (incl. `env` values) expands.
    fn walk_skipping(
        value: &mut Value,
        path: &mut Vec<String>,
        missing: &mut Missing,
    ) -> Result<()> {
        if matches!(path.as_slice(), [a, b, _, c] if a == "containers" && b == "compose" && c == "content")
        {
            return Ok(());
        }
        match value {
            Value::Table(t) => {
                for (k, v) in t.iter_mut() {
                    path.push(k.clone());
                    walk_skipping(v, path, missing)?;
                    path.pop();
                }
                Ok(())
            }
            other => walk(other, path, missing),
        }
    }
    let mut missing = Missing::new();
    for (k, v) in table.iter_mut() {
        walk_skipping(v, &mut vec![k.clone()], &mut missing)?;
    }
    if missing.is_empty() {
        return Ok(());
    }
    let texts: Vec<(String, String)> = files
        .iter()
        .filter_map(|f| {
            let name = f.file_name()?.to_string_lossy().into_owned();
            Some((name, std::fs::read_to_string(f).ok()?))
        })
        .collect();
    let mut lines = vec!["environment variables not set (or empty):".to_string()];
    for (name, path) in &missing {
        let needle = format!("${{{name}}}");
        let at = texts
            .iter()
            .find_map(|(file, text)| {
                let n = text.lines().position(|l| l.contains(&needle))?;
                Some(format!("  ({file}:{})", n + 1))
            })
            .unwrap_or_default();
        lines.push(format!("  ${name} for {}{at}", key_label(path)));
    }
    lines.push(
        "export each one before running anvil; `${NAME:-}` allows an empty value".to_string(),
    );
    Err(AnvilError::Validation(lines.join("\n")))
}

/// `["tailscale", "auth_key"]` → `[tailscale] auth_key`.
fn key_label(path: &[String]) -> String {
    match path.split_first() {
        Some((section, [])) => section.clone(),
        Some((section, rest)) => format!("[{section}] {}", rest.join(".").replace(".[", "[")),
        None => String::new(),
    }
}

/// A valid environment-variable name: non-empty, `[A-Za-z_][A-Za-z0-9_]*`
/// (lowercase included, as POSIX allows). Expansion only ever touches config
/// *values*: generated module content (e.g. unattended-upgrades'
/// `${distro_id}` in `updates.rs`) never passes through [`substitute_env`],
/// which is why it survives — not because of this check. In a config value a
/// `${...}` whose content is not a valid name (`${distro-id}`, `${1x}`) is left
/// literal; a valid one (`${distro_id}`) is looked up, and is an error if unset.
/// There is no escape for a literal valid-name `${WORD}`.
fn is_env_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// True for an include path that is absolute or climbs out with `..`.
fn include_escapes_config_dir(inc: &str) -> bool {
    let p = std::path::Path::new(inc);
    p.is_absolute()
        || p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
}

/// Expand `${VAR}` / `${VAR:-default}` (shell `:-` semantics: default when VAR
/// is unset *or* empty) in `s`. The whole value need not be a placeholder
/// (`key-${VAR}`). Unrelated `${...}` (not a valid env name) is left literal.
/// An unset VAR with no default expands to nothing and is pushed to `missing`.
fn expand_env(s: &str, missing: &mut Vec<String>) -> Result<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            None => {
                // Unterminated `${` — leave the remainder literal.
                out.push_str(&rest[start..]);
                return Ok(out);
            }
            Some(end) => {
                let inner = &after[..end];
                let (name, default) = inner
                    .split_once(":-")
                    .map(|(n, d)| (n, Some(d)))
                    .unwrap_or((inner, None));
                if is_env_name(name) && default.is_some_and(|d| d.contains("${")) {
                    // The scan cuts at the first `}`, so a nested default would
                    // silently expand wrong; reject it rather than guess.
                    return Err(AnvilError::Validation(format!(
                        "config value {s:?}: a `${{{name}:-...}}` default may not \
                         itself contain `${{...}}` (nested substitution is not supported)"
                    )));
                }
                if is_env_name(name) {
                    match std::env::var(name) {
                        Ok(v) if !v.is_empty() => out.push_str(&v),
                        _ => match default {
                            Some(d) => out.push_str(d),
                            None => missing.push(name.to_string()),
                        },
                    }
                } else {
                    out.push_str("${");
                    out.push_str(inner);
                    out.push('}');
                }
                rest = &after[end + 1..];
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// Recursively read `path`, merging its `include`d files first (left-to-right)
/// and the file's own keys last. `include` is stripped at every level; cycles
/// are detected via the canonical-path stack. Each canonical file merges once,
/// at its *first* inclusion (`done`): a diamond (A→{B,C}, B→D, C→D) would
/// otherwise concatenate D's arrays twice and re-apply D's scalars over B's.
fn resolve_file(
    path: &Path,
    visiting: &mut Vec<PathBuf>,
    done: &mut BTreeSet<PathBuf>,
) -> Result<Table> {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if visiting.contains(&canonical) {
        let chain = visiting
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        return Err(AnvilError::IncludeCycle(format!(
            "{chain} -> {}",
            canonical.display()
        )));
    }
    // After the cycle check: a file still on the stack is never in `done`.
    if done.contains(&canonical) {
        return Ok(Table::new());
    }
    visiting.push(canonical);

    let text = std::fs::read_to_string(path).map_err(|source| AnvilError::ConfigRead {
        path: path.display().to_string(),
        source,
    })?;
    let mut table: Table =
        toml::from_str(&text).map_err(|e| AnvilError::ConfigParse(e.to_string()))?;

    let includes = take_include_list(&mut table)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    resolve_compose_files(&mut table, parent)?;

    let mut merged = Table::new();
    for inc in includes {
        // An absolute or `..`-escaping include path can reach outside the
        // config directory; the trust check below still gates it, but warn so
        // the operator notices an unexpected traversal.
        if include_escapes_config_dir(&inc) {
            eprintln!(
                "anvil: warning: include path {inc:?} is absolute or contains '..'; \
                 prefer a path relative to the config file"
            );
        }
        let inc_path = parent.join(&inc);
        check_include_trust(&inc_path)?;
        let mut inc_table = resolve_file(&inc_path, visiting, done)?;
        // An included file's `profile` directive has no meaning; drop it.
        inc_table.remove("profile");
        merge(&mut merged, inc_table, ArrayMerge::Concat);
    }
    merge(&mut merged, table, ArrayMerge::Concat);

    if let Some(c) = visiting.pop() {
        done.insert(c);
    }
    Ok(merged)
}

/// Apply the same trust rules to an included file as to a custom profile
/// (R93 spirit): no symlinks, owned by the invoking user, not group/world-
/// writable. An included file injects module config exactly like a profile, so
/// a symlinked or world-writable include could let another user or a stray
/// process plant `[users].create` with an attacker key — reject it up front.
/// Its immediate parent dir is checked too, as for plugins: a writable
/// parent lets another user rename-swap the file after the check.
fn check_include_trust(path: &Path) -> Result<()> {
    let uid = crate::plugin::invoking_uid().ok_or_else(|| {
        AnvilError::Validation(
            "could not determine the invoking user's uid; refusing to trust includes".into(),
        )
    })?;
    crate::plugin::secure_lstat(path, uid)
        .and_then(|_| match path.parent() {
            Some(parent) => crate::plugin::secure_ancestor_dir(parent, uid),
            None => Ok(()),
        })
        .map_err(|reason| {
            AnvilError::Validation(format!("included file {}: {reason}", path.display()))
        })
}

/// CR16: `[containers.compose.<n>] file = "..."` becomes `content` here, read
/// relative to the TOML file that names it and held to the include trust
/// checks (owner, not group/world-writable, no symlink). Exactly one of
/// `file`/`content` per file; a missing `content` is serde's error.
fn resolve_compose_files(table: &mut Table, dir: &Path) -> Result<()> {
    let Some(Value::Table(projects)) = table
        .get_mut("containers")
        .and_then(|c| c.as_table_mut())
        .and_then(|c| c.get_mut("compose"))
    else {
        return Ok(());
    };
    for (name, project) in projects.iter_mut() {
        let Some(p) = project.as_table_mut() else {
            continue;
        };
        let Some(file) = p.remove("file") else {
            continue;
        };
        let Value::String(file) = file else {
            return Err(AnvilError::ConfigParse(format!(
                "containers.compose.{name}.file must be a string"
            )));
        };
        if p.contains_key("content") {
            return Err(AnvilError::Validation(format!(
                "containers.compose.{name}: set exactly one of `file` and `content`"
            )));
        }
        if include_escapes_config_dir(&file) {
            eprintln!(
                "anvil: warning: compose file path {file:?} is absolute or contains '..'; \
                 prefer a path relative to the config file"
            );
        }
        let path = dir.join(&file);
        check_include_trust(&path)?;
        let text = std::fs::read_to_string(&path).map_err(|source| AnvilError::ConfigRead {
            path: path.display().to_string(),
            source,
        })?;
        p.insert("content".into(), Value::String(text));
    }
    Ok(())
}

/// Extract and remove the `include` array, returning the list of paths.
fn take_include_list(table: &mut Table) -> Result<Vec<String>> {
    match table.remove("include") {
        None => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(vec![s]),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Ok(s),
                other => Err(AnvilError::ConfigParse(format!(
                    "`include` entries must be strings, got {}",
                    other.type_str()
                ))),
            })
            .collect(),
        Some(other) => Err(AnvilError::ConfigParse(format!(
            "`include` must be a string or array of strings, got {}",
            other.type_str()
        ))),
    }
}

/// How [`merge`] treats an array present on both sides. Tables always merge
/// recursively and scalars are always overridden; arrays are the semantic
/// fork between the two merge call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArrayMerge {
    /// Arrays concatenate — `include` composes fragments (R95).
    Concat,
    /// The overlaying array replaces the base's — a `profile` is a defaults
    /// layer, and a user-set array must win outright, not append (R94).
    Replace,
}

/// Deep-merge `over` into `base`: tables merge recursively, scalars are
/// overridden, and arrays follow `arrays` (R94/R95).
fn merge(base: &mut Table, over: Table, arrays: ArrayMerge) {
    for (key, over_val) in over {
        match base.remove(&key) {
            Some(Value::Table(mut base_tbl)) => {
                if let Value::Table(over_tbl) = over_val {
                    merge(&mut base_tbl, over_tbl, arrays);
                    base.insert(key, Value::Table(base_tbl));
                } else {
                    base.insert(key, over_val);
                }
            }
            Some(Value::Array(mut base_arr)) => {
                if let Value::Array(over_arr) = over_val {
                    match arrays {
                        ArrayMerge::Concat => {
                            base_arr.extend(over_arr);
                            base.insert(key, Value::Array(base_arr));
                        }
                        ArrayMerge::Replace => {
                            base.insert(key, Value::Array(over_arr));
                        }
                    }
                } else {
                    base.insert(key, over_val);
                }
            }
            _ => {
                base.insert(key, over_val);
            }
        }
    }
}

/// Resolve a profile name (R94): built-in names first, then a custom profile
/// `<name>.toml` in the profiles directory.
fn resolve_profile(name: &str, dir_override: Option<&Path>) -> Result<Table> {
    if BUILTIN_PROFILES.contains(&name) {
        return builtin_profile(name);
    }
    let Some(dir) = dir_override
        .map(Path::to_path_buf)
        .or_else(default_profiles_dir)
    else {
        return Err(AnvilError::UnknownProfile {
            name: name.to_string(),
            available: BUILTIN_PROFILES.join(", "),
        });
    };
    resolve_custom_profile(name, &dir, crate::plugin::invoking_uid())
}

/// Load a custom profile with the same trust rules as plugins (R93 spirit):
/// no symlinks, owned by the invoking user, not group/world-writable. The
/// `uid` is injectable so the foreign-owner rejection is testable without
/// root.
fn resolve_custom_profile(name: &str, dir: &Path, uid: Option<u32>) -> Result<Table> {
    // The name lands in a filesystem path: constrain it before touching disk.
    if !crate::plugin::valid_name(name) {
        return Err(AnvilError::Validation(format!(
            "profile name {name:?} contains invalid characters \
             (must match ^[A-Za-z0-9_-]+$)"
        )));
    }
    let path = dir.join(format!("{name}.toml"));
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(AnvilError::UnknownProfile {
                name: name.to_string(),
                available: available_profiles(dir),
            })
        }
        Err(e) => {
            return Err(AnvilError::ConfigRead {
                path: path.display().to_string(),
                source: e,
            })
        }
        Ok(_) => {}
    }
    let uid = uid.ok_or_else(|| {
        AnvilError::Validation(
            "could not determine the invoking user's uid; refusing to trust custom profiles".into(),
        )
    })?;
    crate::plugin::secure_lstat(&path, uid)
        .map_err(|reason| AnvilError::Validation(format!("custom profile {name:?}: {reason}")))?;
    let text = std::fs::read_to_string(&path).map_err(|source| AnvilError::ConfigRead {
        path: path.display().to_string(),
        source,
    })?;
    let mut table: Table = toml::from_str(&text)
        .map_err(|e| AnvilError::ConfigParse(format!("custom profile {name:?}: {e}")))?;
    // A profile is a defaults layer, not a full config: nested
    // `profile`/`include` directives have no meaning here.
    table.remove("profile");
    table.remove("include");
    resolve_compose_files(&mut table, dir)?;
    Ok(table)
}

/// Custom profiles discovered in `dir`: sorted `(name, path)` pairs for every
/// `*.toml` file. Security checks happen at *use* time, not list time.
pub fn discover_custom_profiles(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|x| x.to_str()) == Some("toml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push((stem.to_string(), path.clone()));
                }
            }
        }
    }
    out.sort();
    out
}

/// Every profile name an unknown-profile error can offer: builtins, plus any
/// customs discovered in `dir`.
fn available_profiles(dir: &Path) -> String {
    let mut s = BUILTIN_PROFILES.join(", ");
    let customs = discover_custom_profiles(dir);
    if !customs.is_empty() {
        let names: Vec<&str> = customs.iter().map(|(n, _)| n.as_str()).collect();
        s.push_str(&format!(
            "; custom profiles in {}: {}",
            dir.display(),
            names.join(", ")
        ));
    }
    s
}

/// Return the TOML table for a built-in profile (R94).
pub fn builtin_profile(name: &str) -> Result<Table> {
    let text = match name {
        "minimal" => MINIMAL,
        "cis-level1" => CIS_LEVEL1,
        "web-server" => WEB_SERVER,
        "ci-runner" => CI_RUNNER,
        _ => {
            return Err(AnvilError::UnknownProfile {
                name: name.to_string(),
                available: BUILTIN_PROFILES.join(", "),
            })
        }
    };
    toml::from_str(text).map_err(|e| AnvilError::ConfigParse(e.to_string()))
}

/// `minimal` — the smallest defensible baseline: hardened SSH, a default-deny
/// firewall, and unattended security updates. Nothing else.
const MINIMAL: &str = r#"
[sshd]
disable_root_login = true
disable_password_auth = true
disable_empty_passwords = true
strong_ciphers = true

[firewall]
default_incoming = "deny"
default_outgoing = "allow"
restrict_ssh = true

[updates]
security_only = true
"#;

/// `cis-level1` — a defensible CIS Level 1 server set: SSH config + crypto
/// waves, host firewall, kernel/sysctl and module blacklists, PAM password
/// policy with faillock, login/process restrictions, auditd with the
/// cis-level1 rule set, filesystem checks, SUID audit, brute-force banning,
/// and unattended security updates.
const CIS_LEVEL1: &str = r#"
[sshd]
disable_root_login = true
disable_password_auth = true
disable_empty_passwords = true
max_auth_tries = 3
login_grace_time = 30
client_alive_interval = 300
client_alive_count_max = 2
strong_ciphers = true
disable_x11_forwarding = true

[ssh_crypto]

[firewall]
default_incoming = "deny"
default_outgoing = "allow"
restrict_ssh = true

[kernel]
harden_network = true
restrict_dmesg = true
restrict_kernel_pointers = true

[kernel_modules]
blacklist_filesystems = true
blacklist_squashfs = true
blacklist_vfat = true
blacklist_usb_storage = true
blacklist_network_protocols = true

[pam]
minlen = 14
require_uppercase = true
require_lowercase = true
require_digit = true
require_special = true
enable_faillock = true
deny = 5
unlock_time = 900
umask = "027"

[process]
disable_core_dumps = true
disable_sysrq = true
pass_max_days = 365
pass_min_days = 1
pass_warn_age = 7

[auditd]
rule_set = "cis-level1"

[filesystem]
tmp_noexec = true
check_sticky_bits = true
check_world_writable = true

[suid]

[fail2ban]
bantime = "10m"
findtime = "10m"
maxretry = 5

[updates]
security_only = true
"#;

/// `web-server` — the minimal baseline plus what a public HTTP host needs:
/// 80/443 open, fail2ban in front of the exposed surface, and TLS-ready
/// certificate tooling.
const WEB_SERVER: &str = r#"
[sshd]
disable_root_login = true
disable_password_auth = true
disable_empty_passwords = true
strong_ciphers = true

[firewall]
default_incoming = "deny"
default_outgoing = "allow"
restrict_ssh = true

[[firewall.allow]]
port = "80"
proto = "tcp"
comment = "http"

[[firewall.allow]]
port = "443"
proto = "tcp"
comment = "https"

[fail2ban]
bantime = "10m"
findtime = "10m"
maxretry = 5

[tls]
provider = "certbot"

[updates]
security_only = true
"#;

/// `ci-runner` — a light set for ephemeral CI runners: hardened SSH, a
/// default-deny inbound firewall (a runner only dials out), full (not
/// security-only) updates so images stay current, package hygiene stripping
/// legacy remote-access tools, and no auto-reboot (a reboot mid-job kills the
/// runner).
const CI_RUNNER: &str = r#"
[sshd]
disable_root_login = true
disable_password_auth = true
disable_empty_passwords = true
strong_ciphers = true

[firewall]
default_incoming = "deny"
default_outgoing = "allow"
restrict_ssh = true

[packages]
remove = ["telnet", "rsh-client", "talk"]

[updates]
security_only = false
auto_reboot = false
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn load(path: impl AsRef<Path>) -> Result<Config> {
        Ok(load_with(path, &LoadOptions::default())?.config)
    }

    /// `expand_env` with an unset variable as an error, like a load.
    fn expand(s: &str) -> Result<String> {
        let mut missing = Vec::new();
        let out = expand_env(s, &mut missing)?;
        match missing.first() {
            Some(n) => Err(AnvilError::Validation(format!("{n} not set"))),
            None => Ok(out),
        }
    }

    /// Removes the fixture dir (and the per-pid parent once empty) when the
    /// test ends: nextest runs each test in its own process.
    struct TmpDir {
        path: PathBuf,
        /// The per-call dir `tmp()` made; `path` may be below it.
        root: PathBuf,
    }
    impl std::ops::Deref for TmpDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.path
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
            if let Some(pid_dir) = self.root.parent() {
                let _ = std::fs::remove_dir(pid_dir);
            }
        }
    }

    /// A fresh dir per call: `cargo test` runs tests as threads of one
    /// process, so a per-pid dir alone is shared (and raced) between tests.
    fn tmp() -> TmpDir {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let pid_dir = PathBuf::from(base).join(format!("anvil-load-{}", std::process::id()));
        // Remove a previous run's leftovers once (pids get recycled), so the
        // fixture dirs don't accumulate in TMPDIR.
        static CLEAN: std::sync::Once = std::sync::Once::new();
        CLEAN.call_once(|| {
            let _ = std::fs::remove_dir_all(&pid_dir);
        });
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = pid_dir.join(n.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        // Includes trust-check their parent dir: don't depend on umask.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        TmpDir {
            path: dir.clone(),
            root: dir,
        }
    }

    fn write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        p
    }

    #[test]
    fn profile_defaults_then_user_override() {
        let dir = tmp();
        let p = write(
            &dir,
            "prof.toml",
            r#"
                profile = "web-server"
                [host]
                address = "h"
                user = "u"
                [sshd]
                port = 2222
            "#,
        );
        let c = load(&p).unwrap();
        c.validate().unwrap();
        // From profile:
        assert!(c.is_enabled("firewall"));
        assert!(c.is_enabled("tls"));
        // User override wins:
        assert_eq!(c.sshd.unwrap().port, 2222);
    }

    #[test]
    fn includes_merge_left_to_right_local_last() {
        let dir = tmp();
        write(
            &dir,
            "base.toml",
            r#"
                [host]
                address = "base-host"
                user = "u"
                [sshd]
                port = 22
            "#,
        );
        let p = write(
            &dir,
            "main.toml",
            r#"
                include = ["base.toml"]
                [sshd]
                port = 2200
            "#,
        );
        let c = load(&p).unwrap();
        assert_eq!(c.host.as_ref().unwrap().address, "base-host");
        assert_eq!(c.sshd.unwrap().port, 2200); // local overrides include
    }

    #[test]
    fn include_cycle_is_detected() {
        let dir = tmp();
        write(&dir, "a.toml", "include = [\"b.toml\"]\n");
        let p = write(&dir, "b.toml", "include = [\"a.toml\"]\n");
        let err = load(&p).unwrap_err();
        assert!(matches!(err, AnvilError::IncludeCycle(_)));
    }

    #[test]
    fn unknown_profile_is_rejected() {
        let dir = tmp();
        let p = write(
            &dir,
            "u.toml",
            r#"
                profile = "does-not-exist"
                [host]
                address = "h"
                user = "u"
            "#,
        );
        assert!(matches!(
            load(&p).unwrap_err(),
            AnvilError::UnknownProfile { .. }
        ));
    }

    #[test]
    fn profile_arrays_are_replaced_by_user_config() {
        // web-server's profile ships firewall.allow rules for 80 and 443; a
        // user who sets their own allow list must fully replace them, not
        // append to an unremovable default.
        let dir = tmp();
        let p = write(
            &dir,
            "replace.toml",
            r#"
                profile = "web-server"
                [host]
                address = "h"
                user = "u"
                [[firewall.allow]]
                port = "8443"
                proto = "tcp"
            "#,
        );
        let c = load(&p).unwrap();
        let allow = c.firewall.as_ref().unwrap().allow.clone();
        assert_eq!(allow.len(), 1, "user array replaces profile array");
        assert_eq!(allow[0].port, "8443");
    }

    #[test]
    fn profile_arrays_survive_when_user_sets_none() {
        let dir = tmp();
        let p = write(
            &dir,
            "keep.toml",
            r#"
                profile = "web-server"
                [host]
                address = "h"
                user = "u"
            "#,
        );
        let c = load(&p).unwrap();
        let allow = c.firewall.as_ref().unwrap().allow.clone();
        let ports: Vec<&str> = allow.iter().map(|r| r.port.as_str()).collect();
        assert_eq!(ports, vec!["80", "443"], "profile defaults kept");
    }

    #[test]
    fn merge_modes_differ_only_on_arrays() {
        let base_t = || -> Table { toml::from_str("[s]\narr = [1]\nscalar = \"base\"\n").unwrap() };
        let over: Table = toml::from_str("[s]\narr = [2]\nscalar = \"over\"\n").unwrap();

        let mut concat = base_t();
        merge(&mut concat, over.clone(), ArrayMerge::Concat);
        let mut replace = base_t();
        merge(&mut replace, over, ArrayMerge::Replace);

        let arr = |t: &Table| -> Vec<i64> {
            t["s"]["arr"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_integer().unwrap())
                .collect()
        };
        assert_eq!(arr(&concat), vec![1, 2]);
        assert_eq!(arr(&replace), vec![2]);
        // Nested tables deep-merge and scalars override in both modes.
        for t in [&concat, &replace] {
            assert_eq!(t["s"]["scalar"].as_str(), Some("over"));
        }
    }

    // --- plugin-bound section extraction -----------------------------

    fn plugin_opts(sections: &[String]) -> LoadOptions<'_> {
        LoadOptions {
            plugin_sections: sections,
            profiles_dir: None,
        }
    }

    #[test]
    fn plugin_section_is_extracted_not_rejected() {
        let dir = tmp();
        let p = write(
            &dir,
            "plug.toml",
            r#"
                [host]
                address = "h"
                user = "u"
                [sshd]
                [backup_agent]
                target = "/srv/data"
                retries = 3
            "#,
        );
        let sections = vec!["backup_agent".to_string()];
        let loaded = load_with(&p, &plugin_opts(&sections)).unwrap();
        loaded.config.validate().unwrap();
        assert!(loaded.config.is_enabled("sshd"));
        let values = loaded
            .plugin_values
            .get("backup_agent")
            .expect("section captured");
        assert_eq!(values["target"].as_str(), Some("/srv/data"));
        assert_eq!(values["retries"].as_integer(), Some(3));
    }

    #[test]
    fn absent_plugin_section_is_simply_not_enabled() {
        let dir = tmp();
        let p = write(
            &dir,
            "plug-absent.toml",
            "[host]\naddress = \"h\"\nuser = \"u\"\n[sshd]\n",
        );
        let sections = vec!["backup_agent".to_string()];
        let loaded = load_with(&p, &plugin_opts(&sections)).unwrap();
        assert!(loaded.plugin_values.is_empty());
    }

    #[test]
    fn unbound_unknown_section_still_errors() {
        // Typo safety: a section bound to no plugin must keep tripping
        // deny_unknown_fields even when other plugin sections exist.
        let dir = tmp();
        let p = write(
            &dir,
            "plug-typo.toml",
            r#"
                [host]
                address = "h"
                user = "u"
                [backup_agnet]
                target = "x"
            "#,
        );
        let sections = vec!["backup_agent".to_string()];
        let err = load_with(&p, &plugin_opts(&sections)).expect_err("unknown section must fail");
        assert!(err.to_string().contains("backup_agnet"), "{err}");
    }

    #[test]
    fn plugin_section_must_be_a_table() {
        let dir = tmp();
        let p = write(
            &dir,
            "plug-scalar.toml",
            "backup_agent = true\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let sections = vec!["backup_agent".to_string()];
        let err =
            load_with(&p, &plugin_opts(&sections)).expect_err("scalar plugin section must fail");
        assert!(err.to_string().contains("must be a table"), "{err}");
    }

    #[test]
    fn reserved_sections_are_never_extracted() {
        // Even if a caller passed a built-in id as a plugin section, the real
        // module must keep its config.
        let dir = tmp();
        let p = write(
            &dir,
            "plug-reserved.toml",
            "[host]\naddress = \"h\"\nuser = \"u\"\n[sshd]\nport = 2222\n",
        );
        let sections = vec!["sshd".to_string()];
        let loaded = load_with(&p, &plugin_opts(&sections)).unwrap();
        assert!(loaded.plugin_values.is_empty());
        assert_eq!(loaded.config.sshd.unwrap().port, 2222);
    }

    // --- built-in profiles end-to-end (R94) ---------------------------------

    /// Every built-in profile must ride the whole pipeline: load → deserialize
    /// → validate → plan (ordering safety included).
    #[test]
    fn every_builtin_profile_loads_validates_and_plans() {
        let dir = tmp();
        for name in BUILTIN_PROFILES {
            let p = write(
                &dir,
                &format!("builtin-{name}.toml"),
                &format!("profile = \"{name}\"\n[host]\naddress = \"h\"\nuser = \"u\"\n"),
            );
            let c = load(&p).unwrap_or_else(|e| panic!("profile {name} must load: {e}"));
            c.validate()
                .unwrap_or_else(|e| panic!("profile {name} must validate: {e}"));
            let plan = crate::modules::Plan::build(&c)
                .unwrap_or_else(|e| panic!("profile {name} must plan: {e}"));
            assert_eq!(
                plan.order.last().unwrap(),
                "updates",
                "profile {name}: updates last"
            );
        }
    }

    #[test]
    fn builtin_profile_module_sets_match_their_intent() {
        let dir = tmp();
        let load_profile = |name: &str| {
            let p = write(
                &dir,
                &format!("intent-{name}.toml"),
                &format!("profile = \"{name}\"\n[host]\naddress = \"h\"\nuser = \"u\"\n"),
            );
            load(&p).unwrap()
        };

        let minimal = load_profile("minimal");
        for id in ["sshd", "firewall", "updates"] {
            assert!(minimal.is_enabled(id), "minimal enables {id}");
        }
        assert_eq!(minimal.enabled_sections().len(), 3, "minimal is minimal");

        let cis = load_profile("cis-level1");
        for id in [
            "sshd",
            "ssh_crypto",
            "firewall",
            "kernel",
            "kernel_modules",
            "pam",
            "process",
            "auditd",
            "filesystem",
            "suid",
            "fail2ban",
            "updates",
        ] {
            assert!(cis.is_enabled(id), "cis-level1 enables {id}");
        }
        assert_eq!(cis.auditd.as_ref().unwrap().rule_set, "cis-level1");
        assert!(cis.updates.as_ref().unwrap().security_only);

        let web = load_profile("web-server");
        for id in ["sshd", "firewall", "fail2ban", "tls", "updates"] {
            assert!(web.is_enabled(id), "web-server enables {id}");
        }
        let ports: Vec<&str> = web
            .firewall
            .as_ref()
            .unwrap()
            .allow
            .iter()
            .map(|r| r.port.as_str())
            .collect();
        assert_eq!(ports, vec!["80", "443"]);
        assert_eq!(web.tls.as_ref().unwrap().provider, "certbot");

        let ci = load_profile("ci-runner");
        for id in ["sshd", "firewall", "packages", "updates"] {
            assert!(ci.is_enabled(id), "ci-runner enables {id}");
        }
        let fw = ci.firewall.as_ref().unwrap();
        assert_eq!(fw.default_incoming, "deny");
        assert_eq!(
            fw.default_outgoing, "allow",
            "the runner dials out to GitHub"
        );
        assert!(fw.restrict_ssh);
        assert!(
            fw.allow.is_empty(),
            "a runner needs no inbound port but SSH"
        );
        let u = ci.updates.as_ref().unwrap();
        assert!(!u.security_only, "runners take full updates");
        assert!(!u.auto_reboot, "a mid-job reboot kills the runner");
        assert!(!ci.packages.as_ref().unwrap().remove.is_empty());
    }

    // --- custom profiles (R94) ----------------------------------------------

    use std::os::unix::fs::PermissionsExt;

    fn secure_write(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = write(dir, name, body);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        p
    }

    fn profiles_dir(test: &str) -> TmpDir {
        let mut t = tmp();
        t.path = t.path.join(format!("profiles-{test}"));
        std::fs::create_dir_all(&t.path).unwrap();
        t
    }

    #[test]
    fn custom_profile_resolves_and_user_overrides() {
        let pdir = profiles_dir("resolve");
        secure_write(&pdir, "site.toml", "[sshd]\nport = 2200\n[kernel]\n");
        let dir = tmp();
        let cfg = write(
            &dir,
            "custom-prof.toml",
            r#"
                profile = "site"
                [host]
                address = "h"
                user = "u"
                [sshd]
                port = 2222
            "#,
        );
        let loaded = load_with(
            &cfg,
            &LoadOptions {
                plugin_sections: &[],
                profiles_dir: Some(&pdir),
            },
        )
        .unwrap();
        loaded.config.validate().unwrap();
        assert!(loaded.config.is_enabled("kernel"), "profile default kept");
        assert_eq!(
            loaded.config.sshd.unwrap().port,
            2222,
            "user key overrides profile default"
        );
    }

    #[test]
    fn builtin_name_cannot_be_shadowed_by_custom_file() {
        let pdir = profiles_dir("shadow");
        secure_write(&pdir, "minimal.toml", "[docker]\n");
        let dir = tmp();
        let cfg = write(
            &dir,
            "shadowed.toml",
            "profile = \"minimal\"\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let loaded = load_with(
            &cfg,
            &LoadOptions {
                plugin_sections: &[],
                profiles_dir: Some(&pdir),
            },
        )
        .unwrap();
        assert!(
            !loaded.config.is_enabled("docker"),
            "builtin must win over a same-named custom file"
        );
        assert!(loaded.config.is_enabled("firewall"), "builtin content used");
    }

    #[test]
    fn profile_lookup_failure_other_than_not_found_is_not_unknown() {
        // A profiles "dir" that is a file makes the lookup fail with ENOTDIR.
        let base = profiles_dir("enotdir");
        let file = base.join("plain");
        std::fs::write(&file, "x").unwrap();
        let err = resolve_custom_profile("nope", &file, crate::plugin::invoking_uid())
            .expect_err("lookup must fail");
        assert!(!matches!(err, AnvilError::UnknownProfile { .. }), "{err}");
    }

    #[test]
    fn unknown_profile_lists_builtins_and_customs() {
        let pdir = profiles_dir("unknown");
        secure_write(&pdir, "site.toml", "[sshd]\n");
        let err = resolve_custom_profile("nope", &pdir, crate::plugin::invoking_uid())
            .expect_err("unknown profile");
        let msg = err.to_string();
        assert!(matches!(err, AnvilError::UnknownProfile { .. }), "{msg}");
        assert!(msg.contains("minimal"), "{msg}");
        assert!(msg.contains("site"), "{msg}");
    }

    #[test]
    fn custom_profile_symlink_is_rejected() {
        let pdir = profiles_dir("symlink");
        let real = secure_write(&pdir, "real.toml", "[sshd]\n");
        std::os::unix::fs::symlink(&real, pdir.join("linked.toml")).unwrap();
        let err = resolve_custom_profile("linked", &pdir, crate::plugin::invoking_uid())
            .expect_err("symlinked profile");
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn custom_profile_world_writable_is_rejected() {
        let pdir = profiles_dir("worldwr");
        let p = secure_write(&pdir, "loose.toml", "[sshd]\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = resolve_custom_profile("loose", &pdir, crate::plugin::invoking_uid())
            .expect_err("world-writable profile");
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[test]
    fn include_symlink_is_rejected() {
        // An included file is held to the same trust model as a profile —
        // a symlinked include could swap in another user's module config.
        let dir = tmp();
        let real = secure_write(&dir, "real.toml", "[sshd]\nport = 2222\n");
        std::os::unix::fs::symlink(&real, dir.join("linked.toml")).unwrap();
        write(
            &dir,
            "main.toml",
            "include = [\"linked.toml\"]\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let err = load(dir.join("main.toml")).expect_err("symlinked include");
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn include_world_writable_is_rejected() {
        // A world-writable include lets anyone plant module config.
        let dir = tmp();
        let inc = secure_write(&dir, "frag.toml", "[sshd]\nport = 2222\n");
        std::fs::set_permissions(&inc, std::fs::Permissions::from_mode(0o666)).unwrap();
        write(
            &dir,
            "main.toml",
            "include = [\"frag.toml\"]\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let err = load(dir.join("main.toml")).expect_err("world-writable include");
        assert!(err.to_string().contains("writable"), "{err}");
    }

    #[test]
    fn trusted_include_is_accepted() {
        // A normal owner-owned, non-world-writable include still loads.
        let dir = tmp();
        secure_write(&dir, "frag.toml", "[sshd]\nport = 2222\n");
        write(
            &dir,
            "main.toml",
            "include = [\"frag.toml\"]\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let c = load(dir.join("main.toml")).expect("trusted include loads");
        assert_eq!(c.sshd.unwrap().port, 2222);
    }

    // --- containers.compose.<n>.file (CR16) ----------------------------------

    const HOST: &str = "[host]\naddress = \"h\"\nuser = \"u\"\n";
    const YAML: &str =
        "services:\n  web:\n    image: nginx:1.27\n    environment:\n      P: ${P}\n";

    fn compose_main(dir: &Path, project: &str) -> PathBuf {
        write(
            dir,
            "main.toml",
            &format!("{HOST}[containers.compose.web]\n{project}"),
        )
    }

    fn compose_content(c: Config) -> String {
        c.containers.unwrap().compose["web"].content.clone()
    }

    #[test]
    fn compose_file_is_read_relative_to_the_config() {
        let dir = tmp();
        std::fs::create_dir(dir.join("compose")).unwrap();
        std::fs::set_permissions(dir.join("compose"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        secure_write(&dir.join("compose"), "app.yaml", YAML);
        let c = load(compose_main(&dir, "file = \"compose/app.yaml\"\n")).expect("loads");
        // `${P}` is compose's syntax: never expanded by anvil (P is unset here).
        assert_eq!(compose_content(c), YAML);
    }

    #[test]
    fn compose_file_in_an_include_is_relative_to_that_include() {
        let dir = tmp();
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        secure_write(&sub, "app.yaml", YAML);
        secure_write(
            &sub,
            "frag.toml",
            "[containers.compose.web]\nfile = \"app.yaml\"\n",
        );
        write(
            &dir,
            "main.toml",
            &format!("include = [\"sub/frag.toml\"]\n{HOST}"),
        );
        assert_eq!(compose_content(load(dir.join("main.toml")).unwrap()), YAML);
    }

    #[test]
    fn compose_file_and_content_together_are_rejected() {
        let dir = tmp();
        secure_write(&dir, "app.yaml", YAML);
        let err = load(compose_main(&dir, "file = \"app.yaml\"\ncontent = \"x\"\n"))
            .expect_err("both keys");
        assert!(err.to_string().contains("exactly one"), "{err}");
    }

    #[test]
    fn compose_file_must_be_a_string() {
        let err = load(compose_main(&tmp(), "file = 1\n")).expect_err("non-string");
        assert!(err.to_string().contains("must be a string"), "{err}");
    }

    #[test]
    fn compose_file_symlink_is_rejected() {
        let dir = tmp();
        let real = secure_write(&dir, "real.yaml", YAML);
        std::os::unix::fs::symlink(&real, dir.join("app.yaml")).unwrap();
        let err = load(compose_main(&dir, "file = \"app.yaml\"\n")).expect_err("symlink");
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    #[test]
    fn compose_file_group_or_world_writable_is_rejected() {
        for mode in [0o666, 0o664] {
            let dir = tmp();
            let f = secure_write(&dir, "app.yaml", YAML);
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = load(compose_main(&dir, "file = \"app.yaml\"\n")).expect_err("writable");
            assert!(err.to_string().contains("writable"), "{mode:o}: {err}");
        }
    }

    #[test]
    fn compose_file_missing_is_a_read_error() {
        let err = load(compose_main(&tmp(), "file = \"nope.yaml\"\n")).expect_err("missing");
        assert!(err.to_string().contains("nope.yaml"), "{err}");
    }

    #[test]
    fn compose_file_in_a_custom_profile_is_relative_to_the_profile_dir() {
        let pdir = profiles_dir("compose-file");
        secure_write(&pdir, "app.yaml", YAML);
        secure_write(
            &pdir,
            "team.toml",
            "[containers.compose.web]\nfile = \"app.yaml\"\n",
        );
        let t = resolve_custom_profile("team", &pdir, crate::plugin::invoking_uid()).unwrap();
        assert_eq!(
            t["containers"]["compose"]["web"]["content"].as_str(),
            Some(YAML)
        );
    }

    #[test]
    fn custom_profile_foreign_owner_is_rejected() {
        let pdir = profiles_dir("foreign");
        secure_write(&pdir, "site.toml", "[sshd]\n");
        let wrong = crate::plugin::invoking_uid().unwrap().wrapping_add(1);
        let err =
            resolve_custom_profile("site", &pdir, Some(wrong)).expect_err("foreign-owned profile");
        assert!(err.to_string().contains("owned by uid"), "{err}");
    }

    #[test]
    fn custom_profile_name_charset_is_enforced() {
        let pdir = profiles_dir("charset");
        for bad in ["../evil", "a/b", "dot.dot", ""] {
            let err = resolve_custom_profile(bad, &pdir, crate::plugin::invoking_uid())
                .expect_err("bad name");
            assert!(
                err.to_string().contains("invalid characters"),
                "{bad:?}: {err}"
            );
        }
    }

    #[test]
    fn custom_profile_strips_nested_profile_and_include() {
        let pdir = profiles_dir("nested");
        secure_write(
            &pdir,
            "meta.toml",
            "profile = \"minimal\"\ninclude = [\"x.toml\"]\n[sshd]\n",
        );
        let t = resolve_custom_profile("meta", &pdir, crate::plugin::invoking_uid()).unwrap();
        assert!(!t.contains_key("profile"));
        assert!(!t.contains_key("include"));
        assert!(t.contains_key("sshd"));
    }

    #[test]
    fn discover_custom_profiles_lists_toml_only() {
        let pdir = profiles_dir("list");
        secure_write(&pdir, "bbb.toml", "[sshd]\n");
        secure_write(&pdir, "aaa.toml", "[sshd]\n");
        secure_write(&pdir, "notes.txt", "not a profile\n");
        let names: Vec<String> = discover_custom_profiles(&pdir)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["aaa", "bbb"]);
        // A missing directory is just an empty list.
        assert!(discover_custom_profiles(Path::new("/nonexistent/anvil")).is_empty());
    }

    #[test]
    fn arrays_concatenate_across_include_and_local() {
        let dir = tmp();
        write(
            &dir,
            "arr-base.toml",
            r#"
                [host]
                address = "h"
                user = "u"
                [packages]
                install = ["git"]
            "#,
        );
        let p = write(
            &dir,
            "arr-main.toml",
            r#"
                include = ["arr-base.toml"]
                [packages]
                install = ["curl"]
            "#,
        );
        let c = load(&p).unwrap();
        assert_eq!(c.packages.unwrap().install, vec!["git", "curl"]);
    }

    #[test]
    fn include_in_world_writable_dir_is_rejected() {
        // The include file itself is trusted, but its parent dir is
        // world-writable, so another user could rename-swap it after the check.
        let dir = tmp();
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        secure_write(&sub, "frag.toml", "[sshd]\nport = 2222\n");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        write(
            &dir,
            "main.toml",
            "include = [\"sub/frag.toml\"]\n[host]\naddress = \"h\"\nuser = \"u\"\n",
        );
        let err = load(dir.join("main.toml")).expect_err("include under writable dir");
        let msg = err.to_string();
        assert!(msg.contains("ancestor"), "{msg}");
        assert!(msg.contains("writable"), "{msg}");
    }

    #[test]
    fn diamond_include_merges_shared_file_once() {
        // a→{b,c}, b→d, c→d must not concatenate d's arrays twice, and d
        // (merged at its first inclusion, via b) must not re-override c.
        let dir = tmp();
        secure_write(
            &dir,
            "d.toml",
            "[host]\naddress = \"h\"\nuser = \"u\"\n\
             [packages]\ninstall = [\"git\"]\n[sshd]\nport = 1\n",
        );
        secure_write(&dir, "b.toml", "include = [\"d.toml\"]\n");
        secure_write(&dir, "c.toml", "include = [\"d.toml\"]\n[sshd]\nport = 2\n");
        let p = write(&dir, "a.toml", "include = [\"b.toml\", \"c.toml\"]\n");
        let c = load(&p).unwrap();
        assert_eq!(c.packages.unwrap().install, vec!["git"]);
        assert_eq!(c.sshd.unwrap().port, 2);
    }

    #[test]
    fn include_escape_detection() {
        assert!(include_escapes_config_dir("/etc/x.toml"));
        assert!(include_escapes_config_dir("../x.toml"));
        assert!(include_escapes_config_dir("a/../b.toml"));
        assert!(!include_escapes_config_dir("sub/x.toml"));
    }

    #[test]
    fn empty_env_var_takes_the_default() {
        std::env::set_var("ANVIL_EMPTY_VAR_TEST", "");
        assert_eq!(expand("${ANVIL_EMPTY_VAR_TEST:-d}").unwrap(), "d");
    }

    #[test]
    fn nested_env_default_is_rejected() {
        // `${A:-${B}}` used to cut at the first `}` (`x}` when A is set,
        // literal `${B}` when unset). It is now a clear error.
        let err = expand("${ANVIL_T12C_A:-${ANVIL_T12C_B}}").unwrap_err();
        assert!(err.to_string().contains("nested"), "{err}");
        // A plain default and a non-name `${...}` are unaffected.
        assert_eq!(expand("${ANVIL_T12C_A:-x}").unwrap(), "x");
        assert_eq!(expand("${a-b:-${c}}").unwrap(), "${a-b:-${c}}");
    }

    #[test]
    fn env_name_rules_match_doc_comment() {
        // A non-name `${...}` stays literal; a
        // valid lowercase name is looked up like any other and errors if unset.
        assert_eq!(expand("o=${distro-id}").unwrap(), "o=${distro-id}");
        assert_eq!(expand("${1x}").unwrap(), "${1x}");
        assert!(expand("${anvil_t12d_unset}").is_err());
    }

    #[test]
    fn every_unset_env_var_is_named_with_its_key_file_and_line() {
        let dir = tmp();
        write(
            &dir.path,
            "inc.toml",
            "[restic]\nrepository = \"sftp:x:/r\"\npassword = \"${ANVIL_T_MISS_B}\"\n",
        );
        let cfg = write(
            &dir.path,
            "host.toml",
            "include = [\"inc.toml\"]\n[host]\naddress = \"203.0.113.1\"\nuser = \"root\"\n\n\
             [tailscale]\nauth_key = \"${ANVIL_T_MISS_A}\"\n\
             [firewall]\nallow = [{ port = \"${ANVIL_T_MISS_C}\" }]\n",
        );
        let err = load(&cfg).unwrap_err().to_string();
        assert!(
            err.contains("$ANVIL_T_MISS_A for [tailscale] auth_key  (host.toml:7)"),
            "{err}"
        );
        assert!(
            err.contains("$ANVIL_T_MISS_B for [restic] password  (inc.toml:3)"),
            "{err}"
        );
        assert!(
            err.contains("$ANVIL_T_MISS_C for [firewall] allow[0].port  (host.toml:9)"),
            "{err}"
        );
        assert!(err.contains("${NAME:-}"), "{err}");
    }

    #[test]
    fn compose_content_is_not_env_expanded_but_env_values_are() {
        std::env::set_var("ANVIL_T_COMPOSE_SECRET", "s3cret");
        let dir = tmp();
        let cfg = write(
            &dir,
            "c.toml",
            "[containers.compose.app]\n\
             content = \"x: ${ANVIL_T_COMPOSE_UNSET}\"\n\
             env = { PASS = \"${ANVIL_T_COMPOSE_SECRET}\" }\n",
        );
        let c = load(&cfg).unwrap().containers.unwrap();
        let app = &c.compose["app"];
        // Left for docker compose on the host; an unset var is not an error.
        assert_eq!(app.content, "x: ${ANVIL_T_COMPOSE_UNSET}");
        assert_eq!(app.env["PASS"], "s3cret");
    }
}
