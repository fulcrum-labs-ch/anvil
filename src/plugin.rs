//! Out-of-tree plugin subsystem (R91–R93).
//!
//! Plugins are discovered from `~/.config/anvil/plugins/<name>/` (honoring
//! `$XDG_CONFIG_HOME`; the base directory is injectable for tests). Each
//! plugin directory holds a manifest (`plugin.toml`), a required `apply.sh`,
//! and an optional `check.sh`. A plugin binds one config section; when that
//! section is present in the user's config the plugin is enabled and becomes
//! a regular [`Declaration`] with a single [`ManagedCommand`] — `check.sh` is
//! the detect expression, `apply.sh` the converge body — so the engine's
//! probe/apply rendering, the marker protocol, and the CLI's two-phase apply
//! are reused unchanged. Plugins are addressed as `plugin::<name>` in
//! ordering and results (R92).
//!
//! Security (R93, all mandatory): names are validated against
//! `^[A-Za-z0-9_-]+$`; plugin directories/files must be owned by the invoking
//! user and must not be group- or world-writable; symlinked plugin paths are
//! rejected; `{{VAR}}` substitutions from the bound config section are
//! shell-escaped (and must be unquoted), and an undefined variable is a hard error, never an empty
//! string. A malformed or insecure plugin is skipped with a warning and a
//! reason — discovery never aborts.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::Deserialize;
use toml::value::{Table, Value};

use crate::config::schema::OrderOverride;
use crate::engine::{Declaration, ManagedCommand};
use crate::error::{AnvilError, Result};
use crate::escape::shell_escape;

/// The id prefix under which plugins appear in ordering and results (R92).
pub const PLUGIN_ID_PREFIX: &str = "plugin::";

/// The user's config home: `$XDG_CONFIG_HOME`, else `$HOME/.config` — only
/// when absolute. `None` (cron/systemd with no `HOME`, or a relative value)
/// skips plugin and custom-profile discovery: a relative home would resolve
/// against the cwd, e.g. a cloned repo's `.config/anvil/plugins/`.
pub(crate) fn config_home() -> Option<PathBuf> {
    config_home_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
}

fn config_home_from(xdg: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let p = match (xdg, home) {
        (Some(x), _) if !x.is_empty() => PathBuf::from(x),
        (_, Some(h)) if !h.is_empty() => Path::new(&h).join(".config"),
        _ => return None,
    };
    p.is_absolute().then_some(p)
}

/// Default plugin base directory: `~/.config/anvil/plugins` (R91); `None`
/// when there is no absolute config home.
pub fn default_plugins_dir() -> Option<PathBuf> {
    config_home().map(|h| h.join("anvil").join("plugins"))
}

/// A plugin name / bound-section name: `^[A-Za-z0-9_-]+$` — no path
/// separators, no dots, nothing a path or a TOML key could be smuggled
/// through (R93).
pub(crate) fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The uid that owns files this process creates — i.e. the invoking user's
/// effective uid — determined portably (no libc dependency) by statting a
/// freshly created probe file. `None` if it cannot be determined.
pub(crate) fn invoking_uid() -> Option<u32> {
    static UID: OnceLock<Option<u32>> = OnceLock::new();
    *UID.get_or_init(|| {
        let probe = std::env::temp_dir().join(format!(".anvil-uid-probe-{}", std::process::id()));
        probe_uid(&probe)
    })
}

/// Create `probe` exclusively and return its owner uid. A pre-existing file
/// (possibly planted by another user in a shared temp dir) fails closed and
/// is left alone.
fn probe_uid(probe: &Path) -> Option<u32> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(probe)
        .ok()?;
    let uid = file.metadata().map(|m| m.uid()).ok();
    let _ = std::fs::remove_file(probe);
    uid
}

/// `lstat` a path and enforce the trust rules shared by plugins and custom
/// profiles (R93): not a symlink, owned by `expected_uid`, and not group- or
/// world-writable. Returns the metadata on success, a human-readable reason
/// on failure.
pub(crate) fn secure_lstat(
    path: &Path,
    expected_uid: u32,
) -> std::result::Result<std::fs::Metadata, String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink (symlinked paths are not trusted)",
            path.display()
        ));
    }
    if meta.uid() != expected_uid {
        return Err(format!(
            "{} is owned by uid {} but the invoking user is uid {expected_uid}",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{} is group- or world-writable (mode {:04o}); tighten its permissions",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(meta)
}

/// Check a plugin's *ancestor* directory for the rename-substitution threat
/// the plugins/ dir must be owned by the invoking user and not group/
/// world-writable, or another user could `rename(2)` a plugin directory and
/// bypass the per-file checks (their files would be owner-correct and 0644).
/// Unlike [`secure_lstat`] we do NOT reject symlinked ancestors — symlinking
/// the config dir is a legitimate setup and the per-file checks already guard
/// the real files.
pub(crate) fn secure_ancestor_dir(
    path: &Path,
    expected_uid: u32,
) -> std::result::Result<(), String> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("cannot stat ancestor {}: {e}", path.display()))?;
    if meta.uid() != expected_uid {
        return Err(format!(
            "ancestor {} is owned by uid {} but the invoking user is uid {expected_uid}",
            path.display(),
            meta.uid()
        ));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "ancestor {} is group- or world-writable (mode {:04o}); tighten its permissions",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    Ok(())
}

// --- Manifest & discovery ----------------------------------------------------

/// `plugin.toml` — the manifest schema (R92). Unknown keys are rejected so a
/// typo skips the plugin loudly instead of being silently ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    /// Must match the plugin directory name.
    name: String,
    #[serde(default)]
    description: Option<String>,
    /// The config section this plugin binds to; presence of that section in
    /// the user's config enables the plugin.
    section: String,
    /// Explicit absolute order key (same scale as built-in waves).
    #[serde(default)]
    order: Option<i64>,
    /// Module ids this plugin must run before.
    #[serde(default)]
    before: Vec<String>,
    /// Module ids this plugin must run after.
    #[serde(default)]
    after: Vec<String>,
    /// Section keys whose values `--dry-run` masks (tokens, passwords).
    #[serde(default)]
    secrets: Vec<String>,
}

/// A discovered, structurally valid and trusted plugin.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub name: String,
    pub description: Option<String>,
    /// The config section that enables this plugin.
    pub section: String,
    pub order: Option<i64>,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub secrets: Vec<String>,
    /// The plugin directory.
    pub dir: PathBuf,
    apply_sh: String,
    check_sh: Option<String>,
}

/// A plugin directory that was rejected, and why (R93: skipped with a
/// warning, never aborting discovery).
#[derive(Debug, Clone)]
pub struct SkippedPlugin {
    pub name: String,
    pub path: PathBuf,
    pub reason: String,
}

/// The outcome of scanning the plugin base directory.
#[derive(Debug, Default)]
pub struct Discovery {
    pub plugins: Vec<Plugin>,
    pub skipped: Vec<SkippedPlugin>,
}

/// Scan `base` for plugins. Never fails: a missing/unreadable base directory
/// yields an empty discovery, and each malformed or insecure plugin is
/// recorded in `skipped` with its reason (R93).
pub fn discover(base: &Path) -> Discovery {
    discover_as(base, invoking_uid())
}

/// [`discover`] with an explicit expected owner uid (injectable for tests of
/// the foreign-owner rejection, which would otherwise require root).
pub fn discover_as(base: &Path, expected_uid: Option<u32>) -> Discovery {
    let mut d = Discovery::default();
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return d,
    };
    let mut candidates: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    candidates.sort(); // deterministic discovery order
    let mut bound: BTreeMap<String, String> = BTreeMap::new(); // section -> plugin
    for path in candidates {
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(String::from) else {
            continue;
        };
        // Stray regular files (editor droppings etc.) are not plugin
        // candidates; anything else — including symlinked directories —
        // goes through the full checks and is rejected with a reason.
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_symlink() && !meta.is_dir() {
                continue;
            }
        }
        match load_plugin(&path, &name, expected_uid, &bound) {
            Ok(p) => {
                bound.insert(p.section.clone(), p.name.clone());
                d.plugins.push(p);
            }
            Err(reason) => d.skipped.push(SkippedPlugin { name, path, reason }),
        }
    }
    d
}

/// Read a `secure_lstat`-checked file, distinguishing "missing" (its own
/// message) from insecure/unreadable.
fn read_trusted_file(
    path: &Path,
    uid: u32,
    required: bool,
) -> std::result::Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if required {
                Err(format!(
                    "missing {} (required)",
                    path.file_name().and_then(|n| n.to_str()).unwrap_or("file")
                ))
            } else {
                Ok(None)
            }
        }
        _ => {
            let meta = secure_lstat(path, uid)?;
            if !meta.is_file() {
                return Err(format!("{} is not a regular file", path.display()));
            }
            std::fs::read_to_string(path)
                .map(Some)
                .map_err(|e| format!("cannot read {}: {e}", path.display()))
        }
    }
}

/// Read a required trusted file, flattening the `Option` away (a required file
/// is either present-and-trusted or an error — never absent) so callers need no
/// `.expect`. Replaces the two `.expect("required file present")` call sites.
fn read_required_trusted_file(path: &Path, uid: u32) -> std::result::Result<String, String> {
    read_trusted_file(path, uid, true)?
        .ok_or_else(|| format!("{} is required but was not read", path.display()))
}

fn load_plugin(
    dir: &Path,
    dir_name: &str,
    expected_uid: Option<u32>,
    bound: &BTreeMap<String, String>,
) -> std::result::Result<Plugin, String> {
    let uid = expected_uid
        .ok_or("could not determine the invoking user's uid; refusing to trust plugin files")?;
    if !valid_name(dir_name) {
        return Err(format!(
            "invalid plugin name {dir_name:?} (must match ^[A-Za-z0-9_-]+$)"
        ));
    }
    let meta = secure_lstat(dir, uid)?;
    if !meta.is_dir() {
        return Err("not a directory".into());
    }
    // The plugins/ dir itself must be trusted too: a world-writable parent
    // lets another user rename-swap a plugin dir, defeating the per-file
    // checks. We check the immediate parent only — deeper ancestors are
    // not always owned by the user (e.g. a shared /tmp-based discovery root).
    if let Some(parent) = dir.parent() {
        secure_ancestor_dir(parent, uid)?;
    }

    let manifest_text = read_required_trusted_file(&dir.join("plugin.toml"), uid)?;
    let manifest: Manifest =
        toml::from_str(&manifest_text).map_err(|e| format!("malformed plugin.toml: {e}"))?;

    if manifest.name != dir_name {
        return Err(format!(
            "manifest name {:?} does not match the plugin directory name {dir_name:?}",
            manifest.name
        ));
    }
    if !valid_name(&manifest.section) {
        return Err(format!(
            "invalid section name {:?} (must match ^[A-Za-z0-9_-]+$)",
            manifest.section
        ));
    }
    // Binding a built-in module id or structural key would steal its config.
    if crate::config::is_reserved_section(&manifest.section) {
        return Err(format!(
            "section {:?} is a built-in config key and cannot be bound by a plugin",
            manifest.section
        ));
    }
    if let Some(owner) = bound.get(&manifest.section) {
        return Err(format!(
            "section {:?} is already bound by plugin {owner:?}",
            manifest.section
        ));
    }

    let apply_sh = read_required_trusted_file(&dir.join("apply.sh"), uid)?;
    let check_sh = read_trusted_file(&dir.join("check.sh"), uid, false)?;

    Ok(Plugin {
        name: manifest.name,
        description: manifest.description,
        section: manifest.section,
        order: manifest.order,
        before: manifest.before,
        after: manifest.after,
        secrets: manifest.secrets,
        dir: dir.to_path_buf(),
        apply_sh,
        check_sh,
    })
}

// --- {{VAR}} substitution ------------------------------------------------------

/// Render a scalar TOML value for substitution. Arrays/tables have no single
/// shell-word representation and are rejected.
fn scalar_str(context: &str, name: &str, v: &Value) -> Result<String> {
    Ok(match v {
        Value::String(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Datetime(d) => d.to_string(),
        Value::Array(_) | Value::Table(_) => {
            return Err(AnvilError::Validation(format!(
                "{context}: placeholder {{{{{name}}}}} refers to a non-scalar config value \
                 (arrays/tables cannot be substituted)"
            )))
        }
    })
}

/// The quote left open at the end of `line` ("double"/"single"), following
/// bash's rules: `\` escapes the next char outside single quotes.
/// shortcut: per line and no `$(…)` nesting, so a quoted string spanning lines
/// or `"$(cmd "{{v}}")"` is missed; upgrade to a real shell lexer if needed.
fn open_quote(line: &str) -> Option<&'static str> {
    let (mut q, mut esc) = (None, false);
    for c in line.chars() {
        match (q, c) {
            _ if esc => esc = false,
            (Some('\''), '\'') => q = None,
            (Some('\''), _) => {}
            (_, '\\') => esc = true,
            (None, '\'' | '"') => q = Some(c),
            (Some('"'), '"') => q = None,
            _ => {}
        }
    }
    q.map(|c| if c == '"' { "double" } else { "single" })
}

/// Substitute `{{VAR}}` placeholders in a plugin script from the bound config
/// section's keys. Every value passes through [`shell_escape`] (R55/R93); an
/// undefined variable is a hard error, never an empty string (R93), and so is
/// a placeholder inside an open double quote on its line. Text that
/// merely looks like a placeholder but has no well-formed `{{name}}` shape is
/// left untouched.
pub fn substitute(context: &str, script: &str, values: &Table) -> Result<String> {
    let mut out = String::with_capacity(script.len());
    let mut rest = script;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            // A placeholder name: same charset as the TOML bare keys we accept.
            Some(end) if valid_name(&after[..end]) => {
                let name = &after[..end];
                // shell_escape's single quotes are literal inside "…", where
                // `$(…)` still expands: refuse rather than render unsafely.
                let pos = script.len() - rest.len() + start;
                let line = &script[script[..pos].rfind('\n').map_or(0, |i| i + 1)..pos];
                // Inside '…' the escaped value's own quotes close/reopen the
                // string and leave it bare, so single quotes are refused too.
                if let Some(q) = open_quote(line) {
                    return Err(AnvilError::Validation(format!(
                        "{context}: placeholder {{{{{name}}}}} sits inside {q} quotes — \
                         placeholders must be unquoted (the value is already shell-escaped)"
                    )));
                }
                let value = values.get(name).ok_or_else(|| {
                    AnvilError::Validation(format!(
                        "{context}: undefined placeholder {{{{{name}}}}} — the bound config \
                         section does not define `{name}` (undefined variables are an error, \
                         never an empty string)"
                    ))
                })?;
                out.push_str(&shell_escape(&scalar_str(context, name, value)?));
                rest = &after[end + 2..];
            }
            _ => {
                out.push_str("{{");
                rest = after;
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

// --- Enabling: plugin + config section -> Declaration -------------------------

/// An enabled plugin, ready for planning: its ordering hints and the
/// [`Declaration`] rendered from the substituted scripts.
#[derive(Debug, Clone)]
pub struct EnabledPlugin {
    /// `plugin::<name>`. Leaked once per enabled plugin per process so it can
    /// satisfy the `&'static str` id contract of the module registry — a few
    /// bytes for the lifetime of a CLI invocation.
    pub id: &'static str,
    pub order_override: OrderOverride,
    pub declaration: Declaration,
}

impl Plugin {
    /// The id this plugin is addressed by in ordering and results (R92).
    pub fn id_string(&self) -> String {
        format!("{PLUGIN_ID_PREFIX}{}", self.name)
    }

    /// Enable this plugin against its bound section's key/value table:
    /// substitute `{{VAR}}`s and build the single-command [`Declaration`]
    /// (detect = `check.sh`, or always-drifted without one; converge =
    /// `apply.sh`). Substitution failures (undefined variables, non-scalar
    /// values) are hard errors.
    pub fn enable(&self, values: &Table) -> Result<EnabledPlugin> {
        let id = self.id_string();
        let apply = substitute(
            &format!("plugin {} apply.sh", self.name),
            &self.apply_sh,
            values,
        )?;
        // check.sh runs in its own `bash -euo pipefail` (an `if` condition
        // disables `set -e`, so a subshell would ignore every failure but the
        // last); apply.sh runs in a subshell so a stray `exit` cannot end the
        // engine's wrapper, with a trailing `:` so an empty body still parses.
        let detect = match &self.check_sh {
            Some(raw) => {
                let check = substitute(&format!("plugin {} check.sh", self.name), raw, values)?;
                format!("bash -euo pipefail -c {}", shell_escape(&check))
            }
            // No check.sh: the plugin cannot prove alignment, so it is always
            // treated as drifted and apply.sh always runs.
            None => "false".to_string(),
        };
        let converge = format!("(\n{}\n:\n)", apply.trim_end());
        let describe = self
            .description
            .clone()
            .unwrap_or_else(|| format!("plugin {}", self.name));

        let mut declaration =
            Declaration::new(id.clone()).command(ManagedCommand::new(describe, detect, converge));
        for (name, v) in values.iter().filter(|(k, _)| self.secrets.contains(k)) {
            declaration = declaration.secret(scalar_str(&self.name, name, v)?);
        }
        Ok(EnabledPlugin {
            id: Box::leak(id.into_boxed_str()),
            order_override: OrderOverride {
                order: self.order,
                before: self.before.clone(),
                after: self.after.clone(),
            },
            declaration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Removes the fixture dir when the test ends (nextest runs each test in
    /// its own process, so per-pid dirs would otherwise pile up in TMPDIR).
    struct TmpDir(PathBuf);
    impl std::ops::Deref for TmpDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tmp(test: &str) -> TmpDir {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let dir = PathBuf::from(base).join(format!("anvil-plugin-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        TmpDir(dir)
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn write(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        set_mode(path, 0o644);
    }

    /// Create a well-formed plugin directory; tests then break one aspect.
    fn make_plugin(base: &Path, name: &str, section: &str, check: Option<&str>) -> PathBuf {
        let dir = base.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        write(
            &dir.join("plugin.toml"),
            &format!("name = \"{name}\"\nsection = \"{section}\"\n"),
        );
        write(&dir.join("apply.sh"), "echo applying {{value}}\n");
        if let Some(c) = check {
            write(&dir.join("check.sh"), c);
        }
        dir
    }

    fn values(pairs: &[(&str, &str)]) -> Table {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn missing_base_dir_is_empty_discovery() {
        let d = discover(Path::new("/nonexistent/anvil-plugins"));
        assert!(d.plugins.is_empty());
        assert!(d.skipped.is_empty());
    }

    #[test]
    fn valid_plugin_is_discovered_with_manifest_fields() {
        let base = tmp("valid");
        let dir = base.join("pg-tune");
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        write(
            &dir.join("plugin.toml"),
            r#"
                name = "pg-tune"
                description = "tune postgres"
                section = "pg_tune"
                order = 42
                before = ["firewall"]
                after = ["sshd"]
                secrets = ["token"]
            "#,
        );
        write(&dir.join("apply.sh"), "echo hi\n");
        write(&dir.join("check.sh"), "true\n");

        let d = discover(&base);
        assert!(d.skipped.is_empty(), "skipped: {:?}", d.skipped);
        assert_eq!(d.plugins.len(), 1);
        let p = &d.plugins[0];
        assert_eq!(p.name, "pg-tune");
        assert_eq!(p.section, "pg_tune");
        assert_eq!(p.description.as_deref(), Some("tune postgres"));
        assert_eq!(p.order, Some(42));
        assert_eq!(p.before, vec!["firewall"]);
        assert_eq!(p.after, vec!["sshd"]);
        assert_eq!(p.secrets, vec!["token"]);
        assert!(p.check_sh.is_some());
        assert_eq!(p.id_string(), "plugin::pg-tune");
    }

    #[test]
    fn invalid_plugin_names_are_skipped() {
        let base = tmp("badname");
        for bad in ["bad.name", "bad name", "bad/../name"] {
            // `/` cannot exist in a file name; test the two creatable ones and
            // validate the third through the pure name check.
            if !bad.contains('/') {
                make_plugin(&base, bad, "x", None);
            }
            assert!(!valid_name(bad), "{bad:?} must be invalid");
        }
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert_eq!(d.skipped.len(), 2);
        for s in &d.skipped {
            assert!(s.reason.contains("invalid plugin name"), "{}", s.reason);
        }
    }

    #[test]
    fn world_writable_dir_is_skipped() {
        let base = tmp("worldwr");
        let dir = make_plugin(&base, "loose", "loose_cfg", None);
        set_mode(&dir, 0o777);
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert_eq!(d.skipped.len(), 1);
        assert!(
            d.skipped[0].reason.contains("writable"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn world_writable_plugins_parent_dir_is_skipped() {
        // A world-writable plugins/ dir (the plugin's parent) lets another
        // user rename-swap a plugin directory, defeating the per-file checks.
        // The plugin itself is fine; its ancestor is not, so it is skipped.
        let base = tmp("worldwr-parent");
        make_plugin(&base, "ok", "ok_cfg", None);
        set_mode(&base, 0o777); // world-writable parent
        let d = discover(&base);
        assert!(
            d.plugins.is_empty(),
            "plugin under a world-writable parent is skipped"
        );
        assert_eq!(d.skipped.len(), 1);
        let reason = &d.skipped[0].reason;
        assert!(reason.contains("ancestor"), "{reason}");
        assert!(reason.contains("writable"), "{reason}");
    }

    #[test]
    fn group_writable_apply_sh_is_skipped() {
        let base = tmp("groupwr");
        let dir = make_plugin(&base, "loose2", "loose2_cfg", None);
        set_mode(&dir.join("apply.sh"), 0o664);
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("writable"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn symlinked_plugin_dir_is_skipped() {
        let base = tmp("symdir");
        let real = tmp("symdir-target");
        make_plugin(&real, "real", "real_cfg", None);
        std::os::unix::fs::symlink(real.join("real"), base.join("linked")).unwrap();
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert_eq!(d.skipped.len(), 1);
        assert!(
            d.skipped[0].reason.contains("symlink"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn symlinked_script_is_skipped() {
        let base = tmp("symfile");
        let dir = make_plugin(&base, "sneaky", "sneaky_cfg", None);
        std::fs::remove_file(dir.join("apply.sh")).unwrap();
        let outside = base.join("outside.sh");
        write(&outside, "echo outside\n");
        std::os::unix::fs::symlink(&outside, dir.join("apply.sh")).unwrap();
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("symlink"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn foreign_owned_plugin_is_skipped() {
        let base = tmp("foreign");
        make_plugin(&base, "notmine", "notmine_cfg", None);
        // Inject a uid that cannot be ours: everything must be rejected as
        // foreign-owned (creating genuinely foreign files needs root).
        let wrong = invoking_uid().unwrap().wrapping_add(1);
        let d = discover_as(&base, Some(wrong));
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("owned by uid"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn unknown_uid_rejects_everything() {
        let base = tmp("nouid");
        make_plugin(&base, "fine", "fine_cfg", None);
        let d = discover_as(&base, None);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("uid"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn missing_apply_sh_is_skipped() {
        let base = tmp("noapply");
        let dir = make_plugin(&base, "empty", "empty_cfg", None);
        std::fs::remove_file(dir.join("apply.sh")).unwrap();
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("apply.sh"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn malformed_manifest_is_skipped_with_warning() {
        let base = tmp("badmanifest");
        // Missing entirely, syntactically broken, missing `section`, and an
        // unknown key: all four skip with a clear reason.
        let d1 = make_plugin(&base, "m1", "m1_cfg", None);
        std::fs::remove_file(d1.join("plugin.toml")).unwrap();
        let d2 = make_plugin(&base, "m2", "m2_cfg", None);
        write(
            &d2.join("plugin.toml"),
            "name = \"m2\"\nsection = [broken\n",
        );
        let d3 = make_plugin(&base, "m3", "m3_cfg", None);
        write(&d3.join("plugin.toml"), "name = \"m3\"\n");
        let d4 = make_plugin(&base, "m4", "m4_cfg", None);
        write(
            &d4.join("plugin.toml"),
            "name = \"m4\"\nsection = \"m4_cfg\"\nsectoin_typo = true\n",
        );

        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert_eq!(d.skipped.len(), 4);
        let reason = |n: &str| {
            d.skipped
                .iter()
                .find(|s| s.name == n)
                .unwrap()
                .reason
                .clone()
        };
        assert!(reason("m1").contains("plugin.toml"));
        assert!(reason("m2").contains("malformed plugin.toml"));
        assert!(reason("m3").contains("malformed plugin.toml"));
        assert!(reason("m4").contains("malformed plugin.toml"));
    }

    #[test]
    fn manifest_name_must_match_dir_name() {
        let base = tmp("namemismatch");
        let dir = make_plugin(&base, "outer", "outer_cfg", None);
        write(
            &dir.join("plugin.toml"),
            "name = \"inner\"\nsection = \"outer_cfg\"\n",
        );
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("does not match"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn builtin_section_binding_is_rejected() {
        let base = tmp("reserved");
        let dir = make_plugin(&base, "thief", "sshd", None);
        write(
            &dir.join("plugin.toml"),
            "name = \"thief\"\nsection = \"sshd\"\n",
        );
        let d = discover(&base);
        assert!(d.plugins.is_empty());
        assert!(
            d.skipped[0].reason.contains("built-in config key"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn duplicate_section_binding_skips_the_second() {
        let base = tmp("dupsection");
        make_plugin(&base, "aaa", "shared_cfg", None);
        make_plugin(&base, "bbb", "shared_cfg", None);
        let d = discover(&base);
        assert_eq!(d.plugins.len(), 1);
        assert_eq!(d.plugins[0].name, "aaa"); // deterministic: sorted order
        assert_eq!(d.skipped.len(), 1);
        assert_eq!(d.skipped[0].name, "bbb");
        assert!(
            d.skipped[0].reason.contains("already bound"),
            "{}",
            d.skipped[0].reason
        );
    }

    #[test]
    fn discovery_never_aborts_on_a_bad_neighbor() {
        let base = tmp("mixed");
        make_plugin(&base, "good", "good_cfg", Some("true\n"));
        let bad = make_plugin(&base, "bad", "bad_cfg", None);
        std::fs::remove_file(bad.join("apply.sh")).unwrap();
        // A stray regular file in the base dir is ignored silently.
        write(&base.join("README.txt"), "not a plugin\n");

        let d = discover(&base);
        assert_eq!(d.plugins.len(), 1);
        assert_eq!(d.plugins[0].name, "good");
        assert_eq!(d.skipped.len(), 1);
        assert_eq!(d.skipped[0].name, "bad");
    }

    // --- substitution ---------------------------------------------------------

    #[test]
    fn substitution_replaces_and_escapes() {
        let out = substitute(
            "t",
            "systemctl restart {{service}}",
            &values(&[("service", "nginx")]),
        )
        .unwrap();
        assert_eq!(out, "systemctl restart 'nginx'");
    }

    #[test]
    fn substitution_neutralizes_injection() {
        // A hostile config value must arrive inside single quotes, inert.
        let out = substitute("t", "echo {{v}}", &values(&[("v", "'; rm -rf /")])).unwrap();
        assert_eq!(out, "echo ''\\''; rm -rf /'");
    }

    #[test]
    fn substitution_stringifies_scalars() {
        let mut t = Table::new();
        t.insert("port".into(), Value::Integer(8443));
        t.insert("strict".into(), Value::Boolean(true));
        let out = substitute("t", "p={{port}} s={{strict}}", &t).unwrap();
        assert_eq!(out, "p='8443' s='true'");
    }

    #[test]
    fn undefined_placeholder_is_a_hard_error() {
        let err = substitute("plugin x apply.sh", "echo {{missing}}", &Table::new()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("{{missing}}"), "{msg}");
        assert!(msg.contains("plugin x apply.sh"), "{msg}");
        assert!(msg.contains("never an empty string"), "{msg}");
    }

    #[test]
    fn non_scalar_placeholder_is_an_error() {
        let mut t = Table::new();
        t.insert("list".into(), Value::Array(vec![Value::Integer(1)]));
        let err = substitute("t", "echo {{list}}", &t).unwrap_err();
        assert!(err.to_string().contains("non-scalar"), "{err}");
    }

    #[test]
    fn malformed_placeholders_stay_literal() {
        let vals = values(&[("ok", "v")]);
        for (input, expect) in [
            ("a {{not closed", "a {{not closed"),
            ("a {{ spaced }} b", "a {{ spaced }} b"),
            ("{{}} empty", "{{}} empty"),
            ("mix {{ok}} {{bad key}}", "mix 'v' {{bad key}}"),
        ] {
            assert_eq!(substitute("t", input, &vals).unwrap(), expect, "{input:?}");
        }
    }

    // --- enable ---------------------------------------------------------------

    fn sample_plugin(check: Option<&str>) -> Plugin {
        Plugin {
            name: "backup-agent".into(),
            description: Some("nightly backups".into()),
            section: "backup_agent".into(),
            order: None,
            before: vec![],
            after: vec![],
            secrets: vec![],
            dir: PathBuf::from("/x"),
            apply_sh: "install-backup --target {{target}}\n".into(),
            check_sh: check.map(String::from),
        }
    }

    #[test]
    fn enable_builds_a_single_command_declaration() {
        let p = sample_plugin(Some(
            "test -x /usr/bin/backup && grep -q {{target}} /etc/b.conf\n",
        ));
        let e = p.enable(&values(&[("target", "/srv/data")])).unwrap();
        assert_eq!(e.id, "plugin::backup-agent");
        assert_eq!(e.declaration.module_id, "plugin::backup-agent");
        assert_eq!(e.declaration.commands.len(), 1);
        assert!(e.declaration.files.is_empty());

        // The engine renders probe/apply from the substituted scripts.
        let probe = e.declaration.render_probe();
        let apply = e.declaration.render_apply();
        let check = shell_escape("test -x /usr/bin/backup && grep -q '/srv/data' /etc/b.conf\n");
        assert!(
            probe.contains(&format!("bash -euo pipefail -c {check}")),
            "{probe}"
        );
        assert!(!probe.contains("install-backup"), "probe never converges");
        assert!(
            apply.contains("install-backup --target '/srv/data'"),
            "{apply}"
        );
        assert!(apply.contains("CHANGED:"), "marker protocol reused");
    }

    #[test]
    fn listed_secrets_are_masked_in_dry_run_others_shown() {
        let mut p = sample_plugin(Some("probe {{token}}\n"));
        p.apply_sh = "login {{token}} --to {{target}}\n".into();
        p.secrets = vec!["token".into(), "absent".into()];
        let e = p
            .enable(&values(&[
                ("token", "SENTINEL'tok"),
                ("target", "/srv/data"),
            ]))
            .unwrap();
        let d = &e.declaration;
        for s in [d.render_apply(), d.render_probe()] {
            assert!(s.contains("SENTINEL"), "raw script carries it: {s}");
            let shown = d.redact(&s);
            assert!(!shown.contains("SENTINEL"), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
        assert!(d.redact(&d.render_apply()).contains("'/srv/data'"));
    }

    #[test]
    fn enable_without_check_sh_is_always_drifted() {
        let p = sample_plugin(None);
        let e = p.enable(&values(&[("target", "t")])).unwrap();
        assert_eq!(e.declaration.commands[0].detect, "false");
        // A `false` detect makes the probe print DRIFTED unconditionally.
        assert!(e.declaration.render_probe().contains("if false; then"));
    }

    #[test]
    fn enable_propagates_undefined_variable_errors() {
        let p = sample_plugin(None);
        let err = p.enable(&Table::new()).unwrap_err();
        assert!(err.to_string().contains("{{target}}"), "{err}");
    }

    #[test]
    fn enable_carries_manifest_ordering_hints() {
        let mut p = sample_plugin(None);
        p.order = Some(7);
        p.before = vec!["firewall".into()];
        p.after = vec!["sshd".into()];
        let e = p.enable(&values(&[("target", "t")])).unwrap();
        assert_eq!(e.order_override.order, Some(7));
        assert_eq!(e.order_override.before, vec!["firewall"]);
        assert_eq!(e.order_override.after, vec!["sshd"]);
    }

    #[test]
    fn invoking_uid_is_determinable() {
        assert!(invoking_uid().is_some());
    }

    #[test]
    fn default_dir_honors_xdg_shape() {
        // Pure path construction (no env mutation in tests): the default dir
        // always ends in anvil/plugins.
        if let Some(d) = default_plugins_dir() {
            assert!(d.ends_with("anvil/plugins"), "{}", d.display());
        }
    }

    fn bash(args: &[&str], script: &str) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("bash")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    #[test]
    fn multi_line_check_fails_on_any_failing_line() {
        let probe = |check: &str| {
            let e = sample_plugin(Some(check)).enable(&values(&[("target", "t")]));
            let out = bash(&[], &e.unwrap().declaration.render_probe());
            crate::engine::parse_probe(&String::from_utf8_lossy(&out.stdout))
        };
        assert!(matches!(
            probe("false\ntrue\n"),
            crate::engine::Verdict::Drifted(_)
        ));
        assert!(matches!(
            probe("true\ntrue\n"),
            crate::engine::Verdict::Aligned
        ));
    }

    #[test]
    fn double_quoted_placeholder_is_an_error() {
        let v = values(&[("dir", "/srv/data")]);
        let err = substitute("plugin p apply.sh", "mkdir -p \"{{dir}}\"\n", &v).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("plugin p apply.sh") && msg.contains("{{dir}}"),
            "{msg}"
        );
        // Unquoted (also after a closed or escaped quote) still renders.
        assert_eq!(
            substitute("c", "echo \"x\" \\\" {{dir}}\n", &v).unwrap(),
            "echo \"x\" \\\" '/srv/data'\n"
        );
        // Quote state does not leak across lines.
        assert!(substitute("c", "echo \"\nmkdir {{dir}}", &v).is_ok());
        // An escaped backslash does not escape the quote after it, and single
        // quotes leave the escaped value bare: both refused.
        assert!(substitute("c", "echo \\\\\"{{dir}}\"\n", &v).is_err());
        let err = substitute("c", "echo '{{dir}}'\n", &v).unwrap_err();
        assert!(err.to_string().contains("inside single quotes"), "{err}");
        // A backslash inside single quotes is literal and escapes nothing.
        assert!(substitute("c", "echo '\\' {{dir}}\n", &v).is_ok());
        // A later placeholder is judged on its own position.
        assert!(substitute("c", "echo {{dir}} \"{{dir}}\"\n", &v).is_err());
        // A `"` inside single quotes opens nothing.
        assert!(substitute("c", "echo '\"' {{dir}}\n", &v).is_ok());
    }

    #[test]
    fn heredoc_and_empty_apply_render_parseable_bash() {
        for apply in ["cat > /tmp/x <<'EOF'\nhello\nEOF\n", "", "# nothing\n"] {
            let mut p = sample_plugin(Some("true\n"));
            p.apply_sh = apply.into();
            let script = p.enable(&Table::new()).unwrap().declaration.render_apply();
            let out = bash(&["-n"], &script);
            assert!(
                out.status.success(),
                "{}\n---\n{script}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    #[test]
    fn uid_probe_fails_closed_on_a_preexisting_file() {
        let dir = tmp("uid-probe");
        let probe = dir.join("probe");
        write(&probe, "planted");
        assert_eq!(probe_uid(&probe), None);
        assert!(probe.exists(), "someone else's file is left alone");
        let fresh = dir.join("fresh");
        assert!(probe_uid(&fresh).is_some());
        assert!(!fresh.exists());
    }

    #[test]
    fn config_home_must_be_absolute() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(config_home_from(None, None), None);
        assert_eq!(config_home_from(os(""), os("")), None);
        // An empty XDG_CONFIG_HOME falls back to HOME (XDG spec).
        assert_eq!(
            config_home_from(os(""), os("/home/u")),
            Some(PathBuf::from("/home/u/.config"))
        );
        assert_eq!(config_home_from(os("rel"), os("/home/u")), None);
        assert_eq!(config_home_from(None, os("rel")), None);
        assert_eq!(
            config_home_from(os("/x"), os("/home/u")),
            Some(PathBuf::from("/x"))
        );
        assert_eq!(
            config_home_from(None, os("/home/u")),
            Some(PathBuf::from("/home/u/.config"))
        );
    }
}
