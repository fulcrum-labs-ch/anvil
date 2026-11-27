//! The declarative hardening engine (R14–R16, R87–R90).
//!
//! Modules do not hand-write probe/apply bash. Instead they declare what they
//! *own* — a set of [`ManagedFile`]s and [`ManagedCommand`]s (plus an optional
//! validated [`ReloadGuard`]) — and this engine renders the probe and apply
//! scripts from those declarations. Because the same declaration drives probe,
//! apply, diff, and rollback, an entire class of "check disagrees with apply"
//! bugs is designed out.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::escape::shell_escape;

/// The brand used in drop-in filenames and backup suffixes.
pub const BACKUP_SUFFIX: &str = ".anvil.bak";
/// Where per-run change manifests are written on the host (R88).
pub const MANIFEST_DIR: &str = "/var/lib/anvil/runs";
/// Paths anvil created (one per line). A file listed here never gets a
/// `.anvil.bak` — there is no original to keep — so rollback deletes it even
/// after later content changes. `ANVIL_STATE_DIR` relocates it for
/// tests; nothing sets it on a real host.
pub const CREATED_LIST: &str = "/var/lib/anvil/created";

/// How a [`ManagedFile`]'s desired content is produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileContent {
    /// Exact bytes known at render time; base64-embedded into the script so
    /// they are inert to the shell (R55).
    Static(String),
    /// A bash snippet, run on the target, that prints the desired content to
    /// stdout — for files whose correct content depends on the host (e.g.
    /// filtering crypto algorithms by what the host's ssh supports). The
    /// snippet is a trusted, module-authored template; config-derived values
    /// inside it must already be shell-escaped by the module.
    Computed { generator: String },
}

/// A file the tool owns end-to-end: its content, mode and owner are the
/// desired state. The engine backs up any pre-existing file before overwrite
/// (R60) and can diff current-vs-desired directly (R89).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFile {
    pub path: String,
    /// Optional bash snippet (trusted, module-authored; config-derived values
    /// inside it must already be shell-escaped) that prints the file's *real*
    /// path to stdout at runtime. When set, the rendered scripts resolve
    /// `__path` from it instead of using `path` literally — for files whose
    /// location depends on the host (e.g. an account's `authorized_keys`,
    /// found via `getent passwd <name>`). `path` then serves only as a label
    /// for comments/manifests, and the file is skipped by offline `diff`
    /// (its path is unknown until connect time).
    pub path_resolver: Option<String>,
    pub content: FileContent,
    /// Octal mode string, e.g. `"0644"`.
    pub mode: String,
    /// `user:group`, e.g. `"root:root"`.
    pub owner: String,
}

impl ManagedFile {
    /// A file with static desired content (the common case).
    pub fn new(
        path: impl Into<String>,
        desired_content: impl Into<String>,
        mode: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            path_resolver: None,
            content: FileContent::Static(desired_content.into()),
            mode: mode.into(),
            owner: owner.into(),
        }
    }

    /// A file whose desired content is computed on the target by `generator`
    /// (a bash snippet printing the content to stdout).
    pub fn computed(
        path: impl Into<String>,
        generator: impl Into<String>,
        mode: impl Into<String>,
        owner: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            path_resolver: None,
            content: FileContent::Computed {
                generator: generator.into(),
            },
            mode: mode.into(),
            owner: owner.into(),
        }
    }

    /// Resolve this file's real path on the target with `resolver` (a bash
    /// snippet that prints the path to stdout) instead of using `path`
    /// literally. See [`ManagedFile::path_resolver`].
    pub fn with_path_resolver(mut self, resolver: impl Into<String>) -> Self {
        self.path_resolver = Some(resolver.into());
        self
    }

    /// The static desired content, when known at render time (`None` for
    /// [`FileContent::Computed`] files, whose content only exists on the host).
    pub fn static_content(&self) -> Option<&str> {
        match &self.content {
            FileContent::Static(c) => Some(c),
            FileContent::Computed { .. } => None,
        }
    }
}

/// An idempotent side effect that is not a whole-file write: e.g. `useradd`,
/// `ufw enable`, `sysctl --system`. `detect` returns exit 0 when the host is
/// already converged; `converge` performs the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedCommand {
    /// Human-readable summary (appears in output and markers).
    pub describe: String,
    /// Bash expression; exit 0 == already in desired state.
    pub detect: String,
    /// Bash statements that bring the host to desired state.
    pub converge: String,
}

impl ManagedCommand {
    pub fn new(
        describe: impl Into<String>,
        detect: impl Into<String>,
        converge: impl Into<String>,
    ) -> Self {
        Self {
            describe: describe.into(),
            detect: detect.into(),
            converge: converge.into(),
        }
    }
}

/// A validated reload (R57): after files are written, run `validate`; only if
/// it passes do we `reload`. On failure the engine restores every backup it
/// took this run and exits non-zero **without** reloading (auto-revert).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadGuard {
    pub describe: String,
    /// Validation command, e.g. `sshd -t`.
    pub validate: String,
    /// Reload command, run only when validation passes.
    pub reload: String,
}

/// Everything a module owns on a host. The engine turns this into scripts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declaration {
    pub module_id: String,
    pub files: Vec<ManagedFile>,
    pub commands: Vec<ManagedCommand>,
    /// Paths a [`ManagedCommand`] writes or edits *in place* — shared distro
    /// files the module does not own wholesale (e.g. `/etc/login.defs`). The
    /// command must back the file up to `<path>.anvil.bak` before changing it;
    /// [`Declaration::render_rollback`] then restores it from that backup. The
    /// engine never *deletes* a command-edited file (unlike one it created): if
    /// no backup exists it leaves the file alone, so re-running rollback is safe.
    pub command_files: Vec<String>,
    /// Optional module-authored rollback script (trusted bash). For changes
    /// that are only reversible via runtime state a command recorded — e.g. the
    /// `suid` module's state file of stripped set-id modes — which neither a
    /// [`ManagedFile`] restore nor a `command_file` `.anvil.bak` can express.
    /// Runs last in rollback and emits its own `CHANGED:`/`OK:`/`FAILED:`
    /// markers (parsed by [`parse_apply`]); files/command_files are still
    /// undone first.
    pub rollback: Option<String>,
    /// Optional module-authored script run *before* files are undone — e.g.
    /// stopping a service whose unit/config files rollback is about to delete.
    pub rollback_first: Option<String>,
    /// Optional guarded reload evaluated after all files/commands.
    pub reload: Option<ReloadGuard>,
    /// Module-authored cleanup run last in apply only, after the reload
    /// succeeded (never in rollback), e.g. images a restart just released.
    /// Must not fail the apply.
    pub after_apply: Option<String>,
    /// When true, this declaration's scripts run on the **operator's** machine
    /// (plain local `bash -s`, no ssh, no sudo) — e.g. the hetzner module
    /// driving the `hcloud` CLI with a local HCLOUD_TOKEN. Default: false
    /// (scripts run on the target over SSH).
    pub runs_locally: bool,
    /// Config secrets this declaration embeds in its scripts. The scripts must
    /// carry them to the host (ssh stdin), but [`Declaration::redact`] masks
    /// them wherever a script is shown (`--dry-run`).
    pub secrets: Vec<String>,
    /// Host software this module adds beyond its own files, named by
    /// `check` so it is never a surprise, e.g. "Docker".
    pub installs: Vec<String>,
}

impl Declaration {
    pub fn new(module_id: impl Into<String>) -> Self {
        Self {
            module_id: module_id.into(),
            ..Default::default()
        }
    }

    pub fn file(mut self, f: ManagedFile) -> Self {
        self.files.push(f);
        self
    }

    pub fn command(mut self, c: ManagedCommand) -> Self {
        self.commands.push(c);
        self
    }

    /// Declare a path a command edits in place (backed up to `.anvil.bak`),
    /// so `rollback` can restore it. See [`Declaration::command_files`].
    pub fn command_file(mut self, path: impl Into<String>) -> Self {
        self.command_files.push(path.into());
        self
    }

    /// Attach a module-authored rollback script. See [`Declaration::rollback`].
    /// Repeated calls append, in call order.
    pub fn rollback_script(mut self, script: impl Into<String>) -> Self {
        let script = script.into();
        self.rollback = Some(match self.rollback.take() {
            Some(prev) => prev + &script,
            None => script,
        });
        self
    }

    /// Set the script run first in rollback (replaces, unlike
    /// [`Declaration::rollback_script`]). See [`Declaration::rollback_first`].
    pub fn rollback_first(mut self, script: impl Into<String>) -> Self {
        self.rollback_first = Some(script.into());
        self
    }

    /// Append to [`Declaration::after_apply`].
    pub fn after_apply(mut self, script: impl Into<String>) -> Self {
        self.after_apply = Some(self.after_apply.take().unwrap_or_default() + &script.into());
        self
    }

    pub fn guarded_reload(mut self, r: ReloadGuard) -> Self {
        self.reload = Some(r);
        self
    }

    /// Register a secret value for [`Declaration::redact`]. Values under 4
    /// chars are no credential and would garble the shown script: ignored.
    pub fn installs(mut self, what: &[&str]) -> Self {
        self.installs.extend(what.iter().map(|w| w.to_string()));
        self
    }

    pub fn secret(mut self, value: impl Into<String>) -> Self {
        let v = value.into();
        if v.chars().count() >= 4 {
            self.secrets.push(v);
        }
        self
    }

    /// `script` with every registered secret masked, for display: escaped
    /// twice (a generator printing escaped lines), once, then raw — each also
    /// inside a larger escaped string, so the surrounding quotes are not needed.
    pub fn redact(&self, script: &str) -> String {
        let inner = |e: String| e[1..e.len() - 1].to_string();
        let mut s = script.to_string();
        for v in &self.secrets {
            for form in [
                inner(shell_escape(&shell_escape(v))),
                inner(shell_escape(v)),
                v.clone(),
            ] {
                s = s.replace(&form, "<redacted>");
            }
        }
        s
    }

    /// Mark this declaration as running on the operator's machine instead of
    /// the target host (see [`Declaration::runs_locally`]).
    pub fn local(mut self) -> Self {
        self.runs_locally = true;
        self
    }
}

// --- Typed results (R16, R98) ----------------------------------------------

/// Outcome of a read-only probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Aligned,
    Drifted(Vec<String>),
}

impl Verdict {
    /// Stable machine string (R98).
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Aligned => "aligned",
            Verdict::Drifted(_) => "drifted",
        }
    }
}

/// Per-item change classification (R16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Modified,
    Removed,
    NoOp,
}

/// Aggregate status vocabulary for a module apply (R98).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    Changed,
    Ok,
    Failed,
    DryRun,
    Skipped,
}

impl ApplyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApplyStatus::Changed => "changed",
            ApplyStatus::Ok => "ok",
            ApplyStatus::Failed => "failed",
            ApplyStatus::DryRun => "dry-run",
            ApplyStatus::Skipped => "skipped",
        }
    }
}

// --- Marker protocol (R87, Fixed Contract, defined here ONCE) --------------

pub const MARK_CHANGED: &str = "CHANGED:";
pub const MARK_DRIFTED: &str = "DRIFTED:";
pub const MARK_OK: &str = "OK:";
pub const MARK_FAILED: &str = "FAILED:";

/// Interpret probe output. Any `DRIFTED:` line means drift; its text is a
/// reason.
pub fn parse_probe(stdout: &str) -> Verdict {
    let reasons: Vec<String> = stdout
        .lines()
        .filter_map(|l| l.trim().strip_prefix(MARK_DRIFTED))
        .map(|r| r.trim().to_string())
        .collect();
    if reasons.is_empty() {
        Verdict::Aligned
    } else {
        Verdict::Drifted(reasons)
    }
}

/// Interpret apply output into an aggregate status.
pub fn parse_apply(stdout: &str) -> ApplyStatus {
    let mut changed = false;
    for line in stdout.lines() {
        let l = line.trim();
        if l.starts_with(MARK_FAILED) {
            return ApplyStatus::Failed;
        }
        if l.starts_with(MARK_CHANGED) {
            changed = true;
        }
    }
    if changed {
        ApplyStatus::Changed
    } else {
        ApplyStatus::Ok
    }
}

// --- Script rendering -------------------------------------------------------

fn header(module_id: &str) -> String {
    format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n# anvil module: {}\n",
        module_id
    )
}

fn b64(content: &str) -> String {
    B64.encode(content.as_bytes())
}

/// Flatten free text (describe strings, file paths) for embedding in a script
/// `#` comment. A config-derived value containing a newline would otherwise
/// terminate the comment and execute the remainder; every ASCII control
/// character (\n, \r, tab, …) is replaced with a space so the comment stays a
/// single inert line (R55 spirit).
fn comment_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_control() { ' ' } else { c })
        .collect()
}

/// The `__path=…` line that opens a file's script block. A static path is a
/// shell-escaped literal; a file with a `path_resolver` resolves `__path` from
/// that snippet at runtime (host-computed path). Command substitution strips a
/// trailing newline, which is correct for a path.
fn path_line(f: &ManagedFile) -> String {
    match &f.path_resolver {
        Some(resolver) => format!("__path=$({resolver})\n"),
        None => format!("__path={}\n", shell_escape(&f.path)),
    }
}

/// The bash `[ … ]` condition that is true when the file's owner matches the
/// declared `owner`. A full `user:group` (e.g. `root:root`) compares
/// `stat -c '%U:%G'`. A trailing-colon form `user:` — chown's "login group"
/// shorthand — compares only `stat -c '%U'`, because the login group is
/// whatever the account's passwd entry says and must not be pinned to a guessed
/// name (pre-existing accounts, root, …). Either way `chown` is invoked with
/// the raw `owner` string, which chown interprets identically.
fn owner_check(owner: &str) -> String {
    match owner.strip_suffix(':') {
        Some(user) if !user.is_empty() => format!(
            "[ \"$(stat -c '%U' \"$__path\")\" = {} ]",
            shell_escape(user)
        ),
        _ => format!(
            "[ \"$(stat -c '%U:%G' \"$__path\")\" = {} ]",
            shell_escape(owner)
        ),
    }
}

/// An octal mode literal (`"0644"`) normalized the way `stat -c '%a'` reports
/// it on the target — leading zeros stripped, bare `"0"` for an all-zero mode
/// — so a probe's mode comparison matches what `chmod` actually produced. No
/// octal mode contains an 8 or 9, so stripping leading zeros is sound.
pub(crate) fn norm_mode(mode: &str) -> String {
    match mode.trim_start_matches('0') {
        "" => "0".to_string(),
        s => s.to_string(),
    }
}

/// For the read-only probe: an optional `__desired=` assignment line (computed
/// content only) and the bash condition that is true when the live file's
/// *content* already equals the desired bytes. Static content is compared
/// byte-exactly with `cmp` against an inline base64 decode — process
/// substitution `<(...)` feeds the exact decoded bytes, so trailing newlines
/// that `$(...)` would strip survive on both sides (R15 "exact bytes").
/// Computed content is captured into `__desired` once and string-compared.
fn probe_content_parts(f: &ManagedFile) -> (String, String) {
    match &f.content {
        FileContent::Static(content) => (
            String::new(),
            format!(
                "cmp -s \"$__path\" <(printf '%s' {} | base64 -d)",
                shell_escape(&b64(content))
            ),
        ),
        FileContent::Computed { generator } => (
            format!("__desired=$({generator})\n"),
            "[ \"$(cat \"$__path\")\" = \"$__desired\" ]".to_string(),
        ),
    }
}

/// For apply: the same optional assignment and content condition as the probe
/// (so they can never disagree, R15), plus the command that writes the desired
/// bytes to the path. Static content is decoded straight to the file (exact
/// bytes); computed content is written from the captured `__desired`.
fn apply_content_parts(f: &ManagedFile) -> (String, String, String) {
    match &f.content {
        FileContent::Static(content) => {
            let b = shell_escape(&b64(content));
            (
                String::new(),
                format!("cmp -s \"$__path\" <(printf '%s' {b} | base64 -d)"),
                format!("printf '%s' {b} | base64 -d > \"$__path\""),
            )
        }
        FileContent::Computed { generator } => (
            format!("__desired=$({generator})\n"),
            "[ \"$(cat \"$__path\")\" = \"$__desired\" ]".to_string(),
            // `$(...)` dropped the generator's final newline; a config file
            // without one gets glued to the next file (augenrules).
            "printf '%s\\n' \"$__desired\" > \"$__path\"".to_string(),
        ),
    }
}

impl Declaration {
    /// Render the read-only probe script. It prints `OK:`/`DRIFTED:` marker
    /// lines and never mutates the host.
    pub fn render_probe(&self) -> String {
        let mut s = header(&self.module_id);
        // Commands (prerequisites) precede files, matching apply order.
        for c in &self.commands {
            s.push_str(&render_command_probe(c));
        }
        for f in &self.files {
            s.push_str(&render_file_probe(f));
        }
        // A reload guard is not itself drift; probe ignores it.
        s
    }

    /// Render the converging apply script. It backs up before overwrite,
    /// writes a per-run manifest, prints `CHANGED:`/`OK:` markers, and (if a
    /// [`ReloadGuard`] is present) validates before reloading with auto-revert
    /// on failure.
    pub fn render_apply(&self) -> String {
        let mut s = header(&self.module_id);
        s.push_str(&format!(
            "__ts=$(date +%Y%m%dT%H%M%S 2>/dev/null || echo now)\n\
             __manifest={manifest_dir}/{module}.$__ts\n\
             mkdir -p {manifest_dir} 2>/dev/null || true\n\
             : > \"$__manifest\" 2>/dev/null || __manifest=/dev/null\n\
             __reverts=()\n\
             __creates=()\n\
             __rundir=$(mktemp -d /var/lib/anvil/revert.XXXXXX 2>/dev/null || mktemp -d)\n\
             trap 'rm -rf \"$__rundir\"; [ \"$__manifest\" = /dev/null ] || [ -s \"$__manifest\" ] || rm -f \"$__manifest\"' EXIT\n\
             {created_fns}",
            manifest_dir = shell_escape(MANIFEST_DIR),
            module = self.module_id,
            created_fns = created_list_fns(),
        ));
        // Prerequisite commands (package installs, user creation, …) run before
        // any managed file is written, so file ownership/validation succeeds.
        for c in &self.commands {
            s.push_str(&render_command_apply(c));
        }
        // Refuse a symlinked path before any file is written. After the
        // commands, so a resolver can find e.g. a just-created user's home.
        for f in &self.files {
            s.push_str(&path_line(f));
            s.push_str(&refuse_symlink());
        }
        for f in &self.files {
            s.push_str(&render_file_apply(f));
        }
        if let Some(guard) = &self.reload {
            s.push_str(&render_reload_guard(guard));
        }
        if let Some(after) = &self.after_apply {
            s.push_str(after);
        }
        s
    }

    /// Render the rollback script (R60/R88). For each managed file, restore its
    /// `.anvil.bak` backup if one exists; otherwise remove the file, since a
    /// file with no backup was *created* by anvil and undoing a creation means
    /// deletion (a backup-only scheme cannot). Prints `CHANGED:`/`OK:` markers so
    /// [`parse_apply`] can classify the outcome. A module that owns no files has
    /// nothing to roll back.
    pub fn render_rollback(&self) -> String {
        let mut s = header(&self.module_id);
        s.push_str(&created_list_fns());
        if self.files.is_empty()
            && self.command_files.is_empty()
            && self.rollback.is_none()
            && self.rollback_first.is_none()
        {
            s.push_str(&format!(
                "printf '{ok} {module} owns no files; nothing to roll back\\n'\n",
                ok = MARK_OK,
                module = self.module_id,
            ));
            return s;
        }
        if let Some(first) = &self.rollback_first {
            s.push_str(first);
        }
        // Reverse apply order so dependent files are undone last-in-first-out.
        for f in self.files.iter().rev() {
            s.push_str(&render_file_rollback(f));
        }
        // Command-edited shared files: restore from backup if one exists, else
        // leave them alone (we never own them wholesale, so never delete).
        for p in self.command_files.iter().rev() {
            s.push_str(&render_command_file_rollback(p));
        }
        // Module-authored rollback runs last, after files/command_files are
        // undone, and emits its own markers. Used for changes reversible only
        // via runtime state a command recorded (e.g. suid's stripped-bit log).
        if let Some(rb) = &self.rollback {
            s.push_str(rb);
        }
        // Restoring files changes only the disk; re-run the module's
        // validated reload so the running service picks the restored config
        // up. There is nothing to revert to if it fails — report it.
        if let Some(g) = &self.reload {
            s.push_str(&format!(
                "\n# reload with the restored config: {comment}\n\
                 if {{ {validate}\n}} && {{ {reload}\n}}; then\n\
                 \x20 printf '{ok} %s reloaded with the restored config\\n' {desc}\n\
                 else\n\
                 \x20 printf '{failed} %s restored config did not validate or reload\\n' {desc}\n\
                 \x20 exit 1\n\
                 fi\n",
                comment = comment_text(&g.describe),
                validate = g.validate,
                reload = g.reload,
                desc = shell_escape(&g.describe),
                ok = MARK_OK,
                failed = MARK_FAILED,
            ));
        }
        s
    }
}

fn render_file_probe(f: &ManagedFile) -> String {
    let mode = shell_escape(&norm_mode(&f.mode));
    let (assignment, content_check) = probe_content_parts(f);
    format!(
        "\n# file: {comment_path}\n\
         {path_line}\
         {assignment}\
         if [ -L \"$__path\" ]; then\n\
         \x20 printf '{drift} %s is a symlink; anvil refuses to manage a symlinked path\\n' \"$__path\"\n\
         elif [ -f \"$__path\" ] && {content_check} && [ \"$(stat -c '%a' \"$__path\")\" = {mode} ] && {owner_check}; then\n\
         \x20 printf '{ok} %s up to date\\n' \"$__path\"\n\
         elif [ -f \"$__path\" ]; then\n\
         \x20 printf '{drift} %s content, mode, or owner differs\\n' \"$__path\"\n\
         else\n\
         \x20 printf '{drift} %s missing\\n' \"$__path\"\n\
         fi\n",
        comment_path = comment_text(&f.path),
        path_line = path_line(f),
        assignment = assignment,
        content_check = content_check,
        mode = mode,
        owner_check = owner_check(&f.owner),
        ok = MARK_OK,
        drift = MARK_DRIFTED,
    )
}

fn render_file_apply(f: &ManagedFile) -> String {
    let mode = shell_escape(&f.mode);
    let mode_norm = shell_escape(&norm_mode(&f.mode));
    let owner = shell_escape(&f.owner);
    let (assignment, content_check, write) = apply_content_parts(f);
    format!(
        "\n# file: {comment_path}\n\
         {path_line}\
         {assignment}\
         __verb=''\n\
         if [ -f \"$__path\" ] && {content_check}; then\n\
         \x20 : # content already correct\n\
         else\n\
         \x20 # New parent dirs 0755 whatever the host umask (CIS sets 0007 or 027), so\n\
         \x20 # files meant for service users stay reachable; the file's own mode guards it.\n\
         \x20 (umask 022 && mkdir -p \"$(dirname \"$__path\")\")\n\
         \x20 if [ -f \"$__path\" ]; then\n\
         \x20\x20 cp -a \"$__path\" \"$__rundir/${{__path//\\//%}}\"\n\
         \x20\x20 # Keep the pristine original — back up on the first change\n\
         \x20\x20 # only, and never for a file anvil itself created.\n\
         \x20\x20 if [ ! -e \"$__path{bak}\" ] && ! __anvil_created \"$__path\"; then\n\
         \x20\x20\x20 cp -a \"$__path\" \"$__path{bak}\"\n\
         \x20\x20 fi\n\
         \x20\x20 __reverts+=(\"$__path\")\n\
         \x20\x20 __verb=Modified\n\
         \x20 else\n\
         \x20\x20 __creates+=(\"$__path\")\n\
         \x20\x20 __anvil_remember \"$__path\"\n\
         \x20\x20 __verb=Created\n\
         \x20 fi\n\
         \x20 {write}\n\
         fi\n\
         if [ \"$(stat -c '%a' \"$__path\")\" != {mode_norm} ] || ! {owner_check}; then\n\
         \x20 if [ -z \"$__verb\" ]; then\n\
         \x20\x20 # Mode/owner-only fix; the copy keeps both so the guard can revert\n\
         \x20\x20 cp -a \"$__path\" \"$__rundir/${{__path//\\//%}}\"\n\
         \x20\x20 # A pre-existing file needs its pristine mode/owner kept too,\n\
         \x20\x20 # or rollback has no backup and would treat it as anvil-created.\n\
         \x20\x20 if [ ! -e \"$__path{bak}\" ] && ! __anvil_created \"$__path\"; then\n\
         \x20\x20\x20 cp -a \"$__path\" \"$__path{bak}\"\n\
         \x20\x20 fi\n\
         \x20\x20 __reverts+=(\"$__path\")\n\
         \x20\x20 __verb=Modified\n\
         \x20 fi\n\
         fi\n\
         chown {owner} \"$__path\"\n\
         chmod {mode} \"$__path\"\n\
         if [ -n \"$__verb\" ]; then\n\
         \x20 printf '%s\\t%s\\t%s\\n' \"$__verb\" \"$__path\" \"$__ts\" >> \"$__manifest\"\n\
         \x20 printf '{changed} %s (%s)\\n' \"$__path\" \"$__verb\"\n\
         else\n\
         \x20 printf '{ok} %s already correct\\n' \"$__path\"\n\
         fi\n",
        comment_path = comment_text(&f.path),
        path_line = path_line(f),
        assignment = assignment,
        content_check = content_check,
        write = write,
        mode = mode,
        mode_norm = mode_norm,
        owner = owner,
        owner_check = owner_check(&f.owner),
        bak = BACKUP_SUFFIX,
        ok = MARK_OK,
        changed = MARK_CHANGED,
    )
}

/// A symlinked managed path is refused (`FAILED:`, exit 1). Writing
/// follows the link but `cp -a` backs up the link itself, so the target's
/// bytes could never be restored; resolving the link instead would key
/// backup, drift and rollback on a path the declaration does not name.
fn refuse_symlink() -> String {
    format!(
        "if [ -L \"$__path\" ]; then\n\
         \x20 printf '{failed} %s is a symlink; refusing to manage a symlinked path\\n' \"$__path\"\n\
         \x20 exit 1\n\
         fi\n",
        failed = MARK_FAILED,
    )
}

fn render_file_rollback(f: &ManagedFile) -> String {
    format!(
        "\n# rollback: {comment_path}\n\
         {path_line}\
         if [ -f \"$__path{bak}\" ]; then\n\
         \x20 cp -a \"$__path{bak}\" \"$__path\"\n\
         \x20 rm -f \"$__path{bak}\"\n\
         \x20 printf '{changed} %s restored from backup\\n' \"$__path\"\n\
         elif [ -L \"$__path\" ]; then\n\
         \x20 printf '{ok} %s is a symlink anvil does not manage; left alone\\n' \"$__path\"\n\
         elif [ -e \"$__path\" ] && {{ __anvil_created \"$__path\" \\\n\
         \x20 || grep -qsF \"$(printf 'Created\\t%s\\t' \"$__path\")\" \"${{ANVIL_STATE_DIR:-/var/lib/anvil}}\"/runs/*; }}; then\n\
         \x20 rm -f \"$__path\"\n\
         \x20 printf '{changed} %s removed (created by anvil, no backup)\\n' \"$__path\"\n\
         elif [ -e \"$__path\" ]; then\n\
         \x20 # No backup and no record of anvil creating it — never delete.\n\
         \x20 printf '{ok} %s was not created by anvil and has no backup; left in place\\n' \"$__path\"\n\
         else\n\
         \x20 printf '{ok} %s nothing to roll back\\n' \"$__path\"\n\
         fi\n\
         __anvil_forget \"$__path\"\n",
        comment_path = comment_text(&f.path),
        path_line = path_line(f),
        bak = BACKUP_SUFFIX,
        changed = MARK_CHANGED,
        ok = MARK_OK,
    )
}

/// Shell helpers over [`CREATED_LIST`]: `__anvil_created <path>` tests
/// membership, `__anvil_remember`/`__anvil_forget` add/remove a line.
/// Whole-line fixed-string matching (`grep -xF`), so paths are never regexes.
fn created_list_fns() -> String {
    format!(
        "__created_list=${{ANVIL_STATE_DIR:-{state}}}/created\n\
         __anvil_created() {{ grep -qsxF -- \"$1\" \"$__created_list\"; }}\n\
         __anvil_remember() {{ __anvil_created \"$1\" || {{ mkdir -p \"$(dirname \"$__created_list\")\" && printf '%s\\n' \"$1\" >> \"$__created_list\"; }} || true; }}\n\
         __anvil_forget() {{ [ -f \"$__created_list\" ] || return 0; grep -vxF -- \"$1\" \"$__created_list\" > \"$__created_list.tmp\" 2>/dev/null || true; [ -f \"$__created_list.tmp\" ] && mv -f \"$__created_list.tmp\" \"$__created_list\" 2>/dev/null || true; }}\n",
        state = shell_escape(CREATED_LIST.trim_end_matches("/created")),
    )
}

/// Rollback for a path a command edited in place (see [`Declaration::command_files`]).
/// Unlike [`render_file_rollback`], this never deletes the live file: a shared
/// distro file (e.g. `/etc/login.defs`) is restored from its `.anvil.bak` if
/// present, deleted if the command recorded it as created (`__anvil_remember`),
/// and left untouched otherwise — so re-running rollback is safe and never
/// removes a system file anvil did not create.
fn render_command_file_rollback(path: &str) -> String {
    let p = shell_escape(path);
    format!(
        "\n# rollback (command-edited): {comment_path}\n\
         __path={p}\n\
         if [ -f \"$__path{bak}\" ]; then\n\
         \x20 cp -a \"$__path{bak}\" \"$__path\"\n\
         \x20 rm -f \"$__path{bak}\"\n\
         \x20 printf '{changed} %s restored from backup\\n' \"$__path\"\n\
         elif [ -f \"$__path\" ] && __anvil_created \"$__path\"; then\n\
         \x20 rm -f \"$__path\"\n\
         \x20 __anvil_forget \"$__path\"\n\
         \x20 printf '{changed} %s removed (anvil created it)\\n' \"$__path\"\n\
         else\n\
         \x20 printf '{ok} %s nothing to roll back\\n' \"$__path\"\n\
         fi\n",
        comment_path = comment_text(path),
        p = p,
        bak = BACKUP_SUFFIX,
        changed = MARK_CHANGED,
        ok = MARK_OK,
    )
}

fn render_command_probe(c: &ManagedCommand) -> String {
    let desc = shell_escape(&c.describe);
    format!(
        "\n# check: {comment}\n\
         if {detect}; then\n\
         \x20 printf '{ok} %s\\n' {desc}\n\
         else\n\
         \x20 printf '{drift} %s\\n' {desc}\n\
         fi\n",
        comment = comment_text(&c.describe),
        detect = c.detect,
        desc = desc,
        ok = MARK_OK,
        drift = MARK_DRIFTED,
    )
}

fn render_command_apply(c: &ManagedCommand) -> String {
    let desc = shell_escape(&c.describe);
    format!(
        "\n# converge: {comment}\n\
         if {detect}; then\n\
         \x20 printf '{ok} %s (already)\\n' {desc}\n\
         else\n\
         {converge}\n\
         \x20 printf '%s\\t%s\\n' cmd {desc} >> \"$__manifest\"\n\
         \x20 printf '{changed} %s\\n' {desc}\n\
         fi\n",
        comment = comment_text(&c.describe),
        detect = c.detect,
        converge = c.converge,
        desc = desc,
        ok = MARK_OK,
        changed = MARK_CHANGED,
    )
}

/// On validation or reload failure the guard undoes everything this run wrote: files the
/// run *created* are removed (a backup-only scheme would leak them on disk —
/// e.g. an invalid sshd drop-in that breaks the next restart), files it
/// *modified* are restored from their `.anvil.bak` backups (paths registered
/// by module commands without a backup are removed likewise). It then reports
/// FAILED and exits 1 **without** a successful reload.
fn render_reload_guard(g: &ReloadGuard) -> String {
    let desc = shell_escape(&g.describe);
    format!(
        "\n# guarded reload: {comment}\n\
         if {{ {validate}\n\
         }} && {{ {reload}\n\
         }}; then\n\
         \x20 printf '{ok} %s validated and reloaded\\n' {desc}\n\
         else\n\
         \x20 printf '{failed} %s validation or reload failed, reverting\\n' {desc} >&2\n\
         \x20 for __c in \"${{__creates[@]:-}}\"; do\n\
         \x20\x20 [ -n \"$__c\" ] || continue\n\
         \x20\x20 rm -f \"$__c\"\n\
         \x20\x20 __anvil_forget \"$__c\"\n\
         \x20 done\n\
         \x20 for __r in \"${{__reverts[@]:-}}\"; do\n\
         \x20\x20 [ -n \"$__r\" ] || continue\n\
         \x20\x20 if [ -f \"$__rundir/${{__r//\\//%}}\" ]; then cp -a \"$__rundir/${{__r//\\//%}}\" \"$__r\";\n\
         \x20\x20 elif [ -f \"$__r{bak}\" ]; then mv -f \"$__r{bak}\" \"$__r\"; else rm -f \"$__r\"; fi\n\
         \x20 done\n\
         \x20 exit 1\n\
         fi\n",
        comment = comment_text(&g.describe),
        validate = g.validate,
        reload = g.reload,
        desc = desc,
        ok = MARK_OK,
        failed = MARK_FAILED,
        bak = BACKUP_SUFFIX,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_strings_are_the_stable_vocabulary() {
        assert_eq!(Verdict::Aligned.as_str(), "aligned");
        assert_eq!(Verdict::Drifted(vec![]).as_str(), "drifted");
    }

    fn sample() -> Declaration {
        Declaration::new("demo")
            .file(ManagedFile::new(
                "/etc/demo.conf",
                "key = value\n",
                "0644",
                "root:root",
            ))
            .command(ManagedCommand::new(
                "ensure widget",
                "test -e /usr/bin/widget",
                "apt-get install -y widget",
            ))
    }

    #[test]
    fn probe_marks_and_never_mutates() {
        let s = sample().render_probe();
        assert!(s.contains("set -euo pipefail"));
        assert!(s.contains(MARK_DRIFTED));
        assert!(s.contains(MARK_OK));
        // A probe must not write, back up, chmod/chown, remove, or reload —
        // only read (cat/cmp/stat).
        assert!(!s.contains("cp -a"));
        assert!(!s.contains("> \"$__path\""));
        assert!(!s.contains("chmod"));
        assert!(!s.contains("chown"));
        assert!(!s.contains("rm -f"));
        assert!(!s.contains("mkdir"));
    }

    #[test]
    fn apply_creates_parent_dirs_world_traversable() {
        // A CIS umask (0007) made /usr/local/libexec/anvil 0750, hiding the
        // runner's job hook from the github-runner user.
        let s = sample().render_apply();
        assert!(s.contains("(umask 022 && mkdir -p \"$(dirname \"$__path\")\")"));
    }

    #[test]
    fn probe_checks_mode_and_owner() {
        // A file is converged only when content AND mode AND owner all match.
        // Otherwise a world-writable sudoers drop-in or a wrong-owner
        // authorized_keys reports "aligned" forever (R15/R56).
        let s = sample().render_probe();
        assert!(s.contains("stat -c '%a'"), "probe must check mode:\n{s}");
        assert!(
            s.contains("stat -c '%U:%G'"),
            "probe must check owner:\n{s}"
        );
        // Declared mode 0644 normalizes to 644 (what `stat -c '%a'` reports);
        // owner appears verbatim. A drifted value must trip the comparison.
        assert!(s.contains("= '644'"), "mode literal present:\n{s}");
        assert!(s.contains("= 'root:root'"), "owner literal present:\n{s}");
    }

    #[test]
    fn apply_has_unconditional_mode_and_owner_enforcement() {
        // chmod/chown run outside the content-mismatch gate, so a file whose
        // content is already correct but whose mode/owner drifted is still
        // fixed and reported CHANGED (end-to-end behavior pinned by the
        // roundtrip harness in tests/engine_roundtrip.rs).
        let s = sample().render_apply();
        assert!(
            s.contains("stat -c '%a'") && s.contains("stat -c '%U:%G'"),
            "apply must detect mode/owner drift:\n{s}"
        );
        // chmod/chown land after the mode/owner drift check (i.e. outside the
        // content `if`/`fi`), so they run regardless of whether content matched.
        let mode_check = s.find("stat -c '%a'").expect("mode check");
        assert!(
            s.find("chmod").unwrap() > mode_check,
            "chmod after drift check:\n{s}"
        );
        assert!(
            s.find("chown").unwrap() > mode_check,
            "chown after drift check:\n{s}"
        );
    }

    #[test]
    fn static_content_is_compared_and_written_byte_exact() {
        // Trailing newlines survive: the content compare uses cmp against an
        // inline decode (process substitution), and the write decodes straight
        // to the file — neither goes through lossy $(...) (R15 "exact bytes").
        let s = sample().render_apply();
        assert!(
            s.contains("cmp -s \"$__path\" <(printf '%s'"),
            "byte-exact compare via cmp + process sub:\n{s}"
        );
        assert!(
            s.contains("| base64 -d > \"$__path\""),
            "byte-exact write via inline decode:\n{s}"
        );
        assert!(
            !s.contains("__desired="),
            "static apply must not capture __desired via $(...):\n{s}"
        );
    }

    #[test]
    fn apply_backs_up_before_overwrite() {
        let s = sample().render_apply();
        // Backup precedes the write in source order.
        let bak = s.find("cp -a").expect("backup present");
        let write = s.find("base64 -d > \"$__path\"").expect("write present");
        assert!(bak < write, "must back up before writing");
        assert!(s.contains(BACKUP_SUFFIX));
        assert!(s.contains(MANIFEST_DIR));
    }

    #[test]
    fn after_apply_runs_last_in_apply_only() {
        let d = sample()
            .guarded_reload(ReloadGuard {
                describe: "demo".into(),
                validate: "true".into(),
                reload: "true".into(),
            })
            .after_apply("echo tidy-1\n")
            .after_apply("echo tidy-2\n");
        let apply = d.render_apply();
        let guard = apply.find("# guarded reload").unwrap();
        assert!(
            apply.ends_with("echo tidy-1\necho tidy-2\n") && guard < apply.find("tidy-1").unwrap()
        );
        assert!(!d.render_rollback().contains("tidy") && !d.render_probe().contains("tidy"));
    }

    #[test]
    fn apply_keeps_a_manifest_only_when_it_recorded_something() {
        let dir = std::env::temp_dir().join(format!("anvil-runs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let run = |detect: &str| {
            let s = Declaration::new("demo")
                .command(ManagedCommand::new("widget", detect, ":"))
                .render_apply()
                .replace(MANIFEST_DIR, dir.to_str().unwrap());
            let ok = std::process::Command::new("bash")
                .arg("-c")
                .arg(s)
                .status()
                .is_ok_and(|st| st.success());
            assert!(ok);
            std::fs::read_dir(&dir).map_or(0, |d| d.count())
        };
        // A converged run leaves no empty manifest behind…
        assert_eq!(run("true"), 0);
        // …a run that changed something keeps its record.
        assert_eq!(run("false"), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_guard_reverts_on_validation_failure() {
        let d = sample().guarded_reload(ReloadGuard {
            describe: "sshd".into(),
            validate: "sshd -t".into(),
            reload: "systemctl reload ssh".into(),
        });
        let s = d.render_apply();
        assert!(s.contains("sshd -t"));
        // reload only in the success branch, revert + exit 1 on failure.
        assert!(s.contains("exit 1"));
        assert!(s.contains(MARK_FAILED));
    }

    #[test]
    fn guard_failure_restores_preexisting_files_from_backup() {
        let d = sample().guarded_reload(ReloadGuard {
            describe: "sshd".into(),
            validate: "sshd -t".into(),
            reload: "systemctl reload ssh".into(),
        });
        let s = d.render_apply();
        // The Modified branch registers the path for revert after backing up.
        assert!(s.contains("__reverts+=(\"$__path\")"));
        // The failure branch walks the reverts and moves each backup back.
        let failure = s.rfind(MARK_FAILED).expect("failure branch present");
        let restore = s
            .find(&format!("mv -f \"$__r{BACKUP_SUFFIX}\" \"$__r\""))
            .expect("backup restore present");
        let exit = s.rfind("exit 1").expect("exit present");
        assert!(
            failure < restore && restore < exit,
            "restore inside failure branch"
        );
    }

    #[test]
    fn guard_failure_removes_files_created_this_run() {
        // A newly created file has no backup; on validation failure it must be
        // deleted, not left behind (a leaked invalid drop-in would break the
        // service on its next restart).
        let d = sample().guarded_reload(ReloadGuard {
            describe: "sshd".into(),
            validate: "sshd -t".into(),
            reload: "systemctl reload ssh".into(),
        });
        let s = d.render_apply();
        // The Created branch tracks the path separately from reverts.
        assert!(s.contains("__creates+=(\"$__path\")"));
        assert!(s.contains("__creates=()"));
        // The failure branch removes every created file before exiting 1,
        // without reloading.
        let failure = s.rfind(MARK_FAILED).expect("failure branch present");
        let creates_loop = s
            .find("for __c in \"${__creates[@]:-}\"")
            .expect("creates cleanup loop present");
        let remove = s.find("rm -f \"$__c\"").expect("created file removed");
        let exit = s.rfind("exit 1").expect("exit present");
        assert!(failure < creates_loop && creates_loop < remove && remove < exit);
        // The reload command must appear only before the failure branch (the
        // success arm), never after it.
        let reload_at = s.rfind("systemctl reload ssh").expect("reload present");
        assert!(reload_at < failure, "no reload on the failure path");
    }

    #[test]
    fn comment_injection_is_neutralized() {
        // A describe containing a newline must not escape the `# check:` /
        // `# converge:` comment and become an executable line.
        let d = Declaration::new("demo").command(ManagedCommand::new(
            "install package x\nid",
            "true",
            "apt-get install -y x",
        ));
        for s in [d.render_probe(), d.render_apply()] {
            assert!(
                s.contains("install package x id"),
                "describe flattened to one comment line:\n{s}"
            );
            assert!(
                !s.lines().any(|l| l.trim() == "id"),
                "newline in describe must not create an executable line:\n{s}"
            );
        }
    }

    #[test]
    fn comment_injection_via_path_is_neutralized() {
        let d = Declaration::new("demo").file(ManagedFile::new(
            "/etc/x\nrm -rf /tmp/y",
            "content",
            "0644",
            "root:root",
        ));
        for s in [d.render_probe(), d.render_apply(), d.render_rollback()] {
            assert!(
                !s.lines().any(|l| l.trim() == "rm -rf /tmp/y"),
                "newline in path must not create an executable line:\n{s}"
            );
        }
    }

    #[test]
    fn computed_file_uses_generator_in_probe_and_apply() {
        let d = Declaration::new("demo").file(ManagedFile::computed(
            "/etc/demo/computed.conf",
            "gen_supported_algos | sort",
            "0644",
            "root:root",
        ));
        let probe = d.render_probe();
        let apply = d.render_apply();
        // Both scripts materialize the desired content the same way: via the
        // generator, into __desired.
        for s in [&probe, &apply] {
            assert!(
                s.contains("__desired=$(gen_supported_algos | sort)"),
                "generator substitution missing:\n{s}"
            );
            assert!(!s.contains("base64 -d"), "no static embed for computed");
        }
        // Apply still shares the compare/backup/write/chmod/chown logic.
        assert!(apply.contains("cp -a \"$__path\" \"$__path"));
        assert!(apply.contains("printf '%s\\n' \"$__desired\" > \"$__path\""));
        assert!(apply.contains("chmod"));
        assert!(apply.contains("chown"));
    }

    #[test]
    fn static_content_accessor_distinguishes_modes() {
        let s = ManagedFile::new("/etc/a", "abc", "0644", "root:root");
        assert_eq!(s.static_content(), Some("abc"));
        let c = ManagedFile::computed("/etc/b", "echo hi", "0644", "root:root");
        assert_eq!(c.static_content(), None);
    }

    #[test]
    fn computed_path_resolves_via_resolver() {
        // A file whose path depends on the host (e.g. resolved via getent) sets
        // `path_resolver`; every script resolves `__path` from it rather than
        // using the label `path` literally.
        let f = ManagedFile::new("~acct/file", "body\n", "0600", "acct:")
            .with_path_resolver("printf '%s/file' \"$(getent passwd acct | cut -d: -f6)\"");
        let d = Declaration::new("users").file(f);
        for s in [d.render_probe(), d.render_apply(), d.render_rollback()] {
            assert!(
                s.contains("__path=$(printf '%s/file' \"$(getent passwd acct | cut -d: -f6)\")"),
                "resolver drives __path:\n{s}"
            );
            // The literal label must not be baked in as the path.
            assert!(!s.contains("__path=~acct/file"), "label not literal:\n{s}");
        }
    }

    #[test]
    fn owner_colon_form_checks_user_only() {
        // `acct:` (chown login-group form) must compare only the user, never
        // pin the group — the login group is whatever passwd says and must not
        // be guessed. `root:root` still compares the full %U:%G.
        let colon =
            Declaration::new("users").file(ManagedFile::new("/etc/a", "x\n", "0644", "alice:"));
        let probe = colon.render_probe();
        let apply = colon.render_apply();
        assert!(
            probe.contains("$(stat -c '%U' \"$__path\")\" = 'alice'"),
            "colon owner checks %U only:\n{probe}"
        );
        assert!(
            !probe.contains("'%U:%G'"),
            "colon owner must not pin the group:\n{probe}"
        );
        // chown still gets the colon form (chown interprets it as login group).
        assert!(
            apply.contains("chown 'alice:'"),
            "chown colon form:\n{apply}"
        );
        // The apply drift check negates the user-only test.
        assert!(
            apply.contains("! [ \"$(stat -c '%U' \"$__path\")\" = 'alice' ]"),
            "apply drift check negates owner check:\n{apply}"
        );

        // Full U:G is unchanged: compares %U:%G and chowns the full pair.
        let full =
            Declaration::new("sshd").file(ManagedFile::new("/etc/b", "x\n", "0644", "root:root"));
        let probe = full.render_probe();
        assert!(
            probe.contains("'%U:%G'"),
            "full owner checks %U:%G:\n{probe}"
        );
        assert!(probe.contains("= 'root:root'"), "{probe}");

        // A bare colon `":"` (empty user) is degenerate — it must NOT take the
        // login-group branch, which would reduce to an empty-user check. It
        // falls through to the full %U:%G comparison like any non-colon owner.
        let bare = Declaration::new("x").file(ManagedFile::new("/etc/c", "x\n", "0644", ":"));
        let probe = bare.render_probe();
        assert!(
            probe.contains("'%U:%G'"),
            "bare colon is not the login-group form:\n{probe}"
        );
        assert!(
            !probe.contains("'%U'"),
            "bare colon must not reduce to an empty-user check:\n{probe}"
        );
    }

    #[test]
    fn rollback_restores_backup_or_removes_creation() {
        let s = sample().render_rollback();
        // Restore path: copy the backup back over the live file, then drop it.
        assert!(s.contains(&format!("cp -a \"$__path{BACKUP_SUFFIX}\" \"$__path\"")));
        assert!(s.contains(&format!("rm -f \"$__path{BACKUP_SUFFIX}\"")));
        // Creation-undo path: a file with no backup is removed.
        assert!(s.contains("rm -f \"$__path\""));
        assert!(s.contains(MARK_CHANGED));
        // Never writes desired content or reloads a service.
        assert!(!s.contains("base64 -d"));
    }

    #[test]
    fn rollback_reloads_guarded_modules_after_restoring() {
        // A restored config is inert until the service reloads it. The
        // reload runs after every restore, validated, and fails loudly.
        let rb = sample()
            .guarded_reload(ReloadGuard {
                describe: "demo".into(),
                validate: "sshd -t".into(),
                reload: "systemctl reload demo".into(),
            })
            .render_rollback();
        let restore = rb.rfind("restored from backup").unwrap();
        let reload = rb.find("reload with the restored config").unwrap();
        assert!(restore < reload, "reload must follow the restores:\n{rb}");
        let tail = &rb[reload..];
        assert!(
            tail.contains("sshd -t") && tail.contains("FAILED:"),
            "{tail}"
        );
        let unguarded = Declaration::new("x")
            .file(ManagedFile::new("/etc/x", "x\n", "0644", "root:root"))
            .render_rollback();
        assert!(!unguarded.contains("reload with the restored config"));
    }

    #[test]
    fn rollback_of_command_only_module_is_a_noop() {
        let d = Declaration::new("lynis").command(ManagedCommand::new(
            "install lynis",
            "true",
            "apt-get install -y lynis",
        ));
        let s = d.render_rollback();
        assert!(s.contains(MARK_OK));
        assert!(s.contains("nothing to roll back"));
        assert!(!s.contains("rm -f"));
    }

    #[test]
    fn rollback_restores_command_edited_files_from_backup() {
        // A command-edited shared file (e.g. /etc/login.defs) is restored from
        // its .anvil.bak by rollback — and, critically, NOT deleted when no
        // backup exists (it is a distro file anvil does not own wholesale).
        let d = Declaration::new("pam").command_file("/etc/login.defs");
        let s = d.render_rollback();
        // Restore path: copy the backup back over the live file, then drop it.
        assert!(s.contains("cp -a \"$__path.anvil.bak\" \"$__path\""));
        assert!(s.contains("rm -f \"$__path.anvil.bak\""));
        assert!(s.contains(MARK_CHANGED));
        assert!(s.contains("restored from backup"));
        // The no-backup branch leaves the file alone — it must not remove it
        // (unlike a file anvil created).
        assert!(!s.contains("created by anvil"));
    }

    #[test]
    fn rollback_handles_a_mix_of_files_and_command_files() {
        let d = sample().command_file("/etc/login.defs");
        let s = d.render_rollback();
        // Both the managed file and the command-edited file are rolled back.
        assert!(s.contains("/etc/login.defs"));
        assert!(s.contains("/etc/demo.conf"));
    }

    #[test]
    fn rollback_runs_module_authored_script_when_set() {
        // A module with no files/command_files but a rollback_script (e.g. suid)
        // must NOT short-circuit to "owns no files; nothing to roll back" — the
        // module-authored script is the rollback.
        let d =
            Declaration::new("suid").rollback_script("printf 'CHANGED: suid restored modes\\n'\n");
        let s = d.render_rollback();
        assert!(
            !s.contains("nothing to roll back"),
            "module rollback must not be mistaken for a no-op:\n{s}"
        );
        assert!(
            s.contains("CHANGED: suid restored modes"),
            "module-authored rollback script is emitted:\n{s}"
        );
    }

    #[test]
    fn rollback_first_runs_before_any_file_is_undone() {
        let s = sample()
            .rollback_first("printf 'CHANGED: stopped\\n'\n")
            .rollback_script("printf 'CHANGED: tail\\n'\n")
            .render_rollback();
        let first = s.find("CHANGED: stopped").expect("rollback_first emitted");
        assert!(first < s.find("# rollback:").unwrap());
        assert!(
            first > s.find("__anvil_created()").unwrap(),
            "helpers defined"
        );
        assert!(s.find("CHANGED: tail").unwrap() > first);
        let only = Declaration::new("m").rollback_first("printf 'CHANGED: x\\n'\n");
        assert!(!only.render_rollback().contains("nothing to roll back"));
    }

    #[test]
    fn rollback_runs_module_script_after_files_and_command_files() {
        // Files and command-edited files are undone first; the module-authored
        // rollback runs last (it may depend on files the module wrote).
        let d = sample()
            .command_file("/etc/login.defs")
            .rollback_script("printf 'CHANGED: module tail\\n'\n");
        let s = d.render_rollback();
        let file_rb = s.find("# rollback:").expect("managed-file rollback");
        let cmd_rb = s
            .find("# rollback (command-edited):")
            .expect("command-file rollback");
        let tail = s.find("module tail").expect("module-authored rollback");
        assert!(
            file_rb < cmd_rb,
            "managed file undone before command file:\n{s}"
        );
        assert!(cmd_rb < tail, "module rollback runs last:\n{s}");
    }

    #[test]
    fn probe_parser_detects_drift() {
        assert_eq!(parse_probe("OK: fine\n"), Verdict::Aligned);
        match parse_probe("OK: a\nDRIFTED: /etc/x missing\n") {
            Verdict::Drifted(r) => assert_eq!(r, vec!["/etc/x missing".to_string()]),
            _ => panic!("expected drift"),
        }
    }

    #[test]
    fn apply_parser_classifies() {
        assert_eq!(parse_apply("OK: a\n"), ApplyStatus::Ok);
        assert_eq!(parse_apply("OK: a\nCHANGED: b\n"), ApplyStatus::Changed);
        assert_eq!(
            parse_apply("CHANGED: b\nFAILED: boom\n"),
            ApplyStatus::Failed
        );
    }

    #[test]
    fn parser_edges_silence_indentation_and_probe_failures() {
        // Empty output classifies as aligned/ok — the scripts always emit at
        // least one marker, and script *failures* surface via exit status,
        // not stdout parsing. Pinned so a marker rework revisits this.
        assert_eq!(parse_probe(""), Verdict::Aligned);
        assert_eq!(parse_apply(""), ApplyStatus::Ok);
        // Indented markers count; surrounding noise does not.
        assert_eq!(parse_apply("  CHANGED: x\nnoise\n"), ApplyStatus::Changed);
        match parse_probe("noise\n  DRIFTED: y\n") {
            Verdict::Drifted(r) => assert_eq!(r, vec!["y".to_string()]),
            _ => panic!("expected drift"),
        }
        // FAILED means failed no matter what follows it.
        assert_eq!(
            parse_apply("FAILED: boom\nCHANGED: late\n"),
            ApplyStatus::Failed
        );
        // A FAILED line in *probe* output is not drift; probes report failure
        // through their exit code.
        assert_eq!(parse_probe("FAILED: boom\n"), Verdict::Aligned);
    }

    #[test]
    fn declarations_default_to_remote_and_can_opt_into_local() {
        assert!(!Declaration::new("sshd").runs_locally);
        assert!(Declaration::new("hetzner").local().runs_locally);
    }

    #[test]
    fn desired_content_is_recoverable_from_script() {
        // The declared content must survive the base64 round-trip embedded in
        // the script (this is the diff contract, R89/R105).
        let d = sample();
        let encoded = B64.encode("key = value\n");
        assert!(d.render_apply().contains(&encoded));
    }
}
