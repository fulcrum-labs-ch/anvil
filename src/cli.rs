//! CLI surface. Command and flag names are a Fixed Contract.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::json;

use crate::config::{load, Config, HostSpec};
use crate::diff::{self, FileChange, RemoteFile, RemoteStat};
use crate::engine::{parse_apply, parse_probe, ApplyStatus, Verdict, MARK_FAILED};
use crate::error::AnvilError;
use crate::local;
use crate::modules::{lynis, Module, Plan};
use crate::plugin;
use crate::report::{self, DriftState};
use crate::ssh;

/// Execute a rendered script where its declaration demands: on the operator's
/// machine for `runs_locally` declarations (e.g. hetzner driving `hcloud` with
/// a local HCLOUD_TOKEN), else on `host` over SSH.
///
/// A local script acts on shared cloud state, not on `host`, so it runs
/// once per fleet — the first host to reach it runs it (holding the lock, so
/// `--parallel` never races `hcloud`) and every other host reuses its output.
/// Each host still decides for itself whether to reach it (safety skips).
fn exec_script(
    host: &HostSpec,
    script: &str,
    local: bool,
    timeout: Option<Duration>,
) -> crate::error::Result<ssh::RemoteOutput> {
    // shortcut: process-wide memo, correct because one process runs one command.
    static LOCAL_RUNS: Mutex<BTreeMap<String, std::result::Result<ssh::RemoteOutput, String>>> =
        Mutex::new(BTreeMap::new());
    if !local {
        return ssh::run(host, script, timeout);
    }
    let mut runs = LOCAL_RUNS.lock().unwrap_or_else(|p| p.into_inner());
    runs.entry(script.to_string())
        // local::run only fails with AnvilError::Ssh; keep its message, rewrap below.
        .or_insert_with(|| {
            local::run(script, timeout).map_err(|e| match e {
                AnvilError::Ssh(m) => m,
                other => other.to_string(),
            })
        })
        .clone()
        .map_err(AnvilError::Ssh)
}

const DEFAULT_CONFIG: &str = "harden.toml";

#[derive(Debug, Parser)]
#[command(
    name = "anvil",
    version,
    about = "Fulcrum Anvil — declarative Linux server hardening"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Human,
    Json,
    Ndjson,
}

/// `report`'s formats: the shared ones plus `markdown`, its default. Only
/// `report` has a markdown rendering, so only it offers the value.
#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
pub enum ReportFormat {
    Human,
    Json,
    #[default]
    Markdown,
    Ndjson,
}

/// Shared `-c/--config` flag.
#[derive(Debug, Args)]
pub struct ConfigArg {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
}

/// `--host`/`--exclude` fleet selectors, flattened into every fleet
/// command. Selection is by host address (`HostSpec` has no alias field), in
/// config order. `--host` lets you target a subset without editing the file
/// (`--only` filters modules, not hosts); `--exclude` drops the named hosts.
/// A `--host` or `--exclude` entry matching no host is a hard error, like
/// `--only` — a typo'd `--exclude` that silently excluded nothing would harden
/// (and possibly reboot) the one host the operator meant to protect. A
/// selection that leaves no host is also an error: every gate would otherwise
/// pass vacuously against zero probes.
#[derive(Debug, Default, Args)]
pub struct HostFilter {
    /// Comma-separated host addresses to run (others are skipped).
    #[arg(long, value_delimiter = ',')]
    pub host: Vec<String>,
    /// Comma-separated host addresses to skip.
    #[arg(long, value_delimiter = ',')]
    pub exclude: Vec<String>,
}

impl HostFilter {
    /// Apply the selectors to `hosts`, preserving config order. Returns refs
    /// borrowed from `hosts` (not from the slice container, so a temporary
    /// `cfg.hosts()` may be passed).
    pub fn select<'a>(&self, hosts: &[&'a HostSpec]) -> crate::error::Result<Vec<&'a HostSpec>> {
        let known: Vec<&str> = hosts.iter().map(|h| h.address.as_str()).collect();
        for (flag, wanted) in [("--host", &self.host), ("--exclude", &self.exclude)] {
            for want in wanted {
                if !known.contains(&want.as_str()) {
                    return Err(AnvilError::Usage(format!(
                        "{flag} {want:?} matches no host; known: {}",
                        known.join(", ")
                    )));
                }
            }
        }
        let selected: Vec<&'a HostSpec> = hosts
            .iter()
            .copied()
            .filter(|h| {
                (self.host.is_empty() || self.host.contains(&h.address))
                    && !self.exclude.contains(&h.address)
            })
            .collect();
        if selected.is_empty() && !hosts.is_empty() {
            return Err(AnvilError::Usage(
                "--host/--exclude selected no hosts; nothing to run".into(),
            ));
        }
        Ok(selected)
    }
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Connect and converge the host(s) to desired state.
    Apply(ApplyArgs),
    /// Parse & validate config without connecting.
    Validate(ConfigArg),
    /// Detect drift on the host(s).
    Check(CheckArgs),
    /// Preview exactly what `apply` would change (per-file diffs).
    Diff(DiffArgs),
    /// Restore modules to pre-hardening state from backups.
    Rollback(RollbackArgs),
    /// Per-host module summary.
    Status(FanoutArgs),
    /// Run a Lynis audit and print the hardening index.
    Score(ScoreArgs),
    /// Compliance report of module coverage by CIS category.
    Report(ReportArgs),
    /// Preflight checks: config/plan resolve, plugins trusted, each host is
    /// reachable over SSH (and `sudo -n` works for non-root users).
    Doctor(DoctorArgs),
    /// Generate a starter/reference config.
    Init(InitArgs),
    /// Manage plugins.
    Plugins(PluginsArgs),
    /// Manage profiles.
    Profiles(ProfilesArgs),
}

#[derive(Debug, Args)]
pub struct ApplyArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Print the exact scripts; nothing connects.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Only these modules, comma-separated ids (e.g. `sshd,firewall`).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Also print each module's remote output.
    #[arg(short, long)]
    pub verbose: bool,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Hosts to run at once: 1 = one at a time, 0 = all at once.
    #[arg(long, default_value_t = 1)]
    pub parallel: u32,
    /// Skip the read-only probe and converge every selected module.
    #[arg(long)]
    pub no_check: bool,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Also print each module's remote output.
    #[arg(short, long)]
    pub verbose: bool,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Hosts to run at once: 1 = one at a time, 0 = all at once.
    #[arg(long, default_value_t = 1)]
    pub parallel: u32,
    /// Only these modules, comma-separated ids (e.g. `sshd,firewall`).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Only these modules, comma-separated ids (e.g. `sshd,firewall`).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Only these modules, comma-separated ids (e.g. `sshd,firewall`).
    #[arg(long, value_delimiter = ',')]
    pub only: Vec<String>,
    /// Print the exact scripts; nothing connects.
    #[arg(short = 'n', long)]
    pub dry_run: bool,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Hosts to run at once: 1 = one at a time, 0 = all at once.
    #[arg(long, default_value_t = 1)]
    pub parallel: u32,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct FanoutArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Hosts to run at once: 1 = one at a time, 0 = all at once.
    #[arg(long, default_value_t = 1)]
    pub parallel: u32,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct ScoreArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Exit 1 if any host's hardening index is below this.
    #[arg(short = 't', long)]
    pub threshold: Option<u32>,
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
    /// Hosts to run at once: 1 = one at a time, 0 = all at once.
    #[arg(long, default_value_t = 1)]
    pub parallel: u32,
    /// Per-call timeout in seconds; kills a stalled ssh/local child.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Output format; markdown is the default for this report.
    #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
    pub output: ReportFormat,
    /// Probe each enabled module and add its live drift state.
    #[arg(long)]
    pub check: bool,
    /// Per-call timeout in seconds for the `--check` probes.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Config file to read (TOML).
    #[arg(short, long, default_value = DEFAULT_CONFIG)]
    pub config: PathBuf,
    /// Per-call timeout in seconds for the reachability probes.
    #[arg(long)]
    pub timeout: Option<u64>,
    #[command(flatten)]
    pub host_filter: HostFilter,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Write the config to this file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,
    /// Start from a built-in or custom profile (see `anvil profiles list`).
    #[arg(long)]
    pub profile: Option<String>,
    /// Emit every section with example values (a reference config).
    #[arg(long)]
    pub full: bool,
}

#[derive(Debug, Args)]
pub struct PluginsArgs {
    #[command(subcommand)]
    pub command: PluginsCmd,
}

#[derive(Debug, Subcommand)]
pub enum PluginsCmd {
    /// List discovered plugins (valid and skipped, with reasons).
    List(ListingArgs),
}

#[derive(Debug, Args)]
pub struct ProfilesArgs {
    #[command(subcommand)]
    pub command: ProfilesCmd,
}

#[derive(Debug, Subcommand)]
pub enum ProfilesCmd {
    /// List built-in and discovered custom profiles.
    List(ListingArgs),
}

/// Shared flags for the connectionless listing subcommands.
#[derive(Debug, Args)]
pub struct ListingArgs {
    /// Output format: human, json, or ndjson (one object per line).
    #[arg(long, value_enum, default_value_t = OutputFormat::Human)]
    pub output: OutputFormat,
}

/// Parse args and dispatch. Returns the process exit code (R100).
pub fn run() -> Result<i32> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Validate(a) => cmd_validate(&a.config),
        Commands::Init(a) => cmd_init(a),
        Commands::Apply(a) => cmd_apply(a),
        Commands::Check(a) => cmd_check(a),
        Commands::Profiles(a) => cmd_profiles(a),
        Commands::Diff(a) => cmd_diff(a),
        Commands::Rollback(a) => cmd_rollback(a),
        Commands::Status(a) => cmd_status(a),
        Commands::Score(a) => cmd_score(a),
        Commands::Report(a) => cmd_report(a),
        Commands::Doctor(a) => cmd_doctor(a),
        Commands::Plugins(a) => cmd_plugins(a),
    }
}

/// Load + validate a config, returning it together with the enabled plugins.
/// Plugins are discovered from the default plugin directory, their
/// bound sections are extracted during load, and each enabled plugin's
/// scripts are substituted into a ready [`plugin::EnabledPlugin`]. Skipped
/// (malformed/insecure) plugins are warned about on stderr — discovery never
/// aborts (R93).
fn load_config(path: &PathBuf) -> Result<(Config, Vec<plugin::EnabledPlugin>)> {
    let discovery = plugin::default_plugins_dir()
        .map(|d| plugin::discover(&d))
        .unwrap_or_default();
    warn_skipped(&discovery.skipped);
    let sections: Vec<String> = discovery
        .plugins
        .iter()
        .map(|p| p.section.clone())
        .collect();
    let loaded = load::load_with(
        path,
        &load::LoadOptions {
            plugin_sections: &sections,
            profiles_dir: None,
        },
    )?;
    loaded.config.validate()?;
    for w in loaded.config.warnings() {
        eprintln!("anvil: warning: {w}");
    }
    let mut enabled = Vec::new();
    for p in &discovery.plugins {
        if let Some(values) = loaded.plugin_values.get(&p.section) {
            enabled.push(p.enable(values)?);
        }
    }
    Ok((loaded.config, enabled))
}

fn warn_skipped(skipped: &[plugin::SkippedPlugin]) {
    for s in skipped {
        eprintln!(
            "warning: skipped plugin {:?} ({}): {}",
            s.name,
            s.path.display(),
            s.reason
        );
    }
}

fn cmd_validate(path: &PathBuf) -> Result<i32> {
    match load_config(path) {
        Ok((cfg, plugins)) => {
            // Building the plan also enforces ordering safety.
            let plan = Plan::build_with_plugins(&cfg, &plugins)?;
            let hosts = cfg.hosts().len();
            println!(
                "config OK: {} host(s), {} module(s) enabled",
                hosts,
                plan.order.len()
            );
            println!("run order: {}", plan.order.join(" -> "));
            Ok(0)
        }
        Err(e) => {
            // Validation errors already read "invalid config: …"; don't say it twice.
            let msg = e.to_string();
            if msg.starts_with("invalid config:") {
                eprintln!("{msg}");
            } else {
                eprintln!("invalid config: {msg}");
            }
            Ok(1)
        }
    }
}

fn cmd_init(args: InitArgs) -> Result<i32> {
    if let Some(p) = &args.profile {
        // Only names `profiles list` would show; anything else would land raw in TOML.
        let customs = load::default_profiles_dir()
            .as_deref()
            .map(load::discover_custom_profiles)
            .unwrap_or_default();
        let known = load::BUILTIN_PROFILES.contains(&p.as_str())
            || customs.iter().any(|(name, _)| name == p);
        if !known {
            let mut names: Vec<&str> = load::BUILTIN_PROFILES.to_vec();
            names.extend(customs.iter().map(|(n, _)| n.as_str()));
            return Err(AnvilError::Usage(format!(
                "--profile {p:?} is not a known profile; available: [{}] \
                 (see `anvil profiles list`)",
                names.join(", ")
            ))
            .into());
        }
    }
    let text = render_init(args.profile.as_deref(), args.full);
    match &args.output {
        Some(path) => {
            std::fs::write(path, &text)?;
            println!("wrote {}", path.display());
        }
        None => print!("{text}"),
    }
    Ok(0)
}

/// A discovery directory for display; `None` means discovery was skipped.
fn shown_dir(dir: Option<&Path>) -> String {
    dir.map_or_else(
        || "none: no absolute $XDG_CONFIG_HOME or $HOME, discovery skipped".into(),
        |d| d.display().to_string(),
    )
}

fn cmd_profiles(args: ProfilesArgs) -> Result<i32> {
    match args.command {
        ProfilesCmd::List(a) => {
            let dir = load::default_profiles_dir();
            let customs = dir
                .as_deref()
                .map(load::discover_custom_profiles)
                .unwrap_or_default();
            let dir = shown_dir(dir.as_deref());
            if a.output == OutputFormat::Human {
                println!("built-in profiles:");
                for p in load::BUILTIN_PROFILES {
                    println!("  {p}");
                }
                if customs.is_empty() {
                    println!("custom profiles ({dir}): none");
                } else {
                    println!("custom profiles ({dir}):");
                    for (name, path) in &customs {
                        println!("  {:<20} {}", name, path.display());
                    }
                }
            } else {
                let mut docs: Vec<serde_json::Value> = load::BUILTIN_PROFILES
                    .iter()
                    .map(|p| json!({ "name": p, "source": "builtin" }))
                    .collect();
                docs.extend(customs.iter().map(|(name, path)| {
                    json!({
                        "name": name,
                        "source": "custom",
                        "path": path.display().to_string(),
                    })
                }));
                print_machine(a.output, &docs)?;
            }
            Ok(0)
        }
    }
}

// --- plugins --------------------------------------------------------

fn cmd_plugins(args: PluginsArgs) -> Result<i32> {
    match args.command {
        PluginsCmd::List(a) => {
            let dir = plugin::default_plugins_dir();
            let d = dir.as_deref().map(plugin::discover).unwrap_or_default();
            if a.output == OutputFormat::Human {
                println!("plugins directory: {}", shown_dir(dir.as_deref()));
                if d.plugins.is_empty() && d.skipped.is_empty() {
                    println!("  (no plugins discovered)");
                }
                for p in &d.plugins {
                    let mut hints: Vec<String> = Vec::new();
                    if let Some(o) = p.order {
                        hints.push(format!("order={o}"));
                    }
                    if !p.before.is_empty() {
                        hints.push(format!("before={}", p.before.join(",")));
                    }
                    if !p.after.is_empty() {
                        hints.push(format!("after={}", p.after.join(",")));
                    }
                    let hints = if hints.is_empty() {
                        "default-order".to_string()
                    } else {
                        hints.join(" ")
                    };
                    println!(
                        "  {:<20} valid    section={} {} {}",
                        p.name,
                        p.section,
                        hints,
                        p.dir.display()
                    );
                }
                for s in &d.skipped {
                    println!(
                        "  {:<20} skipped  {} ({})",
                        s.name,
                        s.reason,
                        s.path.display()
                    );
                }
            } else {
                let mut docs: Vec<serde_json::Value> = d
                    .plugins
                    .iter()
                    .map(|p| {
                        json!({
                            "name": p.name,
                            "status": "valid",
                            "section": p.section,
                            "description": p.description,
                            "order": p.order,
                            "before": p.before,
                            "after": p.after,
                            "path": p.dir.display().to_string(),
                        })
                    })
                    .collect();
                docs.extend(d.skipped.iter().map(|s| {
                    json!({
                        "name": s.name,
                        "status": "skipped",
                        "reason": s.reason,
                        "path": s.path.display().to_string(),
                    })
                }));
                print_machine(a.output, &docs)?;
            }
            Ok(0)
        }
    }
}

/// Filter a plan's implemented modules by `--only` (empty = all).
fn selected<'a>(plan: &'a Plan, only: &[String]) -> Vec<&'a dyn Module> {
    plan.modules
        .iter()
        .map(|b| b.as_ref())
        .filter(|m| only.is_empty() || only.iter().any(|o| o == m.id()))
        .collect()
}

/// Validate `--only`: every entry must be non-empty and name an enabled
/// module. An unknown id (typo like `ssshd`) or a stray-comma empty entry must
/// exit non-zero with a helpful message — it must never silently select nothing
/// and return success, because for a hardening gate a quiet no-op is dangerous.
/// `selected` keeps its permissive filter for internal callers; this is the
/// user-facing gate, called once per command before any work.
fn resolve_only(plan: &Plan, only: &[String]) -> std::result::Result<Vec<String>, AnvilError> {
    if only.is_empty() {
        return Ok(Vec::new());
    }
    for entry in only {
        if entry.trim().is_empty() {
            return Err(AnvilError::Usage(format!(
                "--only contains an empty entry (check for stray commas); \
                 enabled modules: [{}]",
                plan.order.join(", ")
            )));
        }
        if !plan.order.iter().any(|id| id == entry) {
            return Err(AnvilError::Usage(format!(
                "--only {entry:?} is not an enabled module; \
                 enabled modules: [{}]",
                plan.order.join(", ")
            )));
        }
    }
    Ok(only.to_vec())
}

// --- apply (R50) ---------------------------------------------------------

/// One module's rendered scripts plus its execution routing, prepared once and
/// shipped unchanged to every host.
struct ApplyStep {
    id: &'static str,
    probe: String,
    apply: String,
    local: bool,
}

impl ApplyStep {
    fn from_module(m: &dyn Module) -> ApplyStep {
        let decl = m.declaration();
        ApplyStep {
            id: m.id(),
            probe: decl.render_probe(),
            apply: decl.render_apply(),
            local: decl.runs_locally,
        }
    }
}

/// Outcome of one module during `apply` on one host.
struct ApplyOutcome {
    id: &'static str,
    status: ApplyStatus,
    /// Probe verdict when the probe phase ran (`None` under `--no-check` or
    /// for a safety skip).
    drift: Option<&'static str>,
    /// Skip reason or a concise error line.
    detail: Option<String>,
    /// Captured stdout for `--verbose`.
    output: String,
}

struct HostApplyReport {
    host: String,
    outcomes: Vec<ApplyOutcome>,
}

/// Failure propagation within one run: a module whose action could compound
/// an earlier failure into an SSH lockout (or a mid-run reboot after a broken
/// run) is skipped — its scripts must not run at all. Returns the printed
/// reason, or `None` to proceed.
fn safety_skip_reason(id: &str, failed_earlier: &[&'static str]) -> Option<String> {
    match id {
        // Fencing in a host whose sshd/crypto change — or tailnet join, which
        // `tailnet_only_ssh` relies on as the SSH path — just failed risks lockout.
        "firewall" | "hetzner" | "netcup" => failed_earlier
            .iter()
            .find(|f| matches!(**f, "sshd" | "ssh_crypto" | "tailscale"))
            .map(|culprit| {
                format!(
                    "{culprit} failed earlier in this run; \
                     running {id} now could lock out SSH"
                )
            }),
        // The agent's port is opened by a ufw rule; never start it on a host
        // whose firewall step just failed.
        "beszel" if failed_earlier.contains(&"firewall") => Some(
            "firewall failed earlier in this run; not starting the beszel agent \
             behind an unconverged firewall"
                .into(),
        ),
        // Updates (and any reboot) run last, and only after a clean run (R58).
        "updates" if !failed_earlier.is_empty() => Some(format!(
            "{} earlier module(s) failed; updates runs only after a clean run",
            failed_earlier.len()
        )),
        _ => None,
    }
}

/// T10: `[hetzner]`/`[netcup]` `keep_public_ssh = false` closes public SSH
/// at the provider edge. Only do that when anvil's own session to this host runs over the
/// tailnet — every address `[host] address` resolves to is a tailnet address —
/// so the path `tailnet_only_ssh` relies on is the one in use (DESIGN.md §3).
fn tailnet_gate_reason(addrs: &[std::net::IpAddr]) -> Option<String> {
    let on_tailnet = |ip: &std::net::IpAddr| {
        let ip = ip.to_canonical().to_string();
        crate::modules::tailscale::TAILNET_CIDRS
            .iter()
            .any(|c| crate::config::cidr_within(&ip, c))
    };
    (addrs.is_empty() || !addrs.iter().all(on_tailnet)).then(|| {
        "keep_public_ssh = false but anvil does not reach this host over the tailnet; \
         not closing public SSH at the cloud edge (set [host] address to the tailnet \
         name/IP once SSH over the tailnet works)"
            .into()
    })
}

/// The IPs `[host] address` resolves to; empty when it does not resolve.
fn host_ips(host: &HostSpec) -> Vec<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    (host.address.as_str(), host.port)
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// [`safety_skip_reason`], then the T10 tailnet gate for every provider
/// firewall in `closes_public_ssh` (those with `keep_public_ssh = false`).
fn step_skip_reason(
    id: &str,
    failed_earlier: &[&'static str],
    closes_public_ssh: &[&str],
    host: &HostSpec,
) -> Option<String> {
    safety_skip_reason(id, failed_earlier).or_else(|| {
        closes_public_ssh
            .contains(&id)
            .then(|| tailnet_gate_reason(&host_ips(host)))
            .flatten()
    })
}

/// Two-phase apply for one host (R50): probe first, converge only what
/// drifted; `no_check` skips the probe phase and applies everything.
/// `closes_public_ssh` lists the provider firewalls with
/// `keep_public_ssh = false` (T10 gate).
fn apply_host(
    host: &HostSpec,
    steps: &[ApplyStep],
    no_check: bool,
    timeout: Option<Duration>,
    closes_public_ssh: &[&str],
) -> HostApplyReport {
    let mut failed: Vec<&'static str> = Vec::new();
    let mut outcomes: Vec<ApplyOutcome> = Vec::new();

    for step in steps {
        if let Some(reason) = step_skip_reason(step.id, &failed, closes_public_ssh, host) {
            outcomes.push(ApplyOutcome {
                id: step.id,
                status: ApplyStatus::Skipped,
                drift: None,
                detail: Some(reason),
                output: String::new(),
            });
            continue;
        }

        // Phase 1: read-only probe. Aligned modules are done ("ok").
        if !no_check {
            match exec_script(host, &step.probe, step.local, timeout) {
                Ok(out) if out.success() => match parse_probe(&out.stdout) {
                    Verdict::Aligned => {
                        outcomes.push(ApplyOutcome {
                            id: step.id,
                            status: ApplyStatus::Ok,
                            drift: Some("aligned"),
                            detail: None,
                            output: out.stdout,
                        });
                        continue;
                    }
                    Verdict::Drifted(_) => {} // fall through to converge
                },
                Ok(out) => {
                    failed.push(step.id);
                    outcomes.push(ApplyOutcome {
                        id: step.id,
                        status: ApplyStatus::Failed,
                        drift: None,
                        detail: Some(format!("probe failed: {}", remote_error(&out))),
                        output: out.stdout,
                    });
                    continue;
                }
                Err(e) => {
                    failed.push(step.id);
                    outcomes.push(ApplyOutcome {
                        id: step.id,
                        status: ApplyStatus::Failed,
                        drift: None,
                        detail: Some(format!("probe failed: {e}")),
                        output: String::new(),
                    });
                    continue;
                }
            }
        }

        // Phase 2: converge.
        let drift = (!no_check).then_some("drifted");
        match exec_script(host, &step.apply, step.local, timeout) {
            Ok(out) => {
                let status = if out.success() {
                    parse_apply(&out.stdout)
                } else {
                    ApplyStatus::Failed
                };
                if status == ApplyStatus::Failed {
                    failed.push(step.id);
                }
                let detail = (status == ApplyStatus::Failed).then(|| remote_error(&out));
                outcomes.push(ApplyOutcome {
                    id: step.id,
                    status,
                    drift,
                    detail,
                    output: out.stdout,
                });
            }
            Err(e) => {
                failed.push(step.id);
                outcomes.push(ApplyOutcome {
                    id: step.id,
                    status: ApplyStatus::Failed,
                    drift,
                    detail: Some(e.to_string()),
                    output: String::new(),
                });
            }
        }
    }

    HostApplyReport {
        host: host.address.clone(),
        outcomes,
    }
}

fn cmd_apply(args: ApplyArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;
    let only = resolve_only(&plan, &args.only)?;
    // The firewall-after-sshd edge (R56) lives only in ordering, so
    // applying a fence without sshd could fence the live SSH port.
    let has = |id: &str| only.iter().any(|m| m == id);
    if (has("firewall") || has("hetzner") || has("netcup"))
        && plan.order.iter().any(|id| id == "sshd")
        && !has("sshd")
    {
        return Err(AnvilError::Usage(
            "--only firewall/hetzner/netcup without sshd could fence off the SSH port; \
             add sshd to --only (e.g. --only sshd,firewall)"
                .into(),
        )
        .into());
    }
    // T10: closing the cloud edge relies on tailscale in the same run (order
    // edge + T21 skip-after-failure), so it cannot be applied alone.
    let mut closes_public_ssh: Vec<&str> = Vec::new();
    if cfg.hetzner.as_ref().is_some_and(|h| !h.keep_public_ssh) {
        closes_public_ssh.push("hetzner");
    }
    if cfg.netcup.as_ref().is_some_and(|n| !n.keep_public_ssh) {
        closes_public_ssh.push("netcup");
    }
    if let Some(edge) = closes_public_ssh.iter().find(|e| has(e)) {
        if !has("tailscale") {
            return Err(AnvilError::Usage(format!(
                "--only {edge} with keep_public_ssh = false needs tailscale in the same run; \
                 add tailscale to --only (e.g. --only tailscale,{edge})"
            ))
            .into());
        }
    }

    if args.dry_run {
        if args.output == OutputFormat::Human {
            println!("# dry-run: resolved order: {}", plan.order.join(" -> "));
            for m in selected(&plan, &only) {
                println!("\n# ===== module: {} (apply) =====", m.id());
                let d = m.declaration();
                print!("{}", d.redact(&d.render_apply()));
            }
        } else {
            // Honor --output (matching `rollback --dry-run`): emit one doc per
            // selected module rather than ignoring the format.
            let docs: Vec<serde_json::Value> = selected(&plan, &only)
                .iter()
                .map(|m| {
                    let d = m.declaration();
                    json!({
                        "module": m.id(),
                        "status": "dry-run",
                        "script": d.redact(&d.render_apply()),
                    })
                })
                .collect();
            print_machine(args.output, &docs)?;
        }
        return Ok(0);
    }

    // Render every script once (pure); the fan-out only ships strings.
    let steps: Vec<ApplyStep> = selected(&plan, &only)
        .into_iter()
        .map(ApplyStep::from_module)
        .collect();

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let reports = fanout(&hosts, args.parallel, |host| {
        apply_host(
            host,
            &steps,
            args.no_check,
            args.timeout.map(Duration::from_secs),
            &closes_public_ssh,
        )
    });

    let failures: usize = reports
        .iter()
        .flat_map(|h| &h.outcomes)
        .filter(|o| o.status == ApplyStatus::Failed)
        .count();

    if args.output == OutputFormat::Human {
        for h in &reports {
            println!("== host {} ==", h.host);
            for o in &h.outcomes {
                match &o.detail {
                    Some(d) => println!("  {:<14} {} ({d})", o.id, o.status.as_str()),
                    None => println!("  {:<14} {}", o.id, o.status.as_str()),
                }
                if args.verbose && !o.output.is_empty() {
                    print!("{}", indent_block(&o.output));
                }
            }
            if h.outcomes.is_empty() {
                println!("  (no implemented modules selected)");
            }
        }
    } else {
        let docs: Vec<serde_json::Value> = reports
            .iter()
            .map(|h| {
                let modules: Vec<serde_json::Value> = h
                    .outcomes
                    .iter()
                    .map(|o| {
                        let mut obj = json!({ "module": o.id, "status": o.status.as_str() });
                        if let Some(d) = o.drift {
                            obj["drift"] = json!(d);
                        }
                        if let Some(r) = &o.detail {
                            obj["reason"] = json!(r);
                        }
                        obj
                    })
                    .collect();
                json!({ "host": h.host, "modules": modules })
            })
            .collect();
        print_machine(args.output, &docs)?;
    }

    Ok(if failures == 0 { 0 } else { 1 })
}

// --- check ---------------------------------------------------------------

fn cmd_check(args: CheckArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;
    let only = resolve_only(&plan, &args.only)?;

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let modules = selected(&plan, &only);
    let installs: BTreeMap<String, Vec<String>> = modules
        .iter()
        .map(|m| (m.id().to_string(), m.declaration().installs))
        .filter(|(_, i)| !i.is_empty())
        .collect();
    let results = probe_fleet(&hosts, &modules, args.parallel, args.timeout);

    let mut drifted = 0usize;
    let mut failures = 0usize;
    for (_, outcome) in results.iter().flat_map(|h| &h.modules) {
        match outcome {
            ProbeOutcome::Drifted(_) => drifted += 1,
            ProbeOutcome::Failed(_) => failures += 1,
            ProbeOutcome::Aligned => {}
        }
    }

    if args.output == OutputFormat::Human {
        for h in &results {
            println!("== host {} ==", h.host);
            for (id, outcome) in &h.modules {
                match outcome {
                    ProbeOutcome::Aligned => println!("  {id:<14} aligned"),
                    ProbeOutcome::Drifted(reasons) => {
                        println!("  {id:<14} drifted");
                        if args.verbose {
                            for r in reasons {
                                println!("      - {r}");
                            }
                        }
                    }
                    ProbeOutcome::Failed(e) => println!("  {id:<14} failed: {e}"),
                }
                if let Some(i) = installs.get(*id) {
                    println!("      installs: {}", i.join(", "));
                }
            }
            if h.modules.is_empty() {
                println!("  (no implemented modules selected)");
            }
        }
    } else {
        let docs: Vec<serde_json::Value> = results
            .iter()
            .map(|h| {
                let modules: Vec<serde_json::Value> = h
                    .modules
                    .iter()
                    .map(|(id, o)| {
                        let mut v = match o {
                            // Unified schema: `status` is always present so a
                            // consumer needs one accessor (apply/rollback match);
                            // `reasons` carries the drift detail, only when drifted.
                            ProbeOutcome::Aligned => json!({ "module": id, "status": "aligned" }),
                            ProbeOutcome::Drifted(reasons) => {
                                json!({ "module": id, "status": "drifted", "reasons": reasons })
                            }
                            ProbeOutcome::Failed(e) => {
                                json!({ "module": id, "status": "failed", "error": e })
                            }
                        };
                        if let Some(i) = installs.get(*id) {
                            v["installs"] = json!(i);
                        }
                        v
                    })
                    .collect();
                json!({ "host": h.host, "modules": modules })
            })
            .collect();
        print_machine(args.output, &docs)?;
    }

    // Drift is this command's finding: it participates in the exit code (R100).
    Ok(if failures == 0 && drifted == 0 { 0 } else { 1 })
}

// --- host fan-out (R19/R53) -------------------------------------------------

/// Run `f` for every host, bounded by `parallel` (`1` = sequential, `0` = all
/// at once, `N` = up to N concurrently, R19). Results are returned in host
/// order regardless of completion order. A failure on one host does not abort
/// others (R53); that is the caller's `f` responsibility.
fn fanout<T, F>(hosts: &[&HostSpec], parallel: u32, f: F) -> Vec<T>
where
    T: Send,
    F: Fn(&HostSpec) -> T + Sync,
{
    let n = hosts.len();
    if n == 0 {
        return Vec::new();
    }
    let workers = match parallel {
        0 => n,
        k => (k as usize).clamp(1, n),
    };
    if workers <= 1 {
        return hosts.iter().map(|h| f(h)).collect();
    }

    let next = AtomicUsize::new(0);
    let collected: Mutex<Vec<(usize, T)>> = Mutex::new(Vec::with_capacity(n));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= n {
                    break;
                }
                let r = f(hosts[i]);
                if let Ok(mut g) = collected.lock() {
                    g.push((i, r));
                }
            });
        }
    });

    let mut out = collected
        .into_inner()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

/// A concise one-line reason for a failed remote result: the script's own
/// `FAILED:` line first, from stdout or stderr (it names the cause; exit may
/// be 0), then stderr's first line, then the exit code.
fn remote_error(out: &ssh::RemoteOutput) -> String {
    let stderr = out.stderr.trim();
    let marked = |s: &str| {
        s.lines()
            .map(str::trim)
            .find(|l| l.starts_with(MARK_FAILED))
            .map(str::to_string)
    };
    if let Some(l) = marked(&out.stdout).or_else(|| marked(stderr)) {
        l
    } else if !stderr.is_empty() {
        stderr.lines().next().unwrap_or(stderr).to_string()
    } else {
        format!("exit {}", out.exit_code.unwrap_or(-1))
    }
}

/// Emit a set of per-host JSON documents in the requested machine format:
/// `ndjson` streams one object per line (R97); anything else pretty-prints the
/// array.
fn print_machine(format: OutputFormat, docs: &[serde_json::Value]) -> Result<()> {
    match format {
        OutputFormat::Ndjson => {
            for d in docs {
                println!("{}", serde_json::to_string(d)?);
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(docs)?);
        }
        // Callers gate Human output themselves and never reach here; if one
        // ever does, pretty-JSON is a safer default than the wrong shape.
        OutputFormat::Human => {
            println!("{}", serde_json::to_string_pretty(docs)?);
        }
    }
    Ok(())
}

// --- status ------------------------------------------------------------

/// Outcome of one module's read-only probe on a host.
enum ProbeOutcome {
    Aligned,
    Drifted(Vec<String>),
    Failed(String),
}

impl ProbeOutcome {
    fn from_run(result: crate::error::Result<ssh::RemoteOutput>) -> ProbeOutcome {
        match result {
            Ok(out) if out.success() => match parse_probe(&out.stdout) {
                Verdict::Aligned => ProbeOutcome::Aligned,
                Verdict::Drifted(reasons) => ProbeOutcome::Drifted(reasons),
            },
            Ok(out) => ProbeOutcome::Failed(remote_error(&out)),
            Err(e) => ProbeOutcome::Failed(e.to_string()),
        }
    }
}

struct HostStatus {
    host: String,
    modules: Vec<(&'static str, ProbeOutcome)>,
}

/// Probe every module on every host (shared by check, status and
/// `report --check`). Probes are rendered once (pure); the fan-out only ships
/// strings.
fn probe_fleet(
    hosts: &[&HostSpec],
    mods: &[&dyn Module],
    parallel: u32,
    timeout: Option<u64>,
) -> Vec<HostStatus> {
    let probes: Vec<(&'static str, String, bool)> = mods
        .iter()
        .map(|m| {
            let decl = m.declaration();
            (m.id(), decl.render_probe(), decl.runs_locally)
        })
        .collect();
    fanout(hosts, parallel, |host| HostStatus {
        host: host.address.clone(),
        modules: probes
            .iter()
            .map(|(id, script, local)| {
                let run = exec_script(host, script, *local, timeout.map(Duration::from_secs));
                (*id, ProbeOutcome::from_run(run))
            })
            .collect(),
    })
}

fn cmd_status(args: FanoutArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let results = probe_fleet(&hosts, &selected(&plan, &[]), args.parallel, args.timeout);

    let failures: usize = results
        .iter()
        .flat_map(|h| &h.modules)
        .filter(|(_, o)| matches!(o, ProbeOutcome::Failed(_)))
        .count();

    if args.output == OutputFormat::Human {
        for h in &results {
            println!("== host {} ==", h.host);
            for (id, outcome) in &h.modules {
                match outcome {
                    ProbeOutcome::Aligned => println!("  {id:<14} aligned"),
                    ProbeOutcome::Drifted(_) => println!("  {id:<14} drifted"),
                    ProbeOutcome::Failed(e) => println!("  {id:<14} failed: {e}"),
                }
            }
            if h.modules.is_empty() {
                println!("  (no implemented modules enabled)");
            }
        }
    } else {
        let docs: Vec<serde_json::Value> = results
            .iter()
            .map(|h| {
                let modules: Vec<serde_json::Value> = h
                    .modules
                    .iter()
                    .map(|(id, o)| match o {
                        // Unified schema: `status` always present (matches
                        // apply/rollback); `reasons` holds the drift detail.
                        ProbeOutcome::Aligned => json!({ "module": id, "status": "aligned" }),
                        ProbeOutcome::Drifted(reasons) => {
                            json!({ "module": id, "status": "drifted", "reasons": reasons })
                        }
                        ProbeOutcome::Failed(e) => {
                            json!({ "module": id, "status": "failed", "error": e })
                        }
                    })
                    .collect();
                json!({ "host": h.host, "modules": modules })
            })
            .collect();
        print_machine(args.output, &docs)?;
    }

    Ok(if failures == 0 { 0 } else { 1 })
}

// --- diff (R89) ---------------------------------------------------------

/// A managed file selected for diffing, with its declared desired content
/// (`None` when the content is computed on the host — no local diff possible).
struct DiffTarget {
    module: &'static str,
    path: String,
    desired: Option<String>,
    mode: String,
    owner: String,
}

/// Collect every managed file of every selected module (R89: use the declared
/// desired content directly — no bash scraping). Files of `runs_locally`
/// declarations are excluded: they live on the operator's machine, not the
/// target (no such module declares files today).
fn collect_diff_targets(mods: &[&dyn Module]) -> Vec<DiffTarget> {
    mods.iter()
        .flat_map(|m| {
            let id = m.id();
            let decl = m.declaration();
            let files = if decl.runs_locally {
                Vec::new()
            } else {
                decl.files
            };
            files.into_iter().filter_map(move |f| {
                // A host-computed path (path_resolver) is unknown until connect
                // time, so it cannot be diffed offline — skip it. Computed
                // *content* is kept (reported without a diff, like before).
                if f.path_resolver.is_some() {
                    return None;
                }
                let desired = f.static_content().map(str::to_string);
                Some(DiffTarget {
                    module: id,
                    path: f.path,
                    desired,
                    mode: f.mode,
                    owner: f.owner,
                })
            })
        })
        .collect()
}

/// [`diff::file_diff`] for one target against the host's read results; a path
/// missing from the read is absent.
fn file_diff_for(
    t: &DiffTarget,
    desired: &str,
    remote: &HashMap<String, (RemoteFile, Option<RemoteStat>)>,
) -> (FileChange, String) {
    let (current, stat) = remote
        .get(&t.path)
        .map_or((&RemoteFile::Absent, None), |(f, s)| (f, s.as_ref()));
    diff::file_diff(&t.path, current, stat, desired, &t.mode, &t.owner)
}

fn cmd_diff(args: DiffArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;
    let only = resolve_only(&plan, &args.only)?;

    let targets = collect_diff_targets(&selected(&plan, &only));
    // Only files with locally known desired content need their current remote
    // content; computed files are reported without a diff.
    let paths: Vec<String> = targets
        .iter()
        .filter(|t| t.desired.is_some())
        .map(|t| t.path.clone())
        .collect();
    let script = diff::read_files_script(&paths);

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let mut failures = 0;
    let mut docs: Vec<serde_json::Value> = Vec::new();

    for host in &hosts {
        // No remote content needed at all: report and move on. Targets come
        // only from remote (non-local) declarations, so the read is over SSH.
        let remote: HashMap<String, (RemoteFile, Option<RemoteStat>)> = if paths.is_empty() {
            HashMap::new()
        } else {
            match exec_script(host, &script, false, args.timeout.map(Duration::from_secs)) {
                Ok(out) if out.success() => diff::parse_remote_files(&out.stdout)
                    .into_iter()
                    .map(|(path, file, stat)| (path, (file, stat)))
                    .collect(),
                Ok(out) => {
                    failures += 1;
                    if args.output == OutputFormat::Human {
                        println!("== host {} ==", host.address);
                        println!("  failed to read files: {}", remote_error(&out));
                    } else {
                        docs.push(json!({ "host": host.address, "error": remote_error(&out) }));
                    }
                    continue;
                }
                Err(e) => {
                    failures += 1;
                    if args.output == OutputFormat::Human {
                        println!("== host {} ==", host.address);
                        println!("  failed to read files: {e}");
                    } else {
                        docs.push(json!({ "host": host.address, "error": e.to_string() }));
                    }
                    continue;
                }
            }
        };

        if args.output == OutputFormat::Human {
            println!("== host {} ==", host.address);
            if targets.is_empty() {
                println!("  no managed files to diff");
            }
            for t in &targets {
                let Some(desired) = &t.desired else {
                    println!("  {} ({}): {}", t.path, t.module, diff::COMPUTED_NOTE);
                    continue;
                };
                let (change, d) = file_diff_for(t, desired, &remote);
                if change == FileChange::None {
                    println!("  {} ({}): up to date", t.path, t.module);
                } else {
                    println!("  {} ({}):", t.path, t.module);
                    print!("{}", indent_block(&d));
                }
            }
        } else {
            let files: Vec<serde_json::Value> = targets
                .iter()
                .map(|t| match &t.desired {
                    None => json!({
                        "module": t.module,
                        "path": t.path,
                        "change": "computed",
                        "diff": diff::COMPUTED_NOTE,
                    }),
                    Some(desired) => {
                        let (change, d) = file_diff_for(t, desired, &remote);
                        json!({
                            "module": t.module,
                            "path": t.path,
                            "change": change.as_str(),
                            "diff": d,
                        })
                    }
                })
                .collect();
            docs.push(json!({ "host": host.address, "files": files }));
        }
    }

    if args.output != OutputFormat::Human {
        print_machine(args.output, &docs)?;
    }
    Ok(if failures == 0 { 0 } else { 1 })
}

// --- score (R78) --------------------------------------------------------

struct ScoreResult {
    host: String,
    index: Option<u32>,
    error: Option<String>,
}

/// Whether a host passes: an index at or above the threshold (or any index when
/// no threshold is set). A missing index never passes — we could not confirm.
fn score_passes(index: Option<u32>, threshold: Option<u32>) -> bool {
    match (index, threshold) {
        (Some(i), Some(t)) => i >= t,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn cmd_score(args: ScoreArgs) -> Result<i32> {
    let (cfg, _plugins) = load_config(&args.config)?;
    let script = lynis::audit_script();

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let results = fanout(&hosts, args.parallel, |host| {
        // The Lynis audit always runs on the target (it scores that host).
        match exec_script(host, &script, false, args.timeout.map(Duration::from_secs)) {
            Ok(out) => {
                let index = lynis::parse_hardening_index(&out.stdout);
                let error = if index.is_none() {
                    Some(if out.success() {
                        "no hardening index in Lynis output".to_string()
                    } else {
                        remote_error(&out)
                    })
                } else {
                    None
                };
                ScoreResult {
                    host: host.address.clone(),
                    index,
                    error,
                }
            }
            Err(e) => ScoreResult {
                host: host.address.clone(),
                index: None,
                error: Some(e.to_string()),
            },
        }
    });

    let mut all_pass = true;
    if args.output == OutputFormat::Human {
        for r in &results {
            print!("== host {} == ", r.host);
            match r.index {
                Some(i) => {
                    let pass = score_passes(Some(i), args.threshold);
                    all_pass &= pass;
                    match args.threshold {
                        Some(t) => println!(
                            "hardening index: {i} (threshold {t}) {}",
                            if pass { "PASS" } else { "FAIL" }
                        ),
                        None => println!("hardening index: {i}"),
                    }
                }
                None => {
                    all_pass = false;
                    println!(
                        "hardening index unavailable: {}",
                        r.error.as_deref().unwrap_or("unknown")
                    );
                }
            }
        }
    } else {
        let docs: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let pass = score_passes(r.index, args.threshold);
                all_pass &= pass;
                json!({
                    "host": r.host,
                    "index": r.index,
                    "threshold": args.threshold,
                    "pass": pass,
                    "error": r.error,
                })
            })
            .collect();
        print_machine(args.output, &docs)?;
    }

    // Exit non-zero when a threshold is not met or no index could be read (R100).
    Ok(if all_pass { 0 } else { 1 })
}

// --- rollback (R60/R88) -------------------------------------------------

struct HostRollback {
    host: String,
    modules: Vec<(&'static str, ApplyStatus, Option<String>)>,
}

fn cmd_rollback(args: RollbackArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;
    let only = resolve_only(&plan, &args.only)?;
    // Rolling back `users` deletes the authorized_keys and sudoers
    // drop-in anvil created. If a host logs in as one of those accounts, the
    // run removes its own way back in (with root login still off) — refuse.
    let rolls_back_users = selected(&plan, &only).iter().any(|m| m.id() == "users");
    if rolls_back_users {
        let created: Vec<&str> = cfg
            .users
            .as_ref()
            .map(|u| u.create.iter().map(|a| a.name.as_str()).collect())
            .unwrap_or_default();
        if let Some(h) = cfg
            .hosts()
            .iter()
            .find(|h| created.contains(&h.user.as_str()))
        {
            return Err(AnvilError::Usage(format!(
                "rollback of `users` would delete the SSH key and sudo rule of {:?}, \
                 the account anvil logs in as on {}; that locks the host out. \
                 Roll back the other modules with --only, or log in as another \
                 account first",
                h.user, h.address
            ))
            .into());
        }
    }

    // Reverse apply order (`containers` before `docker`, whose restart hides
    // userns-remapped containers), but sshd/ssh_crypto before `firewall`, so
    // the firewall rollback allows the port the restored sshd listens on.
    // The fourth element is the script as shown by --dry-run: secrets masked.
    let scripts: Vec<(&'static str, String, bool, String)> =
        crate::order::rollback_order(&selected(&plan, &only), |m| m.id())
            .into_iter()
            .map(|m| {
                let decl = m.declaration();
                let script = decl.render_rollback();
                let shown = decl.redact(&script);
                (m.id(), script, decl.runs_locally, shown)
            })
            .collect();

    if args.dry_run {
        if args.output == OutputFormat::Human {
            println!("# dry-run: rollback would run the following per host:");
            for (id, _, _, shown) in &scripts {
                println!("\n# ===== module: {id} (rollback) =====");
                print!("{shown}");
            }
        } else {
            let docs: Vec<serde_json::Value> = scripts
                .iter()
                .map(
                    |(id, _, _, shown)| json!({ "module": id, "status": "dry-run", "script": shown }),
                )
                .collect();
            print_machine(args.output, &docs)?;
        }
        return Ok(0);
    }

    let hosts = args.host_filter.select(&cfg.hosts())?;
    let results = fanout(&hosts, args.parallel, |host| {
        let modules = scripts
            .iter()
            .map(|(id, script, local, _)| {
                let (status, reason) = match exec_script(
                    host,
                    script,
                    *local,
                    args.timeout.map(Duration::from_secs),
                ) {
                    Ok(out) => {
                        let status = if out.success() {
                            parse_apply(&out.stdout)
                        } else {
                            ApplyStatus::Failed
                        };
                        (
                            status,
                            (status == ApplyStatus::Failed).then(|| remote_error(&out)),
                        )
                    }
                    Err(e) => (ApplyStatus::Failed, Some(e.to_string())),
                };
                (*id, status, reason)
            })
            .collect();
        HostRollback {
            host: host.address.clone(),
            modules,
        }
    });

    let failures: usize = results
        .iter()
        .flat_map(|h| &h.modules)
        .filter(|(_, s, _)| *s == ApplyStatus::Failed)
        .count();

    if args.output == OutputFormat::Human {
        for h in &results {
            println!("== host {} ==", h.host);
            for (id, status, reason) in &h.modules {
                match reason {
                    Some(r) => println!("  {:<14} {} ({r})", id, status.as_str()),
                    None => println!("  {:<14} {}", id, status.as_str()),
                }
            }
            if h.modules.is_empty() {
                println!("  (no implemented modules enabled)");
            }
        }
    } else {
        let docs: Vec<serde_json::Value> = results
            .iter()
            .map(|h| {
                let modules: Vec<serde_json::Value> = h
                    .modules
                    .iter()
                    .map(|(id, s, reason)| {
                        let mut obj = json!({ "module": id, "status": s.as_str() });
                        if let Some(r) = reason {
                            obj["reason"] = json!(r);
                        }
                        obj
                    })
                    .collect();
                json!({ "host": h.host, "modules": modules })
            })
            .collect();
        print_machine(args.output, &docs)?;
    }

    Ok(if failures == 0 { 0 } else { 1 })
}

// --- report -------------------------------------------------------

fn cmd_report(args: ReportArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;

    let enabled: Vec<String> = cfg
        .enabled_sections()
        .iter()
        .map(|s| s.id.to_string())
        .collect();

    let mut drift: BTreeMap<String, DriftState> = BTreeMap::new();
    let mut failures = 0;
    if args.check {
        let hosts = args.host_filter.select(&cfg.hosts())?;
        let results = probe_fleet(&hosts, &selected(&plan, &[]), 1, args.timeout);
        for (i, m) in plan.modules.iter().enumerate() {
            let outcomes = || results.iter().map(|h| &h.modules[i].1);
            let state = if outcomes().any(|o| matches!(o, ProbeOutcome::Failed(_))) {
                failures += 1;
                DriftState::Failed
            } else if outcomes().any(|o| matches!(o, ProbeOutcome::Drifted(_))) {
                DriftState::Drifted
            } else {
                DriftState::Aligned
            };
            drift.insert(m.id().to_string(), state);
        }
    }

    let mut rows = report::build_rows(&enabled, &drift);
    let plugin_ids: Vec<&'static str> = plan
        .modules
        .iter()
        .map(|m| m.id())
        .filter(|id| id.starts_with("plugin::"))
        .collect();
    rows.extend(report::plugin_rows(&plugin_ids, &drift));
    match args.output {
        ReportFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report::render_json(&rows, args.check))?
            )
        }
        // ndjson = one JSON object per line; the report is a single document, so
        // emit it compact on one line (not the pretty multi-line blob).
        ReportFormat::Ndjson => {
            println!(
                "{}",
                serde_json::to_string(&report::render_json(&rows, args.check))?
            )
        }
        ReportFormat::Human => print!("{}", report::render_human(&rows, args.check)),
        ReportFormat::Markdown => print!("{}", report::render_markdown(&rows, args.check)),
    }

    Ok(if failures == 0 { 0 } else { 1 })
}

// --- doctor (preflight) -----------------------------------------------------

/// Preflight checks: catch the common breakages — a config that won't
/// parse/validate, a plan that won't resolve, an untrusted plugin, an
/// unreachable host, or a missing `sudo -n` NOPASSWD rule — *before* a real
/// `apply`. The per-host probe runs `printf` under the same transport a real
/// run uses (`ssh … sudo -n bash -s` for non-root), so success implies both
/// reachability and usable passwordless sudo. Exit is non-zero if any check
/// fails.
fn cmd_doctor(args: DoctorArgs) -> Result<i32> {
    let (cfg, plugins) = load_config(&args.config)?;
    let plan = Plan::build_with_plugins(&cfg, &plugins)?;
    let timeout = args.timeout.map(Duration::from_secs);
    let hosts = args.host_filter.select(&cfg.hosts())?;

    println!("config + plan: ok ({} modules)", plan.order.len());
    if plan.order.is_empty() {
        println!("  warning: no modules enabled — nothing to apply");
    }
    if !plugins.is_empty() {
        println!(
            "plugins: {} enabled (skipped/malformed ones were warned on stderr)",
            plugins.len()
        );
    }

    let mut failures = 0usize;
    println!("hosts:");
    for host in &hosts {
        let label = if host.user == "root" {
            "reachable".to_string()
        } else {
            "reachable + sudo NOPASSWD".to_string()
        };
        match exec_script(host, "printf 'anvil-doctor-ok\\n'\n", false, timeout) {
            Ok(o) if o.success() && o.stdout.contains("anvil-doctor-ok") => {
                println!("  {:<24} ok ({label})", host.address);
            }
            Ok(o) => {
                failures += 1;
                let detail = remote_error(&o);
                println!(
                    "  {:<24} FAIL  probe did not succeed: {detail}",
                    host.address
                );
            }
            Err(e) => {
                failures += 1;
                println!("  {:<24} FAIL  could not run probe: {e}", host.address);
            }
        }
    }
    Ok(if failures == 0 { 0 } else { 1 })
}

fn indent_block(s: &str) -> String {
    s.lines()
        .map(|l| format!("      {l}\n"))
        .collect::<String>()
}

/// Render a starter config. Always valid TOML that passes `validate`.
fn render_init(profile: Option<&str>, full: bool) -> String {
    let mut out = String::new();
    if let Some(p) = profile {
        // Escaped too: a custom profile's file stem may still contain quotes.
        out.push_str(&format!("profile = {}\n\n", toml::Value::from(p)));
    }
    out.push_str(
        "# Fulcrum Anvil configuration. Enable a module by adding its [section].\n\
         [host]\n\
         address = \"CHANGEME.example.com\"\n\
         user = \"admin\"\n\
         port = 22\n\n\
         [sshd]\n\
         disable_root_login = true\n\
         disable_password_auth = true\n\
         port = 22\n\n\
         [firewall]\n\
         default_incoming = \"deny\"\n\
         default_outgoing = \"allow\"\n\n\
         [updates]\n\
         security_only = true\n\
         reboot_time = \"02:00\"\n",
    );
    if full {
        out.push_str(FULL_EXTRA);
    }
    out
}

/// Additional sections emitted by `init --full`. Kept valid so the generated
/// file round-trips through `validate`.
const FULL_EXTRA: &str = r#"
[fail2ban]
bantime = "10m"
findtime = "10m"
maxretry = 5

[users]
create = [
  { name = "deploy", sudo = true, ssh_authorized_keys = ["ssh-ed25519 AAAA..."] },
  { name = "agent", ssh_authorized_keys = ["ssh-ed25519 AAAA... orca@mac"] },   # [coding_agents]
]

[kernel]
harden_network = true

[kernel_modules]
blacklist_usb_storage = true

[ssh_crypto]

[suid]

[dns]
dns_servers = ["9.9.9.9"]
dnssec_strict = true

[process]
disable_core_dumps = true

[pam]
minlen = 12

[packages]
install = ["curl", "vim"]

[crowdsec]
# bouncer_mode = "nftables"   # unset: the distro package picks the backend

[auditd]
rule_set = "cis-level1"

[lynis]

[filesystem]
tmp_noexec = true

[docker]
iptables_off = false
source = "vendor"                          # or "distro": Ubuntu's docker.io + docker-compose-v2
log_driver = "json-file"                   # or "journald": containers log to the journal (Vector ships it)

# Compose projects, one systemd unit each. ${VAR} in `content` is resolved on
# the host by docker compose from the project's .env (written from `env`).
# A Podman host instead (without [docker] or compose): [podman] and/or
# runtime = "podman" under [containers]; Quadlet units, refused per host below
# Podman 4.4:
#   [podman]
#   log_driver = "k8s-file"                  # or "journald"
#   [containers.quadlet.web]
#   content = "[Container]\nImage=docker.io/library/nginx:alpine\nPublishPort=127.0.0.1:18080:80\n[Install]\nWantedBy=multi-user.target\n"
# Instead of inline `content`, `file = "compose/web.yaml"` reads the compose
# file at load, relative to this file (owned by you, not group/world-writable).
[containers.compose.web]
content = '''
services:
  web:
    image: nginx:1.27
    ports:
      - "127.0.0.1:18080:80"
    environment:
      TZ: ${TZ}
      SITE_NAME: ${SITE_NAME}
'''
env = { TZ = "UTC", SITE_NAME = "Bob's \"site\"" }

[tls]
provider = "certbot"
domains = ["example.com"]

# Forgejo on 127.0.0.1:3000, proxied by [tls]'s nginx; git over SSH on 2222.
# Put real secrets in the environment: secret_key = "${FORGEJO_SECRET_KEY}".
[forgejo]
domain = "example.com"
secret_key = "replace-me"
internal_token = "replace-me"
jwt_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
actions = true                             # Forgejo Actions; required by [forgejo_runner]
deploy = "native"                          # or "compose" (needs [docker]) / "quadlet" (Podman host): the rootless image, pinned by digest
listen = "public"                          # or "tailnet": ssh_port on tailscale0 only (needs [tailscale])
# image_digest = "sha256:…"                # compose with a non-default version

[hetzner]
server_name = "my-server"
firewall_name = "anvil"
keep_public_ssh = true                     # false: no SSH-from-anywhere rule; needs tailnet_only_ssh

# netcup SCP firewall, run locally with NETCUP_SCP_REFRESH_TOKEN exported.
[netcup]
server = "v2202501234567890123"           # SCP server id, name or nickname
policy = "anvil"                           # the one user policy anvil owns
keep_public_ssh = true                     # false: no SSH-from-anywhere rule; needs tailnet_only_ssh
rules = [{ direction = "in", protocol = "tcp", port = "443" }]

[headscale]
server_url = "https://headscale.example.com"
listen_addr = "127.0.0.1:8080"             # behind [caddy] or [tls]; headscale has no TLS
base_domain = "tailnet.example.com"        # MagicDNS suffix; not the server_url host
# sha256_amd64 = "<64 hex>"                # .deb checksums; required with a non-default version
# sha256_arm64 = "<64 hex>"

[[headscale.auth_keys]]
name = "servers"                           # key in /var/lib/headscale/preauth-servers.key
expiration = "24h"                         # re-created on the next apply once expired
tags = ["tag:server"]
ephemeral = false

[tailscale]
login_server = "https://headscale.example.com"

[greptimedb]
# retention = "30d"                        # TTL on every database at apply; needs version >= "v0.12.0"
memory_max = "2G"                          # container memory limit

[vector]
greptimedb_host = "127.0.0.1"
cgroups_include = ["system.slice/docker-*.scope", "ci.slice/**", "apps.slice/**", "user.slice/user-*.slice", "system.slice/*.service"]  # CPU/memory per container, CI, apps, user, service; [] = all

# [tls] above already binds 80/443; with it gone, drop the ports and ca.
[caddy]
http_port = 8080
https_port = 8443
ca = "internal"
# listen = "tailnet"                       # ports on tailscale0 only; every site tls = "tailscale"

[[caddy.site]]
domain = "git.example.com"
upstream = "127.0.0.1:3000"

[[caddy.site]]
domain = "host.tailnet-name.ts.net"        # MagicDNS name; certificate from tailscaled
upstream = "127.0.0.1:3000"
tls = "tailscale"                          # "acme" (default) | "tailscale" | "dns"
# dns_provider = "infomaniak"              # tls = "dns": ACME DNS-01 (Caddy built on the host)
# dns_token = "${INFOMANIAK_API_TOKEN}"    # written to a root-only env file, never the Caddyfile

[beszel]
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIReplaceWithYourHubKey"
# hub_url = "https://beszel.example.com"   # + token: agent connects out, no open port
# token = "${BESZEL_TOKEN}"
# hub_addresses = ["203.0.113.5"]          # unset: allowed on tailscale0 only
# hub = true                               # run the hub here too (then omit key)
# admin_email = "ops@example.com"          # hub: first admin, created on first start
# admin_password = "${BESZEL_ADMIN_PASSWORD}"
# docker = true                            # container stats: docker group, root-equivalent
# smart = true                             # SMART: smartmontools + disk group + CAP_SYS_RAWIO
# version = "0.22.0"                       # another release needs its tarball hashes:
# sha256 = { "beszel-agent_linux_amd64.tar.gz" = "<64 hex>", "beszel-agent_linux_arm64.tar.gz" = "<64 hex>" }

[restic]
repository = "sftp:backup@backup.example.com:/srv/restic/my-server"
password = "${RESTIC_PASSWORD}"   # export RESTIC_PASSWORD before apply

# One systemd slice (ci.slice) for every CI runner and its jobs: the
# total share of this host for CI. Each runner's own caps still apply inside.
[ci_resources]
cpu_quota = "800%"                         # 8 cores for all CI work together
memory_max = "20G"
tasks_max = 8192
cpu_weight = 50                            # below the default 100: sshd wins under load

# One systemd slice (apps.slice) for the host's apps (Caddy, Vector, Forgejo,
# GreptimeDB); MemoryLow keeps system.slice out of the kernel's first reclaim.
[apps_resources]
cpu_quota = "400%"                         # 4 cores for all apps together
memory_max = "6G"
system_memory_low = "2G"                   # system.slice's MemoryLow= under pressure

# Self-hosted GitHub Actions runner for PRIVATE repos only. The token is a
# one-hour registration token, needed only for the first apply:
#   export GITHUB_RUNNER_TOKEN=$(gh api -X POST orgs/acme/actions/runners/registration-token --jq .token)
[github_runner]
docker = "none"                            # "rootless" (either engine) or "group" (root on the host, Docker host)
cpu_quota = "400%"                         # systemd caps for the runner and its jobs
memory_max = "8G"
tasks_max = 4096
disk_max = "150G"                          # each runner's _work on a capped loop volume
# diag_retention_days = 14                 # daily prune of _diag logs
# home_cache_max = "20G"                   # the prune also wipes ~/.cache, ~/.cargo, ~/.rustup, ~/.npm past this, when idle

[github_runner.runners.build-1]
url = "https://github.com/acme"
token = "${GITHUB_RUNNER_TOKEN:-}"
labels = ["anvil"]
# mode = "ephemeral" instead: one job per sandbox (sysbox on a Docker host,
# Podman on a Podman host), minted with a GitHub App (org runners; see
# examples/github-runner-ephemeral.toml):
#   app_id, installation_id, runner_group_id, app_key = "${GITHUB_APP_KEY}",
#   capacity = 1, sandbox_cpus = "2", sandbox_memory = "4g",
#   sandbox_pids = 2048, sandbox_disk = "40G",
#   sandbox_runtime = "sysbox-runc",          # default by host; or "podman"
#   sandbox_packages = ["build-essential"]

# Forgejo Actions runner. Create it in Forgejo (Settings → Actions → Runners →
# Create new runner) and copy the UUID and token:
#   export FORGEJO_RUNNER_TOKEN=<token>
[forgejo_runner]
# url = "https://git.example.org/"        # default: the [forgejo] instance above
uuid = "00000000-0000-4000-8000-000000000000"
token = "${FORGEJO_RUNNER_TOKEN:-}"
labels = ["debian:host"]                   # "<name>:docker://<image>" needs docker = "rootless" or "group"
docker = "none"                            # "rootless" (either engine) or "group" (root on the host, Docker host)
capacity = 1
# home_cache_max = "20G"                   # daily prune of ~/.cache, ~/.cargo, ~/.rustup, ~/.npm past this, when idle
# mode = "ephemeral" instead: one job per sysbox sandbox (Docker host, Forgejo
# >= 15), an ephemeral runner registered per job; drop uuid, token and docker:
#   api_token = "${FORGEJO_API_TOKEN:-}",  # write:organization (org owner), write:repository or write:admin
#   owner = "acme"                         # or "acme/app"; omitted = instance-wide

# Claude Code and OpenCode for the no-sudo [users] account above; log in once
# per agent over `ssh -t agent@host` (docs/modules/coding-agents.md).
[coding_agents]
user = "agent"
claude_code = "stable"                     # installer channel: "latest" | "none"
opencode = "latest"                        # or a version for the v2 installer, or "none"; both self-update
skills = [{ source = "vercel-labs/skills", names = ["find-skills"] }]
claude_marketplaces = ["anthropics/claude-plugins-official"]
claude_plugins = ["commit-commands@claude-plugins-official"]
opencode_plugins = ["@example-org/example-plugin"]
opencode_mcp = { example-mcp = ["npx", "-y", "example-mcp@latest", "server", "--agent", "opencode"] }
# setup = { url = "https://github.com/owner/setup-repo.git", rev = "<40 hex>", run = "install.sh" }
cpu_quota = "400%"                         # caps on everything the agent runs
memory_max = "12G"
tasks_max = 4096
docker = "rootless"                        # the host's engine as the agent (DOCKER_HOST set); or "none"
# Remote Orca Server as the agent: phone and laptop pair over the tailnet
# (needs [tailscale] + [firewall]); pairing steps in docs/modules/coding-agents.md.
[coding_agents.orca_server]
port = 6769                                # not 6768: Orca's SSH-target runtime uses it
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn selected_filters_by_only_and_defaults_to_all() {
        let cfg: Config = toml::from_str(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            [users]
        "#,
        )
        .unwrap();
        let plan = Plan::build(&cfg).unwrap();
        let ids = |only: &[String]| -> Vec<&str> {
            selected(&plan, only).iter().map(|m| m.id()).collect()
        };
        assert_eq!(ids(&[]), ["users", "sshd"], "empty --only selects all");
        assert_eq!(ids(&["sshd".to_string()]), ["sshd"]);
        assert_eq!(
            ids(&["nope".to_string()]),
            Vec::<&str>::new(),
            "unknown id selects nothing"
        );
    }

    #[test]
    fn resolve_only_rejects_unknown_and_empty_entries() {
        // An unknown --only (typo) or a stray-comma empty entry must fail
        // loudly — never silently select nothing and look like success.
        let cfg: Config = toml::from_str(
            r#"
            [host]
            address = "h"
            user = "u"
            [sshd]
            [users]
        "#,
        )
        .unwrap();
        let plan = Plan::build(&cfg).unwrap();

        // Empty --only selects all (no error).
        assert!(resolve_only(&plan, &[]).unwrap().is_empty());
        // A known id passes through.
        let only = resolve_only(&plan, &["sshd".to_string()]).unwrap();
        assert_eq!(only, ["sshd"]);

        // Unknown id -> Usage error naming the entry and listing valid modules.
        let err = resolve_only(&plan, &["ssshd".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ssshd"), "{msg}");
        assert!(msg.contains("sshd"), "{msg}");
        assert!(msg.contains("users"), "{msg}");

        // Empty entry (stray comma: `--only sshd,,users`) -> Usage error.
        let err = resolve_only(&plan, &["sshd".to_string(), "".to_string()]).unwrap_err();
        assert!(err.to_string().contains("empty entry"), "{err}");

        // Whitespace-only entry is also rejected.
        let err = resolve_only(&plan, &["   ".to_string()]).unwrap_err();
        assert!(err.to_string().contains("empty entry"), "{err}");
    }

    #[test]
    fn init_default_is_valid_config() {
        let text = render_init(None, false);
        let cfg: Config = toml::from_str(&text).expect("parse init output");
        cfg.validate().expect("init default validates");
    }

    #[test]
    fn init_profile_name_is_toml_escaped() {
        // A custom profile stem can contain a quote; it must not break the TOML.
        let text = render_init(Some("a\"b\n[evil]"), false);
        let v: toml::Table = toml::from_str(&text).expect("parse init output");
        assert_eq!(v["profile"].as_str(), Some("a\"b\n[evil]"));
        assert!(!v.contains_key("evil"));
    }

    #[test]
    fn init_full_is_valid_config() {
        let text = render_init(Some("cis-level1"), true);
        // Strip the profile line the way the loader would before deserializing.
        let body: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("profile ="))
            .map(|l| format!("{l}\n"))
            .collect();
        let cfg: Config = toml::from_str(&body).expect("parse full init output");
        cfg.validate().expect("init --full validates");
        assert!(cfg.is_enabled("tailscale"));
        assert!(cfg.is_enabled("hetzner"));
        assert!(cfg.is_enabled("netcup"));
    }

    fn hspec(addr: &str) -> HostSpec {
        HostSpec {
            address: addr.into(),
            user: "admin".into(),
            port: 22,
            identity_file: None,
            ssh_options: Vec::new(),
        }
    }

    #[test]
    fn score_threshold_logic() {
        assert!(score_passes(Some(80), Some(70)));
        assert!(score_passes(Some(70), Some(70)));
        assert!(!score_passes(Some(60), Some(70)));
        // No threshold: any real index passes, a missing index never does.
        assert!(score_passes(Some(1), None));
        assert!(!score_passes(None, None));
        assert!(!score_passes(None, Some(50)));
    }

    #[test]
    fn fanout_preserves_host_order_across_modes() {
        let owned = [hspec("h0"), hspec("h1"), hspec("h2"), hspec("h3")];
        let hosts: Vec<&HostSpec> = owned.iter().collect();
        for parallel in [1u32, 0, 2, 10] {
            let got = fanout(&hosts, parallel, |h| h.address.clone());
            assert_eq!(got, vec!["h0", "h1", "h2", "h3"], "parallel={parallel}");
        }
    }

    #[test]
    fn fanout_empty_is_empty() {
        let got = fanout(&[], 4, |h: &HostSpec| h.address.clone());
        assert!(got.is_empty());
    }

    #[test]
    fn remote_error_prefers_stderr_then_exit() {
        let with_err = ssh::RemoteOutput {
            exit_code: Some(2),
            stdout: String::new(),
            stderr: "boom: permission denied\nsecond line".into(),
        };
        assert_eq!(remote_error(&with_err), "boom: permission denied");

        let no_err = ssh::RemoteOutput {
            exit_code: Some(7),
            stdout: String::new(),
            stderr: "   ".into(),
        };
        assert_eq!(remote_error(&no_err), "exit 7");

        // The script's own FAILED: line beats stderr and a 0 exit.
        let marked = ssh::RemoteOutput {
            exit_code: Some(0),
            stdout: "OK: x\nFAILED: hcloud CLI not found\nFAILED: later".into(),
            stderr: "noise".into(),
        };
        assert_eq!(remote_error(&marked), "FAILED: hcloud CLI not found");

        // A failure the script reports on stderr (the reload guard's,
        // after apt/needrestart noise) beats that noise.
        let noisy = ssh::RemoteOutput {
            exit_code: Some(1),
            stdout: "OK: x\n".into(),
            stderr: "Scanning processes...\n  FAILED: docker daemon validation or reload failed, reverting\n".into(),
        };
        assert_eq!(
            remote_error(&noisy),
            "FAILED: docker daemon validation or reload failed, reverting"
        );
    }

    #[test]
    fn safety_skip_firewall_after_ssh_failures() {
        // firewall is fenced off when sshd or ssh_crypto failed earlier.
        assert!(safety_skip_reason("firewall", &["sshd"]).is_some());
        assert!(safety_skip_reason("beszel", &["firewall"]).is_some());
        assert!(safety_skip_reason("beszel", &["sshd"]).is_none());
        assert!(safety_skip_reason("firewall", &["ssh_crypto"]).is_some());
        let reason = safety_skip_reason("firewall", &["kernel", "ssh_crypto"]).unwrap();
        assert!(reason.contains("ssh_crypto"), "names the culprit: {reason}");
        // Unrelated failures do not fence the firewall.
        assert!(safety_skip_reason("firewall", &["kernel"]).is_none());
        assert!(safety_skip_reason("firewall", &[]).is_none());
        // hetzner's cloud firewall is a fence too.
        let reason = safety_skip_reason("hetzner", &["sshd"]).unwrap();
        assert!(reason.contains("hetzner"), "{reason}");
        assert!(safety_skip_reason("hetzner", &["ssh_crypto"]).is_some());
        assert!(safety_skip_reason("hetzner", &["kernel"]).is_none());
        // T12: so is netcup's SCP firewall.
        for culprit in ["sshd", "ssh_crypto", "tailscale"] {
            let reason = safety_skip_reason("netcup", &[culprit]).unwrap();
            assert!(
                reason.contains(culprit) && reason.contains("netcup"),
                "{reason}"
            );
        }
        assert!(safety_skip_reason("netcup", &["kernel"]).is_none());
    }

    #[test]
    fn safety_skip_fences_after_tailscale_failure_under_hostile_order() {
        // T21: a failed tailscale step fences off firewall and hetzner even when
        // hostile overrides move them after tailscale.
        use crate::config::{EnabledSection, OrderOverride};
        let hostile = |id: &'static str, order: i64| EnabledSection {
            id,
            order_override: OrderOverride {
                order: Some(order),
                ..Default::default()
            },
        };
        let enabled = vec![
            hostile("sshd", 20),
            hostile("tailscale", 1),
            hostile("firewall", 99),
            hostile("hetzner", 98),
            hostile("netcup", 0),
            hostile("updates", 100),
        ];
        let order = crate::order::resolve_order(&enabled, None).unwrap();
        let ts = order.iter().position(|m| m == "tailscale").unwrap();
        let mut failed: Vec<&'static str> = vec!["tailscale"];
        for id in ["firewall", "hetzner", "netcup"] {
            assert!(
                order.iter().position(|m| m == id).unwrap() > ts,
                "{order:?}"
            );
            let reason = safety_skip_reason(id, &failed).unwrap();
            assert!(reason.contains("tailscale"), "names the culprit: {reason}");
        }
        failed.clear();
        assert!(safety_skip_reason("firewall", &failed).is_none());
        // Non-fence modules are not affected by a tailscale failure.
        assert!(safety_skip_reason("beszel", &["tailscale"]).is_none());
        assert!(safety_skip_reason("headscale", &["tailscale"]).is_none());
    }

    #[test]
    fn tailnet_gate_closes_the_edge_only_over_the_tailnet() {
        // T10: hetzner drops public SSH only when anvil's session is on the
        // tailnet; anything else (public IP, mixed, unresolvable) is skipped.
        let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for ok in [
            "100.64.0.1",
            "100.127.255.254",
            "fd7a:115c:a1e0::1",
            "::ffff:100.64.0.1",
        ] {
            assert!(tailnet_gate_reason(&[ip(ok)]).is_none(), "{ok}");
        }
        for bad in [
            "203.0.113.5",
            "100.128.0.1",
            "10.0.0.1",
            "fd7a:115c:a1e1::1",
        ] {
            let r = tailnet_gate_reason(&[ip(bad)]).unwrap();
            assert!(r.contains("not closing public SSH"), "{bad}: {r}");
        }
        assert!(tailnet_gate_reason(&[ip("100.64.0.1"), ip("203.0.113.5")]).is_some());
        assert!(
            tailnet_gate_reason(&[]).is_some(),
            "unresolvable is not proof"
        );
        // T21 still holds: a failed tailscale fences hetzner before the gate.
        assert!(safety_skip_reason("hetzner", &["tailscale"]).is_some());
    }

    #[test]
    fn host_ips_resolves_literals() {
        let host: HostSpec = toml::from_str("address = \"100.64.0.7\"\nuser = \"u\"").unwrap();
        assert_eq!(
            host_ips(&host),
            vec!["100.64.0.7".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn step_skip_gates_only_hetzner_when_closing_public_ssh() {
        let host = |a: &str| -> HostSpec {
            toml::from_str(&format!("address = \"{a}\"\nuser = \"u\"")).unwrap()
        };
        let public = host("203.0.113.5");
        let both: &[&str] = &["hetzner", "netcup"];
        for id in ["hetzner", "netcup"] {
            assert!(step_skip_reason(id, &[], both, &public).is_some());
            assert!(step_skip_reason(id, &[], &[], &public).is_none());
            assert!(step_skip_reason(id, &[], both, &host("100.64.0.7")).is_none());
            let r = step_skip_reason(id, &["tailscale"], both, &host("100.64.0.7")).unwrap();
            assert!(r.contains("tailscale failed"), "T21 wins: {r}");
        }
        assert!(step_skip_reason("firewall", &[], both, &public).is_none());
        // Gated per provider: netcup closing does not gate hetzner.
        assert!(step_skip_reason("netcup", &[], &["netcup"], &public).is_some());
        assert!(step_skip_reason("hetzner", &[], &["netcup"], &public).is_none());
    }

    #[test]
    fn safety_skip_updates_after_any_failure() {
        assert!(safety_skip_reason("updates", &["pam"]).is_some());
        assert!(safety_skip_reason("updates", &["sshd", "pam"]).is_some());
        assert!(safety_skip_reason("updates", &[]).is_none());
        // Other modules are never safety-skipped.
        assert!(safety_skip_reason("kernel", &["sshd", "pam"]).is_none());
    }

    struct FakeModule {
        id: &'static str,
        decl: crate::engine::Declaration,
    }

    impl Module for FakeModule {
        fn id(&self) -> &'static str {
            self.id
        }
        fn declaration(&self) -> crate::engine::Declaration {
            self.decl.clone()
        }
    }

    #[test]
    fn diff_targets_split_static_computed_and_local() {
        use crate::engine::{Declaration, ManagedFile};

        let remote = FakeModule {
            id: "demo",
            decl: Declaration::new("demo")
                .file(ManagedFile::new("/etc/a.conf", "a\n", "0644", "root:root"))
                .file(ManagedFile::computed(
                    "/etc/b.conf",
                    "gen_b",
                    "0644",
                    "root:root",
                )),
        };
        let local_mod = FakeModule {
            id: "cloud",
            decl: Declaration::new("cloud")
                .file(ManagedFile::new("/tmp/local", "x", "0644", "me:me"))
                .local(),
        };

        let mods: Vec<&dyn Module> = vec![&remote, &local_mod];
        let targets = collect_diff_targets(&mods);
        // The local declaration's file is excluded from remote diffing.
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].path, "/etc/a.conf");
        assert_eq!(targets[0].desired.as_deref(), Some("a\n"));
        // The computed file is present but has no local desired content.
        assert_eq!(targets[1].path, "/etc/b.conf");
        assert!(targets[1].desired.is_none());
    }

    #[test]
    fn init_full_plan_respects_safety() {
        let body: String = render_init(None, true)
            .lines()
            .filter(|l| !l.trim_start().starts_with("profile ="))
            .map(|l| format!("{l}\n"))
            .collect();
        let cfg: Config = toml::from_str(&body).unwrap();
        let plan = Plan::build(&cfg).unwrap();
        assert_eq!(plan.order.last().unwrap(), "updates");
        let s = plan.order.iter().position(|m| m == "sshd").unwrap();
        let f = plan.order.iter().position(|m| m == "firewall").unwrap();
        assert!(s < f);
    }
}
