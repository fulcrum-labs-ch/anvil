//! SSH transport (R10, Fixed Contract). We shell out to the system `ssh`
//! binary and deliver the remote script on stdin to a single invocation, so we
//! inherit the operator's `~/.ssh/config`, agent, jump hosts and known-hosts.
//! We never link a Rust SSH library.

use std::hash::{Hash, Hasher};
use std::io::Read;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::HostSpec;
use crate::error::{AnvilError, Result};

/// Result of running a remote script.
#[derive(Debug, Clone)]
pub struct RemoteOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl RemoteOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Directory holding the multiplexing control sockets (R54).
fn control_dir() -> PathBuf {
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    base.join("anvil-control")
}

/// Control socket for connection reuse across probe/apply/per-module calls
/// to one host (R54), named by a 16-hex hash of the connection settings. Not
/// `%C`: its 40 hex chars plus the `.<16 random>` temp suffix ssh binds first
/// overflow the 104-byte socket path under macOS's 49-char `$TMPDIR` — ssh
/// then refuses to connect at all (OpenSSH 10.5).
fn control_path(dir: &Path, host: &HostSpec) -> PathBuf {
    let mut h = std::hash::DefaultHasher::new();
    (
        &host.user,
        &host.address,
        host.port,
        &host.identity_file,
        &host.ssh_options,
    )
        .hash(&mut h);
    dir.join(format!("{:016x}", h.finish()))
}

/// Build the full `ssh` argument vector (excluding the program name). Pure and
/// testable: no process is spawned here.
pub fn build_ssh_argv(host: &HostSpec, control_path: &str, remote_cmd: &str) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();

    // Non-interactive, fail fast, multiplex the session.
    for opt in [
        "BatchMode=yes",
        "ConnectTimeout=15",
        "ControlMaster=auto",
        "ControlPersist=60s",
        "StrictHostKeyChecking=accept-new",
    ] {
        argv.push("-o".into());
        argv.push(opt.into());
    }
    argv.push("-o".into());
    argv.push(format!("ControlPath={control_path}"));

    argv.push("-p".into());
    argv.push(host.port.to_string());

    if let Some(id) = &host.identity_file {
        argv.push("-i".into());
        argv.push(id.clone());
    }

    // Operator-supplied extra `-o` options.
    for opt in &host.ssh_options {
        argv.push("-o".into());
        argv.push(opt.clone());
    }

    argv.push(format!("{}@{}", host.user, host.address));
    // The remote command; the script arrives on stdin (see `run`).
    argv.push(remote_cmd.to_string());
    argv
}

/// The remote command that consumes the generated script from stdin under bash
/// with `set -euo pipefail` (R11). The script itself also sets these; running
/// under `bash -s` makes the shebang a harmless comment.
///
/// Managed files live under `/etc` and `/var/lib`, so the script must run
/// privileged. When the login user is not root the whole bash invocation is
/// wrapped in `sudo -n`: `-n` makes a missing NOPASSWD rule fail fast with a
/// clear error instead of hanging on a password prompt (stdin carries the
/// script, not a password).
pub fn remote_command(user: &str) -> &'static str {
    if user == "root" {
        "bash -s"
    } else {
        "sudo -n bash -s"
    }
}

/// Drain a child pipe on a background thread. `None` in (the caller spawned
/// with [`Stdio::null`], discarding output) yields `None` out, not an error:
/// an absent pipe must never short-circuit [`run_child`] before its kill path,
/// or a hung child outlives us as an orphan (R54).
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> Option<thread::JoinHandle<Vec<u8>>> {
    pipe.map(|mut p| {
        thread::spawn(move || {
            let mut b = Vec::new();
            let _ = p.read_to_end(&mut b);
            b
        })
    })
}

/// Join a [`drain`] thread, yielding its bytes — empty if the pipe was absent
/// or the thread panicked.
fn joined(thr: Option<thread::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    thr.map(|t| t.join().unwrap_or_default())
        .unwrap_or_default()
}

/// Wait for `child`, capturing its output; if `timeout` elapses, SIGKILL the
/// child (via the owned [`Child`] handle — no libc/pid race) and return a
/// timeout error. stdout/stderr are drained on background threads so a *hung*
/// child's full pipes don't block the kill (a blocking `read_to_end` on this
/// thread would defeat it). `what` labels the child in error messages.
///
/// Absent pipes are tolerated (see [`drain`]): every exit path from here must
/// reach the wait/kill below, because nothing else reaps the child — dropping
/// a [`Child`] neither kills nor waits for it.
pub(crate) fn run_child(
    mut child: std::process::Child,
    timeout: Option<Duration>,
    what: &str,
) -> Result<Output> {
    let out_thr = drain(child.stdout.take());
    let err_thr = drain(child.stderr.take());

    let status = match timeout {
        Some(d) => {
            let deadline = Instant::now() + d;
            loop {
                if let Some(s) = child
                    .try_wait()
                    .map_err(|e| AnvilError::Ssh(format!("{what}: {e}")))?
                {
                    break s;
                }
                if Instant::now() >= deadline {
                    // Timed out: kill the child, reap it (closing the pipes so
                    // the drain threads see EOF), then surface a timeout error.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = joined(out_thr);
                    let _ = joined(err_thr);
                    return Err(AnvilError::Ssh(format!(
                        "{what} timed out after {}s",
                        d.as_secs()
                    )));
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        None => child
            .wait()
            .map_err(|e| AnvilError::Ssh(format!("{what} did not complete: {e}")))?,
    };

    Ok(Output {
        status,
        stdout: joined(out_thr),
        stderr: joined(err_thr),
    })
}

/// Best-effort close of the multiplexed control socket (R54), so a timed-out
/// session does not leave a lingering master for `ControlPersist`. Bounded: a
/// real `ssh -O exit` returns in well under a second, but cleanup must never
/// itself hang (e.g. a misbehaving transport), so it is killed after a short
/// deadline.
fn close_control_socket(host: &HostSpec, cpath: &std::path::Path) {
    let target = format!("{}@{}", host.user, host.address);
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-o",
        &format!("ControlPath={}", cpath.to_string_lossy()),
        "-O",
        "exit",
        "-p",
        &host.port.to_string(),
    ]);
    if let Some(id) = &host.identity_file {
        cmd.args(["-i", id]);
    }
    // Piped though the output is discarded: `run_child` tolerates absent pipes,
    // so null would also be correct — but this path only runs after a probe has
    // already failed, making the two drain threads free, and it keeps the kill
    // below reachable even if that tolerance ever regresses. An `-O exit` that
    // escapes the kill is reaped by nobody and spins as an orphan.
    cmd.arg(&target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Ok(child) = cmd.spawn() {
        let _ = run_child(child, Some(Duration::from_secs(3)), "ssh -O exit");
    }
}

/// Run a rendered script on `host` over SSH, returning its captured output.
/// `timeout` bounds the whole call (R-late): a stalled `apt-get`, a
/// misconfigured `sudo`, or a NAT'd dead connection can no longer hang anvil
/// indefinitely — the child is killed and the error reported.
pub fn run(host: &HostSpec, script: &str, timeout: Option<Duration>) -> Result<RemoteOutput> {
    let dir = control_dir();
    std::fs::create_dir_all(&dir).map_err(|e| {
        AnvilError::Ssh(format!("cannot create control dir {}: {e}", dir.display()))
    })?;
    let cpath = control_path(&dir, host);
    let argv = build_ssh_argv(host, &cpath.to_string_lossy(), remote_command(&host.user));

    let mut child = Command::new("ssh")
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AnvilError::Ssh(format!("failed to spawn ssh: {e}")))?;

    child
        .stdin
        .take()
        .ok_or_else(|| AnvilError::Ssh("ssh stdin unavailable".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| AnvilError::Ssh(format!("failed to send script: {e}")))?;

    let result = run_child(child, timeout, "ssh");
    if result.is_err() {
        // A timeout (or spawn failure) — close any lingering master connection.
        close_control_socket(host, &cpath);
    }
    let out = result?;

    Ok(RemoteOutput {
        exit_code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> HostSpec {
        HostSpec {
            address: "server.example".into(),
            user: "admin".into(),
            port: 2222,
            identity_file: Some("/home/me/.ssh/id_ed25519".into()),
            ssh_options: vec!["ServerAliveInterval=30".into()],
        }
    }

    #[test]
    fn control_path_fits_the_socket_limit_for_any_host() {
        // macOS TMPDIR is 49 chars; sun_path is 104 bytes including the
        // NUL, and the master first binds `<path>.<16 random chars>`.
        let dir =
            Path::new("/var/folders/xx/xxxxxxxxxxxxxxxxxxxxxxxx0000gn/T/").join("anvil-control");
        let mut h = host();
        h.address = "a".repeat(253);
        let p = control_path(&dir, &h);
        assert!(
            p.as_os_str().len() + 17 < 104,
            "{} bytes",
            p.as_os_str().len()
        );
        assert!(!p.to_string_lossy().contains('%'), "no ssh token expansion");
        // Distinct connection settings get distinct sockets.
        h.port = 22;
        assert_ne!(control_path(&dir, &h), p);
    }

    #[test]
    fn argv_uses_multiplexing_and_batch_mode() {
        let h = host();
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        let joined = argv.join(" ");
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("ControlMaster=auto"));
        assert!(joined.contains("ControlPersist=60s"));
        assert!(joined.contains("ControlPath=/run/cm"));
    }

    #[test]
    fn argv_carries_port_identity_and_target() {
        let h = host();
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        assert!(argv.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(argv
            .windows(2)
            .any(|w| w == ["-i", "/home/me/.ssh/id_ed25519"]));
        assert!(argv.contains(&"admin@server.example".to_string()));
    }

    #[test]
    fn non_root_user_escalates_with_noninteractive_sudo() {
        // Managed files live under /etc — a non-root operator must run the
        // script under sudo, and `-n` fails fast when NOPASSWD is missing.
        let h = host();
        assert_eq!(h.user, "admin");
        assert_eq!(remote_command(&h.user), "sudo -n bash -s");
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        assert_eq!(argv.last().unwrap(), "sudo -n bash -s");
    }

    #[test]
    fn root_user_runs_plain_bash_without_sudo() {
        let mut h = host();
        h.user = "root".into();
        assert_eq!(remote_command(&h.user), "bash -s");
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        assert_eq!(argv.last().unwrap(), "bash -s");
        assert!(!argv.iter().any(|a| a.contains("sudo")));
    }

    #[test]
    fn extra_ssh_options_are_passed() {
        let h = host();
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        assert!(argv.contains(&"ServerAliveInterval=30".to_string()));
    }

    #[test]
    fn no_identity_flag_when_absent() {
        let mut h = host();
        h.identity_file = None;
        let argv = build_ssh_argv(&h, "/run/cm", remote_command(&h.user));
        assert!(!argv.contains(&"-i".to_string()));
    }
}
