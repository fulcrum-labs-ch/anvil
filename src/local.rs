//! Local execution path for declarations that run on the **operator's**
//! machine rather than the target host (see
//! [`runs_locally`](crate::engine::Declaration::runs_locally)). The canonical
//! example is the hetzner
//! module, which drives the `hcloud` CLI with a local `HCLOUD_TOKEN` — running
//! it over SSH on the target would be a defect.
//!
//! The contract mirrors the SSH transport (R11): the rendered script is
//! delivered on stdin to a single `bash -s` invocation. No ssh, no sudo — a
//! local run uses only the operator's own privileges.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::error::{AnvilError, Result};
use crate::ssh::{run_child, RemoteOutput};

/// Run a rendered script on the operator's machine, returning its captured
/// output in the same shape as the SSH transport so callers can parse markers
/// identically. `timeout` bounds the call.
pub fn run(script: &str, timeout: Option<Duration>) -> Result<RemoteOutput> {
    let mut child = Command::new("bash")
        .arg("-s")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AnvilError::Ssh(format!("failed to spawn local bash: {e}")))?;

    child
        .stdin
        .take()
        .ok_or_else(|| AnvilError::Ssh("local bash stdin unavailable".into()))?
        .write_all(script.as_bytes())
        .map_err(|e| AnvilError::Ssh(format!("failed to send script to local bash: {e}")))?;

    let out = run_child(child, timeout, "local bash")?;

    Ok(RemoteOutput {
        exit_code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_runner_captures_stdout_and_exit_code() {
        let out = run("printf 'OK: local hello\\n'", None).expect("local bash runs");
        assert!(out.success());
        assert_eq!(out.stdout, "OK: local hello\n");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn local_runner_reports_failure_exit_codes() {
        let out = run("echo boom >&2\nexit 3\n", None).expect("local bash runs");
        assert!(!out.success());
        assert_eq!(out.exit_code, Some(3));
        assert!(out.stderr.contains("boom"));
    }

    #[test]
    fn local_runner_timeout_kills_a_stalled_script() {
        // A script that never exits must be killed at the deadline, not
        // hang the run forever. A tight bash busy-loop blocks within bash
        // itself (no child process to orphan after the SIGKILL).
        let start = std::time::Instant::now();
        let err = run("while true; do :\ndone\n", Some(Duration::from_millis(200)))
            .expect_err("stalled script must time out");
        let elapsed = start.elapsed();
        assert!(err.to_string().contains("timed out"), "{err}");
        // Killed promptly — well under any "hung" threshold.
        assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
    }
}
