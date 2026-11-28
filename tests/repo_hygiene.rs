//! Personal agent files (local notes, skills, agent config) never get
//! committed. `.gitignore` covers them; this test catches a `git add -f`.

use std::process::Command;

const PRIVATE: [&str; 3] = [".opencode", ".claude/skills", "*.local.md"];

#[test]
fn no_personal_agent_file_is_tracked() {
    let out = Command::new("git")
        .args(["ls-files", "--"])
        .args(PRIVATE)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();
    // shortcut: skips outside a git checkout (e.g. a crates.io tarball); CI always has one.
    let Ok(out) = out else { return };
    if !out.status.success() {
        return;
    }
    let tracked = String::from_utf8_lossy(&out.stdout);
    assert!(
        tracked.trim().is_empty(),
        "personal agent files are tracked; remove them from git:\n{tracked}"
    );
}
