//! The public repo never tracks the maintainers' private ops files (plan,
//! skills, agent notes). They live in a separate private repo cloned to
//! `.ops/` and linked in locally; `.gitignore` covers the links, this test
//! catches a `git add -f` or a renamed path.

use std::process::Command;

const PRIVATE: [&str; 8] = [
    ".ops",
    "docs/plan",
    "docs/capabilities",
    "tasks.md",
    "AGENTS.md",
    ".opencode",
    ".claude/skills",
    "*.local.md",
];

#[test]
fn no_private_ops_file_is_tracked() {
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
        "private ops files are tracked; move them to .ops:\n{tracked}"
    );
}
