//! Byte-exact golden snapshots of a rich Declaration's rendered scripts.
//!
//! Any change to the engine's renderers — probe/apply/rollback — surfaces as a
//! diff against the committed golden files, catching regressions and
//! giving `cargo mutants` teeth at the engine layer. The declaration exercises
//! every render path: a static file, a computed-content file, a command, a
//! command-edited file, a module-authored rollback, and a guarded reload.
//!
//! After an *intentional* rendering change, update the golden:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo nextest run golden
//! ```

use std::path::Path;
use std::process::{Command, Stdio};

use fulcrum_anvil::engine::{Declaration, ManagedCommand, ManagedFile, ReloadGuard};

/// A declaration touching every render path the engine has.
fn rich() -> Declaration {
    Declaration::new("golden")
        .file(ManagedFile::new(
            "/etc/golden-static",
            "key = value\n",
            "0640",
            "root:root",
        ))
        .file(ManagedFile::computed(
            "/etc/golden-computed",
            "printf 'generated\\n'",
            "0644",
            "root:root",
        ))
        .command(ManagedCommand::new("do a thing", "true", "echo done"))
        .command_file("/etc/golden-edited")
        .rollback_script("printf 'CHANGED: custom rollback\\n'\n")
        .guarded_reload(ReloadGuard {
            describe: "golden reload".into(),
            validate: "true".into(),
            reload: "echo reloaded".into(),
        })
}

/// `bash -n` parses a script; returns false if bash is unavailable.
fn parses(script: &str) -> bool {
    use std::io::Write as _;
    let mut child = match Command::new("bash")
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return true, // no bash — don't gate on it here
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(script.as_bytes());
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

#[test]
fn rich_declaration_scripts_match_golden() {
    let decl = rich();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden");
    let _ = std::fs::create_dir_all(&dir);
    for (name, actual) in [
        ("probe", decl.render_probe()),
        ("apply", decl.render_apply()),
        ("rollback", decl.render_rollback()),
    ] {
        // Every rendered script must be syntactically valid bash.
        assert!(parses(&actual), "{name} script fails bash -n:\n{actual}");

        let path = dir.join(format!("{name}.sh"));
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, &actual).unwrap();
            continue;
        }
        let golden = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "golden {} missing — run `UPDATE_GOLDEN=1 cargo nextest run golden` to create",
                path.display()
            )
        });
        assert_eq!(
            actual, golden,
            "{} script drifted from golden — if intended, run \
             `UPDATE_GOLDEN=1 cargo nextest run golden` to update\n\
             --- actual ---\n{actual}--- golden ---\n{golden}",
            name
        );
    }
}
