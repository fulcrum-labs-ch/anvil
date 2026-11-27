//! File-diff support for the `diff` command (R89, I4).
//!
//! Because modules declare [`ManagedFile`](crate::engine::ManagedFile) values
//! carrying `path` + `desired_content`, `diff` never scrapes generated bash. It
//! reads the current remote file directly (base64-framed so newlines and shell
//! metacharacters are inert) and produces a unified diff against the declared
//! desired content. Everything here is pure and unit-tested; the SSH call lives
//! in the CLI.

use crate::engine::norm_mode;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::escape::shell_escape;

/// Line-leading marker for a read-file record. The path and content are base64
/// so no filename or file byte can be confused for a field delimiter.
pub const DIFF_MARKER: &str = "ANVIL_DIFF";

/// What `diff` reports for a [`FileContent::Computed`]
/// (crate::engine::FileContent) managed file: its desired content only exists
/// once the generator runs on the host, so no local unified diff is possible.
pub const COMPUTED_NOTE: &str = "(content computed on host; no local diff available)";

/// The current state of a managed file on the remote host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteFile {
    /// File exists; carries its full current content.
    Present(String),
    /// File exists but its content is not valid UTF-8, so no line diff is
    /// possible (it can never equal the declared `String` content).
    Binary,
    /// File does not exist on the host.
    Absent,
}

/// The remote file's `stat -c '%a'` mode and `stat -c '%U:%G'` owner — what the
/// engine probe compares, so `diff` sees mode/owner-only drift too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStat {
    pub mode: String,
    pub owner: String,
}

/// What `apply` would do to a file, derived from current-vs-desired (R89).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileChange {
    /// File is absent and would be created.
    Create,
    /// File exists but differs and would be rewritten.
    Modify,
    /// File already matches desired content.
    None,
}

impl FileChange {
    /// Stable machine string for `--output json`.
    pub fn as_str(self) -> &'static str {
        match self {
            FileChange::Create => "create",
            FileChange::Modify => "modify",
            FileChange::None => "none",
        }
    }

    pub fn classify(current: &RemoteFile, desired: &str) -> FileChange {
        match current {
            RemoteFile::Absent => FileChange::Create,
            RemoteFile::Present(c) if c == desired => FileChange::None,
            RemoteFile::Present(_) | RemoteFile::Binary => FileChange::Modify,
        }
    }
}

/// Render the full `diff` verdict for one file: mode/owner change lines (only
/// when `stat` is known) followed by the [`unified_diff`] of the content. A
/// mode/owner-only drift is a [`FileChange::Modify`], as `apply` chmod/chowns.
pub fn file_diff(
    path: &str,
    current: &RemoteFile,
    stat: Option<&RemoteStat>,
    desired: &str,
    mode: &str,
    owner: &str,
) -> (FileChange, String) {
    let mut out = String::new();
    if let Some(st) = stat {
        let want_mode = norm_mode(mode);
        if st.mode != want_mode {
            out.push_str(&format!("mode: {} -> {want_mode}\n", st.mode));
        }
        if !owner_matches(&st.owner, owner) {
            out.push_str(&format!("owner: {} -> {owner}\n", st.owner));
        }
    }
    let change = match FileChange::classify(current, desired) {
        FileChange::None if !out.is_empty() => FileChange::Modify,
        c => c,
    };
    out.push_str(&unified_diff(path, current, desired));
    (change, out)
}

/// Mirrors `engine::owner_check`: a trailing-colon `user:` (chown's login-group
/// shorthand) compares only the user; otherwise the full `user:group`.
fn owner_matches(current: &str, owner: &str) -> bool {
    match owner.strip_suffix(':') {
        Some(user) if !user.is_empty() => current.split(':').next() == Some(user),
        _ => current == owner,
    }
}

/// Build a read-only script that prints one [`DIFF_MARKER`] record per path:
/// `ANVIL_DIFF <b64-path> present <b64-stat> <b64-content>` (stat is
/// `%a %U:%G`, or `-` if unreadable; content last so an empty file simply has
/// no field) or `ANVIL_DIFF <b64-path> absent -`. The path is shell-escaped where interpolated into the shell (R55);
/// the base64 path in the record is injection-safe by construction.
pub fn read_files_script(paths: &[String]) -> String {
    let mut s = String::from("#!/usr/bin/env bash\nset -uo pipefail\n");
    for p in paths {
        let esc = shell_escape(p);
        let b64_path = B64.encode(p.as_bytes());
        s.push_str(&format!(
            "if [ -f {esc} ]; then\n\
             \x20 printf '{marker} %s present %s %s\\n' {b64_path} \"$(stat -c '%a %U:%G' {esc} | base64 | tr -d '\\n' || printf -)\" \"$(base64 {esc} | tr -d '\\n')\"\n\
             else\n\
             \x20 printf '{marker} %s absent -\\n' {b64_path}\n\
             fi\n",
            esc = esc,
            b64_path = shell_escape(&b64_path),
            marker = DIFF_MARKER,
        ));
    }
    s
}

/// Parse the output of [`read_files_script`] into `(path, RemoteFile, stat)`
/// triples, preserving order and silently skipping any malformed line. An
/// undecodable stat field yields `None` (mode/owner then go unreported).
pub fn parse_remote_files(stdout: &str) -> Vec<(String, RemoteFile, Option<RemoteStat>)> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let Some(rest) = line.trim().strip_prefix(DIFF_MARKER) else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let (Some(b64_path), Some(status)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Some(path) = decode_utf8(b64_path) else {
            continue;
        };
        let (file, stat) = if status == "present" {
            let stat = parts.next().and_then(decode_utf8).and_then(|s| {
                let (mode, owner) = s.trim_end().split_once(' ')?;
                Some(RemoteStat {
                    mode: mode.to_string(),
                    owner: owner.to_string(),
                })
            });
            // A missing content field is an empty file; undecodable base64 is
            // a malformed line, and valid base64 that isn't UTF-8 is binary.
            let file = match parts.next().map(|b| B64.decode(b)) {
                None => RemoteFile::Present(String::new()),
                Some(Err(_)) => continue,
                Some(Ok(bytes)) => match String::from_utf8(bytes) {
                    Ok(c) => RemoteFile::Present(c),
                    Err(_) => RemoteFile::Binary,
                },
            };
            (file, stat)
        } else {
            (RemoteFile::Absent, None)
        };
        out.push((path, file, stat));
    }
    out
}

fn decode_utf8(b64: &str) -> Option<String> {
    B64.decode(b64).ok().and_then(|v| String::from_utf8(v).ok())
}

/// A single unified-diff operation over one line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Context(String),
    Del(String),
    Add(String),
}

/// Longest-common-subsequence line alignment. Files here are small drop-ins, so
/// the O(n·m) table is more than fast enough and keeps the diff exact.
fn align(a: &[&str], b: &[&str]) -> Vec<Op> {
    let (n, m) = (a.len(), b.len());
    // lcs[i][j] = length of LCS of a[i..] and b[j..].
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut ops = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            ops.push(Op::Context(a[i].to_string()));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            ops.push(Op::Del(a[i].to_string()));
            i += 1;
        } else {
            ops.push(Op::Add(b[j].to_string()));
            j += 1;
        }
    }
    while i < n {
        ops.push(Op::Del(a[i].to_string()));
        i += 1;
    }
    while j < m {
        ops.push(Op::Add(b[j].to_string()));
        j += 1;
    }
    ops
}

/// Render a unified diff of `current` (as seen on the host) versus the declared
/// `desired` content for `path`. Returns an empty string when they already
/// match, so callers can treat "" as "no change".
pub fn unified_diff(path: &str, current: &RemoteFile, desired: &str) -> String {
    let (cur, cur_label) = match current {
        RemoteFile::Present(c) if c == desired => return String::new(),
        RemoteFile::Present(c) => (c.as_str(), "current"),
        RemoteFile::Binary => ("", "current"),
        RemoteFile::Absent => ("", "absent"),
    };
    let mut out = String::new();
    out.push_str(&format!("--- a/{path} ({cur_label})\n"));
    out.push_str(&format!("+++ b/{path} (desired)\n"));
    if *current == RemoteFile::Binary {
        out.push_str("binary content differs (current is not valid UTF-8)\n");
        return out;
    }
    let a: Vec<&str> = split_lines(cur);
    let b: Vec<&str> = split_lines(desired);
    let ops = align(&a, &b);
    // `lines()` drops a trailing `\n` and a `\r` before it, so bytes that
    // differ only there align as all-context: say so instead of "up to date".
    // shortcut: such a difference alongside real line edits is not marked;
    // diff over `split_inclusive('\n')` if that ever matters.
    if !ops.iter().any(|o| matches!(o, Op::Add(_) | Op::Del(_))) {
        out.push_str("line endings or trailing newline differ\n");
        return out;
    }
    // A zero-length side starts at line 0 (unified-diff convention).
    let start = |len: usize| usize::from(len > 0);
    out.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        start(a.len()),
        a.len(),
        start(b.len()),
        b.len()
    ));
    for op in ops {
        match op {
            Op::Context(l) => out.push_str(&format!(" {l}\n")),
            Op::Del(l) => out.push_str(&format!("-{l}\n")),
            Op::Add(l) => out.push_str(&format!("+{l}\n")),
        }
    }
    out
}

/// Split into lines without inventing a trailing empty line for `""`.
fn split_lines(s: &str) -> Vec<&str> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.lines().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_diff_is_exact_for_mixed_edits() {
        // Pins the LCS alignment byte-for-byte: replace one line, replace the
        // trailing line. Any drift in the align() table arithmetic reorders
        // or duplicates ops and fails here.
        let current = RemoteFile::Present("a\nb\nc\nd\n".into());
        let d = unified_diff("/etc/f", &current, "a\nx\nc\ne\n");
        assert_eq!(
            d,
            "--- a//etc/f (current)\n\
             +++ b//etc/f (desired)\n\
             @@ -1,4 +1,4 @@\n\
             \x20a\n\
             -b\n\
             +x\n\
             \x20c\n\
             -d\n\
             +e\n"
        );
    }

    #[test]
    fn unified_diff_of_absent_file_is_a_pure_create() {
        let d = unified_diff("/etc/new", &RemoteFile::Absent, "one\ntwo\n");
        assert_eq!(
            d,
            "--- a//etc/new (absent)\n\
             +++ b//etc/new (desired)\n\
             @@ -0,0 +1,2 @@\n\
             +one\n\
             +two\n"
        );
    }

    #[test]
    fn unified_diff_of_emptied_file_starts_new_side_at_zero() {
        let d = unified_diff("/etc/f", &RemoteFile::Present("x\n".into()), "");
        assert_eq!(
            d,
            "--- a//etc/f (current)\n\
             +++ b//etc/f (desired)\n\
             @@ -1,1 +0,0 @@\n\
             -x\n"
        );
    }

    #[test]
    fn trailing_newline_and_crlf_differences_are_not_up_to_date() {
        for (cur, desired) in [("x", "x\n"), ("x\r\n", "x\n")] {
            let current = RemoteFile::Present(cur.into());
            let d = unified_diff("/etc/f", &current, desired);
            assert!(
                d.ends_with("line endings or trailing newline differ\n"),
                "{cur:?} vs {desired:?}: {d:?}"
            );
            let (change, _) = file_diff("/etc/f", &current, None, desired, "0644", "root:root");
            assert_eq!(change, FileChange::Modify);
        }
    }

    fn stat(mode: &str, owner: &str) -> RemoteStat {
        RemoteStat {
            mode: mode.into(),
            owner: owner.into(),
        }
    }

    #[test]
    fn mode_and_owner_only_drift_is_a_modify_with_change_lines() {
        let cur = RemoteFile::Present("same\n".into());
        let st = stat("600", "bob:bob");
        let (change, d) = file_diff("/etc/f", &cur, Some(&st), "same\n", "0644", "root:root");
        assert_eq!(change, FileChange::Modify);
        assert_eq!(d, "mode: 600 -> 644\nowner: bob:bob -> root:root\n");

        let wheel = stat("644", "root:wheel");
        let (change, d) = file_diff("/etc/f", &cur, Some(&wheel), "same\n", "0644", "root:root");
        assert_eq!(change, FileChange::Modify);
        assert_eq!(d, "owner: root:wheel -> root:root\n");
    }

    #[test]
    fn mode_and_owner_match_the_way_the_probe_normalizes() {
        let cur = RemoteFile::Present("same\n".into());
        // "0644" is what stat prints as "644"; "0000" as "0"; "deploy:" pins
        // only the user (login-group shorthand), like engine::owner_check.
        for (st, mode, owner) in [
            (stat("644", "root:root"), "0644", "root:root"),
            (stat("0", "root:root"), "0000", "root:root"),
            (stat("640", "deploy:users"), "0640", "deploy:"),
        ] {
            let (change, d) = file_diff("/etc/f", &cur, Some(&st), "same\n", mode, owner);
            assert_eq!((change, d.as_str()), (FileChange::None, ""), "{st:?}");
        }
    }

    #[test]
    fn binary_remote_content_renders_distinctly() {
        let path = "/etc/bin";
        let line = format!(
            "{DIFF_MARKER} {} present {} {}",
            B64.encode(path),
            B64.encode("644 root:root"),
            B64.encode([0xffu8, 0xfe, 0x00])
        );
        let parsed = parse_remote_files(&line);
        assert_eq!(parsed[0].1, RemoteFile::Binary);
        let d = unified_diff(path, &RemoteFile::Binary, "text\n");
        assert!(d.contains("binary content differs"), "{d}");
        assert!(!d.contains("+text"), "no fake pure-addition diff: {d}");
        assert_eq!(
            FileChange::classify(&RemoteFile::Binary, "text\n"),
            FileChange::Modify
        );
    }

    #[test]
    fn unified_diff_handles_repeated_lines_exactly() {
        // Repeated lines make the LCS table earn its keep: any drift in the
        // table arithmetic or tie-break picks a different (longer) alignment
        // than the single leading deletion + single trailing addition.
        let current = RemoteFile::Present("a\nb\na\nb\na\n".into());
        let d = unified_diff("/etc/f", &current, "b\na\nb\na\nb\n");
        assert_eq!(
            d,
            "--- a//etc/f (current)\n\
             +++ b//etc/f (desired)\n\
             @@ -1,5 +1,5 @@\n\
             -a\n\
             \x20b\n\
             \x20a\n\
             \x20b\n\
             \x20a\n\
             +b\n"
        );
    }

    #[test]
    fn unified_diff_shrinking_a_file_emits_trailing_deletions() {
        // Desired shorter than current: the alignment ends in the
        // leftover-deletion tail, which no other test reaches.
        let current = RemoteFile::Present("keep\nold1\nold2\n".into());
        let d = unified_diff("/etc/f", &current, "keep\n");
        assert_eq!(
            d,
            "--- a//etc/f (current)\n\
             +++ b//etc/f (desired)\n\
             @@ -1,3 +1,1 @@\n\
             \x20keep\n\
             -old1\n\
             -old2\n"
        );
    }

    #[test]
    fn identical_content_yields_an_empty_diff() {
        let current = RemoteFile::Present("same\n".into());
        assert_eq!(unified_diff("/etc/f", &current, "same\n"), "");
    }

    #[test]
    fn file_change_classification_and_machine_strings() {
        assert_eq!(
            FileChange::classify(&RemoteFile::Absent, "x"),
            FileChange::Create
        );
        assert_eq!(
            FileChange::classify(&RemoteFile::Present("x".into()), "x"),
            FileChange::None
        );
        assert_eq!(
            FileChange::classify(&RemoteFile::Present("y".into()), "x"),
            FileChange::Modify
        );
        assert_eq!(FileChange::Create.as_str(), "create");
        assert_eq!(FileChange::Modify.as_str(), "modify");
        assert_eq!(FileChange::None.as_str(), "none");
    }

    #[test]
    fn read_script_frames_each_path_and_escapes() {
        let s = read_files_script(&["/etc/ssh/sshd_config.d/99-anvil.conf".into()]);
        assert!(s.contains("set -uo pipefail"));
        assert!(s.contains(DIFF_MARKER));
        // The literal path is single-quoted (shell-escaped) at every use site.
        assert!(s.contains("'/etc/ssh/sshd_config.d/99-anvil.conf'"));
        assert!(s.contains("base64"));
        assert!(s.contains("stat -c '%a %U:%G' '/etc/ssh/sshd_config.d/99-anvil.conf'"));
    }

    #[test]
    fn read_script_escapes_adversarial_paths() {
        let s = read_files_script(&["/etc/x'; rm -rf / #".into()]);
        // The dangerous payload only appears inside single-quoting.
        assert!(!s.contains("rm -rf / #\n"));
        assert!(s.contains("'/etc/x'\\''; rm -rf / #'"));
    }

    #[test]
    fn parse_round_trips_present_and_absent() {
        let path = "/etc/demo.conf";
        let content = "line one\nline two\n";
        let line_present = format!(
            "{DIFF_MARKER} {} present {} {}",
            B64.encode(path),
            B64.encode("644 root:root\n"),
            B64.encode(content)
        );
        let line_absent = format!("{DIFF_MARKER} {} absent -", B64.encode(path));

        let p = parse_remote_files(&line_present);
        assert_eq!(
            p,
            vec![(
                path.to_string(),
                RemoteFile::Present(content.into()),
                Some(stat("644", "root:root"))
            )]
        );

        let a = parse_remote_files(&line_absent);
        assert_eq!(a, vec![(path.to_string(), RemoteFile::Absent, None)]);
    }

    #[test]
    fn parse_skips_garbage_and_reads_empty_present() {
        let path = "/etc/empty.conf";
        // Present but empty: no content field, content decodes to "". An
        // unreadable stat (`-`) is tolerated and leaves mode/owner unknown.
        let line = format!("{DIFF_MARKER} {} present - ", B64.encode(path));
        let out = parse_remote_files(&format!("noise\n{line}\nmore noise"));
        assert_eq!(
            out,
            vec![(path.to_string(), RemoteFile::Present(String::new()), None)]
        );
    }

    #[test]
    fn identical_content_has_no_diff() {
        let desired = "a\nb\nc\n";
        let cur = RemoteFile::Present(desired.into());
        assert_eq!(unified_diff("/x", &cur, desired), "");
        assert_eq!(FileChange::classify(&cur, desired), FileChange::None);
    }

    #[test]
    fn absent_file_is_a_full_creation() {
        let desired = "one\ntwo\n";
        let cur = RemoteFile::Absent;
        let d = unified_diff("/etc/x", &cur, desired);
        assert!(d.contains("--- a//etc/x (absent)"));
        assert!(d.contains("+++ b//etc/x (desired)"));
        assert!(d.contains("+one"));
        assert!(d.contains("+two"));
        assert!(!d.contains("-one"));
        assert_eq!(FileChange::classify(&cur, desired), FileChange::Create);
    }

    #[test]
    fn modified_file_shows_adds_dels_and_context() {
        let cur = RemoteFile::Present("keep\nold\nshared\n".into());
        let desired = "keep\nnew\nshared\n";
        let d = unified_diff("/etc/x", &cur, desired);
        assert!(d.contains(" keep"), "context retained: {d}");
        assert!(d.contains("-old"));
        assert!(d.contains("+new"));
        assert!(d.contains(" shared"));
        assert_eq!(FileChange::classify(&cur, desired), FileChange::Modify);
    }
}
