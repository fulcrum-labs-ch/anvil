//! Workflow guard: the gate enforces G-01…G-03 — no
//! `pull_request_target`, no `workflow_run`, and on any PR-capable trigger no
//! job may reach a non-GitHub-hosted runner unless it is exactly fork-routed
//! or carries a job-level fork exclusion. G-04…G-06 are the acceptances below.
//!
//! For `merge_group` and `workflow_call`, `github.event.pull_request` is null,
//! so fork routing and the exclusion both send those jobs to the routed
//! target; merge queues admit only approved PRs.
//!
//! The real gates are the runner group and fork-PR approval; this test keeps a
//! workflow change from opening a path by accident.

use std::fs;
use std::path::Path;

const PR_CAPABLE: [&str; 5] = [
    "pull_request",
    "pull_request_review",
    "pull_request_review_comment",
    "merge_group",
    "workflow_call",
];

/// Every violation of G-01…G-03 in one workflow file. Empty means clean.
// shortcut: line-based scan, not a YAML parser; covers the forms our workflows use. Upgrade if a workflow needs anchors or multi-document YAML.
fn check_workflow(yaml: &str) -> Vec<String> {
    let lines: Vec<&str> = yaml.lines().map(strip_comment).collect();
    let triggers = parse_triggers(&lines);
    let mut violations = Vec::new();

    if triggers.iter().any(|t| t == "pull_request_target") {
        violations.push(
            "G-01: `pull_request_target` can run fork code with base-repo privileges".to_string(),
        );
    }
    if triggers.iter().any(|t| t == "workflow_run") {
        violations.push(
            "G-02: `workflow_run` can run with base-repo privileges after a fork's run".to_string(),
        );
    }
    if triggers.iter().any(|t| PR_CAPABLE.contains(&t.as_str())) {
        for job in parse_jobs(&lines) {
            if let Some(violation) = job.unrouted_self_hosted() {
                violations.push(violation);
            }
        }
    }
    violations
}

/// Drop a trailing `# ...` comment; a full-line comment becomes empty.
fn strip_comment(line: &str) -> &str {
    let mut prev_space = true;
    for (i, c) in line.char_indices() {
        if c == '#' && prev_space {
            return line[..i].trim_end();
        }
        prev_space = c.is_whitespace();
    }
    line.trim_end()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Trigger names from the top-level `on:` key: scalar, flow list, flow map,
/// block map or block list.
fn parse_triggers(lines: &[&str]) -> Vec<String> {
    let mut triggers = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if indent_of(line) != 0 {
            continue;
        }
        let Some((key, rest)) = split_key(line) else {
            continue;
        };
        if key != "on" {
            continue;
        }
        if rest.is_empty() {
            let mut item_indent = None;
            for next in &lines[i + 1..] {
                if next.trim().is_empty() {
                    continue;
                }
                if indent_of(next) == 0 {
                    break;
                }
                let indent = *item_indent.get_or_insert(indent_of(next));
                if indent == indent_of(next) {
                    triggers.extend(trigger_name(next.trim()));
                }
            }
        } else {
            let flow = rest.trim_matches(|c: char| c.is_whitespace() || "{}[],".contains(c));
            for part in flow.split(',') {
                triggers.extend(trigger_name(part));
            }
        }
        break;
    }
    triggers
}

/// Split `key: value`, dropping quotes around a key like `"on"`.
fn split_key(line: &str) -> Option<(&str, &str)> {
    let (key, rest) = line.trim_start().split_once(':')?;
    let key = key.trim().trim_matches(|c| c == '\'' || c == '"');
    Some((key, rest.trim()))
}

fn trigger_name(text: &str) -> Option<String> {
    let name = text
        .trim_start_matches("- ")
        .split(':')
        .next()?
        .trim()
        .trim_matches(|c| c == '\'' || c == '"');
    (!name.is_empty()).then(|| name.to_string())
}

struct Job<'a> {
    name: String,
    /// `(indent, text)` for every line under the job key.
    props: Vec<(usize, &'a str)>,
}

/// Job keys at the first indentation level under the top-level `jobs:`.
fn parse_jobs<'a>(lines: &[&'a str]) -> Vec<Job<'a>> {
    let mut jobs: Vec<Job<'a>> = Vec::new();
    let mut in_jobs = false;
    let mut job_indent = None;
    for line in lines {
        let text = line.trim_start();
        if text.is_empty() {
            continue;
        }
        let indent = indent_of(line);
        if !in_jobs {
            in_jobs = indent == 0 && split_key(line).is_some_and(|(key, _)| key == "jobs");
            continue;
        }
        if indent == 0 {
            break;
        }
        if indent == *job_indent.get_or_insert(indent) {
            if let Some((name, _)) = split_key(text) {
                jobs.push(Job {
                    name: name.to_string(),
                    props: Vec::new(),
                });
            }
        } else if let Some(job) = jobs.last_mut() {
            job.props.push((indent, text));
        }
    }
    jobs
}

impl Job<'_> {
    /// G-03: allow-list — only a GitHub-hosted target, exact fork routing, or
    /// a job-level fork exclusion is safe under a PR-capable trigger.
    fn unrouted_self_hosted(&self) -> Option<String> {
        // Job properties share one indentation; anything deeper (e.g. `env:`
        // children) is not the job's own `runs-on`.
        let prop_indent = self.props.first()?.0;
        let (pos, rest) = self
            .props
            .iter()
            .enumerate()
            .find_map(|(i, (indent, text))| {
                if *indent != prop_indent {
                    return None;
                }
                split_key(text).and_then(|(key, rest)| (key == "runs-on").then_some((i, rest)))
            })?;

        // Every line under `runs-on:` so block maps, block lists and folded
        // scalars are judged (and reported) whole.
        let mut target_lines = vec![rest];
        for (indent, text) in &self.props[pos + 1..] {
            if *indent <= prop_indent {
                break;
            }
            target_lines.push(text.trim());
        }
        let target = target_lines.join(" ").trim().to_string();

        if github_hosted(&target) || fork_routed(&target) {
            return None;
        }
        // shortcut: substring match on the job `if:`; an adversarial condition
        // (`!fork` inside a string literal, `== false`) still passes. Upgrade
        // to an expression parser if that ever matters.
        let excluded = self.props.iter().any(|(indent, text)| {
            *indent == prop_indent
                && split_key(text).is_some_and(|(key, cond)| {
                    key == "if"
                        && cond.contains("!github.event.pull_request.head.repo.fork")
                        && !cond.contains("||")
                })
        });
        if excluded {
            return None;
        }

        Some(format!(
            "G-03 job '{}': runs-on {target:?} is not a GitHub-hosted label and is neither \
             exactly fork-routed nor fork-excluded",
            self.name
        ))
    }
}

/// GitHub-hosted runner labels. A new hosted image needs adding here.
const GITHUB_HOSTED: [&str; 12] = [
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "ubuntu-24.04-arm",
    "ubuntu-22.04-arm",
    "windows-latest",
    "windows-2025",
    "windows-2022",
    "macos-latest",
    "macos-15",
    "macos-14",
    "macos-13",
];

/// A whole-value GitHub-hosted runner label, optionally quoted.
fn github_hosted(value: &str) -> bool {
    let label = value.trim().trim_matches(|c| c == '\'' || c == '"');
    GITHUB_HOSTED.contains(&label)
}

/// The `ci.yml` form, exactly: the expression starts with the un-negated fork
/// check and the true branch is a GitHub-hosted label.
fn fork_routed(target: &str) -> bool {
    let Some(rest) = target.trim().strip_prefix("${{") else {
        return false;
    };
    let Some(rest) = rest
        .trim_start()
        .strip_prefix("github.event.pull_request.head.repo.fork &&")
    else {
        return false;
    };
    let Some((label, _)) = rest.trim_start().split_once("||") else {
        return false;
    };
    github_hosted(label)
}

#[test]
fn rejects_pull_request_target() {
    let block = r#"on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
"#;
    let flow = r#"on: [push, pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
"#;
    let quoted_key = r#""on": pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
"#;
    let flow_map = r#"on: { pull_request_target: {} }
jobs:
  build:
    runs-on: ubuntu-latest
"#;
    for yaml in [block, flow, quoted_key, flow_map] {
        let violations = check_workflow(yaml);
        assert_eq!(violations.len(), 1, "{yaml:?} -> {violations:?}");
        assert!(
            violations[0].starts_with("G-01"),
            "{yaml:?} -> {violations:?}"
        );
    }
}

#[test]
fn rejects_workflow_run_trigger() {
    let block = r#"on:
  workflow_run:
    workflows: [ci]
jobs:
  deploy:
    runs-on: ubuntu-latest
"#;
    let quoted_key = r#"'on': workflow_run
jobs:
  deploy:
    runs-on: ubuntu-latest
"#;
    for yaml in [block, quoted_key] {
        let violations = check_workflow(yaml);
        assert_eq!(violations.len(), 1, "{yaml:?} -> {violations:?}");
        assert!(
            violations[0].starts_with("G-02"),
            "{yaml:?} -> {violations:?}"
        );
    }
}

#[test]
fn rejects_unrouted_self_hosted_job() {
    let yaml = r#"on: [push, pull_request]
jobs:
  a:
    runs-on: [self-hosted, netcup]
    steps:
      - run: echo a
  b:
    runs-on:
      - self-hosted
      - netcup
    steps:
      - run: echo b
  c:
    runs-on: ${{ matrix.runner }}
    steps:
      - run: echo c
  d:
    runs-on: ubuntu-latest
    steps:
      - run: echo d
"#;
    let violations = check_workflow(yaml);
    assert_eq!(violations.len(), 3, "{violations:?}");
    assert!(
        violations.iter().all(|v| v.starts_with("G-03")),
        "{violations:?}"
    );
    let named: Vec<&str> = violations
        .iter()
        .filter_map(|v| v.split('\'').nth(1))
        .collect();
    assert_eq!(named, vec!["a", "b", "c"], "{violations:?}");
}

#[test]
fn accepts_fork_routed_runs_on() {
    // Exactly the routing expression ci.yml uses.
    let yaml = r#"on: pull_request
jobs:
  ci:
    runs-on: ${{ github.event.pull_request.head.repo.fork && 'ubuntu-latest' || fromJSON('["self-hosted","netcup"]') }}
    steps:
      - run: echo ci
"#;
    let violations = check_workflow(yaml);
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn accepts_self_hosted_job_with_fork_exclusion() {
    let pr = r#"on: pull_request
jobs:
  mutants:
    runs-on: [self-hosted, netcup]
    if: github.event_name == 'pull_request' && !github.event.pull_request.head.repo.fork
    steps:
      - run: echo mutants
"#;
    let violations = check_workflow(pr);
    assert!(violations.is_empty(), "{violations:?}");

    // A push-only workflow cannot receive fork code at all.
    let push = pr.replace("on: pull_request", "on: push");
    let violations = check_workflow(&push);
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn ignores_trigger_names_in_comments() {
    let yaml = r#"# pull_request_target and workflow_run are never used
on: [push]  # pull_request_target
jobs:
  build:
    runs-on: [self-hosted, netcup]
"#;
    let violations = check_workflow(yaml);
    assert!(violations.is_empty(), "{violations:?}");
}

#[test]
fn step_level_fork_exclusion_does_not_exempt_the_job() {
    // The exclusion must be a job-level `if:`; on a step it still queues fork
    // code on the self-hosted runner.
    let yaml = r#"on: pull_request
jobs:
  build:
    runs-on: [self-hosted, netcup]
    steps:
      - if: "!github.event.pull_request.head.repo.fork"
        run: echo build
"#;
    let violations = check_workflow(yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

/// A `pull_request` workflow with one job whose properties are `props`.
fn pr_job(props: &str) -> String {
    format!("on: pull_request\njobs:\n  build:\n{props}")
}

#[test]
fn rejects_negated_fork_routing() {
    // The fork check must be the expression head, not hidden behind `!`.
    let yaml = pr_job(
        r#"    runs-on: ${{ !github.event.pull_request.head.repo.fork && 'ubuntu-latest' || fromJSON('["self-hosted","netcup"]') }}
"#,
    );
    let violations = check_workflow(&yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn rejects_non_hosted_runs_on_forms() {
    // Only a whole-value GitHub-hosted label, exact fork routing, or a job
    // exclusion may pass; every other target is unknown enough to be unsafe.
    let cases = [
        r#"    runs-on: netcup
"#,
        r#"    runs-on: ${{ github.event.pull_request.head.repo.fork && 'netcup' || 'ubuntu-latest' }}
"#,
        r#"    runs-on: { group: anvil-ci }
"#,
        r#"    runs-on:
      group: anvil-ci
"#,
        r#"    runs-on:
      labels: [self-hosted, netcup]
"#,
    ];
    for props in cases {
        let yaml = pr_job(props);
        let violations = check_workflow(&yaml);
        assert_eq!(violations.len(), 1, "{props:?} -> {violations:?}");
        assert!(
            violations[0].starts_with("G-03"),
            "{props:?} -> {violations:?}"
        );
    }
}

#[test]
fn rejects_runs_on_outside_job_properties() {
    // A nested `runs-on` (here under `env:`) must not shadow the job's own.
    let yaml = pr_job("    env:\n      runs-on: ubuntu-latest\n    runs-on: [self-hosted]\n");
    let violations = check_workflow(&yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn rejects_quoted_jobs_key() {
    let yaml = "on: pull_request\n\"jobs\":\n  j:\n    runs-on: [self-hosted]\n";
    let violations = check_workflow(yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");

    // A quoted `runs-on` key is the same job property.
    let quoted_runs_on = "on: pull_request\njobs:\n  build:\n    \"runs-on\": [self-hosted]\n";
    let violations = check_workflow(quoted_runs_on);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn rejects_lookalike_hosted_labels() {
    // Only the exact hosted labels count; a self-hosted runner can carry a
    // label that merely starts with a hosted prefix.
    let cases = [
        r#"    runs-on: ubuntu-netcup
"#,
        r#"    runs-on: ubuntu-${{matrix.x}}
"#,
        r#"    runs-on: ${{ github.event.pull_request.head.repo.fork && 'ubuntu-netcup' || 'self-hosted' }}
"#,
    ];
    for props in cases {
        let yaml = pr_job(props);
        let violations = check_workflow(&yaml);
        assert_eq!(violations.len(), 1, "{props:?} -> {violations:?}");
        assert!(
            violations[0].starts_with("G-03"),
            "{props:?} -> {violations:?}"
        );
    }
}

#[test]
fn rejects_folded_runs_on() {
    let yaml = pr_job("    runs-on: >-\n      ${{ matrix.r }}\n");
    let violations = check_workflow(&yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn rejects_quoted_on_key() {
    // `"on"` is still the trigger key; a self-hosted job under it must fail.
    let yaml = "\"on\": pull_request\njobs:\n  build:\n    runs-on: [self-hosted, netcup]\n";
    let violations = check_workflow(yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn rejects_pr_capable_triggers() {
    // A reusable workflow called from a PR run and a review event can both
    // receive fork code, like `pull_request`.
    for trigger in [
        "workflow_call",
        "pull_request_review",
        "pull_request_review_comment",
        "merge_group",
    ] {
        let yaml = format!("on: {trigger}\njobs:\n  build:\n    runs-on: [self-hosted, netcup]\n");
        let violations = check_workflow(&yaml);
        assert_eq!(violations.len(), 1, "{trigger}: {violations:?}");
        assert!(
            violations[0].starts_with("G-03"),
            "{trigger}: {violations:?}"
        );
    }
}

#[test]
fn rejects_or_in_fork_exclusion() {
    // `always() || !fork` does not exclude forks.
    let yaml = pr_job(
        "    runs-on: [self-hosted, netcup]\n    if: always() || !github.event.pull_request.head.repo.fork\n",
    );
    let violations = check_workflow(&yaml);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn strips_trailing_comments_before_matching() {
    // A comment must not fake a fork exclusion...
    let fake_exclusion = pr_job(
        "    runs-on: [self-hosted, netcup]\n    if: github.event_name == 'pull_request'  # !github.event.pull_request.head.repo.fork\n",
    );
    let violations = check_workflow(&fake_exclusion);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");

    // ...nor hide the real trigger that precedes it.
    let commented_on = "on: [push, pull_request]  # workflow_run is unused\njobs:\n  build:\n    runs-on: [self-hosted, netcup]\n";
    let violations = check_workflow(commented_on);
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].starts_with("G-03"), "{violations:?}");
}

#[test]
fn repo_workflows_pass_the_guard() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|e| e.to_str()),
                Some("yml" | "yaml")
            )
        })
        .collect();
    files.sort();
    assert!(files.len() >= 2, "read only {} workflow files", files.len());

    for path in files {
        let yaml =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let violations = check_workflow(&yaml);
        assert!(violations.is_empty(), "{}: {violations:?}", path.display());
    }
}
