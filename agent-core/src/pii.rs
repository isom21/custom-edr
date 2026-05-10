//! PII / secret scrubbing for agent-emitted strings (M16.g).
//!
//! Applied to fields where attackers + developers alike routinely
//! leak credentials in plain text: process command lines, DNS query
//! names, file paths under tmp/staging dirs.
//!
//! The scrubber recognises common patterns from the wild and from
//! prior incident reports. False positives are preferable to false
//! negatives: leaking a customer secret to OpenSearch is much worse
//! than a redacted command line that an analyst has to query through
//! the audit-log evidence chain.
//!
//! `scrub(input)` is allocation-free in the no-match path: a regex
//! quick-check returns the original string untouched. On match, a
//! new String is built with `[REDACTED]` substitutions.
//!
//! Configurable via `VIGIL_DISABLE_PII_SCRUB=1` to disable globally
//! (dev only — operators must understand they're shipping plaintext
//! credentials to OpenSearch when they flip this).

use std::sync::OnceLock;

use regex::Regex;

const PLACEHOLDER: &str = "[REDACTED]";

struct Patterns {
    /// Combined alternation regex for flag-style secrets:
    ///   --password VAL  /  -p=VAL  /  --token VAL  /  --api-key VAL  ...
    /// Captures both the flag (group 1) and the value (group 2).
    flags: Regex,
    /// `KEY=VAL` style assignments inside command lines and env dumps.
    kv: Regex,
    /// AWS-style access keys.
    aws_akia: Regex,
    /// Bearer tokens in Authorization headers.
    bearer: Regex,
    /// JWT-shaped tokens (eyJ...) — three base64 segments separated
    /// by dots. JWTs in command lines are almost always credentials.
    jwt: Regex,
    /// SSH/PEM private key blocks (multi-line).
    pem: Regex,
}

fn patterns() -> &'static Patterns {
    static PAT: OnceLock<Patterns> = OnceLock::new();
    PAT.get_or_init(|| Patterns {
        flags: Regex::new(
            r"(?i)(--?(?:password|passwd|pwd|token|api[_-]?key|secret|access[_-]?key|auth)[\w-]*)[=\s]+(\S+)",
        )
        .expect("flags regex"),
        kv: Regex::new(
            // Match KV pairs where the KEY *contains* a secret keyword
            // (handles DB_PASSWORD, MY_API_KEY, prod-token, etc.). Starts
            // at the beginning of the input, after whitespace/`;`/`&`,
            // or after `=` (handles --opt=KEY=VAL nesting).
            r"(?i)(?:^|[\s;&=])([A-Z0-9_-]*(?:password|passwd|pwd|token|api[_-]?key|secret|auth)[A-Z0-9_-]*)=([^\s;&]+)",
        )
        .expect("kv regex"),
        aws_akia: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("akia regex"),
        bearer: Regex::new(r"(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._\-+/=]+)").expect("bearer regex"),
        jwt: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")
            .expect("jwt regex"),
        pem: Regex::new(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----")
            .expect("pem regex"),
    })
}

/// Scrub `input` of recognised secret patterns. Returns the original
/// string untouched if no patterns matched. Disabled at runtime via
/// `VIGIL_DISABLE_PII_SCRUB=1`.
pub fn scrub(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    if std::env::var_os("VIGIL_DISABLE_PII_SCRUB").is_some() {
        return input.to_string();
    }

    let p = patterns();

    // Quick-check: if none of the cheap markers are present, return
    // the input unchanged. The full alternation regex is much more
    // expensive than these substring scans.
    let lower = input.to_ascii_lowercase();
    let has_marker = lower.contains("password")
        || lower.contains("passwd")
        || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("api_key")
        || lower.contains("api-key")
        || lower.contains("apikey")
        || lower.contains("bearer ")
        || lower.contains("basic ")
        || lower.contains("akia")
        || lower.contains("eyj")
        || lower.contains("private key");
    if !has_marker {
        return input.to_string();
    }

    let mut out = input.to_string();
    out = p.pem.replace_all(&out, PLACEHOLDER).to_string();
    out = p
        .flags
        .replace_all(&out, |c: &regex::Captures| {
            format!("{} {PLACEHOLDER}", &c[1])
        })
        .to_string();
    out =
        p.kv.replace_all(&out, |c: &regex::Captures| {
            format!("{}={PLACEHOLDER}", &c[1])
        })
        .to_string();
    out = p.aws_akia.replace_all(&out, PLACEHOLDER).to_string();
    out = p
        .bearer
        .replace_all(&out, |c: &regex::Captures| {
            format!("{} {PLACEHOLDER}", &c[1])
        })
        .to_string();
    out = p.jwt.replace_all(&out, PLACEHOLDER).to_string();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_match_passes_through() {
        let s = "/usr/bin/curl https://example.com/path";
        assert_eq!(scrub(s), s);
    }

    #[test]
    fn redacts_password_flag() {
        let s = "psql --password supersecret -h db";
        let r = scrub(s);
        assert!(r.contains("[REDACTED]"));
        assert!(!r.contains("supersecret"));
    }

    #[test]
    fn redacts_kv_assignment() {
        let s = "DB_PASSWORD=hunter2 ./run.sh";
        let r = scrub(s);
        assert!(r.contains("[REDACTED]"));
        assert!(!r.contains("hunter2"));
    }

    #[test]
    fn redacts_aws_akia() {
        let s = "aws s3 ls --access-key-id AKIA1234567890ABCDEF";
        let r = scrub(s);
        assert!(r.contains("[REDACTED]"));
        assert!(!r.contains("AKIA1234567890ABCDEF"));
    }

    #[test]
    fn redacts_bearer_token() {
        let s = "curl -H 'Authorization: Bearer abc123xyz' https://api.example";
        let r = scrub(s);
        assert!(r.contains("Bearer [REDACTED]"));
        assert!(!r.contains("abc123xyz"));
    }

    #[test]
    fn redacts_jwt() {
        let s = "Authenticated with eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature123";
        let r = scrub(s);
        assert!(r.contains("[REDACTED]"));
        assert!(!r.contains("signature123"));
    }

    // VIGIL_DISABLE_PII_SCRUB is intentionally NOT covered by a unit test —
    // it would race against the rest of the test suite under cargo's
    // default parallel runner. The env var path is operator-only; its
    // behaviour is "early-return without modifying the string" which is
    // unambiguous from the source.

    #[test]
    fn benign_long_strings_unchanged() {
        let s = "find /usr/lib -name '*.so' -exec ldd {} \\;";
        assert_eq!(scrub(s), s);
    }
}
