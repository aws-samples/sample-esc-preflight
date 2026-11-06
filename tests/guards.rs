//! Source-level guards for a model-free scan path and the
//! outbound-host allowlist. They read `src/` as text, so a new host or an LLM
//! client cannot be added without this test being changed on purpose.

use std::fs;
use std::path::Path;

/// Hosts the binary may contact outside the AWS SDK (live mode).
const ALLOWED_HOSTS: &[&str] = &[
    "pypi.org",
    "raw.githubusercontent.com",
    "api.regional-table.region-services.aws.a2z.com",
    "docs.aws.eu",
    "registry.terraform.io",
];

/// Hosts of documentation links written into the report, never fetched.
const LINK_ONLY_HOSTS: &[&str] = &["docs.aws.amazon.com"];

/// Hosts that appear only inside `#[cfg(test)]` fixtures and test inputs.
const TEST_ONLY_HOSTS: &[&str] = &[
    "example.com",
    "pypi.org.evil.test",
    "sqs.eu-central-1.amazonaws.com",
];

fn sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push((p.display().to_string(), fs::read_to_string(&p).unwrap()));
            }
        }
    }
    out
}

fn hosts(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for scheme in ["https://", "http://"] {
        for (i, _) in text.match_indices(scheme) {
            let rest = &text[i + scheme.len()..];
            let host: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            if !host.is_empty() {
                found.push(host);
            }
        }
    }
    found
}

#[test]
fn only_allowlisted_hosts_are_contacted() {
    for (file, text) in sources() {
        for h in hosts(&text) {
            assert!(
                ALLOWED_HOSTS.contains(&h.as_str())
                    || LINK_ONLY_HOSTS.contains(&h.as_str())
                    || TEST_ONLY_HOSTS.contains(&h.as_str()),
                "{file}: host `{h}` is not on the allowlist"
            );
        }
    }
}

#[test]
fn no_model_endpoints_or_llm_clients() {
    let banned = [
        "bedrock-runtime",
        "bedrockruntime",
        "aws_sdk_bedrock",
        "InvokeModel",
        "openai",
        "anthropic",
    ];
    for (file, text) in sources() {
        for b in banned {
            assert!(
                !text.to_ascii_lowercase().contains(&b.to_ascii_lowercase()),
                "{file}: contains `{b}`; the scan path must stay model-free"
            );
        }
    }
    let manifest =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    assert!(
        !manifest.contains("aws-sdk-bedrock"),
        "Cargo.toml must not depend on a Bedrock client"
    );
}
