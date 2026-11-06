//! Bundled service index: botocore service metadata and CDK's JS SDK v2 to v3 names.
//! Regenerate `data/botocore-services.json` with `scripts/gen-botocore-services.py`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Service {
    pub service_id: String,
    pub endpoint_prefix: String,
    pub signing_name: String,
    pub protocol: String,
    pub api_version: String,
    pub target_prefix: Option<String>,
    pub json_version: Option<String>,
    /// A read call that needs no input, used to test whether the service answers.
    pub probe: Option<Probe>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Probe {
    pub op: String,
    pub method: String,
    pub uri: String,
}

pub struct Index {
    by_id: BTreeMap<String, Service>,
    by_prefix: BTreeMap<String, Service>,
    v2_to_v3: BTreeMap<String, String>,
}

pub fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        #[derive(Deserialize)]
        struct File {
            services: Vec<Service>,
        }
        let f: File = serde_json::from_str(include_str!("../data/botocore-services.json"))
            .expect("bundled service table is valid");
        let mut by_id = BTreeMap::new();
        let mut by_prefix: BTreeMap<String, Service> = BTreeMap::new();
        for s in f.services {
            // Several service ids share one endpoint (RDS, Neptune, DocDB); prefer one
            // that has a probe.
            if by_prefix
                .get(&s.endpoint_prefix)
                .is_none_or(|e: &Service| e.probe.is_none() && s.probe.is_some())
            {
                by_prefix.insert(s.endpoint_prefix.clone(), s.clone());
            }
            by_id.insert(normalize(&s.service_id), s);
        }
        let v2_to_v3 = serde_json::from_str(include_str!("../data/cdk-sdk-v2-to-v3.json"))
            .expect("bundled CDK name table is valid");
        Index {
            by_id,
            by_prefix,
            v2_to_v3,
        }
    })
}

impl Index {
    /// By botocore `serviceId`, e.g. `Elastic Load Balancing v2`.
    pub fn by_service_id(&self, id: &str) -> Option<&Service> {
        self.by_id.get(&normalize(id))
    }

    pub fn by_endpoint_prefix(&self, prefix: &str) -> Option<&Service> {
        self.by_prefix.get(prefix)
    }

    /// By the service name a CDK `AwsCustomResource` call uses: a JS SDK v2 class name
    /// (`CognitoIdentityServiceProvider`) or a v3 package (`@aws-sdk/client-ssm`).
    pub fn by_sdk_name(&self, name: &str) -> Option<&Service> {
        let lower = name.to_ascii_lowercase();
        let v3 = match lower.strip_prefix("@aws-sdk/client-") {
            Some(pkg) => pkg.to_string(),
            None => self.v2_to_v3.get(&lower).cloned().unwrap_or(lower),
        };
        self.by_service_id(&v3)
    }
}

/// `Cognito Identity Provider` and `cognito-identity-provider` -> `cognitoidentityprovider`.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live mode is read-only: every service probe is a read call.
    #[test]
    fn probes_are_read_calls() {
        for s in index().by_id.values() {
            if let Some(p) = &s.probe {
                assert!(
                    ["List", "Describe", "Get"]
                        .iter()
                        .any(|r| p.op.starts_with(r)),
                    "{}: {}",
                    s.service_id,
                    p.op
                );
            }
        }
    }

    #[test]
    fn lookups() {
        let i = index();
        assert_eq!(
            i.by_service_id("Elastic Load Balancing v2")
                .unwrap()
                .endpoint_prefix,
            "elasticloadbalancing"
        );
        assert_eq!(i.by_endpoint_prefix("rds").unwrap().signing_name, "rds");
        for (name, prefix) in [
            ("CognitoIdentityServiceProvider", "cognito-idp"),
            ("SSM", "ssm"),
            ("@aws-sdk/client-cloudfront", "cloudfront"),
            ("ELBv2", "elasticloadbalancing"),
        ] {
            assert_eq!(
                i.by_sdk_name(name).unwrap().endpoint_prefix,
                prefix,
                "{name}"
            );
        }
        assert!(i.by_sdk_name("NotAService").is_none());
    }

    #[test]
    fn json_services_carry_a_target_prefix() {
        let i = index();
        assert!(i.by_id.len() > 400);
        for s in i.by_id.values() {
            assert_eq!(
                s.protocol == "json",
                s.target_prefix.is_some(),
                "{}",
                s.service_id
            );
        }
    }
}
