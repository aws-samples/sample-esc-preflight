//! `compare --from <a> --to <b>`: what Region `a` offers and Region `b` does not.
//!
//! Public mode reads both Regions from the AWS Knowledge MCP server (products,
//! CloudFormation resource types and config values) and, where both publish one, their
//! CloudFormation schema bundles for property differences of the types both offer.
//! With a profile for `b`, its CloudFormation registry and `DescribeType` replace the
//! public data for `b`. Nothing is deployed or changed.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::provider::knowledge::{Knowledge, State};
use crate::provider::schema::{SchemaProvenance, Schemas};

#[derive(Debug, Clone)]
pub struct Comparison {
    pub from: String,
    pub to: String,
    pub data_provenance: CompareProvenance,
    pub summary: CompareSummary,
    /// Products and features available in `from` and not in `to`.
    pub products: Vec<ProductGap>,
    /// CloudFormation resource types available in `from` and not in `to`.
    pub resource_types: Vec<TypeGap>,
    /// Config values, such as instance types, `from` offers and `to` does not.
    pub config_values: Vec<ConfigGap>,
    /// Top-level properties of types both offer that `to`'s schema lacks.
    pub properties: Vec<PropertyGap>,
    pub warnings: Vec<CompareWarning>,
}

pub type CompareWarning = crate::report::Warning<CompareWarningCode>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum CompareWarningCode {
    /// No public availability data covers the target: products and config values are
    /// not compared.
    PublicDataRegionUnlisted,
    /// A Region publishes no product or config value data (China): products and config
    /// values are not compared.
    ProductsUnchecked,
    /// A Region without a schema bundle, and no live mode for it: properties are not
    /// compared.
    PropertiesUnchecked,
}

#[derive(Debug, Clone)]
pub struct CompareProvenance {
    pub tool_version: String,
    /// Where the CloudFormation types and config values of Regions outside China came
    /// from: the Builder Center capabilities API, or the Knowledge MCP server when the
    /// API failed. Null when both Regions are in China.
    pub cloudformation_url: Option<String>,
    /// Where product states of Regions outside China came from; null when both are
    /// in China.
    pub products_url: Option<String>,
    /// The schema bundles that gave China Regions their resource types.
    pub china_bundle_urls: Vec<String>,
    /// When the public data was fetched.
    pub fetched_at: String,
    /// The account `to` was read from, when a profile was given.
    pub live_account_id: Option<String>,
    /// The schemas read for each Region; both null when properties are not compared.
    pub from_schemas: Option<SchemaProvenance>,
    pub to_schemas: Option<SchemaProvenance>,
    /// Types whose schema both Regions gave, so their properties were compared.
    pub compared_types: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct CompareSummary {
    pub products: usize,
    pub resource_types: usize,
    pub config_values: usize,
    pub properties: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ProductGap {
    pub name: String,
    /// The state in `to`; null when the server does not list the product there.
    pub to_state: Option<State>,
    /// Quarter of a planned launch in `to`.
    pub to_launch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct TypeGap {
    pub resource_type: String,
    /// The product the type belongs to, as `from` lists it.
    pub product: Option<String>,
    /// The product's state in `to`; null when no product is known or `to` does not
    /// list it.
    pub to_state: Option<State>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ConfigGap {
    /// The parent key, such as `AWS::EC2::Instance::InstanceType`.
    pub key: String,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct PropertyGap {
    pub resource_type: String,
    pub missing: Vec<String>,
}

/// What a comparison reads, decided before any data is fetched.
#[derive(Debug, PartialEq, Eq)]
pub struct Scope {
    /// Products and config values: both Regions have Knowledge MCP data.
    pub products: bool,
    /// Where `to`'s schemas come from; null: properties are not compared.
    pub to_schemas: Option<crate::provider::schema::SchemaSource>,
    pub warnings: Vec<CompareWarning>,
}

/// What is known about the two Regions before any data is fetched.
pub struct Sources {
    /// A public source has the Region's resource types: the Knowledge MCP server lists
    /// it, or it is in China.
    pub from_listed: bool,
    pub to_listed: bool,
    /// The Region has product and config value data: the Knowledge MCP server lists it.
    pub from_products: bool,
    pub to_products: bool,
    /// Live mode reads `to`.
    pub live: bool,
    /// `--properties`: live mode reads `to`'s schemas.
    pub properties: bool,
    /// The Region publishes a CloudFormation schema bundle.
    pub from_bundle: bool,
    pub to_bundle: bool,
}

/// The scope of a comparison of two different Regions.
pub fn scope(from: &str, to: &str, s: &Sources) -> Result<Scope, String> {
    use crate::provider::schema::SchemaSource;
    if !s.from_listed {
        return Err(format!("no public availability data covers {from}"));
    }
    if !s.to_listed && !s.live {
        return Err(crate::provider::knowledge::unlisted(to));
    }
    let mut warnings = Vec::new();
    // Each warning names the Region it is about.
    let mut warn = |code, message, region: &str| {
        warnings.push(CompareWarning::new(code, message, vec![region.to_string()]))
    };
    let products = s.to_listed && s.from_products && s.to_products;
    if !s.to_listed {
        warn(
            CompareWarningCode::PublicDataRegionUnlisted,
            format!(
                "No public availability data covers {to}, so products and config values are not compared."
            ),
            to,
        );
    } else if !products {
        let region = if s.from_products { to } else { from };
        warn(
            CompareWarningCode::ProductsUnchecked,
            format!(
                "{region} publishes no product or config value data, so products and config values are not compared."
            ),
            region,
        );
    }
    let to_schemas = if !s.from_bundle {
        warn(
            CompareWarningCode::PropertiesUnchecked,
            format!(
                "{from} publishes no CloudFormation schema bundle, so resource properties are not compared."
            ),
            from,
        );
        None
    } else if s.live && s.properties {
        Some(SchemaSource::Live)
    } else if s.to_bundle {
        Some(SchemaSource::Bundle)
    } else if s.live {
        warn(
            CompareWarningCode::PropertiesUnchecked,
            format!(
                "{to} publishes no CloudFormation schema bundle, so resource properties are not compared. Add --properties to read them from the account, which takes several minutes."
            ),
            to,
        );
        None
    } else {
        warn(
            CompareWarningCode::PropertiesUnchecked,
            format!(
                "{to} publishes no CloudFormation schema bundle, so resource properties are not compared. Run in live mode (--live, --profile or --role-arn) with --properties to read them from the account."
            ),
            to,
        );
        None
    };
    Ok(Scope {
        products,
        to_schemas,
        warnings,
    })
}

/// The available types of a Region's Knowledge MCP data.
pub fn available_types(k: &Knowledge) -> BTreeSet<String> {
    k.types
        .iter()
        .filter(|(_, ok)| **ok)
        .map(|(t, _)| t.clone())
        .collect()
}

/// What `from` offers and `to` does not, before the scope drops what was not compared.
pub struct Diff {
    pub products: Vec<ProductGap>,
    pub resource_types: Vec<TypeGap>,
    pub config_values: Vec<ConfigGap>,
    pub properties: Vec<PropertyGap>,
}

/// Everything `from` offers that `to` does not. `to_types` replaces `to`'s Knowledge
/// MCP types when live mode read its registry.
pub fn diff(
    from: &Knowledge,
    to: &Knowledge,
    to_types: &BTreeSet<String>,
    schemas: Option<(&Schemas, &Schemas)>,
) -> Diff {
    // A merged name stands for its per-service entries, which are compared instead.
    let products = from
        .products
        .iter()
        .filter(|(name, _)| !from.merged.contains(*name) && !to.merged.contains(*name))
        .filter(|(_, p)| p.state == State::Available)
        .filter_map(|(name, _)| {
            let there = to.products.get(name);
            (there.map(|p| p.state) != Some(State::Available)).then(|| ProductGap {
                name: name.clone(),
                to_state: there.map(|p| p.state),
                to_launch: there.and_then(|p| p.launch.clone()),
            })
        })
        .collect();
    let types = available_types(from)
        .into_iter()
        .filter(|t| !to_types.contains(t))
        .map(|t| {
            // The product as `from` lists it; `to` may not list it at all.
            let product = from.product_of(&t).map(|(n, _)| n.to_string());
            TypeGap {
                to_state: product
                    .as_ref()
                    .and_then(|n| to.products.get(n))
                    .map(|p| p.state),
                product,
                resource_type: t,
            }
        })
        .collect();
    let config = from
        .config
        .iter()
        .filter_map(|(key, values)| {
            let there = to.config.get(key);
            let missing: Vec<String> = values
                .iter()
                .filter(|v| there.is_none_or(|t| !t.contains(*v)))
                .cloned()
                .collect();
            (!missing.is_empty()).then(|| ConfigGap {
                key: key.clone(),
                missing,
            })
        })
        .collect();
    let properties = schemas
        .map(|(a, b)| {
            a.iter()
                .filter_map(|(t, props)| {
                    let there = b.get(t)?;
                    let missing: Vec<String> = props.difference(there).cloned().collect();
                    (!missing.is_empty()).then(|| PropertyGap {
                        resource_type: t.clone(),
                        missing,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Diff {
        products,
        resource_types: types,
        config_values: config,
        properties,
    }
}

/// The comparison and its counts. Without Knowledge MCP data for `to`, products and
/// config values are left out.
pub fn build(
    from: &str,
    to: &str,
    data_provenance: CompareProvenance,
    diff: Diff,
    scope: Scope,
) -> Comparison {
    let Diff {
        mut products,
        resource_types,
        mut config_values,
        properties,
    } = diff;
    let warnings = scope.warnings;
    if !scope.products {
        products.clear();
        config_values.clear();
    }
    Comparison {
        from: from.into(),
        to: to.into(),
        data_provenance,
        summary: CompareSummary {
            products: products.len(),
            resource_types: resource_types.len(),
            config_values: config_values.iter().map(|g| g.missing.len()).sum(),
            properties: properties.iter().map(|g| g.missing.len()).sum(),
        },
        products,
        resource_types,
        config_values,
        properties,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::knowledge::Product;

    /// Schemas built by hand.
    fn schemas(pairs: &[(&str, &[&str])]) -> Schemas {
        pairs
            .iter()
            .map(|(t, ps)| (t.to_string(), ps.iter().map(|p| p.to_string()).collect()))
            .collect()
    }

    fn k(
        products: &[(&str, State)],
        types: &[(&str, bool)],
        config: &[(&str, &[&str])],
    ) -> Knowledge {
        Knowledge {
            products: products
                .iter()
                .map(|(n, s)| {
                    (
                        n.to_string(),
                        Product {
                            state: *s,
                            launch: (*s == State::Planned).then(|| "2027 Q1".to_string()),
                        },
                    )
                })
                .collect(),
            types: types.iter().map(|(t, ok)| (t.to_string(), *ok)).collect(),
            config: config
                .iter()
                .map(|(key, v)| (key.to_string(), v.iter().map(|x| x.to_string()).collect()))
                .collect(),
            ..Knowledge::default()
        }
    }

    #[test]
    fn what_from_offers_and_to_does_not() {
        let from = k(
            &[
                ("Amazon S3", State::Available),
                ("Amazon Q Business", State::Available),
                ("Amazon Kendra", State::Available),
                ("Old", State::NotAvailable),
            ],
            &[
                ("AWS::S3::Bucket", true),
                ("AWS::QBusiness::Application", true),
                ("AWS::X::Gone", false),
            ],
            &[(
                "AWS::EC2::Instance::InstanceType",
                &["m7g.large", "p5.48xlarge"],
            )],
        );
        let to = k(
            &[
                ("Amazon S3", State::Available),
                ("Amazon Q Business", State::Planned),
            ],
            &[
                ("AWS::S3::Bucket", true),
                ("AWS::QBusiness::Application", false),
            ],
            &[("AWS::EC2::Instance::InstanceType", &["m7g.large"])],
        );
        let to_types = available_types(&to);
        let a = schemas(&[("AWS::S3::Bucket", &["BucketName", "Tags", "New"])]);
        let b = schemas(&[("AWS::S3::Bucket", &["BucketName", "Tags"])]);
        let Diff {
            products: p,
            resource_types: t,
            config_values: c,
            properties: props,
        } = diff(&from, &to, &to_types, Some((&a, &b)));
        assert_eq!(
            p.iter()
                .map(|g| (g.name.as_str(), g.to_state, g.to_launch.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("Amazon Kendra", None, None),
                ("Amazon Q Business", Some(State::Planned), Some("2027 Q1"))
            ]
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].resource_type, "AWS::QBusiness::Application");
        assert_eq!(
            (t[0].product.as_deref(), t[0].to_state),
            (Some("Amazon Q Business"), Some(State::Planned))
        );
        // `to` unlisted: the product still names itself from `from`.
        let t = diff(&from, &Knowledge::default(), &BTreeSet::new(), None).resource_types;
        let q = t
            .iter()
            .find(|g| g.resource_type == "AWS::QBusiness::Application")
            .unwrap();
        assert_eq!(
            (q.product.as_deref(), q.to_state),
            (Some("Amazon Q Business"), None)
        );
        assert_eq!(c[0].missing, ["p5.48xlarge"]);
        assert_eq!(props[0].missing, ["New"]);
        assert!(diff(&from, &to, &to_types, None).properties.is_empty());
        // A merged name is compared per service.
        let mut from = from.clone();
        let mut to = to.clone();
        for (n, s) in [
            ("PrivateLink Support", State::Available),
            ("S3: PrivateLink Support", State::Available),
        ] {
            from.products.insert(
                n.into(),
                Product {
                    state: s,
                    launch: None,
                },
            );
        }
        to.products.insert(
            "S3: PrivateLink Support".into(),
            Product {
                state: State::Planning,
                launch: None,
            },
        );
        to.merged.insert("PrivateLink Support".into());
        let names: Vec<String> = diff(&from, &to, &to_types, None)
            .products
            .into_iter()
            .map(|g| g.name)
            .collect();
        assert!(names.contains(&"S3: PrivateLink Support".to_string()));
        assert!(!names.contains(&"PrivateLink Support".to_string()));
    }

    #[test]
    fn scope_follows_listing_live_mode_and_bundles() {
        use crate::provider::schema::SchemaSource::{Bundle, Live};
        let s = |listed: (bool, bool), live, bundles: (bool, bool)| {
            scope(
                "a",
                "b",
                &Sources {
                    from_listed: listed.0,
                    to_listed: listed.1,
                    from_products: listed.0,
                    to_products: listed.1,
                    live,
                    properties: live,
                    from_bundle: bundles.0,
                    to_bundle: bundles.1,
                },
            )
        };
        assert!(
            s((false, true), true, (true, true))
                .unwrap_err()
                .contains("covers a")
        );
        assert!(
            s((true, false), false, (true, true))
                .unwrap_err()
                .contains("live mode")
        );
        let codes = |sc: &Scope| sc.warnings.iter().map(|w| w.code).collect::<Vec<_>>();
        // Each warning names its Region.
        let w = s((true, false), true, (false, false)).unwrap();
        assert_eq!(
            w.warnings
                .iter()
                .map(|w| (w.code, w.items.join(",")))
                .collect::<Vec<_>>(),
            [
                (
                    CompareWarningCode::PublicDataRegionUnlisted,
                    "b".to_string()
                ),
                (CompareWarningCode::PropertiesUnchecked, "a".to_string())
            ]
        );
        let public = s((true, true), false, (true, true)).unwrap();
        assert_eq!((public.products, public.to_schemas), (true, Some(Bundle)));
        assert!(public.warnings.is_empty());
        let esc = s((true, true), false, (true, false)).unwrap();
        assert_eq!(esc.to_schemas, None);
        assert_eq!(codes(&esc), [CompareWarningCode::PropertiesUnchecked]);
        let live = s((true, true), true, (true, false)).unwrap();
        assert_eq!(live.to_schemas, Some(Live));
        let unlisted = s((true, false), true, (true, false)).unwrap();
        assert!(!unlisted.products);
        assert_eq!(
            codes(&unlisted),
            [CompareWarningCode::PublicDataRegionUnlisted]
        );
        let china = scope(
            "a",
            "cn-north-1",
            &Sources {
                from_listed: true,
                to_listed: true,
                from_products: true,
                to_products: false,
                live: false,
                properties: false,
                from_bundle: true,
                to_bundle: true,
            },
        )
        .unwrap();
        assert_eq!((china.products, china.to_schemas), (false, Some(Bundle)));
        assert_eq!(codes(&china), [CompareWarningCode::ProductsUnchecked]);
        assert!(
            china.warnings[0]
                .message
                .starts_with("cn-north-1 publishes")
        );
        let quick = scope(
            "a",
            "b",
            &Sources {
                from_listed: true,
                to_listed: true,
                from_products: true,
                to_products: true,
                live: true,
                properties: false,
                from_bundle: true,
                to_bundle: false,
            },
        )
        .unwrap();
        assert_eq!(quick.to_schemas, None);
        assert!(quick.warnings[0].message.contains("--properties"));
        let from_none = s((true, true), true, (false, true)).unwrap();
        assert_eq!(from_none.to_schemas, None);
        assert!(from_none.warnings[0].message.starts_with("a publishes"));
    }

    #[test]
    fn summary_caps_long_lists() {
        let c = Comparison {
            from: "eu-central-1".into(),
            to: "eusc-de-east-1".into(),
            data_provenance: CompareProvenance {
                tool_version: "test".into(),
                cloudformation_url: Some("c".into()),
                products_url: None,
                china_bundle_urls: vec![],
                fetched_at: "t".into(),
                live_account_id: None,
                from_schemas: None,
                to_schemas: None,
                compared_types: 0,
            },
            summary: CompareSummary::default(),
            products: (0..10)
                .map(|i| ProductGap {
                    name: format!("P{i}"),
                    to_state: Some(State::NotExpanding),
                    to_launch: None,
                })
                .collect(),
            resource_types: vec![],
            config_values: vec![],
            properties: vec![],
            warnings: vec![CompareWarning::new(
                CompareWarningCode::PropertiesUnchecked,
                "w".into(),
                Vec::new(),
            )],
        };
        let summary = |c: &Comparison| {
            crate::summary::compare_summary(
                c,
                crate::tui::Style::default(),
                &crate::tui::Run::default(),
            )
        };
        let t = summary(&c);
        assert!(t.contains(" Products "), "{t}");
        assert!(
            t.lines()
                .any(|l| l.contains("not expanding") && l.contains("10") && l.contains("+7 more")),
            "{t}"
        );
        let mut uncompared = c.clone();
        uncompared.warnings[0].code = CompareWarningCode::ProductsUnchecked;
        let u = summary(&uncompared);
        assert!(
            !u.contains(" Products ") && !u.contains(" Config values "),
            "{u}"
        );
        assert!(
            !t.contains(" Properties "),
            "no schemas, no property section"
        );
    }
}
