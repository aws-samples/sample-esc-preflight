//! The ESC User Guide service pages.
//!
//! Each page's "How X differs" section lists feature differences, attached to findings
//! as notes and matched to resources by the rules in `data/esc-guide-rules.json`.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use super::http::Client;
use crate::error::{Result, ScanError};
use crate::services;

pub const BASE: &str = "https://docs.aws.eu/esc/latest/userguide/";
/// The partition the guide documents. Other partitions skip this source.
pub const PARTITION: &str = "aws-eusc";
/// The guide listed 98 service pages on 2026-10-29. Far fewer means the layout changed.
const MIN_PAGES: usize = 80;
const PARALLEL: usize = 8;
const PAGES_JSON: &str = include_str!("../../data/esc-guide-pages.json");

#[derive(Debug, Clone)]
pub struct Page {
    pub slug: String,
    pub title: String,
    pub url: String,
    /// Endpoint prefixes the page documents.
    pub services: Vec<String>,
    /// Resource-type prefixes the page documents beyond its services.
    pub type_prefixes: Vec<String>,
    /// The documented differences, one entry per list item.
    pub differences: Vec<String>,
    /// The whole differences section as plain text, for rule matching.
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct GuideData {
    pub toc_url: String,
    pub pages: Vec<Page>,
    /// Pages that map to no known endpoint prefix.
    pub unmapped: Vec<String>,
}

impl GuideData {
    /// Pages relevant to a resource of this service and type.
    pub fn pages_for<'a>(
        &'a self,
        service: Option<&'a str>,
        resource_type: &'a str,
    ) -> impl Iterator<Item = &'a Page> {
        self.pages.iter().filter(move |p| {
            service.is_some_and(|s| p.services.iter().any(|x| x == s))
                || p.type_prefixes
                    .iter()
                    .any(|t| resource_type.starts_with(t.as_str()))
        })
    }

    pub fn page(&self, slug: &str) -> Option<&Page> {
        self.pages.iter().find(|p| p.slug == slug)
    }
}

#[derive(Deserialize, Default)]
struct Mapping {
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    types: Vec<String>,
}

pub fn fetch(client: &Client) -> Result<GuideData> {
    let toc_url = format!("{BASE}toc-contents.json");
    let toc = service_pages(&client.get_text(&toc_url)?)?;
    if toc.len() < MIN_PAGES {
        return Err(ScanError::DataSource(format!(
            "{toc_url}: found {} service pages, expected at least {MIN_PAGES}; the guide layout may have changed",
            toc.len()
        )));
    }
    let chunk = toc.len().div_ceil(PARALLEL);
    let html: Vec<Result<String>> = std::thread::scope(|s| {
        let handles: Vec<_> = toc
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    part.iter()
                        .map(|(slug, _)| client.get_text(&format!("{BASE}{slug}.html")))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("fetch thread does not panic"))
            .collect()
    });
    let pages = toc
        .into_iter()
        .zip(html)
        .map(|((slug, title), h)| Ok((slug, title, h?)))
        .collect::<Result<Vec<_>>>()?;
    let data = from_pages(pages);
    let without = data.pages.iter().filter(|p| p.text.is_empty()).count();
    if without * 5 > data.pages.len() {
        return Err(ScanError::DataSource(format!(
            "{BASE}: {without} of {} service pages have no differences section; the page layout may have changed",
            data.pages.len()
        )));
    }
    Ok(GuideData { toc_url, ..data })
}

/// `(slug, title)` of every page under the guide's Services node.
pub fn service_pages(toc_json: &str) -> Result<Vec<(String, String)>> {
    let bad = |w: &str| ScanError::DataSource(format!("ESC User Guide table of contents: {w}"));
    let v: Value = serde_json::from_str(toc_json).map_err(|e| bad(&e.to_string()))?;
    let services = v["contents"]
        .as_array()
        .and_then(|c| c.iter().find(|n| n["href"] == "services.html"))
        .and_then(|n| n["contents"].as_array())
        .ok_or_else(|| bad("no Services node"))?;
    Ok(services
        .iter()
        .filter_map(|n| {
            let slug = n["href"].as_str()?.strip_suffix(".html")?;
            Some((slug.to_string(), n["title"].as_str()?.to_string()))
        })
        .collect())
}

/// Builds the guide data from fetched pages. Minimum counts are checked by `fetch`.
pub fn from_pages(pages: Vec<(String, String, String)>) -> GuideData {
    #[derive(Deserialize)]
    struct Table {
        pages: BTreeMap<String, Mapping>,
    }
    let table = serde_json::from_str::<Table>(PAGES_JSON)
        .expect("bundled page table is valid")
        .pages;
    let mut unmapped = Vec::new();
    let pages = pages
        .into_iter()
        .map(|(slug, title, html)| {
            let m = match table.get(&slug) {
                Some(m) => Mapping {
                    services: m.services.clone(),
                    types: m.types.clone(),
                },
                None if services::index().by_endpoint_prefix(&slug).is_some() => Mapping {
                    services: vec![slug.clone()],
                    types: Vec::new(),
                },
                None => {
                    unmapped.push(slug.clone());
                    Mapping::default()
                }
            };
            let (text, differences) = differences(&html);
            Page {
                url: format!("{BASE}{slug}.html"),
                slug,
                title,
                services: m.services,
                type_prefixes: m.types,
                differences,
                text,
            }
        })
        .collect();
    GuideData {
        toc_url: String::new(),
        pages,
        unmapped,
    }
}

/// The "How X differs" section: its plain text and its top-level list items. Nested
/// items are folded into their parent, and an item under a sub-heading carries it.
fn differences(html: &str) -> (String, Vec<String>) {
    let Some(start) = html.match_indices("<h2").map(|(i, _)| i).find(|&i| {
        html[i..]
            .split_once("</h2>")
            .is_some_and(|(h, _)| h.contains("differ"))
    }) else {
        return (String::new(), Vec::new());
    };
    let body = &html[start..];
    let body = &body[body.find("</h2>").map_or(0, |i| i + 5)..];
    let body = &body[..body.find("<h2").unwrap_or(body.len())];

    let (mut items, mut text, mut cur, mut heading) =
        (Vec::new(), String::new(), String::new(), String::new());
    let (mut depth, mut in_heading, mut first_nested) = (0usize, false, false);
    for (i, chunk) in body.split('<').enumerate() {
        let (tag, raw) = if i == 0 {
            ("", chunk)
        } else {
            chunk.split_once('>').unwrap_or((chunk, ""))
        };
        let closing = tag.starts_with('/');
        let name = tag
            .trim_start_matches('/')
            .split(|c: char| c.is_whitespace() || c == '/')
            .next()
            .unwrap_or("");
        match (name, closing) {
            ("ul" | "ol", false) => {
                depth += 1;
                first_nested = depth > 1;
            }
            ("ul" | "ol", true) => depth = depth.saturating_sub(1),
            ("li", false) if depth == 1 => {
                cur = if heading.is_empty() {
                    String::new()
                } else {
                    format!("{heading}: ")
                };
            }
            ("li", false) if depth > 1 => {
                let t = cur.trim_end();
                let sep = if first_nested && !t.ends_with(':') {
                    ": "
                } else if first_nested {
                    " "
                } else {
                    "; "
                };
                cur = format!("{t}{sep}");
                first_nested = false;
            }
            ("li", true) if depth == 1 => {
                let item = squash(&cur);
                if !item.is_empty() && !item.ends_with(':') {
                    items.push(item);
                }
                cur.clear();
            }
            ("h3" | "h4", false) => {
                in_heading = true;
                heading.clear();
            }
            ("h3" | "h4", true) => {
                in_heading = false;
                heading = squash(&heading);
            }
            _ => {}
        }
        let inline = matches!(name, "a" | "b" | "i" | "em" | "strong" | "code" | "span");
        let piece = decode(raw);
        let piece = if inline { piece } else { format!(" {piece}") };
        if in_heading {
            heading.push_str(&piece);
        } else if depth >= 1 {
            cur.push_str(&piece);
        }
        text.push_str(&piece);
    }
    (squash(&text), items)
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const TOC: &str = crate::test_inputs::GUIDE_TOC;

    fn page(slug: &str) -> (String, String, String) {
        let html = match slug {
            "lambda" => crate::test_inputs::GUIDE_LAMBDA,
            "rds" => crate::test_inputs::GUIDE_RDS,
            _ => crate::test_inputs::GUIDE_GENERIC,
        };
        (slug.into(), slug.into(), html.into())
    }

    pub fn fixture() -> GuideData {
        let pages = service_pages(TOC)
            .unwrap()
            .into_iter()
            .map(|(s, _)| page(&s))
            .collect();
        from_pages(pages)
    }

    #[test]
    fn reads_the_services_node() {
        let toc = service_pages(TOC).unwrap();
        assert!(toc.iter().any(|(s, t)| s == "lambda" && t == "AWS Lambda"));
        assert!(!toc.iter().any(|(s, _)| s == "endpoints"));
    }

    #[test]
    fn maps_pages_to_services() {
        let g = fixture();
        let documents = |s: &str| g.pages.iter().any(|p| p.services.iter().any(|x| x == s));
        assert!(documents("lambda") && documents("cognito-idp") && documents("codepipeline"));
        assert!(!documents("cloudfront"));
        assert!(g.page("cdk").unwrap().services.is_empty());
        assert!(g.unmapped.is_empty(), "{:?}", g.unmapped);
        let docdb: Vec<_> = g
            .pages_for(Some("rds"), "AWS::DocDB::DBCluster")
            .map(|p| p.slug.as_str())
            .collect();
        assert_eq!(docdb, ["documentdb", "rds"]);
    }

    #[test]
    fn extracts_items_with_nesting_and_headings() {
        let g = fixture();
        let l = g.page("lambda").unwrap();
        assert_eq!(l.differences[0], "Function URLs is not available.");
        assert_eq!(
            l.differences[1],
            "The following event sources are not available: Apache Kafka; Amazon MQ"
        );
        assert!(l.text.contains("Function URLs is not available"));
        assert!(!l.text.contains("Documentation"));
        let r = g.page("rds").unwrap();
        assert!(r.differences.contains(
            &"Features not available for Aurora PostgreSQL: Optimized Reads".to_string()
        ));
    }

    #[test]
    fn a_page_without_section_has_no_text() {
        let (t, d) = differences("<h1>X</h1><p>no section</p>");
        assert!(t.is_empty() && d.is_empty());
    }
}
