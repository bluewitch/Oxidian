use oxidian_core::canonical_cve;
use oxidian_match::{Advisory, VersionRange};
use serde::Deserialize;

use crate::{http_client, Error, Result, MAX_BODY};

/// Minimal NVD CVE API 2.0 client.
///
/// v1 parses one CVE document and can fetch that one document. It does not
/// page through the full catalog.
pub struct NvdClient {
    base: String,
    api_key: Option<String>,
    http: reqwest::Client,
}

impl NvdClient {
    pub fn new(base: impl Into<String>, api_key: Option<String>) -> Result<Self> {
        let base = base.into().trim_end_matches('/').to_owned();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(Error::BadUrl);
        }
        let api_key = api_key.and_then(|key| {
            let trimmed = key.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });
        Ok(Self {
            base,
            api_key,
            http: http_client()?,
        })
    }

    /// Read `OXIDIAN_NVD_API_KEY` when it is present. The value is not logged.
    pub fn from_env(base: impl Into<String>) -> Result<Self> {
        let key = std::env::var("OXIDIAN_NVD_API_KEY").ok();
        Self::new(base, key)
    }

    pub fn endpoint_for(&self, cve_id: &str) -> Result<String> {
        let cve_id = canonical_cve(cve_id).ok_or(Error::Parse)?;
        Ok(format!("{}?cveId={cve_id}", self.base))
    }

    pub fn parse(body: &str) -> Result<Vec<Advisory>> {
        parse_nvd(body)
    }

    pub async fn fetch_one(&self, cve_id: &str) -> Result<Vec<Advisory>> {
        let url = self.endpoint_for(cve_id)?;
        let mut request = self.http.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }
        let response = request.send().await.map_err(Error::Http)?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Status(status.as_u16()));
        }
        let bytes = response.bytes().await.map_err(Error::Http)?;
        if bytes.len() > MAX_BODY {
            return Err(Error::BodyTooLarge);
        }
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| Error::Parse)?;
        parse_nvd(&text)
    }
}

#[derive(Debug, Deserialize)]
struct Document {
    vulnerabilities: Vec<Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    cve: Cve,
}

#[derive(Debug, Deserialize)]
struct Cve {
    id: String,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct Metrics {
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<CvssMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<CvssMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<CvssMetric>,
}

#[derive(Debug, Deserialize)]
struct CvssMetric {
    #[serde(rename = "cvssData")]
    data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    #[serde(rename = "baseScore")]
    base_score: f64,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    #[serde(default)]
    negate: bool,
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(default, rename = "versionStartIncluding")]
    start_including: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    start_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    end_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    end_excluding: Option<String>,
}

struct Group {
    product: String,
    ranges: Vec<VersionRange>,
}

/// Parse one NVD CVE API 2.0 document into bounded advisories.
pub fn parse_nvd(body: &str) -> Result<Vec<Advisory>> {
    let document: Document = serde_json::from_str(body).map_err(|_| Error::Parse)?;
    let mut advisories = Vec::new();
    for item in document.vulnerabilities {
        let Some(cve_id) = canonical_cve(&item.cve.id) else {
            continue;
        };
        let summary = item
            .cve
            .descriptions
            .iter()
            .find(|description| description.lang.eq_ignore_ascii_case("en"))
            .map(|description| description.value.clone())
            .unwrap_or_default();
        let cvss = cvss_score(&item.cve.metrics);
        let mut groups: Vec<Group> = Vec::new();
        for configuration in &item.cve.configurations {
            for node in &configuration.nodes {
                collect_node(node, &mut groups);
            }
        }
        for group in groups {
            if let Ok(advisory) =
                Advisory::try_new(&cve_id, &group.product, group.ranges, cvss, summary.clone())
            {
                advisories.push(advisory);
            }
        }
    }
    Ok(advisories)
}

fn cvss_score(metrics: &Metrics) -> Option<f64> {
    metrics
        .v31
        .first()
        .or_else(|| metrics.v30.first())
        .or_else(|| metrics.v2.first())
        .map(|metric| metric.data.base_score)
}

fn collect_node(node: &Node, groups: &mut Vec<Group>) {
    if node.negate {
        return;
    }
    for cpe in &node.cpe_match {
        if let Some((product, range)) = cpe_range(cpe) {
            if let Some(existing) = groups.iter_mut().find(|group| group.product == product) {
                existing.ranges.push(range);
            } else {
                groups.push(Group {
                    product,
                    ranges: vec![range],
                });
            }
        }
    }
    for child in &node.nodes {
        collect_node(child, groups);
    }
}

fn cpe_range(cpe: &CpeMatch) -> Option<(String, VersionRange)> {
    if !cpe.vulnerable || cpe.criteria.contains('\\') {
        return None;
    }
    let mut parts = cpe.criteria.split(':');
    let prefix = parts.next()?;
    let version_token = parts.next()?;
    let part = parts.next()?;
    let _vendor = parts.next()?;
    let product = parts.next()?.to_owned();
    let exact = parts.next()?.to_owned();
    if prefix != "cpe"
        || version_token != "2.3"
        || (part != "a" && part != "o")
        || product.is_empty()
    {
        return None;
    }
    let start = match (&cpe.start_including, &cpe.start_excluding) {
        (Some(_), Some(_)) => return None,
        (Some(value), None) => Some((value.as_str(), true)),
        (None, Some(value)) => Some((value.as_str(), false)),
        (None, None) => None,
    };
    let end = match (&cpe.end_including, &cpe.end_excluding) {
        (Some(_), Some(_)) => return None,
        (Some(value), None) => Some((value.as_str(), true)),
        (None, Some(value)) => Some((value.as_str(), false)),
        (None, None) => None,
    };
    let range = if start.is_none() && end.is_none() {
        if exact == "*" || exact == "-" || exact.is_empty() {
            return None;
        }
        VersionRange::new(Some((&exact, true)), Some((&exact, true)))?
    } else {
        VersionRange::new(start, end)?
    };
    Some((product, range))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_cpe_and_skips_unbounded_rows() {
        let body = include_str!("../tests/fixtures/nvd_cve.json");
        let advisories = parse_nvd(body).unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].cve_id, "CVE-2099-9001");
        assert_eq!(advisories[0].product, "fixture");
        assert!((advisories[0].cvss.unwrap() - 9.8).abs() < 1e-9);
        let version = oxidian_match::Version::parse("1.2.0").unwrap();
        assert!(advisories[0].ranges[0].contains(&version));
        let excluded = oxidian_match::Version::parse("2.0.0").unwrap();
        assert!(!advisories[0].ranges[0].contains(&excluded));
    }

    #[test]
    fn endpoint_rejects_ids_that_are_not_cves() {
        let client =
            NvdClient::new("https://services.nvd.nist.gov/rest/json/cves/2.0", None).unwrap();
        let url = client.endpoint_for("CVE-2099-9001").unwrap();
        assert_eq!(
            url,
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-9001"
        );
        assert!(client.endpoint_for("CVE-2099-9001;drop").is_err());
    }
}
