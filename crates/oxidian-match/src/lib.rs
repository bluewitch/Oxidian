//! Product and version matching. A row matches only when both agree.

#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use chrono::Utc;
use oxidian_core::{canonical_cve, Finding, Service, Severity};
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;

/// A catalog row could not be used.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("advisory file could not be read")]
    Read,
    #[error("advisory file was not valid")]
    Syntax,
    #[error("advisory {cve_id} is missing a product or a bounded version range")]
    Unbounded { cve_id: String },
    #[error("advisory path must not contain '..'")]
    BadPath,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Dotted numeric version. Pre-release text does not parse, so it cannot match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    parts: Vec<u64>,
}

impl Version {
    pub fn parse(raw: &str) -> Option<Self> {
        let text = raw.trim();
        if text.is_empty() || !text.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return None;
        }
        let mut parts = Vec::new();
        for piece in text.split('.') {
            if piece.is_empty() {
                return None;
            }
            parts.push(piece.parse().ok()?);
        }
        if parts.is_empty() {
            None
        } else {
            Some(Self { parts })
        }
    }

    fn cmp_version(&self, other: &Self) -> Ordering {
        let width = self.parts.len().max(other.parts.len());
        for index in 0..width {
            let left = self.parts.get(index).copied().unwrap_or(0);
            let right = other.parts.get(index).copied().unwrap_or(0);
            match left.cmp(&right) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Bound {
    version: Version,
    inclusive: bool,
}

/// A version interval with at least one bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRange {
    start: Option<Bound>,
    end: Option<Bound>,
}

impl VersionRange {
    pub fn new(start: Option<(&str, bool)>, end: Option<(&str, bool)>) -> Option<Self> {
        let start = match start {
            Some((raw, inclusive)) => Some(Bound {
                version: Version::parse(raw)?,
                inclusive,
            }),
            None => None,
        };
        let end = match end {
            Some((raw, inclusive)) => Some(Bound {
                version: Version::parse(raw)?,
                inclusive,
            }),
            None => None,
        };
        let range = Self { start, end };
        if range.is_bounded() {
            Some(range)
        } else {
            None
        }
    }

    pub fn is_bounded(&self) -> bool {
        self.start.is_some() || self.end.is_some()
    }

    pub fn contains(&self, version: &Version) -> bool {
        if !self.is_bounded() {
            return false;
        }
        if let Some(start) = &self.start {
            match version.cmp_version(&start.version) {
                Ordering::Less => return false,
                Ordering::Equal if !start.inclusive => return false,
                _ => {}
            }
        }
        if let Some(end) = &self.end {
            match version.cmp_version(&end.version) {
                Ordering::Greater => return false,
                Ordering::Equal if !end.inclusive => return false,
                _ => {}
            }
        }
        true
    }
}

/// One CVE, one product, and the ranges that are known to be affected.
#[derive(Debug, Clone, PartialEq)]
pub struct Advisory {
    pub cve_id: String,
    pub product: String,
    pub ranges: Vec<VersionRange>,
    pub cvss: Option<f64>,
    pub summary: String,
}

impl Advisory {
    pub fn try_new(
        cve_id: &str,
        product: &str,
        ranges: Vec<VersionRange>,
        cvss: Option<f64>,
        summary: impl Into<String>,
    ) -> Result<Self> {
        let Some(cve_id) = canonical_cve(cve_id) else {
            return Err(Error::Unbounded {
                cve_id: "invalid".to_owned(),
            });
        };
        let product = normalize_product(product);
        if product.is_empty() || ranges.is_empty() || ranges.iter().any(|range| !range.is_bounded())
        {
            return Err(Error::Unbounded { cve_id });
        }
        if let Some(score) = cvss {
            if !score.is_finite() || !(0.0..=10.0).contains(&score) {
                return Err(Error::Unbounded { cve_id });
            }
        }
        Ok(Self {
            cve_id,
            product,
            ranges,
            cvss,
            summary: summary.into(),
        })
    }
}

/// Lowercase and strip characters that are not ASCII letters or digits.
pub fn normalize_product(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// `1000` when the CVE is in KEV, plus EPSS scaled to 0–100, plus CVSS.
pub fn rank_score(kev: bool, epss: Option<f64>, cvss: Option<f64>) -> f64 {
    let kev_weight = if kev { 1_000.0 } else { 0.0 };
    let epss_weight = epss.unwrap_or(0.0).clamp(0.0, 1.0) * 100.0;
    let cvss_weight = cvss.unwrap_or(0.0).clamp(0.0, 10.0);
    if !epss_weight.is_finite() || !cvss_weight.is_finite() {
        kev_weight
    } else {
        kev_weight + epss_weight + cvss_weight
    }
}

/// Match services to advisories. Results are sorted by KEV, then EPSS, then CVSS.
pub fn match_services(
    services: &[Service],
    advisories: &[Advisory],
    kev: &HashSet<String>,
    epss: &HashMap<String, f64>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for service in services {
        let Some(product_raw) = service.product.as_deref() else {
            continue;
        };
        let Some(version_raw) = service.version.as_deref() else {
            continue;
        };
        let product = normalize_product(product_raw);
        let Some(version) = Version::parse(version_raw) else {
            continue;
        };
        if product.is_empty() {
            continue;
        }
        let mut seen = HashSet::new();
        for advisory in advisories {
            if advisory.product != product || !seen.insert(advisory.cve_id.clone()) {
                continue;
            }
            if !advisory.ranges.iter().any(|range| range.contains(&version)) {
                continue;
            }
            let kev_hit = kev.contains(&advisory.cve_id);
            let epss_score = epss.get(&advisory.cve_id).copied();
            let severity = Severity::from_cvss(advisory.cvss);
            let severity = if kev_hit {
                severity.at_least(Severity::High)
            } else {
                severity
            };
            findings.push(Finding {
                id: Uuid::new_v4(),
                cve_id: advisory.cve_id.clone(),
                asset_name: service.asset_name.clone(),
                address: service.address,
                port: service.port,
                protocol: service.protocol,
                product: product_raw.to_owned(),
                version: version_raw.to_owned(),
                severity,
                kev: kev_hit,
                epss: epss_score,
                cvss: advisory.cvss,
                rank_score: rank_score(kev_hit, epss_score, advisory.cvss),
                summary: if advisory.summary.is_empty() {
                    format!(
                        "{} affects {} {}",
                        advisory.cve_id, product_raw, version_raw
                    )
                } else {
                    advisory.summary.clone()
                },
                created_at: Utc::now(),
            });
        }
    }
    findings.sort_by(|left, right| {
        right
            .rank_score
            .partial_cmp(&left.rank_score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.cve_id.cmp(&right.cve_id))
            .then_with(|| left.asset_name.cmp(&right.asset_name))
            .then_with(|| left.port.cmp(&right.port))
    });
    findings
}

#[derive(Debug, Deserialize)]
struct AdvisoryFile {
    advisories: Vec<AdvisoryDraft>,
}

#[derive(Debug, Deserialize)]
struct AdvisoryDraft {
    cve_id: String,
    product: String,
    #[serde(default)]
    cvss: Option<f64>,
    #[serde(default)]
    summary: String,
    ranges: Vec<RangeDraft>,
}

#[derive(Debug, Deserialize)]
struct RangeDraft {
    #[serde(default)]
    start: Option<String>,
    #[serde(default = "default_true")]
    start_inclusive: bool,
    #[serde(default)]
    end: Option<String>,
    #[serde(default)]
    end_inclusive: bool,
}

fn default_true() -> bool {
    true
}

/// Load the local advisory catalog. This is not the NVD document shape.
pub fn load_advisories(path: &Path) -> Result<Vec<Advisory>> {
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::BadPath);
    }
    let text = std::fs::read_to_string(path).map_err(|_| Error::Read)?;
    parse_advisories(&text)
}

pub fn parse_advisories(text: &str) -> Result<Vec<Advisory>> {
    let file: AdvisoryFile = serde_json::from_str(text).map_err(|_| Error::Syntax)?;
    file.advisories
        .into_iter()
        .map(|draft| {
            let ranges = draft
                .ranges
                .iter()
                .filter_map(|range| {
                    let start = range
                        .start
                        .as_deref()
                        .map(|value| (value, range.start_inclusive));
                    let end = range
                        .end
                        .as_deref()
                        .map(|value| (value, range.end_inclusive));
                    VersionRange::new(start, end)
                })
                .collect();
            Advisory::try_new(
                &draft.cve_id,
                &draft.product,
                ranges,
                draft.cvss,
                draft.summary,
            )
        })
        .collect()
}

/// Test helper so callers can build a service without repeating fields.
#[cfg(test)]
fn service(product: &str, version: &str, port: u16) -> Service {
    Service::observed(
        "www.example.com",
        Some("192.0.2.10".parse().expect("documentation address")),
        port,
        oxidian_core::Protocol::Tcp,
        Some(product.to_owned()),
        Some(version.to_owned()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: &str, end: &str) -> VersionRange {
        VersionRange::new(Some((start, true)), Some((end, false))).unwrap()
    }

    fn catalog() -> Vec<Advisory> {
        vec![
            Advisory::try_new(
                "CVE-2099-9001",
                "Fixture",
                vec![range("1.0.0", "2.0.0")],
                Some(9.8),
                "higher cvss",
            )
            .unwrap(),
            Advisory::try_new(
                "CVE-2099-9002",
                "fixture",
                vec![VersionRange::new(Some(("1.0.0", true)), Some(("1.5.0", true))).unwrap()],
                Some(5.0),
                "in kev",
            )
            .unwrap(),
            Advisory::try_new(
                "CVE-2099-9003",
                "other",
                vec![VersionRange::new(Some(("1.0.0", true)), Some(("1.0.0", true))).unwrap()],
                Some(10.0),
                "different product",
            )
            .unwrap(),
        ]
    }

    fn close(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    #[test]
    fn product_and_bounds_must_both_agree() {
        let advisories = catalog();
        let kev = HashSet::from(["CVE-2099-9002".to_owned()]);
        let epss = HashMap::from([
            ("CVE-2099-9001".to_owned(), 0.9),
            ("CVE-2099-9002".to_owned(), 0.1),
        ]);
        let hits = match_services(&[service("Fixture", "1.2.0", 80)], &advisories, &kev, &epss);
        assert_eq!(
            hits.iter()
                .map(|hit| hit.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2099-9002", "CVE-2099-9001"]
        );
        assert!(hits[0].kev);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(close(hits[0].rank_score, 1_000.0 + 10.0 + 5.0));
        assert!(close(hits[1].rank_score, 90.0 + 9.8));

        assert!(
            match_services(&[service("Fixture", "2.0.0", 80)], &advisories, &kev, &epss).is_empty()
        );
        assert!(match_services(
            &[service("fixture-extra", "1.2.0", 80)],
            &advisories,
            &kev,
            &epss
        )
        .is_empty());
        assert!(match_services(
            &[service("Fixture", "1.2.0-beta", 80)],
            &advisories,
            &kev,
            &epss
        )
        .is_empty());
        assert!(
            Version::parse("1.10")
                .unwrap()
                .cmp_version(&Version::parse("1.9").unwrap())
                == Ordering::Greater
        );
    }

    #[test]
    fn unbounded_advisory_is_rejected() {
        assert!(VersionRange::new(None, None).is_none());
        let err = Advisory::try_new("CVE-2099-9001", "fixture", Vec::new(), None, "").unwrap_err();
        assert!(matches!(err, Error::Unbounded { .. }));
        let text = include_str!("../../../examples/advisories.json");
        let loaded = parse_advisories(text).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].product, "fixture");
    }

    #[test]
    fn normalize_does_not_use_substrings() {
        assert_eq!(normalize_product("OpenSSH"), "openssh");
        assert_ne!(normalize_product("ssh"), normalize_product("openssh"));
        assert_eq!(normalize_product("Apache Log4j"), "apachelog4j");
        assert_ne!(
            normalize_product("log4j"),
            normalize_product("Apache Log4j")
        );
    }
}
