use oxidian_core::canonical_cve;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// One normalized KEV row. The on-disk cache uses these field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KevRecord {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub summary: String,
    pub date_added: String,
}

#[derive(Debug, Deserialize)]
struct Catalog {
    vulnerabilities: Vec<Raw>,
}

#[derive(Debug, Deserialize)]
struct Raw {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "vendorProject", default)]
    vendor: String,
    #[serde(default)]
    product: String,
    #[serde(rename = "vulnerabilityName", default)]
    name: String,
    #[serde(rename = "shortDescription", default)]
    summary: String,
    #[serde(rename = "dateAdded", default)]
    date_added: String,
}

/// Parse the CISA KEV JSON catalog. Rows with an unusable CVE id are skipped.
pub fn parse_kev(bytes: &[u8]) -> Result<Vec<KevRecord>> {
    let catalog: Catalog = serde_json::from_slice(bytes).map_err(|_| Error::Parse)?;
    let mut records = Vec::new();
    for raw in catalog.vulnerabilities {
        let Some(cve_id) = canonical_cve(&raw.cve_id) else {
            continue;
        };
        records.push(KevRecord {
            cve_id,
            vendor: raw.vendor,
            product: raw.product,
            name: raw.name,
            summary: raw.summary,
            date_added: raw.date_added,
        });
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture_catalog() {
        let records = parse_kev(include_bytes!("../tests/fixtures/kev.json")).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].cve_id, "CVE-2099-9001");
        assert_eq!(records[0].product, "Fixture");
        assert_eq!(records[0].vendor, "Example");
    }
}
