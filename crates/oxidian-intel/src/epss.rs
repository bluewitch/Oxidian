use oxidian_core::canonical_cve;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// One EPSS score in the closed interval 0..=1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    pub cve_id: String,
    pub score: f64,
    pub percentile: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct Envelope {
    data: Vec<Raw>,
}

#[derive(Debug, Deserialize)]
struct Raw {
    cve: String,
    epss: Value,
    #[serde(default)]
    percentile: Option<Value>,
}

/// Parse a FIRST EPSS API page. Scores outside 0..=1 are skipped.
pub fn parse_epss(bytes: &[u8]) -> Result<Vec<EpssScore>> {
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Parse)?;
    let mut scores = Vec::new();
    for raw in envelope.data {
        let Some(cve_id) = canonical_cve(&raw.cve) else {
            continue;
        };
        let Some(score) = number(&raw.epss) else {
            continue;
        };
        if !(0.0..=1.0).contains(&score) {
            continue;
        }
        let percentile = raw.percentile.as_ref().and_then(number);
        let percentile = percentile.filter(|value| (0.0..=1.0).contains(value));
        scores.push(EpssScore {
            cve_id,
            score,
            percentile,
        });
    }
    Ok(scores)
}

fn number(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_string_scores() {
        let scores = parse_epss(include_bytes!("../tests/fixtures/epss.json")).unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].cve_id, "CVE-2099-9001");
        assert!((scores[0].score - 0.5).abs() < 1e-9);
        assert!((scores[0].percentile.unwrap() - 0.9).abs() < 1e-9);
    }
}
