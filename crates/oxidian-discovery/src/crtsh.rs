use std::collections::BTreeSet;

use oxidian_core::Allowlist;
use serde::Deserialize;

use crate::{http_client, Error, Result, MAX_BODY};

/// Names kept from a certificate-transparency response, plus how many were dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertNames {
    pub admitted: Vec<String>,
    pub dropped: usize,
}

/// Client for the public crt.sh JSON output.
pub struct CrtShClient {
    http: reqwest::Client,
    base: String,
}

impl CrtShClient {
    pub fn new(base: impl Into<String>) -> Result<Self> {
        let base = base.into();
        if !(base.starts_with("https://") || base.starts_with("http://")) {
            return Err(Error::BadUrl);
        }
        Ok(Self {
            http: http_client()?,
            base,
        })
    }

    /// Query one allowlisted apex. Names outside the allowlist are counted and dropped.
    pub async fn query_domain(&self, domain: &str, allowlist: &Allowlist) -> Result<CertNames> {
        let url = crtsh_url(&self.base, domain, allowlist)?;
        let response = self.http.get(&url).send().await.map_err(Error::Http)?;
        if !response.status().is_success() {
            return Err(Error::UnexpectedBody);
        }
        let bytes = response.bytes().await.map_err(Error::Http)?;
        if bytes.len() > MAX_BODY {
            return Err(Error::BodyTooLarge);
        }
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| Error::UnexpectedBody)?;
        parse_crtsh(&text, allowlist)
    }
}

/// Build the crt.sh query for an allowlisted domain, or refuse.
pub fn crtsh_url(base: &str, domain: &str, allowlist: &Allowlist) -> Result<String> {
    if !allowlist.admits_domain(domain) {
        return Err(Error::NotAllowlisted);
    }
    let Some(domain) = oxidian_core::normalize_domain(domain) else {
        return Err(Error::NotAllowlisted);
    };
    // `%.name` is the crt.sh wildcard. The domain has already been restricted
    // to letters, digits, dots, and hyphens, so it needs no further encoding.
    let base = base.trim_end_matches('/');
    Ok(format!("{base}/?q=%25.{domain}&output=json"))
}

#[derive(Debug, Deserialize)]
struct Row {
    #[serde(default)]
    name_value: Option<String>,
    #[serde(default)]
    common_name: Option<String>,
}

/// Parse a crt.sh JSON array and keep only allowlisted names.
pub fn parse_crtsh(body: &str, allowlist: &Allowlist) -> Result<CertNames> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(CertNames {
            admitted: Vec::new(),
            dropped: 0,
        });
    }
    let rows: Vec<Row> = serde_json::from_str(trimmed).map_err(|_| Error::UnexpectedBody)?;
    let mut admitted = BTreeSet::new();
    let mut dropped = 0usize;
    for row in rows {
        let mut saw = false;
        for field in [row.name_value, row.common_name].into_iter().flatten() {
            for name in extract_names(&field) {
                saw = true;
                if allowlist.admits_domain(&name) {
                    admitted.insert(name);
                } else {
                    dropped += 1;
                }
            }
        }
        if !saw {
            dropped += 1;
        }
    }
    Ok(CertNames {
        admitted: admitted.into_iter().collect(),
        dropped,
    })
}

/// Split a certificate name field into bare DNS names.
pub fn extract_names(field: &str) -> Vec<String> {
    let mut names = Vec::new();
    for piece in field.split(['\n', ',', ' ']) {
        let mut name = piece.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(stripped) = name.strip_prefix("*.") {
            name = stripped.to_owned();
        }
        if name.is_empty() || name.contains('*') || name.contains('@') || name.contains('/') {
            continue;
        }
        if oxidian_core::normalize_domain(&name).is_some() {
            names.push(name);
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidian_core::Allowlist;

    fn allow() -> Allowlist {
        Allowlist::compile(&["example.com".to_owned()], &["192.0.2.0/24".to_owned()]).unwrap()
    }

    #[test]
    fn url_is_scoped_to_the_allowlist() {
        let allow = allow();
        let url = crtsh_url("https://crt.sh", "example.com", &allow).unwrap();
        assert_eq!(url, "https://crt.sh/?q=%25.example.com&output=json");
        assert!(crtsh_url("https://crt.sh", "example.org", &allow).is_err());
        assert!(crtsh_url("https://crt.sh", "notexample.com", &allow).is_err());
    }

    #[test]
    fn parser_drops_names_outside_the_allowlist() {
        let body = r#"
        [
          {"name_value": "*.example.com\nexample.com"},
          {"name_value": "www.example.com"},
          {"common_name": "mail.example.com"},
          {"name_value": "evil.example.net"},
          {"name_value": "notexample.com"}
        ]
        "#;
        let parsed = parse_crtsh(body, &allow()).unwrap();
        assert_eq!(
            parsed.admitted,
            vec![
                "example.com".to_owned(),
                "mail.example.com".to_owned(),
                "www.example.com".to_owned(),
            ]
        );
        assert_eq!(parsed.dropped, 2);
    }
}
