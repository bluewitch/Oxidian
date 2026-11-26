//! Outbound notifications. The webhook URL is never included in errors.

#![forbid(unsafe_code)]

use oxidian_core::Finding;
use serde::Serialize;
use thiserror::Error;

/// A notification could not be built or delivered.
#[derive(Debug, Error)]
pub enum Error {
    #[error("webhook URL is not set")]
    Missing,
    #[error("webhook URL must be http or https")]
    BadUrl,
    #[error("webhook request failed")]
    Http(#[source] reqwest::Error),
    #[error("webhook request failed with status {0}")]
    Status(u16),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Body accepted by Slack (`text`) and Discord (`content`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct WebhookBody {
    pub text: String,
    pub content: String,
}

pub fn render(project: &str, findings: &[Finding]) -> WebhookBody {
    let mut lines = vec![format!("oxidian {project}: {} finding(s)", findings.len())];
    for finding in findings.iter().take(10) {
        let kev = if finding.kev { " kev" } else { "" };
        lines.push(format!(
            "- {} {}{kev} {}:{} {} {}",
            finding.cve_id,
            finding.severity.as_str(),
            finding.asset_name,
            finding.port,
            finding.product,
            finding.version
        ));
    }
    if findings.len() > 10 {
        lines.push(format!("- {} more", findings.len() - 10));
    }
    let text = lines.join("\n");
    WebhookBody {
        content: text.clone(),
        text,
    }
}

pub fn parse_webhook_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).map_err(|_| Error::BadUrl)?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(Error::BadUrl);
    }
    if url.host_str().is_none() {
        return Err(Error::BadUrl);
    }
    Ok(url)
}

pub fn from_env(var_name: &str) -> Result<reqwest::Url> {
    let raw = std::env::var(var_name).map_err(|_| Error::Missing)?;
    if raw.trim().is_empty() {
        return Err(Error::Missing);
    }
    parse_webhook_url(raw.trim())
}

pub async fn send(url: &reqwest::Url, body: &WebhookBody) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent("oxidian/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(Error::Http)?;
    let response = client
        .post(url.clone())
        .json(body)
        .send()
        .await
        .map_err(Error::Http)?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::Status(response.status().as_u16()))
    }
}

pub async fn notify(project: &str, findings: &[Finding], url: &str) -> Result<()> {
    if findings.is_empty() {
        return Ok(());
    }
    let url = parse_webhook_url(url)?;
    send(&url, &render(project, findings)).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use oxidian_core::{Protocol, Severity};
    use uuid::Uuid;

    fn finding(kev: bool) -> Finding {
        Finding {
            id: Uuid::nil(),
            cve_id: "CVE-2099-9001".to_owned(),
            asset_name: "www.example.com".to_owned(),
            address: Some("192.0.2.10".parse().unwrap()),
            port: 80,
            protocol: Protocol::Tcp,
            product: "fixture".to_owned(),
            version: "1.2.0".to_owned(),
            severity: Severity::High,
            kev,
            epss: Some(0.5),
            cvss: Some(9.8),
            rank_score: 1.0,
            summary: "synthetic".to_owned(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn body_carries_slack_and_discord_fields() {
        let body = render("lab", &[finding(true)]);
        assert_eq!(body.text, body.content);
        assert!(body.text.contains("oxidian lab: 1 finding(s)"));
        assert!(body
            .text
            .contains("CVE-2099-9001 high kev www.example.com:80 fixture 1.2.0"));
        let json = serde_json::to_value(&body).unwrap();
        assert!(json.get("text").is_some());
        assert!(json.get("content").is_some());
    }

    #[test]
    fn urls_must_be_http() {
        assert!(parse_webhook_url("https://example.invalid/hook").is_ok());
        assert!(parse_webhook_url("file:///tmp/hook").is_err());
        assert!(parse_webhook_url("not a url").is_err());
    }
}
