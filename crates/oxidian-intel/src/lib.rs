//! Vulnerability feeds. Network functions are separate from parsers so tests
//! can use fixture documents.

#![forbid(unsafe_code)]

mod cache;
mod epss;
mod kev;
mod nvd;

pub use cache::DiskCache;
pub use epss::{parse_epss, EpssScore};
pub use kev::{parse_kev, KevRecord};
pub use nvd::NvdClient;

use std::collections::{HashMap, HashSet};

use thiserror::Error;

/// A feed could not be fetched, parsed, or cached.
#[derive(Debug, Error)]
pub enum Error {
    #[error("feed URL is invalid")]
    BadUrl,
    #[error("feed request failed")]
    Http(#[source] reqwest::Error),
    #[error("feed returned HTTP {0}")]
    Status(u16),
    #[error("feed body exceeded the size limit")]
    BodyTooLarge,
    #[error("feed body was not valid")]
    Parse,
    #[error("cache path was rejected")]
    Cache,
    #[error("{0}")]
    Match(#[from] oxidian_match::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const MAX_BODY: usize = 8 * 1024 * 1024;

pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("oxidian/0.1")
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(Error::Http)
}

pub fn kev_ids(records: &[KevRecord]) -> HashSet<String> {
    records.iter().map(|record| record.cve_id.clone()).collect()
}

pub fn epss_index(scores: &[EpssScore]) -> HashMap<String, f64> {
    scores
        .iter()
        .map(|score| (score.cve_id.clone(), score.score))
        .collect()
}

/// Download KEV and one EPSS page. Callers persist the normalized rows.
pub async fn sync_feeds(
    kev_url: &str,
    epss_url: &str,
    limit: u32,
) -> Result<(Vec<KevRecord>, Vec<EpssScore>)> {
    let client = http_client()?;
    let kev = fetch_kev(&client, kev_url).await?;
    let epss = fetch_epss(&client, epss_url, limit).await?;
    Ok((kev, epss))
}

pub async fn fetch_kev(client: &reqwest::Client, url: &str) -> Result<Vec<KevRecord>> {
    let bytes = get_bytes(client, url).await?;
    parse_kev(&bytes)
}

pub async fn fetch_epss(
    client: &reqwest::Client,
    base: &str,
    limit: u32,
) -> Result<Vec<EpssScore>> {
    if !(1..=1000).contains(&limit) {
        return Err(Error::BadUrl);
    }
    let url = if base.contains('?') {
        format!("{base}&limit={limit}")
    } else {
        format!("{base}?limit={limit}")
    };
    let bytes = get_bytes(client, &url).await?;
    parse_epss(&bytes)
}

async fn get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(Error::BadUrl);
    }
    let response = client.get(url).send().await.map_err(Error::Http)?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Status(status.as_u16()));
    }
    let bytes = response.bytes().await.map_err(Error::Http)?;
    if bytes.len() > MAX_BODY {
        return Err(Error::BodyTooLarge);
    }
    Ok(bytes.to_vec())
}
