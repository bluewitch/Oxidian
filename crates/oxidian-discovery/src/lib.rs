//! Passive discovery. Nothing in this crate opens a scan against a port.

#![forbid(unsafe_code)]

mod crtsh;
mod dns;

pub use crtsh::{crtsh_url, parse_crtsh, CertNames, CrtShClient};
pub use dns::{classify_addresses, gate_name, Classified, DnsResolver, Resolution};

use thiserror::Error;

/// Discovery failed closed or a feed could not be read.
#[derive(Debug, Error)]
pub enum Error {
    #[error("target is not on the allowlist")]
    NotAllowlisted,
    #[error("discovery URL is invalid")]
    BadUrl,
    #[error("certificate transparency request failed")]
    Http(#[source] reqwest::Error),
    #[error("certificate transparency response was not usable")]
    UnexpectedBody,
    #[error("response body exceeded the size limit")]
    BodyTooLarge,
    #[error("dns resolver could not be configured: {0}")]
    Resolver(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const MAX_BODY: usize = 8 * 1024 * 1024;

pub(crate) fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent("oxidian/0.1")
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(Error::Http)
}
