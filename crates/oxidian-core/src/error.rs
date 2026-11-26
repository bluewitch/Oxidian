use std::path::PathBuf;

use thiserror::Error;

/// An allowlist entry or a candidate target failed a closed check.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AllowlistError {
    #[error("allowlist is empty; refusing to run")]
    Empty,
    #[error("invalid domain `{value}`")]
    Domain { value: String },
    #[error("invalid CIDR `{value}`")]
    Cidr { value: String },
    #[error("CIDR `{value}` is too broad")]
    CidrTooBroad { value: String },
    #[error("target is not on the allowlist")]
    NotAllowlisted,
}

/// Configuration file could not be read or failed validation.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config syntax: {0}")]
    Syntax(#[from] toml::de::Error),
    #[error("{0}")]
    Allowlist(#[from] AllowlistError),
    #[error("{0}")]
    Invalid(String),
}

/// Failure from an [`crate::Inventory`] implementation.
///
/// `detail` is for operator logs. HTTP responses use a fixed string.
#[derive(Debug, Error)]
#[error("inventory request failed")]
pub struct InventoryError {
    detail: String,
}

impl InventoryError {
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}
