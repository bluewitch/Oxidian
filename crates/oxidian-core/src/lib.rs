//! Shared models, allowlist, and configuration.
//!
//! This crate does not open sockets or spawn programs.

#![forbid(unsafe_code)]

mod allowlist;
mod config;
mod error;
mod inventory;
mod model;

pub use allowlist::{normalize_domain, Allowlist, Target};
pub use config::{
    AllowlistSection, ApiSection, Config, DiscoverySection, IntelSection, ProjectSection,
    ScanSection,
};
pub use error::{AllowlistError, ConfigError, InventoryError};
pub use inventory::Inventory;
pub use model::{Asset, AssetKind, Finding, Protocol, Service, Severity};

/// Canonical `CVE-YYYY-NNNN` form, or `None` when `raw` is not that shape.
pub fn canonical_cve(raw: &str) -> Option<String> {
    let upper = raw.trim().to_ascii_uppercase();
    let rest = upper.strip_prefix("CVE-")?;
    let (year, number) = rest.split_once('-')?;
    if year.len() != 4 || !year.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !(4..=7).contains(&number.len()) || !number.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(upper)
}

#[cfg(test)]
mod tests {
    use super::canonical_cve;

    #[test]
    fn accepts_canonical_ids_and_rejects_noise() {
        assert_eq!(
            canonical_cve("cve-2099-9001"),
            Some("CVE-2099-9001".to_owned())
        );
        assert_eq!(
            canonical_cve("CVE-2099-1234567"),
            Some("CVE-2099-1234567".to_owned())
        );
        assert!(canonical_cve("CVE-99-9001").is_none());
        assert!(canonical_cve("CVE-2099-12").is_none());
        assert!(canonical_cve("not-a-cve").is_none());
        assert!(canonical_cve("CVE-2099-9001;id").is_none());
    }
}
