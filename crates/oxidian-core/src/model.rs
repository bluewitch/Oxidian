use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// How serious a finding is, derived from CVSS and raised for KEV membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_cvss(score: Option<f64>) -> Self {
        let score = score.unwrap_or(0.0);
        if !score.is_finite() || score <= 0.0 {
            Self::Info
        } else if score >= 9.0 {
            Self::Critical
        } else if score >= 7.0 {
            Self::High
        } else if score >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub fn at_least(self, floor: Self) -> Self {
        if self < floor {
            floor
        } else {
            self
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            _ => Err(()),
        }
    }
}

/// Transport recorded for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Kind of inventoried asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetKind {
    Domain,
    Host,
    Address,
}

impl AssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Host => "host",
            Self::Address => "address",
        }
    }
}

impl std::str::FromStr for AssetKind {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "domain" => Ok(Self::Domain),
            "host" => Ok(Self::Host),
            "address" => Ok(Self::Address),
            _ => Err(()),
        }
    }
}

/// A name or address observed inside the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub name: String,
    pub kind: AssetKind,
    pub address: Option<IpAddr>,
    pub source: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

impl Asset {
    pub fn domain(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self::new(name.into(), AssetKind::Domain, None, source.into())
    }

    pub fn host(name: impl Into<String>, address: IpAddr, source: impl Into<String>) -> Self {
        Self::new(name.into(), AssetKind::Host, Some(address), source.into())
    }

    pub fn address(address: IpAddr, source: impl Into<String>) -> Self {
        Self::new(
            address.to_string(),
            AssetKind::Address,
            Some(address),
            source.into(),
        )
    }

    fn new(name: String, kind: AssetKind, address: Option<IpAddr>, source: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            kind,
            address,
            source,
            first_seen: now,
            last_seen: now,
        }
    }
}

/// An open port observed on an allowlisted address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub id: Uuid,
    pub asset_name: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub protocol: Protocol,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub observed_at: DateTime<Utc>,
}

impl Service {
    pub fn observed(
        asset_name: impl Into<String>,
        address: Option<IpAddr>,
        port: u16,
        protocol: Protocol,
        product: Option<String>,
        version: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            asset_name: asset_name.into(),
            address,
            port,
            protocol,
            product,
            version,
            banner: None,
            observed_at: Utc::now(),
        }
    }
}

/// A CVE that matched a service under the ranking rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub cve_id: String,
    pub asset_name: String,
    pub address: Option<IpAddr>,
    pub port: u16,
    pub protocol: Protocol,
    pub product: String,
    pub version: String,
    pub severity: Severity,
    pub kev: bool,
    pub epss: Option<f64>,
    pub cvss: Option<f64>,
    pub rank_score: f64,
    pub summary: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::Severity;

    #[test]
    fn cvss_bands_and_kev_floor() {
        assert_eq!(Severity::from_cvss(None), Severity::Info);
        assert_eq!(Severity::from_cvss(Some(0.0)), Severity::Info);
        assert_eq!(Severity::from_cvss(Some(3.9)), Severity::Low);
        assert_eq!(Severity::from_cvss(Some(4.0)), Severity::Medium);
        assert_eq!(Severity::from_cvss(Some(7.0)), Severity::High);
        assert_eq!(Severity::from_cvss(Some(9.0)), Severity::Critical);
        assert_eq!(Severity::from_cvss(Some(f64::NAN)), Severity::Info);
        assert_eq!(Severity::Low.at_least(Severity::High), Severity::High);
        assert_eq!(
            Severity::Critical.at_least(Severity::High),
            Severity::Critical
        );
    }
}
