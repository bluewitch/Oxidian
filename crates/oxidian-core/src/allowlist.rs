use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::error::AllowlistError;

/// A single operator-declared target before it is compiled into an [`Allowlist`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String),
    Network(IpNet),
}

/// Closed set of domains and networks the operator authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    domains: BTreeSet<String>,
    networks: Vec<IpNet>,
}

impl Allowlist {
    /// Compile operator input. An empty input is a valid empty allowlist;
    /// callers that run work must use [`Allowlist::require_non_empty`].
    pub fn compile(domains: &[String], cidrs: &[String]) -> Result<Self, AllowlistError> {
        let mut compiled_domains = BTreeSet::new();
        for domain in domains {
            let normalized = normalize_domain(domain).ok_or_else(|| AllowlistError::Domain {
                value: truncate(domain),
            })?;
            compiled_domains.insert(normalized);
        }

        let mut networks = Vec::with_capacity(cidrs.len());
        for cidr in cidrs {
            let network: IpNet = cidr.trim().parse().map_err(|_| AllowlistError::Cidr {
                value: truncate(cidr),
            })?;
            if network.prefix_len() == 0 {
                return Err(AllowlistError::CidrTooBroad {
                    value: truncate(cidr),
                });
            }
            networks.push(network);
        }
        networks.sort_by_key(|network| (network.addr().is_ipv6(), network.to_string()));
        networks.dedup();

        Ok(Self {
            domains: compiled_domains,
            networks,
        })
    }

    pub fn require_non_empty(self) -> Result<Self, AllowlistError> {
        if self.is_empty() {
            Err(AllowlistError::Empty)
        } else {
            Ok(self)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.networks.is_empty()
    }

    pub fn domains(&self) -> impl Iterator<Item = &str> {
        self.domains.iter().map(String::as_str)
    }

    pub fn networks(&self) -> &[IpNet] {
        &self.networks
    }

    pub fn admits_domain(&self, name: &str) -> bool {
        let Some(name) = normalize_domain(name) else {
            return false;
        };
        if self.domains.contains(&name) {
            return true;
        }
        self.domains.iter().any(|root| is_subdomain(&name, root))
    }

    pub fn admits_ip(&self, address: IpAddr) -> bool {
        self.networks
            .iter()
            .any(|network| network.contains(&address))
    }

    pub fn admits_network(&self, network: IpNet) -> bool {
        self.networks
            .iter()
            .any(|allowed| network_covers(*allowed, network))
    }

    /// Admit a domain, address, or network string.
    pub fn admits(&self, target: &str) -> bool {
        let target = target.trim();
        if target.is_empty() || target.len() > 253 {
            return false;
        }
        if let Ok(address) = target.parse::<IpAddr>() {
            return self.admits_ip(address);
        }
        if let Ok(network) = target.parse::<IpNet>() {
            return self.admits_network(network);
        }
        self.admits_domain(target)
    }

    pub fn require(&self, target: &str) -> Result<(), AllowlistError> {
        if self.admits(target) {
            Ok(())
        } else {
            Err(AllowlistError::NotAllowlisted)
        }
    }
}

fn network_covers(outer: IpNet, inner: IpNet) -> bool {
    if outer.addr().is_ipv4() != inner.addr().is_ipv4() {
        return false;
    }
    outer.prefix_len() <= inner.prefix_len()
        && outer.contains(&inner.network())
        && outer.contains(&inner.broadcast())
}

fn is_subdomain(name: &str, root: &str) -> bool {
    name.len() > root.len()
        && name.ends_with(root)
        && name.as_bytes().get(name.len() - root.len() - 1) == Some(&b'.')
}

/// Lowercase a domain and reject anything that is not a plain DNS name.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.len() < 3 || trimmed.len() > 253 {
        return None;
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return None;
    }
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return None;
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return None;
        }
    }
    Some(trimmed)
}

fn truncate(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.chars().count() <= 80 {
        trimmed.to_owned()
    } else {
        let end = trimmed
            .char_indices()
            .nth(80)
            .map(|(idx, _)| idx)
            .unwrap_or(trimmed.len());
        format!("{}…", &trimmed[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Allowlist {
        Allowlist::compile(
            &["Example.COM.".to_owned()],
            &["192.0.2.0/24".to_owned(), "2001:db8::/32".to_owned()],
        )
        .unwrap()
    }

    #[test]
    fn domain_boundary_is_a_dot() {
        let allow = sample();
        assert!(allow.admits_domain("example.com"));
        assert!(allow.admits_domain("www.example.com"));
        assert!(allow.admits_domain("a.b.example.com."));
        assert!(!allow.admits_domain("notexample.com"));
        assert!(!allow.admits_domain("example.com.evil.test"));
        assert!(!allow.admits_domain("example.org"));
        assert!(!allow.admits_domain("*.example.com"));
    }

    #[test]
    fn addresses_and_nested_networks() {
        let allow = sample();
        let inside: IpAddr = "192.0.2.10".parse().unwrap();
        let outside: IpAddr = "198.51.100.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_out: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(allow.admits_ip(inside));
        assert!(!allow.admits_ip(outside));
        assert!(allow.admits_ip(v6));
        assert!(!allow.admits_ip(v6_out));
        assert!(allow.admits("192.0.2.10"));
        assert!(allow.admits("192.0.2.0/25"));
        assert!(!allow.admits("192.0.2.0/16"));
        assert!(!allow.admits("198.51.100.0/24"));
        assert!(allow.require("www.example.com").is_ok());
        assert!(allow.require("203.0.113.5").is_err());
    }

    #[test]
    fn rejects_broad_and_malformed_entries() {
        let err = Allowlist::compile(&[], &["0.0.0.0/0".to_owned()]).unwrap_err();
        assert!(matches!(err, AllowlistError::CidrTooBroad { .. }));
        assert!(Allowlist::compile(&["*.example.com".to_owned()], &[]).is_err());
        assert!(Allowlist::compile(&["com".to_owned()], &[]).is_err());
        assert!(Allowlist::compile(&["192.0.2.10".to_owned()], &[]).is_err());
        assert!(Allowlist::compile(&[], &["not-a-cidr".to_owned()]).is_err());
        let empty = Allowlist::compile(&[], &[]).unwrap();
        assert!(empty.is_empty());
        assert!(empty.clone().require_non_empty().is_err());
        assert!(!empty.admits("example.com"));
    }
}
