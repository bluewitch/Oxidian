use std::net::IpAddr;

use hickory_resolver::TokioResolver;
use oxidian_core::Allowlist;

use crate::{Error, Result};

/// Addresses from one lookup, split by the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub admitted: Vec<IpAddr>,
    pub dropped: Vec<IpAddr>,
}

/// Outcome of resolving a single allowlisted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub name: String,
    pub admitted: Vec<IpAddr>,
    pub dropped: Vec<IpAddr>,
    pub error: Option<String>,
}

/// Refuse to resolve a name the allowlist does not admit.
pub fn gate_name(name: &str, allowlist: &Allowlist) -> Result<()> {
    if allowlist.admits_domain(name) {
        Ok(())
    } else {
        Err(Error::NotAllowlisted)
    }
}

/// Split a resolver answer. The caller has already gated the queried name.
pub fn classify_addresses(
    addresses: impl IntoIterator<Item = IpAddr>,
    allowlist: &Allowlist,
) -> Classified {
    let mut admitted = Vec::new();
    let mut dropped = Vec::new();
    for address in addresses {
        if allowlist.admits_ip(address) {
            admitted.push(address);
        } else {
            dropped.push(address);
        }
    }
    Classified { admitted, dropped }
}

/// System-resolver DNS client. Resolver addresses come from the host configuration.
pub struct DnsResolver {
    inner: TokioResolver,
}

impl DnsResolver {
    pub fn system() -> Result<Self> {
        let inner = TokioResolver::builder_tokio()
            .map_err(|err| Error::Resolver(brief(err.to_string())))?
            .build()
            .map_err(|err| Error::Resolver(brief(err.to_string())))?;
        Ok(Self { inner })
    }

    pub async fn resolve(&self, name: &str, allowlist: &Allowlist) -> Result<Resolution> {
        gate_name(name, allowlist)?;
        let name = oxidian_core::normalize_domain(name).ok_or(Error::NotAllowlisted)?;
        match self.inner.lookup_ip(name.as_str()).await {
            Ok(lookup) => {
                let classified = classify_addresses(lookup.iter(), allowlist);
                Ok(Resolution {
                    name,
                    admitted: classified.admitted,
                    dropped: classified.dropped,
                    error: None,
                })
            }
            Err(err) => Ok(Resolution {
                name,
                admitted: Vec::new(),
                dropped: Vec::new(),
                error: Some(brief(err.to_string())),
            }),
        }
    }
}

fn brief(message: String) -> String {
    clip(&message, 200)
}

fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Allowlist {
        Allowlist::compile(&["example.com".to_owned()], &["192.0.2.0/24".to_owned()]).unwrap()
    }

    #[test]
    fn gate_rejects_unlisted_names_without_a_query() {
        assert!(gate_name("www.example.com", &allow()).is_ok());
        assert!(gate_name("example.org", &allow()).is_err());
        assert!(gate_name("notexample.com", &allow()).is_err());
    }

    #[test]
    fn classification_keeps_only_allowlisted_answers() {
        let admitted_ip: IpAddr = "192.0.2.10".parse().unwrap();
        let dropped_ip: IpAddr = "198.51.100.10".parse().unwrap();
        let classified = classify_addresses([admitted_ip, dropped_ip], &allow());
        assert_eq!(classified.admitted, vec![admitted_ip]);
        assert_eq!(classified.dropped, vec![dropped_ip]);
    }
}
