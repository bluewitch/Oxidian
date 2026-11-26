use std::collections::BTreeSet;

use oxidian_core::{Allowlist, Asset, Config};
use oxidian_discovery::{CrtShClient, DnsResolver};

use crate::persist;

pub async fn run(config: &Config, allow: &Allowlist) -> anyhow::Result<()> {
    let client = CrtShClient::new(&config.discovery.crtsh_base_url)?;
    let resolver = DnsResolver::system()?;
    let mut assets = Vec::new();
    let mut seen = BTreeSet::new();

    for domain in allow.domains() {
        let names = client.query_domain(domain, allow).await?;
        let mut admitted = names.admitted;
        if admitted.len() > config.discovery.max_names {
            eprintln!(
                "oxidian: certificate names for {domain} truncated to {}",
                config.discovery.max_names
            );
            admitted.truncate(config.discovery.max_names);
        }
        for name in admitted {
            if !seen.insert(name.clone()) {
                continue;
            }
            assets.push(Asset::domain(name.clone(), "certificate-transparency"));
            let resolution = resolver.resolve(&name, allow).await?;
            if let Some(error) = &resolution.error {
                eprintln!("oxidian: dns lookup failed for {name}: {error}");
            }
            if !resolution.dropped.is_empty() {
                eprintln!(
                    "oxidian: dropped {} address(es) for {name} outside the allowlist",
                    resolution.dropped.len()
                );
            }
            for address in resolution.admitted {
                assets.push(Asset::host(name.clone(), address, "dns"));
            }
        }
    }

    persist::store_assets(&assets).await?;
    println!("{}", serde_json::to_string_pretty(&assets)?);
    Ok(())
}
