use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use oxidian_core::{Allowlist, Config, Finding, Protocol, Service};
use oxidian_intel::{epss_index, kev_ids, DiskCache, EpssScore, KevRecord};
use oxidian_scan::{active_targets, resolve_tool, run_naabu, run_nmap, NaabuRequest, NmapRequest};
use serde::Serialize;
use uuid::Uuid;

use crate::persist;

#[derive(Serialize)]
struct Report<'a> {
    services: &'a [Service],
    findings: &'a [Finding],
}

pub async fn run(config: &Config, allow: &Allowlist) -> anyhow::Result<()> {
    let targets = active_targets(allow)?;
    resolve_tool(Path::new(&config.scan.naabu_path))?;
    resolve_tool(Path::new(&config.scan.nmap_path))?;
    let timeout = Duration::from_secs(config.scan.timeout_secs);
    let mut services = Vec::new();

    for target in &targets {
        let request = NaabuRequest {
            bin: Path::new(&config.scan.naabu_path),
            target,
            ports: &config.scan.ports,
            timeout,
        };
        let open = run_naabu(&request, allow).await?;
        services.extend(enrich(config, allow, open, timeout).await?);
    }

    let findings = assess(config, &services).await?;
    let stored = persist::store_services(&services).await?;
    let pairs = pair_findings(&stored, &findings);
    persist::store_findings(&pairs).await?;

    let report = Report {
        services: &services,
        findings: &findings,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);

    if let Ok(url) = std::env::var("OXIDIAN_WEBHOOK_URL") {
        if !url.trim().is_empty() {
            oxidian_alert::notify(&config.project.name, &findings, url.trim()).await?;
        }
    }
    Ok(())
}

async fn enrich(
    config: &Config,
    allow: &Allowlist,
    open: Vec<Service>,
    timeout: Duration,
) -> anyhow::Result<Vec<Service>> {
    let mut grouped: BTreeMap<(IpAddr, Protocol), Vec<u16>> = BTreeMap::new();
    let mut plain = Vec::new();
    for service in open {
        if let Some(address) = service.address {
            grouped
                .entry((address, service.protocol))
                .or_default()
                .push(service.port);
        } else {
            plain.push(service);
        }
    }
    for ((address, protocol), mut ports) in grouped {
        ports.sort_unstable();
        ports.dedup();
        if protocol != Protocol::Tcp {
            for port in ports {
                plain.push(Service::observed(
                    address.to_string(),
                    Some(address),
                    port,
                    protocol,
                    None,
                    None,
                ));
            }
            continue;
        }
        let mut detailed = Vec::new();
        for ports in port_groups(&ports) {
            let target = address.to_string();
            let request = NmapRequest {
                bin: Path::new(&config.scan.nmap_path),
                target: &target,
                ports: &ports,
                timeout,
            };
            detailed.extend(run_nmap(&request, allow).await?);
        }
        if detailed.is_empty() {
            for port in ports {
                plain.push(Service::observed(
                    address.to_string(),
                    Some(address),
                    port,
                    Protocol::Tcp,
                    None,
                    None,
                ));
            }
        } else {
            plain.extend(detailed);
        }
    }
    Ok(plain)
}

fn port_groups(ports: &[u16]) -> Vec<String> {
    let mut groups = Vec::new();
    let mut current = String::new();
    for port in ports {
        let piece = port.to_string();
        if !current.is_empty() && current.len() + 1 + piece.len() > 200 {
            groups.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(',');
        }
        current.push_str(&piece);
    }
    if !current.is_empty() {
        groups.push(current);
    }
    groups
}

async fn assess(config: &Config, services: &[Service]) -> anyhow::Result<Vec<Finding>> {
    if config.intel.advisories_path.is_empty() {
        return Ok(Vec::new());
    }
    let advisories = oxidian_match::load_advisories(Path::new(&config.intel.advisories_path))?;
    let cache = DiskCache::open(&config.intel.cache_dir)?;
    let kev = cache
        .load_json::<Vec<KevRecord>>("kev.json")?
        .unwrap_or_default();
    let epss = cache
        .load_json::<Vec<EpssScore>>("epss.json")?
        .unwrap_or_default();
    Ok(oxidian_match::match_services(
        services,
        &advisories,
        &kev_ids(&kev),
        &epss_index(&epss),
    ))
}

fn pair_findings<'a>(
    stored: &[(Uuid, Service)],
    findings: &'a [Finding],
) -> Vec<(Uuid, &'a Finding)> {
    let mut pairs = Vec::new();
    for finding in findings {
        if let Some((id, _)) = stored.iter().find(|(_, service)| {
            service.asset_name == finding.asset_name
                && service.port == finding.port
                && service.protocol == finding.protocol
        }) {
            pairs.push((*id, finding));
        }
    }
    pairs
}
