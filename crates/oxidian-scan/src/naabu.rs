use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use oxidian_core::{Allowlist, Protocol, Service};
use serde::Deserialize;

use crate::{validate_ports, Error, Result};

/// What to pass to one naabu invocation.
#[derive(Debug, Clone)]
pub struct NaabuRequest<'a> {
    pub bin: &'a Path,
    pub target: &'a str,
    pub ports: &'a str,
    pub timeout: Duration,
}

/// Argument vector for a connect-scan JSON run. One string per argument.
pub fn naabu_arguments(target: &str, ports: &str) -> Vec<String> {
    vec![
        "-host".to_owned(),
        target.to_owned(),
        "-p".to_owned(),
        ports.to_owned(),
        "-json".to_owned(),
        "-silent".to_owned(),
        "-scan-type".to_owned(),
        "c".to_owned(),
    ]
}

#[derive(Debug, Deserialize)]
struct Row {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    host: Option<String>,
    port: u16,
    #[serde(default)]
    protocol: Option<String>,
}

/// Parse naabu JSON. Accepts one object, an array, or NDJSON.
pub fn parse_naabu(input: &str) -> Result<Vec<Service>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if trimmed.starts_with('[') {
        let rows: Vec<Row> = serde_json::from_str(trimmed).map_err(|_| Error::Parse {
            kind: "json",
            item: 0,
        })?;
        return rows
            .into_iter()
            .enumerate()
            .map(|(idx, row)| {
                row_to_service(row).map_err(|_| Error::Parse {
                    kind: "json",
                    item: idx + 1,
                })
            })
            .collect();
    }
    if trimmed.starts_with('{') && !trimmed.contains('\n') {
        let row: Row = serde_json::from_str(trimmed).map_err(|_| Error::Parse {
            kind: "json",
            item: 1,
        })?;
        return Ok(vec![row_to_service(row).map_err(|_| Error::Parse {
            kind: "json",
            item: 1,
        })?]);
    }
    let mut services = Vec::new();
    for (idx, line) in trimmed.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row: Row = serde_json::from_str(line).map_err(|_| Error::Parse {
            kind: "json",
            item: idx + 1,
        })?;
        services.push(row_to_service(row).map_err(|_| Error::Parse {
            kind: "json",
            item: idx + 1,
        })?);
    }
    Ok(services)
}

fn row_to_service(row: Row) -> std::result::Result<Service, ()> {
    if row.port == 0 {
        return Err(());
    }
    let protocol = Protocol::parse(row.protocol.as_deref().unwrap_or("tcp")).ok_or(())?;
    let address = match row.ip.as_deref() {
        Some(ip) => Some(ip.parse::<IpAddr>().map_err(|_| ())?),
        None => None,
    };
    let asset_name = row
        .host
        .filter(|host| !host.trim().is_empty())
        .or_else(|| address.map(|ip| ip.to_string()))
        .ok_or(())?;
    Ok(Service::observed(
        asset_name, address, row.port, protocol, None, None,
    ))
}

pub(crate) fn prepare<'a>(
    request: &'a NaabuRequest<'a>,
    allowlist: &Allowlist,
) -> Result<Vec<String>> {
    allowlist
        .require(request.target)
        .map_err(|_| Error::NotAllowlisted)?;
    validate_ports(request.ports)?;
    Ok(naabu_arguments(request.target, request.ports))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_stay_one_element_even_with_metacharacters() {
        let args = naabu_arguments("192.0.2.10;id", "80");
        assert!(args.iter().any(|arg| arg == "192.0.2.10;id"));
        assert!(!args.iter().any(|arg| arg == "id"));
        assert_eq!(args.iter().filter(|arg| arg.contains(' ')).count(), 0);
    }

    #[test]
    fn parses_ndjson_fixture() {
        let input = include_str!("../tests/fixtures/naabu.json");
        let services = parse_naabu(input).unwrap();
        assert_eq!(services.len(), 3);
        assert_eq!(services[0].port, 80);
        assert_eq!(services[0].asset_name, "www.example.com");
        assert_eq!(
            services[0].address,
            Some("192.0.2.10".parse::<IpAddr>().unwrap())
        );
        assert_eq!(services[2].port, 22);
    }

    #[test]
    fn prepare_rejects_a_target_that_is_not_allowlisted() {
        let allow = Allowlist::compile(&[], &["192.0.2.0/24".to_owned()]).unwrap();
        let request = NaabuRequest {
            bin: Path::new("naabu"),
            target: "203.0.113.5",
            ports: "80",
            timeout: Duration::from_secs(5),
        };
        assert_eq!(
            prepare(&request, &allow).unwrap_err(),
            Error::NotAllowlisted
        );
    }
}
