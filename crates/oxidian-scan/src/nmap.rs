use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use oxidian_core::{Allowlist, Protocol, Service};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::{validate_ports, Error, Result};

/// What to pass to one nmap version scan.
#[derive(Debug, Clone)]
pub struct NmapRequest<'a> {
    pub bin: &'a Path,
    pub target: &'a str,
    pub ports: &'a str,
    pub timeout: Duration,
}

/// Argument vector for an unprivileged version scan. One string per argument.
pub fn nmap_arguments(target: &str, ports: &str) -> Vec<String> {
    vec![
        "-n".to_owned(),
        "-sT".to_owned(),
        "-sV".to_owned(),
        "-oX".to_owned(),
        "-".to_owned(),
        "-p".to_owned(),
        ports.to_owned(),
        "--".to_owned(),
        target.to_owned(),
    ]
}

/// Parse nmap XML and keep open tcp/udp ports.
pub fn parse_nmap_xml(input: &str) -> Result<Vec<Service>> {
    let mut reader = Reader::from_str(input);
    let mut services = Vec::new();
    let mut host = HostBuild::default();
    let mut port: Option<PortBuild> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) => {
                apply_tag(&tag, true, &mut host, &mut port, &mut services)?;
            }
            Ok(Event::Empty(tag)) => {
                apply_tag(&tag, false, &mut host, &mut port, &mut services)?;
            }
            Ok(Event::End(tag)) => {
                if local_name_end(&tag) == "port" {
                    if let Some(done) = port.take() {
                        push_open(&host, done, &mut services);
                    }
                } else if local_name_end(&tag) == "host" {
                    host = HostBuild::default();
                    port = None;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => {
                return Err(Error::Parse {
                    kind: "xml",
                    item: services.len() + 1,
                })
            }
            _ => {}
        }
    }
    Ok(services)
}

#[derive(Default)]
struct HostBuild {
    address: Option<IpAddr>,
    hostname: Option<String>,
}

struct PortBuild {
    protocol: Protocol,
    port: u16,
    state: Option<String>,
    product: Option<String>,
    version: Option<String>,
    banner: Option<String>,
}

fn apply_tag(
    tag: &quick_xml::events::BytesStart<'_>,
    has_children: bool,
    host: &mut HostBuild,
    port: &mut Option<PortBuild>,
    services: &mut Vec<Service>,
) -> Result<()> {
    match local_name(tag).as_str() {
        "host" if has_children => {
            *host = HostBuild::default();
            *port = None;
        }
        "address" => {
            if let Some(addr) = attr(tag, "addr").and_then(|value| value.parse().ok()) {
                if host.address.is_none() {
                    host.address = Some(addr);
                }
            }
        }
        "hostname" => {
            if host.hostname.is_none() {
                host.hostname = attr(tag, "name");
            }
        }
        "port" => {
            if let Some(previous) = port.take() {
                push_open(host, previous, services);
            }
            if let Some(built) = begin_port(tag) {
                if has_children {
                    *port = Some(built);
                } else {
                    push_open(host, built, services);
                }
            }
        }
        "state" => {
            if let Some(current) = port.as_mut() {
                current.state = attr(tag, "state");
            }
        }
        "service" => {
            if let Some(current) = port.as_mut() {
                current.product = attr(tag, "product");
                current.version = attr(tag, "version");
                current.banner = attr(tag, "extrainfo").map(|text| truncate_banner(&text));
            }
        }
        _ => {}
    }
    Ok(())
}

fn begin_port(tag: &quick_xml::events::BytesStart<'_>) -> Option<PortBuild> {
    let protocol = Protocol::parse(&attr(tag, "protocol")?)?;
    let port = attr(tag, "portid")?.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(PortBuild {
        protocol,
        port,
        state: None,
        product: None,
        version: None,
        banner: None,
    })
}

fn push_open(host: &HostBuild, port: PortBuild, services: &mut Vec<Service>) {
    if port.state.as_deref() != Some("open") {
        return;
    }
    let asset_name = host
        .hostname
        .clone()
        .or_else(|| host.address.map(|addr| addr.to_string()))
        .unwrap_or_default();
    if asset_name.is_empty() && host.address.is_none() {
        return;
    }
    let mut service = Service::observed(
        asset_name,
        host.address,
        port.port,
        port.protocol,
        port.product,
        port.version,
    );
    service.banner = port.banner;
    services.push(service);
}

fn local_name(tag: &quick_xml::events::BytesStart<'_>) -> String {
    tag.local_name().as_ref().to_ascii_lowercase()
}

fn local_name_end(tag: &quick_xml::events::BytesEnd<'_>) -> String {
    tag.local_name().as_ref().to_ascii_lowercase()
}

fn attr(tag: &quick_xml::events::BytesStart<'_>, key: &str) -> Option<String> {
    let attribute = tag.try_get_attribute(key).ok().flatten()?;
    let value = attribute
        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
        .ok()?;
    let text = value.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_owned())
    }
}

fn truncate_banner(text: &str) -> String {
    const LIMIT: usize = 512;
    if text.len() <= LIMIT {
        return text.to_owned();
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

pub(crate) fn prepare<'a>(
    request: &'a NmapRequest<'a>,
    allowlist: &Allowlist,
) -> Result<Vec<String>> {
    allowlist
        .require(request.target)
        .map_err(|_| Error::NotAllowlisted)?;
    validate_ports(request.ports)?;
    Ok(nmap_arguments(request.target, request.ports))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_not_a_shell_string() {
        let args = nmap_arguments("192.0.2.10", "80,443");
        assert!(args.contains(&"-sV".to_owned()));
        assert!(args.contains(&"-sT".to_owned()));
        assert!(args.contains(&"--".to_owned()));
        assert!(!args.iter().any(|arg| arg.contains(' ')));
        let weird = nmap_arguments("192.0.2.10;id", "80");
        assert!(weird.iter().any(|arg| arg == "192.0.2.10;id"));
        assert!(!weird.iter().any(|arg| arg == "id"));
    }

    #[test]
    fn parses_open_ports_only() {
        let xml = include_str!("../tests/fixtures/nmap.xml");
        let services = parse_nmap_xml(xml).unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].port, 80);
        assert_eq!(services[0].product.as_deref(), Some("nginx"));
        assert_eq!(services[0].version.as_deref(), Some("1.24.0"));
        assert_eq!(services[0].asset_name, "www.example.com");
        assert_eq!(services[1].port, 53);
        assert_eq!(services[1].protocol, Protocol::Udp);
        assert!(services.iter().all(|service| service.port != 22));
    }
}
