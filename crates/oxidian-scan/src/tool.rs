use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use oxidian_core::{Allowlist, Service};
use tokio::process::Command;

use crate::naabu::{self, NaabuRequest};
use crate::nmap::{self, NmapRequest};
use crate::{Error, Result, MAX_OUTPUT};

pub use crate::Error as ToolError;

/// CIDR strings the operator authorized for active probing.
pub fn active_targets(allowlist: &Allowlist) -> Result<Vec<String>> {
    let mut targets: Vec<String> = allowlist
        .networks()
        .iter()
        .map(ToString::to_string)
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        Err(Error::NoNetworks)
    } else {
        Ok(targets)
    }
}

/// Drop any parsed service whose name or address is outside the allowlist.
pub fn retain_allowlisted(services: Vec<Service>, allowlist: &Allowlist) -> Vec<Service> {
    services
        .into_iter()
        .filter(|service| service_allowed(service, allowlist))
        .collect()
}

fn service_allowed(service: &Service, allowlist: &Allowlist) -> bool {
    if service.port == 0 {
        return false;
    }
    let address_ok = match service.address {
        Some(address) => allowlist.admits_ip(address),
        None => true,
    };
    let name_ok = if service.asset_name.is_empty() {
        service.address.is_some()
    } else if service.asset_name.parse::<std::net::IpAddr>().is_ok() {
        allowlist.admits(&service.asset_name)
    } else {
        allowlist.admits_domain(&service.asset_name)
    };
    address_ok && name_ok && (service.address.is_some() || !service.asset_name.is_empty())
}

/// Run naabu and return allowlisted open ports. Fails before spawn when the
/// target is not allowlisted or the binary is missing.
pub async fn run_naabu(request: &NaabuRequest<'_>, allowlist: &Allowlist) -> Result<Vec<Service>> {
    let args = naabu::prepare(request, allowlist)?;
    let bin = resolve_tool(request.bin)?;
    let stdout = run_command(&bin, &args, request.timeout).await?;
    let parsed = crate::parse_naabu(&stdout)?;
    Ok(retain_allowlisted(parsed, allowlist))
}

/// Run `nmap -sV` and return allowlisted open services.
pub async fn run_nmap(request: &NmapRequest<'_>, allowlist: &Allowlist) -> Result<Vec<Service>> {
    let args = nmap::prepare(request, allowlist)?;
    let bin = resolve_tool(request.bin)?;
    let stdout = run_command(&bin, &args, request.timeout).await?;
    let parsed = crate::parse_nmap_xml(&stdout)?;
    Ok(retain_allowlisted(parsed, allowlist))
}

pub fn resolve_tool(name: &Path) -> Result<PathBuf> {
    let display = name.display().to_string();
    if display.is_empty() || display.contains('\0') {
        return Err(Error::ToolMissing { name: display });
    }
    if name.components().count() > 1 || name.is_absolute() {
        return check_executable(name);
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::ToolMissing { name: display })
}

fn check_executable(path: &Path) -> Result<PathBuf> {
    if is_executable(path) {
        Ok(path.to_path_buf())
    } else {
        Err(Error::ToolMissing {
            name: path.display().to_string(),
        })
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    executable_bit(&meta)
}

#[cfg(unix)]
fn executable_bit(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable_bit(meta: &fs::Metadata) -> bool {
    let _ = meta;
    true
}

async fn run_command(bin: &Path, args: &[String], timeout: Duration) -> Result<String> {
    let mut command = Command::new(bin);
    command
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let output = tokio::time::timeout(timeout, command.output())
        .await
        .map_err(|_| Error::Timeout)?
        .map_err(|_| Error::Io)?;
    if output.stdout.len() > MAX_OUTPUT {
        return Err(Error::OutputTooLarge);
    }
    if !output.status.success() {
        return Err(Error::ToolFailed {
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_owned()),
        });
    }
    String::from_utf8(output.stdout).map_err(|_| Error::Parse {
        kind: "text",
        item: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxidian_core::Protocol;

    #[test]
    fn domain_only_allowlist_cannot_start_a_scan() {
        let allow = Allowlist::compile(&["example.com".to_owned()], &[]).unwrap();
        assert_eq!(active_targets(&allow).unwrap_err(), Error::NoNetworks);
    }

    #[test]
    fn cidr_targets_are_the_allowlisted_networks() {
        let allow =
            Allowlist::compile(&["example.com".to_owned()], &["192.0.2.0/24".to_owned()]).unwrap();
        assert_eq!(
            active_targets(&allow).unwrap(),
            vec!["192.0.2.0/24".to_owned()]
        );
    }

    #[test]
    fn retain_drops_addresses_outside_the_allowlist() {
        let allow =
            Allowlist::compile(&["example.com".to_owned()], &["192.0.2.0/24".to_owned()]).unwrap();
        let input = crate::parse_naabu(include_str!("../tests/fixtures/naabu.json")).unwrap();
        let kept = retain_allowlisted(input, &allow);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().all(|service| {
            service
                .address
                .map(|addr| allow.admits_ip(addr))
                .unwrap_or(false)
        }));
        assert!(kept.iter().all(|service| service.protocol == Protocol::Tcp));
    }

    #[test]
    fn missing_binary_is_reported_clearly() {
        let err = resolve_tool(Path::new("naabu-not-installed-oxidian")).unwrap_err();
        assert_eq!(
            err,
            Error::ToolMissing {
                name: "naabu-not-installed-oxidian".to_owned()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn absolute_path_must_be_an_executable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("oxidian-tool-{}", uuid_ish()));
        fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("fixture-tool");
        fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();
        assert!(resolve_tool(&binary).is_ok());

        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&binary, permissions).unwrap();
        assert!(matches!(
            resolve_tool(&binary),
            Err(Error::ToolMissing { .. })
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    fn uuid_ish() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_string()
    }

    #[tokio::test]
    async fn unlisted_target_never_reaches_the_binary_check() {
        let allow = Allowlist::compile(&[], &["192.0.2.0/24".to_owned()]).unwrap();
        let request = NaabuRequest {
            bin: Path::new("this-binary-does-not-exist-oxidian"),
            target: "203.0.113.5",
            ports: "80",
            timeout: Duration::from_secs(1),
        };
        let err = run_naabu(&request, &allow).await.unwrap_err();
        assert_eq!(err, Error::NotAllowlisted);
    }
}
