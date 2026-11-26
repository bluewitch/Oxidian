use std::path::{Component, Path};

use serde::Deserialize;

use crate::allowlist::Allowlist;
use crate::error::{AllowlistError, ConfigError};

/// Operator configuration. Secrets are not fields on this struct.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub project: ProjectSection,
    pub allowlist: AllowlistSection,
    #[serde(default)]
    pub discovery: DiscoverySection,
    #[serde(default)]
    pub scan: ScanSection,
    #[serde(default)]
    pub intel: IntelSection,
    #[serde(default)]
    pub api: ApiSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectSection {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistSection {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySection {
    #[serde(default = "default_crtsh")]
    pub crtsh_base_url: String,
    #[serde(default = "default_max_names")]
    pub max_names: usize,
}

impl Default for DiscoverySection {
    fn default() -> Self {
        Self {
            crtsh_base_url: default_crtsh(),
            max_names: default_max_names(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSection {
    #[serde(default = "default_naabu")]
    pub naabu_path: String,
    #[serde(default = "default_nmap")]
    pub nmap_path: String,
    #[serde(default = "default_ports")]
    pub ports: String,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

impl Default for ScanSection {
    fn default() -> Self {
        Self {
            naabu_path: default_naabu(),
            nmap_path: default_nmap(),
            ports: default_ports(),
            timeout_secs: default_timeout(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntelSection {
    #[serde(default = "default_kev")]
    pub kev_url: String,
    #[serde(default = "default_epss")]
    pub epss_url: String,
    #[serde(default = "default_nvd")]
    pub nvd_url: String,
    #[serde(default = "default_cache")]
    pub cache_dir: String,
    #[serde(default = "default_epss_limit")]
    pub epss_limit: u32,
    #[serde(default)]
    pub advisories_path: String,
}

impl Default for IntelSection {
    fn default() -> Self {
        Self {
            kev_url: default_kev(),
            epss_url: default_epss(),
            nvd_url: default_nvd(),
            cache_dir: default_cache(),
            epss_limit: default_epss_limit(),
            advisories_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiSection {
    #[serde(default = "default_bind")]
    pub bind: String,
}

impl Default for ApiSection {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

fn default_crtsh() -> String {
    "https://crt.sh".to_owned()
}
fn default_max_names() -> usize {
    200
}
fn default_naabu() -> String {
    "naabu".to_owned()
}
fn default_nmap() -> String {
    "nmap".to_owned()
}
fn default_ports() -> String {
    "22,80,443,8080,8443".to_owned()
}
fn default_timeout() -> u64 {
    300
}
fn default_kev() -> String {
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".to_owned()
}
fn default_epss() -> String {
    "https://api.first.org/data/v1/epss".to_owned()
}
fn default_nvd() -> String {
    "https://services.nvd.nist.gov/rest/json/cves/2.0".to_owned()
}
fn default_cache() -> String {
    ".oxidian/cache".to_owned()
}
fn default_epss_limit() -> u32 {
    100
}
fn default_bind() -> String {
    "127.0.0.1:8080".to_owned()
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Allowlist for callers that only need to know whether work is authorized.
    pub fn allowlist(&self) -> Result<Allowlist, AllowlistError> {
        Allowlist::compile(&self.allowlist.domains, &self.allowlist.cidrs)?.require_non_empty()
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_project_name(&self.project.name)?;
        let _ = Allowlist::compile(&self.allowlist.domains, &self.allowlist.cidrs)?;
        validate_http_url("discovery.crtsh_base_url", &self.discovery.crtsh_base_url)?;
        if self.discovery.max_names == 0 || self.discovery.max_names > 10_000 {
            return Err(ConfigError::Invalid(
                "discovery.max_names must be between 1 and 10000".to_owned(),
            ));
        }
        validate_ports(&self.scan.ports)?;
        validate_tool_name("scan.naabu_path", &self.scan.naabu_path)?;
        validate_tool_name("scan.nmap_path", &self.scan.nmap_path)?;
        if !(1..=3600).contains(&self.scan.timeout_secs) {
            return Err(ConfigError::Invalid(
                "scan.timeout_secs must be between 1 and 3600".to_owned(),
            ));
        }
        validate_http_url("intel.kev_url", &self.intel.kev_url)?;
        validate_http_url("intel.epss_url", &self.intel.epss_url)?;
        validate_http_url("intel.nvd_url", &self.intel.nvd_url)?;
        if !(1..=1000).contains(&self.intel.epss_limit) {
            return Err(ConfigError::Invalid(
                "intel.epss_limit must be between 1 and 1000".to_owned(),
            ));
        }
        reject_parent_dirs("intel.cache_dir", &self.intel.cache_dir)?;
        if !self.intel.advisories_path.is_empty() {
            reject_parent_dirs("intel.advisories_path", &self.intel.advisories_path)?;
        }
        self.api
            .bind
            .parse::<std::net::SocketAddr>()
            .map_err(|_| ConfigError::Invalid("api.bind must be a socket address".to_owned()))?;
        Ok(())
    }
}

fn validate_project_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ConfigError::Invalid(
            "project.name must be 1 to 64 characters".to_owned(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '-' || c == '_')
    {
        return Err(ConfigError::Invalid(
            "project.name has unsupported characters".to_owned(),
        ));
    }
    Ok(())
}

pub fn validate_ports(spec: &str) -> Result<(), ConfigError> {
    if spec.is_empty() || spec.len() > 256 {
        return Err(ConfigError::Invalid(
            "scan.ports must be 1 to 256 characters".to_owned(),
        ));
    }
    if !spec
        .chars()
        .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
    {
        return Err(ConfigError::Invalid(
            "scan.ports may contain only digits, commas, and dashes".to_owned(),
        ));
    }
    Ok(())
}

fn validate_tool_name(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(format!(
            "{field} must be a non-empty path"
        )));
    }
    Ok(())
}

fn validate_http_url(field: &str, value: &str) -> Result<(), ConfigError> {
    let Some((scheme, rest)) = value.split_once("://") else {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an http or https URL"
        )));
    };
    if scheme != "https" && scheme != "http" {
        return Err(ConfigError::Invalid(format!(
            "{field} must be an http or https URL"
        )));
    }
    if rest.is_empty() || rest.chars().any(char::is_control) || rest.contains(' ') {
        return Err(ConfigError::Invalid(format!("{field} is not a usable URL")));
    }
    Ok(())
}

fn reject_parent_dirs(field: &str, value: &str) -> Result<(), ConfigError> {
    if value.is_empty() || value.len() > 256 {
        return Err(ConfigError::Invalid(format!(
            "{field} is empty or too long"
        )));
    }
    let path = Path::new(value);
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ConfigError::Invalid(format!(
            "{field} must not contain '..'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_loads_and_authorizes_documentation_ranges() {
        let text = include_str!("../../../examples/lab.toml");
        let config = Config::parse(text).unwrap();
        let allow = config.allowlist().unwrap();
        assert!(allow.admits_domain("www.example.com"));
        assert!(allow.admits("192.0.2.15"));
        assert!(!allow.admits("198.51.100.1"));
        assert_eq!(config.project.name, "lab");
        assert_eq!(config.api.bind, "127.0.0.1:8080");
    }

    #[test]
    fn empty_allowlist_parses_and_refuses_to_run() {
        let text = r#"
            [project]
            name = "lab"
            [allowlist]
        "#;
        let config = Config::parse(text).unwrap();
        assert!(matches!(config.allowlist(), Err(AllowlistError::Empty)));
    }

    #[test]
    fn rejects_shell_ports_and_parent_paths() {
        let text = r#"
            [project]
            name = "lab"
            [allowlist]
            domains = ["example.com"]
            [scan]
            ports = "80;id"
        "#;
        assert!(Config::parse(text).is_err());

        let text = r#"
            [project]
            name = "lab"
            [allowlist]
            cidrs = ["192.0.2.0/24"]
            [intel]
            cache_dir = "../outside"
        "#;
        assert!(Config::parse(text).is_err());
    }
}
