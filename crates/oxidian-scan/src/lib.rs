//! Active service detection. Targets are checked against the allowlist
//! before any program is spawned, and tool output is checked again after.

#![forbid(unsafe_code)]

mod naabu;
mod nmap;
mod tool;

pub use naabu::{naabu_arguments, parse_naabu, NaabuRequest};
pub use nmap::{nmap_arguments, parse_nmap_xml, NmapRequest};
pub use tool::{active_targets, resolve_tool, retain_allowlisted, run_naabu, run_nmap, ToolError};

use thiserror::Error;

/// A scan could not be planned or a tool could not be read.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("target is not on the allowlist")]
    NotAllowlisted,
    #[error("allowlist has no CIDRs; active scans require an explicit network")]
    NoNetworks,
    #[error("scanner `{name}` was not found or is not executable")]
    ToolMissing { name: String },
    #[error("scan.ports may contain only digits, commas, and dashes")]
    BadPorts,
    #[error("scanner exited with status {status}")]
    ToolFailed { status: String },
    #[error("scanner produced too much output")]
    OutputTooLarge,
    #[error("scanner output was not valid {kind} at item {item}")]
    Parse { kind: &'static str, item: usize },
    #[error("scanner timed out")]
    Timeout,
    #[error("could not read scanner output")]
    Io,
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) const MAX_OUTPUT: usize = 32 * 1024 * 1024;

pub(crate) fn validate_ports(spec: &str) -> Result<()> {
    if spec.is_empty()
        || spec.len() > 256
        || !spec
            .chars()
            .all(|c| c.is_ascii_digit() || c == ',' || c == '-')
    {
        Err(Error::BadPorts)
    } else {
        Ok(())
    }
}
