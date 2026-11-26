//! `oxidian` command line. Every subcommand refuses an empty allowlist.

#![forbid(unsafe_code)]

mod discover;
mod gate;
mod intel;
mod persist;
mod scan;
mod serve;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "oxidian", about = "Allowlist-only attack-surface mapper")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Look up certificate-transparency names and allowlisted addresses.
    Discover(ConfigArgs),
    /// Probe allowlisted networks with naabu and nmap -sV.
    Scan(ConfigArgs),
    /// Vulnerability intelligence feeds.
    Intel {
        #[command(subcommand)]
        command: IntelCommand,
    },
    /// Serve the inventory API.
    Serve(ConfigArgs),
}

#[derive(Subcommand)]
enum IntelCommand {
    /// Download KEV and one page of EPSS into the local cache.
    Sync(ConfigArgs),
}

#[derive(clap::Args, Debug)]
struct ConfigArgs {
    /// Path to the TOML configuration file.
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("oxidian: {err}");
            ExitCode::from(1)
        }
    }
}

async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Discover(args) => {
            let (config, allow) = gate::load(&args.config)?;
            discover::run(&config, &allow).await
        }
        Command::Scan(args) => {
            let (config, allow) = gate::load(&args.config)?;
            scan::run(&config, &allow).await
        }
        Command::Intel {
            command: IntelCommand::Sync(args),
        } => {
            let (config, _allow) = gate::load(&args.config)?;
            intel::sync(&config).await
        }
        Command::Serve(args) => {
            let (config, _allow) = gate::load(&args.config)?;
            serve::run(&config).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_lists_the_required_commands() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        assert!(help.contains("discover"));
        assert!(help.contains("scan"));
        assert!(help.contains("intel"));
        assert!(help.contains("serve"));
    }

    #[test]
    fn intel_sync_parses() {
        let cli =
            Cli::try_parse_from(["oxidian", "intel", "sync", "--config", "oxidian.toml"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Intel {
                command: IntelCommand::Sync(_)
            }
        ));
    }
}
