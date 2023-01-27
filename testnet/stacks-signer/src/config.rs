use clap::Parser;
use serde::Deserialize;
use std::fs;
use toml;

#[derive(Clone, Deserialize, Default, Debug)]
pub struct Config {
    pub common: Common,
    pub signer: Signer,
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct Common {
    pub stacks_node_url: String,
    pub total_signers: usize,
    pub total_parties: usize,
    pub minimum_parties: usize,
}

// on-disk format for frost save data
#[derive(Clone, Deserialize, Default, Debug)]
pub struct Signer {
    pub frost_id: u64,
    pub frost_state_file: String,
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    /// Start a signing round
    #[arg(short, long)]
    pub start: bool,

    /// Turn debugging information on
    #[arg(short, long)]
    id: Option<u64>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Config, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("Invalid path: {}", &e))?;
        Self::from_str(&content)
    }
    pub fn from_str(content: &str) -> Result<Config, String> {
        let config: Config = toml::from_str(content).map_err(|e| format!("Invalid toml: {}", e))?;
        Ok(config)
    }

    pub fn merge(&mut self, cli: &Cli) {
        if let Some(frost_id) = cli.id {
            self.signer.frost_id = frost_id;
        }
    }
}
