// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::PathBuf;

use blockstack_lib::chainstate::stacks::address::PoxAddress;
use blockstack_lib::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;
use clap::{Parser, ValueEnum};
use clarity::vm::types::QualifiedContractIdentifier;
use stacks_common::address::b58;
use stacks_common::types::chainstate::StacksPrivateKey;

use crate::config::Network;

extern crate alloc;

#[derive(Parser, Debug)]
#[command(author, version, about)]
/// The CLI arguments for the stacks signer
pub struct Cli {
    /// Subcommand action to take
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands for the stacks signer binary
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Get a chunk from the stacker-db instance
    GetChunk(GetChunkArgs),
    /// Get the latest chunk from the stacker-db instance
    GetLatestChunk(GetLatestChunkArgs),
    /// List chunks from the stacker-db instance
    ListChunks(StackerDBArgs),
    /// Upload a chunk to the stacker-db instance
    PutChunk(PutChunkArgs),
    /// Run DKG and sign the message through the stacker-db instance
    DkgSign(SignArgs),
    /// Sign the message through the stacker-db instance
    Sign(SignArgs),
    /// Run a DKG round through the stacker-db instance
    Dkg(RunDkgArgs),
    /// Run the signer, waiting for events from the stacker-db instance
    Run(RunDkgArgs),
    /// Generate necessary files for running a collection of signers
    GenerateFiles(GenerateFilesArgs),
    /// Generate a signature for Stacking transactions
    GenerateStackingSignature(GenerateStackingSignatureArgs),
}

/// Basic arguments for all cyrptographic and stacker-db functionality
#[derive(Parser, Debug, Clone)]
pub struct StackerDBArgs {
    /// The Stacks node to connect to
    #[arg(long)]
    pub host: SocketAddr,
    /// The stacker-db contract to use. Must be in the format of "STACKS_ADDRESS.CONTRACT_NAME"
    #[arg(short, long, value_parser = parse_contract)]
    pub contract: QualifiedContractIdentifier,
}

/// Arguments for the get-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    pub slot_version: u32,
}

/// Arguments for the get-latest-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetLatestChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the put-chunk command
pub struct PutChunkArgs {
    /// The base arguments
    #[clap(flatten)]
    pub db_args: StackerDBArgs,
    /// The Stacks private key to use in hexademical format
    #[arg(short, long, value_parser = parse_private_key)]
    pub private_key: StacksPrivateKey,
    /// The slot ID to get
    #[arg(long)]
    pub slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    pub slot_version: u32,
    /// The data to upload
    #[arg(required = false, value_parser = parse_data)]
    // Note this weirdness is due to https://github.com/clap-rs/clap/discussions/4695
    // Need to specify the long name here due to invalid parsing in Clap which looks at the NAME rather than the TYPE which causes issues in how it handles Vec's.
    pub data: alloc::vec::Vec<u8>,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the dkg-sign and sign command
pub struct SignArgs {
    /// Path to config file
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// The reward cycle the signer is registered for and wants to sign for
    /// Note: this must be the current reward cycle of the node
    #[arg(long, short)]
    pub reward_cycle: u64,
    /// The data to sign
    #[arg(required = false, value_parser = parse_data)]
    // Note this weirdness is due to https://github.com/clap-rs/clap/discussions/4695
    // Need to specify the long name here due to invalid parsing in Clap which looks at the NAME rather than the TYPE which causes issues in how it handles Vec's.
    pub data: alloc::vec::Vec<u8>,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the Run and Dkg commands
pub struct RunDkgArgs {
    /// Path to config file
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// The reward cycle the signer is registered for and wants to peform DKG for
    #[arg(long, short)]
    pub reward_cycle: u64,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the generate-files command
pub struct GenerateFilesArgs {
    /// The Stacks node to connect to
    #[arg(long)]
    pub host: SocketAddr,
    #[arg(
        long,
        required_unless_present = "private_keys",
        conflicts_with = "private_keys"
    )]
    /// The number of signers to generate
    pub num_signers: Option<u32>,
    #[clap(long, value_name = "FILE")]
    /// A path to a file containing a list of hexadecimal Stacks private keys of the signers
    pub private_keys: Option<PathBuf>,
    #[arg(long, value_parser = parse_network)]
    /// The network to use. One of "mainnet", "testnet", or "mocknet".
    pub network: Network,
    /// The directory to write the test data files to
    #[arg(long, default_value = ".")]
    pub dir: PathBuf,
    /// The number of milliseconds to wait when polling for events from the stacker-db instance.
    #[arg(long)]
    pub timeout: Option<u64>,
}

#[derive(Clone, Debug)]
/// Wrapper around `Pox4SignatureTopic` to implement `ValueEnum`
pub struct StackingSignatureMethod(Pox4SignatureTopic);

impl StackingSignatureMethod {
    /// Get the inner `Pox4SignatureTopic`
    pub fn topic(&self) -> &Pox4SignatureTopic {
        &self.0
    }
}

impl From<Pox4SignatureTopic> for StackingSignatureMethod {
    fn from(topic: Pox4SignatureTopic) -> Self {
        StackingSignatureMethod(topic)
    }
}

impl ValueEnum for StackingSignatureMethod {
    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new(self.0.get_name_str()))
    }

    fn value_variants<'a>() -> &'a [Self] {
        &[
            StackingSignatureMethod(Pox4SignatureTopic::StackStx),
            StackingSignatureMethod(Pox4SignatureTopic::StackExtend),
            StackingSignatureMethod(Pox4SignatureTopic::AggregationCommit),
        ]
    }

    fn from_str(input: &str, _ignore_case: bool) -> Result<Self, String> {
        let topic = match input {
            "stack-stx" => Pox4SignatureTopic::StackStx,
            "stack-extend" => Pox4SignatureTopic::StackExtend,
            "aggregation-commit" => Pox4SignatureTopic::AggregationCommit,
            "agg-commit" => Pox4SignatureTopic::AggregationCommit,
            _ => return Err(format!("Invalid topic: {}", input)),
        };
        Ok(topic.into())
    }
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the generate-stacking-signature command
pub struct GenerateStackingSignatureArgs {
    /// BTC address used to receive rewards
    #[arg(short, long, value_parser = parse_pox_addr)]
    pub pox_address: PoxAddress,
    /// The reward cycle to be used in the signature's message hash
    #[arg(short, long)]
    pub reward_cycle: u64,
    /// Path to config file
    #[arg(long, value_name = "FILE")]
    pub config: PathBuf,
    /// Topic for signature
    #[arg(long)]
    pub method: StackingSignatureMethod,
    /// Number of cycles used as a lock period.
    /// Use `1` for stack-aggregation-commit
    #[arg(long)]
    pub period: u64,
}

/// Parse the contract ID
fn parse_contract(contract: &str) -> Result<QualifiedContractIdentifier, String> {
    QualifiedContractIdentifier::parse(contract).map_err(|e| format!("Invalid contract: {}", e))
}

/// Parse a BTC address argument and return a `PoxAddress`
pub fn parse_pox_addr(pox_address_literal: &str) -> Result<PoxAddress, String> {
    if let Some(pox_address) = PoxAddress::from_b58(pox_address_literal) {
        Ok(pox_address)
    } else {
        Err(format!("Invalid pox address: {}", pox_address_literal))
    }
}

/// Parse the hexadecimal Stacks private key
fn parse_private_key(private_key: &str) -> Result<StacksPrivateKey, String> {
    StacksPrivateKey::from_hex(private_key).map_err(|e| format!("Invalid private key: {}", e))
}

/// Parse the input data
fn parse_data(data: &str) -> Result<Vec<u8>, String> {
    let encoded_data = if data == "-" {
        // Parse the data from stdin
        let mut data = String::new();
        io::stdin().read_to_string(&mut data).unwrap();
        data
    } else {
        data.to_string()
    };
    let data =
        b58::from(&encoded_data).map_err(|e| format!("Failed to decode provided data: {}", e))?;
    Ok(data)
}

/// Parse the network. Must be one of "mainnet", "testnet", or "mocknet".
fn parse_network(network: &str) -> Result<Network, String> {
    Ok(match network.to_lowercase().as_str() {
        "mainnet" => Network::Mainnet,
        "testnet" => Network::Testnet,
        "mocknet" => Network::Mocknet,
        _ => {
            return Err(format!(
                "Invalid network: {}. Must be one of \"mainnet\", \"testnet\", or \"mocknet\".",
                network
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use blockstack_lib::chainstate::stacks::address::{PoxAddressType20, PoxAddressType32};

    use super::*;

    #[test]
    fn test_parse_pox_addr() {
        let tr = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let pox_addr = parse_pox_addr(tr).expect("Failed to parse segwit address");
        match pox_addr {
            PoxAddress::Addr32(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType32::P2TR);
            }
            _ => panic!("Invalid parsed address"),
        }

        let legacy = "1N8GMS991YDY1E696e9SB9EsYY5ckSU7hZ";
        let pox_addr = parse_pox_addr(legacy).expect("Failed to parse legacy address");
        match pox_addr {
            PoxAddress::Standard(stacks_addr, hash_mode) => {
                assert_eq!(stacks_addr.version, 22);
                assert!(hash_mode.is_none());
            }
            _ => panic!("Invalid parsed address"),
        }

        let p2sh = "33JNgVMNMC9Xm6mJG9oTVf5zWbmt5xi1Mv";
        let pox_addr = parse_pox_addr(p2sh).expect("Failed to parse legacy address");
        match pox_addr {
            PoxAddress::Standard(stacks_addr, hash_mode) => {
                assert_eq!(stacks_addr.version, 20);
                assert!(hash_mode.is_none());
            }
            _ => panic!("Invalid parsed address"),
        }

        let wsh = "bc1qvnpcphdctvmql5gdw6chtwvvsl6ra9gwa2nehc99np7f24juc4vqrx29cs";
        let pox_addr = parse_pox_addr(wsh).expect("Failed to parse segwit address");
        match pox_addr {
            PoxAddress::Addr32(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType32::P2WSH);
            }
            _ => panic!("Invalid parsed address"),
        }

        let wpkh = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4";
        let pox_addr = parse_pox_addr(wpkh).expect("Failed to parse segwit address");
        match pox_addr {
            PoxAddress::Addr20(_, addr_type, _) => {
                assert_eq!(addr_type, PoxAddressType20::P2WPKH);
            }
            _ => panic!("Invalid parsed address"),
        }
    }
}
