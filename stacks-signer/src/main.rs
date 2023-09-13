//! # stacks-signer: Stacks signer binary for executing DKG rounds, signing transactions and blocks, and more.
//!
//! Usage documentation can be found in the [README]("https://github.com/blockstack/stacks-blockchain/stacks-signer/README.md).
//!
//!
// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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
extern crate slog;
extern crate stacks_common;

extern crate clarity;
extern crate serde;
extern crate serde_json;
extern crate toml;

use clap::Parser;
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{RunningSigner, Signer, SignerSession, StackerDBEventReceiver, StackerDBSession};
use libstackerdb::StackerDBChunkData;
use stacks_common::types::chainstate::StacksPrivateKey;
use stacks_signer::{
    config::Config,
    crypto::frost::Coordinator as FrostCoordinator,
    runloop::{RunLoop, RunLoopCommand},
};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{channel, Receiver},
};
use wsts::Point;

#[derive(Parser, Debug)]
#[command(author, version, about)]
/// The CLI arguments for the stacks signer
pub struct Cli {
    /// Path to config file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// The Stacks node to connect to
    #[clap(long, required_unless_present = "config", conflicts_with = "config")]
    host: Option<SocketAddr>,
    /// The stacker-db contract to use
    #[arg(short, long, value_parser = parse_contract, required_unless_present = "config", conflicts_with = "config")]
    contract: Option<QualifiedContractIdentifier>,
    /// The Stacks private key to use in hexademical format
    #[arg(short, long, value_parser = parse_private_key, required_unless_present = "config", conflicts_with = "config")]
    private_key: Option<StacksPrivateKey>,
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
    ListChunks,
    /// Upload a chunk to the stacker-db instance
    PutChunk(PutChunkArgs),
    /// Run DKG and sign the message through the stacker-db instance
    DkgSign(SignArgs),
    /// Sign the message through the stacker-db instance
    Sign(SignArgs),
    /// Run a DKG round through the stacker-db instance
    Dkg,
    /// Run the signer, waiting for events from the stacker-db instance
    Run,
}

/// Arguments for the get-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetChunkArgs {
    /// The slot ID to get
    #[arg(long)]
    slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    slot_version: u32,
}

/// Arguments for the get-latest-chunk command
#[derive(Parser, Debug, Clone)]
pub struct GetLatestChunkArgs {
    /// The slot ID to get
    #[arg(long)]
    slot_id: u32,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the put-chunk command
pub struct PutChunkArgs {
    /// The slot ID to get
    #[arg(long)]
    slot_id: u32,
    /// The slot version to get
    #[arg(long)]
    slot_version: u32,
    /// The data to upload
    #[arg(required = false, value_parser = parse_data)]
    data: Vec<u8>,
}

#[derive(Parser, Debug, Clone)]
/// Arguments for the dkg-sign and sign command
pub struct SignArgs {
    /// The data to sign
    #[arg(required = false, value_parser = parse_data)]
    data: Vec<u8>,
}

/// Parse the contract ID
fn parse_contract(contract: &str) -> Result<QualifiedContractIdentifier, String> {
    QualifiedContractIdentifier::parse(contract).map_err(|e| format!("Invalid contract: {}", e))
}

/// Parse the hexadecimal Stacks private key
fn parse_private_key(private_key: &str) -> Result<StacksPrivateKey, String> {
    StacksPrivateKey::from_hex(private_key).map_err(|e| format!("Invalid private key: {}", e))
}

/// Parse the input data
fn parse_data(data: &str) -> Result<Vec<u8>, String> {
    let data = if data == "-" {
        // Parse the data from stdin
        let mut buf = vec![];
        io::stdin().read_to_end(&mut buf).unwrap();
        buf
    } else {
        data.as_bytes().to_vec()
    };
    Ok(data)
}

/// Create a new stacker db session
fn stackerdb_session(host: SocketAddr, contract: QualifiedContractIdentifier) -> StackerDBSession {
    let mut session = StackerDBSession::new(host, contract.clone());
    session.connect(host, contract).unwrap();
    session
}

/// Write the chunk to stdout
fn write_chunk_to_stdout(chunk_opt: Option<Vec<u8>>) {
    if let Some(chunk) = chunk_opt.as_ref() {
        let bytes = io::stdout().write(chunk).unwrap();
        if bytes < chunk.len() {
            print!(
                "Failed to write complete chunk to stdout. Missing {} bytes",
                chunk.len() - bytes
            );
        }
    }
}

fn spawn_running_signer(
    path: &PathBuf,
    command: RunLoopCommand,
    cmd_recv: Receiver<RunLoopCommand>,
) -> RunningSigner<StackerDBEventReceiver, Vec<Point>> {
    let config = Config::try_from(path).unwrap();
    let ev = StackerDBEventReceiver::new(vec![config.stackerdb_contract_id.clone()]);
    let runloop: RunLoop<FrostCoordinator> = RunLoop::new(&config, command);
    let mut signer: Signer<RunLoopCommand, Vec<Point>, RunLoop<FrostCoordinator>, StackerDBEventReceiver> =
        Signer::new(runloop, ev, cmd_recv);
    let endpoint = config.node_host;
    signer.spawn(endpoint).unwrap()
}

fn main() {
    let cli = Cli::parse();
    let (host, contract, private_key) = if let Some(config) = &cli.config {
        let config = Config::try_from(config).unwrap();
        (
            config.node_host,
            config.stackerdb_contract_id,
            config.stacks_private_key,
        )
    } else {
        (
            cli.host.unwrap(),
            cli.contract.unwrap(),
            cli.private_key.unwrap(),
        )
    };

    let (_cmd_send, cmd_recv) = channel();
    let mut session = stackerdb_session(host, contract);
    match cli.command {
        Command::GetChunk(args) => {
            let chunk_opt = session.get_chunk(args.slot_id, args.slot_version).unwrap();
            write_chunk_to_stdout(chunk_opt);
        }
        Command::GetLatestChunk(args) => {
            let chunk_opt = session.get_latest_chunk(args.slot_id).unwrap();
            write_chunk_to_stdout(chunk_opt);
        }
        Command::ListChunks => {
            let chunk_list = session.list_chunks().unwrap();
            println!("{}", serde_json::to_string(&chunk_list).unwrap());
        }
        Command::PutChunk(args) => {
            let mut chunk =
                StackerDBChunkData::new(args.slot_id, args.slot_version, args.data.clone());
            chunk.sign(&private_key).unwrap();
            let chunk_ack = session.put_chunk(chunk).unwrap();
            println!("{}", serde_json::to_string(&chunk_ack).unwrap());
        }
        Command::Dkg => {
            if let Some(config) = &cli.config {
                let _running_signer = spawn_running_signer(config, RunLoopCommand::Dkg, cmd_recv);
            } else {
                // TODO: update this retrieve data from the .pox contract and then --config will not be required for DKG
                panic!("dkg is currently only supported when using a config file");
            }
        }
        Command::DkgSign(args) => {
            if let Some(config) = &cli.config {
                let _running_signer =
                    spawn_running_signer(config, RunLoopCommand::DkgSign { message: args.data }, cmd_recv);
            } else {
                // TODO: update this retrieve data from the .pox contract and then --config will not be required for DKG
                panic!("dkg-sign is currently only supported when using a config file");
            }
        }
        Command::Sign(args) => {
            if let Some(config) = &cli.config {
                let _running_signer =
                    spawn_running_signer(config, RunLoopCommand::Sign { message: args.data }, cmd_recv);
            } else {
                // TODO: update this retrieve data from the .pox contract and then --config will not be required for DKG
                panic!("dkg-sign is currently only supported when using a config file");
            }
        }
        Command::Run => {
            if let Some(config) = &cli.config {
                let _running_signer = spawn_running_signer(config, RunLoopCommand::Run, cmd_recv);
            } else {
                // TODO: update this retrieve data from the .pox contract and then --config will not be required for DKG
                panic!("dkg-sign is currently only supported when using a config file");
            }
        }
    }
}

#[cfg(test)]
pub mod tests;
