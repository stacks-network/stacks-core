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

use std::fs::File;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Duration;

use blockstack_lib::chainstate::nakamoto::NakamotoBlock;
use clap::Parser;
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{
    RunningSigner, Signer, SignerEventReceiver, SignerSession, StackerDBSession,
    SIGNER_SLOTS_PER_USER,
};
use libstackerdb::StackerDBChunkData;
use slog::{slog_debug, slog_error};
use stacks_common::codec::read_next;
use stacks_common::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks_common::{debug, error};
use stacks_signer::cli::{
    Cli, Command, GenerateFilesArgs, GetChunkArgs, GetLatestChunkArgs, PutChunkArgs, RunDkgArgs,
    SignArgs, StackerDBArgs,
};
use stacks_signer::config::Config;
use stacks_signer::runloop::{RunLoop, RunLoopCommand};
use stacks_signer::utils::{build_signer_config_tomls, build_stackerdb_contract, to_addr};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use wsts::state_machine::coordinator::fire::Coordinator as FireCoordinator;
use wsts::state_machine::OperationResult;
use wsts::v2;

struct SpawnedSigner {
    running_signer: RunningSigner<SignerEventReceiver, Vec<OperationResult>>,
    cmd_send: Sender<RunLoopCommand>,
    res_recv: Receiver<Vec<OperationResult>>,
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

// Spawn a running signer and return its handle, command sender, and result receiver
fn spawn_running_signer(path: &PathBuf) -> SpawnedSigner {
    let config = Config::try_from(path).unwrap();
    let (cmd_send, cmd_recv) = channel();
    let (res_send, res_recv) = channel();
    let ev = SignerEventReceiver::new(
        vec![config.stackerdb_contract_id.clone()],
        config.network.is_mainnet(),
    );
    let runloop: RunLoop<FireCoordinator<v2::Aggregator>> = RunLoop::from(&config);
    let mut signer: Signer<
        RunLoopCommand,
        Vec<OperationResult>,
        RunLoop<FireCoordinator<v2::Aggregator>>,
        SignerEventReceiver,
    > = Signer::new(runloop, ev, cmd_recv, res_send);
    let running_signer = signer.spawn(config.endpoint).unwrap();
    SpawnedSigner {
        running_signer,
        cmd_send,
        res_recv,
    }
}

// Process a DKG result
fn process_dkg_result(dkg_res: &[OperationResult]) {
    assert!(dkg_res.len() == 1, "Received unexpected number of results");
    let dkg = dkg_res.first().unwrap();
    match dkg {
        OperationResult::Dkg(point) => {
            println!("Received aggregate group key: {point}");
        }
        OperationResult::Sign(signature) => {
            panic!(
                "Received unexpected signature ({},{})",
                &signature.R, &signature.z,
            );
        }
        OperationResult::SignTaproot(schnorr_proof) => {
            panic!(
                "Received unexpected schnorr proof ({},{})",
                &schnorr_proof.r, &schnorr_proof.s,
            );
        }
        OperationResult::DkgError(dkg_error) => {
            panic!("Received DkgError {}", dkg_error);
        }
        OperationResult::SignError(sign_error) => {
            panic!("Received SignError {}", sign_error);
        }
    }
}

// Process a Sign result
fn process_sign_result(sign_res: &[OperationResult]) {
    assert!(sign_res.len() == 1, "Received unexpected number of results");
    let sign = sign_res.first().unwrap();
    match sign {
        OperationResult::Dkg(point) => {
            panic!("Received unexpected aggregate group key: {point}");
        }
        OperationResult::Sign(signature) => {
            panic!(
                "Received bood signature ({},{})",
                &signature.R, &signature.z,
            );
        }
        OperationResult::SignTaproot(schnorr_proof) => {
            panic!(
                "Received unexpected schnorr proof ({},{})",
                &schnorr_proof.r, &schnorr_proof.s,
            );
        }
        OperationResult::DkgError(dkg_error) => {
            panic!("Received DkgError {}", dkg_error);
        }
        OperationResult::SignError(sign_error) => {
            panic!("Received SignError {}", sign_error);
        }
    }
}

fn handle_get_chunk(args: GetChunkArgs) {
    debug!("Getting chunk...");
    let mut session = stackerdb_session(args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_chunk(args.slot_id, args.slot_version).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_get_latest_chunk(args: GetLatestChunkArgs) {
    debug!("Getting latest chunk...");
    let mut session = stackerdb_session(args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_latest_chunk(args.slot_id).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_list_chunks(args: StackerDBArgs) {
    debug!("Listing chunks...");
    let mut session = stackerdb_session(args.host, args.contract);
    let chunk_list = session.list_chunks().unwrap();
    println!("{}", serde_json::to_string(&chunk_list).unwrap());
}

fn handle_put_chunk(args: PutChunkArgs) {
    debug!("Putting chunk...");
    let mut session = stackerdb_session(args.db_args.host, args.db_args.contract);
    let mut chunk = StackerDBChunkData::new(args.slot_id, args.slot_version, args.data);
    chunk.sign(&args.private_key).unwrap();
    let chunk_ack = session.put_chunk(&chunk).unwrap();
    println!("{}", serde_json::to_string(&chunk_ack).unwrap());
}

fn handle_dkg(args: RunDkgArgs) {
    debug!("Running DKG...");
    let spawned_signer = spawn_running_signer(&args.config);
    spawned_signer.cmd_send.send(RunLoopCommand::Dkg).unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    spawned_signer.running_signer.stop();
}

fn handle_sign(args: SignArgs) {
    debug!("Signing message...");
    let spawned_signer = spawn_running_signer(&args.config);
    let Some(block) = read_next::<NakamotoBlock, _>(&mut &args.data[..]).ok() else {
        error!("Unable to parse provided message as a NakamotoBlock.");
        spawned_signer.running_signer.stop();
        return;
    };
    spawned_signer
        .cmd_send
        .send(RunLoopCommand::Sign {
            block,
            is_taproot: false,
            merkle_root: None,
        })
        .unwrap();
    let sign_res = spawned_signer.res_recv.recv().unwrap();
    process_sign_result(&sign_res);
    spawned_signer.running_signer.stop();
}

fn handle_dkg_sign(args: SignArgs) {
    debug!("Running DKG and signing message...");
    let spawned_signer = spawn_running_signer(&args.config);
    let Some(block) = read_next::<NakamotoBlock, _>(&mut &args.data[..]).ok() else {
        error!("Unable to parse provided message as a NakamotoBlock.");
        spawned_signer.running_signer.stop();
        return;
    };
    // First execute DKG, then sign
    spawned_signer.cmd_send.send(RunLoopCommand::Dkg).unwrap();
    spawned_signer
        .cmd_send
        .send(RunLoopCommand::Sign {
            block,
            is_taproot: false,
            merkle_root: None,
        })
        .unwrap();
    let dkg_res = spawned_signer.res_recv.recv().unwrap();
    process_dkg_result(&dkg_res);
    let sign_res = spawned_signer.res_recv.recv().unwrap();
    process_sign_result(&sign_res);
    spawned_signer.running_signer.stop();
}

fn handle_run(args: RunDkgArgs) {
    debug!("Running signer...");
    let spawned_signer = spawn_running_signer(&args.config);
    println!("Signer spawned successfully. Waiting for messages to process...");
    // Wait for the spawned signer to stop (will only occur if an error occurs)
    let _ = spawned_signer.running_signer.join();
}

fn handle_generate_files(args: GenerateFilesArgs) {
    debug!("Generating files...");
    let signer_stacks_private_keys = if let Some(path) = args.private_keys {
        let file = File::open(path).unwrap();
        let reader = io::BufReader::new(file);

        let private_keys: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
        println!("{}", StacksPrivateKey::new().to_hex());
        let private_keys = private_keys
            .iter()
            .map(|key| StacksPrivateKey::from_hex(key).expect("Failed to parse private key."))
            .collect::<Vec<StacksPrivateKey>>();
        if private_keys.is_empty() {
            panic!("Private keys file is empty.");
        }
        private_keys
    } else {
        let num_signers = args.num_signers.unwrap();
        if num_signers == 0 {
            panic!("--num-signers must be non-zero.");
        }
        (0..num_signers)
            .map(|_| StacksPrivateKey::new())
            .collect::<Vec<StacksPrivateKey>>()
    };
    let signer_stacks_addresses = signer_stacks_private_keys
        .iter()
        .map(|key| to_addr(key, &args.network))
        .collect::<Vec<StacksAddress>>();
    // Build the signer and miner stackerdb contract
    let signer_stackerdb_contract =
        build_stackerdb_contract(&signer_stacks_addresses, SIGNER_SLOTS_PER_USER);
    write_file(&args.dir, "signers.clar", &signer_stackerdb_contract);

    let signer_config_tomls = build_signer_config_tomls(
        &signer_stacks_private_keys,
        args.num_keys,
        &args.host.to_string(),
        &args.signers_contract.to_string(),
        args.timeout.map(Duration::from_millis),
        &args.network,
    );
    debug!("Built {:?} signer config tomls.", signer_config_tomls.len());
    for (i, file_contents) in signer_config_tomls.iter().enumerate() {
        write_file(&args.dir, &format!("signer-{}.toml", i), file_contents);
    }
}

/// Helper function for writing the given contents to filename in the given directory
fn write_file(dir: &Path, filename: &str, contents: &str) {
    let file_path = dir.join(filename);
    let filename = file_path.to_str().unwrap();
    let mut file = File::create(filename).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    println!("Created file: {}", filename);
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    match cli.command {
        Command::GetChunk(args) => {
            handle_get_chunk(args);
        }
        Command::GetLatestChunk(args) => {
            handle_get_latest_chunk(args);
        }
        Command::ListChunks(args) => {
            handle_list_chunks(args);
        }
        Command::PutChunk(args) => {
            handle_put_chunk(args);
        }
        Command::Dkg(args) => {
            handle_dkg(args);
        }
        Command::DkgSign(args) => {
            handle_dkg_sign(args);
        }
        Command::Sign(args) => {
            handle_sign(args);
        }
        Command::Run(args) => {
            handle_run(args);
        }
        Command::GenerateFiles(args) => {
            handle_generate_files(args);
        }
    }
}

#[cfg(test)]
pub mod tests;
