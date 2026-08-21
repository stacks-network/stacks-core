//! # stacks-signer: Stacks signer binary for signing block proposals, interacting with stackerdb, and more.
//!
//! Usage documentation can be found in the [README]("https://github.com/blockstack/stacks-blockchain/stacks-signer/README.md).
//!
//!
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
extern crate slog;
extern crate stacks_common;

extern crate clarity;
extern crate serde;
extern crate serde_json;
extern crate toml;

use std::io::{self, Write};
use std::time::Duration;

use blockstack_lib::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_signature;
use clap::{CommandFactory, Parser};
use clarity::types::chainstate::StacksPublicKey;
use clarity::util::sleep_ms;
use libsigner::{SignerSession, VERSION_STRING};
use libstackerdb::StackerDBChunkData;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, error};
use stacks_signer::cli::{
    Cli, Command, GenerateStakingSignatureArgs, GenerateVoteArgs, GetChunkArgs, GetLatestChunkArgs,
    MonitorSignersArgs, PutChunkArgs, RunSignerArgs, StackerDBArgs, VerifyVoteArgs,
};
use stacks_signer::config::GlobalConfig;
use stacks_signer::monitor_signers::SignerMonitor;
use stacks_signer::utils::stackerdb_session;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Write the chunk to stdout
fn write_chunk_to_stdout(chunk_opt: Option<Vec<u8>>) {
    if let Some(chunk) = chunk_opt.as_ref() {
        let hexed_string = to_hex(chunk);
        let hexed_chunk = hexed_string.as_bytes();
        let bytes = io::stdout().write(hexed_chunk).unwrap();
        if bytes < hexed_chunk.len() {
            print!(
                "Failed to write complete chunk to stdout. Missing {} bytes",
                hexed_chunk.len() - bytes
            );
        }
    }
}

fn handle_get_chunk(args: GetChunkArgs) {
    debug!("Getting chunk...");
    let mut session = stackerdb_session(
        &args.db_args.host,
        args.db_args.contract,
        Duration::from_secs(args.db_args.stackerdb_timeout_secs),
    );
    let chunk_opt = session.get_chunk(args.slot_id, args.slot_version).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_get_latest_chunk(args: GetLatestChunkArgs) {
    debug!("Getting latest chunk...");
    let mut session = stackerdb_session(
        &args.db_args.host,
        args.db_args.contract,
        Duration::from_secs(args.db_args.stackerdb_timeout_secs),
    );
    let chunk_opt = session.get_latest_chunk(args.slot_id).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_list_chunks(args: StackerDBArgs) {
    debug!("Listing chunks...");
    let mut session = stackerdb_session(
        &args.host,
        args.contract,
        Duration::from_secs(args.stackerdb_timeout_secs),
    );
    let chunk_list = session.list_chunks().unwrap();
    let chunk_list_json = serde_json::to_string(&chunk_list).unwrap();
    let hexed_json = to_hex(chunk_list_json.as_bytes());
    println!("{hexed_json}");
}

fn handle_put_chunk(args: PutChunkArgs) {
    debug!("Putting chunk...");
    let mut session = stackerdb_session(
        &args.db_args.host,
        args.db_args.contract,
        Duration::from_secs(args.db_args.stackerdb_timeout_secs),
    );
    let mut chunk = StackerDBChunkData::new(args.slot_id, args.slot_version, args.data);
    chunk.sign(&args.private_key).unwrap();
    let chunk_ack = session.put_chunk(&chunk).unwrap();
    println!("{}", serde_json::to_string(&chunk_ack).unwrap());
}

fn handle_run(args: RunSignerArgs) {
    debug!("Running signer...");
    let config = GlobalConfig::try_from(&args.config).unwrap();
    let spawned_signer = SpawnedSigner::new(config);
    println!("Signer spawned successfully. Waiting for messages to process...");
    // Wait for the spawned signer to stop (will only occur if an error occurs)
    let _ = spawned_signer.join();
}

fn handle_generate_staking_signature(
    args: GenerateStakingSignatureArgs,
    do_print: bool,
) -> MessageSignature {
    let config = GlobalConfig::try_from(&args.config).unwrap();

    let private_key = config.stacks_private_key;
    let public_key = StacksPublicKey::from_private(&private_key);
    let pk_hex = to_hex(&public_key.to_bytes_compressed());

    let signature = make_pox_5_signer_grant_signature(
        &args.signer_manager,
        args.auth_id,
        config.to_chain_id(),
        &private_key,
    )
    .expect("Failed to generate signature");

    let output_str = if args.json {
        serde_json::to_string(&serde_json::json!({
            "signerKey": pk_hex,
            "signerSignature": to_hex(signature.to_rsv().as_slice()),
            "authId": format!("{}", args.auth_id),
            "signerManager": args.signer_manager.to_string(),
        }))
        .expect("Failed to serialize JSON")
    } else {
        format!(
            "Signer Public Key: 0x{}\nSigner Key Signature: 0x{}\n\n",
            pk_hex,
            to_hex(signature.to_rsv().as_slice()) // RSV is needed for Clarity
        )
    };

    if do_print {
        println!("{output_str}");
    }

    signature
}

fn handle_check_config(args: RunSignerArgs) {
    let config = GlobalConfig::try_from(&args.config).unwrap();
    println!("Signer version: {}\nConfig: \n{config}", *VERSION_STRING);
}

fn handle_generate_vote(args: GenerateVoteArgs, do_print: bool) -> MessageSignature {
    let config = GlobalConfig::try_from(&args.config).unwrap();
    let message_signature = args.vote_info.sign(&config.stacks_private_key).unwrap();
    if do_print {
        println!("{}", to_hex(message_signature.as_bytes()));
    }
    message_signature
}

fn handle_verify_vote(args: VerifyVoteArgs, do_print: bool) -> bool {
    let valid_vote = args
        .vote_info
        .verify(&args.public_key, &args.signature)
        .unwrap();
    if do_print {
        if valid_vote {
            println!("Valid vote");
        } else {
            println!("Invalid vote");
        }
    }
    valid_vote
}

fn handle_monitor_signers(args: MonitorSignersArgs) {
    // Verify that the host is a valid URL
    let mut signer_monitor = SignerMonitor::new(args);
    loop {
        if let Err(e) = signer_monitor.start() {
            error!(
                "Error occurred monitoring signers: {:?}. Waiting and trying again.",
                e
            );
            sleep_ms(1000);
        }
    }
}

fn main() {
    // If no args were passed, exit 0.
    // This differs from the default behavior, which exits with code 2.
    if std::env::args_os().len() == 1 {
        let mut cmd = Cli::command();
        cmd.print_help().ok();
        println!();
        std::process::exit(0);
    }

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
        Command::Run(args) => {
            handle_run(args);
        }
        Command::GenerateStakingSignature(args) => {
            handle_generate_staking_signature(args, true);
        }
        Command::CheckConfig(args) => {
            handle_check_config(args);
        }
        Command::GenerateVote(args) => {
            handle_generate_vote(args, true);
        }
        Command::VerifyVote(args) => {
            handle_verify_vote(args, true);
        }
        Command::MonitorSigners(args) => {
            handle_monitor_signers(args);
        }
    }
}

#[cfg(test)]
pub mod tests {
    use blockstack_lib::util_lib::signed_structured_data::pox5::make_pox_5_signer_grant_message_hash;
    use clarity::util::secp256k1::Secp256k1PrivateKey;
    use clarity::vm::types::PrincipalData;
    use rand::{Rng, RngCore};
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::PublicKey;
    use stacks_common::util::hash::hex_bytes;
    use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
    use stacks_signer::cli::{VerifyVoteArgs, Vote, VoteInfo};

    use super::{handle_generate_staking_signature, *};
    use crate::{GenerateStakingSignatureArgs, GlobalConfig};

    #[test]
    fn test_generate_stacking_signature() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let signer_manager =
            PrincipalData::parse("ST000000000000000000002AMW42H.test-signer").unwrap();
        let args = GenerateStakingSignatureArgs {
            config: "./src/tests/conf/signer-0.toml".into(),
            signer_manager: signer_manager.clone(),
            auth_id: 1,
            json: false,
        };

        let signature = handle_generate_staking_signature(args.clone(), false);

        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);

        let message_hash =
            make_pox_5_signer_grant_message_hash(&signer_manager, args.auth_id, CHAIN_ID_TESTNET);

        let verify_result = public_key.verify(&message_hash.0, &signature);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
    }

    /// Use a fixture generated from our typescript implementation
    /// ([`pox-5-helpers.ts`](../../contrib/core-contract-tests/tests/pox-5/pox-5-helpers.ts))
    #[test]
    fn test_pox_5_signer_grant_signature_typescript_fixture() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let signer_manager =
            PrincipalData::parse("ST000000000000000000002AMW42H.test-signer").unwrap();
        let message_hash =
            make_pox_5_signer_grant_message_hash(&signer_manager, 1, CHAIN_ID_TESTNET);
        let signature = handle_generate_staking_signature(
            GenerateStakingSignatureArgs {
                config: "./src/tests/conf/signer-0.toml".into(),
                signer_manager,
                auth_id: 1,
                json: false,
            },
            false,
        );

        let expected_hash =
            hex_bytes("41339a30baf6f207fb56882c0d5246a91af8db0e6d3a2c07eb455c2330441256").unwrap();
        let expected_signature = MessageSignature::from_rsv(
            &hex_bytes("2c83b6442a993d54ed2696789908fa963a50f748d0d06ca61445baed8bfb809a63f1182b350a46984e3b7cb67baa8e952b6c342f3354370bb7a7060e1bbc535e01").unwrap(),
        )
        .unwrap();

        assert_eq!(message_hash.as_bytes(), expected_hash.as_slice());
        assert_eq!(signature, expected_signature);
        assert!(Secp256k1PublicKey::from_private(&config.stacks_private_key)
            .verify(message_hash.as_bytes(), &signature)
            .unwrap());
    }

    #[test]
    fn test_vote() {
        let mut rand = rand::thread_rng();
        let vote_info = VoteInfo {
            vote: rand.gen_range(0..2).try_into().unwrap(),
            sip: rand.next_u32(),
        };
        let config_file = "./src/tests/conf/signer-0.toml";
        let config = GlobalConfig::load_from_file(config_file).unwrap();
        let private_key = config.stacks_private_key;
        let public_key = StacksPublicKey::from_private(&private_key);
        let args = GenerateVoteArgs {
            config: config_file.into(),
            vote_info: vote_info.clone(),
        };
        let message_signature = handle_generate_vote(args, false);
        assert!(
            vote_info.verify(&public_key, &message_signature).unwrap(),
            "Vote should be valid"
        );
    }

    #[test]
    fn test_verify_vote() {
        let mut rand = rand::thread_rng();
        let private_key = Secp256k1PrivateKey::random();
        let public_key = StacksPublicKey::from_private(&private_key);

        let invalid_private_key = Secp256k1PrivateKey::random();
        let invalid_public_key = StacksPublicKey::from_private(&invalid_private_key);

        let sip = rand.next_u32();
        let vote_info = VoteInfo {
            vote: Vote::No,
            sip,
        };

        let args = VerifyVoteArgs {
            public_key: public_key.clone(),
            signature: vote_info.sign(&private_key).unwrap(),
            vote_info: vote_info.clone(),
        };
        let valid = handle_verify_vote(args, false);
        assert!(valid, "Vote should be valid");

        let args = VerifyVoteArgs {
            public_key: invalid_public_key,
            signature: vote_info.sign(&private_key).unwrap(), // Invalid corresponding public key
            vote_info: vote_info.clone(),
        };
        let valid = handle_verify_vote(args, false);
        assert!(!valid, "Vote should be invalid");

        let args = VerifyVoteArgs {
            public_key: public_key.clone(),
            signature: vote_info.sign(&private_key).unwrap(),
            vote_info: VoteInfo {
                vote: Vote::Yes, // Invalid vote
                sip,
            },
        };
        let valid = handle_verify_vote(args, false);
        assert!(!valid, "Vote should be invalid");

        let args = VerifyVoteArgs {
            public_key,
            signature: vote_info.sign(&private_key).unwrap(),
            vote_info: VoteInfo {
                vote: Vote::No,
                sip: sip.wrapping_add(1), // Invalid sip number
            },
        };
        let valid = handle_verify_vote(args, false);
        assert!(!valid, "Vote should be invalid");
    }
}
