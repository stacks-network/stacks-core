//! # stacks-signer: Stacks signer binary for executing DKG rounds, signing transactions and blocks, and more.
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

use std::collections::HashMap;
use std::io::{self, Write};

use blockstack_lib::util_lib::signed_structured_data::pox4::make_pox_4_signer_key_signature;
use clap::Parser;
use clarity::codec::read_next;
use clarity::types::chainstate::{StacksPrivateKey, StacksPublicKey};
use clarity::types::StacksEpochId;
use clarity::util::sleep_ms;
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::v0::messages::{MessageSlotID, SignerMessage};
use libsigner::{SignerSession, StackerDBSession};
use libstackerdb::StackerDBChunkData;
use slog::{slog_debug, slog_error, slog_info, slog_warn};
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{debug, error, info, warn};
use stacks_signer::cli::{
    Cli, Command, GenerateStackingSignatureArgs, GenerateVoteArgs, GetChunkArgs,
    GetLatestChunkArgs, MonitorSignersArgs, PutChunkArgs, RunSignerArgs, StackerDBArgs,
    VerifyVoteArgs,
};
use stacks_signer::client::{ClientError, StacksClient};
use stacks_signer::config::GlobalConfig;
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

/// Create a new stacker db session
fn stackerdb_session(host: &str, contract: QualifiedContractIdentifier) -> StackerDBSession {
    let mut session = StackerDBSession::new(host, contract.clone());
    session.connect(host.to_string(), contract).unwrap();
    session
}

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
    let mut session = stackerdb_session(&args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_chunk(args.slot_id, args.slot_version).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_get_latest_chunk(args: GetLatestChunkArgs) {
    debug!("Getting latest chunk...");
    let mut session = stackerdb_session(&args.db_args.host, args.db_args.contract);
    let chunk_opt = session.get_latest_chunk(args.slot_id).unwrap();
    write_chunk_to_stdout(chunk_opt);
}

fn handle_list_chunks(args: StackerDBArgs) {
    debug!("Listing chunks...");
    let mut session = stackerdb_session(&args.host, args.contract);
    let chunk_list = session.list_chunks().unwrap();
    let chunk_list_json = serde_json::to_string(&chunk_list).unwrap();
    let hexed_json = to_hex(chunk_list_json.as_bytes());
    println!("{}", hexed_json);
}

fn handle_put_chunk(args: PutChunkArgs) {
    debug!("Putting chunk...");
    let mut session = stackerdb_session(&args.db_args.host, args.db_args.contract);
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

fn handle_generate_stacking_signature(
    args: GenerateStackingSignatureArgs,
    do_print: bool,
) -> MessageSignature {
    let config = GlobalConfig::try_from(&args.config).unwrap();

    let private_key = config.stacks_private_key;
    let public_key = StacksPublicKey::from_private(&private_key);
    let pk_hex = to_hex(&public_key.to_bytes_compressed());

    let signature = make_pox_4_signer_key_signature(
        &args.pox_address,
        &private_key, //
        args.reward_cycle.into(),
        args.method.topic(),
        config.network.to_chain_id(),
        args.period.into(),
        args.max_amount,
        args.auth_id,
    )
    .expect("Failed to generate signature");

    let output_str = if args.json {
        serde_json::to_string(&serde_json::json!({
            "signerKey": pk_hex,
            "signerSignature": to_hex(signature.to_rsv().as_slice()),
            "authId": format!("{}", args.auth_id),
            "rewardCycle": args.reward_cycle,
            "maxAmount": format!("{}", args.max_amount),
            "period": args.period,
            "poxAddress": args.pox_address.to_b58(),
            "method": args.method.topic().to_string(),
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
        println!("{}", output_str);
    }

    signature
}

fn handle_check_config(args: RunSignerArgs) {
    let config = GlobalConfig::try_from(&args.config).unwrap();
    println!("Config: {}", config);
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
    url::Url::parse(&format!("http://{}", args.host)).expect("Failed to parse node host");
    let stacks_client = StacksClient::new(
        StacksPrivateKey::new(), // We don't need a private key to retrieve the reward cycle
        args.host.clone(),
        "FOO".to_string(), // We don't care about authorized paths. Just accessing public info
        args.mainnet,
    );

    loop {
        if let Err(e) = start_monitoring_signers(&stacks_client, &args) {
            error!(
                "Error occurred monitoring signers: {:?}. Waiting and trying again.",
                e
            );
            sleep_ms(1000);
        }
    }
}

fn start_monitoring_signers(
    stacks_client: &StacksClient,
    args: &MonitorSignersArgs,
) -> Result<(), ClientError> {
    let interval_ms = args.interval * 1000;
    let epoch = stacks_client.get_node_epoch()?;
    if epoch < StacksEpochId::Epoch25 {
        return Err(ClientError::UnsupportedStacksFeature(
            "Signer monitoring is only supported for Epoch 2.5 and later".into(),
        ));
    }
    let mut reward_cycle = stacks_client.get_current_reward_cycle_info()?.reward_cycle;
    let mut signers_slots = stacks_client.get_parsed_signer_slots(reward_cycle)?;
    let mut signers_addresses = HashMap::with_capacity(signers_slots.len());
    for (signer_address, slot_id) in signers_slots.iter() {
        signers_addresses.insert(*slot_id, *signer_address);
    }
    let mut slot_ids: Vec<_> = signers_slots.values().map(|value| value.0).collect();

    // Poll stackerdb slots to check for new expected messages
    let mut last_messages = HashMap::with_capacity(slot_ids.len());
    let mut last_updates = HashMap::with_capacity(slot_ids.len());

    let contract = MessageSlotID::BlockResponse.stacker_db_contract(args.mainnet, reward_cycle);
    let mut session = stackerdb_session(&args.host.to_string(), contract.clone());
    info!(
        "Monitoring signers stackerdb. Polling interval: {} secs, Max message age: {} secs, Reward cycle: {reward_cycle}, StackerDB contract: {contract}",
        args.interval, args.max_age
    );
    loop {
        info!("Polling signers stackerdb for new messages...");
        let mut missing_signers = Vec::with_capacity(slot_ids.len());
        let mut stale_signers = Vec::with_capacity(slot_ids.len());
        let mut unexpected_messages = HashMap::new();

        let next_reward_cycle = stacks_client.get_current_reward_cycle_info()?.reward_cycle;
        if next_reward_cycle != reward_cycle {
            info!(
                "Reward cycle has changed from {} to {}. Updating stacker db session to StackerDB contract {contract}.",
                reward_cycle, next_reward_cycle
            );
            reward_cycle = next_reward_cycle;
            signers_slots = stacks_client.get_parsed_signer_slots(reward_cycle)?;
            slot_ids = signers_slots.values().map(|value| value.0).collect();
            for (signer_address, slot_id) in signers_slots.iter() {
                signers_addresses.insert(*slot_id, *signer_address);
            }
            session = stackerdb_session(
                &args.host.to_string(),
                MessageSlotID::BlockResponse.stacker_db_contract(args.mainnet, reward_cycle),
            );

            // Clear the last messages and signer last update times.
            last_messages.clear();
            last_updates.clear();
        }
        let new_messages: Vec<_> = session
            .get_latest_chunks(&slot_ids)?
            .into_iter()
            .map(|chunk_opt| {
                chunk_opt.and_then(|data| read_next::<SignerMessage, _>(&mut &data[..]).ok())
            })
            .collect();
        for ((signer_address, slot_id), signer_message_opt) in
            signers_slots.clone().into_iter().zip(new_messages)
        {
            if let Some(signer_message) = signer_message_opt {
                if let Some(last_message) = last_messages.get(&slot_id) {
                    if last_message == &signer_message {
                        continue;
                    }
                }
                if (epoch == StacksEpochId::Epoch25
                    && !matches!(signer_message, SignerMessage::MockSignature(_)))
                    || (epoch > StacksEpochId::Epoch25
                        && !matches!(signer_message, SignerMessage::BlockResponse(_)))
                {
                    unexpected_messages.insert(signer_address, (signer_message, slot_id));
                    continue;
                }
                last_messages.insert(slot_id, signer_message);
                last_updates.insert(slot_id, std::time::Instant::now());
            } else {
                missing_signers.push(signer_address);
            }
        }
        for (slot_id, last_update_time) in last_updates.iter() {
            if last_update_time.elapsed().as_secs() > args.max_age {
                let address = signers_addresses
                    .get(slot_id)
                    .expect("BUG: missing signer address for given slot id");
                stale_signers.push(*address);
            }
        }
        if missing_signers.is_empty()
            && stale_signers.is_empty()
            && unexpected_messages.is_empty()
            && !signers_addresses.is_empty()
        {
            info!(
                "All {} signers are sending messages as expected.",
                signers_addresses.len()
            );
        } else {
            if !missing_signers.is_empty() {
                let formatted_signers = missing_signers
                    .iter()
                    .map(|addr| format!("{addr}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    "Missing messages for {} of {} signer(s). ", missing_signers.len(), signers_addresses.len();
                    "signers" => formatted_signers
                );
            }
            if !stale_signers.is_empty() {
                let formatted_signers = stale_signers
                    .iter()
                    .map(|addr| format!("{addr}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    "No new updates from {} of {} signer(s) in over {} seconds",
                    stale_signers.len(),
                    signers_addresses.len(),
                    args.max_age;
                    "signers" => formatted_signers
                );
            }
            if !unexpected_messages.is_empty() {
                let formatted_signers = unexpected_messages
                    .iter()
                    .map(|(addr, (msg, slot))| {
                        format!("(address: {addr}, slot_id: {slot}, message: {msg:?})")
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                warn!(
                    "Unexpected messages from {} of {} Epoch {epoch} signer(s).",
                    unexpected_messages.len(),
                    signers_addresses.len();
                    "signers" => formatted_signers
                );
            }
        }
        sleep_ms(interval_ms);
    }
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
        Command::Run(args) => {
            handle_run(args);
        }
        Command::GenerateStackingSignature(args) => {
            handle_generate_stacking_signature(args, true);
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
        Command::MonitorSigners(args) => handle_monitor_signers(args),
    }
}

#[cfg(test)]
pub mod tests {
    use blockstack_lib::chainstate::stacks::address::PoxAddress;
    use blockstack_lib::chainstate::stacks::boot::POX_4_CODE;
    use blockstack_lib::util_lib::signed_structured_data::pox4::{
        make_pox_4_signer_key_message_hash, Pox4SignatureTopic,
    };
    use clarity::util::secp256k1::Secp256k1PrivateKey;
    use clarity::vm::{execute_v2, Value};
    use rand::{Rng, RngCore};
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::PublicKey;
    use stacks_common::util::secp256k1::Secp256k1PublicKey;
    use stacks_signer::cli::{parse_pox_addr, VerifyVoteArgs, Vote, VoteInfo};

    use super::{handle_generate_stacking_signature, *};
    use crate::{GenerateStackingSignatureArgs, GlobalConfig};

    #[allow(clippy::too_many_arguments)]
    fn call_verify_signer_sig(
        pox_addr: &PoxAddress,
        reward_cycle: u128,
        topic: &Pox4SignatureTopic,
        lock_period: u128,
        public_key: &Secp256k1PublicKey,
        signature: Vec<u8>,
        amount: u128,
        max_amount: u128,
        auth_id: u128,
    ) -> bool {
        let program = format!(
            r#"
            {}
            (verify-signer-key-sig {} u{} "{}" u{} (some 0x{}) 0x{} u{} u{} u{})
        "#,
            &*POX_4_CODE,                                               //s
            Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap()), //p
            reward_cycle,
            topic.get_name_str(),
            lock_period,
            to_hex(signature.as_slice()),
            to_hex(public_key.to_bytes_compressed().as_slice()),
            amount,
            max_amount,
            auth_id,
        );
        execute_v2(&program)
            .expect("FATAL: could not execute program")
            .expect("Expected result")
            .expect_result_ok()
            .expect("Expected ok result")
            .expect_bool()
            .expect("Expected buff")
    }

    #[test]
    fn test_stacking_signature_with_pox_code() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let btc_address = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let mut args = GenerateStackingSignatureArgs {
            config: "./src/tests/conf/signer-0.toml".into(),
            pox_address: parse_pox_addr(btc_address).unwrap(),
            reward_cycle: 6,
            method: Pox4SignatureTopic::StackStx.into(),
            period: 12,
            max_amount: u128::MAX,
            auth_id: 1,
            json: false,
        };

        let signature = handle_generate_stacking_signature(args.clone(), false);
        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);

        let valid = call_verify_signer_sig(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            args.period.into(),
            &public_key,
            signature.to_rsv(),
            100,
            args.max_amount,
            args.auth_id,
        );
        assert!(valid);

        // change up some args
        args.period = 6;
        args.method = Pox4SignatureTopic::AggregationCommit.into();
        args.reward_cycle = 7;
        args.auth_id = 2;
        args.max_amount = 100;

        let signature = handle_generate_stacking_signature(args.clone(), false);
        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);

        let valid = call_verify_signer_sig(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::AggregationCommit,
            args.period.into(),
            &public_key,
            signature.to_rsv(),
            100,
            args.max_amount,
            args.auth_id,
        );
        assert!(valid);
    }

    #[test]
    fn test_generate_stacking_signature() {
        let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
        let btc_address = "bc1p8vg588hldsnv4a558apet4e9ff3pr4awhqj2hy8gy6x2yxzjpmqsvvpta4";
        let args = GenerateStackingSignatureArgs {
            config: "./src/tests/conf/signer-0.toml".into(),
            pox_address: parse_pox_addr(btc_address).unwrap(),
            reward_cycle: 6,
            method: Pox4SignatureTopic::StackStx.into(),
            period: 12,
            max_amount: u128::MAX,
            auth_id: 1,
            json: false,
        };

        let signature = handle_generate_stacking_signature(args.clone(), false);

        let public_key = Secp256k1PublicKey::from_private(&config.stacks_private_key);

        let message_hash = make_pox_4_signer_key_message_hash(
            &args.pox_address,
            args.reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            args.period.into(),
            args.max_amount,
            args.auth_id,
        );

        let verify_result = public_key.verify(&message_hash.0, &signature);
        assert!(verify_result.is_ok());
        assert!(verify_result.unwrap());
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
            vote_info,
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
        let private_key = Secp256k1PrivateKey::new();
        let public_key = StacksPublicKey::from_private(&private_key);

        let invalid_private_key = Secp256k1PrivateKey::new();
        let invalid_public_key = StacksPublicKey::from_private(&invalid_private_key);

        let sip = rand.next_u32();
        let vote_info = VoteInfo {
            vote: Vote::No,
            sip,
        };

        let args = VerifyVoteArgs {
            public_key,
            signature: vote_info.sign(&private_key).unwrap(),
            vote_info,
        };
        let valid = handle_verify_vote(args, false);
        assert!(valid, "Vote should be valid");

        let args = VerifyVoteArgs {
            public_key: invalid_public_key,
            signature: vote_info.sign(&private_key).unwrap(), // Invalid corresponding public key
            vote_info,
        };
        let valid = handle_verify_vote(args, false);
        assert!(!valid, "Vote should be invalid");

        let args = VerifyVoteArgs {
            public_key,
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
