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
use clarity::types::chainstate::{StacksAddress, StacksPrivateKey, StacksPublicKey};
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
use stacks_signer::client::{ClientError, SignerSlotID, StacksClient};
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

struct SignerMonitor {
    stacks_client: StacksClient,
    cycle_state: RewardCycleState,
    args: MonitorSignersArgs,
}

#[derive(Debug, Default, Clone)]
struct RewardCycleState {
    signers_slots: HashMap<StacksAddress, SignerSlotID>,
    signers_keys: HashMap<StacksAddress, StacksPublicKey>,
    signers_addresses: HashMap<SignerSlotID, StacksAddress>,
    slot_ids: Vec<u32>,
    /// Reward cycle is not known until the first successful call to the node
    reward_cycle: Option<u64>,
}

impl SignerMonitor {
    fn new(args: MonitorSignersArgs) -> Self {
        url::Url::parse(&format!("http://{}", args.host)).expect("Failed to parse node host");
        let stacks_client = StacksClient::new(
            StacksPrivateKey::new(), // We don't need a private key to read
            args.host.clone(),
            "FOO".to_string(), // We don't care about authorized paths. Just accessing public info
            args.mainnet,
        );
        Self {
            stacks_client,
            cycle_state: RewardCycleState::default(),
            args,
        }
    }

    fn refresh_state(&mut self) -> Result<bool, ClientError> {
        let reward_cycle = self
            .stacks_client
            .get_current_reward_cycle_info()?
            .reward_cycle;
        if Some(reward_cycle) == self.cycle_state.reward_cycle {
            // The reward cycle has not changed. Nothing to refresh.
            return Ok(false);
        }
        self.cycle_state.reward_cycle = Some(reward_cycle);

        self.cycle_state.signers_keys.clear();
        self.cycle_state.signers_addresses.clear();

        self.cycle_state.signers_slots =
            self.stacks_client.get_parsed_signer_slots(reward_cycle)?;
        self.cycle_state.slot_ids = self
            .cycle_state
            .signers_slots
            .values()
            .map(|value| value.0)
            .collect();

        let entries = self
            .stacks_client
            .get_reward_set_signers(reward_cycle)?
            .unwrap_or_else(|| {
                panic!("No signers found for the current reward cycle {reward_cycle}")
            });
        for entry in entries {
            let public_key = StacksPublicKey::from_slice(entry.signing_key.as_slice())
                .expect("Failed to convert signing key to StacksPublicKey");
            let stacks_address = StacksAddress::p2pkh(self.args.mainnet, &public_key);
            self.cycle_state
                .signers_keys
                .insert(stacks_address, public_key);
        }
        for (signer_address, slot_id) in self.cycle_state.signers_slots.iter() {
            self.cycle_state
                .signers_addresses
                .insert(*slot_id, *signer_address);
        }

        self.cycle_state.signers_slots =
            self.stacks_client.get_parsed_signer_slots(reward_cycle)?;

        for (signer_address, slot_id) in self.cycle_state.signers_slots.iter() {
            self.cycle_state
                .signers_addresses
                .insert(*slot_id, *signer_address);
            self.cycle_state.slot_ids.push(slot_id.0);
        }
        Ok(true)
    }

    fn print_missing_signers(&self, missing_signers: &[StacksAddress]) {
        if missing_signers.is_empty() {
            return;
        }
        let formatted_signers = missing_signers
            .iter()
            .map(|addr| format!("{addr}"))
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if missing_signers.contains(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "Missing messages for {} of {} signer(s). ", missing_signers.len(), self.cycle_state.signers_addresses.len();
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    fn print_stale_signers(&self, stale_signers: &[StacksAddress]) {
        if stale_signers.is_empty() {
            return;
        }
        let formatted_signers = stale_signers
            .iter()
            .map(|addr| format!("{addr}"))
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if stale_signers.contains(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "No new updates from {} of {} signer(s) in over {} seconds",
            stale_signers.len(),
            self.cycle_state.signers_addresses.len(),
            self.args.max_age;
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    fn print_unexpected_messages(
        &self,
        unexpected_messages: &HashMap<StacksAddress, (SignerMessage, SignerSlotID)>,
    ) {
        if unexpected_messages.is_empty() {
            return;
        }
        let formatted_signers = unexpected_messages
            .iter()
            .map(|(addr, (msg, slot))| {
                format!("(address: {addr}, slot_id: {slot}, message: {msg:?})")
            })
            .collect::<Vec<_>>()
            .join(", ");
        let formatted_keys = self
            .cycle_state
            .signers_keys
            .iter()
            .filter_map(|(addr, key)| {
                if unexpected_messages.contains_key(addr) {
                    Some(format!("0x{}", key.to_hex()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "Unexpected messages from {} of {} signer(s).",
            unexpected_messages.len(),
            self.cycle_state.signers_addresses.len();
            "signer_addresses" => formatted_signers,
            "signer_keys" => formatted_keys
        );
    }

    /// Start monitoring the signers stackerdb slots for expected new messages
    pub fn start(&mut self) -> Result<(), ClientError> {
        self.refresh_state()?;
        let nmb_signers = self.cycle_state.signers_keys.len();
        let interval_ms = self.args.interval * 1000;
        let reward_cycle = self
            .cycle_state
            .reward_cycle
            .expect("BUG: reward cycle not set");
        let contract =
            MessageSlotID::BlockResponse.stacker_db_contract(self.args.mainnet, reward_cycle);
        info!(
            "Monitoring signers stackerdb. Polling interval: {} secs, Max message age: {} secs, Reward cycle: {reward_cycle}, StackerDB contract: {contract}",
            self.args.interval, self.args.max_age
        );
        let mut session = stackerdb_session(&self.args.host, contract);
        info!("Confirming messages for {nmb_signers} registered signers";
            "signer_addresses" => self.cycle_state.signers_addresses.values().map(|addr| format!("{addr}")).collect::<Vec<_>>().join(", ")
        );
        let mut last_messages = HashMap::with_capacity(nmb_signers);
        let mut last_updates = HashMap::with_capacity(nmb_signers);
        loop {
            info!("Polling signers stackerdb for new messages...");
            let mut missing_signers = Vec::with_capacity(nmb_signers);
            let mut stale_signers = Vec::with_capacity(nmb_signers);
            let mut unexpected_messages = HashMap::new();

            if self.refresh_state()? {
                let reward_cycle = self
                    .cycle_state
                    .reward_cycle
                    .expect("BUG: reward cycle not set");
                let contract = MessageSlotID::BlockResponse
                    .stacker_db_contract(self.args.mainnet, reward_cycle);
                info!(
                    "Reward cycle has changed to {reward_cycle}. Updating stacker db session to StackerDB contract {contract}.",
                );
                session = stackerdb_session(&self.args.host, contract);
                // Clear the last messages and signer last update times.
                last_messages.clear();
                last_updates.clear();
            }
            let new_messages: Vec<_> = session
                .get_latest_chunks(&self.cycle_state.slot_ids)?
                .into_iter()
                .map(|chunk_opt| {
                    chunk_opt.and_then(|data| read_next::<SignerMessage, _>(&mut &data[..]).ok())
                })
                .collect();
            for ((signer_address, slot_id), signer_message_opt) in self
                .cycle_state
                .signers_slots
                .clone()
                .into_iter()
                .zip(new_messages)
            {
                let Some(signer_message) = signer_message_opt else {
                    missing_signers.push(signer_address);
                    continue;
                };
                if let Some(last_message) = last_messages.get(&slot_id) {
                    if last_message == &signer_message {
                        continue;
                    }
                }
                let epoch = self.stacks_client.get_node_epoch()?;
                if epoch < StacksEpochId::Epoch25 {
                    return Err(ClientError::UnsupportedStacksFeature(format!("Monitoring signers is only supported for Epoch 2.5 and later. Current epoch: {epoch:?}")));
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
            }
            for (slot_id, last_update_time) in last_updates.iter() {
                if last_update_time.elapsed().as_secs() > self.args.max_age {
                    let address = self
                        .cycle_state
                        .signers_addresses
                        .get(slot_id)
                        .expect("BUG: missing signer address for given slot id");
                    stale_signers.push(*address);
                }
            }
            if missing_signers.is_empty()
                && stale_signers.is_empty()
                && unexpected_messages.is_empty()
            {
                info!(
                    "All {} signers are sending messages as expected.",
                    nmb_signers
                );
            } else {
                self.print_missing_signers(&missing_signers);
                self.print_stale_signers(&stale_signers);
                self.print_unexpected_messages(&unexpected_messages);
            }
            sleep_ms(interval_ms);
        }
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
        Command::MonitorSigners(args) => {
            handle_monitor_signers(args);
        }
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
