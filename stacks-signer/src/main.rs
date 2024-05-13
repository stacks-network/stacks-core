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

use std::io::{self, Write};

use blockstack_lib::util_lib::signed_structured_data::pox4::make_pox_4_signer_key_signature;
use clap::Parser;
use clarity::vm::types::QualifiedContractIdentifier;
use libsigner::{SignerSession, StackerDBSession};
use libstackerdb::StackerDBChunkData;
use slog::slog_debug;
use stacks_common::debug;
use stacks_common::util::hash::to_hex;
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use stacks_signer::cli::{
    Cli, Command, GenerateStackingSignatureArgs, GetChunkArgs, GetLatestChunkArgs, PutChunkArgs,
    RunSignerArgs, StackerDBArgs,
};
use stacks_signer::config::GlobalConfig;
use stacks_signer::v1;
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
    let spawned_signer = v1::SpawnedSigner::from(config);
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
    let public_key = Secp256k1PublicKey::from_private(&private_key);

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
            "signerKey": to_hex(&public_key.to_bytes_compressed()),
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
            to_hex(&public_key.to_bytes_compressed()),
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
    }
}

#[cfg(test)]
pub mod tests {
    use blockstack_lib::chainstate::stacks::address::PoxAddress;
    use blockstack_lib::chainstate::stacks::boot::POX_4_CODE;
    use blockstack_lib::util_lib::signed_structured_data::pox4::{
        make_pox_4_signer_key_message_hash, Pox4SignatureTopic,
    };
    use clarity::vm::{execute_v2, Value};
    use stacks_common::consts::CHAIN_ID_TESTNET;
    use stacks_common::types::PublicKey;
    use stacks_common::util::secp256k1::Secp256k1PublicKey;
    use stacks_signer::cli::parse_pox_addr;

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
}
