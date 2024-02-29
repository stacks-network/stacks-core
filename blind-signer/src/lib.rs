use libsigner::{BlockResponse, SignerMessage, SignerSession, StackerDBSession};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::nakamoto::signer_set::NakamotoSigners;
use stacks::chainstate::nakamoto::test_signers::TestSigners;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::boot::{MINERS_NAME, SIGNERS_VOTING_NAME};
use stacks::clarity::vm::types::QualifiedContractIdentifier;
use stacks::clarity::vm::Value;
use stacks::codec::StacksMessageCodec;
use stacks::libstackerdb::{SlotMetadata, StackerDBChunkData};
use stacks::net::api::callreadonly::CallReadOnlyRequestBody;
use stacks::net::api::getstackers::GetStackersResponse;
use stacks::types::chainstate::StacksAddress;
use stacks::util::hash::to_hex;
use stacks::util_lib::boot::boot_code_id;
use stacks_common::types::chainstate::StacksPublicKey;
use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_node::config::Config;
use stacks_node::utils::{get_account, make_contract_call, submit_tx, to_addr};
use std::{
    collections::HashSet,
    thread::{self, JoinHandle},
    time::Duration,
};

#[allow(unused_imports)]
#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;
#[macro_use]
extern crate stacks_common;

/// Spawn a blind signing thread. `signer` is the private key
///  of the individual signer who broadcasts the response to the StackerDB
pub fn blind_signer(
    conf: &Config,
    signers: &TestSigners,
    signer: &Secp256k1PrivateKey,
) -> JoinHandle<()> {
    let mut signed_blocks = HashSet::new();
    let conf = conf.clone();
    let signers = signers.clone();
    let signer = signer.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(500));
        match read_and_sign_block_proposal(&conf, &signers, &signer, &signed_blocks) {
            Ok(signed_block) => {
                if signed_blocks.contains(&signed_block) {
                    continue;
                }
                info!("Signed block"; "signer_sig_hash" => signed_block.to_hex());
                signed_blocks.insert(signed_block);
            }
            Err(e) => {
                warn!("Error reading and signing block proposal: {e}");
            }
        }

        signer_vote_if_needed(&conf, &signers, &signer);
    })
}

pub fn read_and_sign_block_proposal(
    conf: &Config,
    signers: &TestSigners,
    signer: &Secp256k1PrivateKey,
    signed_blocks: &HashSet<Sha512Trunc256Sum>,
) -> Result<Sha512Trunc256Sum, String> {
    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let miner_pubkey = StacksPublicKey::from_private(&conf.get_miner_config().mining_key.unwrap());
    let miner_slot_id = NakamotoChainState::get_miner_slot(&sortdb, &tip, &miner_pubkey)
        .map_err(|_| "Unable to get miner slot")?
        .ok_or("No miner slot exists")?;
    let reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();
    let rpc_sock = conf
        .node
        .rpc_bind
        .clone()
        .parse()
        .expect("Failed to parse socket");

    let mut proposed_block: NakamotoBlock = {
        let miner_contract_id = boot_code_id(MINERS_NAME, false);
        let mut miners_stackerdb = StackerDBSession::new(rpc_sock, miner_contract_id);
        miners_stackerdb
            .get_latest(miner_slot_id)
            .map_err(|_| "Failed to get latest chunk from the miner slot ID")?
            .ok_or("No chunk found")?
    };
    let proposed_block_hash = format!("0x{}", proposed_block.header.block_hash());
    let signer_sig_hash = proposed_block.header.signer_signature_hash();
    if signed_blocks.contains(&signer_sig_hash) {
        // already signed off on this block, don't sign again.
        return Ok(signer_sig_hash);
    }

    info!(
        "Fetched proposed block from .miners StackerDB";
        "proposed_block_hash" => &proposed_block_hash,
        "signer_sig_hash" => &signer_sig_hash.to_hex(),
    );

    signers
        .clone()
        .sign_nakamoto_block(&mut proposed_block, reward_cycle);

    let signer_message = SignerMessage::BlockResponse(BlockResponse::Accepted((
        signer_sig_hash.clone(),
        proposed_block.header.signer_signature.clone(),
    )));

    let signers_contract_id =
        NakamotoSigners::make_signers_db_contract_id(reward_cycle, libsigner::BLOCK_MSG_ID, false);

    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let signers_info = get_stacker_set(&http_origin, reward_cycle);
    let signer_index = get_signer_index(&signers_info, &Secp256k1PublicKey::from_private(signer))
        .unwrap()
        .try_into()
        .unwrap();

    let next_version = get_stackerdb_slot_version(&http_origin, &signers_contract_id, signer_index)
        .map(|x| x + 1)
        .unwrap_or(0);
    let mut signers_contract_sess = StackerDBSession::new(rpc_sock, signers_contract_id);
    let mut chunk_to_put = StackerDBChunkData::new(
        u32::try_from(signer_index).unwrap(),
        next_version,
        signer_message.serialize_to_vec(),
    );
    chunk_to_put.sign(signer).unwrap();
    signers_contract_sess
        .put_chunk(&chunk_to_put)
        .map_err(|e| e.to_string())?;
    Ok(signer_sig_hash)
}

fn signer_vote_if_needed(conf: &Config, signers: &TestSigners, signer: &Secp256k1PrivateKey) {
    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();
    let prepare_phase_start = burnchain
        .pox_constants
        .prepare_phase_start(burnchain.first_block_height, reward_cycle);

    if tip.block_height >= prepare_phase_start {
        // If the key is already set, do nothing.
        if is_key_set_for_cycle(reward_cycle + 1, conf.is_mainnet(), &conf.node.rpc_bind)
            .unwrap_or(false)
        {
            return;
        }

        // If we are self-signing, then we need to vote on the aggregate public key
        let http_origin = format!("http://{}", &conf.node.rpc_bind);

        // Get the aggregate key
        let aggregate_key = signers.clone().generate_aggregate_key(reward_cycle + 1);
        let aggregate_public_key = Value::buff_from(aggregate_key.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

        let signer_nonce = get_account(&http_origin, &to_addr(signer)).nonce;

        // Vote on the aggregate public key
        let voting_tx = make_contract_call(
            &signer,
            signer_nonce,
            300,
            &StacksAddress::burn_address(false),
            SIGNERS_VOTING_NAME,
            "vote-for-aggregate-public-key",
            &[
                Value::UInt(0),
                aggregate_public_key.clone(),
                Value::UInt(0),
                Value::UInt(reward_cycle as u128 + 1),
            ],
        );
        submit_tx(&http_origin, &voting_tx);
    }
}

pub fn get_stacker_set(http_origin: &str, cycle: u64) -> GetStackersResponse {
    let client = reqwest::blocking::Client::new();
    let path = format!("{http_origin}/v2/stacker_set/{cycle}");
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<serde_json::Value>()
        .unwrap();
    info!("Stacker set response: {res}");
    let res = serde_json::from_value(res).unwrap();
    res
}

fn get_signer_index(
    stacker_set: &GetStackersResponse,
    signer_key: &Secp256k1PublicKey,
) -> Result<usize, String> {
    let Some(ref signer_set) = stacker_set.stacker_set.signers else {
        return Err("Empty signer set for reward cycle".into());
    };
    let signer_key_bytes = signer_key.to_bytes_compressed();
    signer_set
        .iter()
        .enumerate()
        .find_map(|(ix, entry)| {
            if entry.signing_key.as_slice() == signer_key_bytes.as_slice() {
                Some(ix)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            format!(
                "Signing key not found. {} not found.",
                to_hex(&signer_key_bytes)
            )
        })
}

pub fn get_stackerdb_slot_version(
    http_origin: &str,
    contract: &QualifiedContractIdentifier,
    slot_id: u64,
) -> Option<u32> {
    let client = reqwest::blocking::Client::new();
    let path = format!(
        "{http_origin}/v2/stackerdb/{}/{}",
        &contract.issuer, &contract.name
    );
    let res = client
        .get(&path)
        .send()
        .unwrap()
        .json::<Vec<SlotMetadata>>()
        .unwrap();
    debug!("StackerDB metadata response: {res:?}");
    res.iter().find_map(|slot| {
        if u64::from(slot.slot_id) == slot_id {
            Some(slot.slot_version)
        } else {
            None
        }
    })
}

fn is_key_set_for_cycle(
    reward_cycle: u64,
    is_mainnet: bool,
    http_origin: &str,
) -> Result<bool, String> {
    let client = reqwest::blocking::Client::new();
    let boot_address = StacksAddress::burn_address(is_mainnet);
    let path = format!("http://{http_origin}/v2/contracts/call-read/{boot_address}/signers-voting/get-approved-aggregate-key");
    let body = CallReadOnlyRequestBody {
        sender: boot_address.to_string(),
        sponsor: None,
        arguments: vec![Value::UInt(reward_cycle as u128)
            .serialize_to_hex()
            .map_err(|_| "Failed to serialize reward cycle")?],
    };
    let res = client
        .post(&path)
        .json(&body)
        .send()
        .map_err(|_| "Failed to send request")?
        .json::<serde_json::Value>()
        .map_err(|_| "Failed to extract json Value")?;
    let result_value = Value::try_deserialize_hex_untyped(
        &res.get("result")
            .ok_or("No result in response")?
            .as_str()
            .ok_or("Result is not a string")?[2..],
    )
    .map_err(|_| "Failed to deserialize Clarity value")?;

    result_value
        .expect_optional()
        .map(|v| v.is_some())
        .map_err(|_| "Response is not optional".to_string())
}
