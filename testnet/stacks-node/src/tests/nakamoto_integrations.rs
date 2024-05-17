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
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier};
use clarity::vm::ClarityVersion;
use http_types::headers::AUTHORIZATION;
use lazy_static::lazy_static;
use libsigner::v1::messages::SignerMessage;
use libsigner::{BlockProposal, SignerSession, StackerDBSession};
use rand::RngCore;
use stacks::burnchains::{MagicBytes, Txid};
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::{
    BlockstackOperationType, PreStxOp, StackStxOp, VoteForAggregateKeyOp,
};
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use stacks::chainstate::nakamoto::test_signers::TestSigners;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use stacks::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
use stacks::chainstate::stacks::boot::{
    MINERS_NAME, SIGNERS_VOTING_FUNCTION_NAME, SIGNERS_VOTING_NAME,
};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use stacks::chainstate::stacks::{StacksTransaction, ThresholdSignature, TransactionPayload};
use stacks::core::{
    StacksEpoch, StacksEpochId, BLOCK_LIMIT_MAINNET_10, HELIUM_BLOCK_LIMIT_20,
    PEER_VERSION_EPOCH_1_0, PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05,
    PEER_VERSION_EPOCH_2_1, PEER_VERSION_EPOCH_2_2, PEER_VERSION_EPOCH_2_3, PEER_VERSION_EPOCH_2_4,
    PEER_VERSION_EPOCH_2_5, PEER_VERSION_EPOCH_3_0, PEER_VERSION_TESTNET,
};
use stacks::libstackerdb::SlotMetadata;
use stacks::net::api::callreadonly::CallReadOnlyRequestBody;
use stacks::net::api::getstackers::GetStackersResponse;
use stacks::net::api::postblock_proposal::{
    BlockValidateReject, BlockValidateResponse, NakamotoBlockProposal, ValidateRejectCode,
};
use stacks::util::hash::hex_bytes;
use stacks::util_lib::boot::boot_code_id;
use stacks::util_lib::signed_structured_data::pox4::{
    make_pox_4_signer_key_signature, Pox4SignatureTopic,
};
use stacks_common::address::AddressHashMode;
use stacks_common::bitvec::BitVec;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::consts::{CHAIN_ID_TESTNET, STACKS_EPOCH_MAX};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{to_hex, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks_common::util::sleep_ms;
use wsts::net::Message;

use super::bitcoin_regtest::BitcoinCoreController;
use crate::config::{EventKeyType, EventObserverConfig, InitialBalance};
use crate::nakamoto_node::miner::TEST_BROADCAST_STALL;
use crate::nakamoto_node::relayer::TEST_SKIP_COMMIT_OP;
use crate::neon::{Counters, RunLoopCounter};
use crate::operations::BurnchainOpSigner;
use crate::run_loop::boot_nakamoto;
use crate::tests::neon_integrations::{
    call_read_only, get_account, get_chain_info_result, get_pox_info, next_block_and_wait,
    run_until_burnchain_height, submit_tx, test_observer, wait_for_runloop,
};
use crate::tests::{
    get_chain_info, make_contract_publish, make_contract_publish_versioned, make_stacks_transfer,
    to_addr,
};
use crate::{tests, BitcoinRegtestController, BurnchainController, Config, ConfigFile, Keychain};

pub static POX_4_DEFAULT_STACKER_BALANCE: u64 = 100_000_000_000_000;
static POX_4_DEFAULT_STACKER_STX_AMT: u128 = 99_000_000_000_000;

lazy_static! {
    pub static ref NAKAMOTO_INTEGRATION_EPOCHS: [StacksEpoch; 9] = [
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: BLOCK_LIMIT_MAINNET_10.clone(),
            network_epoch: PEER_VERSION_EPOCH_1_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 1,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_0
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 1,
            end_height: 2,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_05
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: 2,
            end_height: 3,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_1
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: 3,
            end_height: 4,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_2
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: 4,
            end_height: 5,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_3
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: 5,
            end_height: 201,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_4
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: 201,
            end_height: 231,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_2_5
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch30,
            start_height: 231,
            end_height: STACKS_EPOCH_MAX,
            block_limit: HELIUM_BLOCK_LIMIT_20.clone(),
            network_epoch: PEER_VERSION_EPOCH_3_0
        },
    ];
}

pub static TEST_SIGNING: Mutex<Option<TestSigningChannel>> = Mutex::new(None);

pub struct TestSigningChannel {
    pub recv: Option<Receiver<ThresholdSignature>>,
    pub send: Sender<ThresholdSignature>,
}

impl TestSigningChannel {
    /// If the integration test has instantiated the singleton TEST_SIGNING channel,
    ///  wait for a signature from the blind-signer.
    /// Returns None if the singleton isn't instantiated and the miner should coordinate
    ///  a real signer set signature.
    /// Panics if the blind-signer times out.
    pub fn get_signature() -> Option<ThresholdSignature> {
        let mut signer = TEST_SIGNING.lock().unwrap();
        let Some(sign_channels) = signer.as_mut() else {
            return None;
        };
        let recv = sign_channels.recv.take().unwrap();
        drop(signer); // drop signer so we don't hold the lock while receiving.
        let signature = recv.recv_timeout(Duration::from_secs(30)).unwrap();
        let overwritten = TEST_SIGNING
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .recv
            .replace(recv);
        assert!(overwritten.is_none());
        Some(signature)
    }

    /// Setup the TestSigningChannel as a singleton using TEST_SIGNING,
    ///  returning an owned Sender to the channel.
    pub fn instantiate() -> Sender<ThresholdSignature> {
        let (send, recv) = channel();
        let existed = TEST_SIGNING.lock().unwrap().replace(Self {
            recv: Some(recv),
            send: send.clone(),
        });
        assert!(existed.is_none());
        send
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

pub fn add_initial_balances(
    conf: &mut Config,
    accounts: usize,
    amount: u64,
) -> Vec<StacksPrivateKey> {
    (0..accounts)
        .map(|i| {
            let privk = StacksPrivateKey::from_seed(&[5, 5, 5, i as u8]);
            let address = to_addr(&privk).into();

            conf.initial_balances
                .push(InitialBalance { address, amount });
            privk
        })
        .collect()
}

/// Spawn a blind signing thread. `signer` is the private key
///  of the individual signer who broadcasts the response to the StackerDB
pub fn blind_signer(
    conf: &Config,
    signers: &TestSigners,
    proposals_count: RunLoopCounter,
) -> JoinHandle<()> {
    let sender = TestSigningChannel::instantiate();
    let mut signed_blocks = HashSet::new();
    let conf = conf.clone();
    let signers = signers.clone();
    let mut last_count = proposals_count.load(Ordering::SeqCst);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(100));
        let cur_count = proposals_count.load(Ordering::SeqCst);
        if cur_count <= last_count {
            continue;
        }
        last_count = cur_count;
        match read_and_sign_block_proposal(&conf, &signers, &signed_blocks, &sender) {
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
    })
}

pub fn get_latest_block_proposal(
    conf: &Config,
    sortdb: &SortitionDB,
) -> Result<NakamotoBlock, String> {
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let miner_pubkey = StacksPublicKey::from_private(&conf.get_miner_config().mining_key.unwrap());
    let miner_slot_id = NakamotoChainState::get_miner_slot(&sortdb, &tip, &miner_pubkey)
        .map_err(|_| "Unable to get miner slot")?
        .ok_or("No miner slot exists")?;

    let proposed_block = {
        let miner_contract_id = boot_code_id(MINERS_NAME, false);
        let mut miners_stackerdb = StackerDBSession::new(&conf.node.rpc_bind, miner_contract_id);
        let message: SignerMessage = miners_stackerdb
            .get_latest(miner_slot_id.start)
            .expect("Failed to get latest chunk from the miner slot ID")
            .expect("No chunk found");
        let SignerMessage::Packet(packet) = message else {
            panic!("Expected a signer message packet. Got {message:?}");
        };
        let Message::NonceRequest(nonce_request) = packet.msg else {
            panic!("Expected a nonce request. Got {:?}", packet.msg);
        };
        let block_proposal =
            BlockProposal::consensus_deserialize(&mut nonce_request.message.as_slice())
                .expect("Failed to deserialize block proposal");
        block_proposal.block
    };
    Ok(proposed_block)
}

pub fn read_and_sign_block_proposal(
    conf: &Config,
    signers: &TestSigners,
    signed_blocks: &HashSet<Sha512Trunc256Sum>,
    channel: &Sender<ThresholdSignature>,
) -> Result<Sha512Trunc256Sum, String> {
    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let reward_cycle = burnchain
        .block_height_to_reward_cycle(tip.block_height)
        .unwrap();

    let mut proposed_block = get_latest_block_proposal(conf, &sortdb)?;
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

    channel
        .send(proposed_block.header.signer_signature)
        .unwrap();
    return Ok(signer_sig_hash);
}

/// Return a working nakamoto-neon config and the miner's bitcoin address to fund
pub fn naka_neon_integration_conf(seed: Option<&[u8]>) -> (Config, StacksAddress) {
    let mut conf = super::new_test_conf();

    conf.burnchain.mode = "nakamoto-neon".into();

    // tests can override this, but these tests run with epoch 2.05 by default
    conf.burnchain.epochs = Some(NAKAMOTO_INTEGRATION_EPOCHS.to_vec());

    if let Some(seed) = seed {
        conf.node.seed = seed.to_vec();
    }

    // instantiate the keychain so we can fund the bitcoin op signer
    let keychain = Keychain::default(conf.node.seed.clone());

    let mining_key = Secp256k1PrivateKey::from_seed(&[1]);
    conf.miner.mining_key = Some(mining_key);

    conf.node.miner = true;
    conf.node.wait_time_for_microblocks = 500;
    conf.burnchain.burn_fee_cap = 20000;

    conf.burnchain.username = Some("neon-tester".into());
    conf.burnchain.password = Some("neon-tester-pass".into());
    conf.burnchain.peer_host = "127.0.0.1".into();
    conf.burnchain.local_mining_public_key =
        Some(keychain.generate_op_signer().get_public_key().to_hex());
    conf.burnchain.commit_anchor_block_within = 0;
    conf.node.add_signers_stackerdbs(false);
    conf.node.add_miner_stackerdb(false);

    // test to make sure config file parsing is correct
    let mut cfile = ConfigFile::xenon();
    cfile.node.as_mut().map(|node| node.bootstrap_node.take());

    if let Some(burnchain) = cfile.burnchain.as_mut() {
        burnchain.peer_host = Some("127.0.0.1".to_string());
    }

    conf.burnchain.magic_bytes = MagicBytes::from(['T' as u8, '3' as u8].as_ref());
    conf.burnchain.poll_time_secs = 1;
    conf.node.pox_sync_sample_secs = 0;

    conf.miner.first_attempt_time_ms = i64::max_value() as u64;
    conf.miner.subsequent_attempt_time_ms = i64::max_value() as u64;

    // if there's just one node, then this must be true for tests to pass
    conf.miner.wait_for_block_download = false;

    conf.node.mine_microblocks = false;
    conf.miner.microblock_attempt_time_ms = 10;
    conf.node.microblock_frequency = 0;
    conf.node.wait_time_for_blocks = 200;

    let miner_account = keychain.origin_address(conf.is_mainnet()).unwrap();

    conf.burnchain.pox_prepare_length = Some(5);
    conf.burnchain.pox_reward_length = Some(20);

    conf.connection_options.inv_sync_interval = 1;

    (conf, miner_account)
}

pub fn next_block_and<F>(
    btc_controller: &mut BitcoinRegtestController,
    timeout_secs: u64,
    mut check: F,
) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    eprintln!("Issuing bitcoin block");
    btc_controller.build_next_block(1);
    let start = Instant::now();
    while !check()? {
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            error!("Timed out waiting for block to process, trying to continue test");
            return Err("Timed out".into());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

/// Mine a bitcoin block, and wait until:
///  (1) a new block has been processed by the coordinator
pub fn next_block_and_process_new_stacks_block(
    btc_controller: &mut BitcoinRegtestController,
    timeout_secs: u64,
    coord_channels: &Arc<Mutex<CoordinatorChannels>>,
) -> Result<(), String> {
    let blocks_processed_before = coord_channels
        .lock()
        .expect("Mutex poisoned")
        .get_stacks_blocks_processed();
    next_block_and(btc_controller, timeout_secs, || {
        let blocks_processed = coord_channels
            .lock()
            .expect("Mutex poisoned")
            .get_stacks_blocks_processed();
        if blocks_processed > blocks_processed_before {
            return Ok(true);
        }
        Ok(false)
    })
}

/// Mine a bitcoin block, and wait until:
///  (1) a new block has been processed by the coordinator
///  (2) 2 block commits have been issued ** or ** more than 10 seconds have
///      passed since (1) occurred
pub fn next_block_and_mine_commit(
    btc_controller: &mut BitcoinRegtestController,
    timeout_secs: u64,
    coord_channels: &Arc<Mutex<CoordinatorChannels>>,
    commits_submitted: &Arc<AtomicU64>,
) -> Result<(), String> {
    let commits_submitted = commits_submitted.clone();
    let blocks_processed_before = coord_channels
        .lock()
        .expect("Mutex poisoned")
        .get_stacks_blocks_processed();
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let mut block_processed_time: Option<Instant> = None;
    let mut commit_sent_time: Option<Instant> = None;
    next_block_and(btc_controller, timeout_secs, || {
        let commits_sent = commits_submitted.load(Ordering::SeqCst);
        let blocks_processed = coord_channels
            .lock()
            .expect("Mutex poisoned")
            .get_stacks_blocks_processed();
        let now = Instant::now();
        if blocks_processed > blocks_processed_before && block_processed_time.is_none() {
            block_processed_time.replace(now);
        }
        if commits_sent > commits_before && commit_sent_time.is_none() {
            commit_sent_time.replace(now);
        }
        if blocks_processed > blocks_processed_before {
            let block_processed_time = block_processed_time
                .as_ref()
                .ok_or("TEST-ERROR: Processed time wasn't set")?;
            if commits_sent <= commits_before {
                return Ok(false);
            }
            let commit_sent_time = commit_sent_time
                .as_ref()
                .ok_or("TEST-ERROR: Processed time wasn't set")?;
            // try to ensure the commit was sent after the block was processed
            if commit_sent_time > block_processed_time {
                return Ok(true);
            }
            // if two commits have been sent, one of them must have been after
            if commits_sent >= commits_before + 2 {
                return Ok(true);
            }
            // otherwise, just timeout if the commit was sent and its been long enough
            //  for a new commit pass to have occurred
            if block_processed_time.elapsed() > Duration::from_secs(10) {
                return Ok(true);
            }
            Ok(false)
        } else {
            Ok(false)
        }
    })
}

pub fn setup_stacker(naka_conf: &mut Config) -> Secp256k1PrivateKey {
    let stacker_sk = Secp256k1PrivateKey::new();
    let stacker_address = tests::to_addr(&stacker_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(stacker_address.clone()).to_string(),
        POX_4_DEFAULT_STACKER_BALANCE,
    );
    stacker_sk
}

///
/// * `stacker_sks` - must be a private key for sending a large `stack-stx` transaction in order
///   for pox-4 to activate
pub fn boot_to_epoch_3(
    naka_conf: &Config,
    blocks_processed: &Arc<AtomicU64>,
    stacker_sks: &[StacksPrivateKey],
    signer_sks: &[StacksPrivateKey],
    self_signing: Option<&TestSigners>,
    btc_regtest_controller: &mut BitcoinRegtestController,
) {
    assert_eq!(stacker_sks.len(), signer_sks.len());

    let epochs = naka_conf.burnchain.epochs.clone().unwrap();
    let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];

    info!(
        "Chain bootstrapped to bitcoin block 201, starting Epoch 2x miner";
        "Epoch 3.0 Boundary" => (epoch_3.start_height - 1),
    );
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    next_block_and_wait(btc_regtest_controller, &blocks_processed);
    next_block_and_wait(btc_regtest_controller, &blocks_processed);
    // first mined stacks block
    next_block_and_wait(btc_regtest_controller, &blocks_processed);

    // stack enough to activate pox-4

    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    for (stacker_sk, signer_sk) in stacker_sks.iter().zip(signer_sks.iter()) {
        let pox_addr = PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            tests::to_addr(&stacker_sk).bytes,
        );
        let pox_addr_tuple: clarity::vm::Value =
            pox_addr.clone().as_clarity_tuple().unwrap().into();
        let signature = make_pox_4_signer_key_signature(
            &pox_addr,
            &signer_sk,
            reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            12_u128,
            u128::MAX,
            1,
        )
        .unwrap()
        .to_rsv();

        let signer_pk = StacksPublicKey::from_private(signer_sk);

        let stacking_tx = tests::make_contract_call(
            &stacker_sk,
            0,
            1000,
            &StacksAddress::burn_address(false),
            "pox-4",
            "stack-stx",
            &[
                clarity::vm::Value::UInt(POX_4_DEFAULT_STACKER_STX_AMT),
                pox_addr_tuple.clone(),
                clarity::vm::Value::UInt(block_height as u128),
                clarity::vm::Value::UInt(12),
                clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                    .unwrap(),
                clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
                clarity::vm::Value::UInt(u128::MAX),
                clarity::vm::Value::UInt(1),
            ],
        );
        submit_tx(&http_origin, &stacking_tx);
    }

    let prepare_phase_start = btc_regtest_controller
        .get_burnchain()
        .pox_constants
        .prepare_phase_start(
            btc_regtest_controller.get_burnchain().first_block_height,
            reward_cycle,
        );

    // Run until the prepare phase
    run_until_burnchain_height(
        btc_regtest_controller,
        &blocks_processed,
        prepare_phase_start,
        &naka_conf,
    );

    // We need to vote on the aggregate public key if this test is self signing
    if let Some(signers) = self_signing {
        // Get the aggregate key
        let aggregate_key = signers.clone().generate_aggregate_key(reward_cycle + 1);
        let aggregate_public_key =
            clarity::vm::Value::buff_from(aggregate_key.compress().data.to_vec())
                .expect("Failed to serialize aggregate public key");
        let signer_sks_unique: HashMap<_, _> = signer_sks.iter().map(|x| (x.to_hex(), x)).collect();
        let signer_set = get_stacker_set(&http_origin, reward_cycle + 1);
        // Vote on the aggregate public key
        for signer_sk in signer_sks_unique.values() {
            let signer_index =
                get_signer_index(&signer_set, &Secp256k1PublicKey::from_private(signer_sk))
                    .unwrap();
            let voting_tx = tests::make_contract_call(
                signer_sk,
                0,
                300,
                &StacksAddress::burn_address(false),
                SIGNERS_VOTING_NAME,
                SIGNERS_VOTING_FUNCTION_NAME,
                &[
                    clarity::vm::Value::UInt(u128::try_from(signer_index).unwrap()),
                    aggregate_public_key.clone(),
                    clarity::vm::Value::UInt(0),
                    clarity::vm::Value::UInt(reward_cycle as u128 + 1),
                ],
            );
            submit_tx(&http_origin, &voting_tx);
        }
    }

    run_until_burnchain_height(
        btc_regtest_controller,
        &blocks_processed,
        epoch_3.start_height - 1,
        &naka_conf,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, Epoch2x miner should stop");
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

/// Use the read-only API to get the aggregate key for a given reward cycle
pub fn get_key_for_cycle(
    reward_cycle: u64,
    is_mainnet: bool,
    http_origin: &str,
) -> Result<Option<Vec<u8>>, String> {
    let client = reqwest::blocking::Client::new();
    let boot_address = StacksAddress::burn_address(is_mainnet);
    let path = format!("http://{http_origin}/v2/contracts/call-read/{boot_address}/signers-voting/get-approved-aggregate-key");
    let body = CallReadOnlyRequestBody {
        sender: boot_address.to_string(),
        sponsor: None,
        arguments: vec![clarity::vm::Value::UInt(reward_cycle as u128)
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
    let result_value = clarity::vm::Value::try_deserialize_hex_untyped(
        &res.get("result")
            .ok_or("No result in response")?
            .as_str()
            .ok_or("Result is not a string")?[2..],
    )
    .map_err(|_| "Failed to deserialize Clarity value")?;

    let buff_opt = result_value
        .expect_optional()
        .expect("Expected optional type");

    match buff_opt {
        Some(buff_val) => {
            let buff = buff_val
                .expect_buff(33)
                .map_err(|_| "Failed to get buffer value")?;
            Ok(Some(buff))
        }
        None => Ok(None),
    }
}

/// Use the read-only to check if the aggregate key is set for a given reward cycle
pub fn is_key_set_for_cycle(
    reward_cycle: u64,
    is_mainnet: bool,
    http_origin: &str,
) -> Result<bool, String> {
    let key = get_key_for_cycle(reward_cycle, is_mainnet, &http_origin)?;
    Ok(key.is_some())
}

fn signer_vote_if_needed(
    btc_regtest_controller: &BitcoinRegtestController,
    naka_conf: &Config,
    signer_sks: &[StacksPrivateKey], // TODO: Is there some way to get this from the TestSigners?
    signers: &TestSigners,
) {
    // When we reach the next prepare phase, submit new voting transactions
    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let prepare_phase_start = btc_regtest_controller
        .get_burnchain()
        .pox_constants
        .prepare_phase_start(
            btc_regtest_controller.get_burnchain().first_block_height,
            reward_cycle,
        );

    if block_height >= prepare_phase_start {
        // If the key is already set, do nothing.
        if is_key_set_for_cycle(
            reward_cycle + 1,
            naka_conf.is_mainnet(),
            &naka_conf.node.rpc_bind,
        )
        .unwrap_or(false)
        {
            return;
        }

        // If we are self-signing, then we need to vote on the aggregate public key
        let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

        // Get the aggregate key
        let aggregate_key = signers.clone().generate_aggregate_key(reward_cycle + 1);
        let aggregate_public_key =
            clarity::vm::Value::buff_from(aggregate_key.compress().data.to_vec())
                .expect("Failed to serialize aggregate public key");

        for (i, signer_sk) in signer_sks.iter().enumerate() {
            let signer_nonce = get_account(&http_origin, &to_addr(signer_sk)).nonce;

            // Vote on the aggregate public key
            let voting_tx = tests::make_contract_call(
                &signer_sk,
                signer_nonce,
                300,
                &StacksAddress::burn_address(false),
                SIGNERS_VOTING_NAME,
                "vote-for-aggregate-public-key",
                &[
                    clarity::vm::Value::UInt(i as u128),
                    aggregate_public_key.clone(),
                    clarity::vm::Value::UInt(0),
                    clarity::vm::Value::UInt(reward_cycle as u128 + 1),
                ],
            );
            submit_tx(&http_origin, &voting_tx);
        }
    }
}

///
/// * `stacker_sks` - must be a private key for sending a large `stack-stx` transaction in order
///   for pox-4 to activate
/// * `signer_pks` - must be the same size as `stacker_sks`
pub fn boot_to_epoch_3_reward_set_calculation_boundary(
    naka_conf: &Config,
    blocks_processed: &Arc<AtomicU64>,
    stacker_sks: &[StacksPrivateKey],
    signer_sks: &[StacksPrivateKey],
    btc_regtest_controller: &mut BitcoinRegtestController,
) {
    assert_eq!(stacker_sks.len(), signer_sks.len());

    let epochs = naka_conf.burnchain.epochs.clone().unwrap();
    let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];
    let reward_cycle_len = naka_conf.get_burnchain().pox_constants.reward_cycle_length as u64;
    let prepare_phase_len = naka_conf.get_burnchain().pox_constants.prepare_length as u64;

    let epoch_3_start_height = epoch_3.start_height;
    assert!(
        epoch_3_start_height > 0,
        "Epoch 3.0 start height must be greater than 0"
    );
    let epoch_3_reward_cycle_boundary =
        epoch_3_start_height.saturating_sub(epoch_3_start_height % reward_cycle_len);
    let epoch_3_reward_set_calculation_boundary = epoch_3_reward_cycle_boundary
        .saturating_sub(prepare_phase_len)
        .wrapping_add(1);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    next_block_and_wait(btc_regtest_controller, &blocks_processed);
    next_block_and_wait(btc_regtest_controller, &blocks_processed);
    // first mined stacks block
    next_block_and_wait(btc_regtest_controller, &blocks_processed);

    // stack enough to activate pox-4
    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let lock_period = 12;
    debug!("Test Cycle Info";
     "prepare_phase_len" => {prepare_phase_len},
     "reward_cycle_len" => {reward_cycle_len},
     "block_height" => {block_height},
     "reward_cycle" => {reward_cycle},
     "epoch_3_reward_cycle_boundary" => {epoch_3_reward_cycle_boundary},
     "epoch_3_start_height" => {epoch_3_start_height},
    );
    for (stacker_sk, signer_sk) in stacker_sks.iter().zip(signer_sks.iter()) {
        let pox_addr = PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            tests::to_addr(&stacker_sk).bytes,
        );
        let pox_addr_tuple: clarity::vm::Value =
            pox_addr.clone().as_clarity_tuple().unwrap().into();
        let signature = make_pox_4_signer_key_signature(
            &pox_addr,
            &signer_sk,
            reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            lock_period,
            u128::MAX,
            1,
        )
        .unwrap()
        .to_rsv();

        let signer_pk = StacksPublicKey::from_private(signer_sk);
        let stacking_tx = tests::make_contract_call(
            &stacker_sk,
            0,
            1000,
            &StacksAddress::burn_address(false),
            "pox-4",
            "stack-stx",
            &[
                clarity::vm::Value::UInt(POX_4_DEFAULT_STACKER_STX_AMT),
                pox_addr_tuple.clone(),
                clarity::vm::Value::UInt(block_height as u128),
                clarity::vm::Value::UInt(lock_period),
                clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                    .unwrap(),
                clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
                clarity::vm::Value::UInt(u128::MAX),
                clarity::vm::Value::UInt(1),
            ],
        );
        submit_tx(&http_origin, &stacking_tx);
    }

    run_until_burnchain_height(
        btc_regtest_controller,
        &blocks_processed,
        epoch_3_reward_set_calculation_boundary,
        &naka_conf,
    );

    info!("Bootstrapped to Epoch 3.0 reward set calculation boundary height: {epoch_3_reward_set_calculation_boundary}.");
}

///
/// * `stacker_sks` - must be a private key for sending a large `stack-stx` transaction in order
///   for pox-4 to activate
/// * `signer_pks` - must be the same size as `stacker_sks`
pub fn boot_to_epoch_3_reward_set(
    naka_conf: &Config,
    blocks_processed: &Arc<AtomicU64>,
    stacker_sks: &[StacksPrivateKey],
    signer_sks: &[StacksPrivateKey],
    btc_regtest_controller: &mut BitcoinRegtestController,
) {
    boot_to_epoch_3_reward_set_calculation_boundary(
        naka_conf,
        blocks_processed,
        stacker_sks,
        signer_sks,
        btc_regtest_controller,
    );
    let epoch_3_reward_set_calculation =
        btc_regtest_controller.get_headers_height().wrapping_add(1);
    run_until_burnchain_height(
        btc_regtest_controller,
        &blocks_processed,
        epoch_3_reward_set_calculation,
        &naka_conf,
    );
    info!("Bootstrapped to Epoch 3.0 reward set calculation height: {epoch_3_reward_set_calculation}.");
}

#[test]
#[ignore]
/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// This test makes three assertions:
///  * 30 blocks are mined after 3.0 starts. This is enough to mine across 2 reward cycles
///  * A transaction submitted to the mempool in 3.0 will be mined in 3.0
///  * The final chain tip is a nakamoto block
fn simple_neon_integration() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let prom_bind = format!("{}:{}", "127.0.0.1", 6000);
    naka_conf.node.prometheus_bind = Some(prom_bind.clone());
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1000);
    let sender_sk = Secp256k1PrivateKey::new();
    // setup sender + recipient for a test stx transfer
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 100;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        send_amt * 2 + send_fee,
    );
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (mut chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    // query for prometheus metrics
    #[cfg(feature = "monitoring_prom")]
    {
        let prom_http_origin = format!("http://{}", prom_bind);
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(&prom_http_origin)
            .send()
            .unwrap()
            .text()
            .unwrap();
        let expected_result = format!("stacks_node_stacks_tip_height {block_height_pre_3_0}");
        assert!(res.contains(&expected_result));
    }

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    // Mine 15 nakamoto tenures
    for _i in 0..15 {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();

        signer_vote_if_needed(
            &btc_regtest_controller,
            &naka_conf,
            &[sender_signer_sk],
            &signers,
        );
    }

    // Submit a TX
    let transfer_tx = make_stacks_transfer(&sender_sk, 0, send_fee, &recipient, send_amt);
    let transfer_tx_hex = format!("0x{}", to_hex(&transfer_tx));

    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    let mut mempool = naka_conf
        .connect_mempool_db()
        .expect("Database failure opening mempool");

    mempool
        .submit_raw(
            &mut chainstate,
            &sortdb,
            &tip.consensus_hash,
            &tip.anchored_header.block_hash(),
            transfer_tx.clone(),
            &ExecutionCost::max_value(),
            &StacksEpochId::Epoch30,
        )
        .unwrap();

    // Mine 15 more nakamoto tenures
    for _i in 0..15 {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();

        signer_vote_if_needed(
            &btc_regtest_controller,
            &naka_conf,
            &[sender_signer_sk],
            &signers,
        );
    }

    // load the chain tip, and assert that it is a nakamoto block and at least 30 blocks have advanced in epoch 3
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    info!(
        "Latest tip";
        "height" => tip.stacks_block_height,
        "is_nakamoto" => tip.anchored_header.as_stacks_nakamoto().is_some(),
    );

    // assert that the transfer tx was observed
    let transfer_tx_included = test_observer::get_blocks()
        .into_iter()
        .find(|block_json| {
            block_json["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|tx_json| tx_json["raw_tx"].as_str() == Some(&transfer_tx_hex))
                .is_some()
        })
        .is_some();

    assert!(
        transfer_tx_included,
        "Nakamoto node failed to include the transfer tx"
    );

    assert!(tip.anchored_header.as_stacks_nakamoto().is_some());
    assert!(tip.stacks_block_height >= block_height_pre_3_0 + 30);

    // make sure prometheus returns an updated height
    #[cfg(feature = "monitoring_prom")]
    {
        let prom_http_origin = format!("http://{}", prom_bind);
        let client = reqwest::blocking::Client::new();
        let res = client
            .get(&prom_http_origin)
            .send()
            .unwrap()
            .text()
            .unwrap();
        let expected_result = format!("stacks_node_stacks_tip_height {}", tip.stacks_block_height);
        assert!(res.contains(&expected_result));
    }

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// This test makes three assertions:
///  * 5 tenures are mined after 3.0 starts
///  * Each tenure has 10 blocks (the coinbase block and 9 interim blocks)
fn mine_multiple_per_tenure_integration() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    let tenure_count = 5;
    let inter_blocks_per_tenure = 9;
    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        (send_amt + send_fee) * tenure_count * inter_blocks_per_tenure,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    // Mine `tenure_count` nakamoto tenures
    for tenure_ix in 0..tenure_count {
        debug!("Mining tenure {}", tenure_ix);
        let commits_before = commits_submitted.load(Ordering::SeqCst);
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 60, &coord_channel)
            .unwrap();

        let mut last_tip = BlockHeaderHash([0x00; 32]);
        let mut last_tip_height = 0;

        // mine the interim blocks
        for interim_block_ix in 0..inter_blocks_per_tenure {
            let blocks_processed_before = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            // submit a tx so that the miner will mine an extra block
            let sender_nonce = tenure_ix * inter_blocks_per_tenure + interim_block_ix;
            let transfer_tx =
                make_stacks_transfer(&sender_sk, sender_nonce, send_fee, &recipient, send_amt);
            submit_tx(&http_origin, &transfer_tx);

            loop {
                let blocks_processed = coord_channel
                    .lock()
                    .expect("Mutex poisoned")
                    .get_stacks_blocks_processed();
                if blocks_processed > blocks_processed_before {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            let info = get_chain_info_result(&naka_conf).unwrap();
            assert_ne!(info.stacks_tip, last_tip);
            assert_ne!(info.stacks_tip_height, last_tip_height);

            last_tip = info.stacks_tip;
            last_tip_height = info.stacks_tip_height;
        }

        let start_time = Instant::now();
        while commits_submitted.load(Ordering::SeqCst) <= commits_before {
            if start_time.elapsed() >= Duration::from_secs(20) {
                panic!("Timed out waiting for block-commit");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // load the chain tip, and assert that it is a nakamoto block and at least 30 blocks have advanced in epoch 3
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    info!(
        "Latest tip";
        "height" => tip.stacks_block_height,
        "is_nakamoto" => tip.anchored_header.as_stacks_nakamoto().is_some(),
    );

    assert!(tip.anchored_header.as_stacks_nakamoto().is_some());
    assert_eq!(
        tip.stacks_block_height,
        block_height_pre_3_0 + ((inter_blocks_per_tenure + 1) * tenure_count),
        "Should have mined (1 + interim_blocks_per_tenure) * tenure_count nakamoto blocks"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
fn correct_burn_outs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    naka_conf.burnchain.pox_reward_length = Some(10);
    naka_conf.burnchain.pox_prepare_length = Some(3);

    {
        let epochs = naka_conf.burnchain.epochs.as_mut().unwrap();
        let epoch_24_ix = StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch24).unwrap();
        let epoch_25_ix = StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch25).unwrap();
        let epoch_30_ix = StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap();
        epochs[epoch_24_ix].end_height = 208;
        epochs[epoch_25_ix].start_height = 208;
        epochs[epoch_25_ix].end_height = 225;
        epochs[epoch_30_ix].start_height = 225;
    }

    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1000);
    naka_conf.initial_balances.clear();
    let accounts: Vec<_> = (0..8)
        .map(|ix| {
            let sk = Secp256k1PrivateKey::from_seed(&[ix, ix, ix, ix]);
            let address = PrincipalData::from(tests::to_addr(&sk));
            (sk, address)
        })
        .collect();
    for (_, ref addr) in accounts.iter() {
        naka_conf.add_initial_balance(addr.to_string(), 10000000000000000);
    }

    let stacker_accounts = accounts[0..3].to_vec();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let epochs = naka_conf.burnchain.epochs.clone().unwrap();
    let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];
    let epoch_25 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch25).unwrap()];

    info!(
        "Chain bootstrapped to bitcoin block 201, starting Epoch 2x miner";
        "Epoch 3.0 Boundary" => (epoch_3.start_height - 1),
    );

    run_until_burnchain_height(
        &mut btc_regtest_controller,
        &blocks_processed,
        epoch_25.start_height + 1,
        &naka_conf,
    );

    info!("Chain bootstrapped to Epoch 2.5, submitting stacker transaction");

    next_block_and_wait(&mut btc_regtest_controller, &blocks_processed);

    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    let stacker_accounts_copy = stacker_accounts.clone();
    let _stacker_thread = thread::Builder::new()
        .name("stacker".into())
        .spawn(move || loop {
            thread::sleep(Duration::from_secs(2));
            debug!("Checking for stacker-necessity");
            let Some(pox_info) = get_pox_info(&http_origin) else {
                warn!("Failed to get pox_info, waiting.");
                continue;
            };
            if !pox_info.contract_id.ends_with(".pox-4") {
                continue;
            }
            let next_cycle_stx = pox_info.next_cycle.stacked_ustx;
            let min_stx = pox_info.next_cycle.min_threshold_ustx;
            let min_stx = (min_stx * 3) / 2;
            if next_cycle_stx >= min_stx {
                debug!(
                    "Next cycle has enough stacked, skipping stacking";
                    "stacked" => next_cycle_stx,
                    "min" => min_stx,
                );
                continue;
            }
            let Some(account) = stacker_accounts_copy.iter().find_map(|(sk, addr)| {
                let account = get_account(&http_origin, &addr);
                if account.locked == 0 {
                    Some((sk, addr, account))
                } else {
                    None
                }
            }) else {
                continue;
            };

            let pox_addr = PoxAddress::from_legacy(
                AddressHashMode::SerializeP2PKH,
                tests::to_addr(&account.0).bytes,
            );
            let pox_addr_tuple: clarity::vm::Value =
                pox_addr.clone().as_clarity_tuple().unwrap().into();
            let pk_bytes = StacksPublicKey::from_private(&sender_signer_sk).to_bytes_compressed();

            let reward_cycle = pox_info.current_cycle.id;
            let signature = make_pox_4_signer_key_signature(
                &pox_addr,
                &sender_signer_sk,
                reward_cycle.into(),
                &Pox4SignatureTopic::StackStx,
                CHAIN_ID_TESTNET,
                1_u128,
                u128::MAX,
                1,
            )
            .unwrap()
            .to_rsv();

            let stacking_tx = tests::make_contract_call(
                &account.0,
                account.2.nonce,
                1000,
                &StacksAddress::burn_address(false),
                "pox-4",
                "stack-stx",
                &[
                    clarity::vm::Value::UInt(min_stx.into()),
                    pox_addr_tuple,
                    clarity::vm::Value::UInt(pox_info.current_burnchain_block_height.into()),
                    clarity::vm::Value::UInt(1),
                    clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                        .unwrap(),
                    clarity::vm::Value::buff_from(pk_bytes).unwrap(),
                    clarity::vm::Value::UInt(u128::MAX),
                    clarity::vm::Value::UInt(1),
                ],
            );
            let txid = submit_tx(&http_origin, &stacking_tx);
            info!("Submitted stacking transaction: {txid}");
            thread::sleep(Duration::from_secs(10));
        })
        .unwrap();

    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let prepare_phase_start = btc_regtest_controller
        .get_burnchain()
        .pox_constants
        .prepare_phase_start(
            btc_regtest_controller.get_burnchain().first_block_height,
            reward_cycle,
        );

    // Run until the prepare phase
    run_until_burnchain_height(
        &mut btc_regtest_controller,
        &blocks_processed,
        prepare_phase_start,
        &naka_conf,
    );

    signer_vote_if_needed(
        &btc_regtest_controller,
        &naka_conf,
        &[sender_signer_sk],
        &signers,
    );

    run_until_burnchain_height(
        &mut btc_regtest_controller,
        &blocks_processed,
        epoch_3.start_height - 1,
        &naka_conf,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, Epoch2x miner should stop");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    // we should already be able to query the stacker set via RPC
    let burnchain = naka_conf.get_burnchain();
    let first_epoch_3_cycle = burnchain
        .block_height_to_reward_cycle(epoch_3.start_height)
        .unwrap();

    info!("first_epoch_3_cycle: {:?}", first_epoch_3_cycle);

    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    let stacker_response = get_stacker_set(&http_origin, first_epoch_3_cycle);
    assert!(stacker_response.stacker_set.signers.is_some());
    assert_eq!(
        stacker_response.stacker_set.signers.as_ref().unwrap().len(),
        1
    );
    assert_eq!(stacker_response.stacker_set.rewarded_addresses.len(), 1);

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    info!("Bootstrapped to Epoch-3.0 boundary, mining nakamoto blocks");

    let sortdb = burnchain.open_sortition_db(true).unwrap();

    // Mine nakamoto tenures
    for _i in 0..30 {
        let prior_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height;
        if let Err(e) = next_block_and_mine_commit(
            &mut btc_regtest_controller,
            30,
            &coord_channel,
            &commits_submitted,
        ) {
            warn!(
                "Error while minting a bitcoin block and waiting for stacks-node activity: {e:?}"
            );
            panic!();
        }

        let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        assert!(
            tip_sn.sortition,
            "The new chain tip must have had a sortition"
        );
        assert!(
            tip_sn.block_height > prior_tip,
            "The new burnchain tip must have been processed"
        );

        signer_vote_if_needed(
            &btc_regtest_controller,
            &naka_conf,
            &[sender_signer_sk],
            &signers,
        );
    }

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    let new_blocks_with_reward_set: Vec<serde_json::Value> = test_observer::get_blocks()
        .into_iter()
        .filter(|block| {
            block.get("reward_set").map_or(false, |v| !v.is_null())
                && block.get("cycle_number").map_or(false, |v| !v.is_null())
        })
        .collect();
    info!(
        "Announced blocks that include reward sets: {:#?}",
        new_blocks_with_reward_set
    );

    assert_eq!(
        new_blocks_with_reward_set.len(),
        5,
        "There should be exactly 5 blocks including reward cycles"
    );

    let cycle_numbers: Vec<u64> = new_blocks_with_reward_set
        .iter()
        .filter_map(|block| block.get("cycle_number").and_then(|cn| cn.as_u64()))
        .collect();

    let expected_cycles: Vec<u64> = (21..=25).collect();
    assert_eq!(
        cycle_numbers, expected_cycles,
        "Cycle numbers should be 21 to 25 inclusive"
    );

    let mut sorted_new_blocks = new_blocks_with_reward_set.clone();
    sorted_new_blocks.sort_by_key(|block| block["cycle_number"].as_u64().unwrap());
    assert_eq!(
        sorted_new_blocks, new_blocks_with_reward_set,
        "Blocks should be sorted by cycle number already"
    );

    for block in new_blocks_with_reward_set.iter() {
        let cycle_number = block["cycle_number"].as_u64().unwrap();
        let reward_set = block["reward_set"].as_object().unwrap();

        if cycle_number < first_epoch_3_cycle {
            assert!(
                reward_set.get("signers").is_none()
                    || reward_set["signers"].as_array().unwrap().is_empty(),
                "Signers should not be set before the first epoch 3 cycle"
            );
            continue;
        }

        // For cycles in or after first_epoch_3_cycle, ensure signers are present
        let signers = reward_set["signers"].as_array().unwrap();
        assert!(!signers.is_empty(), "Signers should be set in any epoch-3 cycles. First epoch-3 cycle: {first_epoch_3_cycle}. Checked cycle number: {cycle_number}");

        assert_eq!(
            reward_set["rewarded_addresses"].as_array().unwrap().len(),
            1,
            "There should be exactly 1 rewarded address"
        );
        assert_eq!(signers.len(), 1, "There should be exactly 1 signer");

        // the signer should have 1 "slot", because they stacked the minimum stacking amount
        let signer_weight = signers[0]["weight"].as_u64().unwrap();
        assert_eq!(signer_weight, 1, "The signer should have a weight of 1, indicating they stacked the minimum stacking amount");
    }

    run_loop_thread.join().unwrap();
}

/// Test `/v2/block_proposal` API endpoint
///
/// This endpoint allows miners to propose Nakamoto blocks to a node,
/// and test if they would be accepted or rejected
#[test]
#[ignore]
fn block_proposal_api_endpoint() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut conf, _miner_account) = naka_neon_integration_conf(None);
    let password = "12345".to_string();
    conf.connection_options.block_proposal_token = Some(password.clone());
    let account_keys = add_initial_balances(&mut conf, 10, 1_000_000);
    let stacker_sk = setup_stacker(&mut conf);
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    // only subscribe to the block proposal events
    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::BlockProposal],
    });

    let mut btcd_controller = BitcoinCoreController::new(conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");
    blind_signer(&conf, &signers, proposals_submitted);

    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (mut chainstate, _) = StacksChainState::open(
        conf.is_mainnet(),
        conf.burnchain.chain_id,
        &conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let _block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    info!("Nakamoto miner started...");

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    // Mine 3 nakamoto tenures
    for _ in 0..3 {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();
    }

    // TODO (hack) instantiate the sortdb in the burnchain
    _ = btc_regtest_controller.sortdb_mut();

    // ----- Setup boilerplate finished, test block proposal API endpoint -----

    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    let privk = conf.miner.mining_key.unwrap().clone();
    let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn())
        .expect("Failed to get sortition tip");
    let db_handle = sortdb.index_handle(&sort_tip);
    let snapshot = db_handle
        .get_block_snapshot(&tip.burn_header_hash)
        .expect("Failed to get block snapshot")
        .expect("No snapshot");
    // Double check we got the right sortition
    assert_eq!(
        snapshot.consensus_hash, tip.consensus_hash,
        "Found incorrect block snapshot"
    );
    let total_burn = snapshot.total_burn;
    let tenure_change = None;
    let coinbase = None;

    let tenure_cause = tenure_change.and_then(|tx: &StacksTransaction| match &tx.payload {
        TransactionPayload::TenureChange(tc) => Some(tc.cause),
        _ => None,
    });

    // Apply miner signature
    let sign = |p: &NakamotoBlockProposal| {
        let mut p = p.clone();
        p.block
            .header
            .sign_miner(&privk)
            .expect("Miner failed to sign");
        p
    };

    let block = {
        let mut builder = NakamotoBlockBuilder::new(
            &tip,
            &tip.consensus_hash,
            total_burn,
            tenure_change,
            coinbase,
            1,
        )
        .expect("Failed to build Nakamoto block");

        let burn_dbconn = btc_regtest_controller.sortdb_ref().index_conn();
        let mut miner_tenure_info = builder
            .load_tenure_info(&mut chainstate, &burn_dbconn, tenure_cause)
            .unwrap();
        let mut tenure_tx = builder
            .tenure_begin(&burn_dbconn, &mut miner_tenure_info)
            .unwrap();

        let tx = make_stacks_transfer(
            &account_keys[0],
            0,
            100,
            &to_addr(&account_keys[1]).into(),
            10000,
        );
        let tx = StacksTransaction::consensus_deserialize(&mut &tx[..])
            .expect("Failed to deserialize transaction");
        let tx_len = tx.tx_len();

        let res = builder.try_mine_tx_with_len(
            &mut tenure_tx,
            &tx,
            tx_len,
            &BlockLimitFunction::NO_LIMIT_HIT,
            ASTRules::PrecheckSize,
        );
        assert!(
            matches!(res, TransactionResult::Success(..)),
            "Transaction failed"
        );
        builder.mine_nakamoto_block(&mut tenure_tx)
    };

    // Construct a valid proposal. Make alterations to this to test failure cases
    let proposal = NakamotoBlockProposal {
        block,
        chain_id: chainstate.chain_id,
    };

    const HTTP_ACCEPTED: u16 = 202;
    const HTTP_TOO_MANY: u16 = 429;
    const HTTP_NOT_AUTHORIZED: u16 = 401;
    let test_cases = [
        (
            "Valid Nakamoto block proposal",
            sign(&proposal),
            HTTP_ACCEPTED,
            Some(Ok(())),
        ),
        ("Must wait", sign(&proposal), HTTP_TOO_MANY, None),
        (
            "Corrupted (bit flipped after signing)",
            (|| {
                let mut sp = sign(&proposal);
                sp.block.header.consensus_hash.0[3] ^= 0x07;
                sp
            })(),
            HTTP_ACCEPTED,
            Some(Err(ValidateRejectCode::ChainstateError)),
        ),
        (
            "Invalid `chain_id`",
            (|| {
                let mut p = proposal.clone();
                p.chain_id ^= 0xFFFFFFFF;
                sign(&p)
            })(),
            HTTP_ACCEPTED,
            Some(Err(ValidateRejectCode::InvalidBlock)),
        ),
        (
            "Invalid `miner_signature`",
            (|| {
                let mut sp = sign(&proposal);
                sp.block.header.miner_signature.0[1] ^= 0x80;
                sp
            })(),
            HTTP_ACCEPTED,
            Some(Err(ValidateRejectCode::ChainstateError)),
        ),
        ("Not authorized", sign(&proposal), HTTP_NOT_AUTHORIZED, None),
    ];

    // Build HTTP client
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("Failed to build `reqwest::Client`");
    // Build URL
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let path = format!("{http_origin}/v2/block_proposal");

    let mut hold_proposal_mutex = Some(test_observer::PROPOSAL_RESPONSES.lock().unwrap());
    for (ix, (test_description, block_proposal, expected_http_code, _)) in
        test_cases.iter().enumerate()
    {
        // Send POST request
        let request_builder = client
            .post(&path)
            .header("Content-Type", "application/json")
            .json(block_proposal);
        let mut response = if expected_http_code == &HTTP_NOT_AUTHORIZED {
            request_builder.send().expect("Failed to POST")
        } else {
            request_builder
                .header(AUTHORIZATION.to_string(), password.to_string())
                .send()
                .expect("Failed to POST")
        };
        let start_time = Instant::now();
        while ix != 1 && response.status().as_u16() == HTTP_TOO_MANY {
            if start_time.elapsed() > Duration::from_secs(30) {
                error!("Took over 30 seconds to process pending proposal, panicking test");
                panic!();
            }
            info!("Waiting for prior request to finish processing, and then resubmitting");
            thread::sleep(Duration::from_secs(5));
            let request_builder = client
                .post(&path)
                .header("Content-Type", "application/json")
                .json(block_proposal);
            response = if expected_http_code == &HTTP_NOT_AUTHORIZED {
                request_builder.send().expect("Failed to POST")
            } else {
                request_builder
                    .header(AUTHORIZATION.to_string(), password.to_string())
                    .send()
                    .expect("Failed to POST")
            };
        }

        let response_code = response.status().as_u16();
        let response_json = if expected_http_code != &HTTP_NOT_AUTHORIZED {
            response.json::<serde_json::Value>().unwrap().to_string()
        } else {
            "No json response".to_string()
        };
        info!(
            "Block proposal submitted and checked for HTTP response";
            "response_json" => response_json,
            "request_json" => serde_json::to_string(block_proposal).unwrap(),
            "response_code" => response_code,
            "test_description" => test_description,
        );

        assert_eq!(response_code, *expected_http_code);

        if ix == 1 {
            // release the test observer mutex so that the handler from 0 can finish!
            hold_proposal_mutex.take();
        }
    }

    let expected_proposal_responses: Vec<_> = test_cases
        .iter()
        .filter_map(|(_, _, _, expected_response)| expected_response.as_ref())
        .collect();

    let mut proposal_responses = test_observer::get_proposal_responses();
    let start_time = Instant::now();
    while proposal_responses.len() < expected_proposal_responses.len() {
        if start_time.elapsed() > Duration::from_secs(30) {
            error!("Took over 30 seconds to process pending proposal, panicking test");
            panic!();
        }
        info!("Waiting for prior request to finish processing");
        thread::sleep(Duration::from_secs(5));
        proposal_responses = test_observer::get_proposal_responses();
    }

    for (expected_response, response) in expected_proposal_responses
        .iter()
        .zip(proposal_responses.iter())
    {
        match expected_response {
            Ok(_) => {
                assert!(matches!(response, BlockValidateResponse::Ok(_)));
            }
            Err(expected_reject_code) => {
                assert!(matches!(
                    response,
                    BlockValidateResponse::Reject(
                        BlockValidateReject { reason_code, .. })
                        if reason_code == expected_reject_code
                ));
            }
        }
        info!("Proposal response {response:?}");
    }

    // Clean up
    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// This test spins up a nakamoto-neon node and attempts to mine a single Nakamoto block.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// This test makes the following assertions:
///  * The proposed Nakamoto block is written to the .miners stackerdb
fn miner_writes_proposed_block_to_stackerdb() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1000);
    let sender_sk = Secp256k1PrivateKey::new();
    // setup sender + recipient for a test stx transfer
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 100;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        send_amt + send_fee,
    );
    let stacker_sk = setup_stacker(&mut naka_conf);

    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent, EventKeyType::MinedBlocks],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);
    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    // Mine 1 nakamoto tenure
    next_block_and_mine_commit(
        &mut btc_regtest_controller,
        60,
        &coord_channel,
        &commits_submitted,
    )
    .unwrap();

    let sortdb = naka_conf.get_burnchain().open_sortition_db(true).unwrap();

    let proposed_block = get_latest_block_proposal(&naka_conf, &sortdb)
        .expect("Expected to find a proposed block in the StackerDB");
    let proposed_block_hash = format!("0x{}", proposed_block.header.block_hash());

    let mut proposed_zero_block = proposed_block.clone();
    proposed_zero_block.header.signer_signature = ThresholdSignature::empty();
    let proposed_zero_block_hash = format!("0x{}", proposed_zero_block.header.block_hash());

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();

    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();

    let observed_blocks = test_observer::get_mined_nakamoto_blocks();
    assert_eq!(observed_blocks.len(), 1);

    let observed_block = observed_blocks.first().unwrap();
    info!(
        "Checking observed and proposed miner block";
        "observed_block" => ?observed_block,
        "proposed_block" => ?proposed_block,
        "observed_block_hash" => format!("0x{}", observed_block.block_hash),
        "proposed_zero_block_hash" => &proposed_zero_block_hash,
        "proposed_block_hash" => &proposed_block_hash,
    );

    let signer_bitvec_str = observed_block.signer_bitvec.clone();
    let signer_bitvec_bytes = hex_bytes(&signer_bitvec_str).unwrap();
    let signer_bitvec = BitVec::<4000>::consensus_deserialize(&mut signer_bitvec_bytes.as_slice())
        .expect("Failed to deserialize signer bitvec");

    assert_eq!(signer_bitvec.len(), 1);

    assert_eq!(
        format!("0x{}", observed_block.block_hash),
        proposed_zero_block_hash,
        "Observed miner hash should match the proposed block read from StackerDB (after zeroing signatures)"
    );
}

#[test]
#[ignore]
fn vote_for_aggregate_key_burn_op() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let _http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);
    let signer_sk = Secp256k1PrivateKey::new();
    let signer_addr = tests::to_addr(&signer_sk);

    naka_conf.add_initial_balance(PrincipalData::from(signer_addr.clone()).to_string(), 100000);
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let _sortdb = burnchain.open_sortition_db(true).unwrap();
    let (_chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);
    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    // submit a pre-stx op
    let mut miner_signer = Keychain::default(naka_conf.node.seed.clone()).generate_op_signer();
    info!("Submitting pre-stx op");
    let pre_stx_op = PreStxOp {
        output: signer_addr.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::PreStx(pre_stx_op),
                &mut miner_signer,
                1
            )
            .is_some(),
        "Pre-stx operation should submit successfully"
    );

    // Mine until the next prepare phase
    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let prepare_phase_start = btc_regtest_controller
        .get_burnchain()
        .pox_constants
        .prepare_phase_start(
            btc_regtest_controller.get_burnchain().first_block_height,
            reward_cycle,
        );

    let blocks_until_prepare = prepare_phase_start + 1 - block_height;

    info!(
        "Mining until prepare phase start.";
        "prepare_phase_start" => prepare_phase_start,
        "block_height" => block_height,
        "blocks_until_prepare" => blocks_until_prepare,
    );

    for _i in 0..(blocks_until_prepare) {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();
    }

    let reward_cycle = reward_cycle + 1;

    let signer_index = 0;

    info!(
        "Submitting vote for aggregate key op";
        "block_height" => block_height,
        "reward_cycle" => reward_cycle,
        "signer_index" => %signer_index,
    );

    let stacker_pk = StacksPublicKey::from_private(&stacker_sk);
    let signer_key: StacksPublicKeyBuffer = stacker_pk.to_bytes_compressed().as_slice().into();
    let aggregate_key = signer_key.clone();

    let vote_for_aggregate_key_op =
        BlockstackOperationType::VoteForAggregateKey(VoteForAggregateKeyOp {
            signer_key,
            signer_index,
            sender: signer_addr.clone(),
            round: 0,
            reward_cycle,
            aggregate_key,
            // to be filled in
            vtxindex: 0,
            txid: Txid([0u8; 32]),
            block_height: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
        });

    let mut signer_burnop_signer = BurnchainOpSigner::new(signer_sk.clone(), false);
    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                vote_for_aggregate_key_op,
                &mut signer_burnop_signer,
                1
            )
            .is_some(),
        "Vote for aggregate key operation should submit successfully"
    );

    info!("Submitted vote for aggregate key op at height {block_height}, mining a few blocks...");

    // the second block should process the vote, after which the vote should be set
    for _i in 0..2 {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();
    }

    let mut vote_for_aggregate_key_found = false;
    let blocks = test_observer::get_blocks();
    for block in blocks.iter() {
        let transactions = block.get("transactions").unwrap().as_array().unwrap();
        for tx in transactions.iter() {
            let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
            if raw_tx == "0x00" {
                info!("Found a burn op: {:?}", tx);
                let burnchain_op = tx.get("burnchain_op").unwrap().as_object().unwrap();
                if !burnchain_op.contains_key("vote_for_aggregate_key") {
                    warn!("Got unexpected burnchain op: {:?}", burnchain_op);
                    panic!("unexpected btc transaction type");
                }
                let vote_obj = burnchain_op.get("vote_for_aggregate_key").unwrap();
                let agg_key = vote_obj
                    .get("aggregate_key")
                    .expect("Expected aggregate_key key in burn op")
                    .as_str()
                    .unwrap();
                assert_eq!(agg_key, aggregate_key.to_hex());

                vote_for_aggregate_key_found = true;
            }
        }
    }
    assert!(
        vote_for_aggregate_key_found,
        "Expected vote for aggregate key op"
    );

    // Check that the correct key was set
    let saved_key = get_key_for_cycle(reward_cycle, false, &naka_conf.node.rpc_bind)
        .expect("Expected to be able to check key is set after voting")
        .expect("Expected aggregate key to be set");

    assert_eq!(saved_key, aggregate_key.as_bytes().to_vec());

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

/// This test boots a follower node using the block downloader
#[test]
#[ignore]
fn follower_bootup() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    let tenure_count = 5;
    let inter_blocks_per_tenure = 9;
    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        (send_amt + send_fee) * tenure_count * inter_blocks_per_tenure,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    let mut follower_conf = naka_conf.clone();
    follower_conf.events_observers.clear();
    follower_conf.node.working_dir = format!("{}-follower", &naka_conf.node.working_dir);
    follower_conf.node.seed = vec![0x01; 32];
    follower_conf.node.local_peer_seed = vec![0x02; 32];

    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);

    let rpc_port = u16::from_be_bytes(buf[0..2].try_into().unwrap()).saturating_add(1025) - 1; // use a non-privileged port between 1024 and 65534
    let p2p_port = u16::from_be_bytes(buf[2..4].try_into().unwrap()).saturating_add(1025) - 1; // use a non-privileged port between 1024 and 65534

    let localhost = "127.0.0.1";
    follower_conf.node.rpc_bind = format!("{}:{}", &localhost, rpc_port);
    follower_conf.node.p2p_bind = format!("{}:{}", &localhost, p2p_port);
    follower_conf.node.data_url = format!("http://{}:{}", &localhost, rpc_port);
    follower_conf.node.p2p_address = format!("{}:{}", &localhost, p2p_port);

    let node_info = get_chain_info(&naka_conf);
    follower_conf.node.add_bootstrap_node(
        &format!(
            "{}@{}",
            &node_info.node_public_key.unwrap(),
            naka_conf.node.p2p_bind
        ),
        CHAIN_ID_TESTNET,
        PEER_VERSION_TESTNET,
    );

    let mut follower_run_loop = boot_nakamoto::BootRunLoop::new(follower_conf.clone()).unwrap();
    let follower_run_loop_stopper = follower_run_loop.get_termination_switch();
    let follower_coord_channel = follower_run_loop.coordinator_channels();

    debug!(
        "Booting follower-thread ({},{})",
        &follower_conf.node.p2p_bind, &follower_conf.node.rpc_bind
    );
    debug!(
        "Booting follower-thread: neighbors = {:?}",
        &follower_conf.node.bootstrap_node
    );

    // spawn a follower thread
    let follower_thread = thread::Builder::new()
        .name("follower-thread".into())
        .spawn(move || follower_run_loop.start(None, 0))
        .unwrap();

    debug!("Booted follower-thread");

    // Mine `tenure_count` nakamoto tenures
    for tenure_ix in 0..tenure_count {
        let commits_before = commits_submitted.load(Ordering::SeqCst);
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 60, &coord_channel)
            .unwrap();

        let mut last_tip = BlockHeaderHash([0x00; 32]);
        let mut last_tip_height = 0;

        // mine the interim blocks
        for interim_block_ix in 0..inter_blocks_per_tenure {
            let blocks_processed_before = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            // submit a tx so that the miner will mine an extra block
            let sender_nonce = tenure_ix * inter_blocks_per_tenure + interim_block_ix;
            let transfer_tx =
                make_stacks_transfer(&sender_sk, sender_nonce, send_fee, &recipient, send_amt);
            submit_tx(&http_origin, &transfer_tx);

            loop {
                let blocks_processed = coord_channel
                    .lock()
                    .expect("Mutex poisoned")
                    .get_stacks_blocks_processed();
                if blocks_processed > blocks_processed_before {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            let info = get_chain_info_result(&naka_conf).unwrap();
            assert_ne!(info.stacks_tip, last_tip);
            assert_ne!(info.stacks_tip_height, last_tip_height);

            last_tip = info.stacks_tip;
            last_tip_height = info.stacks_tip_height;
        }

        let start_time = Instant::now();
        while commits_submitted.load(Ordering::SeqCst) <= commits_before {
            if start_time.elapsed() >= Duration::from_secs(20) {
                panic!("Timed out waiting for block-commit");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // load the chain tip, and assert that it is a nakamoto block and at least 30 blocks have advanced in epoch 3
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    info!(
        "Latest tip";
        "height" => tip.stacks_block_height,
        "is_nakamoto" => tip.anchored_header.as_stacks_nakamoto().is_some(),
    );

    assert!(tip.anchored_header.as_stacks_nakamoto().is_some());
    assert_eq!(
        tip.stacks_block_height,
        block_height_pre_3_0 + ((inter_blocks_per_tenure + 1) * tenure_count),
        "Should have mined (1 + interim_blocks_per_tenure) * tenure_count nakamoto blocks"
    );

    // wait for follower to reach the chain tip
    loop {
        sleep_ms(1000);
        let follower_node_info = get_chain_info(&follower_conf);

        info!(
            "Follower tip is now {}/{}",
            &follower_node_info.stacks_tip_consensus_hash, &follower_node_info.stacks_tip
        );
        if follower_node_info.stacks_tip_consensus_hash == tip.consensus_hash
            && follower_node_info.stacks_tip == tip.anchored_header.block_hash()
        {
            break;
        }
    }

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    follower_coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    follower_run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
    follower_thread.join().unwrap();
}

#[test]
#[ignore]
fn stack_stx_burn_op_integration_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    naka_conf.burnchain.satoshis_per_byte = 2;
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);

    let signer_sk_1 = setup_stacker(&mut naka_conf);
    let signer_addr_1 = tests::to_addr(&signer_sk_1);

    let signer_sk_2 = Secp256k1PrivateKey::new();
    let signer_addr_2 = tests::to_addr(&signer_sk_2);

    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[signer_sk_1],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);
    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    let block_height = btc_regtest_controller.get_headers_height();

    // submit a pre-stx op
    let mut miner_signer_1 = Keychain::default(naka_conf.node.seed.clone()).generate_op_signer();

    info!("Submitting first pre-stx op");
    let pre_stx_op = PreStxOp {
        output: signer_addr_1.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };

    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::PreStx(pre_stx_op),
                &mut miner_signer_1,
                1
            )
            .is_some(),
        "Pre-stx operation should submit successfully"
    );

    next_block_and_mine_commit(
        &mut btc_regtest_controller,
        60,
        &coord_channel,
        &commits_submitted,
    )
    .unwrap();

    let mut miner_signer_2 = Keychain::default(naka_conf.node.seed.clone()).generate_op_signer();
    info!("Submitting second pre-stx op");
    let pre_stx_op_2 = PreStxOp {
        output: signer_addr_2.clone(),
        // to be filled in
        txid: Txid([0u8; 32]),
        vtxindex: 0,
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash([0u8; 32]),
    };
    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::PreStx(pre_stx_op_2),
                &mut miner_signer_2,
                1
            )
            .is_some(),
        "Pre-stx operation should submit successfully"
    );
    info!("Submitted 2 pre-stx ops at block {block_height}, mining a few blocks...");

    // Mine until the next prepare phase
    let block_height = btc_regtest_controller.get_headers_height();
    let reward_cycle = btc_regtest_controller
        .get_burnchain()
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let prepare_phase_start = btc_regtest_controller
        .get_burnchain()
        .pox_constants
        .prepare_phase_start(
            btc_regtest_controller.get_burnchain().first_block_height,
            reward_cycle,
        );

    let blocks_until_prepare = prepare_phase_start + 1 - block_height;

    let lock_period: u8 = 6;
    let topic = Pox4SignatureTopic::StackStx;
    let auth_id: u32 = 1;
    let pox_addr = PoxAddress::Standard(signer_addr_1, Some(AddressHashMode::SerializeP2PKH));

    info!(
        "Submitting set-signer-key-authorization";
        "block_height" => block_height,
        "reward_cycle" => reward_cycle,
    );

    let signer_pk_1 = StacksPublicKey::from_private(&signer_sk_1);
    let signer_key_arg_1: StacksPublicKeyBuffer =
        signer_pk_1.to_bytes_compressed().as_slice().into();

    let set_signer_key_auth_tx = tests::make_contract_call(
        &signer_sk_1,
        1,
        500,
        &StacksAddress::burn_address(false),
        "pox-4",
        "set-signer-key-authorization",
        &[
            clarity::vm::Value::Tuple(pox_addr.clone().as_clarity_tuple().unwrap()),
            clarity::vm::Value::UInt(lock_period.into()),
            clarity::vm::Value::UInt(reward_cycle.into()),
            clarity::vm::Value::string_ascii_from_bytes(topic.get_name_str().into()).unwrap(),
            clarity::vm::Value::buff_from(signer_pk_1.clone().to_bytes_compressed()).unwrap(),
            clarity::vm::Value::Bool(true),
            clarity::vm::Value::UInt(u128::MAX),
            clarity::vm::Value::UInt(auth_id.into()),
        ],
    );

    submit_tx(&http_origin, &set_signer_key_auth_tx);

    info!(
        "Mining until prepare phase start.";
        "prepare_phase_start" => prepare_phase_start,
        "block_height" => block_height,
        "blocks_until_prepare" => blocks_until_prepare,
    );

    for _i in 0..(blocks_until_prepare) {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();
    }

    let reward_cycle = reward_cycle + 1;

    info!(
        "Submitting stack stx op";
        "block_height" => block_height,
        "reward_cycle" => reward_cycle,
    );

    let mut signer_burnop_signer_1 = BurnchainOpSigner::new(signer_sk_1.clone(), false);
    let mut signer_burnop_signer_2 = BurnchainOpSigner::new(signer_sk_2.clone(), false);

    info!(
        "Before stack-stx op, signer 1 total: {}",
        btc_regtest_controller
            .get_utxos(
                StacksEpochId::Epoch30,
                &signer_burnop_signer_1.get_public_key(),
                1,
                None,
                block_height
            )
            .unwrap()
            .total_available(),
    );
    info!(
        "Before stack-stx op, signer 2 total: {}",
        btc_regtest_controller
            .get_utxos(
                StacksEpochId::Epoch30,
                &signer_burnop_signer_2.get_public_key(),
                1,
                None,
                block_height
            )
            .unwrap()
            .total_available(),
    );

    info!("Signer 1 addr: {}", signer_addr_1.to_b58());
    info!("Signer 2 addr: {}", signer_addr_2.to_b58());

    let pox_info = get_pox_info(&http_origin).unwrap();
    let min_stx = pox_info.next_cycle.min_threshold_ustx;

    let stack_stx_op_with_some_signer_key = StackStxOp {
        sender: signer_addr_1.clone(),
        reward_addr: pox_addr,
        stacked_ustx: min_stx.into(),
        num_cycles: lock_period,
        signer_key: Some(signer_key_arg_1),
        max_amount: Some(u128::MAX),
        auth_id: Some(auth_id),
        // to be filled in
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash::zero(),
    };

    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::StackStx(stack_stx_op_with_some_signer_key),
                &mut signer_burnop_signer_1,
                1
            )
            .is_some(),
        "Stack STX operation should submit successfully"
    );

    let stack_stx_op_with_no_signer_key = StackStxOp {
        sender: signer_addr_2.clone(),
        reward_addr: PoxAddress::Standard(signer_addr_2, None),
        stacked_ustx: 100000,
        num_cycles: 6,
        signer_key: None,
        max_amount: None,
        auth_id: None,
        // to be filled in
        vtxindex: 0,
        txid: Txid([0u8; 32]),
        block_height: 0,
        burn_header_hash: BurnchainHeaderHash::zero(),
    };

    assert!(
        btc_regtest_controller
            .submit_operation(
                StacksEpochId::Epoch30,
                BlockstackOperationType::StackStx(stack_stx_op_with_no_signer_key),
                &mut signer_burnop_signer_2,
                1
            )
            .is_some(),
        "Stack STX operation should submit successfully"
    );

    info!("Submitted 2 stack STX ops at height {block_height}, mining a few blocks...");

    // the second block should process the vote, after which the balances should be unchanged
    for _i in 0..2 {
        next_block_and_mine_commit(
            &mut btc_regtest_controller,
            60,
            &coord_channel,
            &commits_submitted,
        )
        .unwrap();
    }

    let mut stack_stx_found = false;
    let mut stack_stx_burn_op_tx_count = 0;
    let blocks = test_observer::get_blocks();
    info!("stack event observer num blocks: {:?}", blocks.len());
    for block in blocks.iter() {
        let transactions = block.get("transactions").unwrap().as_array().unwrap();
        info!(
            "stack event observer num transactions: {:?}",
            transactions.len()
        );
        for tx in transactions.iter() {
            let raw_tx = tx.get("raw_tx").unwrap().as_str().unwrap();
            if raw_tx == "0x00" {
                info!("Found a burn op: {:?}", tx);
                let burnchain_op = tx.get("burnchain_op").unwrap().as_object().unwrap();
                if !burnchain_op.contains_key("stack_stx") {
                    warn!("Got unexpected burnchain op: {:?}", burnchain_op);
                    panic!("unexpected btc transaction type");
                }
                let stack_stx_obj = burnchain_op.get("stack_stx").unwrap();
                let signer_key_found = stack_stx_obj
                    .get("signer_key")
                    .expect("Expected signer_key in burn op")
                    .as_str()
                    .unwrap();
                assert_eq!(signer_key_found, signer_key_arg_1.to_hex());

                let max_amount_correct = stack_stx_obj
                    .get("max_amount")
                    .expect("Expected max_amount")
                    .as_number()
                    .expect("Expected max_amount to be a number")
                    .eq(&serde_json::Number::from(u128::MAX));
                assert!(max_amount_correct, "Expected max_amount to be u128::MAX");

                let auth_id_correct = stack_stx_obj
                    .get("auth_id")
                    .expect("Expected auth_id in burn op")
                    .as_number()
                    .expect("Expected auth id")
                    .eq(&serde_json::Number::from(auth_id));
                assert!(auth_id_correct, "Expected auth_id to be 1");

                let raw_result = tx.get("raw_result").unwrap().as_str().unwrap();
                let parsed =
                    clarity::vm::Value::try_deserialize_hex_untyped(&raw_result[2..]).unwrap();
                info!("Clarity result of stack-stx op: {parsed}");
                parsed
                    .expect_result_ok()
                    .expect("Expected OK result for stack-stx op");

                stack_stx_found = true;
                stack_stx_burn_op_tx_count += 1;
            }
        }
    }
    assert!(stack_stx_found, "Expected stack STX op");
    assert_eq!(
        stack_stx_burn_op_tx_count, 1,
        "Stack-stx tx without a signer_key shouldn't have been submitted"
    );

    let sortdb = btc_regtest_controller.sortdb_mut();
    let sortdb_conn = sortdb.conn();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb_conn).unwrap();

    let ancestor_burnchain_header_hashes =
        SortitionDB::get_ancestor_burnchain_header_hashes(sortdb.conn(), &tip.burn_header_hash, 6)
            .unwrap();

    let mut all_stacking_burn_ops = vec![];
    let mut found_none = false;
    let mut found_some = false;
    // go from oldest burn header hash to newest
    for ancestor_bhh in ancestor_burnchain_header_hashes.iter().rev() {
        let stacking_ops = SortitionDB::get_stack_stx_ops(sortdb_conn, ancestor_bhh).unwrap();
        for stacking_op in stacking_ops.into_iter() {
            debug!("Stacking op queried from sortdb: {:?}", stacking_op);
            match stacking_op.signer_key {
                Some(_) => found_some = true,
                None => found_none = true,
            }
            all_stacking_burn_ops.push(stacking_op);
        }
    }
    assert_eq!(
        all_stacking_burn_ops.len(),
        2,
        "Both stack-stx ops with and without a signer_key should be considered valid."
    );
    assert!(
        found_none,
        "Expected one stacking_op to have a signer_key of None"
    );
    assert!(
        found_some,
        "Expected one stacking_op to have a signer_key of Some"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// Miner A mines a regular tenure, its last block being block a_x.
/// Miner B starts its tenure, Miner B produces a Stacks block b_0, but miner C submits its block commit before b_0 is broadcasted.
/// Bitcoin block C, containing Miner C's block commit, is mined BEFORE miner C has a chance to update their block commit with b_0's information.
/// This test asserts:
///  * tenure C ignores b_0, and correctly builds off of block a_x.
fn forked_tenure_is_ignored() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(10);
    let sender_sk = Secp256k1PrivateKey::new();
    // setup sender + recipient for a test stx transfer
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        send_amt + send_fee,
    );
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );
    let stacker_sk = setup_stacker(&mut naka_conf);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent, EventKeyType::MinedBlocks],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        naka_mined_blocks: mined_blocks,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::spawn(move || run_loop.start(None, 0));
    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    info!("Starting tenure A.");
    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count > commits_before)
    })
    .unwrap();

    // In the next block, the miner should win the tenure and submit a stacks block
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        let blocks_count = mined_blocks.load(Ordering::SeqCst);
        Ok(commits_count > commits_before && blocks_count > blocks_before)
    })
    .unwrap();

    let block_tenure_a = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    // For the next tenure, submit the commit op but do not allow any stacks blocks to be broadcasted
    TEST_BROADCAST_STALL.lock().unwrap().replace(true);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    info!("Starting tenure B.");
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count > commits_before)
    })
    .unwrap();
    signer_vote_if_needed(
        &btc_regtest_controller,
        &naka_conf,
        &[sender_signer_sk],
        &signers,
    );

    info!("Commit op is submitted; unpause tenure B's block");

    // Unpause the broadcast of Tenure B's block, do not submit commits.
    TEST_SKIP_COMMIT_OP.lock().unwrap().replace(true);
    TEST_BROADCAST_STALL.lock().unwrap().replace(false);

    // Wait for a stacks block to be broadcasted
    let start_time = Instant::now();
    while mined_blocks.load(Ordering::SeqCst) <= blocks_before {
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "FAIL: Test timed out while waiting for block production",
        );
        thread::sleep(Duration::from_secs(1));
    }

    info!("Tenure B broadcasted a block. Issue the next bitcon block and unstall block commits.");
    let block_tenure_b = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let block_b = blocks.last().unwrap();

    info!("Starting tenure C.");
    // Submit a block commit op for tenure C
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    next_block_and(&mut btc_regtest_controller, 60, || {
        TEST_SKIP_COMMIT_OP.lock().unwrap().replace(false);
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        let blocks_count = mined_blocks.load(Ordering::SeqCst);
        Ok(commits_count > commits_before && blocks_count > blocks_before)
    })
    .unwrap();

    info!("Tenure C produced a block!");
    let block_tenure_c = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let block_c = blocks.last().unwrap();

    // Now let's produce a second block for tenure C and ensure it builds off of block C.
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let start_time = Instant::now();
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx =
        make_stacks_transfer(&sender_sk, sender_nonce, send_fee, &recipient, send_amt);
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in Tenure C to mine a second block");
    while mined_blocks.load(Ordering::SeqCst) <= blocks_before {
        assert!(
            start_time.elapsed() < Duration::from_secs(30),
            "FAIL: Test timed out while waiting for block production",
        );
        thread::sleep(Duration::from_secs(1));
    }

    info!("Tenure C produced a second block!");

    let block_2_tenure_c = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let block_2_c = blocks.last().unwrap();

    info!("Starting tenure D.");
    // Submit a block commit op for tenure D and mine a stacks block
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        let blocks_count = mined_blocks.load(Ordering::SeqCst);
        Ok(commits_count > commits_before && blocks_count > blocks_before)
    })
    .unwrap();

    let block_tenure_d = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let block_d = blocks.last().unwrap();
    assert_ne!(block_tenure_b, block_tenure_a);
    assert_ne!(block_tenure_b, block_tenure_c);
    assert_ne!(block_tenure_c, block_tenure_a);

    // Block B was built atop block A
    assert_eq!(
        block_tenure_b.stacks_block_height,
        block_tenure_a.stacks_block_height + 1
    );
    assert_eq!(
        block_b.parent_block_id,
        block_tenure_a.index_block_hash().to_string()
    );

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted, so it should be built off of Block A
    assert_eq!(
        block_tenure_c.stacks_block_height,
        block_tenure_a.stacks_block_height + 1
    );
    assert_eq!(
        block_c.parent_block_id,
        block_tenure_a.index_block_hash().to_string()
    );

    assert_ne!(block_tenure_c, block_2_tenure_c);
    assert_ne!(block_2_tenure_c, block_tenure_d);
    assert_ne!(block_tenure_c, block_tenure_d);

    // Second block of tenure C builds off of block C
    assert_eq!(
        block_2_tenure_c.stacks_block_height,
        block_tenure_c.stacks_block_height + 1,
    );
    assert_eq!(
        block_2_c.parent_block_id,
        block_tenure_c.index_block_hash().to_string()
    );

    // Tenure D builds off of the second block of tenure C
    assert_eq!(
        block_tenure_d.stacks_block_height,
        block_2_tenure_c.stacks_block_height + 1,
    );
    assert_eq!(
        block_d.parent_block_id,
        block_2_tenure_c.index_block_hash().to_string()
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

#[test]
#[ignore]
/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// This test makes three assertions:
///  * 5 tenures are mined after 3.0 starts
///  * Each tenure has 10 blocks (the coinbase block and 9 interim blocks)
///  * Verifies the block heights of the blocks mined
fn check_block_heights() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let signers = TestSigners::default();
    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    let tenure_count = 5;
    let inter_blocks_per_tenure = 9;
    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let deploy_fee = 3000;
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr.clone()).to_string(),
        3 * deploy_fee + (send_amt + send_fee) * tenure_count * inter_blocks_per_tenure,
    );
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_signer_addr.clone()).to_string(),
        100000,
    );
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    let observer_port = test_observer::EVENT_OBSERVER_PORT;
    naka_conf.events_observers.insert(EventObserverConfig {
        endpoint: format!("localhost:{observer_port}"),
        events_keys: vec![EventKeyType::AnyEvent],
    });

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_vrfs: vrfs_submitted,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();
    wait_for_runloop(&blocks_processed);

    let mut sender_nonce = 0;

    // Deploy this version with the Clarity 1 / 2 before epoch 3
    let contract0_name = "test-contract-0";
    let contract_clarity1 =
        "(define-read-only (get-heights) { burn-block-height: burn-block-height, block-height: block-height })";

    let contract_tx0 = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        contract0_name,
        contract_clarity1,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &contract_tx0);

    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        Some(&signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    let heights0_value = call_read_only(
        &naka_conf,
        &sender_addr,
        contract0_name,
        "get-heights",
        vec![],
    );
    let heights0 = heights0_value.expect_tuple().unwrap();
    info!("Heights from pre-epoch 3.0: {}", heights0);

    // first block wakes up the run loop, wait until a key registration has been submitted.
    next_block_and(&mut btc_regtest_controller, 60, || {
        let vrf_count = vrfs_submitted.load(Ordering::SeqCst);
        Ok(vrf_count >= 1)
    })
    .unwrap();

    // second block should confirm the VRF register, wait until a block commit is submitted
    next_block_and(&mut btc_regtest_controller, 60, || {
        let commits_count = commits_submitted.load(Ordering::SeqCst);
        Ok(commits_count >= 1)
    })
    .unwrap();

    let info = get_chain_info_result(&naka_conf).unwrap();
    println!("Chain info: {:?}", info);
    let mut last_burn_block_height = info.burn_block_height as u128;
    let mut last_stacks_block_height = info.stacks_tip_height as u128;
    let mut last_tenure_height = last_stacks_block_height as u128;

    let heights0_value = call_read_only(
        &naka_conf,
        &sender_addr,
        contract0_name,
        "get-heights",
        vec![],
    );
    let heights0 = heights0_value.expect_tuple().unwrap();
    info!("Heights from epoch 3.0 start: {}", heights0);
    assert_eq!(
        heights0
            .get("burn-block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap()
            + 3,
        last_burn_block_height,
        "Burn block height should match"
    );
    assert_eq!(
        heights0
            .get("block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap(),
        last_stacks_block_height,
        "Stacks block height should match"
    );

    // This version uses the Clarity 1 / 2 keywords
    let contract1_name = "test-contract-1";
    let contract_tx1 = make_contract_publish_versioned(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        contract1_name,
        contract_clarity1,
        Some(ClarityVersion::Clarity2),
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &contract_tx1);

    // This version uses the Clarity 3 keywords
    let contract3_name = "test-contract-3";
    let contract_clarity3 =
        "(define-read-only (get-heights) { burn-block-height: burn-block-height, stacks-block-height: stacks-block-height, tenure-height: tenure-height })";

    let contract_tx3 = make_contract_publish(
        &sender_sk,
        sender_nonce,
        deploy_fee,
        contract3_name,
        contract_clarity3,
    );
    sender_nonce += 1;
    submit_tx(&http_origin, &contract_tx3);

    // Mine `tenure_count` nakamoto tenures
    for tenure_ix in 0..tenure_count {
        info!("Mining tenure {}", tenure_ix);
        let commits_before = commits_submitted.load(Ordering::SeqCst);
        next_block_and_process_new_stacks_block(&mut btc_regtest_controller, 60, &coord_channel)
            .unwrap();

        let heights1_value = call_read_only(
            &naka_conf,
            &sender_addr,
            contract1_name,
            "get-heights",
            vec![],
        );
        let heights1 = heights1_value.expect_tuple().unwrap();
        info!("Heights from Clarity 1: {}", heights1);

        let heights3_value = call_read_only(
            &naka_conf,
            &sender_addr,
            contract3_name,
            "get-heights",
            vec![],
        );
        let heights3 = heights3_value.expect_tuple().unwrap();
        info!("Heights from Clarity 3: {}", heights3);

        let bbh1 = heights1
            .get("burn-block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap();
        let bbh3 = heights3
            .get("burn-block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap();
        assert_eq!(bbh1, bbh3, "Burn block heights should match");
        if tenure_ix == 0 {
            // Add two for the 2 blocks with no tenure during Nakamoto bootup
            last_burn_block_height = bbh1 + 2;
        } else {
            assert_eq!(
                bbh1, last_burn_block_height,
                "Burn block height should not have changed yet"
            );
        }

        let bh1 = heights1
            .get("block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap();
        let bh3 = heights3
            .get("tenure-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap();
        assert_eq!(
            bh1, bh3,
            "Clarity 2 block-height should match Clarity 3 tenure-height"
        );
        assert_eq!(
            bh1,
            last_tenure_height + 1,
            "Tenure height should have incremented"
        );
        last_tenure_height = bh1;

        let sbh = heights3
            .get("stacks-block-height")
            .unwrap()
            .clone()
            .expect_u128()
            .unwrap();
        assert_eq!(
            sbh,
            last_stacks_block_height + 1,
            "Stacks block heights should have incremented"
        );
        last_stacks_block_height = sbh;

        // mine the interim blocks
        for interim_block_ix in 0..inter_blocks_per_tenure {
            info!("Mining interim block {interim_block_ix}");
            let blocks_processed_before = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            // submit a tx so that the miner will mine an extra block
            let transfer_tx =
                make_stacks_transfer(&sender_sk, sender_nonce, send_fee, &recipient, send_amt);
            sender_nonce += 1;
            submit_tx(&http_origin, &transfer_tx);

            loop {
                let blocks_processed = coord_channel
                    .lock()
                    .expect("Mutex poisoned")
                    .get_stacks_blocks_processed();
                if blocks_processed > blocks_processed_before {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            let heights1_value = call_read_only(
                &naka_conf,
                &sender_addr,
                contract1_name,
                "get-heights",
                vec![],
            );
            let heights1 = heights1_value.expect_tuple().unwrap();
            info!("Heights from Clarity 1: {}", heights1);

            let heights3_value = call_read_only(
                &naka_conf,
                &sender_addr,
                contract3_name,
                "get-heights",
                vec![],
            );
            let heights3 = heights3_value.expect_tuple().unwrap();
            info!("Heights from Clarity 3: {}", heights3);

            let bbh1 = heights1
                .get("burn-block-height")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap();
            let bbh3 = heights3
                .get("burn-block-height")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap();
            assert_eq!(bbh1, bbh3, "Burn block heights should match");
            if interim_block_ix == 0 {
                assert_eq!(
                    bbh1,
                    last_burn_block_height + 1,
                    "Burn block heights should have incremented"
                );
                last_burn_block_height = bbh1;
            } else {
                assert_eq!(
                    bbh1, last_burn_block_height,
                    "Burn block heights should not have incremented"
                );
            }

            let bh1 = heights1
                .get("block-height")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap();
            let bh3 = heights3
                .get("tenure-height")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap();
            assert_eq!(
                bh1, bh3,
                "Clarity 2 block-height should match Clarity 3 tenure-height"
            );
            assert_eq!(
                bh1, last_tenure_height,
                "Tenure height should not have changed"
            );

            let sbh = heights3
                .get("stacks-block-height")
                .unwrap()
                .clone()
                .expect_u128()
                .unwrap();
            assert_eq!(
                sbh,
                last_stacks_block_height + 1,
                "Stacks block heights should have incremented"
            );
            last_stacks_block_height = sbh;
        }

        let start_time = Instant::now();
        while commits_submitted.load(Ordering::SeqCst) <= commits_before {
            if start_time.elapsed() >= Duration::from_secs(20) {
                panic!("Timed out waiting for block-commit");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    // load the chain tip, and assert that it is a nakamoto block and at least 30 blocks have advanced in epoch 3
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    info!(
        "Latest tip";
        "height" => tip.stacks_block_height,
        "is_nakamoto" => tip.anchored_header.as_stacks_nakamoto().is_some(),
    );

    assert!(tip.anchored_header.as_stacks_nakamoto().is_some());
    assert_eq!(
        tip.stacks_block_height,
        block_height_pre_3_0 + ((inter_blocks_per_tenure + 1) * tenure_count),
        "Should have mined (1 + interim_blocks_per_tenure) * tenure_count nakamoto blocks"
    );

    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}
