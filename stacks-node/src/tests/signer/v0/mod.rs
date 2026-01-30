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
use std::collections::{HashMap, HashSet};
use std::ops::Add;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::PrincipalData;
use libsigner::v0::messages::{
    BlockAccepted, BlockRejection, BlockResponse, MessageSlotID, MinerSlotID, PeerInfo, RejectCode,
    RejectReason, SignerMessage, StateMachineUpdateContent, StateMachineUpdateMinerState,
};
use libsigner::{
    BlockProposal, BlockProposalData, SignerSession, StackerDBSession, VERSION_STRING,
};
use madhouse::{execute_commands, prop_allof, scenario, Command, CommandWrapper};
use pinny::tag;
use proptest::prelude::Strategy;
use rand::{thread_rng, Rng};
use rusqlite::Connection;
use stacks::address::AddressHashMode;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::ConsensusHash;
use stacks::chainstate::coordinator::comm::CoordinatorChannels;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use stacks::chainstate::stacks::address::{PoxAddress, StacksAddressExtensions};
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::miner::{TransactionEvent, TransactionSuccessEvent};
use stacks::chainstate::stacks::{StacksTransaction, TenureChangeCause, TransactionPayload};
use stacks::codec::StacksMessageCodec;
use stacks::config::{Config as NeonConfig, EventKeyType, EventObserverConfig};
use stacks::core::mempool::MemPoolWalkStrategy;
use stacks::core::test_util::{
    insert_tx_in_mempool, make_contract_call, make_contract_publish,
    make_stacks_transfer_serialized,
};
use stacks::core::{StacksEpochId, CHAIN_ID_TESTNET};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::getsigner::GetSignerResponse;
use stacks::net::api::postblock_proposal::{
    BlockValidateResponse, ValidateRejectCode, TEST_VALIDATE_DELAY_DURATION_SECS,
    TEST_VALIDATE_STALL,
};
use stacks::net::api::poststackerdbchunk::StackerDBErrorCodes;
use stacks::net::relay::fault_injection::clear_ignore_block;
use stacks::types::chainstate::{
    BlockHeaderHash, StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks::types::{PrivateKey, PublicKey};
use stacks::util::get_epoch_time_secs;
use stacks::util::hash::{hex_bytes, Hash160, MerkleHashFunc, Sha512Trunc256Sum};
use stacks::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks::util_lib::boot::boot_code_id;
use stacks::util_lib::signed_structured_data::pox4::{
    make_pox_4_signer_key_signature, Pox4SignatureTopic,
};
use stacks_common::bitvec::BitVec;
use stacks_common::util::sleep_ms;
use stacks_signer::chainstate::v1::SortitionsView;
use stacks_signer::chainstate::ProposalEvalConfig;
use stacks_signer::client::StackerDB;
use stacks_signer::config::{
    build_signer_config_tomls, GlobalConfig as SignerConfig, Network,
    DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
};
use stacks_signer::signerdb::SignerDb;
use stacks_signer::v0::signer::TEST_REPEAT_PROPOSAL_RESPONSE;
use stacks_signer::v0::signer_state::SUPPORTED_SIGNER_PROTOCOL_VERSION;
use stacks_signer::v0::tests::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_PAUSE_BLOCK_BROADCAST,
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST, TEST_SKIP_SIGNER_CLEANUP,
    TEST_STALL_BLOCK_RESPONSE, TEST_STALL_BLOCK_VALIDATION_SUBMISSION,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::event_dispatcher::TEST_SKIP_BLOCK_ANNOUNCEMENT;
use crate::nakamoto_node::miner::{
    fault_injection_stall_miner, fault_injection_try_stall_miner, fault_injection_unstall_miner,
    TEST_BROADCAST_PROPOSAL_STALL, TEST_MINE_SKIP,
};
use crate::nakamoto_node::stackerdb_listener::TEST_IGNORE_SIGNERS;
use crate::neon::{Counters, RunLoopCounter};
use crate::run_loop::boot_nakamoto;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_25, boot_to_epoch_3_reward_set, next_block_and,
    next_block_and_process_new_stacks_block, setup_epoch_3_reward_set, wait_for,
    POX_4_DEFAULT_STACKER_BALANCE, POX_4_DEFAULT_STACKER_STX_AMT,
};
use crate::tests::neon_integrations::{
    get_account, get_chain_info, get_chain_info_opt, get_sortition_info, get_sortition_info_ch,
    next_block_and_wait, run_until_burnchain_height, submit_tx, submit_tx_fallible,
    wait_for_tenure_change_tx, TestProxy,
};
use crate::tests::signer::commands::*;
use crate::tests::signer::SpawnedSignerTrait;
use crate::tests::test_observer::TestObserver;
use crate::tests::{self, gen_random_port};
use crate::{nakamoto_node, BitcoinRegtestController, BurnchainController, Config, Keychain};

pub mod reorg;
pub mod tenure_extend;
pub mod tx_replay;

impl<Z: SpawnedSignerTrait> SignerTest<Z> {
    /// Run the test until the epoch 3 boundary
    pub fn boot_to_epoch_3(&self) {
        TEST_MINE_SKIP.set(true);
        boot_to_epoch_3_reward_set(
            &self.running_nodes.conf,
            &self.running_nodes.counters.blocks_processed,
            &self.signer_stacks_private_keys,
            &self.signer_stacks_private_keys,
            &self.running_nodes.btc_regtest_controller,
            Some(self.num_stacking_cycles),
        );

        info!("Waiting for signer set calculation.");
        // Make sure the signer set is calculated before continuing or signers may not
        // recognize that they are registered signers in the subsequent burn block event
        let reward_cycle = self.get_current_reward_cycle() + 1;
        let mut last_probe = Instant::now();
        wait_for(120, || {
            match self.stacks_client.get_reward_set_signers(reward_cycle).unwrap_or_default() {
                Some(reward_set) => {
                    debug!("Signer set: {reward_set:?}");
                    Ok(true)
                }
                None => {
                    // If we've been waiting ~30s since the last probe, maybe the last block failed
                    // so we should try to mine another block
                    if last_probe.elapsed() >= Duration::from_secs(30) {
                        warn!(
                            "Timed out waiting for reward set calculation. Mining another block to try again."
                        );
                        self.running_nodes
                            .btc_regtest_controller
                            .build_next_block(1);
                        last_probe = Instant::now();
                    }
                    Ok(false)
                }
            }
        })
        .expect("Timed out waiting for reward set calculation");

        info!("Signer set calculated");

        // Manually consume one more block to ensure signers refresh their state
        info!("Waiting for signers to initialize.");
        next_block_and_wait(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
        );
        self.wait_for_registered();
        info!("Signers initialized");

        self.run_until_epoch_3_boundary();
        wait_for(30, || {
            Ok(get_chain_info_opt(&self.running_nodes.conf).is_some())
        })
        .expect("Timed out waiting for network to restart after 3.0 boundary reached");

        if self.snapshot_path.is_some() {
            info!("Booted to epoch 3.0, ready for snapshot.");
            return;
        }

        // Wait until we see the first block of epoch 3.0.
        // Note, we don't use `nakamoto_blocks_mined` counter, because there
        // could be other miners mining blocks.
        info!("Waiting for first Epoch 3.0 tenure to start");
        self.mine_nakamoto_block(Duration::from_secs(60), false);
        info!("Ready to mine Nakamoto blocks!");
    }
}

impl SignerTest<SpawnedSigner> {
    /// Run the test until the first epoch 2.5 reward cycle.
    /// Will activate pox-4 and register signers for the first full Epoch 2.5 reward cycle.
    fn boot_to_epoch_25_reward_cycle(&self) {
        boot_to_epoch_25(
            &self.running_nodes.conf,
            &self.running_nodes.counters.blocks_processed,
            &self.running_nodes.btc_regtest_controller,
        );

        next_block_and_wait(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
        );

        let http_origin = format!("http://{}", &self.running_nodes.conf.node.rpc_bind);
        let lock_period = 12;

        let epochs = self.running_nodes.conf.burnchain.epochs.clone().unwrap();
        let epoch_25 = &epochs[StacksEpochId::Epoch25];
        let epoch_25_start_height = epoch_25.start_height;
        // stack enough to activate pox-4
        let block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        let reward_cycle = self
            .running_nodes
            .btc_regtest_controller
            .get_burnchain()
            .block_height_to_reward_cycle(block_height)
            .unwrap();
        for stacker_sk in self.signer_stacks_private_keys.iter() {
            let pox_addr = PoxAddress::from_legacy(
                AddressHashMode::SerializeP2PKH,
                tests::to_addr(stacker_sk).bytes().clone(),
            );
            let pox_addr_tuple: clarity::vm::Value =
                pox_addr.clone().as_clarity_tuple().unwrap().into();
            let signature = make_pox_4_signer_key_signature(
                &pox_addr,
                stacker_sk,
                reward_cycle.into(),
                &Pox4SignatureTopic::StackStx,
                CHAIN_ID_TESTNET,
                lock_period,
                u128::MAX,
                1,
            )
            .unwrap()
            .to_rsv();

            let signer_pk = StacksPublicKey::from_private(stacker_sk);
            let stacking_tx = make_contract_call(
                stacker_sk,
                0,
                1000,
                self.running_nodes.conf.burnchain.chain_id,
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
        next_block_and_wait(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
        );
        next_block_and_wait(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
        );

        let reward_cycle_len = self
            .running_nodes
            .conf
            .get_burnchain()
            .pox_constants
            .reward_cycle_length as u64;

        let epoch_25_reward_cycle_boundary =
            epoch_25_start_height.saturating_sub(epoch_25_start_height % reward_cycle_len);
        let next_reward_cycle_boundary =
            epoch_25_reward_cycle_boundary.wrapping_add(reward_cycle_len);
        let target_height = next_reward_cycle_boundary - 1;
        info!("Advancing to burn block height {target_height}...",);
        run_until_burnchain_height(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
            target_height,
            &self.running_nodes.conf,
        );
        debug!("Waiting for signer set calculation.");
        let mut reward_set_calculated = false;
        let short_timeout = Duration::from_secs(60);
        let now = std::time::Instant::now();
        // Make sure the signer set is calculated before continuing or signers may not
        // recognize that they are registered signers in the subsequent burn block event
        let reward_cycle = self.get_current_reward_cycle().wrapping_add(1);
        while !reward_set_calculated {
            let reward_set = self
                .stacks_client
                .get_reward_set_signers(reward_cycle)
                .expect("Failed to check if reward set is calculated");
            reward_set_calculated = reward_set.is_some();
            if reward_set_calculated {
                debug!("Signer set: {:?}", reward_set.unwrap());
            }
            std::thread::sleep(Duration::from_secs(1));
            assert!(
                now.elapsed() < short_timeout,
                "Timed out waiting for reward set calculation"
            );
        }
        debug!("Signer set calculated");
        // Manually consume one more block to ensure signers refresh their state
        debug!("Waiting for signers to initialize.");
        info!("Advancing to the first full Epoch 2.5 reward cycle boundary...");
        next_block_and_wait(
            &self.running_nodes.btc_regtest_controller,
            &self.running_nodes.counters.blocks_processed,
        );
        self.wait_for_registered();
        debug!("Signers initialized");

        let current_burn_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        info!("At burn block height {current_burn_block_height}. Ready to mine the first Epoch 2.5 reward cycle!");
    }

    /// If this SignerTest is configured to use a snapshot, this
    /// will check if the snapshot exists. If the snapshot doesn't
    /// exist, it will boot to epoch 3.0 and save state to a snapshot.
    ///
    /// This will also shutdown the test early, requiring a restart
    /// of the test.
    ///
    /// If the test is not configured to use snapshots, it will boot to epoch 3.0
    /// and continue.
    ///
    /// Returns `true` if the snapshot was created.
    pub fn bootstrap_snapshot(&self) -> bool {
        if self.snapshot_path.is_none() {
            self.boot_to_epoch_3();
            return false;
        }

        if self.needs_snapshot() {
            self.boot_to_epoch_3();
            warn!("Snapshot created. Shutdown and try again.");
            return true;
        }
        false
    }

    // Only call after already past the epoch 3.0 boundary
    fn mine_and_verify_confirmed_naka_block(
        &self,
        timeout: Duration,
        num_signers: usize,
        use_nakamoto_blocks_mined: bool,
    ) {
        info!("------------------------- Try mining one block -------------------------");

        let reward_cycle = self.get_current_reward_cycle();

        self.mine_nakamoto_block(timeout, use_nakamoto_blocks_mined);
        self.check_signer_states_normal();

        // Verify that the signers accepted the proposed block, sending back a validate ok response
        let proposed_signer_signature_hash = self
            .wait_for_validate_ok_response(timeout.as_secs())
            .signer_signature_hash;
        let message = proposed_signer_signature_hash.0;

        info!("------------------------- Test Block Signed -------------------------");
        // Verify that the signers signed the proposed block
        let signature = self.wait_for_confirmed_block_v0(&proposed_signer_signature_hash, timeout);

        info!("Got {} signatures", signature.len());

        // NOTE: signature.len() does not need to equal signers.len(); the stacks miner can finish the block
        //  whenever it has crossed the threshold.
        assert!(signature.len() >= num_signers * 7 / 10);
        info!("Verifying signatures against signers for reward cycle {reward_cycle:?}");
        let signers = self.get_reward_set_signers(reward_cycle);

        // Verify that the signers signed the proposed block
        let mut signer_index = 0;
        let mut signature_index = 0;
        let mut signing_keys = HashSet::new();
        let start = Instant::now();
        debug!(
            "Validating {} signatures against {num_signers} signers",
            signature.len()
        );
        let validated = loop {
            // Since we've already checked `signature.len()`, this means we've
            //  validated all the signatures in this loop
            let Some(signature) = signature.get(signature_index) else {
                break true;
            };
            let Some(signer) = signers.get(signer_index) else {
                error!("Failed to validate the mined nakamoto block: ran out of signers to try to validate signatures");
                break false;
            };
            if !signing_keys.insert(signer.signing_key) {
                panic!("Duplicate signing key detected: {:?}", signer.signing_key);
            }
            let stacks_public_key = Secp256k1PublicKey::from_slice(signer.signing_key.as_slice())
                .expect("Failed to convert signing key to StacksPublicKey");
            let valid = stacks_public_key
                .verify(&message, signature)
                .expect("Failed to verify signature");
            if !valid {
                info!(
                    "Failed to verify signature for signer, will attempt to validate without this signer";
                    "signer_pk" => stacks_public_key.to_hex(),
                    "signer_index" => signer_index,
                    "signature_index" => signature_index,
                );
                signer_index += 1;
            } else {
                signer_index += 1;
                signature_index += 1;
            }
            // Shouldn't really ever timeout, but do this in case there is some sort of overflow/underflow happening.
            assert!(
                start.elapsed() < timeout,
                "Timed out waiting to confirm block signatures"
            );
        };

        assert!(validated);
    }

    // Only call after already past the epoch 3.0 boundary
    fn run_until_burnchain_height_nakamoto(
        &self,
        timeout: Duration,
        burnchain_height: u64,
        num_signers: usize,
    ) {
        let current_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        let total_nmb_blocks_to_mine = burnchain_height.saturating_sub(current_block_height);
        debug!("Mining {total_nmb_blocks_to_mine} Nakamoto block(s) to reach burnchain height {burnchain_height}");
        for _ in 0..total_nmb_blocks_to_mine {
            self.mine_and_verify_confirmed_naka_block(timeout, num_signers, false);
        }
    }

    fn get_miner_key(&self) -> &Secp256k1PrivateKey {
        self.running_nodes.conf.miner.mining_key.as_ref().unwrap()
    }

    /// Propose a block to the signers
    fn propose_block(&self, block: NakamotoBlock, timeout: Duration) {
        let miners_contract_id = boot_code_id(MINERS_NAME, false);
        let mut session = StackerDBSession::new(
            &self.running_nodes.conf.node.rpc_bind,
            miners_contract_id,
            self.running_nodes.conf.miner.stackerdb_timeout,
        );
        let burn_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        let reward_cycle = self.get_current_reward_cycle();
        let signer_signature_hash = block.header.signer_signature_hash();
        let signed_by = block.header.recover_miner_pk().expect(
            "FATAL: signer tests should only propose blocks that have been signed by the signer test miner. Otherwise, signers won't even consider them via this channel."
        );
        let message = SignerMessage::BlockProposal(BlockProposal {
            block,
            burn_height,
            reward_cycle,
            block_proposal_data: BlockProposalData::empty(),
        });
        let miner_sk = self
            .running_nodes
            .conf
            .miner
            .mining_key
            .clone()
            .expect("No mining key");
        assert_eq!(signed_by, Secp256k1PublicKey::from_private(&miner_sk),
                   "signer tests should only propose blocks that have been signed by the signer test miner. Otherwise, signers won't even consider them via this channel.");

        // Submit the block proposal to the miner's slot
        let mut accepted = false;
        let mut version = 0;
        let slot_id = MinerSlotID::BlockProposal.to_u8() as u32;
        let start = Instant::now();
        debug!("Proposing block to signers: {signer_signature_hash}");
        while !accepted {
            let mut chunk =
                StackerDBChunkData::new(slot_id * 2, version, message.serialize_to_vec());
            chunk.sign(&miner_sk).expect("Failed to sign message chunk");
            debug!("Produced a signature: {:?}", chunk.sig);
            let result = session.put_chunk(&chunk).expect("Failed to put chunk");
            accepted = result.accepted;
            version += 1;
            debug!("Test Put Chunk ACK: {result:?}");
            assert!(
                start.elapsed() < timeout,
                "Timed out waiting for block proposal to be accepted"
            );
        }
    }
}

/// A test harness for running multiple miners with v0::signers
pub struct MultipleMinerTest {
    signer_test: SignerTest<SpawnedSigner>,
    sender_sk: Secp256k1PrivateKey,
    send_amt: u64,
    send_fee: u64,
    conf_node_2: NeonConfig,
    rl2_thread: thread::JoinHandle<()>,
    rl2_counters: Counters,
    rl2_coord_channels: Arc<Mutex<CoordinatorChannels>>,
    rl2_stopper: Arc<AtomicBool>,
}

impl MultipleMinerTest {
    /// Create a new test harness for running multiple miners with num_signers underlying signers and enough funds to send
    /// num_txs transfer transactions.
    ///
    /// Will partition the signer set so that ~half are listening and using node 1 for RPC and events,
    /// and the rest are using node 2
    pub fn new(num_signers: usize, num_txs: u64) -> MultipleMinerTest {
        Self::new_with_config_modifications(num_signers, num_txs, |_| {}, |_| {}, |_| {})
    }

    /// Create a new test harness for running multiple miners with num_signers underlying signers and enough funds to send
    /// num_txs transfer transactions.
    ///
    /// Will also modify the signer config and the node 1 and node 2 configs with the provided
    /// modifiers. Will partition the signer set so that ~half are listening and using node 1 for RPC and events,
    /// and the rest are using node 2 unless otherwise specified via the signer config modifier.
    pub fn new_with_config_modifications<
        F: FnMut(&mut SignerConfig),
        G: FnMut(&mut NeonConfig),
        H: FnMut(&mut NeonConfig),
    >(
        num_signers: usize,
        num_transfer_txs: u64,
        signer_config_modifier: F,
        node_1_config_modifier: G,
        node_2_config_modifier: H,
    ) -> MultipleMinerTest {
        Self::new_with_signer_dist(
            num_signers,
            num_transfer_txs,
            signer_config_modifier,
            node_1_config_modifier,
            node_2_config_modifier,
            |port| u8::try_from(port % 2).unwrap(),
            None,
        )
    }

    /// Create a new test harness for running multiple miners with num_signers underlying signers and enough funds to send
    /// num_txs transfer transactions.
    ///
    /// Will also modify the signer config and the node 1 and node 2 configs with the provided
    /// modifiers. Will partition the signer set so that ~half are listening and using node 1 for RPC and events,
    /// and the rest are using node 2 unless otherwise specified via the signer config modifier.
    pub fn new_with_signer_dist<
        F: FnMut(&mut SignerConfig),
        G: FnMut(&mut NeonConfig),
        H: FnMut(&mut NeonConfig),
        S: Fn(u16) -> u8,
    >(
        num_signers: usize,
        num_transfer_txs: u64,
        mut signer_config_modifier: F,
        mut node_1_config_modifier: G,
        mut node_2_config_modifier: H,
        signer_distributor: S,
        ports: Option<Vec<u16>>,
    ) -> MultipleMinerTest {
        let sender_sk = Secp256k1PrivateKey::random();
        let sender_addr = tests::to_addr(&sender_sk);
        let send_amt = 1000;
        let send_fee = 180;

        let btc_miner_1_seed = vec![1, 1, 1, 1];
        let btc_miner_2_seed = vec![2, 2, 2, 2];
        let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
        let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

        let (node_1_rpc, node_1_p2p, node_2_rpc, node_2_p2p) = if let Some(ports) = ports {
            (ports[0], ports[1], ports[2], ports[3])
        } else {
            (
                gen_random_port(),
                gen_random_port(),
                gen_random_port(),
                gen_random_port(),
            )
        };

        let localhost = "127.0.0.1";
        let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
        let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
        let mut node_2_listeners = Vec::new();

        // partition the signer set so that ~half are listening and using node 1 for RPC and events,
        //  and the rest are using node 2
        let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
            num_signers,
            vec![(sender_addr, (send_amt + send_fee) * num_transfer_txs)],
            |signer_config| {
                let node_host = match signer_distributor(signer_config.endpoint.port()) {
                    0 => &node_1_rpc_bind,
                    1 => &node_2_rpc_bind,
                    o => panic!("Multiminer test can't distribute signer to node #{o}"),
                };
                signer_config.node_host = node_host.to_string();
                signer_config_modifier(signer_config);
            },
            |config, test_observer_port| {
                config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
                config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
                config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
                config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
                config.node.pox_sync_sample_secs = 30;
                config.burnchain.pox_reward_length = Some(30);

                config.node.seed = btc_miner_1_seed.clone();
                config.node.local_peer_seed = btc_miner_1_seed.clone();
                config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
                config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));

                config.events_observers.retain(|listener| {
                    let Ok(addr) = std::net::SocketAddr::from_str(&listener.endpoint) else {
                        warn!(
                            "Cannot parse {} to a socket, assuming it isn't a signer-listener binding",
                            listener.endpoint
                        );
                        return true;
                    };
                    if addr.port() == test_observer_port {
                        return true;
                    }
                    match signer_distributor(addr.port()) {
                        0 => true,
                        1 => {
                            node_2_listeners.push(listener.clone());
                            false
                        }
                        o => panic!("Multiminer test can't distribute signer to node #{o}"),
                    }
                });
                node_1_config_modifier(config);
            },
            Some(vec![btc_miner_1_pk.clone(), btc_miner_2_pk.clone()]),
            None,
        );
        let conf = signer_test.running_nodes.conf.clone();
        let mut conf_node_2 = conf.clone();
        conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
        conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
        conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
        conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
        conf_node_2.node.seed = btc_miner_2_seed.clone();
        conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
        conf_node_2.node.local_peer_seed = btc_miner_2_seed;
        conf_node_2.miner.mining_key = Some(StacksPrivateKey::from_seed(&[2]));
        conf_node_2.node.miner = true;
        conf_node_2.events_observers.clear();
        conf_node_2.events_observers.extend(node_2_listeners);
        node_2_config_modifier(&mut conf_node_2);

        let node_1_sk = StacksPrivateKey::from_seed(&conf.node.local_peer_seed);
        let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

        conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

        conf_node_2.node.set_bootstrap_nodes(
            format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_address),
            conf.burnchain.chain_id,
            conf.burnchain.peer_version,
        );

        let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
        let rl2_stopper = run_loop_2.get_termination_switch();
        let rl2_coord_channels = run_loop_2.coordinator_channels();
        let rl2_counters = run_loop_2.counters();

        let rl2_thread = thread::Builder::new()
            .name("run_loop_2".into())
            .spawn(move || run_loop_2.start(None, 0))
            .unwrap();

        MultipleMinerTest {
            signer_test,
            sender_sk,
            send_amt,
            send_fee,
            conf_node_2,
            rl2_thread,
            rl2_counters,
            rl2_stopper,
            rl2_coord_channels,
        }
    }

    pub fn get_counters_for_miner(&self, miner_index: usize) -> Counters {
        match miner_index {
            1 => self.signer_test.running_nodes.counters.clone(),
            2 => self.rl2_counters.clone(),
            _ => panic!("Invalid miner index {}: must be 1 or 2", miner_index),
        }
    }

    pub fn get_primary_proposals_submitted(&self) -> RunLoopCounter {
        self.signer_test
            .running_nodes
            .counters
            .naka_proposed_blocks
            .clone()
    }

    pub fn get_test_observer(&self) -> &TestObserver {
        &self.signer_test.running_nodes.test_observer
    }

    /// Boot node 1 to epoch 3.0 and wait for node 2 to catch up.
    pub fn boot_to_epoch_3(&mut self) {
        info!(
            "------------------------- Booting Both Miners to Epoch 3.0 -------------------------"
        );

        self.signer_test.boot_to_epoch_3();
        // Use a longer timeout for the miners to advance to epoch 3.0 and so that CI runners don't timeout.
        self.wait_for_chains(600);

        info!("------------------------- Reached Epoch 3.0 -------------------------");
    }

    /// Returns a tuple of the node 1 and node 2 miner private keys respectively
    pub fn get_miner_private_keys(&self) -> (StacksPrivateKey, StacksPrivateKey) {
        (
            self.signer_test
                .running_nodes
                .conf
                .miner
                .mining_key
                .clone()
                .unwrap(),
            self.conf_node_2.miner.mining_key.clone().unwrap(),
        )
    }

    /// Returns a tuple of the node 1 and node 2 miner public keys respectively
    pub fn get_miner_public_keys(&self) -> (StacksPublicKey, StacksPublicKey) {
        let (sk1, sk2) = self.get_miner_private_keys();
        (
            StacksPublicKey::from_private(&sk1),
            StacksPublicKey::from_private(&sk2),
        )
    }

    /// Returns a tuple of the node 1 and node 2 miner private key hashes respectively
    pub fn get_miner_public_key_hashes(&self) -> (Hash160, Hash160) {
        let (pk1, pk2) = self.get_miner_public_keys();
        (
            Hash160::from_node_public_key(&pk1),
            Hash160::from_node_public_key(&pk2),
        )
    }

    /// Returns a tuple of the node 1 and node 2 miner node configs respectively
    pub fn get_node_configs(&self) -> (NeonConfig, NeonConfig) {
        (
            self.signer_test.running_nodes.conf.clone(),
            self.conf_node_2.clone(),
        )
    }

    pub fn btc_regtest_controller_mut(&mut self) -> &mut BitcoinRegtestController {
        &mut self.signer_test.running_nodes.btc_regtest_controller
    }

    /// Mine `nmb_blocks` blocks on the bitcoin regtest chain and wait for the sortition
    /// database to confirm the block.
    pub fn mine_bitcoin_blocks_and_confirm(
        &mut self,
        sortdb: &SortitionDB,
        nmb_blocks: u64,
        timeout_secs: u64,
    ) -> Result<(), String> {
        let burn_block_before = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height;

        self.btc_regtest_controller_mut()
            .build_next_block(nmb_blocks);

        wait_for(timeout_secs, || {
            let burn_block = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .unwrap()
                .block_height;
            Ok(burn_block >= burn_block_before + nmb_blocks
                && self.get_peer_info().burn_block_height >= burn_block_before + nmb_blocks)
        })?;
        let peer_after = self.get_peer_info();
        wait_for_state_machine_update(
            timeout_secs,
            &peer_after.pox_consensus,
            peer_after.burn_block_height,
            None,
            &self.signer_test.signer_addresses_versions(),
            &self.signer_test.running_nodes.test_observer,
        )
    }

    /// Mine `nmb_blocks` blocks on the bitcoin regtest chain and wait for the sortition
    /// database to confirm the block and the test_observer to see the block.
    pub fn mine_bitcoin_blocks_and_confirm_with_test_observer(
        &mut self,
        sortdb: &SortitionDB,
        nmb_blocks: u64,
        timeout_secs: u64,
    ) -> Result<(), String> {
        let blocks_before = &self
            .signer_test
            .running_nodes
            .test_observer
            .get_blocks()
            .len();
        let burn_block_before = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height;

        self.btc_regtest_controller_mut()
            .build_next_block(nmb_blocks);
        wait_for(timeout_secs, || {
            let burn_block = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
                .unwrap()
                .block_height;
            let blocks = self
                .signer_test
                .running_nodes
                .test_observer
                .get_blocks()
                .len();
            Ok(burn_block >= burn_block_before + nmb_blocks
                && blocks >= blocks_before + nmb_blocks as usize)
        })
    }

    /// Mine a bitcoin block and wait for the sortition database to confirm the block and wait
    /// for a tenure change transaction to be subseqently mined in a stacks block at the appropriate height.
    pub fn mine_bitcoin_block_and_tenure_change_tx(
        &mut self,
        sortdb: &SortitionDB,
        cause: TenureChangeCause,
        timeout_secs: u64,
    ) -> Result<serde_json::Value, String> {
        let start = Instant::now();
        let stacks_height_before = self.get_peer_stacks_tip_height();
        self.mine_bitcoin_blocks_and_confirm(sortdb, 1, timeout_secs)?;
        wait_for_tenure_change_tx(
            timeout_secs.saturating_sub(start.elapsed().as_secs()),
            cause,
            stacks_height_before + 1,
            &self.signer_test.running_nodes.test_observer,
        )
    }

    /// Sends a transfer tx to the stacks node and returns the txid and nonce used
    pub fn send_transfer_tx(&self) -> (String, u64) {
        self.signer_test
            .submit_transfer_tx(&self.sender_sk, self.send_fee, self.send_amt)
            .unwrap()
    }

    fn node_http(&self) -> String {
        format!(
            "http://{}",
            &self.signer_test.running_nodes.conf.node.rpc_bind
        )
    }

    /// Sends a transfer tx to the stacks node and waits for the stacks node to mine it
    /// Returns the txid of the transfer tx.
    pub fn send_and_mine_transfer_tx(&mut self, timeout_secs: u64) -> Result<String, String> {
        let (txid, nonce) = self.send_transfer_tx();
        let http_origin = self.node_http();
        let sender_addr = tests::to_addr(&self.sender_sk);
        wait_for(timeout_secs, || {
            Ok(get_account(&http_origin, &sender_addr).nonce > nonce)
        })?;
        Ok(txid)
    }

    pub fn send_contract_publish(
        &mut self,
        sender_nonce: u64,
        contract_name: &str,
        contract_src: &str,
    ) -> String {
        let http_origin = self.node_http();
        let contract_tx = make_contract_publish(
            &self.sender_sk,
            sender_nonce,
            self.send_fee + contract_name.len() as u64 + contract_src.len() as u64,
            self.signer_test.running_nodes.conf.burnchain.chain_id,
            contract_name,
            contract_src,
        );
        submit_tx(&http_origin, &contract_tx)
    }

    /// Sends a contract publish tx to the stacks node and waits for the stacks node to mine it
    /// Returns the txid of the transfer tx.
    pub fn send_and_mine_contract_publish(
        &mut self,
        sender_nonce: u64,
        contract_name: &str,
        contract_src: &str,
        timeout_secs: u64,
    ) -> Result<String, String> {
        let stacks_height_before = self.get_peer_stacks_tip_height();

        let txid = self.send_contract_publish(sender_nonce, contract_name, contract_src);

        // wait for the new block to be mined
        wait_for(timeout_secs, || {
            Ok(self.get_peer_stacks_tip_height() > stacks_height_before)
        })
        .unwrap();

        // wait for the observer to see it
        self.wait_for_test_observer_blocks(timeout_secs);

        if last_block_contains_txid(&txid, &self.signer_test.running_nodes.test_observer) {
            Ok(txid)
        } else {
            Err(txid)
        }
    }

    pub fn send_contract_call(
        &mut self,
        sender_nonce: u64,
        contract_name: &str,
        function_name: &str,
        function_args: &[clarity::vm::Value],
    ) -> String {
        let http_origin = self.node_http();
        // build a fake tx for getting a rough amount of fee
        let fake_contract_tx = make_contract_call(
            &self.sender_sk,
            sender_nonce,
            100,
            self.signer_test.running_nodes.conf.burnchain.chain_id,
            &tests::to_addr(&self.sender_sk),
            contract_name,
            function_name,
            function_args,
        );
        let contract_tx = make_contract_call(
            &self.sender_sk,
            sender_nonce,
            fake_contract_tx.len() as u64,
            self.signer_test.running_nodes.conf.burnchain.chain_id,
            &tests::to_addr(&self.sender_sk),
            contract_name,
            function_name,
            function_args,
        );
        submit_tx(&http_origin, &contract_tx)
    }

    /// Return the Peer Info from node 1
    pub fn get_peer_info(&self) -> PeerInfo {
        self.signer_test.get_peer_info()
    }

    /// Returns the peer info's reported stacks tip height from node 1
    pub fn get_peer_stacks_tip_height(&self) -> u64 {
        self.get_peer_info().stacks_tip_height
    }

    /// Returns the peer stacks tip hash from node 1
    pub fn get_peer_stacks_tip(&self) -> BlockHeaderHash {
        self.get_peer_info().stacks_tip
    }

    /// Return the consensus hash for the current stacks tip from node 1.
    /// This can be used to identify the active tenure.
    pub fn get_peer_stacks_tip_ch(&self) -> ConsensusHash {
        self.get_peer_info().stacks_tip_consensus_hash
    }

    /// Ensures that miner 2 submits a commit pointing to the current view reported by the stacks node as expected
    pub fn submit_commit_miner_2(&mut self, sortdb: &SortitionDB) {
        if !self.rl2_counters.naka_skip_commit_op.get() {
            warn!("Miner 2's commit ops were not paused. This may result in no commit being submitted.");
        }
        let burn_height = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height;

        let stacks_height_before = self.get_peer_stacks_tip_height();
        let rl2_commits_before = self
            .rl2_counters
            .naka_submitted_commits
            .load(Ordering::SeqCst);

        info!("Unpausing commits from RL2");
        self.rl2_counters.naka_skip_commit_op.set(false);

        info!("Waiting for commits from RL2");
        wait_for(30, || {
            Ok(self
                .rl2_counters
                .naka_submitted_commits
                .load(Ordering::SeqCst)
                > rl2_commits_before
                && self
                    .rl2_counters
                    .naka_submitted_commit_last_burn_height
                    .load(Ordering::SeqCst)
                    >= burn_height
                && self
                    .rl2_counters
                    .naka_submitted_commit_last_stacks_tip
                    .load(Ordering::SeqCst)
                    >= stacks_height_before)
        })
        .expect("Timed out waiting for miner 2 to submit a commit op");

        info!("Pausing commits from RL2");
        self.rl2_counters.naka_skip_commit_op.set(true);
    }

    /// Pause miner 1's commits
    pub fn pause_commits_miner_1(&mut self) {
        self.signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(true);
    }

    /// Pause miner 2's commits
    pub fn pause_commits_miner_2(&mut self) {
        self.rl2_counters.naka_skip_commit_op.set(true);
    }

    /// Ensures that miner 1 submits a commit pointing to the current view reported by the stacks node as expected
    pub fn submit_commit_miner_1(&mut self, sortdb: &SortitionDB) {
        if !self
            .signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .get()
        {
            warn!("Miner 1's commit ops were not paused. This may result in no commit being submitted.");
        }
        let burn_height = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height;
        let stacks_height_before = self.get_peer_stacks_tip_height();
        let rl1_commits_before = self
            .signer_test
            .running_nodes
            .counters
            .naka_submitted_commits
            .load(Ordering::SeqCst);

        info!("Unpausing commits from RL1");
        self.signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(false);

        info!("Waiting for commits from RL1");
        wait_for(30, || {
            Ok(self
                .signer_test
                .running_nodes
                .counters
                .naka_submitted_commits
                .load(Ordering::SeqCst)
                > rl1_commits_before
                && self
                    .signer_test
                    .running_nodes
                    .counters
                    .naka_submitted_commit_last_burn_height
                    .load(Ordering::SeqCst)
                    >= burn_height
                && self
                    .signer_test
                    .running_nodes
                    .counters
                    .naka_submitted_commit_last_stacks_tip
                    .load(Ordering::SeqCst)
                    >= stacks_height_before)
        })
        .expect("Timed out waiting for miner 1 to submit a commit op");

        info!("Pausing commits from RL1");
        self.signer_test
            .running_nodes
            .counters
            .naka_skip_commit_op
            .set(true);
    }

    /// Shutdown the test harness
    pub fn shutdown(self) {
        info!("------------------------- Shutting Down Multiple Miners Test -------------------------");
        self.rl2_coord_channels
            .lock()
            .expect("Mutex poisoned")
            .stop_chains_coordinator();
        self.rl2_stopper.store(false, Ordering::SeqCst);
        self.rl2_thread.join().unwrap();
        self.signer_test.shutdown();
    }

    pub fn wait_for_test_observer_blocks(&self, timeout_secs: u64) {
        let block_header_heash_tip = format!("0x{}", self.get_peer_stacks_tip().to_hex());

        wait_for(timeout_secs, || {
            for block in self
                .signer_test
                .running_nodes
                .test_observer
                .get_blocks()
                .iter()
                .rev()
            {
                if block["block_hash"].as_str().unwrap() == block_header_heash_tip {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .expect("Timed out waiting for test_observer blocks");
    }

    /// Wait for both miners to have the same stacks tip height
    pub fn wait_for_chains(&self, timeout_secs: u64) {
        wait_for(timeout_secs, || {
            let Some(node_1_info) = get_chain_info_opt(&self.signer_test.running_nodes.conf) else {
                return Ok(false);
            };
            let Some(node_2_info) = get_chain_info_opt(&self.conf_node_2) else {
                return Ok(false);
            };
            Ok(
                node_1_info.stacks_tip_height == node_2_info.stacks_tip_height
                    && node_1_info.burn_block_height == node_2_info.burn_block_height,
            )
        })
        .expect("Timed out waiting for boostrapped node to catch up to the miner");
    }

    pub fn assert_last_sortition_winner_reorged(&self) {
        let (conf_1, _) = self.get_node_configs();
        let latest_sortition = get_sortition_info(&conf_1);
        assert!(latest_sortition.stacks_parent_ch != latest_sortition.last_sortition_ch);
    }
}

/// Returns whether the last block in the test observer contains a tenure change
/// transaction with the given cause.
fn last_block_contains_tenure_change_tx(
    cause: TenureChangeCause,
    test_observer: &TestObserver,
) -> bool {
    let blocks = test_observer.get_blocks();
    let last_block = &blocks.last().unwrap();
    let transactions = last_block["transactions"].as_array().unwrap();
    let tx = transactions.first().expect("No transactions in block");
    let raw_tx = tx["raw_tx"].as_str().unwrap();
    let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
    let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    match &parsed.payload {
        TransactionPayload::TenureChange(payload) if payload.cause.is_eq(&cause) => {
            info!("Found tenure change transaction: {parsed:?}");
            true
        }
        _ => false,
    }
}

/// Check if a txid exists in the last block
fn last_block_contains_txid(txid: &str, test_observer: &TestObserver) -> bool {
    let blocks = test_observer.get_blocks();
    let last_block = blocks.last().unwrap();
    let transactions = last_block["transactions"].as_array().unwrap();
    for tx in transactions {
        let raw_tx = tx["raw_tx"].as_str().unwrap();
        let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
        let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
        if parsed.txid().to_string() == txid {
            return true;
        }
    }
    false
}

/// Asserts that the last block in the test observer contains a tenure change with the given cause.
fn verify_last_block_contains_tenure_change_tx(
    cause: TenureChangeCause,
    test_observer: &TestObserver,
) {
    assert!(last_block_contains_tenure_change_tx(cause, test_observer));
}

/// Verifies that the tip of the sortition database was won by the provided miner public key hash
pub fn verify_sortition_winner(sortdb: &SortitionDB, miner_pkh: &Hash160) {
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(tip.sortition);
    assert_eq!(&tip.miner_pk_hash.unwrap(), miner_pkh);
}

/// Waits for a block proposal to be observed in the test_observer stackerdb chunks at the expected height
/// and signed by the expected miner
pub fn wait_for_block_proposal(
    timeout_secs: u64,
    expected_height: u64,
    expected_miner: &StacksPublicKey,
    test_observer: &TestObserver,
) -> Result<NakamotoBlock, String> {
    let mut proposed_block = None;
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::BlockProposal(proposal) = message else {
                continue;
            };
            let miner_pk = proposal.block.header.recover_miner_pk().unwrap();
            let block_stacks_height = proposal.block.header.chain_length;
            if block_stacks_height != expected_height {
                continue;
            }
            if &miner_pk == expected_miner {
                proposed_block = Some(proposal.block);
                return Ok(true);
            }
        }
        Ok(false)
    })?;
    proposed_block.ok_or_else(|| "Failed to find block proposal".to_string())
}

/// Waits for a BlockPushed to be observed in the test_observer stackerdb chunks for a block
/// with the provided signer signature hash
fn wait_for_block_pushed(
    timeout_secs: u64,
    block_signer_signature_hash: &Sha512Trunc256Sum,
    test_observer: &TestObserver,
) -> Result<NakamotoBlock, String> {
    let mut block = None;
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockPushed(pushed_block) = message {
                if &pushed_block.header.signer_signature_hash() == block_signer_signature_hash {
                    block = Some(pushed_block);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })?;
    block.ok_or_else(|| "Failed to find block pushed".to_string())
}

/// Waits for a block with the provided expected height to be proposed and pushed by the miner with the provided public key.
pub fn wait_for_block_pushed_by_miner_key(
    timeout_secs: u64,
    expected_height: u64,
    expected_miner: &StacksPublicKey,
    test_observer: &TestObserver,
) -> Result<NakamotoBlock, String> {
    // Do not use wait_for_block_proposal as there might be multiple proposals for the same block
    // if the signers haven't yet updated their miner viewpoint before a miner proposes a block.
    let mut block = None;
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockPushed(pushed_block) = message {
                let block_stacks_height = pushed_block.header.chain_length;
                if block_stacks_height != expected_height {
                    continue;
                }

                let miner_pk = pushed_block.header.recover_miner_pk().unwrap();
                if &miner_pk == expected_miner {
                    block = Some(pushed_block);
                    return Ok(true);
                }
            }
        }
        Ok(false)
    })?;
    block.ok_or_else(|| "Failed to find block pushed".to_string())
}

/// Waits for all of the provided signers to send a pre-commit for a block
/// with the provided signer signature hash
pub fn wait_for_block_pre_commits_from_signers(
    timeout_secs: u64,
    signer_signature_hash: &Sha512Trunc256Sum,
    expected_signers: &[StacksPublicKey],
    test_observer: &TestObserver,
) -> Result<(), String> {
    wait_for(timeout_secs, || {
        let chunks = test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let pk = chunk.recover_pk().expect("Failed to recover pk");
                if !expected_signers.contains(&pk) {
                    return None;
                }
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");

                if let SignerMessage::BlockPreCommit(hash) = message {
                    if hash == *signer_signature_hash {
                        return Some(pk);
                    }
                }
                None
            })
            .collect::<HashSet<_>>();
        Ok(chunks.len() == expected_signers.len())
    })
}

/// Waits for >30% of num_signers block rejection to be observed in the test_observer stackerdb chunks for a block
/// with the provided signer signature hash
fn wait_for_block_global_rejection(
    timeout_secs: u64,
    block_signer_signature_hash: &Sha512Trunc256Sum,
    num_signers: usize,
    test_observer: &TestObserver,
) -> Result<(), String> {
    let mut found_rejections = HashSet::new();
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                signer_signature_hash,
                signature,
                ..
            })) = &message
            {
                if signer_signature_hash == block_signer_signature_hash {
                    found_rejections.insert(signature.clone());
                }
            }
        }
        Ok(found_rejections.len() >= num_signers * 3 / 10)
    })
}

/// Waits for >30% of num_signers block rejection to be observed in the test_observer stackerdb chunks for a block
/// with the provided signer signature hash and the specified reject_reason
pub fn wait_for_block_global_rejection_with_reject_reason(
    timeout_secs: u64,
    block_signer_signature_hash: &Sha512Trunc256Sum,
    num_signers: usize,
    reject_reason: Option<RejectReason>,
    test_observer: &TestObserver,
) -> Result<(), String> {
    let mut found_rejections = HashSet::new();
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                signer_signature_hash,
                signature,
                response_data,
                ..
            })) = &message
            {
                if signer_signature_hash != block_signer_signature_hash {
                    continue;
                }
                if let Some(reason) = reject_reason.as_ref() {
                    if &response_data.reject_reason != reason {
                        continue;
                    }
                }
                found_rejections.insert(signature.clone());
            }
        }
        Ok(found_rejections.len() >= num_signers * 3 / 10)
    })
}

/// Waits for the provided number of block rejections to be observed in the test_observer stackerdb chunks for a block
/// with the provided signer signature hash
fn wait_for_block_rejections(
    timeout_secs: u64,
    block_signer_signature_hash: &Sha512Trunc256Sum,
    num_rejections: usize,
    test_observer: &TestObserver,
) -> Result<(), String> {
    let mut found_rejections = HashSet::new();
    wait_for(timeout_secs, || {
        let chunks = test_observer.get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                signer_signature_hash,
                signature,
                ..
            })) = &message
            {
                if signer_signature_hash == block_signer_signature_hash {
                    found_rejections.insert(signature.clone());
                }
            }
        }
        Ok(found_rejections.len() == num_rejections)
    })
}

/// Waits for >70% of the provided signers to send an acceptance for a block
/// with the provided signer signature hash
pub fn wait_for_block_global_acceptance_from_signers(
    timeout_secs: u64,
    signer_signature_hash: &Sha512Trunc256Sum,
    expected_signers: &[StacksPublicKey],
    test_observer: &TestObserver,
) -> Result<(), String> {
    // Make sure that at least 70% of signers accepted the block proposal
    wait_for(timeout_secs, || {
        let signatures = test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                if let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message {
                    if &accepted.signer_signature_hash == signer_signature_hash
                        && expected_signers.iter().any(|pk| {
                            pk.verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                                .expect("Failed to verify signature")
                        })
                    {
                        return Some(accepted.signature);
                    }
                }
                None
            })
            .collect::<HashSet<_>>();
        Ok(signatures.len() > expected_signers.len() * 7 / 10)
    })
}

/// Waits for all of the provided signers to send an acceptance for a block
/// with the provided signer signature hash
pub fn wait_for_block_acceptance_from_signers(
    timeout_secs: u64,
    signer_signature_hash: &Sha512Trunc256Sum,
    expected_signers: &[StacksPublicKey],
    test_observer: &TestObserver,
) -> Result<Vec<BlockAccepted>, String> {
    let mut result = vec![];
    wait_for(timeout_secs, || {
        let signatures = test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                if let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message {
                    if &accepted.signer_signature_hash == signer_signature_hash
                        && expected_signers.iter().any(|pk| {
                            pk.verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                                .expect("Failed to verify signature")
                        })
                    {
                        return Some((accepted.signature.clone(), accepted));
                    }
                }
                None
            })
            .collect::<HashMap<_, _>>();
        if signatures.len() == expected_signers.len() {
            result = signatures.values().cloned().collect();
            return Ok(true);
        }
        Ok(false)
    })?;
    Ok(result)
}

/// Waits for all of the provided signers to send a rejection for a block
/// with the provided signer signature hash
pub fn wait_for_block_rejections_from_signers(
    timeout_secs: u64,
    signer_signature_hash: &Sha512Trunc256Sum,
    expected_signers: &[StacksPublicKey],
    test_observer: &TestObserver,
) -> Result<Vec<BlockRejection>, String> {
    let mut result = Vec::new();
    wait_for(timeout_secs, || {
        let stackerdb_events = test_observer.get_stackerdb_chunks();
        let block_rejections: HashMap<_, _> = stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) => {
                        let rejected_pubkey = rejection
                            .recover_public_key()
                            .expect("Failed to recover public key from rejection");
                        if &rejection.signer_signature_hash == signer_signature_hash
                            && expected_signers.contains(&rejected_pubkey)
                        {
                            Some((rejected_pubkey, rejection))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .collect();
        if block_rejections.len() == expected_signers.len() {
            result = block_rejections.values().cloned().collect();
            return Ok(true);
        }
        Ok(false)
    })?;
    Ok(result)
}

/// Waits for at least 70% of the provided signers to send an update for a block with the specificed burn block height and parent tenure stacks block height and message version
pub fn wait_for_state_machine_update(
    timeout_secs: u64,
    expected_burn_block: &ConsensusHash,
    expected_burn_block_height: u64,
    expected_miner_info: Option<(Hash160, u64)>,
    signer_addresses: &[(StacksAddress, u64)],
    test_observer: &TestObserver,
) -> Result<(), String> {
    wait_for(timeout_secs, || {
        let mut found_updates = HashSet::new();
        let stackerdb_events = test_observer.get_stackerdb_chunks();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let Some((address, version)) = signer_addresses
                .iter()
                .find(|(addr, _)| chunk.verify(addr).unwrap())
            else {
                continue;
            };
            let (burn_block, burn_block_height, current_miner) = match (version, &update.content) {
                (
                    0,
                    StateMachineUpdateContent::V0 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                    },
                )
                | (
                    1,
                    StateMachineUpdateContent::V1 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                        ..
                    },
                )
                | (
                    2,
                    StateMachineUpdateContent::V2 {
                        burn_block,
                        burn_block_height,
                        current_miner,
                        ..
                    },
                ) => (burn_block, burn_block_height, current_miner.clone()),
                (_, _) => continue,
            };
            if burn_block_height != &expected_burn_block_height || burn_block != expected_burn_block
            {
                continue;
            }
            if let Some((expected_miner_pkh, expected_miner_parent_tenure_last_block_height)) =
                &expected_miner_info
            {
                match current_miner {
                    StateMachineUpdateMinerState::ActiveMiner {
                        current_miner_pkh,
                        parent_tenure_last_block_height,
                        ..
                    } => {
                        if expected_miner_pkh != &current_miner_pkh
                            || *expected_miner_parent_tenure_last_block_height
                                != parent_tenure_last_block_height
                        {
                            continue;
                        }
                    }
                    StateMachineUpdateMinerState::NoValidMiner => {
                        continue;
                    }
                }
            };
            // We only need one update to match our conditions
            found_updates.insert(address);
        }
        Ok(found_updates.len() > signer_addresses.len() * 7 / 10)
    })
}

/// Waits for at least 70% of the provided signers to send an update with the specificed active miner tenure id.
pub fn wait_for_state_machine_update_by_miner_tenure_id(
    timeout_secs: u64,
    expected_tenure_id: &ConsensusHash,
    signer_addresses: &[(StacksAddress, u64)],
    test_observer: &TestObserver,
) -> Result<(), String> {
    wait_for(timeout_secs, || {
        let mut found_updates = HashSet::new();
        let stackerdb_events = test_observer.get_stackerdb_chunks();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");
            let SignerMessage::StateMachineUpdate(update) = message else {
                continue;
            };
            let Some((address, version)) = signer_addresses
                .iter()
                .find(|(addr, _)| chunk.verify(addr).unwrap())
            else {
                continue;
            };
            match (version, &update.content) {
                (
                    0,
                    StateMachineUpdateContent::V0 {
                        current_miner: StateMachineUpdateMinerState::ActiveMiner { tenure_id, .. },
                        ..
                    },
                )
                | (
                    1,
                    StateMachineUpdateContent::V1 {
                        current_miner: StateMachineUpdateMinerState::ActiveMiner { tenure_id, .. },
                        ..
                    },
                )
                | (
                    2,
                    StateMachineUpdateContent::V2 {
                        current_miner: StateMachineUpdateMinerState::ActiveMiner { tenure_id, .. },
                        ..
                    },
                ) => {
                    if tenure_id == expected_tenure_id {
                        found_updates.insert(address);
                    }
                }
                (_, _) => {}
            };
        }
        Ok(found_updates.len() > signer_addresses.len() * 7 / 10)
    })
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// Test that a signer can respond to an invalid block proposal
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// The stacks node is advanced to epoch 3.0 reward set calculation to ensure the signer set is determined.
/// An invalid block proposal is forcibly written to the miner's slot to simulate the miner proposing a block.
/// The signers process the invalid block by first verifying it against the stacks node block proposal endpoint.
/// The signer that submitted the initial block validation request, should issue a  broadcast a rejection of the
/// miner's proposed block back to the respective .signers-XXX-YYY contract.
///
/// Test Assertion:
/// Each signer successfully rejects the invalid block proposal.
fn block_proposal_rejection() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    signer_test.boot_to_epoch_3();
    let short_timeout = Duration::from_secs(30);

    info!("------------------------- Send Block Proposal To Signers -------------------------");
    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    block.header.timestamp = get_epoch_time_secs();

    // First propose a block to the signers that does not have the correct consensus hash or BitVec. This should be rejected BEFORE
    // the block is submitted to the node for validation.
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash_1 = block.header.signer_signature_hash();
    signer_test.propose_block(block.clone(), short_timeout);

    // Wait for the first block to be mined successfully so we have the most up to date sortition view
    signer_test.wait_for_validate_ok_response(short_timeout.as_secs());

    // Propose a block to the signers that passes initial checks but will be rejected by the stacks node
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.data.consensus_hash;
    block.header.chain_length = 35; // We have mined 35 blocks so far.

    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash_2 = block.header.signer_signature_hash();
    signer_test.propose_block(block, short_timeout);

    info!("------------------------- Test Block Proposal Rejected -------------------------");
    // Verify the signers rejected the second block via the endpoint
    let reject = signer_test
        .wait_for_validate_reject_response(short_timeout.as_secs(), &block_signer_signature_hash_2);
    assert!(matches!(
        reject.reason_code,
        ValidateRejectCode::UnknownParent
    ));

    let start_polling = Instant::now();
    let mut found_signer_signature_hash_1 = false;
    let mut found_signer_signature_hash_2 = false;
    while !found_signer_signature_hash_1 && !found_signer_signature_hash_2 {
        std::thread::sleep(Duration::from_secs(1));
        let chunks = signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                reason: _reason,
                reason_code,
                signer_signature_hash,
                response_data,
                ..
            })) = message
            {
                if signer_signature_hash == block_signer_signature_hash_1 {
                    found_signer_signature_hash_1 = true;
                    assert_eq!(reason_code, RejectCode::SortitionViewMismatch,);
                    assert_eq!(response_data.reject_reason, RejectReason::InvalidBitvec);
                } else if signer_signature_hash == block_signer_signature_hash_2 {
                    found_signer_signature_hash_2 = true;
                    assert!(matches!(
                        reason_code,
                        RejectCode::ValidationFailed(ValidateRejectCode::UnknownParent)
                    ));
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }
        assert!(
            start_polling.elapsed() <= short_timeout,
            "Timed out after waiting for response from signer"
        );
    }
    signer_test.shutdown();
}

// Basic test to ensure that miners are able to gather block responses
// from signers and create blocks.
#[test]
#[ignore]
fn miner_gather_signatures() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Disable p2p broadcast of the nakamoto blocks, so that we rely
    //  on the signer's using StackerDB to get pushed blocks
    nakamoto_node::miner::TEST_P2P_BROADCAST_SKIP.set(true);

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine and Verify Confirmed Nakamoto Block -------------------------");
    TEST_MINE_SKIP.set(true);
    signer_test.mine_bitcoin_block();
    TEST_MINE_SKIP.set(false);
    signer_test.check_signer_states_normal();

    // Test prometheus metrics response
    #[cfg(feature = "monitoring_prom")]
    {
        let min_num_expected = (num_signers * 2) as u64;
        wait_for(30, || {
            use regex::Regex;

            let metrics_response = signer_test.get_signer_metrics();
            let re_precommits =
                Regex::new(r#"stacks_signer_block_pre_commits_sent (\d+)"#).unwrap();
            let re_proposals =
                Regex::new(r#"stacks_signer_block_proposals_received (\d+)"#).unwrap();
            let re_responses = Regex::new(
                r#"stacks_signer_block_responses_sent\{response_type="accepted"\} (\d+)"#,
            )
            .unwrap();

            let precommits = re_precommits
                .captures(&metrics_response)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().parse::<u64>().ok())
                .flatten();

            let proposals = re_proposals
                .captures(&metrics_response)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().parse::<u64>().ok())
                .flatten();

            let responses = re_responses
                .captures(&metrics_response)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().parse::<u64>().ok())
                .flatten();

            if let (Some(proposals), Some(responses), Some(precommits)) =
                (proposals, responses, precommits)
            {
                Ok(proposals >= min_num_expected
                    && responses >= min_num_expected
                    && precommits >= min_num_expected)
            } else {
                Ok(false)
            }
        })
        .expect("Failed to advance prometheus metrics");
    }
}

#[test]
#[ignore]
/// Test that signers can handle a transition between Nakamoto reward cycles
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 2 full Nakamoto reward cycles, sending blocks to observing signers to sign and return.
///
/// Test Assertion:
/// All signers sign all blocks successfully.
/// The chain advances 2 full reward cycles.
fn mine_2_nakamoto_reward_cycles() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let nmb_reward_cycles = 2;
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let timeout = Duration::from_secs(200);
    signer_test.boot_to_epoch_3();
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    // Mine 2 full Nakamoto reward cycles (epoch 3 starts in the middle of one, hence the + 1)
    let next_reward_cycle = curr_reward_cycle.saturating_add(1);
    let final_reward_cycle = next_reward_cycle.saturating_add(nmb_reward_cycles);
    let final_reward_cycle_height_boundary = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(final_reward_cycle)
        .saturating_sub(1);

    info!("------------------------- Test Mine 2 Nakamoto Reward Cycles -------------------------");
    signer_test.run_until_burnchain_height_nakamoto(
        timeout,
        final_reward_cycle_height_boundary,
        num_signers,
    );

    let current_burnchain_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    assert_eq!(current_burnchain_height, final_reward_cycle_height_boundary);
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test to make sure that the signers are capable of reloading their reward set
///  if the stacks-node doesn't have it available at the first block of a prepare phase (e.g., if there was no block)
fn reloads_signer_set_in() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);

    setup_epoch_3_reward_set(
        &signer_test.running_nodes.conf,
        &signer_test.running_nodes.counters.blocks_processed,
        &signer_test.signer_stacks_private_keys,
        &signer_test.signer_stacks_private_keys,
        &signer_test.running_nodes.btc_regtest_controller,
        Some(signer_test.num_stacking_cycles),
    );

    let naka_conf = &signer_test.running_nodes.conf;
    let epochs = naka_conf.burnchain.epochs.clone().unwrap();
    let epoch_3 = &epochs[StacksEpochId::Epoch30];
    let reward_cycle_len = naka_conf.get_burnchain().pox_constants.reward_cycle_length as u64;
    let prepare_phase_len = naka_conf.get_burnchain().pox_constants.prepare_length as u64;

    let epoch_3_start_height = epoch_3.start_height;
    assert!(
        epoch_3_start_height > 0,
        "Epoch 3.0 start height must be greater than 0"
    );
    let epoch_3_reward_cycle_boundary =
        epoch_3_start_height.saturating_sub(epoch_3_start_height % reward_cycle_len);
    let before_epoch_3_reward_set_calculation =
        epoch_3_reward_cycle_boundary.saturating_sub(prepare_phase_len);
    run_until_burnchain_height(
        &signer_test.running_nodes.btc_regtest_controller,
        &signer_test.running_nodes.counters.blocks_processed,
        before_epoch_3_reward_set_calculation,
        naka_conf,
    );

    info!("Waiting for signer set calculation.");
    let short_timeout = Duration::from_secs(30);
    // Make sure the signer set is calculated before continuing or signers may not
    // recognize that they are registered signers in the subsequent burn block event
    let reward_cycle = signer_test.get_current_reward_cycle() + 1;
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    wait_for(short_timeout.as_secs(), || {
        let reward_set = match signer_test
            .stacks_client
            .get_reward_set_signers(reward_cycle)
        {
            Ok(x) => x,
            Err(e) => {
                warn!("Failed to check if reward set is calculated yet: {e:?}. Will try again");
                return Ok(false);
            }
        };
        if let Some(ref set) = reward_set {
            info!("Signer set: {set:?}");
        }
        Ok(reward_set.is_some())
    })
    .expect("Timed out waiting for reward set to be calculated");
    info!("Signer set calculated");

    // Manually consume one more block to ensure signers refresh their state
    info!("Waiting for signers to initialize.");
    next_block_and_wait(
        &signer_test.running_nodes.btc_regtest_controller,
        &signer_test.running_nodes.counters.blocks_processed,
    );
    signer_test.wait_for_registered();
    info!("Signers initialized");

    signer_test.run_until_epoch_3_boundary();

    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();

    info!("Waiting 1 burnchain block for miner VRF key confirmation");
    // Wait one block to confirm the VRF register, wait until a block commit is submitted
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count >= 1)
        },
    )
    .unwrap();
    info!("Ready to mine Nakamoto blocks!");

    info!("------------------------- Reached Epoch 3.0 -------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
fn multiple_miners() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let max_nakamoto_tenures = 30;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |_| {},
        |config| {
            config.burnchain.pox_reward_length = Some(30);
            config.miner.block_commit_delay = Duration::from_secs(0);
            config.miner.tenure_cost_limit_per_block_percentage = None;
        },
        |_| {},
    );

    let (conf_1, conf_2) = miners.get_node_configs();
    miners.boot_to_epoch_3();
    let pre_nakamoto_peer_1_height = get_chain_info(&conf_1).stacks_tip_height;

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    info!("------------------------- Mining At Most {max_nakamoto_tenures} Tenures -------------------------");
    let rl1_counters = miners.signer_test.running_nodes.counters.clone();
    let rl2_counters = miners.rl2_counters.clone();
    let (miner_1_pk, miner_2_pk) = miners.get_miner_public_keys();
    let mut btc_blocks_mined = 1;
    let mut miner_1_tenures = 0;
    let mut miner_2_tenures = 0;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        assert!(
            max_nakamoto_tenures >= btc_blocks_mined,
            "Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting"
        );

        let info_1 = get_chain_info(&conf_1);
        let info_2 = get_chain_info(&conf_2);

        info!("Issue next block-build request\ninfo 1: {info_1:?}\ninfo 2: {info_2:?}\n");

        miners.signer_test.mine_block_wait_on_processing(
            &[&conf_1, &conf_2],
            &[&rl1_counters, &rl2_counters],
            Duration::from_secs(30),
        );

        miners.signer_test.check_signer_states_normal();

        btc_blocks_mined += 1;
        let blocks = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer);
        // for this test, there should be one block per tenure
        let consensus_hash_set: HashSet<_> =
            blocks.iter().map(|header| &header.consensus_hash).collect();
        assert_eq!(
            consensus_hash_set.len(),
            blocks.len(),
            "In this test, there should only be one block per tenure"
        );
        miner_1_tenures = blocks
            .iter()
            .filter(|header| {
                let header = header.anchored_header.as_stacks_nakamoto().unwrap();
                miner_1_pk
                    .verify(
                        header.miner_signature_hash().as_bytes(),
                        &header.miner_signature,
                    )
                    .unwrap()
            })
            .count();
        miner_2_tenures = blocks
            .iter()
            .filter(|header| {
                let header = header.anchored_header.as_stacks_nakamoto().unwrap();
                miner_2_pk
                    .verify(
                        header.miner_signature_hash().as_bytes(),
                        &header.miner_signature,
                    )
                    .unwrap()
            })
            .count();
    }

    let new_chain_info_1 = get_chain_info(&conf_1);
    let new_chain_info_2 = get_chain_info(&conf_2);
    info!("New chain info: {new_chain_info_1:?}");
    info!("New chain info: {new_chain_info_2:?}");

    let peer_1_height = new_chain_info_1.stacks_tip_height;
    let peer_2_height = new_chain_info_2.stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);
    assert_eq!(
        peer_1_height,
        pre_nakamoto_peer_1_height + btc_blocks_mined as u64 - 1
    );
    assert_eq!(
        btc_blocks_mined,
        u32::try_from(miner_1_tenures + miner_2_tenures).unwrap()
    );
    miners.shutdown();
}

/// Read processed nakamoto block IDs from the test observer, and use `config` to open
///  a chainstate DB and returns their corresponding StacksHeaderInfos
pub fn get_nakamoto_headers(
    config: &Config,
    test_observer: &TestObserver,
) -> Vec<StacksHeaderInfo> {
    let nakamoto_block_ids: HashSet<_> = test_observer
        .get_blocks()
        .into_iter()
        .filter_map(|block_json| {
            block_json.as_object().unwrap().get("miner_signature")?;
            let block_id = StacksBlockId::from_hex(
                &block_json
                    .as_object()
                    .unwrap()
                    .get("index_block_hash")
                    .unwrap()
                    .as_str()
                    .unwrap()[2..],
            )
            .unwrap();
            Some(block_id)
        })
        .collect();

    let (chainstate, _) = StacksChainState::open(
        config.is_mainnet(),
        config.burnchain.chain_id,
        &config.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    nakamoto_block_ids
        .into_iter()
        .map(|block_id| {
            NakamotoChainState::get_block_header(chainstate.db(), &block_id)
                .unwrap()
                .unwrap()
        })
        .collect()
}

#[test]
#[ignore]
/// This test checks the behavior at the end of a tenure. Specifically:
/// - The miner will broadcast the last block of the tenure, even if the signing is
///   completed after the next burn block arrives
/// - The signers will not sign a block that arrives after the next burn block, but
///   will finish a signing process that was in progress when the next burn block arrived
fn end_of_tenure() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let long_timeout = Duration::from_secs(200);
    let short_timeout = Duration::from_secs(20);
    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let proposed_blocks = signer_test
        .running_nodes
        .counters
        .naka_proposed_blocks
        .clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    signer_test.boot_to_epoch_3();
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    // Advance to one before the next reward cycle to ensure we are on the reward cycle boundary
    let final_reward_cycle = curr_reward_cycle + 1;
    let final_reward_cycle_height_boundary = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(final_reward_cycle)
        - 2;

    // give the system a chance to mine a Nakamoto block
    // But it doesn't have to mine one for this test to succeed?
    wait_for(short_timeout.as_secs(), || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .unwrap();

    info!("------------------------- Test Mine to Next Reward Cycle Boundary  -------------------------");
    signer_test.run_until_burnchain_height_nakamoto(
        long_timeout,
        final_reward_cycle_height_boundary,
        num_signers,
    );
    println!("Advanced to next reward cycle boundary: {final_reward_cycle_height_boundary}");
    assert_eq!(
        signer_test.get_current_reward_cycle(),
        final_reward_cycle - 1
    );

    info!("------------------------- Test Block Validation Stalled -------------------------");
    TEST_VALIDATE_STALL.set(true);

    let proposals_before = proposed_blocks.load(Ordering::SeqCst);
    let info = signer_test.get_peer_info();
    let blocks_before = info.stacks_tip_height;

    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    let start_time = Instant::now();
    while proposed_blocks.load(Ordering::SeqCst) <= proposals_before {
        assert!(
            start_time.elapsed() <= short_timeout,
            "Timed out waiting for block proposal"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    wait_for(short_timeout.as_secs(), || {
        let result = signer_test.get_current_reward_cycle() == final_reward_cycle;
        if !result {
            signer_test
                .running_nodes
                .btc_regtest_controller
                .build_next_block(1);
        }
        Ok(result)
    })
    .expect("Timed out waiting to enter the next reward cycle");

    wait_for(short_timeout.as_secs(), || {
        let blocks = signer_test
            .running_nodes
            .test_observer
            .get_burn_blocks()
            .last()
            .unwrap()
            .burn_block_height;
        Ok(blocks > final_reward_cycle_height_boundary)
    })
    .expect("Timed out waiting for burn block events");

    signer_test.wait_for_cycle(30, final_reward_cycle);

    info!("Block proposed and burn blocks consumed. Verifying that stacks block is still not processed");

    assert_eq!(
        get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height,
        blocks_before
    );

    info!("Unpausing block validation and waiting for block to be processed");
    // Disable the stall and wait for the block to be processed
    TEST_VALIDATE_STALL.set(false);
    wait_for(short_timeout.as_secs(), || {
        let processed_now = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
        Ok(processed_now > blocks_before)
    })
    .expect("Timed out waiting for block to be mined");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(info.stacks_tip_height, blocks_before + 1);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks that the miner will retry when enough signers reject the block.
fn retry_on_rejection() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let short_timeout = Duration::from_secs(30);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, (send_amt + send_fee) * 3)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    // wait until we get a sortition.
    // we might miss a block-commit at the start of epoch 3
    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    wait_for(30, || {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        Ok(tip.sortition)
    })
    .expect("Timed out waiting for sortition");

    // mine a nakamoto block
    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let proposed_blocks = signer_test
        .running_nodes
        .counters
        .naka_proposed_blocks
        .clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let start_time = Instant::now();
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine the first Nakamoto block");

    // a tenure has begun, so wait until we mine a block
    while mined_blocks.load(Ordering::SeqCst) <= blocks_before {
        assert!(
            start_time.elapsed() < short_timeout,
            "FAIL: Test timed out while waiting for block production",
        );
        thread::sleep(Duration::from_secs(1));
    }

    // make all signers reject the block
    let rejecting_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .take(num_signers)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers);

    let proposals_before = proposed_blocks.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    wait_for(60, || {
        if proposed_blocks.load(Ordering::SeqCst) > proposals_before {
            return Ok(true);
        }
        Ok(false)
    })
    .expect("Timed out waiting for block proposal");

    info!("Block proposed, verifying that it is not processed");
    // Wait 10 seconds to be sure that the timeout has occurred
    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(mined_blocks.load(Ordering::SeqCst), blocks_before);

    // resume signing
    info!("Disable unconditional rejection and wait for the block to be processed");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);

    wait_for(60, || {
        if mined_blocks.load(Ordering::SeqCst) > blocks_before {
            return Ok(true);
        }
        Ok(false)
    })
    .expect("Timed out waiting for block to be mined");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks that the signers will broadcast a block once they receive enough signatures.
fn signers_broadcast_signed_blocks() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();
    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let signer_pushed_blocks = signer_test
        .running_nodes
        .counters
        .naka_signer_pushed_blocks
        .clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    wait_for(30, || {
        let blocks_mined = mined_blocks.load(Ordering::SeqCst);
        let info = get_chain_info(&signer_test.running_nodes.conf);
        debug!(
            "blocks_mined: {blocks_mined},{blocks_before}, stacks_tip_height: {},{}",
            info.stacks_tip_height, info_before.stacks_tip_height
        );
        Ok(blocks_mined > blocks_before && info.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for first nakamoto block to be mined");

    TEST_IGNORE_SIGNERS.set(true);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let signer_pushed_before = signer_pushed_blocks.load(Ordering::SeqCst);
    let info_before = get_chain_info(&signer_test.running_nodes.conf);

    // submit a tx so that the miner will mine a blockn
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    debug!("Transaction sent; waiting for block-mining");

    wait_for(30, || {
        let signer_pushed = signer_pushed_blocks
            .load(Ordering::SeqCst);
        let blocks_mined = mined_blocks
            .load(Ordering::SeqCst);
        let info = get_chain_info(&signer_test.running_nodes.conf);
        debug!(
            "blocks_mined: {blocks_mined},{blocks_before}, signers_pushed: {signer_pushed},{signer_pushed_before}, stacks_tip_height: {},{}",
            info.stacks_tip_height,
            info_before.stacks_tip_height
        );
        Ok(blocks_mined > blocks_before
            && info.stacks_tip_height > info_before.stacks_tip_height
            && signer_pushed > signer_pushed_before)
    })
    .expect("Timed out waiting for second nakamoto block to be mined");

    signer_test.shutdown();
}

#[test]
#[ignore]
fn snapshot_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk =
        Secp256k1PrivateKey::from_seed(format!("sender_{}", function_name!()).as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let _recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let idle_timeout = Duration::from_secs(30);
    let miner_idle_timeout = idle_timeout + Duration::from_secs(10);
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(sender_addr.clone(), (send_amt + send_fee) * 1000)],
            |config| {
                config.tenure_idle_timeout = idle_timeout;
            },
            |config, _| {
                config.miner.tenure_timeout = miner_idle_timeout;
                config.miner.tenure_extend_cost_threshold = 0;
                config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );
    let _http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("---- Nakamoto booted, starting test ----");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    info!("---- Submit transfer tx ----");
    let (_transfer_txid, transfer_nonce) = signer_test
        .submit_transfer_tx(&sender_sk, send_fee, send_amt)
        .expect("Failed to submit transfer tx");

    signer_test
        .wait_for_nonce_increase(&sender_addr, transfer_nonce)
        .expect("Timed out waiting for nonce to increase");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks the behaviour of signers when a sortition is empty. Specifically:
/// - An empty tenure will cause the signers to mark a miner as misbehaving once a timeout is exceeded.
/// - The miner will stop trying to mine once it sees a threshold of signers reject the block
fn empty_tenure_delayed() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |node_config, _| {
            node_config.miner.block_commit_delay = Duration::from_secs(2);
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = Duration::from_secs(20);

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    signer_test.boot_to_epoch_3();

    let Counters {
        naka_mined_blocks: mined_blocks,
        naka_submitted_commits: submitted_commits,
        naka_rejected_blocks: rejected_blocks,
        ..
    } = signer_test.running_nodes.counters.clone();

    info!("------------------------- Test Mine Regular Tenure A  -------------------------");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);
    signer_test.check_signer_states_normal();

    info!("------------------------- Test Mine Empty Tenure B  -------------------------");
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let commits_before = submitted_commits.load(Ordering::SeqCst);
    info!("Pausing stacks block proposal to force an empty tenure");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk]);

    // Start new Tenure B
    // In the next block, the miner should win the tenure
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = submitted_commits.load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();
    signer_test.check_signer_states_normal();

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    assert_eq!(blocks_after, blocks_before);

    let rejected_before = rejected_blocks.load(Ordering::SeqCst);

    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    std::thread::sleep(block_proposal_timeout.add(Duration::from_secs(1)));

    signer_test.check_signer_states_revert_to_prior();

    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    info!("------------------------- Test Delayed Block is Rejected  -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle();
    let mut stackerdb = signer_test.readonly_stackerdb_client(reward_cycle);

    let signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();
    assert_eq!(signer_slot_ids.len(), num_signers);

    // The miner's proposed block should get rejected by all the signers
    let mut found_rejections = Vec::new();
    wait_for(short_timeout.as_secs(), || {
        for slot_id in signer_slot_ids.iter() {
            if found_rejections.contains(slot_id) {
                continue;
            }
            let mut latest_msgs = StackerDB::get_messages(
                stackerdb
                    .get_session_mut(&MessageSlotID::BlockResponse)
                    .expect("Failed to get BlockResponse stackerdb session"),
                &[*slot_id]
            ).expect("Failed to get message from stackerdb");
            assert!(latest_msgs.len() <= 1);
            let Some(latest_msg) = latest_msgs.pop() else {
                info!("No message yet from slot #{slot_id}, will wait to try again");
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                reason_code,
                metadata,
                response_data,
                ..
            })) = latest_msg
            {
                assert_eq!(reason_code, RejectCode::SortitionViewMismatch);
                assert_eq!(response_data.reject_reason, RejectReason::InvalidMiner);
                assert_eq!(metadata.server_version, VERSION_STRING.to_string());
                found_rejections.push(*slot_id);
            } else {
                info!("Latest message from slot #{slot_id} isn't a block rejection, will wait to see if the signer updates to a rejection");
            }
        }
        let rejections = rejected_blocks
            .load(Ordering::SeqCst);

        // wait until we've found rejections for all the signers, and the miner has confirmed that
        // the signers have rejected the block
        Ok(found_rejections.len() == signer_slot_ids.len() && rejections > rejected_before)
    }).unwrap();
    info!("------------------------- Shutting Down -------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks that Epoch 2.5 signers will issue a mock signature per burn block they receive.
fn mock_sign_epoch_25() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |node_config, _| {
            node_config.miner.pre_nakamoto_mock_signing = true;
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            epochs[StacksEpochId::Epoch25].end_height = 251;
            epochs[StacksEpochId::Epoch30].start_height = 251;
            epochs[StacksEpochId::Epoch30].end_height = 265;
            epochs[StacksEpochId::Epoch31].start_height = 265;
            epochs[StacksEpochId::Epoch31].end_height = 285;
            epochs[StacksEpochId::Epoch32].start_height = 285;
            epochs[StacksEpochId::Epoch32].end_height = 305;
            epochs[StacksEpochId::Epoch33].start_height = 305;
        },
        None,
        None,
    );

    let epochs = signer_test
        .running_nodes
        .conf
        .burnchain
        .epochs
        .clone()
        .unwrap();
    let epoch_3 = &epochs[StacksEpochId::Epoch30];
    let epoch_3_boundary = epoch_3.start_height - 1; // We only advance to the boundary as epoch 2.5 miner gets torn down at the boundary

    signer_test.boot_to_epoch_25_reward_cycle();

    info!("------------------------- Test Processing Epoch 2.5 Tenures -------------------------");

    // Mine until epoch 3.0 and ensure that no more mock signatures are received
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_slot_ids = signer_test.get_signer_indices(reward_cycle).into_iter();
    let signer_public_keys = signer_test.get_signer_public_keys(reward_cycle);
    assert_eq!(signer_slot_ids.count(), num_signers);

    let miners_stackerdb_contract = boot_code_id(MINERS_NAME, false);

    // Mine until epoch 3.0 and ensure we get a new mock block per epoch 2.5 sortition
    let main_poll_time = Instant::now();
    // Only advance to the boundary as the epoch 2.5 miner will be shut down at this point.
    while signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height()
        < epoch_3_boundary
    {
        let mut mock_block_mesage = None;
        let mock_poll_time = Instant::now();
        signer_test
            .running_nodes
            .btc_regtest_controller
            .build_next_block(1);
        let current_burn_block_height = signer_test
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        debug!("Waiting for mock miner message for burn block height {current_burn_block_height}");
        while mock_block_mesage.is_none() {
            std::thread::sleep(Duration::from_millis(100));
            let chunks = signer_test
                .running_nodes
                .test_observer
                .get_stackerdb_chunks();
            for chunk in chunks
                .into_iter()
                .filter_map(|chunk| {
                    if chunk.contract_id != miners_stackerdb_contract {
                        return None;
                    }
                    Some(chunk.modified_slots)
                })
                .flatten()
            {
                if chunk.data.is_empty() {
                    continue;
                }
                let SignerMessage::MockBlock(mock_block) =
                    SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                        .expect("Failed to deserialize SignerMessage")
                else {
                    continue;
                };
                if mock_block.mock_proposal.peer_info.burn_block_height == current_burn_block_height
                {
                    mock_block
                        .mock_signatures
                        .iter()
                        .for_each(|mock_signature| {
                            assert!(signer_public_keys.iter().any(|signer| {
                                mock_signature
                                    .verify(
                                        &StacksPublicKey::from_slice(signer.to_bytes().as_slice())
                                            .unwrap(),
                                    )
                                    .expect("Failed to verify mock signature")
                            }));
                        });
                    mock_block_mesage = Some(mock_block);
                    break;
                }
            }
            assert!(
                mock_poll_time.elapsed() <= Duration::from_secs(15),
                "Failed to find mock miner message within timeout"
            );
        }
        assert!(
            main_poll_time.elapsed() <= Duration::from_secs(145),
            "Timed out waiting to advance epoch 3.0 boundary"
        );
    }
}

#[test]
#[ignore]
fn multiple_miners_mock_sign_epoch_25() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |_| {},
        |config| {
            config.miner.pre_nakamoto_mock_signing = true;
            let epochs = config.burnchain.epochs.as_mut().unwrap();
            epochs[StacksEpochId::Epoch25].end_height = 251;
            epochs[StacksEpochId::Epoch30].start_height = 251;
            epochs[StacksEpochId::Epoch30].end_height = 265;
            epochs[StacksEpochId::Epoch31].start_height = 265;
            epochs[StacksEpochId::Epoch31].end_height = 285;
            epochs[StacksEpochId::Epoch32].start_height = 285;
            epochs[StacksEpochId::Epoch32].end_height = 305;
            epochs[StacksEpochId::Epoch33].start_height = 305;
        },
        |_| {},
    );
    let epochs = miners
        .signer_test
        .running_nodes
        .conf
        .burnchain
        .epochs
        .clone()
        .unwrap();
    let epoch_3 = &epochs[StacksEpochId::Epoch30];
    let epoch_3_boundary = epoch_3.start_height - 1; // We only advance to the boundary as epoch 2.5 miner gets torn down at the boundary

    miners.signer_test.boot_to_epoch_25_reward_cycle();
    miners.wait_for_chains(600);

    info!("------------------------- Reached Epoch 2.5 Reward Cycle-------------------------");

    // Mine until epoch 3.0 and ensure that no more mock signatures are received
    let reward_cycle = miners.signer_test.get_current_reward_cycle();
    let signer_slot_ids = miners
        .signer_test
        .get_signer_indices(reward_cycle)
        .into_iter();
    let signer_public_keys = miners.signer_test.get_signer_public_keys(reward_cycle);
    assert_eq!(signer_slot_ids.count(), num_signers);

    let miners_stackerdb_contract = boot_code_id(MINERS_NAME, false);

    // Only advance to the boundary as the epoch 2.5 miner will be shut down at this point.
    while miners.btc_regtest_controller_mut().get_headers_height() < epoch_3_boundary {
        let mut mock_block_mesage = None;
        let mock_poll_time = Instant::now();
        miners.btc_regtest_controller_mut().build_next_block(1);
        let current_burn_block_height = miners.btc_regtest_controller_mut().get_headers_height();
        debug!("Waiting for mock miner message for burn block height {current_burn_block_height}");
        while mock_block_mesage.is_none() {
            std::thread::sleep(Duration::from_millis(100));
            let chunks = miners
                .signer_test
                .running_nodes
                .test_observer
                .get_stackerdb_chunks();
            for chunk in chunks
                .into_iter()
                .filter_map(|chunk| {
                    if chunk.contract_id != miners_stackerdb_contract {
                        return None;
                    }
                    Some(chunk.modified_slots)
                })
                .flatten()
            {
                if chunk.data.is_empty() {
                    continue;
                }
                let SignerMessage::MockBlock(mock_block) =
                    SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                        .expect("Failed to deserialize SignerMessage")
                else {
                    continue;
                };
                if mock_block.mock_proposal.peer_info.burn_block_height == current_burn_block_height
                {
                    mock_block
                        .mock_signatures
                        .iter()
                        .for_each(|mock_signature| {
                            assert!(signer_public_keys.iter().any(|signer| {
                                mock_signature
                                    .verify(
                                        &StacksPublicKey::from_slice(signer.to_bytes().as_slice())
                                            .unwrap(),
                                    )
                                    .expect("Failed to verify mock signature")
                            }));
                        });
                    mock_block_mesage = Some(mock_block);
                    break;
                }
            }
            assert!(
                mock_poll_time.elapsed() <= Duration::from_secs(15),
                "Failed to find mock miner message within timeout"
            );
        }
    }
}

#[test]
#[ignore]
/// This test asserts that signer set rollover works as expected.
/// Specifically, if a new set of signers are registered for an upcoming reward cycle,
/// old signers shut down operation and the new signers take over with the commencement of
/// the next reward cycle.
fn signer_set_rollover() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let new_num_signers = 4;

    let new_signer_private_keys: Vec<_> = (0..new_num_signers)
        .map(|_| StacksPrivateKey::random())
        .collect();
    let new_signer_public_keys: Vec<_> = new_signer_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();
    let new_signer_addresses: Vec<_> = new_signer_private_keys.iter().map(tests::to_addr).collect();
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let mut initial_balances = new_signer_addresses
        .iter()
        .map(|addr| (addr.clone(), POX_4_DEFAULT_STACKER_BALANCE))
        .collect::<Vec<_>>();

    initial_balances.push((sender_addr, (send_amt + send_fee) * 4));

    let run_stamp = rand::random();

    let rpc_port = 51024;
    let rpc_bind = format!("127.0.0.1:{rpc_port}");

    // Setup the new signers that will take over
    let new_signer_configs = build_signer_config_tomls(
        &new_signer_private_keys,
        &rpc_bind,
        Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
        &Network::Testnet,
        "12345",
        run_stamp,
        3000 + num_signers,
        Some(100_000),
        None,
        Some(9000 + num_signers),
        None,
    );

    let new_signer_configs: Vec<_> = new_signer_configs
        .iter()
        .map(|conf_str| SignerConfig::load_from_str(conf_str).unwrap())
        .collect();

    let new_spawned_signers: Vec<_> = new_signer_configs
        .iter()
        .map(|signer_config| {
            info!("spawning signer");
            SpawnedSigner::new(signer_config.clone())
        })
        .collect();

    // Boot with some initial signer set
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |naka_conf, _| {
            for signer_config in new_signer_configs.clone() {
                info!(
                    "---- Adding signer endpoint to naka conf ({}) ----",
                    signer_config.endpoint
                );

                naka_conf.events_observers.insert(EventObserverConfig {
                    endpoint: format!("{}", signer_config.endpoint),
                    events_keys: vec![
                        EventKeyType::StackerDBChunks,
                        EventKeyType::BlockProposal,
                        EventKeyType::BurnchainBlocks,
                    ],
                    timeout_ms: 1000,
                    disable_retries: false,
                });
            }
            naka_conf.node.rpc_bind = rpc_bind.clone();
        },
        None,
        None,
    );
    assert_eq!(
        new_spawned_signers[0].config.node_host,
        signer_test.running_nodes.conf.node.rpc_bind
    );
    // Only stack for one cycle so that the signer set changes
    signer_test.num_stacking_cycles = 1_u64;

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = Duration::from_secs(20);

    // Verify that naka_conf has our new signer's event observers
    for signer_config in &new_signer_configs {
        let endpoint = signer_config.endpoint.to_string();
        assert!(signer_test
            .running_nodes
            .conf
            .events_observers
            .iter()
            .any(|observer| observer.endpoint == endpoint));
    }

    // Advance to the first reward cycle, stacking to the old signers beforehand

    info!("---- Booting to epoch 3 -----");
    signer_test.boot_to_epoch_3();

    // verify that the first reward cycle has the old signers in the reward set
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_test_public_keys: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();

    info!("---- Verifying that the current signers are the old signers ----");
    let current_signers = signer_test.get_reward_set_signers(reward_cycle);
    assert_eq!(current_signers.len(), num_signers);
    // Verify that the current signers are the same as the old signers
    for signer in current_signers.iter() {
        assert!(signer_test_public_keys.contains(&signer.signing_key.to_vec()));
        assert!(!new_signer_public_keys.contains(&signer.signing_key.to_vec()));
    }

    info!("---- Mining a block to trigger the signer set -----");
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    signer_test.mine_nakamoto_block(short_timeout, true);
    signer_test.check_signer_states_normal();
    let mined_block = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .pop()
        .unwrap();
    let block_sighash = mined_block.signer_signature_hash;
    let signer_signatures = mined_block.signer_signature;

    // verify the mined_block signatures against the OLD signer set
    for signature in signer_signatures.iter() {
        let pk = Secp256k1PublicKey::recover_to_pubkey(block_sighash.bits(), signature)
            .expect("FATAL: Failed to recover pubkey from block sighash");
        assert!(signer_test_public_keys.contains(&pk.to_bytes_compressed()));
        assert!(!new_signer_public_keys.contains(&pk.to_bytes_compressed()));
    }

    // advance to the next reward cycle, stacking to the new signers beforehand
    let reward_cycle = signer_test.get_current_reward_cycle();

    info!("---- Stacking new signers -----");

    let burn_block_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    let accounts_to_check: Vec<_> = new_signer_private_keys.iter().map(tests::to_addr).collect();
    for stacker_sk in new_signer_private_keys.iter() {
        let pox_addr = PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            tests::to_addr(stacker_sk).bytes().clone(),
        );
        let pox_addr_tuple: clarity::vm::Value =
            pox_addr.clone().as_clarity_tuple().unwrap().into();
        let signature = make_pox_4_signer_key_signature(
            &pox_addr,
            stacker_sk,
            reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            1_u128,
            u128::MAX,
            1,
        )
        .unwrap()
        .to_rsv();

        let signer_pk = Secp256k1PublicKey::from_private(stacker_sk);
        let stacking_tx = make_contract_call(
            stacker_sk,
            0,
            1000,
            signer_test.running_nodes.conf.burnchain.chain_id,
            &StacksAddress::burn_address(false),
            "pox-4",
            "stack-stx",
            &[
                clarity::vm::Value::UInt(POX_4_DEFAULT_STACKER_STX_AMT),
                pox_addr_tuple.clone(),
                clarity::vm::Value::UInt(burn_block_height as u128),
                clarity::vm::Value::UInt(1),
                clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                    .unwrap(),
                clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
                clarity::vm::Value::UInt(u128::MAX),
                clarity::vm::Value::UInt(1),
            ],
        );
        submit_tx(&http_origin, &stacking_tx);
    }

    wait_for(60, || {
        Ok(accounts_to_check
            .iter()
            .all(|acct| get_account(&http_origin, acct).nonce >= 1))
    })
    .expect("Timed out waiting for stacking txs to be mined");

    signer_test.mine_nakamoto_block(short_timeout, true);
    signer_test.check_signer_states_normal();

    let next_reward_cycle = reward_cycle.saturating_add(1);

    let next_cycle_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .nakamoto_first_block_of_cycle(next_reward_cycle)
        .saturating_add(1);

    info!("---- Mining to next reward set calculation -----");
    signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height.saturating_sub(3),
        new_num_signers,
    );

    // Verify that the new reward set is the new signers
    let reward_set = signer_test.get_reward_set_signers(next_reward_cycle);
    for signer in reward_set.iter() {
        assert!(!signer_test_public_keys.contains(&signer.signing_key.to_vec()));
        assert!(new_signer_public_keys.contains(&signer.signing_key.to_vec()));
    }

    info!("---- Mining to just before the next reward cycle (block {next_cycle_height}) -----",);
    signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height.saturating_sub(1),
        new_num_signers,
    );

    let (old_spawned_signers, _, _) = signer_test.replace_signers(
        new_spawned_signers,
        new_signer_private_keys,
        new_signer_configs,
    );

    info!("---- Mining into the next reward cycle (block {next_cycle_height}) -----",);
    signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height,
        new_num_signers,
    );
    let new_reward_cycle = signer_test.get_current_reward_cycle();
    assert_eq!(new_reward_cycle, reward_cycle.saturating_add(1));

    info!("---- Verifying that the current signers are the new signers ----");
    let current_signers = signer_test.get_reward_set_signers(new_reward_cycle);
    assert_eq!(current_signers.len(), new_num_signers);
    for signer in current_signers.iter() {
        assert!(!signer_test_public_keys.contains(&signer.signing_key.to_vec()));
        assert!(new_signer_public_keys.contains(&signer.signing_key.to_vec()));
    }

    info!("---- Mining a block to verify new signer set -----");
    let sender_nonce = 1;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    signer_test.mine_nakamoto_block(short_timeout, true);
    signer_test.check_signer_states_normal();
    let mined_block = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .pop()
        .unwrap();

    info!("---- Verifying that the new signers signed the block -----");
    let signer_signatures = mined_block.signer_signature;

    // verify the mined_block signatures against the NEW signer set
    for signature in signer_signatures.iter() {
        let pk = Secp256k1PublicKey::recover_to_pubkey(block_sighash.bits(), signature)
            .expect("FATAL: Failed to recover pubkey from block sighash");
        assert!(!signer_test_public_keys.contains(&pk.to_bytes_compressed()));
        assert!(new_signer_public_keys.contains(&pk.to_bytes_compressed()));
    }

    signer_test.shutdown();
    for signer in old_spawned_signers {
        assert!(signer.stop().is_none());
    }
}

#[test]
#[ignore]
/// This test checks that the miners and signers will not produce Nakamoto blocks
/// until the minimum time has passed between blocks.
fn min_gap_between_blocks() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let interim_blocks = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let time_between_blocks_ms = 10_000;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * interim_blocks)],
        |_config| {},
        |config, _| {
            config.miner.min_time_between_blocks_ms = time_between_blocks_ms;
        },
        None,
        None,
    );
    let test_observer = &signer_test.running_nodes.test_observer;

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();

    signer_test.boot_to_epoch_3();

    info!("Ensure that the first Nakamoto block was mined");
    let blocks = get_nakamoto_headers(&signer_test.running_nodes.conf, test_observer);
    assert_eq!(blocks.len(), 1);
    // mine the interim blocks
    info!("Mining interim blocks");
    for interim_block_ix in 0..interim_blocks {
        let blocks_processed_before = mined_blocks.load(Ordering::SeqCst);
        // submit a tx so that the miner will mine an extra block
        let transfer_tx = make_stacks_transfer_serialized(
            &sender_sk,
            interim_block_ix, // same as the sender nonce
            send_fee,
            signer_test.running_nodes.conf.burnchain.chain_id,
            &recipient,
            send_amt,
        );
        submit_tx(&http_origin, &transfer_tx);

        info!("Submitted transfer tx and waiting for block to be processed");
        wait_for(60, || {
            Ok(mined_blocks.load(Ordering::SeqCst) > blocks_processed_before)
        })
        .unwrap();
        info!("Mined interim block:{interim_block_ix}");
    }

    wait_for(60, || {
        let new_blocks = get_nakamoto_headers(&signer_test.running_nodes.conf, test_observer);
        Ok(new_blocks.len() == blocks.len() + interim_blocks as usize)
    })
    .unwrap();

    // Verify that every Nakamoto block is mined after the gap is exceeded between each
    let mut blocks = get_nakamoto_headers(&signer_test.running_nodes.conf, test_observer);
    blocks.sort_by(|a, b| a.stacks_block_height.cmp(&b.stacks_block_height));
    for i in 1..blocks.len() {
        let block = &blocks[i];
        let parent_block = &blocks[i - 1];
        assert_eq!(
            block.stacks_block_height,
            parent_block.stacks_block_height + 1
        );
        info!(
            "Checking that the time between blocks {} and {} is respected",
            parent_block.stacks_block_height, block.stacks_block_height
        );
        let block_time = block
            .anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .timestamp;
        let parent_block_time = parent_block
            .anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .timestamp;
        assert!(
            block_time > parent_block_time,
            "Block time is BEFORE parent block time"
        );
        assert!(
            Duration::from_secs(block_time - parent_block_time)
                >= Duration::from_millis(time_between_blocks_ms),
            "Block mined before gap was exceeded: {block_time}s - {parent_block_time}s > {time_between_blocks_ms}ms",
        );
    }
    debug!("Shutting down min_gap_between_blocks test");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test scenario where there are duplicate signers with the same private key
/// First submitted signature should take precedence
fn duplicate_signers() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Disable p2p broadcast of the nakamoto blocks, so that we rely
    //  on the signer's using StackerDB to get pushed blocks
    nakamoto_node::miner::TEST_P2P_BROADCAST_SKIP.set(true);

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let mut signer_stacks_private_keys = (0..num_signers)
        .map(|_| StacksPrivateKey::random())
        .collect::<Vec<_>>();

    // First two signers have same private key
    signer_stacks_private_keys[1] = signer_stacks_private_keys[0].clone();
    let unique_signers = num_signers - 1;
    let duplicate_pubkey = Secp256k1PublicKey::from_private(&signer_stacks_private_keys[0]);
    let duplicate_pubkey_from_copy =
        Secp256k1PublicKey::from_private(&signer_stacks_private_keys[1]);
    assert_eq!(
        duplicate_pubkey, duplicate_pubkey_from_copy,
        "Recovered pubkeys don't match"
    );

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |_| {},
        |_, _| {},
        None,
        Some(signer_stacks_private_keys),
    );

    signer_test.boot_to_epoch_3();
    let timeout = Duration::from_secs(30);

    info!("------------------------- Try mining one block -------------------------");

    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);

    info!("------------------------- Read all `BlockResponse::Accepted` messages -------------------------");

    let mut signer_accepted_responses = vec![];
    let start_polling = Instant::now();
    while start_polling.elapsed() <= timeout {
        std::thread::sleep(Duration::from_secs(1));
        let messages = signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                SignerMessage::consensus_deserialize(&mut chunk.data.as_slice()).ok()
            })
            .filter_map(|message| match message {
                SignerMessage::BlockResponse(BlockResponse::Accepted(m)) => {
                    info!("Message(accepted): {m:?}");
                    Some(m)
                }
                _ => {
                    debug!("Message(ignored): {message:?}");
                    None
                }
            });
        signer_accepted_responses.extend(messages);
    }

    info!("------------------------- Assert there are {unique_signers} unique signatures and recovered pubkeys -------------------------");

    // Pick a message hash
    let accepted = signer_accepted_responses
        .iter()
        .min_by_key(|accepted| accepted.signer_signature_hash.clone())
        .expect("No `BlockResponse::Accepted` messages recieved");
    let selected_sighash = accepted.signer_signature_hash.clone();

    // Filter only resonses for selected block and collect unique pubkeys and signatures
    let (pubkeys, signatures): (HashSet<_>, HashSet<_>) = signer_accepted_responses
        .into_iter()
        .filter(|accepted| accepted.signer_signature_hash == selected_sighash)
        .map(|accepted| {
            let pubkey = Secp256k1PublicKey::recover_to_pubkey(
                accepted.signer_signature_hash.bits(),
                &accepted.signature,
            )
            .expect("Failed to recover pubkey");
            (pubkey, accepted.signature)
        })
        .unzip();

    assert_eq!(pubkeys.len(), unique_signers);
    assert_eq!(signatures.len(), unique_signers);

    signer_test.shutdown();
}

#[test]
#[ignore]
fn signer_multinode_rollover() {
    let num_signers = 5;
    let new_num_signers = 4;

    let new_signer_sks: Vec<_> = (0..new_num_signers)
        .map(|ix| StacksPrivateKey::from_seed(format!("new_signer_{ix}").as_bytes()))
        .collect();
    let new_signer_pks: Vec<_> = new_signer_sks
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();
    let new_signer_addrs: Vec<_> = new_signer_sks.iter().map(tests::to_addr).collect();
    let additional_initial_balances: Vec<_> = new_signer_addrs
        .iter()
        .map(|addr| (addr.clone(), POX_4_DEFAULT_STACKER_BALANCE))
        .collect();
    let new_signers_port_start = 3000 + num_signers;

    let node_1_rpc = 40553;
    let node_1_p2p = 40554;
    let node_2_rpc = 50553;
    let node_2_p2p = 50554;
    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");

    let new_signer_configs = build_signer_config_tomls(
        &new_signer_sks,
        &node_1_rpc_bind,
        Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
        &Network::Testnet,
        "12345",
        rand::random(),
        3000 + num_signers,
        Some(100_000),
        None,
        Some(9000 + num_signers),
        None,
    );

    let new_signer_configs: Vec<_> = new_signer_configs
        .iter()
        .map(|conf_str| SignerConfig::load_from_str(conf_str).unwrap())
        .collect();

    let new_spawned_signers: Vec<_> = new_signer_configs
        .iter()
        .map(|signer_config| {
            info!("spawning signer");
            SpawnedSigner::new(signer_config.clone())
        })
        .collect();

    let mut miners = MultipleMinerTest::new_with_signer_dist(
        num_signers,
        60 * 5,
        |_| {},
        |node_config| {
            for (addr, balance) in additional_initial_balances.iter() {
                node_config.add_initial_balance(addr.to_string(), *balance);
            }
            for (ix, _) in new_signer_sks.iter().enumerate() {
                info!(
                    "---- Adding signer endpoint to naka conf ({}) ----",
                    new_signers_port_start + ix,
                );

                node_config.events_observers.insert(EventObserverConfig {
                    endpoint: format!("localhost:{}", new_signers_port_start + ix),
                    events_keys: vec![
                        EventKeyType::StackerDBChunks,
                        EventKeyType::BlockProposal,
                        EventKeyType::BurnchainBlocks,
                    ],
                    timeout_ms: 1000,
                    disable_retries: false,
                });
            }
        },
        |node_2_conf| {
            node_2_conf.connection_options.reject_blocks_pushed = true;
        },
        |_| 0,
        Some(vec![node_1_rpc, node_1_p2p, node_2_rpc, node_2_p2p]),
    );

    miners.signer_test.num_stacking_cycles = 1;
    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    // verify that the first reward cycle has the old signers in the reward set
    let reward_cycle = miners.signer_test.get_current_reward_cycle();
    let signer_test_pks: Vec<_> = miners
        .signer_test
        .signer_stacks_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();

    info!("---- Verifying that the current signers are the old signers ----");
    let current_signers = miners.signer_test.get_reward_set_signers(reward_cycle);
    assert_eq!(current_signers.len(), num_signers);
    // Verify that the current signers are the same as the old signers
    for signer in current_signers.iter() {
        assert!(signer_test_pks.contains(&signer.signing_key.to_vec()));
        assert!(!new_signer_pks.contains(&signer.signing_key.to_vec()));
    }

    let burnchain = miners.get_node_configs().0.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 120)
        .unwrap();

    let mined_block = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .pop()
        .unwrap();
    let block_sighash = mined_block.signer_signature_hash;
    let signer_signatures = mined_block.signer_signature;

    // verify the mined_block signatures against the OLD signer set
    for signature in signer_signatures.iter() {
        let pk = Secp256k1PublicKey::recover_to_pubkey(block_sighash.bits(), signature)
            .expect("FATAL: Failed to recover pubkey from block sighash");
        assert!(signer_test_pks.contains(&pk.to_bytes_compressed()));
        assert!(!new_signer_pks.contains(&pk.to_bytes_compressed()));
    }

    // advance to the next reward cycle, stacking to the new signers beforehand
    let reward_cycle = miners.signer_test.get_current_reward_cycle();

    info!("---- Stacking new signers -----");

    let burn_block_height = miners
        .signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    let accounts_to_check = new_signer_addrs;
    for stacker_sk in new_signer_sks.iter() {
        let pox_addr = PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            tests::to_addr(stacker_sk).bytes().clone(),
        );
        let pox_addr_tuple: clarity::vm::Value =
            pox_addr.clone().as_clarity_tuple().unwrap().into();
        let signature = make_pox_4_signer_key_signature(
            &pox_addr,
            stacker_sk,
            reward_cycle.into(),
            &Pox4SignatureTopic::StackStx,
            CHAIN_ID_TESTNET,
            1_u128,
            u128::MAX,
            1,
        )
        .unwrap()
        .to_rsv();

        let chain_id = miners.get_node_configs().0.burnchain.chain_id;
        let signer_pk = Secp256k1PublicKey::from_private(stacker_sk);
        let stacking_tx = make_contract_call(
            stacker_sk,
            0,
            1000,
            chain_id,
            &StacksAddress::burn_address(false),
            "pox-4",
            "stack-stx",
            &[
                clarity::vm::Value::UInt(POX_4_DEFAULT_STACKER_STX_AMT),
                pox_addr_tuple.clone(),
                clarity::vm::Value::UInt(burn_block_height as u128),
                clarity::vm::Value::UInt(1),
                clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap())
                    .unwrap(),
                clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
                clarity::vm::Value::UInt(u128::MAX),
                clarity::vm::Value::UInt(1),
            ],
        );
        submit_tx(&miners.node_http(), &stacking_tx);
    }

    wait_for(60, || {
        Ok(accounts_to_check
            .iter()
            .all(|acct| get_account(&miners.node_http(), acct).nonce >= 1))
    })
    .expect("Timed out waiting for stacking txs to be mined");

    let next_reward_cycle = reward_cycle.saturating_add(1);

    let next_cycle_height = miners
        .btc_regtest_controller_mut()
        .get_burnchain()
        .nakamoto_first_block_of_cycle(next_reward_cycle)
        .saturating_add(1);

    miners.signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height.saturating_sub(3),
        new_num_signers,
    );

    miners.wait_for_chains(120);

    // Verify that the new reward set is the new signers
    let reward_set = miners.signer_test.get_reward_set_signers(next_reward_cycle);
    for signer in reward_set.iter() {
        assert!(!signer_test_pks.contains(&signer.signing_key.to_vec()));
        assert!(new_signer_pks.contains(&signer.signing_key.to_vec()));
    }

    info!("---- Mining to just before the next reward cycle (block {next_cycle_height}) -----",);
    miners.signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height.saturating_sub(1),
        new_num_signers,
    );

    let (old_spawned_signers, _, _) =
        miners
            .signer_test
            .replace_signers(new_spawned_signers, new_signer_sks, new_signer_configs);

    miners.wait_for_chains(120);

    info!("---- Mining into the next reward cycle (block {next_cycle_height}) -----",);
    miners.signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height,
        new_num_signers,
    );
    let new_reward_cycle = miners.signer_test.get_current_reward_cycle();
    assert_eq!(new_reward_cycle, reward_cycle.saturating_add(1));

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 120)
        .unwrap();

    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.wait_for_chains(120);

    let mined_block = miners
        .signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .pop()
        .unwrap();

    info!("---- Verifying that the new signers signed the block -----");
    let signer_signatures = mined_block.signer_signature;

    // verify the mined_block signatures against the NEW signer set
    for signature in signer_signatures.iter() {
        let pk = Secp256k1PublicKey::recover_to_pubkey(block_sighash.bits(), signature)
            .expect("FATAL: Failed to recover pubkey from block sighash");
        assert!(!signer_test_pks.contains(&pk.to_bytes_compressed()));
        assert!(new_signer_pks.contains(&pk.to_bytes_compressed()));
    }

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 120)
        .unwrap();
    miners.wait_for_chains(120);
    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.wait_for_chains(120);
    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.wait_for_chains(120);
    miners.send_and_mine_transfer_tx(60).unwrap();
    miners.wait_for_chains(120);

    miners.shutdown();
    for signer in old_spawned_signers {
        assert!(signer.stop().is_none());
    }
}

/// This test involves two miners, each mining tenures with 6 blocks each. Half
/// of the signers are attached to each miner, so the test also verifies that
/// the signers' messages successfully make their way to the active miner.
#[test]
#[ignore]
fn multiple_miners_with_nakamoto_blocks() {
    let num_signers = 5;
    let max_nakamoto_tenures = 20;
    let inter_blocks_per_tenure = 5;

    let mut miners =
        MultipleMinerTest::new(num_signers, inter_blocks_per_tenure * max_nakamoto_tenures);

    let (miner_1_pk, miner_2_pk) = miners.get_miner_public_keys();
    let (conf_1, conf_2) = miners.get_node_configs();
    let rl1_counters = miners.signer_test.running_nodes.counters.clone();
    let rl2_counters = miners.rl2_counters.clone();
    let blocks_mined1 = rl1_counters.naka_mined_blocks.clone();
    let blocks_mined2 = rl2_counters.naka_mined_blocks.clone();

    miners.boot_to_epoch_3();

    let pre_nakamoto_peer_1_height = get_chain_info(&conf_1).stacks_tip_height;

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end

    let mut btc_blocks_mined = 1_u64;
    let mut miner_1_tenures = 0_u64;
    let mut miner_2_tenures = 0_u64;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        if btc_blocks_mined > max_nakamoto_tenures {
            panic!("Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting");
        }
        let blocks_processed_before =
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
        miners.signer_test.mine_block_wait_on_processing(
            &[&conf_1, &conf_2],
            &[&rl1_counters, &rl2_counters],
            Duration::from_secs(30),
        );
        miners.signer_test.check_signer_states_normal();
        btc_blocks_mined += 1;

        // wait for the new block to be processed
        wait_for(60, || {
            let blocks_processed =
                blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
            Ok(blocks_processed > blocks_processed_before)
        })
        .unwrap();

        info!(
            "Nakamoto blocks mined: {}",
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst)
        );

        // mine the interim blocks
        info!("Mining interim blocks");
        for interim_block_ix in 0..inter_blocks_per_tenure {
            miners
                .send_and_mine_transfer_tx(60)
                .expect("Failed to mine interim block");
            info!("Mined interim block {btc_blocks_mined}:{interim_block_ix}");
        }

        let blocks = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer);
        let mut seen_burn_hashes = HashSet::new();
        miner_1_tenures = 0;
        miner_2_tenures = 0;
        for header in blocks.iter() {
            if seen_burn_hashes.contains(&header.burn_header_hash) {
                continue;
            }
            seen_burn_hashes.insert(header.burn_header_hash.clone());

            let header = header.anchored_header.as_stacks_nakamoto().unwrap();
            if miner_1_pk
                .verify(
                    header.miner_signature_hash().as_bytes(),
                    &header.miner_signature,
                )
                .unwrap()
            {
                miner_1_tenures += 1;
            }
            if miner_2_pk
                .verify(
                    header.miner_signature_hash().as_bytes(),
                    &header.miner_signature,
                )
                .unwrap()
            {
                miner_2_tenures += 1;
            }
        }
        info!("Miner 1 tenures: {miner_1_tenures}, Miner 2 tenures: {miner_2_tenures}");
    }
    let chain_info_1 = get_chain_info(&conf_1);
    let chain_info_2 = get_chain_info(&conf_2);
    info!("New chain info 1: {chain_info_1:?}");
    info!("New chain info 2: {chain_info_2:?}");

    let peer_1_height = chain_info_1.stacks_tip_height;
    let peer_2_height = chain_info_2.stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);
    assert_eq!(
        peer_1_height,
        pre_nakamoto_peer_1_height + (btc_blocks_mined - 1) * (inter_blocks_per_tenure as u64 + 1)
    );
    assert_eq!(btc_blocks_mined, miner_1_tenures + miner_2_tenures);
    miners.shutdown();
}

#[test]
#[ignore]
/// Test that when 70% of signers accept a block, mark it globally accepted, but a miner ends its tenure
/// before it receives these signatures, the miner can recover in the following tenure.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed and >70% accept it.
/// The signers delay broadcasting the block and the miner ends its tenure before it receives these signatures. The
/// miner will propose an invalid block N+1' which all signers reject. The broadcast delay is removed and the miner
/// proposes a new block N+2 which all signers accept.
///
/// Test Assertion:
/// Stacks tip advances to N+2
fn miner_recovers_when_broadcast_block_delay_across_tenures_occurs() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |_config| {},
        |config, _| {
            // Accept all block proposals
            config.connection_options.block_proposal_max_age_secs = u64::MAX;
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Starting Tenure A -------------------------");
    info!("------------------------- Test Mine Nakamoto Block N -------------------------");

    // wait until we get a sortition.
    // we might miss a block-commit at the start of epoch 3
    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    wait_for(30, || {
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        Ok(tip.sortition)
    })
    .expect("Timed out waiting for sortition");

    let info_before = signer_test.get_peer_info();
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N");
    sender_nonce += 1;
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    assert_eq!(info_after.stacks_tip, block_n.header.block_hash());

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Propose a valid block, but force the miner to ignore the returned signatures and delay the block being
    // broadcasted to the miner so it can end its tenure before block confirmation obtained
    // Clear the stackerdb chunks
    info!("Forcing miner to ignore block responses for block N+1");
    TEST_IGNORE_SIGNERS.set(true);

    info!("------------------------- Wait for All Signers to Update their Canonical Tip to Block N -------------------------");
    let current_rc = signer_test.get_current_reward_cycle();
    let expected_tip = block_n.header.signer_signature_hash();
    wait_for(30, || {
        let states = signer_test.get_all_states();
        let canonical_tips = states
            .iter()
            .filter(|state| {
                state
                    .signer_canonical_tips
                    .iter()
                    .find_map(|(rc, block_info_opt)| {
                        if current_rc % 2 == *rc {
                            block_info_opt.as_ref()
                        } else {
                            None
                        }
                    })
                    .map(|block_info| {
                        block_info.block.header.signer_signature_hash() == expected_tip
                    })
                    .unwrap_or(false)
            })
            .count();

        Ok(canonical_tips == num_signers)
    })
    .expect("Timed out waiting for all signers to update their global state to Block N");

    info!("Delaying signer block N+1 broadcasting to the miner");
    TEST_PAUSE_BLOCK_BROADCAST.set(true);
    signer_test.running_nodes.test_observer.clear();
    let info_before = signer_test.get_peer_info();

    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    sender_nonce += 1;

    let tx = submit_tx(&http_origin, &transfer_tx);

    info!("Submitted tx {tx} in to attempt to mine block N+1");
    let block_n_1 = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be proposed");
    let all_signers = signer_test.signer_test_pks();
    wait_for_block_global_acceptance_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &all_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1 to be accepted by signers");

    // Ensure that the block was not yet broadcasted to the miner so the stacks tip has NOT advanced to N+1
    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after, info_before);

    info!("------------------------- Starting Tenure B -------------------------");
    signer_test.running_nodes.test_observer.clear();
    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let info = signer_test.get_peer_info();
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before
                && info.burn_block_height > info_before.burn_block_height)
        },
    )
    .unwrap();

    let info_after = signer_test.get_peer_info();
    info!(
        "------------------------- Attempt to Mine Nakamoto Block N+1' -------------------------"
    );
    // Wait for the miner to propose a new invalid block N+1'
    let block_n_1_prime = wait_for_block_proposal(
        30,
        info_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1' to be proposed");
    assert_ne!(
        block_n_1_prime.header.signer_signature_hash(),
        block_n_1.header.signer_signature_hash()
    );
    info!("Allowing miner to accept block responses again. ");
    TEST_IGNORE_SIGNERS.set(false);
    info!("Allowing signers to broadcast block N+1 to the miner");
    TEST_PAUSE_BLOCK_BROADCAST.set(false);

    wait_for(30, || {
        let info = signer_test.get_peer_info();
        Ok(info.stacks_tip_height > info_after.stacks_tip_height)
    })
    .expect("Timed out waiting for the node to advance its Stacks tip");

    // Assert the N+1' block was rejected
    wait_for_block_global_rejection(
        30,
        &block_n_1_prime.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+1' to be rejected");

    // Wait first for state machine to update before submitting the tx to mine so the prior miner doesn't manage to get a last block in
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &info_after.pox_consensus,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signer state to update");

    // Induce block N+2 to get mined
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );

    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in attempt to mine block N+2");

    info!(
        "------------------------- Wait for block N+2 at height {} -------------------------",
        info_before.stacks_tip_height + 2
    );
    let block_n_2 = wait_for_block_pushed_by_miner_key(
        30,
        info_before.stacks_tip_height + 2,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block N+2 to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(
        block_n_2.header.parent_block_id,
        block_n_1.header.block_id()
    );
    assert_eq!(info_after.stacks_tip, block_n_2.header.block_hash());
    assert_eq!(
        info_before.stacks_tip_height + 2,
        info_after.stacks_tip_height
    );
}

#[test]
#[ignore]
/// Test that signers can successfully sign a block proposal in the 0th tenure of a reward cycle
/// This ensures there is no race condition in the /v2/pox endpoint which could prevent it from updating
/// on time, possibly triggering an "off by one" like behaviour in the 0th tenure.
///
fn signing_in_0th_tenure_of_reward_cycle() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let signer_public_keys = signer_test.signer_test_pks();
    let long_timeout = Duration::from_secs(200);
    signer_test.boot_to_epoch_3();
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    let next_reward_cycle = curr_reward_cycle + 1;
    // Mine until the boundary of the first full Nakamoto reward cycles (epoch 3 starts in the middle of one)
    let next_reward_cycle_height_boundary = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(next_reward_cycle)
        .saturating_sub(1);

    info!("------------------------- Advancing to {next_reward_cycle} Boundary at Block {next_reward_cycle_height_boundary} -------------------------");
    signer_test.run_until_burnchain_height_nakamoto(
        long_timeout,
        next_reward_cycle_height_boundary,
        num_signers,
    );

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let get_v3_signer = |pubkey: &Secp256k1PublicKey, reward_cycle: u64| {
        let url = &format!(
            "{http_origin}/v3/signer/{pk}/{reward_cycle}",
            pk = pubkey.to_hex()
        );
        info!("Send request: GET {url}");
        reqwest::blocking::get(url)
            .unwrap_or_else(|e| panic!("GET request failed: {e}"))
            .json::<GetSignerResponse>()
            .unwrap()
            .blocks_signed
    };

    assert_eq!(signer_test.get_current_reward_cycle(), curr_reward_cycle);

    for signer in &signer_public_keys {
        let blocks_signed = get_v3_signer(signer, next_reward_cycle);
        assert_eq!(blocks_signed, 0);
    }

    info!("------------------------- Enter Reward Cycle {next_reward_cycle} -------------------------");
    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    for signer in &signer_public_keys {
        let blocks_signed = get_v3_signer(signer, next_reward_cycle);
        assert_eq!(blocks_signed, 0);
    }
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .unwrap();

    let block_mined = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .last()
        .unwrap()
        .clone();
    // Must ensure that the signers that signed the block have their blocks_signed updated appropriately
    for signature in &block_mined.signer_signature {
        let signer = signer_public_keys
            .iter()
            .find(|pk| {
                pk.verify(block_mined.signer_signature_hash.as_bytes(), signature)
                    .unwrap()
            })
            .expect("Unknown signer signature");
        let blocks_signed = get_v3_signer(signer, next_reward_cycle);
        assert_eq!(blocks_signed, 1);
    }
    assert_eq!(signer_test.get_current_reward_cycle(), next_reward_cycle);
}

/// This test involves two miners with a custom chain id, each mining tenures with 6 blocks each.
/// Half of the signers are attached to each miner, so the test also verifies that
/// the signers' messages successfully make their way to the active miner.
#[test]
#[ignore]
fn multiple_miners_with_custom_chain_id() {
    let num_signers = 5;
    let max_nakamoto_tenures = 20;
    let inter_blocks_per_tenure = 5;
    let num_txs = max_nakamoto_tenures * inter_blocks_per_tenure;

    let chain_id = 0x87654321;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |signer_config| signer_config.chain_id = Some(chain_id),
        |config| {
            config.burnchain.chain_id = chain_id;
        },
        |_| {},
    );
    let (conf_1, conf_2) = miners.get_node_configs();

    miners.boot_to_epoch_3();

    let pre_nakamoto_peer_1_height = get_chain_info(&conf_1).stacks_tip_height;

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    let rl1_counters = miners.signer_test.running_nodes.counters.clone();
    let blocks_mined1 = miners
        .signer_test
        .running_nodes
        .counters
        .naka_mined_blocks
        .clone();

    let rl2_counters = miners.rl2_counters.clone();
    let blocks_mined2 = rl2_counters.naka_mined_blocks.clone();

    let (miner_1_pk, miner_2_pk) = miners.get_miner_public_keys();

    let mut btc_blocks_mined = 1;
    let mut miner_1_tenures = 0;
    let mut miner_2_tenures = 0;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        if btc_blocks_mined > max_nakamoto_tenures {
            panic!("Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting");
        }
        let blocks_processed_before =
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
        miners.signer_test.mine_block_wait_on_processing(
            &[&conf_1, &conf_2],
            &[&rl1_counters, &rl2_counters],
            Duration::from_secs(30),
        );
        btc_blocks_mined += 1;

        // wait for the new block to be processed
        wait_for(60, || {
            let blocks_processed =
                blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
            Ok(blocks_processed > blocks_processed_before)
        })
        .unwrap();

        info!(
            "Nakamoto blocks mined: {}",
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst)
        );

        // mine the interim blocks
        info!("Mining interim blocks");
        for interim_block_ix in 0..inter_blocks_per_tenure {
            miners
                .send_and_mine_transfer_tx(30)
                .expect("Timed out waiting to mine interim block");
            info!("Mined interim block {btc_blocks_mined}:{interim_block_ix}");
        }

        let blocks = get_nakamoto_headers(&conf_1, &miners.signer_test.running_nodes.test_observer);
        let mut seen_burn_hashes = HashSet::new();
        miner_1_tenures = 0;
        miner_2_tenures = 0;
        for header in blocks.iter() {
            if seen_burn_hashes.contains(&header.burn_header_hash) {
                continue;
            }
            seen_burn_hashes.insert(&header.burn_header_hash);

            let header = header.anchored_header.as_stacks_nakamoto().unwrap();
            if miner_1_pk
                .verify(
                    header.miner_signature_hash().as_bytes(),
                    &header.miner_signature,
                )
                .unwrap()
            {
                miner_1_tenures += 1;
            }
            if miner_2_pk
                .verify(
                    header.miner_signature_hash().as_bytes(),
                    &header.miner_signature,
                )
                .unwrap()
            {
                miner_2_tenures += 1;
            }
        }
        info!("Miner 1 tenures: {miner_1_tenures}, Miner 2 tenures: {miner_2_tenures}");
    }

    let chain_info_1 = get_chain_info(&conf_1);
    let chain_info_2 = get_chain_info(&conf_2);
    info!("New chain info 1: {chain_info_1:?}");
    info!("New chain info 2: {chain_info_2:?}");

    let peer_1_height = chain_info_1.stacks_tip_height;
    let peer_2_height = chain_info_2.stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);
    assert_eq!(
        peer_1_height,
        pre_nakamoto_peer_1_height + (btc_blocks_mined - 1) * (inter_blocks_per_tenure + 1)
    );
    assert_eq!(btc_blocks_mined, miner_1_tenures + miner_2_tenures);

    // Verify both nodes have the correct chain id;
    assert_eq!(chain_info_1.network_id, chain_id);
    assert_eq!(chain_info_2.network_id, chain_id);

    miners.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of the `block_commit_delay_ms` configuration option.
fn block_commit_delay() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = Duration::from_secs(600);
        },
        |config, _| {
            // Set the block commit delay to 10 minutes to ensure no block commit is sent
            config.miner.block_commit_delay = Duration::from_secs(600);
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let commits_submitted = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .clone();
    let commits_before = commits_submitted.load(Ordering::SeqCst);

    next_block_and_process_new_stacks_block(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine first block");

    // Ensure that the block commit has been sent before continuing
    wait_for(60, || {
        Ok(commits_submitted.load(Ordering::SeqCst) > commits_before)
    })
    .expect("Timed out waiting for block commit after new Stacks block");

    // Prevent a block from being mined by making signers reject it.
    let all_signers = signer_test.signer_test_pks();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(all_signers);

    info!("------------------------- Test Mine Burn Block  -------------------------");
    let commits_before = commits_submitted.load(Ordering::SeqCst);

    // Mine a burn block and wait for it to be processed.
    signer_test.mine_bitcoin_block();

    // Sleep an extra minute to ensure no block commits are sent
    sleep_ms(60_000);
    assert_eq!(commits_submitted.load(Ordering::SeqCst), commits_before);

    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    info!("------------------------- Resume Signing -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(Vec::new());

    // Wait for a block to be mined
    wait_for(60, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .expect("Timed out waiting for block to be mined");

    // Wait for a block commit to be sent
    wait_for(60, || {
        Ok(commits_submitted.load(Ordering::SeqCst) > commits_before)
    })
    .expect("Timed out waiting for block commit after new Stacks block");

    signer_test.shutdown();
}

// Ensures that a signer that successfully submits a block to the node for validation
// will issue ConnectivityIssues rejections if a block submission times out.
// Also ensures that no other proposal gets submitted for validation if we
// are already waiting for a block submission response.
#[test]
#[ignore]
fn block_validation_response_timeout() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let timeout = Duration::from_secs(30);
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_validation_timeout = timeout;
        },
        |_, _| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    let block_proposals = signer_test
        .running_nodes
        .counters
        .naka_proposed_blocks
        .clone();

    info!("------------------------- Test Mine and Verify Confirmed Nakamoto Block -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);
    info!("------------------------- Test Block Validation Stalled -------------------------");
    TEST_VALIDATE_STALL.set(true);
    let validation_stall_start = Instant::now();

    let proposals_before = block_proposals.load(Ordering::SeqCst);

    // submit a tx so that the miner will attempt to mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    wait_for(30, || {
        Ok(block_proposals.load(Ordering::SeqCst) > proposals_before)
    })
    .expect("Timed out waiting for block proposal");

    assert!(
        validation_stall_start.elapsed() < timeout,
        "Test was too slow to propose another block before the timeout"
    );

    info!("------------------------- Propose Another Block Before Hitting the Timeout -------------------------");
    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    block.header.timestamp = get_epoch_time_secs();

    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    // Propose a block to the signers that passes initial checks but will not be submitted to the stacks node due to the submission stall
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.data.consensus_hash;
    block.header.chain_length = info_before.stacks_tip_height + 1;

    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash_1 = block.header.signer_signature_hash();
    signer_test.propose_block(block, timeout);

    info!("------------------------- Waiting for Timeout -------------------------");
    // Sleep the necessary timeout to make sure the validation times out.
    let elapsed = validation_stall_start.elapsed();
    let wait = timeout.saturating_sub(elapsed);
    info!("Sleeping for {} ms", wait.as_millis());
    std::thread::sleep(timeout.saturating_sub(elapsed));

    info!("------------------------- Wait for Block Rejection Due to Timeout -------------------------");
    // Verify that the signer that submits the block to the node will issue a ConnectivityIssues rejection
    wait_for(30, || {
        let chunks = signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                reason: _reason,
                reason_code,
                signer_signature_hash,
                ..
            })) = message
            else {
                continue;
            };
            // We are waiting for the original block proposal which will have a diff signature to our
            // second proposed block.
            assert_ne!(
                signer_signature_hash, block_signer_signature_hash_1,
                "Received a rejection for the wrong block"
            );
            if matches!(reason_code, RejectCode::ConnectivityIssues(_)) {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .expect("Timed out waiting for block proposal rejections");
    // Make sure our chain has still not advanced
    let info_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(info_before, info_after);
    let info_before = info_after;
    info!("Unpausing block validation");
    // Disable the stall and wait for the block to be processed successfully
    TEST_VALIDATE_STALL.set(false);
    wait_for(30, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block to be processed");

    let info_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1,
    );
    info!("------------------------- Test Mine and Verify Confirmed Nakamoto Block -------------------------");
    let info_before = info_after;
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);

    wait_for(30, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > info_before.stacks_tip_height)
    })
    .unwrap();

    let info_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1,
    );
}

// Verify that the miner timeout while waiting for signers will change accordingly
// to rejections.
#[test]
#[ignore]
fn block_validation_check_rejection_timeout_heuristic() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 20;
    let timeout = Duration::from_secs(30);
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_validation_timeout = timeout;
        },
        |config, _| {
            config.miner.block_rejection_timeout_steps.clear();
            config
                .miner
                .block_rejection_timeout_steps
                .insert(0, Duration::from_secs(123));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(10, Duration::from_secs(20));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(15, Duration::from_secs(10));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(20, Duration::from_secs(99));
        },
        None,
        None,
    );
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();

    signer_test.boot_to_epoch_3();

    // note we just use mined nakamoto_blocks as the second block is not going to be confirmed

    let test_rejections = |signer_split_index: usize, expected_timeout: u64| {
        signer_test.running_nodes.test_observer.clear();
        let blocks_before = signer_test
            .running_nodes
            .test_observer
            .get_mined_nakamoto_blocks()
            .len();
        let (ignore_signers, reject_signers) = all_signers.split_at(signer_split_index);

        info!("------------------------- Check Rejections-based timeout with {} rejections -------------------------", reject_signers.len());

        TEST_REJECT_ALL_BLOCK_PROPOSAL.set(reject_signers.to_vec());
        TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignore_signers.to_vec());

        let height_before = signer_test.get_peer_info().stacks_tip_height;
        next_block_and(
            &signer_test.running_nodes.btc_regtest_controller,
            30,
            || {
                Ok(signer_test
                    .running_nodes
                    .test_observer
                    .get_mined_nakamoto_blocks()
                    .len()
                    > blocks_before)
            },
        )
        .unwrap();

        let proposal = wait_for_block_proposal(
            30,
            height_before + 1,
            &miner_pk,
            &signer_test.running_nodes.test_observer,
        )
        .expect("Timed out waiting for block proposal");

        wait_for_block_rejections_from_signers(
            timeout.as_secs(),
            &proposal.header.signer_signature_hash(),
            &reject_signers,
            &signer_test.running_nodes.test_observer,
        )
        .unwrap();

        wait_for(60, || {
            Ok(signer_test
                .running_nodes
                .counters
                .naka_miner_current_rejections
                .get()
                >= reject_signers.len() as u64)
        })
        .unwrap();
        assert_eq!(
            signer_test
                .running_nodes
                .counters
                .naka_miner_current_rejections_timeout_secs
                .get(),
            expected_timeout
        );
    };

    test_rejections(19, 123);
    test_rejections(18, 20);
    test_rejections(17, 10);
    test_rejections(16, 99);

    // reset reject/ignore
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

/// Test scenario:
///
/// - when a signer submits a block validation request and
///   gets a 429,
/// - the signer stores the pending request
/// - and submits it again after the current block validation
///   request finishes.
#[test]
#[ignore]
fn block_validation_pending_table() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let timeout = Duration::from_secs(30);
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let short_timeout = Duration::from_secs(20);

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |_, _| {},
        None,
        None,
    );
    let db_path = signer_test.signer_configs[0].db_path.clone();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    info!("----- Starting test -----";
        "db_path" => db_path.clone().to_str(),
    );
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers, true);
    TEST_VALIDATE_DELAY_DURATION_SECS.set(30);

    let signer_db = SignerDb::new(db_path).unwrap();

    let proposals_before = signer_test.get_miner_proposal_messages().len();

    let peer_info = signer_test.get_peer_info();

    // submit a tx so that the miner will attempt to mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("----- Waiting for miner to propose a block -----");

    // Wait for the miner to propose a block
    wait_for(30, || {
        Ok(signer_test.get_miner_proposal_messages().len() > proposals_before)
    })
    .expect("Timed out waiting for miner to propose a block");

    info!("----- Proposing a concurrent block -----");
    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    block.header.timestamp = get_epoch_time_secs();

    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.data.consensus_hash;
    block.header.chain_length = peer_info.stacks_tip_height + 1;
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash = block.header.signer_signature_hash();
    signer_test.propose_block(block.clone(), short_timeout);

    info!(
        "----- Waiting for a pending block proposal in SignerDb -----";
        "signer_signature_hash" => block_signer_signature_hash.to_hex(),
    );
    let mut last_log = Instant::now();
    last_log -= Duration::from_secs(5);
    wait_for(120, || {
        let is_pending = signer_db
            .has_pending_block_validation(&block_signer_signature_hash)
            .expect("Unexpected DBError");
        if last_log.elapsed() > Duration::from_secs(5) && !is_pending {
            let pending_block_validations = signer_db
                .get_all_pending_block_validations()
                .expect("Failed to get pending block validations");
            info!(
                "----- Waiting for pending block proposal in SignerDB -----";
                "proposed_block_signer_signature_hash" => block_signer_signature_hash.to_hex(),
                "pending_block_validations_len" => pending_block_validations.len(),
                "pending_block_validations" => pending_block_validations.iter()
                    .map(|p| p.signer_signature_hash.to_hex())
                    .collect::<Vec<String>>()
                    .join(", "),
            );
            last_log = Instant::now();
        }
        Ok(is_pending)
    })
    .expect("Timed out waiting for pending block proposal");

    info!("----- Waiting for pending block validation to be submitted -----");

    // Set the delay to 0 so that the block validation finishes quickly
    TEST_VALIDATE_DELAY_DURATION_SECS.set(0);

    wait_for(30, || {
        let proposal_responses = signer_test
            .running_nodes
            .test_observer
            .get_proposal_responses();
        let found_proposal = proposal_responses
            .iter()
            .any(|p| p.signer_signature_hash() == &block_signer_signature_hash);
        Ok(found_proposal)
    })
    .expect("Timed out waiting for pending block validation to be submitted");

    info!("----- Waiting for pending block validation to be removed -----");
    wait_for(60, || {
        let is_pending = signer_db
            .has_pending_block_validation(&block_signer_signature_hash)
            .expect("Unexpected DBError");
        Ok(!is_pending)
    })
    .expect("Timed out waiting for pending block validation to be removed");

    // for test cleanup we need to wait for block rejections
    let signer_keys = signer_test.signer_test_pks();
    wait_for_block_rejections_from_signers(
        30,
        &block.header.signer_signature_hash(),
        &signer_keys,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejections");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test the block_proposal_max_age_secs signer configuration option. It should reject blocks that are
/// invalid but within the max age window, otherwise it should simply drop the block without further processing.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
///
/// Test Execution:
/// The stacks node is advanced to epoch 3.0 reward set calculation to ensure the signer set is determined.
/// An invalid block proposal with a recent timestamp is forcibly written to the miner's slot to simulate the miner proposing a block.
/// The signers process the invalid block and broadcast a block response rejection to the respective .signers-XXX-YYY contract.
/// A second block proposal with an outdated timestamp is then submitted to the miner's slot to simulate the miner proposing a very old block.
/// The test confirms no further block rejection response is submitted to the .signers-XXX-YYY contract.
///
/// Test Assertion:
/// - Each signer successfully rejects the recent invalid block proposal.
/// - No signer submits a block proposal response for the outdated block proposal.
/// - The stacks tip does not advance
fn block_proposal_max_age_rejections() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            config.block_proposal_max_age_secs = 30;
        },
        |_, _| {},
        None,
        None,
    );
    signer_test.boot_to_epoch_3();
    let short_timeout = Duration::from_secs(30);

    info!("------------------------- Send Block Proposal To Signers -------------------------");
    let _ = get_chain_info(&signer_test.running_nodes.conf);
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    // First propose a stale block that is older than the block_proposal_max_age_secs
    block.header.timestamp = get_epoch_time_secs().saturating_sub(
        signer_test.signer_configs[0]
            .block_proposal_max_age_secs
            .saturating_add(1),
    );
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash_1 = block.header.signer_signature_hash();
    signer_test.propose_block(block.clone(), short_timeout);

    // Next propose a recent invalid block
    block.header.timestamp = get_epoch_time_secs();
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let block_signer_signature_hash_2 = block.header.signer_signature_hash();
    signer_test.propose_block(block, short_timeout);

    info!("------------------------- Test Block Proposal Rejected -------------------------");
    // Verify the signers rejected only the SECOND block proposal. The first was not even processed.
    wait_for(120, || {
        let mut status_map = HashMap::new();
        for chunk in signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            match message {
                SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                    signer_signature_hash,
                    ..
                })) => {
                    let entry = status_map.entry(signer_signature_hash).or_insert((0, 0));
                    entry.0 += 1;
                }
                SignerMessage::BlockResponse(BlockResponse::Accepted(BlockAccepted {
                    signer_signature_hash,
                    ..
                })) => {
                    let entry = status_map.entry(signer_signature_hash).or_insert((0, 0));
                    entry.1 += 1;
                }
                _ => continue,
            }
        }
        let block_1_status = status_map
            .get(&block_signer_signature_hash_1)
            .cloned()
            .unwrap_or((0, 0));
        assert_eq!(block_1_status, (0, 0));

        let block_2_status = status_map
            .get(&block_signer_signature_hash_2)
            .cloned()
            .unwrap_or((0, 0));
        assert_eq!(block_2_status.1, 0, "Block 2 should always be rejected");

        info!("Block 2 status";
            "accepted" => %block_2_status.1, "rejected" => %block_2_status.0
        );
        Ok(block_2_status.0 > num_signers * 7 / 10)
    })
    .expect("Timed out waiting for block rejections");

    info!("------------------------- Test Shutdown-------------------------");
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers for an incoming reward cycle, do not sign blocks for the previous reward cycle.
///
/// Test Setup:
/// The test spins up five stacks signers that are stacked for multiple cycles, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines to the middle of the prepare phase of reward cycle N+1.
/// Sends a status request to the signers to ensure both the current and next reward cycle signers are active.
/// A valid Nakamoto block is proposed.
/// Two invalid Nakamoto blocks are proposed.
///
/// Test Assertion:
/// All signers for cycle N sign the valid block.
/// No signers for cycle N+1 emit any messages.
/// All signers for cycle N reject the invalid blocks.
/// No signers for cycle N+1 emit any messages for the invalid blocks.
/// The chain advances to block N.
fn incoming_signers_ignore_block_proposals() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let timeout = Duration::from_secs(200);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    // Mine to the middle of the prepare phase of the next reward cycle
    let next_reward_cycle = curr_reward_cycle.saturating_add(1);
    let prepare_phase_len = signer_test
        .running_nodes
        .conf
        .get_burnchain()
        .pox_constants
        .prepare_length as u64;
    let middle_of_prepare_phase = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(next_reward_cycle)
        .saturating_sub(prepare_phase_len / 2);

    info!("------------------------- Test Mine Until Middle of Prepare Phase at Block Height {middle_of_prepare_phase} -------------------------");
    signer_test.run_until_burnchain_height_nakamoto(timeout, middle_of_prepare_phase, num_signers);

    signer_test.wait_for_registered_both_reward_cycles();

    let current_burnchain_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    assert_eq!(current_burnchain_height, middle_of_prepare_phase);
    assert_eq!(curr_reward_cycle, signer_test.get_current_reward_cycle());

    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    info!("------------------------- Test Mine A Valid Block -------------------------");
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    // a tenure has begun, so wait until we mine a block
    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .expect("Timed out waiting for a block to be mined");

    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let mut stackerdb = signer_test.readonly_stackerdb_client(next_reward_cycle);

    let next_signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(next_reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();

    let mut no_next_signer_messages = || {
        assert!(wait_for(30, || {
            let latest_msgs = StackerDB::get_messages::<SignerMessage>(
                stackerdb
                    .get_session_mut(&MessageSlotID::BlockResponse)
                    .expect("Failed to get BlockResponse stackerdb session"),
                &next_signer_slot_ids,
            )
            .expect("Failed to get messages from stackerdb");
            assert!(
                latest_msgs.is_empty(),
                "Next signers have messages in their stackerdb"
            );
            Ok(false)
        })
        .is_err());
    };

    no_next_signer_messages();

    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    block.header.timestamp = get_epoch_time_secs();
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let signer_signature_hash_1 = block.header.signer_signature_hash();

    info!("------------------------- Test Attempt to Mine Invalid Block {signer_signature_hash_1} -------------------------");

    let short_timeout = Duration::from_secs(30);
    let all_signers = signer_test.signer_test_pks();
    signer_test.running_nodes.test_observer.clear();

    // Propose a block to the signers that passes initial checks but will be rejected by the stacks node
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.data.consensus_hash;
    block.header.chain_length =
        get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height + 1;
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let signer_signature_hash_2 = block.header.signer_signature_hash();

    info!("------------------------- Test Attempt to Mine Invalid Block {signer_signature_hash_2} -------------------------");

    signer_test.propose_block(block, short_timeout);
    // Verify the signers rejected the second block via the endpoint
    signer_test
        .wait_for_validate_reject_response(short_timeout.as_secs(), &signer_signature_hash_2);
    wait_for_block_rejections_from_signers(
        30,
        &signer_signature_hash_2,
        &all_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block rejections");
    no_next_signer_messages();

    assert_eq!(blocks_before, mined_blocks.load(Ordering::SeqCst));
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers for an outgoing reward cycle, do not sign blocks for the incoming reward cycle.
///
/// Test Setup:
/// The test spins up five stacks signers that are stacked for multiple cycles, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines to the next reward cycle.
/// Sends a status request to the signers to ensure both the current and previoustimeout_heur reward cycle signers are active.
/// A valid Nakamoto block is proposed.
/// Two invalid Nakamoto blocks are proposed.
///
/// Test Assertion:
/// All signers for cycle N+1 sign the valid block.
/// No signers for cycle N emit any messages.
/// All signers for cycle N+1 reject the invalid blocks.
/// No signers for cycle N emit any messages for the invalid blocks.
/// The chain advances to block N.
fn outgoing_signers_ignore_block_proposals() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let timeout = Duration::from_secs(200);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();
    // Do not cleanup stale signers
    TEST_SKIP_SIGNER_CLEANUP.set(true);
    let curr_reward_cycle = signer_test.get_current_reward_cycle();
    // Mine to the middle of the prepare phase of the next reward cycle
    let next_reward_cycle = curr_reward_cycle.saturating_add(1);
    let next_reward_cycle_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .reward_cycle_to_block_height(next_reward_cycle);

    info!("------------------------- Test Mine Until Next Reward Cycle at Height {next_reward_cycle_height} -------------------------");
    signer_test.run_until_burnchain_height_nakamoto(timeout, next_reward_cycle_height, num_signers);

    signer_test.wait_for_registered_both_reward_cycles();

    let current_burnchain_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    assert_eq!(current_burnchain_height, next_reward_cycle_height);
    assert_eq!(next_reward_cycle, signer_test.get_current_reward_cycle());

    let old_reward_cycle = curr_reward_cycle;

    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    signer_test.running_nodes.test_observer.clear();

    info!("------------------------- Test Mine A Valid Block -------------------------");
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    // a tenure has begun, so wait until we mine a block
    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .expect("Timed out waiting for a block to be mined");

    let new_signature_hash = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .last()
        .unwrap()
        .signer_signature_hash
        .clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let mut stackerdb = signer_test.readonly_stackerdb_client(old_reward_cycle);

    let old_signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(old_reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();

    let mut old_signers_ignore_block_proposals = |hash| {
        assert!(wait_for(10, || {
            let latest_msgs = StackerDB::get_messages::<SignerMessage>(
                stackerdb
                    .get_session_mut(&MessageSlotID::BlockResponse)
                    .expect("Failed to get BlockResponse stackerdb session"),
                &old_signer_slot_ids,
            )
            .expect("Failed to get messages from stackerdb");
            for msg in latest_msgs.iter() {
                if let SignerMessage::BlockResponse(response) = msg {
                    assert_ne!(response.get_signer_signature_hash(), hash);
                }
            }
            Ok(false)
        })
        .is_err());
    };
    old_signers_ignore_block_proposals(&new_signature_hash);

    let proposal_conf = ProposalEvalConfig {
        proposal_wait_for_parent_time: Duration::from_secs(0),
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(30),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };
    block.header.timestamp = get_epoch_time_secs();

    let short_timeout = Duration::from_secs(30);
    signer_test.running_nodes.test_observer.clear();

    // Propose a block to the signers that passes initial checks but will be rejected by the stacks node
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.data.consensus_hash;
    block.header.chain_length =
        get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height + 1;
    block
        .header
        .sign_miner(signer_test.get_miner_key())
        .unwrap();
    let signer_signature_hash = block.header.signer_signature_hash();

    info!("------------------------- Test Attempt to Mine Invalid Block {signer_signature_hash} -------------------------");

    signer_test.propose_block(block, short_timeout);
    // Verify the signers rejected the second block via the endpoint
    signer_test.wait_for_validate_reject_response(short_timeout.as_secs(), &signer_signature_hash);
    wait_for_block_global_rejection(
        30,
        &signer_signature_hash,
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to see majority rejections of ivalid block'");
    old_signers_ignore_block_proposals(&signer_signature_hash);

    assert_eq!(blocks_before, mined_blocks.load(Ordering::SeqCst));
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers ignore signatures for blocks that do not belong to their own reward cycle.
/// This is a regression test for a signer bug that caused an internal signer instances to
/// broadcast a block corresponding to a different reward cycle with a higher threshold, stalling the network.
///
/// Test Setup:
/// The test spins up four stacks signers that are stacked for one cycle, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The same four stackers stack for an addiitonal cycle.
/// A new fifth signer is added to the stacker set, stacking for the next reward cycle.
/// The node advances to the next reward cycle.
/// The first two signers are set to ignore block proposals.
/// A valid Nakamoto block N is proposed to the current signers.
/// A signer signature over block N is forcibly written to the outgoing signer's stackerdb instance.
///
/// Test Assertion:
/// All signers for the previous cycle ignore the incoming block N.
/// Outgoing signers ignore the forced signature.
/// The chain does NOT advance to block N.
fn injected_signatures_are_ignored_across_boundaries() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 4;
    let new_num_signers = 5_usize;
    let signer_private_keys: Vec<_> = (0..num_signers)
        .map(|_| StacksPrivateKey::random())
        .collect();
    let new_signer_private_key = StacksPrivateKey::random();
    let mut new_signer_private_keys = signer_private_keys.clone();
    new_signer_private_keys.push(new_signer_private_key.clone());

    let new_signer_public_keys: Vec<_> = new_signer_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();
    let new_signer_addresses: Vec<_> = new_signer_private_keys.iter().map(tests::to_addr).collect();
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let mut initial_balances = new_signer_addresses
        .iter()
        .map(|addr| (addr.clone(), POX_4_DEFAULT_STACKER_BALANCE))
        .collect::<Vec<_>>();

    initial_balances.push((sender_addr, (send_amt + send_fee) * 4));

    let run_stamp = rand::random();

    let rpc_port = 51024;
    let rpc_bind = format!("127.0.0.1:{rpc_port}");

    // Setup the new signers that will take over
    let new_signer_config = build_signer_config_tomls(
        &[new_signer_private_key.clone()],
        &rpc_bind,
        Some(Duration::from_millis(128)), // Timeout defaults to 5 seconds. Let's override it to 128 milliseconds.
        &Network::Testnet,
        "12345",
        run_stamp,
        3000 + num_signers,
        Some(100_000),
        None,
        Some(9000 + num_signers),
        None,
    )
    .first()
    .unwrap()
    .clone();

    info!("---- spawning signer ----");
    let signer_config = SignerConfig::load_from_str(&new_signer_config).unwrap();
    let new_spawned_signer = SpawnedSigner::new(signer_config.clone());

    // Boot with some initial signer set
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |naka_conf, _| {
            info!(
                "---- Adding signer endpoint to naka conf ({}) ----",
                signer_config.endpoint
            );

            naka_conf.events_observers.insert(EventObserverConfig {
                endpoint: format!("{}", signer_config.endpoint),
                events_keys: vec![
                    EventKeyType::StackerDBChunks,
                    EventKeyType::BlockProposal,
                    EventKeyType::BurnchainBlocks,
                ],
                timeout_ms: 1000,
                disable_retries: false,
            });
            naka_conf.node.rpc_bind = rpc_bind.clone();
        },
        None,
        Some(signer_private_keys),
    );
    assert_eq!(
        new_spawned_signer.config.node_host,
        signer_test.running_nodes.conf.node.rpc_bind
    );

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = Duration::from_secs(20);

    // Verify that naka_conf has our new signer's event observers
    let endpoint = format!("{}", signer_config.endpoint);
    assert!(signer_test
        .running_nodes
        .conf
        .events_observers
        .iter()
        .any(|observer| observer.endpoint == endpoint));

    info!("---- Booting to epoch 3 -----");
    signer_test.boot_to_epoch_3();
    // Do not cleanup stale signers
    TEST_SKIP_SIGNER_CLEANUP.set(true);

    // verify that the first reward cycle has the old signers in the reward set
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_test_public_keys: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();

    info!("---- Verifying that the current signers are the old signers ----");
    let current_signers = signer_test.get_reward_set_signers(reward_cycle);
    assert_eq!(current_signers.len(), num_signers);
    // Verify that the current signers are the same as the old signers
    for signer in current_signers.iter() {
        assert!(signer_test_public_keys.contains(&signer.signing_key.to_vec()));
    }

    // advance to the next reward cycle, stacking to the new signers beforehand
    let reward_cycle = signer_test.get_current_reward_cycle();

    info!("---- Stacking new signers -----");

    let burn_block_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_headers_height();
    let accounts_to_check: Vec<_> = new_signer_private_keys.iter().map(tests::to_addr).collect();

    // Stack the new signer
    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        tests::to_addr(&new_signer_private_key).bytes().clone(),
    );
    let pox_addr_tuple: clarity::vm::Value = pox_addr.as_clarity_tuple().unwrap().into();
    let signature = make_pox_4_signer_key_signature(
        &pox_addr,
        &new_signer_private_key,
        reward_cycle.into(),
        &Pox4SignatureTopic::StackStx,
        CHAIN_ID_TESTNET,
        1_u128,
        u128::MAX,
        1,
    )
    .unwrap()
    .to_rsv();

    let signer_pk = Secp256k1PublicKey::from_private(&new_signer_private_key);
    let stacking_tx = make_contract_call(
        &new_signer_private_key,
        0,
        1000,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &StacksAddress::burn_address(false),
        "pox-4",
        "stack-stx",
        &[
            clarity::vm::Value::UInt(POX_4_DEFAULT_STACKER_STX_AMT),
            pox_addr_tuple,
            clarity::vm::Value::UInt(burn_block_height as u128),
            clarity::vm::Value::UInt(1),
            clarity::vm::Value::some(clarity::vm::Value::buff_from(signature).unwrap()).unwrap(),
            clarity::vm::Value::buff_from(signer_pk.to_bytes_compressed()).unwrap(),
            clarity::vm::Value::UInt(u128::MAX),
            clarity::vm::Value::UInt(1),
        ],
    );
    submit_tx(&http_origin, &stacking_tx);

    wait_for(60, || {
        Ok(accounts_to_check
            .iter()
            .all(|acct| get_account(&http_origin, acct).nonce >= 1))
    })
    .expect("Timed out waiting for stacking txs to be mined");

    signer_test.mine_nakamoto_block(short_timeout, true);

    let next_reward_cycle = reward_cycle.saturating_add(1);

    let next_cycle_height = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_burnchain()
        .nakamoto_first_block_of_cycle(next_reward_cycle)
        .saturating_add(1);

    let next_calculation = next_cycle_height.saturating_sub(3);
    info!("---- Mining to next reward set calculation (block {next_calculation}) -----");
    signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_calculation,
        new_num_signers,
    );

    // Verify that the new reward set is the new signers
    let reward_set = signer_test.get_reward_set_signers(next_reward_cycle);
    assert_eq!(reward_set.len(), new_num_signers);
    for signer in reward_set.iter() {
        assert!(new_signer_public_keys.contains(&signer.signing_key.to_vec()));
    }

    info!("---- Manually mine a single burn block to force the signers to update ----");
    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    signer_test.wait_for_registered_both_reward_cycles();

    info!("---- Mining to the next reward cycle (block {next_cycle_height}) -----",);
    signer_test.run_until_burnchain_height_nakamoto(
        Duration::from_secs(60),
        next_cycle_height,
        new_num_signers,
    );
    let new_reward_cycle = signer_test.get_current_reward_cycle();
    assert_eq!(new_reward_cycle, reward_cycle.saturating_add(1));

    let current_signers = signer_test.get_reward_set_signers(new_reward_cycle);
    assert_eq!(current_signers.len(), new_num_signers);

    let mined_blocks = signer_test.running_nodes.counters.naka_mined_blocks.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    // Clear the stackerdb chunks
    signer_test.running_nodes.test_observer.clear();

    let old_reward_cycle = reward_cycle;
    let curr_reward_cycle = new_reward_cycle;

    info!("------------------------- Test Propose A Valid Block -------------------------");
    // Make the last three of the signers ignore the block proposal to ensure it it is not globally accepted/rejected
    let all_signers: Vec<_> = new_signer_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();
    let non_ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(new_num_signers * 5 / 10)
        .collect();
    let ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .skip(new_num_signers * 5 / 10)
        .collect();
    assert_eq!(ignoring_signers.len(), 3);
    assert_eq!(non_ignoring_signers.len(), 2);
    TEST_SIGNERS_SKIP_BLOCK_RESPONSE_BROADCAST.set(ignoring_signers.clone());

    let info_before = signer_test.get_peer_info();
    // submit a tx so that the miner will ATTEMPT to mine a stacks block N
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);

    info!("Submitted tx {tx} in attempt to mine block N");
    let mut new_signature_hash = None;
    wait_for(30, || {
        let accepted_signers: HashSet<_> = signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                if let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message {
                    new_signature_hash = Some(accepted.signer_signature_hash.clone());
                    return non_ignoring_signers.iter().find(|key| {
                        key.verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                            .unwrap()
                    });
                }
                None
            })
            .collect();
        Ok(accepted_signers.len() + ignoring_signers.len() == new_num_signers)
    })
    .expect("FAIL: Timed out waiting for block proposal acceptance");
    let new_signature_hash = new_signature_hash.expect("Failed to get new signature hash");

    // The first 50% of the signers are the ones that are ignoring block proposals and thus haven't sent a signature yet
    let forced_signer = &signer_test.signer_stacks_private_keys[ignoring_signers.len()];
    let mut stackerdb = signer_test.readonly_stackerdb_client(old_reward_cycle);
    signer_test.verify_no_block_response_found(
        &mut stackerdb,
        next_reward_cycle,
        &new_signature_hash,
    );

    // Get the last block proposal
    let block_proposal = signer_test
        .running_nodes
        .test_observer
        .get_stackerdb_chunks()
        .iter()
        .flat_map(|chunk| chunk.modified_slots.clone())
        .filter_map(|chunk| {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");
            if let SignerMessage::BlockProposal(proposal) = message {
                assert_eq!(proposal.reward_cycle, curr_reward_cycle);
                assert_eq!(
                    proposal.block.header.signer_signature_hash(),
                    new_signature_hash
                );
                return Some(proposal);
            }
            None
        })
        .next()
        .expect("Failed to find block proposal for reward cycle {curr_reward_cycle}");

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    let info_after = signer_test.get_peer_info();
    assert_eq!(blocks_after, blocks_before);
    assert_eq!(info_after, info_before);

    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N
    let nakamoto_blocks = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks();
    let block = nakamoto_blocks.last().unwrap();
    assert_ne!(info_after.stacks_tip.to_string(), block.block_hash);

    info!("------------------------- Test Inject Valid Signature To Old Signers -------------------------");
    // Force a signature to force the threshold of the block over the old signers' threshold
    // If the old signers were not fixed, the old signers would stall.
    signer_test.inject_accept_signature(&block_proposal.block, forced_signer, old_reward_cycle);

    assert!(wait_for(10, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .is_err());

    let info_after = signer_test.get_peer_info();
    assert_ne!(info_after.stacks_tip.to_string(), block.block_hash);

    info!("------------------------- Test Inject Valid Signatures to New Signers -------------------------");
    // Force two signatures to force the threshold of the block over the new signers' threshold
    // This signature should be accepted by current signers, but ignored by the old signers.
    signer_test.inject_accept_signature(&block_proposal.block, forced_signer, new_reward_cycle);
    let forced_signer = new_signer_private_keys.last().unwrap();
    signer_test.inject_accept_signature(&block_proposal.block, forced_signer, new_reward_cycle);

    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before)
    })
    .expect("Timed out waiting for block to be mined");

    let info_after = signer_test.get_peer_info();
    assert_eq!(info_after.stacks_tip.to_string(), block.block_hash,);
    // Wait 5 seconds in case there are any lingering block pushes from the signers
    std::thread::sleep(Duration::from_secs(5));
    signer_test.shutdown();

    assert!(new_spawned_signer.stop().is_none());
}

#[test]
#[ignore]
/// Test that signers mark a miner malicious if it doesn't propose any blocks before the block proposal timeout
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing. The block proposal timeout is set to 20 seconds.
///
/// Test Execution:
/// Block proposals are paused for the miner.
/// Tenure A starts.
/// The test waits for the block proposal timeout + 1 second.
/// Block proposals are unpaused for the miner.
/// Miner propose a block N.
/// Signers reject the block and mark the miner as malicious.
///
///
/// Test Assertion:
/// Stacks tip does not advance to block N.
fn block_proposal_timeout() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let block_proposal_timeout = Duration::from_secs(20);
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_, _| {},
        None,
        None,
    );

    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let miner_pkh = Hash160::from_node_public_key(&miner_pk);

    signer_test.boot_to_epoch_3();

    // Pause the miner's block proposals
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk.clone()]);

    info!("------------------------- Start Tenure A -------------------------");
    let commits_before = signer_test
        .running_nodes
        .counters
        .naka_submitted_commits
        .load(Ordering::SeqCst);
    let chain_before = get_chain_info(&signer_test.running_nodes.conf);
    signer_test.running_nodes.test_observer.clear();
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let chain_info = get_chain_info(&signer_test.running_nodes.conf);
            let commits_count = signer_test
                .running_nodes
                .counters
                .naka_submitted_commits
                .load(Ordering::SeqCst);
            Ok(commits_count > commits_before
                && chain_info.burn_block_height > chain_before.burn_block_height)
        },
    )
    .unwrap();
    let reverted_tenure_id = &chain_before.pox_consensus;
    info!("------------------------- Wait for Signers to Mark {miner_pkh} at height {} invalid -------------------------", chain_before.stacks_tip_height;
    "expected_burn_block" => %chain_before.pox_consensus,
    "expected_burn_block_height" => chain_before.burn_block_height,
    "new_miner_pkh" => %miner_pkh,
    "new_tenure_id" => %reverted_tenure_id,
    );
    wait_for_state_machine_update_by_miner_tenure_id(
        block_proposal_timeout.as_secs() + 30,
        reverted_tenure_id,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers state to revert to old miner");

    info!("------------------------- Attempt Mine Block N  -------------------------");
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![]);

    let block_proposal_n = wait_for_block_proposal(
        30,
        chain_before.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block proposal N");
    wait_for_block_global_rejection(
        30,
        &block_proposal_n.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get block rejections for N");

    let chain_after = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(chain_after.stacks_tip, chain_before.stacks_tip);
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks that the miner ignore repeat block rejections.
fn repeated_rejection() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * 3)],
        |_| {},
        |config, _| {
            config.miner.block_rejection_timeout_steps.clear();
            config
                .miner
                .block_rejection_timeout_steps
                .insert(0, Duration::from_secs(120));
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    let proposed_blocks = signer_test
        .running_nodes
        .counters
        .naka_proposed_blocks
        .clone();

    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    // make signer[0] reject all proposals and to repeat the rejection
    let rejecting_signer =
        StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[0]);
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![rejecting_signer.clone()]);
    TEST_REPEAT_PROPOSAL_RESPONSE.set(vec![rejecting_signer]);

    // make signer[1] ignore all proposals
    let ignoring_signer = StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[1]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![ignoring_signer]);

    let proposals_before = proposed_blocks.load(Ordering::SeqCst);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    wait_for(60, || {
        if proposed_blocks.load(Ordering::SeqCst) > proposals_before {
            return Ok(true);
        }
        Ok(false)
    })
    .expect("Timed out waiting for block proposal");

    let proposals_after = proposed_blocks.load(Ordering::SeqCst);
    info!("Block proposed, verifying that it is not rejected");

    // Ensure that the miner does not propose any more blocks
    _ = wait_for(60, || {
        assert_eq!(
            proposed_blocks.load(Ordering::SeqCst),
            proposals_after,
            "Miner proposed another block"
        );
        Ok(false)
    });

    signer_test.shutdown();
}

fn transfers_in_block(block: &serde_json::Value) -> usize {
    let transactions = block["transactions"].as_array().unwrap();
    let mut count = 0;
    for tx in transactions {
        let raw_tx = tx["raw_tx"].as_str().unwrap();
        let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
        let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
        if let TransactionPayload::TokenTransfer(..) = &parsed.payload {
            // don't count phantom unlock transactions (identified as transfers from the boot addr)
            if !parsed.get_origin().address_testnet().is_boot_code_addr() {
                count += 1;
            }
        }
    }
    count
}

#[test]
#[ignore]
/// This test verifies that a miner will re-propose the same block if it times
/// out waiting for signers to reach consensus on the block.
///
/// Spins
fn retry_proposal() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * 3)],
        |_| {},
        |config, _| {
            config.miner.block_rejection_timeout_steps.clear();
            config
                .miner
                .block_rejection_timeout_steps
                .insert(0, Duration::from_secs(123));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(10, Duration::from_secs(20));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(15, Duration::from_secs(10));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(20, Duration::from_secs(30));
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    let proposed_blocks = signer_test
        .running_nodes
        .counters
        .naka_proposed_blocks
        .clone();

    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let block_height_before = info.stacks_tip_height;

    // make signer[0] reject all proposals
    let rejecting_signer =
        StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[0]);
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![rejecting_signer]);

    // make signer[1] ignore all proposals
    let ignoring_signer = StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[1]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![ignoring_signer]);

    let proposals_before = proposed_blocks.load(Ordering::SeqCst);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    wait_for(60, || {
        if proposed_blocks.load(Ordering::SeqCst) > proposals_before {
            return Ok(true);
        }
        Ok(false)
    })
    .expect("Timed out waiting for block proposal");

    info!(
        "Block proposed, submitting another transaction that should not get included in the block"
    );
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        1,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Disable signer 1 from ignoring proposals");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![]);

    let test_observer = &signer_test.running_nodes.test_observer;

    info!("Waiting for the block to be approved");
    wait_for(60, || {
        let blocks = test_observer.get_blocks();
        let last_block = blocks.last().expect("No blocks found");
        let height = last_block["block_height"].as_u64().unwrap();
        if height > block_height_before {
            return Ok(true);
        }
        Ok(false)
    })
    .expect("Timed out waiting for block");

    // Ensure that the block was the original block with just 1 transfer
    let blocks = test_observer.get_blocks();
    let block = blocks.last().expect("No blocks found");
    assert_eq!(transfers_in_block(block), 1);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a a signer will accept a rejected block if it is
/// re-proposed and determined to be legitimate. This can happen if the block
/// is initially rejected due to a test flag or because the stacks-node had
/// not yet processed the block's parent.
fn signer_can_accept_rejected_block() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * 3)],
        |_| {},
        |config, _| {
            config.miner.block_rejection_timeout_steps.clear();
            config
                .miner
                .block_rejection_timeout_steps
                .insert(0, Duration::from_secs(123));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(10, Duration::from_secs(20));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(15, Duration::from_secs(10));
            config
                .miner
                .block_rejection_timeout_steps
                .insert(20, Duration::from_secs(30));
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();

    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let block_height_before = info.stacks_tip_height;

    // make signer[0] reject all proposals
    let rejecting_signer =
        StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[0]);
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![rejecting_signer]);

    // make signer[1] ignore all proposals
    let ignoring_signer = StacksPublicKey::from_private(&signer_test.signer_stacks_private_keys[1]);
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(vec![ignoring_signer]);

    // Stall block validation so we can ensure the timing we want to test
    TEST_VALIDATE_STALL.set(true);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    let block = wait_for_block_proposal(
        30,
        block_height_before + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block proposal");
    let expected_block_height = block.header.chain_length;

    // Wait for signer[0] to reject the block
    wait_for_block_rejections(
        30,
        &block.header.signer_signature_hash(),
        1,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get expected rejections for Miner 1's block");

    info!("Disable signer 0 from rejecting proposals");
    signer_test.running_nodes.test_observer.clear();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);

    // Unstall the other signers
    TEST_VALIDATE_STALL.set(false);

    info!(
        "Block proposed, submitting another transaction that should not get included in the block"
    );
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        1,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    let test_observer = &signer_test.running_nodes.test_observer;

    info!("Waiting for the block to be approved");
    wait_for(60, || {
        let blocks = test_observer.get_blocks();

        // Look for a block with expected height
        let Some(block) = blocks
            .iter()
            .find(|block| block["block_height"].as_u64() == Some(expected_block_height)) else {
                return Ok(false) // Keep waiting if the block hasn't appeared yet
        };

        let transfers_included_in_block = transfers_in_block(block);
        if transfers_included_in_block == 1 {
            Ok(true) // Success: found the block with exactly 1 transfer
        } else {
            Err(format!("Unexpected amount of transfers included in block. Found: {transfers_included_in_block}"))
        }
    })
    .expect("Timed out waiting for block");

    signer_test.shutdown();
}

/// This function intends to check the timing of the mempool iteration when
/// there are a large number of transactions in the mempool. It will boot to
/// epoch 3, fan out some STX transfers to a large number of accounts, wait for
/// these to all be mined, and then pause block mining, and submit a large
/// number of transactions to the mempool.  It will then unpause block mining
/// and wait for the first block to be mined. Since the default miner
/// configuration specifies to spend 5 seconds mining a block, we expect that
/// this first block should be proposed within 10 seconds and approved within
/// 20 seconds. We also verify that the block contains at least 5,000
/// transactions, since a lower count than that would indicate a clear
/// regression. Several tests below call this function, testing different
/// strategies and fees.
fn large_mempool_base(strategy: MemPoolWalkStrategy, set_fee: impl Fn() -> u64) {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let transfer_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    // Start with 10 accounts with initial balances.
    let initial_sender_sks = (0..10)
        .map(|_| StacksPrivateKey::random())
        .collect::<Vec<_>>();
    let initial_sender_addrs = initial_sender_sks
        .iter()
        .map(|sk| tests::to_addr(sk))
        .collect::<Vec<_>>();

    // These 10 accounts will send to 25 accounts each, then those 260 accounts
    // will send to 25 accounts each, for a total of 6760 accounts.
    // At the end of the funding round, we want to have 6760 accounts with
    // enough balance to send 1 uSTX 25 times.
    // With a fee of 180 to 2000 uSTX per send, we need each account to have
    //   2001 * 25 = 50_025 uSTX.
    // The 260 accounts in the middle will need to have enough to send that
    // amount to 25 other accounts, plus the fee, and then enough to send the
    // transfers themselves as well:
    //   (50025 + 180) * 25 + 50025 = 1_305_150 uSTX.
    // The 10 initial accounts will need to have enough to send that amount to
    // 25 other accounts, plus enough to send the transfers themselves as well:
    //   (1305150 + 180) * 25 + 1305150 = 33_938_400 uSTX.
    let initial_balance = 33_938_400;
    let initial_balances = initial_sender_addrs
        .iter()
        .map(|addr| (addr.clone(), initial_balance))
        .collect::<Vec<_>>();

    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |conf, _| {
            conf.miner.mempool_walk_strategy = strategy;
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    // This will hold tuples for all of our senders, with the sender pk and
    // the nonce
    let mut senders = initial_sender_sks
        .iter()
        .map(|sk| (sk, 0))
        .collect::<Vec<_>>();

    let mempool_db_path = format!(
        "{}/nakamoto-neon/chainstate/mempool.sqlite",
        signer_test.running_nodes.conf.node.working_dir
    );
    let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;
    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    // Open a sqlite DB at mempool_db_path so that we can quickly add
    // transactions to the mempool.
    let mut conn = Connection::open(&mempool_db_path).unwrap();
    let db_tx = conn.transaction().unwrap();

    info!("Sending the first round of funding");
    let timer = Instant::now();
    let mut new_senders = vec![];
    for (sender_sk, nonce) in senders.iter_mut() {
        for _ in 0..25 {
            let recipient_sk = StacksPrivateKey::random();
            let recipient_addr = tests::to_addr(&recipient_sk);
            let sender_addr = tests::to_addr(sender_sk);
            let transfer_tx = make_stacks_transfer_serialized(
                sender_sk,
                *nonce,
                transfer_fee,
                chain_id,
                &recipient_addr.into(),
                1_305_150,
            );
            insert_tx_in_mempool(
                &db_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                transfer_fee,
                &tip.consensus_hash,
                &tip.canonical_stacks_tip_hash,
                tip.stacks_block_height,
            );
            *nonce += 1;
            new_senders.push(recipient_sk);
        }
    }
    db_tx.commit().unwrap();

    info!("Sending first round of funding took {:?}", timer.elapsed());

    // Wait for the first round of funding to be mined
    wait_for(120, || {
        for (sender_sk, nonce) in senders.iter() {
            let sender_addr = tests::to_addr(sender_sk);
            let account = get_account(&http_origin, &sender_addr);
            if account.nonce < *nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for first round of funding to be mined");

    info!(
        "Sending and mining first round of funding took {:?}",
        timer.elapsed()
    );

    // Add the new senders to the list of senders
    senders.extend(new_senders.iter().map(|sk| (sk, 0)));

    info!("Sending the second round of funding");
    let db_tx = conn.transaction().unwrap();
    let timer = Instant::now();
    let mut new_senders = vec![];
    for (sender_sk, nonce) in senders.iter_mut() {
        for _ in 0..25 {
            let sender_addr = tests::to_addr(sender_sk);
            let recipient_sk = StacksPrivateKey::random();
            let recipient_addr = tests::to_addr(&recipient_sk);
            let transfer_tx = make_stacks_transfer_serialized(
                sender_sk,
                *nonce,
                transfer_fee,
                chain_id,
                &recipient_addr.into(),
                50_025,
            );
            insert_tx_in_mempool(
                &db_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                transfer_fee,
                &tip.consensus_hash,
                &tip.canonical_stacks_tip_hash,
                tip.stacks_block_height,
            );
            *nonce += 1;
            new_senders.push(recipient_sk);
        }
    }
    db_tx.commit().unwrap();

    info!("Sending second round of funding took {:?}", timer.elapsed());

    // Wait for the second round of funding to be mined
    wait_for(120, || {
        for (sender_sk, nonce) in senders.iter() {
            let sender_addr = tests::to_addr(sender_sk);
            let account = get_account(&http_origin, &sender_addr);
            if account.nonce < *nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for second round of funding to be mined");

    info!(
        "Sending and mining second round of funding took {:?}",
        timer.elapsed()
    );

    // Add the new senders to the list of senders
    senders.extend(new_senders.iter().map(|sk| (sk, 0)));

    info!("Pause mining and fill the mempool with the transfers");

    // Pause block mining
    fault_injection_stall_miner();

    let db_tx = conn.transaction().unwrap();
    let timer = Instant::now();

    // Fill the mempool with the transfers
    for _ in 0..25 {
        for (sender_sk, nonce) in senders.iter_mut() {
            let sender_addr = tests::to_addr(sender_sk);
            let fee = set_fee();
            assert!(fee >= 180 && fee <= 2000);
            let transfer_tx =
                make_stacks_transfer_serialized(sender_sk, *nonce, fee, chain_id, &recipient, 1);
            insert_tx_in_mempool(
                &db_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                fee,
                &tip.consensus_hash,
                &tip.canonical_stacks_tip_hash,
                tip.stacks_block_height,
            );
            *nonce += 1;
        }
    }
    db_tx.commit().unwrap();

    info!("Sending transfers took {:?}", timer.elapsed());

    let test_observer = &signer_test.running_nodes.test_observer;

    let proposed_blocks_before = test_observer.get_mined_nakamoto_blocks().len();
    let blocks_before = test_observer.get_blocks().len();

    info!("Mining transfers...");

    // Unpause block mining
    fault_injection_unstall_miner();

    // Wait for the first block to be proposed.
    wait_for(30, || {
        let proposed_blocks = test_observer.get_mined_nakamoto_blocks().len();
        Ok(proposed_blocks > proposed_blocks_before)
    })
    .expect("Timed out waiting for first block to be mined");

    let blocks = test_observer.get_mined_nakamoto_blocks();
    let last_block = blocks.last().unwrap();
    info!(
        "First block contains {} transactions",
        last_block.tx_events.len()
    );
    if strategy == MemPoolWalkStrategy::NextNonceWithHighestFeeRate {
        assert!(last_block.tx_events.len() > 2000);
    }

    // Wait for the first block to be accepted.
    wait_for(60, || {
        let blocks = test_observer.get_blocks().len();
        Ok(blocks > blocks_before)
    })
    .expect("Timed out waiting for first block to be mined");

    signer_test.shutdown();
}

#[test]
#[ignore]
fn large_mempool_original_constant_fee() {
    large_mempool_base(MemPoolWalkStrategy::GlobalFeeRate, || 180);
}

#[test]
#[ignore]
fn large_mempool_original_random_fee() {
    large_mempool_base(MemPoolWalkStrategy::GlobalFeeRate, || {
        thread_rng().gen_range(180..2000)
    });
}

#[test]
#[ignore]
fn large_mempool_next_constant_fee() {
    large_mempool_base(MemPoolWalkStrategy::NextNonceWithHighestFeeRate, || 180);
}

#[test]
#[ignore]
fn large_mempool_next_random_fee() {
    large_mempool_base(MemPoolWalkStrategy::NextNonceWithHighestFeeRate, || {
        thread_rng().gen_range(180..2000)
    });
}

#[test]
#[ignore]
/// This test intends to check the timing of the mempool iteration when there
/// are a large number of transactions in the mempool. It will boot to epoch 3,
/// fan out some STX transfers to a large number of accounts, wait for these to
/// all be mined, and then pause block mining, and submit a large number of
/// transactions to the mempool from those accounts, all with the same fee. It
/// will then unpause block mining and wait for the first block to be mined.
/// Since the default miner configuration specifies to spend 5 seconds mining a
/// block, we expect that this first block should be proposed within 10 seconds
/// and approved within 20 seconds. We also verify that the block contains at
/// least 5,000 transactions, since a lower count than that would indicate a
/// clear regression.
fn larger_mempool() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let transfer_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    // Start with 10 accounts with initial balances.
    let initial_sender_sks = (0..10)
        .map(|_| StacksPrivateKey::random())
        .collect::<Vec<_>>();
    let initial_sender_addrs = initial_sender_sks
        .iter()
        .map(|sk| tests::to_addr(sk))
        .collect::<Vec<_>>();

    // These 10 accounts will send to 25 accounts each, then those 260 accounts
    // will send to 25 accounts each, for a total of 6760 accounts.
    // At the end of the funding round, we want to have 6760 accounts with
    // enough balance to send 1 uSTX 25 times for each of 2 rounds of sends.
    // With a fee of 180 uSTX per send, we need each account to end up with
    // 2001 * 25 * 10 = 500_250 uSTX.
    // The 260 accounts in the middle will need to have
    // (500250 + 180) * 26 = 13_011_180 uSTX.
    // The 10 initial accounts will need to have
    // (13011180 + 180) * 26 = 338_295_360 uSTX.
    let initial_balance = 338_295_360;
    let initial_balances = initial_sender_addrs
        .iter()
        .map(|addr| (addr.clone(), initial_balance))
        .collect::<Vec<_>>();

    let num_signers = 5;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |conf, _| {
            conf.miner.mempool_walk_strategy = MemPoolWalkStrategy::NextNonceWithHighestFeeRate;
        },
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    // This will hold tuples for all of our senders, with the sender pk and
    // the nonce
    let mut senders = initial_sender_sks
        .iter()
        .map(|sk| (sk, 0))
        .collect::<Vec<_>>();

    let mempool_db_path = format!(
        "{}/nakamoto-neon/chainstate/mempool.sqlite",
        signer_test.running_nodes.conf.node.working_dir
    );
    let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;
    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();

    // Open a sqlite DB at mempool_db_path so that we can quickly add
    // transactions to the mempool.
    let mut conn = Connection::open(&mempool_db_path).unwrap();
    let db_tx = conn.transaction().unwrap();

    info!("Sending the first round of funding");
    let timer = Instant::now();
    let mut new_senders = vec![];
    for (sender_sk, nonce) in senders.iter_mut() {
        for _ in 0..25 {
            let recipient_sk = StacksPrivateKey::random();
            let recipient_addr = tests::to_addr(&recipient_sk);
            let sender_addr = tests::to_addr(sender_sk);
            let transfer_tx = make_stacks_transfer_serialized(
                sender_sk,
                *nonce,
                transfer_fee,
                chain_id,
                &recipient_addr.into(),
                13_011_180,
            );
            insert_tx_in_mempool(
                &db_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                transfer_fee,
                &tip.consensus_hash,
                &tip.canonical_stacks_tip_hash,
                tip.stacks_block_height,
            );
            *nonce += 1;
            new_senders.push(recipient_sk);
        }
    }
    db_tx.commit().unwrap();

    info!("Sending first round of funding took {:?}", timer.elapsed());

    // Wait for the first round of funding to be mined
    wait_for(120, || {
        for (sender_sk, nonce) in senders.iter() {
            let sender_addr = tests::to_addr(sender_sk);
            let account = get_account(&http_origin, &sender_addr);
            if account.nonce < *nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for first round of funding to be mined");

    info!(
        "Sending and mining first round of funding took {:?}",
        timer.elapsed()
    );

    // Add the new senders to the list of senders
    senders.extend(new_senders.iter().map(|sk| (sk, 0)));

    info!("Sending the second round of funding");
    let db_tx = conn.transaction().unwrap();
    let timer = Instant::now();
    let mut new_senders = vec![];
    for (sender_sk, nonce) in senders.iter_mut() {
        for _ in 0..25 {
            let sender_addr = tests::to_addr(sender_sk);
            let recipient_sk = StacksPrivateKey::random();
            let recipient_addr = tests::to_addr(&recipient_sk);
            let transfer_tx = make_stacks_transfer_serialized(
                sender_sk,
                *nonce,
                transfer_fee,
                chain_id,
                &recipient_addr.into(),
                500_250,
            );
            insert_tx_in_mempool(
                &db_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                transfer_fee,
                &tip.consensus_hash,
                &tip.canonical_stacks_tip_hash,
                tip.stacks_block_height,
            );
            *nonce += 1;
            new_senders.push(recipient_sk);
        }
    }
    db_tx.commit().unwrap();

    info!("Sending second round of funding took {:?}", timer.elapsed());

    // Wait for the second round of funding to be mined
    wait_for(120, || {
        for (sender_sk, nonce) in senders.iter() {
            let sender_addr = tests::to_addr(sender_sk);
            let account = get_account(&http_origin, &sender_addr);
            if account.nonce < *nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for second round of funding to be mined");

    info!(
        "Sending and mining second round of funding took {:?}",
        timer.elapsed()
    );

    // Add the new senders to the list of senders
    senders.extend(new_senders.iter().map(|sk| (sk, 0)));

    info!("Pause mining and fill the mempool with the transfers");

    // Pause block mining
    fault_injection_stall_miner();

    let timer = Instant::now();

    // Fill the mempool with the transfers
    for _ in 0..10 {
        let db_tx = conn.transaction().unwrap();
        for _ in 0..25 {
            for (sender_sk, nonce) in senders.iter_mut() {
                let sender_addr = tests::to_addr(sender_sk);
                let transfer_tx = make_stacks_transfer_serialized(
                    sender_sk,
                    *nonce,
                    transfer_fee,
                    chain_id,
                    &recipient,
                    1,
                );
                insert_tx_in_mempool(
                    &db_tx,
                    transfer_tx,
                    &sender_addr,
                    *nonce,
                    transfer_fee,
                    &tip.consensus_hash,
                    &tip.canonical_stacks_tip_hash,
                    tip.stacks_block_height,
                );
                *nonce += 1;
            }
        }
        db_tx.commit().unwrap();
    }

    info!("Sending transfers took {:?}", timer.elapsed());

    let proposed_blocks_before = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .len();

    info!("Mining transfers...");

    // Unpause block mining
    fault_injection_unstall_miner();

    // Wait for the first block to be proposed.
    wait_for(30, || {
        let proposed_blocks = signer_test
            .running_nodes
            .test_observer
            .get_mined_nakamoto_blocks()
            .len();
        Ok(proposed_blocks > proposed_blocks_before)
    })
    .expect("Timed out waiting for first block to be mined");

    let blocks = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks();
    let last_block = blocks.last().unwrap();
    info!(
        "First block contains {} transactions",
        last_block.tx_events.len()
    );

    // Wait for the first round of transfers to all be mined
    wait_for(43200, || {
        for (sender_sk, nonce) in senders.iter() {
            let sender_addr = tests::to_addr(sender_sk);
            let account = get_account(&http_origin, &sender_addr);
            if account.nonce < *nonce {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .expect("Timed out waiting for first round of transfers to be mined");

    info!("Mining first round of transfers took {:?}", timer.elapsed());
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test verifies that a a signer will send update messages to stackerdb when it updates its internal state
///
/// For a new bitcoin block arrival, the signers send a local state update message with this updated block and miner
/// For an inactive miner, the signer sends a local state update message indicating it is reverting to the prior miner
fn signers_send_state_message_updates() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    // We want the miner to be marked as inactive so signers will send an update message indicating it.
    // Therefore, set the block proposal timeout to something small enough to force a winning miner to timeout.
    let block_proposal_timeout = Duration::from_secs(20);
    let tenure_extend_wait_timeout = block_proposal_timeout;
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |signer_config| {
            signer_config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            config.miner.tenure_extend_wait_timeout = tenure_extend_wait_timeout;
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
    );

    let rl1_skip_commit_op = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let rl2_skip_commit_op = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let get_burn_consensus_hash = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .consensus_hash
    };
    let starting_peer_height = get_chain_info(&conf_1).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    rl1_skip_commit_op.set(true);

    info!("------------------------- Miner 1 Tenure Starts and Mines Block N-------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 60)
        .expect("Failed to mine BTC block followed by tenure change tx.");
    btc_blocks_mined += 1;

    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Confirm Miner 1 is the Active Miner in Update -------------------------");
    // Verify that signers first sent a bitcoin block update

    wait_for_state_machine_update(
        60,
        &get_burn_consensus_hash(),
        starting_burn_height + 1,
        Some((miner_pkh_1.clone(), starting_peer_height)),
        &miners.signer_test.signer_addresses_versions(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send a state update");

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    miners.signer_test.running_nodes.test_observer.clear();
    miners.submit_commit_miner_2(&sortdb);

    // Pause the block proposal broadcast so that miner 2 will be unable to broadcast its
    // tenure change proposal BEFORE the block_proposal_timeout and will be marked invalid.
    // Also pause miner 1's blocks so we don't go extending that tenure either
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1.clone(), miner_pk_2.clone()]);

    info!("------------------------- Miner 2 Mines an Empty Tenure B -------------------------");
    miners
        .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
        .expect("Timed out waiting for BTC block");
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner 2 won
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Confirm Miner 2 is the Active Miner -------------------------{}, {}, {miner_pkh_2}", starting_burn_height + 2, starting_peer_height);
    // We cannot confirm the height cause some signers may or may not be aware of the delayed stacks block
    wait_for_state_machine_update(
        60,
        &get_burn_consensus_hash(),
        starting_burn_height + 2,
        Some((miner_pkh_2, starting_peer_height + 1)),
        &miners.signer_test.signer_addresses_versions(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send their state update");

    miners.signer_test.running_nodes.test_observer.clear();
    info!(
        "------------------------- Wait for Miner 2 to be Marked Invalid -------------------------"
    );
    // Make sure that miner 2 gets marked invalid by not proposing a block BEFORE block_proposal_timeout
    std::thread::sleep(block_proposal_timeout.add(Duration::from_secs(1)));
    // Allow miner 2 to propose its late block and see the signer get marked malicious
    TEST_BROADCAST_PROPOSAL_STALL.set(vec![miner_pk_1]);

    info!("------------------------- Confirm Miner 1 is the Active Miner Again -------------------------");
    wait_for_state_machine_update(
        60,
        &get_burn_consensus_hash(),
        starting_burn_height + 2,
        Some((miner_pkh_1.clone(), starting_peer_height)),
        &miners.signer_test.signer_addresses_versions(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send their state update");

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(
        miners.get_peer_stacks_tip_height(),
        starting_peer_height + 1
    );
    miners.shutdown();
}

#[test]
#[ignore]
/// Verify that the mempool caching is working as expected
///
/// This test will boot to epoch 3 then pause mining and:
/// 1. Set the signers to reject all blocks
/// 2. Submit a transfer from the sender to the recipient
/// 3. Wait for this block to be proposed
/// 4. Pause mining
/// 5. Wait for block rejection
/// 6. Check the nonce cache to see if it cached the nonce (it is paused before
///    the cache is cleared).
/// 7. Set the signers to accept blocks and unpause mining
/// 8. Wait for the block to be mined
/// 9. Check the nonce cache and verify that it has correctly cached the nonce
/// 10. Submit a second transfer and wait for it to be mined
fn verify_mempool_caches() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr.clone(), (send_amt + send_fee) * 3)],
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);

    signer_test.boot_to_epoch_3();

    signer_test.mine_nakamoto_block(Duration::from_secs(60), true);

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let block_height_before = info.stacks_tip_height;

    // All signers reject all blocks
    let rejecting_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signers);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        0,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    let block = wait_for_block_proposal(
        30,
        block_height_before + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block proposal");

    // Stall the miners so that this block is not re-proposed after being rejected
    fault_injection_stall_miner();

    // Wait for rejections
    wait_for_block_rejections(
        30,
        &block.header.signer_signature_hash(),
        num_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to get expected rejections for block");

    // Check the nonce cache -- it should have the nonce cached because it will
    // only be cleared after the miner is unpaused.
    let mempool_db_path = format!(
        "{}/nakamoto-neon/chainstate/mempool.sqlite",
        signer_test.running_nodes.conf.node.working_dir
    );
    let conn = Connection::open(&mempool_db_path).unwrap();
    let result = conn
        .query_row(
            "SELECT nonce FROM nonces WHERE address = ?1;",
            [&sender_addr],
            |row| {
                let nonce: u64 = row.get(0)?;
                Ok(nonce)
            },
        )
        .expect("Failed to get nonce from cache");
    assert_eq!(result, 1);

    info!("Nonce cache has the expected nonce");

    // Set signers to accept and unpause the miners
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]);
    fault_injection_unstall_miner();

    info!("Unpausing miners and waiting for block to be mined");

    let test_observer = &signer_test.running_nodes.test_observer;

    // Wait for the block to be mined
    wait_for(60, || {
        let is_next_block = test_observer
            .get_blocks()
            .last()
            .and_then(|block| block["block_height"].as_u64())
            .map_or(false, |h| h == block_height_before + 1);

        Ok(is_next_block)
    })
    .expect("Timed out waiting for block to be mined");

    // Check the nonce cache again -- it should still have the nonce cached
    let result = conn
        .query_row(
            "SELECT nonce FROM nonces WHERE address = ?1;",
            [&sender_addr],
            |row| {
                let nonce: u64 = row.get(0)?;
                Ok(nonce)
            },
        )
        .expect("Failed to get nonce from cache");
    assert_eq!(result, 1);

    info!("Nonce cache has the expected nonce after successfully mining block");

    let transfer_tx = make_stacks_transfer_serialized(
        &sender_sk,
        1,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Waiting for the second block to be mined");
    wait_for(60, || {
        let blocks = test_observer.get_blocks();

        // Look for a block with expected height
        let Some(block) = blocks
            .iter()
            .find(|block| block["block_height"].as_u64() == Some(block_height_before + 2))
        else {
            return Ok(false); // Keep waiting if the block hasn't been observed yet
        };

        // This new block should have just the one new transfer
        let transfers_included_in_block = transfers_in_block(block);
        if transfers_included_in_block == 1 {
            Ok(true)
        } else {
            Err(format!(
                "Expected only one transfer in block, found {transfers_included_in_block}"
            ))
        }
    })
    .expect("Timed out waiting for block");

    signer_test.shutdown();
}

/// Tests that signers are able to upgrade or downgrade their active protocol version numbers based on
/// the majority of other signers current local supported version numbers
#[test]
#[ignore]
fn rollover_signer_protocol_version() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let num_signers = 5;

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    signer_test.boot_to_epoch_3();

    let conf = signer_test.running_nodes.conf.clone();

    let burnchain = conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let all_signers = signer_test.signer_test_pks();
    info!(
        "------------------------- Miner Tenure Starts and Mines Block N-------------------------"
    );
    signer_test.running_nodes.test_observer.clear();
    signer_test.mine_and_verify_confirmed_naka_block(Duration::from_secs(30), num_signers, true);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_consensus_hash = tip.consensus_hash;
    let burn_height = tip.block_height;

    info!("------------------------- Confirm Miner is the Active Miner in Update and All Signers Are Using Protocol Number {SUPPORTED_SIGNER_PROTOCOL_VERSION} -------------------------");
    // Verify that signers first sent a bitcoin block update
    wait_for_state_machine_update(
        60,
        &burn_consensus_hash,
        burn_height,
        None,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send a state update for block N");

    signer_test.running_nodes.test_observer.clear();
    let downgraded_version = SUPPORTED_SIGNER_PROTOCOL_VERSION.saturating_sub(1);
    info!("------------------------- Downgrading Signer Versions to {downgraded_version} for 20 Percent of Signers -------------------------");
    // Take a non blocking minority of signers (20%) and downgrade their version number
    let pinned_signers: Vec<_> = all_signers
        .iter()
        .take(num_signers * 2 / 10)
        .cloned()
        .collect();
    let pinned_signers_versions: HashMap<StacksPublicKey, u64> = pinned_signers
        .iter()
        .map(|signer| (signer.clone(), downgraded_version))
        .collect();
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.set(pinned_signers_versions);

    info!("------------------------- Confirm Signers Still Manage to Sign a Stacks Block With Misaligned Version Numbers -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(Duration::from_secs(30), num_signers, true);

    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_consensus_hash = tip.consensus_hash;
    let burn_height = tip.block_height;
    // Only one signer is downgraded so the active protocol version remains the same.
    wait_for_state_machine_update(
        60,
        &burn_consensus_hash,
        burn_height,
        None,
        &signer_test.signer_addresses_versions(),
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send their downgraded state update for block N+1");

    signer_test.running_nodes.test_observer.clear();
    info!("------------------------- Confirm Signer Version Downgrades Fully Once 70 percent of Signers Downgrade -------------------------");
    let pinned_signers: Vec<_> = all_signers
        .iter()
        .take(num_signers * 7 / 10)
        .cloned()
        .collect();
    let pinned_signers_versions: HashMap<StacksPublicKey, u64> = pinned_signers
        .iter()
        .map(|signer| (signer.clone(), downgraded_version))
        .collect();
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.set(pinned_signers_versions);

    // Not strictly necessary, but makes it easier to logic out if miner doesn't send a proposal until signers are on same page...
    TEST_MINE_SKIP.set(true);
    info!("------------------------- Confirm Signers Sent Downgraded State Machine Updates -------------------------");
    // Cannot use any built in functions that call mine_nakamoto_block since it expects signer updates matching the majority version and we are manually messing with these versions
    signer_test.mine_bitcoin_block();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    let burn_consensus_hash = tip.consensus_hash;
    let burn_height = tip.block_height;
    // Confirm ALL signers downgrade their supported version and then send a corresponding message in that version message
    let downgraded_versions: Vec<_> = signer_test
        .signer_addresses_versions()
        .into_iter()
        .map(|(address, _)| (address, downgraded_version))
        .collect();
    wait_for_state_machine_update(
        60,
        &burn_consensus_hash,
        burn_height,
        None,
        &downgraded_versions,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for signers to send their state update for block N+2");

    let info = signer_test.get_peer_info();
    info!("------------------------- Confirm Signers Sign The Block After Complete Downgraded Version Number -------------------------");
    TEST_MINE_SKIP.set(false);
    let expected_miner = StacksPublicKey::from_private(
        &signer_test
            .running_nodes
            .conf
            .miner
            .mining_key
            .clone()
            .unwrap(),
    );
    let block = wait_for_block_pushed_by_miner_key(
        60,
        info.stacks_tip_height + 1,
        &expected_miner,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to mine block after downgraded version number.");
    // Expect ALL signers even after downgrade to approve the proposed blocks
    wait_for_block_acceptance_from_signers(
        30,
        &block.header.signer_signature_hash(),
        &all_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to confirm all signers accepted last block");

    info!("------------------------- Reset All Signers to {SUPPORTED_SIGNER_PROTOCOL_VERSION} -------------------------");
    TEST_PIN_SUPPORTED_SIGNER_PROTOCOL_VERSION.set(HashMap::new());
    signer_test.running_nodes.test_observer.clear();
    info!("------------------------- Confirm Signers Sign The Block After Upgraded Version Number -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(Duration::from_secs(30), num_signers, true);

    signer_test.shutdown();
}

#[test]
#[ignore]
/// Tests that a miner keeps their stackerdb chunk versions across tenures.
/// This test sets up a proxy between two miners, which allows the test to disconnect the miners
///  from each other temporarily to allow their stackerdbs to temporarily get out of sync.
fn miner_stackerdb_version_rollover() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 6;
    let num_txs = 20;

    // Record where node 1 and 2 want to bind, so that the proxy can bind
    //  there instead.
    let mut node_1_p2p_bind = "".to_string();
    let mut node_2_p2p_bind = "".to_string();

    // These are the proxy upstreams, which are where we will tell the
    //  nodes to bind to.
    let node_1_p2p_rebind = "127.0.0.1:40402";
    let node_2_p2p_rebind = "127.0.0.1:40502";

    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        num_txs,
        |_| {},
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
            config.miner.block_rejection_timeout_steps =
                [(0, Duration::from_secs(120))].into_iter().collect();
            node_1_p2p_bind = config.node.p2p_bind.clone();
            // change the bind to the proxy upstream
            config.node.p2p_bind = node_1_p2p_rebind.to_string();
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
            node_2_p2p_bind = config.node.p2p_bind.clone();
            // change the bind to the proxy upstream
            config.node.p2p_bind = node_2_p2p_rebind.to_string();
        },
    );
    let node_1_p2p_bind_port = std::net::SocketAddr::from_str(&node_1_p2p_bind)
        .unwrap()
        .port();
    let node_2_p2p_bind_port = std::net::SocketAddr::from_str(&node_2_p2p_bind)
        .unwrap()
        .port();

    let proxy_1 = TestProxy {
        bind_port: node_1_p2p_bind_port,
        forward_port: 40402,
        drop_control: Arc::new(Mutex::new(false)),
        keep_running: Arc::new(Mutex::new(true)),
    };

    let proxy_2 = TestProxy {
        bind_port: node_2_p2p_bind_port,
        forward_port: 40502,
        drop_control: Arc::new(Mutex::new(false)),
        keep_running: Arc::new(Mutex::new(true)),
    };

    proxy_1.spawn();
    proxy_2.spawn();

    let (conf_1, conf_2) = miners.get_node_configs();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();
    miners.signer_test.running_nodes.test_observer.clear();

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");
    // Make sure Miner 2 cannot win a sortition at first.
    miners.pause_commits_miner_2();

    miners.boot_to_epoch_3();

    let burnchain = conf_1.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");

    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    miners.pause_commits_miner_1();

    info!("------------------------- Miner 1 Wins Normal Tenure A -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!("------------------------- Miner 1 Mines 10 more Blocks -------------------------");

    for _i in 0..10 {
        miners
            .send_and_mine_transfer_tx(30)
            .expect("Failed to mine tx");
    }

    let mut max_chunk: Option<StackerDBChunkData> = None;
    for chunks in miners
        .signer_test
        .running_nodes
        .test_observer
        .get_stackerdb_chunks()
        .into_iter()
    {
        if !chunks.contract_id.is_boot() || chunks.contract_id.name.as_str() != MINERS_NAME {
            continue;
        }
        for chunk in chunks.modified_slots.into_iter() {
            let pkh = Hash160::from_node_public_key(&chunk.recover_pk().unwrap());
            if pkh != miner_pkh_1 {
                continue;
            }
            match &mut max_chunk {
                Some(prior_chunk) => {
                    if prior_chunk.slot_version < chunk.slot_version {
                        *prior_chunk = chunk;
                    }
                }
                None => max_chunk = Some(chunk),
            }
        }
    }
    let max_chunk = max_chunk.expect("Should have found a miner stackerdb message from Miner 1");

    info!("------------------------- Miner 2 Wins Tenure B -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block");
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Miner 2 Wins Tenure C -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block");
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("------------------------- Miner 2 Wins Tenure D -------------------------");
    miners.submit_commit_miner_2(&sortdb);

    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block");
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    info!("----------------- Miner 1 Submits Block Commit ------------------");
    miners.submit_commit_miner_1(&sortdb);

    info!("------------------------- Miner 1 Wins Tenure E -------------------------");
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Maximum miner 1 slot version: {} ------------------------",
        max_chunk.slot_version
    );

    let mut stackerdb = StackerDBSession::new(
        &conf_2.node.rpc_bind,
        boot_code_id(MINERS_NAME, false),
        conf_2.miner.stackerdb_timeout,
    );

    let proposals_before = miners.get_primary_proposals_submitted().get();

    *proxy_1.drop_control.lock().unwrap() = true;
    *proxy_2.drop_control.lock().unwrap() = true;

    let (_, _sent_nonce) = miners.send_transfer_tx();

    wait_for(30, || {
        let proposals = miners.get_primary_proposals_submitted().get();
        Ok(proposals > proposals_before)
    })
    .unwrap();

    info!("------------------------- Broadcasting max chunk ------------------------");
    stackerdb
        .put_chunk(&max_chunk)
        .expect("Failed to broadcast the max slot version chunk");

    *proxy_1.drop_control.lock().unwrap() = false;
    *proxy_2.drop_control.lock().unwrap() = false;

    miners
        .send_and_mine_transfer_tx(30)
        .expect("Failed to mine tx");

    miners.shutdown();
}

/// Tests that the active signer protocol version is set to the lowest common denominator
#[test]
#[ignore]
fn multiversioned_signer_protocol_version_calculation() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::random();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let deploy_fee = 1000000;
    let call_fee = 1000;
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr,
            (send_amt + send_fee) * 10 + deploy_fee + call_fee,
        )],
        |signer_config| {
            // We don't want the miner of the "inactive" sortition before the flash block
            //  to get timed out.
            signer_config.block_proposal_timeout = Duration::from_secs(600);

            let signer_version = match signer_config.endpoint.port() % num_signers as u16 {
                0 | 1 => 0, // first two -> version 0
                2 | 3 => 1, // next two -> version 1
                _ => 2,     // last ones  -> version 2
            };
            signer_config.supported_signer_protocol_version = signer_version;
        },
        |node_config, _| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.miner.replay_transactions = true;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();
    // Pause the miner to enforce exactly one proposal and to ensure it isn't just rejected with no consensus
    info!("------------------------- Pausing Mining -------------------------");
    TEST_MINE_SKIP.set(true);
    signer_test.running_nodes.test_observer.clear();
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // In the next block, the miner should win the tenure and mine a stacks block
    let peer_info_before = signer_test.get_peer_info();

    info!("------------------------- Mining Burn Block for Tenure A -------------------------");
    next_block_and(
        &signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let peer_info = signer_test.get_peer_info();
            Ok(peer_info.burn_block_height > peer_info_before.burn_block_height)
        },
    )
    .unwrap();
    let peer_info_after = signer_test.get_peer_info();
    // All signers will view the active version as 0
    let signer_addresses: Vec<_> = signer_test
        .signer_addresses_versions()
        .into_iter()
        .map(|(address, _version)| (address, 0u64))
        .collect();

    info!("------------------------- Waiting for Signer Updates with Version 0-------------------------");
    // Make sure all signers are on the same page before proposing a block so its accepted
    wait_for_state_machine_update(
        30,
        &peer_info_after.pox_consensus,
        peer_info_after.burn_block_height,
        None,
        &signer_addresses,
        &signer_test.running_nodes.test_observer,
    )
    .unwrap();

    info!("------------------------- Resuming Mining of Tenure Start Block for Tenure A -------------------------");
    signer_test.running_nodes.test_observer.clear();
    TEST_MINE_SKIP.set(false);
    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > peer_info_before.stacks_tip_height)
    })
    .unwrap();

    info!("------------------------- Verifying Signers ONLY Sends Acceptances -------------------------");
    wait_for(30, || {
        let mut nmb_accept = 0;
        let stackerdb_events = signer_test
            .running_nodes
            .test_observer
            .get_stackerdb_chunks();
        for chunk in stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
        {
            let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                .expect("Failed to deserialize SignerMessage");
            let SignerMessage::BlockResponse(response) = message else {
                continue;
            };
            assert!(
                matches!(response, BlockResponse::Accepted(_)),
                "Should have only received acceptances"
            );
            nmb_accept += 1;
        }
        Ok(nmb_accept == num_signers)
    })
    .unwrap();
    signer_test.shutdown();
}

/// This is a test for backwards compatibility regarding
/// how contracts with an undefined top-level variable are handled.
///
/// Critically, we want to ensure that the cost of the block, along with
/// the resulting block hash, are the same.
#[test]
#[ignore]
fn contract_with_undefined_variable_compat() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::from_seed("sender_1".as_bytes());
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let deploy_fee = 1000000;
    let call_fee = 1000;
    let signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new_with_config_modifications_and_snapshot(
            num_signers,
            vec![(
                sender_addr.clone(),
                (send_amt + send_fee) * 10 + deploy_fee + call_fee,
            )],
            |c| {
                c.validate_with_replay_tx = true;
            },
            |node_config, _| {
                node_config.miner.block_commit_delay = Duration::from_secs(1);
                node_config.miner.replay_transactions = true;
                node_config.miner.activated_vrf_key_path =
                    Some(format!("{}/vrf_key", node_config.node.working_dir));
            },
            None,
            None,
            Some(function_name!()),
        );

    if signer_test.bootstrap_snapshot() {
        signer_test.shutdown_and_snapshot();
        return;
    }

    info!("------------------------- Beginning test -------------------------");

    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let (txid, deploy_nonce) = signer_test
        .submit_contract_deploy(&sender_sk, deploy_fee, "foo", "undefined-var")
        .expect("Failed to submit contract deploy");

    signer_test
        .wait_for_nonce_increase(&sender_addr, deploy_nonce)
        .expect("Failed to wait for nonce increase");

    let blocks = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks();

    let block = blocks.last().unwrap();

    let tx_event = block
        .tx_events
        .iter()
        .find(|event| event.txid().to_hex() == txid)
        .expect("Failed to find deploy event");

    info!("Tx event: {:?}", tx_event);

    let TransactionEvent::Success(success_event) = tx_event else {
        panic!("Failed: Expected success event");
    };

    let block_cost = block.cost.clone();
    let expected_cost = ExecutionCost {
        runtime: 346,
        write_length: 2,
        write_count: 1,
        read_length: 1,
        read_count: 1,
    };

    assert_eq!(block_cost, expected_cost.clone());
    assert_eq!(success_event.execution_cost, expected_cost);

    signer_test.shutdown();
}

/// Ensure that signers can immediately start participating in signing when starting up
/// after crashing mid reward cycle.
///
/// Test scenario:
/// - Miner A wins Tenure A
/// - Miner A proposes block N (Tenure Change)
/// - All signers sign block N.
/// - Miner B wins Tenure B.
/// - Shutdown one signer.
/// - Shutdown signer is restarted.
/// - Miner B proposes block N+1 (TenureChange).
/// - All signers sign the block without issue
/// -> Verifies that updates are loaded from signerdb on init
/// - Same signer is shutdown.
/// - Shutdown signers db is cleared.
/// - Signer is restarted.
/// - Miner B proposes block N+2 (Transfer).
/// - All signers including the restarted signer sign block N+2
/// -> Verifies that updates are loaded from stackerdb on init
#[test]
#[ignore]
fn signer_loads_stackerdb_updates_on_startup() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let mut miners = MultipleMinerTest::new(num_signers, 1);

    let skip_commit_op_rl1 = miners
        .signer_test
        .running_nodes
        .counters
        .naka_skip_commit_op
        .clone();
    let skip_commit_op_rl2 = miners.rl2_counters.naka_skip_commit_op.clone();

    let (conf_1, _conf_2) = miners.get_node_configs();
    let (miner_pk_1, miner_pk_2) = miners.get_miner_public_keys();
    let (miner_pkh_1, miner_pkh_2) = miners.get_miner_public_key_hashes();

    let all_signers = miners.signer_test.signer_test_pks();

    // Pause Miner 2's commits to ensure Miner 1 wins the first sortition.
    skip_commit_op_rl2.set(true);
    miners.boot_to_epoch_3();

    let sortdb = conf_1.get_burnchain().open_sortition_db(true).unwrap();

    info!("Pausing miner 1's block commit submissions");
    skip_commit_op_rl1.set(true);

    info!("------------------------- Miner A Wins Tenure A -------------------------");
    // Let's not mine anything until we see consensus on new tenure start.
    TEST_MINE_SKIP.set(true);
    miners.signer_test.mine_bitcoin_block();
    let chain_after = get_chain_info(&conf_1);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &miners.signer_test.signer_addresses_versions(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for the signers to update their state");
    verify_sortition_winner(&sortdb, &miner_pkh_1);

    info!(
        "------------------------- Miner A Mines Block N (Tenure Change) -------------------------"
    );
    TEST_MINE_SKIP.set(false);
    let block_n = wait_for_block_pushed_by_miner_key(
        30,
        chain_after.stacks_tip_height + 1,
        &miner_pk_1,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to mine block N");
    wait_for_block_acceptance_from_signers(
        30,
        &block_n.header.signer_signature_hash(),
        &all_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Not all signers accepted the block");

    info!("------------------------- Miner B Wins Tenure B -------------------------");
    miners.submit_commit_miner_2(&sortdb);
    // Let's not mine anything until we see consensus on new tenure start.
    TEST_MINE_SKIP.set(true);
    miners.signer_test.mine_bitcoin_block();
    let chain_after = get_chain_info(&conf_1);
    wait_for_state_machine_update_by_miner_tenure_id(
        30,
        &chain_after.pox_consensus,
        &miners.signer_test.signer_addresses_versions(),
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Signers failed to update their state");
    verify_sortition_winner(&sortdb, &miner_pkh_2);

    let stop_idx = 0;
    info!("------------------------- Shutdown Signer at idx {stop_idx} -------------------------");
    let stopped_signer_config = miners.signer_test.stop_signer(stop_idx);
    info!("------------------------- Restart Signer at idx {stop_idx} -------------------------");
    miners
        .signer_test
        .restart_signer(stop_idx, stopped_signer_config);

    info!("------------------------- Miner B Mines Block N+1 (Tenure Change) -------------------------");
    TEST_MINE_SKIP.set(false);
    let block_n_1 = wait_for_block_pushed_by_miner_key(
        30,
        chain_after.stacks_tip_height + 1,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to mine block N+1");
    wait_for_block_acceptance_from_signers(
        30,
        &block_n_1.header.signer_signature_hash(),
        &all_signers,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Not all signers accepted the block");

    info!("------------------------- Shutdown Signer at idx {stop_idx} -------------------------");
    let stopped_signer_config = miners.signer_test.stop_signer(stop_idx);
    {
        let mut signer_db = SignerDb::new(stopped_signer_config.db_path.clone()).unwrap();
        signer_db
            .clear_state_machine_updates()
            .expect("Failed to clear state machine updates");
    }
    info!("------------------------- Restart Signer at idx {stop_idx} -------------------------");
    miners
        .signer_test
        .restart_signer(stop_idx, stopped_signer_config);

    // Wait until signer boots up BEFORE proposing the next block
    miners.signer_test.wait_for_registered();
    info!("------------------------- Miner B Mines Block N+2 (Transfer) -------------------------");
    let (accepting, ignoring) = all_signers.split_at(4);
    // Make some of the signers ignore so that we CANNOT advance without approval from the restarted signer (its at index 0)
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignoring.into());
    miners.send_transfer_tx();
    let block_n_2 = wait_for_block_pushed_by_miner_key(
        30,
        chain_after.stacks_tip_height + 2,
        &miner_pk_2,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Failed to mine block N+2");
    wait_for_block_acceptance_from_signers(
        30,
        &block_n_2.header.signer_signature_hash(),
        &accepting,
        &miners.signer_test.running_nodes.test_observer,
    )
    .expect("Not all signers accepted the block");

    info!("------------------------- Shutdown -------------------------");
    miners.shutdown();
}

// Basic test to ensure that signers will not issue a signature over a block proposal unless
// a threshold number of signers have pre-committed to sign.
#[test]
#[ignore]
fn signers_do_not_commit_unless_threshold_precommitted() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 20;

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();

    signer_test.boot_to_epoch_3();

    // Make sure that more than 30% of signers are set to ignore any incoming proposals so that consensus is not reached
    // on pre-commit round.
    let (ignore_slice, pre_commit_slice) = all_signers.split_at(all_signers.len() / 2);
    let ignore_signers: Vec<_> = ignore_slice.to_vec();
    let pre_commit_signers: Vec<_> = pre_commit_slice.to_vec();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(ignore_signers);
    signer_test.running_nodes.test_observer.clear();
    let blocks_before = signer_test
        .running_nodes
        .test_observer
        .get_mined_nakamoto_blocks()
        .len();
    let height_before = signer_test.get_peer_info().stacks_tip_height;
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        30,
        || {
            Ok(signer_test
                .running_nodes
                .test_observer
                .get_mined_nakamoto_blocks()
                .len()
                > blocks_before)
        },
    )
    .unwrap();

    let proposal = wait_for_block_proposal(
        30,
        height_before + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for block proposal");
    let hash = proposal.header.signer_signature_hash();
    wait_for_block_pre_commits_from_signers(
        30,
        &hash,
        &pre_commit_signers,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Timed out waiting for pre-commits");
    assert!(
        wait_for(30, || {
            for chunk in signer_test
                .running_nodes
                .test_observer
                .get_stackerdb_chunks()
                .into_iter()
                .flat_map(|chunk| chunk.modified_slots)
            {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                if let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message {
                    if accepted.signer_signature_hash == hash {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        })
        .is_err(),
        "Should not have found a single block accept for the block hash {hash}"
    );

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}

// Test to ensure a signer operating a two phase commit signer will treat
// signatures from other signers as pre-commits if it has yet to see their pre-commits
// for that block. This enables upgraded pre-commit signers to operate as they should
// with unupgraded signers or if the pre-commit message was somehow dropped.
#[test]
#[ignore]
fn signers_treat_signatures_as_precommits() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 3;

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let miner_sk = signer_test
        .running_nodes
        .conf
        .miner
        .mining_key
        .clone()
        .unwrap();
    let miner_pk = StacksPublicKey::from_private(&miner_sk);
    let all_signers = signer_test.signer_test_pks();

    signer_test.boot_to_epoch_3();

    let operating_signer = all_signers[0].clone();
    let disabled_signers = all_signers[1..].to_vec();

    // Disable a majority of signers so that we can inject our own custom signatures to simulate an un-upgraded signer.

    info!(
        "------------------------- Disabling {} Signers -------------------------",
        disabled_signers.len()
    );

    TEST_IGNORE_ALL_BLOCK_PROPOSALS.set(disabled_signers.clone());
    let peer_info = signer_test.get_peer_info();

    info!(
        "------------------------- Trigger Tenure Change Block Proposal -------------------------"
    );
    signer_test.mine_bitcoin_block();

    let block_proposal = wait_for_block_proposal(
        30,
        peer_info.stacks_tip_height + 1,
        &miner_pk,
        &signer_test.running_nodes.test_observer,
    )
    .expect("Failed to propose a new tenure block");

    info!(
        "------------------------- Verify Only Operating Signer Issues Pre-Commit -------------------------"
    );

    let signer_signature_hash = block_proposal.header.signer_signature_hash();
    wait_for_block_pre_commits_from_signers(
        30,
        &signer_signature_hash,
        &[operating_signer.clone()],
        &signer_test.running_nodes.test_observer,
    )
    .expect("Operating signer did not send a pre-commit");
    assert!(
        wait_for_block_pre_commits_from_signers(
            10,
            &signer_signature_hash,
            &disabled_signers,
            &signer_test.running_nodes.test_observer
        )
        .is_err(),
        "Disabled signers should not have issued any pre-commits"
    );

    signer_test.running_nodes.test_observer.clear();

    let reward_cycle = signer_test.get_current_reward_cycle();
    // Do not send a signature for the operating signer. Just for the disabled. The operating signer should then issue as signature only after the other 2 signers send their signature
    // Only the operating signer should send a block pre commit.
    for (i, signer_private_key) in signer_test
        .signer_stacks_private_keys
        .iter()
        .enumerate()
        .skip(1)
    {
        let signature = signer_private_key
            .sign(signer_signature_hash.bits())
            .expect("Failed to sign block");
        let accepted = BlockResponse::accepted(
            block_proposal.header.signer_signature_hash(),
            signature,
            get_epoch_time_secs().saturating_add(u64::MAX),
            get_epoch_time_secs().saturating_add(u64::MAX),
        );

        let signers_contract_id =
            MessageSlotID::BlockResponse.stacker_db_contract(false, reward_cycle);
        let mut session = StackerDBSession::new(
            &signer_test.running_nodes.conf.node.rpc_bind,
            signers_contract_id,
            signer_test.running_nodes.conf.miner.stackerdb_timeout,
        );
        let message = SignerMessage::BlockResponse(accepted);

        // Manually submit signature
        let mut accepted = false;
        let mut version = 0;
        let start = Instant::now();
        info!(
            "------------------------- Manually Submitting Signer {i} Block Approval ------------------------",
        );
        // Don't know which slot corresponds to which signer, so just try all of them :)
        let mut slot_id = 0;
        while !accepted {
            let mut chunk = StackerDBChunkData::new(slot_id, version, message.serialize_to_vec());
            chunk
                .sign(&signer_private_key)
                .expect("Failed to sign message chunk");
            debug!("Produced a signature: {:?}", chunk.sig);
            let result = session.put_chunk(&chunk).expect("Failed to put chunk");
            accepted = result.accepted;
            if !accepted && result.code.unwrap() == StackerDBErrorCodes::BadSigner as u32 {
                slot_id += 1;
                assert!(
                    slot_id < num_signers as u32,
                    "Failed to find a matching slot id"
                );
                continue;
            }
            version += 1;
            debug!("Test Put Chunk ACK: {result:?}");
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "Timed out waiting for signer signature to be accepted"
            );
        }
        if i == 1 {
            // Signer will not have seen enough signatures (fake pre-commits) to reach threshold
            info!("------------------------- Verifying Operating Signer Does NOT Issue a Signature ------------------------");
        } else {
            // Signer will have seen enough signatures (fake pre-commits) to reach threshold
            info!("------------------------- Verifying Operating Signer Issues a Signature ------------------------");
        }
        let result = wait_for(20, || {
            for chunk in signer_test
                .running_nodes
                .test_observer
                .get_stackerdb_chunks()
                .into_iter()
                .flat_map(|chunk| chunk.modified_slots)
            {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                let SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) = message
                else {
                    continue;
                };
                assert_eq!(
                    accepted.signer_signature_hash, signer_signature_hash,
                    "Got an acceptance message for an unknown proposal"
                );
                let signed_by_operating_signer = operating_signer
                    .verify(signer_signature_hash.bits(), &accepted.signature)
                    .unwrap();
                if i == 1 {
                    assert!(!signed_by_operating_signer, "The operating signer should only issue a signature once it sees BOTH signatures from the other signers");
                } else if signed_by_operating_signer {
                    return Ok(true);
                }
            }
            Ok(false)
        });
        // If this is the first iteration of the loop (which starts from 1 since we skipped), the operating signer should do nothing (has yet to reach the threshold)
        if i == 1 {
            assert!(
                result.is_err(),
                "We saw a signature from the operating signer before our other two signers issued their signatures!"
            );
        } else {
            assert!(
                result.is_ok(),
                "We never saw our operating signer issue a signature!"
            );
        }
    }

    info!("------------------------- Ensure Chain Advances -------------------------");

    wait_for(30, || {
        Ok(signer_test.get_peer_info().stacks_tip_height > peer_info.stacks_tip_height)
    })
    .expect("We failed to mine the tenure change block");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}
