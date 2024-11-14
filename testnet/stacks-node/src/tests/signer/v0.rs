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
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::vm::types::PrincipalData;
use clarity::vm::StacksEpoch;
use libsigner::v0::messages::{
    BlockRejection, BlockResponse, MessageSlotID, MinerSlotID, RejectCode, SignerMessage,
};
use libsigner::{BlockProposal, SignerSession, StackerDBSession, VERSION_STRING};
use stacks::address::AddressHashMode;
use stacks::burnchains::Txid;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::burn::operations::LeaderBlockCommitOp;
use stacks::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::chainstate::stacks::boot::MINERS_NAME;
use stacks::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo};
use stacks::chainstate::stacks::{StacksTransaction, TenureChangeCause, TransactionPayload};
use stacks::codec::StacksMessageCodec;
use stacks::core::{StacksEpochId, CHAIN_ID_TESTNET};
use stacks::libstackerdb::StackerDBChunkData;
use stacks::net::api::getsigner::GetSignerResponse;
use stacks::net::api::postblock_proposal::{ValidateRejectCode, TEST_VALIDATE_STALL};
use stacks::net::relay::fault_injection::set_ignore_block;
use stacks::types::chainstate::{StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey};
use stacks::types::PublicKey;
use stacks::util::hash::{hex_bytes, Hash160, MerkleHashFunc};
use stacks::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use stacks::util_lib::boot::boot_code_id;
use stacks::util_lib::signed_structured_data::pox4::{
    make_pox_4_signer_key_signature, Pox4SignatureTopic,
};
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::TrieHash;
use stacks_common::util::sleep_ms;
use stacks_signer::chainstate::{ProposalEvalConfig, SortitionsView};
use stacks_signer::client::{SignerSlotID, StackerDB};
use stacks_signer::config::{build_signer_config_tomls, GlobalConfig as SignerConfig, Network};
use stacks_signer::v0::signer::{
    TEST_IGNORE_ALL_BLOCK_PROPOSALS, TEST_PAUSE_BLOCK_BROADCAST, TEST_REJECT_ALL_BLOCK_PROPOSAL,
    TEST_SKIP_BLOCK_BROADCAST,
};
use stacks_signer::v0::SpawnedSigner;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use super::SignerTest;
use crate::config::{EventKeyType, EventObserverConfig};
use crate::event_dispatcher::MinedNakamotoBlockEvent;
use crate::nakamoto_node::miner::{
    TEST_BLOCK_ANNOUNCE_STALL, TEST_BROADCAST_STALL, TEST_MINE_STALL,
};
use crate::nakamoto_node::sign_coordinator::TEST_IGNORE_SIGNERS;
use crate::neon::Counters;
use crate::run_loop::boot_nakamoto;
use crate::tests::nakamoto_integrations::{
    boot_to_epoch_25, boot_to_epoch_3_reward_set, next_block_and, next_block_and_controller,
    next_block_and_process_new_stacks_block, setup_epoch_3_reward_set, wait_for,
    POX_4_DEFAULT_STACKER_BALANCE, POX_4_DEFAULT_STACKER_STX_AMT,
};
use crate::tests::neon_integrations::{
    get_account, get_chain_info, get_chain_info_opt, next_block_and_wait,
    run_until_burnchain_height, submit_tx, submit_tx_fallible, test_observer,
};
use crate::tests::{self, gen_random_port, make_stacks_transfer};
use crate::{nakamoto_node, BitcoinRegtestController, BurnchainController, Config, Keychain};

impl SignerTest<SpawnedSigner> {
    /// Run the test until the first epoch 2.5 reward cycle.
    /// Will activate pox-4 and register signers for the first full Epoch 2.5 reward cycle.
    fn boot_to_epoch_25_reward_cycle(&mut self) {
        boot_to_epoch_25(
            &self.running_nodes.conf,
            &self.running_nodes.blocks_processed,
            &mut self.running_nodes.btc_regtest_controller,
        );

        next_block_and_wait(
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
        );

        let http_origin = format!("http://{}", &self.running_nodes.conf.node.rpc_bind);
        let lock_period = 12;

        let epochs = self.running_nodes.conf.burnchain.epochs.clone().unwrap();
        let epoch_25 =
            &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch25).unwrap()];
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
                tests::to_addr(stacker_sk).bytes,
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
            let stacking_tx = tests::make_contract_call(
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
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
        );
        next_block_and_wait(
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
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
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
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
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
        );
        self.wait_for_registered(30);
        debug!("Signers initialized");

        let current_burn_block_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        info!("At burn block height {current_burn_block_height}. Ready to mine the first Epoch 2.5 reward cycle!");
    }

    /// Run the test until the epoch 3 boundary
    fn boot_to_epoch_3(&mut self) {
        boot_to_epoch_3_reward_set(
            &self.running_nodes.conf,
            &self.running_nodes.blocks_processed,
            &self.signer_stacks_private_keys,
            &self.signer_stacks_private_keys,
            &mut self.running_nodes.btc_regtest_controller,
            Some(self.num_stacking_cycles),
        );
        info!("Waiting for signer set calculation.");
        // Make sure the signer set is calculated before continuing or signers may not
        // recognize that they are registered signers in the subsequent burn block event
        let reward_cycle = self.get_current_reward_cycle() + 1;
        wait_for(30, || {
            Ok(self
                .stacks_client
                .get_reward_set_signers(reward_cycle)
                .expect("Failed to check if reward set is calculated")
                .map(|reward_set| {
                    debug!("Signer set: {reward_set:?}");
                })
                .is_some())
        })
        .expect("Timed out waiting for reward set calculation");
        info!("Signer set calculated");

        // Manually consume one more block to ensure signers refresh their state
        info!("Waiting for signers to initialize.");
        next_block_and_wait(
            &mut self.running_nodes.btc_regtest_controller,
            &self.running_nodes.blocks_processed,
        );
        self.wait_for_registered(30);
        info!("Signers initialized");

        self.run_until_epoch_3_boundary();
        wait_for(30, || {
            Ok(get_chain_info_opt(&self.running_nodes.conf).is_some())
        })
        .expect("Timed out waiting for network to restart after 3.0 boundary reached");

        // Wait until we see the first block of epoch 3.0.
        // Note, we don't use `nakamoto_blocks_mined` counter, because there
        // could be other miners mining blocks.
        let height_before = get_chain_info(&self.running_nodes.conf).stacks_tip_height;
        info!("Waiting for first Nakamoto block: {}", height_before + 1);
        self.mine_nakamoto_block(Duration::from_secs(30));
        wait_for(30, || {
            Ok(get_chain_info(&self.running_nodes.conf).stacks_tip_height > height_before)
        })
        .expect("Timed out waiting for first Nakamoto block after 3.0 boundary");
        info!("Ready to mine Nakamoto blocks!");
    }

    // Only call after already past the epoch 3.0 boundary
    fn mine_and_verify_confirmed_naka_block(&mut self, timeout: Duration, num_signers: usize) {
        info!("------------------------- Try mining one block -------------------------");

        let reward_cycle = self.get_current_reward_cycle();

        self.mine_nakamoto_block(timeout);

        // Verify that the signers accepted the proposed block, sending back a validate ok response
        let proposed_signer_signature_hash = self
            .wait_for_validate_ok_response(timeout)
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
        &mut self,
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
            self.mine_and_verify_confirmed_naka_block(timeout, num_signers);
        }
    }

    /// Propose an invalid block to the signers
    fn propose_block(&mut self, block: NakamotoBlock, timeout: Duration) {
        let miners_contract_id = boot_code_id(MINERS_NAME, false);
        let mut session =
            StackerDBSession::new(&self.running_nodes.conf.node.rpc_bind, miners_contract_id);
        let burn_height = self
            .running_nodes
            .btc_regtest_controller
            .get_headers_height();
        let reward_cycle = self.get_current_reward_cycle();
        let message = SignerMessage::BlockProposal(BlockProposal {
            block,
            burn_height,
            reward_cycle,
        });
        let miner_sk = self
            .running_nodes
            .conf
            .miner
            .mining_key
            .expect("No mining key");
        // Submit the block proposal to the miner's slot
        let mut accepted = false;
        let mut version = 0;
        let slot_id = MinerSlotID::BlockProposal.to_u8() as u32;
        let start = Instant::now();
        debug!("Proposing invalid block to signers");
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
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    signer_test.boot_to_epoch_3();
    let short_timeout = Duration::from_secs(30);

    info!("------------------------- Send Block Proposal To Signers -------------------------");
    let proposal_conf = ProposalEvalConfig {
        first_proposal_burn_block_timing: Duration::from_secs(0),
        block_proposal_timeout: Duration::from_secs(100),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    // First propose a block to the signers that does not have the correct consensus hash or BitVec. This should be rejected BEFORE
    // the block is submitted to the node for validation.
    let block_signer_signature_hash_1 = block.header.signer_signature_hash();
    signer_test.propose_block(block.clone(), short_timeout);

    // Wait for the first block to be mined successfully so we have the most up to date sortition view
    signer_test.wait_for_validate_ok_response(short_timeout);

    // Propose a block to the signers that passes initial checks but will be rejected by the stacks node
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.consensus_hash;
    block.header.chain_length = 35; // We have mined 35 blocks so far.

    let block_signer_signature_hash_2 = block.header.signer_signature_hash();
    signer_test.propose_block(block, short_timeout);

    info!("------------------------- Test Block Proposal Rejected -------------------------");
    // Verify the signers rejected the second block via the endpoint
    let reject =
        signer_test.wait_for_validate_reject_response(short_timeout, block_signer_signature_hash_2);
    assert!(matches!(
        reject.reason_code,
        ValidateRejectCode::UnknownParent
    ));

    let start_polling = Instant::now();
    let mut found_signer_signature_hash_1 = false;
    let mut found_signer_signature_hash_2 = false;
    while !found_signer_signature_hash_1 && !found_signer_signature_hash_2 {
        std::thread::sleep(Duration::from_secs(1));
        let chunks = test_observer::get_stackerdb_chunks();
        for chunk in chunks.into_iter().flat_map(|chunk| chunk.modified_slots) {
            let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
            else {
                continue;
            };
            if let SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                reason: _reason,
                reason_code,
                signer_signature_hash,
                ..
            })) = message
            {
                if signer_signature_hash == block_signer_signature_hash_1 {
                    found_signer_signature_hash_1 = true;
                    assert!(matches!(reason_code, RejectCode::SortitionViewMismatch));
                } else if signer_signature_hash == block_signer_signature_hash_2 {
                    found_signer_signature_hash_2 = true;
                    assert!(matches!(reason_code, RejectCode::ValidationFailed(_)));
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
    *nakamoto_node::miner::TEST_SKIP_P2P_BROADCAST
        .lock()
        .unwrap() = Some(true);

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let timeout = Duration::from_secs(30);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine and Verify Confirmed Nakamoto Block -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers);

    // Test prometheus metrics response
    #[cfg(feature = "monitoring_prom")]
    {
        wait_for(30, || {
            let metrics_response = signer_test.get_signer_metrics();

            // Because 5 signers are running in the same process, the prometheus metrics
            // are incremented once for every signer. This is why we expect the metric to be
            // `10`, even though there are only two blocks proposed.
            let expected_result_1 =
                format!("stacks_signer_block_proposals_received {}", num_signers * 2);
            let expected_result_2 = format!(
                "stacks_signer_block_responses_sent{{response_type=\"accepted\"}} {}",
                num_signers * 2
            );
            Ok(metrics_response.contains(&expected_result_1)
                && metrics_response.contains(&expected_result_2))
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
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
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
fn forked_tenure_invalid() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }
    let result = forked_tenure_testing(Duration::from_secs(5), Duration::from_secs(7), false);

    assert_ne!(
        result.tip_b.index_block_hash(),
        result.tip_a.index_block_hash()
    );
    assert_eq!(
        result.tip_b.index_block_hash(),
        result.tip_c.index_block_hash()
    );
    assert_ne!(result.tip_c, result.tip_a);

    // Block B was built atop block A
    assert_eq!(
        result.tip_b.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_b.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted, so it should be built off of Block A
    assert_eq!(
        result.mined_c.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );
    assert_ne!(
        result
            .tip_c
            .anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .signer_signature_hash(),
        result.mined_c.signer_signature_hash,
        "Mined block during tenure C should not have become the chain tip"
    );

    assert!(result.tip_c_2.is_none());
    assert!(result.mined_c_2.is_none());

    // Tenure D should continue progress
    assert_ne!(result.tip_c, result.tip_d);
    assert_ne!(
        result.tip_b.index_block_hash(),
        result.tip_d.index_block_hash()
    );
    assert_ne!(result.tip_a, result.tip_d);

    // Tenure D builds off of Tenure B
    assert_eq!(
        result.tip_d.stacks_block_height,
        result.tip_b.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_d.parent_block_id,
        result.tip_b.index_block_hash().to_string()
    );
}

#[test]
#[ignore]
fn forked_tenure_okay() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let result = forked_tenure_testing(Duration::from_secs(360), Duration::from_secs(0), true);

    assert_ne!(result.tip_b, result.tip_a);
    assert_ne!(result.tip_b, result.tip_c);
    assert_ne!(result.tip_c, result.tip_a);

    // Block B was built atop block A
    assert_eq!(
        result.tip_b.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_b.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    // Block C was built AFTER Block B was built, but BEFORE it was broadcasted, so it should be built off of Block A
    assert_eq!(
        result.tip_c.stacks_block_height,
        result.tip_a.stacks_block_height + 1
    );
    assert_eq!(
        result.mined_c.parent_block_id,
        result.tip_a.index_block_hash().to_string()
    );

    let tenure_c_2 = result.tip_c_2.unwrap();
    assert_ne!(result.tip_c, tenure_c_2);
    assert_ne!(tenure_c_2, result.tip_d);
    assert_ne!(result.tip_c, result.tip_d);

    // Second block of tenure C builds off of block C
    assert_eq!(
        tenure_c_2.stacks_block_height,
        result.tip_c.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_c_2.unwrap().parent_block_id,
        result.tip_c.index_block_hash().to_string()
    );

    // Tenure D builds off of the second block of tenure C
    assert_eq!(
        result.tip_d.stacks_block_height,
        tenure_c_2.stacks_block_height + 1,
    );
    assert_eq!(
        result.mined_d.parent_block_id,
        tenure_c_2.index_block_hash().to_string()
    );
}

struct TenureForkingResult {
    tip_a: StacksHeaderInfo,
    tip_b: StacksHeaderInfo,
    tip_c: StacksHeaderInfo,
    tip_c_2: Option<StacksHeaderInfo>,
    tip_d: StacksHeaderInfo,
    mined_b: MinedNakamotoBlockEvent,
    mined_c: MinedNakamotoBlockEvent,
    mined_c_2: Option<MinedNakamotoBlockEvent>,
    mined_d: MinedNakamotoBlockEvent,
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_config| {},
        |_| {},
        None,
        None,
    );

    setup_epoch_3_reward_set(
        &signer_test.running_nodes.conf,
        &signer_test.running_nodes.blocks_processed,
        &signer_test.signer_stacks_private_keys,
        &signer_test.signer_stacks_private_keys,
        &mut signer_test.running_nodes.btc_regtest_controller,
        Some(signer_test.num_stacking_cycles),
    );

    let naka_conf = &signer_test.running_nodes.conf;
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
    let before_epoch_3_reward_set_calculation =
        epoch_3_reward_cycle_boundary.saturating_sub(prepare_phase_len);
    run_until_burnchain_height(
        &mut signer_test.running_nodes.btc_regtest_controller,
        &signer_test.running_nodes.blocks_processed,
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
        &mut signer_test.running_nodes.btc_regtest_controller,
        &signer_test.running_nodes.blocks_processed,
    );
    signer_test.wait_for_registered(30);
    info!("Signers initialized");

    signer_test.run_until_epoch_3_boundary();

    let commits_submitted = signer_test.running_nodes.commits_submitted.clone();

    info!("Waiting 1 burnchain block for miner VRF key confirmation");
    // Wait one block to confirm the VRF register, wait until a block commit is submitted
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
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

/// This test spins up a nakamoto-neon node.
/// It starts in Epoch 2.0, mines with `neon_node` to Epoch 3.0, and then switches
///  to Nakamoto operation (activating pox-4 by submitting a stack-stx tx). The BootLoop
///  struct handles the epoch-2/3 tear-down and spin-up.
/// Miner A mines a regular tenure, its last block being block a_x.
/// Miner B starts its tenure, Miner B produces a Stacks block b_0, but miner C submits its block commit before b_0 is broadcasted.
/// Bitcoin block C, containing Miner C's block commit, is mined BEFORE miner C has a chance to update their block commit with b_0's information.
/// This test asserts:
///  * tenure C ignores b_0, and correctly builds off of block a_x.
fn forked_tenure_testing(
    proposal_limit: Duration,
    post_btc_block_pause: Duration,
    expect_tenure_c: bool,
) -> TenureForkingResult {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the reorg attempt will definitely be accepted
            config.first_proposal_burn_block_timing = proposal_limit;
            // don't allow signers to post signed blocks (limits the amount of fault injection we
            // need)
            TEST_SKIP_BLOCK_BROADCAST.lock().unwrap().replace(true);
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();
    sleep_ms(1000);
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let naka_conf = signer_test.running_nodes.conf.clone();
    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let commits_submitted = signer_test.running_nodes.commits_submitted.clone();
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let proposed_blocks = signer_test.running_nodes.nakamoto_blocks_proposed.clone();
    let rejected_blocks = signer_test.running_nodes.nakamoto_blocks_rejected.clone();
    let coord_channel = signer_test.running_nodes.coord_channel.clone();
    let blocks_processed_before = coord_channel
        .lock()
        .expect("Mutex poisoned")
        .get_stacks_blocks_processed();

    info!("Starting Tenure A.");
    // In the next block, the miner should win the tenure and submit a stacks block
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);

    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            let blocks_count = mined_blocks.load(Ordering::SeqCst);
            let blocks_processed = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            Ok(commits_count > commits_before
                && blocks_count > blocks_before
                && blocks_processed > blocks_processed_before)
        },
    )
    .unwrap();

    sleep_ms(1000);

    let tip_a = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    // For the next tenure, submit the commit op but do not allow any stacks blocks to be broadcasted
    TEST_BROADCAST_STALL.lock().unwrap().replace(true);
    TEST_BLOCK_ANNOUNCE_STALL.lock().unwrap().replace(true);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let commits_before = commits_submitted.load(Ordering::SeqCst);

    info!("Starting Tenure B.");
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    info!("Commit op is submitted; unpause tenure B's block");

    // Unpause the broadcast of Tenure B's block, do not submit commits.
    // However, do not allow B to be processed just yet
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .set(true);
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

    info!("Tenure B broadcasted a block. Wait {post_btc_block_pause:?}, issue the next bitcon block, and un-stall block commits.");
    thread::sleep(post_btc_block_pause);

    // the block will be stored, not processed, so load it out of staging
    let tip_sn = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
        .expect("Failed to get sortition tip");

    let tip_b_block = chainstate
        .nakamoto_blocks_db()
        .get_nakamoto_tenure_start_blocks(&tip_sn.consensus_hash)
        .unwrap()
        .first()
        .cloned()
        .unwrap();

    // synthesize a StacksHeaderInfo from this unprocessed block
    let tip_b = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(tip_b_block.header.clone()),
        microblock_tail: None,
        stacks_block_height: tip_b_block.header.chain_length,
        index_root: TrieHash([0x00; 32]), // we can't know this yet since the block hasn't been processed
        consensus_hash: tip_b_block.header.consensus_hash,
        burn_header_hash: tip_sn.burn_header_hash,
        burn_header_height: tip_sn.block_height as u32,
        burn_header_timestamp: tip_sn.burn_header_timestamp,
        anchored_block_size: tip_b_block.serialize_to_vec().len() as u64,
        burn_view: Some(tip_b_block.header.consensus_hash),
    };

    let blocks = test_observer::get_mined_nakamoto_blocks();
    let mined_b = blocks.last().unwrap().clone();

    // Block B was built atop block A
    assert_eq!(tip_b.stacks_block_height, tip_a.stacks_block_height + 1);
    assert_eq!(
        mined_b.parent_block_id,
        tip_a.index_block_hash().to_string()
    );
    assert_ne!(tip_b, tip_a);

    if !expect_tenure_c {
        // allow B to process, so it'll be distinct from C
        TEST_BLOCK_ANNOUNCE_STALL.lock().unwrap().replace(false);
        sleep_ms(1000);
    }

    info!("Starting Tenure C.");

    // Submit a block commit op for tenure C
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = if expect_tenure_c {
        mined_blocks.load(Ordering::SeqCst)
    } else {
        proposed_blocks.load(Ordering::SeqCst)
    };
    let rejected_before = rejected_blocks.load(Ordering::SeqCst);

    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            signer_test
                .running_nodes
                .nakamoto_test_skip_commit_op
                .set(false);

            let commits_count = commits_submitted.load(Ordering::SeqCst);
            if commits_count > commits_before {
                // now allow block B to process if it hasn't already.
                TEST_BLOCK_ANNOUNCE_STALL.lock().unwrap().replace(false);
            }
            let rejected_count = rejected_blocks.load(Ordering::SeqCst);
            let (blocks_count, rbf_count, has_reject_count) = if expect_tenure_c {
                // if tenure C is going to be canonical, then we expect the miner to RBF its commit
                // once (i.e. for the block it mines and gets signed), and we expect zero
                // rejections.
                (mined_blocks.load(Ordering::SeqCst), 1, true)
            } else {
                // if tenure C is NOT going to be canonical, then we expect no RBFs (since the
                // miner can't get its block signed), and we expect at least one rejection
                (
                    proposed_blocks.load(Ordering::SeqCst),
                    0,
                    rejected_count > rejected_before,
                )
            };

            Ok(commits_count > commits_before + rbf_count
                && blocks_count > blocks_before
                && has_reject_count)
        },
    )
    .unwrap();

    // allow blocks B and C to be processed
    sleep_ms(1000);

    info!("Tenure C produced (or proposed) a block!");
    let tip_c = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();

    let blocks = test_observer::get_mined_nakamoto_blocks();
    let mined_c = blocks.last().unwrap().clone();

    if expect_tenure_c {
        assert_ne!(tip_b.index_block_hash(), tip_c.index_block_hash());
    } else {
        assert_eq!(tip_b.index_block_hash(), tip_c.index_block_hash());
    }
    assert_ne!(tip_c, tip_a);

    let (tip_c_2, mined_c_2) = if !expect_tenure_c {
        (None, None)
    } else {
        // Now let's produce a second block for tenure C and ensure it builds off of block C.
        let blocks_before = mined_blocks.load(Ordering::SeqCst);
        let start_time = Instant::now();
        // submit a tx so that the miner will mine an extra block
        let sender_nonce = 0;
        let transfer_tx = make_stacks_transfer(
            &sender_sk,
            sender_nonce,
            send_fee,
            naka_conf.burnchain.chain_id,
            &recipient,
            send_amt,
        );
        let tx = submit_tx(&http_origin, &transfer_tx);
        info!("Submitted tx {tx} in Tenure C to mine a second block");
        while mined_blocks.load(Ordering::SeqCst) <= blocks_before {
            assert!(
                start_time.elapsed() < Duration::from_secs(30),
                "FAIL: Test timed out while waiting for block production",
            );
            thread::sleep(Duration::from_secs(1));
        }

        // give C's second block a moment to process
        sleep_ms(1000);

        info!("Tenure C produced a second block!");

        let block_2_tenure_c =
            NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
                .unwrap()
                .unwrap();
        let blocks = test_observer::get_mined_nakamoto_blocks();
        let block_2_c = blocks.last().cloned().unwrap();
        (Some(block_2_tenure_c), Some(block_2_c))
    };

    // allow block C2 to be processed
    sleep_ms(1000);

    info!("Starting Tenure D.");

    // Submit a block commit op for tenure D and mine a stacks block
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            let blocks_count = mined_blocks.load(Ordering::SeqCst);
            Ok(commits_count > commits_before && blocks_count > blocks_before)
        },
    )
    .unwrap();

    // allow block D to be processed
    sleep_ms(1000);

    let tip_d = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    let blocks = test_observer::get_mined_nakamoto_blocks();
    let mined_d = blocks.last().unwrap().clone();
    signer_test.shutdown();
    TenureForkingResult {
        tip_a,
        tip_b,
        tip_c,
        tip_c_2,
        tip_d,
        mined_b,
        mined_c,
        mined_c_2,
        mined_d,
    }
}

#[test]
#[ignore]
fn bitcoind_forking_test() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let mut signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let conf = signer_test.running_nodes.conf.clone();
    let http_origin = format!("http://{}", &conf.node.rpc_bind);
    let miner_address = Keychain::default(conf.node.seed.clone())
        .origin_address(conf.is_mainnet())
        .unwrap();
    let miner_pk = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .unwrap()
        .unwrap();

    let get_unconfirmed_commit_data = |btc_controller: &mut BitcoinRegtestController| {
        let unconfirmed_utxo = btc_controller
            .get_all_utxos(&miner_pk)
            .into_iter()
            .find(|utxo| utxo.confirmations == 0)?;
        let unconfirmed_txid = Txid::from_bitcoin_tx_hash(&unconfirmed_utxo.txid);
        let unconfirmed_tx = btc_controller.get_raw_transaction(&unconfirmed_txid);
        let unconfirmed_tx_opreturn_bytes = unconfirmed_tx.output[0].script_pubkey.as_bytes();
        info!(
            "Unconfirmed tx bytes: {}",
            stacks::util::hash::to_hex(unconfirmed_tx_opreturn_bytes)
        );
        let data = LeaderBlockCommitOp::parse_data(
            &unconfirmed_tx_opreturn_bytes[unconfirmed_tx_opreturn_bytes.len() - 77..],
        )
        .unwrap();
        Some(data)
    };

    signer_test.boot_to_epoch_3();
    info!("------------------------- Reached Epoch 3.0 -------------------------");
    let pre_epoch_3_nonce = get_account(&http_origin, &miner_address).nonce;
    let pre_fork_tenures = 10;

    for i in 0..pre_fork_tenures {
        info!("Mining pre-fork tenure {} of {pre_fork_tenures}", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30));
    }

    let pre_fork_1_nonce = get_account(&http_origin, &miner_address).nonce;

    assert_eq!(pre_fork_1_nonce, pre_epoch_3_nonce + 2 * pre_fork_tenures);

    info!("------------------------- Triggering Bitcoin Fork -------------------------");

    let burn_block_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
    let burn_header_hash_to_fork = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(burn_block_height);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&burn_header_hash_to_fork);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    info!("Wait for block off of shallow fork");

    // we need to mine some blocks to get back to being considered a frequent miner
    for i in 0..3 {
        let current_burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = signer_test
            .running_nodes
            .commits_submitted
            .load(Ordering::SeqCst);
        next_block_and_controller(
            &mut signer_test.running_nodes.btc_regtest_controller,
            60,
            |btc_controller| {
                let commits_submitted = signer_test
                    .running_nodes
                    .commits_submitted
                    .load(Ordering::SeqCst);
                if commits_submitted <= commits_count {
                    // wait until a commit was submitted
                    return Ok(false)
                }
                let Some(payload) = get_unconfirmed_commit_data(btc_controller) else {
                    warn!("Commit submitted, but bitcoin doesn't see it in the unconfirmed UTXO set, will try to wait.");
                    return Ok(false)
                };
                let burn_parent_modulus = payload.burn_parent_modulus;
                let current_modulus = u8::try_from((current_burn_height + 1) % 5).unwrap();
                info!(
                    "Ongoing Commit Operation check";
                    "burn_parent_modulus" => burn_parent_modulus,
                    "current_modulus" => current_modulus,
                    "payload" => ?payload,
                );
                Ok(burn_parent_modulus == current_modulus)
            },
        )
        .unwrap();
    }

    let post_fork_1_nonce = get_account(&http_origin, &miner_address).nonce;

    assert_eq!(post_fork_1_nonce, pre_fork_1_nonce - 2);

    for i in 0..5 {
        info!("Mining post-fork tenure {} of 5", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30));
    }

    let pre_fork_2_nonce = get_account(&http_origin, &miner_address).nonce;
    assert_eq!(pre_fork_2_nonce, post_fork_1_nonce + 2 * 5);

    info!(
        "New chain info: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("------------------------- Triggering Deeper Bitcoin Fork -------------------------");

    let burn_block_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
    let burn_header_hash_to_fork = signer_test
        .running_nodes
        .btc_regtest_controller
        .get_block_hash(burn_block_height - 3);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .invalidate_block(&burn_header_hash_to_fork);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(4);

    info!("Wait for block off of deep fork");

    // we need to mine some blocks to get back to being considered a frequent miner
    for i in 0..3 {
        let current_burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
        info!(
            "Mining block #{i} to be considered a frequent miner";
            "current_burn_height" => current_burn_height,
        );
        let commits_count = signer_test
            .running_nodes
            .commits_submitted
            .load(Ordering::SeqCst);
        next_block_and_controller(
            &mut signer_test.running_nodes.btc_regtest_controller,
            60,
            |btc_controller| {
                let commits_submitted = signer_test
                    .running_nodes
                    .commits_submitted
                    .load(Ordering::SeqCst);
                if commits_submitted <= commits_count {
                    // wait until a commit was submitted
                    return Ok(false)
                }
                let Some(payload) = get_unconfirmed_commit_data(btc_controller) else {
                    warn!("Commit submitted, but bitcoin doesn't see it in the unconfirmed UTXO set, will try to wait.");
                    return Ok(false)
                };
                let burn_parent_modulus = payload.burn_parent_modulus;
                let current_modulus = u8::try_from((current_burn_height + 1) % 5).unwrap();
                info!(
                    "Ongoing Commit Operation check";
                    "burn_parent_modulus" => burn_parent_modulus,
                    "current_modulus" => current_modulus,
                    "payload" => ?payload,
                );
                Ok(burn_parent_modulus == current_modulus)
            },
        )
        .unwrap();
    }

    let post_fork_2_nonce = get_account(&http_origin, &miner_address).nonce;

    assert_eq!(post_fork_2_nonce, pre_fork_2_nonce - 4 * 2);

    for i in 0..5 {
        info!("Mining post-fork tenure {} of 5", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(30));
    }

    let test_end_nonce = get_account(&http_origin, &miner_address).nonce;
    assert_eq!(test_end_nonce, post_fork_2_nonce + 2 * 5);

    info!(
        "New chain info: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );
    signer_test.shutdown();
}

#[test]
#[ignore]
fn multiple_miners() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();

    let max_nakamoto_tenures = 30;
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Duration::from_secs(5);
            config.node.pox_sync_sample_secs = 30;
            config.burnchain.pox_reward_length = Some(max_nakamoto_tenures);

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
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
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
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);
    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let Counters {
        naka_submitted_commits: rl2_commits,
        ..
    } = run_loop_2.counters();
    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    signer_test.boot_to_epoch_3();

    wait_for(120, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for boostrapped node to catch up to the miner");

    let pre_nakamoto_peer_1_height = get_chain_info(&conf).stacks_tip_height;

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    let rl1_coord_channels = signer_test.running_nodes.coord_channel.clone();
    let rl1_commits = signer_test.running_nodes.commits_submitted.clone();

    let miner_1_pk = StacksPublicKey::from_private(conf.miner.mining_key.as_ref().unwrap());
    let miner_2_pk = StacksPublicKey::from_private(conf_node_2.miner.mining_key.as_ref().unwrap());
    let mut btc_blocks_mined = 1;
    let mut miner_1_tenures = 0;
    let mut miner_2_tenures = 0;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        assert!(
            max_nakamoto_tenures >= btc_blocks_mined,
            "Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting"
        );

        let info_1 = get_chain_info(&conf);
        let info_2 = get_chain_info(&conf_node_2);

        info!("Issue next block-build request\ninfo 1: {info_1:?}\ninfo 2: {info_2:?}\n");

        signer_test.mine_block_wait_on_processing(
            &[&rl1_coord_channels, &rl2_coord_channels],
            &[&rl1_commits, &rl2_commits],
            Duration::from_secs(30),
        );

        btc_blocks_mined += 1;
        let blocks = get_nakamoto_headers(&conf);
        // for this test, there should be one block per tenure
        let consensus_hash_set: HashSet<_> =
            blocks.iter().map(|header| header.consensus_hash).collect();
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

    info!(
        "New chain info: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("New chain info: {:?}", get_chain_info(&conf_node_2));

    let peer_1_height = get_chain_info(&conf).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_node_2).stacks_tip_height;
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

    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

/// Read processed nakamoto block IDs from the test observer, and use `config` to open
///  a chainstate DB and returns their corresponding StacksHeaderInfos
fn get_nakamoto_headers(config: &Config) -> Vec<StacksHeaderInfo> {
    let nakamoto_block_ids: HashSet<_> = test_observer::get_blocks()
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
// Test two nakamoto miners, with the signer set split between them.
//  One of the miners (run-loop-2) is prevented from submitting "good" block commits
//  using the "commit stall" test flag in combination with "block broadcast stalls".
//  (Because RL2 isn't able to RBF their initial commits after the tip is broadcasted).
// This test works by tracking two different scenarios:
//   1. RL2 must win a sortition that this block commit behavior would lead to a fork in.
//   2. After such a sortition, RL1 must win another block.
// The test asserts that every nakamoto sortition either has a successful tenure, or if
//  RL2 wins and they would be expected to fork, no blocks are produced. The test asserts
//  that every block produced increments the chain length.
fn miner_forking() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let first_proposal_burn_block_timing = 1;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();

    let max_sortitions = 30;

    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
            // we're deliberately stalling proposals: don't punish this in this test!
            signer_config.block_proposal_timeout = Duration::from_secs(240);
            // make sure that we don't allow forking due to burn block timing
            signer_config.first_proposal_burn_block_timing =
                Duration::from_secs(first_proposal_burn_block_timing);
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));
            config.node.pox_sync_sample_secs = 30;
            config.burnchain.pox_reward_length = Some(max_sortitions as u32);
            config.miner.block_commit_delay = Duration::from_secs(0);

            config.events_observers.retain(|listener| {
                let Ok(addr) = std::net::SocketAddr::from_str(&listener.endpoint) else {
                    warn!(
                        "Cannot parse {} to a socket, assuming it isn't a signer-listener binding",
                        listener.endpoint
                    );
                    return true;
                };
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
        None,
    );
    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = node_2_rpc_bind;
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let Counters {
        naka_skip_commit_op: skip_commit_op_rl2,
        naka_submitted_commits: commits_submitted_rl2,
        ..
    } = run_loop_2.counters();
    let _run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    signer_test.boot_to_epoch_3();

    wait_for(120, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for boostrapped node to catch up to the miner");

    let commits_submitted_rl1 = signer_test.running_nodes.commits_submitted.clone();
    let skip_commit_op_rl1 = signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .clone();

    let pre_nakamoto_peer_1_height = get_chain_info(&conf).stacks_tip_height;

    let mining_pk_1 = StacksPublicKey::from_private(&conf.miner.mining_key.unwrap());
    let mining_pk_2 = StacksPublicKey::from_private(&conf_node_2.miner.mining_key.unwrap());
    let mining_pkh_1 = Hash160::from_node_public_key(&mining_pk_1);
    let mining_pkh_2 = Hash160::from_node_public_key(&mining_pk_2);
    debug!("The mining key for miner 1 is {mining_pkh_1}");
    debug!("The mining key for miner 2 is {mining_pkh_2}");

    let sortdb = conf.get_burnchain().open_sortition_db(true).unwrap();
    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    info!("Pausing both miners' block commit submissions");
    skip_commit_op_rl1.set(true);
    skip_commit_op_rl2.set(true);

    info!("Flushing any pending commits to enable custom winner selection");
    let burn_height_before = get_burn_height();
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(get_burn_height() > burn_height_before),
    )
    .unwrap();

    info!("------------------------- RL1 Wins Sortition -------------------------");
    info!("Pausing stacks block proposal to force an empty tenure commit from RL2");
    TEST_BROADCAST_STALL.lock().unwrap().replace(true);
    let rl1_commits_before = commits_submitted_rl1.load(Ordering::SeqCst);

    info!("Unpausing commits from RL1");
    skip_commit_op_rl1.set(false);

    info!("Waiting for commits from RL1");
    wait_for(30, || {
        Ok(commits_submitted_rl1.load(Ordering::SeqCst) > rl1_commits_before)
    })
    .expect("Timed out waiting for miner 1 to submit a commit op");

    info!("Pausing commits from RL1");
    skip_commit_op_rl1.set(true);

    let burn_height_before = get_burn_height();
    info!("Mine RL1 Tenure");
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(get_burn_height() > burn_height_before),
    )
    .unwrap();

    // fetch the current sortition info
    let sortdb = conf.get_burnchain().open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    // make sure the tenure was won by RL1
    assert!(tip.sortition, "No sortition was won");
    assert_eq!(
        tip.miner_pk_hash.unwrap(),
        mining_pkh_1,
        "RL1 did not win the sortition"
    );

    info!(
        "------------------------- RL2 Wins Sortition With Outdated View -------------------------"
    );
    let rl2_commits_before = commits_submitted_rl2.load(Ordering::SeqCst);

    info!("Unpausing commits from RL2");
    skip_commit_op_rl2.set(false);

    info!("Waiting for commits from RL2");
    wait_for(30, || {
        Ok(commits_submitted_rl2.load(Ordering::SeqCst) > rl2_commits_before)
    })
    .expect("Timed out waiting for miner 1 to submit a commit op");

    info!("Pausing commits from RL2");
    skip_commit_op_rl2.set(true);

    // unblock block mining
    let blocks_len = test_observer::get_blocks().len();
    TEST_BROADCAST_STALL.lock().unwrap().replace(false);

    // Wait for the block to be broadcasted and processed
    wait_for(30, || Ok(test_observer::get_blocks().len() > blocks_len))
        .expect("Timed out waiting for a block to be processed");

    // sleep for 2*first_proposal_burn_block_timing to prevent the block timing from allowing a fork by the signer set
    thread::sleep(Duration::from_secs(first_proposal_burn_block_timing * 2));

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf)
    .into_iter()
    .map(|header| {
        info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
        (header.consensus_hash, header)
    })
    .collect();

    let header_info = nakamoto_headers.get(&tip.consensus_hash).unwrap();
    let header = header_info
        .anchored_header
        .as_stacks_nakamoto()
        .unwrap()
        .clone();

    mining_pk_1
        .verify(
            header.miner_signature_hash().as_bytes(),
            &header.miner_signature,
        )
        .unwrap();

    let blocks_len = test_observer::get_blocks().len();
    let burn_height_before = get_burn_height();
    info!("Mine RL2 Tenure");
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(get_burn_height() > burn_height_before),
    )
    .unwrap();

    // Ensure that RL2 doesn't produce a valid block
    assert!(
        wait_for(60, || Ok(test_observer::get_blocks().len() > blocks_len)).is_err(),
        "RL2 produced a block"
    );

    // fetch the current sortition info
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    // make sure the tenure was won by RL2
    assert!(tip.sortition, "No sortition was won");
    assert_eq!(
        tip.miner_pk_hash.unwrap(),
        mining_pkh_2,
        "RL2 did not win the sortition"
    );

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf)
        .into_iter()
        .map(|header| {
            info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
            (header.consensus_hash, header)
        })
        .collect();
    assert!(!nakamoto_headers.contains_key(&tip.consensus_hash));

    info!("------------------------- RL1 RBFs its Own Commit -------------------------");
    info!("Pausing stacks block proposal to test RBF capability");
    TEST_BROADCAST_STALL.lock().unwrap().replace(true);
    let rl1_commits_before = commits_submitted_rl1.load(Ordering::SeqCst);

    info!("Unpausing commits from RL1");
    skip_commit_op_rl1.set(false);

    info!("Waiting for commits from RL1");
    wait_for(30, || {
        Ok(commits_submitted_rl1.load(Ordering::SeqCst) > rl1_commits_before)
    })
    .expect("Timed out waiting for miner 1 to submit a commit op");

    info!("Pausing commits from RL1");
    skip_commit_op_rl1.set(true);

    let burn_height_before = get_burn_height();
    info!("Mine RL1 Tenure");
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        30,
        || Ok(get_burn_height() > burn_height_before),
    )
    .unwrap();

    let rl1_commits_before = commits_submitted_rl1.load(Ordering::SeqCst);

    info!("Unpausing commits from RL1");
    skip_commit_op_rl1.set(false);

    info!("Waiting for commits from RL1");
    wait_for(30, || {
        Ok(commits_submitted_rl1.load(Ordering::SeqCst) > rl1_commits_before)
    })
    .expect("Timed out waiting for miner 1 to submit a commit op");

    let rl1_commits_before = commits_submitted_rl1.load(Ordering::SeqCst);
    // unblock block mining
    let blocks_len = test_observer::get_blocks().len();
    TEST_BROADCAST_STALL.lock().unwrap().replace(false);

    // Wait for the block to be broadcasted and processed
    wait_for(30, || Ok(test_observer::get_blocks().len() > blocks_len))
        .expect("Timed out waiting for a block to be processed");

    info!("Ensure that RL1 performs an RBF after unblocking block broadcast");
    wait_for(30, || {
        Ok(commits_submitted_rl1.load(Ordering::SeqCst) > rl1_commits_before)
    })
    .expect("Timed out waiting for miner 1 to RBF its old commit op");

    info!("Mine RL1 Tenure");
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    // fetch the current sortition info
    let sortdb = conf.get_burnchain().open_sortition_db(true).unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    // make sure the tenure was won by RL1
    assert!(tip.sortition, "No sortition was won");
    assert_eq!(
        tip.miner_pk_hash.unwrap(),
        mining_pkh_1,
        "RL1 did not win the sortition"
    );

    let nakamoto_headers: HashMap<_, _> = get_nakamoto_headers(&conf)
        .into_iter()
        .map(|header| {
            info!("Nakamoto block"; "height" => header.stacks_block_height, "consensus_hash" => %header.consensus_hash, "last_sortition_hash" => %tip.consensus_hash);
            (header.consensus_hash, header)
        })
        .collect();

    let header_info = nakamoto_headers.get(&tip.consensus_hash).unwrap();
    let header = header_info
        .anchored_header
        .as_stacks_nakamoto()
        .unwrap()
        .clone();

    mining_pk_1
        .verify(
            header.miner_signature_hash().as_bytes(),
            &header.miner_signature,
        )
        .unwrap();

    info!("------------------------- Verify Peer Data -------------------------");

    let peer_1_height = get_chain_info(&conf).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_node_2).stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);

    let nakamoto_blocks_count = get_nakamoto_headers(&conf).len();

    assert_eq!(
        peer_1_height - pre_nakamoto_peer_1_height,
        u64::try_from(nakamoto_blocks_count).unwrap() - 1, // subtract 1 for the first Nakamoto block
        "There should be no forks in this test"
    );

    signer_test.shutdown();
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let long_timeout = Duration::from_secs(200);
    let short_timeout = Duration::from_secs(20);
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
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
        let mined_blocks = signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst);
        Ok(mined_blocks > blocks_before)
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
    TEST_VALIDATE_STALL.lock().unwrap().replace(true);

    let proposals_before = signer_test
        .running_nodes
        .nakamoto_blocks_proposed
        .load(Ordering::SeqCst);
    let blocks_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let start_height = info.stacks_tip_height;
    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
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
    while signer_test
        .running_nodes
        .nakamoto_blocks_proposed
        .load(Ordering::SeqCst)
        <= proposals_before
    {
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
        let blocks = test_observer::get_burn_blocks()
            .last()
            .unwrap()
            .get("burn_block_height")
            .unwrap()
            .as_u64()
            .unwrap();
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
    TEST_VALIDATE_STALL.lock().unwrap().replace(false);
    wait_for(short_timeout.as_secs(), || {
        let processed_now = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;
        Ok(processed_now > blocks_before)
    })
    .expect("Timed out waiting for block to be mined");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(info.stacks_tip_height, start_height + 1);

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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let short_timeout = Duration::from_secs(30);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> =
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
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let start_time = Instant::now();
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
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
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(rejecting_signers.clone());

    let proposals_before = signer_test
        .running_nodes
        .nakamoto_blocks_proposed
        .load(Ordering::SeqCst);
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);

    // submit a tx so that the miner will mine a block
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    info!("Submitted transfer tx and waiting for block proposal");
    loop {
        let blocks_proposed = signer_test
            .running_nodes
            .nakamoto_blocks_proposed
            .load(Ordering::SeqCst);
        if blocks_proposed > proposals_before {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    info!("Block proposed, verifying that it is not processed");
    // Wait 10 seconds to be sure that the timeout has occurred
    std::thread::sleep(Duration::from_secs(10));
    assert_eq!(
        signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst),
        blocks_before
    );

    // resume signing
    info!("Disable unconditional rejection and wait for the block to be processed");
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(vec![]);
    loop {
        let blocks_mined = signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst);
        if blocks_mined > blocks_before {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, send_amt + send_fee)]);
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();
    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
    signer_test.mine_nakamoto_block(Duration::from_secs(30));

    wait_for(30, || {
        let blocks_mined = signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst);
        let info = get_chain_info(&signer_test.running_nodes.conf);
        debug!(
            "blocks_mined: {blocks_mined},{blocks_before}, stacks_tip_height: {},{}",
            info.stacks_tip_height, info_before.stacks_tip_height
        );
        Ok(blocks_mined > blocks_before && info.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for first nakamoto block to be mined");

    TEST_IGNORE_SIGNERS.lock().unwrap().replace(true);
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
    let signer_pushed_before = signer_test
        .running_nodes
        .nakamoto_blocks_signer_pushed
        .load(Ordering::SeqCst);
    let info_before = get_chain_info(&signer_test.running_nodes.conf);

    // submit a tx so that the miner will mine a blockn
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
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
        let signer_pushed = signer_test
            .running_nodes
            .nakamoto_blocks_signer_pushed
            .load(Ordering::SeqCst);
        let blocks_mined = signer_test
            .running_nodes
            .nakamoto_blocks_mined
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
/// This test checks the behaviour of signers when a sortition is empty. Specifically:
/// - An empty sortition will cause the signers to mark a miner as misbehaving once a timeout is exceeded.
/// - The miner will stop trying to mine once it sees a threshold of signers reject the block
/// - The empty sortition will trigger the miner to attempt a tenure extend.
/// - Signers will accept the tenure extend and sign subsequent blocks built off the old sortition
fn empty_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(20);
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = Duration::from_secs(20);

    signer_test.boot_to_epoch_3();

    TEST_BROADCAST_STALL.lock().unwrap().replace(true);

    info!("------------------------- Test Mine Regular Tenure A  -------------------------");
    let commits_before = signer_test
        .running_nodes
        .commits_submitted
        .load(Ordering::SeqCst);
    // Mine a regular tenure
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = signer_test
                .running_nodes
                .commits_submitted
                .load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    info!("------------------------- Test Mine Empty Tenure B  -------------------------");
    info!("Pausing stacks block mining to trigger an empty sortition.");
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
    let commits_before = signer_test
        .running_nodes
        .commits_submitted
        .load(Ordering::SeqCst);
    // Start new Tenure B
    // In the next block, the miner should win the tenure
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = signer_test
                .running_nodes
                .commits_submitted
                .load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    info!("Pausing stacks block proposal to force an empty tenure");
    TEST_BROADCAST_STALL.lock().unwrap().replace(true);

    info!("Pausing commit op to prevent tenure C from starting...");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .set(true);

    let blocks_after = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
    assert_eq!(blocks_after, blocks_before);

    let rejected_before = signer_test
        .running_nodes
        .nakamoto_blocks_rejected
        .load(Ordering::SeqCst);

    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    std::thread::sleep(block_proposal_timeout.add(Duration::from_secs(1)));

    TEST_BROADCAST_STALL.lock().unwrap().replace(false);

    info!("------------------------- Test Delayed Block is Rejected  -------------------------");
    let reward_cycle = signer_test.get_current_reward_cycle();
    let mut stackerdb = StackerDB::new(
        &signer_test.running_nodes.conf.node.rpc_bind,
        StacksPrivateKey::new(), // We are just reading so don't care what the key is
        false,
        reward_cycle,
        SignerSlotID(0), // We are just reading so again, don't care about index.
    );

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
                ..
            })) = latest_msg
            {
                assert!(matches!(reason_code, RejectCode::SortitionViewMismatch));
                assert_eq!(metadata.server_version, VERSION_STRING.to_string());
                found_rejections.push(*slot_id);
            } else {
                info!("Latest message from slot #{slot_id} isn't a block rejection, will wait to see if the signer updates to a rejection");
            }
        }
        let rejections = signer_test
            .running_nodes
            .nakamoto_blocks_rejected
            .load(Ordering::SeqCst);

        // wait until we've found rejections for all the signers, and the miner has confirmed that
        // the signers have rejected the block
        Ok(found_rejections.len() == signer_slot_ids.len() && rejections > rejected_before)
    }).unwrap();
    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of signers when an empty sortition arrives
/// before the first block of the previous tenure has been approved.
/// Specifically:
/// - The empty sortition will trigger the miner to attempt a tenure extend.
/// - Signers will accept the tenure extend and sign subsequent blocks built
///   off the old sortition
fn empty_sortition_before_approval() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(20);
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    next_block_and_process_new_stacks_block(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .unwrap();

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let burn_height_before = info.burn_block_height;
    let stacks_height_before = info.stacks_tip_height;

    info!("Forcing miner to ignore signatures for next block");
    TEST_IGNORE_SIGNERS.lock().unwrap().replace(true);

    info!("Pausing block commits to trigger an empty sortition.");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .0
        .lock()
        .unwrap()
        .replace(true);

    info!("------------------------- Test Mine Tenure A  -------------------------");
    let proposed_before = signer_test
        .running_nodes
        .nakamoto_blocks_proposed
        .load(Ordering::SeqCst);
    // Mine a regular tenure and wait for a block proposal
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let proposed_count = signer_test
                .running_nodes
                .nakamoto_blocks_proposed
                .load(Ordering::SeqCst);
            Ok(proposed_count > proposed_before)
        },
    )
    .expect("Failed to mine tenure A and propose a block");

    info!("------------------------- Test Mine Empty Tenure B  -------------------------");

    // Trigger an empty tenure
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
            Ok(burn_height == burn_height_before + 2)
        },
    )
    .expect("Failed to mine empty tenure");

    info!("Unpause block commits");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .0
        .lock()
        .unwrap()
        .replace(false);

    info!("Stop ignoring signers and wait for the tip to advance");
    TEST_IGNORE_SIGNERS.lock().unwrap().replace(false);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!("Current state: {:?}", info);

    // Wait for a block with a tenure extend to be mined
    wait_for(60, || {
        let blocks = test_observer::get_blocks();
        let last_block = blocks.last().unwrap();
        info!("Last block mined: {:?}", last_block);
        for tx in last_block["transactions"].as_array().unwrap() {
            let raw_tx = tx["raw_tx"].as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
            if let TransactionPayload::TenureChange(payload) = &parsed.payload {
                match payload.cause {
                    TenureChangeCause::Extended => {
                        info!("Found tenure extend block");
                        return Ok(true);
                    }
                    TenureChangeCause::BlockFound => {}
                }
            };
        }
        Ok(false)
    })
    .expect("Timed out waiting for tenure extend");

    let stacks_height_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;

    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip with STX transfer");

    next_block_and_process_new_stacks_block(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine a normal tenure after the tenure extend");

    signer_test.shutdown();
}

#[test]
#[ignore]
/// This test checks the behavior of signers when an empty sortition arrives
/// before the first block of the previous tenure has been proposed.
/// Specifically:
/// - The empty sortition will trigger the miner to attempt a tenure extend.
/// - Signers will accept the tenure extend and sign subsequent blocks built
///   off the old sortition
fn empty_sortition_before_proposal() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let block_proposal_timeout = Duration::from_secs(20);
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    next_block_and_process_new_stacks_block(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .unwrap();

    let info = get_chain_info(&signer_test.running_nodes.conf);
    let stacks_height_before = info.stacks_tip_height;

    info!("Pause block commits to ensure we get an empty sortition");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .0
        .lock()
        .unwrap()
        .replace(true);

    info!("Pause miner so it doesn't propose a block before the next tenure arrives");
    TEST_MINE_STALL.lock().unwrap().replace(true);

    let burn_height_before = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;

    info!("------------------------- Test Mine Tenure A and B  -------------------------");
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(2);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.burn_block_height == burn_height_before + 2)
    })
    .expect("Failed to advance chain tip");

    // Sleep a bit more to ensure the signers see both burn blocks
    sleep_ms(5_000);

    info!("Unpause miner");
    TEST_MINE_STALL.lock().unwrap().replace(false);

    info!("Unpause block commits");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .0
        .lock()
        .unwrap()
        .replace(false);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip");

    let info = get_chain_info(&signer_test.running_nodes.conf);
    info!("Current state: {:?}", info);

    // Wait for a block with a tenure extend to be mined
    wait_for(60, || {
        let blocks = test_observer::get_blocks();
        let last_block = blocks.last().unwrap();
        info!("Last block mined: {:?}", last_block);
        for tx in last_block["transactions"].as_array().unwrap() {
            let raw_tx = tx["raw_tx"].as_str().unwrap();
            if raw_tx == "0x00" {
                continue;
            }
            let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
            let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
            if let TransactionPayload::TenureChange(payload) = &parsed.payload {
                match payload.cause {
                    TenureChangeCause::Extended => {
                        info!("Found tenure extend block");
                        return Ok(true);
                    }
                    TenureChangeCause::BlockFound => {}
                }
            };
        }
        Ok(false)
    })
    .expect("Timed out waiting for tenure extend");

    let stacks_height_before = get_chain_info(&signer_test.running_nodes.conf).stacks_tip_height;

    // submit a tx so that the miner will mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    wait_for(60, || {
        let info = get_chain_info(&signer_test.running_nodes.conf);
        Ok(info.stacks_tip_height > stacks_height_before)
    })
    .expect("Failed to advance chain tip with STX transfer");

    next_block_and_process_new_stacks_block(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine a normal tenure after the tenure extend");

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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |_| {},
        |node_config| {
            node_config.miner.pre_nakamoto_mock_signing = true;
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            for epoch in epochs.iter_mut() {
                if epoch.epoch_id == StacksEpochId::Epoch25 {
                    epoch.end_height = 251;
                }
                if epoch.epoch_id == StacksEpochId::Epoch30 {
                    epoch.start_height = 251;
                }
            }
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
    let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];
    let epoch_3_boundary = epoch_3.start_height - 1; // We only advance to the boundary as epoch 2.5 miner gets torn down at the boundary

    signer_test.boot_to_epoch_25_reward_cycle();

    info!("------------------------- Test Processing Epoch 2.5 Tenures -------------------------");

    // Mine until epoch 3.0 and ensure that no more mock signatures are received
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();
    let signer_public_keys = signer_test.get_signer_public_keys(reward_cycle);
    assert_eq!(signer_slot_ids.len(), num_signers);

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
            let chunks = test_observer::get_stackerdb_chunks();
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
            main_poll_time.elapsed() <= Duration::from_secs(45),
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();

    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));
            config.miner.pre_nakamoto_mock_signing = true;
            let epochs = config.burnchain.epochs.as_mut().unwrap();
            for epoch in epochs.iter_mut() {
                if epoch.epoch_id == StacksEpochId::Epoch25 {
                    epoch.end_height = 251;
                }
                if epoch.epoch_id == StacksEpochId::Epoch30 {
                    epoch.start_height = 251;
                }
            }
            config.events_observers.retain(|listener| {
                let Ok(addr) = std::net::SocketAddr::from_str(&listener.endpoint) else {
                    warn!(
                        "Cannot parse {} to a socket, assuming it isn't a signer-listener binding",
                        listener.endpoint
                    );
                    return true;
                };
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
        None,
    );
    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    let localhost = "127.0.0.1";
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);
    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let _run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    let epochs = signer_test
        .running_nodes
        .conf
        .burnchain
        .epochs
        .clone()
        .unwrap();
    let epoch_3 = &epochs[StacksEpoch::find_epoch_by_id(&epochs, StacksEpochId::Epoch30).unwrap()];
    let epoch_3_boundary = epoch_3.start_height - 1; // We only advance to the boundary as epoch 2.5 miner gets torn down at the boundary

    signer_test.boot_to_epoch_25_reward_cycle();

    info!("------------------------- Reached Epoch 2.5 Reward Cycle-------------------------");

    // Mine until epoch 3.0 and ensure that no more mock signatures are received
    let reward_cycle = signer_test.get_current_reward_cycle();
    let signer_slot_ids: Vec<_> = signer_test
        .get_signer_indices(reward_cycle)
        .iter()
        .map(|id| id.0)
        .collect();
    let signer_public_keys = signer_test.get_signer_public_keys(reward_cycle);
    assert_eq!(signer_slot_ids.len(), num_signers);

    let miners_stackerdb_contract = boot_code_id(MINERS_NAME, false);

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
            let chunks = test_observer::get_stackerdb_chunks();
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
        .map(|_| StacksPrivateKey::new())
        .collect();
    let new_signer_public_keys: Vec<_> = new_signer_private_keys
        .iter()
        .map(|sk| Secp256k1PublicKey::from_private(sk).to_bytes_compressed())
        .collect();
    let new_signer_addresses: Vec<_> = new_signer_private_keys.iter().map(tests::to_addr).collect();
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let mut initial_balances = new_signer_addresses
        .iter()
        .map(|addr| (*addr, POX_4_DEFAULT_STACKER_BALANCE))
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

    let new_spawned_signers: Vec<_> = new_signer_configs
        .iter()
        .map(|conf| {
            info!("spawning signer");
            let signer_config = SignerConfig::load_from_str(conf).unwrap();
            SpawnedSigner::new(signer_config)
        })
        .collect();

    // Boot with some initial signer set
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        initial_balances,
        |_| {},
        |naka_conf| {
            for toml in new_signer_configs.clone() {
                let signer_config = SignerConfig::load_from_str(&toml).unwrap();
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
    for toml in &new_signer_configs {
        let signer_config = SignerConfig::load_from_str(toml).unwrap();
        let endpoint = format!("{}", signer_config.endpoint);
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
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    signer_test.mine_nakamoto_block(short_timeout);
    let mined_block = test_observer::get_mined_nakamoto_blocks().pop().unwrap();
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
            tests::to_addr(stacker_sk).bytes,
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
        let stacking_tx = tests::make_contract_call(
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

    signer_test.mine_nakamoto_block(short_timeout);

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

    info!("---- Mining to the next reward cycle (block {next_cycle_height}) -----",);
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
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);
    signer_test.mine_nakamoto_block(short_timeout);
    let mined_block = test_observer::get_mined_nakamoto_blocks().pop().unwrap();

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
    for signer in new_spawned_signers {
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;

    let interim_blocks = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let time_between_blocks_ms = 10_000;
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * interim_blocks)],
        |_config| {},
        |config| {
            config.miner.min_time_between_blocks_ms = time_between_blocks_ms;
        },
        None,
        None,
    );

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("Ensure that the first Nakamoto block was mined");
    let blocks = get_nakamoto_headers(&signer_test.running_nodes.conf);
    assert_eq!(blocks.len(), 1);
    // mine the interim blocks
    info!("Mining interim blocks");
    for interim_block_ix in 0..interim_blocks {
        let blocks_processed_before = signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst);
        // submit a tx so that the miner will mine an extra block
        let transfer_tx = make_stacks_transfer(
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
            let blocks_processed = signer_test
                .running_nodes
                .nakamoto_blocks_mined
                .load(Ordering::SeqCst);
            Ok(blocks_processed > blocks_processed_before)
        })
        .unwrap();
        info!("Mined interim block:{interim_block_ix}");
    }

    wait_for(60, || {
        let new_blocks = get_nakamoto_headers(&signer_test.running_nodes.conf);
        Ok(new_blocks.len() == blocks.len() + interim_blocks as usize)
    })
    .unwrap();

    // Verify that every Nakamoto block is mined after the gap is exceeded between each
    let mut blocks = get_nakamoto_headers(&signer_test.running_nodes.conf);
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
    *nakamoto_node::miner::TEST_SKIP_P2P_BROADCAST
        .lock()
        .unwrap() = Some(true);

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let mut signer_stacks_private_keys = (0..num_signers)
        .map(|_| StacksPrivateKey::new())
        .collect::<Vec<_>>();

    // First two signers have same private key
    signer_stacks_private_keys[1] = signer_stacks_private_keys[0];
    let unique_signers = num_signers - 1;
    let duplicate_pubkey = Secp256k1PublicKey::from_private(&signer_stacks_private_keys[0]);
    let duplicate_pubkey_from_copy =
        Secp256k1PublicKey::from_private(&signer_stacks_private_keys[1]);
    assert_eq!(
        duplicate_pubkey, duplicate_pubkey_from_copy,
        "Recovered pubkeys don't match"
    );

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |_| {},
        |_| {},
        None,
        Some(signer_stacks_private_keys),
    );

    signer_test.boot_to_epoch_3();
    let timeout = Duration::from_secs(30);

    info!("------------------------- Try mining one block -------------------------");

    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers);

    info!("------------------------- Read all `BlockResponse::Accepted` messages -------------------------");

    let mut signer_accepted_responses = vec![];
    let start_polling = Instant::now();
    while start_polling.elapsed() <= timeout {
        std::thread::sleep(Duration::from_secs(1));
        let messages = test_observer::get_stackerdb_chunks()
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
        .min_by_key(|accepted| accepted.signer_signature_hash)
        .expect("No `BlockResponse::Accepted` messages recieved");
    let selected_sighash = accepted.signer_signature_hash;

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

/// This test involves two miners, each mining tenures with 6 blocks each. Half
/// of the signers are attached to each miner, so the test also verifies that
/// the signers' messages successfully make their way to the active miner.
#[test]
#[ignore]
fn multiple_miners_with_nakamoto_blocks() {
    let num_signers = 5;
    let max_nakamoto_tenures = 20;
    let inter_blocks_per_tenure = 5;

    // setup sender + recipient for a test stx transfer
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();

    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr,
            (send_amt + send_fee) * max_nakamoto_tenures * inter_blocks_per_tenure,
        )],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Duration::from_secs(5);
            config.node.pox_sync_sample_secs = 30;

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
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
        None,
    );
    let blocks_mined1 = signer_test.running_nodes.nakamoto_blocks_mined.clone();

    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);
    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let Counters {
        naka_submitted_commits: rl2_commits,
        naka_mined_blocks: blocks_mined2,
        ..
    } = run_loop_2.counters();
    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    signer_test.boot_to_epoch_3();

    wait_for(120, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for follower to catch up to the miner");

    let pre_nakamoto_peer_1_height = get_chain_info(&conf).stacks_tip_height;

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    let rl1_coord_channels = signer_test.running_nodes.coord_channel.clone();
    let rl1_commits = signer_test.running_nodes.commits_submitted.clone();

    let miner_1_pk = StacksPublicKey::from_private(conf.miner.mining_key.as_ref().unwrap());
    let miner_2_pk = StacksPublicKey::from_private(conf_node_2.miner.mining_key.as_ref().unwrap());
    let mut btc_blocks_mined = 1;
    let mut miner_1_tenures = 0;
    let mut miner_2_tenures = 0;
    let mut sender_nonce = 0;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        if btc_blocks_mined > max_nakamoto_tenures {
            panic!("Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting");
        }
        let blocks_processed_before =
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
        signer_test.mine_block_wait_on_processing(
            &[&rl1_coord_channels, &rl2_coord_channels],
            &[&rl1_commits, &rl2_commits],
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
            let blocks_processed_before =
                blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
            // submit a tx so that the miner will mine an extra block
            let transfer_tx = make_stacks_transfer(
                &sender_sk,
                sender_nonce,
                send_fee,
                signer_test.running_nodes.conf.burnchain.chain_id,
                &recipient,
                send_amt,
            );
            sender_nonce += 1;
            submit_tx(&http_origin, &transfer_tx);

            wait_for(60, || {
                let blocks_processed =
                    blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
                Ok(blocks_processed > blocks_processed_before)
            })
            .unwrap();
            info!("Mined interim block {btc_blocks_mined}:{interim_block_ix}");
        }

        let blocks = get_nakamoto_headers(&conf);
        let mut seen_burn_hashes = HashSet::new();
        miner_1_tenures = 0;
        miner_2_tenures = 0;
        for header in blocks.iter() {
            if seen_burn_hashes.contains(&header.burn_header_hash) {
                continue;
            }
            seen_burn_hashes.insert(header.burn_header_hash);

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

    info!(
        "New chain info 1: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("New chain info 2: {:?}", get_chain_info(&conf_node_2));

    let peer_1_height = get_chain_info(&conf).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_node_2).stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);
    assert_eq!(
        peer_1_height,
        pre_nakamoto_peer_1_height + (btc_blocks_mined - 1) * (inter_blocks_per_tenure + 1)
    );
    assert_eq!(btc_blocks_mined, miner_1_tenures + miner_2_tenures);
    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

/// This test involves two miners, 1 and 2. During miner 1's first tenure, miner
/// 2 is forced to ignore one of the blocks in that tenure. The next time miner
/// 2 mines a block, it should attempt to fork the chain at that point. The test
/// verifies that the fork is not successful and that miner 1 is able to
/// continue mining after this fork attempt.
#[test]
#[ignore]
fn partial_tenure_fork() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let max_nakamoto_tenures = 30;
    let inter_blocks_per_tenure = 5;

    // setup sender + recipient for a test stx transfer
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");

    // All signers are listening to node 1
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr,
            (send_amt + send_fee) * max_nakamoto_tenures * inter_blocks_per_tenure,
        )],
        |signer_config| {
            signer_config.node_host = node_1_rpc_bind.clone();
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Duration::from_secs(5);
            config.node.pox_sync_sample_secs = 30;

            config.node.seed = btc_miner_1_seed.clone();
            config.node.local_peer_seed = btc_miner_1_seed.clone();
            config.burnchain.local_mining_public_key = Some(btc_miner_1_pk.to_hex());
            config.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[1]));

            // Increase the reward cycle length to avoid missing a prepare phase
            // while we are intentionally forking.
            config.burnchain.pox_reward_length = Some(40);
            config.burnchain.pox_prepare_length = Some(10);

            // Move epoch 2.5 and 3.0 earlier, so we have more time for the
            // test before re-stacking is required.
            if let Some(epochs) = config.burnchain.epochs.as_mut() {
                epochs[6].end_height = 131;
                epochs[7].start_height = 131;
                epochs[7].end_height = 166;
                epochs[8].start_height = 166;
            } else {
                panic!("Expected epochs to be set");
            }
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
        None,
    );
    let blocks_mined1 = signer_test.running_nodes.nakamoto_blocks_mined.clone();

    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let Counters {
        naka_mined_blocks: blocks_mined2,
        naka_proposed_blocks: blocks_proposed2,
        ..
    } = run_loop_2.counters();

    signer_test.boot_to_epoch_3();
    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    let pre_nakamoto_peer_1_height = get_chain_info(&conf).stacks_tip_height;

    wait_for(200, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for follower to catch up to the miner");

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    let mut btc_blocks_mined = 0;
    let mut miner_1_tenures = 0u64;
    let mut miner_2_tenures = 0u64;
    let mut fork_initiated = false;
    let mut min_miner_1_tenures = u64::MAX;
    let mut min_miner_2_tenures = u64::MAX;
    let mut ignore_block = 0;

    let mut miner_1_blocks = 0;
    let mut miner_2_blocks = 0;
    let mut min_miner_2_blocks = 0;

    while miner_1_tenures < min_miner_1_tenures || miner_2_tenures < min_miner_2_tenures {
        if btc_blocks_mined >= max_nakamoto_tenures {
            panic!("Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting");
        }

        // Mine a block and wait for it to be processed, unless we are in a
        // forked tenure, in which case, just wait for the block proposal
        let mined_before_1 = blocks_mined1.load(Ordering::SeqCst);
        let mined_before_2 = blocks_mined2.load(Ordering::SeqCst);
        let proposed_before_2 = blocks_proposed2.load(Ordering::SeqCst);
        let proposed_before_1 = signer_test
            .running_nodes
            .nakamoto_blocks_proposed
            .load(Ordering::SeqCst);

        sleep_ms(1000);

        info!(
            "Next tenure checking";
            "fork_initiated?" => fork_initiated,
            "miner_1_tenures" => miner_1_tenures,
            "miner_2_tenures" => miner_2_tenures,
            "min_miner_1_tenures" => min_miner_2_tenures,
            "min_miner_2_tenures" => min_miner_2_tenures,
            "proposed_before_1" => proposed_before_1,
            "proposed_before_2" => proposed_before_2,
            "mined_before_1" => mined_before_1,
            "mined_before_2" => mined_before_2,
        );

        next_block_and(
            &mut signer_test.running_nodes.btc_regtest_controller,
            60,
            || {
                let mined_1 = blocks_mined1.load(Ordering::SeqCst);
                let mined_2 = blocks_mined2.load(Ordering::SeqCst);
                let proposed_2 = blocks_proposed2.load(Ordering::SeqCst);

                Ok((fork_initiated && proposed_2 > proposed_before_2)
                    || mined_1 > mined_before_1
                    || mined_2 > mined_before_2)
            },
        )
        .unwrap_or_else(|_| {
            let mined_1 = blocks_mined1.load(Ordering::SeqCst);
            let mined_2 = blocks_mined2.load(Ordering::SeqCst);
            let proposed_1 = signer_test
                .running_nodes
                .nakamoto_blocks_proposed
                .load(Ordering::SeqCst);
            let proposed_2 = blocks_proposed2.load(Ordering::SeqCst);
            error!(
                "Next tenure failed to tick";
                "fork_initiated?" => fork_initiated,
                "miner_1_tenures" => miner_1_tenures,
                "miner_2_tenures" => miner_2_tenures,
                "min_miner_1_tenures" => min_miner_2_tenures,
                "min_miner_2_tenures" => min_miner_2_tenures,
                "proposed_before_1" => proposed_before_1,
                "proposed_before_2" => proposed_before_2,
                "mined_before_1" => mined_before_1,
                "mined_before_2" => mined_before_2,
                "mined_1" => mined_1,
                "mined_2" => mined_2,
                "proposed_1" => proposed_1,
                "proposed_2" => proposed_2,
            );
            panic!();
        });
        btc_blocks_mined += 1;

        let mined_1 = blocks_mined1.load(Ordering::SeqCst);
        let miner = if mined_1 > mined_before_1 { 1 } else { 2 };

        if miner == 1 && miner_1_tenures == 0 {
            // Setup miner 2 to ignore a block in this tenure
            ignore_block = pre_nakamoto_peer_1_height
                + (btc_blocks_mined - 1) * (inter_blocks_per_tenure + 1)
                + 3;
            set_ignore_block(ignore_block, &conf_node_2.node.working_dir);

            // Ensure that miner 2 runs at least one more tenure
            min_miner_2_tenures = miner_2_tenures + 1;
            fork_initiated = true;
            min_miner_2_blocks = miner_2_blocks;
        }
        if miner == 2 && miner_2_tenures == min_miner_2_tenures {
            // This is the forking tenure. Ensure that miner 1 runs one more
            // tenure after this to validate that it continues to build off of
            // the proper block.
            min_miner_1_tenures = miner_1_tenures + 1;
        }

        let mut blocks = inter_blocks_per_tenure;
        // mine (or attempt to mine) the interim blocks
        for interim_block_ix in 0..inter_blocks_per_tenure {
            let mined_before_1 = blocks_mined1.load(Ordering::SeqCst);
            let mined_before_2 = blocks_mined2.load(Ordering::SeqCst);
            let proposed_before_2 = blocks_proposed2.load(Ordering::SeqCst);

            info!(
                "Mining interim blocks";
                "fork_initiated?" => fork_initiated,
                "miner_1_tenures" => miner_1_tenures,
                "miner_2_tenures" => miner_2_tenures,
                "min_miner_1_tenures" => min_miner_2_tenures,
                "min_miner_2_tenures" => min_miner_2_tenures,
                "proposed_before_2" => proposed_before_2,
                "mined_before_1" => mined_before_1,
                "mined_before_2" => mined_before_2,
            );

            // submit a tx so that the miner will mine an extra block
            let sender_nonce = (btc_blocks_mined - 1) * inter_blocks_per_tenure + interim_block_ix;
            let transfer_tx = make_stacks_transfer(
                &sender_sk,
                sender_nonce,
                send_fee,
                signer_test.running_nodes.conf.burnchain.chain_id,
                &recipient,
                send_amt,
            );
            // This may fail if the forking miner wins too many tenures and this account's
            // nonces get too high (TooMuchChaining)
            match submit_tx_fallible(&http_origin, &transfer_tx) {
                Ok(_) => {
                    wait_for(60, || {
                        let mined_1 = blocks_mined1.load(Ordering::SeqCst);
                        let mined_2 = blocks_mined2.load(Ordering::SeqCst);
                        let proposed_2 = blocks_proposed2.load(Ordering::SeqCst);

                        Ok((fork_initiated && proposed_2 > proposed_before_2)
                            || mined_1 > mined_before_1
                            || mined_2 > mined_before_2)
                    })
                    .unwrap_or_else(|_| {
                        let mined_1 = blocks_mined1.load(Ordering::SeqCst);
                        let mined_2 = blocks_mined2.load(Ordering::SeqCst);
                        let proposed_1 = signer_test
                            .running_nodes
                            .nakamoto_blocks_proposed
                            .load(Ordering::SeqCst);
                        let proposed_2 = blocks_proposed2.load(Ordering::SeqCst);
                        error!(
                            "Next tenure failed to tick";
                            "fork_initiated?" => fork_initiated,
                            "miner_1_tenures" => miner_1_tenures,
                            "miner_2_tenures" => miner_2_tenures,
                            "min_miner_1_tenures" => min_miner_2_tenures,
                            "min_miner_2_tenures" => min_miner_2_tenures,
                            "proposed_before_1" => proposed_before_1,
                            "proposed_before_2" => proposed_before_2,
                            "mined_before_1" => mined_before_1,
                            "mined_before_2" => mined_before_2,
                            "mined_1" => mined_1,
                            "mined_2" => mined_2,
                            "proposed_1" => proposed_1,
                            "proposed_2" => proposed_2,
                        );
                        panic!();
                    });
                }
                Err(e) => {
                    if e.to_string().contains("TooMuchChaining") {
                        info!("TooMuchChaining error, skipping block");
                        blocks = interim_block_ix;
                        break;
                    } else {
                        panic!("Failed to submit tx: {e}");
                    }
                }
            }
            info!("Attempted to mine interim block {btc_blocks_mined}:{interim_block_ix}");
        }

        if miner == 1 {
            miner_1_tenures += 1;
            miner_1_blocks += blocks;
        } else {
            miner_2_tenures += 1;
            miner_2_blocks += blocks;
        }

        let mined_1 = blocks_mined1.load(Ordering::SeqCst);
        let mined_2 = blocks_mined2.load(Ordering::SeqCst);

        info!(
            "Miner 1 tenures: {miner_1_tenures}, Miner 2 tenures: {miner_2_tenures}, Miner 1 before: {mined_before_1}, Miner 2 before: {mined_before_2}, Miner 1 blocks: {mined_1}, Miner 2 blocks: {mined_2}",
        );

        if miner == 1 {
            assert_eq!(mined_1, mined_before_1 + blocks + 1);
        } else if miner_2_tenures < min_miner_2_tenures {
            assert_eq!(mined_2, mined_before_2 + blocks + 1);
        } else {
            // Miner 2 should have mined 0 blocks after the fork
            assert_eq!(mined_2, mined_before_2);
        }
    }

    info!(
        "New chain info 1: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("New chain info 2: {:?}", get_chain_info(&conf_node_2));

    let peer_1_height = get_chain_info(&conf).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_node_2).stacks_tip_height;
    assert_eq!(peer_2_height, ignore_block - 1);
    // The height may be higher than expected due to extra transactions waiting
    // to be mined during the forking miner's tenure.
    // We cannot guarantee due to TooMuchChaining that the miner will mine inter_blocks_per_tenure
    // Must be at least the number of blocks mined by miner 1 and the number of blocks mined by miner 2
    // before the fork was initiated
    assert!(peer_1_height >= pre_nakamoto_peer_1_height + miner_1_blocks + min_miner_2_blocks);
    assert_eq!(btc_blocks_mined, miner_1_tenures + miner_2_tenures);

    let sortdb = SortitionDB::open(
        &conf_node_2.get_burn_db_file_path(),
        false,
        conf_node_2.get_burnchain().pox_constants,
    )
    .unwrap();

    let (chainstate, _) = StacksChainState::open(
        false,
        conf_node_2.burnchain.chain_id,
        &conf_node_2.get_chainstate_path_str(),
        None,
    )
    .unwrap();
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
        .unwrap()
        .unwrap();
    assert_eq!(tip.stacks_block_height, ignore_block - 1);
    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that signers that accept a block locally, but that was rejected globally will accept a subsequent attempt
/// by the miner essentially reorg their prior locally accepted/signed block, i.e. the globally rejected block overrides
/// their local view.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but rejected by >30% of the signers.
/// The miner then attempts to mine N+1', and all signers accept the block.
///
/// Test Assertion:
/// Stacks tip advances to N+1'
fn locally_accepted_blocks_overriden_by_global_rejection() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let short_timeout_secs = 20;
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
    );

    let all_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let info_before = signer_test.stacks_client.get_peer_info().unwrap();
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N");
    wait_for(short_timeout_secs, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before
            && signer_test
                .stacks_client
                .get_peer_info()
                .unwrap()
                .stacks_tip_height
                > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks block N to be mined");
    sender_nonce += 1;
    let info_after = signer_test.stacks_client.get_peer_info().unwrap();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n.block_hash);
    signer_test
        .wait_for_block_acceptance(
            short_timeout_secs,
            &block_n.signer_signature_hash,
            &all_signers,
        )
        .expect("Timed out waiting for block acceptance of N");

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Make half of the signers reject the block proposal by the miner to ensure its marked globally rejected
    let rejecting_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers / 2 + num_signers % 2)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(rejecting_signers.clone());
    test_observer::clear();
    // Make a new stacks transaction to create a different block signature, but make sure to propose it
    // AFTER the signers are unfrozen so they don't inadvertently prevent the new block being accepted
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} to mine block N+1");

    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test.stacks_client.get_peer_info().unwrap();
    // We cannot gaurantee that ALL signers will reject due to the testing directive as we may hit majority first..So ensure that we only assert that up to the threshold number rejected
    signer_test
        .wait_for_block_rejections(short_timeout_secs, &rejecting_signers)
        .expect("Timed out waiting for block rejection of N+1");

    assert_eq!(blocks_before, mined_blocks.load(Ordering::SeqCst));
    let info_after = signer_test.stacks_client.get_peer_info().unwrap();
    assert_eq!(info_before, info_after);
    // Ensure that the block was not accepted globally so the stacks tip has not advanced to N+1
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1 = nakamoto_blocks.last().unwrap();
    assert_ne!(block_n_1, block_n);

    info!("------------------------- Test Mine Nakamoto Block N+1' -------------------------");
    let info_before = signer_test.stacks_client.get_peer_info().unwrap();
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(Vec::new());

    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} to mine block N+1'");

    wait_for(short_timeout_secs, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before
            && signer_test
                .stacks_client
                .get_peer_info()
                .unwrap()
                .stacks_tip_height
                > info_before.stacks_tip_height
            && test_observer::get_mined_nakamoto_blocks().last().unwrap() != block_n_1)
    })
    .expect("Timed out waiting for stacks block N+1' to be mined");
    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    assert_eq!(blocks_after, blocks_before + 1);

    let info_after = signer_test.stacks_client.get_peer_info().unwrap();
    assert_eq!(
        info_after.stacks_tip_height,
        info_before.stacks_tip_height + 1
    );
    // Ensure that the block was accepted globally so the stacks tip has advanced to N+1'
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1_prime = nakamoto_blocks.last().unwrap();
    assert_eq!(
        info_after.stacks_tip.to_string(),
        block_n_1_prime.block_hash
    );
    assert_ne!(block_n_1_prime, block_n_1);
    // Verify that all signers accepted the new block proposal
    signer_test
        .wait_for_block_acceptance(
            short_timeout_secs,
            &block_n_1_prime.signer_signature_hash,
            &all_signers,
        )
        .expect("Timed out waiting for block acceptance of N+1'");
}

#[test]
#[ignore]
/// Test that signers that reject a block locally, but that was accepted globally will accept
/// a subsequent block built on top of the accepted block
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but rejected by <30% of the signers.
/// The miner then attempts to mine N+2, and all signers accept the block.
///
/// Test Assertion:
/// Stacks tip advances to N+2
fn locally_rejected_blocks_overriden_by_global_acceptance() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;

    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
    );

    let all_signers: Vec<_> = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect();

    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    // submit a tx so that the miner will mine a stacks block N
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N");

    wait_for(short_timeout, || {
        Ok(signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .stacks_tip_height
            > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for N to be mined and processed");

    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );

    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n.block_hash);

    // Make sure that ALL signers accepted the block proposal
    signer_test
        .wait_for_block_acceptance(short_timeout, &block_n.signer_signature_hash, &all_signers)
        .expect("Timed out waiting for block acceptance of N");

    info!("------------------------- Mine Nakamoto Block N+1 -------------------------");
    // Make less than 30% of the signers reject the block and ensure it is STILL marked globally accepted
    let rejecting_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 3 / 10)
        .collect();
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(rejecting_signers.clone());
    test_observer::clear();

    // submit a tx so that the miner will mine a stacks block N+1
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N+1");

    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before
            && signer_test
                .stacks_client
                .get_peer_info()
                .unwrap()
                .stacks_tip_height
                > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks block N+1 to be mined");

    signer_test
        .wait_for_block_rejections(short_timeout, &rejecting_signers)
        .expect("Timed out waiting for block rejection of N+1");

    // Assert the block was mined
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(blocks_before + 1, mined_blocks.load(Ordering::SeqCst));
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );

    // Ensure that the block was still accepted globally so the stacks tip has advanced to N+1
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1 = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n_1.block_hash);
    assert_ne!(block_n_1, block_n);

    signer_test
        .wait_for_block_acceptance(
            short_timeout,
            &block_n_1.signer_signature_hash,
            &all_signers[num_signers * 3 / 10 + 1..],
        )
        .expect("Timed out waiting for block acceptance of N+1");

    info!("------------------------- Test Mine Nakamoto Block N+2 -------------------------");
    // Ensure that all signers accept the block proposal N+2
    let info_before = signer_test.stacks_client.get_peer_info().unwrap();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(Vec::new());

    // submit a tx so that the miner will mine a stacks block N+2 and ensure ALL signers accept it
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N+2");
    wait_for(30, || {
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before
            && signer_test
                .stacks_client
                .get_peer_info()
                .unwrap()
                .stacks_tip_height
                > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for stacks block N+2 to be mined");
    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    assert_eq!(blocks_after, blocks_before + 1);

    let info_after = signer_test.stacks_client.get_peer_info().unwrap();
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height,
    );
    // Ensure that the block was accepted globally so the stacks tip has advanced to N+2
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_2 = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n_2.block_hash);
    assert_ne!(block_n_2, block_n_1);

    // Make sure that ALL signers accepted the block proposal
    signer_test
        .wait_for_block_acceptance(
            short_timeout,
            &block_n_2.signer_signature_hash,
            &all_signers,
        )
        .expect("Timed out waiting for block acceptance of N+2");
}

#[test]
#[ignore]
/// Test that signers that have accepted a locally signed block N+1 built in tenure A can sign a block proposed during a
/// new tenure B built upon the last globally accepted block N if the timeout is exceeded, i.e. a reorg can occur at a tenure boundary.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but <30% accept it. The remaining signers
/// do not make a decision on the block. A new tenure begins and the miner proposes a new block N+1' which all signers accept.
///
/// Test Assertion:
/// Stacks tip advances to N+1'
fn reorg_locally_accepted_blocks_across_tenures_succeeds() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 2;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            // Just accept all reorg attempts
            config.tenure_last_block_proposal_timeout = Duration::from_secs(0);
        },
        |config| {
            config.miner.block_commit_delay = Duration::from_secs(0);
        },
        None,
        None,
    );
    let all_signers = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect::<Vec<_>>();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();
    info!("------------------------- Starting Tenure A -------------------------");
    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N");
    wait_for(short_timeout, || {
        let info_after = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info");
        Ok(info_after.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block to be mined and processed");

    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n.block_hash);

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Make more than >70% of the signers ignore the block proposal to ensure it it is not globally accepted/rejected
    let ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 7 / 10)
        .collect();
    let non_ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .skip(num_signers * 7 / 10)
        .collect();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS
        .lock()
        .unwrap()
        .replace(ignoring_signers.clone());
    // Clear the stackerdb chunks
    test_observer::clear();

    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    // submit a tx so that the miner will ATTEMPT to mine a stacks block N+1
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);

    info!("Submitted tx {tx} in to attempt to mine block N+1");
    wait_for(short_timeout, || {
        let accepted_signers = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        non_ignoring_signers.iter().find(|key| {
                            key.verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                                .is_ok()
                        })
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        Ok(accepted_signers.len() + ignoring_signers.len() == num_signers)
    })
    .expect("FAIL: Timed out waiting for block proposal acceptance");

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(blocks_after, blocks_before);
    assert_eq!(info_after, info_before);
    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N+1
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1 = nakamoto_blocks.last().unwrap();
    assert_ne!(block_n_1, block_n);
    assert_ne!(info_after.stacks_tip.to_string(), block_n_1.block_hash);

    info!("------------------------- Starting Tenure B -------------------------");
    // Start a new tenure and ensure the miner can propose a new block N+1' that is accepted by all signers
    let commits_submitted = signer_test.running_nodes.commits_submitted.clone();
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    info!(
        "------------------------- Mine Nakamoto Block N+1' in Tenure B -------------------------"
    );
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    TEST_IGNORE_ALL_BLOCK_PROPOSALS
        .lock()
        .unwrap()
        .replace(Vec::new());
    wait_for(short_timeout, || {
        let info_after = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info");
        Ok(info_after.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block to be mined and processed");

    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );

    // Ensure that the block was accepted globally so the stacks tip has advanced to N+1'
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1_prime = nakamoto_blocks.last().unwrap();
    assert_eq!(
        info_after.stacks_tip.to_string(),
        block_n_1_prime.block_hash
    );
    assert_ne!(block_n_1_prime, block_n);

    // Make sure that ALL signers accepted the block proposal even though they signed a conflicting one in prior tenure
    signer_test
        .wait_for_block_acceptance(30, &block_n_1_prime.signer_signature_hash, &all_signers)
        .expect("Timed out waiting for block acceptance of N+1'");
}

#[test]
#[ignore]
/// Test that signers that have accepted a locally signed block N+1 built in tenure A cannot sign a block proposed during a
/// new tenure B built upon the last globally accepted block N if the timeout is not exceeded, i.e. a reorg cannot occur at a tenure boundary
/// before the specified timeout has been exceeded.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a corresponding bitcoind.
/// The stacks node is then advanced to Epoch 3.0 boundary to allow block signing.
///
/// Test Execution:
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but <30% accept it. The remaining signers
/// do not make a decision on the block. A new tenure begins and the miner proposes a new block N+1' which all signers reject as the timeout
/// has not been exceeded.
///
/// Test Assertion:
/// Stacks tip remains at N.
fn reorg_locally_accepted_blocks_across_tenures_fails() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 2;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
        |config| {
            // Do not alow any reorg attempts essentially
            config.tenure_last_block_proposal_timeout = Duration::from_secs(100_000);
        },
        |_| {},
        None,
        None,
    );
    let all_signers = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect::<Vec<_>>();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    let short_timeout = 30;
    signer_test.boot_to_epoch_3();
    info!("------------------------- Starting Tenure A -------------------------");
    info!("------------------------- Test Mine Nakamoto Block N -------------------------");
    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    sender_nonce += 1;
    info!("Submitted tx {tx} in to mine block N");
    wait_for(short_timeout, || {
        let info_after = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info");
        Ok(info_after.stacks_tip_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block to be mined and processed");

    // Ensure that the block was accepted globally so the stacks tip has advanced to N
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n.block_hash);

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Make more than >70% of the signers ignore the block proposal to ensure it it is not globally accepted/rejected
    let ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .take(num_signers * 7 / 10)
        .collect();
    let non_ignoring_signers: Vec<_> = all_signers
        .iter()
        .cloned()
        .skip(num_signers * 7 / 10)
        .collect();
    TEST_IGNORE_ALL_BLOCK_PROPOSALS
        .lock()
        .unwrap()
        .replace(ignoring_signers.clone());
    // Clear the stackerdb chunks
    test_observer::clear();

    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    // submit a tx so that the miner will ATTEMPT to mine a stacks block N+1
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);

    info!("Submitted tx {tx} in to attempt to mine block N+1");
    wait_for(short_timeout, || {
        let accepted_signers = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        non_ignoring_signers.iter().find(|key| {
                            key.verify(accepted.signer_signature_hash.bits(), &accepted.signature)
                                .is_ok()
                        })
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        Ok(accepted_signers.len() + ignoring_signers.len() == num_signers)
    })
    .expect("FAIL: Timed out waiting for block proposal acceptance");

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(blocks_after, blocks_before);
    assert_eq!(info_after, info_before);
    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N+1
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1 = nakamoto_blocks.last().unwrap();
    assert_ne!(block_n_1, block_n);
    assert_ne!(info_after.stacks_tip.to_string(), block_n_1.block_hash);

    info!("------------------------- Starting Tenure B -------------------------");
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    // Clear the test observer so any old rejections are not counted
    test_observer::clear();

    // Start a new tenure and ensure the we see the expected rejections
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let rejected_signers = test_observer::get_stackerdb_chunks()
                .into_iter()
                .flat_map(|chunk| chunk.modified_slots)
                .filter_map(|chunk| {
                    let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                        .expect("Failed to deserialize SignerMessage");
                    match message {
                        SignerMessage::BlockResponse(BlockResponse::Rejected(BlockRejection {
                            signature,
                            signer_signature_hash,
                            ..
                        })) => non_ignoring_signers.iter().find(|key| {
                            key.verify(signer_signature_hash.bits(), &signature).is_ok()
                        }),
                        _ => None,
                    }
                })
                .collect::<Vec<_>>();
            Ok(rejected_signers.len() + ignoring_signers.len() == num_signers)
        },
    )
    .expect("FAIL: Timed out waiting for block proposal rejections");

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(blocks_after, blocks_before);
    assert_eq!(info_after.stacks_tip, info_before.stacks_tip);
    // Ensure that the block was NOT accepted globally so the stacks tip has NOT advanced to N+1'
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_1_prime = nakamoto_blocks.last().unwrap();
    assert_ne!(block_n_1, block_n_1_prime);
    assert_ne!(
        info_after.stacks_tip.to_string(),
        block_n_1_prime.block_hash
    );
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
/// The node mines 1 stacks block N (all signers sign it). The subsequent block N+1 is proposed, but >70% accept it.
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let nmb_txs = 3;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * nmb_txs)],
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
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

    let mined_blocks = signer_test.running_nodes.nakamoto_blocks_mined.clone();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    // submit a tx so that the miner will mine a stacks block
    let mut sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to mine block N");

    // a tenure has begun, so wait until we mine a block
    wait_for(30, || {
        let new_height = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .stacks_tip_height;
        Ok(mined_blocks.load(Ordering::SeqCst) > blocks_before
            && new_height > info_before.stacks_tip_height)
    })
    .expect("Timed out waiting for block to be mined and processed");

    sender_nonce += 1;
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(
        info_before.stacks_tip_height + 1,
        info_after.stacks_tip_height
    );

    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n.block_hash);

    info!("------------------------- Attempt to Mine Nakamoto Block N+1 -------------------------");
    // Propose a valid block, but force the miner to ignore the returned signatures and delay the block being
    // broadcasted to the miner so it can end its tenure before block confirmation obtained
    // Clear the stackerdb chunks
    info!("Forcing miner to ignore block responses for block N+1");
    TEST_IGNORE_SIGNERS.lock().unwrap().replace(true);
    info!("Delaying signer block N+1 broadcasting to the miner");
    TEST_PAUSE_BLOCK_BROADCAST.lock().unwrap().replace(true);
    test_observer::clear();
    let blocks_before = mined_blocks.load(Ordering::SeqCst);
    let info_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    let transfer_tx = make_stacks_transfer(
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
    let mut block = None;
    wait_for(30, || {
        block = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .find_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockProposal(proposal) => {
                        if proposal.block.header.consensus_hash
                            == info_before.stacks_tip_consensus_hash
                        {
                            Some(proposal.block)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            });
        let Some(block) = &block else {
            return Ok(false);
        };
        let signatures = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockResponse(BlockResponse::Accepted(accepted)) => {
                        if block.header.signer_signature_hash() == accepted.signer_signature_hash {
                            Some(accepted.signature)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        Ok(signatures.len() == num_signers)
    })
    .expect("Test timed out while waiting for signers signatures for first block proposal");
    let block = block.unwrap();

    let blocks_after = mined_blocks.load(Ordering::SeqCst);
    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");
    assert_eq!(blocks_after, blocks_before);
    assert_eq!(info_after, info_before);
    // Ensure that the block was not yet broadcasted to the miner so the stacks tip has NOT advanced to N+1
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_same = nakamoto_blocks.last().unwrap();
    assert_ne!(block_n_same, block_n);
    assert_ne!(info_after.stacks_tip.to_string(), block_n_same.block_hash);

    info!("------------------------- Starting Tenure B -------------------------");
    let commits_submitted = signer_test.running_nodes.commits_submitted.clone();
    let commits_before = commits_submitted.load(Ordering::SeqCst);
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let commits_count = commits_submitted.load(Ordering::SeqCst);
            Ok(commits_count > commits_before)
        },
    )
    .unwrap();

    info!(
        "------------------------- Attempt to Mine Nakamoto Block N+1' -------------------------"
    );
    // Wait for the miner to propose a new invalid block N+1'
    let mut rejected_block = None;
    wait_for(30, || {
        rejected_block = test_observer::get_stackerdb_chunks()
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .find_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockProposal(proposal) => {
                        if proposal.block.header.consensus_hash != block.header.consensus_hash {
                            assert!(
                                proposal.block.header.chain_length == block.header.chain_length
                            );
                            Some(proposal.block)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            });
        Ok(rejected_block.is_some())
    })
    .expect("Timed out waiting for block proposal of N+1' block proposal");

    info!("Allowing miner to accept block responses again. ");
    TEST_IGNORE_SIGNERS.lock().unwrap().replace(false);
    info!("Allowing signers to broadcast block N+1 to the miner");
    TEST_PAUSE_BLOCK_BROADCAST.lock().unwrap().replace(false);

    // Assert the N+1' block was rejected
    let rejected_block = rejected_block.unwrap();
    wait_for(30, || {
        let stackerdb_events = test_observer::get_stackerdb_chunks();
        let block_rejections = stackerdb_events
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter_map(|chunk| {
                let message = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                    .expect("Failed to deserialize SignerMessage");
                match message {
                    SignerMessage::BlockResponse(BlockResponse::Rejected(rejection)) => {
                        if rejection.signer_signature_hash
                            == rejected_block.header.signer_signature_hash()
                        {
                            Some(rejection)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        Ok(block_rejections.len() == num_signers)
    })
    .expect("FAIL: Timed out waiting for block proposal rejections");

    // Induce block N+2 to get mined
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );

    let tx = submit_tx(&http_origin, &transfer_tx);
    info!("Submitted tx {tx} in to attempt to mine block N+2");

    info!("------------------------- Asserting a both N+1 and N+2 are accepted -------------------------");
    wait_for(30, || {
        // N.B. have to use /v2/info because mined_blocks only increments if the miner's signing
        // coordinator returns successfully (meaning, mined_blocks won't increment for block N+1)
        let info = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info");

        Ok(info_before.stacks_tip_height + 2 <= info.stacks_tip_height)
    })
    .expect("Timed out waiting for blocks to be mined");

    let info_after = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    assert_eq!(
        info_before.stacks_tip_height + 2,
        info_after.stacks_tip_height
    );
    let nmb_signatures = signer_test
        .stacks_client
        .get_tenure_tip(&info_after.stacks_tip_consensus_hash)
        .expect("Failed to get tip")
        .as_stacks_nakamoto()
        .expect("Not a Nakamoto block")
        .signer_signature
        .len();
    assert!(nmb_signatures >= num_signers * 7 / 10);

    // Ensure that the block was accepted globally so the stacks tip has advanced to N+2
    let nakamoto_blocks = test_observer::get_mined_nakamoto_blocks();
    let block_n_2 = nakamoto_blocks.last().unwrap();
    assert_eq!(info_after.stacks_tip.to_string(), block_n_2.block_hash);
    assert_ne!(block_n_2, block_n);
}

/// Test a scenario where:
/// Two miners boot to Nakamoto.
/// Miner 1 wins the first tenure and proposes a block N with a TenureChangePayload
/// Signers accept and the stacks tip advances to N
/// Miner 2 wins the second tenure B but its proposed blocks are rejected by the signers.
/// Mine 2 empty burn blocks (simulate fast blocks scenario)
/// Miner 2 proposes block N+1 with a TenureChangePayload
/// Signers accept and the stacks tip advances to N+1
/// Miner 2 proposes block N+2 with a TokenTransfer
/// Signers accept and the stacks tip advances to N+2
/// Mine an empty burn block
/// Miner 2 proposes block N+3 with a TenureExtend
/// Signers accept and the chain advances to N+3
/// Miner 1 wins the next tenure and proposes a block N+4 with a TenureChangePayload
/// Signers accept and the chain advances to N+4
/// Asserts:
/// - Block N+1 contains the TenureChangePayload
/// - Block N+2 contains the TokenTransfer
/// - Block N+3 contains the TenureExtend
/// - Block N+4 contains the TenureChangePayload
/// - The stacks tip advances to N+4
#[test]
#[ignore]
fn continue_after_fast_block_no_sortition() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let num_txs = 1;
    let sender_nonce = 0;

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();

    let max_nakamoto_tenures = 30;

    info!("------------------------- Test Setup -------------------------");
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, (send_amt + send_fee) * num_txs)],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Duration::from_secs(5);
            config.node.pox_sync_sample_secs = 30;
            config.burnchain.pox_reward_length = Some(max_nakamoto_tenures);

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
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
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
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);
    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let Counters {
        naka_submitted_commits: rl2_commits,
        naka_skip_commit_op: rl2_skip_commit_op,
        naka_mined_blocks: blocks_mined2,
        ..
    } = run_loop_2.counters();

    let rl1_commits = signer_test.running_nodes.commits_submitted.clone();
    let blocks_mined1 = signer_test.running_nodes.nakamoto_blocks_mined.clone();

    // Some helper functions for verifying the blocks contain their expected transactions
    let verify_last_block_contains_tenure_change_tx = |cause: TenureChangeCause| {
        let blocks = test_observer::get_blocks();
        let tenure_change_tx = &blocks.last().unwrap();
        let transactions = tenure_change_tx["transactions"].as_array().unwrap();
        let tx = transactions.first().expect("No transactions in block");
        let raw_tx = tx["raw_tx"].as_str().unwrap();
        let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
        let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
        match &parsed.payload {
            TransactionPayload::TenureChange(payload) => {
                assert_eq!(payload.cause, cause);
            }
            _ => panic!("Expected tenure change transaction, got {parsed:?}"),
        };
    };

    let verify_last_block_contains_transfer_tx = || {
        let blocks = test_observer::get_blocks();
        let tenure_change_tx = &blocks.last().unwrap();
        let transactions = tenure_change_tx["transactions"].as_array().unwrap();
        let tx = transactions.first().expect("No transactions in block");
        let raw_tx = tx["raw_tx"].as_str().unwrap();
        let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
        let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
        assert!(
            matches!(parsed.payload, TransactionPayload::TokenTransfer(_, _, _)),
            "Expected token transfer transaction, got {parsed:?}"
        );
    };

    info!("------------------------- Pause Miner 2's Block Commits -------------------------");

    // Make sure Miner 2 cannot win a sortition at first.
    rl2_skip_commit_op.set(true);

    info!("------------------------- Boot to Epoch 3.0 -------------------------");

    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    signer_test.boot_to_epoch_3();

    wait_for(120, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for boostrapped node to catch up to the miner");

    let mining_pkh_1 = Hash160::from_node_public_key(&StacksPublicKey::from_private(
        &conf.miner.mining_key.unwrap(),
    ));
    let mining_pkh_2 = Hash160::from_node_public_key(&StacksPublicKey::from_private(
        &conf_node_2.miner.mining_key.unwrap(),
    ));
    debug!("The mining key for miner 1 is {mining_pkh_1}");
    debug!("The mining key for miner 2 is {mining_pkh_2}");

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    let burnchain = signer_test.running_nodes.conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();

    let all_signers = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect::<Vec<_>>();
    let get_burn_height = || {
        SortitionDB::get_canonical_burn_chain_tip(sortdb.conn())
            .unwrap()
            .block_height
    };
    let starting_peer_height = get_chain_info(&conf).stacks_tip_height;
    let starting_burn_height = get_burn_height();
    let mut btc_blocks_mined = 0;

    info!("------------------------- Pause Miner 1's Block Commit -------------------------");
    // Make sure miner 1 doesn't submit any further block commits for the next tenure BEFORE mining the bitcoin block
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .set(true);

    info!("------------------------- Miner 1 Mines a Normal Tenure A -------------------------");
    let blocks_processed_before_1 = blocks_mined1.load(Ordering::SeqCst);
    let nmb_old_blocks = test_observer::get_blocks().len();
    let stacks_height_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info")
        .stacks_tip_height;

    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner A won
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(tip.sortition);
    assert_eq!(tip.miner_pk_hash.unwrap(), mining_pkh_1);

    // wait for the new block to be processed
    wait_for(60, || {
        let stacks_height = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .stacks_tip_height;
        Ok(
            blocks_mined1.load(Ordering::SeqCst) > blocks_processed_before_1
                && stacks_height > stacks_height_before
                && test_observer::get_blocks().len() > nmb_old_blocks,
        )
    })
    .unwrap();

    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!("------------------------- Make Signers Reject All Subsequent Proposals -------------------------");

    let stacks_height_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info")
        .stacks_tip_height;

    // Make all signers ignore block proposals
    let ignoring_signers = all_signers.to_vec();
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(ignoring_signers.clone());

    info!("------------------------- Submit Miner 2 Block Commit -------------------------");
    let rejections_before = signer_test
        .running_nodes
        .nakamoto_blocks_rejected
        .load(Ordering::SeqCst);

    let rl2_commits_before = rl2_commits.load(Ordering::SeqCst);
    // Unpause miner 2's block commits
    rl2_skip_commit_op.set(false);

    // Ensure the miner 2 submits a block commit before mining the bitcoin block
    wait_for(30, || {
        Ok(rl2_commits.load(Ordering::SeqCst) > rl2_commits_before)
    })
    .unwrap();

    // Make miner 2 also fail to submit any FURTHER block commits
    rl2_skip_commit_op.set(true);

    let burn_height_before = get_burn_height();

    info!("------------------------- Miner 2 Mines an Empty Tenure B -------------------------";
        "burn_height_before" => burn_height_before,
        "rejections_before" => rejections_before,
    );

    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || Ok(get_burn_height() > burn_height_before),
    )
    .unwrap();
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner B won
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(tip.sortition);
    assert_eq!(tip.miner_pk_hash.unwrap(), mining_pkh_2);

    info!("----- Waiting for block rejections -----");
    let min_rejections = num_signers * 4 / 10;
    // Wait until we have some block rejections
    wait_for(30, || {
        std::thread::sleep(Duration::from_secs(1));
        let chunks = test_observer::get_stackerdb_chunks();
        let rejections: Vec<_> = chunks
            .into_iter()
            .flat_map(|chunk| chunk.modified_slots)
            .filter(|chunk| {
                let Ok(message) = SignerMessage::consensus_deserialize(&mut chunk.data.as_slice())
                else {
                    return false;
                };
                matches!(
                    message,
                    SignerMessage::BlockResponse(BlockResponse::Rejected(_))
                )
            })
            .collect();
        Ok(rejections.len() >= min_rejections)
    })
    .expect("Timed out waiting for block rejections");

    // Mine another couple burn blocks and ensure there is _no_ sortition
    info!("------------------------- Mine Two Burn Block(s) with No Sortitions -------------------------");
    for _ in 0..2 {
        let blocks_processed_before_1 = blocks_mined1.load(Ordering::SeqCst);
        let blocks_processed_before_2 = blocks_mined2.load(Ordering::SeqCst);
        let burn_height_before = get_burn_height();
        let commits_before_1 = rl1_commits.load(Ordering::SeqCst);
        let commits_before_2 = rl2_commits.load(Ordering::SeqCst);

        next_block_and(
            &mut signer_test.running_nodes.btc_regtest_controller,
            30,
            || Ok(get_burn_height() > burn_height_before),
        )
        .unwrap();
        btc_blocks_mined += 1;

        assert_eq!(rl1_commits.load(Ordering::SeqCst), commits_before_1);
        assert_eq!(rl2_commits.load(Ordering::SeqCst), commits_before_2);
        assert_eq!(
            blocks_mined1.load(Ordering::SeqCst),
            blocks_processed_before_1
        );
        assert_eq!(
            blocks_mined2.load(Ordering::SeqCst),
            blocks_processed_before_2
        );

        // assure we have NO sortition
        let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        assert!(!tip.sortition);
    }

    // Verify that no Stacks blocks have been mined (signers are ignoring) and no commits have been submitted by either miner
    let stacks_height = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info")
        .stacks_tip_height;
    assert_eq!(stacks_height, stacks_height_before);
    let stacks_height_before = stacks_height;

    info!("------------------------- Enabling Signer Block Proposals -------------------------";
        "stacks_height" => stacks_height_before,
    );

    let blocks_processed_before_2 = blocks_mined2.load(Ordering::SeqCst);
    let nmb_old_blocks = test_observer::get_blocks().len();
    // Allow signers to respond to proposals again
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(Vec::new());

    info!("------------------------- Wait for Miner B's Block N -------------------------");
    // wait for the new block to be processed
    wait_for(30, || {
        let stacks_height = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .stacks_tip_height;
        Ok(
            blocks_mined2.load(Ordering::SeqCst) > blocks_processed_before_2
                && stacks_height > stacks_height_before
                && test_observer::get_blocks().len() > nmb_old_blocks,
        )
    })
    .expect("Timed out waiting for block to be mined and processed");

    info!(
        "------------------------- Verify Tenure Change Tx in Miner B's Block N -------------------------"
    );
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!("------------------------- Wait for Miner B's Block N+1 -------------------------");

    let nmb_old_blocks = test_observer::get_blocks().len();
    let blocks_processed_before_2 = blocks_mined2.load(Ordering::SeqCst);
    let stacks_height_before = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info")
        .stacks_tip_height;

    // submit a tx so that the miner will mine an extra block
    let transfer_tx = make_stacks_transfer(
        &sender_sk,
        sender_nonce,
        send_fee,
        signer_test.running_nodes.conf.burnchain.chain_id,
        &recipient,
        send_amt,
    );
    submit_tx(&http_origin, &transfer_tx);

    // wait for the new block to be processed
    wait_for(30, || {
        let stacks_height = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .stacks_tip_height;
        Ok(
            blocks_mined2.load(Ordering::SeqCst) > blocks_processed_before_2
                && stacks_height > stacks_height_before
                && test_observer::get_blocks().len() > nmb_old_blocks,
        )
    })
    .expect("Timed out waiting for block to be mined and processed");

    info!("------------------------- Verify Miner B's Block N+1 -------------------------");

    verify_last_block_contains_transfer_tx();

    info!("------------------------- Mine An Empty Sortition -------------------------");
    let nmb_old_blocks = test_observer::get_blocks().len();
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            Ok(get_burn_height() > burn_height_before
                && test_observer::get_blocks().len() > nmb_old_blocks)
        },
    )
    .unwrap();
    btc_blocks_mined += 1;

    info!("------------------------- Verify Miner B's Issues a Tenure Change Extend in Block N+2 -------------------------");
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::Extended);

    info!("------------------------- Unpause Miner A's Block Commits -------------------------");
    let commits_before_1 = rl1_commits.load(Ordering::SeqCst);
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .set(false);
    wait_for(30, || {
        Ok(rl1_commits.load(Ordering::SeqCst) > commits_before_1)
    })
    .unwrap();

    info!("------------------------- Run Miner A's Tenure -------------------------");
    let nmb_old_blocks = test_observer::get_blocks().len();
    let burn_height_before = get_burn_height();
    let blocks_processed_before_1 = blocks_mined1.load(Ordering::SeqCst);
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            Ok(get_burn_height() > burn_height_before
                && blocks_mined1.load(Ordering::SeqCst) > blocks_processed_before_1
                && test_observer::get_blocks().len() > nmb_old_blocks)
        },
    )
    .unwrap();
    btc_blocks_mined += 1;

    // assure we have a successful sortition that miner A won
    let tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
    assert!(tip.sortition);
    assert_eq!(tip.miner_pk_hash.unwrap(), mining_pkh_1);

    info!("------------------------- Verify Miner A's Issued a Tenure Change in Block N+4 -------------------------");
    verify_last_block_contains_tenure_change_tx(TenureChangeCause::BlockFound);

    info!(
        "------------------------- Confirm Burn and Stacks Block Heights -------------------------"
    );
    let peer_info = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info");

    assert_eq!(get_burn_height(), starting_burn_height + btc_blocks_mined);
    assert_eq!(peer_info.stacks_tip_height, starting_peer_height + 5);

    info!("------------------------- Shutdown -------------------------");
    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
}

#[test]
#[ignore]
/// Test that we can mine a tenure extend and then continue mining afterwards.
fn continue_after_tenure_extend() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");
    let num_signers = 5;
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let send_amt = 100;
    let send_fee = 180;
    let mut signer_test: SignerTest<SpawnedSigner> =
        SignerTest::new(num_signers, vec![(sender_addr, (send_amt + send_fee) * 5)]);
    let timeout = Duration::from_secs(200);
    let coord_channel = signer_test.running_nodes.coord_channel.clone();
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);

    signer_test.boot_to_epoch_3();

    info!("------------------------- Mine Normal Tenure -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers);

    info!("------------------------- Extend Tenure -------------------------");
    signer_test
        .running_nodes
        .nakamoto_test_skip_commit_op
        .set(true);

    // It's possible that we have a pending block commit already.
    // Mine two BTC blocks to "flush" this commit.
    let burn_height = signer_test
        .stacks_client
        .get_peer_info()
        .expect("Failed to get peer info")
        .burn_block_height;
    for i in 0..2 {
        info!(
            "------------- After pausing commits, triggering 2 BTC blocks: ({} of 2) -----------",
            i + 1
        );

        let blocks_processed_before = coord_channel
            .lock()
            .expect("Mutex poisoned")
            .get_stacks_blocks_processed();
        signer_test
            .running_nodes
            .btc_regtest_controller
            .build_next_block(1);

        wait_for(60, || {
            let blocks_processed_after = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            Ok(blocks_processed_after > blocks_processed_before)
        })
        .expect("Timed out waiting for tenure extend block");
    }

    wait_for(30, || {
        let new_burn_height = signer_test
            .stacks_client
            .get_peer_info()
            .expect("Failed to get peer info")
            .burn_block_height;
        Ok(new_burn_height == burn_height + 2)
    })
    .expect("Timed out waiting for burnchain to advance");

    // The last block should have a single instruction in it, the tenure extend
    let blocks = test_observer::get_blocks();
    let last_block = blocks.last().unwrap();
    let transactions = last_block["transactions"].as_array().unwrap();
    let tx = transactions.first().expect("No transactions in block");
    let raw_tx = tx["raw_tx"].as_str().unwrap();
    let tx_bytes = hex_bytes(&raw_tx[2..]).unwrap();
    let parsed = StacksTransaction::consensus_deserialize(&mut &tx_bytes[..]).unwrap();
    match &parsed.payload {
        TransactionPayload::TenureChange(payload)
            if payload.cause == TenureChangeCause::Extended => {}
        _ => panic!("Expected tenure extend transaction, got {parsed:?}"),
    };

    // Verify that the miner can continue mining in the tenure with the tenure extend
    info!("------------------------- Mine After Tenure Extend -------------------------");
    let mut blocks_processed_before = coord_channel
        .lock()
        .expect("Mutex poisoned")
        .get_stacks_blocks_processed();
    for sender_nonce in 0..5 {
        // submit a tx so that the miner will mine an extra block
        let transfer_tx = make_stacks_transfer(
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
            let blocks_processed_after = coord_channel
                .lock()
                .expect("Mutex poisoned")
                .get_stacks_blocks_processed();
            Ok(blocks_processed_after > blocks_processed_before)
        })
        .expect("Timed out waiting for block proposal");
        blocks_processed_before = coord_channel
            .lock()
            .expect("Mutex poisoned")
            .get_stacks_blocks_processed();
        info!("Block {blocks_processed_before} processed, continuing");
    }

    signer_test.shutdown();
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
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new(num_signers, vec![]);
    let signer_public_keys = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect::<Vec<_>>();
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
    for signer in &signer_public_keys {
        let blocks_signed = get_v3_signer(signer, next_reward_cycle);
        assert_eq!(blocks_signed, 0);
    }
    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);
    signer_test
        .running_nodes
        .btc_regtest_controller
        .build_next_block(1);

    wait_for(30, || {
        Ok(signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst)
            > blocks_before)
    })
    .unwrap();

    let block_mined = test_observer::get_mined_nakamoto_blocks()
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

    // setup sender + recipient for a test stx transfer
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 1000;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let btc_miner_1_seed = vec![1, 1, 1, 1];
    let btc_miner_2_seed = vec![2, 2, 2, 2];
    let btc_miner_1_pk = Keychain::default(btc_miner_1_seed.clone()).get_pub_key();
    let btc_miner_2_pk = Keychain::default(btc_miner_2_seed.clone()).get_pub_key();

    let node_1_rpc = gen_random_port();
    let node_1_p2p = gen_random_port();
    let node_2_rpc = gen_random_port();
    let node_2_p2p = gen_random_port();

    let localhost = "127.0.0.1";
    let node_1_rpc_bind = format!("{localhost}:{node_1_rpc}");
    let node_2_rpc_bind = format!("{localhost}:{node_2_rpc}");
    let mut node_2_listeners = Vec::new();
    let chain_id = 0x87654321;
    // partition the signer set so that ~half are listening and using node 1 for RPC and events,
    //  and the rest are using node 2
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(
            sender_addr,
            (send_amt + send_fee) * max_nakamoto_tenures * inter_blocks_per_tenure,
        )],
        |signer_config| {
            let node_host = if signer_config.endpoint.port() % 2 == 0 {
                &node_1_rpc_bind
            } else {
                &node_2_rpc_bind
            };
            signer_config.node_host = node_host.to_string();
            signer_config.chain_id = Some(chain_id)
        },
        |config| {
            config.node.rpc_bind = format!("{localhost}:{node_1_rpc}");
            config.node.p2p_bind = format!("{localhost}:{node_1_p2p}");
            config.node.data_url = format!("http://{localhost}:{node_1_rpc}");
            config.node.p2p_address = format!("{localhost}:{node_1_p2p}");
            config.miner.wait_on_interim_blocks = Duration::from_secs(5);
            config.node.pox_sync_sample_secs = 30;
            config.burnchain.chain_id = chain_id;

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
                if addr.port() % 2 == 0 || addr.port() == test_observer::EVENT_OBSERVER_PORT {
                    return true;
                }
                node_2_listeners.push(listener.clone());
                false
            })
        },
        Some(vec![btc_miner_1_pk, btc_miner_2_pk]),
        None,
    );
    let blocks_mined1 = signer_test.running_nodes.nakamoto_blocks_mined.clone();

    let conf = signer_test.running_nodes.conf.clone();
    let mut conf_node_2 = conf.clone();
    conf_node_2.node.rpc_bind = format!("{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_bind = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.data_url = format!("http://{localhost}:{node_2_rpc}");
    conf_node_2.node.p2p_address = format!("{localhost}:{node_2_p2p}");
    conf_node_2.node.seed = btc_miner_2_seed.clone();
    conf_node_2.burnchain.local_mining_public_key = Some(btc_miner_2_pk.to_hex());
    conf_node_2.node.local_peer_seed = btc_miner_2_seed.clone();
    conf_node_2.miner.mining_key = Some(Secp256k1PrivateKey::from_seed(&[2]));
    conf_node_2.node.miner = true;
    conf_node_2.events_observers.clear();
    conf_node_2.events_observers.extend(node_2_listeners);

    assert!(!conf_node_2.events_observers.is_empty());

    let node_1_sk = Secp256k1PrivateKey::from_seed(&conf.node.local_peer_seed);
    let node_1_pk = StacksPublicKey::from_private(&node_1_sk);

    conf_node_2.node.working_dir = format!("{}-1", conf_node_2.node.working_dir);

    conf_node_2.node.set_bootstrap_nodes(
        format!("{}@{}", &node_1_pk.to_hex(), conf.node.p2p_bind),
        conf.burnchain.chain_id,
        conf.burnchain.peer_version,
    );

    let http_origin = format!("http://{}", &conf.node.rpc_bind);

    let mut run_loop_2 = boot_nakamoto::BootRunLoop::new(conf_node_2.clone()).unwrap();
    let run_loop_stopper_2 = run_loop_2.get_termination_switch();
    let rl2_coord_channels = run_loop_2.coordinator_channels();
    let Counters {
        naka_submitted_commits: rl2_commits,
        naka_mined_blocks: blocks_mined2,
        ..
    } = run_loop_2.counters();
    let run_loop_2_thread = thread::Builder::new()
        .name("run_loop_2".into())
        .spawn(move || run_loop_2.start(None, 0))
        .unwrap();

    signer_test.boot_to_epoch_3();

    wait_for(120, || {
        let Some(node_1_info) = get_chain_info_opt(&conf) else {
            return Ok(false);
        };
        let Some(node_2_info) = get_chain_info_opt(&conf_node_2) else {
            return Ok(false);
        };
        Ok(node_1_info.stacks_tip_height == node_2_info.stacks_tip_height)
    })
    .expect("Timed out waiting for follower to catch up to the miner");

    let pre_nakamoto_peer_1_height = get_chain_info(&conf).stacks_tip_height;

    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // due to the random nature of mining sortitions, the way this test is structured
    //  is that we keep track of how many tenures each miner produced, and once enough sortitions
    //  have been produced such that each miner has produced 3 tenures, we stop and check the
    //  results at the end
    let rl1_coord_channels = signer_test.running_nodes.coord_channel.clone();
    let rl1_commits = signer_test.running_nodes.commits_submitted.clone();

    let miner_1_pk = StacksPublicKey::from_private(conf.miner.mining_key.as_ref().unwrap());
    let miner_2_pk = StacksPublicKey::from_private(conf_node_2.miner.mining_key.as_ref().unwrap());
    let mut btc_blocks_mined = 1;
    let mut miner_1_tenures = 0;
    let mut miner_2_tenures = 0;
    let mut sender_nonce = 0;
    while !(miner_1_tenures >= 3 && miner_2_tenures >= 3) {
        if btc_blocks_mined > max_nakamoto_tenures {
            panic!("Produced {btc_blocks_mined} sortitions, but didn't cover the test scenarios, aborting");
        }
        let blocks_processed_before =
            blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
        signer_test.mine_block_wait_on_processing(
            &[&rl1_coord_channels, &rl2_coord_channels],
            &[&rl1_commits, &rl2_commits],
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
            let blocks_processed_before =
                blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
            // submit a tx so that the miner will mine an extra block
            let transfer_tx = make_stacks_transfer(
                &sender_sk,
                sender_nonce,
                send_fee,
                signer_test.running_nodes.conf.burnchain.chain_id,
                &recipient,
                send_amt,
            );
            sender_nonce += 1;
            submit_tx(&http_origin, &transfer_tx);

            wait_for(60, || {
                let blocks_processed =
                    blocks_mined1.load(Ordering::SeqCst) + blocks_mined2.load(Ordering::SeqCst);
                Ok(blocks_processed > blocks_processed_before)
            })
            .unwrap();
            info!("Mined interim block {btc_blocks_mined}:{interim_block_ix}");
        }

        let blocks = get_nakamoto_headers(&conf);
        let mut seen_burn_hashes = HashSet::new();
        miner_1_tenures = 0;
        miner_2_tenures = 0;
        for header in blocks.iter() {
            if seen_burn_hashes.contains(&header.burn_header_hash) {
                continue;
            }
            seen_burn_hashes.insert(header.burn_header_hash);

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

    info!(
        "New chain info 1: {:?}",
        get_chain_info(&signer_test.running_nodes.conf)
    );

    info!("New chain info 2: {:?}", get_chain_info(&conf_node_2));

    let peer_1_height = get_chain_info(&conf).stacks_tip_height;
    let peer_2_height = get_chain_info(&conf_node_2).stacks_tip_height;
    info!("Peer height information"; "peer_1" => peer_1_height, "peer_2" => peer_2_height, "pre_naka_height" => pre_nakamoto_peer_1_height);
    assert_eq!(peer_1_height, peer_2_height);
    assert_eq!(
        peer_1_height,
        pre_nakamoto_peer_1_height + (btc_blocks_mined - 1) * (inter_blocks_per_tenure + 1)
    );
    assert_eq!(btc_blocks_mined, miner_1_tenures + miner_2_tenures);

    // Verify both nodes have the correct chain id
    let miner1_info = get_chain_info(&signer_test.running_nodes.conf);
    assert_eq!(miner1_info.network_id, chain_id);

    let miner2_info = get_chain_info(&conf_node_2);
    assert_eq!(miner2_info.network_id, chain_id);

    rl2_coord_channels
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper_2.store(false, Ordering::SeqCst);
    run_loop_2_thread.join().unwrap();
    signer_test.shutdown();
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
    let block_proposal_timeout = Duration::from_secs(20);
    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |config| {
            // make the duration long enough that the miner will be marked as malicious
            config.block_proposal_timeout = block_proposal_timeout;
        },
        |config| {
            // Set the block commit delay to 10 minutes to ensure no block commit is sent
            config.miner.block_commit_delay = Duration::from_secs(600);
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    let commits_before = signer_test
        .running_nodes
        .commits_submitted
        .load(Ordering::SeqCst);

    next_block_and_process_new_stacks_block(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        &signer_test.running_nodes.coord_channel,
    )
    .expect("Failed to mine first block");

    // Ensure that the block commit has been sent before continuing
    wait_for(60, || {
        let commits = signer_test
            .running_nodes
            .commits_submitted
            .load(Ordering::SeqCst);
        Ok(commits > commits_before)
    })
    .expect("Timed out waiting for block commit after new Stacks block");

    // Prevent a block from being mined by making signers reject it.
    let all_signers = signer_test
        .signer_stacks_private_keys
        .iter()
        .map(StacksPublicKey::from_private)
        .collect::<Vec<_>>();
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(all_signers);

    info!("------------------------- Test Mine Burn Block  -------------------------");
    let burn_height_before = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
    let commits_before = signer_test
        .running_nodes
        .commits_submitted
        .load(Ordering::SeqCst);

    // Mine a burn block and wait for it to be processed.
    next_block_and(
        &mut signer_test.running_nodes.btc_regtest_controller,
        60,
        || {
            let burn_height = get_chain_info(&signer_test.running_nodes.conf).burn_block_height;
            Ok(burn_height > burn_height_before)
        },
    )
    .unwrap();

    // Sleep an extra minute to ensure no block commits are sent
    sleep_ms(60_000);

    let commits = signer_test
        .running_nodes
        .commits_submitted
        .load(Ordering::SeqCst);
    assert_eq!(commits, commits_before);

    let blocks_before = signer_test
        .running_nodes
        .nakamoto_blocks_mined
        .load(Ordering::SeqCst);

    info!("------------------------- Resume Signing -------------------------");
    TEST_REJECT_ALL_BLOCK_PROPOSAL
        .lock()
        .unwrap()
        .replace(Vec::new());

    // Wait for a block to be mined
    wait_for(60, || {
        let blocks = signer_test
            .running_nodes
            .nakamoto_blocks_mined
            .load(Ordering::SeqCst);
        Ok(blocks > blocks_before)
    })
    .expect("Timed out waiting for block to be mined");

    // Wait for a block commit to be sent
    wait_for(60, || {
        let commits = signer_test
            .running_nodes
            .commits_submitted
            .load(Ordering::SeqCst);
        Ok(commits > commits_before)
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
    let sender_sk = Secp256k1PrivateKey::new();
    let sender_addr = tests::to_addr(&sender_sk);
    let send_amt = 100;
    let send_fee = 180;
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));

    let mut signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr, send_amt + send_fee)],
        |config| {
            config.block_proposal_validation_timeout = timeout;
        },
        |_| {},
        None,
        None,
    );
    let http_origin = format!("http://{}", &signer_test.running_nodes.conf.node.rpc_bind);
    signer_test.boot_to_epoch_3();

    info!("------------------------- Test Mine and Verify Confirmed Nakamoto Block -------------------------");
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers);
    info!("------------------------- Test Block Validation Stalled -------------------------");
    TEST_VALIDATE_STALL.lock().unwrap().replace(true);
    let validation_stall_start = Instant::now();

    let proposals_before = signer_test
        .running_nodes
        .nakamoto_blocks_proposed
        .load(Ordering::SeqCst);

    // submit a tx so that the miner will attempt to mine an extra block
    let sender_nonce = 0;
    let transfer_tx = make_stacks_transfer(
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
        Ok(signer_test
            .running_nodes
            .nakamoto_blocks_proposed
            .load(Ordering::SeqCst)
            > proposals_before)
    })
    .expect("Timed out waiting for block proposal");

    assert!(
        validation_stall_start.elapsed() < timeout,
        "Test was too slow to propose another block before the timeout"
    );

    info!("------------------------- Propose Another Block Before Hitting the Timeout -------------------------");
    let proposal_conf = ProposalEvalConfig {
        first_proposal_burn_block_timing: Duration::from_secs(0),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        block_proposal_timeout: Duration::from_secs(100),
    };
    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader::empty(),
        txs: vec![],
    };

    let info_before = get_chain_info(&signer_test.running_nodes.conf);
    // Propose a block to the signers that passes initial checks but will not be submitted to the stacks node due to the submission stall
    let view = SortitionsView::fetch_view(proposal_conf, &signer_test.stacks_client).unwrap();
    block.header.pox_treatment = BitVec::ones(1).unwrap();
    block.header.consensus_hash = view.cur_sortition.consensus_hash;
    block.header.chain_length = info_before.stacks_tip_height + 1;

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
        let chunks = test_observer::get_stackerdb_chunks();
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
            if matches!(reason_code, RejectCode::ConnectivityIssues) {
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
    TEST_VALIDATE_STALL.lock().unwrap().replace(false);
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
    signer_test.mine_and_verify_confirmed_naka_block(timeout, num_signers);

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
