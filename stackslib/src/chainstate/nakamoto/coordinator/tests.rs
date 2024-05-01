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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::types::PrincipalData;
use clarity::vm::Value;
use rand::prelude::SliceRandom;
use rand::{thread_rng, Rng, RngCore};
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, SIGNER_SLOTS_PER_USER,
};
use stacks_common::types::chainstate::{
    StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::{Address, StacksEpoch};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use stacks_common::util::vrf::VRFProof;
use wsts::curve::point::Point;

use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle};
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::coordinator::tests::{p2pkh_from, pox_addr_from};
use crate::chainstate::nakamoto::signer_set::NakamotoSigners;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::pox_4_tests::{get_stacking_minimum, get_tip};
use crate::chainstate::stacks::boot::signers_tests::{readonly_call, readonly_call_with_sortdb};
use crate::chainstate::stacks::boot::test::{
    key_to_stacks_addr, make_pox_4_lockup, make_signer_key_signature,
    make_signers_vote_for_aggregate_public_key, make_signers_vote_for_aggregate_public_key_value,
    with_sortdb,
};
use crate::chainstate::stacks::boot::{MINERS_NAME, SIGNERS_NAME};
use crate::chainstate::stacks::db::{MinerPaymentTxFees, StacksAccount, StacksChainState};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, StacksTransactionSigner, TenureChangeCause,
    TokenTransferMemo, TransactionAnchorMode, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::StacksEpochExtension;
use crate::net::relay::Relayer;
use crate::net::stackerdb::StackerDBConfig;
use crate::net::test::{TestEventObserver, TestPeer, TestPeerConfig};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::signed_structured_data::pox4::Pox4SignatureTopic;

/// Bring a TestPeer into the Nakamoto Epoch
fn advance_to_nakamoto(
    peer: &mut TestPeer,
    test_signers: &mut TestSigners,
    test_stackers: &[TestStacker],
) {
    let mut peer_nonce = 0;
    let private_key = peer.config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    let mut tip = None;
    for sortition_height in 0..11 {
        // stack to pox-3 in cycle 7
        let txs = if sortition_height == 6 {
            // Make all the test Stackers stack
            test_stackers
                .iter()
                .map(|test_stacker| {
                    let pox_addr = PoxAddress::from_legacy(
                        AddressHashMode::SerializeP2PKH,
                        addr.bytes.clone(),
                    );
                    let signature = make_signer_key_signature(
                        &pox_addr,
                        &test_stacker.signer_private_key,
                        6,
                        &Pox4SignatureTopic::StackStx,
                        12_u128,
                        u128::MAX,
                        1,
                    );
                    let signing_key =
                        StacksPublicKey::from_private(&test_stacker.signer_private_key);
                    make_pox_4_lockup(
                        &test_stacker.stacker_private_key,
                        0,
                        test_stacker.amount,
                        &pox_addr,
                        12,
                        &signing_key,
                        34,
                        Some(signature),
                        u128::MAX,
                        1,
                    )
                })
                .collect()
        } else if sortition_height == 8 {
            with_sortdb(peer, |chainstate, sortdb| {
                make_all_signers_vote_for_aggregate_key(
                    chainstate,
                    sortdb,
                    &tip.unwrap(),
                    test_signers,
                    test_stackers,
                    7,
                )
            })
        } else {
            vec![]
        };

        tip = Some(peer.tenure_with_txs(&txs, &mut peer_nonce));
    }
    // peer is at the start of cycle 8
}

pub fn make_all_signers_vote_for_aggregate_key(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    tip: &StacksBlockId,
    test_signers: &mut TestSigners,
    test_stackers: &[TestStacker],
    cycle_id: u128,
) -> Vec<StacksTransaction> {
    info!("Trigger signers vote for cycle {}", cycle_id);

    // Check if we already have an aggregate key for this cycle
    if chainstate
        .get_aggregate_public_key_pox_4(sortdb, tip, cycle_id as u64)
        .unwrap()
        .is_some()
    {
        debug!("Aggregate key already set for cycle {}", cycle_id);
        return vec![];
    }

    // Generate a new aggregate key
    test_signers.generate_aggregate_key(cycle_id as u64);

    let signers_res = readonly_call_with_sortdb(
        chainstate,
        sortdb,
        tip,
        SIGNERS_NAME.into(),
        "get-signers".into(),
        vec![Value::UInt(cycle_id)],
    );

    // If the signers are not set yet, then we're not ready to vote yet.
    let signer_vec = match signers_res.expect_optional().unwrap() {
        Some(signer_vec) => signer_vec.expect_list().unwrap(),
        None => {
            debug!("No signers set for cycle {}", cycle_id);
            return vec![];
        }
    };

    let mut signers_to_index = HashMap::new();
    for (index, value) in signer_vec.into_iter().enumerate() {
        let tuple = value.expect_tuple().unwrap();
        let signer = tuple
            .get_owned("signer")
            .unwrap()
            .expect_principal()
            .unwrap();
        let insert_res = signers_to_index.insert(signer, index);
        assert!(insert_res.is_none(), "Duplicate signer in signers list");
    }

    // Build a map of the signers, their private keys, and their index
    let mut signers = HashMap::new();
    for test_stacker in test_stackers {
        let addr = key_to_stacks_addr(&test_stacker.signer_private_key);
        let principal = PrincipalData::from(addr);
        signers.insert(
            addr,
            (
                test_stacker.signer_private_key,
                signers_to_index[&principal],
            ),
        );
    }

    // Vote for the aggregate key for each signer
    info!("Trigger votes for cycle {}", cycle_id);
    signers
        .iter()
        .map(|(addr, (signer_key, index))| {
            let account = get_account(chainstate, sortdb, &addr);
            make_signers_vote_for_aggregate_public_key_value(
                signer_key,
                account.nonce,
                *index as u128,
                Value::buff_from(test_signers.aggregate_public_key.compress().data.to_vec())
                    .expect("Failed to serialize aggregate public key"),
                0,
                cycle_id,
            )
        })
        .collect()
}

/// Make a peer and transition it into the Nakamoto epoch.
/// The node needs to be stacking and it needs to vote for an aggregate key;
/// otherwise, Nakamoto can't activate.
pub fn boot_nakamoto<'a>(
    test_name: &str,
    mut initial_balances: Vec<(PrincipalData, u64)>,
    test_signers: &mut TestSigners,
    test_stackers: &[TestStacker],
    observer: Option<&'a TestEventObserver>,
) -> TestPeer<'a> {
    let aggregate_public_key = test_signers.aggregate_public_key.clone();
    let mut peer_config = TestPeerConfig::new(test_name, 0, 0);
    let private_key = peer_config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    // reward cycles are 5 blocks long
    // first 25 blocks are boot-up
    // reward cycle 6 instantiates pox-3
    // we stack in reward cycle 7 so pox-3 is evaluated to find reward set participation
    peer_config.aggregate_public_key = Some(aggregate_public_key.clone());
    peer_config
        .stacker_dbs
        .push(boot_code_id(MINERS_NAME, false));
    peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(37));
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];

    // Create some balances for test Stackers
    let mut stacker_balances = test_stackers
        .iter()
        .map(|test_stacker| {
            (
                PrincipalData::from(key_to_stacks_addr(&test_stacker.stacker_private_key)),
                u64::try_from(test_stacker.amount + 10000).expect("Stacking amount too large"),
            )
        })
        .collect();

    // Create some balances for test Signers
    let mut signer_balances = test_stackers
        .iter()
        .map(|stacker| {
            (
                PrincipalData::from(p2pkh_from(&stacker.signer_private_key)),
                1000,
            )
        })
        .collect();

    peer_config.initial_balances.append(&mut stacker_balances);
    peer_config.initial_balances.append(&mut signer_balances);
    peer_config.initial_balances.append(&mut initial_balances);
    peer_config.burnchain.pox_constants.v2_unlock_height = 21;
    peer_config.burnchain.pox_constants.pox_3_activation_height = 26;
    peer_config.burnchain.pox_constants.v3_unlock_height = 27;
    peer_config.burnchain.pox_constants.pox_4_activation_height = 31;
    peer_config.test_stackers = Some(test_stackers.to_vec());
    peer_config.test_signers = Some(test_signers.clone());
    let mut peer = TestPeer::new_with_observer(peer_config, observer);

    advance_to_nakamoto(&mut peer, test_signers, test_stackers);

    peer
}

/// Make a replay peer, used for replaying the blockchain
pub fn make_replay_peer<'a>(peer: &mut TestPeer<'a>) -> TestPeer<'a> {
    let mut replay_config = peer.config.clone();
    replay_config.test_name = format!("{}.replay", &peer.config.test_name);
    replay_config.server_port = 0;
    replay_config.http_port = 0;
    replay_config.test_stackers = peer.config.test_stackers.clone();

    let test_stackers = replay_config.test_stackers.clone().unwrap_or(vec![]);
    let mut test_signers = replay_config.test_signers.clone().unwrap();
    let mut replay_peer = TestPeer::new(replay_config);
    let observer = TestEventObserver::new();
    advance_to_nakamoto(
        &mut replay_peer,
        &mut test_signers,
        test_stackers.as_slice(),
    );

    // sanity check
    let replay_tip = {
        let sort_db = replay_peer.sortdb.as_ref().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        tip
    };
    let tip = {
        let sort_db = peer.sortdb.as_ref().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let sort_ic = sort_db.index_conn();
        let ancestor_tip = SortitionDB::get_ancestor_snapshot(
            &sort_ic,
            replay_tip.block_height,
            &tip.sortition_id,
        )
        .unwrap()
        .unwrap();
        ancestor_tip
    };

    assert_eq!(tip, replay_tip);
    replay_peer
}

/// Make a token-transfer from a private key
pub fn make_token_transfer(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    private_key: &StacksPrivateKey,
    nonce: u64,
    amt: u64,
    fee: u64,
    recipient_addr: &StacksAddress,
) -> StacksTransaction {
    let mut stx_transfer = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(private_key).unwrap(),
        TransactionPayload::TokenTransfer(
            recipient_addr.clone().to_account_principal(),
            amt,
            TokenTransferMemo([0x00; 34]),
        ),
    );
    stx_transfer.chain_id = 0x80000000;
    stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;
    stx_transfer.set_tx_fee(fee);
    stx_transfer.auth.set_origin_nonce(nonce);

    let mut tx_signer = StacksTransactionSigner::new(&stx_transfer);
    tx_signer.sign_origin(&private_key).unwrap();
    let stx_transfer_signed = tx_signer.get_tx().unwrap();

    stx_transfer_signed
}

/// Given the blocks and block-commits for a reward cycle, replay the sortitions on the given
/// TestPeer, always processing the first block of the reward cycle before processing all
/// subsequent blocks in random order.
fn replay_reward_cycle(
    peer: &mut TestPeer,
    burn_ops: &[Vec<BlockstackOperationType>],
    stacks_blocks: &[NakamotoBlock],
) {
    eprintln!("\n\n=============================================\nBegin replay\n==============================================\n");
    let reward_cycle_length = peer.config.burnchain.pox_constants.reward_cycle_length as usize;
    let reward_cycle_indices: Vec<usize> = (0..stacks_blocks.len())
        .step_by(reward_cycle_length)
        .collect();

    let mut indexes: Vec<_> = (0..stacks_blocks.len()).collect();
    indexes.shuffle(&mut thread_rng());

    for burn_ops in burn_ops.iter() {
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    }

    let sortdb = peer.sortdb.take().unwrap();
    let mut node = peer.stacks_node.take().unwrap();

    let sort_tip = SortitionDB::get_canonical_sortition_tip(sortdb.conn()).unwrap();
    let mut sort_handle = sortdb.index_handle(&sort_tip);

    let mut blocks_to_process = stacks_blocks.to_vec();
    blocks_to_process.shuffle(&mut thread_rng());
    while let Some(block) = blocks_to_process.pop() {
        let block_id = block.block_id();
        info!("Process Nakamoto block {} ({:?}", &block_id, &block.header);

        let accepted = Relayer::process_new_nakamoto_block(
            &sortdb,
            &mut sort_handle,
            &mut node.chainstate,
            block.clone(),
            None,
        )
        .unwrap();
        if accepted {
            test_debug!("Accepted Nakamoto block {block_id}");
            peer.coord.handle_new_nakamoto_stacks_block().unwrap();
        } else {
            test_debug!("Did NOT accept Nakamoto block {block_id}");
            blocks_to_process.push(block);
            blocks_to_process.shuffle(&mut thread_rng());
        }
    }

    peer.sortdb = Some(sortdb);
    peer.stacks_node = Some(node);

    peer.check_nakamoto_migration();
}

/// Mine a single Nakamoto tenure with a single Nakamoto block
#[test]
fn test_simple_nakamoto_coordinator_bootup() {
    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops);
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |_miner, _chainstate, _sort_dbconn, _blocks| vec![],
    );
    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
        .unwrap()
        .unwrap();
    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        12
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    peer.check_nakamoto_migration();
}

/// Mine a single Nakamoto tenure with 10 Nakamoto blocks
#[test]
fn test_simple_nakamoto_coordinator_1_tenure_10_blocks() {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 100_000_000)],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();

    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

    // do a stx transfer in each block to a given recipient
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        21
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    // replay the blocks and sortitions in random order, and verify that we still reach the chain
    // tip
    let mut replay_peer = make_replay_peer(&mut peer);
    replay_reward_cycle(&mut replay_peer, &[burn_ops], &blocks);

    let tip = {
        let chainstate = &mut replay_peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = replay_peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        21
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    peer.check_nakamoto_migration();
}

/// Test chainstate getters against an instantiated epoch2/Nakamoto chain.
/// There are 11 epoch2 blocks and 2 nakamto tenure with 10 nakamoto blocks each
/// Tests:
/// * get_header_by_coinbase_height
/// * get_parent_vrf_proof
/// * get_highest_nakamoto_tenure
/// * check_first_nakamoto_tenure
/// * check_valid_consensus_hash
/// * check_nakamoto_tenure
/// * check_tenure_continuity
#[test]
fn test_nakamoto_chainstate_getters() {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 100_000_000)],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let sort_tip = {
        let sort_db = peer.sortdb.as_ref().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    {
        // scope this to drop the chainstate ref and db tx
        let chainstate = &peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let mut sort_tx = sort_db.tx_handle_begin(&sort_tip.sortition_id).unwrap();

        // no tenures yet
        assert!(
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_tx.sqlite())
                .unwrap()
                .is_none()
        );

        // sortition-existence-check works
        assert_eq!(
            NakamotoChainState::check_sortition_exists(&mut sort_tx, &sort_tip.consensus_hash)
                .unwrap(),
            sort_tip
        );
    }

    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof.clone());

    // do a stx transfer in each block to a given recipient
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    let tip = {
        let chainstate = &peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        21
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    let sort_tip = {
        let sort_db = peer.sortdb.as_ref().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    {
        // scope this to drop the chainstate ref and db tx
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_ref().unwrap();

        let (mut stacks_db_tx, _) = chainstate.chainstate_tx_begin().unwrap();

        for coinbase_height in 0..=((tip
            .anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length
            - 10)
            + 1)
        {
            let header_opt = NakamotoChainState::get_header_by_coinbase_height(
                &mut stacks_db_tx,
                &tip.index_block_hash(),
                coinbase_height,
            )
            .unwrap();
            let header = header_opt.expect("No tenure");

            if coinbase_height
                <= tip
                    .anchored_header
                    .as_stacks_nakamoto()
                    .unwrap()
                    .chain_length
                    - 10
            {
                // all tenures except the last are epoch2
                assert!(header.anchored_header.as_stacks_epoch2().is_some());
            } else {
                // last tenure is nakamoto
                assert!(header.anchored_header.as_stacks_nakamoto().is_some());
            }
        }
    }

    debug!("\n======================================\nBegin tests\n===========================================\n");
    {
        // scope this to drop the chainstate ref and db tx
        let chainstate = &peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let mut sort_tx = sort_db.tx_handle_begin(&sort_tip.sortition_id).unwrap();

        // we now have a tenure, and it confirms the last epoch2 block
        let highest_tenure =
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_tx.sqlite())
                .unwrap()
                .unwrap();
        assert_eq!(highest_tenure.coinbase_height, 12);
        assert_eq!(highest_tenure.num_blocks_confirmed, 1);
        assert_eq!(highest_tenure.tenure_index, 1);
        assert_eq!(highest_tenure.tenure_id_consensus_hash, consensus_hash);
        assert_eq!(highest_tenure.burn_view_consensus_hash, consensus_hash);

        // confirm that getting the burn block for this highest tenure works
        let sn = SortitionDB::get_block_snapshot_consensus(
            sort_tx.tx(),
            &highest_tenure.tenure_id_consensus_hash,
        )
        .unwrap()
        .unwrap();

        // this tenure's TC tx is the first-ever TC
        let tenure_change_payload = blocks[0].get_tenure_change_tx_payload().unwrap().clone();

        assert!(NakamotoChainState::check_first_nakamoto_tenure_change(
            chainstate.db(),
            &tenure_change_payload,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_tenure_continuity(
            chainstate.db(),
            sort_tx.sqlite(),
            &blocks[0].header.consensus_hash,
            &blocks[1].header,
        )
        .unwrap());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.prev_tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.burn_view_consensus_hash,
        )
        .unwrap()
        .is_some());

        // this should return the previous tenure
        assert_eq!(
            NakamotoChainState::check_nakamoto_tenure(
                chainstate.db(),
                &mut sort_tx,
                &blocks[0].header,
                &tenure_change_payload,
            )
            .unwrap()
            .unwrap()
            .tenure_id_consensus_hash,
            tenure_change_payload.prev_tenure_consensus_hash
        );

        let cur_burn_tip = SortitionDB::get_canonical_burn_chain_tip(sort_tx.sqlite()).unwrap();
        let (cur_stacks_ch, cur_stacks_bhh, cur_stacks_height) =
            SortitionDB::get_canonical_stacks_chain_tip_hash_and_height(sort_tx.sqlite()).unwrap();
        sort_tx
            .test_update_canonical_stacks_tip(
                &cur_burn_tip.sortition_id,
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
                0,
            )
            .unwrap();

        // drop the highest tenure, so this check can pass
        NakamotoChainState::delete_nakamoto_tenure(
            chainstate.db(),
            &blocks[0].header.consensus_hash,
        )
        .unwrap();

        // check works (this would be the first tenure)
        assert_eq!(
            NakamotoChainState::check_nakamoto_tenure(
                chainstate.db(),
                &mut sort_tx,
                &blocks[0].header,
                &tenure_change_payload,
            )
            .unwrap()
            .unwrap()
            .tenure_id_consensus_hash,
            tenure_change_payload.prev_tenure_consensus_hash
        );

        // restore
        sort_tx
            .test_update_canonical_stacks_tip(
                &cur_burn_tip.sortition_id,
                &cur_stacks_ch,
                &cur_stacks_bhh,
                cur_stacks_height,
            )
            .unwrap();
        NakamotoChainState::insert_nakamoto_tenure(
            chainstate.db(),
            &blocks[0].header,
            12,
            1,
            &tenure_change_payload,
        )
        .unwrap();
    }

    debug!("\n======================================\nBegin second tenure\n===========================================\n");
    // begin another tenure
    let (burn_ops, mut next_tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);

    // find the txid
    let mut txid = None;
    for op in burn_ops.iter() {
        if let BlockstackOperationType::LeaderBlockCommit(ref op) = &op {
            txid = Some(op.txid.clone());
        }
    }
    let txid = txid.unwrap();

    let (_, _, next_consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let next_vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    next_tenure_change.tenure_consensus_hash = next_consensus_hash.clone();
    next_tenure_change.burn_view_consensus_hash = next_consensus_hash.clone();

    let next_tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(next_tenure_change.clone());
    let next_coinbase_tx = peer
        .miner
        .make_nakamoto_coinbase(None, next_vrf_proof.clone());

    // parent VRF proof check
    let parent_vrf_proof = NakamotoChainState::get_parent_vrf_proof(
        &peer.stacks_node.as_ref().unwrap().chainstate.db(),
        peer.sortdb.as_ref().unwrap().conn(),
        &next_consensus_hash,
        &txid,
    )
    .unwrap();
    assert_eq!(parent_vrf_proof, vrf_proof);

    // make the second tenure's blocks
    let blocks_and_sizes = peer.make_nakamoto_tenure(
        next_tenure_change_tx.clone(),
        next_coinbase_tx.clone(),
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let new_blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    let sort_tip = {
        let sort_db = peer.sortdb.as_ref().unwrap();
        SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
    };
    {
        // scope this to drop the chainstate ref and db tx
        let chainstate = &peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();

        let mut sort_tx = sort_db.tx_handle_begin(&sort_tip.sortition_id).unwrap();

        // we now have a new highest tenure
        let highest_tenure =
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_tx.sqlite())
                .unwrap()
                .unwrap();
        assert_eq!(highest_tenure.coinbase_height, 13);
        assert_eq!(highest_tenure.num_blocks_confirmed, 10);
        assert_eq!(highest_tenure.tenure_index, 2);
        assert_eq!(highest_tenure.tenure_id_consensus_hash, next_consensus_hash);
        assert_eq!(highest_tenure.prev_tenure_id_consensus_hash, consensus_hash);
        assert_eq!(highest_tenure.burn_view_consensus_hash, next_consensus_hash);

        // this tenure's TC tx is NOT the first-ever TC
        let tenure_change_payload = new_blocks[0]
            .get_tenure_change_tx_payload()
            .unwrap()
            .clone();
        let old_tenure_change_payload = blocks[0].get_tenure_change_tx_payload().unwrap().clone();

        assert!(NakamotoChainState::check_first_nakamoto_tenure_change(
            chainstate.db(),
            &tenure_change_payload,
        )
        .unwrap()
        .is_none());
        assert!(NakamotoChainState::check_tenure_continuity(
            chainstate.db(),
            sort_tx.sqlite(),
            &new_blocks[0].header.consensus_hash,
            &new_blocks[1].header,
        )
        .unwrap());
        assert!(!NakamotoChainState::check_tenure_continuity(
            chainstate.db(),
            sort_tx.sqlite(),
            &blocks[0].header.consensus_hash,
            &new_blocks[1].header,
        )
        .unwrap());

        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.prev_tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &tenure_change_payload.burn_view_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &old_tenure_change_payload.tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &old_tenure_change_payload.prev_tenure_consensus_hash,
        )
        .unwrap()
        .is_some());
        assert!(NakamotoChainState::check_valid_consensus_hash(
            &mut sort_tx,
            &old_tenure_change_payload.burn_view_consensus_hash,
        )
        .unwrap()
        .is_some());

        let cur_burn_tip = SortitionDB::get_canonical_burn_chain_tip(sort_tx.sqlite()).unwrap();
        let (cur_stacks_ch, cur_stacks_bhh, cur_stacks_height) =
            SortitionDB::get_canonical_stacks_chain_tip_hash_and_height(sort_tx.sqlite()).unwrap();
        sort_tx
            .test_update_canonical_stacks_tip(
                &cur_burn_tip.sortition_id,
                &blocks[9].header.consensus_hash,
                &blocks[9].header.block_hash(),
                blocks[9].header.chain_length,
            )
            .unwrap();

        NakamotoChainState::delete_nakamoto_tenure(
            chainstate.db(),
            &new_blocks[0].header.consensus_hash,
        )
        .unwrap();

        assert_eq!(
            NakamotoChainState::check_nakamoto_tenure(
                chainstate.db(),
                &mut sort_tx,
                &new_blocks[0].header,
                &tenure_change_payload,
            )
            .unwrap()
            .unwrap()
            .tenure_id_consensus_hash,
            tenure_change_payload.prev_tenure_consensus_hash
        );

        // checks on older confired tenures return the prev tenure
        assert_eq!(
            NakamotoChainState::check_nakamoto_tenure(
                chainstate.db(),
                &mut sort_tx,
                &blocks[0].header,
                &old_tenure_change_payload,
            )
            .unwrap()
            .unwrap()
            .tenure_id_consensus_hash,
            old_tenure_change_payload.prev_tenure_consensus_hash
        );

        // restore
        sort_tx
            .test_update_canonical_stacks_tip(
                &cur_burn_tip.sortition_id,
                &cur_stacks_ch,
                &cur_stacks_bhh,
                cur_stacks_height,
            )
            .unwrap();
        NakamotoChainState::insert_nakamoto_tenure(
            chainstate.db(),
            &new_blocks[0].header,
            13,
            2,
            &tenure_change_payload,
        )
        .unwrap();
    }

    peer.check_nakamoto_migration();
}

/// Mine a 10 Nakamoto tenures with between 1 and 10 Nakamoto blocks each.
/// Checks the matured mining rewards as well.
pub fn simple_nakamoto_coordinator_10_tenures_10_sortitions<'a>() -> TestPeer<'a> {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 100_000_000)],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let mut all_blocks: Vec<NakamotoBlock> = vec![];
    let mut all_burn_ops = vec![];
    let mut rc_blocks = vec![];
    let mut rc_burn_ops = vec![];
    let mut consensus_hashes = vec![];
    let mut fee_counts = vec![];
    let mut total_blocks = 0;
    let stx_miner_key = peer.miner.nakamoto_miner_key();
    let stx_miner_addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    for i in 0..10 {
        debug!("Tenure {}", i);
        let (burn_ops, mut tenure_change, miner_key) =
            peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

        tenure_change.tenure_consensus_hash = consensus_hash.clone();
        tenure_change.burn_view_consensus_hash = consensus_hash.clone();

        let tenure_change_tx = peer
            .miner
            .make_nakamoto_tenure_change(tenure_change.clone());
        let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

        debug!("Next burnchain block: {}", &consensus_hash);

        let num_blocks: usize = (thread_rng().gen::<usize>() % 10) + 1;

        let block_height = peer.get_burn_block_height();
        // If we are in the prepare phase, check if we need to generate
        // aggregate key votes
        let txs = if peer.config.burnchain.is_in_prepare_phase(block_height) {
            let cycle_id = peer
                .config
                .burnchain
                .block_height_to_reward_cycle(block_height)
                .unwrap();
            let next_cycle_id = cycle_id as u128 + 1;

            with_sortdb(&mut peer, |chainstate, sortdb| {
                if let Some(tip) = all_blocks.last() {
                    make_all_signers_vote_for_aggregate_key(
                        chainstate,
                        sortdb,
                        &tip.block_id(),
                        &mut test_signers,
                        &test_stackers,
                        next_cycle_id,
                    )
                } else {
                    vec![]
                }
            })
        } else {
            vec![]
        };

        // do a stx transfer in each block to a given recipient
        let recipient_addr =
            StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
        let blocks_and_sizes = peer.make_nakamoto_tenure(
            tenure_change_tx,
            coinbase_tx,
            &mut test_signers,
            |miner, chainstate, sortdb, blocks_so_far| {
                // Include the aggregate key voting transactions in the first block.
                let mut txs = if blocks_so_far.is_empty() {
                    txs.clone()
                } else {
                    vec![]
                };

                if blocks_so_far.len() < num_blocks {
                    debug!("\n\nProduce block {}\n\n", all_blocks.len());

                    let account = get_account(chainstate, sortdb, &addr);

                    let stx_transfer = make_token_transfer(
                        chainstate,
                        sortdb,
                        &private_key,
                        account.nonce,
                        100,
                        1,
                        &recipient_addr,
                    );
                    txs.push(stx_transfer);
                }
                txs
            },
        );

        let fees = blocks_and_sizes
            .iter()
            .map(|(block, _, _)| {
                block
                    .txs
                    .iter()
                    .map(|tx| tx.get_tx_fee() as u128)
                    .sum::<u128>()
            })
            .sum::<u128>();

        consensus_hashes.push(consensus_hash);
        fee_counts.push(fees);
        total_blocks += num_blocks;

        let mut blocks: Vec<NakamotoBlock> = blocks_and_sizes
            .into_iter()
            .map(|(block, _, _)| block)
            .collect();

        // if we're starting a new reward cycle, then save the current one
        let tip = {
            let sort_db = peer.sortdb.as_mut().unwrap();
            SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
        };
        if peer
            .config
            .burnchain
            .is_reward_cycle_start(tip.block_height)
        {
            rc_blocks.push(all_blocks.clone());
            rc_burn_ops.push(all_burn_ops.clone());

            all_burn_ops.clear();
            all_blocks.clear();
        }

        all_blocks.append(&mut blocks);
        all_burn_ops.push(burn_ops);
    }

    rc_blocks.push(all_blocks.clone());
    rc_burn_ops.push(all_burn_ops.clone());

    all_burn_ops.clear();
    all_blocks.clear();

    // in nakamoto, tx fees are rewarded by the next tenure, so the
    // scheduled rewards come 1 tenure after the coinbase reward matures
    let miner = p2pkh_from(&stx_miner_key);
    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    // this is sortition height 12, and this miner has earned all 12 of the coinbases
    // plus the initial per-block mining bonus of 2600 STX, but minus the last three rewards (since
    // the miner rewards take three sortitions to confirm).
    //
    // This is (1000 + 2600) * 10 + 1000 - (3600 * 2 + 1000)
    //            first 10          block    unmatured rewards
    //            blocks             11
    debug!("block fees: {:?}", &fee_counts);
    let mut expected_coinbase_rewards: u128 = 28800000000;
    let mut fees_so_far: u128 = 0;
    for (i, ch) in consensus_hashes.into_iter().enumerate() {
        let sn = SortitionDB::get_block_snapshot_consensus(sort_db.conn(), &ch)
            .unwrap()
            .unwrap();

        if !sn.sortition {
            continue;
        }
        let block_id = StacksBlockId(sn.winning_stacks_block_hash.0);

        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();
        let sort_db_tx = sort_db.tx_begin_at_tip();

        let stx_balance = clarity_instance
            .read_only_connection(&block_id, &chainstate_tx, &sort_db_tx)
            .with_clarity_db_readonly(|db| db.get_account_stx_balance(&miner.clone().into()))
            .unwrap();

        // only count matured rewards (last 3 blocks are not mature)
        let block_fee = if i > 3 {
            fee_counts[i.saturating_sub(4)]
        } else {
            0
        };
        let expected_total_tx_fees = fees_so_far + block_fee;
        let expected_total_coinbase = expected_coinbase_rewards;
        fees_so_far += block_fee;

        if i == 0 {
            // first tenure awards the last of the initial mining bonus
            expected_coinbase_rewards += (1000 + 2600) * 1000000;
        } else {
            // subsequent tenures award normal coinbases
            expected_coinbase_rewards += 1000 * 1000000;
        }

        eprintln!(
            "Checking block #{} ({},{}): {} =?= {} + {}",
            i,
            &ch,
            &sn.block_height,
            stx_balance.amount_unlocked(),
            expected_total_coinbase,
            expected_total_tx_fees
        );
        assert_eq!(
            stx_balance.amount_unlocked(),
            expected_total_coinbase + expected_total_tx_fees
        );
    }

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        (11 + total_blocks) as u64
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &rc_blocks.last().unwrap().last().unwrap().header
    );

    // verify that matured miner records were in place
    let mut matured_rewards = vec![];
    {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let (mut chainstate_tx, _) = chainstate.chainstate_tx_begin().unwrap();
        for i in 0..24 {
            let matured_reward_opt = NakamotoChainState::get_matured_miner_reward_schedules(
                &mut chainstate_tx,
                &tip.index_block_hash(),
                i,
            )
            .unwrap();
            matured_rewards.push(matured_reward_opt);
        }
    }
    for (i, matured_reward_opt) in matured_rewards[4..].into_iter().enumerate() {
        let matured_reward = (*matured_reward_opt).clone().unwrap();
        debug!("{}: {:?}", i, &matured_reward);

        if i < 10 {
            assert_eq!(matured_reward.parent_miner.coinbase, 3600_000_000);
        } else {
            assert_eq!(matured_reward.parent_miner.coinbase, 1000_000_000);
        }

        if i == 8 {
            // epoch2
            assert_eq!(
                matured_reward.parent_miner.tx_fees,
                MinerPaymentTxFees::Epoch2 {
                    // The signers voting transaction is paying a fee of 1 uSTX
                    // currently, but this may change to pay 0.
                    anchored: 1,
                    streamed: 0,
                }
            );
        } else if i < 11 {
            // epoch2
            assert_eq!(
                matured_reward.parent_miner.tx_fees,
                MinerPaymentTxFees::Epoch2 {
                    anchored: 0,
                    streamed: 0,
                }
            );
        } else if i == 11 {
            // transition
            assert_eq!(
                matured_reward.parent_miner.tx_fees,
                MinerPaymentTxFees::Nakamoto { parent_fees: 0 }
            );
        } else {
            // nakamoto
            assert_eq!(
                matured_reward.parent_miner.tx_fees,
                MinerPaymentTxFees::Nakamoto {
                    parent_fees: fee_counts[i - 12]
                }
            )
        }

        assert_eq!(matured_reward.latest_miners.len(), 1);

        let miner_reward = &matured_reward.latest_miners[0];

        if i < 9 {
            assert_eq!(miner_reward.coinbase, 3600_000_000);
        } else {
            assert_eq!(miner_reward.coinbase, 1000_000_000);
        }
        if i == 7 {
            // epoch2
            assert_eq!(
                miner_reward.tx_fees,
                MinerPaymentTxFees::Epoch2 {
                    // The signers voting transaction is paying a fee of 1 uSTX
                    // currently, but this may change to pay 0.
                    anchored: 1,
                    streamed: 0,
                }
            );
        } else if i < 10 {
            // epoch2
            assert_eq!(
                miner_reward.tx_fees,
                MinerPaymentTxFees::Epoch2 {
                    anchored: 0,
                    streamed: 0,
                }
            );
        } else if i == 10 {
            // transition
            assert_eq!(
                miner_reward.tx_fees,
                MinerPaymentTxFees::Nakamoto { parent_fees: 0 }
            )
        } else {
            // nakamoto
            assert_eq!(
                miner_reward.tx_fees,
                MinerPaymentTxFees::Nakamoto {
                    parent_fees: fee_counts[i - 11]
                }
            )
        }
    }

    // replay the blocks and sortitions in random order, and verify that we still reach the chain
    // tip
    let mut replay_peer = make_replay_peer(&mut peer);
    for (burn_ops, blocks) in rc_burn_ops.iter().zip(rc_blocks.iter()) {
        replay_reward_cycle(&mut replay_peer, burn_ops, blocks);
    }

    let tip = {
        let chainstate = &mut replay_peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = replay_peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        (11 + total_blocks) as u64
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &rc_blocks.last().unwrap().last().unwrap().header
    );

    peer.check_nakamoto_migration();
    return peer;
}

#[test]
fn test_nakamoto_coordinator_10_tenures_10_sortitions() {
    simple_nakamoto_coordinator_10_tenures_10_sortitions();
}

/// Mine two tenures across three sortitions, using a tenure-extend to allow the first tenure to
/// cover the time of two sortitions.
///
/// Use a tenure-extend to grant the miner of the first tenure the ability to mine
/// 20 blocks in the first tenure (10 before the second sortiton, and 10 after)
pub fn simple_nakamoto_coordinator_2_tenures_3_sortitions<'a>() -> TestPeer<'a> {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 100_000_000)],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let mut rc_burn_ops = vec![];
    let mut all_blocks = vec![];

    // first tenure
    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

    rc_burn_ops.push(burn_ops);

    // do a stx transfer in each block to a given recipient
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    all_blocks.append(&mut blocks.clone());

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        21
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    // highest tenure is our tenure-change
    let (highest_tenure, sort_tip) = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let tenure =
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
                .unwrap()
                .unwrap();
        (tenure, tip)
    };
    assert_eq!(highest_tenure.tenure_id_consensus_hash, tip.consensus_hash);
    assert_eq!(
        highest_tenure.burn_view_consensus_hash,
        sort_tip.consensus_hash
    );
    assert!(tip.consensus_hash == sort_tip.consensus_hash);
    assert_eq!(highest_tenure.coinbase_height, 12);
    assert_eq!(highest_tenure.cause, TenureChangeCause::BlockFound);
    assert_eq!(highest_tenure.tenure_index, 1);
    assert_eq!(highest_tenure.num_blocks_confirmed, 1);

    // extend first tenure
    let (burn_ops, tenure_change_extend, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::Extended);
    let (_, _, next_consensus_hash) = peer.next_burnchain_block(burn_ops.clone());

    rc_burn_ops.push(burn_ops);

    // extending first tenure
    let tenure_change_extend = tenure_change.extend(
        next_consensus_hash,
        blocks.last().cloned().unwrap().header.block_id(),
        blocks.len() as u32,
    );
    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change_extend.clone());

    let blocks_and_sizes = peer.make_nakamoto_tenure_extension(
        tenure_change_tx,
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce extended block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    all_blocks.append(&mut blocks.clone());

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    // chain grew
    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        31
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    // highest tenure is our tenure-extend
    let (highest_tenure, sort_tip) = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let tenure =
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
                .unwrap()
                .unwrap();
        (tenure, tip)
    };
    assert_eq!(highest_tenure.tenure_id_consensus_hash, tip.consensus_hash);
    assert_eq!(
        highest_tenure.burn_view_consensus_hash,
        sort_tip.consensus_hash
    );
    assert!(tip.consensus_hash != sort_tip.consensus_hash);
    assert_eq!(highest_tenure.coinbase_height, 12);
    assert_eq!(highest_tenure.cause, TenureChangeCause::Extended);
    assert_eq!(highest_tenure.tenure_index, 2);
    assert_eq!(highest_tenure.num_blocks_confirmed, 10);

    // second tenure
    let (burn_ops, mut tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    tenure_change.tenure_consensus_hash = consensus_hash.clone();
    tenure_change.burn_view_consensus_hash = consensus_hash.clone();

    let tenure_change_tx = peer
        .miner
        .make_nakamoto_tenure_change(tenure_change.clone());
    let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

    rc_burn_ops.push(burn_ops);

    // do a stx transfer in each block to a given recipient
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx,
        &mut test_signers,
        |miner, chainstate, sortdb, blocks_so_far| {
            if blocks_so_far.len() < 10 {
                debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                let account = get_account(chainstate, sortdb, &addr);
                let stx_transfer = make_token_transfer(
                    chainstate,
                    sortdb,
                    &private_key,
                    account.nonce,
                    100,
                    1,
                    &recipient_addr,
                );

                vec![stx_transfer]
            } else {
                vec![]
            }
        },
    );

    let blocks: Vec<_> = blocks_and_sizes
        .into_iter()
        .map(|(block, _, _)| block)
        .collect();

    all_blocks.append(&mut blocks.clone());

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        41
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    // highest tenure is our new tenure-change
    let (highest_tenure, sort_tip) = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
        let tenure =
            NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
                .unwrap()
                .unwrap();
        (tenure, tip)
    };
    assert_eq!(highest_tenure.tenure_id_consensus_hash, tip.consensus_hash);
    assert_eq!(
        highest_tenure.burn_view_consensus_hash,
        sort_tip.consensus_hash
    );
    assert!(tip.consensus_hash == sort_tip.consensus_hash);
    assert_eq!(highest_tenure.coinbase_height, 13);
    assert_eq!(highest_tenure.cause, TenureChangeCause::BlockFound);
    assert_eq!(highest_tenure.tenure_index, 3);
    assert_eq!(highest_tenure.num_blocks_confirmed, 20);

    // replay the blocks and sortitions in random order, and verify that we still reach the chain
    // tip
    let mut replay_peer = make_replay_peer(&mut peer);
    replay_reward_cycle(&mut replay_peer, &rc_burn_ops, &all_blocks);

    let tip = {
        let chainstate = &mut replay_peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = replay_peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        41
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &blocks.last().unwrap().header
    );

    peer.check_nakamoto_migration();
    return peer;
}

#[test]
fn test_nakamoto_coordinator_2_tenures_3_sortitions() {
    simple_nakamoto_coordinator_2_tenures_3_sortitions();
}

/// Mine a 10 Nakamoto tenures with 10 Nakamoto blocks, but do a tenure-extend in each block
pub fn simple_nakamoto_coordinator_10_extended_tenures_10_sortitions() -> TestPeer<'static> {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let mut test_signers = TestSigners::default();
    let test_stackers = TestStacker::common_signing_set(&test_signers);
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 100_000_000)],
        &mut test_signers,
        &test_stackers,
        None,
    );

    let mut all_blocks: Vec<NakamotoBlock> = vec![];
    let mut all_burn_ops = vec![];
    let mut rc_blocks = vec![];
    let mut rc_burn_ops = vec![];
    let mut consensus_hashes = vec![];
    let mut fee_counts = vec![];
    let stx_miner_key = peer.miner.nakamoto_miner_key();

    for i in 0..10 {
        let (burn_ops, mut tenure_change, miner_key) =
            peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

        tenure_change.tenure_consensus_hash = consensus_hash.clone();
        tenure_change.burn_view_consensus_hash = consensus_hash.clone();

        let tenure_change_tx = peer
            .miner
            .make_nakamoto_tenure_change(tenure_change.clone());
        let coinbase_tx = peer.miner.make_nakamoto_coinbase(None, vrf_proof);

        debug!("Next burnchain block: {}", &consensus_hash);

        let block_height = peer.get_burn_block_height();
        // If we are in the prepare phase, check if we need to generate
        // aggregate key votes
        let txs = if peer.config.burnchain.is_in_prepare_phase(block_height) {
            let cycle_id = peer
                .config
                .burnchain
                .block_height_to_reward_cycle(block_height)
                .unwrap();
            let next_cycle_id = cycle_id as u128 + 1;

            with_sortdb(&mut peer, |chainstate, sortdb| {
                if let Some(tip) = all_blocks.last() {
                    make_all_signers_vote_for_aggregate_key(
                        chainstate,
                        sortdb,
                        &tip.block_id(),
                        &mut test_signers,
                        &test_stackers,
                        next_cycle_id,
                    )
                } else {
                    vec![]
                }
            })
        } else {
            vec![]
        };

        // do a stx transfer in each block to a given recipient
        let recipient_addr =
            StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
        let blocks_and_sizes = peer.make_nakamoto_tenure(
            tenure_change_tx,
            coinbase_tx,
            &mut test_signers,
            |miner, chainstate, sortdb, blocks_so_far| {
                if blocks_so_far.len() < 10 {
                    // Include the aggregate key voting transactions in the first block.
                    let mut txs = if blocks_so_far.is_empty() {
                        txs.clone()
                    } else {
                        vec![]
                    };

                    debug!("\n\nProduce block {}\n\n", blocks_so_far.len());

                    let account = get_account(chainstate, sortdb, &addr);

                    let stx_transfer = make_token_transfer(
                        chainstate,
                        sortdb,
                        &private_key,
                        account.nonce,
                        100,
                        1,
                        &recipient_addr,
                    );
                    txs.push(stx_transfer);

                    let last_block_opt = blocks_so_far
                        .last()
                        .as_ref()
                        .map(|(block, _size, _cost)| block.header.block_id());

                    let mut final_txs = vec![];
                    if let Some(last_block) = last_block_opt.as_ref() {
                        let tenure_extension = tenure_change.extend(
                            consensus_hash.clone(),
                            last_block.clone(),
                            blocks_so_far.len() as u32,
                        );
                        let tenure_extension_tx =
                            miner.make_nakamoto_tenure_change(tenure_extension.clone());
                        final_txs.push(tenure_extension_tx);
                    }
                    final_txs.append(&mut txs);
                    final_txs
                } else {
                    vec![]
                }
            },
        );

        let fees = blocks_and_sizes
            .iter()
            .map(|(block, _, _)| {
                block
                    .txs
                    .iter()
                    .map(|tx| tx.get_tx_fee() as u128)
                    .sum::<u128>()
            })
            .sum::<u128>();

        consensus_hashes.push(consensus_hash);
        fee_counts.push(fees);
        let mut blocks: Vec<NakamotoBlock> = blocks_and_sizes
            .into_iter()
            .map(|(block, _, _)| block)
            .collect();

        // check that our tenure-extends have been getting applied
        let (highest_tenure, sort_tip) = {
            let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
            let sort_db = peer.sortdb.as_mut().unwrap();
            let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
            let tenure =
                NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
                    .unwrap()
                    .unwrap();
            (tenure, tip)
        };

        let last_block = blocks.last().as_ref().cloned().unwrap();
        assert_eq!(
            highest_tenure.tenure_id_consensus_hash,
            last_block.header.consensus_hash
        );
        assert_eq!(
            highest_tenure.burn_view_consensus_hash,
            sort_tip.consensus_hash
        );
        assert!(last_block.header.consensus_hash == sort_tip.consensus_hash);
        assert_eq!(highest_tenure.coinbase_height, 12 + i);
        assert_eq!(highest_tenure.cause, TenureChangeCause::Extended);
        assert_eq!(highest_tenure.tenure_index, 10 * (i + 1));
        assert_eq!(
            highest_tenure.num_blocks_confirmed,
            (blocks.len() as u32) - 1
        );

        // if we're starting a new reward cycle, then save the current one
        let tip = {
            let sort_db = peer.sortdb.as_mut().unwrap();
            SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap()
        };
        if peer
            .config
            .burnchain
            .is_reward_cycle_start(tip.block_height)
        {
            rc_blocks.push(all_blocks.clone());
            rc_burn_ops.push(all_burn_ops.clone());

            all_burn_ops.clear();
            all_blocks.clear();
        }

        all_blocks.append(&mut blocks);
        all_burn_ops.push(burn_ops);
    }

    rc_blocks.push(all_blocks.clone());
    rc_burn_ops.push(all_burn_ops.clone());

    all_burn_ops.clear();
    all_blocks.clear();

    // in nakamoto, tx fees are rewarded by the next tenure, so the
    // scheduled rewards come 1 tenure after the coinbase reward matures
    let miner = p2pkh_from(&stx_miner_key);
    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    // this is sortition height 12, and this miner has earned all 12 of the coinbases
    // plus the initial per-block mining bonus of 2600 STX, but minus the last three rewards (since
    // the miner rewards take three sortitions to confirm).
    //
    // This is (1000 + 2600) * 10 + 1000 - (3600 * 2 + 1000)
    //            first 10          block    unmatured rewards
    //            blocks             11
    let mut expected_coinbase_rewards: u128 = 28800000000;
    let mut fees_so_far: u128 = 0;
    for (i, ch) in consensus_hashes.into_iter().enumerate() {
        let sn = SortitionDB::get_block_snapshot_consensus(sort_db.conn(), &ch)
            .unwrap()
            .unwrap();

        if !sn.sortition {
            continue;
        }
        let block_id = StacksBlockId(sn.winning_stacks_block_hash.0);

        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();
        let sort_db_tx = sort_db.tx_begin_at_tip();

        let stx_balance = clarity_instance
            .read_only_connection(&block_id, &chainstate_tx, &sort_db_tx)
            .with_clarity_db_readonly(|db| db.get_account_stx_balance(&miner.clone().into()))
            .unwrap();

        // it's 1 * 10 because it's 1 uSTX per token-transfer, and 10 per tenure
        let block_fee = if i > 3 {
            fee_counts[i.saturating_sub(4)]
        } else {
            0
        };
        let expected_total_tx_fees = fees_so_far + block_fee;
        let expected_total_coinbase = expected_coinbase_rewards;
        fees_so_far += block_fee;

        if i == 0 {
            // first tenure awards the last of the initial mining bonus
            expected_coinbase_rewards += (1000 + 2600) * 1000000;
        } else {
            // subsequent tenures award normal coinbases
            expected_coinbase_rewards += 1000 * 1000000;
        }

        eprintln!(
            "Checking block #{} ({},{}): {} =?= {} + {}",
            i,
            &ch,
            &sn.block_height,
            stx_balance.amount_unlocked(),
            expected_total_coinbase,
            expected_total_tx_fees
        );
        assert_eq!(
            stx_balance.amount_unlocked(),
            expected_total_coinbase + expected_total_tx_fees
        );
    }

    let tip = {
        let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        111
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &rc_blocks.last().unwrap().last().unwrap().header
    );

    // replay the blocks and sortitions in random order, and verify that we still reach the chain
    // tip
    let mut replay_peer = make_replay_peer(&mut peer);
    for (burn_ops, blocks) in rc_burn_ops.iter().zip(rc_blocks.iter()) {
        replay_reward_cycle(&mut replay_peer, burn_ops, blocks);
    }

    let tip = {
        let chainstate = &mut replay_peer.stacks_node.as_mut().unwrap().chainstate;
        let sort_db = replay_peer.sortdb.as_mut().unwrap();
        NakamotoChainState::get_canonical_block_header(chainstate.db(), sort_db)
            .unwrap()
            .unwrap()
    };

    assert_eq!(
        tip.anchored_header
            .as_stacks_nakamoto()
            .unwrap()
            .chain_length,
        111
    );
    assert_eq!(
        tip.anchored_header.as_stacks_nakamoto().unwrap(),
        &rc_blocks.last().unwrap().last().unwrap().header
    );

    peer.check_nakamoto_migration();
    return peer;
}

#[test]
fn test_nakamoto_coordinator_10_tenures_and_extensions_10_blocks() {
    simple_nakamoto_coordinator_10_extended_tenures_10_sortitions();
}
