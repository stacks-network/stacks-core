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

use clarity::vm::clarity::ClarityConnection;
use clarity::vm::types::PrincipalData;
use rand::prelude::SliceRandom;
use rand::{thread_rng, RngCore};
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::types::chainstate::{
    StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::{Address, StacksEpoch};
use stacks_common::util::vrf::VRFProof;
use wsts::curve::point::Point;

use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::BlockstackOperationType;
use crate::chainstate::coordinator::tests::p2pkh_from;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::TestSigners;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::boot::test::{make_pox_4_aggregate_key, make_pox_4_lockup};
use crate::chainstate::stacks::db::{StacksAccount, StacksChainState};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksTransaction, StacksTransactionSigner, TenureChangeCause,
    TokenTransferMemo, TransactionAnchorMode, TransactionAuth, TransactionPayload,
    TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::core::StacksEpochExtension;
use crate::net::relay::Relayer;
use crate::net::test::{TestPeer, TestPeerConfig};

/// Bring a TestPeer into the Nakamoto Epoch
fn advance_to_nakamoto(peer: &mut TestPeer, aggregate_public_key: &Point) {
    let mut peer_nonce = 0;
    let private_key = peer.config.private_key.clone();
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    for sortition_height in 0..11 {
        // stack to pox-3 in cycle 7
        let txs = if sortition_height == 6 {
            // stack them all
            let stack_tx = make_pox_4_lockup(
                &private_key,
                0,
                1_000_000_000_000_000_000,
                PoxAddress::from_legacy(AddressHashMode::SerializeP2PKH, addr.bytes.clone()),
                12,
                34,
            );
            let aggregate_tx: StacksTransaction = make_pox_4_aggregate_key(
                &private_key,
                1,
                sortition_height + 1,
                aggregate_public_key,
            );
            vec![stack_tx, aggregate_tx]
        } else {
            vec![]
        };

        peer.tenure_with_txs(&txs, &mut peer_nonce);
    }

    // peer is at the start of cycle 8
}

/// Make a peer and transition it into the Nakamoto epoch.
/// The node needs to be stacking; otherwise, Nakamoto won't activate.
fn boot_nakamoto(
    test_name: &str,
    mut initial_balances: Vec<(PrincipalData, u64)>,
    aggregate_public_key: Point,
) -> TestPeer {
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
    peer_config.epochs = Some(StacksEpoch::unit_test_3_0_only(37));
    peer_config.initial_balances = vec![(addr.to_account_principal(), 1_000_000_000_000_000_000)];
    peer_config.initial_balances.append(&mut initial_balances);
    peer_config.burnchain.pox_constants.v2_unlock_height = 21;
    peer_config.burnchain.pox_constants.pox_3_activation_height = 26;
    peer_config.burnchain.pox_constants.v3_unlock_height = 27;
    peer_config.burnchain.pox_constants.pox_4_activation_height = 31;

    let mut peer = TestPeer::new(peer_config);
    advance_to_nakamoto(&mut peer, &aggregate_public_key);
    peer
}

/// Make a replay peer, used for replaying the blockchain
fn make_replay_peer<'a>(peer: &'a mut TestPeer<'a>, aggregate_public_key: &Point) -> TestPeer<'a> {
    let mut replay_config = peer.config.clone();
    replay_config.test_name = format!("{}.replay", &peer.config.test_name);
    replay_config.server_port = 0;
    replay_config.http_port = 0;

    let mut replay_peer = TestPeer::new(replay_config);
    advance_to_nakamoto(&mut replay_peer, aggregate_public_key);

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
fn make_token_transfer(
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
    let sort_handle = sortdb.index_handle(&sort_tip);

    let mut blocks_to_process = stacks_blocks.to_vec();
    blocks_to_process.shuffle(&mut thread_rng());
    while let Some(block) = blocks_to_process.pop() {
        let block_id = block.block_id();
        info!("Process Nakamoto block {} ({:?}", &block_id, &block.header);

        let accepted = Relayer::process_new_nakamoto_block(
            &sortdb,
            &sort_handle,
            &mut node.chainstate,
            block.clone(),
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
}

/// Mine a single Nakamoto tenure with a single Nakamoto block
#[test]
fn test_simple_nakamoto_coordinator_bootup() {
    let mut test_signers = TestSigners::default();
    let mut peer = boot_nakamoto(function_name!(), vec![], test_signers.aggregate_public_key);

    let (burn_ops, tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops);
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);
    let blocks_and_sizes = peer.make_nakamoto_tenure(
        &consensus_hash,
        tenure_change,
        &mut test_signers,
        vrf_proof,
        |_miner, _chainstate, _sort_dbconn, _count| vec![],
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
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 10_000)],
        test_signers.aggregate_public_key,
    );

    let (burn_ops, tenure_change, miner_key) =
        peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
    let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
    let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

    // do a stx transfer in each block to a given recipient
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let blocks_and_sizes = peer.make_nakamoto_tenure(
        &consensus_hash,
        tenure_change,
        &mut test_signers,
        vrf_proof,
        |miner, chainstate, sortdb, count| {
            if count < 10 {
                debug!("\n\nProduce block {}\n\n", count);

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
    let mut replay_peer = make_replay_peer(&mut peer, &test_signers.aggregate_public_key);
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
}

/// Mine a 10 Nakamoto tenures with 10 Nakamoto blocks
#[test]
fn test_simple_nakamoto_coordinator_10_tenures_10_blocks() {
    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();

    let mut test_signers = TestSigners::default();
    let mut peer = boot_nakamoto(
        function_name!(),
        vec![(addr.into(), 11_000)],
        test_signers.aggregate_public_key,
    );

    let mut all_blocks = vec![];
    let mut all_burn_ops = vec![];
    let mut rc_blocks = vec![];
    let mut rc_burn_ops = vec![];
    let mut consensus_hashes = vec![];
    let stx_miner_key = peer.miner.nakamoto_miner_key();

    for i in 0..10 {
        let (burn_ops, tenure_change, miner_key) =
            peer.begin_nakamoto_tenure(TenureChangeCause::BlockFound);
        let (_, _, consensus_hash) = peer.next_burnchain_block(burn_ops.clone());
        let vrf_proof = peer.make_nakamoto_vrf_proof(miner_key);

        debug!("Next burnchain block: {}", &consensus_hash);

        // do a stx transfer in each block to a given recipient
        let recipient_addr =
            StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
        let aggregate_public_key = test_signers.aggregate_public_key.clone();
        let blocks_and_sizes = peer.make_nakamoto_tenure(
            &consensus_hash,
            tenure_change,
            &mut test_signers,
            vrf_proof,
            |miner, chainstate, sortdb, count| {
                if count < 10 {
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

                    let aggregate_tx = make_pox_4_aggregate_key(
                        &private_key,
                        account.nonce + 1,
                        7 + i,
                        &aggregate_public_key,
                    );
                    vec![stx_transfer, aggregate_tx]
                } else {
                    vec![]
                }
            },
        );

        consensus_hashes.push(consensus_hash);
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
    let mut expected_coinbase_rewards: u128 = 28800000000;
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
            .with_clarity_db_readonly(|db| db.get_account_stx_balance(&miner.clone().into()));

        // it's 1 * 10 because it's 1 uSTX per token-transfer, and 10 per tenure
        let expected_total_tx_fees = 1 * 10 * (i as u128).saturating_sub(3);
        let expected_total_coinbase = expected_coinbase_rewards;

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
    let mut replay_peer = make_replay_peer(&mut peer, &test_signers.aggregate_public_key);
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
}
