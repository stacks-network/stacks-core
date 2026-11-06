// Copyright (C) 2013-2021 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

mod nakamoto_transition_schedule;

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use clarity::vm::costs::ExecutionCost;
use clarity::vm::test_util::TEST_BURN_STATE_DB;
use clarity::vm::types::{PrincipalData, QualifiedContractIdentifier, StacksAddressExtensions};
use clarity::vm::{ContractName, Value};
use rand::prelude::*;
use rand::thread_rng;
use rusqlite::params;
use stacks_common::codec::StacksMessageCodec;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, StacksWorkScore, TrieHash,
};
use stacks_common::types::{Address, MempoolCollectionBehavior, StacksEpochId};
use stacks_common::util::hash::{Hash160, *};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::VRFProof;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs, sleep_ms};

use super::mempool::MemPoolWalkStrategy;
use super::MemPoolDB;
use crate::burnchains::Txid;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::db::blocks::MemPoolRejection;
use crate::chainstate::stacks::db::testing::{chainstate_path, TestChainstateBuilder};
use crate::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::miner::TransactionResult;
use crate::chainstate::stacks::test::codec_all_transactions;
use crate::chainstate::stacks::{
    Error as ChainstateError, SinglesigHashMode, SinglesigSpendingCondition, StacksBlockHeader,
    StacksPrivateKey, StacksTransaction, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionPublicKeyEncoding,
    TransactionSpendingCondition, TransactionVersion,
};
use crate::core::mempool::{
    db_get_all_nonces, next_arrival_seq, take_arrival_seq, ArrivalSeqBlock, MemPoolSyncData,
    MemPoolWalkSettings, MemPoolWalkTxTypes, TxTag, ARRIVAL_SEQ_BLOCK_LEN, BLOOM_COUNTER_DEPTH,
    BLOOM_COUNTER_ERROR_RATE, MAX_BLOOM_COUNTER_TXS,
};
use crate::core::test_util::{
    insert_tx_in_mempool, make_stacks_transfer_serialized, make_stacks_transfer_tx, to_addr,
};
use crate::core::{CHAIN_ID_TESTNET, FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use crate::cost_estimates::metrics::UnitMetric;
use crate::cost_estimates::UnitEstimator;
use crate::util_lib::bloom::test::setup_bloom_counter;
use crate::util_lib::bloom::*;
use crate::util_lib::db::tx_begin_immediate;

#[test]
fn mempool_db_init() {
    let _chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let _mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
}

pub fn make_block(
    chainstate: &mut StacksChainState,
    block_consensus: ConsensusHash,
    parent: &(ConsensusHash, BlockHeaderHash),
    burn_height: u64,
    block_height: u64,
) -> (ConsensusHash, BlockHeaderHash) {
    let (mut chainstate_tx, clar_tx) = chainstate.chainstate_tx_begin();

    let anchored_header = StacksBlockHeader {
        version: 1,
        total_work: StacksWorkScore {
            work: block_height,
            burn: 1,
        },
        proof: VRFProof::empty(),
        parent_block: parent.1.clone(),
        parent_microblock: BlockHeaderHash([0; 32]),
        parent_microblock_sequence: 0,
        tx_merkle_root: Sha512Trunc256Sum::empty(),
        state_index_root: TrieHash::EMPTY,
        microblock_pubkey_hash: Hash160([0; 20]),
    };

    let block_hash = anchored_header.block_hash();

    let c_tx = StacksChainState::chainstate_block_begin(
        &chainstate_tx,
        clar_tx,
        &TEST_BURN_STATE_DB,
        &parent.0,
        &parent.1,
        &block_consensus,
        &block_hash,
    );

    let new_tip_info = StacksHeaderInfo {
        anchored_header: anchored_header.into(),
        microblock_tail: None,
        index_root: TrieHash::EMPTY,
        stacks_block_height: block_height,
        consensus_hash: block_consensus.clone(),
        burn_header_hash: BurnchainHeaderHash([0; 32]),
        burn_header_height: burn_height as u32,
        burn_header_timestamp: 0,
        anchored_block_size: 1,
        burn_view: None,
        total_tenure_size: 0,
    };

    c_tx.commit_block();

    let new_index_hash = StacksBlockId::new(&block_consensus, &block_hash);

    // instantiate the inner MARF
    chainstate_tx
        .put_indexed_all(
            &StacksBlockId::new(&parent.0, &parent.1),
            &new_index_hash,
            &[],
            &[],
        )
        .unwrap();

    StacksChainState::insert_stacks_block_header(
        &chainstate_tx,
        &new_index_hash,
        &new_tip_info,
        &ExecutionCost::ZERO,
    )
    .unwrap();

    chainstate_tx.commit().unwrap();

    (block_consensus, block_hash)
}

#[test]
fn mempool_walk_over_fork() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

    // genesis -> b_1* -> b_2*
    //               \-> b_3 -> b_4
    //
    // *'d blocks accept transactions,
    //   try to walk at b_4, we should be able to find
    //   the transaction at b_1

    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);
    let b_5 = make_block(&mut chainstate, ConsensusHash([0x5; 20]), &b_2, 5, 3);
    let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 3, 2);
    let b_4 = make_block(&mut chainstate, ConsensusHash([0x4; 20]), &b_3, 4, 3);

    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let mut all_txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    let blocks_to_broadcast_in = [&b_1, &b_2, &b_4];
    let mut txs = [
        all_txs.pop().unwrap(),
        all_txs.pop().unwrap(),
        all_txs.pop().unwrap(),
    ];
    for tx in txs.iter_mut() {
        tx.set_tx_fee(123);
    }

    for ix in 0..3 {
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let block = &blocks_to_broadcast_in[ix];
        let good_tx = &txs[ix];

        let origin_address = StacksAddress::new(22, Hash160::from_data(&[ix as u8; 32])).unwrap();
        let sponsor_address =
            StacksAddress::new(22, Hash160::from_data(&[0x80 | (ix as u8); 32])).unwrap();

        let txid = good_tx.txid();
        let tx_bytes = good_tx.serialize_to_vec();
        let tx_fee = good_tx.get_tx_fee();

        let height = 1 + ix as u64;

        let origin_nonce = 0; // (2 * ix + i) as u64;
        let sponsor_nonce = 0; // (2 * ix + i) as u64;

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &block.0,
            &block.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        mempool_tx.commit().unwrap();
    }

    // genesis -> b_1* -> b_2* -> b_5
    //               \-> b_3 -> b_4
    //
    // *'d blocks accept transactions,
    //   try to walk at b_4, we should be able to find
    //   the transaction at b_1

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_2"
            );
        },
    );

    // Now that the mempool has iterated over those transactions, its view of the
    //  nonce for the origin address should have changed. Now it should find *no* transactions.
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 0, "Mempool should find no transactions");
        },
    );

    mempool
        .reset_mempool_caches()
        .expect("Should be able to reset nonces");

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_5.0, &b_5.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_5"
            );
        },
    );

    mempool
        .reset_mempool_caches()
        .expect("Should be able to reset nonces");

    // The mempool iterator no longer does any consideration of what block accepted
    //  the transaction, so b_3 should have the same view.
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_3.0, &b_3.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_3"
            );
        },
    );

    mempool
        .reset_mempool_caches()
        .expect("Should be able to reset nonces");

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_4.0, &b_4.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 3,
                "Mempool should find three transactions from b_4"
            );
        },
    );

    mempool
        .reset_mempool_caches()
        .expect("Should be able to reset nonces");

    // let's test replace-across-fork while we're here.
    // first try to replace a tx in b_2 in b_1 - should fail because they are in the same fork
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let block = &b_1;
    let tx = &txs[1];
    let origin_address = StacksAddress::new(22, Hash160::from_data(&[1; 32])).unwrap();
    let sponsor_address = StacksAddress::new(22, Hash160::from_data(&[0x81; 32])).unwrap();

    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();

    let height = 3;
    let origin_nonce = 0;
    let sponsor_nonce = 0;

    // make sure that we already have the transaction we're testing for replace-across-fork
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    assert!(MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &block.0,
        &block.1,
        true,
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .is_err());

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    mempool_tx.commit().unwrap();

    // now try replace-across-fork from b_2 to b_4
    // check that the number of transactions at b_2 and b_4 starts at 1 each
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
        1
    );
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
        1
    );
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let block = &b_4;
    let tx = &txs[1];
    let origin_address = StacksAddress::new(22, Hash160::from_data(&[0; 32])).unwrap();
    let sponsor_address = StacksAddress::new(22, Hash160::from_data(&[1; 32])).unwrap();

    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();

    let height = 3;
    let origin_nonce = 1;
    let sponsor_nonce = 1;

    // make sure that we already have the transaction we're testing for replace-across-fork
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &block.0,
        &block.1,
        true,
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    mempool_tx.commit().unwrap();

    // after replace-across-fork, tx[1] should have moved from the b_2->b_5 fork to b_4
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_4.0, &b_4.1).unwrap(),
        2
    );
    assert_eq!(
        MemPoolDB::get_num_tx_at_block(&mempool.db, &b_2.0, &b_2.1).unwrap(),
        0
    );
}

#[test]
/// This test verifies that all transactions are visited, regardless of the
/// setting for `consider_no_estimate_tx_prob`.
fn test_iterate_candidates_consider_no_estimate_tx_prob() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mut mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 24 transactions into the mempool, alternating whether or not they have a fee-rate.
    for nonce in 0..24 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        if nonce & 1 == 0 {
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![Some(123.0), txid],
                )
                .unwrap();
        } else {
            let none: Option<f64> = None;
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![none, txid],
                )
                .unwrap();
        }

        mempool_tx.commit().unwrap();
    }

    // First, with default (5%)
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    // Next with 0%
    let _ = mempool.reset_mempool_caches();
    mempool_settings.consider_no_estimate_tx_prob = 0;

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    // Then with with 100%
    let _ = mempool.reset_mempool_caches();
    mempool_settings.consider_no_estimate_tx_prob = 100;

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );
}

#[test]
/// This test verifies that when a transaction is skipped, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_skipped_transaction() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::skipped(
                                &available_tx.tx.tx,
                                "event not relevant to test".to_string(),
                            )
                            .convert_to_event()
                        } else {
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that when a transaction reports a processing error, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_processing_error_transaction() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::error(
                                &available_tx.tx.tx,
                                crate::chainstate::stacks::Error::StacksTransactionSkipped(
                                    "error for testing".to_string(),
                                ),
                            )
                            .convert_to_event()
                        } else {
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that when a transaction is skipped, other transactions
/// from the same address with higher nonces are not considered for inclusion in a block.
fn test_iterate_candidates_problematic_transaction() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    // Load 3 transactions into the mempool
    for nonce in 0..3 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        mempool_tx.commit().unwrap();
    }

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        // For the second transaction, return a `Skipped` result
                        let result = if count_txs == 2 {
                            TransactionResult::problematic(
                                &available_tx.tx.tx,
                                crate::chainstate::stacks::Error::StacksTransactionSkipped(
                                    "problematic for testing".to_string(),
                                ),
                            )
                            .convert_to_event()
                        } else {
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event()
                        };
                        Ok(Some(result))
                    },
                )
                .unwrap();
            assert_eq!(
                count_txs, 2,
                "Mempool iteration should not proceed past the skipped transaction"
            );
        },
    );
}

#[test]
/// This test verifies that all transactions are visited, and nonce cache on disk updated, even if
/// there's a concurrent write-lock on the mempool DB.
fn test_iterate_candidates_concurrent_write_lock() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mut mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );

    let mut expected_addr_nonces = HashMap::new();

    // Load 24 transactions into the mempool, alternating whether or not they have a fee-rate.
    for nonce in 0..24 {
        let mut tx = txs.pop().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();

        let origin_address = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);

        if let Some(nonce) = expected_addr_nonces.get_mut(&origin_address) {
            *nonce = cmp::max(*nonce, origin_nonce);
        } else {
            expected_addr_nonces.insert(origin_address.clone(), origin_nonce);
        }

        if let Some(nonce) = expected_addr_nonces.get_mut(&sponsor_address) {
            *nonce = cmp::max(*nonce, sponsor_nonce);
        } else {
            expected_addr_nonces.insert(sponsor_address.clone(), sponsor_nonce);
        }

        tx.set_tx_fee(100);
        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let tx_fee = tx.get_tx_fee();
        let height = 100;

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_1.0,
            &b_1.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            nonce,
            &sponsor_address,
            nonce,
            None,
        )
        .unwrap();

        if nonce & 1 == 0 {
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![Some(123.0), txid],
                )
                .unwrap();
        } else {
            let none: Option<f64> = None;
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![none, txid],
                )
                .unwrap();
        }

        mempool_tx.commit().unwrap();
    }
    assert!(!expected_addr_nonces.is_empty());

    let all_addr_nonces = db_get_all_nonces(mempool.conn()).unwrap();
    assert!(all_addr_nonces.is_empty());

    // start a thread that holds a write-lock on the mempool
    let write_thread = std::thread::spawn(move || {
        let mut thread_mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();
        let mempool_tx = thread_mempool.tx_begin().unwrap();
        sleep_ms(10_000);
    });

    sleep_ms(1_000);

    // 50% chance of considering a transaction with unknown fee estimate
    mempool_settings.consider_no_estimate_tx_prob = 50;
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 24, "Mempool should find all 24 transactions");
        },
    );

    write_thread.join().unwrap();

    let all_addr_nonces = db_get_all_nonces(mempool.conn()).unwrap();
    assert_eq!(all_addr_nonces.len(), expected_addr_nonces.len());

    for (addr, nonce) in all_addr_nonces {
        assert!(expected_addr_nonces.contains_key(&addr));
        assert_eq!(nonce, 24);
    }
}

#[test]
fn mempool_do_not_replace_tx() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

    // genesis -> b_1 -> b_2
    //      \-> b_3
    //
    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);
    let b_3 = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &b_1, 1, 1);

    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let mut txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    let mut tx = txs.pop().unwrap();

    let mut mempool_tx = mempool.tx_begin().unwrap();

    // do an initial insert
    let origin_address = StacksAddress::new(22, Hash160::from_data(&[0; 32])).unwrap();
    let sponsor_address = StacksAddress::new(22, Hash160::from_data(&[1; 32])).unwrap();

    tx.set_tx_fee(123);

    // test insert
    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();

    let tx_fee = tx.get_tx_fee();
    let height = 100;

    let origin_nonce = tx.get_origin_nonce();
    let sponsor_nonce = match tx.get_sponsor_nonce() {
        Some(n) => n,
        None => origin_nonce,
    };

    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &b_1.0,
        &b_1.1,
        true,
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let prior_txid = txid.clone();

    // now, let's try inserting again, with a lower fee, but at a different block hash
    tx.set_tx_fee(100);
    let txid = tx.txid();
    let tx_bytes = tx.serialize_to_vec();
    let tx_fee = tx.get_tx_fee();
    let height = 100;

    let err_resp = MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &b_2.0,
        &b_2.1,
        true,
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap_err();
    assert!(match err_resp {
        MemPoolRejection::ConflictingNonceInMempool => true,
        e => panic!("Failed: {e:?}"),
    });

    assert!(MemPoolDB::db_has_tx(&mempool_tx, &prior_txid).unwrap());
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
}

#[rstest]
#[case(MempoolCollectionBehavior::ByStacksHeight)]
#[case(MempoolCollectionBehavior::ByReceiveTime)]
fn mempool_db_load_store_replace_tx(#[case] behavior: MempoolCollectionBehavior) {
    let path_name = format!("{}::{:?}", function_name!(), behavior);
    let mut chainstate = TestChainstateBuilder::new_testnet(&path_name).build();
    let chainstate_path = chainstate_path(&path_name);
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let txs = codec_all_transactions(
        &TransactionVersion::Testnet,
        0x80000000,
        &TransactionAnchorMode::Any,
        &TransactionPostConditionMode::Allow,
        StacksEpochId::latest(),
    );
    let num_txs = txs.len() as u64;

    let mut mempool_tx = mempool.tx_begin().unwrap();

    eprintln!("add all txs");
    for (i, mut tx) in txs.into_iter().enumerate() {
        // make sure each address is unique per tx (not the case in codec_all_transactions)
        let origin_address = StacksAddress::new(22, Hash160::from_data(&i.to_be_bytes())).unwrap();
        let sponsor_address =
            StacksAddress::new(22, Hash160::from_data(&(i + 1).to_be_bytes())).unwrap();

        tx.set_tx_fee(123);

        // test insert

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();

        let tx_fee = tx.get_tx_fee();
        let height = 100;
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_nonce = match tx.get_sponsor_nonce() {
            Some(n) => n,
            None => origin_nonce,
        };
        let len = tx_bytes.len() as u64;

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        // test retrieval
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
        let tx_info = tx_info_opt.unwrap();

        assert_eq!(tx_info.tx, expected_tx);
        assert_eq!(tx_info.metadata.len, len);
        assert_eq!(tx_info.metadata.tx_fee, 123);
        assert_eq!(tx_info.metadata.origin_address, origin_address);
        assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
        assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
        assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
        assert_eq!(
            tx_info.metadata.tenure_consensus_hash,
            ConsensusHash([0x1; 20])
        );
        assert_eq!(
            tx_info.metadata.tenure_block_header_hash,
            BlockHeaderHash([0x2; 32])
        );
        assert_eq!(tx_info.metadata.coinbase_height, height);

        // test replace-by-fee with a higher fee
        let old_txid = txid.clone();

        tx.set_tx_fee(124);
        assert!(txid != tx.txid());

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();

        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_before =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert_eq!(tx_info_before, tx_info.metadata);

        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap();

        // was replaced
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

        let tx_info_after =
            MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
                .unwrap()
                .unwrap();
        assert!(tx_info_after != tx_info.metadata);

        // test retrieval -- transaction should have been replaced because it has a higher
        // estimated fee
        let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();

        let tx_info = tx_info_opt.unwrap();
        assert_eq!(tx_info.metadata, tx_info_after);

        assert_eq!(tx_info.tx, expected_tx);
        assert_eq!(tx_info.metadata.len, len);
        assert_eq!(tx_info.metadata.tx_fee, 124);
        assert_eq!(tx_info.metadata.origin_address, origin_address);
        assert_eq!(tx_info.metadata.origin_nonce, origin_nonce);
        assert_eq!(tx_info.metadata.sponsor_address, sponsor_address);
        assert_eq!(tx_info.metadata.sponsor_nonce, sponsor_nonce);
        assert_eq!(
            tx_info.metadata.tenure_consensus_hash,
            ConsensusHash([0x1; 20])
        );
        assert_eq!(
            tx_info.metadata.tenure_block_header_hash,
            BlockHeaderHash([0x2; 32])
        );
        assert_eq!(tx_info.metadata.coinbase_height, height);

        // test replace-by-fee with a lower fee
        let old_txid = txid.clone();

        tx.set_tx_fee(122);
        assert!(txid != tx.txid());

        let txid = tx.txid();
        let mut tx_bytes = vec![];
        tx.consensus_serialize(&mut tx_bytes).unwrap();
        let _expected_tx = tx.clone();
        let tx_fee = tx.get_tx_fee();

        assert!(match MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1; 20]),
            &BlockHeaderHash([0x2; 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            height,
            &origin_address,
            origin_nonce,
            &sponsor_address,
            sponsor_nonce,
            None,
        )
        .unwrap_err()
        {
            MemPoolRejection::ConflictingNonceInMempool => true,
            _ => false,
        });

        // was NOT replaced
        assert!(MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
        assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    }
    mempool_tx.commit().unwrap();

    eprintln!("get all txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert_eq!(txs.len() as u64, num_txs);

    eprintln!("get empty txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x3; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert!(txs.is_empty());

    eprintln!("get empty txs");
    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x2; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert!(txs.is_empty());

    eprintln!("garbage-collect");
    let mempool_tx = mempool.tx_begin().unwrap();
    match behavior {
        MempoolCollectionBehavior::ByStacksHeight => {
            MemPoolDB::garbage_collect_by_coinbase_height(&mempool_tx, 101, None)
        }
        MempoolCollectionBehavior::ByReceiveTime => {
            let test_max_age = Duration::from_secs(1);
            std::thread::sleep(2 * test_max_age);
            MemPoolDB::garbage_collect_by_time(&mempool_tx, &test_max_age, None)
        }
    }
    .unwrap();
    mempool_tx.commit().unwrap();

    let txs = MemPoolDB::get_txs_after(
        &mempool.db,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        0,
        num_txs,
    )
    .unwrap();
    assert!(txs.is_empty());
}

#[test]
fn mempool_db_test_rbf() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    // create initial transaction
    let mut mempool_tx = mempool.tx_begin().unwrap();
    let spending_condition = TransactionSpendingCondition::Singlesig(SinglesigSpendingCondition {
        signer: Hash160([0x11; 20]),
        hash_mode: SinglesigHashMode::P2PKH,
        key_encoding: TransactionPublicKeyEncoding::Uncompressed,
        nonce: 123,
        tx_fee: 456,
        signature: MessageSignature::from_raw(&[0xff; 65]),
    });
    let stx_address = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let payload = TransactionPayload::TokenTransfer(
        PrincipalData::from(QualifiedContractIdentifier {
            issuer: stx_address.clone().into(),
            name: ContractName::from_literal("hello-contract-name"),
        }),
        123,
        TokenTransferMemo([0u8; 34]),
    );
    let mut tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 0x80000000,
        auth: TransactionAuth::Standard(spending_condition),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: Vec::new(),
        payload,
    };

    let i: usize = 0;
    let origin_address = StacksAddress::new(22, Hash160::from_data(&i.to_be_bytes())).unwrap();
    let sponsor_address =
        StacksAddress::new(22, Hash160::from_data(&(i + 1).to_be_bytes())).unwrap();

    tx.set_tx_fee(123);
    let txid = tx.txid();
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    let expected_tx = tx.clone();
    let tx_fee = tx.get_tx_fee();
    let height = 100;
    let origin_nonce = tx.get_origin_nonce();
    let sponsor_nonce = match tx.get_sponsor_nonce() {
        Some(n) => n,
        None => origin_nonce,
    };
    let first_len = tx_bytes.len() as u64;

    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());
    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        false, // don't resolve the above chain tip since it doesn't exist
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    // test retrieval of initial transaction
    let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
    let tx_info = tx_info_opt.unwrap();

    // test replace-by-fee with a higher fee, where the payload is smaller
    let old_txid = txid.clone();
    let old_tx_fee = tx_fee;

    tx.set_tx_fee(124);
    tx.payload =
        TransactionPayload::TokenTransfer(stx_address.into(), 123, TokenTransferMemo([0u8; 34]));
    assert!(txid != tx.txid());
    let txid = tx.txid();
    let mut tx_bytes = vec![];
    tx.consensus_serialize(&mut tx_bytes).unwrap();
    let expected_tx = tx.clone();
    let tx_fee = tx.get_tx_fee();
    let second_len = tx_bytes.len() as u64;

    // these asserts are to ensure we are using the fee directly, not the fee rate
    assert!(second_len < first_len);
    assert!(second_len * tx_fee < first_len * old_tx_fee);
    assert!(tx_fee > old_tx_fee);
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let tx_info_before =
        MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
            .unwrap()
            .unwrap();
    assert_eq!(tx_info_before, tx_info.metadata);

    MemPoolDB::try_add_tx(
        &mut mempool_tx,
        &mut chainstate,
        &ConsensusHash([0x1; 20]),
        &BlockHeaderHash([0x2; 32]),
        false, // don't resolve the above chain tip since it doesn't exist
        &txid,
        tx_bytes,
        tx_fee,
        height,
        &origin_address,
        origin_nonce,
        &sponsor_address,
        sponsor_nonce,
        None,
    )
    .unwrap();

    // check that the transaction was replaced
    assert!(!MemPoolDB::db_has_tx(&mempool_tx, &old_txid).unwrap());
    assert!(MemPoolDB::db_has_tx(&mempool_tx, &txid).unwrap());

    let tx_info_after =
        MemPoolDB::get_tx_metadata_by_address(&mempool_tx, true, &origin_address, origin_nonce)
            .unwrap()
            .unwrap();
    assert!(tx_info_after != tx_info.metadata);

    // test retrieval -- transaction should have been replaced because it has a higher fee
    let tx_info_opt = MemPoolDB::get_tx(&mempool_tx, &txid).unwrap();
    let tx_info = tx_info_opt.unwrap();
    assert_eq!(tx_info.metadata, tx_info_after);
    assert_eq!(tx_info.metadata.len, second_len);
    assert_eq!(tx_info.metadata.tx_fee, 124);
}

#[test]
fn test_add_txs_bloom_filter() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

    let mut all_txids: Vec<Vec<Txid>> = vec![];

    // none conflict
    for block_height in 10..(10 + 10 * BLOOM_COUNTER_DEPTH) {
        let mut txids: Vec<Txid> = vec![];
        let mut fp_count = 0;

        let bf = mempool.get_txid_bloom_filter().unwrap();
        let mut mempool_tx = mempool.tx_begin().unwrap();
        for i in 0..128 {
            let pk = StacksPrivateKey::random();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                anchor_mode: TransactionAnchorMode::Any,
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: vec![],
                payload: TransactionPayload::TokenTransfer(
                    addr.to_account_principal(),
                    (block_height + i * 128) as u64,
                    TokenTransferMemo([0u8; 34]),
                ),
            };
            tx.set_tx_fee(1000);
            tx.set_origin_nonce(0);

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            // should succeed
            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1 + (block_height as u8); 20]),
                &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                false, // don't resolve the above chain tip since it doesn't exist
                &txid,
                tx_bytes,
                tx_fee,
                block_height as u64,
                &origin_addr,
                origin_nonce,
                &sponsor_addr,
                sponsor_nonce,
                None,
            )
            .unwrap();

            if bf.contains_raw(&tx.txid().0) {
                fp_count += 1;
            }

            txids.push(txid);
        }

        mempool_tx.commit().unwrap();

        // nearly all txs should be new
        assert!((fp_count as f64) / (MAX_BLOOM_COUNTER_TXS as f64) <= BLOOM_COUNTER_ERROR_RATE);

        let bf = mempool.get_txid_bloom_filter().unwrap();
        for txid in txids.iter() {
            assert!(
                bf.contains_raw(&txid.0),
                "Bloom filter does not contain {}",
                &txid
            );
        }

        all_txids.push(txids);

        if block_height > 10 + BLOOM_COUNTER_DEPTH {
            let expired_block_height = block_height - BLOOM_COUNTER_DEPTH;
            let bf = mempool.get_txid_bloom_filter().unwrap();
            for txids in &all_txids[..block_height - 10 - BLOOM_COUNTER_DEPTH] {
                let mut fp_count = 0;
                for txid in txids {
                    if bf.contains_raw(&txid.0) {
                        fp_count += 1;
                    }
                }

                // these expired txids should mostly be absent
                assert!(
                    (fp_count as f64) / (MAX_BLOOM_COUNTER_TXS as f64) <= BLOOM_COUNTER_ERROR_RATE
                );
            }
        }
    }
}

#[test]
fn test_txtags() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);

    let mut all_txtags: Vec<Vec<TxTag>> = vec![];

    for block_height in 10..(10 + 10 * BLOOM_COUNTER_DEPTH) {
        let mut txtags: Vec<TxTag> = vec![];

        let mut mempool_tx = mempool.tx_begin().unwrap();
        for i in 0..128 {
            let pk = StacksPrivateKey::random();
            let mut tx = StacksTransaction {
                version: TransactionVersion::Testnet,
                chain_id: 0x80000000,
                auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                anchor_mode: TransactionAnchorMode::Any,
                post_condition_mode: TransactionPostConditionMode::Allow,
                post_conditions: vec![],
                payload: TransactionPayload::TokenTransfer(
                    addr.to_account_principal(),
                    (block_height + i * 128) as u64,
                    TokenTransferMemo([0u8; 34]),
                ),
            };
            tx.set_tx_fee(1000);
            tx.set_origin_nonce(0);

            let txid = tx.txid();
            let tx_bytes = tx.serialize_to_vec();
            let origin_addr = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let tx_fee = tx.get_tx_fee();

            let txtag = TxTag::from(&seed, &txid);

            // should succeed
            MemPoolDB::try_add_tx(
                &mut mempool_tx,
                &mut chainstate,
                &ConsensusHash([0x1 + (block_height as u8); 20]),
                &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                false, // don't resolve the above chain tip since it doesn't exist
                &txid,
                tx_bytes,
                tx_fee,
                block_height as u64,
                &origin_addr,
                origin_nonce,
                &sponsor_addr,
                sponsor_nonce,
                None,
            )
            .unwrap();

            txtags.push(txtag);
        }

        mempool_tx.commit().unwrap();
        all_txtags.push(txtags);

        if block_height - 10 >= BLOOM_COUNTER_DEPTH {
            assert_eq!(
                MemPoolDB::get_num_recent_txs(mempool.conn()).unwrap(),
                (BLOOM_COUNTER_DEPTH * 128) as u64
            );
        }

        let txtags = mempool.get_txtags(&seed).unwrap();
        let len_txtags = all_txtags.len();
        let last_txtags = &all_txtags[len_txtags.saturating_sub(BLOOM_COUNTER_DEPTH)..len_txtags];

        let mut expected_txtag_set = HashSet::new();
        for txtags in last_txtags.iter() {
            for txtag in txtags.iter() {
                expected_txtag_set.insert(txtag.clone());
            }
        }

        assert_eq!(expected_txtag_set.len(), txtags.len());
        for txtag in txtags.into_iter() {
            assert!(expected_txtag_set.contains(&txtag));
        }
    }
}

#[test]
#[ignore]
fn test_make_mempool_sync_data() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

    let mut txids = vec![];
    let mut nonrecent_fp_rates = vec![];
    for block_height in 10..(10 + BLOOM_COUNTER_DEPTH + 1) {
        for i in 0..((MAX_BLOOM_COUNTER_TXS + 128) as usize) {
            let mut mempool_tx = mempool.tx_begin().unwrap();
            for j in 0..128 {
                let pk = StacksPrivateKey::random();
                let mut tx = StacksTransaction {
                    version: TransactionVersion::Testnet,
                    chain_id: 0x80000000,
                    auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
                    anchor_mode: TransactionAnchorMode::Any,
                    post_condition_mode: TransactionPostConditionMode::Allow,
                    post_conditions: vec![],
                    payload: TransactionPayload::TokenTransfer(
                        addr.to_account_principal(),
                        123,
                        TokenTransferMemo([0u8; 34]),
                    ),
                };
                tx.set_tx_fee(1000);
                tx.set_origin_nonce(0);

                let txid = tx.txid();
                let tx_bytes = tx.serialize_to_vec();
                let origin_addr = tx.origin_address();
                let origin_nonce = tx.get_origin_nonce();
                let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
                let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
                let tx_fee = tx.get_tx_fee();

                // should succeed
                MemPoolDB::try_add_tx(
                    &mut mempool_tx,
                    &mut chainstate,
                    &ConsensusHash([0x1 + (block_height as u8); 20]),
                    &BlockHeaderHash([0x2 + (block_height as u8); 32]),
                    false, // don't resolve the above chain tip since it doesn't exist
                    &txid,
                    tx_bytes,
                    tx_fee,
                    block_height as u64,
                    &origin_addr,
                    origin_nonce,
                    &sponsor_addr,
                    sponsor_nonce,
                    None,
                )
                .unwrap();

                txids.push(txid);
            }
            mempool_tx.commit().unwrap();

            let ts_1 = get_epoch_time_ms();
            let ms = mempool.make_mempool_sync_data().unwrap();
            let ts_2 = get_epoch_time_ms();
            eprintln!(
                "make_mempool_sync_data({}): {} ms",
                txids.len(),
                ts_2.saturating_sub(ts_1)
            );

            let mut present_count: u32 = 0;
            let mut absent_count: u32 = 0;
            let mut fp_count: u32 = 0;
            match ms {
                MemPoolSyncData::BloomFilter(ref bf) => {
                    eprintln!(
                        "bloomfilter({}); txids.len() == {}",
                        block_height,
                        txids.len()
                    );
                    let recent_txids = mempool.get_bloom_txids().unwrap();
                    assert!(recent_txids.len() <= MAX_BLOOM_COUNTER_TXS as usize);

                    let max_height = MemPoolDB::get_max_coinbase_height(mempool.conn())
                        .unwrap()
                        .unwrap_or(0);
                    eprintln!(
                        "bloomfilter({}): recent_txids.len() == {}, max height is {}",
                        block_height,
                        recent_txids.len(),
                        max_height
                    );

                    let mut recent_set = HashSet::new();
                    let mut in_bf = 0;
                    for txid in recent_txids.iter() {
                        if bf.contains_raw(&txid.0) {
                            in_bf += 1;
                        }
                        recent_set.insert(txid.clone());
                    }

                    eprintln!("in bloom filter: {}", in_bf);
                    assert!(in_bf >= recent_txids.len());

                    for txid in txids.iter() {
                        if !recent_set.contains(txid) && bf.contains_raw(&txid.0) {
                            fp_count += 1;
                        }
                        if bf.contains_raw(&txid.0) {
                            present_count += 1;
                        } else {
                            absent_count += 1;
                        }
                    }

                    // all recent transactions should be present
                    assert!(present_count >= cmp::min(MAX_BLOOM_COUNTER_TXS, txids.len() as u32));
                }
                MemPoolSyncData::TxTags(ref seed, ref tags) => {
                    eprintln!("txtags({}); txids.len() == {}", block_height, txids.len());
                    let recent_txids = mempool.get_bloom_txids().unwrap();

                    // all tags are present in the recent set
                    let mut recent_set = HashSet::new();
                    for txid in recent_txids {
                        recent_set.insert(TxTag::from(seed, &txid));
                    }

                    for tag in tags.iter() {
                        assert!(recent_set.contains(tag));
                    }
                }
            }

            let mut nonrecent_fp_rate = 0.0f64;
            let recent_txids = mempool.get_bloom_txids().unwrap();
            if recent_txids.len() < (present_count + absent_count) as usize {
                nonrecent_fp_rate = (fp_count as f64)
                    / ((present_count + absent_count - (recent_txids.len() as u32)) as f64);
                eprintln!(
                    "Nonrecent false positive rate: {} / ({} + {} - {} = {}) = {}",
                    fp_count,
                    present_count,
                    absent_count,
                    recent_txids.len(),
                    present_count + absent_count - (recent_txids.len() as u32),
                    nonrecent_fp_rate
                );
            }

            let total_count = MemPoolDB::get_num_recent_txs(mempool.conn()).unwrap();
            eprintln!(
                "present_count: {}, absent count: {}, total sent: {}, total recent: {}",
                present_count,
                absent_count,
                txids.len(),
                total_count
            );

            nonrecent_fp_rates.push(nonrecent_fp_rate);
        }
    }

    // average false positive rate for non-recent transactions should be around the bloom
    // counter false positive rate
    let num_nonrecent_fp_samples = nonrecent_fp_rates.len() as f64;
    let avg_nonrecent_fp_rate =
        nonrecent_fp_rates.iter().fold(0.0f64, |acc, x| acc + x) / num_nonrecent_fp_samples;

    assert!((avg_nonrecent_fp_rate - BLOOM_COUNTER_ERROR_RATE).abs() < 0.001);
}

#[test]
fn test_find_next_missing_transactions() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();

    let block_height = 10;
    let mut txids = vec![];

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..(2 * MAX_BLOOM_COUNTER_TXS) {
        let pk = StacksPrivateKey::random();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            block_height,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txids.push(txid);
    }
    mempool_tx.commit().unwrap();

    let mut txid_set = HashSet::new();
    for txid in txids.iter() {
        txid_set.insert(txid.clone());
    }

    eprintln!("Find next missing transactions");

    let txtags = mempool.get_txtags(&[0u8; 32]).unwrap();

    // no txs returned for a full txtag set
    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], txtags.clone()),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            MAX_BLOOM_COUNTER_TXS as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with full txtag set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    assert!(txs.is_empty());
    assert!(next_page_opt.is_some());

    // all txs returned for an empty txtag set
    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], vec![]),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            MAX_BLOOM_COUNTER_TXS as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with empty txtag set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    for tx in txs {
        assert!(txid_set.contains(&tx.txid()));
    }
    assert!(next_page_opt.is_some());

    // all bloom-filter-absent txids should be returned
    let ts_before = get_epoch_time_ms();
    let txid_bloom = mempool.get_txid_bloom_filter().unwrap();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(txid_bloom),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with full bloom filter set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    assert!(txs.is_empty());
    assert!(next_page_opt.is_some());

    let mut empty_bloom_conn = setup_bloom_counter(function_name!());
    let mut empty_tx = tx_begin_immediate(&mut empty_bloom_conn).unwrap();
    let hasher = BloomNodeHasher::new(&[0u8; 32]);
    let empty_bloom = BloomCounter::new(
        &mut empty_tx,
        "bloom_counter",
        BLOOM_COUNTER_ERROR_RATE,
        MAX_BLOOM_COUNTER_TXS,
        hasher,
    )
    .unwrap();
    empty_tx.commit().unwrap();

    let ts_before = get_epoch_time_ms();
    let (txs, next_page_opt, _) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap()),
            block_height,
            &Txid([0u8; 32]),
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    let ts_after = get_epoch_time_ms();
    eprintln!(
        "find_next_missing_transactions with empty bloom filter set took {} ms",
        ts_after.saturating_sub(ts_before)
    );

    for tx in txs {
        assert!(txid_set.contains(&tx.txid()));
    }
    assert!(next_page_opt.is_some());

    // paginated access works too
    let mut last_txid = Txid([0u8; 32]);
    let page_size = 128;
    let mut all_txs = vec![];
    for i in 0..(txtags.len() / (page_size as usize)) + 1 {
        let (mut txs, next_page_opt, num_visited) = mempool
            .find_next_missing_transactions(
                &MemPoolSyncData::TxTags([0u8; 32], vec![]),
                block_height,
                &last_txid,
                (2 * MAX_BLOOM_COUNTER_TXS) as u64,
                page_size,
            )
            .unwrap();
        assert!(txs.len() <= page_size as usize);
        assert!(num_visited <= page_size);

        if txs.is_empty() {
            assert!(next_page_opt.is_none());
            break;
        }

        last_txid = mempool
            .get_randomized_txid(&txs.last().unwrap().txid())
            .unwrap()
            .unwrap();

        assert_eq!(last_txid, next_page_opt.unwrap());
        all_txs.append(&mut txs);
    }

    for tx in all_txs {
        assert!(txid_set.contains(&tx.txid()));
    }

    last_txid = Txid([0u8; 32]);
    all_txs = vec![];
    for i in 0..(txtags.len() / (page_size as usize)) + 1 {
        let ts_before = get_epoch_time_ms();
        let (mut txs, next_page_opt, num_visited) = mempool
            .find_next_missing_transactions(
                &MemPoolSyncData::BloomFilter(
                    empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap(),
                ),
                block_height,
                &last_txid,
                (2 * MAX_BLOOM_COUNTER_TXS) as u64,
                page_size,
            )
            .unwrap();
        let ts_after = get_epoch_time_ms();
        eprintln!("find_next_missing_transactions with empty bloom filter took {} ms to serve {} transactions", ts_after.saturating_sub(ts_before), page_size);

        assert!(txs.len() <= page_size as usize);
        assert!(num_visited <= page_size);

        if txs.is_empty() {
            assert!(next_page_opt.is_none());
            break;
        }

        last_txid = mempool
            .get_randomized_txid(&txs.last().unwrap().txid())
            .unwrap()
            .unwrap();

        assert_eq!(last_txid, next_page_opt.unwrap());
        all_txs.append(&mut txs);
    }

    for tx in all_txs {
        assert!(txid_set.contains(&tx.txid()));
    }

    // old transactions are ignored
    let (old_txs, next_page_opt, num_visited) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::TxTags([0u8; 32], vec![]),
            block_height + (BLOOM_COUNTER_DEPTH as u64) + 1,
            &last_txid,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    assert!(old_txs.is_empty());
    assert!(next_page_opt.is_none());

    let (old_txs, next_page_opt, num_visited) = mempool
        .find_next_missing_transactions(
            &MemPoolSyncData::BloomFilter(empty_bloom.to_bloom_filter(&empty_bloom_conn).unwrap()),
            block_height + (BLOOM_COUNTER_DEPTH as u64) + 1,
            &last_txid,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
            (2 * MAX_BLOOM_COUNTER_TXS) as u64,
        )
        .unwrap();
    assert!(old_txs.is_empty());
    assert!(next_page_opt.is_none());
}

#[test]
fn test_drop_and_blacklist_txs_by_time() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let mut txs = vec![];
    let block_height = 10;

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::random();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txs.push(tx);
    }
    mempool_tx.commit().unwrap();
    let txids: Vec<_> = txs.iter().map(|tx| tx.txid()).collect();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // blacklist some txs
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::inner_blacklist_txs(&mempool_tx, &txids, get_epoch_time_secs()).unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by time
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 1,
        0,
        i64::MAX as u64,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    mempool.drop_and_blacklist_txs(&txids).unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(!mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by time
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 2,
        0,
        i64::MAX as u64,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(!mempool.has_tx(&tx.txid()));
    }
}

#[test]
fn test_drop_and_blacklist_txs_by_size() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let mut txs = vec![];
    let block_height = 10;

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::random();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &ConsensusHash([0x1 + (block_height as u8); 20]),
            &BlockHeaderHash([0x2 + (block_height as u8); 32]),
            false, // don't resolve the above chain tip since it doesn't exist
            &txid,
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {} {}", i, &txid);
        txs.push(tx);
    }
    mempool_tx.commit().unwrap();
    let txids: Vec<_> = txs.iter().map(|tx| tx.txid()).collect();

    for tx in txs.iter() {
        assert!(!mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // blacklist some txs
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::inner_blacklist_txs(&mempool_tx, &txids, get_epoch_time_secs()).unwrap();
    mempool_tx.commit().unwrap();

    for tx in txs.iter() {
        assert!(mempool.is_tx_blacklisted(&tx.txid()).unwrap());
        assert!(mempool.has_tx(&tx.txid()));
    }

    // purge blacklisted txs by size
    let mempool_tx = mempool.tx_begin().unwrap();
    MemPoolDB::garbage_collect_tx_blacklist(
        &mempool_tx,
        get_epoch_time_secs() + 1,
        i64::MAX as u64,
        5,
    )
    .unwrap();
    mempool_tx.commit().unwrap();

    // 5 txs remain blacklisted
    let mut num_blacklisted = 0;
    for tx in txs.iter() {
        if mempool.is_tx_blacklisted(&tx.txid()).unwrap() {
            num_blacklisted += 1;
        }
        assert!(mempool.has_tx(&tx.txid()));
    }

    assert_eq!(num_blacklisted, 5);
}

#[test]
fn test_filter_txs_by_type() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let addr = StacksAddress::new(1, Hash160([0xff; 20])).unwrap();
    let block_height = 10;
    let mut total_len = 0;

    let b_1 = make_block(
        &mut chainstate,
        ConsensusHash([0x1; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        1,
        1,
    );
    let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);

    let mut mempool_tx = mempool.tx_begin().unwrap();
    for i in 0..10 {
        let pk = StacksPrivateKey::random();
        let mut tx = StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                addr.to_account_principal(),
                123,
                TokenTransferMemo([0u8; 34]),
            ),
        };
        tx.set_tx_fee(1000);
        tx.set_origin_nonce(0);

        let txid = tx.txid();
        let tx_bytes = tx.serialize_to_vec();
        let origin_addr = tx.origin_address();
        let origin_nonce = tx.get_origin_nonce();
        let sponsor_addr = tx.sponsor_address().unwrap_or(origin_addr.clone());
        let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
        let tx_fee = tx.get_tx_fee();

        total_len += tx_bytes.len();

        // should succeed
        MemPoolDB::try_add_tx(
            &mut mempool_tx,
            &mut chainstate,
            &b_2.0,
            &b_2.1,
            true,
            &txid,
            tx_bytes,
            tx_fee,
            block_height as u64,
            &origin_addr,
            origin_nonce,
            &sponsor_addr,
            sponsor_nonce,
            None,
        )
        .unwrap();

        eprintln!("Added {i} {txid}");
    }
    mempool_tx.commit().unwrap();

    let mut mempool_settings = MemPoolWalkSettings::default();
    let mut tx_events = Vec::new();
    mempool_settings.txs_to_consider = [
        MemPoolWalkTxTypes::SmartContract,
        MemPoolWalkTxTypes::ContractCall,
    ]
    .into_iter()
    .collect();

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 0);
        },
    );

    // NextNonceWithHighestFeeRate tracks processed txs in the `considered_txs` table.
    // We need to clear this tracking so that the following call can re-consider
    // the previously processed transactions.
    mempool
        .reset_mempool_caches()
        .expect("Should be able to reset nonces");

    mempool_settings.txs_to_consider = [MemPoolWalkTxTypes::TokenTransfer].into_iter().collect();

    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b_2.0, &b_2.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            assert_eq!(count_txs, 10);
        },
    );
}

#[test]
fn large_mempool() {
    let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
    let chainstate_path = chainstate_path(function_name!());
    let mut mempool = MemPoolDB::open_test(false, 0x80000000, &chainstate_path).unwrap();

    let mut senders = (0..1024)
        .map(|_| (StacksPrivateKey::random(), 0))
        .collect::<Vec<_>>();
    let recipient = PrincipalData::from(StacksAddress::burn_address(false));
    let b = make_block(
        &mut chainstate,
        ConsensusHash([0x2; 20]),
        &(
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        ),
        2,
        2,
    );
    let block_height = 10;

    println!("Adding transactions to mempool");
    let mempool_tx = mempool.tx_begin().unwrap();
    for _ in 0..25 {
        for (sender_sk, nonce) in senders.iter_mut() {
            let sender_addr = to_addr(sender_sk);
            let fee = thread_rng().gen_range(180..2000);
            let transfer_tx =
                make_stacks_transfer_serialized(sender_sk, *nonce, fee, 0x80000000, &recipient, 1);
            insert_tx_in_mempool(
                &mempool_tx,
                transfer_tx,
                &sender_addr,
                *nonce,
                fee,
                &ConsensusHash([0x2; 20]),
                &FIRST_STACKS_BLOCK_HASH,
                block_height,
            );
            *nonce += 1;
        }
    }
    mempool_tx.commit().unwrap();

    let mempool_settings = MemPoolWalkSettings {
        strategy: MemPoolWalkStrategy::NextNonceWithHighestFeeRate,
        ..Default::default()
    };
    let mut tx_events = Vec::new();

    println!("Iterating mempool");
    chainstate.with_read_only_clarity_tx(
        &TEST_BURN_STATE_DB,
        &StacksBlockHeader::make_index_block_hash(&b.0, &b.1),
        |clarity_conn| {
            let mut count_txs = 0;
            mempool
                .iterate_candidates::<_, ChainstateError, _>(
                    clarity_conn,
                    &mut tx_events,
                    mempool_settings.clone(),
                    |_, available_tx, _| {
                        count_txs += 1;
                        Ok(Some(
                            // Generate any success result
                            TransactionResult::success(
                                &available_tx.tx.tx,
                                StacksTransactionReceipt::from_stx_transfer(
                                    available_tx.tx.tx.clone(),
                                    vec![],
                                    Value::okay(Value::Bool(true)).unwrap(),
                                    ExecutionCost::ZERO,
                                ),
                            )
                            .convert_to_event(),
                        ))
                    },
                )
                .unwrap();
            // It should be able to iterate through at least 10000 transactions in 5s
            assert!(count_txs > 10000);
        },
    );
}

/// Arrival-order tie-break tests: a chainstate with `b_1`, its child `b_2`, and `b_fork` (a
/// sibling of `b_1`), so transactions can be admitted at `b_1` (or across a fork at `b_fork`) and
/// the mempool walked at `b_2`.
pub(crate) struct ArrivalOrderFixture {
    chainstate: StacksChainState,
    chainstate_path: String,
    b_1: (ConsensusHash, BlockHeaderHash),
    b_2: (ConsensusHash, BlockHeaderHash),
    b_fork: (ConsensusHash, BlockHeaderHash),
}

impl ArrivalOrderFixture {
    pub(crate) fn new(test_name: &str) -> Self {
        let mut chainstate = TestChainstateBuilder::new_testnet(test_name).build();
        let chainstate_path = chainstate_path(test_name);
        let genesis = (
            FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            FIRST_STACKS_BLOCK_HASH.clone(),
        );
        let b_1 = make_block(&mut chainstate, ConsensusHash([0x1; 20]), &genesis, 1, 1);
        let b_2 = make_block(&mut chainstate, ConsensusHash([0x2; 20]), &b_1, 2, 2);
        let b_fork = make_block(&mut chainstate, ConsensusHash([0x3; 20]), &genesis, 1, 1);
        Self {
            chainstate,
            chainstate_path,
            b_1,
            b_2,
            b_fork,
        }
    }

    pub(crate) fn open_mempool(&self, name: &str) -> MemPoolDB {
        MemPoolDB::open_db(
            &format!("{}/{name}.sqlite", &self.chainstate_path),
            Box::new(UnitEstimator),
            Box::new(UnitMetric),
        )
        .unwrap()
    }

    /// Admit `(tx, fee_rate, arrival_seq)` entries at `b_1` in one DB transaction: each with the
    /// stamp it got on receipt, and the fee rate to store.
    pub(crate) fn admit(
        &mut self,
        mempool: &mut MemPoolDB,
        txs: &[(&StacksTransaction, f64, u64)],
    ) -> Result<(), MemPoolRejection> {
        let tip = self.b_1.clone();
        self.admit_at(mempool, &tip, txs)
    }

    /// Like `admit()`, but at `b_fork`
    pub(crate) fn admit_on_fork(
        &mut self,
        mempool: &mut MemPoolDB,
        txs: &[(&StacksTransaction, f64, u64)],
    ) -> Result<(), MemPoolRejection> {
        let tip = self.b_fork.clone();
        self.admit_at(mempool, &tip, txs)
    }

    fn admit_at(
        &mut self,
        mempool: &mut MemPoolDB,
        tip: &(ConsensusHash, BlockHeaderHash),
        txs: &[(&StacksTransaction, f64, u64)],
    ) -> Result<(), MemPoolRejection> {
        let mut mempool_tx = mempool.tx_begin().unwrap();
        for (tx, fee_rate, arrival_seq) in txs {
            let origin_address = tx.origin_address();
            let origin_nonce = tx.get_origin_nonce();
            let sponsor_address = tx.sponsor_address().unwrap_or(origin_address.clone());
            let sponsor_nonce = tx.get_sponsor_nonce().unwrap_or(origin_nonce);
            let txid = tx.txid();
            MemPoolDB::try_add_tx_with_arrival_seq(
                &mut mempool_tx,
                &mut self.chainstate,
                &tip.0,
                &tip.1,
                true,
                &txid,
                tx.serialize_to_vec(),
                tx.get_tx_fee(),
                100,
                &origin_address,
                origin_nonce,
                &sponsor_address,
                sponsor_nonce,
                None,
                *arrival_seq,
            )?;
            mempool_tx
                .execute(
                    "UPDATE mempool SET fee_rate = ? WHERE txid = ?",
                    params![Some(*fee_rate), &txid],
                )
                .unwrap();
        }
        mempool_tx.commit().unwrap();
        Ok(())
    }

    /// Walk the whole mempool at `b_2`, returning txids in the order they were considered
    pub(crate) fn walk(
        &mut self,
        mempool: &mut MemPoolDB,
        strategy: MemPoolWalkStrategy,
    ) -> Vec<Txid> {
        mempool.reset_mempool_caches().unwrap();
        let settings = MemPoolWalkSettings {
            strategy,
            max_walk_time_ms: 600_000,
            ..Default::default()
        };
        let mut considered = vec![];
        let mut tx_events = vec![];
        self.chainstate.with_read_only_clarity_tx(
            &TEST_BURN_STATE_DB,
            &StacksBlockHeader::make_index_block_hash(&self.b_2.0, &self.b_2.1),
            |clarity_conn| {
                mempool
                    .iterate_candidates::<_, ChainstateError, _>(
                        clarity_conn,
                        &mut tx_events,
                        settings,
                        |_, available_tx, _| {
                            considered.push(available_tx.tx.tx.txid());
                            Ok(Some(
                                TransactionResult::success(
                                    &available_tx.tx.tx,
                                    StacksTransactionReceipt::from_stx_transfer(
                                        available_tx.tx.tx.clone(),
                                        vec![],
                                        Value::okay(Value::Bool(true)).unwrap(),
                                        ExecutionCost::ZERO,
                                    ),
                                )
                                .convert_to_event(),
                            ))
                        },
                    )
                    .unwrap()
            },
        );
        considered
    }

    pub(crate) fn arrival_seq(mempool: &MemPoolDB, txid: &Txid) -> u64 {
        MemPoolDB::get_tx(mempool.conn(), txid)
            .unwrap()
            .unwrap()
            .metadata
            .arrival_seq
    }
}

/// An STX transfer with nonce 0 from the key derived from `seed`
pub(crate) fn arrival_order_transfer(seed: u64, fee: u64, amount: u64) -> StacksTransaction {
    let sender = StacksPrivateKey::from_seed(&seed.to_be_bytes());
    let recipient = PrincipalData::from(
        StacksAddress::from_string("ST1RFD5Q2QPK3E0F08HG9XDX7SSC7CNRS0QR0SGEV").unwrap(),
    );
    make_stacks_transfer_tx(&sender, 0, fee, CHAIN_ID_TESTNET, &recipient, amount)
}

#[test]
/// An RBF replacement is stored with its own arrival stamp, so it does not move ahead of a
/// transaction that arrived before it at the same fee rate.
fn mempool_arrival_seq_rbf() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    for strategy in [
        MemPoolWalkStrategy::GlobalFeeRate,
        MemPoolWalkStrategy::NextNonceWithHighestFeeRate,
    ] {
        let mut mempool = fixture.open_mempool(&format!("{strategy:?}"));
        let x = arrival_order_transfer(1, 200, 1);
        let y = arrival_order_transfer(2, 200, 1);
        let x_rbf = arrival_order_transfer(1, 400, 1);
        let (x_seq, y_seq, x_rbf_seq) =
            (next_arrival_seq(), next_arrival_seq(), next_arrival_seq());

        fixture
            .admit(&mut mempool, &[(&x, 100.0, x_seq), (&y, 200.0, y_seq)])
            .unwrap();
        // replace x with a higher fee, matching y's fee rate
        fixture
            .admit(&mut mempool, &[(&x_rbf, 200.0, x_rbf_seq)])
            .unwrap();
        assert!(!mempool.has_tx(&x.txid()));
        assert_eq!(
            ArrivalOrderFixture::arrival_seq(&mempool, &x_rbf.txid()),
            x_rbf_seq
        );

        // y arrived before the replacement
        assert_eq!(
            fixture.walk(&mut mempool, strategy),
            vec![y.txid(), x_rbf.txid()],
            "{strategy:?}"
        );
    }
}

#[test]
/// A transaction re-added across a fork keeps the earlier of its arrival stamps.
fn mempool_arrival_seq_replace_across_fork() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let tx = arrival_order_transfer(1, 200, 1);
    let (earliest, early, late) = (next_arrival_seq(), next_arrival_seq(), next_arrival_seq());

    fixture.admit(&mut mempool, &[(&tx, 200.0, early)]).unwrap();

    // received again later, and re-added on another fork
    fixture
        .admit_on_fork(&mut mempool, &[(&tx, 200.0, late)])
        .unwrap();
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()),
        early
    );

    // a receipt stamped before the stored one, re-added back on the first fork
    fixture
        .admit(&mut mempool, &[(&tx, 200.0, earliest)])
        .unwrap();
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()),
        earliest
    );
}

#[test]
/// Of two conflicting transactions at equal fee, the one received first is kept, whichever was
/// admitted first. A higher fee still wins, whatever the stamps.
fn mempool_arrival_seq_conflict_keeps_earlier_arrival() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let (earlier, later) = (next_arrival_seq(), next_arrival_seq());

    // the later one is admitted first (an RPC upload), then the earlier one (from the relayer)
    let later_tx = arrival_order_transfer(1, 200, 1);
    let earlier_tx = arrival_order_transfer(1, 200, 2);
    fixture
        .admit(&mut mempool, &[(&later_tx, 200.0, later)])
        .unwrap();
    fixture
        .admit(&mut mempool, &[(&earlier_tx, 200.0, earlier)])
        .unwrap();
    assert!(!mempool.has_tx(&later_tx.txid()));
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &earlier_tx.txid()),
        earlier
    );

    // the earlier one is admitted first: the later one is rejected
    let earlier_tx = arrival_order_transfer(2, 200, 1);
    let later_tx = arrival_order_transfer(2, 200, 2);
    fixture
        .admit(&mut mempool, &[(&earlier_tx, 200.0, earlier)])
        .unwrap();
    assert!(matches!(
        fixture.admit(&mut mempool, &[(&later_tx, 200.0, later)]),
        Err(MemPoolRejection::ConflictingNonceInMempool)
    ));
    assert!(mempool.has_tx(&earlier_tx.txid()));

    // a lower fee doesn't replace, even with an earlier stamp; a higher fee does, even with a later
    let stored = arrival_order_transfer(3, 200, 1);
    let lower_fee = arrival_order_transfer(3, 100, 1);
    let higher_fee = arrival_order_transfer(3, 300, 1);
    fixture
        .admit(&mut mempool, &[(&stored, 200.0, later)])
        .unwrap();
    assert!(matches!(
        fixture.admit(&mut mempool, &[(&lower_fee, 100.0, earlier)]),
        Err(MemPoolRejection::ConflictingNonceInMempool)
    ));
    assert!(mempool.has_tx(&stored.txid()));
    let latest = next_arrival_seq();
    fixture
        .admit(&mut mempool, &[(&higher_fee, 300.0, latest)])
        .unwrap();
    assert!(!mempool.has_tx(&stored.txid()));
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &higher_fee.txid()),
        latest
    );
}

#[test]
/// Rows inserted by the test helper get arrival stamps in insertion order, so tests using it don't
/// all tie at the column's default of 0.
fn insert_tx_in_mempool_stamps_rows() {
    let fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let txs: Vec<_> = (0..2)
        .map(|seed| arrival_order_transfer(seed, 200, 1))
        .collect();
    let mempool_tx = mempool.tx_begin().unwrap();
    for tx in txs.iter() {
        insert_tx_in_mempool(
            &mempool_tx,
            tx.serialize_to_vec(),
            &tx.origin_address(),
            0,
            200,
            &ConsensusHash([0x2; 20]),
            &FIRST_STACKS_BLOCK_HASH,
            1,
        );
    }
    mempool_tx.commit().unwrap();
    let stamps = txs
        .iter()
        .map(|tx| ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()));
    assert!(std::iter::once(0).chain(stamps).is_sorted_by(|a, b| a < b));
}

#[test]
/// `note_tx_arrival()` lowers a stored arrival stamp, never raises it, and ignores transactions
/// that are not in the mempool.
fn mempool_arrival_seq_note_tx_arrival() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let tx = arrival_order_transfer(1, 200, 1);
    let (early, stored, late) = (next_arrival_seq(), next_arrival_seq(), next_arrival_seq());
    fixture
        .admit(&mut mempool, &[(&tx, 200.0, stored)])
        .unwrap();

    mempool.note_tx_arrival(&tx.txid(), late).unwrap();
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()),
        stored
    );

    mempool.note_tx_arrival(&tx.txid(), early).unwrap();
    assert_eq!(
        ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()),
        early
    );

    mempool.note_tx_arrival(&Txid([0x11; 32]), 1).unwrap();
}

#[test]
/// Reopening the mempool keeps the stored order and resumes the arrival counter above it.
fn mempool_arrival_seq_restart() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let early = arrival_order_transfer(1, 200, 1);
    // far above anything the other tests in this process can reach
    let early_seq = next_arrival_seq() + (1 << 60);
    fixture
        .admit(&mut mempool, &[(&early, 200.0, early_seq)])
        .unwrap();
    drop(mempool);

    let mut mempool = fixture.open_mempool("mempool");
    let late_seq = next_arrival_seq();
    assert!(late_seq > early_seq);
    let late = arrival_order_transfer(2, 200, 1);
    fixture
        .admit(&mut mempool, &[(&late, 200.0, late_seq)])
        .unwrap();
    for strategy in [
        MemPoolWalkStrategy::GlobalFeeRate,
        MemPoolWalkStrategy::NextNonceWithHighestFeeRate,
    ] {
        assert_eq!(
            fixture.walk(&mut mempool, strategy),
            vec![early.txid(), late.txid()],
            "{strategy:?}"
        );
    }
}

#[test]
/// Migrating a schema-8 mempool backfills `arrival_seq` by accept time, then insertion order,
/// and replaces `by_fee_rate` with the arrival-order indexes.
fn mempool_arrival_seq_migration() {
    let mut fixture = ArrivalOrderFixture::new(function_name!());
    let mut mempool = fixture.open_mempool("mempool");
    let txs: Vec<_> = (0..4)
        .map(|seed| arrival_order_transfer(seed, 200, 1))
        .collect();
    let batch: Vec<_> = txs
        .iter()
        .map(|tx| (tx, 200.0, next_arrival_seq()))
        .collect();
    fixture.admit(&mut mempool, &batch).unwrap();
    for (tx, accept_time) in txs.iter().zip([30, 10, 20, 10]) {
        mempool
            .db
            .execute(
                "UPDATE mempool SET accept_time = ? WHERE txid = ?",
                params![accept_time, tx.txid()],
            )
            .unwrap();
    }

    // strip it back to schema 8
    mempool
        .db
        .execute_batch(
            "DROP INDEX by_fee_rate_arrival_seq;
             DROP INDEX by_arrival_seq;
             ALTER TABLE mempool DROP COLUMN arrival_seq;
             CREATE INDEX by_fee_rate ON mempool(fee_rate);
             DELETE FROM schema_version WHERE version = 9;",
        )
        .unwrap();
    drop(mempool);

    let mempool = fixture.open_mempool("mempool");
    let version: i64 = mempool
        .db
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, 9);

    // accept time first; the two admitted at time 10 in insertion order
    let stamps: Vec<_> = txs
        .iter()
        .map(|tx| ArrivalOrderFixture::arrival_seq(&mempool, &tx.txid()))
        .collect();
    assert_eq!(stamps, vec![4, 1, 3, 2]);

    for (index, expected) in [
        ("by_fee_rate_arrival_seq", 1),
        ("by_arrival_seq", 1),
        ("by_fee_rate", 0),
    ] {
        let found: i64 = mempool
            .db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?",
                params![index],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(found, expected, "index {index}");
    }
}

#[test]
/// The arrival counter resumes above the largest stored stamp. Out-of-range stamps from a damaged
/// mempool are ignored (negative) or saturate (too large) instead of failing the open.
fn mempool_arrival_seq_resume_point() {
    assert_eq!(MemPoolDB::arrival_seq_resume_point(None), None);
    assert_eq!(MemPoolDB::arrival_seq_resume_point(Some(41)), Some(42));
    assert_eq!(MemPoolDB::arrival_seq_resume_point(Some(-1)), None);
    assert_eq!(
        MemPoolDB::arrival_seq_resume_point(Some(i64::MAX - 1)),
        Some(i64::MAX as u64)
    );
    assert_eq!(
        MemPoolDB::arrival_seq_resume_point(Some(i64::MAX)),
        Some(i64::MAX as u64)
    );
}

#[test]
/// Each socket read gets its own block of arrival stamps: what it completes takes them in order,
/// after every stamp taken before the block was reserved and before every stamp taken after it.
/// A block that runs out keeps returning its last stamp.
fn mempool_arrival_seq_blocks() {
    let before = next_arrival_seq();
    let mut block = ArrivalSeqBlock::reserve();
    let first = take_arrival_seq(Some(&mut block));
    assert!(first > before);
    assert_eq!(take_arrival_seq(Some(&mut block)), first + 1);

    let after = take_arrival_seq(None);
    assert!(after >= first + ARRIVAL_SEQ_BLOCK_LEN);

    let mut exhausted = block;
    for _ in 0..ARRIVAL_SEQ_BLOCK_LEN {
        exhausted.take();
    }
    let last = first + ARRIVAL_SEQ_BLOCK_LEN - 1;
    assert_eq!(exhausted.take(), last);
    assert_eq!(exhausted.take(), last);
}
