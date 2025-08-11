// Copyright (C) 2025 Stacks Open Internet Foundation
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

use std::fs;

use clarity::vm::ast::ASTRules;
use rand::seq::SliceRandom;
use rand::thread_rng;
use stacks_common::types::chainstate::StacksBlockId;

use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::{MARFOpenOpts, MARF};
use crate::chainstate::stacks::index::storage::{TrieFileStorage, TrieHashCalculationMode};
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::TransactionPayload;
use crate::clarity::vm::database::ClarityBackingStore;
use crate::clarity_vm::database::marf::{MarfedKV, WritableMarfStore};
use crate::net::test::{TestEventObserver, TestPeer};
use crate::net::tests::inv::nakamoto::make_nakamoto_peer_from_invs;
use crate::net::tests::NakamotoBootPlan;

/// Verify that an ephemeral MARF can be created off of an already-written block of an on-disk
/// MARF.
/// * Verify that keys inserted into the ephemeral MARF land in the RAM-backed MARF
/// * Verify that the ephemeral MARF store can read all keys inserted into the RAM-backed MARF, as
/// well as all keys in the disk-backed MARF.
/// * Verify that discarding the ephemeral MARF store leaves the disk-backed MARF unaltered (no new
/// keys)
#[test]
fn test_ephemeral_marf_store() {
    let path = format!("/tmp/{}.marf", function_name!());
    if fs::metadata(&path).is_ok() {
        fs::remove_dir_all(&path).unwrap();
    }

    let mut marfed_kv = MarfedKV::open(
        &path,
        None,
        Some(MARFOpenOpts::new(
            TrieHashCalculationMode::Deferred,
            "noop",
            false,
        )),
    )
    .unwrap();

    // insert some key/value pairs into the disk-backed MARF
    let mut blocks = vec![StacksBlockId::sentinel()];
    let mut block_data = vec![vec![]];

    for blk in 0..10 {
        let final_block_id = StacksBlockId([blk as u8; 32]);
        let target_block_id = StacksBlockId([0xf0; 32]);
        let mut keys_and_values = vec![];
        for k in 0..10 {
            let key = format!("key-{}", blk * 10 + k);
            let value = format!("value-{}", blk * 10 + k);
            keys_and_values.push((key, value));
        }
        let mut marf = marfed_kv.begin(blocks.last().as_ref().unwrap(), &target_block_id);
        marf.put_all_data(keys_and_values.clone()).unwrap();
        marf.commit_to(&final_block_id).unwrap();

        blocks.push(final_block_id);
        block_data.push(keys_and_values);
    }

    // verify all keys are present at the right chain tips
    for (i, block_id) in blocks.iter().enumerate() {
        debug!("readonly: open block #{}: {}", i, block_id);
        let mut marf_ro = marfed_kv.begin_read_only(Some(block_id));
        for j in 0..=i {
            // all values up to those inserted in the block with this ID are present
            let keys_and_values = &block_data[j];
            for (key, expected_value) in keys_and_values.iter() {
                let value = marf_ro.get_data(key).unwrap().unwrap();
                assert_eq!(expected_value, &value);
                debug!(
                    "readonly: at block #{} {}: {} == {}",
                    i, block_id, key, &value
                );
            }
        }
        for j in i + 1..blocks.len() {
            // all values afterwards are not present
            let keys_and_values = &block_data[j];
            for (key, _) in keys_and_values.iter() {
                assert!(marf_ro.get_data(key).unwrap().is_none());
                debug!("readonly: at block #{} {}: {} not mapped", i, block_id, key);
            }
        }
    }

    // verify that we can read all keys with an ephemeral MARF opened to each block_id as its
    // base_tip
    for (i, block_id) in blocks.iter().enumerate() {
        debug!("ephemeral: open block #{}: {}", i, block_id);
        let ephemeral_tip = StacksBlockId([0xf0; 32]);
        let mut marf_ephemeral = marfed_kv
            .begin_ephemeral(&block_id, &ephemeral_tip)
            .unwrap();
        for j in 0..=i {
            // all values up to those inserted in the block with this ID are present
            let keys_and_values = &block_data[j];
            for (key, expected_value) in keys_and_values.iter() {
                let value = marf_ephemeral.get_data(key).unwrap().unwrap();
                assert_eq!(expected_value, &value);
                debug!(
                    "ephemeral: at block #{} {}: {} == {}",
                    i, block_id, key, &value
                );
            }
        }
        for j in i + 1..blocks.len() {
            // all values afterwards are not present
            let keys_and_values = &block_data[j];
            for (key, _) in keys_and_values.iter() {
                assert!(marf_ephemeral.get_data(key).unwrap().is_none());
                debug!(
                    "ephemeral: at block #{} {}: {} not mapped",
                    i, block_id, key
                );
            }
        }
    }

    // create one block at each base_tip and add ephemeral key/value pairs to it.
    // verify that we can read them back as long as the ephemeral tx is open, and
    // verify that we can read all other keys.
    // verify that the ephemeral data is dropped along with the ephemeral tx
    for (i, block_id) in blocks.iter().enumerate() {
        let ephemeral_tip = StacksBlockId([0xf0; 32]);
        let final_block_id = StacksBlockId([i as u8; 32]);

        let mut keys_and_values = vec![];
        for k in 0..10 {
            let key = format!("ephemeral-key-{}", i * 10 + k);
            let value = format!("ephemeral-value-{}", i * 10 + k);
            keys_and_values.push((key, value));
        }
        debug!(
            "ephemeral: open block #{}: {} --> {}",
            i, block_id, &ephemeral_tip
        );
        let mut marf_ephemeral = marfed_kv
            .begin_ephemeral(&block_id, &ephemeral_tip)
            .unwrap();
        marf_ephemeral
            .put_all_data(keys_and_values.clone())
            .unwrap();

        // can read back all ephemeral data
        for (key, expected_value) in keys_and_values.iter() {
            let value = marf_ephemeral.get_data(key).unwrap().unwrap();
            assert_eq!(expected_value, &value);
            debug!(
                "ephemeral: at block #{}: {} --> {}: {} == {}",
                i, block_id, &ephemeral_tip, key, &value
            );
        }

        // can read back all disk-backed data represented up to the base_tip
        for j in 0..=i {
            // all values up to those inserted in the block with this ID are present
            let keys_and_values = &block_data[j];
            for (key, expected_value) in keys_and_values.iter() {
                let value = marf_ephemeral.get_data(key).unwrap().unwrap();
                assert_eq!(expected_value, &value);
                debug!(
                    "ephemeral: at block #{} {} --> {}: {} == {}",
                    i, block_id, &ephemeral_tip, key, &value
                );
            }
        }

        // cannot read data beyond the base tip
        for j in i + 1..blocks.len() {
            // all values afterwards are not present
            let keys_and_values = &block_data[j];
            for (key, _) in keys_and_values.iter() {
                assert!(marf_ephemeral.get_data(key).unwrap().is_none());
                debug!(
                    "ephemeral: at block #{} {} --> {}: {} not mapped",
                    i, block_id, &ephemeral_tip, key
                );
            }
        }

        // can read all ephemeral values and all disk-backed values up to base_tip in random order
        let mut all_keys_and_values: Vec<(String, String)> = block_data[0..=i]
            .iter()
            .map(|keys_and_values| keys_and_values.clone())
            .flatten()
            .collect();

        all_keys_and_values.append(&mut keys_and_values.clone());
        all_keys_and_values.shuffle(&mut thread_rng());
        for (key, expected_value) in all_keys_and_values.iter() {
            let value = marf_ephemeral.get_data(key).unwrap().unwrap();
            assert_eq!(expected_value, &value);
            debug!(
                "ephemeral: at block #{} {} --> {} (random): {} == {}",
                i, block_id, &ephemeral_tip, key, &value
            );
        }

        // "commit" the data
        marf_ephemeral.commit_to(&final_block_id).unwrap();

        // data is _not_ persisted
        let mut marf_ephemeral = marfed_kv
            .begin_ephemeral(&block_id, &ephemeral_tip)
            .unwrap();
        for (key, _) in keys_and_values.iter() {
            assert!(marf_ephemeral.get_data(key).unwrap().is_none());
            debug!(
                "ephemeral: at block #{}: {} --> {} post-commit: {} not mapped after commit",
                i, block_id, &ephemeral_tip, key
            );
        }

        // can still read back all disk-backed data represented up to the base_tip
        for j in 0..=i {
            // all values up to those inserted in the block with this ID are present
            let keys_and_values = &block_data[j];
            for (key, expected_value) in keys_and_values.iter() {
                let value = marf_ephemeral.get_data(key).unwrap().unwrap();
                assert_eq!(expected_value, &value);
                debug!(
                    "ephemeral: at block #{} {} --> {} post-commit: {} == {}",
                    i, block_id, &ephemeral_tip, key, &value
                );
            }
        }

        // cannot still read data beyond the base tip
        for j in i + 1..blocks.len() {
            // all values afterwards are not present
            let keys_and_values = &block_data[j];
            for (key, _) in keys_and_values.iter() {
                assert!(marf_ephemeral.get_data(key).unwrap().is_none());
                debug!(
                    "ephemeral: at block #{} {} --> {} post-commit: {} not mapped",
                    i, block_id, &ephemeral_tip, key
                );
            }
        }
    }
}

fn replay_block(
    sortdb: &SortitionDB,
    chainstate: &mut StacksChainState,
    original_block: NakamotoBlock,
    observer: &TestEventObserver,
) {
    test_debug!(
        "Replay block {} (id {}) ephemerally: {:?}",
        &original_block.header.block_hash(),
        &original_block.header.block_id(),
        &original_block
    );
    // open sortition view to the current burn view.
    // If the block has a TenureChange with an Extend cause, then the burn view is whatever is
    // indicated in the TenureChange.
    // Otherwise, it's the same as the block's parent's burn view.
    let parent_stacks_header = NakamotoChainState::get_block_header(
        chainstate.db(),
        &original_block.header.parent_block_id,
    )
    .expect("FATAL: failed to find parent stacks header")
    .expect("FATAL: no parent found");

    let burn_view_consensus_hash =
        NakamotoChainState::get_block_burn_view(sortdb, &original_block, &parent_stacks_header)
            .expect("FATAL: could not get burn block view");

    let sort_tip =
        SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &burn_view_consensus_hash)
            .expect("FATAL: could not load block snapshot")
            .expect("FATAL: no such snapshot for burn view");

    let burn_dbconn: SortitionHandleConn = sortdb.index_handle(&sort_tip.sortition_id);

    let tenure_change = original_block
        .txs
        .iter()
        .find(|tx| matches!(tx.payload, TransactionPayload::TenureChange(..)));
    let coinbase = original_block
        .txs
        .iter()
        .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)));
    let tenure_cause = tenure_change.and_then(|tx| match &tx.payload {
        TransactionPayload::TenureChange(tc) => Some(tc.cause),
        _ => None,
    });
    let mut builder = NakamotoBlockBuilder::new(
        &parent_stacks_header,
        &original_block.header.consensus_hash,
        original_block.header.burn_spent,
        tenure_change,
        coinbase,
        original_block.header.pox_treatment.len(),
        None,
    )
    .unwrap();

    let mut miner_tenure_info = builder
        .load_ephemeral_tenure_info(chainstate, &burn_dbconn, tenure_cause)
        .unwrap();
    let burn_chain_height = miner_tenure_info.burn_tip_height;
    let mut tenure_tx = builder
        .tenure_begin(&burn_dbconn, &mut miner_tenure_info)
        .unwrap();

    let mut receipts = vec![];

    for (i, tx) in original_block.txs.iter().enumerate() {
        let tx_len = tx.tx_len();

        let tx_result = builder.try_mine_tx_with_len(
            &mut tenure_tx,
            tx,
            tx_len,
            &BlockLimitFunction::NO_LIMIT_HIT,
            ASTRules::PrecheckSize,
            None,
        );
        let err = match &tx_result {
            TransactionResult::Success(_) => Ok(()),
            TransactionResult::Skipped(ref s) => Err(format!("tx {i} skipped: {}", &s.error)),
            TransactionResult::ProcessingError(e) => {
                Err(format!("Error processing tx {i}: {}", &e.error))
            }
            TransactionResult::Problematic(ref p) => {
                Err(format!("Problematic tx {i}: {}", &p.error))
            }
        };
        if let Err(reason) = err {
            error!(
                "Failed to replay block";
                "reason" => %reason,
                "tx" => ?tx,
            );
            panic!();
        }
        let mut receipt = tx_result.unwrap().1;
        receipt.tx_index = i as u32;
        receipts.push(receipt);
    }

    let _block = builder.mine_nakamoto_block(&mut tenure_tx, burn_chain_height);

    // NOTE: the block hash (state root hash) will be *different* from what was originally computed.
    // This is okay, however, since this API is only meant for extracting block receipts. So, as
    // long as all Clarity code in the ephemeral MARF behaves the same, then it's fine that the
    // state root hash (which is not visible in Clarity) never matches.

    let observed_blocks = observer.get_blocks();
    let mut found = false;
    for block in observed_blocks {
        if block.metadata.index_block_hash() == original_block.header.block_id() {
            assert_eq!(block.receipts, receipts);
            found = true;
        }
    }
    assert!(found);
}

/// Verify that we can replay nakamoto blocks and get the same block hash (including state root
/// hash).
///
/// Note that this does not fully test this behavior -- specifically, all of the blocks will
/// contain only STX transfers. There are no smart contact or contract-call blocks, and thus no
/// exercizing of Clarity DB functions.
#[test]
fn test_ephemeral_nakamoto_block_replay_simple() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let mut peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
    );

    // read out all Nakamoto blocks
    let sortdb = peer.sortdb.take().unwrap();
    let mut stacks_node = peer.stacks_node.take().unwrap();
    let naka_tip =
        NakamotoChainState::get_canonical_block_header(stacks_node.chainstate.db(), &sortdb)
            .unwrap()
            .unwrap();
    let tip_id = naka_tip.index_block_hash();

    let sortitions = SortitionDB::get_all_snapshots(&sortdb).unwrap();
    let mut all_nakamoto_blocks = vec![];

    for sort in sortitions {
        let nakamoto_db = stacks_node.chainstate.nakamoto_blocks_db();
        let mut nakamoto_blocks = nakamoto_db
            .get_all_blocks_in_tenure(&sort.consensus_hash, &tip_id)
            .unwrap();
        all_nakamoto_blocks.append(&mut nakamoto_blocks);
    }

    for naka_block in all_nakamoto_blocks {
        replay_block(&sortdb, &mut stacks_node.chainstate, naka_block, &observer);
    }
}

// Test TODO:
// * nakamoto boot plan with Clarity smart contracts which exercise the Clarity DB thoroghly 
// * stacks 2.x test
