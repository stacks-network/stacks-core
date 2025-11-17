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

use clarity::vm::types::StacksAddressExtensions;
use clarity::vm::{ClarityName, ContractName};
use proptest::prelude::*;
use rand::seq::SliceRandom;
use rand::thread_rng;
use stacks_common::address::{AddressHashMode, C32_ADDRESS_VERSION_TESTNET_SINGLESIG};
use stacks_common::types::chainstate::{
    StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use stacks_common::types::Address;

use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use crate::chainstate::nakamoto::miner::{MinerTenureInfoCause, NakamotoBlockBuilder};
use crate::chainstate::nakamoto::tests::node::TestStacker;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState};
use crate::chainstate::stacks::db::StacksChainState;
use crate::chainstate::stacks::index::marf::MARFOpenOpts;
use crate::chainstate::stacks::index::storage::TrieHashCalculationMode;
use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::{
    StacksTransaction, StacksTransactionSigner, TransactionAnchorMode, TransactionAuth,
    TransactionContractCall, TransactionPayload, TransactionPostConditionMode,
    TransactionSmartContract, TransactionVersion,
};
use crate::clarity::vm::database::ClarityBackingStore;
use crate::clarity_vm::clarity::ClarityMarfStoreTransaction;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::config::DEFAULT_MAX_TENURE_BYTES;
use crate::net::test::TestEventObserver;
use crate::net::tests::inv::nakamoto::make_nakamoto_peer_from_invs;
use crate::net::tests::{NakamotoBootPlan, NakamotoBootStep, NakamotoBootTenure};
use crate::util_lib::strings::StacksString;

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
        marf.commit_to_processed_block(&final_block_id).unwrap();

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
        // skip opening ::sentinel() since it's not mapped
        if i == 0 {
            continue;
        }
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
        // skip opening ::sentinel() since it's not mapped
        if i == 0 {
            continue;
        }
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
        marf_ephemeral
            .commit_to_processed_block(&final_block_id)
            .unwrap();

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
    let tenure_cause = tenure_change
        .and_then(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(MinerTenureInfoCause::from(tc.cause)),
            _ => Some(MinerTenureInfoCause::NoTenureChange),
        })
        .unwrap_or(MinerTenureInfoCause::NoTenureChange);

    let mut builder = NakamotoBlockBuilder::new(
        &parent_stacks_header,
        &original_block.header.consensus_hash,
        original_block.header.burn_spent,
        tenure_change,
        coinbase,
        original_block.header.pox_treatment.len(),
        None,
        Some(100),
        Some(original_block.header.timestamp),
        u64::from(DEFAULT_MAX_TENURE_BYTES),
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
    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut stacks_node = peer.chain.stacks_node.take().unwrap();
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

/// Test block replay with contract-calls which exercise the clarity DB
#[test]
fn test_ephemeral_nakamoto_block_replay_smart_contract() {
    let test_name = function_name!();
    let observer = TestEventObserver::new();

    let private_key = StacksPrivateKey::from_seed(&[2]);
    let addr = StacksAddress::from_public_keys(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        &AddressHashMode::SerializeP2PKH,
        1,
        &vec![StacksPublicKey::from_private(&private_key)],
    )
    .unwrap();
    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();

    let initial_balances = vec![(addr.to_account_principal(), 1_000_000)];

    let code_body = r#"
(define-constant RECIPIENT 'ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM)
(define-map test-data-map uint uint)
(define-data-var test-var uint u0)
(define-fungible-token stackaroos)
(define-non-fungible-token stacka-nfts uint)
(define-data-var start-height uint stacks-block-height)

(define-private (test-get-burn-block-info? (height uint))
    (begin
        (print (get-burn-block-info? header-hash height))
        (print (get-burn-block-info? pox-addrs height))
        true))

(define-private (test-get-stacks-block-info? (height uint))
    (begin
        (print (get-stacks-block-info? id-header-hash height))
        (print (get-stacks-block-info? header-hash height))
        (print (get-stacks-block-info? time height))
        true))

(define-private (test-get-tenure-info? (height uint))
    (begin
        (print (get-tenure-info? burnchain-header-hash height))
        (print (get-tenure-info? miner-address height))
        (print (get-tenure-info? time height))
        (print (get-tenure-info? vrf-seed height))
        (print (get-tenure-info? block-reward height))
        (print (get-tenure-info? miner-spend-total height))
        (print (get-tenure-info? miner-spend-winner height))
        true))

(define-read-only (test-readonly-map (height uint))
    (begin
        (print (map-get? test-data-map height))
        true))

(define-private (test-map (height uint))
    (begin
        (test-readonly-map height)
        (print (map-set test-data-map (+ u1 height) (+ u1 height)))
        true))

(define-read-only (test-readonly-data-var (height uint))
    (begin
        (print (var-get test-var))
        true))

(define-private (test-data-var (height uint))
    (begin
        (test-readonly-data-var height)
        (print (var-set test-var height))
        true))

(define-read-only (test-readonly-ft (height uint) (user principal))
    (begin
        (print (ft-get-balance stackaroos user))
        (print (ft-get-supply stackaroos))
        true))

(define-private (test-ft (height uint))
    (begin
        (test-readonly-ft height tx-sender)
        (test-readonly-ft height RECIPIENT)
        (print (match (ft-mint? stackaroos height tx-sender) success success failure false))
        (test-readonly-ft height tx-sender)
        (test-readonly-ft height RECIPIENT)
        (print (match (ft-transfer? stackaroos height tx-sender RECIPIENT) success success failure false))
        (test-readonly-ft height tx-sender)
        (test-readonly-ft height RECIPIENT)
        true))

(define-read-only (test-readonly-nft (height uint))
    (begin
        (print (nft-get-owner? stacka-nfts height))
        true))

(define-private (test-nft (height uint))
    (begin
        (print (match (nft-mint? stacka-nfts height tx-sender) success success failure false))
        (test-readonly-nft height)
        (print (match (nft-transfer? stacka-nfts height tx-sender RECIPIENT) success success failure false))
        (test-readonly-nft height)
        true))

(define-read-only (test-readonly-stx-account (user principal))
    (begin
        (print (stx-get-balance user))
        (print (stx-account user))
        true))

(define-private (test-stx-account (height uint))
    (begin
        (test-readonly-stx-account tx-sender)
        (test-readonly-stx-account RECIPIENT)
        (print (match (stx-transfer? height tx-sender RECIPIENT) success success failure false))
        (print (match (stx-transfer-memo? height tx-sender RECIPIENT 0x01) success success failure false))
        (test-readonly-stx-account tx-sender)
        (test-readonly-stx-account RECIPIENT)
        true))

(define-read-only (test-readonly-clarity-db-funcs)
    (let (
        (prev-stacks-block-height (if (> stacks-block-height (var-get start-height)) (- stacks-block-height u1) stacks-block-height))
        (prev-burn-block-height (if (> burn-block-height u0) (- burn-block-height u1) burn-block-height))
    )
    (test-get-burn-block-info? burn-block-height)
    (test-get-burn-block-info? prev-burn-block-height)

    (test-get-stacks-block-info? stacks-block-height)
    (test-get-stacks-block-info? prev-stacks-block-height)

    (test-get-tenure-info? stacks-block-height)
    (test-get-tenure-info? prev-stacks-block-height)
    
    (test-readonly-map stacks-block-height)
    (test-readonly-map prev-stacks-block-height)

    (test-readonly-data-var stacks-block-height)
    (test-readonly-data-var prev-stacks-block-height)

    (test-readonly-ft stacks-block-height tx-sender)
    (test-readonly-ft stacks-block-height RECIPIENT)
    (test-readonly-ft prev-stacks-block-height tx-sender)
    (test-readonly-ft prev-stacks-block-height RECIPIENT)
    
    (test-readonly-nft stacks-block-height)
    (test-readonly-nft prev-stacks-block-height)
    
    (test-readonly-stx-account tx-sender)
    (test-readonly-stx-account RECIPIENT)

    true))

(define-private (test-clarity-db-funcs)
    (let (
        (prev-stacks-block-height (if (> stacks-block-height (var-get start-height)) (- stacks-block-height u1) stacks-block-height))
        (prev-burn-block-height (if (> burn-block-height u0) (- burn-block-height u1) burn-block-height))
    )
    (test-map prev-stacks-block-height)
    (test-map stacks-block-height)

    (test-data-var prev-stacks-block-height)
    (test-data-var stacks-block-height)

    (test-ft stacks-block-height)
    (test-nft stacks-block-height)
    (test-stx-account stacks-block-height)

    true
))

(define-read-only (test-readonly-clarity-db-funcs-at-prev-block)
    (let (
        (prev-block-opt (if (> stacks-block-height (var-get start-height)) (get-stacks-block-info? id-header-hash (- stacks-block-height u1)) none))
    )
    (match prev-block-opt
        prev-block
            (at-block prev-block (test-readonly-clarity-db-funcs))
        true)))

(define-public (test-all)
    (begin
        (test-readonly-clarity-db-funcs)
        (test-clarity-db-funcs)
        (test-readonly-clarity-db-funcs-at-prev-block)
        (ok true)))
"#;

    let contract_deploy = || {
        let smart_contract_payload = TransactionPayload::SmartContract(
            TransactionSmartContract {
                name: ContractName::try_from("test-clarity-db").unwrap(),
                code_body: StacksString::from_str(&code_body).expect("FATAL: invalid code body"),
            },
            None,
        );

        let auth = TransactionAuth::from_p2pkh(&private_key).unwrap();
        let mut smart_contract =
            StacksTransaction::new(TransactionVersion::Testnet, auth, smart_contract_payload);

        smart_contract.chain_id = 0x80000000;
        smart_contract.anchor_mode = TransactionAnchorMode::OnChainOnly;
        smart_contract.post_condition_mode = TransactionPostConditionMode::Allow;
        smart_contract.set_tx_fee(code_body.len() as u64);
        smart_contract.auth.set_origin_nonce(0);

        let mut tx_signer = StacksTransactionSigner::new(&smart_contract);
        tx_signer.sign_origin(&private_key).unwrap();
        let smart_contract_signed = tx_signer.get_tx().unwrap();

        smart_contract_signed
    };

    let mut sender_nonce = 1;
    let mut next_contract_call = || {
        let cc_payload = TransactionPayload::ContractCall(TransactionContractCall {
            address: addr.clone(),
            contract_name: ContractName::try_from("test-clarity-db").unwrap(),
            function_name: ClarityName::try_from("test-all").unwrap(),
            function_args: vec![],
        });

        let auth = TransactionAuth::from_p2pkh(&private_key).unwrap();
        let mut cc = StacksTransaction::new(TransactionVersion::Testnet, auth, cc_payload);

        cc.chain_id = 0x80000000;
        cc.anchor_mode = TransactionAnchorMode::OnChainOnly;
        cc.post_condition_mode = TransactionPostConditionMode::Allow;
        cc.set_tx_fee(1);
        cc.auth.set_origin_nonce(sender_nonce);
        sender_nonce += 1;

        let mut tx_signer = StacksTransactionSigner::new(&cc);
        tx_signer.sign_origin(&private_key).unwrap();
        let cc_signed = tx_signer.get_tx().unwrap();

        cc_signed
    };

    let mut boot_tenures = vec![];

    // deploy
    boot_tenures.push(NakamotoBootTenure::Sortition(vec![
        NakamotoBootStep::Block(vec![contract_deploy(), next_contract_call()]),
        NakamotoBootStep::Block(vec![next_contract_call()]),
        NakamotoBootStep::Block(vec![next_contract_call(), next_contract_call()]),
    ]));

    for i in 1..10 {
        if i % 2 == 1 {
            boot_tenures.push(NakamotoBootTenure::NoSortition(vec![
                NakamotoBootStep::Block(vec![next_contract_call()]),
                NakamotoBootStep::Block(vec![next_contract_call(), next_contract_call()]),
            ]));
        } else {
            boot_tenures.push(NakamotoBootTenure::Sortition(vec![
                NakamotoBootStep::Block(vec![next_contract_call()]),
                NakamotoBootStep::Block(vec![next_contract_call(), next_contract_call()]),
            ]));
        }
    }

    // make malleablized blocks
    let (test_signers, test_stackers) = TestStacker::multi_signing_set(&[
        0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3,
    ]);

    let plan = NakamotoBootPlan::new(test_name)
        .with_private_key(private_key)
        .with_test_signers(test_signers)
        .with_test_stackers(test_stackers)
        .with_pox_constants(10, 5)
        .with_extra_peers(0)
        .with_initial_balances(initial_balances);

    let (mut peer, _other_peers) = plan.boot_into_nakamoto_peers(boot_tenures, Some(&observer));

    // read out all Nakamoto blocks
    let sortdb = peer.chain.sortdb.take().unwrap();
    let mut stacks_node = peer.chain.stacks_node.take().unwrap();
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

    all_nakamoto_blocks
        .sort_by(|blk1, blk2| blk1.header.chain_length.cmp(&blk2.header.chain_length));

    for naka_block in all_nakamoto_blocks {
        replay_block(&sortdb, &mut stacks_node.chainstate, naka_block, &observer);
    }
}

#[test]
fn prop_ephemeral_tip_height_matches_current() {
    proptest!(|(n in 1usize..=12)| {
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

        let target_block_id = StacksBlockId([0xf0; 32]);
        let mut tip = StacksBlockId::sentinel();
        for blk in 0..n {
            let final_block_id = StacksBlockId([(blk as u8) + 1; 32]);
            let mut marf = marfed_kv.begin(&tip, &target_block_id);
            let keys_and_values = vec![(
                format!("key-{}", blk),
                format!("value-{}", blk)
            )];
            marf.put_all_data(keys_and_values).unwrap();
            marf.commit_to_processed_block(&final_block_id).unwrap();
            tip = final_block_id;
        }

        let ephemeral_tip = StacksBlockId([0xee; 32]);
        let mut marf_ephemeral =
            marfed_kv.begin_ephemeral(&tip, &ephemeral_tip).unwrap();

        // Invariant: ephemeral tip height equals current height.
        let height = marf_ephemeral.get_current_block_height();
        let open_height = marf_ephemeral.get_open_chain_tip_height();
        prop_assert_eq!(height, open_height);
    });
}

// Test TODO:
// * stacks 2.x test
