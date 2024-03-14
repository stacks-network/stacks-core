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

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};

use clarity::boot_util::boot_code_addr;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::contracts::Contract;
use clarity::vm::costs::{CostOverflowingMath, LimitedCostTracker};
use clarity::vm::database::*;
use clarity::vm::errors::{
    CheckErrors, Error, IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use clarity::vm::eval;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::tests::{execute, is_committed, is_err_code, symbols_from_values};
use clarity::vm::types::Value::Response;
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    StacksAddressExtensions, StandardPrincipalData, TupleData, TupleTypeSignature, TypeSignature,
    Value, NONE,
};
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::Address;
use stacks_common::util::hash::{hex_bytes, to_hex, Sha256Sum, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use wsts::curve::point::{Compressed, Point};

use super::test::*;
use super::RawRewardSetEntry;
use crate::burnchains::{Burnchain, PoxConstants};
use crate::chainstate::burn::db::sortdb::{self, SortitionDB};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::nakamoto::coordinator::tests::make_token_transfer;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::{TestSigners, TestStacker};
use crate::chainstate::nakamoto::NakamotoBlock;
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::pox_2_tests::{
    check_pox_print_event, generate_pox_clarity_value, get_reward_set_entries_at,
    get_stacking_state_pox, get_stx_account_at, with_clarity_db_ro, PoxPrintFields,
    StackingStateCheckData,
};
use crate::chainstate::stacks::boot::pox_4_tests::{
    assert_latest_was_burn, get_last_block_sender_transactions, get_tip, make_test_epochs_pox,
};
use crate::chainstate::stacks::boot::signers_tests::{get_signer_index, prepare_signers_test};
use crate::chainstate::stacks::boot::{
    BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET, SIGNERS_NAME,
    SIGNERS_VOTING_NAME,
};
use crate::chainstate::stacks::db::{
    MinerPaymentSchedule, StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::tests::make_coinbase;
use crate::chainstate::stacks::*;
use crate::chainstate::{self};
use crate::clarity_vm::clarity::{ClarityBlockConnection, Error as ClarityError};
use crate::clarity_vm::database::marf::{MarfedKV, WritableMarfStore};
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{DBConn, FromRow};

pub fn prepare_pox4_test<'a>(
    test_name: &str,
    observer: Option<&'a TestEventObserver>,
) -> (
    Burnchain,
    TestPeer<'a>,
    Vec<StacksPrivateKey>,
    StacksBlockId,
    u64,
    usize,
) {
    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, test_name, Some(epochs.clone()), observer);

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    let mut latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[3].start_height {
            assert_latest_was_burn(&mut peer);
        }
    }

    let block_height = get_tip(peer.sortdb.as_ref()).block_height;

    info!("Block height: {}", block_height);

    (
        burnchain,
        peer,
        keys,
        latest_block,
        block_height,
        coinbase_nonce,
    )
}

/// In this test case, Alice votes in the first block of the first tenure of the prepare phase.
/// Alice can vote successfully.
/// A second vote on the same key and round fails with "duplicate vote" error
#[test]
fn vote_for_aggregate_public_key_in_first_block() {
    let stacker_1 = TestStacker::from_seed(&[3, 4]);
    let stacker_2 = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    let signer = key_to_stacks_addr(&stacker_1.signer_private_key).to_account_principal();

    let (mut peer, mut test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![(signer, 1000)],
        &[stacker_1.clone(), stacker_2.clone()],
        Some(&observer),
    );

    // create vote txs

    let signer_nonce = 0;
    let signer_key = &stacker_1.signer_private_key;
    let signer_address = key_to_stacks_addr(signer_key);
    let signer_principal = PrincipalData::from(signer_address);
    let cycle_id = current_reward_cycle;

    let signer_index = get_signer_index(&mut peer, latest_block_id, signer_address);

    let aggregate_public_key: Point = Point::new();
    let aggreagte_public_key_value =
        Value::buff_from(aggregate_public_key.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_key,
            signer_nonce,
            signer_index,
            &aggregate_public_key,
            0,
        ),
        // cast the vote twice
        make_signers_vote_for_aggregate_public_key(
            signer_key,
            signer_nonce + 1,
            signer_index,
            &aggregate_public_key,
            0,
        ),
    ];

    //
    // vote in the first burn block of prepare phase
    //
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs], signer_key);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // first vote should succeed
    let tx1 = &receipts[receipts.len() - 2];
    assert_eq!(
        tx1.result,
        Value::Response(ResponseData {
            committed: true,
            data: Box::new(Value::Bool(true))
        })
    );

    // second vote should fail with duplicate vote error
    let tx2 = &receipts[receipts.len() - 1];
    assert_eq!(
        tx2.result,
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::UInt(10006)) // err-duplicate-vote
        })
    );
}

/// In this test case, Alice votes in the first block of the last tenure of the prepare phase.
/// Bob votes in the second block of that tenure.
/// Alice can vote successfully.
/// Bob is out of the voting window.
#[test]
fn vote_for_aggregate_public_key_in_last_block() {
    let stacker_1 = TestStacker::from_seed(&[3, 4]);
    let stacker_2 = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    let signer_1 = key_to_stacks_addr(&stacker_1.signer_private_key).to_account_principal();
    let signer_2 = key_to_stacks_addr(&stacker_2.signer_private_key).to_account_principal();

    let (mut peer, mut test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![(signer_1, 1000), (signer_2, 1000)],
        &[stacker_1.clone(), stacker_2.clone()],
        Some(&observer),
    );

    let mut stacker_1_nonce: u64 = 1;
    let dummy_tx_1 = make_dummy_tx(
        &mut peer,
        &stacker_1.stacker_private_key,
        &mut stacker_1_nonce,
    );
    let dummy_tx_2 = make_dummy_tx(
        &mut peer,
        &stacker_1.stacker_private_key,
        &mut stacker_1_nonce,
    );
    let dummy_tx_3 = make_dummy_tx(
        &mut peer,
        &stacker_1.stacker_private_key,
        &mut stacker_1_nonce,
    );

    let cycle_id: u128 = current_reward_cycle;
    let aggregated_public_key: Point = Point::new();

    // create vote txs for alice
    let signer_1_nonce = 0;
    let signer_1_key = &stacker_1.signer_private_key;
    let signer_1_address = key_to_stacks_addr(signer_1_key);
    let signer_1_principal = PrincipalData::from(signer_1_address);
    let signer_1_index = get_signer_index(&mut peer, latest_block_id, signer_1_address);

    let txs_1 = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_1_key,
            signer_1_nonce,
            signer_1_index,
            &aggregated_public_key,
            0,
        ),
        // cast the vote twice
        make_signers_vote_for_aggregate_public_key(
            signer_1_key,
            signer_1_nonce + 1,
            signer_1_index,
            &aggregated_public_key,
            0,
        ),
    ];

    // create vote txs for bob
    let signer_2_nonce = 0;
    let signer_2_key = &stacker_2.signer_private_key;
    let signer_2_address = key_to_stacks_addr(signer_2_key);
    let signer_2_principal = PrincipalData::from(signer_2_address);
    let signer_2_index = get_signer_index(&mut peer, latest_block_id, signer_2_address);

    let txs_2 = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_2_key,
            signer_2_nonce,
            signer_2_index,
            &aggregated_public_key,
            0,
        ),
    ];

    //
    // vote in the last burn block of prepare phase
    //

    nakamoto_tenure(
        &mut peer,
        &mut test_signers,
        vec![vec![dummy_tx_1]],
        signer_1_key,
    );

    nakamoto_tenure(
        &mut peer,
        &mut test_signers,
        vec![vec![dummy_tx_2]],
        signer_1_key,
    );

    // alice votes in first block of tenure
    // bob votes in second block of tenure
    let blocks_and_sizes = nakamoto_tenure(
        &mut peer,
        &mut test_signers,
        vec![txs_1, txs_2],
        signer_1_key,
    );

    // check alice's and bob's txs
    let blocks = observer.get_blocks();
    // alice's block
    let block = &blocks[blocks.len() - 2].clone();
    let receipts = &block.receipts;
    assert_eq!(receipts.len(), 4);

    // first vote should succeed
    let tx1 = &receipts[receipts.len() - 2];
    assert_eq!(
        tx1.result,
        Value::Response(ResponseData {
            committed: true,
            data: Box::new(Value::Bool(true))
        })
    );

    // second vote should fail with duplicate vote error
    let tx2 = &receipts[receipts.len() - 1];
    assert_eq!(
        tx2.result,
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::UInt(10006)) // err-duplicate-vote
        })
    );

    // bob's block
    let block = blocks.last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 1);

    // vote should succeed
    let tx1 = &receipts[receipts.len() - 1];
    assert_eq!(
        tx1.result,
        Value::Response(ResponseData {
            committed: false,
            data: Box::new(Value::UInt(10002)) // err-out-of-voting-window
        })
    );
}

fn nakamoto_tenure(
    peer: &mut TestPeer,
    test_signers: &mut TestSigners,
    txs_of_blocks: Vec<Vec<StacksTransaction>>,
    stacker_private_key: &StacksPrivateKey,
) -> Vec<(NakamotoBlock, u64, ExecutionCost)> {
    let current_height = peer.get_burnchain_view().unwrap().burn_block_height;

    info!("current height: {}", current_height);

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
    let recipient_addr = boot_code_addr(false);
    let mut mutable_txs_of_blocks = txs_of_blocks.clone();
    mutable_txs_of_blocks.reverse();
    let blocks_and_sizes = peer.make_nakamoto_tenure(
        tenure_change_tx,
        coinbase_tx.clone(),
        test_signers,
        |miner, chainstate, sortdb, blocks| mutable_txs_of_blocks.pop().unwrap_or(vec![]),
    );
    info!("tenure length {}", blocks_and_sizes.len());
    blocks_and_sizes
}

fn make_dummy_tx(
    peer: &mut TestPeer,
    private_key: &StacksPrivateKey,
    nonce: &mut u64,
) -> StacksTransaction {
    peer.with_db_state(|sortdb, chainstate, _, _| {
        let addr = key_to_stacks_addr(&private_key);
        let account = get_account(chainstate, sortdb, &addr);
        let recipient_addr = boot_code_addr(false);
        let stx_transfer = make_token_transfer(
            chainstate,
            sortdb,
            &private_key,
            *nonce,
            1,
            1,
            &recipient_addr,
        );
        *nonce += 1;
        Ok(stx_transfer)
    })
    .unwrap()
}
