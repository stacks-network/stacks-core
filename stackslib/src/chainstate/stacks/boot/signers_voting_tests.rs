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
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    StacksAddressExtensions, StandardPrincipalData, TupleData, TupleTypeSignature, TypeSignature,
    Value, NONE,
};
use stacks_common::address::AddressHashMode;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};
use stacks_common::types::{Address, PrivateKey};
use stacks_common::util::hash::{hex_bytes, to_hex, Sha256Sum, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::Secp256k1PrivateKey;
use wsts::curve::{point::Point, scalar::Scalar};

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

/// In this test case, Alice and Bob both successfully vote for the same key
/// and the key is accepted.
#[test]
fn vote_for_aggregate_public_key_success() {
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    let bob_key = &bob.signer_private_key;
    let bob_address = key_to_stacks_addr(bob_key);
    let bob_principal = PrincipalData::from(bob_address);

    let (mut peer, mut test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![
            (alice_principal.clone(), 1000),
            (bob_principal.clone(), 1000),
        ],
        &[alice.clone(), bob.clone()],
        Some(&observer),
    );

    // Alice and Bob will each have voted once while booting to Nakamoto
    let alice_nonce = 1;
    let bob_nonce = 1;

    let cycle_id = current_reward_cycle;

    // create vote txs
    let alice_index = get_signer_index(&mut peer, latest_block_id, alice_address, cycle_id);
    let bob_index = get_signer_index(&mut peer, latest_block_id, bob_address, cycle_id);

    let aggregate_public_key: Point = Point::new();
    let aggregate_public_key_value =
        Value::buff_from(aggregate_public_key.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            alice_key,
            alice_nonce,
            alice_index,
            &aggregate_public_key,
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            bob_key,
            bob_nonce,
            bob_index,
            &aggregate_public_key,
            0,
            cycle_id + 1,
        ),
    ];

    //
    // vote in the first burn block of prepare phase
    //
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // first vote should succeed
    let alice_vote_tx = &receipts[2];
    assert_eq!(alice_vote_tx.result, Value::okay_true());
    assert_eq!(alice_vote_tx.events.len(), 1);
    let alice_vote_event = &alice_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = alice_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key_value.clone()),
                ("new-total".into(), Value::UInt(1000000000000000000)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(alice_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }

    // second vote should fail with duplicate vote error
    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
    assert_eq!(bob_vote_tx.events.len(), 2);
    let bob_vote_event = &bob_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = bob_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key_value.clone()),
                ("new-total".into(), Value::UInt(2000000000000000000)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    let approve_event = &bob_vote_tx.events[1];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = approve_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes(
                        "approved-aggregate-public-key".as_bytes().to_vec()
                    )
                    .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key_value.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }
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
    let signer_nonce = 1; // Start at 1 because the signer has already voted once
    let signer_key = &stacker_1.signer_private_key;
    let signer_address = key_to_stacks_addr(signer_key);
    let signer_principal = PrincipalData::from(signer_address);
    let cycle_id = current_reward_cycle;

    let signer_index = get_signer_index(&mut peer, latest_block_id, signer_address, cycle_id);

    let aggregate_public_key: Point = Point::new();

    let txs = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_key,
            signer_nonce,
            signer_index,
            &aggregate_public_key,
            0,
            cycle_id + 1,
        ),
        // cast the vote twice
        make_signers_vote_for_aggregate_public_key(
            signer_key,
            signer_nonce + 1,
            signer_index,
            &aggregate_public_key,
            0,
            cycle_id + 1,
        ),
    ];

    //
    // vote in the first burn block of prepare phase
    //
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // first vote should succeed
    let alice_first_vote_tx = &receipts[2];
    assert_eq!(alice_first_vote_tx.result, Value::okay_true());

    // second vote should fail with duplicate vote error
    let alice_second_vote_tx = &receipts[3];
    assert_eq!(
        alice_second_vote_tx.result,
        Value::err_uint(7) // err-duplicate-vote
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
    let aggregate_public_key_1 = Point::from(Scalar::from(1));
    let aggregate_public_key_2 = Point::from(Scalar::from(2));

    // create vote txs for alice
    let signer_1_nonce = 1; // Start at 1 because the signer has already voted once
    let signer_1_key = &stacker_1.signer_private_key;
    let signer_1_address = key_to_stacks_addr(signer_1_key);
    let signer_1_principal = PrincipalData::from(signer_1_address);
    let signer_1_index = get_signer_index(&mut peer, latest_block_id, signer_1_address, cycle_id);

    let txs_block_1 = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_1_key,
            signer_1_nonce,
            signer_1_index,
            &aggregate_public_key_1,
            1,
            cycle_id + 1,
        ),
        // cast the vote twice
        make_signers_vote_for_aggregate_public_key(
            signer_1_key,
            signer_1_nonce + 1,
            signer_1_index,
            &aggregate_public_key_1,
            1,
            cycle_id + 1,
        ),
        // cast a vote for old round
        make_signers_vote_for_aggregate_public_key(
            signer_1_key,
            signer_1_nonce + 2,
            signer_1_index,
            &aggregate_public_key_2,
            0,
            cycle_id + 1,
        ),
    ];

    // create vote txs for bob
    let signer_2_nonce = 1; // Start at 1 because the signer has already voted once
    let signer_2_key = &stacker_2.signer_private_key;
    let signer_2_address = key_to_stacks_addr(signer_2_key);
    let signer_2_principal = PrincipalData::from(signer_2_address);
    let signer_2_index = get_signer_index(&mut peer, latest_block_id, signer_2_address, cycle_id);

    let txs_block_2 = vec![
        // cast a vote for the aggregate public key
        make_signers_vote_for_aggregate_public_key(
            signer_2_key,
            signer_2_nonce,
            signer_2_index,
            &aggregate_public_key_1,
            0,
            cycle_id + 1,
        ),
    ];

    //
    // vote in the last burn block of prepare phase
    //

    nakamoto_tenure(&mut peer, &mut test_signers, vec![vec![dummy_tx_1]]);

    nakamoto_tenure(&mut peer, &mut test_signers, vec![vec![dummy_tx_2]]);

    // alice votes in first block of tenure
    // bob votes in second block of tenure
    let blocks_and_sizes =
        nakamoto_tenure(&mut peer, &mut test_signers, vec![txs_block_1, txs_block_2]);

    // check alice's and bob's txs
    let blocks = observer.get_blocks();
    // alice's block
    let block = &blocks[blocks.len() - 2].clone();
    let receipts = &block.receipts;
    assert_eq!(receipts.len(), 5);

    // first vote should succeed
    let alice_first_vote_tx = &receipts[2];
    assert_eq!(alice_first_vote_tx.result, Value::okay_true());

    // second vote should fail with duplicate vote error
    let alice_second_vote_tx = &receipts[3];
    assert_eq!(
        alice_second_vote_tx.result,
        Value::err_uint(7) // err-duplicate-vote
    );

    // third vote should succeed even though it is on an old round
    let alice_third_vote_tx = &receipts[4];
    assert_eq!(alice_third_vote_tx.result, Value::okay_true());

    // bob's block
    let block = blocks.last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 1);

    // vote fails because the reward cycle has changed
    //  and the signer set hasn't been set yet.
    let tx1_bob = &receipts[0];
    assert_eq!(
        tx1_bob.result,
        Value::err_uint(2) // err-out-of-voting-window
    );
}

fn nakamoto_tenure(
    peer: &mut TestPeer,
    test_signers: &mut TestSigners,
    txs_of_blocks: Vec<Vec<StacksTransaction>>,
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
