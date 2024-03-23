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
use wsts::curve::point::Point;
use wsts::curve::scalar::Scalar;

use super::test::*;
use super::RawRewardSetEntry;
use crate::burnchains::{Burnchain, PoxConstants};
use crate::chainstate::burn::db::sortdb::{self, SortitionDB};
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::nakamoto::coordinator::tests::make_token_transfer;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::tests::get_account;
use crate::chainstate::nakamoto::tests::node::TestStacker;
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
use crate::chainstate::stacks::boot::signers_tests::{
    get_signer_index, prepare_signers_test, readonly_call,
};
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

/// In this test case, Alice & Bob both successfully vote for the same key.
/// Alice votes successfully, then Bob votes successfully, reaching the
/// threshold and setting the aggregate public key.
#[test]
fn vote_for_aggregate_public_key_success() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_key = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key = Value::buff_from(aggregate_key.compress().data.to_vec())
        .expect("Failed to serialize aggregate public key");

    let aggregate_public_key_ill_formed = Value::buff_from_byte(0x00);

    let txs = vec![
        // Alice casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key.clone(),
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

    // Alice's vote should succeed
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
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

    // Bob's vote should succeed and reach the threshold, setting the aggregate public key
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(4)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
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
                ("key".into(), aggregate_public_key.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }
}

/// In this test case, Alice & Bob both successfully vote for the same key,
/// but also trigger all tenure-agnostic errors.
#[test]
fn vote_for_aggregate_public_key_with_errors() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_key = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key = Value::buff_from(aggregate_key.compress().data.to_vec())
        .expect("Failed to serialize aggregate public key");

    let aggregate_public_key_ill_formed = Value::buff_from_byte(0x00);

    let txs = vec![
        // Alice casts a vote with a non-existant index - should return signer index mismatch error
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Alice casts a vote with Bobs index - should return invalid signer index error
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 1,
            2,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Alice casts a vote with an invalid public key - should return ill-formed public key error
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 2,
            alice_index,
            aggregate_public_key_ill_formed,
            0,
            cycle_id + 1,
        ),
        // Alice casts a vote with an incorrect reward cycle - should return cycle not set error
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 3,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 2,
        ),
        // Alice casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 4,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Alice casts vote twice - should return duplicate vote error
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 5,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote with the wrong round - should return an invalid round error
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key.clone(),
            2,
            cycle_id + 1,
        ),
        // Bob casts a vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 1,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
    ];

    //
    // vote in the first burn block of prepare phase
    //
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last eight txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 10);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // Alice's first vote should fail (signer mismatch)
    let alice_first_vote_tx = &receipts[2];
    let alice_first_vote_tx_result = alice_first_vote_tx.result.clone();
    assert_eq!(
        alice_first_vote_tx_result,
        Value::err_uint(10) // ERR_SIGNER_INDEX_MISMATCH
    );
    assert_eq!(alice_first_vote_tx.events.len(), 0);

    // Alice's second vote should fail (invalid signer)
    let alice_second_vote_tx = &receipts[3];
    let alice_second_vote_tx_result = alice_second_vote_tx.result.clone();
    assert_eq!(
        alice_second_vote_tx_result,
        Value::err_uint(11) // ERR_INVALID_SIGNER_INDEX
    );
    assert_eq!(alice_second_vote_tx.events.len(), 0);

    // Alice's third vote should fail (ill formed aggregate public key)
    let alice_third_vote_tx = &receipts[4];
    let alice_third_vote_tx_result = alice_third_vote_tx.result.clone();
    assert_eq!(
        alice_third_vote_tx_result,
        Value::err_uint(13) // ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY
    );
    assert_eq!(alice_third_vote_tx.events.len(), 0);

    // Alice's fourth vote should fail (cycle not set)
    let alice_fourth_vote_tx = &receipts[5];
    let alice_fourth_vote_tx_result = alice_fourth_vote_tx.result.clone();
    assert_eq!(
        alice_fourth_vote_tx_result,
        Value::err_uint(2) // ERR_CYCLE_NOT_SET
    );
    assert_eq!(alice_fourth_vote_tx.events.len(), 0);

    // Alice's fifth  vote, correct vote should succeed
    let alice_fifth_vote_tx = &receipts[6];
    assert_eq!(alice_fifth_vote_tx.result, Value::okay_true());
    assert_eq!(alice_fifth_vote_tx.events.len(), 1);
    let alice_vote_event = &alice_fifth_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = alice_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
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

    // Alice's sixth vote should fail (duplicate vote)
    let alice_sixth_vote_tx = &receipts[7];
    let alice_sixth_vote_tx_result = alice_sixth_vote_tx.result.clone();
    assert_eq!(
        alice_sixth_vote_tx_result,
        Value::err_uint(15) // ERR_DUPLICATE_VOTE
    );
    assert_eq!(alice_sixth_vote_tx.events.len(), 0);

    // Bob's first vote should fail (invalid round)
    let bob_first_vote_tx = &receipts[8];
    let bob_first_vote_tx_result = bob_first_vote_tx.result.clone();
    assert_eq!(
        bob_first_vote_tx_result,
        Value::err_uint(17) // ERR_INVALID_ROUND
    );
    assert_eq!(bob_first_vote_tx.events.len(), 0);

    // Bob's second vote should succeed and reach the threshold, setting the aggregate public key
    let bob_second_vote_tx = &receipts[9];
    assert_eq!(bob_second_vote_tx.result, Value::okay_true());
    assert_eq!(bob_second_vote_tx.events.len(), 2);
    let bob_vote_event = &bob_second_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = bob_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(4)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }
    let approve_event = &bob_second_vote_tx.events[1];
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
                ("key".into(), aggregate_public_key.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }
}

/// 4 stackers vote for the same aggregate public key. The threshold is reached
/// after the 3rd vote, so the 4th gets an "out of voting window" error.
#[test]
fn vote_for_aggregate_public_key_out_of_window() {
    // Test setup
    let stacker1 = TestStacker::from_seed(&[3, 4]);
    let stacker2 = TestStacker::from_seed(&[5, 6]);
    let stacker3 = TestStacker::from_seed(&[7, 8]);
    let stacker4 = TestStacker::from_seed(&[9, 10]);
    let observer = TestEventObserver::new();

    // Signer 1
    let stacker1_key = &stacker1.signer_private_key;
    let stacker1_address = key_to_stacks_addr(stacker1_key);
    let stacker1_principal = PrincipalData::from(stacker1_address);

    // Signer 2
    let stacker2_key = &stacker2.signer_private_key;
    let stacker2_address = key_to_stacks_addr(stacker2_key);
    let stacker2_principal = PrincipalData::from(stacker2_address);

    // Signer 3
    let stacker3_key = &stacker3.signer_private_key;
    let stacker3_address = key_to_stacks_addr(stacker3_key);
    let stacker3_principal = PrincipalData::from(stacker3_address);

    // Signer 4
    let stacker4_key = &stacker4.signer_private_key;
    let stacker4_address = key_to_stacks_addr(stacker4_key);
    let stacker4_principal = PrincipalData::from(stacker4_address);

    let (mut peer, mut test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![
            (stacker1_principal.clone(), 1000),
            (stacker2_principal.clone(), 1000),
            (stacker3_principal.clone(), 1000),
            (stacker4_principal.clone(), 1000),
        ],
        &[
            stacker1.clone(),
            stacker2.clone(),
            stacker3.clone(),
            stacker4.clone(),
        ],
        Some(&observer),
    );

    // Stackers will each have voted once while booting to Nakamoto
    let stacker1_nonce = 1;
    let stacker2_nonce = 1;
    let stacker3_nonce = 1;
    let stacker4_nonce = 1;

    let cycle_id = current_reward_cycle;

    // create vote txs
    let stacker1_index = get_signer_index(&mut peer, latest_block_id, stacker1_address, cycle_id);
    let stacker2_index = get_signer_index(&mut peer, latest_block_id, stacker2_address, cycle_id);
    let stacker3_index = get_signer_index(&mut peer, latest_block_id, stacker3_address, cycle_id);
    let stacker4_index = get_signer_index(&mut peer, latest_block_id, stacker4_address, cycle_id);

    let mut signers = TestSigners::default();
    let aggregate_key = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key = Value::buff_from(aggregate_key.compress().data.to_vec())
        .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // stacker1 casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            stacker1_key,
            stacker1_nonce,
            stacker1_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // stacker2 casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            stacker2_key,
            stacker2_nonce,
            stacker2_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // stacker3 casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            stacker3_key,
            stacker3_nonce,
            stacker3_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // stacker4 casts vote correctly, but it will return an out of voting window error
        make_signers_vote_for_aggregate_public_key_value(
            stacker4_key,
            stacker4_nonce,
            stacker4_index,
            aggregate_public_key.clone(),
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
    assert_eq!(receipts.len(), 6);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // stacker1's vote should succeed
    let stacker1_vote_tx = &receipts[2];
    assert_eq!(stacker1_vote_tx.result, Value::okay_true());
    assert_eq!(stacker1_vote_tx.events.len(), 1);
    let stacker1_vote_event = &stacker1_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = stacker1_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(1)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                (
                    "signer".into(),
                    Value::Principal(stacker1_principal.clone())
                ),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", stacker1_vote_event);
    }

    // stacker2's vote should succeed
    let stacker2_vote_tx = &receipts[3];
    assert_eq!(stacker2_vote_tx.result, Value::okay_true());
    assert_eq!(stacker2_vote_tx.events.len(), 1);
    let stacker2_vote_event = &stacker2_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = stacker2_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                (
                    "signer".into(),
                    Value::Principal(stacker2_principal.clone())
                ),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", stacker2_vote_event);
    }

    // stacker3's vote should succeed
    let stacker3_vote_tx = &receipts[4];
    assert_eq!(stacker3_vote_tx.result, Value::okay_true());
    assert_eq!(stacker3_vote_tx.events.len(), 2);
    let stacker3_vote_event = &stacker3_vote_tx.events[0];
    if let StacksTransactionEvent::SmartContractEvent(contract_event) = stacker3_vote_event {
        assert_eq!(
            contract_event.value,
            TupleData::from_data(vec![
                (
                    "event".into(),
                    Value::string_ascii_from_bytes("voted".as_bytes().to_vec())
                        .expect("Failed to create string")
                ),
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(3)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
                (
                    "signer".into(),
                    Value::Principal(stacker3_principal.clone())
                ),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", stacker3_vote_event);
    }
    let approve_event = &stacker3_vote_tx.events[1];
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
                ("key".into(), aggregate_public_key.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }

    // stacker4's vote should get an out of voting window error
    let stacker4_vote_tx = &receipts[5];
    assert_eq!(
        stacker4_vote_tx.result,
        Value::err_uint(12) // ERR_OUT_OF_VOTING_WINDOW
    );
    assert_eq!(stacker4_vote_tx.events.len(), 0);
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

    let mut signers = TestSigners::default();
    let aggregate_public_key = signers.generate_aggregate_key(cycle_id as u64 + 1);

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
        Value::err_uint(15) // ERR_DUPLICATE_VOTE
    );
    assert_eq!(alice_second_vote_tx.events.len(), 0);
}

/// In this test case, Alice votes in the first block of the last tenure of the prepare phase.
/// Bob votes in the second block of that tenure.
/// Both can vote successfully.
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
    let mut signers = TestSigners::default();
    let aggregate_public_key_1 = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key_2 = signers.generate_aggregate_key(cycle_id as u64 + 2);

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
        Value::err_uint(15) // ERR_DUPLICATE_VOTE
    );
    assert_eq!(alice_second_vote_tx.events.len(), 0);

    // third vote should succeed even though it is on an old round
    let alice_third_vote_tx = &receipts[4];
    assert_eq!(alice_third_vote_tx.result, Value::okay_true());

    // bob's block
    let block = blocks.last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 1);

    // bob's vote should succeed
    let tx1_bob = &receipts[0];
    assert_eq!(tx1_bob.result, Value::okay_true());
}

/// In this test case, Alice & Bob both successfully vote in cycle N, then
/// Alice tries to vote for the same signature in cycle N+1, but fails with
/// "duplicate aggregate public key" error.
#[test]
fn vote_for_duplicate_aggregate_public_key() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_public_key_point = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key =
        Value::buff_from(aggregate_public_key_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
    ];

    // vote in the first burn block of prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // Both votes should succeed
    let alice_vote_tx = &receipts[2];
    assert_eq!(alice_vote_tx.result, Value::okay_true());
    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());

    // Proceed to the next prepare phase
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());

    let aggregate_public_key_point = signers.generate_aggregate_key(cycle_id as u64 + 2);
    let aggregate_public_key_2 =
        Value::buff_from(aggregate_public_key_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote for the same key as the last cycle
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 1,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 2,
        ),
        // Alice casts vote for a new key
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 2,
            alice_index,
            aggregate_public_key_2.clone(),
            0,
            cycle_id + 2,
        ),
        // Bob casts vote for the same key
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 1,
            bob_index,
            aggregate_public_key_2.clone(),
            0,
            cycle_id + 2,
        ),
    ];

    // Submit the vote in a new block
    nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // Check the last 3 tx in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 5);

    // Alice's vote should fail with duplicate aggregate public key error
    let alice_vote_tx = &receipts[2];
    assert_eq!(
        alice_vote_tx.result,
        Value::err_uint(14) // ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY
    );
    assert_eq!(alice_vote_tx.events.len(), 0);

    // Both remaining votes should succeed
    let alice_vote_tx = &receipts[3];
    assert_eq!(alice_vote_tx.result, Value::okay_true());
    let bob_vote_tx = &receipts[4];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
}

/// In this test case, Alice & Bob both successfully vote in cycle N, but for
/// different keys. Then in round 1, they both vote for the same key and
/// key selection is successful. In the first cycle, these two rounds happen
/// in the same tenure. In the second cycle, the first round happens in the
/// first tenure of the prepare phase, and the second round happens in the
/// second tenure of the prepare phase.
#[test]
fn vote_for_aggregate_public_key_two_rounds() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_public_key_0_point = signers.generate_aggregate_key(0);
    let aggregate_public_key_0 =
        Value::buff_from(aggregate_public_key_0_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");
    let aggregate_public_key_1_point = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key_1 =
        Value::buff_from(aggregate_public_key_1_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote for key 0 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            alice_index,
            aggregate_public_key_0.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote for key 1 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key_1.clone(),
            0,
            cycle_id + 1,
        ),
        // Alice casts vote for key 1 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 1,
            alice_index,
            aggregate_public_key_1.clone(),
            1,
            cycle_id + 1,
        ),
        // Bob casts a vote for key 1 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 1,
            bob_index,
            aggregate_public_key_1.clone(),
            1,
            cycle_id + 1,
        ),
    ];

    // vote in the first burn block of prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last four txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 6);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // All votes should succeed
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
                ("key".into(), aggregate_public_key_0.clone()),
                ("new-total".into(), Value::UInt(2)),
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

    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
    assert_eq!(bob_vote_tx.events.len(), 1);
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(2)),
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

    let alice_vote_tx = &receipts[4];
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(1)),
                ("signer".into(), Value::Principal(alice_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }

    let bob_vote_tx = &receipts[5];
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(4)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(1)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    // The aggregate key is approved in round 1
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(1)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }

    // Proceed to the next prepare phase
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());

    // In this cycle, the two rounds are in separate tenures.

    let aggregate_public_key_0_point = signers.generate_aggregate_key(1);
    let aggregate_public_key_0 =
        Value::buff_from(aggregate_public_key_0_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");
    let aggregate_public_key_1_point = signers.generate_aggregate_key(cycle_id as u64 + 2);
    let aggregate_public_key_1 =
        Value::buff_from(aggregate_public_key_1_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote for key 0 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 2,
            alice_index,
            aggregate_public_key_0.clone(),
            0,
            cycle_id + 2,
        ),
        // Bob casts a vote for key 1 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 2,
            bob_index,
            aggregate_public_key_1.clone(),
            0,
            cycle_id + 2,
        ),
    ];

    // vote in the first burn block of prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // Both votes should succeed, but the aggregate key is not approved yet
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
                ("key".into(), aggregate_public_key_0.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(alice_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }

    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
    assert_eq!(bob_vote_tx.events.len(), 1);
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    let txs = vec![
        // Alice casts vote for key 1 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 3,
            alice_index,
            aggregate_public_key_1.clone(),
            1,
            cycle_id + 2,
        ),
        // Bob casts a vote for key 1 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 3,
            bob_index,
            aggregate_public_key_1.clone(),
            1,
            cycle_id + 2,
        ),
    ];

    // vote again in the next burn block
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(1)),
                ("signer".into(), Value::Principal(alice_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }

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
                ("key".into(), aggregate_public_key_1.clone()),
                ("new-total".into(), Value::UInt(4)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(1)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    // The aggregate key is approved in round 1
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
                ("key".into(), aggregate_public_key_1.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(1)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }
}

/// In this test case, Alice & Bob both successfully vote for the same key in
/// cycle N, then in cycle N + 1, Alice tries to vote before the prepare phase,
/// but fails with a "cycle not set" error.
#[test]
fn vote_for_aggregate_public_key_early() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_key = signers.generate_aggregate_key(cycle_id as u64 + 1);
    let aggregate_public_key = Value::buff_from(aggregate_key.compress().data.to_vec())
        .expect("Failed to serialize aggregate public key");

    let aggregate_public_key_ill_formed = Value::buff_from_byte(0x00);

    let txs = vec![
        // Alice casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
    ];
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);

    // Both votes should succeed
    let alice_vote_tx = &receipts[2];
    assert_eq!(alice_vote_tx.result, Value::okay_true());
    assert_eq!(alice_vote_tx.events.len(), 1);
    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
    assert_eq!(bob_vote_tx.events.len(), 2);

    // Proceed to the reward phase
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());

    // In this tenure, signers have not been set yet, so the vote should fail
    let aggregate_public_key_point = signers.generate_aggregate_key(cycle_id as u64 + 2);
    let aggregate_public_key =
        Value::buff_from(aggregate_public_key_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote for key 0 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 1,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 2,
        ),
    ];

    // vote before the prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last two txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 3);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // Alice's vote should fail with a "cycle not set" error
    let alice_vote_tx = &receipts[2];
    assert_eq!(
        alice_vote_tx.result,
        Value::err_uint(2) // ERR_CYCLE_NOT_SET
    );
    assert_eq!(alice_vote_tx.events.len(), 0);

    // Proceed to the prepare phase
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());
    let _ = nakamoto_tenure(&mut peer, &mut test_signers, Vec::new());

    let txs = vec![
        // Alice casts vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 2,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 2,
        ),
        // Bob casts a vote correctly
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 1,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 2,
        ),
    ];
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // This time, the votes should succeed and the key should be approved
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(alice_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", alice_vote_event);
    }

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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(4)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(0)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    // The aggregate key is approved in round 1
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
                ("key".into(), aggregate_public_key.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 2)),
                ("round".into(), Value::UInt(0)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }
}

/// In this test case, Alice votes in round 0 and Bob votes in round 1.
/// Although they both voted for the same key, the key is not approved. In the
/// next tenure, Bob votes in round 0, and the key is approved.
#[test]
fn vote_for_aggregate_public_key_mixed_rounds() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
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

    let mut signers = TestSigners::default();
    let aggregate_public_key_point = signers.generate_aggregate_key(0);
    let aggregate_public_key =
        Value::buff_from(aggregate_public_key_point.compress().data.to_vec())
            .expect("Failed to serialize aggregate public key");

    let txs = vec![
        // Alice casts vote for key 0 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce,
            alice_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Bob casts a vote for key 0 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce,
            bob_index,
            aggregate_public_key.clone(),
            1,
            cycle_id + 1,
        ),
    ];

    // vote in the first burn block of prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last four txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    // All votes should succeed
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
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

    let bob_vote_tx = &receipts[3];
    assert_eq!(bob_vote_tx.result, Value::okay_true());
    assert_eq!(bob_vote_tx.events.len(), 1);
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(2)),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(1)),
                ("signer".into(), Value::Principal(bob_principal.clone())),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", bob_vote_event);
    }

    let txs = vec![
        // Bob casts a vote for key 0 in round 0
        make_signers_vote_for_aggregate_public_key_value(
            bob_key,
            bob_nonce + 1,
            bob_index,
            aggregate_public_key.clone(),
            0,
            cycle_id + 1,
        ),
        // Alice casts vote for key 0 in round 1
        make_signers_vote_for_aggregate_public_key_value(
            alice_key,
            alice_nonce + 1,
            alice_index,
            aggregate_public_key.clone(),
            1,
            cycle_id + 1,
        ),
    ];

    // vote again in the next block of prepare phase
    let blocks_and_sizes = nakamoto_tenure(&mut peer, &mut test_signers, vec![txs]);

    // check the last four txs in the last block
    let block = observer.get_blocks().last().unwrap().clone();
    let receipts = block.receipts.as_slice();
    assert_eq!(receipts.len(), 4);
    // ignore tenure change tx
    // ignore tenure coinbase tx

    let bob_vote_tx = &receipts[2];
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
                ("key".into(), aggregate_public_key.clone()),
                ("new-total".into(), Value::UInt(4)),
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

    // The aggregate key is approved in round 0
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
                ("key".into(), aggregate_public_key.clone()),
                ("reward-cycle".into(), Value::UInt(cycle_id + 1)),
                ("round".into(), Value::UInt(0)),
            ])
            .expect("Failed to create tuple")
            .into()
        );
    } else {
        panic!("Expected SmartContractEvent, got {:?}", approve_event);
    }

    // Alice's vote should fail with an "out of voting window" error, since the
    // key is already set
    let alice_vote_tx = &receipts[3];
    assert_eq!(alice_vote_tx.result, Value::err_uint(12)); // ERR_OUT_OF_VOTING_WINDOW
    assert_eq!(alice_vote_tx.events.len(), 0);
}

// In this test case, Alice & Bob advance through setup & check
// the round info from the very first reward cycle & round.
#[test]
fn test_get_round_info() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
    let bob_key = &bob.signer_private_key;
    let bob_address = key_to_stacks_addr(bob_key);
    let bob_principal = PrincipalData::from(bob_address);

    let (mut peer, test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![
            (alice_principal.clone(), 1000),
            (bob_principal.clone(), 1000),
        ],
        &[alice.clone(), bob.clone()],
        Some(&observer),
    );

    // Get the current creward cycle
    let cycle_id = current_reward_cycle;

    let round_info = get_round_info(&mut peer, latest_block_id, cycle_id, 0)
        .unwrap()
        .expect_tuple()
        .unwrap();
    let votes_count = round_info.get("votes-count").unwrap();
    let votes_weight = round_info.get("votes-weight").unwrap();

    assert_eq!(votes_count, &Value::UInt(2));
    assert_eq!(votes_weight, &Value::UInt(4));
}

pub fn get_round_info(
    peer: &mut TestPeer<'_>,
    latest_block_id: StacksBlockId,
    reward_cycle: u128,
    round: u128,
) -> Option<Value> {
    let round_tuple = readonly_call(
        peer,
        &latest_block_id,
        "signers-voting".into(),
        "get-round-info".into(),
        vec![Value::UInt(reward_cycle), Value::UInt(round)],
    )
    .expect_optional()
    .unwrap();
    round_tuple
}

// In this test case, Alice & Bob advance through setup & check
// the weight threshold info from the very first reward cycle & round.
#[test]
fn test_get_threshold_weight() {
    // Test setup
    let alice = TestStacker::from_seed(&[3, 4]);
    let bob = TestStacker::from_seed(&[5, 6]);
    let observer = TestEventObserver::new();

    // Alice - Signer 1
    let alice_key = &alice.signer_private_key;
    let alice_address = key_to_stacks_addr(alice_key);
    let alice_principal = PrincipalData::from(alice_address);

    // Bob - Signer 2
    let bob_key = &bob.signer_private_key;
    let bob_address = key_to_stacks_addr(bob_key);
    let bob_principal = PrincipalData::from(bob_address);

    let (mut peer, test_signers, latest_block_id, current_reward_cycle) = prepare_signers_test(
        function_name!(),
        vec![
            (alice_principal.clone(), 1000),
            (bob_principal.clone(), 1000),
        ],
        &[alice.clone(), bob.clone()],
        Some(&observer),
    );

    // Get the current creward cycle
    let cycle_id = current_reward_cycle;

    // Call get-threshold-weight
    let threshold_weight: u128 = get_threshold_weight(&mut peer, latest_block_id, cycle_id);

    // Since there are four votes, the threshold weight should be 3 (75% of 4)
    assert_eq!(threshold_weight, 3);
}

pub fn get_threshold_weight(
    peer: &mut TestPeer<'_>,
    latest_block_id: StacksBlockId,
    reward_cycle: u128,
) -> u128 {
    let threshold_weight = readonly_call(
        peer,
        &latest_block_id,
        "signers-voting".into(),
        "get-threshold-weight".into(),
        vec![Value::UInt(reward_cycle)],
    )
    .expect_u128()
    .unwrap();
    threshold_weight
}

pub fn nakamoto_tenure(
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

pub fn make_dummy_tx(
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
