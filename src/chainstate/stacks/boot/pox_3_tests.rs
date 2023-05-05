use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryFrom;
use std::convert::TryInto;

use crate::address::AddressHashMode;
use crate::burnchains::PoxConstants;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::burn::ConsensusHash;
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::pox_2_tests::{
    check_pox_print_event, generate_pox_clarity_value, get_partial_stacked, get_reward_cycle_total,
    get_reward_set_entries_at, get_stacking_state_pox, get_stacking_state_pox_2,
    get_stx_account_at, PoxPrintFields,
};
use crate::chainstate::stacks::boot::{
    BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET, POX_2_NAME,
    POX_3_NAME,
};
use crate::chainstate::stacks::db::{
    MinerPaymentSchedule, StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::*;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::util_lib::db::{DBConn, FromRow};
use crate::vm::events::StacksTransactionEvent;
use clarity::types::Address;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::contracts::Contract;
use clarity::vm::costs::CostOverflowingMath;
use clarity::vm::database::*;
use clarity::vm::errors::{
    CheckErrors, Error, IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use clarity::vm::eval;
use clarity::vm::representations::SymbolicExpression;
use clarity::vm::tests::{execute, is_committed, is_err_code, symbols_from_values};
use clarity::vm::types::Value::Response;
use clarity::vm::types::{
    BuffData, OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, SequenceData,
    StacksAddressExtensions, StandardPrincipalData, TupleData, TupleTypeSignature, TypeSignature,
    Value, NONE,
};
use stacks_common::util::hash::hex_bytes;
use stacks_common::util::hash::to_hex;
use stacks_common::util::hash::{Sha256Sum, Sha512Trunc256Sum};

use crate::net::test::TestPeer;
use crate::util_lib::boot::boot_code_id;
use crate::{
    burnchains::Burnchain,
    chainstate::{
        burn::db::sortdb::SortitionDB,
        stacks::{events::TransactionOrigin, tests::make_coinbase},
    },
    clarity_vm::{clarity::ClarityBlockConnection, database::marf::WritableMarfStore},
    net::test::TestEventObserver,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};

use super::{test::*, RawRewardSetEntry};
use crate::clarity_vm::clarity::Error as ClarityError;

use crate::chainstate::burn::operations::*;
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::LimitedCostTracker;

const USTX_PER_HOLDER: u128 = 1_000_000;

/// Return the BlockSnapshot for the latest sortition in the provided
///  SortitionDB option-reference. Panics on any errors.
fn get_tip(sortdb: Option<&SortitionDB>) -> BlockSnapshot {
    SortitionDB::get_canonical_burn_chain_tip(&sortdb.unwrap().conn()).unwrap()
}

fn make_test_epochs_pox() -> (Vec<StacksEpoch>, PoxConstants) {
    let EMPTY_SORTITIONS = 25;
    let EPOCH_2_1_HEIGHT = 11; // 36
    let EPOCH_2_2_HEIGHT = EPOCH_2_1_HEIGHT + 14; // 50
    let EPOCH_2_3_HEIGHT = EPOCH_2_2_HEIGHT + 2; // 52
                                                 // epoch-2.4 will start at the first block of cycle 11!
                                                 //  this means that cycle 11 should also be treated like a "burn"
    let EPOCH_2_4_HEIGHT = EPOCH_2_2_HEIGHT + 6; // 56

    // cycle 11 = 60

    let epochs = vec![
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch10,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_1_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch20,
            start_height: 0,
            end_height: 0,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_0,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch2_05,
            start_height: 0,
            end_height: EMPTY_SORTITIONS + EPOCH_2_1_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: EMPTY_SORTITIONS + EPOCH_2_1_HEIGHT,
            end_height: EMPTY_SORTITIONS + EPOCH_2_2_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: EMPTY_SORTITIONS + EPOCH_2_2_HEIGHT,
            end_height: EMPTY_SORTITIONS + EPOCH_2_3_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: EMPTY_SORTITIONS + EPOCH_2_3_HEIGHT,
            end_height: EMPTY_SORTITIONS + EPOCH_2_4_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: EMPTY_SORTITIONS + EPOCH_2_4_HEIGHT,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
    ];

    let mut pox_constants = PoxConstants::mainnet_default();
    pox_constants.reward_cycle_length = 5;
    pox_constants.prepare_length = 2;
    pox_constants.anchor_threshold = 1;
    pox_constants.v1_unlock_height = (EMPTY_SORTITIONS + EPOCH_2_1_HEIGHT + 1) as u32;
    pox_constants.v2_unlock_height = (EMPTY_SORTITIONS + EPOCH_2_2_HEIGHT + 1) as u32;
    pox_constants.pox_3_activation_height = (EMPTY_SORTITIONS + EPOCH_2_4_HEIGHT + 1) as u32;

    (epochs, pox_constants)
}

/// In this test case, two Stackers, Alice and Bob stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition and then
///  again with the PoX v3 contract.
///
/// Alice: stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        After the early unlock, Alice re-stacks in PoX v2
/// Bob:   stacks via PoX v2 for 6 cycles. He attempted to stack via PoX v1 as well,
///        but is forbidden because he has already placed an account lock via PoX v2.
///        
/// After the PoX-3 contract is instantiated, Alice and Bob both stack via PoX v3.
///
#[test]
fn simple_pox_lockup_transition_pox_2() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "pox_3_tests::simple_pox_lockup_transition_pox_2",
        7104,
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 20));

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;

    let mut coinbase_nonce = 0;

    // our "tenure counter" is now at 0
    let tip = get_tip(peer.sortdb.as_ref());
    assert_eq!(tip.block_height, 0 + EMPTY_SORTITIONS as u64);

    // first tenure is empty
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(
        alice_account.stx_balance.amount_unlocked(),
        1024 * POX_THRESHOLD_STEPS_USTX
    );
    assert_eq!(alice_account.stx_balance.amount_locked(), 0);
    assert_eq!(alice_account.stx_balance.unlock_height(), 0);

    // next tenure include Alice's lockup
    let tip = get_tip(peer.sortdb.as_ref());
    let alice_lockup = make_pox_lockup(
        &alice,
        0,
        1024 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        4,
        tip.block_height,
    );

    // our "tenure counter" is now at 1
    assert_eq!(tip.block_height, 1 + EMPTY_SORTITIONS as u64);

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_first_reward_cycle, EXPECTED_ALICE_FIRST_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until immediately before the 2.1 epoch switch
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[3].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
    }

    // Have Charlie try to use the PoX2 contract. This transaction
    //  should be accepted (checked via the tx receipt). Also, importantly,
    //  the cost tracker should assign costs to Charlie's transaction.
    //  This is also checked by the transaction receipt.
    let tip = get_tip(peer.sortdb.as_ref());

    let test = make_pox_2_contract_call(
        &charlie,
        0,
        "delegate-stx",
        vec![
            Value::UInt(1_000_000),
            PrincipalData::from(key_to_stacks_addr(&charlie)).into(),
            Value::none(),
            Value::none(),
        ],
    );
    peer.tenure_with_txs(&[test], &mut coinbase_nonce);

    // alice is still locked, balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10, and 11
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip.block_height,
    );

    let block_id = peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    assert_eq!(
        get_tip(peer.sortdb.as_ref()).block_height as u32,
        pox_constants.v1_unlock_height + 1,
        "Test should have reached 1 + PoX-v1 unlock height"
    );

    // Auto unlock height is reached, Alice balance should be unlocked
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    // Now, Bob tries to lock in PoX v1 too, but it shouldn't work!
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_lockup(
        &bob,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
        4,
        tip.block_height,
    );

    let block_id = peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    // At this point, the auto unlock height for v1 accounts has been reached.
    //  let Alice stack in PoX v2
    let tip = get_tip(peer.sortdb.as_ref());

    let alice_lockup = make_pox_2_lockup(
        &alice,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        12,
        tip.block_height,
    );
    peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // Alice locked half her balance in PoX 2
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now, let's roll the chain forward until just before Epoch-2.2
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[4].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always include this half lockup
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // this block is mined in epoch-2.2
    peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    // this block should unlock alice's balance
    peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    // now, roll the chain forward to Epoch-2.4
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[6].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always be unlocked
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);
    }

    let tip = get_tip(peer.sortdb.as_ref()).block_height;
    let bob_lockup = make_pox_3_lockup(
        &bob,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip,
    );

    let alice_lockup = make_pox_3_lockup(
        &alice,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip,
    );

    peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);

    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
    assert_eq!(bob_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut charlie_txs = HashMap::new();

    debug!("Alice addr: {}, Bob addr: {}", alice_address, bob_address);

    let mut tested_charlie = false;

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                debug!("Transaction addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == key_to_stacks_addr(&charlie) {
                    assert!(
                        r.execution_cost != ExecutionCost::zero(),
                        "Execution cost is not zero!"
                    );
                    charlie_txs.insert(t.auth.get_origin_nonce(), r);

                    tested_charlie = true;
                }
            }
        }
    }

    assert!(tested_charlie, "Charlie TX must be tested");
    // Alice should have three accepted transactions:
    //  TX0 -> Alice's initial lockup in PoX 1
    //  TX1 -> Alice's PoX 2 lockup
    //  TX2 -> Alice's PoX 3 lockup
    assert_eq!(alice_txs.len(), 3, "Alice should have 3 confirmed txs");
    // Bob should have two accepted transactions:
    //  TX0 -> Bob's initial lockup in PoX 2
    //  TX1 -> Bob's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    //  TX2 -> Bob's PoX 3 lockup
    assert_eq!(bob_txs.len(), 3, "Bob should have 3 confirmed txs");
    // Charlie should have one accepted transactions:
    //  TX0 -> Charlie's delegation in PoX 2. This tx just checks that the
    //         initialization code tracks costs in txs that occur after the
    //         initialization code (which uses a free tracker).
    assert_eq!(charlie_txs.len(), 1, "Charlie should have 1 confirmed txs");

    //  TX0 -> Alice's initial lockup in PoX 1
    assert!(
        match alice_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx0 should have committed okay"
    );

    //  TX1 -> Alice's PoX 2 lockup
    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx1 should have committed okay"
    );

    //  TX2 -> Alice's PoX 3 lockup
    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx3 should have committed okay"
    );

    //  TX0 -> Bob's initial lockup in PoX 2
    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    //  TX1 -> Bob's attempt to lock again in PoX 1 -- this one should fail
    //         because PoX 1 is now defunct. Checked via the tx receipt.
    assert_eq!(
        bob_txs.get(&1).unwrap().result,
        Value::err_none(),
        "Bob tx1 should have resulted in a runtime error"
    );

    //  TX0 -> Charlie's delegation in PoX 2. This tx just checks that the
    //         initialization code tracks costs in txs that occur after the
    //         initialization code (which uses a free tracker).
    assert!(
        match charlie_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Charlie tx0 should have committed okay"
    );
}

#[test]
fn test_simple_pox_2_auto_unlock_ab() {
    test_simple_pox_2_auto_unlock(true)
}

#[test]
fn test_simple_pox_2_auto_unlock_ba() {
    test_simple_pox_2_auto_unlock(false)
}

/// In this test case, two Stackers, Alice and Bob stack and interact with the
///  PoX v1 contract and PoX v2 contract across the epoch transition.
///
/// Alice: stacks via PoX v1 for 4 cycles. The third of these cycles occurs after
///        the PoX v1 -> v2 transition, and so Alice gets "early unlocked".
///        After the early unlock, Alice re-stacks in PoX v2
///        Alice tries to stack again via PoX v1, which is allowed by the contract,
///        but forbidden by the VM (because PoX has transitioned to v2)
/// Bob:   stacks via PoX v2 for 6 cycles. He attempted to stack via PoX v1 as well,
///        but is forbidden because he has already placed an account lock via PoX v2.
///
/// Note: this test is symmetric over the order of alice and bob's stacking calls.
///       when alice goes first, the auto-unlock code doesn't need to perform a "move"
///       when bob goes first, the auto-unlock code does need to perform a "move"
fn test_simple_pox_2_auto_unlock(alice_first: bool) {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    let first_v3_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_3_activation_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &format!("pox_3_tests::simple_pox_auto_unlock_{}", alice_first),
        7102,
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();

    let mut coinbase_nonce = 0;

    // produce blocks until epoch 2.1
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[3].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10, and 11
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let alice_lockup = make_pox_2_lockup(
        &alice,
        0,
        1024 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        1 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip.block_height,
    );

    let txs = if alice_first {
        [alice_lockup, bob_lockup]
    } else {
        [bob_lockup, alice_lockup]
    };
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice and bob
    //  for the pox-2 cycles
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..first_v3_cycle {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&bob).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // we'll produce blocks until the next reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE) + 1;

    // but first, check that bob has locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let first_auto_unlock_coinbase = height_target - 1 - EMPTY_SORTITIONS;

    // check that the "raw" reward sets for all cycles just contains entries for alice
    //  at the cycle start
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..first_v3_cycle {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // now check that bob has no locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), 0);

    // but bob's still locked at (height_target): the unlock is accelerated to the "next" burn block
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), 0);

    // check that the total reward cycle amounts have decremented correctly
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..first_v3_cycle {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            1024 * POX_THRESHOLD_STEPS_USTX
        );
    }

    // check that bob's stacking-state is gone and alice's stacking-state is correct
    assert!(
        get_stacking_state_pox_2(
            &mut peer,
            &latest_block,
            &key_to_stacks_addr(&bob).to_account_principal()
        )
        .is_none(),
        "Bob should not have a stacking-state entry"
    );

    let alice_state = get_stacking_state_pox_2(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&alice).to_account_principal(),
    )
    .expect("Alice should have stacking-state entry")
    .expect_tuple();
    let reward_indexes_str = format!("{}", alice_state.get("reward-set-indexes").unwrap());
    assert_eq!(reward_indexes_str, "(u0 u0 u0 u0 u0 u0)");

    // now, lets check behavior in Epochs 2.2-2.4, with pox-3 auto unlock tests

    // produce blocks until epoch 2.2
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[4].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
    }

    // check that alice is unlocked now
    peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    // produce blocks until epoch 2.4
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[6].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // repeat the lockups as before, so we can test the pox-3 auto unlock behavior
    let tip = get_tip(peer.sortdb.as_ref());

    let alice_lockup = make_pox_3_lockup(
        &alice,
        1,
        1024 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );

    let bob_lockup = make_pox_3_lockup(
        &bob,
        1,
        1 * POX_THRESHOLD_STEPS_USTX,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        6,
        tip.block_height,
    );

    let txs = if alice_first {
        [alice_lockup, bob_lockup]
    } else {
        [bob_lockup, alice_lockup]
    };
    latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice and bob
    //  for the pox-3 cycles
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&bob).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // we'll produce blocks until the next reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(first_v3_cycle) + 1;
    let second_auto_unlock_coinbase = height_target - 1 - EMPTY_SORTITIONS;

    // but first, check that bob has locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), POX_THRESHOLD_STEPS_USTX);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward sets for all cycles just contains entries for alice
    //  at the cycle start
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
    }

    // now check that bob has no locked tokens at (height_target + 1)
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), 0);

    // but bob's still locked at (height_target): the unlock is accelerated to the "next" burn block
    let bob_bal = get_stx_account_at(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&bob).to_account_principal(),
    );
    assert_eq!(bob_bal.amount_locked(), 0);

    // check that the total reward cycle amounts have decremented correctly
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            1024 * POX_THRESHOLD_STEPS_USTX
        );
    }

    // check that bob's stacking-state is gone and alice's stacking-state is correct
    assert!(
        get_stacking_state_pox(
            &mut peer,
            &latest_block,
            &key_to_stacks_addr(&bob).to_account_principal(),
            POX_3_NAME,
        )
        .is_none(),
        "Bob should not have a stacking-state entry"
    );

    let alice_state = get_stacking_state_pox(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(&alice).to_account_principal(),
        POX_3_NAME,
    )
    .expect("Alice should have stacking-state entry")
    .expect_tuple();
    let reward_indexes_str = format!("{}", alice_state.get("reward-set-indexes").unwrap());
    assert_eq!(reward_indexes_str, "(u0 u0 u0 u0 u0 u0)");

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();
    let mut coinbase_txs = vec![];

    for b in blocks.into_iter() {
        for (i, r) in b.receipts.into_iter().enumerate() {
            if i == 0 {
                coinbase_txs.push(r);
                continue;
            }
            match r.transaction {
                TransactionOrigin::Stacks(ref t) => {
                    let addr = t.auth.origin().address_testnet();
                    if addr == alice_address {
                        alice_txs.insert(t.auth.get_origin_nonce(), r);
                    } else if addr == bob_address {
                        bob_txs.insert(t.auth.get_origin_nonce(), r);
                    }
                }
                _ => {}
            }
        }
    }

    assert_eq!(alice_txs.len(), 2);
    assert_eq!(bob_txs.len(), 2);

    //  TX0 -> Bob's initial lockup in PoX 2
    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    assert_eq!(coinbase_txs.len(), 37);

    info!(
        "Expected first auto-unlock coinbase index: {}",
        first_auto_unlock_coinbase
    );

    // Check that the event produced by "handle-unlock" has a well-formed print event
    // and that this event is included as part of the coinbase tx
    for unlock_coinbase_index in [first_auto_unlock_coinbase, second_auto_unlock_coinbase] {
        // expect the unlock to occur 1 block after the handle-unlock method was invoked.
        let expected_unlock_height = unlock_coinbase_index + EMPTY_SORTITIONS + 1;
        let expected_cycle = pox_constants
            .block_height_to_reward_cycle(0, expected_unlock_height)
            .unwrap();

        let auto_unlock_tx = coinbase_txs[unlock_coinbase_index as usize].events[0].clone();
        let pox_addr_val = generate_pox_clarity_value("60c59ab11f7063ef44c16d3dc856f76bbb915eba");
        let auto_unlock_op_data = HashMap::from([
            ("first-cycle-locked", Value::UInt(expected_cycle.into())),
            ("first-unlocked-cycle", Value::UInt(expected_cycle.into())),
            ("pox-addr", pox_addr_val),
        ]);
        let common_data = PoxPrintFields {
            op_name: "handle-unlock".to_string(),
            stacker: Value::Principal(
                StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                    .unwrap()
                    .to_account_principal(),
            ),
            balance: Value::UInt(10230000000000),
            locked: Value::UInt(10000000000),
            burnchain_unlock_height: Value::UInt(expected_unlock_height.into()),
        };
        check_pox_print_event(&auto_unlock_tx, common_data, auto_unlock_op_data);
    }
}

/// In this test case, Alice delegates to Bob.
///  Bob stacks Alice's funds via PoX v2 for 6 cycles. In the third cycle,
///  Bob increases Alice's stacking amount.
///
#[test]
fn delegate_stack_increase() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    let first_v3_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_3_activation_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &format!("pox_3_delegate_stack_increase"),
        7103,
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, bob_address.bytes.clone());
    let mut alice_nonce = 0;
    let mut bob_nonce = 0;

    let alice_delegation_amount = 1023 * POX_THRESHOLD_STEPS_USTX;
    let alice_first_lock_amount = 512 * POX_THRESHOLD_STEPS_USTX;

    let mut coinbase_nonce = 0;

    // produce blocks until epoch 2.1
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[3].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit delegation tx
    let alice_delegation_1 = make_pox_2_contract_call(
        &alice,
        alice_nonce,
        "delegate-stx",
        vec![
            Value::UInt(alice_delegation_amount),
            bob_principal.clone().into(),
            Value::none(),
            Value::none(),
        ],
    );

    let alice_delegation_pox_2_nonce = alice_nonce;
    alice_nonce += 1;

    let delegate_stack_tx = make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-stx",
        vec![
            alice_principal.clone().into(),
            Value::UInt(alice_first_lock_amount),
            bob_pox_addr.clone(),
            Value::UInt(tip.block_height as u128),
            Value::UInt(6),
        ],
    );

    bob_nonce += 1;

    let mut latest_block = peer.tenure_with_txs(
        &[alice_delegation_1, delegate_stack_tx],
        &mut coinbase_nonce,
    );

    let expected_pox_2_unlock_ht =
        burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 6) - 1;
    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);
    assert_eq!(alice_bal.unlock_height(), expected_pox_2_unlock_ht);

    // check that the partial stacking state contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // we'll produce blocks until the 1st reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 1) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);

    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);

    // check that the partial stacking state contains entries for bob
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let mut txs_to_submit = vec![];

    let fail_direct_increase_delegation = alice_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &alice,
        alice_nonce,
        "stack-increase",
        vec![Value::UInt(1)],
    ));
    alice_nonce += 1;

    let fail_delegate_too_much_locked = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount + 1),
        ],
    ));
    bob_nonce += 1;

    let fail_invalid_amount = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(0),
        ],
    ));
    bob_nonce += 1;

    let fail_insufficient_funds = bob_nonce;
    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_bal.amount_unlocked() + 1),
        ],
    ));
    bob_nonce += 1;

    txs_to_submit.push(make_pox_2_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount),
        ],
    ));
    let bob_delegate_increase_pox_2_nonce = bob_nonce;
    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), alice_delegation_amount);
    assert_eq!(alice_bal.unlock_height(), expected_pox_2_unlock_ht);

    // check that the partial stacking state contains entries for bob and they've incremented correctly
    for cycle_number in (EXPECTED_FIRST_V2_CYCLE)..(EXPECTED_FIRST_V2_CYCLE + 2) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, alice_first_lock_amount);
    }

    for cycle_number in (EXPECTED_FIRST_V2_CYCLE + 2)..(EXPECTED_FIRST_V2_CYCLE + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_2_NAME,
        );
        assert_eq!(partial_stacked, alice_delegation_amount,);
    }

    // okay, now let's progress through epochs 2.2-2.4, and perform the delegation tests
    //  on pox-3

    // roll the chain forward until just before Epoch-2.2
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[4].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always include this half lockup
        assert_eq!(
            get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
            alice_delegation_amount
        );
        assert_eq!(
            get_stx_account_at(&mut peer, &latest_block, &bob_principal).amount_locked(),
            0,
        );
    }

    // this block is mined in epoch-2.2
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        alice_delegation_amount
    );
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &bob_principal).amount_locked(),
        0,
    );
    // this block should unlock alice's balance
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        0,
    );
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &bob_principal).amount_locked(),
        0,
    );
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_unlocked(),
        1024 * POX_THRESHOLD_STEPS_USTX
    );
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &bob_principal).amount_unlocked(),
        1024 * POX_THRESHOLD_STEPS_USTX
    );

    // Roll to Epoch-2.4 and re-do the above tests
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[6].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());

    // submit delegation tx
    let alice_delegation_1 = make_pox_3_contract_call(
        &alice,
        alice_nonce,
        "delegate-stx",
        vec![
            Value::UInt(alice_delegation_amount),
            bob_principal.clone().into(),
            Value::none(),
            Value::none(),
        ],
    );
    let alice_delegation_pox_3_nonce = alice_nonce;
    alice_nonce += 1;

    let delegate_stack_tx = make_pox_3_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-stx",
        vec![
            alice_principal.clone().into(),
            Value::UInt(alice_first_lock_amount),
            bob_pox_addr.clone(),
            Value::UInt(tip.block_height as u128),
            Value::UInt(6),
        ],
    );

    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(
        &[alice_delegation_1, delegate_stack_tx],
        &mut coinbase_nonce,
    );

    let expected_pox_3_unlock_ht = burnchain.reward_cycle_to_block_height(first_v3_cycle + 6) - 1;
    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);
    assert_eq!(alice_bal.unlock_height(), expected_pox_3_unlock_ht);

    // check that the partial stacking state contains entries for bob
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_3_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // we'll produce blocks until the 3rd reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(first_v3_cycle + 3) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), alice_first_lock_amount);
    let bob_bal = get_stx_account_at(&mut peer, &latest_block, &bob_principal);
    assert_eq!(bob_bal.amount_locked(), 0);

    // check that the partial stacking state contains entries for bob
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_3_NAME,
        );
        assert_eq!(partial_stacked, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let mut txs_to_submit = vec![];

    let pox_3_fail_direct_increase_delegation = alice_nonce;
    txs_to_submit.push(make_pox_3_contract_call(
        &alice,
        alice_nonce,
        "stack-increase",
        vec![Value::UInt(1)],
    ));
    alice_nonce += 1;

    let pox_3_fail_delegate_too_much_locked = bob_nonce;
    txs_to_submit.push(make_pox_3_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount + 1),
        ],
    ));
    bob_nonce += 1;

    let pox_3_fail_invalid_amount = bob_nonce;
    txs_to_submit.push(make_pox_3_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(0),
        ],
    ));
    bob_nonce += 1;

    let pox_3_fail_insufficient_funds = bob_nonce;
    txs_to_submit.push(make_pox_3_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_bal.amount_unlocked() + 1),
        ],
    ));
    bob_nonce += 1;

    txs_to_submit.push(make_pox_3_contract_call(
        &bob,
        bob_nonce,
        "delegate-stack-increase",
        vec![
            alice_principal.clone().into(),
            bob_pox_addr.clone(),
            Value::UInt(alice_delegation_amount - alice_first_lock_amount),
        ],
    ));
    let bob_delegate_increase_pox_3_nonce = bob_nonce;
    bob_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        alice_delegation_amount
    );

    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).unlock_height(),
        expected_pox_3_unlock_ht,
    );

    // check that the partial stacking state contains entries for bob and they've incremented correctly
    for cycle_number in first_v3_cycle..(first_v3_cycle + 4) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_3_NAME,
        );
        assert_eq!(
            partial_stacked,
            alice_first_lock_amount,
            "Unexpected partially stacked amount in cycle: {} = {} + {}",
            cycle_number,
            first_v3_cycle,
            first_v3_cycle - cycle_number,
        );
    }

    for cycle_number in (first_v3_cycle + 4)..(first_v3_cycle + 6) {
        let partial_stacked = get_partial_stacked(
            &mut peer,
            &latest_block,
            &bob_pox_addr,
            cycle_number,
            &bob_principal,
            POX_3_NAME,
        );
        assert_eq!(partial_stacked, alice_delegation_amount);
    }

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len() as u64, 4);
    assert_eq!(bob_txs.len() as u64, 10);

    // transaction should fail because Alice cannot increase her own stacking amount while delegating
    assert_eq!(
        &alice_txs[&fail_direct_increase_delegation]
            .result
            .to_string(),
        "(err 20)"
    );

    // transaction should fail because Alice did not delegate enough funds to Bob
    assert_eq!(
        &bob_txs[&fail_delegate_too_much_locked].result.to_string(),
        "(err 22)"
    );

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &bob_txs[&fail_insufficient_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(
        &bob_txs[&fail_invalid_amount].result.to_string(),
        "(err 18)"
    );

    assert_eq!(
        &alice_txs[&pox_3_fail_direct_increase_delegation]
            .result
            .to_string(),
        "(err 30)"
    );

    // transaction should fail because Alice did not delegate enough funds to Bob
    assert_eq!(
        &bob_txs[&pox_3_fail_delegate_too_much_locked]
            .result
            .to_string(),
        "(err 22)"
    );

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &bob_txs[&pox_3_fail_insufficient_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(
        &bob_txs[&pox_3_fail_invalid_amount].result.to_string(),
        "(err 18)"
    );

    for delegation_nonce in [alice_delegation_pox_2_nonce, alice_delegation_pox_3_nonce] {
        let delegate_stx_tx = &alice_txs.get(&delegation_nonce).unwrap().clone().events[0];
        let delegate_stx_op_data = HashMap::from([
            ("pox-addr", Value::none()),
            ("amount-ustx", Value::UInt(10230000000000)),
            ("unlock-burn-height", Value::none()),
            (
                "delegate-to",
                Value::Principal(
                    StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                        .unwrap()
                        .to_account_principal(),
                ),
            ),
        ]);
        let common_data = PoxPrintFields {
            op_name: "delegate-stx".to_string(),
            stacker: Value::Principal(
                StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                    .unwrap()
                    .to_account_principal(),
            ),
            balance: Value::UInt(10240000000000),
            locked: Value::UInt(0),
            burnchain_unlock_height: Value::UInt(0),
        };
        check_pox_print_event(delegate_stx_tx, common_data, delegate_stx_op_data);
    }

    // Check that the call to `delegate-stack-increase` has a well-formed print event.
    for (unlock_height, del_increase_nonce) in [
        (expected_pox_2_unlock_ht, bob_delegate_increase_pox_2_nonce),
        (expected_pox_3_unlock_ht, bob_delegate_increase_pox_3_nonce),
    ] {
        let delegate_stack_increase_tx =
            &bob_txs.get(&del_increase_nonce).unwrap().clone().events[0];
        let pox_addr_val = generate_pox_clarity_value("60c59ab11f7063ef44c16d3dc856f76bbb915eba");
        let delegate_op_data = HashMap::from([
            ("pox-addr", pox_addr_val),
            ("increase-by", Value::UInt(5110000000000)),
            ("total-locked", Value::UInt(10230000000000)),
            (
                "delegator",
                Value::Principal(
                    StacksAddress::from_string("ST1GCB6NH3XR67VT4R5PKVJ2PYXNVQ4AYQATXNP4P")
                        .unwrap()
                        .to_account_principal(),
                ),
            ),
        ]);
        let common_data = PoxPrintFields {
            op_name: "delegate-stack-increase".to_string(),
            stacker: Value::Principal(
                StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                    .unwrap()
                    .to_account_principal(),
            ),
            balance: Value::UInt(5120000000000),
            locked: Value::UInt(5120000000000),
            burnchain_unlock_height: Value::UInt(unlock_height.into()),
        };
        check_pox_print_event(delegate_stack_increase_tx, common_data, delegate_op_data);
    }
}

#[test]
fn stack_increase() {
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    let first_v3_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_3_activation_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        &format!("pox_3_stack_increase"),
        7105,
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let mut alice_nonce = 0;

    let mut coinbase_nonce = 0;

    let first_lockup_amt = 512 * POX_THRESHOLD_STEPS_USTX;
    let total_balance = 1024 * POX_THRESHOLD_STEPS_USTX;
    let increase_amt = total_balance - first_lockup_amt;

    // produce blocks until epoch 2.1
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[3].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit an increase: this should fail, because Alice is not yet locked
    let fail_no_lock_tx = alice_nonce;
    let alice_increase = make_pox_2_increase(&alice, alice_nonce, increase_amt);
    alice_nonce += 1;

    let alice_lockup = make_pox_2_lockup(
        &alice,
        alice_nonce,
        first_lockup_amt,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );
    alice_nonce += 1;

    let mut latest_block =
        peer.tenure_with_txs(&[alice_increase, alice_lockup], &mut coinbase_nonce);

    let expected_pox_2_unlock_ht =
        burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 6) - 1;
    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), first_lockup_amt);
    assert_eq!(alice_bal.unlock_height(), expected_pox_2_unlock_ht);
    assert_eq!(alice_bal.get_total_balance(), total_balance,);

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..first_v3_cycle {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    // we'll produce blocks until the 1st reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(EXPECTED_FIRST_V2_CYCLE + 1) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward sets for all cycles contains entries for alice
    for cycle_number in EXPECTED_FIRST_V2_CYCLE..first_v3_cycle {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    let mut txs_to_submit = vec![];
    let fail_bad_amount = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, 0));
    alice_nonce += 1;

    // this stack-increase tx should work
    let pox_2_success_increase = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, increase_amt));
    alice_nonce += 1;

    // increase by an amount we don't have!
    let fail_not_enough_funds = alice_nonce;
    txs_to_submit.push(make_pox_2_increase(&alice, alice_nonce, 1));
    alice_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), first_lockup_amt + increase_amt,);
    assert_eq!(alice_bal.unlock_height(), expected_pox_2_unlock_ht);
    assert_eq!(alice_bal.get_total_balance(), total_balance,);

    // check that the total reward cycle amounts have incremented correctly
    for cycle_number in first_v2_cycle..(first_v2_cycle + 2) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    assert!(
        first_v2_cycle + 2 < first_v3_cycle,
        "Make sure that we can actually test a stack-increase in pox-2 before pox-3 activates"
    );

    for cycle_number in (first_v2_cycle + 2)..first_v3_cycle {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt + increase_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[0].amount_stacked,
            first_lockup_amt + increase_amt,
        );
    }

    // Roll to Epoch-2.4 and re-do the above tests
    // okay, now let's progress through epochs 2.2-2.4, and perform the delegation tests
    //  on pox-3

    // roll the chain forward until just before Epoch-2.2
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[4].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always include this half lockup
        assert_eq!(
            get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
            first_lockup_amt + increase_amt,
        );
    }

    // this block is mined in epoch-2.2
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        first_lockup_amt + increase_amt,
    );

    // this block should unlock alice's balance

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_locked(),
        0,
    );
    assert_eq!(
        get_stx_account_at(&mut peer, &latest_block, &alice_principal).amount_unlocked(),
        total_balance,
    );

    // Roll to Epoch-2.4 and re-do the above stack-increase tests
    while get_tip(peer.sortdb.as_ref()).block_height <= epochs[6].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // in the next tenure, PoX 2 should now exist.
    let tip = get_tip(peer.sortdb.as_ref());

    // submit an increase: this should fail, because Alice is not yet locked
    let pox_3_fail_no_lock_tx = alice_nonce;
    let alice_increase = make_pox_3_contract_call(
        &alice,
        alice_nonce,
        "stack-increase",
        vec![Value::UInt(increase_amt)],
    );
    alice_nonce += 1;

    let alice_lockup = make_pox_3_lockup(
        &alice,
        alice_nonce,
        first_lockup_amt,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        tip.block_height,
    );
    alice_nonce += 1;

    let mut latest_block =
        peer.tenure_with_txs(&[alice_increase, alice_lockup], &mut coinbase_nonce);

    let expected_pox_3_unlock_ht = burnchain.reward_cycle_to_block_height(first_v3_cycle + 6) - 1;
    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), first_lockup_amt);
    assert_eq!(alice_bal.unlock_height(), expected_pox_3_unlock_ht);
    assert_eq!(alice_bal.get_total_balance(), total_balance,);

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    // we'll produce blocks until the 3rd reward cycle gets through the "handled start" code
    //  this is one block after the reward cycle starts
    let height_target = burnchain.reward_cycle_to_block_height(first_v3_cycle + 3) + 1;

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v3_cycle..(first_v3_cycle + 6) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    let mut txs_to_submit = vec![];
    let pox_3_fail_bad_amount = alice_nonce;
    let bad_amount_tx =
        make_pox_3_contract_call(&alice, alice_nonce, "stack-increase", vec![Value::UInt(0)]);
    txs_to_submit.push(bad_amount_tx);
    alice_nonce += 1;

    // this stack-increase tx should work
    let pox_3_success_increase = alice_nonce;
    let good_amount_tx = make_pox_3_contract_call(
        &alice,
        alice_nonce,
        "stack-increase",
        vec![Value::UInt(increase_amt)],
    );
    txs_to_submit.push(good_amount_tx);
    alice_nonce += 1;

    // increase by an amount we don't have!
    let pox_3_fail_not_enough_funds = alice_nonce;
    let not_enough_tx =
        make_pox_3_contract_call(&alice, alice_nonce, "stack-increase", vec![Value::UInt(1)]);
    txs_to_submit.push(not_enough_tx);
    alice_nonce += 1;

    latest_block = peer.tenure_with_txs(&txs_to_submit, &mut coinbase_nonce);

    let alice_bal = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    assert_eq!(alice_bal.amount_locked(), first_lockup_amt + increase_amt,);
    assert_eq!(alice_bal.unlock_height(), expected_pox_3_unlock_ht);
    assert_eq!(alice_bal.get_total_balance(), total_balance,);

    // check that the total reward cycle amounts have incremented correctly
    for cycle_number in first_v3_cycle..(first_v3_cycle + 4) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, first_lockup_amt,);
    }

    for cycle_number in (first_v3_cycle + 4)..(first_v3_cycle + 6) {
        assert_eq!(
            get_reward_cycle_total(&mut peer, &latest_block, cycle_number),
            first_lockup_amt + increase_amt,
        );
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(
            reward_set_entries[0].amount_stacked,
            first_lockup_amt + increase_amt,
        );
    }

    // now let's check some tx receipts
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len() as u64, alice_nonce);

    // transaction should fail because lock isn't applied
    assert_eq!(&alice_txs[&fail_no_lock_tx].result.to_string(), "(err 27)");

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &alice_txs[&fail_not_enough_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(&alice_txs[&fail_bad_amount].result.to_string(), "(err 18)");

    // transaction should fail because lock isn't applied
    assert_eq!(
        &alice_txs[&pox_3_fail_no_lock_tx].result.to_string(),
        "(err 27)"
    );

    // transaction should fail because Alice doesn't have enough funds
    assert_eq!(
        &alice_txs[&pox_3_fail_not_enough_funds].result.to_string(),
        "(err 1)"
    );

    // transaction should fail because the amount supplied is invalid (i.e., 0)
    assert_eq!(
        &alice_txs[&pox_3_fail_bad_amount].result.to_string(),
        "(err 18)"
    );

    // Check that the call to `stack-increase` has a well-formed print event.
    for (increase_nonce, unlock_height) in [
        (pox_2_success_increase, expected_pox_2_unlock_ht),
        (pox_3_success_increase, expected_pox_3_unlock_ht),
    ] {
        let stack_increase_tx = &alice_txs.get(&increase_nonce).unwrap().clone().events[0];
        let pox_addr_val = generate_pox_clarity_value("ae1593226f85e49a7eaff5b633ff687695438cc9");
        let stack_op_data = HashMap::from([
            ("increase-by", Value::UInt(5120000000000)),
            ("total-locked", Value::UInt(10240000000000)),
            ("pox-addr", pox_addr_val),
        ]);
        let common_data = PoxPrintFields {
            op_name: "stack-increase".to_string(),
            stacker: Value::Principal(
                StacksAddress::from_string("ST2Q1B4S2DY2Y96KYNZTVCCZZD1V9AGWCS5MFXM4C")
                    .unwrap()
                    .to_account_principal(),
            ),
            balance: Value::UInt(5120000000000),
            locked: Value::UInt(5120000000000),
            burnchain_unlock_height: Value::UInt(unlock_height.into()),
        };
        check_pox_print_event(stack_increase_tx, common_data, stack_op_data);
    }
}
