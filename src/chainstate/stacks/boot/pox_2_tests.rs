use std::collections::{HashMap, VecDeque};
use std::convert::TryFrom;
use std::convert::TryInto;

use address::AddressHashMode;
use chainstate::burn::ConsensusHash;
use chainstate::stacks::boot::{
    BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET,
};
use chainstate::stacks::db::{MinerPaymentSchedule, StacksHeaderInfo, MINER_REWARD_MATURITY};
use chainstate::stacks::index::MarfTrieId;
use chainstate::stacks::*;
use clarity_vm::database::marf::MarfedKV;
use core::*;
use util::db::{DBConn, FromRow};
use util::hash::to_hex;
use util::hash::{Sha256Sum, Sha512Trunc256Sum};
use vm::contexts::OwnedEnvironment;
use vm::contracts::Contract;
use vm::costs::CostOverflowingMath;
use vm::database::*;
use vm::errors::{
    CheckErrors, Error, IncomparableError, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use vm::eval;
use vm::representations::SymbolicExpression;
use vm::tests::{execute, is_committed, is_err_code, symbols_from_values};
use vm::types::Value::Response;
use vm::types::{
    OptionalData, PrincipalData, QualifiedContractIdentifier, ResponseData, StandardPrincipalData,
    TupleData, TupleTypeSignature, TypeSignature, Value, NONE,
};

use crate::{
    burnchains::Burnchain,
    chainstate::{
        burn::db::sortdb::SortitionDB,
        stacks::{events::TransactionOrigin, miner::test::make_coinbase},
    },
    clarity_vm::{clarity::ClarityBlockConnection, database::marf::WritableMarfStore},
    net::test::TestEventObserver,
    util::boot::boot_code_id,
};
use types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, VRFSeed,
};
use types::proof::{ClarityMarfTrieId, TrieMerkleProof};

use clarity_vm::clarity::Error as ClarityError;

use super::test::*;

const USTX_PER_HOLDER: u128 = 1_000_000;

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
#[test]
fn test_simple_pox_lockup_transition_pox_2() {
    let AUTO_UNLOCK_HEIGHT = 12;
    let EXPECTED_FIRST_V2_CYCLE = 8;
    // the sim environment produces 25 empty sortitions before
    //  tenures start being tracked.
    let EMPTY_SORTITIONS = 25;

    let mut burnchain = Burnchain::default_unittest(0, &BurnchainHeaderHash::zero());
    burnchain.pox_constants.reward_cycle_length = 5;
    burnchain.pox_constants.prepare_length = 2;
    burnchain.pox_constants.anchor_threshold = 1;
    burnchain.pox_constants.v1_unlock_height = AUTO_UNLOCK_HEIGHT + EMPTY_SORTITIONS;

    let first_v2_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.v1_unlock_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    eprintln!("First v2 cycle = {}", first_v2_cycle);

    let epochs = StacksEpoch::all(0, EMPTY_SORTITIONS as u64 + 10);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        "test_simple_pox_lockup_transition_pox_2",
        6002,
        Some(epochs.clone()),
        Some(&observer),
    );

    let num_blocks = 35;

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let charlie = keys.pop().unwrap();

    let EXPECTED_ALICE_REWARD_CYCLE = 6;

    let mut coinbase_nonce = 0;

    // these checks are very repetitive
    let reward_cycle_checks = |tip_index_block| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) =
            with_sortdb(&mut peer, |ref mut c, ref sortdb| {
                (
                    c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                    get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block)
                        .unwrap(),
                    c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                        .unwrap(),
                )
            });

        eprintln!(
            "\nreward cycle: {}\nmin-uSTX: {}\naddrs: {:?}\ntotal-stacked: {}\n",
            cur_reward_cycle, min_ustx, &reward_addrs, total_stacked
        );

        if cur_reward_cycle < EXPECTED_ALICE_REWARD_CYCLE {
            // no reward addresses yet
            assert_eq!(reward_addrs.len(), 0);
        } else if cur_reward_cycle < EXPECTED_FIRST_V2_CYCLE as u128 {
            // After the start of Alice's first cycle, but before the first V2 cycle,
            //  Alice is the only Stacker, so check that.
            let (amount_ustx, pox_addr, lock_period, first_reward_cycle) =
                get_stacker_info(&mut peer, &key_to_stacks_addr(&alice).into()).unwrap();
            eprintln!("\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n", amount_ustx, lock_period, &pox_addr, first_reward_cycle);

            // one reward address, and it's Alice's
            // either way, there's a single reward address
            assert_eq!(reward_addrs.len(), 1);
            assert_eq!(
                (reward_addrs[0].0).version,
                AddressHashMode::SerializeP2PKH.to_version_testnet()
            );
            assert_eq!((reward_addrs[0].0).bytes, key_to_stacks_addr(&alice).bytes);
            assert_eq!(reward_addrs[0].1, 1024 * POX_THRESHOLD_STEPS_USTX);
        } else {
            // v2 reward cycles have begun, so reward addrs should be read from PoX2 which is Bob + Alice
            assert_eq!(reward_addrs.len(), 2);
            assert_eq!(
                (reward_addrs[0].0).version,
                AddressHashMode::SerializeP2PKH.to_version_testnet()
            );
            assert_eq!((reward_addrs[0].0).bytes, key_to_stacks_addr(&bob).bytes);
            assert_eq!(reward_addrs[0].1, 512 * POX_THRESHOLD_STEPS_USTX);

            assert_eq!(
                (reward_addrs[1].0).version,
                AddressHashMode::SerializeP2PKH.to_version_testnet()
            );
            assert_eq!((reward_addrs[1].0).bytes, key_to_stacks_addr(&alice).bytes);
            assert_eq!(reward_addrs[1].1, 512 * POX_THRESHOLD_STEPS_USTX);
        }
    };

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
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();
    let alice_lockup = make_pox_lockup(
        &alice,
        0,
        1024 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        4,
        tip.block_height,
    );
    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(min_ustx, total_liquid_ustx / 480);

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |ref mut chainstate, ref sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap() as u128;

    assert_eq!(alice_reward_cycle, EXPECTED_ALICE_REWARD_CYCLE);

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // produce blocks until immediately before the epoch switch (7 more blocks to block height 35)

    for _i in 0..7 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);

        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
    }

    // now, try to use PoX 2 contract. this should _fail_.
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();
    assert_eq!(tip.block_height, 9 + EMPTY_SORTITIONS as u64);
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
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
        6,
        tip.block_height,
    );

    peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    // alice is still locked, balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    // Now, Bob tries to lock in PoX v1 too, but it shouldn't work!
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

    let bob_lockup = make_pox_lockup(
        &bob,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&bob).bytes,
        4,
        tip.block_height,
    );

    peer.tenure_with_txs(&[bob_lockup], &mut coinbase_nonce);

    // One more empty tenure to reach the unlock height
    peer.tenure_with_txs(&[], &mut coinbase_nonce);

    // Auto unlock height is reached, Alice balance should be unlocked
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 1024 * POX_THRESHOLD_STEPS_USTX);

    // At this point, the auto unlock height for v1 accounts should be reached.
    //  let Alice stack in PoX v2
    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();

    assert_eq!(tip.block_height, 13 + EMPTY_SORTITIONS as u64);

    let alice_lockup = make_pox_2_lockup(
        &alice,
        1,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );
    peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // Alice locked half her balance in PoX 2
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now, let's roll the chain forward until Alice *would* have unlocked in v1 anyways.
    //  that's block height 31, so play 27 empty blocks

    for _i in 0..17 {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should always include this half lockup
        assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    let tip =
        SortitionDB::get_canonical_burn_chain_tip(&peer.sortdb.as_ref().unwrap().conn()).unwrap();
    assert_eq!(tip.block_height, 31 + EMPTY_SORTITIONS as u64);
    let alice_lockup = make_pox_lockup(
        &alice,
        2,
        512 * POX_THRESHOLD_STEPS_USTX,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        12,
        tip.block_height,
    );
    peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    assert_eq!(alice_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    eprintln!("Alice addr: {}", alice_address);
    eprintln!("Bob addr: {}", bob_address);

    let mut tested_charlie = false;

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                eprintln!("TX addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == key_to_stacks_addr(&charlie) {
                    assert!(
                        r.execution_cost != ExecutionCost::zero(),
                        "Execution cost is not zero!"
                    );
                    tested_charlie = true;
                }
            }
        }
    }

    assert!(tested_charlie, "Charlie TX must be tested");
    assert_eq!(alice_txs.len(), 3, "Alice should have 3 confirmed txs");
    assert_eq!(bob_txs.len(), 2, "Bob should have 2 confirmed txs");

    assert!(
        match alice_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx0 should have committed okay"
    );

    assert!(
        match alice_txs.get(&1).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Alice tx1 should have committed okay"
    );

    assert_eq!(
        alice_txs.get(&2).unwrap().result,
        Value::err_none(),
        "Alice tx2 should have resulted in a runtime error"
    );

    assert!(
        match bob_txs.get(&0).unwrap().result {
            Value::Response(ref r) => r.committed,
            _ => false,
        },
        "Bob tx0 should have committed okay"
    );

    assert_eq!(
        bob_txs.get(&1).unwrap().result,
        Value::err_none(),
        "Bob tx1 should have resulted in a runtime error"
    );
}
