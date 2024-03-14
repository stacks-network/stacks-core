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

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};

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
use stacks_common::util::secp256k1::{Secp256k1PrivateKey, Secp256k1PublicKey};
use wsts::curve::point::{Compressed, Point};

use super::test::*;
use super::RawRewardSetEntry;
use crate::burnchains::{Burnchain, PoxConstants};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::operations::*;
use crate::chainstate::burn::{BlockSnapshot, ConsensusHash};
use crate::chainstate::stacks::address::{PoxAddress, PoxAddressType20, PoxAddressType32};
use crate::chainstate::stacks::boot::pox_2_tests::{
    check_pox_print_event, generate_pox_clarity_value, get_reward_set_entries_at,
    get_stacking_state_pox, get_stx_account_at, with_clarity_db_ro, PoxPrintFields,
    StackingStateCheckData,
};
use crate::chainstate::stacks::boot::{
    BOOT_CODE_COST_VOTING_TESTNET as BOOT_CODE_COST_VOTING, BOOT_CODE_POX_TESTNET, POX_2_NAME,
    POX_3_NAME,
};
use crate::chainstate::stacks::db::{
    MinerPaymentSchedule, StacksChainState, StacksHeaderInfo, MINER_REWARD_MATURITY,
};
use crate::chainstate::stacks::events::{StacksTransactionReceipt, TransactionOrigin};
use crate::chainstate::stacks::index::marf::MarfConnection;
use crate::chainstate::stacks::index::MarfTrieId;
use crate::chainstate::stacks::tests::make_coinbase;
use crate::chainstate::stacks::*;
use crate::clarity_vm::clarity::{ClarityBlockConnection, Error as ClarityError};
use crate::clarity_vm::database::marf::{MarfedKV, WritableMarfStore};
use crate::clarity_vm::database::HeadersDBConn;
use crate::core::*;
use crate::net::test::{TestEventObserver, TestPeer};
use crate::util_lib::boot::boot_code_id;
use crate::util_lib::db::{DBConn, FromRow};

const USTX_PER_HOLDER: u128 = 1_000_000;

const ERR_REUSED_SIGNER_KEY: i128 = 33;

/// Return the BlockSnapshot for the latest sortition in the provided
///  SortitionDB option-reference. Panics on any errors.
pub fn get_tip(sortdb: Option<&SortitionDB>) -> BlockSnapshot {
    SortitionDB::get_canonical_burn_chain_tip(&sortdb.unwrap().conn()).unwrap()
}

pub fn make_test_epochs_pox() -> (Vec<StacksEpoch>, PoxConstants) {
    let EMPTY_SORTITIONS = 25;
    let EPOCH_2_1_HEIGHT = EMPTY_SORTITIONS + 11; // 36
    let EPOCH_2_2_HEIGHT = EPOCH_2_1_HEIGHT + 14; // 50
    let EPOCH_2_3_HEIGHT = EPOCH_2_2_HEIGHT + 2; // 52
                                                 // epoch-2.4 will start at the first block of cycle 11!
                                                 //  this means that cycle 11 should also be treated like a "burn"
    let EPOCH_2_4_HEIGHT = EPOCH_2_3_HEIGHT + 4; // 56
    let EPOCH_2_5_HEIGHT = EPOCH_2_4_HEIGHT + 44; // 100

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
            end_height: EPOCH_2_1_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_05,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch21,
            start_height: EPOCH_2_1_HEIGHT,
            end_height: EPOCH_2_2_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_1,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch22,
            start_height: EPOCH_2_2_HEIGHT,
            end_height: EPOCH_2_3_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_2,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch23,
            start_height: EPOCH_2_3_HEIGHT,
            end_height: EPOCH_2_4_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_3,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch24,
            start_height: EPOCH_2_4_HEIGHT,
            end_height: EPOCH_2_5_HEIGHT,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_4,
        },
        StacksEpoch {
            epoch_id: StacksEpochId::Epoch25,
            start_height: EPOCH_2_5_HEIGHT,
            end_height: STACKS_EPOCH_MAX,
            block_limit: ExecutionCost::max_value(),
            network_epoch: PEER_VERSION_EPOCH_2_5,
        },
    ];

    let mut pox_constants = PoxConstants::mainnet_default();
    pox_constants.reward_cycle_length = 5;
    pox_constants.prepare_length = 2;
    pox_constants.anchor_threshold = 1;
    pox_constants.v1_unlock_height = (EPOCH_2_1_HEIGHT + 1) as u32;
    pox_constants.v2_unlock_height = (EPOCH_2_2_HEIGHT + 1) as u32;
    pox_constants.v3_unlock_height = (EPOCH_2_5_HEIGHT + 1) as u32;
    pox_constants.pox_3_activation_height = (EPOCH_2_4_HEIGHT + 1) as u32;
    // Activate pox4 2 cycles into epoch 2.5
    // Don't use Epoch 3.0 in order to avoid nakamoto blocks
    pox_constants.pox_4_activation_height =
        (EPOCH_2_5_HEIGHT as u32) + 1 + (2 * pox_constants.reward_cycle_length);

    (epochs, pox_constants)
}

#[test]
fn pox_extend_transition() {
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

    let first_v4_cycle = burnchain
        .block_height_to_reward_cycle(burnchain.pox_constants.pox_4_activation_height as u64)
        .unwrap()
        + 1;

    assert_eq!(first_v2_cycle, EXPECTED_FIRST_V2_CYCLE);

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    peer.config.check_pox_invariants =
        Some((EXPECTED_FIRST_V2_CYCLE, EXPECTED_FIRST_V2_CYCLE + 10));

    let alice = keys.pop().unwrap();
    let bob = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());

    let EXPECTED_ALICE_FIRST_REWARD_CYCLE = 6;
    let mut coinbase_nonce = 0;

    let INITIAL_BALANCE = 1024 * POX_THRESHOLD_STEPS_USTX;
    let ALICE_LOCKUP = 1024 * POX_THRESHOLD_STEPS_USTX;
    let BOB_LOCKUP = 512 * POX_THRESHOLD_STEPS_USTX;

    // these checks should pass between Alice's first reward cycle,
    //  and the start of V2 reward cycles
    let alice_rewards_to_v2_start_checks = |tip_index_block, peer: &mut TestPeer| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) = with_sortdb(peer, |ref mut c, ref sortdb| {
            (
                c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block).unwrap(),
                c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                    .unwrap(),
            )
        });

        assert!(
            cur_reward_cycle >= EXPECTED_ALICE_FIRST_REWARD_CYCLE
                && cur_reward_cycle < first_v2_cycle as u128
        );
        //  Alice is the only Stacker, so check that.
        let (amount_ustx, pox_addr, lock_period, first_reward_cycle) =
            get_stacker_info(peer, &key_to_stacks_addr(&alice).into()).unwrap();
        eprintln!(
            "\nAlice: {} uSTX stacked for {} cycle(s); addr is {:?}; first reward cycle is {}\n",
            amount_ustx, lock_period, &pox_addr, first_reward_cycle
        );

        // one reward address, and it's Alice's
        // either way, there's a single reward address
        assert_eq!(reward_addrs.len(), 1);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[0].0).hash160(),
            key_to_stacks_addr(&alice).bytes
        );
        assert_eq!(reward_addrs[0].1, ALICE_LOCKUP);
    };

    // these checks should pass after the start of V2 reward cycles
    let v2_rewards_checks = |tip_index_block, peer: &mut TestPeer| {
        let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
        let cur_reward_cycle = burnchain
            .block_height_to_reward_cycle(tip_burn_block_height)
            .unwrap() as u128;
        let (min_ustx, reward_addrs, total_stacked) = with_sortdb(peer, |ref mut c, ref sortdb| {
            (
                c.get_stacking_minimum(sortdb, &tip_index_block).unwrap(),
                get_reward_addresses_with_par_tip(c, &burnchain, sortdb, &tip_index_block).unwrap(),
                c.test_get_total_ustx_stacked(sortdb, &tip_index_block, cur_reward_cycle)
                    .unwrap(),
            )
        });

        eprintln!(
            "reward_cycle = {}, reward_addrs = {}, total_stacked = {}",
            cur_reward_cycle,
            reward_addrs.len(),
            total_stacked
        );

        assert!(cur_reward_cycle >= first_v2_cycle as u128);
        // v2 reward cycles have begun, so reward addrs should be read from PoX2 which is Bob + Alice
        assert_eq!(reward_addrs.len(), 2);
        assert_eq!(
            (reward_addrs[0].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[0].0).hash160(),
            key_to_stacks_addr(&bob).bytes
        );
        assert_eq!(reward_addrs[0].1, BOB_LOCKUP);

        assert_eq!(
            (reward_addrs[1].0).version(),
            AddressHashMode::SerializeP2PKH as u8
        );
        assert_eq!(
            (reward_addrs[1].0).hash160(),
            key_to_stacks_addr(&alice).bytes
        );
        assert_eq!(reward_addrs[1].1, ALICE_LOCKUP);
    };

    // first tenure is empty
    let mut latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);

    let alice_account = get_account(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_account.stx_balance.amount_unlocked(), INITIAL_BALANCE);
    assert_eq!(alice_account.stx_balance.amount_locked(), 0);
    assert_eq!(alice_account.stx_balance.unlock_height(), 0);

    // next tenure include Alice's lockup
    let tip = get_tip(peer.sortdb.as_ref());
    let alice_lockup = make_pox_lockup(
        &alice,
        0,
        ALICE_LOCKUP,
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(&alice).bytes,
        4,
        tip.block_height,
    );

    let tip_index_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    // check the stacking minimum
    let total_liquid_ustx = get_liquid_ustx(&mut peer);
    let min_ustx = with_sortdb(&mut peer, |chainstate, sortdb| {
        chainstate.get_stacking_minimum(sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(
        min_ustx,
        total_liquid_ustx / POX_TESTNET_STACKING_THRESHOLD_25
    );

    // no reward addresses
    let reward_addrs = with_sortdb(&mut peer, |chainstate, sortdb| {
        get_reward_addresses_with_par_tip(chainstate, &burnchain, sortdb, &tip_index_block)
    })
    .unwrap();
    assert_eq!(reward_addrs.len(), 0);

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &tip_index_block);
    let alice_first_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap();

    assert_eq!(
        alice_first_reward_cycle as u128,
        EXPECTED_ALICE_FIRST_REWARD_CYCLE
    );
    let height_target = burnchain.reward_cycle_to_block_height(alice_first_reward_cycle) + 1;

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);

    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // produce blocks until epoch 2.1
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[3].start_height {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
        alice_rewards_to_v2_start_checks(latest_block, &mut peer);
    }

    // in the next tenure, PoX 2 should now exist.
    // Lets have Bob lock up for v2
    // this will lock for cycles 8, 9, 10
    //  the first v2 cycle will be 8
    let tip = get_tip(peer.sortdb.as_ref());

    let bob_lockup = make_pox_2_lockup(
        &bob,
        0,
        BOB_LOCKUP,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        3,
        tip.block_height,
    );

    // Alice _will_ auto-unlock: she can stack-extend in PoX v2
    let alice_lockup = make_pox_2_extend(
        &alice,
        1,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
    );

    latest_block = peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);
    alice_rewards_to_v2_start_checks(latest_block, &mut peer);

    // Extend bob's lockup via `stack-extend` for 1 more cycle
    let bob_extend = make_pox_2_extend(
        &bob,
        1,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        1,
    );

    latest_block = peer.tenure_with_txs(&[bob_extend], &mut coinbase_nonce);

    alice_rewards_to_v2_start_checks(latest_block, &mut peer);

    // produce blocks until the v2 reward cycles start
    let height_target = burnchain.reward_cycle_to_block_height(first_v2_cycle) - 1;
    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // alice is still locked, balance should be 0
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);

        alice_rewards_to_v2_start_checks(latest_block, &mut peer);
    }

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    v2_rewards_checks(latest_block, &mut peer);

    // roll the chain forward until just before Epoch-2.2
    while get_tip(peer.sortdb.as_ref()).block_height < epochs[4].start_height {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // at this point, alice's balance should be locked, and so should bob's
        let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
        assert_eq!(alice_balance, 0);
        let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
        assert_eq!(bob_balance, 512 * POX_THRESHOLD_STEPS_USTX);
    }

    // this block is mined in epoch-2.2
    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_balance = get_balance(&mut peer, &key_to_stacks_addr(&alice).into());
    assert_eq!(alice_balance, 0);
    let bob_balance = get_balance(&mut peer, &key_to_stacks_addr(&bob).into());
    assert_eq!(bob_balance, 512 * POX_THRESHOLD_STEPS_USTX);

    // this block should unlock alice and bob's balance

    latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    let alice_account = get_stx_account_at(&mut peer, &latest_block, &alice_principal);
    let bob_account = get_stx_account_at(&mut peer, &latest_block, &bob_principal);
    assert_eq!(alice_account.amount_locked(), 0);
    assert_eq!(alice_account.amount_unlocked(), INITIAL_BALANCE);
    assert_eq!(bob_account.amount_locked(), 0);
    assert_eq!(bob_account.amount_unlocked(), INITIAL_BALANCE);

    // Roll to pox4 activation and re-do the above stack-extend tests
    while get_tip(peer.sortdb.as_ref()).block_height
        < u64::from(burnchain.pox_constants.pox_4_activation_height)
    {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let tip = get_tip(peer.sortdb.as_ref());
    let alice_lockup = make_pox_4_lockup(
        &alice,
        2,
        ALICE_LOCKUP,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        4,
        StacksPublicKey::default(),
        tip.block_height,
    );
    let alice_pox_4_lock_nonce = 2;
    let alice_first_pox_4_unlock_height =
        burnchain.reward_cycle_to_block_height(first_v4_cycle + 4) - 1;
    let alice_pox_4_start_burn_height = tip.block_height;

    latest_block = peer.tenure_with_txs(&[alice_lockup], &mut coinbase_nonce);

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v4_cycle..(first_v4_cycle + 4) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);

        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP,);
    }

    // check the first reward cycle when Alice's tokens get stacked
    let tip_burn_block_height = get_par_burn_block_height(peer.chainstate(), &latest_block);
    let alice_first_v4_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(tip_burn_block_height)
        .unwrap();

    let height_target = burnchain.reward_cycle_to_block_height(alice_first_v4_reward_cycle) + 1;

    // alice locked, so balance should be 0
    let alice_balance = get_balance(&mut peer, &alice_principal);
    assert_eq!(alice_balance, 0);

    // advance to the first v3 reward cycle
    while get_tip(peer.sortdb.as_ref()).block_height < height_target {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let bob_signer_key: [u8; 33] = [
        0x02, 0xb6, 0x19, 0x6d, 0xe8, 0x8b, 0xce, 0xe7, 0x93, 0xfa, 0x9a, 0x8a, 0x85, 0x96, 0x9b,
        0x64, 0x7f, 0x84, 0xc9, 0x0e, 0x9d, 0x13, 0xf9, 0xc8, 0xb8, 0xce, 0x42, 0x6c, 0xc8, 0x1a,
        0x59, 0x98, 0x3c,
    ];
    let alice_signer_key: [u8; 33] = [
        0x03, 0xa0, 0xf9, 0x81, 0x8e, 0xa8, 0xc1, 0x4a, 0x82, 0x7b, 0xb1, 0x44, 0xae, 0xc9, 0xcf,
        0xba, 0xeb, 0xa2, 0x25, 0xaf, 0x22, 0xbe, 0x18, 0xed, 0x78, 0xa2, 0xf2, 0x98, 0x10, 0x6f,
        0x4e, 0x28, 0x1b,
    ];

    let tip = get_tip(peer.sortdb.as_ref());
    let bob_lockup = make_pox_4_lockup(
        &bob,
        2,
        BOB_LOCKUP,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&bob).bytes,
        ),
        3,
        StacksPublicKey::from_slice(&bob_signer_key).unwrap(),
        tip.block_height,
    );

    // Alice can stack-extend in PoX v2
    let alice_lockup = make_pox_4_extend(
        &alice,
        3,
        PoxAddress::from_legacy(
            AddressHashMode::SerializeP2PKH,
            key_to_stacks_addr(&alice).bytes,
        ),
        6,
        StacksPublicKey::from_slice(&alice_signer_key).unwrap(),
    );

    let alice_pox_4_extend_nonce = 3;
    let alice_extend_pox_4_unlock_height =
        burnchain.reward_cycle_to_block_height(first_v4_cycle + 10) - 1;

    latest_block = peer.tenure_with_txs(&[bob_lockup, alice_lockup], &mut coinbase_nonce);

    // check that the "raw" reward set will contain entries for alice at the cycle start
    for cycle_number in first_v4_cycle..(first_v4_cycle + 1) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP);
    }

    for cycle_number in (first_v4_cycle + 1)..(first_v4_cycle + 4) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);
        assert_eq!(reward_set_entries.len(), 2);
        assert_eq!(
            reward_set_entries[1].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[1].amount_stacked, ALICE_LOCKUP);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&bob).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, BOB_LOCKUP);
    }

    for cycle_number in (first_v4_cycle + 4)..(first_v4_cycle + 10) {
        let cycle_start = burnchain.reward_cycle_to_block_height(cycle_number);
        let reward_set_entries = get_reward_set_entries_at(&mut peer, &latest_block, cycle_start);

        assert_eq!(reward_set_entries.len(), 1);
        assert_eq!(
            reward_set_entries[0].reward_address.bytes(),
            key_to_stacks_addr(&alice).bytes.0.to_vec()
        );
        assert_eq!(reward_set_entries[0].amount_stacked, ALICE_LOCKUP);
    }

    // now let's check some tx receipts

    let alice_address = key_to_stacks_addr(&alice);
    let bob_address = key_to_stacks_addr(&bob);
    let blocks = observer.get_blocks();

    let mut alice_txs = HashMap::new();
    let mut bob_txs = HashMap::new();

    for b in blocks.into_iter() {
        for r in b.receipts.into_iter() {
            if let TransactionOrigin::Stacks(ref t) = r.transaction {
                let addr = t.auth.origin().address_testnet();
                eprintln!("TX addr: {}", addr);
                if addr == alice_address {
                    alice_txs.insert(t.auth.get_origin_nonce(), r);
                } else if addr == bob_address {
                    bob_txs.insert(t.auth.get_origin_nonce(), r);
                }
            }
        }
    }

    assert_eq!(alice_txs.len(), 4);
    assert_eq!(bob_txs.len(), 3);

    for tx in alice_txs.iter() {
        assert!(
            if let Value::Response(ref r) = tx.1.result {
                r.committed
            } else {
                false
            },
            "Alice txs should all have committed okay"
        );
    }

    for tx in bob_txs.iter() {
        assert!(
            if let Value::Response(ref r) = tx.1.result {
                r.committed
            } else {
                false
            },
            "Bob txs should all have committed okay"
        );
    }

    // Check that the call to `stack-stx` has a well-formed print event.
    let stack_tx = &alice_txs
        .get(&alice_pox_4_lock_nonce)
        .unwrap()
        .clone()
        .events[0];
    let pox_addr_val = generate_pox_clarity_value("ae1593226f85e49a7eaff5b633ff687695438cc9");
    let stack_op_data = HashMap::from([
        ("lock-amount", Value::UInt(ALICE_LOCKUP)),
        (
            "unlock-burn-height",
            Value::UInt(alice_first_pox_4_unlock_height.into()),
        ),
        (
            "start-burn-height",
            Value::UInt(alice_pox_4_start_burn_height.into()),
        ),
        ("pox-addr", pox_addr_val.clone()),
        ("lock-period", Value::UInt(4)),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-stx".to_string(),
        stacker: Value::Principal(alice_principal.clone()),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(stack_tx, common_data, stack_op_data);

    // Check that the call to `stack-extend` has a well-formed print event.
    let stack_extend_tx = &alice_txs
        .get(&alice_pox_4_extend_nonce)
        .unwrap()
        .clone()
        .events[0];
    let stack_ext_op_data = HashMap::from([
        ("extend-count", Value::UInt(6)),
        ("pox-addr", pox_addr_val),
        (
            "unlock-burn-height",
            Value::UInt(alice_extend_pox_4_unlock_height.into()),
        ),
    ]);
    let common_data = PoxPrintFields {
        op_name: "stack-extend".to_string(),
        stacker: Value::Principal(alice_principal.clone()),
        balance: Value::UInt(0),
        locked: Value::UInt(ALICE_LOCKUP),
        burnchain_unlock_height: Value::UInt(alice_first_pox_4_unlock_height.into()),
    };
    check_pox_print_event(stack_extend_tx, common_data, stack_ext_op_data);
}

fn get_burn_pox_addr_info(peer: &mut TestPeer) -> (Vec<PoxAddress>, u128) {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;
    let addrs_and_payout = with_sortdb(peer, |ref mut chainstate, ref mut sortdb| {
        let addrs = chainstate
            .maybe_read_only_clarity_tx(&sortdb.index_conn(), &tip_index_block, |clarity_tx| {
                clarity_tx
                    .with_readonly_clarity_env(
                        false,
                        0x80000000,
                        ClarityVersion::Clarity2,
                        PrincipalData::Standard(StandardPrincipalData::transient()),
                        None,
                        LimitedCostTracker::new_free(),
                        |env| {
                            env.eval_read_only(
                                &boot_code_id("pox-2", false),
                                &format!("(get-burn-block-info? pox-addrs u{})", &burn_height),
                            )
                        },
                    )
                    .unwrap()
            })
            .unwrap();
        addrs
    })
    .unwrap()
    .expect_optional()
    .unwrap()
    .unwrap()
    .expect_tuple()
    .unwrap();

    let addrs = addrs_and_payout
        .get("addrs")
        .unwrap()
        .to_owned()
        .expect_list()
        .unwrap()
        .into_iter()
        .map(|tuple| PoxAddress::try_from_pox_tuple(false, &tuple).unwrap())
        .collect();

    let payout = addrs_and_payout
        .get("payout")
        .unwrap()
        .to_owned()
        .expect_u128()
        .unwrap();
    (addrs, payout)
}

/// Test that we can lock STX for a couple cycles after pox4 starts,
/// and that it unlocks after the desired number of cycles
#[test]
fn pox_lock_unlock() {
    // Config for this test
    // We are going to try locking for 2 reward cycles (10 blocks)
    let lock_period = 2;
    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, function_name!(), Some(epochs.clone()), None);

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[3].start_height {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .enumerate()
        .map(|(ix, (key, hash_mode))| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            let lock_period = if ix == 3 { 12 } else { lock_period };
            txs.push(make_pox_4_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr.clone(),
                lock_period,
                StacksPublicKey::default(),
                tip_height,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs");
    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // Advance to start of rewards cycle stackers are participating in
    let target_height = burnchain.pox_constants.pox_4_activation_height + 5;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;
    let mut rewarded = HashSet::new();

    // Check that STX are locked for 2 reward cycles
    for _ in 0..lock_period {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert!(balances[0].amount_locked() > 0);
        assert!(balances[1].amount_locked() > 0);
        assert!(balances[2].amount_locked() > 0);
        assert!(balances[3].amount_locked() > 0);

        info!("Checking we have 2 stackers for cycle {cycle}");
        for i in 0..reward_blocks {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // only the first 2 reward blocks contain pox outputs, because there are 6 slots and only 4 are occuppied
            if i < 2 {
                assert_latest_was_pox(&mut peer)
                    .into_iter()
                    .filter(|addr| !addr.is_burn())
                    .for_each(|addr| {
                        rewarded.insert(addr);
                    });
            } else {
                assert_latest_was_burn(&mut peer);
            }
        }

        assert_eq!(rewarded.len(), 4);
        for stacker in stackers.iter() {
            assert!(
                rewarded.contains(stacker),
                "Reward cycle should include {stacker}"
            );
        }

        // now we should be back in a prepare phase
        info!("Checking we are in prepare phase");
        for _ in 0..burnchain.pox_constants.prepare_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }
    }

    info!("Checking STX unlocked after {lock_period} cycles");
    let mut rewarded = HashSet::new();
    for i in 0..burnchain.pox_constants.reward_cycle_length {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // only 1 entry in reward set now, but they get 5 slots -- so that's 3 blocks
        info!("Checking {i}th block of next reward cycle");
        if i < 3 {
            assert_latest_was_pox(&mut peer)
                .into_iter()
                .filter(|addr| !addr.is_burn())
                .for_each(|addr| {
                    rewarded.insert(addr);
                });
        } else {
            assert_latest_was_burn(&mut peer);
        }
    }

    assert_eq!(rewarded.len(), 1);
    assert!(
        rewarded.contains(&stackers[3]),
        "Reward set should include the index-3 stacker"
    );

    info!("Checking that stackers[0..2] have no STX locked");
    let balances = balances_from_keys(&mut peer, &latest_block, &keys);
    assert_eq!(balances[0].amount_locked(), 0);
    assert_eq!(balances[1].amount_locked(), 0);
    assert_eq!(balances[2].amount_locked(), 0);
}

/// Test that pox3 methods fail once pox4 is activated
#[test]
fn pox_3_defunct() {
    // Config for this test
    // We are going to try locking for 2 reward cycles (10 blocks)
    let lock_period = 2;
    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[3].start_height {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .map(|(key, hash_mode)| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            txs.push(make_pox_3_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr.clone(),
                lock_period,
                tip_height,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs with pox3");
    latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    info!("Checking that stackers have no STX locked");
    let balances = balances_from_keys(&mut peer, &latest_block, &keys);
    assert_eq!(balances[0].amount_locked(), 0);
    assert_eq!(balances[1].amount_locked(), 0);

    info!("Checking tx receipts, all `pox3` calls should have returned `(err none)`");
    let last_observer_block = observer.get_blocks().last().unwrap().clone();

    let receipts = last_observer_block
        .receipts
        .iter()
        .filter(|receipt| match &receipt.result {
            Value::Response(r) => !r.committed,
            _ => false,
        })
        .collect::<Vec<_>>();

    assert_eq!(receipts.len(), txs.len());
    for r in receipts.iter() {
        let err = r
            .result
            .clone()
            .expect_result_err()
            .unwrap()
            .expect_optional()
            .unwrap();
        assert!(err.is_none());
    }

    // Advance to start of rewards cycle stackers are participating in
    let target_height = burnchain.pox_constants.pox_4_activation_height + 5;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;

    // Check next 3 reward cycles
    for _ in 0..=lock_period {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have no STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert_eq!(balances[0].amount_locked(), 0);
        assert_eq!(balances[1].amount_locked(), 0);

        info!("Checking no stackers for cycle {cycle}");
        for _ in 0..burnchain.pox_constants.reward_cycle_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // Should all be burn because no stackers
            assert_latest_was_burn(&mut peer);
        }
    }
}

// Test that STX locked in pox3 automatically unlocks at `v3_unlock_height`
#[test]
fn pox_3_unlocks() {
    // Config for this test
    // We are going to try locking for 4 reward cycles (20 blocks)
    let lock_period = 4;
    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let (mut peer, keys) =
        instantiate_pox_peer_with_epoch(&burnchain, function_name!(), Some(epochs.clone()), None);

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block;

    // Advance to a few blocks before pox 3 unlock
    let target_height = burnchain.pox_constants.v3_unlock_height - 14;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
        // if we reach epoch 2.1, perform the check
        if get_tip(peer.sortdb.as_ref()).block_height > epochs[3].start_height {
            assert_latest_was_burn(&mut peer);
        }
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    let mut txs = vec![];
    let tip_height = get_tip(peer.sortdb.as_ref()).block_height;
    let stackers: Vec<_> = keys
        .iter()
        .zip([
            AddressHashMode::SerializeP2PKH,
            AddressHashMode::SerializeP2SH,
            AddressHashMode::SerializeP2WPKH,
            AddressHashMode::SerializeP2WSH,
        ])
        .map(|(key, hash_mode)| {
            let pox_addr = PoxAddress::from_legacy(hash_mode, key_to_stacks_addr(key).bytes);
            txs.push(make_pox_3_lockup(
                key,
                0,
                1024 * POX_THRESHOLD_STEPS_USTX,
                pox_addr.clone(),
                lock_period,
                tip_height,
            ));
            pox_addr
        })
        .collect();

    info!("Submitting stacking txs");
    latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    // Advance a couple more blocks
    for _ in 0..3 {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    // now we should be in the reward phase, produce the reward blocks
    let reward_blocks =
        burnchain.pox_constants.reward_cycle_length - burnchain.pox_constants.prepare_length;
    let mut rewarded = HashSet::new();

    // Check that STX are locked for 2 reward cycles
    for _ in 0..2 {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking that stackers have STX locked for cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert!(balances[0].amount_locked() > 0);
        assert!(balances[1].amount_locked() > 0);

        info!("Checking STX locked for cycle {cycle}");
        for i in 0..reward_blocks {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            // only the first 2 reward blocks contain pox outputs, because there are 6 slots and only 4 are occuppied
            if i < 2 {
                assert_latest_was_pox(&mut peer)
                    .into_iter()
                    .filter(|addr| !addr.is_burn())
                    .for_each(|addr| {
                        rewarded.insert(addr);
                    });
            } else {
                assert_latest_was_burn(&mut peer);
            }
        }

        assert_eq!(rewarded.len(), 4);
        for stacker in stackers.iter() {
            assert!(
                rewarded.contains(stacker),
                "Reward cycle should include {stacker}"
            );
        }

        // now we should be back in a prepare phase
        info!("Checking we are in prepare phase");
        for _ in 0..burnchain.pox_constants.prepare_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }
    }

    // Advance to v3 unlock
    let target_height = burnchain.pox_constants.v3_unlock_height;
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );

    // Check that STX are not locked for 3 reward cycles after pox4 starts
    for _ in 0..3 {
        let tip = get_tip(peer.sortdb.as_ref());
        let cycle = burnchain
            .block_height_to_reward_cycle(tip.block_height)
            .unwrap();

        info!("Checking no stackers for cycle {cycle}");
        for _ in 0..burnchain.pox_constants.reward_cycle_length {
            latest_block = peer.tenure_with_txs(&[], &mut coinbase_nonce);
            assert_latest_was_burn(&mut peer);
        }

        info!("Checking that stackers have no STX locked after cycle {cycle}");
        let balances = balances_from_keys(&mut peer, &latest_block, &keys);
        assert_eq!(balances[0].amount_locked(), 0);
        assert_eq!(balances[1].amount_locked(), 0);
    }
}

// test that revoke-delegate-stx calls emit an event and
// test that revoke-delegate-stx is only successfull if user has delegated.
#[test]
fn pox_4_revoke_delegate_stx_events() {
    // Config for this test
    let (epochs, pox_constants) = make_test_epochs_pox();

    let mut burnchain = Burnchain::default_unittest(
        0,
        &BurnchainHeaderHash::from_hex(BITCOIN_REGTEST_FIRST_BLOCK_HASH).unwrap(),
    );
    burnchain.pox_constants = pox_constants.clone();

    let observer = TestEventObserver::new();

    let (mut peer, mut keys) = instantiate_pox_peer_with_epoch(
        &burnchain,
        function_name!(),
        Some(epochs.clone()),
        Some(&observer),
    );

    assert_eq!(burnchain.pox_constants.reward_slots(), 6);
    let mut coinbase_nonce = 0;
    let mut latest_block = None;

    // alice
    let alice = keys.pop().unwrap();
    let alice_address = key_to_stacks_addr(&alice);
    let alice_principal = PrincipalData::from(alice_address.clone());

    // bob
    let bob = keys.pop().unwrap();
    let bob_address = key_to_stacks_addr(&bob);
    let bob_principal = PrincipalData::from(bob_address.clone());
    let bob_pox_addr = make_pox_addr(AddressHashMode::SerializeP2PKH, bob_address.bytes.clone());

    // steph the solo stacker stacks stx so nakamoto signer set stays stacking.
    let steph = keys.pop().unwrap();
    let steph_address = key_to_stacks_addr(&steph);
    let steph_principal = PrincipalData::from(steph_address.clone());
    let steph_pox_addr =
        make_pox_addr(AddressHashMode::SerializeP2PKH, steph_address.bytes.clone());

    let steph_signing_key = Secp256k1PublicKey::from_private(&steph);
    let steph_key_val = Value::buff_from(steph_signing_key.to_bytes_compressed()).unwrap();

    let mut alice_nonce = 0;

    // Advance into pox4
    let target_height = burnchain.pox_constants.pox_4_activation_height;
    // produce blocks until the first reward phase that everyone should be in
    while get_tip(peer.sortdb.as_ref()).block_height < u64::from(target_height) {
        latest_block = Some(peer.tenure_with_txs(&[], &mut coinbase_nonce));
    }

    info!(
        "Block height: {}",
        get_tip(peer.sortdb.as_ref()).block_height
    );
    let block_height = get_tip(peer.sortdb.as_ref()).block_height;
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block.unwrap());
    let steph_stacking = make_pox_4_contract_call(
        &steph,
        0,
        "stack-stx",
        vec![
            Value::UInt(min_ustx),
            steph_pox_addr,
            Value::UInt(block_height as u128),
            Value::UInt(12),
            steph_key_val,
        ],
    );

    // alice delegates 100 STX to Bob
    let alice_delegation_amount = 100_000_000;
    let alice_delegate = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        alice_delegation_amount,
        bob_principal,
        None,
        None,
    );
    let alice_delegate_nonce = alice_nonce;
    alice_nonce += 1;

    let alice_revoke = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_nonce = alice_nonce;
    alice_nonce += 1;

    let alice_revoke_2 = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_2_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(
        &[steph_stacking, alice_delegate, alice_revoke, alice_revoke_2],
        &mut coinbase_nonce,
    );

    // check delegate with expiry

    let target_height = get_tip(peer.sortdb.as_ref()).block_height + 10;
    let alice_delegate_2 = make_pox_4_delegate_stx(
        &alice,
        alice_nonce,
        alice_delegation_amount,
        PrincipalData::from(bob_address.clone()),
        Some(target_height as u128),
        None,
    );
    let alice_delegate_2_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(&[alice_delegate_2], &mut coinbase_nonce);

    // produce blocks until delegation expired
    while get_tip(peer.sortdb.as_ref()).block_height <= u64::from(target_height) {
        peer.tenure_with_txs(&[], &mut coinbase_nonce);
    }

    let alice_revoke_3 = make_pox_4_revoke_delegate_stx(&alice, alice_nonce);
    let alice_revoke_3_nonce = alice_nonce;
    alice_nonce += 1;

    peer.tenure_with_txs(&[alice_revoke_3], &mut coinbase_nonce);

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
    assert_eq!(alice_txs.len() as u64, 5);

    // check event for first revoke delegation tx
    let revoke_delegation_tx_events = &alice_txs.get(&alice_revoke_nonce).unwrap().clone().events;
    assert_eq!(revoke_delegation_tx_events.len() as u64, 1);
    let revoke_delegation_tx_event = &revoke_delegation_tx_events[0];
    let revoke_delegate_stx_op_data = HashMap::from([(
        "delegate-to",
        Value::Principal(PrincipalData::from(bob_address.clone())),
    )]);
    let common_data = PoxPrintFields {
        op_name: "revoke-delegate-stx".to_string(),
        stacker: alice_principal.clone().into(),
        balance: Value::UInt(10240000000000),
        locked: Value::UInt(0),
        burnchain_unlock_height: Value::UInt(0),
    };
    check_pox_print_event(
        revoke_delegation_tx_event,
        common_data,
        revoke_delegate_stx_op_data,
    );

    // second revoke transaction should fail
    assert_eq!(
        &alice_txs[&alice_revoke_2_nonce].result.to_string(),
        "(err 34)"
    );

    // second delegate transaction should succeed
    assert_eq!(
        &alice_txs[&alice_delegate_2_nonce].result.to_string(),
        "(ok true)"
    );
    // third revoke transaction should fail
    assert_eq!(
        &alice_txs[&alice_revoke_3_nonce].result.to_string(),
        "(err 34)"
    );
}

pub fn assert_latest_was_burn(peer: &mut TestPeer) {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;

    let conn = peer.sortdb().conn();

    // check the *parent* burn block, because that's what we'll be
    //  checking with get_burn_pox_addr_info
    let mut burn_ops =
        SortitionDB::get_block_commits_by_block(conn, &tip.parent_sortition_id).unwrap();
    assert_eq!(burn_ops.len(), 1);
    let commit = burn_ops.pop().unwrap();
    assert!(commit.all_outputs_burn());
    assert!(commit.burn_fee > 0);

    let (addrs, payout) = get_burn_pox_addr_info(peer);
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;
    info!("Checking burn outputs at burn_height = {burn_height}");
    if peer.config.burnchain.is_in_prepare_phase(burn_height) {
        assert_eq!(addrs.len(), 1);
        assert_eq!(payout, 1000);
        assert!(addrs[0].is_burn());
    } else {
        assert_eq!(addrs.len(), 2);
        assert_eq!(payout, 500);
        assert!(addrs[0].is_burn());
        assert!(addrs[1].is_burn());
    }
}

fn assert_latest_was_pox(peer: &mut TestPeer) -> Vec<PoxAddress> {
    let tip = get_tip(peer.sortdb.as_ref());
    let tip_index_block = tip.get_canonical_stacks_block_id();
    let burn_height = tip.block_height - 1;

    let conn = peer.sortdb().conn();

    // check the *parent* burn block, because that's what we'll be
    //  checking with get_burn_pox_addr_info
    let mut burn_ops =
        SortitionDB::get_block_commits_by_block(conn, &tip.parent_sortition_id).unwrap();
    assert_eq!(burn_ops.len(), 1);
    let commit = burn_ops.pop().unwrap();
    assert!(!commit.all_outputs_burn());
    let commit_addrs = commit.commit_outs;

    let (addrs, payout) = get_burn_pox_addr_info(peer);
    info!(
        "Checking pox outputs at burn_height = {burn_height}, commit_addrs = {commit_addrs:?}, fetch_addrs = {addrs:?}"
    );
    assert_eq!(addrs.len(), 2);
    assert_eq!(payout, 500);
    assert!(commit_addrs.contains(&addrs[0]));
    assert!(commit_addrs.contains(&addrs[1]));
    addrs
}

fn balances_from_keys(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    keys: &[Secp256k1PrivateKey],
) -> Vec<STXBalance> {
    keys.iter()
        .map(|key| key_to_stacks_addr(key))
        .map(|addr| PrincipalData::from(addr))
        .map(|principal| get_stx_account_at(peer, tip, &principal))
        .collect()
}

#[test]
fn stack_stx_signer_key() {
    let lock_period = 2;
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), None);

    let stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    // (define-public (stack-stx (amount-ustx uint)
    //                       (pox-addr (tuple (version (buff 1)) (hashbytes (buff 32))))
    //                       (start-burn-ht uint)
    //                       (lock-period uint)
    //                       (signer-key (buff 33)))
    let pox_addr = make_pox_addr(
        AddressHashMode::SerializeP2WSH,
        key_to_stacks_addr(stacker_key).bytes,
    );

    let signer_bytes =
        hex_bytes("03a0f9818ea8c14a827bb144aec9cfbaeba225af22be18ed78a2f298106f4e281b").unwrap();
    let signer_key = Secp256k1PublicKey::from_slice(&signer_bytes).unwrap();
    let signer_key_val = Value::buff_from(signer_bytes.clone()).unwrap();

    let txs = vec![make_pox_4_contract_call(
        stacker_key,
        stacker_nonce,
        "stack-stx",
        vec![
            Value::UInt(min_ustx),
            pox_addr.clone(),
            Value::UInt(block_height as u128),
            Value::UInt(2),
            signer_key_val.clone(),
        ],
    )];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(
        PoxAddress::try_from_pox_tuple(false, &pox_addr).unwrap(),
        reward_entry.reward_address
    );
    assert_eq!(&reward_entry.signer.unwrap(), &signer_bytes.as_slice());
}

#[test]
fn stack_extend_signer_key() {
    let lock_period = 2;
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), None);

    let mut stacker_nonce = 0;
    let stacker_key = &keys[0];
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block) * 2;

    let pox_addr = make_pox_addr(
        AddressHashMode::SerializeP2WSH,
        key_to_stacks_addr(stacker_key).bytes,
    );

    let signer_sk = Secp256k1PrivateKey::from_seed(&[0]);
    let signer_extend_sk = Secp256k1PrivateKey::from_seed(&[1]);

    let signer_key = Secp256k1PublicKey::from_private(&signer_sk);
    let signer_bytes = signer_key.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_bytes.clone()).unwrap();

    let signer_extend_key = Secp256k1PublicKey::from_private(&signer_extend_sk);
    let signer_extend_bytes = signer_extend_key.to_bytes_compressed();
    let signer_extend_key_val = Value::buff_from(signer_extend_bytes.clone()).unwrap();

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let txs = vec![make_pox_4_contract_call(
        stacker_key,
        stacker_nonce,
        "stack-stx",
        vec![
            Value::UInt(min_ustx),
            pox_addr.clone(),
            Value::UInt(block_height as u128),
            Value::UInt(2),
            signer_key_val.clone(),
        ],
    )];

    stacker_nonce += 1;

    let mut latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    // now stack-extend with a new signer-key

    // (define-public (stack-extend (extend-count uint)
    //                          (pox-addr { version: (buff 1), hashbytes: (buff 32) })
    //                          (signer-key (buff 33)))
    let update_txs = vec![make_pox_4_contract_call(
        stacker_key,
        stacker_nonce,
        "stack-extend",
        vec![
            Value::UInt(1),
            pox_addr.clone(),
            signer_extend_key_val.clone(),
        ],
    )];

    latest_block = peer.tenure_with_txs(&update_txs, &mut coinbase_nonce);
    let new_stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .unwrap()
    .expect_tuple();

    let extend_reward_cycle = 2 + next_reward_cycle;
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let extend_cycle_ht = burnchain.reward_cycle_to_block_height(extend_reward_cycle);

    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(
        PoxAddress::try_from_pox_tuple(false, &pox_addr).unwrap(),
        reward_entry.reward_address
    );
    assert_eq!(&reward_entry.signer.unwrap(), signer_bytes.as_slice(),);

    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, extend_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(
        PoxAddress::try_from_pox_tuple(false, &pox_addr).unwrap(),
        reward_entry.reward_address
    );
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_extend_bytes.as_slice(),
    );
}

#[test]
fn delegate_stack_stx_signer_key() {
    let lock_period = 2;
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), None);

    let stacker_nonce = 0;
    let stacker_key = &keys[0];
    let delegate_nonce = 0;
    let delegate_key = &keys[1];
    let delegate_principal = PrincipalData::from(key_to_stacks_addr(delegate_key));

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    // (define-public (delegate-stx (amount-ustx uint)
    //                          (delegate-to principal)
    //                          (until-burn-ht (optional uint))
    //                          (pox-addr (optional { version: (buff 1), hashbytes: (buff 32) })))
    let pox_addr = make_pox_addr(
        AddressHashMode::SerializeP2WSH,
        key_to_stacks_addr(delegate_key).bytes,
    );
    let signer_bytes =
        hex_bytes("03a0f9818ea8c14a827bb144aec9cfbaeba225af22be18ed78a2f298106f4e281b").unwrap();
    let signer_key = Secp256k1PublicKey::from_slice(&signer_bytes).unwrap();
    let signer_key_val = Value::buff_from(signer_bytes.clone()).unwrap();
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);

    let txs = vec![
        make_pox_4_contract_call(
            stacker_key,
            stacker_nonce,
            "delegate-stx",
            vec![
                Value::UInt(min_ustx + 1),
                delegate_principal.clone().into(),
                Value::none(),
                Value::Optional(OptionalData {
                    data: Some(Box::new(pox_addr.clone())),
                }),
            ],
        ),
        make_pox_4_contract_call(
            delegate_key,
            delegate_nonce,
            "delegate-stack-stx",
            vec![
                PrincipalData::from(key_to_stacks_addr(stacker_key)).into(),
                Value::UInt(min_ustx + 1),
                pox_addr.clone(),
                Value::UInt(block_height as u128),
                Value::UInt(lock_period),
            ],
        ),
        make_pox_4_contract_call(
            delegate_key,
            delegate_nonce + 1,
            "stack-aggregation-commit",
            vec![
                pox_addr.clone(),
                Value::UInt(next_reward_cycle.into()),
                signer_key_val.clone(),
            ],
        ),
    ];
    // (define-public (delegate-stack-stx (stacker principal)
    //                                (amount-ustx uint)
    //                                (pox-addr { version: (buff 1), hashbytes: (buff 32) })
    //                                (start-burn-ht uint)
    //                                (lock-period uint)
    //                                (signer-key (buff 33)))

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    let delegation_state = get_delegation_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No delegation state, delegate-stx failed")
    .expect_tuple();

    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(stacker_key).to_account_principal(),
    )
    .expect("No stacking state, delegate-stack-stx failed")
    .expect_tuple();

    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(
        PoxAddress::try_from_pox_tuple(false, &pox_addr).unwrap(),
        reward_entry.reward_address
    );
    assert_eq!(&reward_entry.signer.unwrap(), signer_bytes.as_slice(),);
}

// In this test case, Alice delegates to Bob.
//  Bob then stacks the delegated stx for one cycle with an
//  'old' signer key. The next cycle, Bob extends the delegation
//  & rotates to a 'new' signer key.
//
// This test asserts that the signing key in Alice's stacking state
//  is equal to Bob's 'new' signer key.
#[test]
fn delegate_stack_stx_extend_signer_key() {
    let lock_period: u128 = 2;
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), None);

    let alice_nonce = 0;
    let alice_stacker_key = &keys[0];
    let mut bob_nonce = 0;
    let bob_delegate_private_key = &keys[1];
    let bob_delegate_principal = PrincipalData::from(key_to_stacks_addr(bob_delegate_private_key));

    let signer_sk = Secp256k1PrivateKey::from_seed(&[0]);
    let signer_extend_sk = Secp256k1PrivateKey::from_seed(&[1]);

    let signer_key = Secp256k1PublicKey::from_private(&signer_sk);
    let signer_bytes = signer_key.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_bytes.clone()).unwrap();

    let signer_extend_key = Secp256k1PublicKey::from_private(&signer_extend_sk);
    let signer_extend_bytes = signer_extend_key.to_bytes_compressed();
    let signer_extend_key_val = Value::buff_from(signer_extend_bytes.clone()).unwrap();

    let min_ustx = 2 * get_stacking_minimum(&mut peer, &latest_block);

    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(bob_delegate_private_key).bytes,
    );

    let delegate_stx = make_pox_4_delegate_stx(
        alice_stacker_key,
        alice_nonce,
        min_ustx + 1,
        bob_delegate_principal.clone().into(),
        None,
        Some(pox_addr.clone()),
    );

    let delegate_stack_stx = make_pox_4_delegate_stack_stx(
        bob_delegate_private_key,
        bob_nonce,
        key_to_stacks_addr(alice_stacker_key).into(),
        min_ustx + 1,
        pox_addr.clone(),
        block_height as u128,
        lock_period,
    );

    // Initial txs arr includes initial delegate_stx & delegate_stack_stx
    // Both are pox_4 helpers found in mod.rs
    let txs = vec![delegate_stx, delegate_stack_stx];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    let delegation_state = get_delegation_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacker_key).into(),
    )
    .expect("No delegation state, delegate-stx failed")
    .expect_tuple();

    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacker_key).into(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let extend_cycle = 1 + next_reward_cycle;

    let partially_stacked_0 = get_partially_stacked_state_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        next_reward_cycle,
        &key_to_stacks_addr(bob_delegate_private_key),
    );

    let partially_stacked_1 = get_partially_stacked_state_pox_4(
        &mut peer,
        &latest_block,
        &pox_addr,
        next_reward_cycle,
        &key_to_stacks_addr(bob_delegate_private_key),
    );

    info!("Currently partially stacked = {partially_stacked_0:?} + {partially_stacked_1:?}");

    bob_nonce += 1;

    let delegate_stack_extend = make_pox_4_delegate_stack_extend(
        bob_delegate_private_key,
        bob_nonce,
        key_to_stacks_addr(alice_stacker_key).into(),
        pox_addr.clone(),
        1,
    );

    let agg_tx_0 = make_pox_4_contract_call(
        bob_delegate_private_key,
        bob_nonce + 1,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(next_reward_cycle.into()),
            signer_key_val.clone(),
        ],
    );

    let agg_tx_1 = make_pox_4_contract_call(
        bob_delegate_private_key,
        bob_nonce + 2,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(extend_cycle.into()),
            signer_extend_key_val.clone(),
        ],
    );

    // Next tx arr calls a delegate_stack_extend pox_4 helper found in mod.rs
    let txs = vec![delegate_stack_extend, agg_tx_0, agg_tx_1];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);
    let new_stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacker_key).to_account_principal(),
    )
    .unwrap()
    .expect_tuple();

    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let extend_cycle_ht = burnchain.reward_cycle_to_block_height(extend_cycle);

    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(pox_addr, reward_entry.reward_address);
    assert_eq!(&reward_entry.signer.unwrap(), signer_bytes.as_slice(),);

    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, extend_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(pox_addr, reward_entry.reward_address);
    assert_eq!(
        &reward_entry.signer.unwrap(),
        signer_extend_bytes.as_slice(),
    );
}

// In this test case, Alice is a solo stacker-signer.
//  Alice stacks the stacking minimum for two cycles.
//  In the next cycle, Alice calls stack-increase to increase
//  her total-locked by a second stacking minimum.
//
// This test asserts that Alice's total-locked is equal to
//  twice the stacking minimum after calling stack-increase.
#[test]
fn stack_increase() {
    let lock_period = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), Some(&observer));

    let mut alice_nonce = 0;
    let alice_stacking_private_key = &keys[0];
    let alice_address = key_to_stacks_addr(alice_stacking_private_key);
    let signing_sk = StacksPrivateKey::from_seed(&[1]);
    let signing_pk = StacksPublicKey::from_private(&signing_sk);
    let signing_bytes = signing_pk.to_bytes_compressed();

    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(alice_stacking_private_key).bytes,
    );

    let stack_stx = make_pox_4_lockup(
        alice_stacking_private_key,
        alice_nonce,
        min_ustx,
        pox_addr.clone(),
        lock_period,
        signing_pk,
        block_height as u64,
    );

    // Initial tx arr includes a stack_stx pox_4 helper found in mod.rs
    let txs = vec![stack_stx];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);
    let stacking_state = get_stacking_state_pox_4(
        &mut peer,
        &latest_block,
        &key_to_stacks_addr(alice_stacking_private_key).to_account_principal(),
    )
    .expect("No stacking state, stack-stx failed")
    .expect_tuple();

    alice_nonce += 1;

    let stack_increase =
        make_pox_4_stack_increase(alice_stacking_private_key, alice_nonce, min_ustx);
    // Next tx arr includes a stack_increase pox_4 helper found in mod.rs
    let txs = vec![stack_increase];
    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);
    let stacker_transactions = get_last_block_sender_transactions(&observer, alice_address);

    let actual_result = stacker_transactions.first().cloned().unwrap().result;

    let expected_result = Value::okay(Value::Tuple(
        TupleData::from_data(vec![
            (
                "stacker".into(),
                Value::Principal(PrincipalData::from(alice_address.clone())),
            ),
            ("total-locked".into(), Value::UInt(min_ustx * 2)),
        ])
        .unwrap(),
    ))
    .unwrap();

    // Testing stack_increase response is equal to expected response
    // Test is straightforward because 'stack-increase' in PoX-4 is the same as PoX-3
    assert_eq!(actual_result, expected_result);

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(pox_addr, reward_entry.reward_address);
    assert_eq!(&reward_entry.signer.unwrap(), &signing_bytes.as_slice());
}

// In this test case, Alice delegates twice the stacking minimum to Bob.
//  Bob stacks half of Alice's funds. In the next cycle,
//  Bob stacks Alice's remaining funds.
//
// This test asserts that Alice's total-locked is equal to
//  twice the stacking minimum after calling delegate-stack-increase.
#[test]
fn delegate_stack_increase() {
    let lock_period: u128 = 2;
    let observer = TestEventObserver::new();
    let (burnchain, mut peer, keys, latest_block, block_height, mut coinbase_nonce) =
        prepare_pox4_test(function_name!(), Some(&observer));

    let alice_nonce = 0;
    let alice_key = &keys[0];
    let alice_address = PrincipalData::from(key_to_stacks_addr(alice_key));
    let mut bob_nonce = 0;
    let bob_delegate_key = &keys[1];
    let bob_delegate_address = PrincipalData::from(key_to_stacks_addr(bob_delegate_key));
    let min_ustx = get_stacking_minimum(&mut peer, &latest_block);
    let signer_sk = StacksPrivateKey::from_seed(&[1, 3, 3, 7]);
    let signer_pk = StacksPublicKey::from_private(&signer_sk);
    let signer_pk_bytes = signer_pk.to_bytes_compressed();
    let signer_key_val = Value::buff_from(signer_pk_bytes.clone()).unwrap();

    let pox_addr = PoxAddress::from_legacy(
        AddressHashMode::SerializeP2PKH,
        key_to_stacks_addr(bob_delegate_key).bytes,
    );

    let next_reward_cycle = 1 + burnchain
        .block_height_to_reward_cycle(block_height)
        .unwrap();

    let delegate_stx = make_pox_4_delegate_stx(
        alice_key,
        alice_nonce,
        2 * min_ustx,
        bob_delegate_address.clone(),
        None,
        Some(pox_addr.clone()),
    );

    let delegate_stack_stx = make_pox_4_delegate_stack_stx(
        bob_delegate_key,
        bob_nonce,
        PrincipalData::from(key_to_stacks_addr(alice_key)).into(),
        min_ustx,
        pox_addr.clone(),
        block_height as u128,
        lock_period,
    );

    // Initial tx arr includes a delegate_stx & delegate_stack_stx pox_4 helper found in mod.rs
    let txs = vec![delegate_stx, delegate_stack_stx];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    bob_nonce += 1;

    let delegate_increase = make_pox_4_delegate_stack_increase(
        bob_delegate_key,
        bob_nonce,
        &alice_address,
        pox_addr.clone(),
        min_ustx,
    );

    let agg_tx = make_pox_4_contract_call(
        bob_delegate_key,
        bob_nonce + 1,
        "stack-aggregation-commit",
        vec![
            pox_addr.as_clarity_tuple().unwrap().into(),
            Value::UInt(next_reward_cycle.into()),
            signer_key_val.clone(),
        ],
    );

    // Next tx arr includes a delegate_increase pox_4 helper found in mod.rs
    let txs = vec![delegate_increase, agg_tx];

    let latest_block = peer.tenure_with_txs(&txs, &mut coinbase_nonce);

    let delegate_transactions =
        get_last_block_sender_transactions(&observer, key_to_stacks_addr(bob_delegate_key));

    let actual_result = delegate_transactions.first().cloned().unwrap().result;

    let expected_result = Value::okay(Value::Tuple(
        TupleData::from_data(vec![
            (
                "stacker".into(),
                Value::Principal(PrincipalData::from(alice_address.clone())),
            ),
            ("total-locked".into(), Value::UInt(min_ustx * 2)),
        ])
        .unwrap(),
    ))
    .unwrap();

    // Testing stack_increase response is equal to expected response
    // Test is straightforward because 'stack-increase' in PoX-4 is the same as PoX-3
    assert_eq!(actual_result, expected_result);

    // test that the reward set contains the increased amount and the expected key
    let reward_cycle_ht = burnchain.reward_cycle_to_block_height(next_reward_cycle);
    let mut reward_set = get_reward_set_entries_at(&mut peer, &latest_block, reward_cycle_ht);
    assert_eq!(reward_set.len(), 1);
    let reward_entry = reward_set.pop().unwrap();
    assert_eq!(pox_addr, reward_entry.reward_address);
    assert_eq!(min_ustx * 2, reward_entry.amount_stacked);
    assert_eq!(&reward_entry.signer.unwrap(), signer_pk_bytes.as_slice());
}

pub fn get_stacking_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> Option<Value> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = Value::Tuple(
            TupleData::from_data(vec![("stacker".into(), account.clone().into())]).unwrap(),
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "stacking-state",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
    })
}

pub fn get_partially_stacked_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    pox_addr: &PoxAddress,
    reward_cycle: u64,
    sender: &StacksAddress,
) -> Option<u128> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = TupleData::from_data(vec![
            (
                "pox-addr".into(),
                pox_addr.as_clarity_tuple().unwrap().into(),
            ),
            ("reward-cycle".into(), Value::UInt(reward_cycle.into())),
            ("sender".into(), PrincipalData::from(sender.clone()).into()),
        ])
        .unwrap()
        .into();
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "partial-stacked-by-cycle",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
        .map(|v| {
            v.expect_tuple()
                .unwrap()
                .get_owned("stacked-amount")
                .unwrap()
                .expect_u128()
                .unwrap()
        })
    })
}

pub fn get_delegation_state_pox_4(
    peer: &mut TestPeer,
    tip: &StacksBlockId,
    account: &PrincipalData,
) -> Option<Value> {
    with_clarity_db_ro(peer, tip, |db| {
        let lookup_tuple = Value::Tuple(
            TupleData::from_data(vec![("stacker".into(), account.clone().into())]).unwrap(),
        );
        let epoch = db.get_clarity_epoch_version().unwrap();
        db.fetch_entry_unknown_descriptor(
            &boot_code_id(boot::POX_4_NAME, false),
            "delegation-state",
            &lookup_tuple,
            &epoch,
        )
        .unwrap()
        .expect_optional()
        .unwrap()
    })
}

pub fn get_stacking_minimum(peer: &mut TestPeer, latest_block: &StacksBlockId) -> u128 {
    with_sortdb(peer, |ref mut chainstate, ref sortdb| {
        chainstate.get_stacking_minimum(sortdb, &latest_block)
    })
    .unwrap()
}

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
pub fn get_last_block_sender_transactions(
    observer: &TestEventObserver,
    address: StacksAddress,
) -> Vec<StacksTransactionReceipt> {
    observer
        .get_blocks()
        .last()
        .unwrap()
        .clone()
        .receipts
        .into_iter()
        .filter(|receipt| {
            if let TransactionOrigin::Stacks(ref transaction) = receipt.transaction {
                return transaction.auth.origin().address_testnet() == address;
            }
            false
        })
        .collect::<Vec<_>>()
}
