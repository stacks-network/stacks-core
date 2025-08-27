// Copyright (C) 2020-2025 Stacks Open Internet Foundation
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
use std::collections::HashMap;

use blockstack_lib::chainstate::stacks::{
    StacksTransaction, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionPostConditionMode, TransactionVersion,
};
use clarity::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
};
use clarity::util::hash::Hash160;

use crate::v0::messages::{
    StateMachineUpdate as StateMachineUpdateMessage, StateMachineUpdateContent,
    StateMachineUpdateMinerState,
};
use crate::v0::signer_state::{GlobalStateEvaluator, ReplayTransactionSet, SignerStateMachine};

/// Test setup helper struct containing common test data
struct SignerStateTest {
    global_eval: GlobalStateEvaluator,
    addresses: Vec<StacksAddress>,
    burn_block: ConsensusHash,
    burn_block_height: u64,
    current_miner: StateMachineUpdateMinerState,
    local_supported_signer_protocol_version: u64,
    active_signer_protocol_version: u64,
    tx_a: StacksTransaction,
    tx_b: StacksTransaction,
    tx_c: StacksTransaction,
    tx_d: StacksTransaction,
}

impl SignerStateTest {
    fn new(num_signers: u32) -> Self {
        let global_eval = generate_global_state_evaluator(num_signers);
        let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
        let local_address = addresses[0].clone();

        let burn_block = ConsensusHash([20u8; 20]);
        let burn_block_height = 100;
        let current_miner = StateMachineUpdateMinerState::ActiveMiner {
            current_miner_pkh: Hash160([0xab; 20]),
            tenure_id: ConsensusHash([0x44; 20]),
            parent_tenure_id: ConsensusHash([0x22; 20]),
            parent_tenure_last_block: StacksBlockId([0x33; 32]),
            parent_tenure_last_block_height: 1,
        };

        let local_supported_signer_protocol_version = 1;
        let active_signer_protocol_version = 1;

        // Create test transactions with different memos for uniqueness
        let pk1 = StacksPrivateKey::random();
        let pk2 = StacksPrivateKey::random();
        let pk3 = StacksPrivateKey::random();
        let pk4 = StacksPrivateKey::random();

        let make_tx = |pk: &StacksPrivateKey, memo: [u8; 34]| StacksTransaction {
            version: TransactionVersion::Testnet,
            chain_id: 0x80000000,
            auth: TransactionAuth::from_p2pkh(pk).unwrap(),
            anchor_mode: TransactionAnchorMode::Any,
            post_condition_mode: TransactionPostConditionMode::Allow,
            post_conditions: vec![],
            payload: TransactionPayload::TokenTransfer(
                local_address.clone().into(),
                100,
                TokenTransferMemo(memo),
            ),
        };

        let tx_a = make_tx(&pk1, [1u8; 34]);
        let tx_b = make_tx(&pk2, [2u8; 34]);
        let tx_c = make_tx(&pk3, [3u8; 34]);
        let tx_d = make_tx(&pk4, [4u8; 34]);

        Self {
            global_eval,
            addresses,
            burn_block,
            burn_block_height,
            current_miner,
            local_supported_signer_protocol_version,
            active_signer_protocol_version,
            tx_a,
            tx_b,
            tx_c,
            tx_d,
        }
    }

    /// Create a replay transaction update message
    fn create_replay_update(
        &self,
        transactions: Vec<StacksTransaction>,
    ) -> StateMachineUpdateMessage {
        StateMachineUpdateMessage::new(
            self.active_signer_protocol_version,
            self.local_supported_signer_protocol_version,
            StateMachineUpdateContent::V1 {
                burn_block: self.burn_block.clone(),
                burn_block_height: self.burn_block_height,
                current_miner: self.current_miner.clone(),
                replay_transactions: transactions,
            },
        )
        .unwrap()
    }

    /// Update multiple signers with the same replay transaction set
    fn update_signers(&mut self, signer_indices: &[usize], transactions: Vec<StacksTransaction>) {
        let update = self.create_replay_update(transactions);
        for &index in signer_indices {
            self.global_eval
                .insert_update(self.addresses[index].clone(), update.clone());
        }
    }

    /// Get the global state replay set
    fn get_global_replay_set(&mut self) -> Vec<StacksTransaction> {
        self.global_eval
            .determine_global_state()
            .unwrap()
            .tx_replay_set
            .unwrap_or_default()
    }
}

fn generate_global_state_evaluator(num_addresses: u32) -> GlobalStateEvaluator {
    let address_weights = generate_random_address_with_equal_weights(num_addresses);
    let active_protocol_version = 0;
    let local_supported_signer_protocol_version = 1;

    let update = StateMachineUpdateMessage::new(
        active_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V0 {
            burn_block: ConsensusHash([0x55; 20]),
            burn_block_height: 100,
            current_miner: StateMachineUpdateMinerState::ActiveMiner {
                current_miner_pkh: Hash160([0xab; 20]),
                tenure_id: ConsensusHash([0x44; 20]),
                parent_tenure_id: ConsensusHash([0x22; 20]),
                parent_tenure_last_block: StacksBlockId([0x33; 32]),
                parent_tenure_last_block_height: 1,
            },
        },
    )
    .unwrap();

    let mut address_updates = HashMap::new();
    for address in address_weights.keys() {
        address_updates.insert(address.clone(), update.clone());
    }
    GlobalStateEvaluator::new(address_updates, address_weights)
}

fn generate_random_address_with_equal_weights(num_addresses: u32) -> HashMap<StacksAddress, u32> {
    let mut address_weights = HashMap::new();
    for _ in 0..num_addresses {
        let stacks_address = StacksAddress::p2pkh(false, &StacksPublicKey::new());
        address_weights.insert(stacks_address, 10);
    }
    address_weights
}

#[test]
fn determine_latest_supported_signer_protocol_versions() {
    let mut global_eval = generate_global_state_evaluator(5);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    let local_address = addresses[0].clone();

    let local_update = global_eval
        .address_updates
        .get(&local_address)
        .unwrap()
        .clone();
    assert_eq!(
        global_eval
            .determine_latest_supported_signer_protocol_version()
            .unwrap(),
        local_update.local_supported_signer_protocol_version
    );

    let StateMachineUpdateMessage {
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        content:
            StateMachineUpdateContent::V0 {
                burn_block,
                burn_block_height,
                current_miner,
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };

    // Let's update 3 signers (60 percent) to support seperate but greater protocol versions
    for (i, address) in addresses.into_iter().skip(1).take(3).enumerate() {
        let new_version = local_update.local_supported_signer_protocol_version + i as u64 + 1;
        let new_update = StateMachineUpdateMessage::new(
            active_signer_protocol_version,
            new_version,
            StateMachineUpdateContent::V0 {
                burn_block: burn_block.clone(),
                burn_block_height,
                current_miner: current_miner.clone(),
            },
        )
        .unwrap();
        global_eval.insert_update(address, new_update);
    }

    assert_eq!(
        global_eval
            .determine_latest_supported_signer_protocol_version()
            .unwrap(),
        local_supported_signer_protocol_version
    );

    // Let's tip the scales over to version number 2 by updating the local signer's version...
    // i.e. > 70% will have version 2 or higher in their map
    let local_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        3,
        StateMachineUpdateContent::V0 {
            burn_block,
            burn_block_height,
            current_miner,
        },
    )
    .unwrap();

    global_eval.insert_update(local_address, local_update);

    assert_eq!(
        global_eval
            .determine_latest_supported_signer_protocol_version()
            .unwrap(),
        local_supported_signer_protocol_version + 1
    );
}

#[test]
fn determine_global_burn_views() {
    let mut global_eval = generate_global_state_evaluator(5);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    let local_address = addresses[0].clone();
    let local_update = global_eval
        .address_updates
        .get(&local_address)
        .unwrap()
        .clone();
    let StateMachineUpdateMessage {
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        content:
            StateMachineUpdateContent::V0 {
                burn_block,
                burn_block_height,
                current_miner,
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };

    assert_eq!(
        global_eval.determine_global_burn_view().unwrap(),
        (&burn_block, burn_block_height)
    );

    // Let's update 3 signers (60 percent) to support a new burn block view
    let new_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V0 {
            burn_block: burn_block.clone(),
            burn_block_height: burn_block_height.wrapping_add(1),
            current_miner,
        },
    )
    .unwrap();
    for address in addresses.into_iter().skip(1).take(3) {
        global_eval.insert_update(address, new_update.clone());
    }

    assert!(
        global_eval.determine_global_burn_view().is_none(),
        "We should not have reached agreement on the burn block height"
    );

    // Let's tip the scales over to burn block height + 1
    global_eval.insert_update(local_address, new_update);
    assert_eq!(
        global_eval.determine_global_burn_view().unwrap(),
        (&burn_block, burn_block_height.wrapping_add(1))
    );
}

#[test]
fn determine_global_states() {
    let mut global_eval = generate_global_state_evaluator(5);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    let local_address = addresses[0].clone();
    let local_update = global_eval
        .address_updates
        .get(&local_address)
        .unwrap()
        .clone();
    let StateMachineUpdateMessage {
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        content:
            StateMachineUpdateContent::V0 {
                burn_block,
                burn_block_height,
                current_miner,
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };

    let state_machine = SignerStateMachine {
        burn_block: burn_block.clone(),
        burn_block_height,
        current_miner: current_miner.clone().into(),
        active_signer_protocol_version: local_supported_signer_protocol_version, // a majority of signers are saying they support version the same local_supported_signer_protocol_version, so update it here...
        tx_replay_set: ReplayTransactionSet::none(),
    };

    global_eval.insert_update(local_address.clone(), local_update);
    assert_eq!(global_eval.determine_global_state().unwrap(), state_machine);
    let new_miner = StateMachineUpdateMinerState::ActiveMiner {
        current_miner_pkh: Hash160([0x00; 20]),
        tenure_id: ConsensusHash([0x44; 20]),
        parent_tenure_id: ConsensusHash([0x22; 20]),
        parent_tenure_last_block: StacksBlockId([0x33; 32]),
        parent_tenure_last_block_height: 1,
    };

    let new_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V0 {
            burn_block: burn_block.clone(),
            burn_block_height,
            current_miner: new_miner.clone(),
        },
    )
    .unwrap();

    // Let's update 3 signers to some new miner key (60 percent)
    for address in addresses.into_iter().skip(1).take(3) {
        global_eval.insert_update(address, new_update.clone());
    }

    assert!(
        global_eval.determine_global_state().is_none(),
        "We should have a disagreement about the current miner"
    );

    let state_machine = SignerStateMachine {
        burn_block,
        burn_block_height,
        current_miner: new_miner.into(),
        active_signer_protocol_version: local_supported_signer_protocol_version, // a majority of signers are saying they support version the same local_supported_signer_protocol_version, so update it here...
        tx_replay_set: ReplayTransactionSet::none(),
    };

    global_eval.insert_update(local_address, new_update);
    // Let's tip the scales over to a different miner
    assert_eq!(global_eval.determine_global_state().unwrap(), state_machine)
}

#[test]
fn determine_global_states_with_tx_replay_set() {
    let mut global_eval = generate_global_state_evaluator(5);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    let local_address = addresses[0].clone();
    let local_update = global_eval
        .address_updates
        .get(&local_address)
        .unwrap()
        .clone();
    let StateMachineUpdateMessage {
        content:
            StateMachineUpdateContent::V0 {
                burn_block,
                burn_block_height,
                current_miner,
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };

    let local_supported_signer_protocol_version = 1;
    let active_signer_protocol_version = 1;

    let state_machine = SignerStateMachine {
        burn_block,
        burn_block_height,
        current_miner: current_miner.clone().into(),
        active_signer_protocol_version, // a majority of signers are saying they support version the same local_supported_signer_protocol_version, so update it here...
        tx_replay_set: ReplayTransactionSet::none(),
    };

    let burn_block = ConsensusHash([20u8; 20]);
    let burn_block_height = burn_block_height + 1;
    assert_eq!(global_eval.determine_global_state().unwrap(), state_machine);

    let no_tx_replay_set_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V1 {
            burn_block: ConsensusHash([20u8; 20]),
            burn_block_height,
            current_miner: current_miner.clone(),
            replay_transactions: vec![],
        },
    )
    .unwrap();

    // Let's update 3 signers to some new tx_replay_set but one that has no txs in it
    for address in addresses.iter().skip(1).take(3) {
        global_eval.insert_update(address.clone(), no_tx_replay_set_update.clone());
    }

    // we have disagreement about the burn block height
    assert!(
        global_eval.determine_global_state().is_none(),
        "We should have disagreement about the burn view"
    );

    global_eval.insert_update(local_address.clone(), no_tx_replay_set_update.clone());

    let new_burn_view_state_machine = SignerStateMachine {
        burn_block: burn_block.clone(),
        burn_block_height,
        current_miner: current_miner.clone().into(),
        active_signer_protocol_version: local_supported_signer_protocol_version, // a majority of signers are saying they support version the same local_supported_signer_protocol_version, so update it here...
        tx_replay_set: ReplayTransactionSet::none(),
    };

    // Let's tip the scales over to the correct burn view
    global_eval.insert_update(local_address.clone(), no_tx_replay_set_update);
    assert_eq!(
        global_eval.determine_global_state().unwrap(),
        new_burn_view_state_machine
    );

    let pk = StacksPrivateKey::random();
    let tx = StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 0x80000000,
        auth: TransactionAuth::from_p2pkh(&pk).unwrap(),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::TokenTransfer(
            local_address.clone().into(),
            123,
            TokenTransferMemo([0u8; 34]),
        ),
    };

    let tx_replay_set_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V1 {
            burn_block: burn_block.clone(),
            burn_block_height,
            current_miner: current_miner.clone(),
            replay_transactions: vec![tx.clone()],
        },
    )
    .unwrap();

    // Let's update 3 signers to some new non empty replay set
    for address in addresses.into_iter().skip(1).take(3) {
        global_eval.insert_update(address, tx_replay_set_update.clone());
    }

    // We still have a valid view but with no global tx set so we aren't blocked entirely but also aren't enforcing the tx replays set
    assert_eq!(
        global_eval.determine_global_state().unwrap(),
        new_burn_view_state_machine
    );

    // Let's tip the scales over to require a tx replay set
    global_eval.insert_update(local_address, tx_replay_set_update.clone());

    let tx_replay_state_machine = SignerStateMachine {
        burn_block,
        burn_block_height,
        current_miner: current_miner.into(),
        active_signer_protocol_version,
        tx_replay_set: ReplayTransactionSet::new(vec![tx]),
    };

    assert_eq!(
        global_eval.determine_global_state().unwrap(),
        tx_replay_state_machine
    );
}

#[test]
/// Case: One signer has [A,B,C], another has [A,B] - should find common prefix [A,B]
fn test_replay_set_common_prefix_coalescing() {
    let mut state_test = SignerStateTest::new(5);

    // Signers 0, 1: [A,B,C] (40% weight)
    state_test.update_signers(
        &[0, 1],
        vec![
            state_test.tx_a.clone(),
            state_test.tx_b.clone(),
            state_test.tx_c.clone(),
        ],
    );

    // Signers 2, 3, 4: [A,B] (60% weight - should win)
    state_test.update_signers(
        &[2, 3, 4],
        vec![state_test.tx_a.clone(), state_test.tx_b.clone()],
    );

    let transactions = state_test.get_global_replay_set();

    // Should find common prefix [A,B] since it's the longest prefix with majority support
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], state_test.tx_a); // Order matters!
    assert_eq!(transactions[1], state_test.tx_b);
    assert!(!transactions.contains(&state_test.tx_c));
}

#[test]
/// Case: One sequence has clear majority - should use that sequence
fn test_replay_set_majority_prefix_selection() {
    let mut state_test = SignerStateTest::new(5);

    // Signer 0: [A] (20% weight)
    state_test.update_signers(&[0], vec![state_test.tx_a.clone()]);

    // Signers 1, 2, 3, 4: [C] (80% weight - above threshold)
    state_test.update_signers(&[1, 2, 3, 4], vec![state_test.tx_c.clone()]);

    let transactions = state_test.get_global_replay_set();

    // Should use [C] since it has majority support (80% > 70%)
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0], state_test.tx_c);
}

#[test]
/// Case: Exact agreement should be prioritized over subset coalescing
fn test_replay_set_exact_agreement_prioritized() {
    let mut state_test = SignerStateTest::new(5);

    // 4 signers agree on [A,B] exactly (80% - above threshold)
    state_test.update_signers(
        &[0, 1, 2, 3],
        vec![state_test.tx_a.clone(), state_test.tx_b.clone()],
    );

    // 1 signer has just [A] (20%)
    state_test.update_signers(&[4], vec![state_test.tx_a.clone()]);

    let transactions = state_test.get_global_replay_set();

    // Should use exact agreement [A,B] rather than common prefix [A]
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], state_test.tx_a); // Order matters!
    assert_eq!(transactions[1], state_test.tx_b);
}

#[test]
/// Case: Complete disagreement - no overlap and no majority
fn test_replay_set_no_agreement_returns_empty() {
    let mut state_test = SignerStateTest::new(5);

    // Signer 0: [A] (20% weight)
    state_test.update_signers(&[0], vec![state_test.tx_a.clone()]);

    // Signer 1: [B] (20% weight)
    state_test.update_signers(&[1], vec![state_test.tx_b.clone()]);

    // Signer 2: [C] (20% weight)
    state_test.update_signers(&[2], vec![state_test.tx_c.clone()]);

    // Signers 3, 4: empty sets (40% weight)
    state_test.update_signers(&[3, 4], vec![]);

    let transactions = state_test.get_global_replay_set();

    // Should return empty set to prioritize liveness when no agreement
    assert_eq!(transactions.len(), 0);
}

#[test]
/// Case: Same transactions in different order have no common prefix
fn test_replay_set_order_matters_no_common_prefix() {
    let mut state_test = SignerStateTest::new(4);

    // Signers 0, 1: [A,B] (50% weight)
    state_test.update_signers(
        &[0, 1],
        vec![state_test.tx_a.clone(), state_test.tx_b.clone()],
    );

    // Signers 2, 3: [B,A] (50% weight)
    state_test.update_signers(
        &[2, 3],
        vec![state_test.tx_b.clone(), state_test.tx_a.clone()],
    );

    let transactions = state_test.get_global_replay_set();

    // Should return empty set since [A,B] and [B,A] have no common prefix
    // Even though both contain the same transactions, order matters for replay
    assert_eq!(transactions.len(), 0);
}

#[test]
/// Case: [A,B,C] vs [A,B,D] should find common prefix [A,B]
fn test_replay_set_partial_prefix_match() {
    let mut state_test = SignerStateTest::new(5);

    // Signer 0, 1: [A,B,C] (40% weight)
    state_test.update_signers(
        &[0, 1],
        vec![
            state_test.tx_a.clone(),
            state_test.tx_b.clone(),
            state_test.tx_c.clone(),
        ],
    );

    // Signers 2, 3, 4: [A,B,D] (60% weight)
    state_test.update_signers(
        &[2, 3, 4],
        vec![
            state_test.tx_a.clone(),
            state_test.tx_b.clone(),
            state_test.tx_d.clone(),
        ],
    );

    let transactions = state_test.get_global_replay_set();

    // Should find [A,B] as the longest common prefix with majority support
    assert_eq!(transactions.len(), 2);
    assert_eq!(transactions[0], state_test.tx_a);
    assert_eq!(transactions[1], state_test.tx_b);
}

#[test]
/// Edge case: Equal-weight competing prefixes should find common prefix
fn test_replay_set_equal_weight_competing_prefixes() {
    let mut state_test = SignerStateTest::new(6);

    // Signers 0, 1, 2: [A,B] (50% weight - not enough alone)
    state_test.update_signers(
        &[0, 1, 2],
        vec![state_test.tx_a.clone(), state_test.tx_b.clone()],
    );

    // Signers 3, 4, 5: [A,C] (50% weight - not enough alone)
    state_test.update_signers(
        &[3, 4, 5],
        vec![state_test.tx_a.clone(), state_test.tx_c.clone()],
    );

    let transactions = state_test.get_global_replay_set();

    // Should find common prefix [A] since both [A,B] and [A,C] start with [A]
    // and [A] has 100% support (above the 70% threshold)
    assert_eq!(transactions.len(), 1, "Should find common prefix [A]");
    assert_eq!(
        transactions[0], state_test.tx_a,
        "Should contain transaction A"
    );
}
