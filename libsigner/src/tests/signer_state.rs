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

use blockstack_lib::core::NAKAMOTO_SIGNER_BLOCK_APPROVAL_THRESHOLD;
use clarity::types::chainstate::{ConsensusHash, StacksAddress, StacksBlockId, StacksPublicKey};
use clarity::util::hash::Hash160;

use crate::v0::messages::{
    StateMachineUpdate as StateMachineUpdateMessage, StateMachineUpdateContent,
    StateMachineUpdateMinerState,
};
use crate::v0::signer_state::{GlobalStateEvaluator, SignerStateMachine};

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

    // Let's update 3 signers (60 percent) to support separate but greater protocol versions
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
    };

    global_eval.insert_update(local_address, new_update);
    // Let's tip the scales over to a different miner
    assert_eq!(global_eval.determine_global_state().unwrap(), state_machine)
}

/// The threshold tests below hardcode 70% / 30% boundaries and a specific u32
/// wrap value (170_503_271 for `reached_disagreement_no_u32_overflow`) that are
/// only correct when the supermajority constant is 7. If this assert ever
/// fires, the test values must be recomputed deliberately, not just bumped.
const _: () = assert!(
    NAKAMOTO_SIGNER_BLOCK_APPROVAL_THRESHOLD == 7,
    "threshold tests in this file assume NAKAMOTO_SIGNER_BLOCK_APPROVAL_THRESHOLD == 7"
);

/// Builds a `GlobalStateEvaluator` with empty address maps and the given
/// `total_weight`. Threshold helpers (`reached_agreement` /
/// `reached_disagreement`) only read `total_weight`, so the maps can stay empty.
fn evaluator_with_total_weight(total_weight: u32) -> GlobalStateEvaluator {
    GlobalStateEvaluator {
        address_weights: HashMap::new(),
        address_updates: HashMap::new(),
        total_weight,
    }
}

#[test]
/// Regression: u32 multiplication in `reached_agreement` wrapped silently in
/// release builds for `total_weight > u32::MAX / 7 ≈ 613_566_756`. With
/// `total_weight = 1_000_000_000` the buggy expression `total_weight * 7 / 10`
/// wrapped to ~270_503_270, allowing roughly 27% of total weight to satisfy
/// the 70% supermajority check. The fix widens to u64 first.
fn reached_agreement_no_u32_overflow() {
    let evaluator = evaluator_with_total_weight(1_000_000_000);

    // Pre-fix wrap landed at 270_503_270; assert that vote_weight at the wrapped
    // value is correctly rejected — i.e., 27% does not satisfy 70%.
    assert!(
        !evaluator.reached_agreement(270_503_270),
        "27% of total_weight must not satisfy the 70% threshold"
    );
    // Boundary: exactly 70% must pass.
    assert!(
        evaluator.reached_agreement(700_000_000),
        "70% of total_weight must satisfy the 70% threshold"
    );
    // Just below 70% must fail.
    assert!(
        !evaluator.reached_agreement(699_999_999),
        "below 70% must not satisfy the threshold"
    );
}

#[test]
/// Regression for the same u32-overflow class as `reached_agreement_no_u32_overflow`,
/// but on the disagreement path. Here the multiplier is `10 - threshold = 3`,
/// so the wrap point is `total_weight > u32::MAX / 3 ≈ 1_431_655_765`, well
/// above the agreement wrap point (≈ 613M). The agreement test uses
/// `total_weight = 1_000_000_000` and so doesn't cover this path.
///
/// At `total_weight = 2_000_000_000`, the buggy `total_weight * 3` wrapped to
/// 1_705_032_704 and `/ 10` landed at 170_503_270. That made ~8.5% of total
/// weight look like a blocking minority instead of the required > 30%.
fn reached_disagreement_no_u32_overflow() {
    let evaluator = evaluator_with_total_weight(2_000_000_000);

    // One past the pre-fix wrap value (~8.5% of total). Must not count as a
    // blocking minority.
    assert!(
        !evaluator.reached_disagreement(170_503_271),
        "~8.5% of total_weight must not satisfy the >30% disagreement check"
    );
    // Exactly 30%: strict `>`, so still not disagreement.
    assert!(
        !evaluator.reached_disagreement(600_000_000),
        "exactly 30% must not satisfy the strict > threshold"
    );
    // One unit past 30%: disagreement.
    assert!(
        evaluator.reached_disagreement(600_000_001),
        "just above 30% must satisfy the threshold"
    );
}

#[test]
/// Locks the joint behavior of `reached_agreement` and `reached_disagreement`
/// at a single `total_weight`:
///   - agreement: `>=` 70% (inclusive)
///   - disagreement: `>` 30% (strict)
///   - three regions: [0, 30%] neither, (30%, 70%) disagreement only,
///     [70%, total] both
///
/// Walking 0, 30%, 30%+1, 70%-1, 70% catches a flipped inequality on either
/// side and any drift between the two threshold constants. Also pins the
/// "agreement implies disagreement" relation, which holds as long as the
/// agreement threshold sits above the disagreement one.
fn thresholds_partition_weight_space() {
    let evaluator = evaluator_with_total_weight(1_000_000_000);

    // 0%: neither.
    assert!(!evaluator.reached_agreement(0));
    assert!(!evaluator.reached_disagreement(0));

    // Exactly 30%: strict `>`, so not yet disagreement.
    assert!(!evaluator.reached_agreement(300_000_000));
    assert!(!evaluator.reached_disagreement(300_000_000));

    // One unit past 30%: gap region, disagreement only.
    assert!(!evaluator.reached_agreement(300_000_001));
    assert!(evaluator.reached_disagreement(300_000_001));

    // One unit below 70%: still in the gap.
    assert!(!evaluator.reached_agreement(699_999_999));
    assert!(evaluator.reached_disagreement(699_999_999));

    // Exactly 70%: agreement (`>=`), and disagreement still holds since 70% > 30%.
    assert!(evaluator.reached_agreement(700_000_000));
    assert!(evaluator.reached_disagreement(700_000_000));
}
