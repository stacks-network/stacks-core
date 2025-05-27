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
use std::time::SystemTime;

use clarity::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey,
    StacksPublicKey,
};
use clarity::util::hash::Hash160;
use clarity::util::secp256k1::MessageSignature;
use libsigner::v0::messages::{
    StateMachineUpdate as StateMachineUpdateMessage, StateMachineUpdateContent,
    StateMachineUpdateMinerState,
};
use libsigner::v0::signer_state::{GlobalStateEvaluator, SignerStateMachine};

use crate::signerdb::tests::{create_block_override, tmp_db_path};
use crate::signerdb::SignerDb;
use crate::v0::signer_state::LocalStateMachine;

#[test]
fn check_capitulate_miner_view() {
    let mut address_weights = HashMap::new();
    for _ in 0..10 {
        let stacks_address = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        address_weights.insert(stacks_address, 10);
    }

    let active_signer_protocol_version = 0;
    let local_supported_signer_protocol_version = 0;
    let burn_block = ConsensusHash([0x55; 20]);
    let parent_tenure_id = ConsensusHash([0x22; 20]);
    let parent_tenure_last_block = StacksBlockId([0x33; 32]);
    let parent_tenure_last_block_height = 1;

    let old_miner_tenure_id = ConsensusHash([0x01; 20]);
    let new_miner_tenure_id = ConsensusHash([0x00; 20]);

    let burn_block_height = 100;

    let old_miner = StateMachineUpdateMinerState::ActiveMiner {
        current_miner_pkh: Hash160([0xab; 20]),
        tenure_id: old_miner_tenure_id,
        parent_tenure_id,
        parent_tenure_last_block,
        parent_tenure_last_block_height,
    };
    // Make sure the old update still has the newer burn block height
    let old_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V0 {
            burn_block,
            burn_block_height,
            current_miner: old_miner.clone(),
        },
    )
    .unwrap();

    let mut address_updates = HashMap::new();
    for address in address_weights.keys() {
        address_updates.insert(*address, old_update.clone());
    }
    let mut global_eval = GlobalStateEvaluator::new(address_updates, address_weights);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    // Let's say we are the very first signer in the list
    let local_address = addresses[0];
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
                ..
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };
    // Let's create a new miner view
    let new_miner = StateMachineUpdateMinerState::ActiveMiner {
        current_miner_pkh: Hash160([0x00; 20]),
        tenure_id: new_miner_tenure_id,
        parent_tenure_id,
        parent_tenure_last_block,
        parent_tenure_last_block_height,
    };
    let new_update = StateMachineUpdateMessage::new(
        active_signer_protocol_version,
        local_supported_signer_protocol_version,
        StateMachineUpdateContent::V0 {
            burn_block,
            burn_block_height,
            current_miner: new_miner.clone(),
        },
    )
    .unwrap();

    // Update the database to have both the burn blocks corresponding to the tenure ids
    // and both tenures have a locally accepted block
    let db_path = tmp_db_path();
    let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
    // Make sure both burn block corresponding to the tenure id's exist in our DB.
    db.insert_burn_block(
        &BurnchainHeaderHash([0u8; 32]),
        &old_miner_tenure_id,
        burn_block_height.saturating_sub(1),
        &SystemTime::now(),
        &BurnchainHeaderHash([1u8; 32]),
    )
    .unwrap();
    db.insert_burn_block(
        &BurnchainHeaderHash([0u8; 32]),
        &new_miner_tenure_id,
        burn_block_height,
        &SystemTime::now(),
        &BurnchainHeaderHash([1u8; 32]),
    )
    .unwrap();
    let (mut block_info_1, _block_proposal) = create_block_override(|b| {
        b.block.header.consensus_hash = old_miner_tenure_id;
        b.block.header.miner_signature = MessageSignature([0x02; 65]);
        b.block.header.chain_length = 1;
        b.burn_height = burn_block_height.saturating_sub(1);
    });
    db.insert_block(&block_info_1).unwrap();

    let (mut block_info_2, _block_proposal) = create_block_override(|b| {
        b.block.header.consensus_hash = new_miner_tenure_id;
        b.block.header.miner_signature = MessageSignature([0x01; 65]);
        b.block.header.chain_length = 1;
        b.burn_height = burn_block_height;
    });
    db.insert_block(&block_info_2).unwrap();

    let signer_state_machine = SignerStateMachine {
        burn_block,
        burn_block_height,
        current_miner: (&new_miner).into(),
        tx_replay_set: None,
        active_signer_protocol_version,
    };

    let mut local_state_machine = LocalStateMachine::Initialized(signer_state_machine.clone());

    // Let's update 40 percent of other signers to some new miner key
    for address in addresses.into_iter().take(4) {
        global_eval.insert_update(address, new_update.clone());
    }
    // Miner view should be None as we can't find consensus on a single miner
    assert!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .is_none(),
        "Evaluator should have told me to capitulate to the old miner"
    );

    // Mark the old miner's block as globally accepted
    db.mark_block_globally_accepted(&mut block_info_1).unwrap();
    db.insert_block(&block_info_1).unwrap();

    // Miner view should stay as the old miner as it has a globally accepted block and 60% consider it valid.
    assert_eq!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .unwrap(),
        old_miner,
        "Evaluator should have told me to capitulate to the old miner"
    );

    // Now that we have a globally approved block for the new miner
    db.mark_block_globally_accepted(&mut block_info_2).unwrap();
    db.insert_block(&block_info_2).unwrap();

    // Now that the blocking minority references a tenure which would actually get reorged, lets capitulate to the NEW view
    // even though both the old and new signer have > 30% approval (it has a higher burn block).
    assert_eq!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .unwrap(),
        new_miner,
        "Evaluator should have told me to capitulate to the new miner"
    );
}
