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

use clarity::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey, StacksPublicKey,
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
    for _ in 0..5 {
        let stacks_address = StacksAddress::p2pkh(
            false,
            &StacksPublicKey::from_private(&StacksPrivateKey::random()),
        );
        address_weights.insert(stacks_address, 10);
    }

    let active_signer_protocol_version = 0;
    let local_supported_signer_protocol_version = 0;
    let burn_block = ConsensusHash([0x55; 20]);
    let burn_block_height = 100;
    let parent_tenure_id = ConsensusHash([0x22; 20]);
    let parent_tenure_last_block = StacksBlockId([0x33; 32]);
    let parent_tenure_last_block_height = 1;
    let old_miner = StateMachineUpdateMinerState::ActiveMiner {
        current_miner_pkh: Hash160([0xab; 20]),
        tenure_id: ConsensusHash([0x44; 20]),
        parent_tenure_id,
        parent_tenure_last_block,
        parent_tenure_last_block_height,
    };
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
                current_miner,
            },
        ..
    } = local_update.clone()
    else {
        panic!("Unexpected state machine update message version");
    };
    // Let's create a new miner view
    let new_tenure_id = ConsensusHash([0x00; 20]);

    let db_path = tmp_db_path();
    let mut db = SignerDb::new(db_path).expect("Failed to create signer db");
    let (mut block_info_1, _block_proposal) = create_block_override(|b| {
        b.block.header.consensus_hash = new_tenure_id;
        b.block.header.miner_signature = MessageSignature([0x01; 65]);
        b.block.header.chain_length = 1;
        b.burn_height = burn_block_height;
    });

    db.insert_block(&block_info_1).unwrap();
    let new_miner = StateMachineUpdateMinerState::ActiveMiner {
        current_miner_pkh: Hash160([0x00; 20]),
        tenure_id: new_tenure_id,
        parent_tenure_id,
        parent_tenure_last_block,
        parent_tenure_last_block_height,
    };

    // Let's update only our own view: the evaluator will tell me to revert my viewpoint to the old miner
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

    let signer_state_machine = SignerStateMachine {
        burn_block,
        burn_block_height,
        current_miner: (&new_miner).into(),
        tx_replay_set: None,
        active_signer_protocol_version,
    };

    let mut local_state_machine = LocalStateMachine::Initialized(signer_state_machine.clone());
    assert_eq!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .unwrap(),
        current_miner
    );

    // Let's set a blocking minority to this different view: evaluator should see no global blocks for the blocking majority and return none
    // I.e. only if the blocking minority is attempting to reject an reorg should it take priority over the rest.
    // Let's update 1 other signer to some new miner key (60 percent)
    for address in addresses.into_iter().skip(1).take(1) {
        global_eval.insert_update(address, new_update.clone());
    }
    assert!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .is_none(),
        "Evaluator should have been unable to determine a majority view and return none"
    );

    db.mark_block_globally_accepted(&mut block_info_1).unwrap();

    db.insert_block(&block_info_1).unwrap();

    // Now that the blocking minority references a tenure which would actually get reorged, lets capitulate to their view
    assert_eq!(
        local_state_machine
            .capitulate_miner_view(&mut global_eval, &mut db, local_address, &new_update)
            .unwrap(),
        new_miner
    );
}
