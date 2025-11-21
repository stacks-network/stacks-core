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
use std::fs;
use std::time::{Duration, SystemTime};

use blockstack_lib::chainstate::nakamoto::NakamotoBlockHeader;
use blockstack_lib::chainstate::stacks::db::StacksBlockHeaderTypes;
use blockstack_lib::net::api::get_tenures_fork_info::TenureForkingInfo;
use blockstack_lib::net::api::getsortition::SortitionInfo;
use clarity::types::chainstate::{
    BurnchainHeaderHash, ConsensusHash, SortitionId, StacksAddress, StacksBlockId,
    StacksPrivateKey, StacksPublicKey, TrieHash,
};
use clarity::util::get_epoch_time_secs;
use clarity::util::hash::{Hash160, Sha512Trunc256Sum};
use clarity::util::secp256k1::MessageSignature;
use libsigner::v0::messages::{
    StateMachineUpdate as StateMachineUpdateMessage, StateMachineUpdateContent,
    StateMachineUpdateMinerState,
};
use libsigner::v0::signer_state::{
    GlobalStateEvaluator, MinerState, ReplayTransactionSet, SignerStateMachine,
};
use stacks_common::bitvec::BitVec;
use stacks_common::function_name;

use crate::chainstate::{ProposalEvalConfig, SortitionData};
use crate::client::tests::{build_get_tenure_tip_response, MockServerClient};
use crate::client::StacksClient;
use crate::config::{GlobalConfig, DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS};
use crate::signerdb::tests::{create_block_override, tmp_db_path};
use crate::signerdb::SignerDb;
use crate::v0::signer_state::{LocalStateMachine, NewBurnBlock, StateMachineUpdate};

#[test]
fn check_capitulate_miner_view() {
    let MockServerClient {
        mut server,
        client,
        config,
    } = MockServerClient::new();

    let mut address_weights = HashMap::new();
    address_weights.insert(client.get_signer_address().clone(), 10);
    for _ in 1..10 {
        let stacks_address = StacksAddress::p2pkh(false, &StacksPublicKey::new());
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
        tenure_id: old_miner_tenure_id.clone(),
        parent_tenure_id: parent_tenure_id.clone(),
        parent_tenure_last_block: parent_tenure_last_block.clone(),
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
        address_updates.insert(address.clone(), old_update.clone());
    }
    let mut global_eval = GlobalStateEvaluator::new(address_updates, address_weights);

    let addresses: Vec<_> = global_eval.address_weights.keys().cloned().collect();
    // Let's say we are the very first signer in the list
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
        tenure_id: new_miner_tenure_id.clone(),
        parent_tenure_id: parent_tenure_id.clone(),
        parent_tenure_last_block: parent_tenure_last_block.clone(),
        parent_tenure_last_block_height,
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
        current_miner: new_miner.clone().into(),
        tx_replay_set: ReplayTransactionSet::none(),
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
            .capitulate_miner_view(
                &client,
                &mut global_eval,
                &mut db,
                &new_update,
                Duration::from_secs(u64::MAX)
            )
            .is_none(),
        "Evaluator should have told me to capitulate to the old miner"
    );

    let h = std::thread::spawn(move || {
        // Mark the old miner's block as globally accepted
        db.mark_block_globally_accepted(&mut block_info_1).unwrap();
        db.insert_block(&block_info_1).unwrap();

        // Miner view should stay as the old miner as it has a globally accepted block and 60% consider it valid.
        assert_eq!(
            local_state_machine
                .capitulate_miner_view(
                    &client,
                    &mut global_eval,
                    &mut db,
                    &new_update,
                    Duration::from_secs(u64::MAX)
                )
                .unwrap(),
            old_miner,
            "Evaluator should have told me to capitulate to the old miner"
        );

        // Now that we have a globally approved block for the new miner
        db.mark_block_globally_accepted(&mut block_info_2).unwrap();
        db.insert_block(&block_info_2).unwrap();

        assert_eq!(
            local_state_machine
                .capitulate_miner_view(
                    &client,
                    &mut global_eval,
                    &mut db,
                    &new_update,
                    Duration::from_secs(u64::MAX)
                )
                .unwrap(),
            new_miner,
            "Evaluator should have told me to capitulate to the new miner"
        );
    });

    let expected_result = StacksBlockHeaderTypes::Nakamoto(NakamotoBlockHeader {
        version: 1,
        chain_length: parent_tenure_last_block_height,
        burn_spent: 0,
        consensus_hash: parent_tenure_id,
        parent_block_id: parent_tenure_last_block,
        tx_merkle_root: Sha512Trunc256Sum([0u8; 32]),
        state_index_root: TrieHash([0u8; 32]),
        timestamp: 0,
        miner_signature: MessageSignature([0u8; 65]),
        signer_signature: vec![],
        pox_treatment: BitVec::ones(1).unwrap(),
    });

    let to_send = build_get_tenure_tip_response(&expected_result);
    for _ in 0..2 {
        crate::client::tests::write_response(server, to_send.as_bytes());
        server = crate::client::tests::mock_server_from_config(&config);
    }
    crate::client::tests::write_response(server, to_send.as_bytes());
    h.join().unwrap();
}

#[test]
fn check_miner_inactivity_timeout() {
    let config = GlobalConfig::load_from_file("./src/tests/conf/signer-0.toml").unwrap();
    let stacks_client = StacksClient::from(&config);

    let fn_name = function_name!();
    let signer_db_dir = "/tmp/stacks-node-tests/signer-units/";
    let signer_db_path = format!("{signer_db_dir}/{fn_name}.{}.sqlite", get_epoch_time_secs());
    fs::create_dir_all(signer_db_dir).unwrap();
    let mut signer_db = SignerDb::new(signer_db_path).unwrap();

    let mut proposal_config = ProposalEvalConfig {
        first_proposal_burn_block_timing: Duration::from_secs(30),
        block_proposal_timeout: Duration::from_secs(5),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(3),
        proposal_wait_for_parent_time: Duration::from_secs(0),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
        read_count_idle_timeout: Duration::from_secs(12000),
    };

    let block_sk = StacksPrivateKey::from_seed(&[0, 1]);
    let block_pk = StacksPublicKey::from_private(&block_sk);
    let block_pkh = Hash160::from_node_public_key(&block_pk);

    let cur_sortition = SortitionData {
        miner_pkh: block_pkh.clone(),
        miner_pubkey: None,
        prior_sortition: ConsensusHash([0; 20]),
        parent_tenure_id: ConsensusHash([0; 20]),
        consensus_hash: ConsensusHash([1; 20]),
        burn_header_timestamp: 2,
        burn_block_hash: BurnchainHeaderHash([1; 32]),
    };
    let last_sortition = SortitionData {
        miner_pkh: block_pkh.clone(),
        miner_pubkey: None,
        prior_sortition: ConsensusHash([128; 20]),
        parent_tenure_id: ConsensusHash([128; 20]),
        consensus_hash: ConsensusHash([0; 20]),
        burn_header_timestamp: 1,
        burn_block_hash: BurnchainHeaderHash([0; 32]),
    };

    // Ensure we have a burn height to compare against
    let burn_hash = cur_sortition.burn_block_hash.clone();
    let consensus_hash = cur_sortition.consensus_hash.clone();
    let burn_height = 1;
    let received_time = SystemTime::now();
    signer_db
        .insert_burn_block(
            &burn_hash,
            &consensus_hash,
            burn_height,
            &received_time,
            &BurnchainHeaderHash([0; 32]),
        )
        .unwrap();

    let cur = SortitionInfo {
        burn_block_hash: cur_sortition.burn_block_hash.clone(),
        burn_block_height: burn_height,
        burn_header_timestamp: cur_sortition.burn_header_timestamp,
        sortition_id: SortitionId([1u8; 32]),
        parent_sortition_id: SortitionId([3u8; 32]),
        consensus_hash: cur_sortition.consensus_hash.clone(),
        was_sortition: true,
        miner_pk_hash160: Some(block_pkh.clone()),
        last_sortition_ch: Some(last_sortition.consensus_hash.clone()),
        committed_block_hash: None,
        vrf_seed: None,
        stacks_parent_ch: Some(last_sortition.parent_tenure_id.clone()),
    };
    let last = SortitionInfo {
        burn_block_hash: last_sortition.burn_block_hash.clone(),
        burn_block_height: 0,
        burn_header_timestamp: last_sortition.burn_header_timestamp,
        sortition_id: SortitionId([0u8; 32]),
        parent_sortition_id: SortitionId([4u8; 32]),
        consensus_hash: last_sortition.consensus_hash.clone(),
        was_sortition: true,
        miner_pk_hash160: Some(block_pkh),
        last_sortition_ch: Some(ConsensusHash([9u8; 20])),
        committed_block_hash: None,
        vrf_seed: None,
        stacks_parent_ch: Some(cur_sortition.parent_tenure_id.clone()),
    };

    let active_miner = MinerState::ActiveMiner {
        current_miner_pkh: cur_sortition.miner_pkh,
        tenure_id: cur_sortition.consensus_hash.clone(),
        parent_tenure_id: cur_sortition.parent_tenure_id.clone(),
        parent_tenure_last_block: StacksBlockId([1; 32]),
        parent_tenure_last_block_height: 1,
    };

    let inactive_miner = MinerState::NoValidMiner;

    let genesis_block = NakamotoBlockHeader::genesis();
    let reassigned_miner = MinerState::ActiveMiner {
        current_miner_pkh: last_sortition.miner_pkh,
        tenure_id: last_sortition.consensus_hash.clone(),
        parent_tenure_id: genesis_block.consensus_hash.clone(),
        parent_tenure_last_block: genesis_block.block_id(),
        parent_tenure_last_block_height: 0,
    };

    let mut address_weights = HashMap::new();
    let address = stacks_client.get_signer_address();
    address_weights.insert(address.clone(), 10_u32);

    let eval = GlobalStateEvaluator::new(HashMap::new(), address_weights);
    // This local state machine should not change as an uninitialized local state cannot be modified
    let mut local_state_machine = LocalStateMachine::Uninitialized;
    local_state_machine
        .check_miner_inactivity(&signer_db, &stacks_client, &proposal_config, &eval)
        .unwrap();
    assert_eq!(local_state_machine, LocalStateMachine::Uninitialized);

    // Nothing should happen for a Inactive Miner
    let mut signer_state = SignerStateMachine {
        burn_block: cur_sortition.consensus_hash.clone(),
        burn_block_height: 1,
        current_miner: inactive_miner,
        active_signer_protocol_version: 0,
        tx_replay_set: ReplayTransactionSet::none(),
    };
    local_state_machine = LocalStateMachine::Initialized(signer_state.clone());
    local_state_machine
        .check_miner_inactivity(&signer_db, &stacks_client, &proposal_config, &eval)
        .unwrap();
    assert_eq!(
        local_state_machine,
        LocalStateMachine::Initialized(signer_state.clone())
    );

    // Nothing should happen for a pending state machine
    let update = StateMachineUpdate::BurnBlock(NewBurnBlock {
        burn_block_height: 3,
        consensus_hash: ConsensusHash([9u8; 20]),
    });
    local_state_machine = LocalStateMachine::Pending {
        prior: signer_state.clone(),
        update: update.clone(),
    };
    local_state_machine
        .check_miner_inactivity(&signer_db, &stacks_client, &proposal_config, &eval)
        .unwrap();
    assert_eq!(
        local_state_machine,
        LocalStateMachine::Pending {
            prior: signer_state.clone(),
            update
        }
    );

    // For a current miner it should actually start to do some checks, but since it has not timed out, nothing will change
    signer_state.current_miner = active_miner;
    local_state_machine = LocalStateMachine::Initialized(signer_state.clone());
    local_state_machine
        .check_miner_inactivity(&signer_db, &stacks_client, &proposal_config, &eval)
        .unwrap();
    assert_eq!(
        local_state_machine,
        LocalStateMachine::Initialized(signer_state.clone())
    );

    // lower the time out so forcibly time out the miner
    proposal_config.block_proposal_timeout = Duration::from_secs(0);
    // First the signer will see that the current miner has timed out,
    // so it will next query the node for the current and prior sortition
    // to determine if the prior sortition is valid and should take over
    let expected_result = vec![cur, last];
    let json_payload = serde_json::to_string(&expected_result).unwrap();
    let to_send_1 = format!("HTTP/1.1 200 OK\n\n{json_payload}");

    // Next it will check if the prior sortition is both valid
    // and that it has chosen a good parent
    let expected_result = vec![
        TenureForkingInfo {
            burn_block_hash: last_sortition.burn_block_hash.clone(),
            burn_block_height: 2,
            sortition_id: SortitionId([2; 32]),
            parent_sortition_id: SortitionId([1; 32]),
            consensus_hash: last_sortition.consensus_hash.clone(),
            was_sortition: true,
            first_block_mined: Some(StacksBlockId([1; 32])),
            nakamoto_blocks: None,
        },
        TenureForkingInfo {
            burn_block_hash: BurnchainHeaderHash([128; 32]),
            burn_block_height: 1,
            sortition_id: SortitionId([1; 32]),
            parent_sortition_id: SortitionId([0; 32]),
            consensus_hash: cur_sortition.parent_tenure_id.clone(),
            was_sortition: true,
            first_block_mined: Some(StacksBlockId([2; 32])),
            nakamoto_blocks: None,
        },
    ];
    let json_payload = serde_json::to_string(&expected_result).unwrap();
    let to_send_2 = format!("HTTP/1.1 200 OK\n\n{json_payload}");

    // Then it will grab the tip of the prior sortition
    let expected_result = StacksBlockHeaderTypes::Nakamoto(genesis_block);
    let json_payload = serde_json::to_string(&expected_result).unwrap();
    let to_send_3 = format!("HTTP/1.1 200 OK\n\n{json_payload}");

    let MockServerClient {
        mut server,
        client,
        config,
    } = MockServerClient::new();
    let h = std::thread::spawn(move || {
        local_state_machine
            .check_miner_inactivity(&signer_db, &client, &proposal_config, &eval)
            .unwrap();
        // The new miner will have the reassigned miner
        signer_state.current_miner = reassigned_miner;
        assert_eq!(
            local_state_machine,
            LocalStateMachine::Initialized(signer_state)
        );
    });

    crate::client::tests::write_response(server, to_send_1.as_bytes());

    server = crate::client::tests::mock_server_from_config(&config);
    crate::client::tests::write_response(server, to_send_2.as_bytes());

    server = crate::client::tests::mock_server_from_config(&config);
    crate::client::tests::write_response(server, to_send_3.as_bytes());
    h.join().unwrap();
}
