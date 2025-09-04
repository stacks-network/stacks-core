// Copyright (C) 2024 Stacks Open Internet Foundation
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
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, SystemTime};

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, StacksTransaction, TenureChangeCause,
    TenureChangePayload, TransactionAnchorMode, TransactionAuth, TransactionPayload,
    TransactionPostConditionMode, TransactionPublicKeyEncoding, TransactionSpendingCondition,
    TransactionVersion,
};
use blockstack_lib::core::test_util::make_stacks_transfer_tx;
use blockstack_lib::net::api::get_tenures_fork_info::TenureForkingInfo;
use clarity::types::chainstate::{BurnchainHeaderHash, SortitionId, StacksAddress};
use clarity::types::PrivateKey;
use clarity::util::secp256k1::Secp256k1PublicKey;
use libsigner::v0::messages::RejectReason;
use libsigner::v0::signer_state::{
    GlobalStateEvaluator, MinerState, ReplayTransactionSet, SignerStateMachine,
};
use libsigner::{BlockProposal, BlockProposalData};
use stacks_common::bitvec::BitVec;
use stacks_common::consts::CHAIN_ID_TESTNET;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksBlockId, StacksPrivateKey, StacksPublicKey, TrieHash,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::{function_name, info};

use crate::chainstate::v2::{GlobalStateView, SortitionState};
use crate::chainstate::{ProposalEvalConfig, SignerChainstateError, SortitionData};
use crate::client::tests::MockServerClient;
use crate::client::StacksClient;
use crate::config::DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS;
use crate::signerdb::tests::tmp_db_path;
use crate::signerdb::{BlockInfo, SignerDb};

fn setup_test_environment(
    fn_name: &str,
) -> (
    StacksClient,
    SignerDb,
    StacksPrivateKey,
    NakamotoBlock,
    SortitionState,
    SortitionState,
    GlobalStateView,
) {
    let block_sk = StacksPrivateKey::from_seed(&[0, 1]);
    let block_pk = StacksPublicKey::from_private(&block_sk);
    let block_pkh = Hash160::from_node_public_key(&block_pk);

    let data = SortitionData {
        miner_pkh: block_pkh,
        miner_pubkey: None,
        prior_sortition: ConsensusHash([0; 20]),
        parent_tenure_id: ConsensusHash([0; 20]),
        consensus_hash: ConsensusHash([1; 20]),
        burn_header_timestamp: 2,
        burn_block_hash: BurnchainHeaderHash([1; 32]),
    };
    let cur_sortition = SortitionState { data };

    let data = SortitionData {
        miner_pkh: block_pkh,
        miner_pubkey: None,
        prior_sortition: ConsensusHash([128; 20]),
        parent_tenure_id: ConsensusHash([128; 20]),
        consensus_hash: ConsensusHash([0; 20]),
        burn_header_timestamp: 1,
        burn_block_hash: BurnchainHeaderHash([0; 32]),
    };
    let last_sortition = SortitionState { data };
    let config = ProposalEvalConfig {
        first_proposal_burn_block_timing: Duration::from_secs(30),
        block_proposal_timeout: Duration::from_secs(5),
        tenure_last_block_proposal_timeout: Duration::from_secs(30),
        tenure_idle_timeout: Duration::from_secs(300),
        tenure_idle_timeout_buffer: Duration::from_secs(2),
        reorg_attempts_activity_timeout: Duration::from_secs(3),
        proposal_wait_for_parent_time: Duration::from_secs(0),
        reset_replay_set_after_fork_blocks: DEFAULT_RESET_REPLAY_SET_AFTER_FORK_BLOCKS,
    };

    let stacks_client = StacksClient::new(
        &StacksPrivateKey::random(),
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 10000).to_string(),
        "FOO".into(),
        false,
        CHAIN_ID_TESTNET,
    );

    let signer_db_dir = "/tmp/stacks-node-tests/signer-units/";
    let signer_db_path = format!("{signer_db_dir}/{fn_name}.{}.sqlite", get_epoch_time_secs());
    fs::create_dir_all(signer_db_dir).unwrap();
    let signer_db = SignerDb::new(signer_db_path).unwrap();

    let mut block = NakamotoBlock {
        header: NakamotoBlockHeader {
            version: 1,
            chain_length: 10,
            burn_spent: 10,
            consensus_hash: ConsensusHash([15; 20]),
            parent_block_id: StacksBlockId([0; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 3,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
        },
        txs: vec![],
    };

    block.header.miner_signature = block_sk
        .sign(block.header.miner_signature_hash().as_bytes())
        .unwrap();

    let signer_state = SignerStateMachine {
        burn_block: cur_sortition.data.consensus_hash,
        burn_block_height: 1,
        current_miner: MinerState::ActiveMiner {
            current_miner_pkh: cur_sortition.data.miner_pkh,
            tenure_id: cur_sortition.data.consensus_hash,
            parent_tenure_id: cur_sortition.data.parent_tenure_id,
            parent_tenure_last_block: StacksBlockId([0u8; 32]),
            parent_tenure_last_block_height: 1,
        },
        active_signer_protocol_version: 0,
        tx_replay_set: ReplayTransactionSet::none(),
    };

    let sortitions_view = GlobalStateView {
        signer_state,
        config,
    };

    (
        stacks_client,
        signer_db,
        block_sk,
        block,
        cur_sortition,
        last_sortition,
        sortitions_view,
    )
}

#[test]
fn check_proposal_units() {
    let (
        stacks_client,
        mut signer_db,
        miner_sk,
        mut block,
        current_sortition,
        _,
        mut sortitions_view,
    ) = setup_test_environment(function_name!());
    assert!(matches!(
        sortitions_view
            .check_proposal(&stacks_client, &mut signer_db, &block)
            .expect_err("Should fail to validate"),
        RejectReason::ConsensusHashMismatch { .. }
    ));
    sortitions_view.signer_state.current_miner = MinerState::NoValidMiner;
    assert!(matches!(
        sortitions_view
            .check_proposal(&stacks_client, &mut signer_db, &block)
            .expect_err("Should fail to validate"),
        RejectReason::InvalidMiner
    ));
    sortitions_view.signer_state.current_miner = MinerState::ActiveMiner {
        current_miner_pkh: current_sortition.data.miner_pkh,
        tenure_id: block.header.consensus_hash,
        parent_tenure_id: current_sortition.data.parent_tenure_id,
        parent_tenure_last_block: block.header.parent_block_id,
        parent_tenure_last_block_height: 1,
    };
    sortitions_view
        .check_proposal(&stacks_client, &mut signer_db, &block)
        .expect("Proposal should have validated");

    block.header.pox_treatment = BitVec::zeros(1).unwrap();
    block.header.miner_signature = miner_sk
        .sign(block.header.miner_signature_hash().as_bytes())
        .unwrap();
    assert!(matches!(
        sortitions_view
            .check_proposal(&stacks_client, &mut signer_db, &block)
            .expect_err("Should fail to validate"),
        RejectReason::InvalidBitvec
    ));
}

#[test]
fn check_proposal_miner_pkh_mismatch() {
    let (stacks_client, mut signer_db, miner_sk, mut block, current_sortition, _, sortitions_view) =
        setup_test_environment(function_name!());
    block.header.consensus_hash = current_sortition.data.consensus_hash;
    let different_block_privk = StacksPrivateKey::from_seed(&[2, 3]);
    assert_ne!(different_block_privk, miner_sk);
    block.header.miner_signature = different_block_privk
        .sign(block.header.miner_signature_hash().as_bytes())
        .unwrap();
    assert!(matches!(
        sortitions_view
            .check_proposal(&stacks_client, &mut signer_db, &block)
            .expect_err("Should fail to validate"),
        RejectReason::PubkeyHashMismatch
    ));
}

fn reorg_timing_testing(
    test_name: &str,
    first_proposal_burn_block_timing_secs: u64,
    sortition_timing_secs: u64,
) -> Result<bool, SignerChainstateError> {
    let (
        _stacks_client,
        mut signer_db,
        block_sk,
        mut block,
        mut cur_sortition,
        last_sortition,
        mut sortitions_view,
    ) = setup_test_environment(test_name);
    sortitions_view.config.first_proposal_burn_block_timing =
        Duration::from_secs(first_proposal_burn_block_timing_secs);
    cur_sortition.data.parent_tenure_id = last_sortition.data.parent_tenure_id;
    block.header.consensus_hash = cur_sortition.data.consensus_hash;
    let block_pk = StacksPublicKey::from_private(&block_sk);
    cur_sortition.data.miner_pkh = Hash160::from_node_public_key(&block_pk);
    cur_sortition.data.miner_pubkey = Some(block_pk);

    let block_proposal_1 = BlockProposal {
        block: NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 1,
                chain_length: 10,
                burn_spent: 10,
                consensus_hash: last_sortition.data.consensus_hash,
                parent_block_id: StacksBlockId([0; 32]),
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                timestamp: 11,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs: vec![],
        },
        burn_height: 2,
        reward_cycle: 1,
        block_proposal_data: BlockProposalData::empty(),
    };
    let mut block_info_1 = BlockInfo::from(block_proposal_1);
    block_info_1.mark_locally_accepted(false).unwrap();
    signer_db.insert_block(&block_info_1).unwrap();

    let sortition_time = SystemTime::UNIX_EPOCH
        + Duration::from_secs(block_info_1.proposed_time + sortition_timing_secs);
    signer_db
        .insert_burn_block(
            &cur_sortition.data.burn_block_hash,
            &cur_sortition.data.consensus_hash,
            3,
            &sortition_time,
            &last_sortition.data.burn_block_hash,
        )
        .unwrap();

    let expected_result = vec![
        TenureForkingInfo {
            burn_block_hash: last_sortition.data.burn_block_hash,
            burn_block_height: 2,
            sortition_id: SortitionId([2; 32]),
            parent_sortition_id: SortitionId([1; 32]),
            consensus_hash: last_sortition.data.consensus_hash,
            was_sortition: true,
            first_block_mined: Some(StacksBlockId([1; 32])),
            nakamoto_blocks: None,
        },
        TenureForkingInfo {
            burn_block_hash: BurnchainHeaderHash([128; 32]),
            burn_block_height: 1,
            sortition_id: SortitionId([1; 32]),
            parent_sortition_id: SortitionId([0; 32]),
            consensus_hash: cur_sortition.data.parent_tenure_id,
            was_sortition: true,
            first_block_mined: Some(StacksBlockId([2; 32])),
            nakamoto_blocks: None,
        },
    ];
    let MockServerClient { server, client, .. } = MockServerClient::new();
    let h = std::thread::spawn(move || {
        cur_sortition.data.check_parent_tenure_choice(
            &signer_db,
            &client,
            &sortitions_view.config.first_proposal_burn_block_timing,
        )
    });

    crate::client::tests::write_response(
        server,
        format!("HTTP/1.1 200 Ok\n\n{}", serde_json::json!(expected_result)).as_bytes(),
    );
    let result = h.join().unwrap();
    info!("Result: {result:?}");
    result
}

#[test]
fn check_parent_tenure_choice_reorg_timing_bad() {
    let is_good = reorg_timing_testing(function_name!(), 30, 31).unwrap();
    assert!(!is_good, "Tenure choice should be bad because the reorg occurred in a block whose proposed time was long enough before the sortition");
}

#[test]
fn check_parent_tenure_choice_reorg_timing_ok() {
    let is_good = reorg_timing_testing(function_name!(), 30, 29).unwrap();
    assert!(is_good, "Tenure choice should be okay because the reorg occurred in a block whose proposed time was close to the sortition");
}

fn make_tenure_change_payload() -> TenureChangePayload {
    TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0; 20]),
        burn_view_consensus_hash: ConsensusHash([0; 20]),
        previous_tenure_end: StacksBlockId([0; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::Extended,
        pubkey_hash: Hash160([0; 20]),
    }
}

fn make_tenure_change_tx(payload: TenureChangePayload) -> StacksTransaction {
    StacksTransaction {
        version: TransactionVersion::Testnet,
        chain_id: 1,
        auth: TransactionAuth::Standard(TransactionSpendingCondition::Singlesig(
            SinglesigSpendingCondition {
                hash_mode: SinglesigHashMode::P2PKH,
                signer: Hash160([0; 20]),
                nonce: 0,
                tx_fee: 0,
                key_encoding: TransactionPublicKeyEncoding::Compressed,
                signature: MessageSignature([0; 65]),
            },
        )),
        anchor_mode: TransactionAnchorMode::Any,
        post_condition_mode: TransactionPostConditionMode::Allow,
        post_conditions: vec![],
        payload: TransactionPayload::TenureChange(payload),
    }
}

#[test]
fn check_proposal_tenure_extend() {
    let (stacks_client, mut signer_db, block_sk, mut block, cur_sortition, _, sortitions_view) =
        setup_test_environment(function_name!());
    block.header.consensus_hash = cur_sortition.data.consensus_hash;
    let mut extend_payload = make_tenure_change_payload();
    extend_payload.burn_view_consensus_hash = cur_sortition.data.consensus_hash;
    extend_payload.tenure_consensus_hash = block.header.consensus_hash;
    extend_payload.prev_tenure_consensus_hash = block.header.consensus_hash;
    let tx = make_tenure_change_tx(extend_payload);
    block.txs = vec![tx];
    sortitions_view
        .check_proposal(&stacks_client, &mut signer_db, &block)
        .expect_err("Proposal should not validate");

    let mut extend_payload = make_tenure_change_payload();
    extend_payload.burn_view_consensus_hash = ConsensusHash([64; 20]);
    extend_payload.tenure_consensus_hash = block.header.consensus_hash;
    extend_payload.prev_tenure_consensus_hash = block.header.consensus_hash;
    let tx = make_tenure_change_tx(extend_payload);
    block.txs = vec![tx];
    block.header.miner_signature = block_sk
        .sign(block.header.miner_signature_hash().as_bytes())
        .unwrap();
    sortitions_view
        .check_proposal(&stacks_client, &mut signer_db, &block)
        .expect("Proposal should validate");
}

#[test]
fn check_proposal_with_extend_during_replay() {
    let (stacks_client, mut signer_db, block_sk, mut block, cur_sortition, _, mut sortitions_view) =
        setup_test_environment(function_name!());
    block.header.consensus_hash = cur_sortition.data.consensus_hash;
    let mut extend_payload = make_tenure_change_payload();
    extend_payload.burn_view_consensus_hash = cur_sortition.data.consensus_hash;
    extend_payload.tenure_consensus_hash = block.header.consensus_hash;
    extend_payload.prev_tenure_consensus_hash = block.header.consensus_hash;
    let tx = make_tenure_change_tx(extend_payload);
    block.txs = vec![tx];
    block.header.sign_miner(&block_sk).unwrap();

    let replay_tx = make_stacks_transfer_tx(
        &block_sk,
        0,
        0,
        1,
        &StacksAddress::p2pkh(true, &Secp256k1PublicKey::new()).into(),
        1000000,
    );
    let replay_set = ReplayTransactionSet::new(vec![replay_tx]);

    sortitions_view.signer_state.tx_replay_set = replay_set;

    sortitions_view
        .check_proposal(&stacks_client, &mut signer_db, &block)
        .expect("Proposal should validate");
}

#[test]
fn check_sortition_timeout() {
    let signer_db_path = tmp_db_path();
    let mut signer_db = SignerDb::new(signer_db_path).unwrap();

    let block_sk = StacksPrivateKey::from_seed(&[0, 1]);
    let block_pk = StacksPublicKey::from_private(&block_sk);
    let block_pkh = Hash160::from_node_public_key(&block_pk);

    let data = SortitionData {
        miner_pkh: block_pkh,
        miner_pubkey: None,
        prior_sortition: ConsensusHash([0; 20]),
        parent_tenure_id: ConsensusHash([0; 20]),
        consensus_hash: ConsensusHash([1; 20]),
        burn_header_timestamp: 2,
        burn_block_hash: BurnchainHeaderHash([1; 32]),
    };
    let sortition = SortitionState { data };
    // Ensure we have a burn height to compare against
    let burn_hash = sortition.data.burn_block_hash;
    let consensus_hash = sortition.data.consensus_hash;
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

    std::thread::sleep(Duration::from_secs(3));
    let address = StacksAddress::p2pkh(false, &StacksPublicKey::new());
    let mut address_weights = HashMap::new();
    address_weights.insert(address.clone(), 10);
    let eval = GlobalStateEvaluator::new(HashMap::new(), address_weights);
    // We have not yet timed out
    assert!(!SortitionState::is_timed_out(
        &consensus_hash,
        &signer_db,
        &eval,
        &address,
        Duration::from_secs(10)
    )
    .unwrap());
    // We are a valid sortition, have an empty tenure, and have now timed out
    assert!(SortitionState::is_timed_out(
        &consensus_hash,
        &signer_db,
        &eval,
        &address,
        Duration::from_secs(0),
    )
    .unwrap());

    // Insert a signed over block so its no longer an empty tenure
    let block_proposal = BlockProposal {
        block: NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 1,
                chain_length: 10,
                burn_spent: 10,
                consensus_hash: sortition.data.consensus_hash,
                parent_block_id: StacksBlockId([0; 32]),
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                timestamp: 11,
                miner_signature: MessageSignature::empty(),
                signer_signature: vec![],
                pox_treatment: BitVec::ones(1).unwrap(),
            },
            txs: vec![],
        },
        burn_height: 2,
        reward_cycle: 1,
        block_proposal_data: BlockProposalData::empty(),
    };

    let mut block_info = BlockInfo::from(block_proposal);
    block_info.signed_over = true;
    signer_db.insert_block(&block_info).unwrap();

    // This will no longer be timed out as we have a non-empty tenure
    assert!(!SortitionState::is_timed_out(
        &consensus_hash,
        &signer_db,
        &eval,
        &address,
        Duration::from_secs(1),
    )
    .unwrap());
}
