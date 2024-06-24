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

use std::fs;
use std::net::{Ipv4Addr, SocketAddrV4};

use blockstack_lib::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader};
use blockstack_lib::chainstate::stacks::{
    SinglesigHashMode, SinglesigSpendingCondition, StacksTransaction, TenureChangeCause,
    TenureChangePayload, TransactionAnchorMode, TransactionAuth, TransactionPayload,
    TransactionPostConditionMode, TransactionPublicKeyEncoding, TransactionSpendingCondition,
    TransactionVersion,
};
use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksBlockId, StacksPrivateKey, StacksPublicKey, TrieHash,
};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;

use crate::chainstate::{SortitionMinerStatus, SortitionState, SortitionsView};
use crate::client::StacksClient;
use crate::signerdb::SignerDb;

fn setup_test_environment(
    fn_name: &str,
) -> (
    StacksClient,
    SignerDb,
    StacksPublicKey,
    SortitionsView,
    NakamotoBlock,
) {
    let block_sk = StacksPrivateKey::from_seed(&[0, 1]);
    let block_pk = StacksPublicKey::from_private(&block_sk);
    let block_pkh = Hash160::from_node_public_key(&block_pk);

    let cur_sortition = SortitionState {
        miner_pkh: block_pkh,
        miner_pubkey: None,
        prior_sortition: ConsensusHash([0; 20]),
        parent_tenure_id: ConsensusHash([0; 20]),
        consensus_hash: ConsensusHash([1; 20]),
        miner_status: SortitionMinerStatus::Valid,
    };

    let last_sortition = Some(SortitionState {
        miner_pkh: block_pkh,
        miner_pubkey: None,
        prior_sortition: ConsensusHash([128; 20]),
        parent_tenure_id: ConsensusHash([128; 20]),
        consensus_hash: ConsensusHash([0; 20]),
        miner_status: SortitionMinerStatus::Valid,
    });

    let view = SortitionsView {
        latest_consensus_hash: cur_sortition.consensus_hash,
        cur_sortition,
        last_sortition,
    };

    let stacks_client = StacksClient::new(
        StacksPrivateKey::new(),
        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 10000).into(),
        "FOO".into(),
        false,
    );

    let signer_db_dir = "/tmp/stacks-node-tests/signer-units/";
    let signer_db_path = format!("{signer_db_dir}/{fn_name}.{}.sqlite", get_epoch_time_secs());
    fs::create_dir_all(signer_db_dir).unwrap();
    let signer_db = SignerDb::new(signer_db_path).unwrap();

    let block = NakamotoBlock {
        header: NakamotoBlockHeader {
            version: 1,
            chain_length: 10,
            burn_spent: 10,
            consensus_hash: ConsensusHash([15; 20]),
            parent_block_id: StacksBlockId([0; 32]),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            timestamp: 11,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::ones(1).unwrap(),
        },
        txs: vec![],
    };

    (stacks_client, signer_db, block_pk, view, block)
}

#[test]
fn check_proposal_units() {
    let (stacks_client, signer_db, block_pk, mut view, block) =
        setup_test_environment("check_proposal_units");

    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk,)
        .unwrap());

    view.last_sortition = None;

    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk,)
        .unwrap());
}

#[test]
fn check_proposal_miner_pkh_mismatch() {
    let (stacks_client, signer_db, _block_pk, view, mut block) =
        setup_test_environment("miner_pkh_mismatch");
    block.header.consensus_hash = view.cur_sortition.consensus_hash;
    let different_block_pk = StacksPublicKey::from_private(&StacksPrivateKey::from_seed(&[2, 3]));
    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &different_block_pk)
        .unwrap());

    block.header.consensus_hash = view.last_sortition.as_ref().unwrap().consensus_hash;
    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &different_block_pk)
        .unwrap());
}

#[test]
fn check_proposal_invalid_status() {
    let (stacks_client, signer_db, block_pk, mut view, mut block) =
        setup_test_environment("invalid_status");
    block.header.consensus_hash = view.cur_sortition.consensus_hash;
    assert!(view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());
    view.cur_sortition.miner_status = SortitionMinerStatus::InvalidatedAfterFirstBlock;
    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());

    block.header.consensus_hash = view.last_sortition.as_ref().unwrap().consensus_hash;
    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());

    view.cur_sortition.miner_status = SortitionMinerStatus::InvalidatedBeforeFirstBlock;
    block.header.consensus_hash = view.last_sortition.as_ref().unwrap().consensus_hash;
    // this block passes the signer state checks, even though it doesn't have a tenure change tx.
    // this is because the signer state does not perform the tenure change logic checks: it needs
    // the stacks-node to do that (because the stacks-node actually knows whether or not their
    // parent blocks have been seen before, while the signer state checks are only reasoning about
    // stacks blocks seen by the signer, which may be a subset)
    assert!(view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());
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
fn check_proposal_tenure_extend_invalid_conditions() {
    let (stacks_client, signer_db, block_pk, view, mut block) =
        setup_test_environment("tenure_extend");
    block.header.consensus_hash = view.cur_sortition.consensus_hash;
    let mut extend_payload = make_tenure_change_payload();
    extend_payload.burn_view_consensus_hash = view.cur_sortition.consensus_hash;
    extend_payload.tenure_consensus_hash = block.header.consensus_hash;
    extend_payload.prev_tenure_consensus_hash = block.header.consensus_hash;
    let tx = make_tenure_change_tx(extend_payload);
    block.txs = vec![tx];
    assert!(!view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());

    let mut extend_payload = make_tenure_change_payload();
    extend_payload.burn_view_consensus_hash = ConsensusHash([64; 20]);
    extend_payload.tenure_consensus_hash = block.header.consensus_hash;
    extend_payload.prev_tenure_consensus_hash = block.header.consensus_hash;
    let tx = make_tenure_change_tx(extend_payload);
    block.txs = vec![tx];
    assert!(view
        .check_proposal(&stacks_client, &signer_db, &block, &block_pk)
        .unwrap());
}
