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

use std::borrow::BorrowMut;
use std::fs;

use clarity::types::chainstate::{PoxId, SortitionId, StacksBlockId};
use clarity::vm::clarity::ClarityConnection;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::types::StacksAddressExtensions;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksAddress, StacksPrivateKey,
    StacksWorkScore, TrieHash,
};
use stacks_common::types::{PrivateKey, StacksEpoch, StacksEpochId};
use stacks_common::util::hash::{hex_bytes, Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, SchnorrSignature, Secp256k1PublicKey};
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof};
use stdext::prelude::Integer;
use stx_genesis::GenesisData;

use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::SortitionDB;
use crate::chainstate::burn::{BlockSnapshot, OpsHash, SortitionHash};
use crate::chainstate::coordinator::tests::{
    get_burnchain, get_burnchain_db, get_chainstate, get_rw_sortdb, get_sortition_db, p2pkh_from,
    pox_addr_from, setup_states_with_epochs,
};
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoBlockHeader, NakamotoChainState};
use crate::chainstate::stacks::db::{
    ChainStateBootData, ChainstateAccountBalance, ChainstateAccountLockup, ChainstateBNSName,
    ChainstateBNSNamespace, StacksAccount, StacksBlockHeaderTypes, StacksChainState,
    StacksHeaderInfo,
};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksBlock, StacksBlockHeader, StacksTransaction, StacksTransactionSigner,
    TenureChangeCause, TenureChangePayload, ThresholdSignature, TokenTransferMemo,
    TransactionAnchorMode, TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::core;
use crate::core::StacksEpochExtension;
use crate::net::codec::test::check_codec_and_corruption;

/// Get an address's account
pub fn get_account(
    chainstate: &mut StacksChainState,
    sortdb: &SortitionDB,
    addr: &StacksAddress,
) -> StacksAccount {
    let tip = NakamotoChainState::get_canonical_block_header(chainstate.db(), sortdb)
        .unwrap()
        .unwrap();
    debug!(
        "Canonical block header is {}/{} ({}): {:?}",
        &tip.consensus_hash,
        &tip.anchored_header.block_hash(),
        &tip.index_block_hash(),
        &tip
    );

    chainstate
        .with_read_only_clarity_tx(
            &sortdb.index_conn(),
            &tip.index_block_hash(),
            |clarity_conn| {
                StacksChainState::get_account(clarity_conn, &addr.to_account_principal())
            },
        )
        .unwrap()
}

fn test_path(name: &str) -> String {
    format!("/tmp/stacks-node-tests/nakamoto-tests/{}", name)
}

pub mod node;

#[test]
fn codec_nakamoto_header() {
    let header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: SchnorrSignature::default(),
    };

    let bytes = vec![
        // version
        0x01, // chain length
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // burn spent
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, // consensus hash
        0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04,
        0x04, 0x04, 0x04, 0x04, 0x04, // parent block id
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        0x05, 0x05, // tx merkle root
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06, 0x06,
        0x06, 0x06, // state index root
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
        0x07, 0x07, // miner signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, // stacker signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    check_codec_and_corruption(&header, &bytes);
}

#[test]
pub fn test_nakamoto_first_tenure_block_syntactic_validation() {
    let private_key = StacksPrivateKey::new();
    let header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: SchnorrSignature::default(),
    };

    let tenure_change_payload = TransactionPayload::TenureChange(
        TenureChangePayload {
            previous_tenure_end: header.parent_block_id.clone(),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160([0x02; 20]),
            signers: vec![],
        },
        ThresholdSignature::mock(),
    );

    let invalid_tenure_change_payload = TransactionPayload::TenureChange(
        TenureChangePayload {
            // bad parent block ID
            previous_tenure_end: StacksBlockId([0x00; 32]),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160([0x02; 20]),
            signers: vec![],
        },
        ThresholdSignature::mock(),
    );

    let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof.clone()));

    // invalid coinbase payload -- needs a proof
    let invalid_coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, None);

    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut invalid_tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        invalid_tenure_change_payload.clone(),
    );
    invalid_tenure_change_tx.chain_id = 0x80000000;
    invalid_tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut invalid_coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        invalid_coinbase_payload.clone(),
    );
    invalid_coinbase_tx.chain_id = 0x80000000;
    invalid_coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    // no tenure change if the block doesn't have a tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), None);
    assert_eq!(block.tenure_changed(), None);
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    ); // empty blocks not allowed

    // syntactically invalid block if there's a tenure change but no coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone()],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there's a coinbase but not tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there's a coinbase and tenure change, but the coinbase is
    // missing a proof
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone(), invalid_coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there is more than one coinbase transaction
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if the coinbase comes before a tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![coinbase_tx.clone(), tenure_change_tx.clone()],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid block if there is a tenure change after the coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
            tenure_change_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(false));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntatically invalid block if there's an invalid tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            invalid_tenure_change_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(true));
    assert_eq!(block.tenure_changed(), Some(false));
    assert_eq!(block.get_coinbase_tx(), Some(&coinbase_tx));
    assert_eq!(block.get_vrf_proof(), Some(&proof));
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically valid only if we have syntactically valid tenure changes and a syntactically
    // valid coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(true));
    assert_eq!(block.tenure_changed(), Some(true));
    assert_eq!(block.get_coinbase_tx(), Some(&coinbase_tx));
    assert_eq!(block.get_vrf_proof(), Some(&proof));
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // can have multiple valid tenure changes (but note that this block is syntactically invalid
    // because duplicate txs are not allowed)
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_first_tenure_block(), Some(true));
    assert_eq!(block.tenure_changed(), Some(true));
    assert_eq!(block.get_coinbase_tx(), Some(&coinbase_tx));
    assert_eq!(block.get_vrf_proof(), Some(&proof));
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    ); // duplicate transaction
}

#[test]
pub fn test_load_store_update_nakamoto_blocks() {
    let test_name = function_name!();
    let path = test_path(&test_name);
    let pox_constants = PoxConstants::new(5, 3, 3, 25, 5, 0, 0, 0, 0, 0, 0, 0);
    let epochs = StacksEpoch::unit_test_3_0_only(1);
    let _ = std::fs::remove_dir_all(&path);
    let burnchain_conf = get_burnchain(&path, Some(pox_constants.clone()));

    setup_states_with_epochs(
        &[&path],
        &[],
        &[],
        Some(pox_constants.clone()),
        None,
        StacksEpochId::Epoch30,
        Some(epochs),
    );

    let private_key = StacksPrivateKey::new();
    let epoch2_proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let epoch2_proof = VRFProof::from_bytes(&epoch2_proof_bytes[..].to_vec()).unwrap();

    let nakamoto_proof_bytes = hex_bytes("973c815ac3e81a4aff3243f3d8310d24ab9783acd6caa4dcfab20a3744584b2f966acf08140e1a7e1e685695d51b1b511f4f19260a21887244a6c47f7637b8bdeaf5eafe85c1975bab75bc0668fe8a0b").unwrap();
    let nakamoto_proof = VRFProof::from_bytes(&nakamoto_proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload = TransactionPayload::Coinbase(
        CoinbasePayload([0x12; 32]),
        None,
        Some(nakamoto_proof.clone()),
    );

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let epoch2_txs = vec![coinbase_tx.clone()];
    let epoch2_tx_merkle_root = {
        let txid_vecs = epoch2_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let epoch2_header = StacksBlockHeader {
        version: 0,
        total_work: StacksWorkScore {
            burn: 123,
            work: 456,
        },
        proof: epoch2_proof.clone(),
        parent_block: BlockHeaderHash([0x11; 32]),
        parent_microblock: BlockHeaderHash([0x00; 32]),
        parent_microblock_sequence: 0,
        tx_merkle_root: epoch2_tx_merkle_root,
        state_index_root: TrieHash([0x55; 32]),
        microblock_pubkey_hash: Hash160([0x66; 20]),
    };
    let epoch2_consensus_hash = ConsensusHash([0x03; 20]);
    let epoch2_parent_block_id =
        StacksBlockId::new(&epoch2_consensus_hash, &epoch2_header.block_hash());

    let epoch2_header_info = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Epoch2(epoch2_header.clone()),
        microblock_tail: None,
        stacks_block_height: epoch2_header.total_work.work,
        index_root: TrieHash([0x56; 32]),
        consensus_hash: epoch2_consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x77; 32]),
        burn_header_height: 100,
        burn_header_timestamp: 1000,
        anchored_block_size: 12345,
    };

    let epoch2_execution_cost = ExecutionCost {
        write_length: 100,
        write_count: 101,
        read_length: 102,
        read_count: 103,
        runtime: 104,
    };

    let tenure_change_payload = TransactionPayload::TenureChange(
        TenureChangePayload {
            previous_tenure_end: epoch2_parent_block_id.clone(),
            previous_tenure_blocks: 1,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160([0x02; 20]),
            signers: vec![],
        },
        ThresholdSignature::mock(),
    );

    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let nakamoto_txs = vec![tenure_change_tx.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root = {
        let txid_vecs = nakamoto_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: epoch2_parent_block_id.clone(),
        tx_merkle_root: nakamoto_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: SchnorrSignature::default(),
    };

    let nakamoto_header_info = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
    };

    let nakamoto_execution_cost = ExecutionCost {
        write_length: 200,
        write_count: 201,
        read_length: 202,
        read_count: 203,
        runtime: 204,
    };

    let total_nakamoto_execution_cost = ExecutionCost {
        write_length: 400,
        write_count: 401,
        read_length: 402,
        read_count: 403,
        runtime: 404,
    };

    let epoch2_block = StacksBlock {
        header: epoch2_header.clone(),
        txs: epoch2_txs,
    };

    let nakamoto_block = NakamotoBlock {
        header: nakamoto_header.clone(),
        txs: nakamoto_txs,
    };

    let mut chainstate = get_chainstate(&path);

    // store epoch2 and nakamoto headers
    {
        let tx = chainstate.db_tx_begin().unwrap();
        StacksChainState::insert_stacks_block_header(
            &tx,
            &epoch2_parent_block_id,
            &epoch2_header_info,
            &epoch2_execution_cost,
            1,
        )
        .unwrap();
        NakamotoChainState::insert_stacks_block_header(
            &tx,
            &nakamoto_header_info,
            &nakamoto_header,
            Some(&nakamoto_proof),
            &nakamoto_execution_cost,
            &total_nakamoto_execution_cost,
            epoch2_header_info.anchored_header.height() + 1,
            true,
            300,
        )
        .unwrap();
        NakamotoChainState::store_block(&tx, nakamoto_block.clone(), false, false).unwrap();
        tx.commit().unwrap();
    }

    // can load Nakamoto block, but only the Nakamoto block
    assert_eq!(
        NakamotoChainState::load_nakamoto_block(
            chainstate.db(),
            &nakamoto_header.consensus_hash,
            &nakamoto_header.block_hash()
        )
        .unwrap()
        .unwrap(),
        nakamoto_block
    );
    assert_eq!(
        NakamotoChainState::load_nakamoto_block(
            chainstate.db(),
            &epoch2_header_info.consensus_hash,
            &epoch2_header.block_hash()
        )
        .unwrap(),
        None
    );

    // nakamoto block should not be processed yet
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.db(),
            &nakamoto_header.consensus_hash,
            &nakamoto_header.block_hash()
        )
        .unwrap()
        .unwrap(),
        (false, false)
    );
    assert_eq!(
        NakamotoChainState::get_nakamoto_block_status(
            chainstate.db(),
            &epoch2_header_info.consensus_hash,
            &epoch2_header.block_hash()
        )
        .unwrap(),
        None
    );

    // set nakamoto block processed
    {
        let tx = chainstate.db_tx_begin().unwrap();
        NakamotoChainState::set_block_processed(&tx, &nakamoto_header.block_id()).unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                &tx,
                &nakamoto_header.consensus_hash,
                &nakamoto_header.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, false)
        );
    }
    // set nakamoto block orphaned
    {
        let tx = chainstate.db_tx_begin().unwrap();
        NakamotoChainState::set_block_orphaned(&tx, &nakamoto_header.block_id()).unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                &tx,
                &nakamoto_header.consensus_hash,
                &nakamoto_header.block_hash()
            )
            .unwrap()
            .unwrap(),
            (true, true)
        );
    }
    // orphan nakamoto block by parent
    {
        let tx = chainstate.db_tx_begin().unwrap();
        NakamotoChainState::set_block_orphaned(&tx, &nakamoto_header.parent_block_id).unwrap();
        assert_eq!(
            NakamotoChainState::get_nakamoto_block_status(
                &tx,
                &nakamoto_header.consensus_hash,
                &nakamoto_header.block_hash()
            )
            .unwrap()
            .unwrap(),
            (false, true)
        );
    }

    // only one nakamoto block in this tenure, so it's both the start and finish
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_start_block_header(
            chainstate.db(),
            &nakamoto_header.consensus_hash
        )
        .unwrap()
        .unwrap(),
        nakamoto_header_info
    );
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_finish_block_header(
            chainstate.db(),
            &nakamoto_header.consensus_hash
        )
        .unwrap()
        .unwrap(),
        nakamoto_header_info
    );

    // can query the tenure-start and epoch2 headers by consensus hash
    assert_eq!(
        NakamotoChainState::get_block_header_by_consensus_hash(
            chainstate.db(),
            &nakamoto_header.consensus_hash
        )
        .unwrap()
        .unwrap(),
        nakamoto_header_info
    );
    assert_eq!(
        NakamotoChainState::get_block_header_by_consensus_hash(
            chainstate.db(),
            &epoch2_consensus_hash
        )
        .unwrap()
        .unwrap(),
        epoch2_header_info
    );

    // can query the tenure-start and epoch2 headers by block ID
    assert_eq!(
        NakamotoChainState::get_block_header(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        nakamoto_header_info
    );
    assert_eq!(
        NakamotoChainState::get_block_header(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap()
        .unwrap(),
        epoch2_header_info
    );

    // can get tenure height of nakamoto blocks and epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_tenure_height(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        epoch2_header_info.anchored_header.height() + 1
    );
    assert_eq!(
        NakamotoChainState::get_tenure_height(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap()
        .unwrap(),
        epoch2_header_info.anchored_header.height()
    );

    // can get total tenure cost for nakamoto blocks, but not epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        total_nakamoto_execution_cost
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap(),
        None
    );

    // can get total tenure tx fees for nakamoto blocks, but not in epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_total_tenure_tx_fees_at(
            chainstate.db(),
            &nakamoto_header.block_id()
        )
        .unwrap()
        .unwrap(),
        300
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_tx_fees_at(
            chainstate.db(),
            &epoch2_header_info.index_block_hash()
        )
        .unwrap(),
        None
    );

    // can get block VRF proof for both nakamoto and epoch2 blocks
    assert_eq!(
        NakamotoChainState::get_block_vrf_proof(chainstate.db(), &nakamoto_header.consensus_hash)
            .unwrap()
            .unwrap(),
        nakamoto_proof
    );
    assert_eq!(
        NakamotoChainState::get_block_vrf_proof(chainstate.db(), &epoch2_consensus_hash)
            .unwrap()
            .unwrap(),
        epoch2_proof
    );

    // can get nakamoto VRF proof only for nakamoto blocks
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_vrf_proof(
            chainstate.db(),
            &nakamoto_header.consensus_hash
        )
        .unwrap()
        .unwrap(),
        nakamoto_proof
    );
    assert_eq!(
        NakamotoChainState::get_nakamoto_tenure_vrf_proof(chainstate.db(), &epoch2_consensus_hash)
            .unwrap(),
        None
    );

    // next ready nakamoto block is None unless both the burn block and stacks parent block have
    // been processed
    {
        let tx = chainstate.db_tx_begin().unwrap();
        assert_eq!(
            NakamotoChainState::next_ready_nakamoto_block(&tx).unwrap(),
            None
        );

        // set burn processed, but this isn't enough
        NakamotoChainState::set_burn_block_processed(&tx, &nakamoto_header.consensus_hash).unwrap();
        assert_eq!(
            NakamotoChainState::next_ready_nakamoto_block(&tx).unwrap(),
            None
        );

        // set parent block processed
        NakamotoChainState::set_block_processed(&tx, &epoch2_header_info.index_block_hash())
            .unwrap();

        // this works now
        assert_eq!(
            NakamotoChainState::next_ready_nakamoto_block(&tx)
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block
        );
    }
}
