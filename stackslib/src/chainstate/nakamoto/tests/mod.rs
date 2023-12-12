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
    StacksPublicKey, StacksWorkScore, TrieHash,
};
use stacks_common::types::{Address, PrivateKey, StacksEpoch, StacksEpochId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, Hash160, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::{MessageSignature, Secp256k1PublicKey};
use stacks_common::util::vrf::{VRFPrivateKey, VRFProof, VRFPublicKey, VRF};
use stdext::prelude::Integer;
use stx_genesis::GenesisData;

use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::tests::make_fork_run;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleTx};
use crate::chainstate::burn::{BlockSnapshot, OpsHash, SortitionHash};
use crate::chainstate::coordinator::tests::{
    get_burnchain, get_burnchain_db, get_chainstate, get_rw_sortdb, get_sortition_db, p2pkh_from,
    pox_addr_from, setup_states_with_epochs,
};
use crate::chainstate::nakamoto::coordinator::tests::boot_nakamoto;
use crate::chainstate::nakamoto::tenure::NakamotoTenure;
use crate::chainstate::nakamoto::tests::node::TestSigners;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, FIRST_STACKS_BLOCK_ID,
};
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
        signer_signature: ThresholdSignature::mock(),
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
        0x00, 0x00, 0x00, 0x00, 0x00, // stacker signature (mocked)
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
        signer_signature: ThresholdSignature::mock(),
    };

    // sortition-inducing tenure change
    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    // non-sortition-inducing tenure change
    let tenure_extend_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x04; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::Extended,
        pubkey_hash: Hash160([0x02; 20]),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    let invalid_tenure_change_payload = TenureChangePayload {
        // bad parent block ID
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x00; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

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
        TransactionPayload::TenureChange(tenure_change_payload.clone()),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut tenure_extend_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(tenure_extend_payload.clone()),
    );
    tenure_extend_tx.chain_id = 0x80000000;
    tenure_extend_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut invalid_tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(invalid_tenure_change_payload.clone()),
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

    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut stx_transfer = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(
            recipient_addr.to_account_principal(),
            1,
            TokenTransferMemo([0x00; 34]),
        ),
    );
    stx_transfer.chain_id = 0x80000000;
    stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;

    // no tenure change if the block doesn't have a tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    ); // empty blocks not allowed

    // syntactically invalid block if there's a sortition-inducing tenure change but no coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
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
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically valid tenure-start block only if we have a syntactically valid tenure change and a syntactically
    // valid coinbase
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(true));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), Some(&coinbase_tx));
    assert_eq!(
        block.get_tenure_change_tx_payload(),
        Some(&tenure_change_payload)
    );
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), Some(&proof));
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically valid non-tenure-start block only if we have a syntactically valid tenure change which is not sortition-induced,
    // or we don't have one at all.
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(true));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(
        block.get_tenure_extend_tx_payload(),
        Some(&tenure_extend_payload)
    );
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically valid non-tenure-start block only if we have a syntactically valid tenure change which is not sortition-induced,
    // or we don't have one at all.
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone(), stx_transfer.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Ok(false));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(true));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(
        block.get_tenure_extend_tx_payload(),
        Some(&tenure_extend_payload)
    );
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        true
    );

    // syntactically invalid if there's more than one tenure change, no matter what
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![tenure_extend_tx.clone(), tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // syntactically invalid if there's a tx before the one tenure change
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![stx_transfer.clone(), tenure_extend_tx.clone()],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Err(()));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );

    // invalid if there are multiple tenure changes
    let block = NakamotoBlock {
        header: header.clone(),
        txs: vec![
            tenure_change_tx.clone(),
            tenure_change_tx.clone(),
            coinbase_tx.clone(),
        ],
    };
    assert_eq!(block.is_wellformed_tenure_start_block(), Err(()));
    assert_eq!(block.is_wellformed_tenure_extend_block(), Ok(false));
    assert_eq!(block.get_coinbase_tx(), None);
    assert_eq!(block.get_tenure_change_tx_payload(), None);
    assert_eq!(block.get_tenure_extend_tx_payload(), None);
    assert_eq!(block.get_vrf_proof(), None);
    assert_eq!(
        block.validate_transactions_static(false, 0x80000000, StacksEpochId::Epoch30),
        false
    );
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

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: epoch2_parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload.clone());
    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut stx_transfer_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(recipient_addr.into(), 123, TokenTransferMemo([0u8; 34])),
    );
    stx_transfer_tx.chain_id = 0x80000000;
    stx_transfer_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let nakamoto_txs = vec![tenure_change_tx.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root = {
        let txid_vecs = nakamoto_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_2 = vec![stx_transfer_tx.clone()];
    let nakamoto_tx_merkle_root_2 = {
        let txid_vecs = nakamoto_txs_2
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: epoch2_parent_block_id.clone(),
        tx_merkle_root: nakamoto_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::mock(),
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

    let epoch2_block = StacksBlock {
        header: epoch2_header.clone(),
        txs: epoch2_txs,
    };

    let nakamoto_block = NakamotoBlock {
        header: nakamoto_header.clone(),
        txs: nakamoto_txs,
    };

    let nakamoto_execution_cost = ExecutionCost {
        write_length: 200,
        write_count: 201,
        read_length: 202,
        read_count: 203,
        runtime: 204,
    };

    // second nakamoto block
    let nakamoto_header_2 = NakamotoBlockHeader {
        version: 1,
        chain_length: 458,
        burn_spent: 127,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: nakamoto_header.block_id(),
        tx_merkle_root: nakamoto_tx_merkle_root_2,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::mock(),
    };

    let nakamoto_header_info_2 = StacksHeaderInfo {
        anchored_header: StacksBlockHeaderTypes::Nakamoto(nakamoto_header_2.clone()),
        microblock_tail: None,
        stacks_block_height: nakamoto_header_2.chain_length,
        index_root: TrieHash([0x67; 32]),
        consensus_hash: nakamoto_header_2.consensus_hash.clone(),
        burn_header_hash: BurnchainHeaderHash([0x88; 32]),
        burn_header_height: 200,
        burn_header_timestamp: 1001,
        anchored_block_size: 123,
    };

    let nakamoto_block_2 = NakamotoBlock {
        header: nakamoto_header_2.clone(),
        txs: nakamoto_txs_2,
    };

    let nakamoto_execution_cost_2 = ExecutionCost {
        write_length: 200,
        write_count: 201,
        read_length: 202,
        read_count: 203,
        runtime: 204,
    };

    let mut total_nakamoto_execution_cost = nakamoto_execution_cost.clone();
    total_nakamoto_execution_cost
        .add(&nakamoto_execution_cost_2)
        .unwrap();

    let nakamoto_tenure = NakamotoTenure {
        tenure_id_consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        prev_tenure_id_consensus_hash: tenure_change_payload.prev_tenure_consensus_hash.clone(),
        burn_view_consensus_hash: tenure_change_payload.burn_view_consensus_hash.clone(),
        cause: tenure_change_payload.cause,
        block_hash: nakamoto_block.header.block_hash(),
        block_id: nakamoto_block.header.block_id(),
        coinbase_height: epoch2_header.total_work.work + 1,
        tenure_index: 1,
        num_blocks_confirmed: 1,
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

        // tenure length doesn't apply to epoch2 blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(&tx, &epoch2_header_info.consensus_hash)
                .unwrap(),
            0
        );

        // no tenure rows
        assert_eq!(
            NakamotoChainState::get_highest_nakamoto_coinbase_height(&tx, i64::MAX as u64).unwrap(),
            None
        );

        // but, this upcoming tenure-change payload should be the first-ever tenure-change payload!
        assert!(NakamotoChainState::check_first_nakamoto_tenure_change(
            &tx,
            &tenure_change_payload
        )
        .unwrap()
        .is_some());

        // no tenure yet, so zero blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &nakamoto_block.header.consensus_hash
            )
            .unwrap(),
            0
        );

        // no tenure rows
        assert_eq!(
            NakamotoChainState::get_highest_nakamoto_coinbase_height(&tx, i64::MAX as u64).unwrap(),
            None
        );

        // add the tenure for these blocks
        NakamotoChainState::insert_nakamoto_tenure(
            &tx,
            &nakamoto_header,
            epoch2_header.total_work.work + 1,
            1,
            &tenure_change_payload,
        )
        .unwrap();

        // no blocks yet, so zero blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &nakamoto_block.header.consensus_hash
            )
            .unwrap(),
            0
        );

        // have a tenure
        assert_eq!(
            NakamotoChainState::get_highest_nakamoto_coinbase_height(&tx, i64::MAX as u64)
                .unwrap()
                .unwrap(),
            epoch2_header.total_work.work + 1
        );

        // this succeeds now
        NakamotoChainState::insert_stacks_block_header(
            &tx,
            &nakamoto_header_info,
            &nakamoto_header,
            Some(&nakamoto_proof),
            &nakamoto_execution_cost,
            &nakamoto_execution_cost,
            true,
            300,
        )
        .unwrap();
        NakamotoChainState::store_block(&tx, nakamoto_block.clone(), false, false).unwrap();

        // tenure has one block
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &nakamoto_block.header.consensus_hash
            )
            .unwrap(),
            1
        );

        // same tenure
        assert_eq!(
            NakamotoChainState::get_highest_nakamoto_coinbase_height(&tx, i64::MAX as u64)
                .unwrap()
                .unwrap(),
            epoch2_header.total_work.work + 1
        );

        // this succeeds now
        NakamotoChainState::insert_stacks_block_header(
            &tx,
            &nakamoto_header_info_2,
            &nakamoto_header_2,
            None,
            &nakamoto_execution_cost,
            &total_nakamoto_execution_cost,
            false,
            400,
        )
        .unwrap();

        NakamotoChainState::store_block(&tx, nakamoto_block_2.clone(), false, false).unwrap();

        // tenure has two blocks
        assert_eq!(
            NakamotoChainState::get_nakamoto_tenure_length(
                &tx,
                &nakamoto_block.header.consensus_hash
            )
            .unwrap(),
            2
        );

        // same tenure
        assert_eq!(
            NakamotoChainState::get_highest_nakamoto_coinbase_height(&tx, i64::MAX as u64)
                .unwrap()
                .unwrap(),
            epoch2_header.total_work.work + 1
        );
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
            &nakamoto_header_2.consensus_hash,
            &nakamoto_header_2.block_hash()
        )
        .unwrap()
        .unwrap(),
        nakamoto_block_2
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
            &nakamoto_header_2.consensus_hash,
            &nakamoto_header_2.block_hash()
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

    // check start/finish
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
        nakamoto_header_info_2
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
        NakamotoChainState::get_block_header(chainstate.db(), &nakamoto_header_2.block_id())
            .unwrap()
            .unwrap(),
        nakamoto_header_info_2
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
        NakamotoChainState::get_coinbase_height(chainstate.db(), &nakamoto_header.block_id())
            .unwrap()
            .unwrap(),
        epoch2_header_info.anchored_header.height() + 1
    );
    assert_eq!(
        NakamotoChainState::get_coinbase_height(chainstate.db(), &nakamoto_header_2.block_id())
            .unwrap()
            .unwrap(),
        epoch2_header_info.anchored_header.height() + 1
    );
    assert_eq!(
        NakamotoChainState::get_coinbase_height(
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
        nakamoto_execution_cost
    );
    assert_eq!(
        NakamotoChainState::get_total_tenure_cost_at(
            chainstate.db(),
            &nakamoto_header_2.block_id()
        )
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
            &nakamoto_header_2.block_id()
        )
        .unwrap()
        .unwrap(),
        400
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

        // set parent epoch2 block processed
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

        // set parent nakamoto block processed
        NakamotoChainState::set_block_processed(&tx, &nakamoto_header_info.index_block_hash())
            .unwrap();

        // next nakamoto block
        assert_eq!(
            NakamotoChainState::next_ready_nakamoto_block(&tx)
                .unwrap()
                .unwrap()
                .0,
            nakamoto_block_2
        );
    }
}

/// Tests:
/// * NakamotoBlockHeader::check_miner_signature
/// * NakamotoBlockHeader::check_tenure_tx
/// * NakamotoBlockHeader::check_coinbase_tx
#[test]
fn test_nakamoto_block_static_verification() {
    let private_key = StacksPrivateKey::new();
    let private_key_2 = StacksPrivateKey::new();

    let vrf_privkey = VRFPrivateKey::new();
    let vrf_pubkey = VRFPublicKey::from_private(&vrf_privkey);
    let sortition_hash = SortitionHash([0x01; 32]);
    let vrf_proof = VRF::prove(&vrf_privkey, sortition_hash.as_bytes());

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(vrf_proof.clone()));

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(&private_key)),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    let tenure_change_payload_bad_ch = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x05; 20]), // wrong
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160::from_node_public_key(&StacksPublicKey::from_private(&private_key)),
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    let tenure_change_payload_bad_miner_sig = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]), // same as in nakamoto header
        prev_tenure_consensus_hash: ConsensusHash([0x01; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: StacksBlockId([0x03; 32]),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]), // wrong
        signature: ThresholdSignature::mock(),
        signers: vec![],
    };

    let tenure_change_tx_payload = TransactionPayload::TenureChange(tenure_change_payload.clone());
    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload.clone(),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_tx_payload_bad_ch =
        TransactionPayload::TenureChange(tenure_change_payload_bad_ch.clone());
    let mut tenure_change_tx_bad_ch = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload_bad_ch.clone(),
    );
    tenure_change_tx_bad_ch.chain_id = 0x80000000;
    tenure_change_tx_bad_ch.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let tenure_change_tx_payload_bad_miner_sig =
        TransactionPayload::TenureChange(tenure_change_payload_bad_miner_sig.clone());
    let mut tenure_change_tx_bad_miner_sig = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        tenure_change_tx_payload_bad_miner_sig.clone(),
    );
    tenure_change_tx_bad_miner_sig.chain_id = 0x80000000;
    tenure_change_tx_bad_miner_sig.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let nakamoto_txs = vec![tenure_change_tx.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root = {
        let txid_vecs = nakamoto_txs
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_bad_ch = vec![tenure_change_tx_bad_ch.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root_bad_ch = {
        let txid_vecs = nakamoto_txs_bad_ch
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let nakamoto_txs_bad_miner_sig =
        vec![tenure_change_tx_bad_miner_sig.clone(), coinbase_tx.clone()];
    let nakamoto_tx_merkle_root_bad_miner_sig = {
        let txid_vecs = nakamoto_txs_bad_miner_sig
            .iter()
            .map(|tx| tx.txid().as_bytes().to_vec())
            .collect();

        MerkleTree::<Sha512Trunc256Sum>::new(&txid_vecs).root()
    };

    let mut nakamoto_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::mock(),
    };
    nakamoto_header.sign_miner(&private_key).unwrap();

    let nakamoto_block = NakamotoBlock {
        header: nakamoto_header.clone(),
        txs: nakamoto_txs,
    };

    let mut nakamoto_header_bad_ch = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root_bad_ch,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::mock(),
    };
    nakamoto_header_bad_ch.sign_miner(&private_key).unwrap();

    let nakamoto_block_bad_ch = NakamotoBlock {
        header: nakamoto_header_bad_ch.clone(),
        txs: nakamoto_txs_bad_ch,
    };

    let mut nakamoto_header_bad_miner_sig = NakamotoBlockHeader {
        version: 1,
        chain_length: 457,
        burn_spent: 126,
        consensus_hash: tenure_change_payload.tenure_consensus_hash.clone(),
        parent_block_id: StacksBlockId([0x03; 32]),
        tx_merkle_root: nakamoto_tx_merkle_root_bad_miner_sig,
        state_index_root: TrieHash([0x07; 32]),
        miner_signature: MessageSignature::empty(),
        signer_signature: ThresholdSignature::mock(),
    };
    nakamoto_header_bad_miner_sig
        .sign_miner(&private_key)
        .unwrap();

    let nakamoto_block_bad_miner_sig = NakamotoBlock {
        header: nakamoto_header_bad_miner_sig.clone(),
        txs: nakamoto_txs_bad_miner_sig,
    };

    assert_eq!(
        nakamoto_block.header.recover_miner_pk().unwrap(),
        StacksPublicKey::from_private(&private_key)
    );
    assert_eq!(
        nakamoto_block.recover_miner_pubkh().unwrap(),
        tenure_change_payload.pubkey_hash
    );

    assert!(nakamoto_block
        .check_miner_signature(&tenure_change_payload.pubkey_hash)
        .is_ok());
    assert!(nakamoto_block
        .check_miner_signature(&Hash160::from_node_public_key(
            &StacksPublicKey::from_private(&private_key_2)
        ))
        .is_err());

    assert!(nakamoto_block.check_tenure_tx().is_ok());
    assert!(nakamoto_block_bad_ch.check_tenure_tx().is_err());
    assert!(nakamoto_block_bad_miner_sig.check_tenure_tx().is_err());

    let vrf_alt_privkey = VRFPrivateKey::new();
    let vrf_alt_pubkey = VRFPublicKey::from_private(&vrf_alt_privkey);

    assert!(nakamoto_block
        .check_coinbase_tx(&vrf_pubkey, &sortition_hash)
        .is_ok());
    assert!(nakamoto_block
        .check_coinbase_tx(&vrf_pubkey, &SortitionHash([0x02; 32]))
        .is_err());
    assert!(nakamoto_block
        .check_coinbase_tx(&vrf_alt_pubkey, &sortition_hash)
        .is_err());
}

/// Mock block arrivals
fn make_fork_run_with_arrivals(
    sort_db: &mut SortitionDB,
    start_snapshot: &BlockSnapshot,
    length: u64,
    bit_pattern: u8,
) -> Vec<BlockSnapshot> {
    let mut last_snapshot = start_snapshot.clone();
    let mut new_snapshots = vec![];
    for i in last_snapshot.block_height..(last_snapshot.block_height + length) {
        let snapshot = BlockSnapshot {
            accumulated_coinbase_ustx: 0,
            pox_valid: true,
            block_height: last_snapshot.block_height + 1,
            burn_header_timestamp: get_epoch_time_secs(),
            burn_header_hash: BurnchainHeaderHash([(i as u8) | bit_pattern; 32]),
            sortition_id: SortitionId([(i as u8) | bit_pattern; 32]),
            parent_sortition_id: last_snapshot.sortition_id.clone(),
            parent_burn_header_hash: last_snapshot.burn_header_hash.clone(),
            consensus_hash: ConsensusHash([((i + 1) as u8) | bit_pattern; 20]),
            ops_hash: OpsHash([(i as u8) | bit_pattern; 32]),
            total_burn: 0,
            sortition: true,
            sortition_hash: SortitionHash([(i as u8) | bit_pattern; 32]),
            winning_block_txid: Txid([(i as u8) | bit_pattern; 32]),
            winning_stacks_block_hash: BlockHeaderHash([(i as u8) | bit_pattern; 32]),
            index_root: TrieHash([0u8; 32]),
            num_sortitions: last_snapshot.num_sortitions + 1,
            stacks_block_accepted: false,
            stacks_block_height: 0,
            arrival_index: 0,
            canonical_stacks_tip_height: last_snapshot.canonical_stacks_tip_height + 10,
            canonical_stacks_tip_hash: BlockHeaderHash([((i + 1) as u8) | bit_pattern; 32]),
            canonical_stacks_tip_consensus_hash: ConsensusHash([((i + 1) as u8) | bit_pattern; 20]),
            miner_pk_hash: None,
        };
        new_snapshots.push(snapshot.clone());
        {
            let mut tx = SortitionHandleTx::begin(sort_db, &last_snapshot.sortition_id).unwrap();
            let _index_root = tx
                .append_chain_tip_snapshot(
                    &last_snapshot,
                    &snapshot,
                    &vec![],
                    &vec![],
                    None,
                    None,
                    None,
                )
                .unwrap();
            tx.test_update_canonical_stacks_tip(
                &snapshot.sortition_id,
                &snapshot.canonical_stacks_tip_consensus_hash,
                &snapshot.canonical_stacks_tip_hash,
                snapshot.canonical_stacks_tip_height,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        last_snapshot = SortitionDB::get_block_snapshot(sort_db.conn(), &snapshot.sortition_id)
            .unwrap()
            .unwrap();
    }
    new_snapshots
}

/// Tests that getting the highest nakamoto tenure works in the presence of forks
#[test]
pub fn test_get_highest_nakamoto_tenure() {
    let test_signers = TestSigners::default();
    let mut peer = boot_nakamoto(function_name!(), vec![], test_signers.aggregate_public_key);

    // extract chainstate and sortdb -- we don't need the peer anymore
    let chainstate = &mut peer.stacks_node.as_mut().unwrap().chainstate;
    let sort_db = peer.sortdb.as_mut().unwrap();

    // seed a single fork of tenures
    let last_snapshot = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    // mock block arrivals
    let snapshots = make_fork_run_with_arrivals(sort_db, &last_snapshot, 5, 0);

    let mut last_header: Option<NakamotoBlockHeader> = None;
    let mut last_tenure_change: Option<TenureChangePayload> = None;
    let mut all_headers = vec![];
    let mut all_tenure_changes = vec![];
    for (i, sn) in snapshots.iter().enumerate() {
        let block_header = NakamotoBlockHeader {
            version: 0,
            chain_length: sn.canonical_stacks_tip_height,
            burn_spent: i as u64,
            consensus_hash: sn.consensus_hash.clone(),
            parent_block_id: last_header
                .as_ref()
                .map(|hdr| hdr.block_id())
                .unwrap_or(FIRST_STACKS_BLOCK_ID.clone()),
            tx_merkle_root: Sha512Trunc256Sum([0x00; 32]),
            state_index_root: TrieHash([0x00; 32]),
            miner_signature: MessageSignature::empty(),
            signer_signature: ThresholdSignature::mock(),
        };
        let tenure_change = TenureChangePayload {
            tenure_consensus_hash: sn.consensus_hash.clone(),
            prev_tenure_consensus_hash: last_tenure_change
                .as_ref()
                .map(|tc| tc.tenure_consensus_hash.clone())
                .unwrap_or(last_snapshot.consensus_hash.clone()),
            burn_view_consensus_hash: sn.consensus_hash.clone(),
            previous_tenure_end: block_header.block_id(),
            previous_tenure_blocks: 10,
            cause: TenureChangeCause::BlockFound,
            pubkey_hash: Hash160([0x00; 20]),
            signature: ThresholdSignature::mock(),
            signers: vec![],
        };

        let tx = chainstate.db_tx_begin().unwrap();
        NakamotoChainState::insert_nakamoto_tenure(
            &tx,
            &block_header,
            1 + i as u64,
            1 + i as u64,
            &tenure_change,
        )
        .unwrap();
        tx.commit().unwrap();

        all_headers.push(block_header.clone());
        all_tenure_changes.push(tenure_change.clone());

        last_header = Some(block_header);
        last_tenure_change = Some(tenure_change);
    }

    // highest tenure should be the last one we inserted
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    let (stacks_ch, stacks_bhh, stacks_height) =
        SortitionDB::get_canonical_stacks_chain_tip_hash_and_height(sort_db.conn()).unwrap();
    debug!("tip = {:?}", &tip);
    debug!(
        "stacks tip = {},{},{}",
        &stacks_ch, &stacks_bhh, stacks_height
    );
    let highest_tenure =
        NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
            .unwrap()
            .unwrap();

    let last_tenure_change = last_tenure_change.unwrap();
    let last_header = last_header.unwrap();
    assert_eq!(
        highest_tenure.tenure_id_consensus_hash,
        last_tenure_change.tenure_consensus_hash
    );
    assert_eq!(
        highest_tenure.prev_tenure_id_consensus_hash,
        last_tenure_change.prev_tenure_consensus_hash
    );
    assert_eq!(
        highest_tenure.burn_view_consensus_hash,
        last_tenure_change.burn_view_consensus_hash
    );
    assert_eq!(highest_tenure.cause, last_tenure_change.cause);
    assert_eq!(highest_tenure.block_hash, last_header.block_hash());
    assert_eq!(highest_tenure.block_id, last_header.block_id());
    assert_eq!(highest_tenure.coinbase_height, 5);
    assert_eq!(highest_tenure.tenure_index, 5);
    assert_eq!(highest_tenure.num_blocks_confirmed, 10);

    // uh oh, a bitcoin fork!
    let last_snapshot = snapshots[2].clone();
    let snapshots = make_fork_run(sort_db, &last_snapshot, 7, 0x80);

    let new_tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();
    debug!("tip = {:?}", &new_tip);
    debug!(
        "stacks tip = {},{},{}",
        &stacks_ch, &stacks_bhh, stacks_height
    );

    // new tip doesn't include the last two tenures
    let highest_tenure =
        NakamotoChainState::get_highest_nakamoto_tenure(chainstate.db(), sort_db.conn())
            .unwrap()
            .unwrap();
    let last_tenure_change = &all_tenure_changes[2];
    let last_header = &all_headers[2];
    assert_eq!(
        highest_tenure.tenure_id_consensus_hash,
        last_tenure_change.tenure_consensus_hash
    );
    assert_eq!(
        highest_tenure.prev_tenure_id_consensus_hash,
        last_tenure_change.prev_tenure_consensus_hash
    );
    assert_eq!(
        highest_tenure.burn_view_consensus_hash,
        last_tenure_change.burn_view_consensus_hash
    );
    assert_eq!(highest_tenure.cause, last_tenure_change.cause);
    assert_eq!(highest_tenure.block_hash, last_header.block_hash());
    assert_eq!(highest_tenure.block_id, last_header.block_id());
    assert_eq!(highest_tenure.coinbase_height, 3);
    assert_eq!(highest_tenure.tenure_index, 3);
    assert_eq!(highest_tenure.num_blocks_confirmed, 10);
}
