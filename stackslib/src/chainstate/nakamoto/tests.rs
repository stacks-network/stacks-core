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

use std::fs;

use clarity::types::chainstate::{PoxId, SortitionId, StacksBlockId};
use clarity::vm::clarity::ClarityConnection;
use stacks_common::consts::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksPrivateKey, StacksWorkScore,
    TrieHash,
};
use stacks_common::types::{StacksEpoch, StacksEpochId};
use stacks_common::util::hash::{Hash160, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
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
    ChainstateBNSNamespace, StacksBlockHeaderTypes, StacksChainState, StacksHeaderInfo,
};
use crate::chainstate::stacks::{
    CoinbasePayload, StacksBlockHeader, StacksTransaction, StacksTransactionSigner,
    TokenTransferMemo, TransactionAuth, TransactionPayload, TransactionVersion,
};
use crate::core;
use crate::core::StacksEpochExtension;

fn test_path(name: &str) -> String {
    format!("/tmp/stacks-node-tests/nakamoto-tests/{}", name)
}

#[test]
pub fn nakamoto_advance_tip_simple() {
    let path = test_path(function_name!());
    let _r = std::fs::remove_dir_all(&path);

    let burnchain_conf = get_burnchain(&path, None);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let stacker_sk = StacksPrivateKey::from_seed(&[0]);
    let stacker = p2pkh_from(&stacker_sk);
    let balance = 6_000_000_000 * (core::MICROSTACKS_PER_STACKS as u64);
    let stacked_amt = 1_000_000_000 * (core::MICROSTACKS_PER_STACKS as u128);
    let initial_balances = vec![(stacker.clone().into(), balance)];

    let pox_constants = PoxConstants::mainnet_default();

    setup_states_with_epochs(
        &[&path],
        &vrf_keys,
        &committers,
        None,
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 1000000)),
    );

    let mut sort_db = get_rw_sortdb(&path, None);
    let tip = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

    let b = get_burnchain(&path, None);
    let burnchain = get_burnchain_db(&path, None);
    let mut chainstate = get_chainstate(&path);
    let chainstate_chain_id = chainstate.chain_id;
    let (mut chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();

    let mut sortdb_tx = sort_db.tx_handle_begin(&tip.sortition_id).unwrap();

    let chain_tip_consensus_hash = ConsensusHash([0; 20]);
    let chain_tip_burn_header_hash = BurnchainHeaderHash([0; 32]);
    let chain_tip_burn_header_height = 1;
    let chain_tip_burn_header_timestamp = 100;
    let coinbase_tx_payload = TransactionPayload::Coinbase(CoinbasePayload([0; 32]), None);
    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&stacker_sk).unwrap(),
        coinbase_tx_payload,
    );
    coinbase_tx.chain_id = chainstate_chain_id;
    let txid = coinbase_tx.txid();
    coinbase_tx.sign_next_origin(&txid, &stacker_sk).unwrap();
    let block = NakamotoBlock {
        header: NakamotoBlockHeader {
            version: 100,
            chain_length: 1,
            burn_spent: 5,
            parent: FIRST_STACKS_BLOCK_HASH,
            burn_view: tip.burn_header_hash.clone(),
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash::from_hex(
                "582a30eeea84437d222cf8f27cc090860c9eefbaa0fba166b6ef8a814bcc0a85",
            )
            .unwrap(),
            stacker_signature: MessageSignature([0; 65]),
            miner_signature: MessageSignature([0; 65]),
        },
        txs: vec![coinbase_tx],
    };
    let block_size = 10;
    let burnchain_commit_burn = 1;
    let burnchain_sortition_burn = 5;
    let affirmation_weight = 1;
    let parent_chain_tip = StacksHeaderInfo {
        anchored_header: StacksBlockHeader {
            version: 100,
            total_work: StacksWorkScore::genesis(),
            proof: VRFProof::empty(),
            parent_block: BlockHeaderHash([0; 32]),
            parent_microblock: BlockHeaderHash([0; 32]),
            parent_microblock_sequence: 0,
            tx_merkle_root: Sha512Trunc256Sum([0; 32]),
            state_index_root: TrieHash([0; 32]),
            microblock_pubkey_hash: Hash160([1; 20]),
        }
        .into(),
        microblock_tail: None,
        stacks_block_height: 0,
        index_root: TrieHash([0; 32]),
        consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
        burn_header_hash: tip.burn_header_hash.clone(),
        burn_header_height: 2,
        burn_header_timestamp: 50,
        anchored_block_size: 10,
    };

    NakamotoChainState::append_block(
        &mut chainstate_tx,
        clarity_instance,
        &mut sortdb_tx,
        &pox_constants,
        &parent_chain_tip,
        &chain_tip_consensus_hash,
        &chain_tip_burn_header_hash,
        chain_tip_burn_header_height,
        chain_tip_burn_header_timestamp,
        &block,
        block_size,
        burnchain_commit_burn,
        burnchain_sortition_burn,
        affirmation_weight,
    )
    .unwrap();
}

// Assemble 5 nakamoto blocks, invoking append_block. Check that miner rewards
//  mature as expected.
#[test]
pub fn nakamoto_advance_tip_multiple() {
    let path = test_path(function_name!());
    let _r = std::fs::remove_dir_all(&path);

    let burnchain_conf = get_burnchain(&path, None);

    let vrf_keys: Vec<_> = (0..50).map(|_| VRFPrivateKey::new()).collect();
    let committers: Vec<_> = (0..50).map(|_| StacksPrivateKey::new()).collect();

    let miner_sk = StacksPrivateKey::from_seed(&[0]);
    let miner = p2pkh_from(&miner_sk);

    let transacter_sk = StacksPrivateKey::from_seed(&[1]);
    let transacter = p2pkh_from(&transacter_sk);

    let recipient_sk = StacksPrivateKey::from_seed(&[2]);
    let recipient = p2pkh_from(&recipient_sk);

    let initial_balances = vec![
        (miner.clone().into(), 0),
        (transacter.clone().into(), 100000),
    ];
    let transacter_fee = 1000;
    let transacter_send = 250;

    let pox_constants = PoxConstants::mainnet_default();

    setup_states_with_epochs(
        &[&path],
        &vrf_keys,
        &committers,
        None,
        Some(initial_balances),
        StacksEpochId::Epoch21,
        Some(StacksEpoch::all(0, 0, 1000000)),
    );

    let mut sort_db = get_rw_sortdb(&path, None);

    let b = get_burnchain(&path, None);
    let burnchain = get_burnchain_db(&path, None);
    let mut chainstate = get_chainstate(&path);
    let chainstate_chain_id = chainstate.chain_id;

    let mut last_block: Option<NakamotoBlock> = None;
    let index_roots = [
        "a8fa50e42ee48d393ac86036d8eec1bf6ada344de4100478fed37f1106281033",
        "c431be733f37dee9dce70e6de51f616c2ed8b23583af8f7c4a8bce86c5f0a183",
        "0c5e890e95e2f92ef36934bc0e5d71a6715974593f7d952b07ee6f959dae3f1c",
        "0cd7696c4920ea5bc498ea46ee1df8566e06ea0bc8fd16a1e0ffd292d55f746e",
        "84177188b1c02af772d2442b760fd9215b9dfadeed5723504acda2c94b068d15",
    ];

    for i in 1..6 {
        eprintln!("Advance tip: {}", i);
        let parent_snapshot = SortitionDB::get_canonical_burn_chain_tip(sort_db.conn()).unwrap();

        let (mut chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();
        let mut sortdb_tx = sort_db
            .tx_handle_begin(&parent_snapshot.sortition_id)
            .unwrap();

        let parent = match last_block.as_ref() {
            Some(x) => x.header.block_hash(),
            None => FIRST_STACKS_BLOCK_HASH,
        };

        let parent_header: StacksBlockHeaderTypes = match last_block.clone() {
            Some(x) => x.header.into(),
            None => StacksBlockHeader {
                version: 100,
                total_work: StacksWorkScore::genesis(),
                proof: VRFProof::empty(),
                parent_block: BlockHeaderHash([0; 32]),
                parent_microblock: BlockHeaderHash([0; 32]),
                parent_microblock_sequence: 0,
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash([0; 32]),
                microblock_pubkey_hash: Hash160([1; 20]),
            }
            .into(),
        };

        let coinbase_tx_payload = TransactionPayload::Coinbase(CoinbasePayload([i; 32]), None);
        let mut coinbase_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&miner_sk).unwrap(),
            coinbase_tx_payload,
        );
        coinbase_tx.chain_id = chainstate_chain_id;
        coinbase_tx.set_origin_nonce((i - 1).into());
        let mut coinbase_tx_signer = StacksTransactionSigner::new(&coinbase_tx);
        coinbase_tx_signer.sign_origin(&miner_sk).unwrap();
        let coinbase_tx = coinbase_tx_signer.get_tx().unwrap();

        let transacter_tx_payload = TransactionPayload::TokenTransfer(
            recipient.clone().into(),
            transacter_send,
            TokenTransferMemo([0; 34]),
        );
        let mut transacter_tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            TransactionAuth::from_p2pkh(&transacter_sk).unwrap(),
            transacter_tx_payload,
        );
        transacter_tx.chain_id = chainstate_chain_id;
        transacter_tx.set_tx_fee(transacter_fee);
        transacter_tx.set_origin_nonce((i - 1).into());
        let mut transacter_tx_signer = StacksTransactionSigner::new(&transacter_tx);
        transacter_tx_signer.sign_origin(&transacter_sk).unwrap();
        let transacter_tx = transacter_tx_signer.get_tx().unwrap();

        let block = NakamotoBlock {
            header: NakamotoBlockHeader {
                version: 100,
                chain_length: i.into(),
                burn_spent: 10,
                parent,
                burn_view: parent_snapshot.burn_header_hash.clone(),
                tx_merkle_root: Sha512Trunc256Sum([0; 32]),
                state_index_root: TrieHash::from_hex(&index_roots[usize::from(i) - 1]).unwrap(),
                stacker_signature: MessageSignature([0; 65]),
                miner_signature: MessageSignature([0; 65]),
            },
            txs: vec![coinbase_tx, transacter_tx],
        };

        let new_bhh = BurnchainHeaderHash([i; 32]);
        let new_ch = ConsensusHash([i; 20]);
        let new_sh = SortitionHash([1; 32]);

        let new_snapshot = BlockSnapshot {
            block_height: parent_snapshot.block_height + 1,
            burn_header_timestamp: 100 * u64::from(i),
            burn_header_hash: new_bhh.clone(),
            parent_burn_header_hash: parent_snapshot.burn_header_hash.clone(),
            consensus_hash: new_ch.clone(),
            ops_hash: OpsHash([0; 32]),
            total_burn: 10,
            sortition: true,
            sortition_hash: new_sh,
            winning_block_txid: Txid([0; 32]),
            winning_stacks_block_hash: block.header.block_hash(),
            index_root: block.header.state_index_root,
            num_sortitions: parent_snapshot.num_sortitions + 1,
            stacks_block_accepted: true,
            stacks_block_height: block.header.chain_length,
            arrival_index: i.into(),
            canonical_stacks_tip_height: i.into(),
            canonical_stacks_tip_hash: block.header.block_hash(),
            canonical_stacks_tip_consensus_hash: new_ch.clone(),
            sortition_id: SortitionId::new(&new_bhh.clone(), &PoxId::new(vec![true])),
            parent_sortition_id: parent_snapshot.sortition_id.clone(),
            pox_valid: true,
            accumulated_coinbase_ustx: 0,
        };

        sortdb_tx
            .append_chain_tip_snapshot(
                &parent_snapshot,
                &new_snapshot,
                &vec![],
                &vec![],
                None,
                None,
                None,
            )
            .unwrap();

        sortdb_tx.commit().unwrap();
        let mut sortdb_tx = sort_db.tx_handle_begin(&new_snapshot.sortition_id).unwrap();

        let chain_tip_consensus_hash = new_snapshot.consensus_hash.clone();
        let chain_tip_burn_header_hash = new_snapshot.burn_header_hash.clone();
        let chain_tip_burn_header_height = new_snapshot.block_height;
        let chain_tip_burn_header_timestamp = new_snapshot.burn_header_timestamp;

        let block_size = 10;
        let burnchain_commit_burn = 1;
        let burnchain_sortition_burn = 10;
        let affirmation_weight = 1;
        let parent_chain_tip = StacksHeaderInfo {
            anchored_header: parent_header.clone(),
            microblock_tail: None,
            stacks_block_height: parent_header.height(),
            index_root: parent_snapshot.index_root.clone(),
            consensus_hash: parent_snapshot.consensus_hash.clone(),
            burn_header_hash: parent_snapshot.burn_header_hash.clone(),
            burn_header_height: parent_snapshot.block_height.try_into().unwrap(),
            burn_header_timestamp: parent_snapshot.burn_header_timestamp,
            anchored_block_size: 10,
        };

        let (_receipt, clarity_tx) = NakamotoChainState::append_block(
            &mut chainstate_tx,
            clarity_instance,
            &mut sortdb_tx,
            &pox_constants,
            &parent_chain_tip,
            &chain_tip_consensus_hash,
            &chain_tip_burn_header_hash,
            chain_tip_burn_header_height.try_into().unwrap(),
            chain_tip_burn_header_timestamp,
            &block,
            block_size,
            burnchain_commit_burn,
            burnchain_sortition_burn,
            affirmation_weight,
        )
        .unwrap();

        clarity_tx.commit();
        chainstate_tx.commit().unwrap();

        last_block = Some(block);
    }

    // we've produced 5 simulated blocks now (1, 2, 3, 4, and 5)
    //
    // rewards from block 1 should mature 2 tenures later in block 3.
    //  however, due to the way `find_mature_miner_rewards` works, in
    //  the current setup block 1's reward is missed:
    //  `find_mature_miner_rewards` checks the *parent* of the current
    //  block (i.e., the block that block 1's reward mature's in) for
    //   `<= MINER_REWARD_MATURITY`.
    // this means that for these unit tests, blocks 2 and 3 will have rewards
    // processed at blocks 4 and 5
    //
    // in nakamoto, tx fees are rewarded by the next tenure, so the
    // scheduled rewards come 1 tenure after the coinbase reward matures
    for i in 1..6 {
        let ch = ConsensusHash([i; 20]);
        let bh = SortitionDB::get_block_snapshot_consensus(sort_db.conn(), &ch)
            .unwrap()
            .unwrap()
            .winning_stacks_block_hash;
        let block_id = StacksBlockId::new(&ch, &bh);

        let (chainstate_tx, clarity_instance) = chainstate.chainstate_tx_begin().unwrap();
        let sort_db_tx = sort_db.tx_begin_at_tip();

        let stx_balance = clarity_instance
            .read_only_connection(&block_id, &chainstate_tx, &sort_db_tx)
            .with_clarity_db_readonly(|db| db.get_account_stx_balance(&miner.clone().into()));

        eprintln!("Checking block #{}", i);
        let expected_total_tx_fees = u128::from(transacter_fee) * u128::from(i).saturating_sub(3);
        let expected_total_coinbase = 1000000000 * u128::from(i).saturating_sub(3);
        assert_eq!(
            stx_balance.amount_unlocked(),
            expected_total_coinbase + expected_total_tx_fees
        );
    }
}
